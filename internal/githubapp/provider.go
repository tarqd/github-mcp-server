package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/github/github-mcp-server/pkg/http/transport"
	"github.com/github/github-mcp-server/pkg/utils"
	gogithub "github.com/google/go-github/v87/github"
)

const (
	defaultRefreshBefore  = 5 * time.Minute
	defaultRequestTimeout = 30 * time.Second
)

// InstallationConfig identifies the GitHub App installation to use. Set
// InstallationID directly, or set exactly one lookup field.
type InstallationConfig struct {
	InstallationID int64
	Org            string
	Repo           string
	User           string
}

// Config configures GitHub App server-to-server authentication.
type Config struct {
	AppID             int64
	PrivateKeyPath    string
	PrivateKeyCommand string
	Installation      InstallationConfig
	Host              string
	Logger            *slog.Logger
}

// TokenProvider creates and refreshes GitHub App installation access tokens.
type TokenProvider struct {
	appClient      *gogithub.Client
	installationID int64
	identity       *Identity
	logger         *slog.Logger

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// Identity describes the GitHub App installation backing this token provider.
type Identity struct {
	AppID                 int64
	AppSlug               string
	AppName               string
	AppURL                string
	BotLogin              string
	InstallationID        int64
	InstallationTarget    string
	InstallationAccount   string
	InstallationAccountID int64
	RepositorySelection   string
}

// NewTokenProvider creates a provider for GitHub App installation tokens. If
// InstallationID is not set, it resolves the id from the configured org, repo,
// or user using an App JWT.
func NewTokenProvider(ctx context.Context, cfg Config) (*TokenProvider, error) {
	if cfg.AppID == 0 {
		return nil, fmt.Errorf("GitHub App ID is required")
	}

	keyBytes, err := loadPrivateKey(ctx, cfg.PrivateKeyPath, cfg.PrivateKeyCommand)
	if err != nil {
		return nil, err
	}

	privateKey, err := parsePrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	apiHost, err := utils.NewAPIHost(cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API host: %w", err)
	}
	restURL, err := apiHost.BaseRESTURL(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get base REST URL: %w", err)
	}
	uploadURL, err := apiHost.UploadURL(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get upload URL: %w", err)
	}

	jwtSource := &jwtSource{
		appID:      cfg.AppID,
		privateKey: privateKey,
		now:        time.Now,
	}
	appClient, err := gogithub.NewClient(
		gogithub.WithHTTPClient(&http.Client{Transport: &transport.BearerAuthTransport{
			Transport:     http.DefaultTransport,
			TokenProvider: jwtSource.Token,
		}}),
		gogithub.WithEnterpriseURLs(restURL.String(), uploadURL.String()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub App client: %w", err)
	}

	app, _, err := appClient.Apps.Get(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get authenticated GitHub App: %w", err)
	}

	installation, err := resolveInstallation(ctx, appClient, cfg.Installation)
	if err != nil {
		return nil, err
	}
	identity := buildIdentity(app, installation)

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &TokenProvider{
		appClient:      appClient,
		installationID: installation.GetID(),
		identity:       identity,
		logger:         logger.With("component", "githubapp"),
	}, nil
}

// AccessToken returns a cached installation access token, refreshing it when it
// is missing or close to expiry. On refresh failure, a still-cached token is
// returned so in-flight sessions can continue until GitHub rejects it.
func (p *TokenProvider) AccessToken() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.token != "" && time.Until(p.expiresAt) > defaultRefreshBefore {
		return p.token
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	token, _, err := p.appClient.Apps.CreateInstallationToken(ctx, p.installationID, nil)
	if err != nil {
		p.logger.Warn("failed to refresh GitHub App installation token", "error", err)
		return p.token
	}
	if token == nil || token.GetToken() == "" {
		p.logger.Warn("GitHub App installation token response did not include a token")
		return p.token
	}

	p.token = token.GetToken()
	if token.ExpiresAt != nil {
		p.expiresAt = token.ExpiresAt.Time
	} else {
		p.expiresAt = time.Now().Add(time.Hour)
	}
	p.logger.Debug("refreshed GitHub App installation token", "installationID", p.installationID, "expiresAt", p.expiresAt)
	return p.token
}

// Identity returns a copy of the configured GitHub App installation identity.
func (p *TokenProvider) Identity() *Identity {
	if p.identity == nil {
		return nil
	}
	identity := *p.identity
	return &identity
}

func resolveInstallation(ctx context.Context, client *gogithub.Client, cfg InstallationConfig) (*gogithub.Installation, error) {
	lookupCount := 0
	if cfg.Org != "" {
		lookupCount++
	}
	if cfg.Repo != "" {
		lookupCount++
	}
	if cfg.User != "" {
		lookupCount++
	}
	if cfg.InstallationID != 0 {
		if lookupCount != 0 {
			return nil, fmt.Errorf("GitHub App installation ID cannot be combined with org, repo, or user lookup")
		}
		ctx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
		defer cancel()
		installation, _, err := client.Apps.GetInstallation(ctx, cfg.InstallationID)
		if err != nil {
			return nil, fmt.Errorf("failed to get GitHub App installation: %w", err)
		}
		if installation == nil || installation.GetID() == 0 {
			return nil, fmt.Errorf("GitHub App installation response did not include an ID")
		}
		return installation, nil
	}
	if lookupCount != 1 {
		return nil, fmt.Errorf("set exactly one GitHub App installation lookup: installation ID, org, repo, or user")
	}

	ctx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
	defer cancel()

	var installation *gogithub.Installation
	var err error
	switch {
	case cfg.Org != "":
		installation, _, err = client.Apps.FindOrganizationInstallation(ctx, cfg.Org)
	case cfg.Repo != "":
		owner, repo, parseErr := splitRepo(cfg.Repo)
		if parseErr != nil {
			return nil, parseErr
		}
		installation, _, err = client.Apps.FindRepositoryInstallation(ctx, owner, repo)
	case cfg.User != "":
		installation, _, err = client.Apps.FindUserInstallation(ctx, cfg.User)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to resolve GitHub App installation ID: %w", err)
	}
	if installation == nil || installation.GetID() == 0 {
		return nil, fmt.Errorf("resolved GitHub App installation did not include an ID")
	}
	return installation, nil
}

func buildIdentity(app *gogithub.App, installation *gogithub.Installation) *Identity {
	identity := &Identity{}
	if app != nil {
		identity.AppID = app.GetID()
		identity.AppSlug = app.GetSlug()
		identity.AppName = app.GetName()
		identity.AppURL = app.GetHTMLURL()
		if identity.AppSlug != "" {
			identity.BotLogin = identity.AppSlug + "[bot]"
		}
	}
	if installation != nil {
		identity.InstallationID = installation.GetID()
		identity.InstallationTarget = installation.GetTargetType()
		identity.RepositorySelection = installation.GetRepositorySelection()
		if identity.AppSlug == "" {
			identity.AppSlug = installation.GetAppSlug()
			if identity.AppSlug != "" {
				identity.BotLogin = identity.AppSlug + "[bot]"
			}
		}
		if identity.AppID == 0 {
			identity.AppID = installation.GetAppID()
		}
		if account := installation.GetAccount(); account != nil {
			identity.InstallationAccount = account.GetLogin()
			identity.InstallationAccountID = account.GetID()
		}
	}
	return identity
}

func splitRepo(repo string) (string, string, error) {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("GitHub App installation repo must be in owner/repo form")
	}
	return parts[0], parts[1], nil
}

func loadPrivateKey(ctx context.Context, path, command string) ([]byte, error) {
	if path != "" && command != "" {
		return nil, fmt.Errorf("GitHub App private key path and command are mutually exclusive")
	}
	if path == "" && command == "" {
		return nil, fmt.Errorf("GitHub App private key path or command is required")
	}
	if path != "" {
		keyBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read GitHub App private key: %w", err)
		}
		return keyBytes, nil
	}

	ctx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
	defer cancel()

	cmd := shellCommand(ctx, command)
	output, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("GitHub App private key command timed out: %w", ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("GitHub App private key command failed: %w", err)
	}
	return []byte(strings.TrimSpace(string(output))), nil
}

func shellCommand(ctx context.Context, command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "cmd", "/C", command)
	}
	return exec.CommandContext(ctx, "sh", "-c", command)
}

func parsePrivateKey(keyBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode GitHub App private key PEM")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GitHub App private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("GitHub App private key must be an RSA private key")
	}
	return rsaKey, nil
}

type jwtSource struct {
	appID      int64
	privateKey *rsa.PrivateKey
	now        func() time.Time
}

func (s *jwtSource) Token() string {
	now := s.now()
	claims := map[string]any{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(s.appID, 10),
	}
	token, err := signJWT(claims, s.privateKey)
	if err != nil {
		return ""
	}
	return token
}

func signJWT(claims map[string]any, privateKey *rsa.PrivateKey) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encoding := base64.RawURLEncoding
	unsigned := encoding.EncodeToString(headerJSON) + "." + encoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}

	return unsigned + "." + encoding.EncodeToString(signature), nil
}
