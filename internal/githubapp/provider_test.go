package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPrivateKey(t *testing.T) {
	t.Parallel()

	keyPEM := testPrivateKeyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "github-app.pem")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	tests := []struct {
		name    string
		path    string
		command string
		wantErr string
	}{
		{
			name: "loads from path",
			path: keyPath,
		},
		{
			name:    "loads from command",
			command: "cat " + shellQuote(keyPath),
		},
		{
			name:    "rejects path and command",
			path:    keyPath,
			command: "cat " + shellQuote(keyPath),
			wantErr: "mutually exclusive",
		},
		{
			name:    "requires path or command",
			wantErr: "path or command is required",
		},
		{
			name:    "command failure",
			command: "exit 2",
			wantErr: "command failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := loadPrivateKey(context.Background(), tc.path, tc.command)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, strings.TrimSpace(string(keyPEM)), strings.TrimSpace(string(got)))
			_, err = parsePrivateKey(got)
			require.NoError(t, err)
		})
	}
}

func testPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
