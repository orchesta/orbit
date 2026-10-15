package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecretSealer encrypts secrets before they are stored and decrypts them on read.
type SecretSealer interface {
	Seal(plaintext string) (string, error)
	Open(stored string) (string, error)
	IsSealed(stored string) bool
}

// secretColumns lists every column that holds an access token.
var secretColumns = []struct{ table, column string }{
	{"access_tokens", "token"},
	{"repositories", "auth_token"},
}

// SealPlaintextSecrets encrypts token columns still holding plaintext from
// before encryption at rest was enabled. It runs in one transaction, is
// idempotent, and returns how many values it sealed. Values that are already
// sealed must open with the current key; if any does not, it seals nothing
// and returns an error, so a wrong or rotated key fails at startup.
func SealPlaintextSecrets(ctx context.Context, pool *pgxpool.Pool, secrets SecretSealer) (int, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	sealed := 0
	for _, c := range secretColumns {
		type row struct {
			id    uuid.UUID
			value string
		}
		rows, err := tx.Query(ctx, fmt.Sprintf("SELECT id, %s FROM %s WHERE %s <> ''", c.column, c.table, c.column))
		if err != nil {
			return 0, fmt.Errorf("read %s.%s: %w", c.table, c.column, err)
		}
		var plain []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.value); err != nil {
				rows.Close()
				return 0, err
			}
			if !secrets.IsSealed(r.value) {
				plain = append(plain, r)
				continue
			}
			if _, err := secrets.Open(r.value); err != nil {
				rows.Close()
				return 0, fmt.Errorf("stored value in %s.%s (row %s) does not match ORBIT_CRYPTO_ENCRYPTION_KEY; restore the original key, or remove the token and add it again: %w", c.table, c.column, r.id, err)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, err
		}

		for _, r := range plain {
			value, err := secrets.Seal(r.value)
			if err != nil {
				return 0, err
			}
			if _, err := tx.Exec(ctx, fmt.Sprintf("UPDATE %s SET %s = $1 WHERE id = $2", c.table, c.column), value, r.id); err != nil {
				return 0, fmt.Errorf("seal %s.%s: %w", c.table, c.column, err)
			}
			sealed++
		}
	}
	return sealed, tx.Commit(ctx)
}

// MaskToken hides all but the last four characters of a token.
func MaskToken(token string) string {
	if len(token) <= 8 {
		return "****"
	}
	return "****" + token[len(token)-4:]
}
