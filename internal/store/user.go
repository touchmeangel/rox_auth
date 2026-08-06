package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/touchmeangel/rox_sdk_go/models/user"
)

type UserStore struct {
	pool *pgxpool.Pool
}

func NewUserStore(pool *pgxpool.Pool) *UserStore {
	return &UserStore{pool: pool}
}

type userRow struct {
	ID       string   `db:"id"`
	Email    string   `db:"email"`
	Username string   `db:"username"`
	Roles    []string `db:"roles"`
}

func (r userRow) toSDK() user.User {
	roles := make([]user.Role, len(r.Roles))
	for i, ro := range r.Roles {
		roles[i] = user.Role(ro)
	}
	return user.User{
		ID:       r.ID,
		Email:    r.Email,
		Username: r.Username,
		Roles:    roles,
	}
}

func (s *UserStore) GetUserProfile(ctx context.Context, userID string) (user.User, error) {
	const query = `SELECT id, email, username, roles FROM users WHERE id = $1`

	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return user.User{}, fmt.Errorf("querying user profile %s: %w", userID, err)
	}

	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[userRow])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return user.User{}, user.ErrNotFound
		}
		return user.User{}, fmt.Errorf("scanning user profile %s: %w", userID, err)
	}

	return row.toSDK(), nil
}
