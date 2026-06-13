package store

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

type NotFoundError struct{ Resource string }

func (e *NotFoundError) Error() string { return fmt.Sprintf("%s not found", e.Resource) }

type AlreadyExistsError struct{ Resource string }

func (e *AlreadyExistsError) Error() string { return fmt.Sprintf("%s already exists", e.Resource) }

func NotFound(resource string) error { return &NotFoundError{Resource: resource} }

func AlreadyExists(resource string) error { return &AlreadyExistsError{Resource: resource} }

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
