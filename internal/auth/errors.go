package auth

import (
	"errors"
	"fmt"
)

var (
	ErrUserNotFound     = errors.New("user not found")
	ErrUserDisabled     = errors.New("user account is disabled")
	ErrInvalidPassword  = errors.New("invalid password")
	ErrUsernameExists   = errors.New("username already exists")
	ErrSessionNotFound  = errors.New("session not found")
	ErrSessionExpired   = errors.New("session expired")
	ErrInvalidToken     = errors.New("invalid token")
	ErrMFARequired      = errors.New("MFA verification required")
)

func errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
