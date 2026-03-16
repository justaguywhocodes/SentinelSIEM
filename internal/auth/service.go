package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// Backend is the interface for persisting auth data to storage.
type Backend interface {
	IndexDoc(ctx context.Context, index, id string, doc []byte) error
	GetDoc(ctx context.Context, index, id string) ([]byte, error)
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]json.RawMessage, error)
	UpdateDoc(ctx context.Context, index, id string, doc []byte) error
	DeleteDoc(ctx context.Context, index, id string) error
	CountDocs(ctx context.Context, index string, query map[string]any) (int64, error)
}

// Service handles authentication and user management.
type Service struct {
	backend      Backend
	jwt          *JWTManager
	userIndex    string
	sessionIndex string
}

// NewService creates a new auth Service.
func NewService(backend Backend, jwtManager *JWTManager, userIndex, sessionIndex string) *Service {
	return &Service{
		backend:      backend,
		jwt:          jwtManager,
		userIndex:    userIndex,
		sessionIndex: sessionIndex,
	}
}

// CreateUser creates a new user account with a bcrypt-hashed password.
func (s *Service) CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	// Check if username already exists.
	existing, _ := s.GetUserByUsername(ctx, req.Username)
	if existing != nil {
		return nil, ErrUsernameExists
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generating user ID: %w", err)
	}

	now := time.Now().UTC()
	user := &User{
		ID:           hex.EncodeToString(idBytes),
		Username:     req.Username,
		DisplayName:  req.DisplayName,
		Email:        req.Email,
		PasswordHash: string(hash),
		Role:         req.Role,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	doc, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("marshaling user: %w", err)
	}

	if err := s.backend.IndexDoc(ctx, s.userIndex, user.ID, doc); err != nil {
		return nil, fmt.Errorf("storing user: %w", err)
	}

	return user, nil
}

// GetUser returns a user by ID.
func (s *Service) GetUser(ctx context.Context, id string) (*User, error) {
	doc, err := s.backend.GetDoc(ctx, s.userIndex, id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	var user User
	if err := json.Unmarshal(doc, &user); err != nil {
		return nil, fmt.Errorf("unmarshaling user: %w", err)
	}
	return &user, nil
}

// GetUserByUsername looks up a user by username.
func (s *Service) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	query := map[string]any{
		"query": map[string]any{
			"term": map[string]any{
				"username": username,
			},
		},
		"size": 1,
	}

	docs, err := s.backend.SearchDocs(ctx, s.userIndex, query)
	if err != nil {
		return nil, fmt.Errorf("searching user by username: %w", err)
	}
	if len(docs) == 0 {
		return nil, ErrUserNotFound
	}

	var user User
	if err := json.Unmarshal(docs[0], &user); err != nil {
		return nil, fmt.Errorf("unmarshaling user: %w", err)
	}
	return &user, nil
}

// Login authenticates a user with username and password.
// Returns tokens if successful, or indicates MFA is required.
func (s *Service) Login(ctx context.Context, req *LoginRequest, userAgent, ip string) (*LoginResponse, error) {
	user, err := s.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, ErrInvalidPassword // don't reveal whether user exists
	}

	if user.Disabled {
		return nil, ErrUserDisabled
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, ErrInvalidPassword
	}

	// If MFA is enabled, return a short-lived MFA token instead of full tokens.
	if user.MFAEnabled {
		mfaToken, err := s.jwt.GenerateAccessToken(&User{
			ID:       user.ID,
			Username: user.Username,
			Role:     user.Role,
		})
		if err != nil {
			return nil, fmt.Errorf("generating MFA token: %w", err)
		}
		return &LoginResponse{
			MFARequired: true,
			MFAToken:    mfaToken,
		}, nil
	}

	return s.issueTokens(ctx, user, userAgent, ip)
}

// issueTokens generates access and refresh tokens and creates a session.
func (s *Service) issueTokens(ctx context.Context, user *User, userAgent, ip string) (*LoginResponse, error) {
	accessToken, err := s.jwt.GenerateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	// Create session for refresh token.
	session, err := s.createSession(ctx, user.ID, refreshToken, userAgent, ip)
	if err != nil {
		return nil, err
	}
	_ = session

	// Update last login time.
	now := time.Now().UTC()
	user.LastLoginAt = &now
	doc, _ := json.Marshal(user)
	_ = s.backend.UpdateDoc(ctx, s.userIndex, user.ID, doc)

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(AccessTokenExpiry.Seconds()),
		User:         user.ToResponse(),
	}, nil
}

// createSession stores a refresh token session in ES.
func (s *Service) createSession(ctx context.Context, userID, refreshToken, userAgent, ip string) (*Session, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generating session ID: %w", err)
	}

	now := time.Now().UTC()
	session := &Session{
		ID:        hex.EncodeToString(idBytes),
		UserID:    userID,
		TokenHash: hashToken(refreshToken),
		CreatedAt: now,
		ExpiresAt: now.Add(RefreshTokenExpiry),
		UserAgent: userAgent,
		IP:        ip,
	}

	doc, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("marshaling session: %w", err)
	}

	if err := s.backend.IndexDoc(ctx, s.sessionIndex, session.ID, doc); err != nil {
		return nil, fmt.Errorf("storing session: %w", err)
	}

	return session, nil
}

// RefreshAccessToken validates a refresh token and issues a new access token.
func (s *Service) RefreshAccessToken(ctx context.Context, refreshToken string) (*LoginResponse, error) {
	session, err := s.findSession(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	if !session.IsValid() {
		return nil, ErrSessionExpired
	}

	user, err := s.GetUser(ctx, session.UserID)
	if err != nil {
		return nil, err
	}

	if user.Disabled {
		return nil, ErrUserDisabled
	}

	accessToken, err := s.jwt.GenerateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(AccessTokenExpiry.Seconds()),
		User:         user.ToResponse(),
	}, nil
}

// Logout revokes the session associated with a refresh token.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	session, err := s.findSession(ctx, refreshToken)
	if err != nil {
		return err
	}

	session.Revoked = true
	revokedAt := time.Now().UTC()
	session.RevokedAt = &revokedAt

	doc, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshaling revoked session: %w", err)
	}

	return s.backend.UpdateDoc(ctx, s.sessionIndex, session.ID, doc)
}

// findSession looks up a session by refresh token hash.
func (s *Service) findSession(ctx context.Context, refreshToken string) (*Session, error) {
	hash := hashToken(refreshToken)
	query := map[string]any{
		"query": map[string]any{
			"term": map[string]any{
				"token_hash": hash,
			},
		},
		"size": 1,
	}

	docs, err := s.backend.SearchDocs(ctx, s.sessionIndex, query)
	if err != nil {
		return nil, fmt.Errorf("searching session: %w", err)
	}
	if len(docs) == 0 {
		return nil, ErrSessionNotFound
	}

	var session Session
	if err := json.Unmarshal(docs[0], &session); err != nil {
		return nil, fmt.Errorf("unmarshaling session: %w", err)
	}
	return &session, nil
}

// ChangePassword updates a user's password after verifying the current one.
func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
		return ErrInvalidPassword
	}

	if len(newPassword) < 8 {
		return errorf("new password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return fmt.Errorf("hashing new password: %w", err)
	}

	user.PasswordHash = string(hash)
	user.UpdatedAt = time.Now().UTC()

	doc, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshaling user: %w", err)
	}

	return s.backend.UpdateDoc(ctx, s.userIndex, user.ID, doc)
}

// ListUsers returns all users (safe representation).
func (s *Service) ListUsers(ctx context.Context) ([]*UserResponse, error) {
	query := map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
		"size":  1000,
	}

	docs, err := s.backend.SearchDocs(ctx, s.userIndex, query)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}

	users := make([]*UserResponse, 0, len(docs))
	for _, doc := range docs {
		var user User
		if err := json.Unmarshal(doc, &user); err != nil {
			continue
		}
		users = append(users, user.ToResponse())
	}
	return users, nil
}

// UserCount returns the total number of users.
func (s *Service) UserCount(ctx context.Context) (int64, error) {
	query := map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
	}
	return s.backend.CountDocs(ctx, s.userIndex, query)
}

// UpdateProfile updates a user's display name and email.
func (s *Service) UpdateProfile(ctx context.Context, userID, displayName, email string) (*UserResponse, error) {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	if displayName != "" {
		user.DisplayName = displayName
	}
	if email != "" {
		user.Email = email
	}
	user.UpdatedAt = time.Now().UTC()

	doc, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("marshaling user: %w", err)
	}

	if err := s.backend.UpdateDoc(ctx, s.userIndex, user.ID, doc); err != nil {
		return nil, fmt.Errorf("updating user: %w", err)
	}

	return user.ToResponse(), nil
}

// hashToken returns the SHA-256 hex digest of a token string.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
