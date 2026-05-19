package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const UserKey contextKey = "user"

type Claims struct {
	Username string `json:"sub"`
	jwt.RegisteredClaims
}

type Service struct {
	secret   []byte
	username string
	password []byte
}

func New(secret, username, plainPassword string) (*Service, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Service{
		secret:   []byte(secret),
		username: username,
		password: hash,
	}, nil
}

func (s *Service) Login(username, password string) (string, time.Time, error) {
	if username != s.username {
		return "", time.Time{}, errors.New("identifiants invalides")
	}
	if err := bcrypt.CompareHashAndPassword(s.password, []byte(password)); err != nil {
		return "", time.Time{}, errors.New("identifiants invalides")
	}
	exp := time.Now().Add(24 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	signed, err := token.SignedString(s.secret)
	return signed, exp, err
}

func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			http.Error(w, `{"error":"non autorisé"}`, http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(h, "Bearer ")
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("algorithme inattendu")
			}
			return s.secret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, `{"error":"token invalide"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), UserKey, claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
