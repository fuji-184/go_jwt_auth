package go_jwt_auth

import (
    "time"
    "github.com/dgrijalva/jwt-go"
)

var (
    jwtSecretKey = []byte("your_secret_key_here")
)

type Claims struct {
    UserID   int    `json:"user_id"`
    Username string `json:"username"`
    jwt.StandardClaims
}

func GenerateTokens(userID int, username string) (accessToken, refreshToken string, err error) {
    accessClaims := &Claims{
        UserID:   userID,
        Username: username,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
        },
    }

    refreshClaims := &Claims{
        UserID:   userID,
        Username: username,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(),
        },
    }

    accessToken, err = generateToken(accessClaims)
    if err != nil {
        return "", "", err
    }

    refreshToken, err = generateToken(refreshClaims)
    if err != nil {
        return "", "", err
    }

    return accessToken, refreshToken, nil
}

func generateToken(claims *Claims) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtSecretKey)
}

func VerifyToken(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return jwtSecretKey, nil
    })

    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    } else {
        return nil, err
    }
}
