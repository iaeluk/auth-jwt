package com.iaeluk.auth_jwt.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.iaeluk.auth_jwt.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;

    public String generateAccessToken(User user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);

            long accessTokenExpirationHours = 3;
            return JWT.create()
                    .withIssuer("auth-jwt")
                    .withSubject(user.getEmail())
                    .withClaim("name", user.getName())
                    .withExpiresAt(generateExpirationDate(accessTokenExpirationHours))
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            throw new RuntimeException("Error while generating token");
        }
    }

    public String generateRefreshToken(User user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);

            long refreshTokenExpirationDays = 7;
            return JWT.create()
                    .withIssuer("auth-jwt")
                    .withSubject(user.getEmail())
                    .withExpiresAt(generateExpirationDate(refreshTokenExpirationDays * 24))
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            throw new RuntimeException("Error while generating refresh token");
        }
    }

    public String validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                    .withIssuer("auth-jwt")
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException exception) {
            return null;
        }
    }

    private Instant generateExpirationDate(long hours) {
        return LocalDateTime.now().plusHours(hours).toInstant(ZoneOffset.of("-03:00"));
    }
}
