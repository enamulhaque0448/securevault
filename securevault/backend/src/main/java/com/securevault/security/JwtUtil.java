package com.securevault.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {

    private static final long PRE_AUTH_EXPIRATION_MS = 5 * 60 * 1000;
    private static final String CLAIM_TYPE = "type";
    private static final String TYPE_PRE_AUTH = "2fa_pending";

    private final SecretKey signingKey;
    private final long expirationMs;

    public JwtUtil(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expiration-ms}") long expirationMs
    ) {
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes());
        this.expirationMs = expirationMs;
    }

    public String generateToken(String email) {
        return buildToken(email, expirationMs, null);
    }

    public String generatePreAuthToken(String email) {
        return buildToken(email, PRE_AUTH_EXPIRATION_MS, TYPE_PRE_AUTH);
    }

    private String buildToken(String email, long ttlMs, String typeClaim) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + ttlMs);

        var builder = Jwts.builder()
                .subject(email)
                .issuedAt(now)
                .expiration(expiry);

        if (typeClaim != null) {
            builder.claim(CLAIM_TYPE, typeClaim);
        }

        return builder.signWith(signingKey, SignatureAlgorithm.HS256).compact();
    }

    public String extractEmail(String token) {
        return parseClaims(token).getSubject();
    }

    public boolean isValid(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isPreAuthToken(String token) {
        try {
            return TYPE_PRE_AUTH.equals(parseClaims(token).get(CLAIM_TYPE));
        } catch (Exception e) {
            return false;
        }
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
