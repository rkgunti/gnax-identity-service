package com.gnax.identity.service;

import com.gnax.identity.config.JwtProperties;
import com.gnax.identity.dto.LoginRequest;
import com.gnax.identity.dto.TokenResponse;
import com.gnax.identity.entity.RefreshToken;
import com.gnax.identity.entity.User;
import com.gnax.identity.exception.AuthException;
import com.gnax.identity.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokens;
    private final JwtProperties props;

    @Transactional
    public TokenResponse login(LoginRequest req) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.username(), req.password()));
        } catch (AuthenticationException e) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
        return issueTokens(userService.getByUsername(req.username()));
    }

    /** Rotates the refresh token: the presented one is revoked and a new pair is issued. */
    @Transactional
    public TokenResponse refresh(String rawToken) {
        RefreshToken stored = refreshTokens.findByTokenHash(hash(rawToken))
                .orElseThrow(() -> new AuthException(HttpStatus.UNAUTHORIZED, "Invalid refresh token"));
        if (stored.isRevoked() || stored.getExpiresAt().isBefore(Instant.now())
                || !stored.getUser().isEnabled()) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
        }
        stored.setRevoked(true);
        return issueTokens(stored.getUser());
    }

    @Transactional
    public void logout(String rawToken) {
        refreshTokens.findByTokenHash(hash(rawToken)).ifPresent(t -> t.setRevoked(true));
    }

    private TokenResponse issueTokens(User user) {
        byte[] bytes = new byte[48];
        RANDOM.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        RefreshToken rt = new RefreshToken();
        rt.setUser(user);
        rt.setTokenHash(hash(raw));
        rt.setExpiresAt(Instant.now().plus(props.refreshTokenTtl()));
        refreshTokens.save(rt);

        return new TokenResponse(jwtService.generateAccessToken(user), raw, "Bearer",
                jwtService.accessTokenTtlSeconds());
    }

    private static String hash(String raw) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
