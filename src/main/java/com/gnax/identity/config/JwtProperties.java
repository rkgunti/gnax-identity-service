package com.gnax.identity.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * privateKey / publicKey are a file path (or file:/classpath: URL) or inline PEM contents (PKCS#8 / X.509). If both are blank an
 * ephemeral key pair is generated at startup (local development only).
 */
@ConfigurationProperties(prefix = "gnax.jwt")
public record JwtProperties(
        String issuer,
        String privateKey,
        String publicKey,
        Duration accessTokenTtl,
        Duration refreshTokenTtl) {

    public JwtProperties {
        if (issuer == null) issuer = "gnax-identity-service";
        if (accessTokenTtl == null) accessTokenTtl = Duration.ofMinutes(15);
        if (refreshTokenTtl == null) refreshTokenTtl = Duration.ofDays(7);
    }
}
