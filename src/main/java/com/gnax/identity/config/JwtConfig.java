package com.gnax.identity.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfig {

    private static final Logger log = LoggerFactory.getLogger(JwtConfig.class);

    @Bean
    RSAKey rsaKey(JwtProperties props) throws Exception {
        RSAPublicKey publicKey;
        RSAPrivateKey privateKey;
        if (hasText(props.privateKey()) && hasText(props.publicKey())) {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(decodePem(props.privateKey())));
            publicKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(decodePem(props.publicKey())));
        } else {
            log.warn("No gnax.jwt.private-key/public-key configured; generating an EPHEMERAL RSA key pair. "
                    + "Tokens will be invalid after restart. Do not use in production.");
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair pair = gen.generateKeyPair();
            publicKey = (RSAPublicKey) pair.getPublic();
            privateKey = (RSAPrivateKey) pair.getPrivate();
        }
        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    }

    @Bean
    JwtEncoder jwtEncoder(RSAKey rsaKey) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(rsaKey)));
    }

    @Bean
    JwtDecoder jwtDecoder(RSAKey rsaKey) throws Exception {
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey())
                .signatureAlgorithm(SignatureAlgorithm.RS256).build();
    }

    private static boolean hasText(String s) {
        return s != null && !s.isBlank();
    }

    private static byte[] decodePem(String pem) {
        return Base64.getMimeDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", ""));
    }
}
