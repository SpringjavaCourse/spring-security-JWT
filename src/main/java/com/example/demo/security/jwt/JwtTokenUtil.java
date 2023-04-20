package com.example.demo.security.jwt;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * Métodos para generar y validar los token JWT
 */
@Component
public class JwtTokenUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenUtil.class);

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration-ms}")
    private int jwtExpirationMs;

    /**
     * Genera un token JWT para el usuario
     * @param authentication
     * @return
     */
    public String generateJwtToken(Authentication authentication) {

        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername())) //nombre de usuario
                .setIssuedAt(new Date()) //fecha de creación
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs)) //fecha de expiración
                .signWith(SignatureAlgorithm.HS512, jwtSecret) //firma
                .compact(); //genera el token
    }

    /**
     * Obtiene el nombre de usuario desde el token JWT
     * @param token
     * @return
     */
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    /**
     * Valida el token JWT
     * @param authToken
     * @return
     */
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) { //error en la firma
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) { //token mal formado
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) { //token expirado
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) { //token no soportado por el sistema
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) { //token vacío
            log.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}

