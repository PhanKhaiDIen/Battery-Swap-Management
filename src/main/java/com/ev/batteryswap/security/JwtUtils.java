package com.ev.batteryswap.security;
import com.ev.batteryswap.services.AuthServices;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;


@Component
public class JwtUtils {

    // khóa bí mật
    private static final String SECRET_KEY = "u$ax5^-#y0=mmd6p7^@4$$o=6klasg#q(@b1-5meaz-iy7pk^$";

    // thời gian sống của token JWT
    private static final long EXPIRATION_TIME = 1000 * 60 * 30;  // 30 phút


    @Autowired
    AuthServices  authServices;

    private SecretKey getSigningKey() {
        // Dùng StandardCharsets.UTF_8 để đảm bảo mã hóa ổn định
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    // Sinh token cho username và role_name
    public String generateToken(String username, String role_name) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + EXPIRATION_TIME);

        return Jwts.builder()
                .subject(username)
                .claim("role", role_name)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Trích xuất username từ token
    public String extractUsername(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.getSubject();
    }

    // Trích xuất role từ token
    public String extractRole(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.get("role", String.class);
    }

    // Kiểm tra token hợp lệ hay không
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);

            // ❗ kiểm tra token đã nằm trong mảng blacklist chưa
            if (authServices.isBlacklisted(token)) {
                return false;
            }

            return true;
        } catch (Exception e) {
            // Có thể log lỗi chi tiết ở đây nếu muốn
            return false;
        }
    }


    // "Hủy" token = đưa vào blacklist
    public boolean logout(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            Date expiration = claims.getExpiration();
            long now = System.currentTimeMillis();
            long ttlMillis = expiration.getTime() - now;

            if (ttlMillis <= 0) {
                // token hết hạn rồi thì coi như xong, không cần blacklist
                return true;
            }

            authServices.blacklist(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }




}
