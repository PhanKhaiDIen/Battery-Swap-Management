package com.ev.batteryswap.security;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    public JwtAuthFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)  throws ServletException, IOException  {
        if (request.getCookies() != null) { // kiểm tra trong request có cookies không
            for (Cookie cookie : request.getCookies()) {
                if ("jwt".equals(cookie.getName())) { // kiểm tra tên cookie có phải là jwt không
                    String token = cookie.getValue(); // lấy value trong cookie
                    if (jwtUtils.validateToken(token)) { // kiểm tra token jwt còn sống không hoặc hợp lệ không
                        String username = jwtUtils.extractUsername(token); // lấy username từ token jwt
                        String role = jwtUtils.extractRole(token); // lấy role người dùng từ token jwt

                        // Tạo đối tượng xác thực (Authentication)
                        UsernamePasswordAuthenticationToken authentication =  new UsernamePasswordAuthenticationToken(
                                username, "", Collections.singleton(() -> role.toUpperCase()
                            )
                        );
                        SecurityContextHolder.getContext().setAuthentication(authentication); // Lưu thông tin xác thực vào SecurityContext (ThreadLocal).
                    }
                }
            }
        }
        filterChain.doFilter(request, response); // Cho phép request đi tiếp nếu hợp lệ
    }



}
