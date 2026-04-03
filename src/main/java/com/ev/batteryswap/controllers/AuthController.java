package com.ev.batteryswap.controllers;
import com.ev.batteryswap.dto.AuthRequestLogin;
import com.ev.batteryswap.dto.AuthRequestRegister;
import com.ev.batteryswap.pojo.User;
import com.ev.batteryswap.security.JwtUtils;
import com.ev.batteryswap.services.AuthServices;
import com.ev.batteryswap.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;


@RestController
@RequestMapping("/api")
public class AuthController {

    @Autowired
    AuthServices authServices;

    @Autowired
    UserService userService;

    @Autowired
    JwtUtils jwtUtils;

    // API đăng nhập
    @PostMapping("/login")
    public ResponseEntity<?> login(@ModelAttribute AuthRequestLogin authRequestLogin, HttpServletResponse response) {

        // kiểm tra username và password có tồn tại trong database
        if (authServices.login(authRequestLogin.getUsername(), authRequestLogin.getPassword())) {

            // nếu True
            String role = userService.findByUsername(authRequestLogin.getUsername()).getRole(); // lấy role người dùng

            String token = jwtUtils.generateToken(authRequestLogin.getUsername(), role); // tạo token

            ResponseCookie cookie = ResponseCookie.from("jwt", token)
                    .httpOnly(true) // ẩn với JS
                    .secure(false) // đặt true nếu dùng HTTPS
                    .path("/") // phạm vi đường dẫn, "/" nghĩa là gửi cho mọi endpoint trên domain.
                    .maxAge(3600)  // thời hạn (giây), Hết hạn → trình duyệt tự xóa cookie.
                    .build(); // tạo đối tượng và đính vào response
            response.addHeader("Set-Cookie", cookie.toString());

            return ResponseEntity.ok("Đăng nhập thành công.");
        } else {
            return ResponseEntity.badRequest().body("Đăng nhập thất bại.");
        }
    }


    @GetMapping("/logout")
    public void logout(
            @CookieValue(name = "jwt", required = false) String token,
            HttpServletResponse response, HttpServletRequest request
    )  throws IOException {
        // 1. Nếu có token thì đưa vào blacklist (in-memory)
        if (token != null && !token.isEmpty() && jwtUtils.validateToken(token)) {
            jwtUtils.logout(token); // hàm này bạn đã viết để blacklist token (in-memory)
        }

        // 2. Xoá cookie trên trình duyệt
        ResponseCookie cookie = ResponseCookie.from("jwt", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
        // 3. Redirect về trang index
        response.sendRedirect("/");

    }


    // API đăng ký
    @PostMapping("/register")
    public ResponseEntity<?> register(@ModelAttribute AuthRequestRegister authRequest) {
        if (!authRequest.getPassword().equals(authRequest.getConfirmPassword())) {
            return ResponseEntity.badRequest().body("Mật khẩu không hợp lệ.");
        }

        if (authServices.existsByUsername(authRequest.getUsername())) {
            return ResponseEntity.badRequest().body("Tên tài khoản đã tồn tại.");
        }
        User user = new User();
        user.setFullName(authRequest.getFullName());
        user.setUsername(authRequest.getUsername());
        user.setPassword(authRequest.getPassword());
        authServices.register(user);

        return ResponseEntity.ok("Đăng ký thành công.");
    }

}
