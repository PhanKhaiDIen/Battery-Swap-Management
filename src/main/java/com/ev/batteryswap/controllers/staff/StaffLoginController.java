package com.ev.batteryswap.controllers.staff;


import com.ev.batteryswap.pojo.User;
import com.ev.batteryswap.security.JwtUtils;
import com.ev.batteryswap.services.AuthServices;
import com.ev.batteryswap.services.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;


@Controller
@RequestMapping("/staff/login")
public class StaffLoginController {

    @Autowired
    AuthServices authServices;

    @Autowired
    UserService userService;

    @Autowired
    JwtUtils jwtUtils;


    @GetMapping
    public String staffLogin() {
        return "staff/login";
    }


    @PostMapping
    @ResponseBody
    public ResponseEntity<?> staffLogin(@RequestParam("username") String username, @RequestParam("password") String password, HttpServletResponse response) {
        // kiểm tra username và password có tồn tại trong database
        if (authServices.login(username, password)) {
            // nếu True
            //String role = userService.findByUsername(username).getRole(); // lấy role người dùng

            User user = userService.findByUsername(username);
            String role = user.getRole();

            if (role.equals("STAFF")) {

                // staff phải được gán trạm
                if (user.getStation() == null) {
                    return ResponseEntity.badRequest().body("Tài khoản Staff chưa được gán trạm. Vui lòng liên hệ Admin.");
                }

                String token = jwtUtils.generateToken(username, role); // tạo token

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

        } else {
            return ResponseEntity.badRequest().body("Đăng nhập thất bại.");
        }
    }


}
