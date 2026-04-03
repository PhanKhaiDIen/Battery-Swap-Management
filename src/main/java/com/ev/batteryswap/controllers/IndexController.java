package com.ev.batteryswap.controllers;
import com.ev.batteryswap.pojo.*;
import com.ev.batteryswap.security.JwtUtils;
import com.ev.batteryswap.services.PaymentInfoService;
import com.ev.batteryswap.services.RentalPackageService;
import com.ev.batteryswap.services.UserService;
import com.ev.batteryswap.services.interfaces.IBatteryService;
import com.ev.batteryswap.services.interfaces.IStationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import jakarta.servlet.http.Cookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Controller
public class IndexController {

    @Autowired
    private UserService userService;

    @Autowired
    private IStationService stationService;

    @Autowired
    private IBatteryService batteryService;

    @Autowired
    private JwtUtils  jwtUtils;

    @Autowired
    private RentalPackageService  rentalPackageService;

    @Autowired
    private PaymentInfoService paymentInfoService;


    @GetMapping("/")
    public String index(@CookieValue(value = "jwt", required = false) String token) {

        if (token == null || !jwtUtils.validateToken(token)) {
            return "index";
        } else {
            return "redirect:/my";
        }
    }

    public void update_info(Model model, String token) {

        String username = jwtUtils.extractUsername(token); // lấy username từ token jwt

        User user = userService.findByUsername(username); // lấy toàn bộ thông tin người dùng

        Rental rental = userService.findRentalByUser(user);  // lấy gói dịch vụ mà người dùng đăng ký

        Battery battery = batteryService.getBatteryByCurrentUser(user);

        String pack_name;
        String model_battery;

        if (rental != null) {
            RentalPackage rentalPackage = rentalPackageService.findById(rental.getPackageField().getId()); // tìm gói
            pack_name = rentalPackage.getName();
        } else {
            pack_name = "Không có gói";
        }

        if (battery != null) {
            model_battery = battery.getModel();
        } else {
            model_battery = "Không có PIN";
        }

        BigDecimal money = userService.findByUsername(username).getWalletBalance();

        // Định dạng tiền tệ theo locale Việt Nam
        String formattedMoney = String.format("%,.0f VND", money);
        model.addAttribute("money_amount", formattedMoney);

        model.addAttribute("info_user", user);
        model.addAttribute("pack_name", pack_name);
        model.addAttribute("model_battery", model_battery);

    }

    @GetMapping("/login")
    public String login(@CookieValue(value = "jwt", required = false) String token) {
        if (token == null || !jwtUtils.validateToken(token)) {
            return "login";
        } else {
            return "redirect:/my";
        }
    }

    @GetMapping("/register")
    public String register(@CookieValue(value = "jwt", required = false) String token) {
        if (token == null || !jwtUtils.validateToken(token)) {
            return "register";
        } else {
            return "redirect:/my";
        }
    }

    @GetMapping("/my")
    public String my(@CookieValue(value = "jwt", required = false) String token, Model model) {
        if (token == null || !jwtUtils.validateToken(token)) {
            return "login";
        } else {
            update_info(model, token);
            return "user/my";
        }
    }


    @GetMapping("/profile")
    public String profile(@CookieValue(value = "jwt", required = false) String token, Model model) {


        if (token == null || !jwtUtils.validateToken(token)) {
            return "login";
        } else {
            update_info(model, token);
            return "user/profile";
        }
    }

    @GetMapping("/vehicle")
    public String vehicle(@CookieValue(value = "jwt", required = false) String token, Model model) {
        if (token == null || !jwtUtils.validateToken(token)) {
            return "login";
        } else {
            update_info(model, token);
            return "user/vehicle";
        }
    }

    @GetMapping("/contact")
    public String contact(@CookieValue(value = "jwt", required = false) String token, Model model) {

        if (token == null || !jwtUtils.validateToken(token)) {
            return "login";
        } else {
            update_info(model, token);
            return "user/contact";
        }

    }

    @GetMapping("/packages")
    public String packages(@CookieValue(value = "jwt", required = false) String token, Model model) {
        if (token == null || !jwtUtils.validateToken(token)) {
            return "packages";
        } else {
            update_info(model, token);
            return "redirect:/pricing";
        }
    }

    @GetMapping("/datlich")
    public String datlich(@CookieValue(value = "jwt", required = false) String token, Model model) {
        if (token == null || !jwtUtils.validateToken(token)) {
            return "login";
        } else {
            update_info(model, token);
            return "user/datlich";
        }
    }

    @GetMapping("/pricing")
    public String packages_user(@CookieValue(value = "jwt", required = false) String token, Model model) {

        if (token == null || !jwtUtils.validateToken(token)) {
            return "login";
        } else {
            update_info(model, token);

            RentalPackage pack_30 = rentalPackageService.findRentalPackageByName("Gói Cơ Bản 30 ngày");
            RentalPackage pack_90 = rentalPackageService.findRentalPackageByName("Gói Nâng Cao 90 ngày");
            RentalPackage pack_180 = rentalPackageService.findRentalPackageByName("Gói Cao Cấp 180 ngày");
            Rental rental = userService.findRentalByUser(userService.findByUsername(jwtUtils.extractUsername(token)));

            model.addAttribute("rental", rental);

            model.addAttribute("price_amount_30", pack_30.getPrice());
            model.addAttribute("price_amount_90", pack_90.getPrice());
            model.addAttribute("price_amount_180", pack_180.getPrice());

            model.addAttribute("content_pack_30", pack_30.getName());
            model.addAttribute("content_pack_90", pack_90.getName());
            model.addAttribute("content_pack_180", pack_180.getName());

            model.addAttribute("days_30", pack_30.getDurationDays());
            model.addAttribute("days_90", pack_90.getDurationDays());
            model.addAttribute("days_180", pack_180.getDurationDays());

//            model.addAttribute("description_30", pack_30.getDescription());
//            model.addAttribute("description_90", pack_90.getDescription());
//            model.addAttribute("description_180", pack_180.getDescription());

            return "user/packages";
        }

    }


    // tạo mã QR ACB
    @PostMapping("/qr")
    @ResponseBody
    public ResponseEntity<?> handleForm(@RequestParam BigDecimal amount, @CookieValue(value = "jwt", required = false) String token) {

        String stk = "160313102005"; // số tài khoản ngân hàng
        String name_nganhang = "MB Bank"; // tên ngân hàngs

        String username = jwtUtils.extractUsername(token); // lấy username từ token jwt
        String url = "https://img.vietqr.io/image/MB-160313102005-qr_only.png"+name_nganhang+"-"+stk+"-compact1.jpg?addInfo="+username+"&amount="+amount;
        return ResponseEntity.ok(url);
    }


    @GetMapping("/naptien")
    public String naptien(@CookieValue(value = "jwt", required = false) String token, Model model) {

        if (token == null || !jwtUtils.validateToken(token)) {
            return "login";
        } else {
            update_info(model, token);
            return "user/naptien";
        }
    }

    @GetMapping("/station")
    public String station(@RequestParam() int id, Model model, @CookieValue(value = "jwt", required = false) String token) {
        update_info(model, token);
        Station station = stationService.getStationById(id);
        Map<String, Long> batteryStatsByStation = batteryService.getBatteryStatisticsForStation(station);

        Page<Battery> batteryPage = batteryService.filterBatteries(id, null, null, PageRequest.of(0, 10));

        // System.out.println(batteryPage);

        model.addAttribute("stationName", station.getName());
        model.addAttribute("stationAddress", station.getAddress());
        model.addAttribute("stationId", station.getId());
        model.addAttribute("batteryStatsByStation", batteryStatsByStation);
        model.addAttribute("batteryPage", batteryPage);

        return "user/station";
    }


    @GetMapping("/dashboard")
    public String listStations(Model model, @RequestParam(defaultValue = "1") int page, @CookieValue(value = "jwt", required = false) String token) {

        update_info(model, token);
        Page<Station> stationPage = stationService.filterStations(null, PageRequest.of(page-1, 6));
//        model.addAttribute("stations", stationPage.getContent());

        // List<Station> stations =  batteryService.getAllStations();

        // Map<StationId, Map<key,value>> để lưu thống kê pin từng trạm
        Map<Integer, Map<String, Long>> batteryStatsByStation = new HashMap<>();

        for (Station station : stationPage) {
            Map<String, Long> stats = batteryService.getBatteryStatisticsForStation(station);
            batteryStatsByStation.put(station.getId(), stats);
        }

        model.addAttribute("stations", stationPage);
        model.addAttribute("batteryStatsByStation", batteryStatsByStation);
        model.addAttribute("totalPages", stationPage.getTotalPages());
        model.addAttribute("currentPage", page);

        return "user/dashboard";
    }


    @GetMapping("/lichsu")
    public String lichsu(@CookieValue(value = "jwt", required = false) String token, Model model, @RequestParam(defaultValue = "1") int page) {

        if (token == null || !jwtUtils.validateToken(token)) {
            return "login";
        } else {
            update_info(model, token);

            User user = userService.findByUsername(jwtUtils.extractUsername(token)); // lấy toàn bộ thông tin người dùng


            Page<PaymentInfo> paymentInfos = paymentInfoService.filterPaymentInfo(user.getId(), PageRequest.of(page-1, 15));

            model.addAttribute("payinfos", paymentInfos);

            return "user/lichsu";
        }
    }

}
