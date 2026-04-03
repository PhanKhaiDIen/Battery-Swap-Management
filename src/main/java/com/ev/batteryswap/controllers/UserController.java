package com.ev.batteryswap.controllers;
import com.ev.batteryswap.pojo.*;
import com.ev.batteryswap.security.JwtUtils;
import com.ev.batteryswap.services.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;


@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private BatteryService batteryService;

    @Autowired
    private StationService stationService;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RentalPackageService rentalPackageService;

    @Autowired
    private TicketService ticketService;

    @Autowired
    private StationReviewService stationReviewService;

    @Autowired
    private VehicleService vehicleService;

    @Autowired
    private PaymentInfoService paymentInfoService;

    @Autowired
    private ReservationService reservationService;


    String generateTransactionId() {
        long number = ThreadLocalRandom.current().nextLong(100000000000L, 999999999999L);
        return String.valueOf(number);
    }


    @PostMapping("/information")
    public User information(@RequestParam(value = "username") String username) {
        return userService.findByUsername(username);
    }

    @GetMapping("/information/{id}")
    public User getInformationById(@PathVariable("id") int id) {
        return userService.findById(id);
    }



    // API đăng ký gói dịch vụ
    @PostMapping("/register-package")
    public ResponseEntity<?> updateBalanceById(@RequestParam(value = "name_pack") String name_pack,
                                            @RequestParam(value = "days") int days, @CookieValue(value = "jwt") String token) {

        try{
            // trích xuất thông tin token ví dụ username, id
            String username = jwtUtils.extractUsername(token);
            Integer userId = userService.findByUsername(username).getId();
            RentalPackage rentalPackage = rentalPackageService.findRentalPackageByName(name_pack);

            // kiểm tra name và days
            if (rentalPackage.getName() == null) {
                return  ResponseEntity.badRequest().body("Không tồn tại gói");
            }
            if (rentalPackage.getDurationDays() != days){
                return ResponseEntity.badRequest().body("Không tồn tại gói");
            }

            User user = userService.findById(userId);
            BigDecimal balanceUser = user.getWalletBalance();
            BigDecimal packagePrice = rentalPackage.getPrice();

            // kiểm tra tiền có đủ thanh toán không
            if (balanceUser.compareTo(packagePrice) < 0){
                return ResponseEntity.badRequest().body("Không đủ tiền");
            }

            Rental rental = new Rental();
            rental.setUser(user);
            rental.setPackageField(rentalPackage);
            rental.setTotalAmount(packagePrice);
            userService.registerPackage(rental);

            BigDecimal newBalance = balanceUser.subtract(packagePrice);
            userService.updateBalanceById(userId, newBalance);


            // Lưu lịch sử giao dịch
            PaymentInfo paymentInfo = new PaymentInfo();
            paymentInfo.setUser(user);
            paymentInfo.setAmount(packagePrice);
            paymentInfo.setTransactionId(generateTransactionId());
            paymentInfo.setPaymentMethod("Thuê gói");
            paymentInfo.setNote(name_pack);
            paymentInfoService.save(paymentInfo);

            return ResponseEntity.ok().body("Đăng ký gói thành công");
        } catch (Exception e){
            return  ResponseEntity.badRequest().body("Không thể đăng ký gói.");
        }
    }


    // API đổi pin xe điện
    @PostMapping("/change")
    public ResponseEntity<?> doiPin(@RequestParam("station_id") Integer station_id, @RequestParam("pin_id") Integer pin_id,
                        @RequestParam("serial_number") String serial_number, @RequestParam("model_batteries") String model_batteries,
                        @RequestParam(value = "pin_id_user", required = false) Integer pin_id_user, @CookieValue(value = "jwt") String token) {

        Station station = stationService.getStationById(station_id);

        try {
            if (station != null) { // kiểm tra trạm có tồn tại trong database không

                Battery battery = batteryService.getBatteryById(pin_id);
                if  (battery != null && battery.getStation().equals(station) && battery.getModel().equals(model_batteries) && battery.getSerialNumber().equals(serial_number) && battery.getStatus().equals("AVAILABLE")) {


                    String username = jwtUtils.extractUsername(token); // trích xuất username từ token

                    BigDecimal balance_user = userService.findByUsername(username).getWalletBalance(); // lấy giá trị tiền hiện tại của người dùng

                    if (balance_user.compareTo(battery.getAmount()) >= 0) { // kiểm tra số dư có đủ tiền không
                        BigDecimal newBalance = balance_user.subtract(battery.getAmount()); // trừ tiền của người dùng
                        User user = userService.findByUsername(username);
                        batteryService.updateCurrentUser(user, pin_id);
                        batteryService.updateStatusById(pin_id, "RENTED"); // thay đổi trạng thái của Pin
                        userService.updateBalanceById(user.getId(), newBalance); // cập nhật lại số tiền


                        // Lưu lịch sử giao dịch
                        PaymentInfo paymentInfo = new PaymentInfo();
                        paymentInfo.setUser(user);
                        paymentInfo.setAmount(battery.getAmount());
                        paymentInfo.setTransactionId(generateTransactionId());
                        paymentInfo.setPaymentMethod("Đổi pin");
                        paymentInfo.setNote(model_batteries);
                        paymentInfoService.save(paymentInfo);

                        return ResponseEntity.ok("Đổi Pin Thành Công");
                        // return "Đổi Pin Thành Công";
                    } else {
                        return ResponseEntity.badRequest().body("Không Đủ Số Dư");
                        // return "Không Đủ Số Dư";
                    }
                }
            }
            return ResponseEntity.badRequest().body("Đổi Pin Thất Bại");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Đổi Pin Thất Bại");
        }
    }


    // API gửi hỗ trợ
    @PostMapping("/support")
    public ResponseEntity<?> supportUser(@RequestParam("subject") String subject, @RequestParam("message") String message, @CookieValue(value = "jwt") String token){

        try{
            String username = jwtUtils.extractUsername(token);

            User user = userService.findByUsername(username);

            SupportTicket supportTicket = new SupportTicket();

            supportTicket.setUser_id(user);
            supportTicket.setSubject(subject);
            supportTicket.setMessage(message);

            ticketService.save(supportTicket);

            return ResponseEntity.ok().body("Gửi yêu cầu hỗ trợ thành công.");

        } catch (Exception e) {
            return ResponseEntity.ok().body("Gửi yêu cầu hỗ trợ thất bại.");
        }

    }


    // API đánh giá trạm
    @PostMapping("/rating")
    public ResponseEntity<?> reviewStation(@RequestParam("rating") Byte rating, @RequestParam("comment") String comment, @RequestParam("station_id") Integer station_id, @CookieValue(value = "jwt") String token){
        try{
            String username = jwtUtils.extractUsername(token);
            User user = userService.findByUsername(username);
            Station station = stationService.getStationById(station_id);
            StationReview stationReview = new StationReview();

            stationReview.setUser(user);
            stationReview.setStation(station);
            stationReview.setRating(rating);
            stationReview.setComment(comment);

            stationReviewService.save(stationReview);

            return ResponseEntity.ok().body("Đánh giá thành công.");

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Đánh giá thất bại.");
        }
    }


    // API liên kết phương tiện
    @PostMapping("/vehicle")
    public ResponseEntity<?> vehicle(@RequestParam("vin_code")  String vin_code, @RequestParam("model")  String model, @CookieValue(value = "jwt") String token){
        try{
            String username = jwtUtils.extractUsername(token);
            User user = userService.findByUsername(username);

            Vehicle vehicle = new Vehicle();
            vehicle.setUser(user);
            vehicle.setModel(model);
            vehicle.setVinCode(vin_code);
            vehicleService.save(vehicle);

            return ResponseEntity.ok().body("Liên kết phương tiện thành công.");

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Liên kết phương tiện thất bại.");
        }
    }


    @PostMapping("/reserve-battery")
    public ResponseEntity<?> reserveBattery(
            @RequestParam("station_id") Integer stationId,
            @RequestParam("battery_id") Integer batteryId,
            @RequestParam("pickup_time") String pickupTime,
            @CookieValue(value = "jwt", required = false) String token) {

        if (token == null || !jwtUtils.validateToken(token)) {
            return ResponseEntity.status(401).body("Vui lòng đăng nhập để đặt lịch.");
        }

        try {
            String username = jwtUtils.extractUsername(token);
            User user = userService.findByUsername(username);

            reservationService.createReservation(user.getId(), stationId, batteryId, pickupTime);

            return ResponseEntity.ok("Đặt lịch thành công! Vui lòng đến trạm đúng giờ.");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Lỗi: " + e.getMessage());
        }
    }

}
