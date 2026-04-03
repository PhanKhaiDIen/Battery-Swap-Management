package com.ev.batteryswap.controllers.staff;

import com.ev.batteryswap.pojo.Battery;
import com.ev.batteryswap.pojo.Reservation;
import com.ev.batteryswap.pojo.User;
import com.ev.batteryswap.services.ReservationService;
import com.ev.batteryswap.services.interfaces.IBatteryService;
import com.ev.batteryswap.services.interfaces.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
@RequestMapping("/staff/reservations")
public class StaffReservationController {

    @Autowired private ReservationService reservationService;
    @Autowired private IUserService userService;
    @Autowired private IBatteryService batteryService;

    private User getCurrentStaffUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return userService.findByUsername(username);
    }

    @GetMapping
    public String listReservations(Model model,
                                   @RequestParam(defaultValue = "0") int page) {
        User staff = getCurrentStaffUser();
        if (staff.getStation() == null) return "redirect:/staff/login";

        Page<Reservation> reservationPage = reservationService.getReservationsByStation(
                staff.getStation().getId(),
                "PENDING",
                PageRequest.of(page, 10, Sort.by("reservationTime").ascending())
        );

        model.addAttribute("reservationPage", reservationPage);
        model.addAttribute("station", staff.getStation());

        List<Battery> rentedBatteries = batteryService.filterBatteries(null, "RENTED", null, PageRequest.of(0, 1000)).getContent();
        model.addAttribute("rentedBatteries", rentedBatteries);

        return "staff/reservations";
    }

    @PostMapping("/complete")
    public String completeReservation(@RequestParam("reservationId") Integer reservationId,
                                      @RequestParam("batteryInId") Integer batteryInId,
                                      @RequestParam("paymentMethod") String paymentMethod,
                                      RedirectAttributes redirectAttributes) {
        try {
            reservationService.fulfillReservation(reservationId, batteryInId, paymentMethod);
            redirectAttributes.addFlashAttribute("successMessage", "Đã hoàn tất đặt lịch và tạo giao dịch thành công!");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Lỗi: " + e.getMessage());
        }
        return "redirect:/staff/reservations";
    }

    @PostMapping("/cancel")
    public String cancelReservation(@RequestParam("reservationId") Integer reservationId,
                                    RedirectAttributes redirectAttributes) {
        try {
            reservationService.cancelReservation(reservationId);
            redirectAttributes.addFlashAttribute("successMessage", "Đã hủy đơn đặt lịch. Pin đã trở lại kho.");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Lỗi: " + e.getMessage());
        }
        return "redirect:/staff/reservations";
    }
}