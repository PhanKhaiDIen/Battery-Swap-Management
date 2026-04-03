package com.ev.batteryswap.controllers.admin;

import com.ev.batteryswap.services.interfaces.IBatteryService;
import com.ev.batteryswap.services.interfaces.IStationService;
import com.ev.batteryswap.services.interfaces.ITransactionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/admin")
public class AdminDashboardController {

    @Autowired private IBatteryService batteryService;
    @Autowired private IStationService stationService;
    @Autowired private ITransactionService transactionService;

    @GetMapping("/dashboard")
    public String showDashboard(Model model) {
        // 1. Lấy các chỉ số thống kê cơ bản
        model.addAttribute("batteryStats", batteryService.getBatteryStatistics());
        model.addAttribute("stationStats", stationService.getStationStatistics());
        Map<String, Long> transactionStats = transactionService.getTransactionStatistics();
        model.addAttribute("transactionStats", transactionStats);

        // 2. Lấy Tổng doanh thu (MỚI)
        model.addAttribute("totalRevenue", transactionService.getTotalRevenue());

        // 3. Chuẩn bị dữ liệu cho Biểu đồ tần suất (MỚI)
        List<Map<String, Object>> rawChartData = transactionService.getHourlySwapReport();
        int[] dataByHour = new int[24];
        for (Map<String, Object> row : rawChartData) {
            Number hour = (Number) row.get("hour");
            Number count = (Number) row.get("count");
            if (hour != null && count != null) {
                dataByHour[hour.intValue()] = count.intValue();
            }
        }
        List<Integer> chartData = new ArrayList<>();
        for (int count : dataByHour) chartData.add(count);
        model.addAttribute("hourlySwapData", chartData);

        return "admin/dashboard";
    }
}