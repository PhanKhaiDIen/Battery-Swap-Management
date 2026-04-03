package com.ev.batteryswap.services.interfaces;

import com.ev.batteryswap.pojo.Rental;
import com.ev.batteryswap.pojo.RentalPackage;
import com.ev.batteryswap.pojo.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.math.BigDecimal;
import java.util.List;


public interface IUserService {

    Page<User> filterUsers(String searchKeyword, Pageable pageable);
    void updateUserRole(Integer userId, String role);
    void saveUser(User user);
    void deleteUser(Integer userId);
    User findById(Integer userId);

    User findByUsername(String username);
    User findById(int id);

    // đăng ký gói dịch vụ
    Rental registerPackage(Rental rental);

    // cập nhật tiền của người dùng
    int updateBalanceById(int userId, BigDecimal price);

    //Tìm nhân viên dựa theo id trạm
    List<User> getStaffByStation(Integer stationId);

    //Tìm user theo role
    List<User> getUsersByRole(String role);

    // Tìm kiếm gói đăng ký từ người dùng
    Rental findRentalByUser(User user);

}