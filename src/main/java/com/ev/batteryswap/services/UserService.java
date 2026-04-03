package com.ev.batteryswap.services;
import com.ev.batteryswap.pojo.Rental;
import com.ev.batteryswap.pojo.RentalPackage;
import com.ev.batteryswap.pojo.User;
import com.ev.batteryswap.repositories.RentalPackageRepository;
import com.ev.batteryswap.repositories.RentalRepository;
import com.ev.batteryswap.repositories.UserRepository;
import com.ev.batteryswap.services.interfaces.IUserService;
import jakarta.persistence.criteria.Predicate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

@Service
public class UserService implements IUserService {

    @Autowired
    private UserRepository userRepository;


    @Autowired
    private RentalRepository  rentalRepository;



    @Override
    public Page<User> filterUsers(String searchKeyword, Pageable pageable) {
        return userRepository.findAll((Specification<User>) (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (searchKeyword != null && !searchKeyword.trim().isEmpty()) {
                String likePattern = "%" + searchKeyword.toLowerCase() + "%";
                predicates.add(criteriaBuilder.or(
                        criteriaBuilder.like(criteriaBuilder.lower(root.get("username")), likePattern),
                        criteriaBuilder.like(criteriaBuilder.lower(root.get("fullName")), likePattern),
                        criteriaBuilder.like(criteriaBuilder.lower(root.get("email")), likePattern)
                ));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        }, pageable);
    }

    @Override
    public void updateUserRole(Integer userId, String role) {
        User user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            throw new RuntimeException("User not found with id: " + userId);
        }
        user.setRole(role);
        userRepository.save(user);
    }

    @Override
    public void deleteUser(Integer userId) {
        userRepository.deleteById(userId);
    }
    @Override
    public void saveUser(User user) {
        userRepository.save(user);
    }
    @Override
    public User findById(Integer userId) {
        return userRepository.findById(userId).orElse(null);
    }


    @Override
    public Rental registerPackage(Rental rental){
        return rentalRepository.save(rental);
    }

    @Override
    public int updateBalanceById(int userId, BigDecimal price) {
        return userRepository.updateBalanceById(userId, price);
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public User findById(int id) {
        return userRepository.findById(id);
    }

    @Override
    public List<User> getStaffByStation(Integer stationId) {
        return userRepository.findByStation_IdAndRole(stationId, "STAFF");
    }
    @Override
    public List<User> getUsersByRole(String role) {
        return userRepository.findByRole(role);
    }


    // Tìm kiếm gói đăng ký từ người dùng
    @Override
    public Rental findRentalByUser(User user) {
        return rentalRepository.findRentalByUser(user);
    }


}