package com.ev.batteryswap.repositories;
import com.ev.batteryswap.pojo.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import java.math.BigDecimal;
import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Integer>, JpaSpecificationExecutor<User> {
    // Tìm nhân viên(Staff) theo id trạm và vai trò là staff)
    List<User> findByStation_IdAndRole(Integer stationId, String role);
    List<User> findByRole(String role);


    boolean existsByUsernameAndPassword(String username, String password);
    boolean existsByUsername(String username);

    User findByUsername(String username);
    User findById(int id);

    @Transactional
    @Modifying()
    @Query("UPDATE User u SET u.walletBalance = :balance WHERE u.id = :id")
    int updateBalanceById(int id, BigDecimal balance);

}