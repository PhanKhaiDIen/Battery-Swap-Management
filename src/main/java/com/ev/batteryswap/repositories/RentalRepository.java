package com.ev.batteryswap.repositories;


import com.ev.batteryswap.pojo.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;
import com.ev.batteryswap.pojo.Rental;

@Repository
public interface RentalRepository extends JpaRepository<Rental, Integer>, JpaSpecificationExecutor<Rental> {

    Rental findRentalByUser(User user);

}
