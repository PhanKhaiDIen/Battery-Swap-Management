package com.ev.batteryswap.repositories;

import com.ev.batteryswap.pojo.Vehicle;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface VehicleRepository extends JpaRepository<Vehicle, Integer> {

}
