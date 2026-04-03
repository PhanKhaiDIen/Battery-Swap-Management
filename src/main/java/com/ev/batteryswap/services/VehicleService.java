package com.ev.batteryswap.services;


import com.ev.batteryswap.pojo.Vehicle;
import com.ev.batteryswap.repositories.VehicleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class VehicleService {

    @Autowired
    private VehicleRepository vehicleRepository;

    public Vehicle save(Vehicle vehicle) {
        return vehicleRepository.save(vehicle);
    }

}
