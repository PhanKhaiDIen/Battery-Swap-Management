package com.ev.batteryswap.pojo;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Getter
@Setter
@Entity
@Table(name = "batteries")
@EntityListeners(AuditingEntityListener.class)
public class Battery {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "current_station_id")
    private Station station;

    @Column(name = "serial_number", nullable = false, length = 100)
    private String serialNumber;

    @Column(name = "model", nullable = false, length = 100)
    private String model;

    @Column(name = "capacity_kwh", nullable = false, precision = 8, scale = 2)
    private BigDecimal capacityKwh;


    @Column(name = "amount", precision = 12, scale = 2)
    private BigDecimal amount =  BigDecimal.ZERO;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User currentUser;

    @ColumnDefault("0.00")
    @Column(name = "current_charge_percentage", precision = 5, scale = 2)
    private BigDecimal currentChargePercentage;

    @ColumnDefault("100.00")
    @Column(name = "health_percentage", precision = 5, scale = 2)
    private BigDecimal healthPercentage;

    @ColumnDefault("0")
    @Column(name = "charge_cycles")
    private Integer chargeCycles;

    @ColumnDefault("'EMPTY'")
    @Column(name = "status")
    private String status;

    @Column(name = "manufacture_date")
    private LocalDate manufactureDate;

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private Instant updatedAt;



}