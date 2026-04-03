package com.ev.batteryswap.pojo;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "vehicles")
@EntityListeners(AuditingEntityListener.class)
public class Vehicle {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @OnDelete(action = OnDeleteAction.CASCADE)

    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "vin_code", nullable = false, length = 17)
    private String vinCode;

    @Column(name = "model", nullable = false, length = 100)
    private String model;

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

}