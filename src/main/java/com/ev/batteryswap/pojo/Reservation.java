package com.ev.batteryswap.pojo;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "reservations")
@EntityListeners(AuditingEntityListener.class)
public class Reservation {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "station_id", nullable = false)
    private Station station;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "battery_id", nullable = false)
    private Battery battery;

    @Column(name = "reservation_time", nullable = false)
    private Instant reservationTime; // Thời gian khách hẹn đến lấy

    @ColumnDefault("'PENDING'")
    @Lob
    @Column(name = "status")
    private String status = "PENDING"; // Mặc định là PENDING

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt; // Thời gian hết hạn (ví dụ: quá 30p k đến thì hủy)

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;
}