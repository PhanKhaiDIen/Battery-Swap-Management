package com.ev.batteryswap.pojo;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "swap_transactions")
@EntityListeners(AuditingEntityListener.class)
public class SwapTransaction {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "station_id")
    private Station station;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "battery_out_id")
    private Battery batteryOut;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "battery_in_id")
    private Battery batteryIn;

    @ColumnDefault("0.00")
    @Column(name = "amount", precision = 10, scale = 2)
    private BigDecimal amount;

    @Lob
    @Column(name = "payment_method", nullable = false)
    private String paymentMethod;

    @Lob
    @Column(name = "payment_status", nullable = false)
    private String paymentStatus;

    @Lob
    @Column(name = "notes")
    private String notes;

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

}