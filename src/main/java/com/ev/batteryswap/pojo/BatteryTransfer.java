package com.ev.batteryswap.pojo;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;

import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "battery_transfers")
public class BatteryTransfer {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "battery_id", nullable = false)
    private Battery battery;

    @Column(name = "transfer_date", nullable = false)
    private Instant transferDate;

    @ColumnDefault("'PENDING'")
    @Lob
    @Column(name = "status", nullable = false)
    private String status;

    @Lob
    @Column(name = "notes")
    private String notes;

}