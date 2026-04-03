package com.ev.batteryswap.pojo;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "stations")
@EntityListeners(AuditingEntityListener.class)
public class Station {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @Column(name = "name", nullable = false)
    private String name;

    @Lob
    @Column(name = "address", nullable = false)
    private String address;

    @Column(name = "quan", nullable = false, length = 45)
    private String quan;

    @Column(name = "province", nullable = false, length = 45)
    private String province;

    @ColumnDefault("'ACTIVE'")
    @Lob
    @Column(name = "status")
    private String status;

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;


    @LastModifiedDate
    @Column(name = "updated_at")
    private Instant updatedAt;

}