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
@Table(name = "support_tickets")
@EntityListeners(AuditingEntityListener.class)
public class SupportTicket {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user_id;

    @Column(name = "subject", nullable = false)
    private String subject;

    @Lob
    @Column(name = "message", nullable = false)
    private String message;

    @Lob
    @Column(name = "status")
    private String status = "OPEN";

    @Lob
    @Column(name = "priority")
    private String priority = "MEDIUM";

    @Lob
    @Column(name = "admin_response")
    private String adminResponse;

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private Instant updatedAt;

}