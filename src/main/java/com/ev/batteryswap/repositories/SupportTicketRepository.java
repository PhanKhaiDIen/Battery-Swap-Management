package com.ev.batteryswap.repositories;

import com.ev.batteryswap.pojo.SupportTicket;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface SupportTicketRepository extends JpaRepository<SupportTicket, Integer>, JpaSpecificationExecutor<SupportTicket> {
    long countByStatus(String status);
    long countByPriority(String priority);
}