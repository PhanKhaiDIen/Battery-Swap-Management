package com.ev.batteryswap.services.interfaces;
import com.ev.batteryswap.pojo.Battery;
import com.ev.batteryswap.pojo.PaymentInfo;
import com.ev.batteryswap.pojo.User;
import com.ev.batteryswap.services.PaymentInfoService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Map;

public interface IPaymentInfoService {

    Page<PaymentInfo> filterPaymentInfo(Integer userId, Pageable pageable);
}
