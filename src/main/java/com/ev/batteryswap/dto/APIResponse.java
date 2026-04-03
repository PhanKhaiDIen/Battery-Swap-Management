package com.ev.batteryswap.dto;

import lombok.Getter;

@Getter
public class APIResponse {

    // Base trả kết quả cho các API
    private final boolean success;
    private final String message;


    public APIResponse(boolean success, String message) {
        this.success = success;
        this.message = message;
    }

}
