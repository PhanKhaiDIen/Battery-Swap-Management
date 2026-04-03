package com.ev.batteryswap.dto;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthRequestLogin {
    private String username;
    private String password;

    @Override
    public String toString() {
        return "AuthRequest{" +
                "username='" + username + '\'' +
                ", password='" + password + '\'' +
                '}';
    }
}
