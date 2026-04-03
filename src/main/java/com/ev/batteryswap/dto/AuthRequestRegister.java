package com.ev.batteryswap.dto;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthRequestRegister {
    private String fullName;
    private String username;
    private String password;
    private String confirmPassword;

    @Override
    public String toString() {
        return "AuthRequestRegister{" +
                "fullName='" + fullName + '\'' +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", confirmPassword='" + confirmPassword + '\'' +
                '}';
    }
}
