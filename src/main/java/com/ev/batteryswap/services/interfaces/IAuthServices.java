package com.ev.batteryswap.services.interfaces;

import com.ev.batteryswap.pojo.User;

public interface IAuthServices {
    boolean login(String username, String password);
    User register(User user);
    boolean existsByUsername(String username);

    public void blacklist (String token);
    public boolean isBlacklisted(String token);
}
