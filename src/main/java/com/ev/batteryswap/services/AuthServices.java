package com.ev.batteryswap.services;
import com.ev.batteryswap.pojo.User;
import com.ev.batteryswap.repositories.UserRepository;
import com.ev.batteryswap.services.interfaces.IAuthServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;


@Service
public class AuthServices implements IAuthServices {


    List<String> tokenBlacklist = new ArrayList<>();


    @Autowired
    private UserRepository userRepositories;

    @Override
    public boolean login(String username, String password) {
        return userRepositories.existsByUsernameAndPassword(username, password);
    }

    @Override
    public User register(User user) {
        return userRepositories.save(user);
    }

    @Override
    public boolean existsByUsername(String username) {
        return userRepositories.existsByUsername(username);
    }


    @Override
    public void blacklist (String token) {
        tokenBlacklist.add(token);
    }

    @Override
    public boolean isBlacklisted(String token) {
        return tokenBlacklist.contains(token);
    }
}
