package com.siem.service;

import com.siem.exception.AuthenticationException;
import com.siem.model.Role;
import com.siem.model.User;

import java.util.Map;

/**
 * AuthenticationService handles login for the application's OWN users
 * (not Windows accounts). For this educational project, credentials are
 * hardcoded rather than stored in a real database - a real system would
 * hash passwords and store them securely, which is noted here as a
 * natural extension point.
 */
public class AuthenticationService {

    // username -> password (demo only - never store plain-text passwords in a real system)
    private static final Map<String, String> CREDENTIALS = Map.of(
            "admin", "admin123",
            "analyst", "analyst123"
    );

    private static final Map<String, Role> ROLES = Map.of(
            "admin", Role.ADMIN,
            "analyst", Role.ANALYST
    );

    private User currentUser;

    public User login(String username, String password) throws AuthenticationException {
        if (username == null || password == null
                || !CREDENTIALS.containsKey(username)
                || !CREDENTIALS.get(username).equals(password)) {
            throw new AuthenticationException("Invalid username or password.");
        }
        currentUser = new User(username, ROLES.get(username));
        return currentUser;
    }

    public void logout() {
        currentUser = null;
    }

    public User getCurrentUser() {
        return currentUser;
    }

    public boolean isLoggedIn() {
        return currentUser != null;
    }
}
