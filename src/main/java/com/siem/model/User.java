package com.siem.model;

/**
 * Represents an application user (not a Windows account - this is a user
 * of the SIEM tool itself, used for login and role-based access).
 */
public class User {
    private final String username;
    private final Role role;

    public User(String username, Role role) {
        this.username = username;
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public Role getRole() {
        return role;
    }

    public boolean isAdmin() {
        return role == Role.ADMIN;
    }

    @Override
    public String toString() {
        return username + " (" + role + ")";
    }
}
