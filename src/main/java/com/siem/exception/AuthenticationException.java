package com.siem.exception;

/** Thrown when a login attempt fails (wrong username or password). */
public class AuthenticationException extends SiemException {
    public AuthenticationException(String message) {
        super(message);
    }
}
