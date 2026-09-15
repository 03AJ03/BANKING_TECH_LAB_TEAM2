package com.example.demo.exception;

/**
 * Thrown when a login attempt fails — either the username does not exist
 * or the supplied password does not match the stored BCrypt hash.
 *
 * The message is intentionally generic ("Invalid username or password")
 * wherever it's thrown from AuthService, so the 401 response never reveals
 * which of the two checks failed (avoids username enumeration).
 */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
