package com.example.demo.exception;

/**
 * Thrown when POST /api/auth/users is called with a "role" that isn't one
 * ADMIN is allowed to hand out (must be BANK_OFFICER or ADMIN — never
 * CUSTOMER, never garbage input).
 *
 * Deliberately extends IllegalArgumentException so GlobalExceptionHandler's
 * existing handleIllegalArgumentException(...) picks it up automatically —
 * no new exception handler needed for this to return a 400.
 */
public class InvalidRoleException extends IllegalArgumentException {

    public InvalidRoleException(String message) {
        super(message);
    }
}
