package com.example.demo.dto;

public class RegistrationResponse {

    private Long userId;
    private String username;
    private String email;
    private String role;
    private String status;
    private String message;

    public RegistrationResponse() {
        this.message = "User registered successfully";
    }

    public RegistrationResponse(Long userId, String username, String email, String role, String status) {
        this(userId, username, email, role, status, "User registered successfully");
    }

    public RegistrationResponse(Long userId, String username, String email, String role, String status, String message) {
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.role = role;
        this.status = status;
        this.message = message == null ? "User registered successfully" : message;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
