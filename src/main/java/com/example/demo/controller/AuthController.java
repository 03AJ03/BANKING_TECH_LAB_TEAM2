package com.example.demo.controller;

import com.example.demo.dto.CreateUserRequest;
import com.example.demo.dto.LoginRequest;
import com.example.demo.dto.LoginResponse;
import com.example.demo.dto.RegistrationRequest;
import com.example.demo.dto.RegistrationResponse;
import com.example.demo.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// Base path moved from "/api" to "/api/auth" so register AND login both
// match the swagger contract's /api/auth/{register,login} paths exactly.
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegistrationResponse> register(@Valid @RequestBody RegistrationRequest request) {
        RegistrationResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // B2.3/B2.4 — POST /api/auth/login per the swagger contract.
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    // ADMIN-only. SecurityConfig restricts this route to hasRole("ADMIN")
    // before the request ever reaches here — non-admins get a 403 from the
    // filter chain, and requests with no/invalid/expired JWT get a 401,
    // without this method needing to check anything itself.
    @PostMapping("/users")
    public ResponseEntity<RegistrationResponse> createUser(@Valid @RequestBody CreateUserRequest request) {
        RegistrationResponse response = authService.createPrivilegedUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
