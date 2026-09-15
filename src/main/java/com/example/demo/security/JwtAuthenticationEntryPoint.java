package com.example.demo.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Fires when a protected endpoint (e.g. POST /api/auth/users) is called
 * with no token, or one JwtAuthenticationFilter couldn't validate (missing,
 * malformed, expired, bad signature). Runs at the security-filter level —
 * before any controller or @RestControllerAdvice runs — so the JSON body is
 * written directly here. Shaped the same as GlobalExceptionHandler's
 * ErrorResponse-style bodies (status/message/code) for consistency.
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                          AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "error");
        body.put("message", "Missing, invalid, or expired authentication token");
        body.put("code", null);

        objectMapper.writeValue(response.getWriter(), body);
    }
}
