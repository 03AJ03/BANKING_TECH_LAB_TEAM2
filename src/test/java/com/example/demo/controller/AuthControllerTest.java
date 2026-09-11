package com.example.demo.controller;

import com.example.demo.dto.RegistrationRequest;
import com.example.demo.dto.RegistrationResponse;
import com.example.demo.exception.GlobalExceptionHandler;
import com.example.demo.exception.UsernameAlreadyExistsException;
import com.example.demo.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    private MockMvc mockMvc;

    private ObjectMapper objectMapper;

    @Mock
    private AuthService authService;

    @InjectMocks
    private AuthController authController;

    private RegistrationRequest validRequest;
    private RegistrationResponse validResponse;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        mockMvc = MockMvcBuilders.standaloneSetup(authController)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();

        validRequest = new RegistrationRequest("akshat_user", "akshat@example.com", "Password123!");
        validResponse = new RegistrationResponse(1L, "akshat_user", "akshat@example.com", "USER", "ACTIVE");
    }

    @Test
    void register_Success_Returns201CreatedAndSafeResponse() throws Exception {
        when(authService.register(any(RegistrationRequest.class))).thenReturn(validResponse);

        mockMvc.perform(post("/api/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.userId").value(1))
                .andExpect(jsonPath("$.username").value("akshat_user"))
                .andExpect(jsonPath("$.email").value("akshat@example.com"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                // 9. Response does not contain password
                .andExpect(jsonPath("$.password").doesNotExist())
                // 10. Response does not contain password hash
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void register_DuplicateUsername_Returns409Conflict() throws Exception {
        when(authService.register(any(RegistrationRequest.class)))
                .thenThrow(new UsernameAlreadyExistsException("Username 'akshat_user' is already registered"));

        mockMvc.perform(post("/api/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.error").value("Conflict"))
                .andExpect(jsonPath("$.message").value("Username 'akshat_user' is already registered"));
    }

    @Test
    void register_InvalidUsername_Returns400BadRequest() throws Exception {
        RegistrationRequest invalidRequest = new RegistrationRequest("", "email@example.com", "Password123!");

        mockMvc.perform(post("/api/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_InvalidEmail_Returns400BadRequest() throws Exception {
        RegistrationRequest invalidRequest = new RegistrationRequest("akshat_user", "invalid-email", "Password123!");

        mockMvc.perform(post("/api/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_MissingPassword_Returns400BadRequest() throws Exception {
        RegistrationRequest invalidRequest = new RegistrationRequest("akshat_user", "email@example.com", "");

        mockMvc.perform(post("/api/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }
}
