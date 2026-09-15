package com.example.demo.controller;

import com.example.demo.dto.CreateUserRequest;
import com.example.demo.dto.LoginRequest;
import com.example.demo.dto.LoginResponse;
import com.example.demo.dto.RegistrationRequest;
import com.example.demo.dto.RegistrationResponse;
import com.example.demo.exception.GlobalExceptionHandler;
import com.example.demo.exception.InvalidCredentialsException;
import com.example.demo.exception.InvalidRoleException;
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
        validResponse = new RegistrationResponse(1L, "akshat_user", "akshat@example.com", "CUSTOMER", "ACTIVE");
    }

    @Test
    void register_Success_Returns201CreatedAndSafeResponse() throws Exception {
        when(authService.register(any(RegistrationRequest.class))).thenReturn(validResponse);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.userId").value(1))
                .andExpect(jsonPath("$.username").value("akshat_user"))
                .andExpect(jsonPath("$.email").value("akshat@example.com"))
                .andExpect(jsonPath("$.role").value("CUSTOMER"))
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

        mockMvc.perform(post("/api/auth/register")
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

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_InvalidEmail_Returns400BadRequest() throws Exception {
        RegistrationRequest invalidRequest = new RegistrationRequest("akshat_user", "invalid-email", "Password123!");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_MissingPassword_Returns400BadRequest() throws Exception {
        RegistrationRequest invalidRequest = new RegistrationRequest("akshat_user", "email@example.com", "");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // ---------------------------------------------------------------
    // Login: B2.3 (controller/DTO), B2.4 (POST /api/auth/login), B2.8
    // ---------------------------------------------------------------

    @Test
    void login_Success_Returns200WithTokenAndRole() throws Exception {
        LoginRequest loginRequest = new LoginRequest("akshat_user", "Password123!");
        LoginResponse loginResponse = new LoginResponse("dummy.jwt.token", "Bearer", 36000L, "CUSTOMER");

        when(authService.login(any(LoginRequest.class))).thenReturn(loginResponse);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("dummy.jwt.token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(36000))
                .andExpect(jsonPath("$.role").value("CUSTOMER"));
    }

    @Test
    void login_InvalidCredentials_Returns401WithErrorSchema() throws Exception {
        LoginRequest loginRequest = new LoginRequest("akshat_user", "WrongPassword!");

        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new InvalidCredentialsException("Invalid username or password"));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("error"))
                .andExpect(jsonPath("$.message").value("Invalid username or password"));
    }

    @Test
    void login_MissingPassword_Returns400BadRequest() throws Exception {
        LoginRequest invalidRequest = new LoginRequest("akshat_user", "");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void login_MissingUsername_Returns400BadRequest() throws Exception {
        LoginRequest invalidRequest = new LoginRequest("", "Password123!");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // ---------------------------------------------------------------
    // POST /api/auth/users — controller/DTO wiring only.
    // Role-based 401/403 enforcement lives in the security filter chain,
    // not this controller, so that's covered separately by
    // UserManagementSecurityIntegrationTest (real filter chain, real JWTs)
    // rather than here (this MockMvc instance is a standalone controller
    // test with no security filters attached at all).
    // ---------------------------------------------------------------

    @Test
    void createUser_ValidBankOfficerRequest_Returns201() throws Exception {
        CreateUserRequest request = new CreateUserRequest("officer01", "officer@bank.com", "Bank@123456", "BANK_OFFICER");
        RegistrationResponse response = new RegistrationResponse(5L, "officer01", "officer@bank.com", "BANK_OFFICER", "ACTIVE");

        when(authService.createPrivilegedUser(any(CreateUserRequest.class))).thenReturn(response);

        mockMvc.perform(post("/api/auth/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("officer01"))
                .andExpect(jsonPath("$.role").value("BANK_OFFICER"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void createUser_InvalidRole_Returns400() throws Exception {
        CreateUserRequest request = new CreateUserRequest("someone", "someone@example.com", "Password123!", "SUPERUSER");

        when(authService.createPrivilegedUser(any(CreateUserRequest.class)))
                .thenThrow(new InvalidRoleException("role must be one of [BANK_OFFICER, ADMIN]"));

        mockMvc.perform(post("/api/auth/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createUser_MissingRole_Returns400BadRequest() throws Exception {
        CreateUserRequest invalidRequest = new CreateUserRequest("officer01", "officer@bank.com", "Bank@123456", "");

        mockMvc.perform(post("/api/auth/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createUser_DuplicateUsername_Returns409Conflict() throws Exception {
        CreateUserRequest request = new CreateUserRequest("officer01", "officer@bank.com", "Bank@123456", "BANK_OFFICER");

        when(authService.createPrivilegedUser(any(CreateUserRequest.class)))
                .thenThrow(new UsernameAlreadyExistsException("Username 'officer01' is already registered"));

        mockMvc.perform(post("/api/auth/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict());
    }
}
