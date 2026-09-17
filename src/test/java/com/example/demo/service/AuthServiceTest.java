package com.example.demo.service;

import com.example.demo.dto.CreateUserRequest;
import com.example.demo.dto.LoginRequest;
import com.example.demo.dto.LoginResponse;
import com.example.demo.dto.RegistrationRequest;
import com.example.demo.dto.RegistrationResponse;
import com.example.demo.entity.AuthUser;
import com.example.demo.exception.InvalidCredentialsException;
import com.example.demo.exception.InvalidRoleException;
import com.example.demo.exception.UsernameAlreadyExistsException;
import com.example.demo.repository.AuthUserRepository;
import com.example.demo.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final String TEST_JWT_SECRET = "wELlrzgLdgUqv1gGrvgQmx9153+14FyGO34AYx0rxGs=";
    private static final long TEST_JWT_EXPIRATION_MS = 36000000L;

    @Mock
    private AuthUserRepository authUserRepository;

    private PasswordEncoder passwordEncoder;
    private JwtService jwtService;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        jwtService = new JwtService(TEST_JWT_SECRET, TEST_JWT_EXPIRATION_MS);
        authService = new AuthService(authUserRepository, passwordEncoder, jwtService);
    }

    @Test
    void register_SuccessfulRegistration() {
        RegistrationRequest request = new RegistrationRequest("akshat_user", "akshat@example.com", "SecurePass123!");

        when(authUserRepository.existsByUsrUsername("akshat_user")).thenReturn(false);

        AuthUser savedUser = new AuthUser();
        savedUser.setUsrId(1L);
        savedUser.setUsrUsername("akshat_user");
        savedUser.setUsrEmail("akshat@example.com");
        savedUser.setUsrRole("CUSTOMER");
        savedUser.setUsrSts("ACTIVE");
        savedUser.setUsrPasswordHash(passwordEncoder.encode("SecurePass123!"));

        when(authUserRepository.save(any(AuthUser.class))).thenReturn(savedUser);

        RegistrationResponse response = authService.register(request);

        assertNotNull(response);
        assertEquals(1L, response.getUserId());
        assertEquals("akshat_user", response.getUsername());
        assertEquals("akshat@example.com", response.getEmail());
        assertEquals("CUSTOMER", response.getRole());
        assertEquals("ACTIVE", response.getStatus());

        ArgumentCaptor<AuthUser> userCaptor = ArgumentCaptor.forClass(AuthUser.class);
        verify(authUserRepository).save(userCaptor.capture());
        AuthUser capturedUser = userCaptor.getValue();

        // Self-registration must always default to CUSTOMER — BANK_OFFICER
        // and ADMIN are provisioned manually, never through this endpoint.
        assertEquals("CUSTOMER", capturedUser.getUsrRole());
        assertNotEquals("SecurePass123!", capturedUser.getUsrPasswordHash());
        assertTrue(passwordEncoder.matches("SecurePass123!", capturedUser.getUsrPasswordHash()));
        assertTrue(capturedUser.getUsrPasswordHash().startsWith("$2a$"));
    }

    @Test
    void register_DuplicateUsername_ThrowsException() {
        RegistrationRequest request = new RegistrationRequest("existing_user", "email@example.com", "password123");

        when(authUserRepository.existsByUsrUsername("existing_user")).thenReturn(true);

        assertThrows(UsernameAlreadyExistsException.class, () -> authService.register(request));
        verify(authUserRepository, never()).save(any());
    }

    @Test
    void register_BCryptHashing_Verification() {
        RegistrationRequest request = new RegistrationRequest("new_user", "new@example.com", "mySecretPass");

        when(authUserRepository.existsByUsrUsername("new_user")).thenReturn(false);
        when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
            AuthUser user = invocation.getArgument(0);
            user.setUsrId(10L);
            return user;
        });

        authService.register(request);

        ArgumentCaptor<AuthUser> captor = ArgumentCaptor.forClass(AuthUser.class);
        verify(authUserRepository).save(captor.capture());
        AuthUser savedUser = captor.getValue();

        // 6. BCrypt hashing test
        // 7. Stored hash is not equal to plaintext
        assertNotEquals("mySecretPass", savedUser.getUsrPasswordHash());
        // 8. Stored value is a valid BCrypt hash
        assertTrue(passwordEncoder.matches("mySecretPass", savedUser.getUsrPasswordHash()));
        assertTrue(savedUser.getUsrPasswordHash().startsWith("$2a$"));
    }

    // ---------------------------------------------------------------
    // Login: B2.5 (find by username), B2.6 (retrieve hash),
    // B2.7 (BCrypt compare), B2.8 (success/error response)
    // ---------------------------------------------------------------

    @Test
    void login_ValidCredentials_ReturnsTokenAndRole() {
        LoginRequest request = new LoginRequest("akshat_user", "SecurePass123!");

        AuthUser storedUser = new AuthUser();
        storedUser.setUsrId(1L);
        storedUser.setUsrUsername("akshat_user");
        storedUser.setUsrPasswordHash(passwordEncoder.encode("SecurePass123!"));
        storedUser.setUsrRole("ADMIN");

        when(authUserRepository.findByUsrUsername("akshat_user")).thenReturn(Optional.of(storedUser));

        LoginResponse response = authService.login(request);

        assertNotNull(response.getToken());
        assertEquals("Bearer", response.getTokenType());
        assertEquals("ADMIN", response.getRole());
        assertEquals(36000L, response.getExpiresIn());
    }

    @Test
    void login_UnknownUsername_ThrowsInvalidCredentials() {
        when(authUserRepository.findByUsrUsername("ghost_user")).thenReturn(Optional.empty());

        LoginRequest request = new LoginRequest("ghost_user", "whatever123");

        InvalidCredentialsException ex = assertThrows(InvalidCredentialsException.class,
                () -> authService.login(request));
        assertEquals("Invalid username or password", ex.getMessage());
    }

    @Test
    void login_WrongPassword_ThrowsInvalidCredentials() {
        AuthUser storedUser = new AuthUser();
        storedUser.setUsrUsername("akshat_user");
        storedUser.setUsrPasswordHash(passwordEncoder.encode("CorrectPass1!"));
        storedUser.setUsrRole("CUSTOMER");

        when(authUserRepository.findByUsrUsername("akshat_user")).thenReturn(Optional.of(storedUser));

        LoginRequest request = new LoginRequest("akshat_user", "WrongPass1!");

        // Same exception/message as the unknown-username case above —
        // the response never reveals which check failed.
        assertThrows(InvalidCredentialsException.class, () -> authService.login(request));
    }

    @Test
    void login_CustomerCredentials_ReturnsTokenWithCustomerRole() {
        AuthUser storedUser = new AuthUser();
        storedUser.setUsrUsername("jane_customer");
        storedUser.setUsrPasswordHash(passwordEncoder.encode("Password123!"));
        storedUser.setUsrRole("CUSTOMER");

        when(authUserRepository.findByUsrUsername("jane_customer")).thenReturn(Optional.of(storedUser));

        LoginResponse response = authService.login(new LoginRequest("jane_customer", "Password123!"));

        assertNotNull(response.getToken());
        assertEquals("CUSTOMER", response.getRole());
    }

    @Test
    void login_BankOfficerCredentials_ReturnsTokenWithBankOfficerRole() {
        AuthUser storedUser = new AuthUser();
        storedUser.setUsrUsername("officer01");
        storedUser.setUsrPasswordHash(passwordEncoder.encode("Bank@123456"));
        storedUser.setUsrRole("BANK_OFFICER");

        when(authUserRepository.findByUsrUsername("officer01")).thenReturn(Optional.of(storedUser));

        LoginResponse response = authService.login(new LoginRequest("officer01", "Bank@123456"));

        assertNotNull(response.getToken());
        assertEquals("BANK_OFFICER", response.getRole());
    }

    // ---------------------------------------------------------------
    // POST /api/auth/users — admin-only creation of BANK_OFFICER/ADMIN
    // ---------------------------------------------------------------

    @Test
    void createPrivilegedUser_BankOfficerRole_CreatesAndReturnsIt() {
        CreateUserRequest request = new CreateUserRequest("officer01", "officer@bank.com", "Bank@123456", "BANK_OFFICER");

        when(authUserRepository.existsByUsrUsername("officer01")).thenReturn(false);
        when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
            AuthUser u = invocation.getArgument(0);
            u.setUsrId(10L);
            return u;
        });

        RegistrationResponse response = authService.createPrivilegedUser(request);

        assertEquals("officer01", response.getUsername());
        assertEquals("BANK_OFFICER", response.getRole());
        assertEquals("ACTIVE", response.getStatus());

        ArgumentCaptor<AuthUser> captor = ArgumentCaptor.forClass(AuthUser.class);
        verify(authUserRepository).save(captor.capture());
        assertTrue(passwordEncoder.matches("Bank@123456", captor.getValue().getUsrPasswordHash()));
    }

    @Test
    void createPrivilegedUser_AdminRole_CreatesAndReturnsIt() {
        CreateUserRequest request = new CreateUserRequest("admin02", "admin02@bank.com", "Admin@123456", "ADMIN");

        when(authUserRepository.existsByUsrUsername("admin02")).thenReturn(false);
        when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        RegistrationResponse response = authService.createPrivilegedUser(request);

        assertEquals("ADMIN", response.getRole());
    }

    @Test
    void createPrivilegedUser_CustomerRoleRequested_ThrowsInvalidRole() {
        // The admin endpoint is for BANK_OFFICER/ADMIN only — CUSTOMER goes
        // through the public register() flow instead.
        CreateUserRequest request = new CreateUserRequest("sneaky", "sneaky@example.com", "Password123!", "CUSTOMER");

        assertThrows(InvalidRoleException.class, () -> authService.createPrivilegedUser(request));
        verify(authUserRepository, never()).save(any());
    }

    @Test
    void createPrivilegedUser_GarbageRole_ThrowsInvalidRole() {
        CreateUserRequest request = new CreateUserRequest("someone", "someone@example.com", "Password123!", "SUPERUSER");

        assertThrows(InvalidRoleException.class, () -> authService.createPrivilegedUser(request));
    }

    @Test
    void createPrivilegedUser_DuplicateUsername_ThrowsUsernameAlreadyExists() {
        CreateUserRequest request = new CreateUserRequest("officer01", "officer@bank.com", "Bank@123456", "BANK_OFFICER");

        when(authUserRepository.existsByUsrUsername("officer01")).thenReturn(true);

        assertThrows(UsernameAlreadyExistsException.class, () -> authService.createPrivilegedUser(request));
        verify(authUserRepository, never()).save(any());
    }
}
