package com.example.demo.service;

import com.example.demo.dto.RegistrationRequest;
import com.example.demo.dto.RegistrationResponse;
import com.example.demo.entity.AuthUser;
import com.example.demo.exception.UsernameAlreadyExistsException;
import com.example.demo.repository.AuthUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthUserRepository authUserRepository;

    private PasswordEncoder passwordEncoder;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        authService = new AuthService(authUserRepository, passwordEncoder);
    }

    @Test
    void register_SuccessfulRegistration() {
        RegistrationRequest request = new RegistrationRequest("akshat_user", "akshat@example.com", "SecurePass123!");

        when(authUserRepository.existsByUsrUsername("akshat_user")).thenReturn(false);

        AuthUser savedUser = new AuthUser();
        savedUser.setUsrId(1L);
        savedUser.setUsrUsername("akshat_user");
        savedUser.setUsrEmail("akshat@example.com");
        savedUser.setUsrRole("USER");
        savedUser.setUsrSts("ACTIVE");
        savedUser.setUsrPasswordHash(passwordEncoder.encode("SecurePass123!"));

        when(authUserRepository.save(any(AuthUser.class))).thenReturn(savedUser);

        RegistrationResponse response = authService.register(request);

        assertNotNull(response);
        assertEquals(1L, response.getUserId());
        assertEquals("akshat_user", response.getUsername());
        assertEquals("akshat@example.com", response.getEmail());
        assertEquals("USER", response.getRole());
        assertEquals("ACTIVE", response.getStatus());

        ArgumentCaptor<AuthUser> userCaptor = ArgumentCaptor.forClass(AuthUser.class);
        verify(authUserRepository).save(userCaptor.capture());
        AuthUser capturedUser = userCaptor.getValue();

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
}
