package com.example.demo.config;

import com.example.demo.entity.AuthUser;
import com.example.demo.repository.AuthUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminInitializerTest {

    @Mock
    private AuthUserRepository authUserRepository;

    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
    }

    @Test
    void bootstrap_NoAdminExists_CreatesExactlyOneAdmin() {
        AdminInitializer adminInitializer = new AdminInitializer(
                authUserRepository, passwordEncoder, "admin", "admin@bank.local", "Sup3rSecret!");

        when(authUserRepository.existsByUsrRole("ADMIN")).thenReturn(false);

        adminInitializer.bootstrapAdminIfNeeded();

        ArgumentCaptor<AuthUser> captor = ArgumentCaptor.forClass(AuthUser.class);
        verify(authUserRepository, times(1)).save(captor.capture());

        AuthUser saved = captor.getValue();
        assertEquals("admin", saved.getUsrUsername());
        assertEquals("ADMIN", saved.getUsrRole());
        assertEquals("ACTIVE", saved.getUsrSts());
        // Never the plaintext password, and it must actually verify against it.
        assertNotEquals("Sup3rSecret!", saved.getUsrPasswordHash());
        assertTrue(passwordEncoder.matches("Sup3rSecret!", saved.getUsrPasswordHash()));
    }

    @Test
    void bootstrap_AdminAlreadyExists_DoesNotCreateAnother() {
        AdminInitializer adminInitializer = new AdminInitializer(
                authUserRepository, passwordEncoder, "admin", "admin@bank.local", "Sup3rSecret!");

        when(authUserRepository.existsByUsrRole("ADMIN")).thenReturn(true);

        adminInitializer.bootstrapAdminIfNeeded();

        verify(authUserRepository, never()).save(any());
    }

    @Test
    void bootstrap_NoAdminAndNoPasswordConfigured_SkipsWithoutCreating() {
        // Simulates INITIAL_ADMIN_PASSWORD not being set — must not crash
        // startup, and must not create an admin with a blank/guessable password.
        AdminInitializer adminInitializer = new AdminInitializer(
                authUserRepository, passwordEncoder, "admin", "admin@bank.local", "");

        when(authUserRepository.existsByUsrRole("ADMIN")).thenReturn(false);

        adminInitializer.bootstrapAdminIfNeeded();

        verify(authUserRepository, never()).save(any());
    }
}
