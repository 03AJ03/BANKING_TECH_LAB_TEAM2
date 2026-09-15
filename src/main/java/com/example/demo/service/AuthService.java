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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Service
public class AuthService {

    private static final String INVALID_CREDENTIALS_MESSAGE = "Invalid username or password";

    // Roles an ADMIN is allowed to hand out through POST /api/auth/users.
    // CUSTOMER is deliberately excluded — that only ever comes from
    // self-registration via POST /api/auth/register.
    private static final Set<String> ADMIN_ASSIGNABLE_ROLES = Set.of("BANK_OFFICER", "ADMIN");

    private final AuthUserRepository authUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthService(AuthUserRepository authUserRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.authUserRepository = authUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Transactional
    public RegistrationResponse register(RegistrationRequest request) {
        // Self-registration is always CUSTOMER — BANK_OFFICER and ADMIN
        // accounts are only ever provisioned via POST /api/auth/users by an
        // existing ADMIN (or, for the very first ADMIN, AdminInitializer).
        // Matches the swagger Role enum (CUSTOMER, BANK_OFFICER, ADMIN).
        AuthUser savedUser = createAndSaveUser(
                request.getUsername(), request.getEmail(), request.getPassword(),
                "CUSTOMER", "REGISTRATION_MODULE");
        return toRegistrationResponse(savedUser);
    }

    /**
     * POST /api/auth/users — an authenticated ADMIN provisions a BANK_OFFICER
     * or another ADMIN.
     *
     * The caller's own admin privilege is already enforced by the security
     * filter chain (hasRole("ADMIN") on this route, backed by the validated
     * JWT) before this method ever runs. The "role" on the incoming request
     * is never trusted as a statement about the CALLER — it only ever
     * describes the role of the new user being created.
     */
    @Transactional
    public RegistrationResponse createPrivilegedUser(CreateUserRequest request) {
        String requestedRole = request.getRole() == null ? "" : request.getRole().trim().toUpperCase(Locale.ROOT);
        if (!ADMIN_ASSIGNABLE_ROLES.contains(requestedRole)) {
            throw new InvalidRoleException("role must be one of " + ADMIN_ASSIGNABLE_ROLES);
        }

        AuthUser savedUser = createAndSaveUser(
                request.getUsername(), request.getEmail(), request.getPassword(),
                requestedRole, "ADMIN_USER_MANAGEMENT");
        return toRegistrationResponse(savedUser);
    }

    /**
     * B2.5 — find the user by username
     * B2.6 — retrieve the stored BCrypt hash off that record
     * B2.7 — compare the supplied password against it
     * B2.8 — return a JWT + role on success, or a generic 401 on failure
     *
     * The same InvalidCredentialsException/message is used whether the
     * username doesn't exist or the password doesn't match, so the caller
     * can't use the error to enumerate valid usernames. Works identically
     * for CUSTOMER, BANK_OFFICER, and ADMIN logins — role is just whatever
     * is stored on the row.
     */
    public LoginResponse login(LoginRequest request) {
        AuthUser authUser = authUserRepository.findByUsrUsername(request.getUsername())
                .orElseThrow(() -> new InvalidCredentialsException(INVALID_CREDENTIALS_MESSAGE));

        boolean passwordMatches = passwordEncoder.matches(request.getPassword(), authUser.getUsrPasswordHash());
        if (!passwordMatches) {
            throw new InvalidCredentialsException(INVALID_CREDENTIALS_MESSAGE);
        }

        String token = jwtService.generateToken(authUser.getUsrUsername(), authUser.getUsrRole());

        return new LoginResponse(
                token,
                "Bearer",
                jwtService.getExpirationSeconds(),
                authUser.getUsrRole()
        );
    }

    /** Shared by register() and createPrivilegedUser() — same uniqueness check, hashing, and audit fields either way. */
    private AuthUser createAndSaveUser(String username, String email, String rawPassword, String role, String programId) {
        if (authUserRepository.existsByUsrUsername(username)) {
            throw new UsernameAlreadyExistsException("Username '" + username + "' is already registered");
        }

        LocalDateTime now = LocalDateTime.now();

        AuthUser authUser = new AuthUser();
        authUser.setUsrUsername(username);
        authUser.setUsrEmail(email);
        authUser.setUsrPasswordHash(passwordEncoder.encode(rawPassword));
        authUser.setUsrRole(role);
        authUser.setUsrSts("ACTIVE");
        authUser.setUsrUsrId(username);
        authUser.setUsrWsId("WS_DEFAULT");
        authUser.setUsrLocalTs(now);
        authUser.setUsrHostTs(now);
        authUser.setUsrPrgmId(programId);
        authUser.setUsrAcptTs(now);
        authUser.setUsrAcptTsUtcOsft("+00:00");
        authUser.setUsrUuid(UUID.randomUUID().toString());
        authUser.setUsrCrudVal("C");

        return authUserRepository.save(authUser);
    }

    private RegistrationResponse toRegistrationResponse(AuthUser savedUser) {
        return new RegistrationResponse(
                savedUser.getUsrId(),
                savedUser.getUsrUsername(),
                savedUser.getUsrEmail(),
                savedUser.getUsrRole(),
                savedUser.getUsrSts()
        );
    }
}
