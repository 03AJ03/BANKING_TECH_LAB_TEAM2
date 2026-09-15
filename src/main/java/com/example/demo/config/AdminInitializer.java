package com.example.demo.config;

import com.example.demo.entity.AuthUser;
import com.example.demo.repository.AuthUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One-time bootstrap: creates exactly one ADMIN account on startup if
 * AUTH_USERS has none yet. This is deliberately the ONLY way an ADMIN can
 * come into existence without an existing ADMIN creating one through
 * POST /api/auth/users — there is no public endpoint for it.
 *
 * The password is never hard-coded. It's read from the
 * app.security.initial-admin-password property, which in turn reads the
 * INITIAL_ADMIN_PASSWORD environment variable (see application.properties
 * and the README). If that variable isn't set, bootstrap is skipped with a
 * warning log rather than failing startup, so the app still runs for
 * teammates/CI who haven't configured it.
 */
@Component
public class AdminInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminInitializer.class);
    private static final String ADMIN_ROLE = "ADMIN";

    private final AuthUserRepository authUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final String initialAdminUsername;
    private final String initialAdminEmail;
    private final String initialAdminPassword;

    public AdminInitializer(AuthUserRepository authUserRepository,
                             PasswordEncoder passwordEncoder,
                             @Value("${app.security.initial-admin-username}") String initialAdminUsername,
                             @Value("${app.security.initial-admin-email}") String initialAdminEmail,
                             @Value("${app.security.initial-admin-password}") String initialAdminPassword) {
        this.authUserRepository = authUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.initialAdminUsername = initialAdminUsername;
        this.initialAdminEmail = initialAdminEmail;
        this.initialAdminPassword = initialAdminPassword;
    }

    @Override
    public void run(ApplicationArguments args) {
        bootstrapAdminIfNeeded();
    }

    /** Package-private on purpose — lets the test call it directly without booting the whole app context. */
    void bootstrapAdminIfNeeded() {
        if (authUserRepository.existsByUsrRole(ADMIN_ROLE)) {
            log.info("An ADMIN already exists — skipping initial admin bootstrap.");
            return;
        }

        if (initialAdminPassword == null || initialAdminPassword.isBlank()) {
            log.warn("No ADMIN exists yet and INITIAL_ADMIN_PASSWORD is not set — skipping initial admin " +
                    "bootstrap. Set INITIAL_ADMIN_PASSWORD and restart the application to create one.");
            return;
        }

        LocalDateTime now = LocalDateTime.now();

        AuthUser admin = new AuthUser();
        admin.setUsrUsername(initialAdminUsername);
        admin.setUsrEmail(initialAdminEmail);
        admin.setUsrPasswordHash(passwordEncoder.encode(initialAdminPassword));
        admin.setUsrRole(ADMIN_ROLE);
        admin.setUsrSts("ACTIVE");
        admin.setUsrUsrId(initialAdminUsername);
        admin.setUsrWsId("WS_DEFAULT");
        admin.setUsrLocalTs(now);
        admin.setUsrHostTs(now);
        admin.setUsrPrgmId("ADMIN_BOOTSTRAP");
        admin.setUsrAcptTs(now);
        admin.setUsrAcptTsUtcOsft("+00:00");
        admin.setUsrUuid(UUID.randomUUID().toString());
        admin.setUsrCrudVal("C");

        authUserRepository.save(admin);
        // Plaintext password is never logged, returned, or persisted anywhere.
        log.info("Initial ADMIN account '{}' created.", initialAdminUsername);
    }
}
