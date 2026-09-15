package com.example.demo.security;

import com.example.demo.entity.AuthUser;
import com.example.demo.repository.AuthUserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end tests for POST /api/auth/users through the REAL security
 * filter chain (JwtAuthenticationFilter + SecurityConfig's
 * authorizeHttpRequests rules) — unlike AuthControllerTest, which uses a
 * standalone MockMvc with no security filters attached at all and so can't
 * exercise 401/403 behavior.
 *
 * CUSTOMER/BANK_OFFICER/ADMIN rows are seeded directly via the repository
 * and real tokens are minted via JwtService, rather than going through
 * /api/auth/register + /api/auth/login, so each test stays focused on
 * authorization rather than re-testing login itself.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class UserManagementSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuthUserRepository authUserRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private String adminToken;
    private String bankOfficerToken;
    private String customerToken;

    @BeforeEach
    void setUp() {
        adminToken = jwtService.generateToken(seedUser("existing_admin", "ADMIN"), "ADMIN");
        bankOfficerToken = jwtService.generateToken(seedUser("existing_officer", "BANK_OFFICER"), "BANK_OFFICER");
        customerToken = jwtService.generateToken(seedUser("existing_customer", "CUSTOMER"), "CUSTOMER");
    }

    private String seedUser(String username, String role) {
        LocalDateTime now = LocalDateTime.now();
        AuthUser user = new AuthUser();
        user.setUsrUsername(username);
        user.setUsrEmail(username + "@example.com");
        user.setUsrPasswordHash(passwordEncoder.encode("Password123!"));
        user.setUsrRole(role);
        user.setUsrSts("ACTIVE");
        user.setUsrUsrId(username);
        user.setUsrWsId("WS_DEFAULT");
        user.setUsrLocalTs(now);
        user.setUsrHostTs(now);
        user.setUsrPrgmId("TEST_SEED");
        user.setUsrAcptTs(now);
        user.setUsrAcptTsUtcOsft("+00:00");
        user.setUsrUuid(UUID.randomUUID().toString());
        user.setUsrCrudVal("C");
        authUserRepository.save(user);
        return username;
    }

    private Map<String, String> newOfficerBody(String username) {
        return Map.of(
                "username", username,
                "email", username + "@bank.com",
                "password", "Bank@123456",
                "role", "BANK_OFFICER"
        );
    }

    @Test
    void adminCanCreateBankOfficer() throws Exception {
        mockMvc.perform(post("/api/auth/users")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(newOfficerBody("new_officer_1"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("BANK_OFFICER"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void adminCanCreateAnotherAdmin() throws Exception {
        Map<String, String> body = Map.of(
                "username", "new_admin_1",
                "email", "new_admin_1@bank.com",
                "password", "Admin@123456",
                "role", "ADMIN"
        );

        mockMvc.perform(post("/api/auth/users")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    void customerCannotCreateUsers() throws Exception {
        mockMvc.perform(post("/api/auth/users")
                        .header("Authorization", "Bearer " + customerToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(newOfficerBody("new_officer_2"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void bankOfficerCannotCreateUsers() throws Exception {
        mockMvc.perform(post("/api/auth/users")
                        .header("Authorization", "Bearer " + bankOfficerToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(newOfficerBody("new_officer_3"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void missingTokenCannotCreateUsers() throws Exception {
        mockMvc.perform(post("/api/auth/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(newOfficerBody("new_officer_4"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void invalidTokenCannotCreateUsers() throws Exception {
        mockMvc.perform(post("/api/auth/users")
                        .header("Authorization", "Bearer this.is.not.a.valid.jwt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(newOfficerBody("new_officer_5"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void duplicateUsernameIsRejectedEvenForAdmin() throws Exception {
        mockMvc.perform(post("/api/auth/users")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(newOfficerBody("existing_admin"))))
                .andExpect(status().isConflict());
    }

    @Test
    void registerAndLoginRemainPublic_NoTokenNeeded() throws Exception {
        Map<String, String> registerBody = Map.of(
                "username", "public_customer_1",
                "email", "public_customer_1@example.com",
                "password", "Password123!"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerBody)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("CUSTOMER"));

        Map<String, String> loginBody = Map.of(
                "username", "public_customer_1",
                "password", "Password123!"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginBody)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("CUSTOMER"));
    }
}
