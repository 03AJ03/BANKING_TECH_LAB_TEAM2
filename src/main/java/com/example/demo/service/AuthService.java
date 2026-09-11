package com.example.demo.service;

import com.example.demo.dto.RegistrationRequest;
import com.example.demo.dto.RegistrationResponse;
import com.example.demo.entity.AuthUser;
import com.example.demo.exception.UsernameAlreadyExistsException;
import com.example.demo.repository.AuthUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class AuthService {

    private final AuthUserRepository authUserRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(AuthUserRepository authUserRepository, PasswordEncoder passwordEncoder) {
        this.authUserRepository = authUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public RegistrationResponse register(RegistrationRequest request) {
        if (authUserRepository.existsByUsrUsername(request.getUsername())) {
            throw new UsernameAlreadyExistsException("Username '" + request.getUsername() + "' is already registered");
        }

        String hashedPassword = passwordEncoder.encode(request.getPassword());

        LocalDateTime now = LocalDateTime.now();

        AuthUser authUser = new AuthUser();
        authUser.setUsrUsername(request.getUsername());
        authUser.setUsrEmail(request.getEmail());
        authUser.setUsrPasswordHash(hashedPassword);
        authUser.setUsrRole("USER");
        authUser.setUsrSts("ACTIVE");
        authUser.setUsrUsrId(request.getUsername());
        authUser.setUsrWsId("WS_DEFAULT");
        authUser.setUsrLocalTs(now);
        authUser.setUsrHostTs(now);
        authUser.setUsrPrgmId("REGISTRATION_MODULE");
        authUser.setUsrAcptTs(now);
        authUser.setUsrAcptTsUtcOsft("+00:00");
        authUser.setUsrUuid(UUID.randomUUID().toString());
        authUser.setUsrCrudVal("C");

        AuthUser savedUser = authUserRepository.save(authUser);

        return new RegistrationResponse(
                savedUser.getUsrId(),
                savedUser.getUsrUsername(),
                savedUser.getUsrEmail(),
                savedUser.getUsrRole(),
                savedUser.getUsrSts()
        );
    }
}
