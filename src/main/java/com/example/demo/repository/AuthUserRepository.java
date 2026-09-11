package com.example.demo.repository;

import com.example.demo.entity.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthUserRepository extends JpaRepository<AuthUser, Long> {

    boolean existsByUsrUsername(String usrUsername);

    Optional<AuthUser> findByUsrUsername(String usrUsername);

    boolean existsByUsrEmail(String usrEmail);
}
