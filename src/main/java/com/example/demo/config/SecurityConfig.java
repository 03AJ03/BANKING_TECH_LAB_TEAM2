package com.example.demo.config;

import com.example.demo.security.JwtAccessDeniedHandler;
import com.example.demo.security.JwtAuthenticationEntryPoint;
import com.example.demo.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
     * Previously this class only exposed the PasswordEncoder bean — there
     * was no SecurityFilterChain at all, so nothing was actually validating
     * incoming Bearer tokens or restricting any endpoint. This bean is the
     * piece that was missing: it wires JwtAuthenticationFilter into the
     * chain, keeps /api/auth/register and /api/auth/login public, requires
     * ADMIN for /api/auth/users, and requires (at minimum) a valid JWT for
     * anything else — matching the swagger spec's global bearerAuth
     * requirement, which only register/login opt out of.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                     JwtAuthenticationFilter jwtAuthenticationFilter,
                                                     JwtAuthenticationEntryPoint authenticationEntryPoint,
                                                     JwtAccessDeniedHandler accessDeniedHandler) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/auth/register", "/api/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/users").hasRole("ADMIN")
                        // Everything else (e.g. the customer module, still to be built by
                        // the rest of the team) requires at least a valid JWT, per the
                        // swagger spec's global "security: [bearerAuth: []]" requirement.
                        .anyRequest().authenticated()
                )
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
