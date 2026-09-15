package com.example.demo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Reads "Authorization: Bearer <jwt>", validates it via JwtService, and — on
 * success — populates the SecurityContext with the username (subject) and a
 * ROLE_&lt;role&gt; authority taken from the token's "role" claim, so
 * SecurityConfig's authorizeHttpRequests rules (e.g. hasRole("ADMIN") on
 * POST /api/auth/users) have something to check.
 *
 * On a missing, malformed, expired, or tampered token, this filter does NOT
 * reject the request itself — it just leaves the SecurityContext empty and
 * lets the request continue unauthenticated. The authorization step further
 * down the chain then denies access to protected routes via
 * JwtAuthenticationEntryPoint (401). Public routes (register/login) are
 * unaffected either way, since they're permitAll().
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                     @NonNull HttpServletResponse response,
                                     @NonNull FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader(AUTH_HEADER);

        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length());
            try {
                Claims claims = jwtService.parseToken(token);
                String username = claims.getSubject();
                String role = claims.get("role", String.class);

                List<SimpleGrantedAuthority> authorities = (role == null)
                        ? List.of()
                        : List.of(new SimpleGrantedAuthority("ROLE_" + role));

                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JwtException | IllegalArgumentException ex) {
                // Expired / malformed / bad signature / anything else invalid.
                // Leave the context empty rather than failing the request here.
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }
}
