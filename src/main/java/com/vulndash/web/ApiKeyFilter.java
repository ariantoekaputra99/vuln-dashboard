package com.vulndash.web;

import com.vulndash.config.VulnDashProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Set;

/**
 * Autentikasi sederhana berbasis header {@code X-API-Key}.
 * Operasi tulis (POST/PUT/PATCH/DELETE) di /api/** selalu wajib; operasi baca wajib bila protect-reads=true.
 * Perbandingan dilakukan constant-time untuk menghindari timing attack.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class ApiKeyFilter extends OncePerRequestFilter {

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    private final byte[] expected;
    private final boolean protectReads;

    public ApiKeyFilter(VulnDashProperties props) {
        this.expected = props.security().apiKey().getBytes(StandardCharsets.UTF_8);
        this.protectReads = props.security().protectReads();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        boolean needsKey = !SAFE_METHODS.contains(req.getMethod()) || protectReads;
        if (needsKey) {
            String provided = req.getHeader("X-API-Key");
            boolean ok = provided != null && MessageDigest.isEqual(expected, provided.getBytes(StandardCharsets.UTF_8));
            if (!ok) {
                res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                res.setContentType("application/problem+json");
                res.getWriter().write("{\"status\":401,\"title\":\"Unauthorized\",\"detail\":\"X-API-Key tidak valid atau tidak ada\"}");
                return;
            }
        }
        chain.doFilter(req, res);
    }
}
