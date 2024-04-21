package com.swr.security.security.service;

import com.swr.security.dto.TokenType;
import com.swr.security.repository.RefreshTokenJpaRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final RefreshTokenJpaRepository refreshTokenJpaRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(Objects.isNull(authHeader) || authHeader.isBlank() || !authHeader.startsWith(TokenType.Bearer.name())) {
            return;
        }

        final String refreshToken = authHeader.substring(7);

        refreshTokenJpaRepository.findByRefreshToken(refreshToken)
                .map(token -> {
                    refreshTokenJpaRepository.delete(token);
                    return token;
                });
    }
}
