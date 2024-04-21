package com.swr.security.service;

import com.swr.security.dto.AuthResponseDTO;
import com.swr.security.dto.TokenType;
import com.swr.security.entity.RefreshTokenEntity;
import com.swr.security.entity.UserEntity;
import com.swr.security.repository.RefreshTokenJpaRepository;
import com.swr.security.repository.UserInfoJpaRepository;
import com.swr.security.security.config.JwtTokenGenerator;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Objects;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserInfoJpaRepository userInfoJpaRepository;
    private final RefreshTokenJpaRepository refreshTokenJpaRepository;
    private final JwtTokenGenerator jwtTokenGenerator;

    public AuthResponseDTO getJwtToken(Authentication authentication, HttpServletResponse response) {
        try {
            var userInfo = userInfoJpaRepository.findByUsernameOrEmail(authentication.getName(), authentication.getName());
            if(userInfo.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found !");
            }

            var token = jwtTokenGenerator.generateJwtToken(authentication);
            var refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            //Persist this refresh token in database
            persistRefreshToken(refreshToken, userInfo.get());

            //We will add refresh token in Http-Only cookie
            createRefreshTokenCookie(refreshToken, response);

            log.info("Generating JWT Token for user :: {}", authentication.getName());

            return AuthResponseDTO.builder()
                    .accessToken(token)
                    .accessTokenExpiry(15 * 60)
                    .username(userInfo.get().getUsername())
                    .tokenType(TokenType.Bearer)
                    .build();
        } catch (Exception e) {
            log.error("Error while generating JWT Token for user :: {}", authentication.getName());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
    }

    private void createRefreshTokenCookie(String refreshToken, HttpServletResponse response) {
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);

        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60);

        response.addCookie(refreshTokenCookie);
    }

    private void persistRefreshToken(String refreshToken, UserEntity userInfo) {
        RefreshTokenEntity refreshTokenEntity = RefreshTokenEntity.builder()
                .user(userInfo)
                .refreshToken(refreshToken)
                .revoked(false)
                .build();

        refreshTokenJpaRepository.save(refreshTokenEntity);
    }

    public AuthResponseDTO getJwtTokenFromRefreshToken(String authHeader) {
        if(Objects.isNull(authHeader) || authHeader.isBlank() || !authHeader.startsWith(TokenType.Bearer.name())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        final String refreshToken = authHeader.substring(7);

        var refreshTokenEntity = refreshTokenJpaRepository.findByRefreshToken(refreshToken)
                .filter(token -> !token.isRevoked())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));

        UserEntity userEntity = refreshTokenEntity.getUser();

        Authentication authentication = getAuthenticationObject(userEntity);

        String jwtToken = jwtTokenGenerator.generateJwtToken(authentication);

        return AuthResponseDTO.builder()
                .accessToken(jwtToken)
                .accessTokenExpiry(15 * 60)
                .username(userEntity.getUsername())
                .tokenType(TokenType.Bearer)
                .build();
    }

    private Authentication getAuthenticationObject(UserEntity userEntity) {
        var grantedAuthorities = userEntity.getUserRoles().stream().map(role ->
                new SimpleGrantedAuthority(role.getRoleName())).toList();

        return new UsernamePasswordAuthenticationToken(userEntity.getUsername(), userEntity.getPassword(), grantedAuthorities);
    }
}
