package com.swr.security.service;

import com.swr.security.dto.AuthResponseDTO;
import com.swr.security.dto.TokenType;
import com.swr.security.repository.UserInfoJpaRepository;
import com.swr.security.security.config.JwtTokenGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserInfoJpaRepository userInfoJpaRepository;
    private final JwtTokenGenerator jwtTokenGenerator;

    public AuthResponseDTO getJwtToken(Authentication authentication) {
        try {
            var userInfo = userInfoJpaRepository.findByUsernameOrEmail(authentication.getName(), authentication.getName());
            var token = jwtTokenGenerator.generateJwtToken(authentication);

            if(userInfo.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found !");
            }

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
}
