package com.swr.security.utility;

import com.swr.security.repository.UserInfoJpaRepository;
import com.swr.security.security.service.UserConfigService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Objects;

@Component
@RequiredArgsConstructor
public class JwtTokenUtils {

    private final UserConfigService userConfigService;

    public String getUsername(Jwt jwtToken) {
        return jwtToken.getSubject();
    }

    public boolean isTokenValid(Jwt jwtToken, UserDetails userDetail) {
        final String username = getUsername(jwtToken);
        boolean isTokenExpired = isTokenExpired(jwtToken);
        boolean isUserValid = username.equals(userDetail.getUsername());

        return !isTokenExpired && isUserValid;
    }

    private boolean isTokenExpired(Jwt jwtToken) {
        return Objects.requireNonNull(jwtToken.getExpiresAt()).isBefore(Instant.now());
    }
}
