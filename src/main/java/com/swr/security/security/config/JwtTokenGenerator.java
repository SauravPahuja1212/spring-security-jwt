package com.swr.security.security.config;

import com.swr.security.constant.RoleConstant;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtTokenGenerator {

    private final JwtEncoder jwtEncoder;

    public String generateJwtToken(Authentication authentication) {
        log.info("Generating JWT Token for user :: {}", authentication.getName());

        List<String> roles = getRolesOfUser(authentication);
        List<String> permissions = getPermissionsForRoles(roles);

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("swr")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("scope", permissions)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }

    private List<String> getPermissionsForRoles(List<String> roles) {
        for(var role : roles) {
            if(role.equalsIgnoreCase(RoleConstant.ROLE_NAME_USER)) {
                return RoleConstant.ROLE_USER_PERMISSIONS;
            }

            if(role.equalsIgnoreCase(RoleConstant.ROLE_NAME_MANAGER)) {
                return RoleConstant.ROLE_MANAGER_PERMISSIONS;
            }

            if(role.equalsIgnoreCase(RoleConstant.ROLE_NAME_ADMIN)) {
                return RoleConstant.ROLE_ADMIN_PERMISSIONS;
            }
        }

        return Collections.emptyList();
    }

    private List<String> getRolesOfUser(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();
    }
}
