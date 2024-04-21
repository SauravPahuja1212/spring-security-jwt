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
import java.util.ArrayList;
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

    public String generateRefreshToken(Authentication authentication) {
        log.info("Generating refersh token for user :: " + authentication.getName());

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuer("swr")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(15, ChronoUnit.DAYS))
                .subject(authentication.getName())
                .claim("scope", "REFRESH_TOKEN")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
    }

    private List<String> getPermissionsForRoles(List<String> roles) {
        //Initialized with default size of max permissions available in system
        var permissions = new ArrayList<String>(RoleConstant.ROLE_ADMIN_PERMISSIONS.size());

        for(var role : roles) {
            if(role.equalsIgnoreCase(RoleConstant.ROLE_NAME_ADMIN)) {
                permissions.addAll(RoleConstant.ROLE_ADMIN_PERMISSIONS);
            }

            if(role.equalsIgnoreCase(RoleConstant.ROLE_NAME_MANAGER)) {
                permissions.addAll(RoleConstant.ROLE_MANAGER_PERMISSIONS);
            }

            if(role.equalsIgnoreCase(RoleConstant.ROLE_NAME_USER)) {
                permissions.addAll(RoleConstant.ROLE_USER_PERMISSIONS);
            }
        }

        return permissions;
    }

    private List<String> getRolesOfUser(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();
    }
}
