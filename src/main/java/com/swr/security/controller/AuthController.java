package com.swr.security.controller;

import com.swr.security.dto.AuthResponseDTO;
import com.swr.security.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/api")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/sign-in")
    public ResponseEntity<AuthResponseDTO> signIn(Authentication authentication, HttpServletResponse response) {
        return ResponseEntity.ok(authService.getJwtToken(authentication, response));
    }

    @PostMapping("/refresh-token")
    @PreAuthorize("hasAuthority('REFRESH_TOKEN')")
    public ResponseEntity<AuthResponseDTO> getAccessToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        return ResponseEntity.ok(authService.getJwtTokenFromRefreshToken(authHeader));
    }
}
