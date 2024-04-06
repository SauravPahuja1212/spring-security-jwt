package com.swr.security.controller;

import com.swr.security.dto.AuthResponseDTO;
import com.swr.security.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/api")
public class AuthController {

    private final AuthService authService;

    @GetMapping("/sign-in")
    public ResponseEntity<AuthResponseDTO> signIn(Authentication authentication) {
        return ResponseEntity.ok(authService.getJwtToken(authentication));
    }
}
