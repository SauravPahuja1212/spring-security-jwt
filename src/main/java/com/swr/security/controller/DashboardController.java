package com.swr.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping(value = "/api/dashboard")
public class DashboardController {

    @GetMapping(path = "/user")
    @PreAuthorize("hasAnyAuthority('READ', 'WRITE', 'DELETE')")
    public ResponseEntity<String> getUserData(Authentication authentication) {
        return ResponseEntity.ok("Welcome use - "+authentication.getName());
    }

    @GetMapping(path = "/manager")
    @PreAuthorize("hasAnyAuthority('READ', 'WRITE')")
    public ResponseEntity<String> getManagerData(Principal principal) {
        return ResponseEntity.ok("Manager::"+principal.getName());
    }

    @GetMapping(path = "/admin")
    @PreAuthorize("hasAuthority('DELETE')")
    public ResponseEntity<String> getAdminData(@RequestParam("message") String message, Principal principal) {
        return ResponseEntity.ok("Admin::"+principal.getName()+" has this message::"+message);
    }
}
