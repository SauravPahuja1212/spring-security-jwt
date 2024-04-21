package com.swr.security.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    private UUID id;
    private String refreshToken;
    private boolean revoked;
}
