package com.swr.security.dto;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponseDTO {

    private String accessToken;
    private int accessTokenExpiry;
    private TokenType tokenType;
    private String username;
}
