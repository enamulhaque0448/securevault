package com.securevault.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class LoginResponse {
    private boolean requires2fa;
    private String token;
    private String preAuthToken;
    private String email;
}
