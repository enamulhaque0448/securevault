package com.securevault.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

/** recoveryCode is shown exactly once - the frontend must prompt the user to save it, then never fetch it again. */
@Getter
@AllArgsConstructor
public class RegisterResponse {
    private String token;
    private String email;
    private String recoveryCode;
}
