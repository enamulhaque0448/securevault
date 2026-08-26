package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RecoverAccountRequest {
    @NotBlank
    private String email;

    @NotBlank
    private String recoveryCode;

    @NotBlank
    @Size(min = 8, message = "New master password must be at least 8 characters")
    private String newMasterPassword;
}
