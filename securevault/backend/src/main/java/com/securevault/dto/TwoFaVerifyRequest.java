package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TwoFaVerifyRequest {
    @NotBlank
    private String preAuthToken;

    @NotBlank
    private String code;
}
