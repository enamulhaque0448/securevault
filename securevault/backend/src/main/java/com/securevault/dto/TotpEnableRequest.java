package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TotpEnableRequest {
    @NotBlank
    private String code;
}
