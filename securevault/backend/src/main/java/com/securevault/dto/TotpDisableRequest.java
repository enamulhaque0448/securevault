package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TotpDisableRequest {
    @NotBlank
    private String masterPassword;
}
