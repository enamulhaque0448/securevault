package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RevealRequest {
    @NotBlank
    private String masterPassword;
}
