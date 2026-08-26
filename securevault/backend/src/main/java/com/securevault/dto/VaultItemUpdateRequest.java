package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VaultItemUpdateRequest {
    @NotBlank
    private String title;

    @NotBlank
    private String secretData;

    @NotBlank
    private String masterPassword;
}
