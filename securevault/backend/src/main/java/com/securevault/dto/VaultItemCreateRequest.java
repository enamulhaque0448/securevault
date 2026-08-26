package com.securevault.dto;

import com.securevault.entity.ItemType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VaultItemCreateRequest {
    @NotNull
    private ItemType itemType;

    @NotBlank
    private String title;

    @NotBlank
    private String secretData;

    @NotBlank
    private String masterPassword;
}
