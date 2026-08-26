package com.securevault.dto;

import com.securevault.entity.ItemType;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class VaultItemRevealResponse {
    private Long id;
    private ItemType itemType;
    private String title;
    private String secretData;
}
