package com.securevault.dto;

import com.securevault.entity.ItemType;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class VaultItemSummaryResponse {
    private Long id;
    private ItemType itemType;
    private String title;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
