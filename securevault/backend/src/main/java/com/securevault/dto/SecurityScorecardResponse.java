package com.securevault.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class SecurityScorecardResponse {
    private int totalItems;
    private int loginItems;
    private int weakPasswordCount;
    private int reusedPasswordCount;
    private boolean twoFaEnabled;
    private List<String> weakItemTitles;
    private List<String> reusedItemTitles;
}
