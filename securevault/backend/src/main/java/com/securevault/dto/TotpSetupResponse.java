package com.securevault.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TotpSetupResponse {
    private String secret;
    private String otpauthUrl;
    private String qrImageUrl;
}
