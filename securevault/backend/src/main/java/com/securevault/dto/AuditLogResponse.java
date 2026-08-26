package com.securevault.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class AuditLogResponse {
    private String action;
    private boolean success;
    private LocalDateTime timestamp;
}
