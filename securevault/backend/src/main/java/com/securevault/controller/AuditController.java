package com.securevault.controller;

import com.securevault.dto.AuditLogResponse;
import com.securevault.entity.User;
import com.securevault.repository.AuditLogRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditLogRepository auditLogRepository;

    public AuditController(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping("/me")
    public ResponseEntity<List<AuditLogResponse>> myActivity() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        List<AuditLogResponse> logs = auditLogRepository
                .findByUserEmailOrderByTimestampDesc(user.getEmail())
                .stream()
                .map(a -> new AuditLogResponse(a.getAction(), a.isSuccess(), a.getTimestamp()))
                .limit(50)
                .toList();

        return ResponseEntity.ok(logs);
    }
}
