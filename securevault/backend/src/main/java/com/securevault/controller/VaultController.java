package com.securevault.controller;

import com.securevault.dto.RevealRequest;
import com.securevault.dto.SecurityScorecardResponse;
import com.securevault.dto.VaultItemCreateRequest;
import com.securevault.dto.VaultItemRevealResponse;
import com.securevault.dto.VaultItemSummaryResponse;
import com.securevault.dto.VaultItemUpdateRequest;
import com.securevault.entity.User;
import com.securevault.service.VaultService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/vault")
public class VaultController {

    private final VaultService vaultService;

    public VaultController(VaultService vaultService) {
        this.vaultService = vaultService;
    }

    @PostMapping
    public ResponseEntity<VaultItemSummaryResponse> create(@Valid @RequestBody VaultItemCreateRequest request) {
        return ResponseEntity.ok(vaultService.createItem(currentUser(), request));
    }

    @GetMapping
    public ResponseEntity<List<VaultItemSummaryResponse>> list() {
        return ResponseEntity.ok(vaultService.listItems(currentUser()));
    }

    @PostMapping("/{id}/reveal")
    public ResponseEntity<VaultItemRevealResponse> reveal(
            @PathVariable Long id, @Valid @RequestBody RevealRequest request
    ) {
        return ResponseEntity.ok(vaultService.revealItem(currentUser(), id, request.getMasterPassword()));
    }

    @PutMapping("/{id}")
    public ResponseEntity<VaultItemSummaryResponse> update(
            @PathVariable Long id, @Valid @RequestBody VaultItemUpdateRequest request
    ) {
        return ResponseEntity.ok(vaultService.updateItem(currentUser(), id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        vaultService.deleteItem(currentUser(), id);
        return ResponseEntity.noContent().build();
    }

    /** Requires master password since the server can't inspect vault contents without it. */
    @PostMapping("/security-scorecard")
    public ResponseEntity<SecurityScorecardResponse> scorecard(@Valid @RequestBody RevealRequest request) {
        return ResponseEntity.ok(vaultService.computeScorecard(currentUser(), request.getMasterPassword()));
    }

    private User currentUser() {
        return (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadRequest(IllegalArgumentException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.getMessage()));
    }
}
