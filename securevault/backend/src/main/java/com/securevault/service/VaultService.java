package com.securevault.service;

import com.securevault.dto.SecurityScorecardResponse;
import com.securevault.dto.VaultItemCreateRequest;
import com.securevault.dto.VaultItemRevealResponse;
import com.securevault.dto.VaultItemSummaryResponse;
import com.securevault.dto.VaultItemUpdateRequest;
import com.securevault.entity.AuditLog;
import com.securevault.entity.ItemType;
import com.securevault.entity.User;
import com.securevault.entity.VaultItem;
import com.securevault.repository.AuditLogRepository;
import com.securevault.repository.VaultItemRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class VaultService {

    private final VaultItemRepository vaultItemRepository;
    private final AuditLogRepository auditLogRepository;
    private final KeyDerivationService keyDerivationService;
    private final EncryptionService encryptionService;
    private final VaultItemFactory vaultItemFactory;

    public VaultService(
            VaultItemRepository vaultItemRepository,
            AuditLogRepository auditLogRepository,
            KeyDerivationService keyDerivationService,
            EncryptionService encryptionService,
            VaultItemFactory vaultItemFactory
    ) {
        this.vaultItemRepository = vaultItemRepository;
        this.auditLogRepository = auditLogRepository;
        this.keyDerivationService = keyDerivationService;
        this.encryptionService = encryptionService;
        this.vaultItemFactory = vaultItemFactory;
    }

    /**
     * Every vault operation starts here: derive the master-password KEK,
     * unwrap the real DEK, and use THAT to encrypt/decrypt items. Wrong
     * master password -> unwrap fails -> IllegalArgumentException, same
     * generic message every time so we don't leak which part was wrong.
     */
    private byte[] unwrapDek(User owner, String masterPassword) {
        byte[] masterKek = keyDerivationService.deriveKey(masterPassword, owner.getMasterSalt());
        try {
            String dekBase64 = encryptionService.decrypt(
                    new EncryptionService.EncryptedPayload(owner.getWrappedDekByMaster(), owner.getWrappedDekByMasterIv()),
                    masterKek
            );
            return Base64.getDecoder().decode(dekBase64);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Incorrect master password");
        }
    }

    public VaultItemSummaryResponse createItem(User owner, VaultItemCreateRequest request) {
        byte[] dek = unwrapDek(owner, request.getMasterPassword());
        EncryptionService.EncryptedPayload payload = encryptionService.encrypt(request.getSecretData(), dek);

        VaultItem item = vaultItemFactory.create(owner, request.getItemType(), request.getTitle(), payload);
        vaultItemRepository.save(item);

        log(owner.getEmail(), "VAULT_ITEM_CREATED", true);
        return toSummary(item);
    }

    public List<VaultItemSummaryResponse> listItems(User owner) {
        return vaultItemRepository.findByOwner(owner).stream()
                .map(this::toSummary)
                .toList();
    }

    public VaultItemRevealResponse revealItem(User owner, Long itemId, String masterPassword) {
        VaultItem item = vaultItemRepository.findByIdAndOwner(itemId, owner)
                .orElseThrow(() -> new IllegalArgumentException("Item not found"));

        byte[] dek = unwrapDek(owner, masterPassword);

        try {
            String secret = encryptionService.decrypt(
                    new EncryptionService.EncryptedPayload(item.getEncryptedData(), item.getIv()),
                    dek
            );
            log(owner.getEmail(), "VAULT_ITEM_VIEWED:" + itemId, true);
            return new VaultItemRevealResponse(item.getId(), item.getItemType(), item.getTitle(), secret);
        } catch (RuntimeException e) {
            log(owner.getEmail(), "VAULT_ITEM_VIEW_FAILED:" + itemId, false);
            throw new IllegalArgumentException("Incorrect master password");
        }
    }

    public VaultItemSummaryResponse updateItem(User owner, Long itemId, VaultItemUpdateRequest request) {
        VaultItem item = vaultItemRepository.findByIdAndOwner(itemId, owner)
                .orElseThrow(() -> new IllegalArgumentException("Item not found"));

        byte[] dek = unwrapDek(owner, request.getMasterPassword());
        EncryptionService.EncryptedPayload payload = encryptionService.encrypt(request.getSecretData(), dek);

        item.setTitle(request.getTitle());
        item.setEncryptedData(payload.ciphertextBase64());
        item.setIv(payload.ivBase64());
        item.setUpdatedAt(LocalDateTime.now());
        vaultItemRepository.save(item);

        log(owner.getEmail(), "VAULT_ITEM_UPDATED:" + itemId, true);
        return toSummary(item);
    }

    public void deleteItem(User owner, Long itemId) {
        VaultItem item = vaultItemRepository.findByIdAndOwner(itemId, owner)
                .orElseThrow(() -> new IllegalArgumentException("Item not found"));
        vaultItemRepository.delete(item);
        log(owner.getEmail(), "VAULT_ITEM_DELETED:" + itemId, true);
    }

    public SecurityScorecardResponse computeScorecard(User owner, String masterPassword) {
        byte[] dek = unwrapDek(owner, masterPassword);
        List<VaultItem> allItems = vaultItemRepository.findByOwner(owner);

        int weakCount = 0;
        List<String> weakTitles = new ArrayList<>();
        Map<String, List<String>> passwordToTitles = new HashMap<>();

        for (VaultItem item : allItems) {
            if (item.getItemType() != ItemType.LOGIN) continue;

            String decrypted = encryptionService.decrypt(
                    new EncryptionService.EncryptedPayload(item.getEncryptedData(), item.getIv()), dek
            );

            String password = decrypted.contains("|") ? decrypted.split("\\|", 2)[1] : decrypted;

            if (isWeak(password)) {
                weakCount++;
                weakTitles.add(item.getTitle());
            }

            passwordToTitles.computeIfAbsent(password, k -> new ArrayList<>()).add(item.getTitle());
        }

        List<String> reusedTitles = new ArrayList<>();
        int reusedCount = 0;
        for (List<String> titles : passwordToTitles.values()) {
            if (titles.size() > 1) {
                reusedCount += titles.size();
                reusedTitles.addAll(titles);
            }
        }

        log(owner.getEmail(), "SECURITY_SCORECARD_GENERATED", true);

        long loginCount = allItems.stream().filter(i -> i.getItemType() == ItemType.LOGIN).count();

        return new SecurityScorecardResponse(
                allItems.size(), (int) loginCount, weakCount, reusedCount,
                owner.isTotpEnabled(), weakTitles, reusedTitles
        );
    }

    private boolean isWeak(String password) {
        if (password.length() < 10) return true;
        int variety = 0;
        if (password.matches(".*[a-z].*")) variety++;
        if (password.matches(".*[A-Z].*")) variety++;
        if (password.matches(".*[0-9].*")) variety++;
        if (password.matches(".*[^A-Za-z0-9].*")) variety++;
        return variety < 3;
    }

    private VaultItemSummaryResponse toSummary(VaultItem item) {
        return new VaultItemSummaryResponse(
                item.getId(), item.getItemType(), item.getTitle(), item.getCreatedAt(), item.getUpdatedAt()
        );
    }

    private void log(String email, String action, boolean success) {
        AuditLog entry = new AuditLog();
        entry.setUserEmail(email);
        entry.setAction(action);
        entry.setSuccess(success);
        auditLogRepository.save(entry);
    }
}
