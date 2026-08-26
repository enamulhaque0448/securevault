package com.securevault.service;

import com.securevault.entity.ItemType;
import com.securevault.entity.User;
import com.securevault.entity.VaultItem;

import org.springframework.stereotype.Component;

@Component
public class VaultItemFactory {

    public VaultItem create(
            User owner,
            ItemType itemType,
            String title,
            EncryptionService.EncryptedPayload payload
    ) {
        VaultItem item = new VaultItem();
        item.setOwner(owner);
        item.setItemType(itemType);
        item.setTitle(title);
        item.setEncryptedData(payload.ciphertextBase64());
        item.setIv(payload.ivBase64());
        return item;
    }
}
