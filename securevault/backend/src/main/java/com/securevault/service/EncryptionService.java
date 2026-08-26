package com.securevault.service;

public interface EncryptionService {
    EncryptedPayload encrypt(String plaintext, byte[] key);
    String decrypt(EncryptedPayload payload, byte[] key);
    record EncryptedPayload(String ciphertextBase64, String ivBase64) {}
}
