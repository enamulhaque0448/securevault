package com.securevault.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Key architecture (DEK/KEK pattern, same approach real password managers
 * like Bitwarden use):
 *
 * - A single random Data Encryption Key (DEK) is generated once at
 *   registration. It's the ONLY key ever used to encrypt/decrypt vault
 *   items, for the account's entire lifetime.
 * - The DEK is never stored directly. Instead it's "wrapped" (encrypted)
 *   under TWO separate Key Encryption Keys (KEKs):
 *     1. masterKek, derived via PBKDF2 from the master password + masterSalt
 *     2. recoveryKek, derived via PBKDF2 from the recovery code + recoverySalt
 * - This means changing the master password (via recovery) only requires
 *   re-wrapping the DEK under a new masterKek - the DEK itself, and every
 *   vault item encrypted with it, never has to change.
 */
@Entity
@Table(name = "users")
@Getter
@Setter
public class User extends Account {

    private String masterSalt;
    private String wrappedDekByMaster;
    private String wrappedDekByMasterIv;

    private String recoverySalt;
    private String wrappedDekByRecovery;
    private String wrappedDekByRecoveryIv;

    private int failedLoginAttempts = 0;
    private LocalDateTime lockedUntil;

    private String totpSecret;
    private boolean totpEnabled = false;

    @OneToMany(mappedBy = "owner", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<VaultItem> vaultItems = new ArrayList<>();

    @Override
    public String getAccountType() {
        return "PERSONAL";
    }
}
