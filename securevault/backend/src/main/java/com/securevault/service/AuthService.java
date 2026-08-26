package com.securevault.service;

import com.securevault.dto.AuthResponse;
import com.securevault.dto.LoginRequest;
import com.securevault.dto.LoginResponse;
import com.securevault.dto.RegisterRequest;
import com.securevault.dto.RegisterResponse;
import com.securevault.entity.AuditLog;
import com.securevault.entity.User;
import com.securevault.repository.AuditLogRepository;
import com.securevault.repository.UserRepository;
import com.securevault.security.JwtUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCKOUT_MINUTES = 15;
    private static final int DEK_LENGTH_BYTES = 32; // 256-bit AES key

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final PasswordEncoder passwordEncoder;
    private final KeyDerivationService keyDerivationService;
    private final EncryptionService encryptionService;
    private final JwtUtil jwtUtil;
    private final TotpService totpService;

    public AuthService(
            UserRepository userRepository,
            AuditLogRepository auditLogRepository,
            PasswordEncoder passwordEncoder,
            KeyDerivationService keyDerivationService,
            EncryptionService encryptionService,
            JwtUtil jwtUtil,
            TotpService totpService
    ) {
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
        this.passwordEncoder = passwordEncoder;
        this.keyDerivationService = keyDerivationService;
        this.encryptionService = encryptionService;
        this.jwtUtil = jwtUtil;
        this.totpService = totpService;
    }

    public RegisterResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("An account with this email already exists");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPasswordHash(passwordEncoder.encode(request.getMasterPassword()));

        // --- Generate the one true vault key (DEK), independent of any password ---
        byte[] dek = new byte[DEK_LENGTH_BYTES];
        new SecureRandom().nextBytes(dek);
        String dekBase64 = Base64.getEncoder().encodeToString(dek);

        // --- Wrap the DEK under a key derived from the master password ---
        String masterSalt = keyDerivationService.generateSalt();
        byte[] masterKek = keyDerivationService.deriveKey(request.getMasterPassword(), masterSalt);
        EncryptionService.EncryptedPayload wrappedByMaster = encryptionService.encrypt(dekBase64, masterKek);

        // --- Wrap the SAME DEK under a key derived from a fresh recovery code ---
        String recoveryCode = generateRecoveryCode();
        String recoverySalt = keyDerivationService.generateSalt();
        byte[] recoveryKek = keyDerivationService.deriveKey(recoveryCode, recoverySalt);
        EncryptionService.EncryptedPayload wrappedByRecovery = encryptionService.encrypt(dekBase64, recoveryKek);

        user.setMasterSalt(masterSalt);
        user.setWrappedDekByMaster(wrappedByMaster.ciphertextBase64());
        user.setWrappedDekByMasterIv(wrappedByMaster.ivBase64());
        user.setRecoverySalt(recoverySalt);
        user.setWrappedDekByRecovery(wrappedByRecovery.ciphertextBase64());
        user.setWrappedDekByRecoveryIv(wrappedByRecovery.ivBase64());

        userRepository.save(user);
        log(request.getEmail(), "REGISTER_SUCCESS", true);

        String token = jwtUtil.generateToken(user.getEmail());
        // The recovery code is returned exactly once, right now. We never store it -
        // only its effect (the wrapped DEK). If lost, recovery becomes impossible,
        // same tradeoff every real zero-knowledge manager makes.
        return new RegisterResponse(token, user.getEmail(), recoveryCode);
    }

    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> {
                    log(request.getEmail(), "LOGIN_FAILED_NO_SUCH_USER", false);
                    return new IllegalArgumentException("Invalid email or password");
                });

        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(LocalDateTime.now())) {
            long minutesLeft = Duration.between(LocalDateTime.now(), user.getLockedUntil()).toMinutes() + 1;
            log(request.getEmail(), "LOGIN_BLOCKED_ACCOUNT_LOCKED", false);
            throw new IllegalArgumentException(
                    "Account locked due to repeated failed attempts. Try again in " + minutesLeft + " minute(s)."
            );
        }

        if (!passwordEncoder.matches(request.getMasterPassword(), user.getPasswordHash())) {
            user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

            if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
                user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCKOUT_MINUTES));
                user.setFailedLoginAttempts(0);
                userRepository.save(user);
                log(request.getEmail(), "ACCOUNT_LOCKED_TOO_MANY_ATTEMPTS", false);
                throw new IllegalArgumentException(
                        "Too many failed attempts. Account locked for " + LOCKOUT_MINUTES + " minutes."
                );
            }

            userRepository.save(user);
            log(request.getEmail(), "LOGIN_FAILED_WRONG_PASSWORD", false);
            throw new IllegalArgumentException("Invalid email or password");
        }

        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        if (user.isTotpEnabled()) {
            log(request.getEmail(), "LOGIN_PASSWORD_OK_2FA_PENDING", true);
            String preAuthToken = jwtUtil.generatePreAuthToken(user.getEmail());
            return new LoginResponse(true, null, preAuthToken, user.getEmail());
        }

        log(request.getEmail(), "LOGIN_SUCCESS", true);
        String token = jwtUtil.generateToken(user.getEmail());
        return new LoginResponse(false, token, null, user.getEmail());
    }

    public AuthResponse verify2fa(String preAuthToken, String code) {
        if (!jwtUtil.isValid(preAuthToken) || !jwtUtil.isPreAuthToken(preAuthToken)) {
            throw new IllegalArgumentException("Your 2FA session expired - please log in again");
        }

        String email = jwtUtil.extractEmail(preAuthToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.isTotpEnabled() || !totpService.verifyCode(user.getTotpSecret(), code)) {
            log(email, "2FA_FAILED", false);
            throw new IllegalArgumentException("Invalid authentication code");
        }

        log(email, "2FA_SUCCESS", true);
        String token = jwtUtil.generateToken(email);
        return new AuthResponse(token, email);
    }

    /**
     * Recovery flow: unwrap the DEK using the recovery code, then re-wrap
     * that SAME DEK under a freshly derived key from the new master
     * password. Because the DEK itself never changes, every existing vault
     * item stays decryptable under the new master password with zero
     * re-encryption needed.
     */
    public AuthResponse recoverAccount(String email, String recoveryCode, String newMasterPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Invalid recovery details"));

        if (user.getWrappedDekByRecovery() == null) {
            throw new IllegalArgumentException("No recovery kit found for this account");
        }

        byte[] recoveryKek = keyDerivationService.deriveKey(recoveryCode, user.getRecoverySalt());
        String dekBase64;
        try {
            dekBase64 = encryptionService.decrypt(
                    new EncryptionService.EncryptedPayload(user.getWrappedDekByRecovery(), user.getWrappedDekByRecoveryIv()),
                    recoveryKek
            );
        } catch (RuntimeException e) {
            log(email, "RECOVERY_FAILED_BAD_CODE", false);
            throw new IllegalArgumentException("Invalid recovery code");
        }

        String newMasterSalt = keyDerivationService.generateSalt();
        byte[] newMasterKek = keyDerivationService.deriveKey(newMasterPassword, newMasterSalt);
        EncryptionService.EncryptedPayload rewrapped = encryptionService.encrypt(dekBase64, newMasterKek);

        user.setPasswordHash(passwordEncoder.encode(newMasterPassword));
        user.setMasterSalt(newMasterSalt);
        user.setWrappedDekByMaster(rewrapped.ciphertextBase64());
        user.setWrappedDekByMasterIv(rewrapped.ivBase64());
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        log(email, "ACCOUNT_RECOVERED", true);
        String token = jwtUtil.generateToken(email);
        return new AuthResponse(token, email);
    }

    private String generateRecoveryCode() {
        byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).toUpperCase().replace("_", "9").replace("-", "8");
        StringBuilder grouped = new StringBuilder();
        for (int i = 0; i < raw.length() && i < 25; i++) {
            if (i > 0 && i % 5 == 0) grouped.append('-');
            grouped.append(raw.charAt(i));
        }
        return grouped.toString();
    }

    private void log(String email, String action, boolean success) {
        AuditLog entry = new AuditLog();
        entry.setUserEmail(email);
        entry.setAction(action);
        entry.setSuccess(success);
        auditLogRepository.save(entry);
    }
}
