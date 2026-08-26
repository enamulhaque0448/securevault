package com.securevault.controller;

import com.securevault.dto.TotpDisableRequest;
import com.securevault.dto.TotpEnableRequest;
import com.securevault.dto.TotpSetupResponse;
import com.securevault.entity.User;
import com.securevault.repository.UserRepository;
import com.securevault.service.TotpService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@RestController
@RequestMapping("/api/2fa")
public class TwoFactorController {

    private final TotpService totpService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public TwoFactorController(TotpService totpService, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.totpService = totpService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/setup")
    public ResponseEntity<TotpSetupResponse> setup() {
        User user = currentUser();
        String secret = totpService.generateSecret();
        user.setTotpSecret(secret);
        user.setTotpEnabled(false);
        userRepository.save(user);

        String otpauthUrl = totpService.buildOtpAuthUrl("SecureVault", user.getEmail(), secret);
        String qrImageUrl = "https://api.qrserver.com/v1/create-qr-code/?size=220x220&data="
                + URLEncoder.encode(otpauthUrl, StandardCharsets.UTF_8);

        return ResponseEntity.ok(new TotpSetupResponse(secret, otpauthUrl, qrImageUrl));
    }

    @PostMapping("/enable")
    public ResponseEntity<Map<String, String>> enable(@Valid @RequestBody TotpEnableRequest request) {
        User user = currentUser();
        if (user.getTotpSecret() == null || !totpService.verifyCode(user.getTotpSecret(), request.getCode())) {
            throw new IllegalArgumentException("Invalid code - check your authenticator app and try again");
        }
        user.setTotpEnabled(true);
        userRepository.save(user);
        return ResponseEntity.ok(Map.of("status", "2FA enabled"));
    }

    @PostMapping("/disable")
    public ResponseEntity<Map<String, String>> disable(@Valid @RequestBody TotpDisableRequest request) {
        User user = currentUser();
        if (!passwordEncoder.matches(request.getMasterPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Incorrect master password");
        }
        user.setTotpEnabled(false);
        user.setTotpSecret(null);
        userRepository.save(user);
        return ResponseEntity.ok(Map.of("status", "2FA disabled"));
    }

    private User currentUser() {
        return (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadRequest(IllegalArgumentException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.getMessage()));
    }
}
