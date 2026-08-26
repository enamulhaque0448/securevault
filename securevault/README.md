# SecureVault

A zero-knowledge encrypted credential manager. Built as a combined Web
Programming + OOP (Java) project: a Spring Boot backend (OOP design,
design patterns) serving a REST API to a plain HTML/CSS/JS frontend.

## Architecture

```
Master Password
      |
      v (PBKDF2-HMAC-SHA256, 210,000 iterations)
Master KEK (Key Encryption Key)
      |
      v (unwraps, AES-256-GCM)
Data Encryption Key (DEK)  <-- random, generated once, never changes
      |
      v (AES-256-GCM, unique IV per item)
Encrypted Vault Items (stored in MySQL)
```

The server never stores the master password or the DEK. It only stores:
- A BCrypt hash of the master password (for login verification)
- The DEK, wrapped (encrypted) under a key derived from the master password
- A second copy of the DEK, wrapped under a key derived from a one-time
  recovery code

This two-wrap design means changing your master password (via account
recovery) only re-wraps the DEK — it never has to re-encrypt your actual
vault data.

## Security features implemented

- AES-256-GCM authenticated encryption (tamper-evident, unique IV per item)
- PBKDF2 key derivation (210k iterations) — the master password never
  touches the vault's actual encryption key directly
- BCrypt password hashing for login, separate from the encryption key
- JWT-based stateless auth, with a distinct short-lived "pre-auth" token
  used only during the 2FA handshake
- TOTP two-factor authentication (RFC 6238), implemented from scratch —
  no external auth library
- Account lockout after 5 failed logins (15-minute cooldown)
- Full audit log of login attempts, lockouts, and vault access
- Recovery kit: a one-time high-entropy recovery code generated at
  signup, letting a user regain access without the server ever being
  able to derive the vault key on its own
- Password strength meter + generator (random-character and
  Diceware-style passphrase modes)
- Have I Been Pwned breach check via k-Anonymity (only a 5-character hash
  prefix ever leaves the browser — the password itself never does)
- Vault security scorecard: flags weak and reused passwords, checks 2FA
  status
- Clipboard auto-clear after copying a revealed secret

## Design patterns (for the OOP course writeup)

- **Strategy** — `EncryptionService` interface / `AesEncryptionService` implementation
- **Factory** — `VaultItemFactory` centralizes VaultItem construction
- **Inheritance/polymorphism** — `Account` (abstract) → `User`
- **Single Responsibility** — key derivation, encryption, and TOTP logic
  are each their own service class

## Roadmap (not implemented — documented as future work)

These were scoped out to hit the project deadline, not because they
weren't considered:

- **Client-side key derivation (Argon2id in-browser via WebAssembly)** —
  would remove the master password from the network entirely, at the
  cost of a much larger frontend build and an in-browser crypto worker.
- **WebAuthn / FIDO2 hardware key support** — requires a real HTTPS
  domain (browsers block WebAuthn on plain `localhost` deployments) and
  device attestation handling.
- **Device/session management with IP geolocation** — needs a token
  allowlist/session table (JWTs are stateless by design) plus a
  geolocation provider integration.
- **Browser extension (Manifest V3) for autofill** — a separate codebase
  and packaging pipeline from this web app.
- **Web Workers for off-main-thread crypto** — worth doing once
  client-side Argon2id lands; not meaningful before that.

## Running locally

See the setup steps covered separately — MySQL (XAMPP), JDK 21, VS Code
with the Java + Spring Boot extensions, and Live Server for the frontend.
