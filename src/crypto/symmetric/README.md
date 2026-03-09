# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## What to look for in CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: different errors/timings for bad padding.
- **MAC confusion**: using CBC-MAC with variable-length messages, or MAC-then-encrypt mistakes.
- **XOR everywhere**: stream ciphers and custom constructions often reduce to XOR with a keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. That enables:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

If you can control plaintext and observe ciphertext (or cookies), try making repeated blocks (e.g., many `A`s) and look for repeats.

### CBC: Cipher Block Chaining

- CBC is **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- If the system exposes valid padding vs invalid padding, you may have a **padding oracle**.

### CTR

CTR turns AES into a stream cipher: `C = P XOR keystream`.

If a nonce/IV is reused with the same key:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- With known plaintext, you can recover the keystream and decrypt others.

**Nonce/IV reuse exploitation patterns**

- Recover keystream wherever plaintext is known/guessable:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Apply the recovered keystream bytes to decrypt any other ciphertext produced with the same key+IV at the same offsets.
- Highly structured data (e.g., ASN.1/X.509 certificates, file headers, JSON/CBOR) gives large known-plaintext regions. You can often XOR the ciphertext of the certificate with the predictable certificate body to derive keystream, then decrypt other secrets encrypted under the reused IV. See also [TLS & Certificates](../tls-and-certificates/README.md) for typical certificate layouts.
- When multiple secrets of the **same serialized format/size** are encrypted under the same key+IV, field alignment leaks even without full known plaintext. Example: PKCS#8 RSA keys of the same modulus size place prime factors at matching offsets (~99.6% alignment for 2048-bit). XORing two ciphertexts under the reused keystream isolates `p ⊕ p'` / `q ⊕ q'`, which can be brute-recovered in seconds.
- Default IVs in libraries (e.g., constant `000...01`) are a critical footgun: every encryption repeats the same keystream, turning CTR into a reused one-time pad.

**CTR malleability**

- CTR provides confidentiality only: flipping bits in ciphertext deterministically flips the same bits in plaintext. Without an authentication tag, attackers can tamper data (e.g., tweak keys, flags, or messages) undetected.
- Use AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) and enforce tag verification to catch bit-flips.

### GCM

GCM also breaks badly under nonce reuse. If the same key+nonce is used more than once, you typically get:

- Keystream reuse for encryption (like CTR), enabling plaintext recovery when any plaintext is known.
- Loss of integrity guarantees. Depending on what is exposed (multiple message/tag pairs under the same nonce), attackers may be able to forge tags.

Operational guidance:

- Treat "nonce reuse" in AEAD as a critical vulnerability.
- Misuse-resistant AEADs (e.g., GCM-SIV) reduce nonce-misuse fallout but still require unique nonces/IVs.
- If you have multiple ciphertexts under the same nonce, start by checking `C1 XOR C2 = P1 XOR P2` style relations.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) encrypts each block independently:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

If you login several times and **always get the same cookie**, the ciphertext may be deterministic (ECB or fixed IV).

If you create two users with mostly identical plaintext layouts (e.g., long repeated characters) and see repeated ciphertext blocks at the same offsets, ECB is a prime suspect.

### Exploitation patterns

#### Removing entire blocks

If the token format is something like `<username>|<password>` and the block boundary aligns, you can sometimes craft a user so the `admin` block appears aligned, then remove preceding blocks to obtain a valid token for `admin`.

#### Moving blocks

If the backend tolerates padding/extra spaces (`admin` vs `admin    `), you can:

- Align a block that contains `admin   `
- Swap/reuse that ciphertext block into another token

## Padding Oracle

### What it is

In CBC mode, if the server reveals (directly or indirectly) whether decrypted plaintext has **valid PKCS#7 padding**, you can often:

- Decrypt ciphertext without the key
- Encrypt chosen plaintext (forge ciphertext)

The oracle can be:

- A specific error message
- A different HTTP status / response size
- A timing difference

### Practical exploitation

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Σημειώσεις:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Γιατί λειτουργεί

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Με την τροποποίηση byte σε `C[i-1]` και την παρατήρηση αν το padding είναι έγκυρο, μπορείτε να ανακτήσετε το `P[i]` byte-ξεχωριστά.

## Bit-flipping σε CBC

Ακόμα και χωρίς padding oracle, το CBC είναι malleable. Αν μπορείτε να τροποποιήσετε μπλοκ του ciphertext και η εφαρμογή χρησιμοποιεί το αποκρυπτογραφημένο plaintext ως δομημένα δεδομένα (π.χ. `role=user`), μπορείτε να αντιστρέψετε (flip) συγκεκριμένα bits για να αλλάξετε επιλεγμένα plaintext bytes σε επιλεγμένη θέση στο επόμενο μπλοκ.

Τυπικό μοτίβο σε CTF:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

Αυτό από μόνο του δεν αποτελεί παραβίαση της εμπιστευτικότητας, αλλά είναι ένα κοινό primitive για privilege-escalation όταν λείπει η ακεραιότητα.

## CBC-MAC

CBC-MAC είναι ασφαλές μόνο υπό συγκεκριμένες συνθήκες (ειδικά **μηνύματα σταθερού μήκους** και σωστός διαχωρισμός πεδίου).

### Κλασικό πρότυπο πλαστογράφησης για μεταβλητό μήκος

CBC-MAC συνήθως υπολογίζεται ως:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Αν μπορείτε να αποκτήσετε tags για επιλεγμένα μηνύματα, συχνά μπορείτε να δημιουργήσετε (craft) ένα tag για μια concatenation (ή σχετική κατασκευή) χωρίς να γνωρίζετε το κλειδί, εκμεταλλευόμενοι τον τρόπο που το CBC αλυσιδώνει τα μπλοκ.

Αυτό εμφανίζεται συχνά σε CTF cookies/tokens που MAC-άρουν το username ή το role με CBC-MAC.

### Πιο ασφαλείς εναλλακτικές

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Συμπεριλάβετε το μήκος του μηνύματος / διαχωρισμό πεδίου

## Stream ciphers: XOR and RC4

### Το νοητικό μοντέλο

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

Οπότε:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Αν γνωρίζετε οποιοδήποτε τμήμα plaintext στη θέση `i`, μπορείτε να ανακτήσετε τα keystream bytes και να αποκρυπτογραφήσετε άλλα ciphertexts σε αυτές τις θέσεις.

Αυτοματοποιημένα εργαλεία:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 είναι stream cipher; η κρυπτογράφηση/αποκρυπτογράφηση είναι η ίδια λειτουργία.

Αν μπορείτε να πάρετε RC4 encryption γνωστού plaintext με το ίδιο κλειδί, μπορείτε να ανακτήσετε το keystream και να αποκρυπτογραφήσετε άλλα μηνύματα του ίδιου μήκους/offset.

Αναλυτικό writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Αναφορές

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
