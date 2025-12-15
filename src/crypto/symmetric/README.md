# Kriptografia ya Simetriki

{{#include ../../banners/hacktricks-training.md}}

## Nini cha kutafuta katika CTFs

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

### GCM

GCM also breaks badly under nonce reuse. If the same key+nonce is used more than once, you typically get:

- Keystream reuse for encryption (like CTR), enabling plaintext recovery when any plaintext is known.
- Loss of integrity guarantees. Depending on what is exposed (multiple message/tag pairs under the same nonce), attackers may be able to forge tags.

Operational guidance:

- Treat "nonce reuse" in AEAD as a critical vulnerability.
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
Notes:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Kwa nini inafanya kazi

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Kwa kubadilisha bytes katika `C[i-1]` na kuangalia ikiwa padding ni valid, unaweza kupata `P[i]` byte kwa byte.

## Bit-flipping katika CBC

Hata bila padding oracle, CBC inaweza kubadilishwa (malleable). Ikiwa unaweza kubadilisha ciphertext blocks na application inatumia decrypted plaintext kama structured data (mfano, `role=user`), unaweza kubadilisha bits maalum badilisha bytes fulani za plaintext katika nafasi unayotaka kwenye block inayofuata.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- Unadhibiti bytes katika `C[i]`
- Unalenga plaintext bytes katika `P[i+1]` kwa sababu `P[i+1] = D(C[i+1]) XOR C[i]`

Hii si uvunjaji wa usiri kwa yenyewe, lakini ni primitive ya kawaida ya privilege-escalation wakati integrity haipo.

## CBC-MAC

CBC-MAC ni salama tu chini ya masharti maalum (hasa **fixed-length messages** na correct domain separation).

### Classic variable-length forgery pattern

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Ikiwa unaweza kupata tags kwa messages unazochagua, mara nyingi unaweza kutengeneza tag kwa concatenation (au konstruksheni inayohusiana) bila kujua key, kwa kutumia jinsi CBC inavyofuatilia blocks.

Hii mara nyingi inaonekana katika CTF cookies/tokens ambazo zina-MAC username au role kwa CBC-MAC.

### Mbadala salama

- Tumia HMAC (SHA-256/512)
- Tumia CMAC (AES-CMAC) correctly
- Jumuisha message length / domain separation

## Stream ciphers: XOR and RC4

### Mfano wa kifikra

Wengi wa matukio ya stream cipher yanashuka hadi:

`ciphertext = plaintext XOR keystream`

Hivyo:

- Ikiwa unajua plaintext, unapata keystream.
- Ikiwa keystream inarudiwa (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Ikiwa unajua sehemu yoyote ya plaintext katika nafasi `i`, unaweza kupata keystream bytes na ku-decrypt ciphertexts nyingine kwenye nafasi hizo.

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 ni stream cipher; encrypt/decrypt ni operation ile ile.

Ikiwa unaweza kupata RC4 encryption ya known plaintext chini ya key ile ile, unaweza kupata keystream na ku-decrypt messages nyingine za urefu/offset ule ule.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
