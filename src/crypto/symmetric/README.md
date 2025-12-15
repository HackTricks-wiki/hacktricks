# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Wat om na te soek in CTFs

- **Modus-misbruik**: ECB patrone, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: verskillende foutboodskappe/tydverskille vir slegte padding.
- **MAC confusion**: gebruik van CBC-MAC met variable-length messages, of MAC-then-encrypt fouten.
- **XOR everywhere**: stream ciphers en custom constructions val dikwels terug na XOR met 'n keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Dit maak die volgende moontlik:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

As jy plaintext kan beheer en ciphertext (of cookies) kan waarneem, probeer om herhalende blocks te maak (bv. baie `A`s) en kyk vir herhalings.

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

ECB (Electronic Code Book) enkripteer elke block onafhanklik:

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

- Belyn 'n blok wat `admin   ` bevat
- Swap/reuse that ciphertext block into another token

## Padding Oracle

### Wat dit is

In CBC mode, if the server reveals (directly or indirectly) whether decrypted plaintext has **valid PKCS#7 padding**, you can often:

- Decrypt ciphertext without the key
- Encrypt chosen plaintext (forge ciphertext)

Die oracle kan wees:

- 'n spesifieke foutboodskap
- 'n ander HTTP status / response size
- 'n tydverskil

### Praktiese uitbuiting

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Voorbeeld:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notas:

- Blokgrootte is dikwels `16` vir AES.
- `-encoding 0` beteken Base64.
- Gebruik `-error` as die oracle 'n spesifieke string is.

### Waarom dit werk

CBC dekripsie bereken `P[i] = D(C[i]) XOR C[i-1]`. Deur bytes in `C[i-1]` te wysig en te kyk of die padding geldig is, kan jy `P[i]` byte-vir-byte herstel.

## Bit-flipping in CBC

Selfs sonder 'n padding oracle is CBC vervormbaar. As jy ciphertext-blokke kan wysig en die toepassing die gedekripteerde plaintext as gestruktureerde data gebruik (bv. `role=user`), kan jy spesifieke bits omdraai om gekose plaintext-bytes op 'n gekose posisie in die volgende blok te verander.

Tipiese CTF-patroon:

- Token = `IV || C1 || C2 || ...`
- Jy beheer bytes in `C[i]`
- Jy mik op plaintext-bytes in `P[i+1]` omdat `P[i+1] = D(C[i+1]) XOR C[i]`

Dit is op sigself nie 'n skending van vertroulikheid nie, maar dit is 'n algemene privilege-escalation primitive wanneer integriteit ontbreek.

## CBC-MAC

CBC-MAC is slegs veilig onder spesifieke voorwaardes (veral **vaste-lengte boodskappe** en korrekte domeinskeiding).

### Klassieke vervalsing-patroon vir veranderlike lengte

CBC-MAC word gewoonlik soos volg bereken:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

As jy tags vir gekose boodskappe kan bekom, kan jy dikwels 'n tag vir 'n samevoeging (of verwante konstruk) saamstel sonder om die sleutel te ken, deur te misbruik hoe CBC blokke koppel.

Dit kom gereeld voor in CTF cookies/tokens wat gebruikersnaam of role met CBC-MAC beskerm.

### Veiliger alternatiewe

- Gebruik HMAC (SHA-256/512)
- Gebruik CMAC (AES-CMAC) korrek
- Sluit boodskaplengte / domeinskeiding in

## Stream ciphers: XOR and RC4

### Die mentale model

Die meeste stream cipher-situasies kom neer op:

`ciphertext = plaintext XOR keystream`

Dus:

- As jy plaintext ken, herstel jy die keystream.
- As die keystream hergebruik word (dieselfde key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

As jy enige plaintext-segment by posisie `i` ken, kan jy keystream-bytes herstel en ander ciphertexts by daardie posisies ontsleutel.

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 is 'n stream cipher; enkripsie/dekripsie is dieselfde operasie.

As jy RC4-enkripsie van bekende plaintext onder dieselfde key kan kry, kan jy die keystream herstel en ander boodskappe van dieselfde lengte/offset ontsleutel.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
