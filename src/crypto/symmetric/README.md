# Cryptographie symétrique

{{#include ../../banners/hacktricks-training.md}}

## Ce qu'il faut rechercher dans les CTFs

- **Mode misuse** : motifs ECB, malléabilité CBC, réutilisation de nonce CTR/GCM.
- **Padding oracles** : erreurs/temps différents pour un bad padding.
- **MAC confusion** : utilisation de CBC-MAC avec des messages de longueur variable, ou erreurs de type MAC-then-encrypt.
- **XOR everywhere** : les stream ciphers et constructions personnalisées se réduisent souvent à XOR avec un keystream.

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

Exemple:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes :

- La taille de bloc est souvent `16` pour `AES`.
- `-encoding 0` signifie Base64.
- Utilisez `-error` si l'oracle est une chaîne spécifique.

### Pourquoi cela fonctionne

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. En modifiant les octets de `C[i-1]` et en observant si le padding est valide, vous pouvez récupérer `P[i]` octet par octet.

## Bit-flipping in CBC

Même sans padding oracle, CBC est malléable. Si vous pouvez modifier des blocs de ciphertext et que l'application utilise le plaintext déchiffré comme données structurées (par ex., `role=user`), vous pouvez inverser des bits spécifiques pour changer des octets choisis du plaintext à une position donnée dans le bloc suivant.

Schéma typique en CTF :

- Token = `IV || C1 || C2 || ...`
- Vous contrôlez des octets dans `C[i]`
- Vous ciblez des octets du plaintext dans `P[i+1]` parce que `P[i+1] = D(C[i+1]) XOR C[i]`

Ce n'est pas, en soi, une rupture de confidentialité, mais c'est une primitive d'escalade de privilèges courante lorsque l'intégrité fait défaut.

## CBC-MAC

CBC-MAC n'est sécurisé que sous conditions spécifiques (notamment **messages de longueur fixe** et séparation correcte des domaines).

### Modèle classique de falsification pour messages de longueur variable

CBC-MAC est généralement calculé comme :

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Si vous pouvez obtenir des tags pour des messages choisis, vous pouvez souvent fabriquer un tag pour une concaténation (ou une construction associée) sans connaître la clé, en exploitant la façon dont CBC enchaîne les blocs.

Cela apparaît fréquemment dans des cookies/tokens CTF qui MAC le username ou le role avec CBC-MAC.

### Alternatives plus sûres

- Utilisez HMAC (SHA-256/512)
- Utilisez CMAC (AES-CMAC) correctement
- Inclure la longueur du message / séparation de domaine

## Chiffrement par flot : XOR et RC4

### Modèle mental

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

Donc :

- Si vous connaissez le plaintext, vous récupérez le keystream.
- Si le keystream est réutilisé (même key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Si vous connaissez un segment de plaintext à la position `i`, vous pouvez récupérer les octets du keystream et déchiffrer d'autres ciphertexts à ces positions.

Auto-solveurs :

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 est un stream cipher ; encrypt/decrypt sont la même opération.

Si vous pouvez obtenir le chiffrement RC4 d'un plaintext connu sous la même key, vous pouvez récupérer le keystream et déchiffrer d'autres messages de la même longueur/décalage.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Références

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
