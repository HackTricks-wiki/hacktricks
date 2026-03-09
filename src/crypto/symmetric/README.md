# Criptografía simétrica

{{#include ../../banners/hacktricks-training.md}}

## Qué buscar en CTFs

- **Mode misuse**: patrones ECB, malleabilidad CBC, CTR/GCM nonce reuse.
- **Padding oracles**: diferentes errores/tiempos para padding incorrecto.
- **MAC confusion**: uso de CBC-MAC con mensajes de longitud variable, o errores de MAC-then-encrypt.
- **XOR everywhere**: stream ciphers y construcciones custom a menudo se reducen a XOR con un keystream.

## Modos AES y uso indebido

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. That enables:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

Si puedes controlar plaintext y observar ciphertext (o cookies), intenta crear bloques repetidos (p.ej., muchos `A`s) y busca repeticiones.

### CBC: Cipher Block Chaining

- CBC is **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Si el sistema expone padding válido vs padding inválido, podrías tener un **padding oracle**.

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

Guidance operacional:

- Trata la "nonce reuse" en AEAD como una vulnerabilidad crítica.
- Misuse-resistant AEADs (e.g., GCM-SIV) reducen el impacto de nonce-misuse pero aún requieren nonces/IVs únicos.
- Si tienes múltiples ciphertexts bajo el mismo nonce, empieza comprobando relaciones del estilo `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef para experimentos rápidos: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` para scripting

## ECB exploitation patterns

ECB (Electronic Code Book) encrypts each block independently:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Si inicias sesión varias veces y **siempre obtienes la misma cookie**, el ciphertext puede ser determinista (ECB o IV fijo).

Si creas dos usuarios con layouts de plaintext mayormente idénticos (p.ej., largos caracteres repetidos) y ves bloques de ciphertext repetidos en las mismas posiciones, ECB es el principal sospechoso.

### Exploitation patterns

#### Removing entire blocks

Si el formato del token es algo como `<username>|<password>` y el límite de bloque se alinea, a veces puedes crear un usuario de manera que el bloque `admin` aparezca alineado, luego eliminar los bloques anteriores para obtener un token válido para `admin`.

#### Moving blocks

Si el backend tolera padding/espacios extra (`admin` vs `admin    `), puedes:

- Alinear un bloque que contenga `admin   `
- Intercambiar/reutilizar ese bloque de ciphertext en otro token

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
Notas:

- El tamaño de bloque suele ser `16` para AES.
- `-encoding 0` significa Base64.
- Usa `-error` si el oracle es una cadena específica.

### Por qué funciona

El descifrado CBC calcula `P[i] = D(C[i]) XOR C[i-1]`. Al modificar bytes en `C[i-1]` y observar si el padding es válido, puedes recuperar `P[i]` byte por byte.

## Bit-flipping en CBC

Even without a padding oracle, CBC is malleable. If you can modify ciphertext blocks and the application uses the decrypted plaintext as structured data (e.g., `role=user`), you can flip specific bits to change selected plaintext bytes at a chosen position in the next block.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

This is not a break of confidentiality by itself, but it is a common privilege-escalation primitive when integrity is missing.

## CBC-MAC

CBC-MAC es seguro solo bajo condiciones específicas (notablemente **mensajes de longitud fija** y separación de dominios correcta).

### Classic variable-length forgery pattern

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

If you can obtain tags for chosen messages, you can often craft a tag for a concatenation (or related construction) without knowing the key, by exploiting how CBC chains blocks.

This frequently appears in CTF cookies/tokens that MAC username or role with CBC-MAC.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### Modelo mental

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

So:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

If you know any plaintext segment at position `i`, you can recover keystream bytes and decrypt other ciphertexts at those positions.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 es un stream cipher; encrypt/decrypt son la misma operación.

Si puedes obtener RC4 encryption de plaintext conocido bajo la misma key, puedes recuperar el keystream y descifrar otros mensajes de la misma longitud/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
