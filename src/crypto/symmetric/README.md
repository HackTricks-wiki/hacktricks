# Simetrična kriptografija

{{#include ../../banners/hacktricks-training.md}}

## Šta tražiti na CTF-ovima

- **Zloupotreba moda**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: različite greške/vremenska odstupanja za loš padding.
- **MAC confusion**: using CBC-MAC with variable-length messages, or MAC-then-encrypt mistakes.
- **XOR everywhere**: stream ciphers and custom constructions often reduce to XOR with a keystream.

## AES modovi i zloupotreba

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. That enables:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

If you can control plaintext and observe ciphertext (or cookies), try making repeated blocks (e.g., many `A`s) and look for repeats.

### CBC: Cipher Block Chaining

- CBC je **malleable**: flipovanje bitova u `C[i-1]` menja predvidljive bitove u `P[i]`.
- Ako sistem otkriva validan naspram nevalidnog paddinga, mogli biste imati **padding oracle**.

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

- jednaki plaintext blokovi → jednaki ciphertext blokovi
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

### Šta je to

U CBC modu, ako server otkriva (direktno ili indirektno) da li dekriptovani plaintext ima **valid PKCS#7 padding**, često možete:

- Dekriptovati ciphertext bez ključa
- Enkriptovati odabrani plaintext (forgovati ciphertext)

Oracle može biti:

- Specifična poruka o greški
- Drugi HTTP status / veličina odgovora
- Razlika u vremenu odgovora

### Praktična eksploatacija

PadBuster je klasičan alat:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Primer:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Veličina bloka je često `16` za AES.
- `-encoding 0` znači Base64.
- Koristite `-error` ako je oracle specifičan string.

### Zašto radi

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Modifikujući bajtove u `C[i-1]` i posmatrajući da li je padding validan, možete oporaviti `P[i]` bajt po bajt.

## Bit-flipping in CBC

Čak i bez padding oracle-a, CBC je podložan modifikacijama. Ako možete menjati blokove šifroteksta i aplikacija koristi dekriptovani plaintext kao strukturirane podatke (npr. `role=user`), možete promeniti specifične bitove da biste izmenili odabrane bajtove plaintexta na izabranoj poziciji u sledećem bloku.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- Vi kontrolišete bajtove u `C[i]`
- Ciljate bajtove plaintexta u `P[i+1]` jer `P[i+1] = D(C[i+1]) XOR C[i]`

Ovo samo po sebi nije kršenje poverljivosti, ali predstavlja uobičajen primit za eskalaciju privilegija kada nedostaje integritet.

## CBC-MAC

CBC-MAC je bezbedan samo pod specifičnim uslovima (posebno **fixed-length messages** i korektna separacija domena).

### Classic variable-length forgery pattern

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

If you can obtain tags for chosen messages, you can often craft a tag for a concatenation (or related construction) without knowing the key, by exploiting how CBC chains blocks.

Ovo se često pojavljuje u CTF cookie-ima/tokenima koji MAC-uju username ili role pomoću CBC-MAC.

### Bezbednije alternative

- Koristite HMAC (SHA-256/512)
- Koristite CMAC (AES-CMAC) ispravno
- Uključite dužinu poruke / odvajanje domena

## Stream ciphers: XOR and RC4

### Mentalni model

Većina situacija sa stream cipher-ima svodi se na:

`ciphertext = plaintext XOR keystream`

Dakle:

- Ako znate plaintext, dobijate keystream.
- Ako se keystream ponovo koristi (isti key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Ako znate bilo koji segment plaintexta na poziciji `i`, možete rekonstruisati keystream bajtove i dekriptovati druge šifrotekste na tim pozicijama.

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 je stream cipher; enkripcija/dekripcija su ista operacija.

Ako možete dobiti RC4 enkripciju poznatog plaintexta pod istim ključem, možete rekonstruisati keystream i dekriptovati druge poruke iste dužine/offseta.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
