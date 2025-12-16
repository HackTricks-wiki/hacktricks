# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Wat om te soek in CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: verskillende foute/tydverskille vir slegte padding.
- **MAC confusion**: gebruik van CBC-MAC met boodskappe van veranderlike lengte, of MAC-then-encrypt foute.
- **XOR everywhere**: stream ciphers en aangepaste konstruksies gaan dikwels neer op XOR met 'n keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Dit maak die volgende moontlik:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

As jy plaintext kan beheer en ciphertext (of cookies) kan waarneem, probeer herhaalde blocks maak (bv. baie `A`s) en kyk vir herhalings.

### CBC: Cipher Block Chaining

- CBC is **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- As die stelsel geldige padding teenoor ongeldig padding openbaar, kan jy 'n **padding oracle** hê.

### CTR

CTR turns AES into a stream cipher: `C = P XOR keystream`.

If a nonce/IV is reused with the same key:

- `C1 XOR C2 = P1 XOR P2` (klassieke keystream reuse)
- Met bekende plaintext kan jy die keystream herstel en ander ontsleutel.

### GCM

GCM breek ook sleg onder nonce reuse. As dieselfde sleutel+nonce meer as een keer gebruik word, kry jy tipies:

- Keystream reuse vir enkripsie (soos CTR), wat plaintext herstel moontlik maak as enige plaintext bekend is.
- Verlies van integriteitswaarborge. Afhangend van wat openbaar word (meervoudige boodskap/tag-paartjies onder dieselfde nonce), mag aanvallers in staat wees om tags te vervals.

Operationele riglyne:

- Beskou "nonce reuse" in AEAD as 'n kritieke kwesbaarheid.
- As jy meervoudige ciphertexts onder dieselfde nonce het, begin deur `C1 XOR C2 = P1 XOR P2` styl verhoudings te kontroleer.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` vir scripting

## ECB exploit-patrone

ECB (Electronic Code Book) enkripteer elke blok onafhanklik:

- equal plaintext blocks → equal ciphertext blocks
- this leaks struktuur en maak cut-and-paste styl-aanvalle moontlik

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

As jy verskeie kere aanmeld en **altyd dieselfde cookie kry**, kan die ciphertext deterministies wees (ECB of vaste IV).

As jy twee gebruikers skep met meestal identiese plaintext-lay-outs (bv. lang herhaalde karakters) en herhaalde ciphertext-blokke op dieselfde offsets sien, is ECB 'n hoofverdagte.

### Exploitation patterns

#### Verwydering van hele blokke

As die token-formaat iets soos `<username>|<password>` is en die blokgrens belyn is, kan jy soms 'n gebruiker skep sodat die `admin` blok belyn verskyn, en dan voorafgaande blokke verwyder om 'n geldige token vir `admin` te kry.

#### Verskuif blokke

As die backend padding/ekstra spasies (`admin` vs `admin    `) tolereer, kan jy:

- Belyn 'n blok wat `admin   ` bevat
- Ruil/hergebruik daardie ciphertext-blok in 'n ander token

## Padding Oracle

### Wat dit is

In CBC modus, as die bediener openbaar (direk of indirek) of ontsleutelde plaintext **geldige PKCS#7 padding** het, kan jy dikwels:

- Ontsleutel ciphertext sonder die sleutel
- Enkripteer gekose plaintext (vervalsing van ciphertext)

Die oracle kan wees:

- 'n Spesifieke foutboodskap
- 'n Ander HTTP status / reaksie-grootte
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
Notes:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Waarom dit werk

CBC dekripsie bereken `P[i] = D(C[i]) XOR C[i-1]`. Deur bytes in `C[i-1]` te wysig en te kyk of die padding geldig is, kan jy `P[i]` byte vir byte herstel.

## Bit-flipping in CBC

Selfs sonder 'n padding oracle is CBC malleable. As jy ciphertext blocks kan wysig en die toepassing gebruik die ontsleutelde plaintext as gestruktureerde data (bv. `role=user`), kan jy spesifieke bits omdraai om gekose plaintext-bytes op 'n gekose posisie in die volgende blok te verander.

Tipiese CTF-patroon:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- Jy teiken plaintext-bytes in `P[i+1]` omdat `P[i+1] = D(C[i+1]) XOR C[i]`

Dit is op sigself nie 'n breuk van vertroulikheid nie, maar dit is 'n algemene privilege-escalation primitive wanneer integriteit ontbreek.

## CBC-MAC

CBC-MAC is slegs veilig onder spesifieke toestande (veral **fixed-length messages** en korrekte domain separation).

### Klassieke veranderlike-lengte vervalsingspatroon

CBC-MAC word gewoonlik bereken as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

As jy tags vir gekose boodskappe kan verkry, kan jy dikwels 'n tag skep vir 'n concatenation (of verwante konstruksie) sonder om die sleutel te ken, deur misbruik te maak van hoe CBC blokke aaneenskakel.

Dit kom dikwels voor in CTF cookies/tokens wat username of role met CBC-MAC MAC.

### Veiliger alternatiewe

- Gebruik HMAC (SHA-256/512)
- Gebruik CMAC (AES-CMAC) korrek
- Sluit message length / domain separation in

## Stream ciphers: XOR and RC4

### Die mentale model

Die meeste stream cipher situasies verminder tot:

`ciphertext = plaintext XOR keystream`

Dus:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

As jy enige plaintext-segment by posisie `i` ken, kan jy keystream-bytes herstel en ander ciphertexts op daardie posisies ontsleutel.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 is a stream cipher; encrypt/decrypt are the same operation.

As jy RC4-enkripsie van bekende plaintext onder dieselfde sleutel kan kry, kan jy die keystream herstel en ander boodskappe van dieselfde lengte/offset ontsleutel.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
