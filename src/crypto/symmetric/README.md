# Simmetriese Kripto

{{#include ../../banners/hacktricks-training.md}}

## Waarna om in CTFs te kyk

- **Mode misuse**: ECB-patrone, CBC-malleability, CTR/GCM-nonce-hergebruik.
- **Padding oracles**: verskillende foute/tydsberekeninge vir verkeerde padding.
- **MAC confusion**: die gebruik van CBC-MAC met boodskappe van veranderlike lengte, of MAC-then-encrypt-foute.
- **XOR oral**: stream ciphers en custom constructions reduseer dikwels tot XOR met ’n keystream.

## AES-modes en misuse

### ECB: Electronic Codebook

ECB leks patrone: gelyke plaintext-blokke → gelyke ciphertext-blokke. Dit maak die volgende moontlik:

- Cut-and-paste / block reordering
- Block deletion (indien die formaat geldig bly)

As jy plaintext kan beheer en ciphertext (of cookies) kan waarneem, probeer om herhaalde blokke te maak (bv. baie `A`s) en kyk vir herhalings.

### CBC: Cipher Block Chaining

- CBC is **malleable**: die omkeer van bisse in `C[i-1]` keer voorspelbare bisse in `P[i]` om.
- As die system valid padding teenoor invalid padding blootlê, het jy moontlik ’n **padding oracle**.

### CTR

CTR verander AES in ’n stream cipher: `C = P XOR keystream`.

As ’n nonce/IV met dieselfde key hergebruik word:

- `C1 XOR C2 = P1 XOR P2` (klassieke keystream-hergebruik)
- Met bekende plaintext kan jy die keystream herwin en ander eenhede decrypt.

**Nonce/IV-hergebruik exploitation patterns**

- Herwin die keystream waar plaintext bekend/voorspelbaar is:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Pas die herwonne keystream-bytes toe om enige ander ciphertext te decrypt wat met dieselfde key+IV by dieselfde offsets geproduseer is.
- Hoogs gestruktureerde data (bv. ASN.1/X.509-sertifikate, file headers, JSON/CBOR) verskaf groot known-plaintext-gebiede. Jy kan dikwels die ciphertext van die sertifikaat met die voorspelbare sertifikaatliggaam XOR om die keystream af te lei, en dan ander secrets te decrypt wat onder die hergebruikte IV encrypted is. Sien ook [TLS & Certificates](../tls-and-certificates/README.md) vir tipiese sertifikaat-uitlegte.<sup>[[1]](#references)</sup>
- Wanneer verskeie secrets van dieselfde **serialized format/size** onder dieselfde key+IV encrypted word, lek field alignment selfs sonder volledige known plaintext. Voorbeeld: PKCS#8 RSA-keys van dieselfde modulus-grootte plaas priemfaktore by ooreenstemmende offsets (~99.6% alignment vir 2048-bit). Deur twee ciphertexts onder die hergebruikte keystream te XOR, word `p ⊕ p'` / `q ⊕ q'` geïsoleer, wat binne sekondes deur brute force herwin kan word.<sup>[[1]](#references)</sup>
- Default IVs in libraries (bv. konstante `000...01`) is ’n kritieke footgun: elke encryption herhaal dieselfde keystream, wat CTR in ’n hergebruikte one-time pad verander.<sup>[[1]](#references)</sup>

**CTR-malleability**

- CTR bied slegs confidentiality: die omkeer van bisse in ciphertext keer deterministies dieselfde bisse in plaintext om. Sonder ’n authentication tag kan attackers data tamper (bv. keys, flags of boodskappe verander) sonder opsporing.
- Gebruik AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, ens.) en dwing tag verification af om bit-flips op te spoor.

### GCM

GCM breek ook ernstig onder nonce-hergebruik. As dieselfde key+nonce meer as een keer gebruik word, kry jy tipies:

- Keystream-hergebruik vir encryption (soos CTR), wat plaintext recovery moontlik maak wanneer enige plaintext bekend is.
- Verlies van integrity guarantees. Afhangend van wat blootgelê word (multiple message/tag pairs onder dieselfde nonce), kan attackers moontlik tags forge.

Operational guidance:

- Behandel "nonce reuse" in AEAD as ’n kritieke vulnerability.
- Misuse-resistant AEADs (bv. GCM-SIV) verminder die gevolge van nonce-misuse, maar vereis steeds unieke nonces/IVs.
- As jy verskeie ciphertexts onder dieselfde nonce het, begin deur verhoudings in die styl van `C1 XOR C2 = P1 XOR P2` na te gaan.

### Tools

- CyberChef vir vinnige eksperimente: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` vir scripting

## ECB exploitation patterns

ECB (Electronic Code Book) encrypt elke blok onafhanklik:

- gelyke plaintext-blokke → gelyke ciphertext-blokke
- dit lek struktuur en maak cut-and-paste-styl-aanvalle moontlik

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

As jy verskeie kere login en **altyd dieselfde cookie kry**, kan die ciphertext deterministies wees (ECB of fixed IV).

As jy twee users met meestal identiese plaintext-layouts skep (bv. lang herhaalde karakters) en herhaalde ciphertext-blokke by dieselfde offsets sien, is ECB ’n primêre verdagte.

### Exploitation patterns

#### Removing entire blocks

As die token-formaat iets soos `<username>|<password>` is en die blokgrens align, kan jy soms ’n user craft sodat die `admin`-blok aligned verskyn, en dan voorafgaande blokke remove om ’n valid token vir `admin` te verkry.

#### Moving blocks

As die backend padding/ekstra spasies verdra (`admin` teenoor `admin    `), kan jy:

- ’n Blok align wat `admin   ` bevat
- Daardie ciphertext-blok in ’n ander token swap/reuse

## Padding Oracle

### Wat dit is

In CBC mode, as die server direk of indirek openbaar of decrypted plaintext **valid PKCS#7 padding** het, kan jy dikwels:

- Ciphertext sonder die key decrypt
- Chosen plaintext encrypt (ciphertext forge)

Die oracle kan wees:

- ’n Spesifieke foutboodskap
- ’n Verskillende HTTP-status / response-grootte
- ’n Tydsberekeningsverskil

### Praktiese exploitation

PadBuster is die klassieke tool:

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

CBC-dekripsie bereken `P[i] = D(C[i]) XOR C[i-1]`. Deur grepe in `C[i-1]` te wysig en dop te hou of die padding geldig is, kan jy `P[i]` greep vir greep herwin.

## Bit-flipping in CBC

Selfs sonder 'n padding oracle is CBC manipuleerbaar. As jy ciphertext-blokke kan wysig en die toepassing die gedekripteerde plaintext as gestruktureerde data gebruik (bv. `role=user`), kan jy spesifieke bisse omkeer om geselekteerde plaintext-grepe op 'n gekose posisie in die volgende blok te verander.

Tipiese CTF-patroon:

- Token = `IV || C1 || C2 || ...`
- Jy beheer grepe in `C[i]`
- Jy teiken plaintext-grepe in `P[i+1]` omdat `P[i+1] = D(C[i+1]) XOR C[i]`

Dit is nie op sigself 'n verbreking van confidentiality nie, maar dit is 'n algemene privilege-escalation-primitive wanneer integriteit ontbreek.

## CBC-MAC

CBC-MAC is slegs onder spesifieke toestande veilig (veral **fixed-length messages** en korrekte domain separation).

### Classic variable-length forgery pattern

CBC-MAC word gewoonlik soos volg bereken:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

As jy tags vir gekose boodskappe kan bekom, kan jy dikwels 'n tag vir 'n concatenation (of verwante konstruksie) skep sonder om die key te ken, deur uit te buit hoe CBC blokke aan mekaar koppel.

Dit verskyn dikwels in CTF-cookies/tokens wat 'n username of role met CBC-MAC MAC.

### Veiliger alternatiewe

- Gebruik HMAC (SHA-256/512)
- Gebruik CMAC (AES-CMAC) korrek
- Sluit message length / domain separation in

## Stream ciphers: XOR and RC4

### Die mental model

Die meeste stream cipher-situasies reduseer tot:

`ciphertext = plaintext XOR keystream`

Dus:

- As jy plaintext ken, herwin jy die keystream.
- As die keystream hergebruik word (dieselfde key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

As jy enige plaintext-segment op posisie `i` ken, kan jy keystream-grepe herwin en ander ciphertexts op daardie posisies dekripteer.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 is 'n stream cipher; encrypt/decrypt is dieselfde operasie.

As jy RC4-enkripsie van bekende plaintext onder dieselfde key kan verkry, kan jy die keystream herwin en ander boodskappe van dieselfde lengte/offset dekripteer.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
