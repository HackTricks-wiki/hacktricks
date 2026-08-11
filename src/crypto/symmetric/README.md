# Simmetriese Crypto

{{#include ../../banners/hacktricks-training.md}}

## Waarna om in CTFs te kyk

- **Mode misuse**: ECB-patrone, CBC-malleability, CTR/GCM nonce reuse.
- **Padding oracles**: verskillende foute/tydsberekeninge vir verkeerde padding.
- **MAC confusion**: die gebruik van CBC-MAC met boodskappe van veranderlike lengte, of MAC-then-encrypt-foute.
- **XOR everywhere**: stream ciphers en custom constructions reduseer dikwels tot XOR met ’n keystream.

## AES modes en misuse

NIST spesifiseer die ECB-, CBC- en CTR-confidentiality modes in SP 800-38A, en GCM authenticated encryption in SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB leks patrone: gelyke plaintext blocks → gelyke ciphertext blocks. Dit maak die volgende moontlik:

- Cut-and-paste / block reordering
- Block deletion (indien die formaat geldig bly)

As jy plaintext kan beheer en ciphertext (of cookies) kan waarneem, probeer om herhaalde blocks te maak (bv. baie `A`s) en kyk vir herhalings.

### CBC: Cipher Block Chaining

- CBC is **malleable**: deur bits in `C[i-1]` om te draai, word voorspelbare bits in `P[i]` omgedraai, terwyl `P[i-1]` ook beskadig word. Deur die IV te wysig, teiken jy die eerste plaintext block sonder om ’n vroeëre plaintext block te beskadig.
- As die stelsel geldige padding teenoor ongeldige padding blootstel, het jy moontlik ’n **padding oracle**.

### CTR

CTR verander AES in ’n stream cipher: `C = P XOR keystream`.

As ’n nonce/IV met dieselfde key hergebruik word:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Met bekende plaintext kan jy die keystream herwin en ander boodskappe decrypt.

**Nonce/IV reuse exploitation patterns**

- Herwin die keystream waar plaintext bekend/voorspelbaar is:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Pas die herwinde keystream-bytes toe om enige ander ciphertext wat met dieselfde key+IV op dieselfde offsets geproduseer is, te decrypt.
- Hoogs gestruktureerde data (bv. ASN.1/X.509 certificates, file headers, JSON/CBOR) bied groot bekende-plaintext-gebiede. Jy kan dikwels die ciphertext van die certificate met die voorspelbare certificate body XOR om die keystream af te lei, en dan ander secrets decrypt wat onder die hergebruikte IV encrypted is. Sien ook [TLS & Certificates](../tls-and-certificates/README.md) vir tipiese certificate layouts.<sup>[[1]](#references)</sup>
- Wanneer verskeie secrets van dieselfde **serialized format/size** onder dieselfde key+IV encrypted word, leks field alignment selfs sonder volledige bekende plaintext. Voorbeeld: PKCS#8 RSA keys met dieselfde modulus-grootte plaas prime factors by ooreenstemmende offsets (~99.6% alignment vir 2048-bit). Deur twee ciphertexts onder die hergebruikte keystream te XOR, word `p ⊕ p'` / `q ⊕ q'` geïsoleer, wat binne sekondes met brute force herwin kan word.<sup>[[1]](#references)</sup>
- Default IVs in libraries (bv. konstante `000...01`) is ’n kritieke footgun: elke encryption herhaal dieselfde keystream, wat CTR in ’n hergebruikte one-time pad verander.<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR bied slegs confidentiality: deur bits in ciphertext om te draai, word dieselfde bits deterministies in plaintext omgedraai. Sonder ’n authentication tag kan attackers data ongemerk manipuleer (bv. keys, flags of messages verander).
- Gebruik AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, ens.) en dwing tag verification af om bit-flips op te spoor.

### GCM

GCM breek ook ernstig onder nonce reuse. As dieselfde key+nonce meer as een keer gebruik word, kry jy tipies:

- Keystream reuse vir encryption (soos CTR), wat plaintext recovery moontlik maak wanneer enige plaintext bekend is.
- Verlies van integrity guarantees. Afhangend van wat blootgestel word (multiple message/tag pairs onder dieselfde nonce), kan attackers moontlik tags forge.

Operasionele riglyne:

- Behandel "nonce reuse" in AEAD as ’n kritieke vulnerability.
- Misuse-resistant AEADs soos AES-GCM-SIV verminder die gevolge van nonce reuse. Callers moet steeds unieke nonces verskaf soos deur die construction se interface vereis word; toevallige reuse het beperkte gevolge in vergelyking met gewone GCM.<sup>[[3]](#references)[[4]](#references)</sup>
- As jy verskeie ciphertexts onder dieselfde nonce het, begin deur verhoudings in die styl van `C1 XOR C2 = P1 XOR P2` na te gaan.

### Tools

- [CyberChef](https://gchq.github.io/CyberChef/) vir vinnige eksperimente.<sup>[[8]](#references)</sup>
- Python se [PyCryptodome](https://www.pycryptodome.org/) package vir scripting.<sup>[[9]](#references)</sup>

## ECB exploitation patterns

ECB (Electronic Code Book) encrypt elke block onafhanklik:

- gelyke plaintext blocks → gelyke ciphertext blocks
- dit lek struktuur en maak cut-and-paste style attacks moontlik

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

As jy verskeie kere login en **altyd dieselfde cookie kry**, kan die ciphertext deterministies wees (ECB of fixed IV).

As jy twee users met meestal identiese plaintext layouts skep (bv. lang herhaalde karakters) en herhaalde ciphertext blocks by dieselfde offsets sien, is ECB ’n sterk verdagte.

### Exploitation patterns

#### Removing entire blocks

As die token-formaat iets soos `<username>|<password>` is en die block boundary aligned, kan jy soms ’n user craft sodat die `admin` block aligned verskyn, en dan voorafgaande blocks remove om ’n geldige token vir `admin` te verkry.

#### Moving blocks

As die backend padding/extra spaces verdra (`admin` vs `admin    `), kan jy:

- ’n block wat `admin   ` bevat, align
- Daardie ciphertext block in ’n ander token swap/reuse

## Padding Oracle

### Wat dit is

In CBC mode, as die server direk of indirek openbaar of decrypted plaintext **valid PKCS#7 padding** het, kan jy dikwels:<sup>[[7]](#references)</sup>

- Ciphertext decrypt sonder die key
- ’n Ciphertext construct wat na chosen plaintext decrypt wanneer jy crafted preceding blocks of IVs kan submit en die application die gevolglik validly padded message aanvaar

Die oracle kan wees:

- ’n Spesifieke error message
- ’n Verskillende HTTP status / response size
- ’n Verskil in timing

### Praktiese exploitation

PadBuster is die classic tool:

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

CBC-dekripsie bereken `P[i] = D(C[i]) XOR C[i-1]`. Deur grepe in `C[i-1]` te wysig en te kyk of die padding geldig is, kan jy `P[i]` greep vir greep herwin.

## Bit-flipping in CBC

Selfs sonder 'n padding oracle is CBC manipuleerbaar. As jy ciphertext-blokke kan wysig en die toepassing die gedekripteerde plaintext as gestruktureerde data gebruik (bv. `role=user`), kan jy spesifieke bisse omkeer om geselekteerde plaintext-grepe op 'n gekose posisie in die volgende blok te verander.

Tipiese CTF-patroon:

- Token = `IV || C1 || C2 || ...`
- Jy beheer grepe in `C[i]`
- Jy teiken plaintext-grepe in `P[i+1]` omdat `P[i+1] = D(C[i+1]) XOR C[i]`

Dit is op sigself nie 'n verbreking van vertroulikheid nie, maar dit is 'n algemene privilege-escalation-primitive wanneer integriteit ontbreek.

## CBC-MAC

CBC-MAC is slegs onder spesifieke voorwaardes veilig (veral **boodskappe met 'n vaste lengte** en korrekte domeinskeiding). AES-CMAC is 'n gestandaardiseerde konstruk wat veranderlike-lengte-insette veilig hanteer.<sup>[[5]](#references)</sup>

### Klassieke vervalsingspatroon vir veranderlike lengtes

CBC-MAC word gewoonlik soos volg bereken:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

As jy tags vir gekose boodskappe kan verkry, kan jy dikwels 'n tag vir 'n aaneenskakeling (of verwante konstruk) vervaardig sonder om die sleutel te ken, deur uit te buit hoe CBC blokke aaneenskakel.

Dit kom gereeld voor in CTF-cookies/tokens wat die gebruikersnaam of rol met CBC-MAC MAC.

### Veiliger alternatiewe

- Gebruik HMAC (SHA-256/512)
- Gebruik CMAC (AES-CMAC) korrek
- Sluit boodskaplengte / domeinskeiding in

## Stream ciphers: XOR and RC4

### Die denkmodel

Die meeste stream cipher-situasies kan gereduseer word tot:

`ciphertext = plaintext XOR keystream`

Dus:

- As jy plaintext ken, herwin jy die keystream.
- As die keystream hergebruik word (dieselfde sleutel+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-gebaseerde encryption

As jy enige plaintext-segment op posisie `i` ken, kan jy keystream-grepe herwin en ander ciphertexts op daardie posisies dekripteer.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 is 'n legacy stream cipher; encryption/decryption is dieselfde XOR-operasie. Die bekende biases daarvan maak dit ongeskik vir nuwe stelsels, en TLS verbied sy cipher suites uitdruklik.<sup>[[6]](#references)</sup>

As jy RC4-encryption van bekende plaintext onder dieselfde sleutel kan verkry, kan jy die keystream herwin en ander boodskappe van dieselfde lengte/offset dekripteer.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Onverskilligheid teenoor vakmanskap in kriptografie](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Aanbeveling vir blokcipher-bedryfsmodusse](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Aanbeveling vir Galois/Counter Mode (GCM) en GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Authenticated Encryption wat bestand is teen nonce-misbruik](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - Die AES-CMAC-algoritme](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Verbod op RC4-cipher suites](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Toetsing vir Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome-dokumentasie](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
