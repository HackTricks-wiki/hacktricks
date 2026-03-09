# Simmetriese Crypto

{{#include ../../banners/hacktricks-training.md}}

## Waar om na te kyk in CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: verskillende foute/tydverskille vir slegte padding.
- **MAC confusion**: using CBC-MAC with variable-length messages, or MAC-then-encrypt mistakes.
- **XOR everywhere**: stream ciphers en aangepaste konstruksies verminder dikwels tot XOR met 'n keystream.

## AES-modi en wangebruik

### ECB: Electronic Codebook

ECB leaks patterns: gelyke plaintext-blokke → gelyke ciphertext-blokke. Dit maak die volgende moontlik:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

As jy plaintext kan beheer en ciphertext (of cookies) kan observeer, probeer herhaalde blokke maak (bv. baie `A`s) en kyk vir herhalings.

### CBC: Cipher Block Chaining

- CBC is **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- As die stelsel geldige padding vs ongeldige padding openbaar, kan jy moontlik 'n **padding oracle** hê.

### CTR

CTR draai AES in 'n stream cipher: `C = P XOR keystream`.

As 'n nonce/IV hergebruik word met dieselfde sleutel:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Met bekende plaintext kan jy die keystream herstel en ander ontsleutel.

**Nonce/IV reuse exploitation patterns**

- Herwin keystream waar plaintext bekend/skatbaar is:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Pas die herwonne keystream-byte toe om enige ander ciphertext te ontsleutel wat met dieselfde sleutel+IV by dieselfde offsets geproduseer is.
- Hoogs gestruktureerde data (bv. ASN.1/X.509 certificates, file headers, JSON/CBOR) bied groot bekende-plaintext gebiede. Jy kan dikwels die ciphertext van die sertifikaat met die voorspelbare sertifikaatliggaam XOR om keystream af te lei, en dan ander geheime ontsleutel wat onder die hergebruikte IV versleutel is. Sien ook [TLS & Certificates](../tls-and-certificates/README.md) vir tipiese sertifikaatlye.
- Wanneer verskeie geheime van die **same serialized format/size** onder dieselfde sleutel+IV versleutel is, lek velduitlijning selfs sonder volledige bekende plaintext. Voorbeeld: PKCS#8 RSA-sleutels met dieselfde modulusgrootte plaas priemfaktore by ooreenstemmende offsets (~99.6% uitlijning vir 2048-bit). XORing twee ciphertexts onder die hergebruikte keystream isoleer `p ⊕ p'` / `q ⊕ q'`, wat binne sekondes deur brute krag herstel kan word.
- Default IVs in libraries (bv. konstante `000...01`) is 'n ernstige foutbron: elke enkripsie herhaal dieselfde keystream, wat CTR in 'n hergebruikte one-time pad verander.

**CTR malleability**

- CTR bied slegs confidentiality: flipping bits in ciphertext deterministies flip dieselfde bits in plaintext. Sonder 'n authentication tag kan aanvallers data manipuleer (bv. wysig sleutels, vlae of boodskappe) onopgemerk.
- Gebruik AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, ens.) en dwing tag-verifikasie af om bit-flips op te spoor.

### GCM

GCM breek ook erg onder nonce reuse. As dieselfde sleutel+nonce meer as een keer gebruik word, kry jy gewoonlik:

- Keystream reuse vir enkripsie (soos CTR), wat plaintextherstel moontlik maak wanneer enige plaintext bekend is.
- Verlies van integriteitswaarborge. Afhangend van wat blootgestel is (meerdere boodskap/tag pare onder dieselfde nonce), kan aanvallers dalk tags vervals.

Operationele leiding:

- Beskou "nonce reuse" in AEAD as 'n kritieke kwesbaarheid.
- Misuse-resistant AEADs (bv. GCM-SIV) verminder nonce-misuse gevolge maar vereis steeds unieke nonces/IVs.
- As jy meerdere ciphertexts onder dieselfde nonce het, begin deur `C1 XOR C2 = P1 XOR P2` styl verhoudings te kontroleer.

### Gereedskap

- CyberChef vir vinnige eksperimente: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` vir scripting

## ECB uitbuitingpatrone

ECB (Electronic Code Book) enkripteer elke blok onafhanklik:

- equal plaintext blocks → equal ciphertext blocks
- Dit leaks struktuur en maak cut-and-paste styl aanvalle moontlik

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Opsporingsidee: token/cookie patroon

As jy verskeie kere aanmeld en **altyd dieselfde cookie kry**, mag die ciphertext deterministies wees (ECB of vaste IV).

As jy twee gebruikers skep met hoofsaaklik identiese plaintext-lay-outs (bv. lang herhaalde karakters) en herhaalde ciphertext-blokke op dieselfde offsets sien, is ECB 'n waarskynlike verdagte.

### Uitbuitingpatrone

#### Verwydering van hele blokke

As die token-formaat iets soos `<username>|<password>` is en die blokgrens uitlijn, kan jy soms 'n gebruiker skep sodat die `admin`-blok blyk uit te lyn, en dan die voorafgaande blokke verwyder om 'n geldige token vir `admin` te kry.

#### Verskuif van blokke

As die backend padding/extra spaces (`admin` vs `admin    `) verdra, kan jy:

- Lyn 'n blok uit wat `admin   ` bevat
- Ruil/hergebruik daardie ciphertext-blok in 'n ander token

## Padding Oracle

### Wat dit is

In CBC-modus, as die bediener (direk of indirek) openbaar of ontsleutelde plaintext **geldige PKCS#7 padding** het, kan jy dikwels:

- Ontsleutel ciphertext sonder die sleutel
- Enkripteer gekose plaintext (vervals ciphertext)

Die oracle kan wees:

- 'n spesifieke foutboodskap
- 'n ander HTTP-status / responsgrootte
- 'n tydverskil

### Praktiese uitbuiting

PadBuster is die klassieke hulpmiddel:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Voorbeeld:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Aantekeninge:

- Blokgrootte is dikwels `16` vir AES.
- `-encoding 0` beteken Base64.
- Gebruik `-error` as die oracle 'n spesifieke string is.

### Waarom dit werk

CBC-dekripsie bereken `P[i] = D(C[i]) XOR C[i-1]`. Deur bytes in `C[i-1]` te wysig en te kyk of die padding geldig is, kan jy `P[i]` byte-vir-byte herstel.

## Bit-flipping in CBC

Selfs sonder 'n padding oracle is CBC manipuleerbaar. As jy ciphertext-blokke kan wysig en die toepassing gebruik die gedekripsieerde plaintext as gestruktureerde data (bv. `role=user`), kan jy spesifieke bits omkeer om gekose plaintext-bytes in die volgende blok te verander.

Tipiese CTF-patroon:

- Token = `IV || C1 || C2 || ...`
- Jy beheer bytes in `C[i]`
- Jy mik op plaintext-bytes in `P[i+1]` omdat `P[i+1] = D(C[i+1]) XOR C[i]`

Dit is op sigself nie 'n breuk van vertroulikheid nie, maar dit is 'n algemene privilege-escalation primitive wanneer integriteit ontbreek.

## CBC-MAC

CBC-MAC is slegs veilig onder spesifieke voorwaardes (naamlik **vaste-lengte boodskappe** en korrekte domain separation).

### Klassieke veranderlike-lengte vervalsingspatroon

CBC-MAC word gewoonlik bereken as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

As jy tags vir gekose boodskappe kan bekom, kan jy dikwels 'n tag vir 'n aaneenvoeging (of verwante konstruksie) saamstel sonder om die sleutel te ken, deur te misbruik hoe CBC blokke aaneenskakel.

Dit verskyn gereeld in CTF cookies/tokens wat username of role met CBC-MAC MAC.

### Veiliger alternatiewe

- Gebruik HMAC (SHA-256/512)
- Gebruik CMAC (AES-CMAC) korrek
- Sluit boodskaplengte / domain separation in

## Stream ciphers: XOR and RC4

### Die mentale model

Die meeste stream cipher situasies kom neer op:

`ciphertext = plaintext XOR keystream`

Dus:

- As jy plaintext ken, herstel jy die keystream.
- As die keystream hergebruik word (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

As jy enige plaintext-segment op posisie `i` ken, kan jy keystream-bytes herstel en ander ciphertexts op daardie posisies dekripteer.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 is 'n stream cipher; enkripsie/dekripsie is dieselfde operasie.

As jy RC4-enkripsie van bekende plaintext onder dieselfde sleutel kan kry, kan jy die keystream herstel en ander boodskappe met dieselfde lengte/offset dekripteer.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
