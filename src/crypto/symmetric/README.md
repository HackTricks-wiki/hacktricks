# Symmetriese Crypto

{{#include ../../banners/hacktricks-training.md}}

## Wat om na te kyk in CTFs

- **Mode-misbruik**: ECB-patrone, CBC-malleability, CTR/GCM nonce-hergebruik.
- **Padding oracles**: verskillende foutboodskappe/tydverskille vir slegte padding.
- **MAC confusion**: gebruik van CBC-MAC met veranderlike lengte boodskappe, of MAC-then-encrypt foute.
- **XOR everywhere**: stream ciphers en pasgemaakte konstruksies verminder dikwels tot XOR met 'n keystream.

## AES-modi en misbruik

### ECB: Electronic Codebook

ECB leaks patrone: gelyke plaintext-blokke → gelyke ciphertext-blokke. Dit maak moontlik:

- Cut-and-paste / blok-herskikking
- Blok-verwydering (as die formaat geldig bly)

As jy plaintext kan beheer en ciphertext (of cookies) kan waarneem, probeer herhaalde blokke maak (bv. baie `A`s) en kyk vir herhalings.

### CBC: Cipher Block Chaining

- CBC is **malleable**: bits in `C[i-1]` omgooi veroorsaak voorspelbare bitsomkapping in `P[i]`.
- As die stelsel geldig padding teenoor ongeldige padding openbaar, kan jy 'n **padding oracle** hê.

### CTR

CTR verander AES in 'n stream cipher: `C = P XOR keystream`.

As 'n nonce/IV met dieselfde sleutel hergebruik word:

- `C1 XOR C2 = P1 XOR P2` (klassieke keystream-hergebruik)
- Met bekende plaintext kan jy die keystream herstel en ander ontsleutel.

**Nonce/IV-hergebruik exploitasiepatrone**

- Herstel keystream waar plaintext bekend/raai-baar is:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Pas die herstellde keystream-byte toe om enige ander ciphertext wat met dieselfde key+IV by dieselfde offsets geproduseer is, te ontsleutel.
- Sterk gestruktureerde data (bv. ASN.1/X.509 certificates, file headers, JSON/CBOR) bied groot bekende-plaintext-gebiede. Jy kan dikwels die ciphertext van die sertifikaat met die voorspelbare sertifikaat-liggaam XOR'en om die keystream af te lei, en dan ander geheime wat onder die hergebruikte IV versleutel is, ontsleutel. Sien ook [TLS & Certificates](../tls-and-certificates/README.md) vir tipiese sertifikaat-lay-outs.
- Wanneer meerdere geheime van dieselfde geserialiseerde formaat/grootte onder dieselfde key+IV versleutel is, lek veld-uitslyn selfs sonder volle bekende plaintext. Voorbeeld: PKCS#8 RSA-sleutels met dieselfde modulus-grootte plaas priemfaktore by ooreenstemmende offsets (~99.6% uitlyning vir 2048-bit). Die XOR van twee ciphertexts onder die hergebruikte keystream isoleer `p ⊕ p'` / `q ⊕ q'`, wat in sekondes brute-herwin kan word.
- Default IVs in libraries (bv. konstante `000...01`) is 'n kritieke valstrik: elke enkripsie herhaal dieselfde keystream, wat CTR in 'n hergebruikte one-time pad verander.

**CTR malleability**

- CTR bied slegs vertroulikheid: bits in ciphertext omskakel deterministies dieselfde bits in plaintext. Sonder 'n authentikasiestuk (tag) kan aanvallers data manipuleer (bv. tweak sleutels, vlae, of boodskappe) onopgemerk.
- Gebruik AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, ens.) en afdwing tag-verifikasie om bit-flips te vang.

### GCM

GCM breek ook sleg onder nonce-hergebruik. As dieselfde key+nonce meer as eens gebruik word, kry jy gewoonlik:

- Keystream-hergebruik vir enkripsie (soos CTR), wat plaintextherwinning moontlik maak wanneer enige plaintext bekend is.
- Verlies van integriteitswaarborge. Afhangend van wat openbaar is (meervoudige boodskap/tag-paartjies onder dieselfde nonce), mag aanvallers tags kan forgeer.

Operasionele riglyne:

- Beskou "nonce reuse" in AEAD as 'n kritieke kwesbaarheid.
- Misuse-resistant AEADs (bv. GCM-SIV) verminder nonce-misbruik gevolge maar vereis steeds unieke nonces/IVs.
- As jy meervoudige ciphertexts onder dieselfde nonce het, begin deur na `C1 XOR C2 = P1 XOR P2` styl-relasies te kyk.

### Tools

- CyberChef vir vinnige eksperimente: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` vir scripting

## ECB-uitbuitingspatrone

ECB (Electronic Code Book) enkripteer elke blok onafhanklik:

- gelyke plaintext-blokke → gelyke ciphertext-blokke
- dit lek struktuur en maak cut-and-paste styl-aanvalle moontlik

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Opsporingsidee: token/cookie-patroon

As jy verskeie kere aanmeld en altyd dieselfde cookie kry, mag die ciphertext deterministies wees (ECB of vaste IV).

As jy twee gebruikers skep met meestal identiese plaintext-indelings (bv. lang herhaalde karakters) en herhaalde ciphertext-blokke op dieselfde offsets sien, is ECB 'n primêre verdagte.

### Uitbuitingpatrone

#### Verwyder hele blokke

As die token-formaat iets soos `<username>|<password>` is en die blok-grens lyn op, kan jy soms 'n gebruiker kraf sodat die `admin`-blok uitgelê word, en dan die voorafgaande blokke verwyder om 'n geldige token vir `admin` te verkry.

#### Verskuif blokke

As die backend padding/extra spasies (`admin` vs `admin    `) verdra, kan jy:

- 'n blok uitlyn wat `admin   ` bevat
- daardie ciphertext-blok ruil/hergebruik in 'n ander token

## Padding Oracle

### Wat dit is

In CBC-mode, as die bediener openbaar (direk of indirek) of ontsleutelde plaintext **geldig PKCS#7 padding** het, kan jy dikwels:

- Ciphertext sonder die sleutel ontsleutel
- Gekose plaintext enkripteer (ciphertext forgeer)

Die oracle kan wees:

- 'n spesifieke foutboodskap
- 'n ander HTTP-status / reaksiegrootte
- 'n timing-onderskyding

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

Selfs sonder 'n padding oracle is CBC aanpasbaar. As jy ciphertext-blokke kan wysig en die toepassing gebruik die ontsleutelde plaintext as gestruktureerde data (bv. `role=user`), kan jy spesifieke bits flip om geselekteerde plaintext-bytes by 'n gekose posisie in die volgende blok te verander.

Tipiese CTF-patroon:

- Token = `IV || C1 || C2 || ...`
- Jy beheer bytes in `C[i]`
- Jy teiken plaintext-bytes in `P[i+1]` omdat `P[i+1] = D(C[i+1]) XOR C[i]`

Dit is nie 'n inbreuk op vertroulikheid op sigself nie, maar dit is 'n algemene privilege-escalation primitive wanneer integriteit ontbreek.

## CBC-MAC

CBC-MAC is slegs veilig onder spesifieke voorwaardes (veral **vaste-lengte boodskappe** en korrekte domein-separasie).

### Classic variable-length forgery pattern

CBC-MAC word gewoonlik bereken as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

As jy tags vir gekose boodskappe kan bekom, kan jy dikwels 'n tag vir 'n aaneenvoeging (of verwante konstruk) saamstel sonder om die sleutel te ken, deur te misbruik hoe CBC blokke aan mekaar koppel.

Dit kom gereeld voor in CTF cookies/tokens wat gebruikersnaam of rol met CBC-MAC tag.

### Safer alternatives

- Gebruik HMAC (SHA-256/512)
- Gebruik CMAC (AES-CMAC) korrek
- Sluit boodskaplengte / domein-separasie in

## Stream ciphers: XOR and RC4

### The mental model

Meeste stream cipher-situasies kom neer op:

`ciphertext = plaintext XOR keystream`

Dus:

- As jy plaintext ken, herstel jy keystream.
- As keystream hergebruik word (dieselfde key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

As jy enige plaintext-segment by posisie `i` ken, kan jy keystream-bytes herstel en ander ciphertexts by daardie posisies ontsleutel.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 is 'n stream cipher; encrypt/decrypt is dieselfde operasie.

As jy RC4-enkripsie van bekende plaintext onder dieselfde sleutel kan kry, kan jy die keystream herstel en ander boodskappe met dieselfde lengte/offset ontsleutel.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
