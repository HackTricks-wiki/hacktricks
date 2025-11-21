# Kriptografiese/Kompressie-algoritmes

{{#include ../../banners/hacktricks-training.md}}

## Identifisering van algoritmes

As jy op 'n kode stuit wat **using shift rights and lefts, xors and several arithmetic operations** gebruik, is dit baie waarskynlik dat dit die implementering van 'n **kriptografiese algoritme** is. Hier word 'n paar maniere getoon om die **algoritme wat gebruik word te identifiseer sonder om elke stap om te keer**.

### API-funksies

**CryptDeriveKey**

As hierdie funksie gebruik word, kan jy vind watter **algoritme gebruik word** deur die waarde van die tweede parameter te kontroleer:

![](<../../images/image (156).png>)

Kyk hier na die tabel van moontlike algoritmes en hul toegewezen waardes: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Komprimeer en dekomprimeer 'n gegewe buffer van data.

**CryptAcquireContext**

From [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Die **CryptAcquireContext**-funksie word gebruik om 'n hanteer te verkry na 'n spesifieke sleutelhouer binne 'n spesifieke kriptografiese diensverskaffer (CSP). **Hierdie teruggegewe hanteer word gebruik in oproepe na CryptoAPI**-funksies wat die geselekteerde CSP gebruik.

**CryptCreateHash**

Inisieer die hash van 'n datastroom. As hierdie funksie gebruik word, kan jy vind watter **algoritme gebruik word** deur die waarde van die tweede parameter te kontroleer:

![](<../../images/image (549).png>)

\
Kyk hier na die tabel van moontlike algoritmes en hul toegewezen waardes: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Kode-konstantes

Soms is dit baie maklik om 'n algoritme te identifiseer weens die feit dat dit 'n spesiale en unieke waarde benodig.

![](<../../images/image (833).png>)

As jy vir die eerste konstante op Google soek, kry jy dit:

![](<../../images/image (529).png>)

Daarom kan jy aanvaar dat die gedecompileerde funksie 'n **sha256 calculator.** is.\
Jy kan enige van die ander konstantes soek en sal (waarskynlik) dieselfde resultaat kry.

### data-inligting

As die kode geen betekenisvolle konstante het nie, mag dit wees dat dit **inligting uit die .data section** laai.\
Jy kan daardie data benader, **groepeer die eerste dword** en dit op Google soek soos ons in die vorige afdeling gedoen het:

![](<../../images/image (531).png>)

In hierdie geval, as jy vir **0xA56363C6** soek, sal jy vind dat dit verwant is aan die **tabelle van die AES algoritme**.

## RC4 **(Simmetriese Kriptografie)**

### Kenmerke

Dit bestaan uit 3 hoofdele:

- **Initialiseringsfase/**: Skep 'n **tabel van waardes van 0x00 tot 0xFF** (256 bytes in totaal, 0x100). Hierdie tabel word algemeen 'n **Substitution Box** (of SBox) genoem.
- **Scrambleringsfase**: Sal **deur die tabel loop** wat voorheen geskep is (lus van 0x100 iterasies) en elke waarde wysig met **semi-random** bytes. Om hierdie semi-random bytes te skep, word die RC4 **key** gebruik. RC4 **keys** kan **tussen 1 en 256 bytes lank wees**, maar dit word gewoonlik aanbeveel dat dit meer as 5 bytes is. Gewoonlik is RC4-sleutels 16 bytes lank.
- **XOR-fase**: Laastens word die plain-text of cyphertext **met die voorheen geskepte waardes XORed**. Die funksie om te enkripteer en dekodeer is dieselfde. Hiervoor word 'n **lus deur die geskepte 256 bytes** uitgevoer soveel keer as nodig. Dit word gewoonlik in 'n gedecompileerde kode herken met 'n **%256 (mod 256)**.

> [!TIP]
> **Om 'n RC4 in 'n disassembly/gedecompileerde kode te identifiseer, kan jy kyk vir 2 lusse van grootte 0x100 (met die gebruik van 'n key) en dan 'n XOR van die insetdata met die 256 waardes wat voorheen in die 2 lusse geskep is, waarskynlik met 'n %256 (mod 256)**

### **Initialiseringsfase/Substitution Box:** (Let op die nommer 256 wat as teller gebruik word en hoe 'n 0 in elke posisie van die 256 karakters geskryf word)

![](<../../images/image (584).png>)

### **Scrambleringsfase:**

![](<../../images/image (835).png>)

### **XOR-fase:**

![](<../../images/image (904).png>)

## **AES (Simmetriese Kriptografie)**

### **Kenmerke**

- Gebruik van **substitution boxes en lookup tables**
- Dit is moontlik om **AES te onderskei danksy die gebruik van spesifieke lookup table-waardes** (konstantes). _Let daarop dat die **konstante** óf in die binêre gestoor óf **dinamies** geskep kan word._
- Die **enkripsiesleutel** moet **deelbaar** wees deur **16** (gewoonlik 32B) en gewoonlik word 'n **IV** van 16B gebruik.

### SBox-konstantes

![](<../../images/image (208).png>)

## Serpent **(Simmetriese Kriptografie)**

### Kenmerke

- Dit is skaars om malware te vind wat dit gebruik maar daar is voorbeelde (Ursnif)
- Eenvoudig om te bepaal of 'n algoritme Serpent is gebaseer op die lengte (uiters lang funksie)

### Identifisering

In die volgende beeld, let daarop hoe die konstante **0x9E3779B9** gebruik word (let wel dat hierdie konstante ook deur ander crypto algoritmes soos **TEA** - Tiny Encryption Algorithm gebruik word).\
Let ook op die **grootte van die lus** (**132**) en die **aantal XOR-operasies** in die **disassembly** instruksies en in die **kode** voorbeeld:

![](<../../images/image (547).png>)

Soos vroeër genoem, kan hierdie kode in enige dekompileerder as 'n **baie lang funksie** gesien word aangesien daar **geen jumps** daarin is nie. Die gedecompileerde kode kan soos volg lyk:

![](<../../images/image (513).png>)

Daarom is dit moontlik om hierdie algoritme te identifiseer deur die **magic number** en die **initiële XORs** na te gaan, 'n **baie lang funksie** te sien en sommige **instruksies** van die lang funksie te **vergelyk** met 'n **implementering** (soos die shift left met 7 en die rotate left met 22).

## RSA **(Asimmetriese Kriptografie)**

### Kenmerke

- Meer kompleks as simmetriese algoritmes
- Daar is geen konstantes nie! (aangepaste implementasies is moeilik om te bepaal)
- KANAL (a crypto analyzer) misluk om wenke oor RSA te gee aangesien dit op konstantes staatmaak.

### Identifisering deur vergelykings

![](<../../images/image (1113).png>)

- In lyn 11 (links) is daar 'n `+7) >> 3` wat dieselfde is as in lyn 35 (regs): `+7) / 8`
- Lyn 12 (links) kontroleer of `modulus_len < 0x040` en in lyn 36 (regs) word gekyk of `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Kenmerke

- 3 funksies: Init, Update, Final
- Gelyksoortige initialiseringsfunksies

### Identifiseer

**Init**

Jy kan beide identifiseer deur die konstantes na te gaan. Let daarop dat die sha_init 'n konstante het wat MD5 nie het nie:

![](<../../images/image (406).png>)

**MD5 Transform**

Let op die gebruik van meer konstantes

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Kleiner en meer doeltreffend aangesien die doel daarvan is om toevallige veranderings in data te vind
- Gebruik lookup tables (sodat jy konstantes kan identifiseer)

### Identifiseer

Kyk na **lookup table-konstantes**:

![](<../../images/image (508).png>)

'n CRC-hash algoritme lyk soos:

![](<../../images/image (391).png>)

## APLib (Kompressie)

### Kenmerke

- Geen herkenbare konstantes nie
- Jy kan probeer om die algoritme in Python te skryf en vir soortgelyke implementasies aanlyn te soek

### Identifiseer

Die grafiek is redelik groot:

![](<../../images/image (207) (2) (1).png>)

Kyk na **3 vergelykings om dit te herken**:

![](<../../images/image (430).png>)

## Elliptic-Curve Signature Implementation Bugs

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 vereis dat HashEdDSA-verifiers 'n handtekening `sig = R || s` moet split en enige skalaar met `s \geq n`, waar `n` die groeporde is, moet verwerp. Die `elliptic` JS-biblioteek het daardie grenskontrole oorgeslaan, dus enige aanvaller wat 'n geldige paar `(msg, R || s)` ken, kan alternatiewe handtekeninge valsmaak `s' = s + k·n` en aanhou om `sig' = R || s'` te herkodeer.
- Die verifikasieroetines gebruik slegs `s mod n`, daarom word alle `s'` wat kongruent is aan `s` aanvaar al is dit verskillende byte-reekse. Systeme wat handtekeninge as kanoniese tokens behandel (blockchain consensus, replay caches, DB-sleutels, ens.) kan gedesinchroniseer word omdat streng implementasies `s'` sal verwerp.
- Wanneer jy ander HashEdDSA-kode oudit, verseker dat die parser beide die punt `R` en die skalaarlengte valideer; probeer om veelvoude van `n` by 'n bekende-goeie `s` te hang om te bevestig dat die verifier fails closed.

### ECDSA truncation vs. leading-zero hashes

- ECDSA-verifiers moet slegs die linkerkantse `log2(n)` bits van die boodskaphash `H` gebruik. In `elliptic` het die truncation helper `delta = (BN(msg).byteLength()*8) - bitlen(n)` bereken; die `BN`-konstruktor verwyder voorloop-nul oktette, dus enige hash wat met ≥4 nul bytes begin op kurwes soos secp192r1 (192-bit order) het na vore gekom as net 224 bits in plaas van 256.
- Die verifier het regs geskuiw met 32 bits in plaas van 64, wat 'n `E` produseer wat nie ooreenstem met die waarde wat deur die ondertekenaar gebruik is nie. Geldige handtekeninge op daardie hashes misluk daarom met waarskynlikheid ≈`2^-32` vir SHA-256 insette.
- Voer beide die “all good” vektor en leading-zero variante (bv. Wycheproof `ecdsa_secp192r1_sha256_test.json` geval `tc296`) na 'n teikenimplementering; as die verifier nie saamstem met die ondertekenaar nie, het jy 'n uitbuitbare truncation-bug gevind.

### Exercising Wycheproof vectors against libraries

- Wycheproof verskaf JSON-toetse wat verkragte punte, malleerbare skalare, ongewone hashes en ander hoekgevalle kodeer. Om 'n toetsraamwerk rondom `elliptic` (of enige crypto library) te bou is reguit: laai die JSON, deserialiseer elke toetsgeval en maak seker dat die implementering ooreenstem met die verwagte `result` vlag.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Foute moet getriageer word om spesifikasie-oortredings van vals positiewe te onderskei. Vir die twee foute hierbo het die mislukte Wycheproof-gevalle dadelik aangedui dat daar ontbrekende kontroles vir scalar-reekse (EdDSA) en onjuiste hash-afkapping (ECDSA) was.
- Integreer die toetsharnas in CI sodat regressies in scalar-ontleding, hash-hantering, of koördinaatgeldigheid toetse aktiveer sodra dit voorkom. Dit is veral nuttig vir hoëvlak-tale (JS, Python, Go) waar subtiele bignum-omskakelings maklik verkeerd kan wees.

## Verwysings

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
