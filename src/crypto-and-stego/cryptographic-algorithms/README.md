# Kriptografiese/Kompressie-algoritmes

{{#include ../../banners/hacktricks-training.md}}

## Identifisering van algoritmes

As jy op 'n kode stuit wat **bitskuif regs en links, XORs en verskeie rekenkundige operasies** gebruik, is dit hoogs waarskynlik dat dit die implementering van 'n **kriptografiese algoritme** is. Hier sal 'n paar maniere getoon word om die algoritme wat gebruik word te **identifiseer sonder om elke stap te reverseer**.

### API-funksies

**CryptDeriveKey**

As hierdie funksie gebruik word, kan jy vind watter **algoritme gebruik word** deur die waarde van die tweede parameter te kontroleer:

![](<../../images/image (156).png>)

Kyk hier na die tabel van moontlike algoritmes en hul toegewyde waardes: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Pak saam en los 'n gegewe databuffer.

**CryptAcquireContext**

Volgens [die dokumentasie](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Die **CryptAcquireContext** funksie word gebruik om 'n handvatsel te kry vir 'n bepaalde sleutelhouer binne 'n bepaalde cryptographic service provider (CSP). **Hierdie teruggegewe handvatsel word gebruik in oproepe na CryptoAPI** funksies wat die geselekteerde CSP gebruik.

**CryptCreateHash**

Inisieer die hashing van 'n datastroom. As hierdie funksie gebruik word, kan jy vind watter **algoritme gebruik word** deur die waarde van die tweede parameter te kontroleer:

![](<../../images/image (549).png>)

\
Kyk hier na die tabel van moontlike algoritmes en hul toegewyde waardes: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Kode-constantes

Dikwels is dit maklik om 'n algoritme te identifiseer weens die feit dat dit 'n spesiale en unieke waarde benodig.

![](<../../images/image (833).png>)

As jy vir die eerste konstante op Google soek kry jy dit:

![](<../../images/image (529).png>)

Daarom kan jy aanneem dat die gedecompileerde funksie 'n **sha256-berekenaar** is.\
Jy kan enige van die ander konstantes soek en jy sal waarskynlik dieselfde resultaat kry.

### Data-inligting

As die kode nie enige betekenisvolle konstante het nie, mag dit **inligting uit die .data-seksie laai**.\
Jy kan daardie data benader, **groepeer die eerste dword** en daarna in Google soek soos voorheen gedoen is:

![](<../../images/image (531).png>)

In hierdie geval, as jy vir **0xA56363C6** soek, kan jy vind dat dit verband hou met die **tabelle van die AES-algoritme**.

## RC4 **(Symmetriese Kriptografie)**

### Kenmerke

Dit bestaan uit 3 hoofdele:

- **Initialiseringsfase/**: Skep 'n **tabel van waardes van 0x00 tot 0xFF** (256 bytes in totaal, 0x100). Hierdie tabel word gewoonlik 'n **Substitution Box** (of SBox) genoem.
- **Verwarringsfase**: Sal deur die voorafgeskrewe tabel **loop** (lus van 0x100 iterasies, weer) en elke waarde wysig met **semi-willekeurige** bytes. Om hierdie semi-willekeurige bytes te genereer, word die RC4 **sleutel gebruik**. RC4 **sleutels** kan **tussen 1 en 256 bytes lank** wees, maar dit word gewoonlik aanbeveel dat dit meer as 5 bytes is. Gewoonlik is RC4-sleutels 16 bytes lank.
- **XOR-fase**: Laastens word die plain-text of ciphertext **met die vroeër geskepte waardes XORed**. Die funksie om te enkripteer en te dekripteer is dieselfde. Hiervoor word 'n **lus deur die geskepte 256 bytes** uitgevoer soveel keer as nodig. Dit word gewoonlik in 'n gedecompileerde kode herken deur 'n **%256 (mod 256)**.

> [!TIP]
> **Om 'n RC4 in 'n disassembly/dekompileerde kode te identifiseer kan jy kyk vir 2 lusse van grootte 0x100 (met die gebruik van 'n sleutel) en daarna 'n XOR van die insetdata met die 256 waardes wat eerder in die 2 lusse geskep is, waarskynlik met 'n %256 (mod 256)**

### **Initialiseringsfase/Substitution Box:** (Let op die getal 256 gebruik as teller en hoe 'n 0 in elke plek van die 256 karakters geskryf word)

![](<../../images/image (584).png>)

### **Verwarringsfase:**

![](<../../images/image (835).png>)

### **XOR-fase:**

![](<../../images/image (904).png>)

## **AES (Symmetriese Kriptografie)**

### **Kenmerke**

- Gebruik van **substitution boxes en lookup tables**
- Dit is moontlik om **AES te onderskei danksy die gebruik van spesifieke lookup table waardes** (konstantes). _Let wel dat die **konstante** in die binêre **gestoor** kan wees of **dinamies** geskep kan word._
- Die **enkripsiesleutel** moet **deelbaar** wees deur **16** (gewoonlik 32B) en gewoonlik word 'n **IV** van 16B gebruik.

### SBox-konstantes

![](<../../images/image (208).png>)

## Serpent **(Symmetriese Kriptografie)**

### Kenmerke

- Dit is selde om malware te vind wat dit gebruik, maar daar is voorbeelde (Ursnif)
- Eenvoudig om te bepaal of 'n algoritme Serpent is gebaseer op die lengte daarvan (uiters lang funksie)

### Identifisering

In die volgende beeld let op hoe die konstante **0x9E3779B9** gebruik word (let dat hierdie konstante ook deur ander crypto-algoritmes soos **TEA** - Tiny Encryption Algorithm gebruik word).\
Let ook op die **grootte van die lus** (**132**) en die **aantal XOR-operasies** in die **disassembly** instruksies en in die **kode** voorbeeld:

![](<../../images/image (547).png>)

Soos vroeër genoem, kan hierdie kode in enige dekompiler as 'n **uiters lang funksie** gesien word aangesien daar **geen spronge** daarin is nie. Die gedecompileerde kode kan soos volg lyk:

![](<../../images/image (513).png>)

Daarom is dit moontlik om hierdie algoritme te identifiseer deur te kyk na die **magic number** en die **aanvangs-XORs**, 'n **uiters lang funksie** te sien en sommige **instruksies** van die lang funksie **met 'n implementering** te **vergelyk** (soos die shift left met 7 en die rotate left met 22).

## RSA **(Asimmetriese Kriptografie)**

### Kenmerke

- Meer kompleks as symmetriese algoritmes
- Daar is geen konstantes nie! (aangepaste implementasies is moeilik om te bepaal)
- KANAL (a crypto analyzer) faal om leidrade oor RSA te wys aangesien dit op konstantes staatmaak.

### Identifisering deur vergelykings

![](<../../images/image (1113).png>)

- In lyn 11 (links) is daar `+7) >> 3` wat dieselfde is as in lyn 35 (regs): `+7) / 8`
- Lyn 12 (links) kontroleer of `modulus_len < 0x040` en in lyn 36 (regs) kontroleer dit of `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Kenmerke

- 3 funksies: Init, Update, Final
- Gelyksoortige initialiseringsfunksies

### Identifiseer

**Init**

Jy kan albei identifiseer deur die konstantes te kontroleer. Let daarop dat die sha_init 'n konstante het wat MD5 nie het nie:

![](<../../images/image (406).png>)

**MD5 Transform**

Let op die gebruik van meer konstantes

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Kleiner en meer doeltreffend aangesien dit gebruik word om toevallige veranderinge in data te vind
- Gebruik lookup tables (dus kan jy konstantes identifiseer)

### Identifiseer

Kyk na **lookup table konstantes**:

![](<../../images/image (508).png>)

'n CRC-hash algoritme lyk soos:

![](<../../images/image (391).png>)

## APLib (Kompressie)

### Kenmerke

- Geen herkenbare konstantes nie
- Jy kan probeer om die algoritme in Python te skryf en aanlyn vir soortgelyke dinge te soek

### Identifiseer

Die grafiek is redelik groot:

![](<../../images/image (207) (2) (1).png>)

Kyk na **3 vergelykings om dit te herken**:

![](<../../images/image (430).png>)

## Foute in Elliptiese-kromme Handtekening-implementasies

### EdDSA scalar-bereik afdwinging (HashEdDSA malleabiliteit)

- FIPS 186-5 §7.8.2 vereis dat HashEdDSA-verifikateurs 'n handtekening `sig = R || s` opsplits en enige skalar met `s \geq n` verwerp, waar `n` die groeporde is. Die `elliptic` JS-biblioteek het daardie grenskontrole oorgeslaan, so enige aanvaller wat 'n geldige paar `(msg, R || s)` ken, kan alternatiewe handtekeninge vervals `s' = s + k·n` en bly herkodeer `sig' = R || s'`.
- Die verifikasie-routines gebruik slegs `s mod n`, dus word alle `s'` wat congruent is met `s` aanvaar, al is hulle verskillende bytreekse. Stelsels wat handtekeninge as kanonieke tokens behandel (blockchain consensus, replay caches, DB-sleutels, ens.) kan gedesinchroniseer raak omdat streng implementasies `s'` sal verwerp.
- Wanneer jy ander HashEdDSA-kode ouditeer, verseker dat die ontleder beide die punt `R` en die skalarlengte valideer; probeer om veelvoude van `n` aan 'n bekende-goeie `s` aan te heg om te bevestig dat die verifikateur gesluit faal.

### ECDSA afkapping vs. voorloop-nul hashes

- ECDSA-verifikateurs mag slegs die linkermost `log2(n)` bisse van die boodskaphash `H` gebruik. In `elliptic` het die truncation helper `delta = (BN(msg).byteLength()*8) - bitlen(n)` bereken; die `BN` konstruktor verwyder voorloop-nul oktette, dus enige hash wat met ≥4 nulbytes begin op kurwes soos secp192r1 (192-bit orde) het gelyk of dit slegs 224 bits is in plaas van 256.
- Die verifikateur het regs geskuiwe met 32 bits in plaas van 64, wat 'n `E` produseer wat nie ooreenstem met die waarde wat deur die ondertekenaar gebruik is nie. Geldige handtekeninge op daardie hashes misluk dus met waarskynlikheid ≈`2^-32` vir SHA-256 insette.
- Voer beide die “alles goed” vektor en voorloop-nul variante (bv. Wycheproof `ecdsa_secp192r1_sha256_test.json` geval `tc296`) na 'n teiken-implementasie; as die verifikateur nie saamstem met die ondertekenaar nie, het jy 'n uitbuitbare afkappingsfout gevind.

### Toets van Wycheproof-vektore teen biblioteke
- Wycheproof lewer JSON-toetsstelle wat verkrumpelde punte, maleubare skalers, ongebruiklike hashes en ander uithoeksgevalle kodeer. Om 'n harnas om `elliptic` (of enige crypto-biblioteek) te bou is reguit: laai die JSON, deserialiseer elke toetsgeval, en bevestig dat die implementasie ooreenstem met die verwagte `result` vlag.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Foute moet getriageer word om spesifikasie-oortredings van vals positiewe te onderskei. By die twee foutes hierbo het die mislukte Wycheproof-gevalle onmiddellik gewys op ontbrekende skalaarreekskontroles (EdDSA) en onjuiste hash-afknyping (ECDSA).
- Integreer die harness in CI sodat regressies in skalaarparsings, hashverwerking, of koördinaatgeldigheid toetse uitloke sodra dit geïntroduseer word. Dit is veral nuttig vir hoëvlak tale (JS, Python, Go) waar subtiele bignum-omskakelings maklik verkeerd kan gaan.

## Verwysings

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
