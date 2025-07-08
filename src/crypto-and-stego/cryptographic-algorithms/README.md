# Kriptografiese/Kompressie Algoritmes

{{#include ../../banners/hacktricks-training.md}}

## Identifisering van Algoritmes

As jy eindig in 'n kode **wat regte en linke verskuiwings, xors en verskeie aritmetiese operasies gebruik**, is dit hoogs waarskynlik dat dit die implementering van 'n **kriptografiese algoritme** is. Hier gaan daar 'n paar maniere gewys word om die **algoritme wat gebruik word te identifiseer sonder om elke stap om te keer**.

### API funksies

**CryptDeriveKey**

As hierdie funksie gebruik word, kan jy vind watter **algoritme gebruik word** deur die waarde van die tweede parameter te kontroleer:

![](<../../images/image (156).png>)

Kontroleer hier die tabel van moontlike algoritmes en hul toegewyde waardes: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Komprimeer en dekomprimeer 'n gegewe buffer van data.

**CryptAcquireContext**

Van [die dokumentasie](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Die **CryptAcquireContext** funksie word gebruik om 'n handvatsel te verkry na 'n spesifieke sleutelhouer binne 'n spesifieke kriptografiese diensverskaffer (CSP). **Hierdie teruggegee handvatsel word gebruik in oproepe na CryptoAPI** funksies wat die geselekteerde CSP gebruik.

**CryptCreateHash**

Begin die hashing van 'n datastroom. As hierdie funksie gebruik word, kan jy vind watter **algoritme gebruik word** deur die waarde van die tweede parameter te kontroleer:

![](<../../images/image (549).png>)

\
Kontroleer hier die tabel van moontlike algoritmes en hul toegewyde waardes: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Kode konstantes

Soms is dit regtig maklik om 'n algoritme te identifiseer danksy die feit dat dit 'n spesiale en unieke waarde moet gebruik.

![](<../../images/image (833).png>)

As jy die eerste konstante in Google soek, is dit wat jy kry:

![](<../../images/image (529).png>)

Daarom kan jy aanvaar dat die dekompilde funksie 'n **sha256 sakrekenaar** is.\
Jy kan enige van die ander konstantes soek en jy sal (waarskynlik) dieselfde resultaat verkry.

### data info

As die kode geen betekenisvolle konstante het nie, kan dit **inligting van die .data afdeling laai**.\
Jy kan daardie data toegang, **die eerste dword groepeer** en dit in Google soek soos ons in die vorige afdeling gedoen het:

![](<../../images/image (531).png>)

In hierdie geval, as jy soek vir **0xA56363C6** kan jy vind dat dit verband hou met die **tabelle van die AES algoritme**.

## RC4 **(Simmetriese Kriptografie)**

### Kenmerke

Dit bestaan uit 3 hoofdele:

- **Inisialisering fase/**: Skep 'n **tabel van waardes van 0x00 tot 0xFF** (256bytes in totaal, 0x100). Hierdie tabel word algemeen die **Substitusie Boks** (of SBox) genoem.
- **Scrambling fase**: Sal **deur die tabel loop** wat voorheen geskep is (lus van 0x100 iterasies, weer) en elke waarde met **semi-ewe random** bytes aanpas. Om hierdie semi-ewe random bytes te skep, word die RC4 **sleutel gebruik**. RC4 **sleutels** kan **tussen 1 en 256 bytes in lengte** wees, maar dit word gewoonlik aanbeveel dat dit bo 5 bytes is. Gewoonlik is RC4 sleutels 16 bytes in lengte.
- **XOR fase**: Laastens, die plain-text of cyphertext word **XORed met die waardes wat voorheen geskep is**. Die funksie om te enkripteer en te dekripteer is dieselfde. Hiervoor sal 'n **lus deur die geskepte 256 bytes** uitgevoer word soveel keer as wat nodig is. Dit word gewoonlik in 'n dekompilde kode erken met 'n **%256 (mod 256)**.

> [!TIP]
> **Om 'n RC4 in 'n disassembly/dekompilde kode te identifiseer, kan jy kyk vir 2 lusse van grootte 0x100 (met die gebruik van 'n sleutel) en dan 'n XOR van die invoerdata met die 256 waardes wat voorheen in die 2 lusse geskep is, waarskynlik met 'n %256 (mod 256)**

### **Inisialisering fase/Substitusie Boks:** (Let op die nommer 256 wat as teenwoordiger gebruik word en hoe 'n 0 in elke plek van die 256 karakters geskryf word)

![](<../../images/image (584).png>)

### **Scrambling Fase:**

![](<../../images/image (835).png>)

### **XOR Fase:**

![](<../../images/image (904).png>)

## **AES (Simmetriese Kriptografie)**

### **Kenmerke**

- Gebruik van **substitusie bokse en opsoek tabelle**
- Dit is moontlik om **AES te onderskei danksy die gebruik van spesifieke opsoek tabel waardes** (konstantes). _Let daarop dat die **konstante** in die binêre **of geskep** _**dynamies**._
- Die **enkripsiesleutel** moet **deelbaar** wees deur **16** (gewoonlik 32B) en gewoonlik word 'n **IV** van 16B gebruik.

### SBox konstantes

![](<../../images/image (208).png>)

## Serpent **(Simmetriese Kriptografie)**

### Kenmerke

- Dit is selde om sekere malware wat dit gebruik te vind, maar daar is voorbeelde (Ursnif)
- Eenvoudig om te bepaal of 'n algoritme Serpent is of nie gebaseer op sy lengte (uiters lang funksie)

### Identifisering

In die volgende beeld let op hoe die konstante **0x9E3779B9** gebruik word (let daarop dat hierdie konstante ook deur ander kripto algoritmes soos **TEA** -Tiny Encryption Algorithm gebruik word).\
Let ook op die **grootte van die lus** (**132**) en die **aantal XOR operasies** in die **disassembly** instruksies en in die **kode** voorbeeld:

![](<../../images/image (547).png>)

Soos voorheen genoem, kan hierdie kode binne enige decompiler as 'n **baie lang funksie** gesien word aangesien daar **nie spronge** binne dit is nie. Die dekompilde kode kan soos volg lyk:

![](<../../images/image (513).png>)

Daarom is dit moontlik om hierdie algoritme te identifiseer deur die **magiese nommer** en die **begin XORs** te kontroleer, 'n **baie lang funksie** te sien en **instruksies** van die lang funksie **met 'n implementering** te vergelyk (soos die verskuiwing links deur 7 en die rotasie links deur 22).

## RSA **(Asimmetriese Kriptografie)**

### Kenmerke

- Meer kompleks as simmetriese algoritmes
- Daar is geen konstantes nie! (aangepaste implementasies is moeilik om te bepaal)
- KANAL (n kripto ontleder) slaag nie daarin om leidrade oor RSA te wys nie en dit staatmaak op konstantes.

### Identifisering deur vergelykings

![](<../../images/image (1113).png>)

- In lyn 11 (links) is daar 'n `+7) >> 3` wat dieselfde is as in lyn 35 (regs): `+7) / 8`
- Lyn 12 (links) kontroleer of `modulus_len < 0x040` en in lyn 36 (regs) kontroleer dit of `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Kenmerke

- 3 funksies: Init, Update, Final
- Soortgelyke inisialisering funksies

### Identifiseer

**Init**

Jy kan albei identifiseer deur die konstantes te kontroleer. Let daarop dat die sha_init 'n konstante het wat MD5 nie het nie:

![](<../../images/image (406).png>)

**MD5 Transform**

Let op die gebruik van meer konstantes

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Kleiner en meer doeltreffend aangesien dit se funksie is om toevallige veranderinge in data te vind
- Gebruik opsoek tabelle (sodat jy konstantes kan identifiseer)

### Identifiseer

Kontroleer **opsoek tabel konstantes**:

![](<../../images/image (508).png>)

'n CRC hash algoritme lyk soos:

![](<../../images/image (391).png>)

## APLib (Kompressie)

### Kenmerke

- Nie herkenbare konstantes
- Jy kan probeer om die algoritme in python te skryf en soortgelyke dinge aanlyn te soek

### Identifiseer

Die grafiek is redelik groot:

![](<../../images/image (207) (2) (1).png>)

Kontroleer **3 vergelykings om dit te herken**:

![](<../../images/image (430).png>)

{{#include ../../banners/hacktricks-training.md}}
