# Kriptografski/kompresioni algoritmi

{{#include ../../banners/hacktricks-training.md}}

## Identifikacija algoritama

Ako se završi u kodu koristeći pomeranja udesno i ulevo, xors i nekoliko aritmetičkih operacija, velika je verovatnoća da je u pitanju implementacija nekog kriptografskog algoritma. Ovde će biti prikazani neki načini da se identifikuje koji se algoritam koristi bez potrebe da se reverzuje svaki korak.

### API funkcije

**CryptDeriveKey**

Ako se koristi ova funkcija, možete pronaći koji se **algoritam koristi** proverom vrednosti drugog parametra:

![](<../../images/image (156).png>)

Proverite tabelu mogućih algoritama i njihovih dodeljenih vrednosti ovde: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Kompresuje i dekompresuje dati buffer podataka.

**CryptAcquireContext**

Iz [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Funkcija **CryptAcquireContext** se koristi za pribavljanje handle-a za određeni key container unutar određenog cryptographic service provider (CSP). **Ovaj vraćeni handle se koristi u pozivima CryptoAPI funkcija koje koriste odabrani CSP.**

**CryptCreateHash**

Inicira hashing toka podataka. Ako se koristi ova funkcija, možete pronaći koji se **algoritam koristi** proverom vrednosti drugog parametra:

![](<../../images/image (549).png>)

\
Proverite tabelu mogućih algoritama i njihovih vrednosti ovde: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Konstantе u kodu

Ponekad je za identifikovanje algoritma dovoljno što koristi specifičnu i jedinstvenu vrednost.

![](<../../images/image (833).png>)

Ako u Google potražite prvu konstantu, dobićete sledeće:

![](<../../images/image (529).png>)

Dakle, možete pretpostaviti da je dekompilovana funkcija **sha256 calculator.**\
Možete pretražiti i bilo koju od ostalih konstanti i verovatno ćete dobiti isti rezultat.

### informacije iz data sekcije

Ako kod nema značajne konstante, moguće je da **učitava informacije iz .data sekcije**.\
Možete pristupiti tim podacima, **grupisati prvi dword** i potražiti ga na Google-u kao što smo radili u prethodnom delu:

![](<../../images/image (531).png>)

U ovom slučaju, ako potražite **0xA56363C6** možete pronaći da je povezan sa **tabelama AES algoritma**.

## RC4 **(Symmetric Crypt)**

### Karakteristike

Sastoji se od 3 glavna dela:

- **Initialization stage/**: Kreira **table of values from 0x00 to 0xFF** (256 bytes ukupno, 0x100). Ova tabela se obično naziva **Substitution Box** (ili SBox).
- **Scrambling stage**: Prolazi kroz prethodno kreiranu tabelu (petlja od 0x100 iteracija, ponovo) i menja svaku vrednost pomoću **semi-random** bajtova. Za stvaranje ovih semi-random bajtova koristi se RC4 **key**. RC4 **keys** mogu biti **između 1 i 256 bajtova** dužine, ali se obično preporučuje da budu duži od 5 bajtova. U praksi, RC4 keys su često 16 bajtova dugi.
- **XOR stage**: Na kraju, plain-text ili cyphertext se **XOR-uje sa vrednostima koje su prethodno kreirane**. Funkcija za enkripciju i dekripciju je ista. Za to se vrši **petlja kroz kreiranih 256 bajtova** onoliko puta koliko je potrebno. Ovo se obično prepoznaje u dekompajlovanom kodu kao **%256 (mod 256)**.

> [!TIP]
> **Da biste identifikovali RC4 u disassemblu/dekompajlovanom kodu možete proveriti 2 petlje veličine 0x100 (uz korišćenje ključa) i potom XOR ulaznih podataka sa 256 vrednosti kreiranih u te dve petlje, verovatno koristeći %256 (mod 256).**

### **Initialization stage/Substitution Box:** (Obratite pažnju na broj 256 koji se koristi kao brojač i kako se 0 upisuje na svako mesto od 256 elemenata)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### **Karakteristike**

- Upotreba **substitution boxes i lookup tabela**
- Moguće je **prepoznati AES zahvaljujući upotrebi specifičnih vrednosti u lookup tabelama** (konstanti). _Imajte u vidu da konstanta može biti **smeštena** u binaru ili **kreirana** **dinamički**._
- **Encryption key** mora biti deljiv sa **16** (obično 32B) i obično se koristi **IV** od 16B.

### SBox konstante

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### Karakteristike

- Retko se sreće u malveru ali postoje primeri (Ursnif)
- Jednostavno je odrediti da li je algoritam Serpent na osnovu njegove dužine (izuzetno duga funkcija)

### Identifikacija

Na donjoj slici primetite kako se koristi konstanta **0x9E3779B9** (ova konstanta se takođe koristi i kod drugih crypto algoritama kao što je **TEA** - Tiny Encryption Algorithm).\
Takođe obratite pažnju na **veličinu petlje** (**132**) i broj XOR operacija u instrukcijama u **disassembly**-ju i u primeru **koda**:

![](<../../images/image (547).png>)

Kao što je ranije pomenuto, ovaj kod se u bilo kom dekompajleru može videti kao **veoma duga funkcija** jer u njoj **nema skokova**. Dekomplovani kod može izgledati kao sledeći:

![](<../../images/image (513).png>)

Dakle, moguće je identifikovati ovaj algoritam proverom **magic number** i početnih XOR-ova, primećivanjem **veoma duge funkcije** i upoređivanjem nekih **instrukcija** iz te funkcije sa implementacijom (npr. shift left za 7 i rotate left za 22).

## RSA **(Asymmetric Crypt)**

### Karakteristike

- Komplikovaniji od simetričnih algoritama
- Nema konstantе! (custom implementacije je teško odrediti)
- KANAL (a crypto analyzer) ne daje naznake za RSA jer se oslanja na konstante.

### Identifikacija poređenjem

![](<../../images/image (1113).png>)

- U liniji 11 (levo) postoji `+7) >> 3` što je isto kao u liniji 35 (desno): `+7) / 8`
- Linija 12 (levo) proverava da li je `modulus_len < 0x040` a u liniji 36 (desno) proverava da li je `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Karakteristike

- 3 funkcije: Init, Update, Final
- Slične inicijalizacione funkcije

### Identifikacija

**Init**

Možete identifikovati oba proverom konstanti. Imajte u vidu da sha_init ima 1 konstantu koju MD5 nema:

![](<../../images/image (406).png>)

**MD5 Transform**

Obratite pažnju na upotrebu više konstanti

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Manji i efikasniji pošto je njegova funkcija da pronađe slučajne promene u podacima
- Koristi lookup tabele (tako da možete identifikovati konstante)

### Identifikacija

Proverite **lookup table konstante**:

![](<../../images/image (508).png>)

CRC hash algoritam izgleda ovako:

![](<../../images/image (391).png>)

## APLib (Compression)

### Karakteristike

- Nema prepoznatljivih konstanti
- Možete pokušati da napišete algoritam u python-u i pretražite sličnosti online

### Identifikacija

Graf je prilično veliki:

![](<../../images/image (207) (2) (1).png>)

Proverite **3 poređenja da biste ga prepoznali**:

![](<../../images/image (430).png>)

## Implementacione greške u Elliptic-Curve potpisima

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 zahteva od HashEdDSA verifikatora da razdvoje potpis `sig = R || s` i odbace bilo koji skalar sa `s \geq n`, gde je `n` red grupe. Biblioteka `elliptic` u JS-u je preskočila tu proveru granice, pa svaki napadač koji zna validan par `(msg, R || s)` može falsifikovati alternativne potpise `s' = s + k·n` i ponovo enkodirati `sig' = R || s'`.
- Verifikacione rutine koriste samo `s mod n`, zato su svi `s'` koji su kongruentni `s` prihvaćeni iako su različiti stringovi bajtova. Sistemi koji tretiraju potpise kao kanoničke tokene (blockchain consensus, replay cache-ovi, DB ključevi, itd.) mogu biti desinhronizovani jer stroge implementacije odbacuju `s'`.
- Prilikom revizije drugog HashEdDSA koda, osigurajte da parser validira i tačku `R` i dužinu skalara; pokušajte dodati multipla od `n` poznatom ispravnom `s` da potvrdite da verifikator pravilno odbacuje.

### ECDSA skraćivanje vs. hashovi sa vodećim nulama

- ECDSA verifikatori moraju koristiti samo najlevlje `log2(n)` bitova hash-a poruke `H`. U `elliptic`, pomoćna funkcija za skraćivanje je izračunavala `delta = (BN(msg).byteLength()*8) - bitlen(n)`; konstruktor `BN` odbacuje vodeće nule u oktetima, pa je svaki hash koji počinje sa ≥4 nulte bajta na krivama kao što je secp192r1 (192-bitni red) izgledao kao da ima samo 224 bita umesto 256.
- Verifikator je desno pomerao za 32 bita umesto za 64, proizvodeći `E` koji se ne poklapa sa vrednošću koju koristi potpisivač. Validni potpisi na tim hash-ovima stoga ne uspevaju sa verovatnoćom ≈`2^-32` za SHA-256 ulaze.
- Testirajte i “sve dobro” vektor i varijante sa vodećim nulama (npr. Wycheproof `ecdsa_secp192r1_sha256_test.json` slučaj `tc296`) na ciljnoj implementaciji; ako verifikator ne slaže sa potpisivačem, pronašli ste eksploatabilnu grešku skraćivanja.

### Pokretanje Wycheproof vektora protiv biblioteka
- Wycheproof isporučuje JSON test setove koji enkodiraju malformirane tačke, malleable skalare, neobične hash-ove i druge corner case-ove. Izgradnja harness-a oko `elliptic` (ili bilo koje crypto biblioteke) je jednostavna: učitajte JSON, deserijalizujte svaki test slučaj i proverite da li implementacija odgovara očekivanom `result` flagu.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Neuspehe treba triajirati kako bi se razlikovale povrede specifikacije od lažno pozitivnih rezultata. Za dve greške navedene iznad, neuspešni Wycheproof slučajevi su odmah ukazali na nedostatak provera opsega skalara (EdDSA) i pogrešno skraćivanje heša (ECDSA).
- Integrisati harness u CI tako da regresije u parsiranju skalara, rukovanju hešom ili validnosti koordinata pokreću testove čim se pojave. Ovo je posebno korisno za visokonivojske jezike (JS, Python, Go) gde su suptilne konverzije bignum vrednosti lake za pogrešno izvođenje.

## Reference

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
