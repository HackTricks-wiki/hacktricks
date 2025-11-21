# Kriptografski/kompresioni algoritmi

{{#include ../../banners/hacktricks-training.md}}

## Identifikacija algoritama

Ako naiđete u kodu koji koristi shift rights and lefts, xors i nekoliko aritmetičkih operacija, vrlo je verovatno da je to implementacija kriptografskog algoritma. Ovde će biti prikazani neki načini da se identifikuje koji algoritam se koristi bez potrebe da se reverzuje svaki korak.

### API funkcije

**CryptDeriveKey**

Ako se ova funkcija koristi, možete naći koji **algorithm is being used** proverom vrednosti drugog parametra:

![](<../../images/image (156).png>)

Pogledajte ovde tabelu mogućih algoritama i njihovih dodeljenih vrednosti: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Kompresuje i dekompresuje dati buffer podataka.

**CryptAcquireContext**

Prema [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Funkcija **CryptAcquireContext** se koristi za dobijanje handla ka određenom key container-u unutar određenog cryptographic service provider-a (CSP). **Ovaj vraćeni handle se koristi u pozivima CryptoAPI** funkcija koje koriste izabrani CSP.

**CryptCreateHash**

Pokreće hashing toka podataka. Ako se ova funkcija koristi, možete naći koji **algorithm is being used** proverom vrednosti drugog parametra:

![](<../../images/image (549).png>)

\
Pogledajte ovde tabelu mogućih algoritama i njihovih dodeljenih vrednosti: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Konstantne u kodu

Ponekad je zaista lako identifikovati algoritam zahvaljujući činjenici da mora da koristi neku specijalnu i jedinstvenu vrednost.

![](<../../images/image (833).png>)

Ako pretražite prvu konstantu na Google-u, dobijate ovo:

![](<../../images/image (529).png>)

Dakle, možete pretpostaviti da je dekompajlirana funkcija **sha256 calculator.**\
Možete pretražiti bilo koju od ostalih konstanti i verovatno ćete dobiti isti rezultat.

### Informacije iz .data

Ako kod nema značajnih konstanti, moguće je da **učitava informacije iz .data sekcije**.\
Možete pristupiti tim podacima, **grupisati prvi dword** i potražiti ga na google-u kao što smo uradili u prethodnom delu:

![](<../../images/image (531).png>)

U ovom slučaju, ako potražite **0xA56363C6** možete naći da je povezan sa **tabelama AES algoritma**.

## RC4 **(Symmetric Crypt)**

### Karakteristike

Sastoji se iz 3 glavna dela:

- **Initialization stage/**: Kreira **tabelu vrednosti od 0x00 do 0xFF** (ukupno 256 bajtova, 0x100). Ova tabela se obično zove **Substitution Box** (ili SBox).
- **Scrambling stage**: Prolazi kroz prethodno kreiranu tabelu (petlja od 0x100 iteracija, opet) i menja svaku vrednost pomoću **polu-slučajnih** bajtova. Za generisanje tih polu-slučajnih bajtova koristi se RC4 **key**. RC4 **keys** mogu biti **između 1 i 256 bajtova**, međutim obično se preporučuje da budu duži od 5 bajtova. Uobičajeno, RC4 keys su 16 bajtova.
- **XOR stage**: Konačno, plain-text ili cyphertext se **XOR-uje sa vrednostima kreiranim ranije**. Funkcija za enkripciju i dekripciju je ista. Za ovo će se izvršavati **petlja kroz kreiranih 256 bajtova** onoliko puta koliko je potrebno. Ovo se obično prepoznaje u dekompajliranom kodu pomoću **%256 (mod 256)**.

> [!TIP]
> **Da biste identifikovali RC4 u disasembliranom/dekompajliranom kodu možete proveriti da li postoje 2 petlje veličine 0x100 (uz korišćenje ključa), a zatim XOR ulaznih podataka sa 256 vrednosti kreiranih u te dve petlje, verovatno koristeći %256 (mod 256)**

### **Initialization stage/Substitution Box:** (Obratite pažnju na broj 256 koji se koristi kao brojač i kako se u svako mesto od 256 piše 0)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### Karakteristike

- Upotreba **substitution boxes i lookup tabela**
- Moguće je **razlikovati AES zahvaljujući upotrebi specifičnih vrednosti u lookup tabelama** (konstante). _Imajte na umu da konstanta može biti **smeštena** u binarnom fajlu **ili kreirana** _**dinamički**._
- **Encryption key** mora biti deljiv sa **16** (obično 32B) i obično se koristi **IV** od 16B.

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### Karakteristike

- Retko se nalazi u malverima, ali postoje primeri (Ursnif)
- Jednostavno je odrediti da li je algoritam Serpent na osnovu njegove dužine (izuzetno duga funkcija)

### Identifikacija

Na sledećoj slici obratite pažnju kako se koristi konstanta **0x9E3779B9** (napomena: ova konstanta se takođe koristi i u drugim kripto algoritmima kao što je **TEA** - Tiny Encryption Algorithm).\
Takođe obratite pažnju na **veličinu petlje** (**132**) i broj XOR operacija u **disasembliranim** instrukcijama i u primeru **koda**:

![](<../../images/image (547).png>)

Kao što je već pomenuto, ovaj kod se u bilo kom dekompajleru može prikazati kao **veoma duga funkcija** jer **nema skokova** unutar nje. Dekompajlirani kod može izgledati slično sledećem:

![](<../../images/image (513).png>)

Dakle, moguće je identifikovati ovaj algoritam proverom **magic number** i početnih XOR-ova, uočavanjem **veoma duge funkcije** i **upoređivanjem** nekih **instrukcija** iz te duge funkcije **sa implementacijom** (npr. shift left za 7 i rotate left za 22).

## RSA **(Asymmetric Crypt)**

### Karakteristike

- Složeniji od simetričnih algoritama
- Nema konstanti! (prilagođene implementacije je teško odrediti)
- KANAL (a crypto analyzer) ne prikazuje indikacije za RSA jer se oslanja na konstante.

### Identifikacija upoređivanjem

![](<../../images/image (1113).png>)

- U liniji 11 (levo) postoji `+7) >> 3` što je isto kao u liniji 35 (desno): `+7) / 8`
- U liniji 12 (levo) se proverava `modulus_len < 0x040`, a u liniji 36 (desno) se proverava `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Karakteristike

- 3 funkcije: Init, Update, Final
- Slične funkcije za inicijalizaciju

### Identifikacija

**Init**

Možete identifikovati oba proverom konstanti. Imajte na umu da sha_init ima jednu konstantu koju MD5 nema:

![](<../../images/image (406).png>)

**MD5 Transform**

Obratite pažnju na upotrebu više konstanti

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Manji i efikasniji jer je njegova funkcija da pronađe slučajne promene u podacima
- Koristi lookup tabele (tako da možete identifikovati konstante)

### Identifikacija

Proverite **lookup table constants**:

![](<../../images/image (508).png>)

CRC hash algoritam izgleda ovako:

![](<../../images/image (391).png>)

## APLib (Compression)

### Karakteristike

- Nema prepoznatljivih konstanti
- Možete pokušati da napišete algoritam u python-u i tražite sličnosti online

### Identifikacija

Graf je prilično veliki:

![](<../../images/image (207) (2) (1).png>)

Proverite **3 upoređenja da biste ga prepoznali**:

![](<../../images/image (430).png>)

## Greške u implementacijama potpisa na eliptičkim krivama

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 zahteva da HashEdDSA verifikatori raskomponuju potpis `sig = R || s` i odbace bilo koji skalar sa `s \geq n`, gde je `n` red grupe. `elliptic` JS biblioteka je preskočila tu proveru ograničenja, pa svaki napadač koji zna važeći par `(msg, R || s)` može falsifikovati alternativne potpise `s' = s + k·n` i nastaviti da re-enkodira `sig' = R || s'`.
- Rutinе za verifikaciju koriste samo `s mod n`, dakle svi `s'` kongruentni sa `s` su prihvaćeni iako su različiti bajt nizovi. Sistemi koji tretiraju potpise kao kanoničke tokene (blockchain consensus, replay caches, DB keys, itd.) mogu biti desinhronizovani jer strože implementacije će odbiti `s'`.
- Prilikom audita drugog HashEdDSA koda, osigurajte da parser validira i tačku `R` i dužinu skalara; pokušajte da dodate višekratnike `n` poznato dobronamernom `s` da biste potvrdili da verifier zatvara pristup (fails closed).

### ECDSA truncation vs. leading-zero hashes

- ECDSA verifikatori moraju koristiti samo levih `log2(n)` bita hash-a poruke `H`. U `elliptic`, pomoćna funkcija za truncation je izračunavala `delta = (BN(msg).byteLength()*8) - bitlen(n)`; konstruktor `BN` uklanja vodeće nul-octete, tako da je svaki hash koji počinje sa ≥4 nula bajta na krivama poput secp192r1 (192-bitni red) izgledao kao da ima samo 224 bita umesto 256.
- Verifikator je right-shift-ovao za 32 bita umesto 64, proizvodeći `E` koji se ne poklapa sa vrednošću koju koristi potpisivač. Važeći potpisi nad tim hash-evima stoga ne uspevaju sa verovatnoćom ≈`2^-32` za SHA-256 ulaze.
- Pohranite i „sve u redu“ vektor i varijante sa vodećim nulama (npr. Wycheproof `ecdsa_secp192r1_sha256_test.json` slučaj `tc296`) u ciljnu implementaciju; ako verifier ne slaže sa potpisivačem, pronašli ste iskoristivu grešku u truncation-u.

### Testiranje Wycheproof vektora protiv biblioteka
- Wycheproof isporučuje JSON test setove koji kodiraju malformirane tačke, malleable scalars, neuobičajene hash-eve i druge corner case-ove. Izgradnja harness-a oko `elliptic` (ili bilo koje crypto biblioteke) je jednostavna: učitajte JSON, deserializujte svaki test slučaj i asertujte da implementacija odgovara očekivanom `result` flag-u.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Neuspehe treba trijagovati kako bi se razlikovale povrede specifikacije od lažno pozitivnih rezultata. Za dve greške iznad, neuspešni Wycheproof testovi su odmah ukazali na nedostatak provere opsega skalarnih vrednosti (EdDSA) i pogrešno skraćivanje heša (ECDSA).
- Integrisati harness u CI tako da regresije u parsiranju skalarnih vrednosti, obradi heša ili validnosti koordinata pokreću testove čim se pojave. Ovo je posebno korisno za visokonivojske jezike (JS, Python, Go) gde je lako pogrešiti kod suptilnih bignum konverzija.

## References

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
