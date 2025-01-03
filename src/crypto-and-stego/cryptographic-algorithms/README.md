# Kriptografski/Kompresioni Algoritmi

## Kriptografski/Kompresioni Algoritmi

{{#include ../../banners/hacktricks-training.md}}

## Identifikacija Algoritama

Ako završite u kodu **koristeći pomeranja udesno i ulevo, XOR-ove i nekoliko aritmetičkih operacija**, veoma je verovatno da je to implementacija **kriptografskog algoritma**. Ovde će biti prikazani neki načini da se **identifikuje algoritam koji se koristi bez potrebe da se obrne svaki korak**.

### API funkcije

**CryptDeriveKey**

Ako se ova funkcija koristi, možete saznati koji se **algoritam koristi** proverom vrednosti drugog parametra:

![](<../../images/image (156).png>)

Proverite ovde tabelu mogućih algoritama i njihovih dodeljenih vrednosti: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Kompresuje i dekompresuje dati bafer podataka.

**CryptAcquireContext**

Iz [dokumentacije](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Funkcija **CryptAcquireContext** se koristi za sticanje rukohvata za određeni kontejner ključeva unutar određenog kriptografskog servisnog provajdera (CSP). **Ovaj vraćeni rukohvat se koristi u pozivima funkcija CryptoAPI** koje koriste odabrani CSP.

**CryptCreateHash**

Inicira heširanje toka podataka. Ako se ova funkcija koristi, možete saznati koji se **algoritam koristi** proverom vrednosti drugog parametra:

![](<../../images/image (549).png>)

\
Proverite ovde tabelu mogućih algoritama i njihovih dodeljenih vrednosti: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Konstantne u kodu

Ponekad je zaista lako identifikovati algoritam zahvaljujući činjenici da mora koristiti posebnu i jedinstvenu vrednost.

![](<../../images/image (833).png>)

Ako pretražujete prvu konstantu na Google-u, ovo je ono što dobijate:

![](<../../images/image (529).png>)

Stoga, možete pretpostaviti da je dekompilovana funkcija **sha256 kalkulator.**\
Možete pretražiti bilo koju od drugih konstanti i dobićete (verovatno) isti rezultat.

### informacija o podacima

Ako kod nema nijednu značajnu konstantu, može biti da **učitava informacije iz .data sekcije**.\
Možete pristupiti tim podacima, **grupisati prvi dword** i pretražiti ga na Google-u kao što smo uradili u prethodnoj sekciji:

![](<../../images/image (531).png>)

U ovom slučaju, ako tražite **0xA56363C6**, možete pronaći da je povezan sa **tabelama AES algoritma**.

## RC4 **(Simetrična Kriptografija)**

### Karakteristike

Sastoji se od 3 glavne komponente:

- **Faza inicijalizacije/**: Kreira **tabelu vrednosti od 0x00 do 0xFF** (ukupno 256 bajtova, 0x100). Ova tabela se obično naziva **Substituciona Kutija** (ili SBox).
- **Faza premeštanja**: **Prolazi kroz tabelu** kreiranu ranije (petlja od 0x100 iteracija, ponovo) modifikujući svaku vrednost sa **polu-nasumičnim** bajtovima. Da bi se kreirali ovi polu-nasumični bajtovi, koristi se RC4 **ključ**. RC4 **ključevi** mogu biti **između 1 i 256 bajtova dužine**, međutim obično se preporučuje da budu iznad 5 bajtova. Obično, RC4 ključevi su 16 bajtova dužine.
- **XOR faza**: Na kraju, običan tekst ili šifrovani tekst se **XOR-uje sa vrednostima kreiranim ranije**. Funkcija za enkripciju i dekripciju je ista. Za ovo, **proći će se kroz kreiranih 256 bajtova** onoliko puta koliko je potrebno. Ovo se obično prepoznaje u dekompilovanom kodu sa **%256 (mod 256)**.

> [!NOTE]
> **Da biste identifikovali RC4 u disasembleru/dekompilovanom kodu, možete proveriti 2 petlje veličine 0x100 (uz korišćenje ključa) i zatim XOR ulaznih podataka sa 256 vrednosti kreiranih ranije u 2 petlje, verovatno koristeći %256 (mod 256)**

### **Faza inicijalizacije/Substituciona Kutija:** (Obratite pažnju na broj 256 korišćen kao brojač i kako se 0 piše na svakom mestu od 256 karaktera)

![](<../../images/image (584).png>)

### **Faza premeštanja:**

![](<../../images/image (835).png>)

### **XOR Faza:**

![](<../../images/image (904).png>)

## **AES (Simetrična Kriptografija)**

### **Karakteristike**

- Korišćenje **substitucionih kutija i tabela za pretragu**
- Moguće je **razlikovati AES zahvaljujući korišćenju specifičnih vrednosti tabela za pretragu** (konstanti). _Napomena da se **konstant** može **čuvati** u binarnom **ili kreirati** _**dinamički**._
- **Ključ za enkripciju** mora biti **deljiv** sa **16** (obično 32B) i obično se koristi **IV** od 16B.

### SBox konstante

![](<../../images/image (208).png>)

## Serpent **(Simetrična Kriptografija)**

### Karakteristike

- Retko se nalazi neki malware koji ga koristi, ali postoje primeri (Ursnif)
- Lako je odrediti da li je algoritam Serpent ili ne na osnovu njegove dužine (ekstremno duga funkcija)

### Identifikacija

Na sledećoj slici obratite pažnju na to kako se konstanta **0x9E3779B9** koristi (napomena da se ova konstanta takođe koristi i od drugih kripto algoritama kao što je **TEA** -Tiny Encryption Algorithm).\
Takođe obratite pažnju na **veličinu petlje** (**132**) i **broj XOR operacija** u **disasembleru** i u **primeru koda**:

![](<../../images/image (547).png>)

Kao što je ranije pomenuto, ovaj kod može biti vizualizovan unutar bilo kog dekompilatora kao **veoma duga funkcija** jer **nema skakanja** unutar nje. Dekomplovani kod može izgledati ovako:

![](<../../images/image (513).png>)

Stoga, moguće je identifikovati ovaj algoritam proverom **magične brojke** i **početnih XOR-ova**, videći **veoma dugu funkciju** i **upoređujući** neke **instrukcije** duge funkcije **sa implementacijom** (kao što su pomeranje ulevo za 7 i rotacija ulevo za 22).

## RSA **(Asimetrična Kriptografija)**

### Karakteristike

- Složeniji od simetričnih algoritama
- Nema konstanti! (prilagođene implementacije su teške za određivanje)
- KANAL (analizator kriptografije) ne uspeva da pokaže naznake o RSA jer se oslanja na konstante.

### Identifikacija poređenjem

![](<../../images/image (1113).png>)

- U liniji 11 (levo) postoji `+7) >> 3` što je isto kao u liniji 35 (desno): `+7) / 8`
- Linija 12 (levo) proverava da li je `modulus_len < 0x040` a u liniji 36 (desno) proverava da li je `inputLen+11 > modulusLen`

## MD5 & SHA (heš)

### Karakteristike

- 3 funkcije: Init, Update, Final
- Slične inicijalizacione funkcije

### Identifikacija

**Init**

Možete identifikovati oboje proverom konstanti. Napomena da sha_init ima 1 konstantu koju MD5 nema:

![](<../../images/image (406).png>)

**MD5 Transformacija**

Obratite pažnju na korišćenje više konstanti

![](<../../images/image (253) (1) (1).png>)

## CRC (heš)

- Manji i efikasniji jer je njegova funkcija da pronađe slučajne promene u podacima
- Koristi tabele za pretragu (tako da možete identifikovati konstante)

### Identifikacija

Proverite **konstante tabela za pretragu**:

![](<../../images/image (508).png>)

CRC heš algoritam izgleda ovako:

![](<../../images/image (391).png>)

## APLib (Kompresija)

### Karakteristike

- Nema prepoznatljivih konstanti
- Možete pokušati da napišete algoritam u Python-u i pretražite slične stvari na mreži

### Identifikacija

Grafik je prilično veliki:

![](<../../images/image (207) (2) (1).png>)

Proverite **3 poređenja da biste ga prepoznali**:

![](<../../images/image (430).png>)

{{#include ../../banners/hacktricks-training.md}}
