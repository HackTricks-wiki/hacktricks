# Simetrična kriptografija

{{#include ../../banners/hacktricks-training.md}}

## Na šta obratiti pažnju u CTF-ovima

- **Pogrešna upotreba režima**: ECB obrasci, CBC podložnost izmenama, ponovna upotreba nonce-a u CTR/GCM.
- **Padding oracles**: različite greške/vremena odziva za neispravan padding.
- **Zabuna oko MAC-a**: upotreba CBC-MAC-a sa porukama promenljive dužine ili greške tipa MAC-then-encrypt.
- **XOR svuda**: stream cipher-i i prilagođene konstrukcije često se svode na XOR sa keystream-om.

## AES režimi i pogrešna upotreba

NIST definiše režime poverljivosti ECB, CBC i CTR u dokumentu SP 800-38A, a autentifikovano šifrovanje GCM u dokumentu SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB otkriva obrasce: jednaki blokovi otvorenog teksta → jednaki blokovi šifrovanog teksta. To omogućava:

- Cut-and-paste / promenu redosleda blokova
- Brisanje blokova (ako format ostane ispravan)

Ako možete da kontrolišete otvoreni tekst i posmatrate šifrovani tekst (ili kolačiće), pokušajte da napravite ponovljene blokove (npr. mnogo znakova `A`) i potražite ponavljanja.

### CBC: Cipher Block Chaining

- CBC je **podložan izmenama**: promena bitova u `C[i-1]` menja predvidljive bitove u `P[i]`, a istovremeno oštećuje `P[i-1]`. Izmenom IV-a cilja se prvi blok otvorenog teksta, bez oštećivanja prethodnog bloka otvorenog teksta.
- Ako sistem otkriva da li je padding ispravan ili neispravan, možda postoji **padding oracle**.

### CTR

CTR pretvara AES u stream cipher: `C = P XOR keystream`.

Ako se nonce/IV ponovo upotrebi sa istim ključem:

- `C1 XOR C2 = P1 XOR P2` (klasična ponovna upotreba keystream-a)
- Ako je poznat otvoreni tekst, možete da oporavite keystream i dešifrujete druge poruke.

**Obrasci iskorišćavanja ponovne upotrebe nonce-a/IV-a**

- Oporavite keystream svuda gde je otvoreni tekst poznat/može da se pogodi:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  Primeni oporavljene bajtove keystream-a da dešifruješ bilo koji drugi ciphertext nastao korišćenjem istog key+IV na istim pomerajima.
- Visoko strukturirani podaci (npr. ASN.1/X.509 sertifikati, zaglavlja fajlova, JSON/CBOR) sadrže velike regione poznatog plaintext-a. Često možeš da XOR-uješ ciphertext sertifikata sa predvidljivim telom sertifikata da bi izveo keystream, a zatim dešifrovao druge tajne šifrovane uz ponovo korišćen IV. Pogledaj i [TLS & Certificates](../tls-and-certificates/README.md) za uobičajene rasporede sertifikata.<sup>[[1]](#references)</sup>
- Kada je više tajni **istog serijalizovanog formata/veličine** šifrovano istim key+IV, poravnanje polja leak-uje informacije čak i bez potpuno poznatog plaintext-a. Primer: PKCS#8 RSA ključevi iste veličine modula smeštaju proste faktore na iste pomeraje (oko 99,6% poravnanja za 2048-bitne ključeve). XOR-ovanje dva ciphertext-a uz ponovo korišćen keystream izdvaja `p ⊕ p'` / `q ⊕ q'`, što se može brute-force-om oporaviti za nekoliko sekundi.<sup>[[1]](#references)</sup>
- Podrazumevani IV-ovi u bibliotekama (npr. konstantni `000...01`) predstavljaju kritičan izvor grešaka: svako šifrovanje ponavlja isti keystream, pretvarajući CTR u ponovo korišćeni one-time pad.<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR pruža samo poverljivost: promena bitova u ciphertext-u deterministički menja iste bitove u plaintext-u. Bez authentication tag-a, napadači mogu neprimećeno da menjaju podatke (npr. ključeve, zastavice ili poruke).
- Koristi AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 itd.) i obavezno proveravaj tag da bi otkrio promene bitova.

### GCM

GCM je takođe ozbiljno ranjiv pri ponovnoj upotrebi nonce-a. Ako se isti key+nonce upotrebi više puta, obično dolazi do sledećeg:

- Ponovne upotrebe keystream-a pri šifrovanju (kao kod CTR-a), što omogućava oporavak plaintext-a kada je poznat bilo koji plaintext.
- Gubitka garancija integriteta. U zavisnosti od toga šta je izloženo (više parova poruka/tag pod istim nonce-om), napadači mogu da falsifikuju tag-ove.

Operativne smernice:

- Tretiraj „ponovnu upotrebu nonce-a“ u AEAD-u kao kritičnu ranjivost.
- AEAD algoritmi otporni na zloupotrebu, kao što je AES-GCM-SIV, smanjuju posledice ponovne upotrebe nonce-a. Pozivaoci i dalje treba da obezbede jedinstvene nonce-ove, kako zahteva interfejs konstrukcije; slučajna ponovna upotreba ima ograničene posledice u poređenju sa običnim GCM-om.<sup>[[3]](#references)[[4]](#references)</sup>
- Ako imaš više ciphertext-ova pod istim nonce-om, prvo proveri relacije oblika `C1 XOR C2 = P1 XOR P2`.

### Tools

- [CyberChef](https://gchq.github.io/CyberChef/) za brze eksperimente.<sup>[[8]](#references)</sup>
- Python paket [PyCryptodome](https://www.pycryptodome.org/) za skriptovanje.<sup>[[9]](#references)</sup>

## Obrasci eksploatacije ECB-a

ECB (Electronic Code Book) šifruje svaki blok nezavisno:

- jednaki plaintext blokovi → jednaki ciphertext blokovi
- ovo leak-uje strukturu i omogućava napade tipa cut-and-paste

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ideja za otkrivanje: obrazac tokena/cookie-ja

Ako se prijaviš više puta i **uvek dobiješ isti cookie**, ciphertext može biti deterministički (ECB ili fiksni IV).

Ako napraviš dva korisnika sa uglavnom identičnim rasporedom plaintext-a (npr. dugačkim nizovima ponovljenih znakova) i vidiš ponovljene ciphertext blokove na istim pomerajima, ECB je glavni osumnjičeni.

### Obrasci eksploatacije

#### Uklanjanje celih blokova

Ako je format tokena nešto poput `<username>|<password>` i granica bloka se poklapa, ponekad možeš da napraviš korisnika tako da se blok `admin` poravna, a zatim ukloniš prethodne blokove i dobiješ važeći token za `admin`.

#### Premeštanje blokova

Ako backend prihvata padding/dodatne razmake (`admin` naspram `admin    `), možeš da:

- Poravnaš blok koji sadrži `admin   `
- Zameniš/ponovo upotrebiš taj ciphertext blok u drugom tokenu

## Padding Oracle

### Šta je to

U CBC režimu, ako server otkrije (direktno ili indirektno) da li dešifrovani plaintext ima **važeći PKCS#7 padding**, često možeš da:<sup>[[7]](#references)</sup>

- Dešifruješ ciphertext bez ključa
- Napraviš ciphertext koji se dešifruje u izabrani plaintext kada možeš da pošalješ prilagođene prethodne blokove ili IV-ove, a aplikacija prihvata dobijenu poruku sa važećim padding-om

Oracle može biti:

- Konkretna poruka o grešci
- Različit HTTP status / veličina odgovora
- Vremenska razlika

### Praktična eksploatacija

PadBuster je klasičan alat:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Primer:

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
  -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```

Beleške:

- Veličina bloka je često `16` za AES.
- `-encoding 0` znači Base64.
- Koristite `-error` ako je oracle određeni string.

### Zašto funkcioniše

CBC dešifrovanje računa `P[i] = D(C[i]) XOR C[i-1]`. Menjanjem bajtova u `C[i-1]` i posmatranjem da li je padding ispravan, možete oporaviti `P[i]` bajt po bajt.

## Bit-flipping u CBC-u

Čak i bez padding oracle-a, CBC je podložan manipulaciji. Ako možete da menjate blokove šifrovanog teksta, a aplikacija koristi dešifrovani otvoreni tekst kao strukturisane podatke (npr. `role=user`), možete da preokrenete određene bitove i promenite odabrane bajtove otvorenog teksta na željenoj poziciji u sledećem bloku.

Tipičan CTF obrazac:

- Token = `IV || C1 || C2 || ...`
- Vi kontrolišete bajtove u `C[i]`
- Ciljate bajtove otvorenog teksta u `P[i+1]` jer je `P[i+1] = D(C[i+1]) XOR C[i]`

Ovo samo po sebi ne razbija poverljivost, ali je čest primitiv za eskalaciju privilegija kada nedostaje integritet.

## CBC-MAC

CBC-MAC je bezbedan samo pod određenim uslovima (posebno **poruke fiksne dužine** i ispravna separacija domena). AES-CMAC je standardizovana konstrukcija koja bezbedno obrađuje ulaze promenljive dužine.<sup>[[5]](#references)</sup>

### Klasičan obrazac falsifikovanja za promenljivu dužinu

CBC-MAC se obično računa ovako:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Ako možete da dobijete tag-ove za odabrane poruke, često možete da napravite tag za konkatenaciju (ili srodnu konstrukciju) bez познавања кључа, искоришћавањем начина на који CBC повезује блокове.

Ово се често појављује у CTF колачићима/токенима који користе CBC-MAC за MAC-овање корисничког имена или улоге.

### Безбедније алтернативе

- Користите HMAC (SHA-256/512)
- Правилно користите CMAC (AES-CMAC)
- Укључите дужину поруке / сепарацију домена

## Стрим шифре: XOR и RC4

### Ментални модел

Већина ситуација са стрим шифрама своди се на:

`ciphertext = plaintext XOR keystream`

Дакле:

- Ако знате отворени текст, можете да повратите keystream.
- Ако се keystream поново користи (исти кључ+nonce), `C1 XOR C2 = P1 XOR P2`.

### Шифровање засновано на XOR-у

Ако знате било који сегмент отвореног текста на позицији `i`, можете да повратите бајтове keystream-а и дешифрујете друге шифроване текстове на тим позицијама.

Аутоматски решавачи:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 је застарела стрим шифра; шифровање и дешифровање су иста XOR операција. Познате пристрасности чине је неприкладном за нове системе, а TLS изричито забрањује њене cipher suite-ове.<sup>[[6]](#references)</sup>

Ако можете да добијете RC4 шифровање познатог отвореног текста помоћу истог кључа, можете да повратите keystream и дешифрујете друге поруке исте дужине/помераја.

Референтни writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Немарност наспрам мајсторства у криптографији](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Препорука за режиме рада блоковских шифара](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Препорука за Galois/Counter Mode (GCM) и GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Аутентификовано шифровање отпорно на злоупотребу nonce-а](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - AES-CMAC алгоритам](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Забрана RC4 cipher suite-ова](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Тестирање на Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome документација](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
