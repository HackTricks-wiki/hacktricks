# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Na šta obratiti pažnju u CTF-ovima

- **Pogrešna upotreba režima**: ECB obrasci, CBC malleability, ponovna upotreba CTR/GCM nonce-a.
- **Padding oracles**: različite greške/vremena odziva za neispravan padding.
- **MAC konfuzija**: korišćenje CBC-MAC-a sa porukama promenljive dužine ili greške tipa MAC-then-encrypt.
- **XOR svuda**: stream cipher-i i prilagođene konstrukcije često se svode na XOR sa keystream-om.

## AES režimi i pogrešna upotreba

NIST definiše ECB, CBC i CTR režime poverljivosti u dokumentu SP 800-38A, kao i authenticated encryption GCM u dokumentu SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB otkriva obrasce: jednaki blokovi plaintext-a → jednaki blokovi ciphertext-a. To omogućava:

- Cut-and-paste / preuređivanje blokova
- Brisanje blokova (ako format ostane validan)

Ako možete da kontrolišete plaintext i posmatrate ciphertext (ili cookies), pokušajte da napravite ponovljene blokove (npr. mnogo `A`-ova) i potražite ponavljanja.

### CBC: Cipher Block Chaining

- CBC je **malleable**: promena bitova u `C[i-1]` menja predvidljive bitove u `P[i]`, dok istovremeno kvari `P[i-1]`. Menjanje IV-a cilja prvi plaintext blok bez kvarenja prethodnog plaintext bloka.
- Ako sistem otkriva validan padding u odnosu na nevalidan padding, možda imate **padding oracle**.

### CTR

CTR pretvara AES u stream cipher: `C = P XOR keystream`.

Ako se nonce/IV ponovo koristi sa istim ključem:

- `C1 XOR C2 = P1 XOR P2` (klasična ponovna upotreba keystream-a)
- Uz poznati plaintext možete povratiti keystream i dekriptovati druge poruke.

**Obrasci iskorišćavanja ponovne upotrebe Nonce/IV-a**

- Povratite keystream svuda gde je plaintext poznat ili se može pogoditi:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Primijenite povraćene bajtove keystream-a na dešifrovanje bilo kog drugog ciphertext-a proizvedenog istim ključem+IV-om na istim offsetima.
- Visoko strukturisani podaci (npr. ASN.1/X.509 sertifikati, zaglavlja fajlova, JSON/CBOR) daju velike regione poznatog plaintext-a. Često možete XOR-ovati ciphertext sertifikata sa predvidljivim telom sertifikata da biste izveli keystream, a zatim dešifrovali druge tajne šifrovane ponovo korišćenim IV-om. Pogledajte i [TLS & Certificates](../tls-and-certificates/README.md) za tipične rasporede sertifikata.<sup>[[1]](#references)</sup>
- Kada se više tajni istog serijalizovanog formata/veličine šifruje istim ključem+IV-om, poravnanje polja otkriva informacije čak i bez potpunog poznatog plaintext-a. Primer: PKCS#8 RSA ključevi iste veličine modula postavljaju faktore prostih brojeva na odgovarajuće offsete (~99,6% poravnanja za 2048-bitne ključeve). XOR-ovanje dva ciphertext-a pod ponovo korišćenim keystream-om izoluje `p ⊕ p'` / `q ⊕ q'`, što se može brute-force-ovati za nekoliko sekundi.<sup>[[1]](#references)</sup>
- Podrazumevani IV-ovi u bibliotekama (npr. konstantni `000...01`) predstavljaju kritičnu grešku: svaka enkripcija ponavlja isti keystream, pretvarajući CTR u ponovo korišćeni one-time pad.<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR pruža samo poverljivost: promena bitova u ciphertext-u deterministički menja iste bitove u plaintext-u. Bez authentication tag-a, napadači mogu neprimećeno da menjaju podatke (npr. ključeve, zastavice ili poruke).
- Koristite AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 itd.) i obavezno proveravajte tag kako biste otkrili promene bitova.

### GCM

GCM se takođe ozbiljno kompromituje pri ponovnoj upotrebi nonce-a. Ako se isti ključ+nonce koristi više od jednom, obično dobijate:

- Ponovnu upotrebu keystream-a za enkripciju (kao kod CTR-a), što omogućava povrat plaintext-a kada je bilo koji plaintext poznat.
- Gubitak garancija integriteta. U zavisnosti od toga šta je izloženo (više parova poruka/tag pod istim nonce-om), napadači mogu biti u stanju da krivotvore tag-ove.

Operativne smernice:

- Tretirajte "nonce reuse" u AEAD-u kao kritičnu ranjivost.
- AEAD režimi otporni na pogrešnu upotrebu, kao što je AES-GCM-SIV, smanjuju posledice ponovne upotrebe nonce-a. Pozivaoci i dalje treba da obezbede jedinstvene nonce-ove kako zahtevaju interfejsi konstrukcije; slučajna ponovna upotreba ima ograničene posledice u poređenju sa običnim GCM-om.<sup>[[3]](#references)[[4]](#references)</sup>
- Ako imate više ciphertext-ova pod istim nonce-om, počnite proverom relacija u stilu `C1 XOR C2 = P1 XOR P2`.

### Alati

- [CyberChef](https://gchq.github.io/CyberChef/) za brze eksperimente.<sup>[[8]](#references)</sup>
- Python paket [PyCryptodome](https://www.pycryptodome.org/) za scripting.<sup>[[9]](#references)</sup>

## Obrasci iskorišćavanja ECB-a

ECB (Electronic Code Book) šifruje svaki blok nezavisno:

- jednaki plaintext blokovi → jednaki ciphertext blokovi
- ovo otkriva strukturu i omogućava napade u stilu cut-and-paste

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ideja za detekciju: obrazac tokena/cookie-ja

Ako se prijavite nekoliko puta i **uvek dobijete isti cookie**, ciphertext je možda deterministički (ECB ili fiksni IV).

Ako napravite dva korisnika sa uglavnom identičnim rasporedima plaintext-a (npr. dugim ponovljenim karakterima) i vidite ponovljene ciphertext blokove na istim offsetima, ECB je glavni osumnjičeni.

### Obrasci iskorišćavanja

#### Uklanjanje celih blokova

Ako je format tokena nešto poput `<username>|<password>` i granica bloka se poklapa, ponekad možete napraviti korisnika tako da blok `admin` bude pravilno poravnat, a zatim ukloniti prethodne blokove da biste dobili validan token za `admin`.

#### Pomeranje blokova

Ako backend prihvata padding/dodatne razmake (`admin` naspram `admin    `), možete:

- Poravnati blok koji sadrži `admin   `
- Zameniti/ponovo upotrebiti taj ciphertext blok u drugom tokenu

## Padding Oracle

### Šta je to

U CBC režimu, ako server direktno ili indirektno otkriva da li dekriptovani plaintext ima **validan PKCS#7 padding**, često možete:<sup>[[7]](#references)</sup>

- Dešifrovati ciphertext bez ključa
- Konstruisati ciphertext koji se dešifruje u izabrani plaintext kada možete poslati posebno pripremljene prethodne blokove ili IV-ove i kada aplikacija prihvati rezultujuću poruku sa validnim padding-om

Oracle može biti:

- Specifična poruka o grešci
- Drugačiji HTTP status / veličina odgovora
- Razlika u vremenu odziva

### Praktično iskorišćavanje

PadBuster je klasičan alat:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Primer:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Napomene:

- Veličina bloka je često `16` za AES.
- `-encoding 0` znači Base64.
- Koristite `-error` ako je oracle određeni string.

### Zašto funkcioniše

CBC dešifrovanje računa `P[i] = D(C[i]) XOR C[i-1]`. Menjanjem bajtova u `C[i-1]` i posmatranjem da li je padding validan, možete oporaviti `P[i]` bajt po bajt.

## Bit-flipping in CBC

Čak i bez padding oracle-a, CBC je podložan malleability napadima. Ako možete da menjate ciphertext blokove, a aplikacija koristi dešifrovani plaintext kao strukturirane podatke (npr. `role=user`), možete promeniti određene bitove kako biste izmenili odabrane bajtove plaintext-a na određenoj poziciji u sledećem bloku.

Tipičan CTF obrazac:

- Token = `IV || C1 || C2 || ...`
- Vi kontrolišete bajtove u `C[i]`
- Ciljate bajtove plaintext-a u `P[i+1]` zato što je `P[i+1] = D(C[i+1]) XOR C[i]`

Ovo samo po sebi nije probijanje poverljivosti, ali je čest primitive za eskalaciju privilegija kada integritet nije obezbeđen.

## CBC-MAC

CBC-MAC je bezbedan samo pod određenim uslovima (naročito kod **poruka fiksne dužine** i pravilne separacije domena). AES-CMAC je standardizovana konstrukcija koja bezbedno obrađuje ulaze promenljive dužine.<sup>[[5]](#references)</sup>

### Klasičan obrazac forgery-ja promenljive dužine

CBC-MAC se obično računa ovako:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Ako možete da dobijete tag-ove za poruke po izboru, često možete da napravite tag za konkatenaciju (ili povezanu konstrukciju) bez poznavanja ključa, iskorišćavanjem načina na koji CBC ulančava blokove.

Ovo se često pojavljuje u CTF kolačićima/tokenima koji koriste CBC-MAC za autentikaciju username-a ili role-a.

### Bezbednije alternative

- Koristite HMAC (SHA-256/512)
- Ispravno koristite CMAC (AES-CMAC)
- Uključite dužinu poruke / separaciju domena

## Stream ciphers: XOR and RC4

### Mentalni model

Većina situacija sa stream cipher-ima svodi se na:

`ciphertext = plaintext XOR keystream`

Dakle:

- Ako znate plaintext, oporavljate keystream.
- Ako se keystream ponovo koristi (isti key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Ako znate bilo koji segment plaintext-a na poziciji `i`, možete oporaviti bajtove keystream-a i dešifrovati druge ciphertext-e na tim pozicijama.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 je zastareli stream cipher; encrypt/decrypt su ista XOR operacija. Njegovi poznati bias-i čine ga nepogodnim za nove sisteme, a TLS izričito zabranjuje njegove cipher suite-ove.<sup>[[6]](#references)</sup>

Ako možete da dobijete RC4 encryption poznatog plaintext-a koristeći isti ključ, možete oporaviti keystream i dešifrovati druge poruke iste dužine/pomaka.

Referentni writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Nemarnost nasuprot umeću u kriptografiji](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Preporuka za režime rada blokovskih šifara](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Preporuka za Galois/Counter Mode (GCM) i GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Autentikovana enkripcija otporna na pogrešnu upotrebu nonce-a](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - AES-CMAC algoritam](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Zabrana RC4 cipher suite-ova](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP vodič za testiranje web bezbednosti - Testiranje na Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome dokumentacija](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
