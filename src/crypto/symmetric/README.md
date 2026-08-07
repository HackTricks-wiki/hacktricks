# Simetrična kriptografija

{{#include ../../banners/hacktricks-training.md}}

## Na šta treba obratiti pažnju u CTF-ovima

- **Pogrešna upotreba režima**: ECB obrasci, CBC malleability, CTR/GCM ponovna upotreba nonce-a.
- **Padding oracles**: različite greške/vremena odziva za neispravan padding.
- **MAC konfuzija**: korišćenje CBC-MAC-a sa porukama promenljive dužine ili greške tipa MAC-then-encrypt.
- **XOR svuda**: stream ciphers i prilagođene konstrukcije često se svode na XOR sa keystream-om.

## AES režimi i pogrešna upotreba

### ECB: Electronic Codebook

ECB otkriva obrasce: jednaki blokovi plaintext-a → jednaki blokovi ciphertext-a. To omogućava:

- Cut-and-paste / preuređivanje blokova
- Brisanje blokova (ako format ostane validan)

Ako možete da kontrolišete plaintext i posmatrate ciphertext (ili cookies), pokušajte da napravite ponovljene blokove (npr. mnogo `A` znakova) i potražite ponavljanja.

### CBC: Cipher Block Chaining

- CBC je **malleable**: menjanje bitova u `C[i-1]` menja predvidive bitove u `P[i]`.
- Ako sistem otkriva validan naspram nevalidnog padding-a, možda imate **padding oracle**.

### CTR

CTR pretvara AES u stream cipher: `C = P XOR keystream`.

Ako se nonce/IV ponovo koristi sa istim ključem:

- `C1 XOR C2 = P1 XOR P2` (klasična ponovna upotreba keystream-a)
- Uz poznati plaintext možete rekonstruisati keystream i dekriptovati druge podatke.

**Obrasci iskorišćavanja ponovne upotrebe nonce-a/IV-a**

- Rekonstruišite keystream svuda gde je plaintext poznat ili se može pogoditi:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Primenite rekonstruisane bajtove keystream-a da dekriptujete bilo koji drugi ciphertext kreiran istim ključem+IV-om na istim offsetima.
- Visoko strukturirani podaci (npr. ASN.1/X.509 sertifikati, zaglavlja fajlova, JSON/CBOR) daju velike regione poznatog plaintext-a. Često možete XOR-ovati ciphertext sertifikata sa predvidivim telom sertifikata da biste izveli keystream, a zatim dekriptovati druge tajne šifrovane ponovo korišćenim IV-om. Pogledajte i [TLS & Certificates](../tls-and-certificates/README.md) za tipične rasporede sertifikata.<sup>[[1]](#references)</sup>
- Kada je više tajni istog **serijalizovanog formata/veličine** šifrovano istim ključem+IV-om, poravnanje polja otkriva informacije čak i bez potpunog poznatog plaintext-a. Primer: PKCS#8 RSA ključevi iste veličine modula postavljaju proste faktore na odgovarajuće offsete (oko 99,6% poravnanja za 2048-bitne ključeve). XOR-ovanje dva ciphertext-a uz ponovo korišćeni keystream izoluje `p ⊕ p'` / `q ⊕ q'`, što se može brute-force-ovati za nekoliko sekundi.<sup>[[1]](#references)</sup>
- Podrazumevani IV-ovi u bibliotekama (npr. konstantni `000...01`) predstavljaju kritičan footgun: svako šifrovanje ponavlja isti keystream, pretvarajući CTR u ponovo korišćeni one-time pad.<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR pruža samo poverljivost: menjanje bitova u ciphertext-u deterministički menja iste bitove u plaintext-u. Bez authentication tag-a, napadači mogu neprimećeno da menjaju podatke (npr. ključeve, flagove ili poruke).
- Koristite AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 itd.) i zahtevajte proveru tag-a kako biste otkrili izmene bitova.

### GCM

GCM se takođe ozbiljno kompromituje pri ponovnoj upotrebi nonce-a. Ako se isti key+nonce koristi više puta, obično dobijate:

- Ponovnu upotrebu keystream-a pri šifrovanju (kao kod CTR-a), što omogućava oporavak plaintext-a kada je bilo koji plaintext poznat.
- Gubitak garancija integriteta. U zavisnosti od toga šta je izloženo (više parova poruka/tag-ova sa istim nonce-om), napadači mogu moći da falsifikuju tag-ove.

Operativne smernice:

- Tretirajte „ponovnu upotrebu nonce-a“ u AEAD-u kao kritičnu ranjivost.
- AEAD algoritmi otporni na pogrešnu upotrebu (npr. GCM-SIV) smanjuju posledice pogrešne upotrebe nonce-a, ali i dalje zahtevaju jedinstvene nonce-ove/IV-ove.
- Ako imate više ciphertext-ova sa istim nonce-om, počnite proverom relacija tipa `C1 XOR C2 = P1 XOR P2`.

### Alati

- CyberChef za brze eksperimente: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` za scripting

## Obrasci iskorišćavanja ECB-a

ECB (Electronic Code Book) šifruje svaki blok nezavisno:

- jednaki blokovi plaintext-a → jednaki blokovi ciphertext-a
- ovo otkriva strukturu i omogućava napade tipa cut-and-paste

![Dijagram dekripcije blokova u ECB režimu](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ideja za detekciju: obrazac tokena/cookie-ja

Ako se prijavite nekoliko puta i **uvek dobijete isti cookie**, ciphertext može biti deterministički (ECB ili fiksni IV).

Ako kreirate dva korisnika sa uglavnom identičnim rasporedom plaintext-a (npr. dugim ponovljenim karakterima) i vidite ponovljene blokove ciphertext-a na istim offsetima, ECB je glavni osumnjičeni.

### Obrasci iskorišćavanja

#### Uklanjanje čitavih blokova

Ako je format tokena nešto poput `<username>|<password>` i granica bloka je poravnata, ponekad možete kreirati korisnika tako da blok `admin` bude poravnat, a zatim ukloniti prethodne blokove da biste dobili validan token za `admin`.

#### Pomeranje blokova

Ako backend prihvata padding/dodatne razmake (`admin` naspram `admin    `), možete:

- Poravnati blok koji sadrži `admin   `
- Zameniti/ponovo upotrebiti taj ciphertext blok u drugom tokenu

## Padding Oracle

### Šta je to

U CBC režimu, ako server direktno ili indirektno otkriva da li dekriptovani plaintext ima **validan PKCS#7 padding**, često možete:

- Dekriptovati ciphertext bez ključa
- Šifrovati izabrani plaintext (falsifikovati ciphertext)

Oracle može biti:

- Konkretna poruka o grešci
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

CBC dešifrovanje izračunava `P[i] = D(C[i]) XOR C[i-1]`. Menjanjem bajtova u `C[i-1]` i posmatranjem da li je padding validan, možete oporaviti `P[i]` bajt po bajt.

## Bit-flipping u CBC-u

Čak i bez padding oracle-a, CBC je malleable. Ako možete da menjate blokove ciphertext-a, a aplikacija koristi dešifrovani plaintext kao strukturisane podatke (npr. `role=user`), možete promeniti određene bitove kako biste izmenili odabrane bajtove plaintext-a na izabranoj poziciji u sledećem bloku.

Tipičan CTF obrazac:

- Token = `IV || C1 || C2 || ...`
- Vi kontrolišete bajtove u `C[i]`
- Ciljate bajtove plaintext-a u `P[i+1]`, jer je `P[i+1] = D(C[i+1]) XOR C[i]`

Ovo samo po sebi nije razbijanje poverljivosti, ali je čest primitive za privilege-escalation kada integritet nedostaje.

## CBC-MAC

CBC-MAC je bezbedan samo pod određenim uslovima (posebno za **poruke fiksne dužine** i ispravnu separaciju domena).

### Klasičan obrazac forgery-ja za promenljivu dužinu

CBC-MAC se obično izračunava ovako:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Ako možete da dobijete tag-ove za poruke po izboru, često možete da kreirate tag za konkatenaciju (ili srodnu konstrukciju) bez poznavanja ključa, iskorišćavanjem načina na koji CBC ulančava blokove.

Ovo se često pojavljuje u CTF cookies/token-ima koji koriste CBC-MAC za MAC korisničkog imena ili role-a.

### Bezbednije alternative

- Koristite HMAC (SHA-256/512)
- Koristite CMAC (AES-CMAC) ispravno
- Uključite dužinu poruke / separaciju domena

## Stream cipher-i: XOR i RC4

### Mentalni model

Većina situacija sa stream cipher-ima svodi se na:

`ciphertext = plaintext XOR keystream`

Dakle:

- Ako znate plaintext, oporavljate keystream.
- Ako se keystream ponovo koristi (isti key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Ako znate bilo koji segment plaintext-a na poziciji `i`, možete da oporavite bajtove keystream-a i dešifrujete druge ciphertext-e na tim pozicijama.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 je stream cipher; encrypt/decrypt su ista operacija.

Ako možete da dobijete RC4 encryption poznatog plaintext-a pod istim ključem, možete da oporavite keystream i dešifrujete druge poruke iste dužine/offset-a.

Referentni writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Reference

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
