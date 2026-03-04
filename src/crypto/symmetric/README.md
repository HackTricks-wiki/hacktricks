# Simetrična kriptografija

{{#include ../../banners/hacktricks-training.md}}

## Šta tražiti u CTF-ovima

- **Nepravilna upotreba modova**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: različite greške/tajming za neispravan padding.
- **MAC confusion**: korišćenje CBC-MAC sa porukama promenljive dužine, ili MAC-then-encrypt greške.
- **XOR everywhere**: stream ciphers i custom konstrukcije često se svode na XOR sa keystream-om.

## AES modovi i nepravilna upotreba

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. To omogućava:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

Ako možeš da kontrolišeš plaintext i posmatraš ciphertext (ili cookies), pokušaj da napraviš ponovljene blokove (npr. mnogo `A`s) i traži ponavljanja.

### CBC: Cipher Block Chaining

- CBC je **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Ako sistem otkriva validan padding naspram nevalidnog padding-a, možda imaš **padding oracle**.

### CTR

CTR pretvara AES u stream cipher: `C = P XOR keystream`.

Ako se nonce/IV ponovo koristi sa istim ključem:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Sa poznatim plaintext-om možeš da povratiš keystream i dekriptuješ ostalo.

**Nonce/IV reuse exploitation patterns**

- Povrati keystream gde god je plaintext poznat/pogodiv:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Primeni povraćeni keystream bajtove da dekriptuješ bilo koji drugi ciphertext koji je proizveden sa istim key+IV na istim offset-ima.
- Visoko strukturirani podaci (npr. ASN.1/X.509 certificates, file headers, JSON/CBOR) daju velike poznate-plaintext regione. Često možeš XOR-ovati ciphertext sertifikata sa predvidljivim telom sertifikata da dobiješ keystream, pa onda dešifruješ druge tajne šifrovane pod ponovljenim IV-om. Vidi takođe [TLS & Certificates](../tls-and-certificates/README.md) za tipične rasporede sertifikata.
- Kada je više tajni istog serializovanog formata/veličine šifrovano pod istim key+IV, poravnanje polja curi čak i bez potpunog poznatog plaintext-a. Primer: PKCS#8 RSA keys iste veličine modula stavljaju fakore na podudarne offset-e (~99.6% poravnanje za 2048-bit). XORovanjem dva ciphertext-a pod ponovljenim keystream-om izoluješ `p ⊕ p'` / `q ⊕ q'`, što se može brute-oporaviti za sekunde.
- Default IVs u bibliotekama (npr. konstantni `000...01`) su kritična zamka: svaka enkripcija ponavlja isti keystream, pretvarajući CTR u reused one-time pad.

**CTR malleability**

- CTR pruža samo konfidenicjalnost: flipping bits u ciphertext-u deterministički menja iste bitove u plaintext-u. Bez authentication taga, napadači mogu neprimetno menjati podatke (npr. tweak-ovati ključeve, flagove, ili poruke).
- Koristi AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, itd.) i forsiraj verifikaciju taga da uhvatiš bit-flipove.

### GCM

GCM takođe slabo podnosi nonce reuse. Ako se isti key+nonce koristi više puta, tipično dobijaš:

- Keystream reuse za enkripciju (kao CTR), omogućavajući povraćaj plaintext-a kad je bilo koji plaintext poznat.
- Gubitak integriteta. U zavisnosti šta je izloženo (više message/tag parova pod istim nonce-om), napadači mogu biti u stanju da forguju tagove.

Operativna uputstva:

- Tretiraj "nonce reuse" u AEAD kao kritičnu ranjivost.
- Misuse-resistant AEADs (npr. GCM-SIV) redukuju posledice nonce-misuse, ali i dalje zahtevaju jedinstvene nonces/IV-e.
- Ako imaš više ciphertext-ova pod istim nonce-om, počni proverom `C1 XOR C2 = P1 XOR P2` stil relacija.

### Alati

- CyberChef za brze eksperimente: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` za scripting

## ECB exploitation patterns

ECB (Electronic Code Book) enkriptuje svaki blok nezavisno:

- equal plaintext blocks → equal ciphertext blocks
- ovo curi strukturu i omogućava cut-and-paste style napade

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ideja za detekciju: token/cookie obrazac

Ako se prijavljuješ više puta i **uvek dobijaš isti cookie**, ciphertext može biti determinističan (ECB ili fiksni IV).

Ako kreiraš dva korisnika sa uglavnom identičnim plaintext rasporedima (npr. dugi ponovljeni karakteri) i vidiš ponovljene ciphertext blokove na istim offset-ima, ECB je glavni osumnjičeni.

### Patterni eksploatacije

#### Removing entire blocks

Ako je format tokena nešto poput `<username>|<password>` i granica bloka se poklapa, ponekad možeš da kreiraš korisnika tako da blok sa `admin` bude poravnat, pa ukloniš prethodne blokove da dobiješ validan token za `admin`.

#### Moving blocks

Ako backend toleriše padding/extra spaces (`admin` vs `admin    `), možeš:

- Poravnati blok koji sadrži `admin   `
- Zameniti/ponovo iskoristiti taj ciphertext blok u drugom tokenu

## Padding Oracle

### Šta je

U CBC modu, ako server otkriva (direktno ili indirektno) da li dekriptovani plaintext ima validan PKCS#7 padding, često možeš:

- Dekriptovati ciphertext bez ključa
- Enkriptovati izabrani plaintext (forge-ovati ciphertext)

Oracle može biti:

- Specifična poruka o grešci
- Drugačiji HTTP status / veličina odgovora
- Razlika u tajmingu

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
Napomene:

- Veličina bloka je često `16` za AES.
- `-encoding 0` znači Base64.
- Koristite `-error` ako je oracle specifičan string.

### Zašto funkcioniše

CBC dekriptovanje izračunava `P[i] = D(C[i]) XOR C[i-1]`. Menjanjem bajtova u `C[i-1]` i posmatranjem da li je padding ispravan, možete vratiti `P[i]` bajt po bajt.

## Bit-flipping in CBC

Čak i bez padding oracle-a, CBC je podložan izmenama. Ako možete izmeniti ciphertext blokove i aplikacija koristi dekriptovani plaintext kao strukturirane podatke (npr. `role=user`), možete flip-ovati specifične bitove da promenite izabrane bajtove plaintext-a na odabranoj poziciji u sledećem bloku.

Tipičan CTF obrazac:

- Token = `IV || C1 || C2 || ...`
- Kontrolišete bajtove u `C[i]`
- Ciljate bajtove plaintext-a u `P[i+1]` jer `P[i+1] = D(C[i+1]) XOR C[i]`

Ovo samo po sebi nije narušavanje poverljivosti, ali predstavlja uobičajen primitivan način za privilege-escalation kada nedostaje integritet.

## CBC-MAC

CBC-MAC je siguran samo pod specifičnim uslovima (naročito **poruke fiksne dužine** i ispravna domain separation).

### Klasičan obrazac za forgeriju promenljive dužine

CBC-MAC se obično računa kao:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Ako možete dobiti tagove za izabrane poruke, često možete konstruisati tag za konkatenaciju (ili srodnu konstrukciju) bez poznavanja ključa, iskorišćavanjem načina na koji CBC povezuje blokove.

Ovo se često pojavljuje u CTF cookies/tokens koji MAC-uju username ili role pomoću CBC-MAC.

### Bezbednije alternative

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Uključi dužinu poruke / domain separation

## Stream ciphers: XOR and RC4

### Mentalni model

Većina slučajeva sa stream cipher-ima svodi se na:

`ciphertext = plaintext XOR keystream`

Dakle:

- Ako znate plaintext, dobijate keystream.
- Ako se keystream ponovo koristi (isti key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Šifrovanje zasnovano na XOR-u

Ako znate bilo koji segment plaintext-a na poziciji `i`, možete rekonstruisati keystream bajtove i dešifrovati druge ciphertext-ove na tim pozicijama.

Automatski solveri:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 je stream cipher; encrypt/decrypt su ista operacija.

Ako možete dobiti RC4 enkripciju poznatog plaintext-a pod istim ključem, možete rekonstruisati keystream i dešifrovati druge poruke iste dužine/offseta.

Referentni writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Reference

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
