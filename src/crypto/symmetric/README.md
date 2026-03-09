# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## Šta tražiti na CTF-ovima

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: različite greške/tajming za loš padding.
- **MAC confusion**: using CBC-MAC with variable-length messages, or MAC-then-encrypt mistakes.
- **XOR everywhere**: stream ciphers i prilagođene konstrukcije često se svode na XOR sa keystream-om.

## AES modovi i zloupotrebe

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. To omogućava:

- Cut-and-paste / block reordering
- Brisanje blokova (ako format ostane validan)

Ako možeš kontrolisati plaintext i posmatrati ciphertext (ili cookies), pokušaj da napraviš ponovljene blokove (npr. mnogo `A`-ova) i traži ponavljanja.

### CBC: Cipher Block Chaining

- CBC is **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Ako sistem otkriva validan padding naspram nevalidnog, možda imaš **padding oracle**.

### CTR

CTR turns AES into a stream cipher: `C = P XOR keystream`.

Ako se nonce/IV ponovo koristi sa istim ključem:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Ako je plaintext poznat, možeš rekonstruisati keystream i dešifrovati druge.

Obrasci eksploatacije ponovnog korišćenja Nonce/IV

- Rekonstruši keystream gde je plaintext poznat/pogodiv:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Primeni rekonstruisane keystream bajtove da dešifruješ bilo koji drugi ciphertext koji je proizveden sa istim key+IV na istim offset-ima.
- Visoko strukturirani podaci (npr. ASN.1/X.509 certificates, file headers, JSON/CBOR) daju velike poznate plaintext regione. Često možeš XOR-ovati ciphertext sertifikata sa predvidivim telom sertifikata da izvedeš keystream, zatim dešifruješ druge tajne enkriptovane pod reuse-ovanim IV. Vidi takođe [TLS & Certificates](../tls-and-certificates/README.md) za tipične layout-e sertifikata.
- Kada je više tajni istog serijalizovanog formata/veličine enkriptovano pod istim key+IV, poravnanje polja curi čak i bez potpunog poznatog plaintext-a. Primer: PKCS#8 RSA keys iste veličine modula stavljaju faktore na podudarne offset-e (~99.6% poravnanje za 2048-bit). XOR-ovanjem dva ciphertext-a pod reuse-ovanim keystream-om izoluješ `p ⊕ p'` / `q ⊕ q'`, što se može bruteforce-ovano rekonstruisati za sekunde.
- Podrazumevani IV u bibliotekama (npr. konstantni `000...01`) su kritična pogrešna praksa: svaka enkripcija ponavlja isti keystream, pretvarajući CTR u reuse-ovani one-time pad.

CTR malleability

- CTR pruža samo konfidencijalnost: flipovanje bitova u ciphertext-u deterministički flipuje iste bitove u plaintext-u. Bez autentikacionog taga, napadači mogu neprimetno menjati podatke (npr. tweak-ovati ključeve, flagove ili poruke).
- Koristi AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, itd.) i primoraj verifikaciju taga da otkriješ bit-flipove.

### GCM

GCM takođe loše pada pod nonce reuse. Ako se isti key+nonce koristi više puta, obično dobijaš:

- Keystream reuse za enkripciju (kao CTR), omogućavajući oporavak plaintext-a kad god je neki plaintext poznat.
- Gubitak integriteta. U zavisnosti šta je izloženo (više message/tag parova pod istim nonce-om), napadači mogu biti u mogućnosti da forge-uju tagove.

Operativna uputstva:

- Tretiraj "nonce reuse" u AEAD kao kritičnu ranjivost.
- Misuse-resistant AEADs (npr. GCM-SIV) smanjuju posledice nonce-misuse-a ali i dalje zahtevaju jedinstvene nonces/IV-e.
- Ako imaš više ciphertext-ova pod istim nonce-om, počni proverom relacija tipa `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## Obrasci eksploatacije ECB-a

ECB (Electronic Code Book) šifruje svaki blok nezavisno:

- equal plaintext blocks → equal ciphertext blocks
- ovo curi strukturu i omogućava cut-and-paste stil napada

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ideja detekcije: token/cookie pattern

Ako se prijaviš više puta i **uvek dobijaš isti cookie**, ciphertext može biti deterministički (ECB ili fiksni IV).

Ako kreiraš dva user-a sa uglavnom identičnim plaintext layout-ima (npr. dugi ponovljeni karakteri) i vidiš ponovljene ciphertext blokove na istim offset-ima, ECB je glavni osumnjičeni.

### Obrasci eksploatacije

#### Removing entire blocks

Ako je token format nešto poput `<username>|<password>` i granica bloka se poklapa, ponekad možeš kreirati user-a tako da se `admin` blok poravna, pa zatim ukloniti prethodne blokove da dobiješ validan token za `admin`.

#### Moving blocks

Ako backend toleriše padding/dodatne razmake (`admin` vs `admin    `), možeš:

- Poravnati blok koji sadrži `admin   `
- Zameniti/ponovo iskoristiti taj ciphertext blok u drugom tokenu

## Padding Oracle

### Šta je to

U CBC modu, ako server otkriva (direktno ili indirektno) da li dekriptovani plaintext ima **valid PKCS#7 padding**, često možeš:

- Dešifrovati ciphertext bez ključa
- Enkriptovati izabrani plaintext (forge-ovati ciphertext)

Oracle može biti:

- Specifična poruka o grešci
- Drugačiji HTTP status / veličina odgovora
- Razlika u tajmingu

### Praktična eksploatacija

PadBuster is the classic tool:

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

### Zašto radi

CBC dekripcija izračunava `P[i] = D(C[i]) XOR C[i-1]`. Menjanjem bajtova u `C[i-1]` i posmatranjem da li je padding važeći, možete povratiti `P[i]` bajt-po-bajt.

## Bit-flipping u CBC

Čak i bez padding oracle-a, CBC je malleable. Ako možete izmeniti blokove šifroteksta i aplikacija koristi dekriptovani plaintext kao strukturirane podatke (npr. `role=user`), možete flip-ovati specifične bitove da promenite odabrane bajtove plaintext-a na odabranoj poziciji u sledećem bloku.

Tipičan CTF obrazac:

- Token = `IV || C1 || C2 || ...`
- Vi kontrolišete bajtove u `C[i]`
- Ciljate bajtove plaintext-a u `P[i+1]` jer `P[i+1] = D(C[i+1]) XOR C[i]`

Ovo samo po sebi nije kršenje poverljivosti, ali je uobičajen primitiv za eskalaciju privilegija kada nedostaje integritet.

## CBC-MAC

CBC-MAC je siguran samo pod specifičnim uslovima (naročito **poruke fiksne dužine** i ispravno odvajanje domena).

### Klasičan obrazac falsifikovanja za promenljivu dužinu

CBC-MAC se obično izračunava kao:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Ako možete dobiti tagove za poruke po izboru, često možete napraviti tag za konkatenaciju (ili srodnu konstrukciju) bez poznavanja ključa, iskorišćujući kako CBC povezuje blokove.

Ovo se često pojavljuje u CTF cookie-ima/tokens koji MAC-uju username ili role pomoću CBC-MAC.

### Bezbednije alternative

- Koristite HMAC (SHA-256/512)
- Koristite CMAC (AES-CMAC) ispravno
- Uključite dužinu poruke / odvajanje domena

## Stream ciphers: XOR and RC4

### Mentalni model

Većina situacija sa stream cipher-ima svodi se na:

`ciphertext = plaintext XOR keystream`

Dakle:

- Ako znate plaintext, dobijate keystream.
- Ako se keystream ponovo koristi (isti key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Ako znate bilo koji segment plaintext-a na poziciji `i`, možete rekonstruisati bajtove keystream-a i dekriptovati druge šifrotekste na tim pozicijama.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 je stream cipher; enkripcija/dekripcija su ista operacija.

Ako možete dobiti RC4 enkripciju poznatog plaintext-a pod istim ključem, možete rekonstruisati keystream i dekriptovati druge poruke iste dužine/offseta.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
