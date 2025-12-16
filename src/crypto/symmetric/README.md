# Simetrična kriptografija

{{#include ../../banners/hacktricks-training.md}}

## Šta tražiti na CTF-ovima

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: različite greške/vremenska odstupanja za loš padding.
- **MAC confusion**: korišćenje CBC-MAC za poruke promenljive dužine, ili greške tipa MAC-then-encrypt.
- **XOR everywhere**: stream ciphers i custom constructions se često svode na XOR sa keystream-om.

## AES režimi i zloupotrebe

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. To omogućava:

- Cut-and-paste / block reordering
- Brisanje blokova (ako format ostane validan)

Ako možeš kontrolisati plaintext i posmatrati ciphertext (ili cookies), probaj napraviti ponovljene blokove (npr., mnogo `A`-ova) i potraži ponavljanja.

### CBC: Cipher Block Chaining

- CBC je **malleable**: menjanje bita u `C[i-1]` menja predvidive bitove u `P[i]`.
- Ako sistem otkriva validnost padding-a naspram nevalidnog padding-a, možda imaš **padding oracle**.

### CTR

CTR pretvara AES u stream cipher: `C = P XOR keystream`.

Ako se nonce/IV ponovo koristi sa istim ključem:

- `C1 XOR C2 = P1 XOR P2` (klasično ponovno korišćenje keystream-a)
- Sa poznatim plaintext-om, možeš rekonstruisati keystream i dekriptovati ostale.

### GCM

GCM takođe slabo funkcioniše pri nonce reuse. Ako se isti key+nonce koristi više puta, obično dobijaš:

- Ponovno korišćenje keystream-a za enkripciju (kao CTR), što omogućava oporavak plaintext-a kada je bilo koji plaintext poznat.
- Gubitak garancija integriteta. U zavisnosti šta je izloženo (više parova message/tag pod istim nonce-om), napadači mogu uspeti da forge-uju tagove.

Operativne smernice:

- Smatraj "nonce reuse" u AEAD kritičnom ranjivošću.
- Ako imaš više ciphertext-ova pod istim nonce-om, počni proverom relacija tipa `C1 XOR C2 = P1 XOR P2`.

### Alati

- CyberChef za brze eksperimente: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` za skriptovanje

## Obrasci eksploatacije ECB

ECB (Electronic Code Book) enkriptuje svaki blok nezavisno:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ideja za detekciju: obrazac token/cookie

Ako se prijavljuješ nekoliko puta i **uvek dobijaš isti cookie**, ciphertext može biti deterministički (ECB ili fiksni IV).

Ako kreiraš dva korisnika sa uglavnom identičnim plaintext rasporedima (npr. duga ponovljena slova) i vidiš ponovljene ciphertext blokove na istim offset-ima, ECB je glavni osumnjičeni.

### Obrasci eksploatacije

#### Uklanjanje celih blokova

Ako je format tokena nešto poput `<username>|<password>` i granica bloka se poklapa, ponekad možeš kreirati korisnika tako da se `admin` blok pojavi poravnan, pa ukloniti prethodne blokove da dobiješ validan token za `admin`.

#### Premestanje blokova

Ako backend toleriše padding/extra spaces (`admin` vs `admin    `), možeš:

- Poravnati blok koji sadrži `admin   `
- Zameniti/ponovno iskoristiti taj ciphertext blok u drugi token

## Padding Oracle

### Šta je to

U CBC modu, ako server otkriva (direktno ili indirektno) da li dekriptovani plaintext ima **valid PKCS#7 padding**, često možeš:

- Dešifrovati ciphertext bez ključa
- Enkriptovati izabrani plaintext (forge ciphertext)

Oracle može biti:

- Specifična poruka o grešci
- Drugi HTTP status / veličina odgovora
- Razlika u trajanju (timingu)

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
Beleške:

- Veličina bloka je često `16` za AES.
- `-encoding 0` znači Base64.
- Upotrebite `-error` ako je oracle specifičan string.

### Zašto to radi

CBC dekripcija računa `P[i] = D(C[i]) XOR C[i-1]`. Modifikovanjem bajtova u `C[i-1]` i posmatranjem da li je padding validan, možete rekonstruisati `P[i]` bajt po bajt.

## Bit-flipping in CBC

Čak i bez padding oracle-a, CBC je podložan modifikacijama. Ako možete izmeniti blokove ciphertext-a i aplikacija koristi dešifrovani plaintext kao strukturirane podatke (npr. `role=user`), možete promeniti određene bitove da izmenite izabrane bajtove plaintext-a na odabranoj poziciji u sledećem bloku.

Tipičan CTF obrazac:

- Token = `IV || C1 || C2 || ...`
- Kontrolišete bajtove u `C[i]`
- Ciljate bajtove plaintext-a u `P[i+1]` jer `P[i+1] = D(C[i+1]) XOR C[i]`

Ovo samo po sebi nije kompromitovanje poverljivosti, ali je česta primitivna metoda za eskalaciju privilegija kada nedostaje integritet.

## CBC-MAC

CBC-MAC je bezbedan samo pod određenim uslovima (naročito **poruke fiksne dužine** i ispravna separacija domena).

### Klasični obrazac falsifikovanja za poruke promenljive dužine

CBC-MAC se obično računa kao:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Ako možete dobiti tagove za izabrane poruke, često možete napraviti tag za konkatenaciju (ili srodnu konstrukciju) bez poznavanja ključa iskorišćavajući kako CBC povezuje blokove.

Ovo se često pojavljuje u CTF cookies/tokenima koji MAC-uju username ili role koristeći CBC-MAC.

### Bezbednije alternative

- Koristite HMAC (SHA-256/512)
- Koristite CMAC (AES-CMAC) ispravno
- Uključite dužinu poruke / separaciju domena

## Stream ciphers: XOR and RC4

### Mentalni model

Većina situacija sa stream cipher-ima svodi se na:

`ciphertext = plaintext XOR keystream`

Dakle:

- Ako znate plaintext, dobijate keystream.
- Ako se keystream ponovo koristi (isti key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Ako znate bilo koji segment plaintext-a na poziciji `i`, možete rekonstruisati bajtove keystream-a i dešifrovati druge ciphertext-e na tim pozicijama.

Automatski alati:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 je stream cipher; šifrovanje i dešifrovanje su ista operacija.

Ako možete dobiti RC4 enkripciju poznatog plaintext-a pod istim ključem, možete rekonstruisati keystream i dešifrovati druge poruke iste dužine/offset-a.

Referentni writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
