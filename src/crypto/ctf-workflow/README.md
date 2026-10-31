# Crypto CTF tok rada

{{#include ../../banners/hacktricks-training.md}}

## Kontrolna lista za trijažu

1. Utvrdite šta imate: encoding, encryption, hash, signature ili MAC.
2. Odredite šta je pod vašom kontrolom: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing) ili delimični leak.
3. Klasifikujte: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Prvo primenite provere s najvećom verovatnoćom uspeha: dekodirajte slojeve, isprobajte known-plaintext XOR, ponovnu upotrebu nonce-a, pogrešnu upotrebu režima i ponašanje oracle-a.
5. Napredne metode primenjujte samo kada je neophodno: lattices (LLL/Coppersmith), SMT/Z3 i side-channels.

## Onlajn resursi i alati

Korisni su kada treba da identifikujete sadržaj i uklonite slojeve ili brzo potvrdite hipotezu.

### Pretraga hash vrednosti

- Potražite hash izazova ako je poznato da je sintetički/javan.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Pretraga na hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Ne šaljite stvarne password hash vrednosti niti poverljiv materijal izazova servisima za pretragu trećih strana. Ako postoji rizik u vezi sa otkrivanjem podataka, uslovima korišćenja ili pravilima takmičenja, radije koristite offline napad pomoću wordlist-a i pravila.

### Alati za identifikaciju

- CyberChef (Magic, dekodiranje i konverzija).<sup>[[7]](#references)</sup>
- dCode (okruženje za testiranje šifara/encoding-a).<sup>[[8]](#references)</sup>
- Boxentriq (alati za rešavanje substitution šifara).<sup>[[9]](#references)</sup>

### Platforme za vežbu / reference

- CryptoHack (praktični izazovi iz kriptografije).<sup>[[10]](#references)</sup>
- Cryptopals (klasične zamke moderne kriptografije).<sup>[[11]](#references)</sup>

### Automatizovano dekodiranje

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (isprobava mnoge baze/encoding-e).<sup>[[13]](#references)</sup>

## Encoding-i i klasične šifre

### Tehnika

Mnogi CTF crypto zadaci sastoje se od slojevitih transformacija: base encoding + jednostavna substitution + kompresija. Cilj je da identifikujete slojeve i bezbedno ih uklonite.

### Encoding-i: isprobajte mnogo baza

Ako sumnjate na slojevito kodiranje (base64 → base32 → …), isprobajte:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Uobičajeni pokazatelji:

- Base64: `A-Za-z0-9+/=` (padding znakom `=` je čest)
- Base32: `A-Z2-7=` (često ima mnogo padding znakova `=`)
- Ascii85/Base85: mnogo znakova interpunkcije; ponekad omeđen sa `<~ ~>`

### Substitution / monoalphabetic šифрование

- Boxentriq alat za rešavanje cryptogram-а.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Oporavak na osnovu poznatog plaintext-a za Base32 imena fajlova sa substitution-om

Kada zamagljeno ime fajla sadrži samo znakove `a-z2-7`, nakon uklanjanja fiksnog sufiksa ima približno `ceil(8 * byte_length / 5)` znakova i isti plaintext daje isti izlaz u različitim fajlovima, testirajte **unpadded Base32 iza kog sledi fiksna zamena simbola**. Ovi pokazatelji sami po sebi nisu dokaz. Prikupite predvidiva imena fajlova i odgovarajuće ciphertext-е, sačuvajte velika i mala slova, kodirajte svaki plaintext pomoću Base32, pa poravnajte simbole po pozicijama. Svaki ponovljeni simbol plaintext-а mora se mapirati na isti simbol ciphertext-а, a obrnuto mapiranje takođe mora biti jedinstveno. U jednom slučaju ransomware-a, `ntuser.ini` i `NTUSER.DAT` dali su takve parove; time su oporavljena imena fajlova, **a ne sadržaj fajlova niti ključevi za encryption**.<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

Ako cilj sadrži nepovezane simbole, pribavite još poznatih parova ili permutujte samo neiskorišćena preslikavanja simbola Base32. Vratite padding tako da dužina bude deljiva sa osam, odbacite neispravan Base32 i neštampiva dekodirana imena, a zatim ponovo kodirajte preostale kandidate i uporedite **ceo** originalni šifrat. Blokovi šifrata koji se ponavljaju mogu dati dodatne pretpostavke: u gornjem slučaju, `3gpng2wv` je preslikan nazad u Base32 `gaydambq`, koji se dekodira u pet ASCII nula. Samo štampiv kandidat nije jedinstven dokaz.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Automatski alat za razbijanje Caesar šifre Nayuki.<sup>[[15]](#references)</sup>
- Rumkin Atbash alat.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère alat.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon cipher

Često se pojavljuje u grupama od 5 bitova ili 5 slova:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Rune

Rune su često zamenski alfabeti; pretražite „futhark cipher“ i isprobajte tabele preslikavanja.

## Kompresija u izazovima

### Tehnika

Kompresija se stalno pojavljuje kao dodatni sloj (zlib/deflate/gzip/xz/zstd), ponekad i ugnježden. Ako se izlaz skoro može parsirati, ali izgleda kao besmislica, posumnjajte na kompresiju.

### Brza identifikacija

- `file <blob>`
- Potražite magične bajtove:
  - gzip: `1f 8b`
  - zlib: najčešće `78 01`, `78 5e`, `78 9c` ili `78 da` (drugi bajt zavisi od zastavica kompresije)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ima **Raw Deflate/Raw Inflate**, što je često najbrži put kada blob izgleda kompresovano, ali `zlib` ne uspeva.

### Koristan CLI

```bash
python3 - blob.bin <<'PY'
import sys, zlib
data = open(sys.argv[1], 'rb').read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
  try:
    print(zlib.decompress(data, wbits=wbits)[:200])
  except Exception:
    pass
PY
```

## Uobičajeni kriptografski obrasci u CTF-ovima

### Tehnika

Oni se često pojavljuju jer predstavljaju realistične greške programera ili čestu pogrešnu upotrebu biblioteka. Cilj je obično da ih prepoznate i primenite poznati postupak za izdvajanje ili rekonstrukciju.

### Fernet

Tipičan nagoveštaj: dva Base64 niza (token + ključ).

- Dekoder/b beleške: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- U Pythonu: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ako vidite više delova tajne i pominje se prag `t`, verovatno je reč o Shamir-u.

- Online alat za rekonstrukciju (samo za nesenzitivne CTF delove tajne).<sup>[[19]](#references)</sup>

### OpenSSL formati sa saltom

CTF-ovi ponekad daju izlaze komande `openssl enc` (zaglavlje često počinje sa `Salted__`).

Alati za brute-force:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Opšti skup alata

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Preporučeno lokalno okruženje

Praktičan CTF skup alata:

- Python i `pycryptodome` za simetrične primitive i brzo prototipiranje.<sup>[[25]](#references)</sup>
- SageMath za modularnu aritmetiku, CRT, rešetke i rad sa RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 za izazove zasnovane na ograničenjima (kada se kriptografija može svesti na ograničenja).<sup>[[27]](#references)</sup>

Preporučeni Python paketi:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [pretraga hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode alati](https://www.dcode.fr/tools-list)
- [9] [Boxentriq alati za razbijanje šifara](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - automatski razbijač Caesar šifre](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash šifra](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère rešavač](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet dekoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [rekonstruktor Shamir deljenja tajne](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome dokumentacija](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – lenji način za razbijanje šifarskih algoritama](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
