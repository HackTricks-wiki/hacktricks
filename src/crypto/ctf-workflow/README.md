# Radni tok za Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Kontrolna lista za trijažu

1. Utvrdite šta imate: kodiranje naspram šifrovanja, hash-a, potpisa ili MAC-a.
2. Utvrdite šta je pod vašom kontrolom: plaintext/ciphertext, IV/nonce, ključ, oracle (padding/greška/vremensko trajanje), delimični leak.
3. Klasifikujte: simetrično (AES/CTR/GCM), javni ključ (RSA/ECC), hash/MAC (SHA/MD5/HMAC), klasično (Vigenere/XOR).
4. Prvo primenite provere s najvećom verovatnoćom uspeha: dekodirajte slojeve, proverite known-plaintext XOR, ponovnu upotrebu nonce-a, pogrešnu upotrebu režima i ponašanje oracle-a.
5. Napredne metode koristite samo ako su neophodne: rešetke (LLL/Coppersmith), SMT/Z3, side-channels.

## Onlajn resursi i alati

Ovi resursi su korisni kada treba identifikovati podatke i ukloniti slojeve ili brzo proveriti hipotezu.

### Pretraga hash-eva

- Pretražite hash izazova ako je poznato da je sintetički/javan.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Pretraga na hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Ne šaljite stvarne password hash-eve ni poverljiv materijal izazova servisima za pretragu trećih strana. Ako postoji rizik u vezi s otkrivanjem podataka, uslovima korišćenja ili pravilima takmičenja, prednost dajte offline napadu pomoću wordlist-e i pravila.

### Alati za identifikaciju

- CyberChef (Magic, dekodiranje i konverzija).<sup>[[7]](#references)</sup>
- dCode (alat za šifre i kodiranja).<sup>[[8]](#references)</sup>
- Boxentriq (rešavači supstitucija).<sup>[[9]](#references)</sup>

### Platforme za vežbu / reference

- CryptoHack (praktični kriptografski izazovi).<sup>[[10]](#references)</sup>
- Cryptopals (klasične zamke moderne kriptografije).<sup>[[11]](#references)</sup>

### Automatsko dekodiranje

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (isprobava mnoge baze/kodiranja).<sup>[[13]](#references)</sup>

Za izvorni kod ezoteričnih jezika i stanje prilagođenog interpretera, pogledajte [Crypto CTF Misc](../ctf-misc/).

## Kodiranja i klasične šifre

### Tehnika

Mnogi CTF crypto zadaci sastoje se od transformacija u slojevima: kodiranje bazom + jednostavna supstitucija + kompresija. Cilj je prepoznati slojeve i bezbedno ih ukloniti.

### Kodiranja: isprobajte više baza

Ako sumnjate na kodiranje u slojevima (base64 → base32 → …), isprobajte:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Uobičajeni pokazatelji:

- Base64: `A-Za-z0-9+/=` (padding `=` je čest)
- Base32: `A-Z2-7=` (često ima mnogo padding znakova `=`)
- Ascii85/Base85: gust niz znakova interpunkcije; ponekad omeđen sa `<~ ~>`

### Supstitucija / monoalfabetska šifra

- Rešavač kriptograma Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Oporavak zamenjene Base32 šifre fajla pomoću poznatog plaintext-a

Ako maskirano ime fajla sadrži samo `a-z2-7`, proširi se na približno `ceil(8 * byte_length / 5)` znakova nakon uklanjanja fiksnog sufiksa i isti plaintext daje isti izlaz u različitim fajlovima, testirajte **Base32 bez padding-a, praćen fiksnom zamenom simbola**. Ovi pokazatelji sami po sebi nisu dokaz. Prikupite predvidiva imena fajlova i njihove ciphertext-e, sačuvajte velika i mala slova, Base32-enkodirajte svaki plaintext i poravnajte simbole po pozicijama. Svaki ponovljeni plaintext simbol mora odgovarati istom ciphertext simbolu, a i obrnuto preslikavanje mora biti jedinstveno. U jednom slučaju ransomware-a, `ntuser.ini` i `NTUSER.DAT` dali su takve parove; time su oporavljena imena fajlova, **a ne sadržaj fajlova ni ključevi za šifrovanje**.<sup>[[28]](#references)</sup>

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

Ako cilj sadrži nemapirane simbole, pribavite više poznatih parova ili permutujte samo mapiranja neiskorišćenih Base32 simbola. Vratite padding tako da dužina bude deljiva sa osam, odbacite nevažeći Base32 i dekodirana imena koja sadrže neštampajuće znakove, a zatim ponovo enkodirajte preostale kandidate i uporedite **ceo** originalni ciphertext. Ponovljeni blokovi ciphertexta mogu pružiti dodatne pretpostavke: u gornjem slučaju, `3gpng2wv` je mapiran nazad u Base32 `gaydambq`, koji se dekodira u pet ASCII nula. Samo štampajući kandidat nije jedinstven dokaz.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatski alat za razbijanje Caesar ciphera.<sup>[[15]](#references)</sup>
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

### Morze

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Rune

Rune su često zamenski alfabeti; pretražite „futhark cipher“ i isprobajte tabele mapiranja.

## Kompresija u izazovima

### Tehnika

Kompresija se stalno pojavljuje kao dodatni sloj (zlib/deflate/gzip/xz/zstd), ponekad i ugnježdena. Ako izlaz deluje kao da će moći da se parsira, ali izgleda kao besmislica, posumnjajte na kompresiju.

### Brza identifikacija

- `file <blob>`
- Potražite magične bajtove:
  - gzip: `1f 8b`
  - zlib: obično `78 01`, `78 5e`, `78 9c` ili `78 da` (drugi bajt zavisi od oznaka kompresije)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ima **Raw Deflate/Raw Inflate**, što je često najbrži način kada blob izgleda kompresovano, ali `zlib` ne uspeva.

### Korisne CLI komande

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

## Uobičajene kripto konstrukcije u CTF-ovima

### Tehnika

Često se pojavljuju jer predstavljaju realistične greške programera ili pogrešnu upotrebu uobičajenih biblioteka. Cilj je obično da ih prepoznate i primenite poznati postupak izdvajanja ili rekonstrukcije.

### Fernet

Tipičan nagoveštaj: dva Base64 niza (token + ključ).

- Decoder/beleške: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- U Python-u: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ako vidite više delova tajne i pominje se prag `t`, verovatno je u pitanju Shamir.

- Online rekonstruktor (samo za neosetljive CTF delove tajne).<sup>[[19]](#references)</sup>

### OpenSSL formati sa salt-om

CTF-ovi ponekad daju izlaze komande `openssl enc` (zaglavlje često počinje sa `Salted__`).

Pomoćni alati za brute-force:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Opšti skup alata

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Preporučeno lokalno okruženje

Praktičan CTF skup alata:

- Python uz `pycryptodome` za simetrične primitive i brzu izradu prototipova.<sup>[[25]](#references)</sup>
- SageMath za modularnu aritmetiku, CRT, rešetke i rad sa RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 za izazove zasnovane na ograničenjima (kada se kriptografija svodi na ograničenja).<sup>[[27]](#references)</sup>

Predloženi Python paketi:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```



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
- [15] [Nayuki - Automatski alat za razbijanje Caesarove šifre](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash šifra](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère alat za rešavanje](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet dekoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Rekonstruktor Shamir-ovog deljenja tajne](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome dokumentacija](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – Razbijanje šifarskih shema na lenji način](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
{{#include ../../banners/hacktricks-training.md}}
