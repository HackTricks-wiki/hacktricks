# Crypto CTF tok rada

{{#include ../../banners/hacktricks-training.md}}

## Kontrolna lista za trijažu

1. Identifikujte šta imate: encoding naspram encryption, hash naspram signature ili MAC.
2. Utvrdite šta je pod vašom kontrolom: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), delimični leak.
3. Klasifikujte: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Prvo primenite provere sa najvećom verovatnoćom uspeha: dekodiranje slojeva, known-plaintext XOR, ponovna upotreba nonce-a, pogrešna upotreba mode-a, ponašanje oracle-a.
5. Napredne metode koristite samo kada su neophodne: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resursi i utilities

Ovo je korisno kada je zadatak identifikacija i uklanjanje slojeva ili kada vam je potrebna brza potvrda hipoteze.

### Pretraga hash vrednosti

- Pretražite hash challenge-a kada se zna da je synthetic/public.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org search.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Ne šaljite stvarne password hash vrednosti niti poverljivi materijal challenge-a third-party lookup servisima. Kada postoji zabrinutost u vezi sa disclosure-om, uslovima korišćenja ili pravilima takmičenja, prednost dajte offline wordlist/rule napadu.

### Pomagala za identifikaciju

- CyberChef (Magic, dekodiranje i konverzija).<sup>[[7]](#references)</sup>
- dCode (cipher/encoding playground).<sup>[[8]](#references)</sup>
- Boxentriq (substitution solvers).<sup>[[9]](#references)</sup>

### Practice platforme / reference

- CryptoHack (hands-on cryptography challenges).<sup>[[10]](#references)</sup>
- Cryptopals (classic modern-cryptography pitfalls).<sup>[[11]](#references)</sup>

### Automated decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (isprobava mnoge baze/encodings).<sup>[[13]](#references)</sup>

## Encodings i classical ciphers

### Technique

Mnogi CTF crypto zadaci koriste slojevite transformacije: base encoding + simple substitution + compression. Cilj je identifikovati slojeve i bezbedno ih ukloniti.

### Encodings: isprobajte mnoge baze

Ako sumnjate na layered encoding (base64 → base32 → …), isprobajte:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Uobičajeni pokazatelji:

- Base64: `A-Za-z0-9+/=` (padding `=` je čest)
- Base32: `A-Z2-7=` (često ima mnogo `=` padding-a)
- Ascii85/Base85: gusta interpunkcija; ponekad je obavijen sa `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon cipher

Često se pojavljuje kao grupe od 5 bitova ili 5 slova:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runes su često substitution alphabets; pretražite "futhark cipher" i pokušajte sa mapping tabelama.

## Kompresija u izazovima

### Tehnika

Kompresija se stalno pojavljuje kao dodatni sloj (zlib/deflate/gzip/xz/zstd), ponekad ugnježden. Ako se izlaz skoro parsira, ali izgleda kao besmisleni podaci, posumnjajte na kompresiju.

### Brza identifikacija

- `file <blob>`
- Potražite magic bytes:
- gzip: `1f 8b`
- zlib: najčešće `78 01`, `78 5e`, `78 9c` ili `78 da` (drugi byte zavisi od compression flags)
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ima **Raw Deflate/Raw Inflate**, što je često najbrži način kada blob izgleda kompresovano, ali `zlib` ne uspe.

### Korisne CLI
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
## Uobičajene CTF crypto konstrukcije

### Tehnika

Ovo se često pojavljuje zato što predstavlja realne greške developera ili uobičajene biblioteke koje se nepravilno koriste. Cilj je obično prepoznavanje i primena poznatog workflow-a za ekstrakciju ili rekonstrukciju.

### Fernet

Tipičan hint: dva Base64 stringa (token + key).

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- U Pythonu: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ako vidite više share-ova i pominje se prag `t`, verovatno je u pitanju Shamir.

- Online reconstructor (samo za nesenzitivne CTF share-ove).<sup>[[19]](#references)</sup>

### OpenSSL salted formati

CTF-ovi ponekad daju izlaze komande `openssl enc` (header često počinje sa `Salted__`).

Bruteforce helpers:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Opšti alatni skup

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Preporučeno lokalno okruženje

Praktični CTF stack:

- Python plus `pycryptodome` za simetrične primitive i brzo prototipisanje.<sup>[[25]](#references)</sup>
- SageMath za modularnu aritmetiku, CRT, lattice algoritme i RSA/ECC rad.<sup>[[26]](#references)</sup>
- Z3 za izazove zasnovane na ograničenjima (kada se crypto svodi na ograničenja).<sup>[[27]](#references)</sup>

Predloženi Python paketi:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org pretraga](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode alati](https://www.dcode.fr/tools-list)
- [9] [Boxentriq alati za razbijanje kodova](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Automatski razbijač Cezarove šifre](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash šifra](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère rešavač](https://www.guballa.de/vigenere-solver)
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
{{#include ../../banners/hacktricks-training.md}}
