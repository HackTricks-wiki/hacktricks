# Crypto CTF-werkvloei

{{#include ../../banners/hacktricks-training.md}}

## Triage-kontrolelys

1. Identifiseer wat jy het: encoding teenoor encryption teenoor hash teenoor signature teenoor MAC.
2. Bepaal wat beheer word: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), gedeeltelike leakage.
3. Klassifiseer: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Pas die kontroles met die hoogste waarskynlikheid eerste toe: decode-lae, known-plaintext XOR, nonce-hergebruik, mode-misbruik, oracle-gedrag.
5. Eskaleer slegs na gevorderde metodes wanneer nodig: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Aanlyn hulpbronne & nutsprogramme

Hierdie is nuttig wanneer die taak identification en layer peeling behels, of wanneer jy vinnige bevestiging van ’n hipotese benodig.

### Hash lookups

- Soek na ’n challenge hash wanneer dit bekend is dat dit synthetic/public is.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org search.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Moenie regte password hashes of confidential challenge-materiaal na third-party lookup services stuur nie. Verkies ’n offline wordlist/rule attack wanneer disclosure, terms of service of competition rules ’n bekommernis is.

### Identification helpers

- CyberChef (Magic, decoding en conversion).<sup>[[7]](#references)</sup>
- dCode (cipher/encoding playground).<sup>[[8]](#references)</sup>
- Boxentriq (substitution solvers).<sup>[[9]](#references)</sup>

### Practice platforms / references

- CryptoHack (hands-on cryptography challenges).<sup>[[10]](#references)</sup>
- Cryptopals (classic modern-cryptography pitfalls).<sup>[[11]](#references)</sup>

### Automated decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (tries many bases/encodings).<sup>[[13]](#references)</sup>

## Encodings & classical ciphers

### Technique

Baie CTF crypto-take is layered transforms: base encoding + simple substitution + compression. Die doel is om lae te identifiseer en dit veilig af te skil.

### Encodings: probeer baie bases

As jy layered encoding vermoed (base64 → base32 → …), probeer:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Algemene aanduidings:

- Base64: `A-Za-z0-9+/=` (padding `=` is algemeen)
- Base32: `A-Z2-7=` (dikwels baie `=` padding)
- Ascii85/Base85: digte punctuation; word soms in `<~ ~>` toegedraai

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

Kom dikwels voor as groepe van 5 bits of 5 letters:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runes is dikwels substitusie-alfabette; soek vir "futhark cipher" en probeer karteringstabelle.

## Kompressie in uitdagings

### Tegniek

Kompressie verskyn voortdurend as ’n ekstra laag (zlib/deflate/gzip/xz/zstd), soms genestel. As uitvoer amper ontleedbaar is, maar soos gemors lyk, vermoed kompressie.

### Vinnige identifikasie

- `file <blob>`
- Soek vir magic bytes:
- gzip: `1f 8b`
- zlib: algemeen `78 01`, `78 5e`, `78 9c`, of `78 da` (die tweede byte hang van kompressievlae af)
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef het **Raw Deflate/Raw Inflate**, wat dikwels die vinnigste pad is wanneer die blob komprimeer lyk, maar `zlib` misluk.

### Nuttige CLI
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
## Algemene CTF-kriptokonstrukte

### Tegniek

Hierdie verskyn gereeld omdat dit realistiese ontwikkelaarsfoute of algemene libraries is wat verkeerd gebruik word. Die doel is gewoonlik herkenning en die toepassing van ’n bekende extraction- of reconstruction-workflow.

### Fernet

Tipiese wenk: twee Base64-stringe (token + key).

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

As jy meerdere shares sien en ’n threshold `t` genoem word, is dit waarskynlik Shamir.

- Online reconstructor (slegs vir nie-sensitiewe CTF-shares).<sup>[[19]](#references)</sup>

### OpenSSL salted formats

CTFs gee soms `openssl enc`-uitsette (die header begin dikwels met `Salted__`).

Bruteforce-hulpmiddels:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Algemene toolset

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Aanbevole plaaslike opstelling

Praktiese CTF-stack:

- Python plus `pycryptodome` vir symmetric primitives en vinnige prototyping.<sup>[[25]](#references)</sup>
- SageMath vir modular arithmetic, CRT, lattices en RSA/ECC-werk.<sup>[[26]](#references)</sup>
- Z3 vir constraint-based challenges (wanneer die crypto tot constraints gereduseer word).<sup>[[27]](#references)</sup>

Voorgestelde Python-pakkette:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org-soektog](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode-nutsgoed](https://www.dcode.fr/tools-list)
- [9] [Boxentriq-kodebreeknutsgoed](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Outomatiese Caesar cipher-kraker](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère-oplosser](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet-dekodeerder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Rekonstruktor vir Shamir secret-sharing](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome-dokumentasie](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
