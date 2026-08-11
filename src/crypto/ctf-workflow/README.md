# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Orodha ya ukaguzi wa awali

1. Tambua ulicho nacho: encoding dhidi ya encryption dhidi ya hash dhidi ya signature dhidi ya MAC.
2. Bainisha kinachodhibitiwa: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Panga kwa makundi: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Tumia ukaguzi wenye uwezekano mkubwa kwanza: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Tumia advanced methods pale tu inapohitajika: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Rasilimali za mtandaoni na utilities

Hizi ni muhimu wakati kazi ni kutambua na kuondoa layers, au unapohitaji uthibitisho wa haraka wa hypothesis.

### Utafutaji wa hash

- Tafuta challenge hash inapojulikana kuwa synthetic/public.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Utafutaji wa hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Usiwasilishe real password hashes au confidential challenge material kwenye lookup services za third-party. Pendelea offline wordlist/rule attack wakati disclosure, terms of service, au competition rules ni jambo la kuzingatia.

### Vifaa vya kusaidia identification

- CyberChef (Magic, decoding, na conversion).<sup>[[7]](#references)</sup>
- dCode (cipher/encoding playground).<sup>[[8]](#references)</sup>
- Boxentriq (substitution solvers).<sup>[[9]](#references)</sup>

### Practice platforms / references

- CryptoHack (hands-on cryptography challenges).<sup>[[10]](#references)</sup>
- Cryptopals (classic modern-cryptography pitfalls).<sup>[[11]](#references)</sup>

### Automated decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (tries many bases/encodings).<sup>[[13]](#references)</sup>

## Encodings na classical ciphers

### Technique

Kazi nyingi za crypto za CTF ni layered transforms: base encoding + simple substitution + compression. Lengo ni kutambua layers na kuziondoa kwa usalama.

### Encodings: jaribu bases nyingi

Ukihisi kuna layered encoding (base64 → base32 → …), jaribu:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Viashiria vya kawaida:

- Base64: `A-Za-z0-9+/=` (padding `=` ni ya kawaida)
- Base32: `A-Z2-7=` (mara nyingi huwa na `=` padding nyingi)
- Ascii85/Base85: punctuation nyingi; wakati mwingine hufungwa ndani ya `<~ ~>`

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

Mara nyingi huonekana kama makundi ya bits 5 au herufi 5:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runes mara nyingi ni substitution alphabets; tafuta "futhark cipher" na ujaribu mapping tables.

## Compression in challenges

### Technique

Compression hujitokeza mara kwa mara kama layer ya ziada (zlib/deflate/gzip/xz/zstd), wakati mwingine ikiwa nested. Ikiwa output inakaribia ku-parse lakini inaonekana kama garbage, shuku compression.

### Quick identification

- `file <blob>`
- Tafuta magic bytes:
- gzip: `1f 8b`
- zlib: kwa kawaida `78 01`, `78 5e`, `78 9c`, au `78 da` (byte ya pili hutegemea compression flags)
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ina **Raw Deflate/Raw Inflate**, ambayo mara nyingi ndiyo njia ya haraka zaidi wakati blob inaonekana kuwa compressed lakini `zlib` inashindwa.

### Useful CLI
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
## Miundo ya kawaida ya crypto ya CTF

### Mbinu

Haya hujitokeza mara kwa mara kwa sababu ni makosa halisi ya developers au libraries za kawaida zilizotumiwa vibaya. Kwa kawaida lengo ni kuyatambua na kutumia workflow inayojulikana ya extraction au reconstruction.

### Fernet

Hint ya kawaida: strings mbili za Base64 (token + key).

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Katika Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ukiona shares nyingi na threshold `t` imetajwa, huenda ni Shamir.

- Online reconstructor (kwa shares za CTF zisizo na taarifa nyeti pekee).<sup>[[19]](#references)</sup>

### OpenSSL salted formats

Wakati mwingine CTF hutoa matokeo ya `openssl enc` (header mara nyingi huanza na `Salted__`).

Bruteforce helpers:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### General toolset

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Mpangilio wa local unaopendekezwa

CTF stack ya matumizi ya vitendo:

- Python pamoja na `pycryptodome` kwa symmetric primitives na prototyping ya haraka.<sup>[[25]](#references)</sup>
- SageMath kwa modular arithmetic, CRT, lattices, na kazi za RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 kwa challenges zinazotegemea constraints (crypto inapopunguzwa kuwa constraints).<sup>[[27]](#references)</sup>

Python packages zinazopendekezwa:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [Utafutaji wa hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [Zana za dCode](https://www.dcode.fr/tools-list)
- [9] [Zana za Boxentriq za kuvunja misimbo](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Kivunja cipher ya Caesar kiotomatiki](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - cipher ya Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [Kisuluhishi cha Vigenère cha Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - decoder ya Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [Kijenzi upya cha ushiriki wa siri cha Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [Nyaraka za PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
