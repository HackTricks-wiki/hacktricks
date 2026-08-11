# Crypto CTF कार्यप्रवाह

{{#include ../../banners/hacktricks-training.md}}

## Triage चेकलिस्ट

1. पहचानें कि आपके पास क्या है: encoding बनाम encryption बनाम hash बनाम signature बनाम MAC।
2. निर्धारित करें कि क्या नियंत्रित है: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), आंशिक leak।
3. वर्गीकृत करें: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR)।
4. सबसे अधिक संभावित checks पहले लागू करें: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior।
5. केवल आवश्यकता होने पर advanced methods पर जाएँ: lattices (LLL/Coppersmith), SMT/Z3, side-channels।

## Online resources & utilities

ये तब उपयोगी हैं जब task identification और layer peeling से संबंधित हो, या जब आपको किसी hypothesis की quick confirmation चाहिए।

### Hash lookups

- जब किसी challenge hash के synthetic/public होने की जानकारी हो, तो उसे search करें।
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org search.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Real password hashes या confidential challenge material को third-party lookup services पर submit न करें। जब disclosure, terms of service या competition rules चिंता का विषय हों, तो offline wordlist/rule attack को प्राथमिकता दें।

### Identification helpers

- CyberChef (Magic, decoding और conversion)।<sup>[[7]](#references)</sup>
- dCode (cipher/encoding playground)।<sup>[[8]](#references)</sup>
- Boxentriq (substitution solvers)।<sup>[[9]](#references)</sup>

### Practice platforms / references

- CryptoHack (hands-on cryptography challenges)।<sup>[[10]](#references)</sup>
- Cryptopals (classic modern-cryptography pitfalls)।<sup>[[11]](#references)</sup>

### Automated decoding

- Ciphey।<sup>[[12]](#references)</sup>
- python-codext (कई bases/encodings आज़माता है)।<sup>[[13]](#references)</sup>

## Encodings & classical ciphers

### Technique

कई CTF crypto tasks layered transforms होते हैं: base encoding + simple substitution + compression। लक्ष्य layers की पहचान करना और उन्हें सुरक्षित रूप से peel करना है।

### Encodings: कई bases आज़माएँ

यदि आपको layered encoding (base64 → base32 → …) का संदेह है, तो ये आज़माएँ:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Common tells:

- Base64: `A-Za-z0-9+/=` (padding `=` सामान्य है)
- Base32: `A-Z2-7=` (अक्सर बहुत अधिक `=` padding होता है)
- Ascii85/Base85: dense punctuation; कभी-कभी `<~ ~>` में wrapped होता है

### Substitution / monoalphabetic

- Boxentriq cryptogram solver।<sup>[[9]](#references)</sup>
- quipqiup।<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker।<sup>[[15]](#references)</sup>
- Rumkin Atbash tool।<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool।<sup>[[8]](#references)</sup>
- Guballa Vigenère solver।<sup>[[17]](#references)</sup>

### Bacon cipher

अक्सर 5 bits या 5 letters के groups के रूप में दिखाई देता है:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runes अक्सर substitution alphabets होते हैं; `"futhark cipher"` खोजें और mapping tables आज़माएँ।

## Challenges में Compression

### Technique

Compression लगातार एक अतिरिक्त layer के रूप में दिखाई देता है (zlib/deflate/gzip/xz/zstd), कभी-कभी nested भी। यदि output लगभग parse हो जाता है लेकिन garbage जैसा दिखता है, तो compression का संदेह करें।

### Quick identification

- `file <blob>`
- Magic bytes देखें:
- gzip: `1f 8b`
- zlib: आमतौर पर `78 01`, `78 5e`, `78 9c`, या `78 da` (दूसरा byte compression flags पर निर्भर करता है)
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef में **Raw Deflate/Raw Inflate** है, जो अक्सर तब सबसे तेज़ तरीका होता है जब blob compressed दिखता है लेकिन `zlib` fail हो जाता है।

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
## सामान्य CTF crypto constructs

### Technique

ये अक्सर दिखाई देते हैं क्योंकि ये वास्तविक developer mistakes या गलत तरीके से उपयोग की गई common libraries होते हैं। लक्ष्य आमतौर पर पहचान करना और किसी ज्ञात extraction या reconstruction workflow को लागू करना होता है।

### Fernet

Typical hint: दो Base64 strings (token + key)।

- Decoder/notes: Asecuritysite Fernet decoder।<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

यदि आपको multiple shares दिखाई दें और threshold `t` का उल्लेख हो, तो यह संभवतः Shamir है।

- Online reconstructor (केवल non-sensitive CTF shares के लिए)।<sup>[[19]](#references)</sup>

### OpenSSL salted formats

CTFs में कभी-कभी `openssl enc` outputs दिए जाते हैं (header अक्सर `Salted__` से शुरू होता है)।

Bruteforce helpers:

- `bruteforce-salted-openssl`।<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`।<sup>[[21]](#references)</sup>

### General toolset

- RsaCtfTool।<sup>[[22]](#references)</sup>
- featherduster।<sup>[[23]](#references)</sup>
- cryptovenom।<sup>[[24]](#references)</sup>

## Recommended local setup

Practical CTF stack:

- Symmetric primitives और fast prototyping के लिए `pycryptodome` के साथ Python।<sup>[[25]](#references)</sup>
- Modular arithmetic, CRT, lattices और RSA/ECC work के लिए SageMath।<sup>[[26]](#references)</sup>
- Constraint-based challenges के लिए Z3 (जब crypto constraints तक सीमित हो जाए)।<sup>[[27]](#references)</sup>

Suggested Python packages:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org खोज](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode tools](https://www.dcode.fr/tools-list)
- [9] [Boxentriq code-breaking tools](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Automatic Caesar cipher breaker](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère solver](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet decoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing reconstructor](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome documentation](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
