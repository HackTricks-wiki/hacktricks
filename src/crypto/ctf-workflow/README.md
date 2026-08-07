# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage checklist

1. आपके पास क्या है, इसकी पहचान करें: encoding बनाम encryption बनाम hash बनाम signature बनाम MAC।
2. निर्धारित करें कि क्या नियंत्रित है: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage।
3. वर्गीकृत करें: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR)।
4. पहले सबसे अधिक संभावित checks लागू करें: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior।
5. advanced methods का उपयोग केवल आवश्यकता होने पर करें: lattices (LLL/Coppersmith), SMT/Z3, side-channels।

## Online resources & utilities

ये तब उपयोगी हैं जब task identification और layer peeling से संबंधित हो, या जब आपको किसी hypothesis की तुरंत पुष्टि चाहिए।

### Hash lookups

- hash को Google करें (आश्चर्यजनक रूप से प्रभावी)।
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Identification helpers

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Practice platforms / references

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Automated decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (कई bases/encodings आज़माता है): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### Technique

कई CTF crypto tasks layered transforms होते हैं: base encoding + simple substitution + compression। लक्ष्य layers की पहचान करना और उन्हें सुरक्षित रूप से peel करना है।

### Encodings: try many bases

यदि आपको layered encoding (base64 → base32 → …) का संदेह है, तो आज़माएँ:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Common tells:

- Base64: `A-Za-z0-9+/=` (padding `=` सामान्य है)
- Base32: `A-Z2-7=` (अक्सर बहुत-सा `=` padding होता है)
- Ascii85/Base85: dense punctuation; कभी-कभी `<~ ~>` में wrapped होता है

### Substitution / monoalphabetic

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)

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

Compression लगातार एक अतिरिक्त layer के रूप में दिखाई देता है (zlib/deflate/gzip/xz/zstd), और कभी-कभी nested भी होता है। यदि output लगभग parse हो जाता है लेकिन garbage जैसा दिखता है, तो compression का संदेह करें।

### Quick identification

- `file <blob>`
- Magic bytes देखें:
- gzip: `1f 8b`
- zlib: अक्सर `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef में **Raw Deflate/Raw Inflate** उपलब्ध है, जो अक्सर तब सबसे तेज़ तरीका होता है जब blob compressed जैसा दिखे लेकिन `zlib` fail हो जाए।

### Useful CLI
```bash
python3 - <<'PY'
import sys, zlib
data = sys.stdin.buffer.read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
try:
print(zlib.decompress(data, wbits=wbits)[:200])
except Exception:
pass
PY
```
## सामान्य CTF crypto constructs

### Technique

ये अक्सर दिखाई देते हैं क्योंकि ये वास्तविक developer mistakes या गलत तरीके से उपयोग की गई common libraries के परिणाम होते हैं। लक्ष्य आमतौर पर इन्हें पहचानना और ज्ञात extraction या reconstruction workflow लागू करना होता है।

### Fernet

Typical hint: दो Base64 strings (token + key)।

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

यदि आपको multiple shares दिखाई दें और threshold `t` का उल्लेख हो, तो यह संभवतः Shamir है।

- Online reconstructor (CTFs के लिए उपयोगी): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs में कभी-कभी `openssl enc` outputs दिए जाते हैं (header अक्सर `Salted__` से शुरू होता है)।

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### General toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Recommended local setup

Practical CTF stack:

- Python + `pycryptodome` symmetric primitives और fast prototyping के लिए
- SageMath modular arithmetic, CRT, lattices और RSA/ECC work के लिए
- Z3 constraint-based challenges के लिए (जब crypto constraints में बदल जाता है)

Suggested Python packages:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
