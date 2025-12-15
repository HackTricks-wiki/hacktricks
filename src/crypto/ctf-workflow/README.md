# Crypto CTF वर्कफ़्लो

{{#include ../../banners/hacktricks-training.md}}

## ट्रायज चेकलिस्ट

1. जानें आपके पास क्या है: encoding vs encryption vs hash vs signature vs MAC.
2. निर्धारित करें क्या नियंत्रित है: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. वर्गीकृत करें: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. सबसे अधिक-प्रायिकता वाली जाँच पहले लागू करें: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. आवश्यक होने पर ही उन्नत तरीकों पर जाएँ: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## ऑनलाइन संसाधन और उपयोगी टूल्स

ये तब उपयोगी होते हैं जब टास्क पहचान और परत हटाने (layer peeling) का हो, या जब आपको किसी परिकल्पना की त्वरित पुष्टि चाहिए।

### हैश लुकअप्स

- हैश को Google करें (आश्चर्यजनक रूप से प्रभावी)।
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### पहचान सहायक

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### प्रैक्टिस प्लेटफ़ॉर्म / संदर्भ

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### स्वचालित डिकोडिंग

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### तकनीक

कई CTF crypto कार्य परतों वाले रूपांतरण होते हैं: base encoding + simple substitution + compression. लक्ष्य परतों की पहचान कर उन्हें सुरक्षित ढंग से हटाना है।

### Encodings: कई बेस आज़माएँ

यदि आपको शंका है कि लेयर्ड एन्कोडिंग है (base64 → base32 → …), तो आज़माएँ:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

सामान्य संकेत:

- Base64: `A-Za-z0-9+/=` (padding `=` सामान्य है)
- Base32: `A-Z2-7=` (अक्सर बहुत सारे `=` padding होते हैं)
- Ascii85/Base85: घना विरामचिह्न; कभी-कभी `<~ ~>` में लिपटा होता है

### Substitution / monoalphabetic

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- https://www.dcode.fr/vigenere-cipher
- https://www.guballa.de/vigenere-solver

### Bacon cipher

अक्सर 5 बिट्स या 5 अक्षरों के समूह के रूप में दिखाई देता है:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### रून्स

रून्स अक्सर प्रतिस्थापन वर्णमालाएँ होती हैं; "futhark cipher" खोजें और mapping tables आज़माएँ।

## चुनौतियों में संपीड़न

### तकनीक

संपीड़न अक्सर एक अतिरिक्त परत के रूप में दिखाई देता है (zlib/deflate/gzip/xz/zstd), कभी-कभी नेस्टेड। अगर आउटपुट लगभग पार्स हो रहा है लेकिन कचरे जैसा दिखता है, तो संपीड़न की शंका रखें।

### त्वरित पहचान

- `file <blob>`
- मैजिक बाइट्स देखें:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef में **Raw Deflate/Raw Inflate** होते हैं, जो अक्सर तब सबसे तेज़ रास्ता होते हैं जब blob संपीड़ित दिखता है लेकिन `zlib` विफल हो जाता है।

### उपयोगी CLI
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
## सामान्य CTF क्रिप्टो संरचनाएँ

### तकनीक

ये अक्सर दिखाई देते हैं क्योंकि ये वास्तविक developer गलतियाँ या गलत तरीके से उपयोग की गई सामान्य libraries होती हैं। लक्ष्य आमतौर पर इन्हें पहचानना और किसी ज्ञात extraction या reconstruction workflow को लागू करना होता है।

### Fernet

Typical hint: two Base64 strings (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- Python में: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

यदि आप multiple shares देखते हैं और एक threshold `t` का उल्लेख है, तो यह संभवतः Shamir है।

- Online reconstructor (CTF के लिए उपयोगी): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF कभी-कभी `openssl enc` आउटपुट देते हैं (header अक्सर `Salted__` से शुरू होता है)।

Bruteforce helpers:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### सामान्य टूलसेट

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## अनुशंसित लोकल सेटअप

प्रैक्टिकल CTF स्टैक:

- Python + `pycryptodome` symmetric primitives और तेज़ प्रोटोटाइपिंग के लिए
- SageMath मॉड्यूलर गणित, CRT, lattices, और RSA/ECC काम के लिए
- Z3 constraint-based challenges के लिए (जब crypto constraints में घट जाता है)

सुझावित Python पैकेज:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
