# Crypto CTF वर्कफ़्लो

{{#include ../../banners/hacktricks-training.md}}

## Triage चेकलिस्ट

1. पहचानें कि आपके पास क्या है: encoding vs encryption vs hash vs signature vs MAC.
2. निर्धारित करें कि क्या नियंत्रित है: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. श्रेणीबद्ध करें: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. सबसे संभावित चेक पहले लागू करें: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. केवल आवश्यक होने पर ही advanced methods पर जाएँ: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## ऑनलाइन संसाधन & उपयोगिताएँ

ये उपयोगी होते हैं जब टास्क पहचान और लेयर पीलिंग हो, या जब आपको किसी अनुमान की त्वरित पुष्टि चाहिए।

### Hash लुकअप्स

- Google the hash (अविश्वसनीय रूप से प्रभावी).
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
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### तकनीक

अनेक CTF crypto टास्क layered transforms होते हैं: base encoding + simple substitution + compression. लक्ष्य लेयर्स की पहचान कर उन्हें सुरक्षित रूप से खोलना है।

### Encodings: कई बेस आज़माएँ

यदि आप layered encoding (base64 → base32 → …) का संदेह करते हैं, तो आज़माएँ:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

आम संकेत:

- Base64: `A-Za-z0-9+/=` (padding `=` सामान्य है)
- Base32: `A-Z2-7=` (अक्सर बहुत `=` padding होता है)
- Ascii85/Base85: घने punctuation; कभी-कभी `<~ ~>` में लिपटा होता है

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

रून्स अक्सर प्रतिस्थापन वर्णमालाएँ होती हैं; "futhark cipher" खोजें और मैपिंग तालिकाएँ आज़माएँ।

## चुनौतियों में कंप्रेशन

### तकनीक

कंप्रेशन अक्सर एक अतिरिक्त परत के रूप में दिखाई देता है (zlib/deflate/gzip/xz/zstd), कभी-कभी नेस्टेड। यदि आउटपुट लगभग पार्स हो रहा है पर कचरा जैसा दिखता है, तो कंप्रेशन की शंका करें।

### त्वरित पहचान

- `file <blob>`
- मैजिक बाइट्स के लिए देखें:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

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

ये अक्सर दिखाई देते हैं क्योंकि ये वास्तविक डेवलपर गलतियाँ या सामान्य लाइब्रेरियों का गलत उपयोग हैं। उद्देश्य आमतौर पर इन्हें पहचानना और किसी ज्ञात extraction या reconstruction workflow को लागू करना होता है।

### Fernet

Typical hint: two Base64 strings (token + key).

- डिकोडर/नोट्स: https://asecuritysite.com/encryption/ferdecode
- Python में: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

यदि आप कई shares देखते हैं और threshold `t` का उल्लेख है, तो यह संभवतः Shamir होगा।

- ऑनलाइन reconstructor (CTFs के लिए उपयोगी): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs कभी-कभी `openssl enc` outputs देते हैं (header अक्सर `Salted__` से शुरू होता है)।

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### सामान्य टूलसेट

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## अनुशंसित स्थानीय सेटअप

व्यावहारिक CTF स्टैक:

- Python + `pycryptodome` — symmetric primitives और तेज़ प्रोटोटाइपिंग के लिए
- SageMath — modular arithmetic, CRT, lattices, और RSA/ECC के काम के लिए
- Z3 — constraint-based challenges के लिए (जब crypto constraints में घट जाए)

सुझावित Python पैकेज:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
