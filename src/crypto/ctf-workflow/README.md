# Crypto CTF İş Akışı

{{#include ../../banners/hacktricks-training.md}}

## Triage kontrol listesi

1. Elinizde ne olduğunu belirleyin: encoding mi, encryption mı, hash mi, signature mı, MAC mi?
2. Neyin kontrol edildiğini belirleyin: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), kısmi leak.
3. Sınıflandırın: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Önce en yüksek olasılıklı kontrolleri uygulayın: decode katmanları, known-plaintext XOR, nonce reuse, mode misuse, oracle davranışı.
5. Yalnızca gerektiğinde gelişmiş yöntemlere geçin: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online kaynaklar ve yardımcı araçlar

Bunlar, görevin identification ve katmanları ayıklama olduğu veya bir hipotezi hızlıca doğrulamanız gerektiği durumlarda kullanışlıdır.

### Hash lookups

- Hash'i Google'da arayın (şaşırtıcı derecede etkilidir).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Identification yardımcıları

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Practice platformları / referanslar

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Otomatik decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (birçok base/encoding dener): https://github.com/dhondta/python-codext

## Encodings ve classical ciphers

### Teknik

Birçok CTF crypto görevi katmanlı transform'lar içerir: base encoding + simple substitution + compression. Amaç, katmanları belirlemek ve güvenli şekilde ayıklamaktır.

### Encodings: birçok base deneyin

Katmanlı encoding'den şüpheleniyorsanız (base64 → base32 → …), şunları deneyin:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Yaygın göstergeler:

- Base64: `A-Za-z0-9+/=` (padding olarak `=` yaygındır)
- Base32: `A-Z2-7=` (çoğunlukla çok sayıda `=` padding içerir)
- Ascii85/Base85: yoğun punctuation; bazen `<~ ~>` içine sarılır

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

Genellikle 5 bitlik veya 5 harflik gruplar olarak görünür:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runes genellikle substitution alphabets'tir; "futhark cipher" için arama yapın ve mapping tablolarını deneyin.

## Challenges'ta Compression

### Technique

Compression, ekstra bir katman olarak sürekli karşımıza çıkar (zlib/deflate/gzip/xz/zstd); bazen iç içe olabilir. Çıktı neredeyse parse edilebiliyor ancak anlamsız görünüyorsa compression'dan şüphelenin.

### Quick identification

- `file <blob>`
- Magic byte'ları arayın:
- gzip: `1f 8b`
- zlib: genellikle `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef'te **Raw Deflate/Raw Inflate** bulunur; blob compressed görünüyorsa ancak `zlib` başarısız oluyorsa genellikle en hızlı yoldur.

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
## Yaygın CTF crypto yapıları

### Technique

Bunlar, gerçekçi developer hataları veya yaygın kütüphanelerin yanlış kullanılması nedeniyle sık görülür. Amaç genellikle bunları tanımak ve bilinen bir extraction veya reconstruction workflow uygulamaktır.

### Fernet

Tipik ipucu: iki Base64 string'i (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- Python'da: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Birden fazla share görüyorsanız ve bir threshold `t` belirtilmişse, büyük olasılıkla Shamir kullanılıyordur.

- Online reconstructor (CTF'ler için kullanışlı): http://christian.gen.co/secrets/

### OpenSSL salted formatları

CTF'lerde bazen `openssl enc` çıktıları verilir (header genellikle `Salted__` ile başlar).

Bruteforce yardımcıları:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Genel toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Önerilen local setup

Pratik CTF stack'i:

- Simetrik primitive'ler ve hızlı prototyping için Python + `pycryptodome`
- Modular arithmetic, CRT, lattices ve RSA/ECC çalışmaları için SageMath
- Constraint tabanlı challenge'lar için Z3 (crypto, constraint'lere indirgenebildiğinde)

Önerilen Python package'ları:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
