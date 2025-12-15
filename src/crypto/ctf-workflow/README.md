# Kripto CTF İş Akışı

{{#include ../../banners/hacktricks-training.md}}

## Triage kontrol listesi

1. Neye sahip olduğunuzu belirleyin: encoding vs encryption vs hash vs signature vs MAC.
2. Kontrol edilenleri tespit edin: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Sınıflandırın: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Önce en yüksek olasılıklı kontrolleri uygulayın: decode katmanları, known-plaintext XOR, nonce reuse, mode misuse, oracle davranışı.
5. İleri yöntemlere yalnızca gerektiğinde geçin: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resources & utilities

Bunlar, görevin kimliklendirme ve katman soyma olduğu durumlarda veya bir hipotezin hızlıca doğrulanması gerektiğinde kullanışlıdır.

### Hash lookups

- Google the hash (surprisingly effective).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

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

### Technique

Birçok CTF kripto görevi katmanlı dönüşümler içerir: base encoding + simple substitution + compression. Amaç, katmanları belirlemek ve güvenli şekilde soymaktır.

### Encodings: try many bases

Eğer katmanlı encoding (base64 → base32 → …) şüphesi varsa, deneyin:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Yaygın işaretler:

- Base64: `A-Za-z0-9+/=` (padding `=` is common)
- Base32: `A-Z2-7=` (often lots of `=` padding)
- Ascii85/Base85: yoğun noktalama işaretleri; bazen `<~ ~>` içinde sarılı olur

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

Çoğunlukla 5 bitlik veya 5 harflik gruplar halinde ortaya çıkar:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Rünler

Rünler genellikle yerine koyma alfabeleridir; "futhark cipher" arayın ve eşleme tablolarını deneyin.

## Challenge'larda Sıkıştırma

### Teknik

Sıkıştırma sık sık ekstra bir katman olarak (zlib/deflate/gzip/xz/zstd) ortaya çıkar, bazen iç içe. Çıktı neredeyse çözümlenebiliyor ama çöp gibi görünüyorsa, sıkıştırma olasılığını düşünün.

### Hızlı tespit

- `file <blob>`
- Magic bytes'lara bakın:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef'te **Raw Deflate/Raw Inflate** bulunur; blob sıkıştırılmış gibi göründüğünde ama `zlib` başarısız olduğunda bu genellikle en hızlı yoldur.

### Kullanışlı CLI
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
## Yaygın CTF kripto yapıları

### Teknik

Bunlar sıklıkla görünür çünkü gerçekçi geliştirici hataları veya yanlış kullanılan yaygın kütüphanelerdir. Amaç genellikle tanıma ve bilinen bir çıkarma veya yeniden yapılandırma iş akışını uygulamaktır.

### Fernet

Tipik ipucu: iki Base64 string'i (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- Python'da: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Birden fazla shares görürseniz ve bir eşik `t` belirtilmişse, muhtemelen Shamir'dir.

- Online reconstructor (CTF'ler için kullanışlı): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF'ler bazen `openssl enc` çıktıları verir (başlık genellikle `Salted__` ile başlar).

Bruteforce yardımcıları:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### Genel araç seti

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Önerilen yerel kurulum

Pratik CTF yığını:

- Python + `pycryptodome` — simetrik kriptografi ve hızlı prototipleme için
- SageMath — modüler aritmetik, CRT, lattice'ler ve RSA/ECC çalışmaları için
- Z3 — kısıt-temelli zorluklar için (kriptografik problem kısıtlara indirgeniyorsa)

Önerilen Python paketleri:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
