# Kripto CTF İş Akışı

{{#include ../../banners/hacktricks-training.md}}

## Triage kontrol listesi

1. Elinizde olanı belirleyin: encoding vs encryption vs hash vs signature vs MAC.
2. Kontrol edilenleri tespit edin: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Sınıflandırın: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Önce en yüksek olasılıkları kontrol edin: decode katmanları, known-plaintext XOR, nonce reuse, mode misuse, oracle davranışı.
5. Gelişmiş yöntemleri yalnızca gerektiğinde kullanın: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Çevrimiçi kaynaklar & araçlar

Bunlar, görevin tanımlama ve katman sökme olduğu durumlarda ya da bir hipotezi hızlıca doğrulamanız gerektiğinde faydalıdır.

### Hash aramaları

- Hashi Google'da ara (şaşırtıcı derecede etkili).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Tanımlama yardımcıları

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Pratik platformları / referanslar

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Otomatik dekodlama

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Encodings & klasik şifreler

### Yöntem

Birçok CTF kripto görevi katmanlı dönüşümlerdir: base encoding + simple substitution + compression. Amaç, katmanları tespit etmek ve güvenli biçimde soymaktır.

### Encodings: birçok base deneyin

Katmanlı encoding (base64 → base32 → …) olduğunu düşünüyorsanız, deneyin:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Yaygın göstergeler:

- Base64: `A-Za-z0-9+/=` (padding `=` is common)
- Base32: `A-Z2-7=` (often lots of `=` padding)
- Ascii85/Base85: yoğun noktalama; bazen `<~ ~>` ile sarılır

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

Genellikle 5 bitlik veya 5 harflik gruplar halinde görülür:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Rünler

Rünler sık sık yerine koyma alfabeleridir; "futhark cipher" arayın ve eşleme tablolarını deneyin.

## Challenge'larda Sıkıştırma

### Teknik

Sıkıştırma, sıkça ekstra bir katman olarak (zlib/deflate/gzip/xz/zstd) karşınıza çıkar; bazen iç içe olur. Çıktı neredeyse çözümleniyor ama anlamsız görünüyorsa, sıkıştırmayı şüpheleyin.

### Hızlı tespit

- `file <blob>`
- Magic byte'lara bakın:
- gzip: `1f 8b`
- zlib: çoğunlukla `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef'te **Raw Deflate/Raw Inflate** bulunur; blob sıkıştırılmış gibi görünüp `zlib` başarısız olduğunda genellikle en hızlı yol budur.

### Faydalı CLI
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

### Teknik

Bunlar sıkça görülür çünkü gerçekçi developer hataları veya yanlış kullanılan common libraries'dir. Amaç genellikle tanıma ve bilinen bir extraction veya reconstruction workflow'unu uygulamaktır.

### Fernet

Tipik ipucu: iki Base64 dizesi (token + key).

- Çözücü/notlar: https://asecuritysite.com/encryption/ferdecode
- Python'da: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Birden fazla share görürseniz ve bir eşik `t` belirtilmişse, muhtemelen Shamir'dir.

- Çevrimiçi yeniden oluşturucu (CTF'ler için kullanışlı): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF'ler bazen `openssl enc` çıktıları verir (başlık genellikle `Salted__` ile başlar).

Bruteforce yardımcı araçları:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Genel araç seti

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Önerilen yerel kurulum

Pratik CTF yığını:

- Python + `pycryptodome` simetrik primitive'ler ve hızlı prototipleme için
- SageMath modüler aritmetik, CRT, lattices ve RSA/ECC çalışmaları için
- Z3 kısıt tabanlı zorluklar için (crypto kısıtlara indirgeniyorsa)

Önerilen Python paketleri:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
