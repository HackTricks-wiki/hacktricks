# Crypto CTF Робочий процес

{{#include ../../banners/hacktricks-training.md}}

## Контрольний список тріажу

1. Визначте, що у вас є: encoding vs encryption vs hash vs signature vs MAC.
2. Визначте, що контролюється: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Класифікуйте: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Застосовуйте найімовірніші перевірки першими: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Переходьте до просунутих методів тільки за потреби: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Онлайн-ресурси та утиліти

Це корисно, коли завдання — ідентифікація та зняття шарів, або коли потрібно швидко підтвердити гіпотезу.

### Hash lookups

- Google the hash (surprisingly effective).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Інструменти для ідентифікації

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Платформи для практики / посилання

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Автоматичне декодування

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Кодування та класичні шифри

### Метод

Багато CTF crypto задач — це багатошарові трансформації: base encoding + simple substitution + compression. Мета — ідентифікувати шари та зняти їх безпечно.

### Encodings: try many bases

Якщо підозрюєте багатошарове кодування (base64 → base32 → …), спробуйте:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Поширені ознаки:

- Base64: `A-Za-z0-9+/=` (padding `=` is common)
- Base32: `A-Z2-7=` (often lots of `=` padding)
- Ascii85/Base85: dense punctuation; sometimes wrapped in `<~ ~>`

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

Часто зустрічається як групи по 5 біт або 5 літер:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Руни

Руни часто є алфавітами підстановки; пошукайте "futhark cipher" і спробуйте таблиці відображень.

## Стиснення в задачах

### Техніка

Стиснення часто зустрічається як додатковий шар (zlib/deflate/gzip/xz/zstd), іноді вкладений. Якщо вивід майже парситься, але виглядає як сміття, підозрюйте стиснення.

### Швидка ідентифікація

- `file <blob>`
- Шукайте magic bytes:
- gzip: `1f 8b`
- zlib: часто `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef має **Raw Deflate/Raw Inflate**, що часто є найшвидшим шляхом, коли blob виглядає стисненим, але `zlib` не справляється.

### Корисні CLI
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
## Поширені конструкції crypto для CTF

### Техніка

Вони часто зустрічаються, оскільки це реалістичні помилки розробників або поширені бібліотеки, використані неправильно. Мета зазвичай — розпізнати їх і застосувати відому методику вилучення або реконструкції.

### Fernet

Типова підказка: два рядки Base64 (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Якщо ви бачите кілька shares і згадується поріг `t`, ймовірно, це Shamir.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF іноді дають `openssl enc` outputs (header often begins with `Salted__`).

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Загальний набір інструментів

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Рекомендоване локальне налаштування

Практичний стек для CTF:

- Python + `pycryptodome` для симетричних примітивів і швидкого прототипування
- SageMath для модульної арифметики, CRT, решіток та роботи з RSA/ECC
- Z3 для задач на основі обмежень (коли crypto зводиться до обмежень)

Рекомендовані Python пакети:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
