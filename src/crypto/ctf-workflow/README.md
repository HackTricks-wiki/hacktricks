# Робочий процес Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Чекліст тріажу

1. Визначте, що у вас є: encoding vs encryption vs hash vs signature vs MAC.
2. Встановіть, що контролюється: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), часткове витікання.
3. Класифікуйте: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Застосуйте найімовірніші перевірки першими: розкодування шарів, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Перейдіть до просунутих методів лише за потреби: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Онлайн-ресурси та утиліти

Це корисно, коли завдання — ідентифікація та зняття шарів, або коли потрібно швидко підтвердити гіпотезу.

### Hash lookups

- Google the hash (surprisingly effective).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### Помічники для ідентифікації

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

### Техніка

Багато крипто-завдань CTF — це багатошарові перетворення: base encoding + simple substitution + compression. Мета — ідентифікувати шари та акуратно їх зняти.

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

- https://www.dcode.fr/vigenere-cipher
- https://www.guballa.de/vigenere-solver

### Bacon cipher

Часто зустрічається у вигляді груп по 5 біт або 5 букв:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Руни

Руни часто є підстановчими алфавітами; шукайте "futhark cipher" і пробуйте таблиці відображень.

## Стиснення в задачах

### Техніка

Стиснення часто зустрічається як додатковий шар (zlib/deflate/gzip/xz/zstd), іноді вкладене. Якщо вивід майже парситься, але виглядає як сміття, підозрюйте стиснення.

### Швидка ідентифікація

- `file <blob>`
- Шукайте magic bytes:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

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
## Поширені CTF crypto конструкції

### Техніка

Вони з'являються часто, бо це реалістичні помилки розробників або помилкове використання поширених бібліотек. Мета зазвичай — розпізнати проблему та застосувати відомий workflow для витягання або реконструкції.

### Fernet

Типова підказка: два Base64 рядки (token + key).

- Декодер/нотатки: https://asecuritysite.com/encryption/ferdecode
- У Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Якщо ви бачите кілька shares і згадується поріг `t`, ймовірно це Shamir.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

Іноді в CTF дають вивід `openssl enc` (заголовок часто починається з `Salted__`).

Bruteforce helpers:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### Загальний набір інструментів

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Рекомендована локальна конфігурація

Практичний CTF стек:

- Python + `pycryptodome` для симетричних примітивів і швидкого прототипування
- SageMath для модульної арифметики, CRT, решіток та роботи з RSA/ECC
- Z3 для задач на основі обмежень (коли crypto зводиться до обмежень)

Рекомендовані Python пакети:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
