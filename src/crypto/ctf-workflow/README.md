# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Чекліст тріажу

1. Визначте, що саме у вас є: encoding, encryption, hash, signature чи MAC.
2. Визначте, що контролюється: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), частковий leak.
3. Класифікуйте: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Спочатку застосуйте перевірки з найвищою ймовірністю успіху: декодування шарів, XOR із відомим plaintext, повторне використання nonce, неправильне використання режиму, поведінка oracle.
5. Переходьте до складніших методів лише за потреби: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Онлайн-ресурси та утиліти

Вони корисні, коли завдання полягає в ідентифікації та знятті шарів або коли потрібно швидко підтвердити гіпотезу.

### Пошук hash

- Пошукайте hash у Google (на диво ефективно).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Допоміжні інструменти для ідентифікації

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (майданчик для ciphers/encodings): https://www.dcode.fr/tools-list
- Boxentriq (розв'язувачі substitution): https://www.boxentriq.com/code-breaking

### Платформи для практики / reference

- CryptoHack (практичні crypto challenges): https://cryptohack.org/
- Cryptopals (класичні сучасні crypto pitfalls): https://cryptopals.com/

### Автоматичне декодування

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (перебирає багато bases/encodings): https://github.com/dhondta/python-codext

## Encodings та classical ciphers

### Technique

Багато crypto-завдань у CTF є багаторівневими перетвореннями: base encoding + проста substitution + compression. Мета полягає в тому, щоб визначити шари та безпечно зняти їх.

### Encodings: спробуйте багато bases

Якщо ви підозрюєте багаторівневе encoding (base64 → base32 → …), спробуйте:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Типові ознаки:

- Base64: `A-Za-z0-9+/=` (padding `=` є поширеним)
- Base32: `A-Z2-7=` (часто багато padding-символів `=`)
- Ascii85/Base85: щільна punctuation; іноді обгортається в `<~ ~>`

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

Часто зустрічається у вигляді груп із 5 bits або 5 letters:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Руни

Руни часто є алфавітами підстановки; шукайте "futhark cipher" і спробуйте таблиці відповідностей.

## Стиснення у challenge

### Техніка

Стиснення постійно зустрічається як додатковий шар (zlib/deflate/gzip/xz/zstd), іноді вкладений. Якщо результат майже парситься, але виглядає як сміття, запідозріть стиснення.

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

У CyberChef є **Raw Deflate/Raw Inflate** — це часто найшвидший шлях, коли blob виглядає стисненим, але `zlib` не спрацьовує.

### Корисний CLI
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
## Поширені криптографічні конструкції CTF

### Technique

Вони часто трапляються, оскільки є реалістичними помилками розробників або результатом неправильного використання поширених бібліотек. Зазвичай мета полягає у розпізнаванні та застосуванні відомого workflow для extraction або reconstruction.

### Fernet

Типова підказка: два рядки Base64 (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Якщо ви бачите кілька shares і згадується threshold `t`, найімовірніше, це Shamir.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

У CTF іноді надають результати `openssl enc` (заголовок часто починається з `Salted__`).

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
- SageMath для модульної арифметики, CRT, lattices і роботи з RSA/ECC
- Z3 для challenges на основі constraints (коли криптографія зводиться до constraints)

Рекомендовані Python packages:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
