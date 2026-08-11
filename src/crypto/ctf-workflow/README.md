# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Чекліст triage

1. Визначте, що саме у вас є: кодування, encryption, hash, signature чи MAC.
2. Визначте, що контролюється: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), частковий leak.
3. Класифікуйте: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Спочатку застосуйте перевірки з найвищою ймовірністю успіху: декодування шарів, known-plaintext XOR, повторне використання nonce, неправильне використання mode, поведінка oracle.
5. Переходьте до advanced methods лише за потреби: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Онлайн-ресурси та утиліти

Вони корисні, коли завдання полягає в ідентифікації та поетапному знятті шарів або коли потрібно швидко підтвердити гіпотезу.

### Пошук hash

- Виконайте пошук hash challenge, якщо відомо, що він synthetic/public.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Пошук на hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Не надсилайте справжні password hashes або конфіденційні матеріали challenge до сторонніх сервісів пошуку. Якщо є ризики, пов’язані з розголошенням, умовами використання або правилами змагання, віддавайте перевагу offline-атаці зі wordlist/rule.

### Допоміжні засоби ідентифікації

- CyberChef (Magic, декодування та конвертація).<sup>[[7]](#references)</sup>
- dCode (майданчик для cipher/encoding).<sup>[[8]](#references)</sup>
- Boxentriq (розв’язувачі substitution).<sup>[[9]](#references)</sup>

### Платформи для практики / reference

- CryptoHack (практичні cryptography challenges).<sup>[[10]](#references)</sup>
- Cryptopals (класичні вразливості modern cryptography).<sup>[[11]](#references)</sup>

### Автоматичне декодування

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (перебирає багато base/encoding).<sup>[[13]](#references)</sup>

## Encoding та classical ciphers

### Technique

Багато crypto-завдань CTF — це багатошарові перетворення: base encoding + проста substitution + compression. Мета — ідентифікувати шари та безпечно знімати їх поетапно.

### Encoding: спробуйте багато base

Якщо ви підозрюєте layered encoding (base64 → base32 → …), спробуйте:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Типові ознаки:

- Base64: `A-Za-z0-9+/=` (padding `=` є поширеним)
- Base32: `A-Z2-7=` (часто багато `=` padding)
- Ascii85/Base85: щільна пунктуація; іноді обгортається в `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon cipher

Часто зустрічається у вигляді груп із 5 бітів або 5 літер:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Руни

Руни часто є substitution alphabets; шукайте "futhark cipher" і спробуйте таблиці відповідностей.

## Стиснення у challenge

### Техніка

Стиснення постійно зустрічається як додатковий рівень (zlib/deflate/gzip/xz/zstd), іноді вкладений. Якщо output майже парситься, але виглядає як сміття, підозрюйте стиснення.

### Швидка ідентифікація

- `file <blob>`
- Шукайте магічні байти:
- gzip: `1f 8b`
- zlib: зазвичай `78 01`, `78 5e`, `78 9c` або `78 da` (другий байт залежить від compression flags)
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef має **Raw Deflate/Raw Inflate**, що часто є найшвидшим шляхом, коли blob виглядає стисненим, але `zlib` не спрацьовує.

### Корисні CLI
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
## Поширені криптографічні конструкції CTF

### Technique

Вони часто трапляються, оскільки є реалістичними помилками розробників або результатом неправильного використання поширених бібліотек. Зазвичай мета полягає у розпізнаванні та застосуванні відомого workflow для extraction або reconstruction.

### Fernet

Типова підказка: два рядки Base64 (token + key).

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Якщо ви бачите кілька shares і згадується threshold `t`, найімовірніше, це Shamir.

- Online reconstructor (лише для несекретних CTF shares).<sup>[[19]](#references)</sup>

### OpenSSL salted formats

У CTF іноді надаються результати `openssl enc` (заголовок часто починається з `Salted__`).

Bruteforce helpers:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Загальний набір інструментів

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Рекомендоване локальне налаштування

Практичний стек для CTF:

- Python разом із `pycryptodome` для симетричних примітивів і швидкого прототипування.<sup>[[25]](#references)</sup>
- SageMath для модульної арифметики, CRT, lattice та роботи з RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 для challenges на основі обмежень (коли криптографічна задача зводиться до обмежень).<sup>[[27]](#references)</sup>

Рекомендовані Python packages:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [пошук hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Набір інструментів для хешів](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [інструменти dCode](https://www.dcode.fr/tools-list)
- [9] [інструменти для зламування кодів Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - автоматичний зламувальник шифру Цезаря](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - шифр Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [засіб розв'язання шифру Віженера Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - декодер Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [реконструктор розподілу секрету Шаміра](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [документація PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
