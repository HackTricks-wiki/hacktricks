# Робочий процес Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Контрольний список первинного аналізу

1. Визначте, що саме маєте: кодування, шифрування, hash, підпис чи MAC.
2. Визначте, що можна контролювати: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), частковий витік даних.
3. Класифікуйте: симетричне (AES/CTR/GCM), з відкритим ключем (RSA/ECC), hash/MAC (SHA/MD5/HMAC), класичне (Vigenere/XOR).
4. Спершу перевірте найімовірніші варіанти: шари декодування, XOR із відомим plaintext, повторне використання nonce, неправильне використання режиму, поведінку oracle.
5. Переходьте до просунутих методів лише за потреби: lattices (LLL/Coppersmith), SMT/Z3, side-channel атаки.

## Онлайн-ресурси та утиліти

Ці ресурси корисні для визначення типу даних і зняття шарів кодування, а також для швидкої перевірки гіпотези.

### Пошук hash

- Пошукайте hash із завдання, якщо він, імовірно, синтетичний або публічний.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Пошук на hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Не надсилайте реальні password hash або конфіденційні матеріали завдання стороннім сервісам пошуку. Якщо є ризик розголошення, порушення умов використання чи правил змагання, надавайте перевагу офлайн-атаці зі словником і правилами.

### Допоміжні засоби ідентифікації

- CyberChef (Magic, декодування та перетворення).<sup>[[7]](#references)</sup>
- dCode (середовище для шифрів і кодувань).<sup>[[8]](#references)</sup>
- Boxentriq (розв’язувачі шифрів заміни).<sup>[[9]](#references)</sup>

### Платформи для практики / довідкові матеріали

- CryptoHack (практичні завдання з криптографії).<sup>[[10]](#references)</sup>
- Cryptopals (класичні помилки в сучасній криптографії).<sup>[[11]](#references)</sup>

### Автоматичне декодування

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (перебирає багато систем числення та кодувань).<sup>[[13]](#references)</sup>

## Кодування та класичні шифри

### Методика

Багато завдань із криптографії на CTF — це ланцюжки перетворень: кодування base + проста заміна + стиснення. Мета — визначити шари та безпечно зняти їх.

### Кодування: спробуйте різні системи числення

Якщо підозрюєте багатошарове кодування (base64 → base32 → …), спробуйте:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Типові ознаки:

- Base64: `A-Za-z0-9+/=` (символ `=` часто використовується для доповнення)
- Base32: `A-Z2-7=` (часто багато символів `=` для доповнення)
- Ascii85/Base85: багато розділових знаків; іноді обгорнуто в `<~ ~>`

### Заміна / моноалфавітний шифр

- Розв’язувач криптограм Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Автоматичний зламувач шифру Caesar від Nayuki.<sup>[[15]](#references)</sup>
- Інструмент Atbash від Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Інструмент dCode для Vigenère.<sup>[[8]](#references)</sup>
- Розв’язувач Vigenère від Guballa.<sup>[[17]](#references)</sup>

### Шифр Bacon

Часто трапляється у вигляді груп із 5 бітів або 5 літер:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Руни

Руни часто є алфавітами для підстановки; шукайте «шифр футарком» і спробуйте таблиці відповідностей.

## Стиснення у завданнях

### Методика

Стиснення постійно трапляється як додатковий шар (zlib/deflate/gzip/xz/zstd), іноді вкладений. Якщо вивід майже розбирається, але схожий на сміття, запідозріть стиснення.

### Швидке визначення

- `file <blob>`
- Шукайте сигнатурні байти:
  - gzip: `1f 8b`
  - zlib: зазвичай `78 01`, `78 5e`, `78 9c` або `78 da` (другий байт залежить від прапорців стиснення)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

У CyberChef є **Raw Deflate/Raw Inflate** — часто це найшвидший спосіб, якщо дані схожі на стиснені, але `zlib` не спрацьовує.

### Корисні CLI-команди

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

### Техніка

Вони трапляються часто, оскільки відображають реалістичні помилки розробників або неправильне використання поширених бібліотек. Зазвичай потрібно розпізнати їх і застосувати відомий процес вилучення або відновлення.

### Fernet

Типова підказка: два рядки Base64 (токен + ключ).

- Декодер/нотатки: декодер Fernet від Asecuritysite.<sup>[[18]](#references)</sup>
- У Python: `from cryptography.fernet import Fernet`

### Розділення секрету Шаміра

Якщо є кілька часток і згадується поріг `t`, імовірно, це Shamir.

- Онлайн-відновлювач (лише для несекретних часток CTF).<sup>[[19]](#references)</sup>

### Формати OpenSSL із сіллю

У CTF іноді надають результати `openssl enc` (заголовок часто починається з `Salted__`).

Інструменти для перебору:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Загальний набір інструментів

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Рекомендоване локальне середовище

Практичний стек для CTF:

- Python із `pycryptodome` для симетричних примітивів і швидкого прототипування.<sup>[[25]](#references)</sup>
- SageMath для модульної арифметики, CRT, ґраток, а також роботи з RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 для завдань на основі обмежень (коли криптографічну задачу можна звести до обмежень).<sup>[[27]](#references)</sup>

Рекомендовані пакети Python:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [пошук hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [інструменти dCode](https://www.dcode.fr/tools-list)
- [9] [інструменти Boxentriq для зламу шифрів](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki — автоматичний злам шифру Цезаря](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin — шифр Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [розв'язувач шифру Віженера Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite — декодер Fernet](https://asecuritysite.com/encryption/ferdecode)
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
