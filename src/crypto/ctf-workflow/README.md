# Робочий процес Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Контрольний список тріажу

1. Визначте, що саме маєте: кодування, шифрування, хеш, підпис чи MAC.
2. Визначте, що контролюється: відкритий текст/шифротекст, IV/nonce, ключ, oracle (padding/error/timing), частковий витік даних.
3. Класифікуйте: симетричне шифрування (AES/CTR/GCM), криптографія з відкритим ключем (RSA/ECC), хеш/MAC (SHA/MD5/HMAC), класичні шифри (Vigenere/XOR).
4. Спершу виконайте перевірки з найбільшою ймовірністю успіху: декодуйте шари, перевірте XOR із відомим відкритим текстом, повторне використання nonce, неправильне використання режиму, поведінку oracle.
5. Переходьте до складніших методів лише за потреби: решітки (LLL/Coppersmith), SMT/Z3, побічні канали.

## Онлайн-ресурси та утиліти

Вони стануть у пригоді для ідентифікації та зняття шарів або для швидкої перевірки гіпотези.

### Пошук хешів

- Шукайте хеш завдання, якщо він, імовірно, синтетичний або загальнодоступний.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Пошук на hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Не надсилайте реальні хеші паролів або конфіденційні матеріали завдання до сторонніх сервісів пошуку. Якщо є ризик розголошення або проблем із правилами користування чи змагання, віддавайте перевагу офлайн-атаці зі словником і правилами.

### Допоміжні засоби для ідентифікації

- CyberChef (Magic, декодування та перетворення).<sup>[[7]](#references)</sup>
- dCode (майданчик для шифрів і кодувань).<sup>[[8]](#references)</sup>
- Boxentriq (розв’язувачі шифрів заміни).<sup>[[9]](#references)</sup>

### Навчальні платформи / довідкові матеріали

- CryptoHack (практичні завдання з криптографії).<sup>[[10]](#references)</sup>
- Cryptopals (класичні помилки сучасної криптографії).<sup>[[11]](#references)</sup>

### Автоматичне декодування

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (перевіряє багато систем числення та кодувань).<sup>[[13]](#references)</sup>

## Кодування та класичні шифри

### Методика

У багатьох криптографічних завданнях CTF застосовано кілька послідовних перетворень: кодування base + проста заміна + стиснення. Мета — визначити шари й безпечно зняти їх.

### Кодування: спробуйте різні системи числення

Якщо підозрюєте багатошарове кодування (base64 → base32 → …), спробуйте:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Типові ознаки:

- Base64: `A-Za-z0-9+/=` (символ `=` часто використовується для доповнення)
- Base32: `A-Z2-7=` (часто багато символів `=` для доповнення)
- Ascii85/Base85: багато знаків пунктуації; іноді формат обрамлено символами `<~ ~>`

### Заміна / моноалфавітний шифр

- Розв’язувач криптограм Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Відновлення заміни за відомими відкритими текстами в іменах файлів Base32

Якщо обфусковане ім’я файлу містить лише символи `a-z2-7`, після вилучення фіксованого суфікса має приблизно `ceil(8 * byte_length / 5)` символів, а той самий відкритий текст дає однаковий результат для різних файлів, перевірте гіпотезу про **Base32 без доповнення, за яким іде заміна символів за фіксованою схемою**. Самі по собі ці ознаки нічого не доводять. Зберіть передбачувані імена файлів і відповідні їм шифротексти, збережіть регістр, закодуйте кожен відкритий текст у Base32 та зіставте символи позиція за позицією. Кожен повторюваний символ відкритого тексту має відповідати тому самому символу шифротексту, а зворотне зіставлення також має бути однозначним. В одному випадку ransomware такі пари дали `ntuser.ini` та `NTUSER.DAT`; це дало змогу відновити імена файлів, **але не вміст файлів чи ключі шифрування**.<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

Якщо ціль містить невідображені символи, отримайте більше відомих пар або переставляйте лише невикористані відповідності символів Base32. Відновіть padding до межі у вісім символів, відхиліть некоректний Base32 і декодовані імена з недрукованими символами, а потім знову закодуйте кандидатів, що залишилися, і порівняйте з **усім** оригінальним ciphertext. Повторювані блоки ciphertext можуть дати додаткові здогадки: у наведеному вище випадку `3gpng2wv` відповідало Base32 `gaydambq`, яке декодується у п’ять нульових символів ASCII. Сам по собі кандидат із друкованими символами не є однозначним доказом.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Автоматичний дешифрувальник шифру Caesar від Nayuki.<sup>[[15]](#references)</sup>
- Інструмент Atbash від Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Інструмент Vigenère від dCode.<sup>[[8]](#references)</sup>
- Розв’язувач Vigenère від Guballa.<sup>[[17]](#references)</sup>

### Bacon cipher

Часто трапляється у вигляді груп по 5 бітів або 5 літер:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Руни

Руни часто є алфавітами заміни; пошукайте "futhark cipher" і спробуйте таблиці відповідностей.

## Стиснення у завданнях

### Техніка

Стиснення постійно трапляється як додатковий шар (zlib/deflate/gzip/xz/zstd), іноді вкладений. Якщо вивід майже розбирається, але виглядає як сміття, запідозріть стиснення.

### Швидке визначення

- `file <blob>`
- Шукайте магічні байти:
  - gzip: `1f 8b`
  - zlib: зазвичай `78 01`, `78 5e`, `78 9c` або `78 da` (другий байт залежить від прапорців стиснення)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

У CyberChef є **Raw Deflate/Raw Inflate** — часто це найшвидший спосіб, якщо blob схожий на стиснений, але `zlib` не спрацьовує.

### Корисні CLI-файли

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

Вони часто трапляються, оскільки це реалістичні помилки розробників або поширені бібліотеки, використані неправильно. Зазвичай потрібно розпізнати їх і застосувати відомий алгоритм вилучення або відновлення.

### Fernet

Типова підказка: два рядки Base64 (токен + ключ).

- Декодер/нотатки: декодер Fernet від Asecuritysite.<sup>[[18]](#references)</sup>
- У Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Якщо є кілька часток і згадується поріг `t`, імовірно, це Shamir.

- Онлайн-засіб відновлення (лише для несекретних часток CTF).<sup>[[19]](#references)</sup>

### Формати OpenSSL із сіллю

У CTF іноді надають результати `openssl enc` (заголовок часто починається з `Salted__`).

Засоби для брутфорсу:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Загальний набір інструментів

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Рекомендоване локальне середовище

Практичний стек для CTF:

- Python і `pycryptodome` для симетричних примітивів і швидкого прототипування.<sup>[[25]](#references)</sup>
- SageMath для модульної арифметики, CRT, ґраток і задач із RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 для задач із обмеженнями (коли криптографічна задача зводиться до обмежень).<sup>[[27]](#references)</sup>

Рекомендовані пакети Python:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [пошук hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [інструменти dCode](https://www.dcode.fr/tools-list)
- [9] [інструменти зламу кодів Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki — автоматичний злам шифру Цезаря](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin — шифр Атбаш](https://rumkin.com/tools/cipher/atbash/)
- [17] [розв’язувач шифру Віженера Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite — декодер Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [реконструктор розділення секрету Шаміра](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [документація PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research — злам схем шифрування найпростішим способом](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
