# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## На що звертати увагу в CTFs

- **Неправильне використання режимів**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: різні помилки/затримки для некоректного padding.
- **MAC confusion**: використання CBC-MAC з повідомленнями змінної довжини, або помилки типу MAC-then-encrypt.
- **XOR everywhere**: stream ciphers та кастомні конструкції часто зводяться до XOR з keystream.

## AES режими та їх неправильне використання

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Це дозволяє:

- Вирізати-та-вставити / перестановка блоків
- Видалення блоків (якщо формат залишається дійсним)

Якщо ви можете контролювати plaintext і спостерігати ciphertext (або cookies), спробуйте зробити повторювані блоки (наприклад, багато `A`s) і шукати повтори.

### CBC: Cipher Block Chaining

- CBC є **malleable**: зміна бітів у `C[i-1]` змінює передбачувані біти в `P[i]`.
- Якщо система розрізняє валідне padding і невалідне padding, у вас може бути **padding oracle**.

### CTR

CTR turns AES into a stream cipher: `C = P XOR keystream`.

Якщо nonce/IV повторно використовуються з тим самим ключем:

- `C1 XOR C2 = P1 XOR P2` (класичне повторне використання keystream)
- Якщо plaintext відомий, ви можете відновити keystream і розшифрувати інші.

### GCM

GCM також сильно ламається при повторному використанні nonce. Якщо той самий key+nonce використовується більше одного разу, зазвичай отримуєте:

- Повторне використання keystream для шифрування (як CTR), що дозволяє відновити plaintext, якщо будь-який plaintext відомий.
- Втрата гарантій цілісності. Залежно від того, що відкрито (кілька пар message/tag під тим самим nonce), атакуючі можуть змогти зфальсифікувати теги.

Операційні поради:

- Розглядайте "nonce reuse" в AEAD як критичну вразливість.
- Якщо у вас є кілька ciphertext під тим самим nonce, почніть з перевірки співвідношень типу `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef для швидких експериментів: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` для скриптингу

## ECB exploitation patterns

ECB (Electronic Code Book) шифрує кожний блок незалежно:

- equal plaintext blocks → equal ciphertext blocks
- це leaks структуру і дозволяє атаки стилю cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Якщо ви входите кілька разів і **завжди отримуєте той самий cookie**, ciphertext може бути детермінованим (ECB або фіксований IV).

Якщо ви створите двох користувачів з майже ідентичними plaintext макетами (наприклад, довгі повторювані символи) і побачите повторювані ciphertext блоки на тих самих зміщеннях, ECB — головний підозрюваний.

### Exploitation patterns

#### Removing entire blocks

Якщо формат токена схожий на `<username>|<password>` і межа блоку вирівнена, іноді можна створити користувача так, щоб блок з `admin` виявився вирівняним, потім видалити попередні блоки щоб отримати дійсний токен для `admin`.

#### Moving blocks

Якщо бекенд допускає padding/додаткові пробіли (`admin` vs `admin    `), ви можете:

- Вирівняти блок, який містить `admin   `
- Замінити/перевикористати той ciphertext блок в іншому токені

## Padding Oracle

### What it is

В режимі CBC, якщо сервер розкриває (прямо чи опосередковано), чи розшифрований plaintext має **valid PKCS#7 padding**, ви часто можете:

- Розшифрувати ciphertext без ключа
- Зашифрувати обраний plaintext (підробити ciphertext)

Оракл може бути:

- Конкретне повідомлення про помилку
- Інший HTTP статус / розмір відповіді
- Різниця в часі

### Practical exploitation

PadBuster — класичний інструмент:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Примітки:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Чому це працює

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Змінюючи байти в `C[i-1]` і спостерігаючи, чи валідний padding, ви можете відновити `P[i]` побайтно.

## Bit-flipping in CBC

Навіть без padding oracle, CBC є змінюваним. Якщо ви можете змінювати блоки ciphertext і застосунок використовує розшифрований plaintext як структуровані дані (наприклад, `role=user`), ви можете перевертати конкретні біти, щоб змінити вибрані байти plaintext у заданій позиції наступного блоку.

Типовий шаблон у CTF:

- Token = `IV || C1 || C2 || ...`
- Ви контролюєте байти в `C[i]`
- Ви цілитесь у байти plaintext в `P[i+1]`, тому що `P[i+1] = D(C[i+1]) XOR C[i]`

Само по собі це не порушення конфіденційності, але це поширений примітив для підвищення привілеїв, коли відсутня цілісність.

## CBC-MAC

CBC-MAC є безпечним лише за певних умов (зокрема **повідомлення фіксованої довжини** і коректне розділення доменів).

### Класичний шаблон підробки для змінної довжини

CBC-MAC зазвичай обчислюється так:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Якщо ви можете отримати теги для обраних повідомлень, ви часто можете сфабрикувати тег для конкатенації (або спорідненої конструкції) без знання ключа, експлуатуючи те, як CBC пов'язує блоки.

Це часто зустрічається в CTF cookie/tokens, які MAC username або role за допомогою CBC-MAC.

### Більш безпечні альтернативи

- Використовуйте HMAC (SHA-256/512)
- Використовуйте CMAC (AES-CMAC) правильно
- Включайте довжину повідомлення / розділення доменів

## Stream ciphers: XOR and RC4

### Ментальна модель

Більшість випадків stream cipher зводяться до:

`ciphertext = plaintext XOR keystream`

Отже:

- Якщо ви знаєте plaintext, ви відновлюєте keystream.
- Якщо keystream повторно використовується (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Якщо ви знаєте будь-який сегмент plaintext на позиції `i`, ви можете відновити байти keystream і розшифрувати інші ciphertext на тих позиціях.

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 is a stream cipher; encrypt/decrypt are the same operation.

Якщо ви можете отримати RC4 encryption від відомого plaintext під тим самим key, ви можете відновити keystream і розшифрувати інші messages тієї ж довжини/зсуву.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
