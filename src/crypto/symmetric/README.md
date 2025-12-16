# Симетрична криптографія

{{#include ../../banners/hacktricks-training.md}}

## На що звертати увагу в CTFs

- **Неправильне використання режиму**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: різні помилки/затримки для некоректного padding.
- **MAC confusion**: використання CBC-MAC з повідомленнями змінної довжини або помилки MAC-then-encrypt.
- **XOR everywhere**: потокові шифри та кастомні конструкції часто зводяться до XOR з keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Це дозволяє:

- Cut-and-paste / block reordering
- Block deletion (якщо формат залишається дійсним)

Якщо ви можете контролювати plaintext і спостерігати ciphertext (або cookies), спробуйте зробити повторювані блоки (наприклад багато `A`) і дивитися на повтори.

### CBC: Cipher Block Chaining

- CBC is **malleable**: зміна бітів в `C[i-1]` змінює передбачувані біти в `P[i]`.
- Якщо система видає відмінність між валідним padding та невалідним padding, у вас може бути **padding oracle**.

### CTR

CTR перетворює AES у stream cipher: `C = P XOR keystream`.

Якщо nonce/IV повторно використовується з тим самим ключем:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- За наявності відомого plaintext ви можете відновити keystream і розшифрувати інші повідомлення.

### GCM

GCM також сильно ламатиметься при повторному використанні nonce. Якщо той самий key+nonce використовується більше одного разу, зазвичай отримуєте:

- Keystream reuse для шифрування (як CTR), що дозволяє відновити plaintext при відомому plaintext.
- Втрату гарантій цілісності. Залежно від того, що відкрито (декілька message/tag пар під тим самим nonce), атакуючі можуть зуміти сфальсифікувати теги.

Оперативні рекомендації:

- Розглядайте "nonce reuse" в AEAD як критичну вразливість.
- Якщо у вас є кілька ciphertext під тим самим nonce, почніть перевірку відношень типу `C1 XOR C2 = P1 XOR P2`.

### Інструменти

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) шифрує кожен блок незалежно:

- equal plaintext blocks → equal ciphertext blocks
- це витікає структуру і дозволяє cut-and-paste стилі атак

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ідея виявлення: шаблон token/cookie

Якщо ви логінитесь кілька разів і **завжди отримуєте той самий cookie**, ciphertext може бути детермінованим (ECB або фіксований IV).

Якщо ви створите двох користувачів з переважно ідентичними plaintext макетами (наприклад довгі повторювані символи) і бачите повторювані ciphertext blocks на тих самих офсетах, ECB — головний підозрюваний.

### Шаблони експлуатації

#### Видалення цілих блоків

Якщо формат токена виглядає як `<username>|<password>` і межа блока вирівняна, іноді можна створити користувача так, щоб блок `admin` опинився вирівняним, а потім видалити попередні блоки щоб отримати валідний токен для `admin`.

#### Переміщення блоків

Якщо бекенд толерує padding/extra spaces (`admin` vs `admin    `), ви можете:

- Вирівняти блок що містить `admin   `
- Замінити/перевикористати той ciphertext block в іншому токені

## Padding Oracle

### Що це таке

В CBC режимі, якщо сервер розкриває (прямо чи опосередковано), чи розшифрований plaintext має **valid PKCS#7 padding**, ви часто можете:

- Decrypt ciphertext без ключа
- Encrypt chosen plaintext (forge ciphertext)

Оракул може бути:

- Специфічне повідомлення про помилку
- Інший HTTP status / response size
- Різниця в часі виконання

### Практична експлуатація

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Приклад:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Примітки:

- Розмір блоку зазвичай `16` для AES.
- `-encoding 0` означає Base64.
- Використовуйте `-error`, якщо oracle є конкретним рядком.

### Чому це працює

CBC-розшифрування обчислює `P[i] = D(C[i]) XOR C[i-1]`. Модифікуючи байти в `C[i-1]` і спостерігаючи, чи padding валідний, можна відновити `P[i]` байт за байтом.

## Bit-flipping in CBC

Навіть без padding oracle, CBC є змінним. Якщо ви можете модифікувати блоки шифротексту і застосунок використовує розшифрований plaintext як структуровані дані (наприклад, `role=user`), ви можете перевірнути конкретні біти, щоб змінити обрані байти plaintext у вибраній позиції наступного блоку.

Типовий CTF патерн:

- Token = `IV || C1 || C2 || ...`
- Ви контролюєте байти в `C[i]`
- Ви націлюєте plaintext-байти в `P[i+1]`, тому що `P[i+1] = D(C[i+1]) XOR C[i]`

Саме по собі це не порушення конфіденційності, але це поширений privilege-escalation primitive, коли відсутня цілісність.

## CBC-MAC

CBC-MAC захищений лише за конкретних умов (зокрема **повідомлення фіксованої довжини** і правильне розділення доменів).

### Classic variable-length forgery pattern

CBC-MAC зазвичай обчислюється так:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Якщо ви можете отримати теги для обраних повідомлень, часто можна змайструвати тег для конкатенації (або пов'язаної конструкції) без знання ключа, експлуатуючи те, як CBC зв'язує блоки.

Це часто з'являється в CTF cookies/tokens, які MAC username або role з використанням CBC-MAC.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### The mental model

Більшість випадків з потоковими шифрами зводяться до:

`ciphertext = plaintext XOR keystream`

Отже:

- Якщо ви знаєте plaintext, ви відновлюєте keystream.
- Якщо keystream повторно використовується (той самий key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Якщо ви знаєте будь-який сегмент plaintext на позиції `i`, ви можете відновити байти keystream і розшифрувати інші ciphertexts на тих позиціях.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 — потоковий шифр; encrypt/decrypt — та сама операція.

Якщо ви можете отримати RC4 encryption відомого plaintext під тим самим ключем, ви можете відновити keystream і розшифрувати інші повідомлення тієї самої довжини/зсуву.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
