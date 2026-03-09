# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## На що звертати увагу в CTFs

- **Неправильне використання режимів**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: різні помилки/затримки при некоректному padding.
- **MAC confusion**: використання CBC-MAC з повідомленнями змінної довжини або помилки типу MAC-then-encrypt.
- **XOR everywhere**: потокові шифри та кастомні конструкції часто зводяться до XOR з keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Це дозволяє:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

Якщо ви можете контролювати plaintext і спостерігати ciphertext (або cookies), спробуйте зробити повторювані блоки (наприклад, багато `A`s) і шукати повтори.

### CBC: Cipher Block Chaining

- CBC є **malleable**: зміна бітів у `C[i-1]` призводить до зміни передбачуваних бітів у `P[i]`.
- Якщо система видає (безпосередньо або опосередковано) інформацію про валідний чи невалідний padding, у вас може бути **padding oracle**.

### CTR

CTR перетворює AES на потоковий шифр: `C = P XOR keystream`.

Якщо nonce/IV повторно використовується з тим самим ключем:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- З відомим plaintext можна відновити keystream і розшифрувати інші повідомлення.

**Nonce/IV reuse exploitation patterns**

- Відновіть keystream де відомий/можна вгадати plaintext:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Застосуйте відновлені байти keystream для розшифровки будь-якого іншого ciphertext, згенерованого з тим самим key+IV на тих же офсетах.
- Highly structured data (наприклад, ASN.1/X.509 certificates, file headers, JSON/CBOR) дають великі області відомого plaintext. Ви часто можете XORити ciphertext сертифіката з передбачуваною частиною сертифіката, щоб вивести keystream, а потім розшифрувати інші секрети, зашифровані під тим самим IV. See also [TLS & Certificates](../tls-and-certificates/README.md) for typical certificate layouts.
- Коли кілька секретів того ж самого serialized формату/розміру зашифровані під тим самим key+IV, вирівнювання полів пролить інформацію навіть без повного відомого plaintext. Приклад: PKCS#8 RSA keys одного розміру модуля розміщують прості фактори в тих самих офсетах (~99.6% вирівнювання для 2048-bit). XOR двох ciphertext під повторно використаним keystream ізолює `p ⊕ p'` / `q ⊕ q'`, що може бути відновлено перебором за секунди.
- Default IVs in libraries (e.g., constant `000...01`) are a critical footgun: кожне шифрування повторює той самий keystream, перетворюючи CTR у повторно використаний one-time pad.

**CTR malleability**

- CTR надає лише конфіденційність: зміна бітів у ciphertext детерміновано змінює ті ж біти в plaintext. Без authentication tag атакувальники можуть підміняти дані (наприклад, tweak keys, flags або messages) непоміченими.
- Використовуйте AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) і забезпечуйте верифікацію тегу, щоб виявляти bit-flips.

### GCM

GCM також сильно ламається при повторному використанні nonce. Якщо той самий key+nonce використовується більше ніж один раз, зазвичай ви отримуєте:

- Keystream reuse для шифрування (як CTR), що дозволяє відновити plaintext, коли будь-який plaintext відомий.
- Втрату гарантій цілісності. Залежно від того, що відкрите (кілька message/tag пар під тим самим nonce), атакувальники можуть сформувати теги.

Операційні рекомендації:

- Розглядайте "nonce reuse" в AEAD як критичну вразливість.
- Misuse-resistant AEADs (наприклад, GCM-SIV) зменшують наслідки повторного використання nonce, але все одно вимагають унікальних nonces/IVs.
- Якщо у вас є кілька ciphertext під тим самим nonce, почніть з перевірки відношень типу `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) шифрує кожен блок незалежно:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Якщо ви логінитесь кілька разів і **завжди отримуєте той самий cookie**, ciphertext може бути детермінований (ECB або фіксований IV).

Якщо ви створите двох користувачів з майже ідентичними plaintext layouts (наприклад, довгі повторювані символи) і побачите повторювані ciphertext blocks в тих самих офсетах, ECB — головний підозрюваний.

### Exploitation patterns

#### Removing entire blocks

Якщо формат token виглядає як `<username>|<password>` і межа блока вирівняна, іноді можна створити користувача так, щоб блок із `admin` опинився вирівняним, потім видалити попередні блоки, щоб отримати дійсний token для `admin`.

#### Moving blocks

Якщо бекенд терпить padding/extra spaces (`admin` vs `admin    `), ви можете:

- Вирівняти блок, що містить `admin   `
- Замінити/повторно використати той ciphertext block у іншому token

## Padding Oracle

### What it is

У режимі CBC, якщо сервер розкриває (безпосередньо або опосередковано), чи розшифрований plaintext має **valid PKCS#7 padding**, ви часто можете:

- Розшифрувати ciphertext без ключа
- Зашифрувати вибраний plaintext (зфабрикувати ciphertext)

The oracle can be:

- A specific error message
- A different HTTP status / response size
- A timing difference

### Practical exploitation

PadBuster is the classic tool:

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

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Модифікуючи байти в `C[i-1]` і спостерігаючи, чи є padding валідним, ви можете відновити `P[i]` по байту.

## Bit-flipping у CBC

Навіть без padding oracle, CBC є змінюваним. Якщо ви можете модифікувати блоки шифротексту і додаток використовує розшифрований текст як структуровані дані (наприклад, `role=user`), ви можете інвертувати конкретні біти, щоб змінити вибрані байти у наступному блоці на заданій позиції.

Типовий CTF-патерн:

- Token = `IV || C1 || C2 || ...`
- Ви контролюєте байти в `C[i]`
- Ви націлюєтеся на байти в `P[i+1]`, бо `P[i+1] = D(C[i+1]) XOR C[i]`

Саме по собі це не злом конфіденційності, але це поширений примітив privilege-escalation, коли відсутня цілісність.

## CBC-MAC

CBC-MAC є безпечним лише за певних умов (зокрема **фіксованої довжини повідомлень** та правильного розділення доменів).

### Класичний патерн підробки для повідомлень змінної довжини

CBC-MAC зазвичай обчислюється так:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Якщо ви можете отримати теги для вибраних повідомлень, ви часто можете створити тег для конкатенації (або спорідненої конструкції) без знання ключа, експлуатуючи те, як CBC зв'язує блоки.

Це часто зустрічається в CTF у cookie/tokens, які MAC-ують username або role за допомогою CBC-MAC.

### Більш безпечні альтернативи

- Використовуйте HMAC (SHA-256/512)
- Використовуйте CMAC (AES-CMAC) правильно
- Включайте довжину повідомлення / розділення доменів

## Потокові шифри: XOR та RC4

### Ментальна модель

Більшість сценаріїв з потоковими шифрами зводяться до:

`ciphertext = plaintext XOR keystream`

Отже:

- Якщо ви знаєте plaintext, ви відновлюєте keystream.
- Якщо keystream повторно використовується (той самий key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Шифрування на основі XOR

Якщо ви знаєте будь-який сегмент plaintext на позиції `i`, ви можете відновити байти keystream і дешифрувати інші шифротексти на тих позиціях.

Автоматичні інструменти:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 — потоковий шифр; операції encrypt/decrypt однакові.

Якщо ви можете отримати RC4 encryption відомого plaintext під тим самим ключем, ви можете відновити keystream і дешифрувати інші повідомлення тієї самої довжини/зсуву.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Посилання

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
