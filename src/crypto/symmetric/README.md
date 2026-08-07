# Симетрична криптографія

{{#include ../../banners/hacktricks-training.md}}

## На що звертати увагу в CTF

- **Неправильне використання режимів**: патерни ECB, malleability CBC, повторне використання nonce у CTR/GCM.
- **Padding oracles**: різні помилки/таймінги для неправильного padding.
- **Плутанина з MAC**: використання CBC-MAC для повідомлень змінної довжини або помилки MAC-then-encrypt.
- **XOR всюди**: stream ciphers і custom constructions часто зводяться до XOR із keystream.

## Режими AES і неправильне використання

### ECB: Electronic Codebook

ECB leak-ить патерни: однакові блоки plaintext → однакові блоки ciphertext. Це дає змогу:

- Виконувати cut-and-paste / перестановку блоків
- Видаляти блоки (якщо формат залишається коректним)

Якщо ви можете контролювати plaintext і спостерігати ciphertext (або cookies), спробуйте створити повторювані блоки (наприклад, багато `A`) і пошукайте повтори.

### CBC: Cipher Block Chaining

- CBC є **malleable**: зміна бітів у `C[i-1]` змінює передбачувані біти в `P[i]`.
- Якщо система розкриває інформацію про коректний або некоректний padding, у вас може бути **padding oracle**.

### CTR

CTR перетворює AES на stream cipher: `C = P XOR keystream`.

Якщо nonce/IV повторно використовується з тим самим ключем:

- `C1 XOR C2 = P1 XOR P2` (класичне повторне використання keystream)
- Знаючи plaintext, можна відновити keystream і розшифрувати інші дані.

**Патерни exploitation повторного використання Nonce/IV**

- Відновлюйте keystream всюди, де plaintext відомий або його можна передбачити:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Застосовуйте відновлені байти keystream для розшифрування будь-якого іншого ciphertext, створеного з тим самим key+IV, на тих самих offsets.
- Дані з чіткою структурою (наприклад, сертифікати ASN.1/X.509, заголовки файлів, JSON/CBOR) містять великі області відомого plaintext. Часто можна виконати XOR ciphertext сертифіката з передбачуваним тілом сертифіката, щоб отримати keystream, а потім розшифрувати інші secrets, зашифровані з повторно використаним IV. Див. також [TLS і Certificates](../tls-and-certificates/README.md) для типових структур сертифікатів.<sup>[[1]](#references)</sup>
- Коли кілька secrets однакового **serialized format/size** зашифровані з тим самим key+IV, вирівнювання полів leak-ить інформацію навіть без повністю відомого plaintext. Наприклад, RSA keys формату PKCS#8 з однаковим розміром модуля розміщують прості множники на відповідних offsets (приблизно 99,6% вирівнювання для 2048-bit). XOR двох ciphertext із повторно використаним keystream ізолює `p ⊕ p'` / `q ⊕ q'`, що можна brute-force відновити за секунди.<sup>[[1]](#references)</sup>
- Стандартні IV у libraries (наприклад, константа `000...01`) є критичною footgun: кожне шифрування повторює той самий keystream, перетворюючи CTR на повторно використаний one-time pad.<sup>[[1]](#references)</sup>

**Malleability CTR**

- CTR забезпечує лише confidentiality: зміна бітів у ciphertext детерміновано змінює ті самі біти в plaintext. Без authentication tag attackers можуть непомітно змінювати дані (наприклад, keys, flags або messages).
- Використовуйте AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 тощо) і забезпечте перевірку tag, щоб виявляти bit-flips.

### GCM

GCM також серйозно ламається в разі повторного використання nonce. Якщо той самий key+nonce використовується більше одного разу, зазвичай виникає таке:

- Повторне використання keystream для encryption (як у CTR), що дає змогу відновити plaintext, якщо відомий будь-який plaintext.
- Втрата гарантій integrity. Залежно від того, що саме відкрито (кілька пар message/tag з тим самим nonce), attackers можуть підробляти tags.

Операційні рекомендації:

- Вважайте "nonce reuse" критичною vulnerability в AEAD.
- Misuse-resistant AEAD (наприклад, GCM-SIV) зменшують наслідки неправильного використання nonce, але все одно потребують унікальних nonces/IVs.
- Якщо у вас є кілька ciphertext з тим самим nonce, почніть із перевірки співвідношень на кшталт `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef для швидких експериментів: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` для scripting

## Патерни exploitation ECB

ECB (Electronic Code Book) шифрує кожен блок незалежно:

- однакові блоки plaintext → однакові блоки ciphertext
- це leak-ить структуру і дає змогу виконувати атаки у стилі cut-and-paste

![Діаграма розшифрування блоків у режимі ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ідея виявлення: патерн token/cookie

Якщо ви входите в систему кілька разів і **завжди отримуєте той самий cookie**, ciphertext може бути deterministic (ECB або fixed IV).

Якщо ви створюєте двох users із майже ідентичними layout plaintext (наприклад, із довгими повторюваними символами) і бачите повторювані блоки ciphertext на тих самих offsets, ECB є головним підозрюваним.

### Патерни exploitation

#### Видалення цілих блоків

Якщо формат token має вигляд `<username>|<password>` і межа блоку вирівняна, іноді можна створити user так, щоб блок `admin` був вирівняний, а потім видалити попередні блоки й отримати коректний token для `admin`.

#### Переміщення блоків

Якщо backend допускає padding/додаткові пробіли (`admin` проти `admin    `), можна:

- Вирівняти блок, що містить `admin   `
- Замінити/повторно використати цей блок ciphertext в іншому token

## Padding Oracle

### Що це таке

У режимі CBC, якщо server прямо або опосередковано розкриває, чи має розшифрований plaintext **коректний PKCS#7 padding**, часто можна:

- Розшифрувати ciphertext без ключа
- Зашифрувати вибраний plaintext (підробити ciphertext)

Oracle може бути:

- Конкретне повідомлення про помилку
- Інший HTTP status / розмір response
- Різниця в timing

### Практичне exploitation

PadBuster — класичний tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Приклад:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Розмір блоку часто дорівнює `16` для AES.
- `-encoding 0` означає Base64.
- Використовуйте `-error`, якщо oracle повертає певний рядок.

### Чому це працює

CBC-розшифрування обчислює `P[i] = D(C[i]) XOR C[i-1]`. Змінюючи байти в `C[i-1]` і спостерігаючи, чи є padding коректним, можна відновити `P[i]` побайтно.

## Bit-flipping in CBC

Навіть без padding oracle CBC є malleable. Якщо ви можете змінювати блоки ciphertext, а застосунок використовує розшифрований plaintext як структуровані дані (наприклад, `role=user`), можна змінювати окремі біти, щоб змінити вибрані байти plaintext у потрібній позиції наступного блоку.

Типовий CTF-патерн:

- Token = `IV || C1 || C2 || ...`
- Ви контролюєте байти в `C[i]`
- Ви націлюєтеся на байти plaintext у `P[i+1]`, оскільки `P[i+1] = D(C[i+1]) XOR C[i]`

Саме по собі це не є зламом confidentiality, але це поширений primitive для privilege escalation, коли integrity відсутня.

## CBC-MAC

CBC-MAC є безпечним лише за певних умов (зокрема, для **повідомлень фіксованої довжини** та за умови коректного domain separation).

### Класичний патерн forgery для повідомлень змінної довжини

CBC-MAC зазвичай обчислюється так:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Якщо ви можете отримувати tags для вибраних повідомлень, часто можна створити tag для конкатенації (або пов'язаної конструкції), не знаючи ключа, використовуючи спосіб, у який CBC об'єднує блоки.

Це часто трапляється в CTF cookies/tokens, які використовують CBC-MAC для MAC username або role.

### Безпечніші альтернативи

- Використовуйте HMAC (SHA-256/512)
- Коректно використовуйте CMAC (AES-CMAC)
- Додавайте довжину повідомлення / domain separation

## Stream ciphers: XOR and RC4

### Ментальна модель

Більшість ситуацій зі stream cipher зводиться до:

`ciphertext = plaintext XOR keystream`

Отже:

- Якщо ви знаєте plaintext, ви відновлюєте keystream.
- Якщо keystream повторно використовується (той самий key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Якщо ви знаєте будь-який сегмент plaintext у позиції `i`, можна відновити байти keystream і розшифрувати інші ciphertext у цих позиціях.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 — це stream cipher; encrypt/decrypt є тією самою операцією.

Якщо ви можете отримати RC4 encryption відомого plaintext з тим самим key, можна відновити keystream і розшифрувати інші повідомлення такої самої довжини/зміщення.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
