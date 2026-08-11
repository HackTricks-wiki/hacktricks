# Симетрична криптографія

{{#include ../../banners/hacktricks-training.md}}

## На що звертати увагу в CTF

- **Неправильне використання режимів**: шаблони ECB, malleability CBC, повторне використання nonce у CTR/GCM.
- **Padding oracles**: різні помилки/затримки для неправильного padding.
- **Плутанина з MAC**: використання CBC-MAC для повідомлень змінної довжини або помилки MAC-then-encrypt.
- **XOR всюди**: stream ciphers і custom constructions часто зводяться до XOR із keystream.

## Режими AES і неправильне використання

NIST визначає режими конфіденційності ECB, CBC і CTR у SP 800-38A, а authenticated encryption GCM — у SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB leaks patterns: однакові блоки plaintext → однакові блоки ciphertext. Це дає змогу:

- Виконувати cut-and-paste / перестановку блоків
- Видаляти блоки (якщо формат залишається коректним)

Якщо ви можете контролювати plaintext і спостерігати ciphertext (або cookies), спробуйте створити повторювані блоки (наприклад, багато `A`), а потім шукайте повтори.

### CBC: Cipher Block Chaining

- CBC є **malleable**: перевертання бітів у `C[i-1]` передбачувано перевертає відповідні біти в `P[i]`, одночасно пошкоджуючи `P[i-1]`. Зміна IV впливає на перший блок plaintext, не пошкоджуючи попередній блок plaintext.
- Якщо система розрізняє коректний і некоректний padding, у вас може бути **padding oracle**.

### CTR

CTR перетворює AES на stream cipher: `C = P XOR keystream`.

Якщо nonce/IV повторно використовується з тим самим ключем:

- `C1 XOR C2 = P1 XOR P2` (класичне повторне використання keystream)
- За відомим plaintext можна відновити keystream і розшифрувати інші дані.

**Шаблони експлуатації повторного використання nonce/IV**

- Відновлюйте keystream там, де plaintext відомий або його можна вгадати:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Застосовуйте відновлені байти keystream для розшифрування будь-якого іншого ciphertext, створеного з тим самим key+IV на тих самих offset.
- Дані з чіткою структурою (наприклад, сертифікати ASN.1/X.509, заголовки файлів, JSON/CBOR) містять великі ділянки відомого plaintext. Часто можна виконати XOR ciphertext сертифіката з передбачуваним тілом сертифіката, щоб отримати keystream, а потім розшифрувати інші secrets, зашифровані з повторно використаним IV. Див. також [TLS & Certificates](../tls-and-certificates/README.md) для типових структур сертифікатів.<sup>[[1]](#references)</sup>
- Коли кілька secrets одного **серіалізованого формату/розміру** зашифровано з тим самим key+IV, вирівнювання полів leaks навіть без повного відомого plaintext. Наприклад, PKCS#8 RSA keys однакового розміру модуля розміщують прості множники за однаковими offset (приблизно 99,6% вирівнювання для 2048-bit). XOR двох ciphertext з використанням повторно застосованого keystream ізолює `p ⊕ p'` / `q ⊕ q'`, що можна відновити brute-force за кілька секунд.<sup>[[1]](#references)</sup>
- Default IVs у libraries (наприклад, константа `000...01`) є критичною помилкою: кожне шифрування повторює той самий keystream, перетворюючи CTR на повторно використаний one-time pad.<sup>[[1]](#references)</sup>

**Malleability CTR**

- CTR забезпечує лише конфіденційність: перевертання бітів у ciphertext детерміновано перевертає ті самі біти в plaintext. Без authentication tag attackers можуть непомітно змінювати дані (наприклад, keys, flags або messages).
- Використовуйте AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 тощо) і забезпечуйте перевірку tag, щоб виявляти bit-flips.

### GCM

GCM також серйозно ламається через повторне використання nonce. Якщо той самий key+nonce використовується більше одного разу, зазвичай виникає:

- Повторне використання keystream для шифрування (як у CTR), що дає змогу відновити plaintext, якщо будь-який plaintext відомий.
- Втрата гарантій integrity. Залежно від того, що саме доступно (кілька пар message/tag з тим самим nonce), attackers можуть отримати змогу підробляти tags.

Операційні рекомендації:

- Вважайте "nonce reuse" критичною вразливістю в AEAD.
- Misuse-resistant AEADs, такі як AES-GCM-SIV, зменшують наслідки повторного використання nonce. Callers все одно мають надавати унікальні nonces, як того вимагає interface конструкції; випадкове повторне використання має обмежені наслідки порівняно зі звичайним GCM.<sup>[[3]](#references)[[4]](#references)</sup>
- Якщо у вас є кілька ciphertext з тим самим nonce, почніть із перевірки relations на кшталт `C1 XOR C2 = P1 XOR P2`.

### Tools

- [CyberChef](https://gchq.github.io/CyberChef/) для швидких експериментів.<sup>[[8]](#references)</sup>
- Пакет [PyCryptodome](https://www.pycryptodome.org/) для scripting на Python.<sup>[[9]](#references)</sup>

## Шаблони експлуатації ECB

ECB (Electronic Code Book) шифрує кожен блок незалежно:

- однакові блоки plaintext → однакові блоки ciphertext
- це leaks structure і дає змогу виконувати атаки на кшталт cut-and-paste

![Діаграма блокового розшифрування в режимі ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ідея виявлення: шаблон token/cookie

Якщо ви кілька разів виконуєте login і **завжди отримуєте той самий cookie**, ciphertext може бути детермінованим (ECB або fixed IV).

Якщо ви створюєте двох users із майже ідентичними структурами plaintext (наприклад, із довгими повторюваними символами) і бачите повторювані блоки ciphertext на тих самих offset, ECB є основним підозрюваним.

### Шаблони експлуатації

#### Видалення цілих блоків

Якщо формат token має вигляд `<username>|<password>` і межа блока вирівняна, іноді можна створити user так, щоб блок `admin` був вирівняний, а потім видалити попередні блоки й отримати коректний token для `admin`.

#### Переміщення блоків

Якщо backend допускає padding/додаткові пробіли (`admin` проти `admin    `), можна:

- Вирівняти блок, що містить `admin   `
- Замінити/повторно використати цей блок ciphertext в іншому token

## Padding Oracle

### Що це таке

У режимі CBC, якщо server безпосередньо або опосередковано повідомляє, чи має розшифрований plaintext **коректний PKCS#7 padding**, часто можна:<sup>[[7]](#references)</sup>

- Розшифрувати ciphertext без ключа
- Створити ciphertext, який розшифровується у вибраний plaintext, якщо можна передавати створені попередні блоки або IV, а application приймає отримане повідомлення з коректним padding

Oracle може бути:

- Конкретним повідомленням про помилку
- Іншим HTTP status / розміром response
- Різницею в timing

### Практична експлуатація

PadBuster — класичний tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Приклад:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Нотатки:

- Розмір блоку часто дорівнює `16` для AES.
- `-encoding 0` означає Base64.
- Використовуйте `-error`, якщо oracle повертає певний рядок.

### Чому це працює

CBC-розшифрування обчислює `P[i] = D(C[i]) XOR C[i-1]`. Змінюючи байти в `C[i-1]` і спостерігаючи, чи є padding дійсним, можна відновити `P[i]` побайтно.

## Bit-flipping in CBC

Навіть без padding oracle CBC є malleable. Якщо ви можете змінювати блоки ciphertext, а застосунок використовує розшифрований plaintext як структуровані дані (наприклад, `role=user`), можна змінювати певні біти, щоб змінити вибрані байти plaintext у потрібній позиції наступного блоку.

Типовий шаблон CTF:

- Token = `IV || C1 || C2 || ...`
- Ви контролюєте байти в `C[i]`
- Ви націлюєтеся на байти plaintext у `P[i+1]`, оскільки `P[i+1] = D(C[i+1]) XOR C[i]`

Саме по собі це не є зламом конфіденційності, але це поширений примітив для підвищення привілеїв, коли відсутня цілісність.

## CBC-MAC

CBC-MAC є безпечним лише за певних умов (зокрема, для **повідомлень фіксованої довжини** та за умови правильного розділення доменів). AES-CMAC — це стандартизована конструкція, яка безпечно обробляє вхідні дані змінної довжини.<sup>[[5]](#references)</sup>

### Класичний шаблон forgery для повідомлень змінної довжини

CBC-MAC зазвичай обчислюється так:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Якщо ви можете отримувати tags для вибраних повідомлень, часто можна створити tag для конкатенації (або пов’язаної конструкції), не знаючи ключа, використовуючи спосіб з’єднання блоків у CBC.

Це часто зустрічається в CTF cookies/tokens, які обчислюють MAC для username або role за допомогою CBC-MAC.

### Безпечніші альтернативи

- Використовуйте HMAC (SHA-256/512)
- Правильно використовуйте CMAC (AES-CMAC)
- Додавайте довжину повідомлення / domain separation

## Stream ciphers: XOR and RC4

### Ментальна модель

Більшість ситуацій зі stream cipher зводиться до:

`ciphertext = plaintext XOR keystream`

Отже:

- Якщо ви знаєте plaintext, ви відновлюєте keystream.
- Якщо keystream використовується повторно (той самий key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Якщо ви знаєте будь-який сегмент plaintext у позиції `i`, ви можете відновити байти keystream і розшифрувати інші ciphertext у цих позиціях.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 — це застарілий stream cipher; шифрування та розшифрування виконуються тією самою операцією XOR. Відомі biases роблять його непридатним для нових систем, а TLS явно забороняє його cipher suites.<sup>[[6]](#references)</sup>

Якщо ви можете отримати RC4 encryption відомого plaintext з тим самим ключем, ви можете відновити keystream і розшифрувати інші повідомлення такої самої довжини/зі таким самим offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Недбалість проти майстерності в криптографії](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Рекомендації щодо режимів роботи блочних шифрів](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Рекомендації щодо Galois/Counter Mode (GCM) і GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Автентифіковане шифрування, стійке до неправильного використання nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - Алгоритм AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Заборона RC4 Cipher Suites](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Тестування на Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Документація PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
