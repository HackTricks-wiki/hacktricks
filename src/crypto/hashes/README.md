# Хеші, MAC і KDF

{{#include ../../banners/hacktricks-training.md}}

## Поширені шаблони CTF

- «Підпис» насправді є `hash(secret || message)` → length extension.
- Хеші паролів без солі → швидший повторний перебір і атаки з попередньо обчисленими таблицями.
- Плутанина між хешем і MAC (hash != authentication).

## Атака length extension

### Методика

Атака length extension може бути можливою, якщо сервер обчислює «підпис» на кшталт:

`sig = HASH(secret || message)`

і використовує хеш Merkle-Damgård, як-от MD5, SHA-1 або SHA-256.

Якщо вам відомі:

- `message`
- `sig`
- хеш-функція
- (або ви можете перебрати) `len(secret)`

то ви можете обчислити дійсний підпис для:

`message || padding || appended_data`

не знаючи секрету.<sup>[[1]](#references)</sup>

### Важливе обмеження: HMAC не вразливий

Атаки length extension застосовуються до вразливих конструкцій із префіксом, як-от `HASH(secret || message)`. Вони не розкривають конструкцію HMAC (наприклад, HMAC-SHA256), яка поєднує ключ із окремими внутрішнім і зовнішнім обчисленнями хешу.<sup>[[1]](#references)[[2]](#references)</sup>

### Інструменти

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python-обгортки для інструмента length extension HashPump<sup>[[7]](#references)</sup>

### Гарне пояснення

[Усе, що потрібно знати про атаки length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Хешування паролів і cracking

### Перші запитання<sup>[[4]](#references)</sup>

- Чи використовується **сіль**? (шукайте формати `salt$hash`)
- Це **швидкий хеш** (MD5/SHA1/SHA256) чи **повільний KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Чи є **підказка щодо формату** (режим hashcat / формат John)?

### Практичний процес<sup>[[5]](#references)[[6]](#references)</sup>

1. Визначте хеш:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Якщо хеш без солі й поширений: перевірте онлайн-бази даних та інструменти ідентифікації з розділу про crypto workflow.
3. В інших випадках виконайте cracking:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Поширені помилки, які можна використати

- Той самий пароль використовується кількома користувачами → зламайте один і виконайте pivot.
- Обрізані хеші / власні перетворення → нормалізуйте й повторіть спробу.
- Слабкі параметри KDF (наприклад, мала кількість ітерацій PBKDF2) → пароль усе ще можна зламати.

### Oracle bcrypt із керованим вводом і дописаним секретом

Викличний helper, який повертає `bcrypt(user_input || secret)`, може розкрити інформацію про дописаний секрет, якщо його реалізація bcrypt непомітно обрізає ввід після 72 **байтів**. Обмеження кількості символів до кодування UTF-8 не забезпечує це обмеження в байтах: багатобайтові символи можуть заповнити ввід bcrypt, залишивши місце лише для невеликого префікса секрету. Тоді введені на вибір дані та відповідні хеші можуть дати змогу офлайн перевіряти байти-кандидати суфікса. Для цього потрібен контроль над вводом helper, знання точного перетворення та кодування, а також реалізація, яка справді обрізає дані; сам факт наявності викличного helper або хешу bcrypt не підтверджує весь цей ланцюжок. У документації [pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) зазначено, що поточний `hashpw` викликає помилку для вводів понад 72 байти, тоді як попередні версії непомітно їх обрізали. Інші обгортки можуть попередньо хешувати або відхиляти довгі вводи, тому перевірте встановлену реалізацію, а не припускайте, що обрізання відбувається.

Щоб використати відновлений секрет для іншого облікового запису, потрібні докази, що його оприлюднений хеш було згенеровано з **тим самим** секретом і перетворенням, а також окремий шлях отримання облікових даних або входу. Helper для хешування, що запускається від root, слід розглядати як oracle лише тоді, коли користувач із нижчими привілеями може його викликати відповідно до чинної політики; пасивне перерахування хоста не обов’язково передбачає його виклик або надсилання довільних паролів.

## References

- [1] [SkullSecurity — Усе, що потрібно знати про атаки length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 — Код автентифікації повідомлень на основі ключованого хешу](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [Пам’ятка OWASP щодо зберігання паролів](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Приклади хешів Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Параметри командного рядка John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: Python-обгортки `hashpumpy` для HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
