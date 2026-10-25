# Хеші, MACs і KDFs

{{#include ../../banners/hacktricks-training.md}}

## Типові шаблони CTF

- «Підпис» насправді є `hash(secret || message)` → length extension.
- Несолоні хеші паролів → швидший повторний crack і атаки з пошуком у попередньо обчислених таблицях.
- Плутанина між хешем і MAC (hash != authentication).

## Пошук MD5-хешів із заданим вхідним значенням

Ці приклади на Python шукають два різні шаблони вихідних даних: заданий суфікс MD5 і значення MD5, що починається з `0e`, за яким ідуть лише цифри. Другий шаблон актуальний, коли застосунок нестрого порівнює числові рядки; див. поведінку та застереження щодо версій, специфічні для PHP, у [нестрогих порівняннях PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force суфікса хешу MD5

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### Генерація хешу MD5 0e для нестрогих порівнянь

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Hash length extension attack

### Technique

Атака з подовженням довжини може бути можливою, якщо сервер обчислює «підпис» на кшталт:

`sig = HASH(secret || message)`

і використовує hash Merkle–Damgård, наприклад MD5, SHA-1 або SHA-256.

Якщо вам відомі:

- `message`
- `sig`
- hash function
- (або ви можете brute-force) `len(secret)`

Тоді можна обчислити дійсний підпис для:

`message || padding || appended_data`

не знаючи secret.<sup>[[1]](#references)</sup>

### Важливе обмеження: HMAC не вразливий

Атаки з подовженням довжини застосовуються до вразливих конструкцій із префіксом, таких як `HASH(secret || message)`. Вони не розкривають конструкцію HMAC (наприклад, HMAC-SHA256), яка поєднує ключ з окремими внутрішнім і зовнішнім застосуваннями hash.<sup>[[1]](#references)[[2]](#references)</sup>

Щоб дізнатися, як знаходити й тестувати такі підписи у web API, див. [Request and parameter signatures](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures).

### Інструменти

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings для інструмента подовження довжини HashPump<sup>[[7]](#references)</sup>

### Гарне пояснення

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Неоднозначне хешування кортежів і MAC

### Атака зі змішуванням меж

Інкрементальні hash API не автентифікують межі викликів. `update(A); update(B)` хешує той самий рядок байтів, що й `update(A + B)`. Тому хешування або обчислення MAC для необробленої конкатенації не автентифікує кортеж. Якщо сусідні поля мають змінну довжину, зловмисник може перерозподілити байти в інший кортеж, не знаходячи колізії в underlying hash:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Це стає вразливим, коли верифікатор вважає, що дайджест фіксує значення полів, але контрольовані зловмисником дані можуть потрапити до іншого парсера або етапу протоколу, який визначає інші межі. У commitments можуть з’явитися альтернативні відкриття, а транскрипти Fiat-Shamir можуть інтерпретуватися як інші твердження. HMAC запобігає [hash length extension](#hash-length-extension-attack), але `HMAC(K, A || B)` усе ще має цю неоднозначність кодування кортежу, оскільки обидва кортежі дають однакові байти повідомлення.<sup>[[8]](#references)[[9]](#references)</sup>

Використовуйте цей порядок аудиту, щоб перевірити, чи перетинає неоднозначне кодування кортежу межу безпеки.<sup>[[8]](#references)[[9]](#references)</sup>

1. Знайдіть `HASH(A || B)`, `HMAC(K, A || B)` і послідовні виклики `update()`/`Write()` для двох або більше полів.
2. Позначте кожне поле, контрольоване зловмисником або змінної довжини. Спробуйте переміщати байти через кожну межу, зберігаючи незмінною повну конкатенацію. Врахуйте й порожні поля.
3. Перевірте схеми з роздільниками на наявність байтів роздільника, які можуть міститися у вхідних даних, розбіжностей в екрануванні та конструкцій, що кодують довжину лише деяких полів.
4. Простежте, як кожен споживач парсить автентифіковані байти. Альтернативне розбиття має значення лише тоді, коли воно змінює рішення щодо безпеки, твердження у доказі, запис, транзакцію або відкриття commitment. Поля фіксованої ширини або канонічна ін’єктивна серіалізація запобігають саме цій атаці.
5. Перевірте, чи приймається той самий закодований дайджест в іншій версії протоколу, типі повідомлення, раунді або застосунку. Явно прив’язуйте ці контексти, а не покладайтеся на те, що викликачі розділятимуть їх.

### SequenceHash і SequenceMAC

SequenceHash — це конструкція, не прив’язана до конкретної хеш-функції, для послідовностей байтових рядків. Кожна операція `add()` є атомарною: вона додає значення та суфікс довжини фіксованого розміру 16 байтів у little-endian до внутрішнього хешу. Порожні значення залишаються окремими об’єктами. Зовнішній хеш запобігає розкриттю внутрішнього стану, який можна продовжити за довжиною, а необов’язковий рядок налаштування забезпечує розділення доменів. Не замінюйте `add()` звичайними викликами запису API базової хеш-функції.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Вибирайте customizer як частину визначення протоколу та включайте достатньо інформації, щоб розрізняти застосунок, версію протоколу, тип повідомлення й раунд. SequenceHash усе ще вимагає, щоб усі сторони узгодили порядок полів, кодування байтів і канонічну серіалізацію, і не може захистити поле, яке було пропущено. Реалізації слід перевіряти за проміжними й фінальними тестовими векторами C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Для автентифікації SequenceMAC забезпечує той самий інтерфейс атомарного кодування та налаштування. Для нього потрібен ключ завдовжки щонайменше 32 байти. На відміну від попередньої обробки ключа в HMAC, його заголовки фіксують точну довжину ключа: довгий необроблений ключ не еквівалентний його хешу, а додавання нульових байтів змінює ключ. Ця відмінність важлива, коли компоненти приймають різні представлення ключа або метадані про його довжину.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python API та еквівалентні реалізації на Go і Rust доступні як довідкові матеріали, але реалізації протоколу мають відповідати актуальній специфікації C2SP, а не відтворювати кодування з цього огляду.<sup>[[8]](#references)[[10]](#references)</sup>

## Хешування паролів і злам

### Перші запитання<sup>[[4]](#references)</sup>

- Чи використовується **сіль**? (шукайте формати `salt$hash`)
- Це **швидкий хеш** (MD5/SHA1/SHA256) чи **повільна KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Чи маєте ви **підказку щодо формату** (режим hashcat / формат John)?

### Практичний процес<sup>[[5]](#references)[[6]](#references)</sup>

1. Визначте хеш:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Якщо хеш поширений і без солі: спробуйте онлайн-бази даних та засоби ідентифікації з розділу про криптографічний процес.
3. Інакше спробуйте зламати:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Поширені помилки, якими можна скористатися

- Той самий пароль повторно використовується різними користувачами → зламайте один і перейдіть до інших.
- Обрізані хеші / власні перетворення → нормалізуйте та спробуйте ще раз.
- Слабкі параметри KDF (наприклад, мала кількість ітерацій PBKDF2) → усе ще можна зламати.

### Оракул bcrypt з вибраним вводом і доданим секретом

Викличний допоміжний засіб, що повертає `bcrypt(user_input || secret)`, може розкрити інформацію про доданий секрет, якщо його реалізація bcrypt непомітно обрізає ввід після 72 **байтів**. Обмеження довжини за кількістю символів до кодування UTF-8 не забезпечує цього обмеження за байтами: багатобайтові символи можуть заповнити ввід bcrypt, залишивши місце лише для невеликого префікса секрету. Тоді вибрані вводи та повернуті хеші можуть дати змогу офлайн перевірити байти-кандидати суфікса. Для цього потрібен контроль над вводом допоміжного засобу, знання його точного перетворення та кодування, а також реалізація, яка справді обрізає ввід; сам факт наявності викличного допоміжного засобу або хешу bcrypt не підтверджує весь цей ланцюжок. У документації [pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) зазначено, що поточна функція `hashpw` видає помилку для вводів понад 72 байти, тоді як попередні версії непомітно їх обрізали. Інші обгортки можуть попередньо хешувати або відхиляти довгі вводи, тому перевіряйте встановлену реалізацію, а не припускайте, що вона обрізає ввід.

Використання відновленого секрету для іншого облікового запису також вимагає доказів, що розкритий хеш було згенеровано з **тим самим** секретом і перетворенням, а також окремого способу отримати облікові дані або ввійти в систему. Допоміжний засіб хешування, запущений від root, слід розглядати як оракул лише тоді, коли користувач із меншими привілеями може викликати його відповідно до чинних правил; пасивне дослідження вузла не зобов’язане викликати цей засіб або надсилати вибрані паролі.

## References

- [1] [SkullSecurity - усе, що потрібно знати про атаки розширення довжини хешу](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - код автентифікації повідомлень на основі ключованого хешу](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - пам’ятка з безпечного зберігання паролів](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Приклади хешів hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Параметри командного рядка John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: прив’язки Python для HashPump — `hashpumpy`](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - специфікація SequenceHash і SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: мультихешування для всіх](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - реалізація SequenceHash на Python](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - тестові вектори SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
