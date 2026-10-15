# Хеші, MAC і KDF

{{#include ../../banners/hacktricks-training.md}}

## Поширені шаблони CTF

- «Підпис» насправді є `hash(secret || message)` → розширення довжини.
- Несолоні хеші паролів → швидший перебір і атаки з попередньо обчисленими таблицями.
- Плутанина між хешем і MAC (хеш ≠ автентифікація).

## Пошук MD5-хешів із вибраним введенням

Ці приклади на Python шукають два різні шаблони результатів: заданий суфікс MD5 і значення MD5, що починається з `0e`, за яким ідуть лише цифри. Другий шаблон важливий, коли застосунок нестрого порівнює числові рядки; див. специфічну для PHP поведінку та застереження щодо версій у розділі [нестрогі порівняння в PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Перебір суфіксів MD5-хешу

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

### Генерація MD5-хешів 0e для нестрогих порівнянь

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

### Методика

Атака length-extension може бути можливою, коли сервер обчислює «підпис» на кшталт:

`sig = HASH(secret || message)`

і використовує хеш Merkle-Damgård, наприклад MD5, SHA-1 або SHA-256.

Якщо вам відомі:

- `message`
- `sig`
- хеш-функція
- (або ви можете перебрати) `len(secret)`

то ви можете обчислити дійсний підпис для:

`message || padding || appended_data`

не знаючи секрету.<sup>[[1]](#references)</sup>

### Важливе обмеження: HMAC не вразливий

Атаки length-extension застосовуються до вразливих конструкцій із префіксом, як-от `HASH(secret || message)`. Вони не розкривають конструкцію HMAC (наприклад, HMAC-SHA256), яка поєднує ключ із окремими внутрішнім і зовнішнім обчисленнями хешу.<sup>[[1]](#references)[[2]](#references)</sup>

### Інструменти

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python-прив’язки для інструмента length-extension HashPump<sup>[[7]](#references)</sup>

### Гарне пояснення

[Усе, що потрібно знати про атаки length-extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Хешування неоднозначних кортежів і MAC

### Boundary-confusion attack

Інкрементальні API хешування не автентифікують межі викликів. `update(A); update(B)` хешує той самий рядок байтів, що й `update(A + B)`. Тому хешування або обчислення MAC для необробленої конкатенації не автентифікує кортеж. Якщо сусідні поля мають змінну довжину, зловмисник може розділити байти по-іншому, отримавши інший кортеж, і для цього йому не потрібно знаходити колізію в базовій хеш-функції:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Це стає вразливим до експлуатації, коли верифікатор вважає, що дайджест фіксує значення полів, але контрольований атакувальником ввід може потрапити до іншого парсера або етапу протоколу, який визначає інші межі. У комітментів можуть з’явитися альтернативні відкриття, а транскрипти Fiat-Shamir можуть інтерпретуватися як інші твердження. HMAC запобігає [розширенню хешу за довжиною](#hash-length-extension-attack), але `HMAC(K, A || B)` усе одно має цю неоднозначність кодування кортежу, оскільки обидва кортежі породжують однакові байти повідомлення.<sup>[[8]](#references)[[9]](#references)</sup>

Використовуйте цей робочий процес аудиту, щоб перевірити, чи перетинає неоднозначне кодування кортежу межу безпеки.<sup>[[8]](#references)[[9]](#references)</sup>

1. Знайдіть `HASH(A || B)`, `HMAC(K, A || B)` і послідовні виклики `update()`/`Write()` для двох або більше полів.
2. Позначте всі поля, контрольовані атакувальником або змінної довжини. Спробуйте переміщати байти через кожну межу, не змінюючи повної конкатенації. Врахуйте порожні поля.
3. Перевірте схеми з роздільниками на наявність байтів роздільника, які можуть міститися у вхідних даних, розбіжностей в екрануванні та конструкцій, у яких довжина кодується лише для деяких полів.
4. Простежте, як кожен споживач розбирає автентифіковані байти. Альтернативне розбиття має значення лише тоді, коли воно змінює рішення безпеки, твердження доказу, запис, транзакцію або відкриття комітменту. Поля фіксованої ширини або канонічна ін’єктивна серіалізація запобігають саме цій атаці.
5. Перевірте, чи приймається той самий закодований дайджест в іншій версії протоколу, типі повідомлення, раунді або застосунку. Явно прив’язуйте ці контексти, а не покладайтеся на те, що виклики розділятимуть їх.

### SequenceHash і SequenceMAC

SequenceHash — це конструкція, незалежна від хеш-функції, для послідовностей байтових рядків. Кожна операція `add()` є атомарною: вона додає значення та суфікс фіксованої довжини 16 байтів у форматі little-endian до внутрішнього хешу. Порожні значення залишаються окремими об’єктами. Зовнішній хеш запобігає розкриттю внутрішнього стану, який можна розширити за довжиною, а необов’язковий рядок налаштування забезпечує розділення доменів. Не замінюйте `add()` звичайними викликами запису з API базової хеш-функції.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Вибирайте customizer як частину визначення протоколу, включивши достатньо інформації, щоб розрізнити застосунок, версію протоколу, тип повідомлення та раунд. SequenceHash усе ще вимагає, щоб усі сторони узгодили порядок полів, кодування байтів і канонічну серіалізацію, і не може захистити пропущене поле. Портовані реалізації слід перевіряти за проміжними й фінальними тестовими векторами C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Для автентифікації SequenceMAC забезпечує такий самий інтерфейс атомарного кодування й налаштування. Він вимагає ключ довжиною щонайменше 32 байти. На відміну від попередньої обробки ключа в HMAC, його заголовки фіксують точну довжину ключа: довгий необроблений ключ не еквівалентний його хешу, а додавання нульових байтів змінює ключ. Ця відмінність важлива, коли компоненти приймають різні представлення ключа або метадані про його довжину.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python API та еквівалентні реалізації на Go і Rust доступні як довідкові матеріали, але реалізації протоколу мають відповідати чинній специфікації C2SP, а не відтворювати кодування з цього резюме.<sup>[[8]](#references)[[10]](#references)</sup>

## Хешування паролів і злам

### Перші запитання<sup>[[4]](#references)</sup>

- Чи є хеш **salted**? (шукайте формати `salt$hash`)
- Це **fast hash** (MD5/SHA1/SHA256) чи **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Чи маєте ви **підказку щодо формату** (режим hashcat / формат John)?

### Практичний процес<sup>[[5]](#references)[[6]](#references)</sup>

1. Визначте хеш:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Якщо хеш unsalted і поширений: спробуйте онлайн-бази даних та інструменти визначення з розділу про криптографічний процес.
3. Інакше зламуйте:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Поширені помилки, якими можна скористатися

- Повторне використання одного пароля різними користувачами → зламайте один і зробіть pivot.
- Обрізані хеші / власні перетворення → нормалізуйте й спробуйте ще раз.
- Слабкі параметри KDF (наприклад, мала кількість ітерацій PBKDF2) → хеш усе ще можна зламати.

### bcrypt oracle із вибраним введенням і доданим секретом

Виклична допоміжна функція, що повертає `bcrypt(user_input || secret)`, може розкрити інформацію про доданий секрет, якщо її реалізація bcrypt непомітно обрізає введення після 72 **байтів**. Обмеження кількості символів до кодування UTF-8 не забезпечує дотримання цього байтового ліміту: багатобайтові символи можуть заповнити вхідні дані bcrypt, залишивши місце лише для невеликого префікса секрету. Тоді вибрані введення та повернуті хеші можуть дати змогу офлайн перевіряти байти-кандидати суфікса. Для цього потрібен контроль над введенням допоміжної функції, знання її точного перетворення й кодування, а також реалізація, яка справді обрізає дані; сама наявність викличної допоміжної функції або хешу bcrypt не підтверджує всю цю послідовність. У документації [pyca/bcrypt зазначено](https://github.com/pyca/bcrypt#maximum-password-length), що поточна версія `hashpw` викликає помилку для введень понад 72 байти, тоді як попередні версії непомітно їх обрізали. Інші обгортки можуть попередньо хешувати або відхиляти довгі введення, тому перевірте встановлену реалізацію, а не припускайте, що вона обрізає дані.

Використання відновленого секрету для іншого облікового запису також вимагає доказів, що його відкритий хеш було створено з **тим самим** секретом і перетворенням, а також окремого облікового запису чи шляху входу. Допоміжну функцію хешування, запущену від root, слід розглядати як oracle лише тоді, коли користувач із нижчими привілеями може її викликати відповідно до чинної політики; пасивне перерахування хоста не обов’язково має викликати її чи надсилати вибрані паролі.

## References

- [1] [SkullSecurity - Усе, що потрібно знати про атаки подовження хешу](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Код автентифікації повідомлень на основі ключового хешу](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Пам’ятка щодо зберігання паролів](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Приклади хешів hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Параметри командного рядка John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: прив’язки `hashpumpy` для Python до HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Специфікація SequenceHash і SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: мультихешування для всіх](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Реалізація SequenceHash на Python](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Тестові вектори SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
