# Інструменти реверс-інжинірингу та базові методи

{{#include ../../banners/hacktricks-training.md}}

## Інструменти реверс-інжинірингу на основі ImGui

Програмне забезпечення:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Налагодження ядра Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Декомпілятор Wasm / компілятор Wat

Онлайн:

- Використовуйте [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), щоб **декомпілювати** wasm (бінарний формат) у wat (звичайний текст)
- Використовуйте [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), щоб **компілювати** wat у wasm
- Для декомпіляції також можна спробувати [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Програмне забезпечення:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Кешований байткод Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Декомпілятор .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek — це декомпілятор, який **декомпілює та аналізує різні формати**, зокрема **бібліотеки** (.dll), **файли метаданих Windows** (.winmd) і **виконувані файли** (.exe). Після декомпіляції збірку можна зберегти як проєкт Visual Studio (.csproj).

Перевага цього інструмента полягає в тому, що він заощаджує час, коли потрібно відновити втрачений вихідний код зі старої збірки. Крім того, dotPeek забезпечує зручну навігацію декомпільованим кодом, що робить його одним із найкращих інструментів для **аналізу алгоритмів Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Завдяки розширеній моделі надбудов і API, що дає змогу налаштувати інструмент відповідно до ваших потреб, .NET Reflector заощаджує час і спрощує розробку. Розгляньмо широкий спектр можливостей зворотного інжинірингу, які надає цей інструмент:

- Дає змогу побачити, як дані проходять через бібліотеку або компонент
- Допомагає зрозуміти реалізацію та використання мов і фреймворків .NET
- Виявляє недокументовані та приховані функції, щоб ви могли більше використовувати API та задіяні технології
- Знаходить залежності та різні збірки
- Допомагає визначити точне місце помилок у вашому коді, сторонніх компонентах і бібліотеках
- Дає змогу налагоджувати вихідний код усього коду .NET, з яким ви працюєте

### [ILSpy](https://github.com/icsharpcode/ILSpy) та [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Плагін ILSpy для Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): його можна використовувати в будь-якій ОС (можна встановити безпосередньо з VSCode, завантажувати git не потрібно. Натисніть **Розширення** та **пошукайте ILSpy**).\
Якщо потрібно **декомпілювати**, **змінити** й знову **скомпілювати**, можна скористатися [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) або його активно підтримуваним форком [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Клацніть правою кнопкою миші -> Змінити метод**, щоб щось змінити всередині функції).

### Логування DNSpy

Щоб **DNSpy записував певну інформацію у файл**, можна скористатися таким фрагментом:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Налагодження в DNSpy

Щоб налагоджувати код за допомогою DNSpy, потрібно:

Спочатку змініть атрибути **Assembly**, пов’язані з **налагодженням**:

![Журналювання в DNSpy — налагодження в DNSpy: спочатку змініть атрибути Assembly, пов’язані з налагодженням](<../../images/image (973).png>)

З:

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

До:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

І натисніть **compile**:

![DNSpy Logging - DNSpy Debugging: І натисніть compile](<../../images/image (314) (1).png>)

Потім збережіть новий файл через _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Потім збережіть новий файл через File Save module](<../../images/image (602).png>)

Це необхідно, адже інакше під час **виконання** до коду буде застосовано кілька **оптимізацій**, і в результаті під час налагодження **точка зупинки може не спрацювати** або **деякі змінні можуть бути відсутні**.

Якщо вашу програму .NET **запускає** **IIS**, її можна **перезапустити** так:

```
iisreset /noforce
```

Потім, щоб почати налагодження, закрийте всі відкриті файли та на вкладці **Debug** виберіть **Attach to Process...**:

![DNSpy Logging - Налагодження в DNSpy: щоб почати налагодження, закрийте всі відкриті файли та на вкладці Debug виберіть Attach to Process](<../../images/image (318).png>)

Потім виберіть **w3wp.exe**, щоб під’єднатися до **IIS server**, і натисніть **attach**:

![DNSpy Logging - Налагодження в DNSpy: виберіть w3wp.exe, щоб під’єднатися до IIS server, і натисніть attach](<../../images/image (113).png>)

Тепер, коли ми налагоджуємо процес, потрібно зупинити його й завантажити всі модулі. Спершу натисніть _Debug >> Break All_, а потім _**Debug >> Windows >> Modules**_:

![DNSpy Logging - Налагодження в DNSpy: тепер, коли ми налагоджуємо процес, потрібно зупинити його й завантажити всі модулі. Спершу натисніть Debug Break All, а потім Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - Налагодження в DNSpy: тепер, коли ми налагоджуємо процес, потрібно зупинити його й завантажити всі модулі. Спершу натисніть Debug Break All, а потім Debug Windows Modules](<../../images/image (834).png>)

Клацніть будь-який модуль у **Modules** і виберіть **Open All Modules**:

![DNSpy Logging - Налагодження в DNSpy: клацніть будь-який модуль у Modules і виберіть Open All Modules](<../../images/image (922).png>)

Клацніть правою кнопкою миші будь-який модуль в **Assembly Explorer** і виберіть **Sort Assemblies**:

![DNSpy Logging - Налагодження в DNSpy: клацніть правою кнопкою миші будь-який модуль в Assembly Explorer і виберіть Sort Assemblies](<../../images/image (339).png>)

## Java-декомпілятор

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Налагодження DLL

### Using IDA

- **Завантажте rundll32** (64-бітна версія розташована в C:\Windows\System32\rundll32.exe, а 32-бітна — в C:\Windows\SysWOW64\rundll32.exe)
- Виберіть debugger **Windbg**
- Виберіть "**Suspend on library load/unload**"

![Налагодження DLL - Using IDA: виберіть " Suspend on library load/unload "](<../../images/image (868).png>)

- Налаштуйте **параметри** запуску, вказавши **шлях до DLL** і функцію, яку потрібно викликати:

![Налагодження DLL - Using IDA: налаштуйте параметри запуску, вказавши шлях до DLL і функцію, яку потрібно викликати](<../../images/image (704).png>)

Після початку налагодження **виконання зупинятиметься під час завантаження кожної DLL**. Тож коли rundll32 завантажить вашу DLL, виконання зупиниться.

Цей метод зупиняє виконання на подіях завантаження модулів, але перехід до точки входу завантаженої DLL менш прямолінійний, ніж у наведеному нижче сценарії з x64dbg.

### Using x64dbg/x32dbg

- **Завантажте rundll32** (64-бітна версія розташована в C:\Windows\System32\rundll32.exe, а 32-бітна — в C:\Windows\SysWOW64\rundll32.exe)
- **Змініть командний рядок** ( _File --> Change Command Line_ ) і вкажіть шлях до DLL та функцію, яку потрібно викликати. Наприклад: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Змініть _Options --> Settings_ і виберіть "**DLL Entry**".
- Потім **запустіть виконання**. Debugger зупинятиметься на кожній dll main, і в певний момент ви **зупинитеся на точці входу вашої DLL**. Звідти знайдіть місця, де потрібно встановити breakpoint.

Зверніть увагу: коли виконання з будь-якої причини зупинене у win64dbg, **у верхній частині вікна win64dbg** можна побачити, **у якому коді ви перебуваєте**:

![Using IDA - Using x64dbg/x32dbg: зверніть увагу, що коли виконання з будь-якої причини зупинене у win64dbg, у верхній частині вікна win64dbg можна побачити, у якому коді ви перебуваєте](<../../images/image (842).png>)

Цей індикатор підтверджує, що виконання зупинилося всередині DLL, яку потрібно налагодити.

## GUI-застосунки / відеоігри

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) — корисна програма для пошуку важливих значень у пам’яті запущеної гри та їх зміни. Більше інформації:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) — front-end/reverse engineering tool для GNU Project Debugger (GDB), орієнтований на ігри. Однак його можна використовувати для будь-яких завдань, пов’язаних із reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) — web front-end для кількох декомпіляторів. Цей вебсервіс дає змогу порівнювати результати роботи різних декомпіляторів на невеликих виконуваних файлах.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Налагодження shellcode за допомогою blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) виділяє пам’ять для **shellcode**, виводить її **адресу** й призупиняє виконання.\
Під’єднайте debugger, наприклад IDA або x64dbg, встановіть breakpoint за виведеною адресою та відновіть виконання, щоб налагодити shellcode.

На сторінці релізів github є zip-архіви зі скомпільованими релізами: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Трохи змінену версію Blobrunner можна знайти за посиланням нижче. Щоб скомпілювати її, **створіть проєкт C/C++ у Visual Studio Code, скопіюйте та вставте код і зберіть його**.


{{#ref}}
blobrunner.md
{{#endref}}

### Налагодження shellcode за допомогою jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) працює подібно до BlobRunner. Він виділяє пам’ять для shellcode і входить у нескінченний цикл. Під’єднайте debugger, відновіть виконання на **2–5 секунд**, призупиніть його всередині цього циклу та перейдіть до наступного виклику, який передає виконання виділеному shellcode.

![Debugger призупинений у нескінченному циклі jmp2it безпосередньо перед викликом виділеного shellcode](<../../images/image (509).png>)

Скомпільовану версію [jmp2it можна завантажити зі сторінки релізів](https://github.com/adamkramer/jmp2it/releases/).

### Налагодження shellcode за допомогою Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) — це GUI для radare. Cutter дає змогу емулювати shellcode та досліджувати його під час виконання.

Зверніть увагу, що Cutter дає змогу вибрати «Open File» або «Open Shellcode». У моєму випадку, коли я відкрив shellcode як файл, він декомпілювався правильно, а коли відкрив його як shellcode — ні:

![Cutter показує різні результати аналізу тих самих байтів, відкритих як файл або як shellcode](<../../images/image (562).png>)

Щоб почати емуляцію в потрібному місці, встановіть там bp — схоже, Cutter автоматично почне емуляцію звідти:

![Встановлення breakpoint у потрібній точці входу shellcode перед запуском емуляції в Cutter](<../../images/image (589).png>)

![Емулятор Cutter призупинений на вибраному breakpoint у shellcode](<../../images/image (387).png>)

Наприклад, стек можна переглянути у hex dump:

![Перегляд стека емульованого shellcode у hex dump Cutter](<../../images/image (186).png>)

### Деобфускація shellcode та отримання списку викликаних функцій

Спробуйте [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Він показує, наприклад, **які функції** використовує shellcode і чи **декодує** він себе в пам’яті.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg також має графічний лаунчер, де можна вибрати потрібні параметри й запустити shellcode

![scDbg graphical launcher for selecting shellcode emulation and tracing options](<../../images/image (258).png>)

Параметр **Create Dump** збереже фінальний shellcode, якщо під час виконання він динамічно змінювався в пам’яті (корисно, щоб завантажити декодований shellcode). **start offset** може стати в пригоді, щоб запустити shellcode з певного зміщення. Параметр **Debug Shell** дає змогу налагоджувати shellcode через термінал scDbg (однак, на мою думку, для цього краще підходить будь-який із описаних раніше варіантів, оскільки можна використовувати IDA або x64dbg).

### Дизасемблювання за допомогою CyberChef

Завантажте файл shellcode як вхідні дані й скористайтеся таким рецептом, щоб дизасемблювати його: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Деобфускація MBA-обфускації

Обфускація **Mixed Boolean-Arithmetic (MBA)** приховує прості вирази на кшталт `x + y` за формулами, що поєднують арифметичні (`+`, `-`, `*`) і побітові оператори (`&`, `|`, `^`, `~`, зсуви). Важливо, що ці тотожності зазвичай правильні лише за **модульної арифметики з фіксованою розрядністю**, тому переноси й переповнення мають значення:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Якщо спростити цей тип виразу за допомогою універсальних засобів алгебраїчних перетворень, легко отримати неправильний результат, оскільки семантику розрядності було проігноровано.<sup>[[1]](#references)</sup>

### Практичний робочий процес

1. **Збережіть початкову розрядність** lifted-коду/IR/виводу decompiler (`8/16/32/64` бітів).
2. **Класифікуйте вираз** перед спробою його спростити:
   - **Лінійний**: зважені суми побітових атомів
   - **Напівлінійний**: лінійний вираз із константними масками, наприклад `x & 0xFF`
   - **Поліноміальний**: містить добутки
   - **Змішаний**: добутки й побітова логіка переплетені, часто з повторюваними підвиразами
3. **Перевірте кожне запропоноване перетворення** за допомогою випадкового тестування або SMT-доведення. Якщо еквівалентність неможливо довести, залиште початковий вираз замість того, щоб вгадувати.

### Обійдіть сплощений потік керування за допомогою вузького зрізу виконання

Відновлювати повний граф потоку керування часто не потрібно. За наявності сплощення потоку керування, непрозорих предикатів, великих диспетчерів або коду з великою кількістю MBA-прийомів відстежуйте посилання від зашифрованих блоків даних і вихідних буферів до найменшої процедури, що їх перетворює. Потім відтворіть лише цей зріз потоку даних або виконайте його окремо; диспетчер не є частиною необхідного рішення, якщо відповідний стан можна ініціалізувати безпосередньо.<sup>[[7]](#references)</sup>

Практичний робочий процес:<sup>[[7]](#references)</sup>

1. Складіть перелік виконуваних і інформаційних секцій, релокацій і перехресних посилань. Вивантажте можливі таблиці з `.rodata`, зберігши порядок байтів і ширину елементів.
2. Знайдіть останню процедуру, яка записує відкритий текст або вихідний буфер. Зафіксуйте її входи, таблиці, на які вона посилається, імпортовані виклики та потрібний глобальний стан.
3. Перенесіть лише ці операції у модель Python із фіксованою розрядністю. Якщо зріз усе ще залежить від надто великої кількості стану, викличте процедуру в Unicorn, QEMU або debugger і перехопіть непотрібні імпорти замість емуляції всієї програми.
4. Переконайтеся, що extractor справді отримує результат із переданого бінарного файла: приберіть приховані запасні варіанти, перевірте його на наявність вбудованих відповідей і запустіть на невідомих раніше збірках зі зміненими рядками, ключами, ідентифікаторами, структурами та seed-значеннями обфускації.

Корисні команди для першого аналізу:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Виявлення MBA-виразів, замаскованих під константи

Вираз для байта, який на перший погляд залежить від вхідних даних, може повністю їх нівелювати. Після вилучення таблиць обчисліть вираз для всіх можливих 8-бітних значень; якщо множина результатів містить лише одне значення, це доводить, що байт є константою, і відновлювати решту скінченного автомата не потрібно.<sup>[[7]](#references)</sup>

```python
def mba(a, b, c, d, e, x):
    return ((((a | (~x & 0xff)) & c) +
             ((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
    outputs = {mba(*row, x) for x in range(256)}
    if len(outputs) != 1:
        raise ValueError("expression depends on x")
    decoded.append(outputs.pop())
print(decoded)
```

Залиште фінальну маску, оскільки початкове додавання має циклічне переповнення за розрядністю байта. Для ширшої області значень запитайте SMT solver, чи є формула `f(x1) != f(x2)` для двох символьних входів однакової розрядності задовільною: `unsat` доводить інваріантність, а `sat` надає контрприклад і означає, що вхід не можна відкинути.<sup>[[7]](#references)</sup>

#### Розпізнавання декодування, прив’язаного до середовища

Перевірки на протидію аналізу не обов’язково спричиняють перехід або аварійне завершення. Декодер може домішати результат датчика до біта ключа, константи opaque predicate або стану flattened dispatcher, продовжити нормальну роботу й видати правдоподібний, але хибний відкритий текст в емуляторі. Тому недостатньо пропатчити лише видимі гілки помилок; відстежуйте залежності даних від перевірок середовища до стану декодера, порівнюйте той самий зріз на справжньому пристрої та в емуляторі й перевіряйте, як примусове встановлення результату кожного датчика змінює кінцевий буфер.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) — це практичний спрощувач MBA для аналізу malware і реверсингу захищених бінарних файлів. Він класифікує вираз і спрямовує його через спеціалізовані конвеєри замість того, щоб застосовувати один загальний прохід переписування до всього.<sup>[[2]](#references)</sup>

Швидкий приклад використання:

```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```

Корисні випадки:

- **Linear MBA**: CoBRA обчислює вираз на булевих входах, виводить сигнатуру та паралельно запускає кілька методів відновлення, як-от зіставлення зі зразком, перетворення ANF і інтерполяція коефіцієнтів.
- **Semilinear MBA**: атоми з константною маскою відновлюються за допомогою реконструкції з розбиттям на біти, щоб масковані ділянки залишалися коректними.
- **Polynomial/Mixed MBA**: добутки розкладаються на ядра, а повторювані підвирази можна винести в тимчасові змінні перед спрощенням зовнішнього співвідношення.

Приклад змішаної тотожності, яку часто варто спробувати відновити:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Це можна звести до:

```c
x * y
```

### Нотатки з реверсингу

- Краще запускати CoBRA на **піднятих виразах IR** або результатах роботи декомпілятора після того, як виокремили точне обчислення.
- Явно задавайте `--bitwidth`, якщо вираз отримано з арифметики з масками або вузьких регістрів.
- Якщо потрібен надійніший крок доведення, перегляньте локальні нотатки про Z3 тут:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA також постачається як **плагін-прохід LLVM** (`libCobraPass.so`), що корисно, коли потрібно нормалізувати LLVM IR із великою кількістю MBA перед подальшими проходами аналізу.
- Непідтримувані залишкові вирази зі змішаними доменами, чутливі до перенесення, слід розглядати як сигнал зберегти початковий вираз і вручну проаналізувати шлях перенесення.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Цей обфускатор замінює операції програми послідовностями інструкцій на основі `mov` і використовує обробку сигналів/винятків для зміни потоку керування. Докладніше:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Для підтримуваних бінарних файлів [demovfuscator](https://github.com/kirschju/demovfuscator) може деобфускувати результат. Він має кілька залежностей.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

І [встановіть keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Якщо ви граєте в **CTF, цей обхідний спосіб пошуку прапорця** може бути дуже корисним: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Щоб знайти **точку входу**, знайдіть функції за `::main`, як у прикладі:

![Пошук точки входу Rust у Ghidra за іменами функцій із подвійною двокрапкою перед main](<../../images/image (1080).png>)

У цьому випадку бінарний файл називався authenticator, тож досить очевидно, що саме ця функція main є цікавою.\
Знайдіть **назви** викликаних **функцій** в **Інтернеті**, щоб дізнатися про їхні **входи** та **виходи**.

### Відновлення рядків Rust із прошивки ELF

У бінарних файлах **Rust ELF** на багато статичних рядків не посилаються як на вказівники з завершальним NUL-символом у стилі C. Поширене компонування `rustc` — це **кортеж pointer/length** у **`.data.rel.ro`**, який вказує на справжній блок рядків у **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Це означає, що `strings` або аналіз Ghidra за замовчуванням можуть об’єднувати сусідні рядки або взагалі не виявляти перехресні посилання.<sup>[[3]](#references)</sup>

Швидкий робочий процес:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Отримайте віртуальну адресу та розмір **`.rodata`**.
2. Переберіть **`.data.rel.ro`** по одному слову за раз.
3. Розглядайте будь-яке значення в межах адресного діапазону `.rodata` як кандидат на вказівник на рядок.
4. Розглядайте наступне слово як кандидат на довжину.
5. Застосуйте фільтри перевірки достовірності (наприклад, залиште довжини від **4** до **100** байтів).
6. Прочитайте з `.rodata` рівно `length` байтів, замість того щоб сканувати до `0x00`.

Мінімальна логіка екстрактора:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Це особливо корисно під час реверсу firmware, оскільки відновлені рядки Rust часто розкривають **HTTP-маршрути, назви RPC, повідомлення журналу, перевірки, імена файлів, ключі конфігурації, обробники команд і логіку, пов’язану з автентифікацією**.

Якщо Ghidra не знаходить ці рядки, запустіть власний скрипт/плагін, який застосовує ту саму евристику та створює дані рядків за адресами відповідних зміщень у `.rodata`. Опубліковані інструменти `rust-strings` і `RustStrings.py` від Pen Test Partners — хороші приклади для адаптації цієї ідеї до інших **розмірів слова, порядку байтів і структури секцій**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Для скомпільованих бінарних файлів Delphi можна використовувати [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Якщо потрібно виконати реверс бінарного файлу Delphi, раджу скористатися плагіном IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Натисніть **Alt+F7** в IDA, щоб завантажити плагін Python, а потім виберіть файл плагіна.

Цей плагін запускає бінарний файл і динамічно визначає назви функцій на початку налагодження. Після початку налагодження знову натисніть кнопку Start (зелену або f9), і на початку справжнього коду спрацює breakpoint.

Якщо натиснути кнопку в графічному застосунку, налагоджувач може зупинитися у функції, викликаній цією кнопкою.

## Golang

Для звичайних бінарних файлів Go інструмент [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) може відновити структури runtime та покращити назви функцій в IDA. Завантажте його плагін Python за допомогою **Alt+F7**.

### Відновлення метаданих без таблиці символів

Навіть stripped-виконуваному файлу Go потрібні метадані runtime, щоб зіставляти лічильники команд із функціями. [GoReSym](https://github.com/mandiant/GoReSym) знаходить і розбирає такі структури, як `pclntab` і `moduledata`, використовуючи код, похідний від Go runtime. Це дає змогу відновити межі функцій, їхні назви, шляхи до вихідних файлів, типи й відомості про збірку без опори на звичайну таблицю символів.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Обфускатор може залишити ці структури придатними до використання, замінивши відновлені назви. Наприклад, Garble хешує ідентифікатори та шляхи пакетів і видаляє інформацію про збірку, модулі й налагодження.<sup>[[12]](#references)</sup> Токен обфускованого пакета має залишатися однаковим для всіх функцій цього пакета. Згрупуйте функції за повторюваним токеном, визначте пакет за його callees, рядками та API, а потім призначте цю мітку всій групі.<sup>[[13]](#references)</sup>

### Відновлення назв Garble за допомогою GoResolver

[GoResolver](https://github.com/volexity/GoResolver) поєднує вилучення символів runtime із генерацією чистих еталонів і зіставленням графів потоку керування (CFG). Виконайте такі кроки:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Визначте версію компілятора.** Спочатку перевірте `BuildInfo` та вбудовані рядки версії. Якщо обфускатор їх видалив, порівняйте частини вбудованого runtime Go з еталонними runtime різних версій. У тестах Volexity приблизно `2%` runtime було достатньо, щоб розрізнити основні версії Go. Вважайте це емпіричною оптимізацією, а не універсальним порогом.<sup>[[13]](#references)</sup>
2. **Створіть відповідні еталони.** Згенеруйте чисті бінарні файли для визначеної версії Go, цільової архітектури та ймовірних бібліотек. Відповідність набору інструментів зменшує відмінності CFG, створені компілятором.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Порівняйте функції.** GoGrapher зіставляє CFG функцій і формує нормалізовані оцінки від `0.0` до `1.0`. Зіставлення базових блоків ґрунтується на зваженому порівнянні подібних інструкцій. Збіги з високою впевненістю зіставляють рандомізовані функції з чистою реалізацією. Менш упевнені збіги все одно можуть визначити пакет або модуль.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Перевірте та імпортуйте результати.** Підтвердьте запропоновані назви за зв’язками викликів, константами, рядками та побічними ефектами, а потім імпортуйте JSON-звіт за допомогою плагіна GoResolver для IDA або Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Установіть набір інструментів і запустіть комбінований екстрактор та зіставлювач графів:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

Порогове значення значущої відповідності за замовчуванням — `0.9`. Параметри `--extract` і `--graph` дають змогу ізолювати будь-який з етапів, а за замовчуванням запускаються обидва, оскільки відновлені метадані runtime та дані CFG доповнюють одне одного.<sup>[[10]](#references)</sup> Оцінки CFG евристичні: inlining, прапорці збірки, архітектура та відмінності між версіями бібліотек можуть змінити структуру графа, тому зберігайте нерозпізнані функції, а не призначайте їм назви з низькою впевненістю.<sup>[[13]](#references)</sup>

## Скомпільований Python

На цій сторінці ви знайдете інструкції, як отримати код Python із бінарного файлу ELF/EXE, скомпільованого з Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Якщо ви отримали **бінарний файл** гри для GBA, можна скористатися різними інструментами для її **емуляції** та **налагодження**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Завантажте debug-версію_) - Містить debugger з інтерфейсом
- [**mgba** ](https://mgba.io)- Містить CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Плагін Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Плагін Ghidra

У [**no$gba**](https://problemkaputt.de/gba.htm), у розділі _**Options --> Emulation Setup --> Controls**_** ** можна побачити, як натискати **кнопки** Game Boy Advance

![конфігурація керування no$gba з відповідністю кнопок Game Boy Advance](<../../images/image (581).png>)

Після натискання кожна **клавіша має значення**, за яким її можна ідентифікувати:

```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```

Отже, у програмі такого типу цікаво буде те, **як програма обробляє введені користувачем дані**. За адресою **0x4000130** ви знайдете поширену функцію: **KEYINPUT**.

![Вікно Ghidra з посиланням на KEYINPUT за адресою 0x4000130 у бінарному файлі GBA](<../../images/image (447).png>)

На попередньому зображенні видно, що функцію викликає **FUN_080015a8** (адреси: _0x080015fa_ і _0x080017ac_).

У цій функції після кількох операцій ініціалізації (які не мають значення):

```c
void FUN_080015a8(void)

{
  ushort uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  ushort uVar4;
  int iVar5;
  ushort *puVar6;
  undefined *local_2c;

  DISPCNT = 0x1140;
  FUN_08000a74();
  FUN_08000ce4(1);
  DISPCNT = 0x404;
  FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
  FUN_08000354(&DAT_030000dc,0x3c);
  uVar4 = DAT_030004d8;
```

Знайдено такий код:

```c
  do {
    DAT_030004da = uVar4; //This is the last key pressed
    DAT_030004d8 = KEYINPUT | 0xfc00;
    puVar6 = &DAT_0200b03c;
    uVar4 = DAT_030004d8;
    do {
      uVar2 = DAT_030004dc;
      uVar1 = *puVar6;
      if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```

Останній if перевіряє, чи **`uVar4`** є серед **last Keys** і не є поточною клавішею; це також називають відпусканням кнопки (поточна клавіша зберігається в **`uVar1`**).

```c
        if (uVar1 == 4) {
          DAT_030000d4 = 0;
          uVar3 = FUN_08001c24(DAT_030004dc);
          FUN_08001868(uVar2,0,uVar3);
          DAT_05000000 = 0x1483;
          FUN_08001844(&DAT_0200ba18);
          FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
          DAT_030000d8 = 0;
          uVar4 = DAT_030004d8;
        }
        else {
          if (uVar1 == 8) {
            if (DAT_030000d8 == 0xf3) {
              DISPCNT = 0x404;
              FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
              FUN_08000354(&DAT_030000dc,0x3c);
              uVar4 = DAT_030004d8;
            }
          }
          else {
            if (DAT_030000d4 < 8) {
              DAT_030000d4 = DAT_030000d4 + 1;
              FUN_08000864();
              if (uVar1 == 0x10) {
                DAT_030000d8 = DAT_030000d8 + 0x3a;
```

У попередньому коді видно, що ми порівнюємо **uVar1** (місце, де зберігається **значення натиснутої кнопки**) з деякими значеннями:

- Спочатку його порівнюють зі **значенням 4** (кнопка **SELECT**): у цьому завданні ця кнопка очищає екран.
- Потім значення порівнюють із **8** (кнопка **START**); у цьому завданні ця гілка перевіряє, чи введений код правильний.
  - У цьому випадку змінну **`DAT_030000d8`** порівнюють із 0xf3, і якщо значення збігається, виконується певний код.
- В усіх інших випадках перевіряють і збільшують лічильник (`DAT_030000d4`).\
  Поки лічильник менший за 8, значення натиснутих клавіш додаються до `DAT_030000d8`.

Отже, у цьому завданні, знаючи значення кнопок, потрібно було **натиснути комбінацію довжиною меншою за 8, сума значень якої дорівнює 0xf3.**

**Посилання на цей посібник:** [архівований розбір завдання Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Курси

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Деобфускація бінарних файлів)

## References

- [1] [Спрощення MBA-обфускації за допомогою CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Репозиторій Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Декодування рядків Rust — Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering — рядки Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering — RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia — посібник із реверсингу GBA (архівований)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Як подолати реверсинг за допомогою ШІ — або принаймні спробувати](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Підхід до порівняння графів потоку керування на основі зіставлення базових блоків](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Механізм обфускації Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: використання подібності графів потоку керування для автоматичної деобфускації бінарних файлів Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
