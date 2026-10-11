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
- Для декомпіляції можна також спробувати [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Програмне забезпечення:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Кешований байткод Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Декомпілятор .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek — це декомпілятор, який **декомпілює та аналізує різні формати**, зокрема **бібліотеки** (.dll), **файли метаданих Windows** (.winmd) та **виконувані файли** (.exe). Після декомпіляції збірку можна зберегти як проєкт Visual Studio (.csproj).

Цей інструмент стане в пригоді, якщо потрібно відновити втрачений вихідний код із застарілої збірки: це допоможе заощадити час. Крім того, dotPeek забезпечує зручну навігацію декомпільованим кодом, що робить його одним із найкращих інструментів для **аналізу алгоритмів Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Завдяки комплексній моделі надбудов та API, що дає змогу налаштувати інструмент під ваші потреби, .NET Reflector заощаджує час і спрощує розробку. Розгляньмо численні можливості зворотного інжинірингу, які надає цей інструмент:

- Дає змогу зрозуміти, як дані проходять через бібліотеку або компонент
- Допомагає зрозуміти реалізацію та використання мов і фреймворків .NET
- Допомагає знаходити недокументовані та приховані можливості, щоб ефективніше використовувати API та застосовані технології.
- Допомагає знаходити залежності та різні збірки
- Допомагає точно визначати місце помилок у вашому коді, сторонніх компонентах і бібліотеках.
- Дає змогу налагоджувати вихідний код усього коду .NET, з яким ви працюєте.

### [ILSpy](https://github.com/icsharpcode/ILSpy) та [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Плагін ILSpy для Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): його можна використовувати в будь-якій ОС (його можна встановити безпосередньо з VSCode, завантажувати git не потрібно. Натисніть **Extensions** і **знайдіть ILSpy**).\
Якщо потрібно **декомпілювати**, **змінити** та знову **скомпілювати**, можна скористатися [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) або його форком, який активно підтримується, — [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Клацніть правою кнопкою миші -> Modify Method**, щоб змінити щось усередині функції).

### Логування DNSpy

Щоб **DNSpy записував певну інформацію у файл**, можна скористатися цим фрагментом:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Налагодження DNSpy

Щоб налагоджувати код за допомогою DNSpy, потрібно:

Спочатку змінити **атрибути збірки**, пов’язані з **налагодженням**:

![Журналювання DNSpy — налагодження DNSpy: спочатку змініть атрибути збірки, пов’язані з налагодженням](<../../images/image (973).png>)

З:

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

Кому:

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

Це необхідно, оскільки без цього під час **виконання** до коду буде застосовано кілька **оптимізацій**, і під час налагодження може статися, що **точка зупинки не спрацює** або деякі **змінні будуть відсутні**.

Якщо вашу програму .NET **запускає** **IIS**, її можна **перезапустити** так:

```
iisreset /noforce
```

Потім, щоб розпочати debugging, закрийте всі відкриті файли й у вкладці **Debug** виберіть **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Потім, щоб розпочати debugging, закрийте всі відкриті файли й у вкладці Debug виберіть Attach to Process](<../../images/image (318).png>)

Потім виберіть **w3wp.exe**, щоб приєднатися до **IIS server**, і натисніть **attach**:

![DNSpy Logging - DNSpy Debugging: Потім виберіть w3wp.exe, щоб приєднатися до IIS server, і натисніть attach](<../../images/image (113).png>)

Тепер, коли ми налагоджуємо процес, час зупинити його й завантажити всі модулі. Спочатку натисніть _Debug >> Break All_, а потім _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Тепер, коли ми налагоджуємо процес, час зупинити його й завантажити всі модулі. Спочатку натисніть Debug Break All, а потім Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Тепер, коли ми налагоджуємо процес, час зупинити його й завантажити всі модулі. Спочатку натисніть Debug Break All, а потім Debug Windows Modules](<../../images/image (834).png>)

Натисніть будь-який модуль у **Modules** і виберіть **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Натисніть будь-який модуль у Modules і виберіть Open All Modules](<../../images/image (922).png>)

Клацніть правою кнопкою миші будь-який модуль в **Assembly Explorer** і натисніть **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Клацніть правою кнопкою миші будь-який модуль в Assembly Explorer і натисніть Sort Assemblies](<../../images/image (339).png>)

## Декомпілятор Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Налагодження DLL

### За допомогою IDA

- **Завантажте rundll32** (64-бітну версію знайдете в C:\Windows\System32\rundll32.exe, а 32-бітну — в C:\Windows\SysWOW64\rundll32.exe)
- Виберіть debugger **Windbg**
- Виберіть "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Виберіть " Suspend on library load/unload "](<../../images/image (868).png>)

- Налаштуйте **параметри** виконання, указавши **шлях до DLL** і функцію, яку потрібно викликати:

![Debugging DLLs - Using IDA: Налаштуйте параметри виконання, указавши шлях до DLL і функцію, яку потрібно викликати](<../../images/image (704).png>)

Після початку debugging **виконання зупинятиметься під час завантаження кожної DLL**. Отже, коли rundll32 завантажить вашу DLL, виконання зупиниться.

Цей метод зупиняє виконання на подіях завантаження модуля, але дістатися до точки входу завантаженої DLL менш зручно, ніж за допомогою наведеного нижче підходу з x64dbg.

### За допомогою x64dbg/x32dbg

- **Завантажте rundll32** (64-бітну версію знайдете в C:\Windows\System32\rundll32.exe, а 32-бітну — в C:\Windows\SysWOW64\rundll32.exe)
- **Змініть командний рядок** ( _File --> Change Command Line_ ) і вкажіть шлях до DLL та функцію, яку потрібно викликати, наприклад: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Змініть _Options --> Settings_ і виберіть "**DLL Entry**".
- Потім **запустіть виконання**. Debugger зупинятиметься на кожній точці dll main, і зрештою ви **зупинитеся на точці входу вашої DLL**. Звідти просто знайдіть місця, де потрібно встановити breakpoint.

Зауважте: коли виконання зупиняється з будь-якої причини у win64dbg, **у верхній частині вікна win64dbg** можна побачити, **у якому коді ви перебуваєте**:

![Using IDA - Using x64dbg/x32dbg: Зауважте: коли виконання зупиняється з будь-якої причини у win64dbg, у верхній частині вікна win64dbg можна побачити, у якому коді ви перебуваєте](<../../images/image (842).png>)

Цей індикатор підтверджує, що виконання зупинилося всередині DLL, яку ви хочете налагодити.

## GUI-програми / відеоігри

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) — корисна програма для пошуку важливих значень, збережених у пам’яті запущеної гри, та їх зміни. Докладніше:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) — це front-end/інструмент reverse engineering для GNU Project Debugger (GDB), орієнтований на ігри. Водночас його можна використовувати для будь-яких завдань, пов’язаних із reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) — це вебінтерфейс для кількох декомпіляторів. Цей вебсервіс дає змогу порівнювати результати роботи різних декомпіляторів на невеликих виконуваних файлах.

## ARM і MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### Налагодження shellcode за допомогою blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) виділяє **shellcode**, виводить його **адресу в пам’яті** й призупиняє виконання.\
Приєднайте debugger, наприклад IDA або x64dbg, установіть breakpoint за виведеною адресою та відновіть виконання, щоб налагодити shellcode.

На сторінці релізів GitHub є ZIP-архіви зі скомпільованими версіями: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Трохи змінену версію Blobrunner можна знайти за посиланням нижче. Щоб скомпілювати її, просто **створіть проєкт C/C++ у Visual Studio Code, скопіюйте й вставте код та виконайте збірку**.


{{#ref}}
blobrunner.md
{{#endref}}

### Налагодження shellcode за допомогою jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) працює подібно до BlobRunner. Він виділяє shellcode й запускає нескінченний цикл. Приєднайте debugger, відновіть виконання на **2–5 секунд**, призупиніть його всередині циклу й перейдіть до наступного виклику, який передає виконання виділеному shellcode.

![Debugger призупинений у нескінченному циклі jmp2it безпосередньо перед викликом виділеного shellcode](<../../images/image (509).png>)

Скомпільовану версію [jmp2it можна завантажити зі сторінки релізів](https://github.com/adamkramer/jmp2it/releases/).

### Налагодження shellcode за допомогою Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) — це GUI для radare. За допомогою Cutter можна емулювати shellcode й аналізувати його під час виконання.

Зауважте, що Cutter дає змогу вибрати «Open File» або «Open Shellcode». У моєму випадку, коли я відкрив shellcode як файл, програма коректно його декомпілювала, але під час відкриття як shellcode цього не сталося:

![Cutter показує різні результати аналізу під час відкриття тих самих байтів як файлу або shellcode](<../../images/image (562).png>)

Щоб розпочати емуляцію в потрібному місці, установіть там bp — схоже, Cutter автоматично розпочне емуляцію саме звідти:

![Установлення breakpoint на потрібній точці входу shellcode перед запуском емуляції в Cutter](<../../images/image (589).png>)

![Емулятор Cutter призупинений на вибраному breakpoint у shellcode](<../../images/image (387).png>)

Наприклад, стек можна переглянути у вигляді hex dump:

![Перегляд стека емульованого shellcode у hex dump Cutter](<../../images/image (186).png>)

### Деобфускація shellcode та отримання виконаних функцій

Спробуйте [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Він покаже, зокрема, **які функції** використовує shellcode і чи **декодує** він себе в пам’яті.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg також має графічний лаунчер, у якому можна вибрати потрібні параметри й виконати shellcode

![Графічний лаунчер scDbg для вибору параметрів емуляції та трасування shellcode](<../../images/image (258).png>)

Параметр **Create Dump** збереже фінальний shellcode, якщо під час виконання його було змінено в пам’яті (корисно, щоб завантажити декодований shellcode). Параметр **start offset** може стати в пригоді, щоб запустити shellcode з певного зсуву. Параметр **Debug Shell** корисний для налагодження shellcode через термінал scDbg (однак я вважаю, що для цього краще підійдуть будь-які з описаних вище варіантів, оскільки ви зможете використовувати Ida або x64dbg).

### Дизасемблювання за допомогою CyberChef

Завантажте файл shellcode як вхідні дані й скористайтеся таким рецептом для його декомпіляції: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Деобфускація MBA-обфускації

Обфускація **Mixed Boolean-Arithmetic (MBA)** приховує прості вирази, як-от `x + y`, за формулами, що поєднують арифметичні (`+`, `-`, `*`) і побітові оператори (`&`, `|`, `^`, `~`, зсуви). Важливо, що ці тотожності зазвичай правильні лише за **модульної арифметики з фіксованою розрядністю**, тому перенесення й переповнення мають значення:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Якщо спростити такий вираз за допомогою універсальних інструментів алгебри, можна легко отримати неправильний результат, оскільки семантику розрядності було проігноровано.<sup>[[1]](#references)</sup>

### Практичний робочий процес

1. **Зберігайте початкову розрядність** з lifted-коду/IR/виводу декомпілятора (`8/16/32/64` бітів).
2. **Класифікуйте вираз** перед спробою його спростити:
   - **Лінійний**: зважені суми побітових атомів
   - **Напівлінійний**: лінійна частина плюс сталі маски, як-от `x & 0xFF`
   - **Поліноміальний**: містить добутки
   - **Змішаний**: добутки та побітова логіка чергуються, часто з повторюваними підвиразами
3. **Перевіряйте кожне запропоноване перетворення** за допомогою випадкових тестів або SMT-доведення. Якщо еквівалентність не можна довести, залиште початковий вираз замість того, щоб вгадувати.

### Обійдіть сплощений потік керування за допомогою вузького зрізу виконання

Відновлювати повний граф потоку керування часто не потрібно. За наявності сплощення потоку керування, непрозорих предикатів, великих диспетчерів або коду з великою кількістю MBA простежте посилання від зашифрованих блоків даних і вихідних буферів до найменшої процедури, яка їх перетворює. Потім відтворіть лише цей зріз потоку даних або виконайте його окремо; диспетчер не потрібен для розв’язання, якщо відповідний стан можна ініціалізувати безпосередньо.<sup>[[7]](#references)</sup>

Практичний робочий процес:<sup>[[7]](#references)</sup>

1. Перевірте виконувані та секції даних, релокації й перехресні посилання. Вивантажте кандидатні таблиці з `.rodata`, зберігаючи порядок байтів і ширину елементів.
2. Знайдіть останню процедуру, яка записує відкритий текст або вихідний буфер. Зафіксуйте її входи, таблиці, на які вона посилається, імпортовані виклики та потрібний глобальний стан.
3. Перенесіть лише ці операції у Python-модель із фіксованою розрядністю. Якщо зріз і далі залежить від надмірної кількості стану, викличте процедуру в Unicorn, QEMU або налагоджувачі й перехоплюйте непотрібні імпортовані функції замість емуляції всієї програми.
4. Переконайтеся, що екстрактор справді отримує результат із наданого бінарного файлу: приберіть приховані резервні варіанти, перевірте його на наявність вбудованих відповідей і запустіть на невідомих збірках зі зміненими рядками, ключами, ідентифікаторами, структурами та seed-значеннями обфускації.

Корисні команди для первинної перевірки:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Виявлення MBA-виразів, що маскують константи

На перший погляд, вираз для байта, залежний від вхідних даних, може повністю нівелювати їхній вплив. Після вилучення таблиць обчисліть вираз для всього 8-бітного діапазону; якщо множина результатів містить лише один елемент, це доводить, що байт є константою, і відновлювати решту скінченного автомата не потрібно.<sup>[[7]](#references)</sup>

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

Залиште фінальну маску, оскільки початкове додавання має циклічне переповнення в межах байтової ширини. Для ширшої області значень попросіть SMT-солвер перевірити, чи є розв’язною умова `f(x1) != f(x2)` для двох символічних входів однакової ширини: `unsat` доводить інваріантність, тоді як `sat` надає контрприклад і означає, що вхід не можна відкинути.<sup>[[7]](#references)</sup>

#### Розпізнавання декодування, залежного від середовища

Перевірки протидії аналізу не обов’язково мають спричиняти перехід або аварійне завершення. Декодер може підмішати результат сенсора в біт ключа, константу opaque predicate або стан flattened dispatcher, продовжити роботу у звичайному режимі й отримати правдоподібний, але хибний відкритий текст в емуляторі. Тому недостатньо виправити лише видимі гілки помилок; простежте залежності даних від перевірок середовища до стану декодера, порівняйте той самий зріз на справжньому пристрої та в емуляторі й перевірте, як примусова зміна результату кожного сенсора впливає на кінцевий буфер.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) — практичний спрощувач MBA для аналізу malware та реверсингу захищених бінарних файлів. Він класифікує вираз і спрямовує його до спеціалізованих конвеєрів замість того, щоб застосовувати один універсальний прохід переписування до всього.<sup>[[2]](#references)</sup>

Швидке використання:

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

- **Linear MBA**: CoBRA обчислює вираз на булевих входах, виводить сигнатуру та паралельно запускає кілька методів відновлення, як-от зіставлення зі зразками, перетворення ANF і інтерполяція коефіцієнтів.
- **Semilinear MBA**: атоми з маскою-константою відновлюються за допомогою реконструкції з розбиттям на біти, щоб замасковані області залишалися коректними.
- **Polynomial/Mixed MBA**: добутки розкладаються на ядра, а повторювані підвирази можна винести в тимчасові змінні перед спрощенням зовнішнього співвідношення.

Приклад змішаної тотожності, яку часто варто спробувати відновити:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Це можна згорнути до:

```c
x * y
```

### Нотатки з реверсингу

- Краще запускати CoBRA на **піднятих виразах IR** або виводі декомпілятора після того, як ви виокремили точне обчислення.
- Явно задавайте `--bitwidth`, якщо вираз отримано з арифметики з масками або вузьких регістрів.
- Якщо потрібен надійніший крок доведення, перегляньте локальні нотатки про Z3 тут:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA також постачається як **плагін-прохід LLVM** (`libCobraPass.so`), що корисно, коли потрібно нормалізувати LLVM IR із великою кількістю MBA перед подальшими проходами аналізу.
- Непідтримувані залишкові вирази зі змішаними доменами, чутливі до переносу, слід вважати сигналом зберегти початковий вираз і вручну проаналізувати шлях переносу.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Цей обфускатор замінює операції програми послідовностями інструкцій на основі `mov` і використовує обробку сигналів/винятків для зміни потоку керування. Докладніше:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Для підтримуваних бінарних файлів [demovfuscator](https://github.com/kirschju/demovfuscator) може деобфускувати результат. Він має кілька залежностей.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

А також [встановіть keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Якщо ви граєте в **CTF, цей обхідний спосіб пошуку flag** може бути дуже корисним: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Щоб знайти **точку входу**, шукайте функції за `::main`, як-от:

![Пошук точки входу Rust у Ghidra за назвами функцій із подвійною двокрапкою перед main](<../../images/image (1080).png>)

У цьому випадку бінарний файл називався authenticator, тож цю головну функцію досить легко впізнати.\
Знайшовши **назви** викликаних **функцій**, пошукайте їх в **Інтернеті**, щоб дізнатися про їхні **вхідні дані** та **вихідні дані**.

### Відновлення рядків Rust із прошивки ELF

У бінарних файлах **Rust ELF** багато статичних рядків не посилаються через вказівники з нульовим завершенням у стилі C. Поширене компонування `rustc` — це **кортеж вказівника й довжини** всередині **`.data.rel.ro`**, який вказує на справжній блок рядків у **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Це означає, що `strings` або стандартний аналіз Ghidra може об’єднувати суміжні рядки або зовсім не знаходити перехресні посилання.<sup>[[3]](#references)</sup>

Швидкий робочий процес:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Отримайте віртуальну адресу та розмір **`.rodata`**.
2. Переберіть **`.data.rel.ro`** по одному слову за раз.
3. Вважайте будь-яке значення в діапазоні адрес `.rodata` потенційним вказівником на рядок.
4. Вважайте наступне слово потенційною довжиною.
5. Застосуйте фільтри перевірки коректності (наприклад, залиште довжини від **4** до **100** байтів).
6. Прочитайте з `.rodata` рівно `length` байтів, а не скануйте до `0x00`.

Мінімальна логіка екстрактора:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Це особливо корисно під час реверсингу firmware, оскільки відновлені рядки Rust часто розкривають **HTTP routes, назви RPC, повідомлення журналу, assertions, імена файлів, ключі конфігурації, обробники команд і логіку, пов’язану з автентифікацією**.

Якщо Ghidra не знаходить ці рядки, запустіть власний скрипт/plugin, який застосовує ту саму евристику й створює рядкові дані за відповідними зміщеннями в `.rodata`. Опубліковані інструменти `rust-strings` і `RustStrings.py` від Pen Test Partners — хороші приклади для адаптації цієї ідеї до інших **розмірів слів, порядку байтів і структур секцій**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Для скомпільованих бінарних файлів Delphi можна скористатися [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Якщо вам потрібно реверсити бінарний файл Delphi, рекомендую скористатися plugin для IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Натисніть **Alt+F7** в IDA, щоб завантажити Python plugin, а потім виберіть файл plugin.

Цей plugin запустить бінарний файл і динамічно визначить назви функцій на початку налагодження. Після початку налагодження знову натисніть кнопку Start (зелену або f9), і на початку основного коду спрацює breakpoint.

Якщо натиснути кнопку в графічному застосунку, відладчик може зупинитися на функції, яку викликає ця кнопка.

## Golang

Якщо вам потрібно реверсити бінарний файл Golang, рекомендую скористатися plugin для IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Натисніть **Alt+F7** в IDA, щоб завантажити Python plugin, а потім виберіть файл plugin.

Це визначить назви функцій.

## Скомпільований Python

На цій сторінці описано, як отримати код Python зі скомпільованого бінарного файла ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Якщо у вас є **бінарний файл** гри для GBA, можна скористатися різними інструментами, щоб її **емулятувати** й **налагоджувати**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Завантажте debug-версію_) - Містить відладчик з інтерфейсом
- [**mgba** ](https://mgba.io)- Містить CLI-відладчик
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - plugin для Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - plugin для Ghidra

У [**no$gba**](https://problemkaputt.de/gba.htm), у меню _**Options --> Emulation Setup --> Controls**_** ** можна побачити, як натискати **кнопки** Game Boy Advance

![Конфігурація керування no$gba з призначенням кнопок Game Boy Advance](<../../images/image (581).png>)

Під час натискання кожна **клавіша має значення**, за яким її можна ідентифікувати:

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

Отже, у програмі такого типу найцікавіше — **як програма обробляє введені користувачем дані**. За адресою **0x4000130** ви знайдете поширену функцію: **KEYINPUT**.

![Вигляд Ghidra бінарного файлу GBA з посиланням на KEYINPUT за адресою 0x4000130](<../../images/image (447).png>)

На попередньому зображенні видно, що функцію викликає **FUN_080015a8** (адреси: _0x080015fa_ та _0x080017ac_).

У цій функції після кількох ініціалізаційних операцій (які не мають значення):

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

Останній if перевіряє, чи є **`uVar4`** серед останніх Keys і чи не є він поточним ключем, тобто чи відпускають кнопку (поточний ключ зберігається в **`uVar1`**).

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

У попередньому коді видно, що ми порівнюємо **uVar1** (місце, де міститься **значення натиснутої кнопки**) з деякими значеннями:

- Спочатку його порівнюють зі **значенням 4** (кнопка **SELECT**): у цьому завданні ця кнопка очищає екран.
- Потім значення порівнюють із **8** (кнопка **START**); у цьому завданні цей шлях перевіряє, чи правильний введений код.
  - У цьому випадку змінну **`DAT_030000d8`** порівнюють із 0xf3, і якщо значення збігається, виконується певний код.
- В усіх інших випадках перевіряють і збільшують лічильник (`DAT_030000d4`).\
  Поки лічильник менший за 8, значення натиснутих клавіш накопичуються в `DAT_030000d8`.

Отже, у цьому завданні, знаючи значення кнопок, потрібно було **натискати комбінацію довжиною меншою за 8, сума значень якої дорівнює 0xf3.**

**Джерело для цього посібника:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Деобфускація бінарних файлів)

## References

- [1] [Спрощення MBA-обфускації за допомогою CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Репозиторій CoBRA від Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Декодування рядків Rust — Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia — посібник із reversing для GBA (архівна копія)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Подолання reverse engineering за допомогою AI або принаймні спроба](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
