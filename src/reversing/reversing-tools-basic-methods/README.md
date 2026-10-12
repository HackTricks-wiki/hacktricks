# Інструменти реверс-інжинірингу та базові методи

{{#include ../../banners/hacktricks-training.md}}

## Інструменти реверс-інжинірингу на базі ImGui

Програмне забезпечення:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Налагодження ядра Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Декомпілятор Wasm / компілятор Wat

Онлайн:

- Використовуйте [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), щоб **декомпілювати** wasm (бінарний файл) у wat (звичайний текст)
- Використовуйте [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), щоб **компілювати** wat у wasm
- Для декомпіляції також можна спробувати [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Програмне забезпечення:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Кешований байткод Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Віртуалізовані payloads і спеціальні VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Декомпілятор .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek — це декомпілятор, який **декомпілює та аналізує різні формати**, зокрема **бібліотеки** (.dll), **файли метаданих Windows** (.winmd) та **виконувані файли** (.exe). Після декомпіляції збірку можна зберегти як проєкт Visual Studio (.csproj).

Цей інструмент стане в пригоді, якщо потрібно відновити втрачений вихідний код із застарілої збірки, адже це заощадить час. Крім того, dotPeek забезпечує зручну навігацію декомпільованим кодом, що робить його одним із найкращих інструментів для **аналізу алгоритмів Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Завдяки широким можливостям розширення та API, що дає змогу налаштувати інструмент відповідно до ваших потреб, .NET Reflector заощаджує час і спрощує розробку. Розгляньмо численні можливості реверс-інжинірингу, які надає цей інструмент:

- Допомагає зрозуміти, як дані проходять через бібліотеку або компонент
- Допомагає зрозуміти реалізацію та використання мов і фреймворків .NET
- Виявляє недокументовані та недоступні функції, щоб отримати більше від API і використовуваних технологій.
- Знаходить залежності та різні збірки
- Допомагає точно визначити місце помилок у вашому коді, сторонніх компонентах і бібліотеках.
- Дає змогу налагоджувати вихідний код усього коду .NET, з яким ви працюєте.

### [ILSpy](https://github.com/icsharpcode/ILSpy) і [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Плагін ILSpy для Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): доступний для будь-якої ОС (його можна встановити безпосередньо з VSCode — завантажувати git не потрібно. Натисніть **Extensions** і **знайдіть ILSpy**).\
Якщо потрібно **декомпілювати**, **змінити** і знову **скомпілювати**, скористайтеся [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) або його форком, який активно підтримується, — [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Клацніть правою кнопкою миші -> Modify Method**, щоб щось змінити всередині функції).

### Логування в DNSpy

Щоб **записувати певну інформацію з DNSpy у файл**, можна скористатися таким фрагментом:

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Потім збережіть новий файл через _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Це необхідно, оскільки без цього під час **runtime** до коду буде застосовано кілька **оптимізацій**, і під час налагодження може статися так, що **break-point ніколи не спрацює** або деякі **variables не існуватимуть**.

Якщо вашу .NET-програму **запускає** **IIS**, його можна **перезапустити** так:

```
iisreset /noforce
```

Потім, щоб розпочати налагодження, закрийте всі відкриті файли та на вкладці **Debug Tab** виберіть **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Потім, щоб розпочати налагодження, закрийте всі відкриті файли та на вкладці Debug Tab виберіть Attach to Process](<../../images/image (318).png>)

Потім виберіть **w3wp.exe**, щоб під’єднатися до **IIS server**, і натисніть **attach**:

![DNSpy Logging - DNSpy Debugging: Потім виберіть w3wp.exe, щоб під’єднатися до IIS server, і натисніть attach](<../../images/image (113).png>)

Тепер, коли ми налагоджуємо процес, час зупинити його та завантажити всі модулі. Спочатку натисніть _Debug >> Break All_, а потім — _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Тепер, коли ми налагоджуємо процес, час зупинити його та завантажити всі модулі. Спочатку натисніть Debug Break All, а потім — Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Тепер, коли ми налагоджуємо процес, час зупинити його та завантажити всі модулі. Спочатку натисніть Debug Break All, а потім — Debug Windows Modules](<../../images/image (834).png>)

Натисніть будь-який модуль у **Modules** і виберіть **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Натисніть будь-який модуль у Modules і виберіть Open All Modules](<../../images/image (922).png>)

Клацніть правою кнопкою миші будь-який модуль в **Assembly Explorer** і натисніть **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Клацніть правою кнопкою миші будь-який модуль в Assembly Explorer і натисніть Sort Assemblies](<../../images/image (339).png>)

## Декомпілятор Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Налагодження DLL

### За допомогою IDA

- **Завантажте rundll32** (64-розрядна версія: C:\Windows\System32\rundll32.exe, 32-розрядна: C:\Windows\SysWOW64\rundll32.exe)
- Виберіть налагоджувач **Windbg**
- Виберіть "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Виберіть " Suspend on library load/unload "](<../../images/image (868).png>)

- Налаштуйте **параметри** запуску, вказавши **шлях до DLL** і функцію, яку потрібно викликати:

![Debugging DLLs - Using IDA: Налаштуйте параметри запуску, вказавши шлях до DLL і функцію, яку потрібно викликати](<../../images/image (704).png>)

Після початку налагодження **виконання зупинятиметься під час завантаження кожної DLL**. Тож коли rundll32 завантажить вашу DLL, виконання зупиниться.

Цей метод зупиняє виконання під час завантаження модулів, але перехід до точки входу завантаженої DLL менш прямолінійний, ніж у наведеному нижче сценарії з x64dbg.

### За допомогою x64dbg/x32dbg

- **Завантажте rundll32** (64-розрядна версія: C:\Windows\System32\rundll32.exe, 32-розрядна: C:\Windows\SysWOW64\rundll32.exe)
- **Змініть командний рядок** ( _File --> Change Command Line_ ) і вкажіть шлях до DLL та функцію, яку потрібно викликати. Наприклад: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Змініть _Options --> Settings_ і виберіть "**DLL Entry**".
- Потім **запустіть виконання**. Налагоджувач зупинятиметься в точці входу кожної DLL; зрештою ви **зупинитеся на точці входу своєї DLL**. Звідти знайдіть місця, де потрібно встановити breakpoint.

Зауважте, що коли виконання з будь-якої причини зупиняється у win64dbg, **у якому коді ви перебуваєте**, можна побачити **у верхній частині вікна win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Зауважте, що коли виконання з будь-якої причини зупиняється у win64dbg, у якому коді ви перебуваєте, можна побачити у верхній частині вікна win64dbg](<../../images/image (842).png>)

Цей індикатор підтверджує, що виконання зупинилося всередині DLL, яку ви хочете налагодити.

## GUI-застосунки / відеоігри

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) — корисна програма для пошуку важливих значень у пам’яті запущеної гри та їх зміни. Докладніше:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) — інтерфейсний інструмент для GNU Project Debugger (GDB) і reverse engineering, орієнтований на ігри. Однак його можна використовувати для будь-яких завдань, пов’язаних із reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) — вебінтерфейс для різних декомпіляторів. Цей вебсервіс дає змогу порівнювати результати роботи різних декомпіляторів на невеликих виконуваних файлах.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Налагодження shellcode за допомогою blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) виділяє пам’ять для **shellcode**, виводить її **адресу** та призупиняє виконання.\
Під’єднайте налагоджувач, наприклад IDA або x64dbg, встановіть breakpoint за виведеною адресою та відновіть виконання, щоб налагодити shellcode.

На сторінці релізів GitHub є ZIP-архіви зі скомпільованими версіями: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Трохи модифіковану версію Blobrunner можна знайти за посиланням нижче. Щоб скомпілювати її, просто **створіть проєкт C/C++ у Visual Studio Code, скопіюйте й вставте код та зберіть його**.


{{#ref}}
blobrunner.md
{{#endref}}

### Налагодження shellcode за допомогою jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) працює подібно до BlobRunner. Він виділяє пам’ять для shellcode та входить у нескінченний цикл. Під’єднайте налагоджувач, відновіть виконання на **2–5 секунд**, призупиніть його всередині циклу та перейдіть до наступного виклику, який передає керування виділеній області пам’яті з shellcode.

![Налагоджувач призупинено в нескінченному циклі jmp2it безпосередньо перед викликом shellcode у виділеній області пам’яті](<../../images/image (509).png>)

Скомпільовану версію [jmp2it можна завантажити зі сторінки релізів](https://github.com/adamkramer/jmp2it/releases/).

### Налагодження shellcode за допомогою Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) — графічний інтерфейс radare. За допомогою Cutter можна емулювати shellcode та досліджувати його під час виконання.

Зауважте, що Cutter дає змогу вибрати «Open File» або «Open Shellcode». У моєму випадку, коли я відкрив shellcode як файл, він декомпілювався правильно, але під час відкриття як shellcode — ні:

![Cutter показує різні результати аналізу під час відкриття тих самих байтів як файла або як shellcode](<../../images/image (562).png>)

Щоб почати емуляцію в потрібному місці, встановіть там bp — схоже, Cutter автоматично почне емуляцію звідти:

![Встановлення breakpoint у потрібній точці входу shellcode перед запуском емуляції в Cutter](<../../images/image (589).png>)

![Емулятор Cutter призупинено на вибраному breakpoint у shellcode](<../../images/image (387).png>)

Наприклад, стек можна переглянути в hex dump:

![Перегляд стека емульованого shellcode у hex dump Cutter](<../../images/image (186).png>)

### Деобфускація shellcode та визначення викликаних функцій

Спробуйте [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Він покаже, зокрема, **які функції** використовує shellcode та чи **декодує** він себе в пам’яті.

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

Параметр **Create Dump** збереже кінцевий shellcode, якщо його було змінено динамічно в пам’яті (корисно для завантаження декодованого shellcode). **start offset** може стати в пригоді, щоб почати виконання shellcode з певного зміщення. Параметр **Debug Shell** корисний для налагодження shellcode за допомогою термінала scDbg (однак для цього я вважаю кращими будь-які з описаних раніше варіантів, оскільки можна буде скористатися Ida або x64dbg).

### Дизасемблювання за допомогою CyberChef

Завантажте файл shellcode як вхідні дані й використайте такий рецепт для його декомпіляції: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Деобфускація MBA-обфускації

Обфускація **Mixed Boolean-Arithmetic (MBA)** приховує прості вирази, наприклад `x + y`, за формулами, що поєднують арифметичні (`+`, `-`, `*`) і побітові оператори (`&`, `|`, `^`, `~`, зсуви). Важливо, що ці тотожності зазвичай правильні лише за **модульної арифметики з фіксованою шириною**, тому переноси й переповнення мають значення:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Якщо спростити такий вираз за допомогою універсальних засобів алгебри, легко отримати неправильний результат, оскільки семантику розрядності було проігноровано.<sup>[[1]](#references)</sup>

### Практичний процес

1. **Збережіть початкову розрядність** lifted-коду/IR/виводу decompiler (`8/16/32/64` бітів).
2. **Класифікуйте вираз**, перш ніж намагатися його спростити:
   - **Лінійний**: зважені суми бітових атомів
   - **Напівлінійний**: лінійний вираз плюс константні маски на кшталт `x & 0xFF`
   - **Поліноміальний**: містить добутки
   - **Змішаний**: добутки й побітова логіка переплетені, часто з повторюваними підвиразами
3. **Перевірте кожне можливе перетворення** за допомогою випадкового тестування або SMT-доведення. Якщо еквівалентність неможливо довести, залиште початковий вираз, а не вгадуйте.

### Обійдіть сплощений control flow за допомогою вузького зрізу виконання

Відновлювати повний граф control flow часто необов'язково. За наявності сплощення control flow, opaque predicates, великих диспетчерів або коду з великою кількістю MBA-виразів простежте посилання від зашифрованих блоків даних і вихідних буферів до найменшої процедури, яка їх перетворює. Потім відтворіть лише цей зріз потоку даних або виконайте його окремо; диспетчер не є частиною необхідного рішення, якщо відповідний стан можна ініціалізувати напряму.<sup>[[7]](#references)</sup>

Практичний процес:<sup>[[7]](#references)</sup>

1. Складіть перелік виконуваних секцій і секцій даних, релокацій та перехресних посилань. Вивантажте можливі таблиці з `.rodata`, зберігаючи порядок байтів і розмір елементів.
2. Визначте останню процедуру, яка записує відкритий текст або вихідний буфер. Зафіксуйте її входи, таблиці, на які вона посилається, імпортовані виклики та необхідний глобальний стан.
3. Перенесіть лише ці операції у модель Python із фіксованою розрядністю. Якщо зріз усе ще залежить від надто великої кількості стану, викличте процедуру в Unicorn, QEMU або debugger і перехопіть несуттєві імпортовані функції замість емуляції всієї програми.
4. Перевірте, що екстрактор справді отримує результат із наданого бінарного файла: приберіть тихі запасні варіанти, пошукайте в ньому вбудовані відповіді та запустіть його на невідомих раніше збірках зі зміненими рядками, ключами, ідентифікаторами, структурами даних і seed-значеннями обфускації.

Корисні команди для початкової перевірки:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Виявлення MBA-виразів, що маскують константи

На перший погляд, байтовий вираз, що залежить від вхідних даних, може повністю скорочуватися за вхідним значенням. Після вилучення таблиць обчисліть вираз для всього 8-бітного діапазону; якщо множина результатів містить лише одне значення, це доводить, що байт є константою, без відновлення навколишньої машини станів.<sup>[[7]](#references)</sup>

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

Збережіть фінальну маску, оскільки початкове додавання має циклічне переповнення на ширині байта. Для ширшої області значень попросіть SMT-розв’язувач перевірити, чи є задача `f(x1) != f(x2)` для двох символічних входів однакової ширини виконуваною: `unsat` доводить інваріантність, тоді як `sat` надає контрприклад і означає, що вхід не можна відкинути.<sup>[[7]](#references)</sup>

#### Розпізнавання декодування, залежного від середовища

Перевірки Anti-analysis не обов’язково мають спричиняти перехід або аварійне завершення. Декодер може змішати результат датчика з бітом ключа, константою opaque predicate або станом flattened dispatcher, продовжити роботу у звичайному режимі й видати правдоподібний, але хибний відкритий текст в емуляторі. Тому недостатньо виправити лише видимі гілки помилок; відстежуйте залежності даних від перевірок середовища до стану декодера, порівнюйте той самий фрагмент на автентичному пристрої та в емуляторі й перевіряйте, як примусове встановлення результату кожного датчика змінює фінальний буфер.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) — практичний спрощувач MBA для аналізу malware і реверсингу захищених бінарних файлів. Він класифікує вираз і спрямовує його до спеціалізованих конвеєрів замість застосування одного універсального проходу перезапису до всіх виразів.<sup>[[2]](#references)</sup>

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

- **Лінійний MBA**: CoBRA обчислює вираз на булевих входах, виводить сигнатуру та запускає кілька методів відновлення: зіставлення зі зразком, перетворення до ANF і інтерполяцію коефіцієнтів.
- **Напівлінійний MBA**: атоми з константною маскою відновлюються за допомогою реконструкції з розбиттям на біти, щоб масковані ділянки залишалися правильними.
- **Поліноміальний/змішаний MBA**: добутки розкладаються на ядра, а повторювані підвирази можна винести в тимчасові змінні перед спрощенням зовнішнього співвідношення.

Приклад змішаної тотожності, яку зазвичай варто спробувати відновити:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Це можна звести до:

```c
x * y
```

### Нотатки з реверсингу

- Надавайте перевагу запуску CoBRA на **піднятих IR-виразах** або виході декомпілятора після того, як виокремили точне обчислення.
- Явно вказуйте `--bitwidth`, якщо вираз отримано з арифметики з масками або вузьких регістрів.
- Якщо потрібен надійніший крок доведення, перегляньте локальні нотатки про Z3 тут:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA також постачається як **плагін LLVM pass** (`libCobraPass.so`), що стане в пригоді, якщо потрібно нормалізувати LLVM IR, насичений MBA-конструкціями, перед подальшими етапами аналізу.
- Непідтримувані залишкові вирази зі змішаними доменами, чутливі до переносу, слід вважати сигналом зберегти початковий вираз і вручну проаналізувати шлях переносу.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Цей обфускатор замінює операції програми послідовностями інструкцій на основі `mov` і змінює потік керування за допомогою обробки сигналів і винятків. Докладніше:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Для підтримуваних бінарних файлів [demovfuscator](https://github.com/kirschju/demovfuscator) може деобфускувати результат. Він має кілька залежностей.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Якщо ви граєте в **CTF, цей обхідний спосіб знайти flag** може бути дуже корисним: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Щоб знайти **точку входу**, пошукайте функції за `::main`, як-от:

![Пошук точки входу Rust у Ghidra за іменами функцій із подвійною двокрапкою перед main](<../../images/image (1080).png>)

У цьому випадку бінарний файл називався authenticator, тож досить очевидно, що це потрібна функція main.\
Дізнавшись **назви** викликаних **функцій**, пошукайте їх в **Інтернеті**, щоб з’ясувати їхні **вхідні та вихідні дані**.

### Відновлення рядків Rust із прошивки ELF

У бінарних файлах **Rust ELF** багато статичних рядків не адресуються як покажчики з нульовим завершенням у стилі C. Поширений формат `rustc` — це **кортеж покажчика й довжини** всередині **`.data.rel.ro`**, що вказує на справжній блок рядків у **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Це означає, що `strings` або стандартний аналіз Ghidra може об’єднувати суміжні рядки або взагалі не знаходити перехресні посилання.<sup>[[3]](#references)</sup>

Швидкий робочий процес:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Отримайте віртуальну адресу та розмір **`.rodata`**.
2. Переберіть **`.data.rel.ro`** по одному слову за раз.
3. Розглядайте будь-яке значення в діапазоні адрес `.rodata` як можливий вказівник на рядок.
4. Розглядайте наступне слово як можливу довжину.
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

Це особливо корисно під час реверсингу прошивки, оскільки відновлені рядки Rust часто розкривають **HTTP-маршрути, назви RPC, повідомлення журналу, твердження, імена файлів, ключі конфігурації, обробники команд і логіку, пов’язану з автентифікацією**.

Якщо Ghidra не знаходить ці рядки, запустіть власний скрипт або плагін, який застосовує ту саму евристику й створює рядкові дані за адресами `.rodata`, на які є посилання. Опубліковані інструменти `rust-strings` і `RustStrings.py` від Pen Test Partners — хороші приклади для адаптації цієї ідеї до інших **розмірів слова, порядків байтів і макетів секцій**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Для бінарних файлів, скомпільованих Delphi, можна скористатися [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Якщо вам потрібно реверсити бінарний файл Delphi, раджу скористатися плагіном IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Натисніть **Alt+F7** в IDA, щоб завантажити плагін Python, а потім виберіть файл плагіна.

На початку налагодження цей плагін запустить бінарний файл і динамічно визначить назви функцій. Після початку налагодження знову натисніть кнопку Start (зелену або f9), і на початку справжнього коду спрацює точка зупинки.

Якщо натиснути кнопку в графічному застосунку, налагоджувач може зупинитися у функції, яку викликає ця кнопка.

## Golang

Для звичайних бінарних файлів Go [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) може відновити структури середовища виконання й покращити назви функцій в IDA. Завантажте його плагін Python за допомогою **Alt+F7**.

### Відновлення метаданих без таблиці символів

Навіть у Go-виконуваному файлі зі стертими символами потрібні метадані середовища виконання, щоб зіставляти лічильники команд із функціями. [GoReSym](https://github.com/mandiant/GoReSym) знаходить і аналізує такі структури, як `pclntab` і `moduledata`, використовуючи код, похідний від середовища виконання Go. Це дає змогу відновити межі функцій, їхні назви, шляхи до вихідних файлів, типи й відомості про збірку без використання традиційної таблиці символів.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Обфускатор може залишити ці структури придатними до використання, замінивши відновлені назви. Наприклад, Garble хешує ідентифікатори та шляхи пакетів і видаляє інформацію про збірку, модулі та налагодження.<sup>[[12]](#references)</sup> Токен обфускованого пакета має залишатися однаковим у функціях цього пакета. Згрупуйте функції за повторюваним токеном, визначте пакет однієї з них за її викликаними функціями, рядками та API, а потім призначте цю мітку пакета всій групі.<sup>[[13]](#references)</sup>

### Відновлення назв Garble за допомогою GoResolver

[GoResolver](https://github.com/volexity/GoResolver) поєднує вилучення runtime-символів зі створенням еталонних бінарних файлів без обфускації та зіставленням графів потоку керування (CFG). Виконайте такі кроки:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Визначте версію компілятора.** Спочатку перевірте `BuildInfo` та вбудовані рядки версії. Якщо обфускатор їх видалив, порівняйте частини вбудованого Go runtime з еталонними runtime різних версій. У тестах Volexity близько `2%` runtime було достатньо, щоб розрізнити основні версії Go. Вважайте це емпіричною оптимізацією, а не універсальним пороговим значенням.<sup>[[13]](#references)</sup>
2. **Створіть відповідні еталонні бінарні файли.** Згенеруйте бінарні файли без обфускації для визначеної версії Go, цільової архітектури та ймовірних бібліотек. Відповідність toolchain зменшує відмінності CFG, спричинені компілятором.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Порівняйте функції.** GoGrapher зіставляє CFG функцій і видає нормалізовані оцінки від `0.0` до `1.0`. Зіставлення базових блоків ґрунтується на зваженому порівнянні схожих інструкцій. Відповідності з високою впевненістю пов’язують функції з рандомізованими назвами з відповідною реалізацією без обфускації. Відповідності з нижчою впевненістю все одно можуть допомогти визначити пакет або модуль.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Перевірте та імпортуйте результати.** Перевірте запропоновані назви за зв’язками викликів, константами, рядками та побічними ефектами, а потім імпортуйте JSON-звіт за допомогою плагіна GoResolver для IDA або Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Встановіть toolchain і запустіть комбінований екстрактор та зіставлювач графів:<sup>[[10]](#references)</sup>

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

The default значення порога значущого збігу — `0.9`. Параметри `--extract` і `--graph` дають змогу запускати окремо кожен етап, тоді як за замовчуванням запускаються обидва, оскільки відновлені метадані runtime та дані CFG доповнюють одне одного.<sup>[[10]](#references)</sup> Оцінки CFG евристичні: інлайнінг, прапорці збірки, архітектура та відмінності між версіями бібліотек можуть змінювати структуру графа, тому залишайте нерозпізнані функції без змін, а не призначайте їм імена з низькою впевненістю.<sup>[[13]](#references)</sup>

## Compiled Python

На цій сторінці ви знайдете інструкції, як отримати код Python із скомпільованого бінарного файлу Python у форматі ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Якщо у вас є **бінарний файл** гри для GBA, можна використовувати різні інструменти для її **емуляції** та **налагодження**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_завантажте debug-версію_) — містить debugger з інтерфейсом
- [**mgba** ](https://mgba.io) — містить CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) — плагін для Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) — плагін для Ghidra

У [**no$gba**](https://problemkaputt.de/gba.htm), у меню _**Options --> Emulation Setup --> Controls**_** ** можна подивитися, як натискати **кнопки** Game Boy Advance

![Конфігурація керування no$gba з відповідністю кнопок Game Boy Advance](<../../images/image (581).png>)

Після натискання кожна **клавіша має значення**, за яким її можна визначити:

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

![Вигляд Ghidra двійкового файлу GBA із посиланням на KEYINPUT за адресою 0x4000130](<../../images/image (447).png>)

На попередньому зображенні видно, що функцію викликають із **FUN_080015a8** (адреси: _0x080015fa_ і _0x080017ac_).

У цій функції після кількох початкових операцій (які не мають значення):

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

Остання умова if перевіряє, чи **uVar4** є серед **останніх клавіш** і чи не є поточною клавішею — тобто чи відпустили кнопку (поточна клавіша зберігається в **uVar1**).

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

- Спочатку його порівнюють зі **значенням 4** (кнопка **SELECT**): у цьому челенджі ця кнопка очищає екран.
- Потім значення порівнюють із **8** (кнопка **START**); у цьому челенджі ця гілка перевіряє, чи введений код дійсний.
  - У цьому випадку змінну **`DAT_030000d8`** порівнюють із 0xf3, і якщо значення збігається, виконується певний код.
- В усіх інших випадках перевіряється та збільшується лічильник (`DAT_030000d4`).\
  Поки лічильник менший за 8, значення натиснутих клавіш накопичуються в `DAT_030000d8`.

Отже, у цьому челенджі, знаючи значення кнопок, потрібно було **натиснути комбінацію довжиною менш як 8, щоб отримана сума дорівнювала 0xf3.**

**Джерело для цього посібника:** [архівований опис розв’язання челенджу Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Курси

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (декомпіляція бінарних файлів)

## References

- [1] [Спрощення MBA-обфускації за допомогою CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Репозиторій Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Декодування рядків Rust — Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering — рядки Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering — RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia — посібник із реверсингу GBA (архів)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Як перемогти реверсинг за допомогою AI — або принаймні спробувати](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Підхід до порівняння графів потоку керування на основі зіставлення базових блоків](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Механізм обфускації Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: використання подібності графів потоку керування для автоматичної деобфускації бінарних файлів Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
