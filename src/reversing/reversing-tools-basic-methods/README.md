# Інструменти реверсингу та базові методи

{{#include ../../banners/hacktricks-training.md}}

## Інструменти реверсингу на основі ImGui

Програмне забезпечення:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Декомпілятор Wasm / компілятор Wat

Онлайн:

- Використовуйте [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), щоб **декомпілювати** wasm (бінарний формат) у wat (текстовий формат)
- Використовуйте [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), щоб **скомпілювати** wat у wasm
- Також можна спробувати [web-wasmdec](https://wwwg.github.io/web-wasmdec/) для декомпіляції.

Програмне забезпечення:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Декомпілятор .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek — це декомпілятор, який **декомпілює та аналізує декілька форматів**, зокрема **бібліотеки** (.dll), **файли метаданих Windows** (.winmd) і **виконувані файли** (.exe). Після декомпіляції збірку можна зберегти як проєкт Visual Studio (.csproj).

Перевага полягає в тому, що якщо потрібно відновити втрачений вихідний код зі застарілої збірки, цей процес може заощадити час. Крім того, dotPeek забезпечує зручну навігацію декомпільованим кодом, що робить його одним із найкращих інструментів для **аналізу алгоритмів Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Завдяки комплексній моделі add-in та API, який розширює інструмент відповідно до ваших точних потреб, .NET Reflector заощаджує час і спрощує розробку. Розгляньмо широкий спектр сервісів реверсингу, які надає цей інструмент:

- Надає уявлення про рух даних через бібліотеку або компонент
- Надає уявлення про реалізацію та використання мов і framework .NET
- Знаходить недокументовану та недоступну функціональність, щоб отримати більше можливостей від використовуваних API і технологій.
- Знаходить залежності та різні збірки
- Допомагає визначити точне розташування помилок у вашому коді, сторонніх компонентах і бібліотеках.
- Виконує debugging вихідного коду всього коду .NET, з яким ви працюєте.

### [ILSpy](https://github.com/icsharpcode/ILSpy) та [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Плагін ILSpy для Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): його можна використовувати в будь-якій ОС (його можна встановити безпосередньо з VSCode, тому немає потреби завантажувати git. Натисніть **Extensions** і **знайдіть ILSpy**).\
Якщо потрібно **декомпілювати**, **змінити** та знову **скомпілювати**, можна використати [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) або форк, який активно підтримується, — [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Клацніть правою кнопкою миші -> Modify Method**, щоб змінити щось усередині функції).

### Логування DNSpy

Щоб змусити **DNSpy записувати певну інформацію у файл**, можна використати цей фрагмент:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Налагодження DNSpy

Щоб налагоджувати код за допомогою DNSpy, потрібно:

Спочатку змініть **атрибути Assembly**, пов’язані з **налагодженням**:

![Журналювання DNSpy — налагодження DNSpy: спочатку змініть атрибути Assembly, пов’язані з налагодженням](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: Натисніть compile](<../../images/image (314) (1).png>)

Потім збережіть новий файл через _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Потім збережіть новий файл через File Save module](<../../images/image (602).png>)

Це необхідно, оскільки якщо цього не зробити, під час **runtime** до коду буде застосовано кілька **optimisations**, і може статися так, що під час debugging **break-point ніколи не буде досягнуто** або деякі **variables не існуватимуть**.

Потім, якщо ваш .NET application **запускається** через **IIS**, ви можете **перезапустити** його за допомогою:
```
iisreset /noforce
```
Потім, щоб розпочати debugging, слід закрити всі відкриті файли та у **Debug Tab** вибрати **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Потім, щоб розпочати debugging, слід закрити всі відкриті файли та у вкладці Debug вибрати Attach to Process](<../../images/image (318).png>)

Потім виберіть **w3wp.exe**, щоб підключитися до **IIS server**, і натисніть **attach**:

![DNSpy Logging - DNSpy Debugging: Потім виберіть w3wp.exe, щоб підключитися до IIS server, і натисніть attach](<../../images/image (113).png>)

Тепер, коли ми debugging process, настав час зупинити його та завантажити всі modules. Спочатку натисніть _Debug >> Break All_, а потім _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Тепер, коли ми debugging process, настав час зупинити його та завантажити всі modules. Спочатку натисніть Debug Break All, а потім Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Тепер, коли ми debugging process, настав час зупинити його та завантажити всі modules. Спочатку натисніть Debug Break All, а потім Debug Windows Modules](<../../images/image (834).png>)

Натисніть будь-який module у **Modules** та виберіть **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Натисніть будь-який module у Modules та виберіть Open All Modules](<../../images/image (922).png>)

Клацніть правою кнопкою миші будь-який module в **Assembly Explorer** та натисніть **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Клацніть правою кнопкою миші будь-який module в Assembly Explorer та натисніть Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Використання IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Виберіть **Windbg** debugger
- Виберіть "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Виберіть " Suspend on library load/unload "](<../../images/image (868).png>)

- Налаштуйте **parameters** execution, вказавши **path to the DLL** і function, яку потрібно викликати:

![Debugging DLLs - Using IDA: Налаштуйте parameters execution, вказавши path to the DLL і function, яку потрібно викликати](<../../images/image (704).png>)

Потім, коли ви запустите debugging, **execution буде зупинено під час завантаження кожної DLL**, а коли rundll32 завантажить вашу DLL, execution буде зупинено.

Цей метод зупиняється на подіях завантаження module, але досягнення entry point завантаженої DLL є менш прямим, ніж у workflow з x64dbg нижче.

### Використання x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) і вкажіть path до dll та function, яку потрібно викликати, наприклад: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Змініть _Options --> Settings_ та виберіть "**DLL Entry**".
- Потім **start the execution**, debugger зупинятиметься на кожному dll main; у певний момент ви **зупинитеся на dll Entry вашої dll**. Звідти просто знайдіть місця, де потрібно встановити breakpoint.

Зверніть увагу, що коли execution зупинено з будь-якої причини у win64dbg, ви можете побачити, **у якому code перебуваєте**, подивившись у **верхню частину вікна win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Зверніть увагу, що коли execution зупинено з будь-якої причини у win64dbg, ви можете побачити, у якому code перебуваєте, подивившись у верхню частину вікна win64dbg](<../../images/image (842).png>)

Цей indicator підтверджує, що execution зупинився всередині DLL, яку ви хочете debugging.

## GUI Apps / Відеоігри

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) — корисна програма для пошуку важливих values, збережених у memory запущеної game, та їх зміни. Більше інформації:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) — це front-end/reverse engineering tool для GNU Project Debugger (GDB), орієнтований на games. Однак його можна використовувати для будь-яких завдань, пов’язаних із reverse-engineering.

[**Decompiler Explorer**](https://dogbolt.org/) — це web front-end для низки decompilers. Цей web service дає змогу порівнювати output різних decompilers на невеликих executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging shellcode за допомогою blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) виділяє **shellcode**, виводить його **memory address** і призупиняє execution.\
Підключіть debugger, наприклад IDA або x64dbg, встановіть breakpoint за виведеною address та відновіть execution, щоб debugging shellcode.

На github page релізів містяться zips зі скомпільованими releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Трохи змінену версію Blobrunner можна знайти за цим link. Щоб скомпілювати її, просто **створіть C/C++ project у Visual Studio Code, скопіюйте та вставте code і виконайте його build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging shellcode за допомогою jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) подібний до BlobRunner. Він виділяє shellcode та входить у infinite loop. Підключіть debugger, відновіть execution на **2–5 секунд**, призупиніть його всередині цього loop і виконайте step до наступного call, який передає execution виділеному shellcode.

![Debugger призупинено в infinite loop jmp2it безпосередньо перед call до виділеного shellcode](<../../images/image (509).png>)

Ви можете завантажити скомпільовану версію [jmp2it на сторінці releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode за допомогою Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) — це GUI для radare. За допомогою cutter можна емулювати shellcode та динамічно його inspect.

Зверніть увагу, що Cutter дає змогу **Open File** і **Open Shellcode**. У моєму випадку, коли я відкрив shellcode як file, він правильно decompiled його, але коли я відкрив його як shellcode, цього не сталося:

![Cutter показує різні результати analysis під час відкриття однакових bytes як file або як shellcode](<../../images/image (562).png>)

Щоб розпочати emulation у потрібному місці, встановіть там bp, і, очевидно, cutter автоматично почне emulation із цього місця:

![Встановлення breakpoint у потрібній entry point shellcode перед початком emulation у Cutter](<../../images/image (589).png>)

![Cutter emulator призупинено на вибраному breakpoint shellcode](<../../images/image (387).png>)

Наприклад, ви можете переглянути stack усередині hex dump:

![Перегляд stack емульованого shellcode у hex dump Cutter](<../../images/image (186).png>)

### Deobfuscating shellcode та отримання executed functions

Спробуйте [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Він повідомить такі відомості, як **які functions** використовує shellcode і чи **decoding** shellcode себе в memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg також має графічний launcher, у якому можна вибрати потрібні параметри та виконати shellcode

![Графічний launcher scDbg для вибору параметрів емуляції та трасування shellcode](<../../images/image (258).png>)

Опція **Create Dump** збереже фінальний shellcode, якщо до shellcode динамічно внесено зміни в пам'яті (це корисно для завантаження декодованого shellcode). **start offset** може бути корисним для запуску shellcode із певного зміщення. Опція **Debug Shell** корисна для налагодження shellcode за допомогою термінала scDbg (однак я вважаю будь-який із наведених вище варіантів кращим для цього завдання, оскільки ви зможете використовувати Ida або x64dbg).

### Дизасемблювання за допомогою CyberChef

Завантажте файл shellcode як вхідні дані та скористайтеся наведеним нижче рецептом для його декомпіляції: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Деобфускація MBA-обфускації

Обфускація **Mixed Boolean-Arithmetic (MBA)** приховує прості вирази, такі як `x + y`, за формулами, що поєднують арифметичні (`+`, `-`, `*`) і побітові оператори (`&`, `|`, `^`, `~`, зсуви). Важливо, що ці тотожності зазвичай правильні лише в умовах **модульної арифметики фіксованої розрядності**, тому перенесення та переповнення мають значення:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Якщо спростити такий вираз за допомогою загальних algebra tooling, можна легко отримати неправильний результат, оскільки семантику bit-width було проігноровано.<sup>[[1]](#references)</sup>

### Практичний workflow

1. **Зберігайте оригінальний bit-width** із lifted code/IR/decompiler output (`8/16/32/64` бітів).
2. **Класифікуйте вираз** перед спробою його спростити:
- **Linear**: зважені суми bitwise atoms
- **Semilinear**: linear плюс constant masks, такі як `x & 0xFF`
- **Polynomial**: присутні добутки
- **Mixed**: добутки та bitwise logic взаємопов'язані, часто з повторюваними підвиразами
3. **Перевіряйте кожне потенційне перетворення** за допомогою random testing або SMT proof. Якщо еквівалентність неможливо довести, збережіть оригінальний вираз замість припущень.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) — практичний MBA simplifier для malware analysis і protected-binary reversing. Він класифікує вираз і передає його до спеціалізованих pipeline замість застосування одного загального rewrite pass до всього.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA обчислює вираз на булевих входах, виводить сигнатуру та одночасно застосовує кілька методів відновлення, зокрема зіставлення зі зразком, перетворення в ANF і інтерполяцію коефіцієнтів.
- **Semilinear MBA**: атоми з constant masking перебудовуються за допомогою реконструкції з розбиттям на біти, щоб замасковані області залишалися коректними.
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

- Надавайте перевагу запуску CoBRA на **піднятих IR-виразах** або виводі декомпілятора після ізоляції точного обчислення.
- Явно використовуйте `--bitwidth`, якщо вираз походить від арифметики з маскуванням або вузьких регістрів.
- Якщо потрібен сильніший крок доведення, перегляньте локальні нотатки щодо Z3 тут:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA також постачається як **плагін проходу LLVM** (`libCobraPass.so`), що корисно, коли потрібно нормалізувати насичений MBA LLVM IR перед подальшими проходами аналізу.
- Непідтримувані залишкові вирази зі змішаними доменами, чутливі до переносу, слід розглядати як сигнал до збереження оригінального виразу та ручного аналізу шляху переносу.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Цей обфускатор замінює операції програми на послідовності інструкцій на основі `mov` і використовує обробку сигналів/винятків для зміни потоку виконання. Докладніше:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Для підтримуваних бінарних файлів [demovfuscator](https://github.com/kirschju/demovfuscator) може деобфускувати результат. Він має кілька залежностей.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
І [встановіть keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Якщо ви граєте в **CTF, цей обхідний спосіб для пошуку flag** може бути дуже корисним: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Щоб знайти **точку входу**, шукайте функції за `::main`, як у прикладі:

![Пошук точки входу Rust у Ghidra за назвами функцій із подвійною двокрапкою перед main](<../../images/image (1080).png>)

У цьому випадку binary називався authenticator, тому цілком очевидно, що це потрібна main-функція.\
Знаючи **назви** викликаних **функцій**, шукайте їх в **Internet**, щоб дізнатися про їхні **вхідні** та **вихідні дані**.

### Відновлення рядків Rust із ELF firmware

У binary **Rust ELF** багато статичних рядків не представлені як вказівники на рядки, завершені NUL, у стилі C. Поширений layout `rustc` — це **кортеж вказівника/довжини** всередині **`.data.rel.ro`**, що вказує на справжній blob рядка, збережений у **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Це означає, що `strings` або стандартний аналіз Ghidra може об’єднувати сусідні рядки або повністю пропускати перехресні посилання.<sup>[[3]](#references)</sup>

Швидкий робочий процес:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Отримайте віртуальну адресу та розмір **`.rodata`**.
2. Перерахуйте **`.data.rel.ro`** послівно.
3. Розглядайте будь-яке значення в діапазоні адрес `.rodata` як потенційний вказівник на рядок.
4. Розглядайте наступне слово як потенційну довжину.
5. Застосуйте фільтри перевірки коректності (наприклад, залишайте довжини від **4** до **100** байтів).
6. Зчитайте з `.rodata` рівно `length` байтів замість сканування до `0x00`.

Мінімальна логіка екстрактора:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Це особливо корисно під час firmware reversing, оскільки відновлені Rust strings часто розкривають **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers та auth-related logic**.

Якщо Ghidra не знаходить ці strings, запустіть custom script/plugin, який застосовує ту саму heuristic і створює string data за вказаними `.rodata` offsets. Опубліковані інструменти `rust-strings` і `RustStrings.py` від Pen Test Partners є хорошими прикладами для адаптації цієї ідеї до інших **word sizes, endianness і section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Для скомпільованих Delphi binaries можна використовувати [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Якщо потрібно виконати reverse engineering Delphi binary, рекомендую використовувати IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Натисніть **Alt+F7** в IDA, щоб завантажити Python plugin, а потім виберіть файл plugin.

Цей plugin запустить binary і динамічно визначить назви функцій на початку debugging. Після запуску debugging знову натисніть кнопку Start (зелену або f9), і breakpoint спрацює на початку реального коду.

Якщо натиснути кнопку в graphical application, debugger може зупинитися у функції, викликаній цією кнопкою.

## Golang

Якщо потрібно виконати reverse engineering Golang binary, рекомендую використовувати IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Натисніть **Alt+F7** в IDA, щоб завантажити Python plugin, а потім виберіть файл plugin.

Це визначить назви функцій.

## Скомпільований Python

На цій сторінці описано, як отримати Python code з ELF/EXE Python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Якщо ви отримали **binary** GBA game, можна використовувати різні інструменти для його **emulate** та **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Завантажте debug version_) - Містить debugger з interface
- [**mgba** ](https://mgba.io)- Містить CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

У [**no$gba**](https://problemkaputt.de/gba.htm), у _**Options --> Emulation Setup --> Controls**_** ** можна побачити, як натискати **buttons** Game Boy Advance

![Конфігурація керування no$gba, що показує відповідність кнопок Game Boy Advance](<../../images/image (581).png>)

Після натискання кожна **key має value**, за яким її можна ідентифікувати:
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
Отже, у такій програмі цікаво буде те, **як програма обробляє введені користувачем дані**. За адресою **0x4000130** ви знайдете поширену функцію: **KEYINPUT**.

![Вигляд Ghidra бінарного файлу GBA із посиланням на KEYINPUT за адресою 0x4000130](<../../images/image (447).png>)

На попередньому зображенні видно, що функція викликається з **FUN_080015a8** (адреси: _0x080015fa_ та _0x080017ac_).

У цій функції після кількох операцій init (які не мають значення):
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
Остання if перевіряє, чи міститься **`uVar4`** у **last Keys** і чи не є він поточним key; це також називається відпусканням кнопки (поточний key зберігається в **`uVar1`**).
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
У попередньому коді видно, що ми порівнюємо **uVar1** (місце, де знаходиться **value натиснутої кнопки**) з деякими значеннями:

- Спочатку воно порівнюється зі **значенням 4** (кнопка **SELECT**): у цьому завданні ця кнопка очищає екран
- Потім значення порівнюється з **8** (кнопка **START**); у цьому завданні цей шлях перевіряє, чи є введений code дійсним.
- У цьому випадку змінна **`DAT_030000d8`** порівнюється з 0xf3, і якщо значення збігається, виконується певний code.
- В усіх інших випадках перевіряється та збільшується лічильник (`DAT_030000d4`).\
Поки лічильник менший за 8, значення натиснутих клавіш накопичуються в `DAT_030000d8`.

Отже, у цьому завданні, знаючи значення кнопок, потрібно було **натиснути комбінацію довжиною меншою за 8, сума елементів якої дорівнює 0xf3.**

**Посилання на цей tutorial:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Курси

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Спрощення MBA obfuscation за допомогою CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Репозиторій Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Декодування рядків Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial з reversing для GBA (архів)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
