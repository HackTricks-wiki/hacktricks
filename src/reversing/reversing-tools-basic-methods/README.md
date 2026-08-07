# Інструменти реверсингу та базові методи

{{#include ../../banners/hacktricks-training.md}}

## Інструменти реверсингу на основі ImGui

Програмне забезпечення:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Декомпілятор Wasm / компілятор Wat

Онлайн:

- Використовуйте [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), щоб **декомпілювати** wasm (бінарний формат) у wat (звичайний текст)
- Використовуйте [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), щоб **компілювати** wat у wasm
- також можна спробувати використати [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) для декомпіляції

Програмне забезпечення:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Декомпілятор .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek — це декомпілятор, який **декомпілює та аналізує декілька форматів**, зокрема **бібліотеки** (.dll), **файли метаданих Windows** (.winmd) і **виконувані файли** (.exe). Після декомпіляції збірку можна зберегти як проєкт Visual Studio (.csproj).

Перевага полягає в тому, що якщо втрачений вихідний код потрібно відновити зі застарілої збірки, це може заощадити час. Крім того, dotPeek забезпечує зручну навігацію декомпільованим кодом, що робить його одним із найкращих інструментів для **аналізу алгоритмів Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Завдяки комплексній моделі add-in і API, яке розширює інструмент відповідно до ваших потреб, .NET Reflector заощаджує час і спрощує розробку. Розгляньмо численні можливості reverse engineering, які надає цей інструмент:

- Дає змогу зрозуміти, як дані проходять через бібліотеку або компонент
- Дає змогу зрозуміти реалізацію та використання мов і фреймворків .NET
- Знаходить недокументовані та недоступні функції, щоб отримати більше можливостей від API і використовуваних технологій.
- Знаходить залежності та різні збірки
- Визначає точне розташування помилок у вашому коді, сторонніх компонентах і бібліотеках.
- Дає змогу виконувати debug вихідного коду всього коду .NET, з яким ви працюєте.

### [ILSpy](https://github.com/icsharpcode/ILSpy) та [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Плагін ILSpy для Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): його можна використовувати в будь-якій ОС (його можна встановити безпосередньо з VSCode, завантажувати git не потрібно. Натисніть **Extensions** і **знайдіть ILSpy**).\
Якщо вам потрібно **декомпілювати**, **змінити** та знову **скомпілювати**, можна використати [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) або його активно підтримуваний fork — [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Клацніть правою кнопкою миші -> Modify Method**, щоб змінити щось усередині функції).

### Логування DNSpy

Щоб змусити **DNSpy записувати певну інформацію у файл**, можна використати цей snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Налагодження в DNSpy

Щоб налагодити code за допомогою DNSpy, потрібно:

Спочатку змініть **Assembly attributes**, пов’язані з **debugging**:

![DNSpy Logging - Налагодження в DNSpy: Спочатку змініть Assembly attributes, пов’язані з debugging](<../../images/image (973).png>)

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

Це необхідно, оскільки якщо цього не зробити, під час **runtime** до коду буде застосовано кілька **оптимізацій**, і може статися так, що під час налагодження **break-point ніколи не буде досягнуто** або деякі **змінні не існуватимуть**.

Потім, якщо ваш .NET-застосунок **запущено** через **IIS**, його можна **перезапустити** за допомогою:
```
iisreset /noforce
```
Потім, щоб почати debugging, слід закрити всі відкриті файли та у **Debug Tab** вибрати **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Потім, щоб почати debugging, слід закрити всі відкриті файли та у вкладці Debug вибрати Attach to Process](<../../images/image (318).png>)

Потім виберіть **w3wp.exe**, щоб під’єднатися до **IIS server**, і натисніть **attach**:

![DNSpy Logging - DNSpy Debugging: Потім виберіть w3wp.exe, щоб під’єднатися до IIS server, і натисніть attach](<../../images/image (113).png>)

Тепер, коли ми debugging процес, час зупинити його та завантажити всі модулі. Спочатку натисніть _Debug >> Break All_, а потім _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Тепер, коли ми debugging процес, час зупинити його та завантажити всі модулі. Спочатку натисніть Debug Break All, а потім Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Тепер, коли ми debugging процес, час зупинити його та завантажити всі модулі. Спочатку натисніть Debug Break All, а потім Debug Windows Modules](<../../images/image (834).png>)

Клацніть будь-який модуль у **Modules** і виберіть **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Клацніть будь-який модуль у Modules і виберіть Open All Modules](<../../images/image (922).png>)

Клацніть правою кнопкою миші будь-який модуль у **Assembly Explorer** і натисніть **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Клацніть правою кнопкою миші будь-який модуль у Assembly Explorer і натисніть Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Виберіть " Suspend on library load/unload "](<../../images/image (868).png>)

- Налаштуйте **parameters** виконання, вказавши **path to the DLL** і функцію, яку потрібно викликати:

![Debugging DLLs - Using IDA: Налаштуйте parameters виконання, вказавши path to the DLL і функцію, яку потрібно викликати](<../../images/image (704).png>)

Після цього, коли ви почнете debugging, **виконання буде зупинено щоразу, коли завантажується кожна DLL**, а коли rundll32 завантажить вашу DLL, виконання буде зупинено.

Але як отримати доступ до коду завантаженої DLL? За допомогою цього методу я не знаю як.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) і вкажіть path до dll та функцію, яку потрібно викликати, наприклад: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Змініть _Options --> Settings_ і виберіть "**DLL Entry**".
- Потім **start the execution**, і debugger зупинятиметься в кожній dll main; у певний момент ви **зупинитеся в dll Entry вашої dll**. Звідти просто знайдіть місця, у яких потрібно встановити breakpoint.

Зверніть увагу, що коли виконання з будь-якої причини зупинено у win64dbg, ви можете побачити, **у якому коді перебуваєте**, подивившись у **верхню частину вікна win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Зверніть увагу, що коли виконання з будь-якої причини зупинено у win64dbg, ви можете побачити, у якому коді перебуваєте, подивившись у верхню частину вікна win64dbg](<../../images/image (842).png>)

Так можна побачити, коли виконання було зупинено в dll, яку потрібно debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) — корисна програма для пошуку місць, де важливі значення зберігаються в пам’яті запущеної гри, та їхньої зміни. Більше інформації:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) — це front-end/reverse engineering tool для GNU Project Debugger (GDB), орієнтований на games. Однак його можна використовувати для будь-яких завдань, пов’язаних із reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) — це web front-end для низки decompilers. Цей web service дає змогу порівнювати результати роботи різних decompilers на невеликих executable-файлах.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **allocate** **shellcode** у ділянці пам’яті, **indicate** **memory address**, за якою було розміщено shellcode, і **stop** виконання.\
Потім потрібно **attach a debugger** (Ida або x64dbg) до процесу, встановити **breakpoint на вказаній memory address** і **resume** виконання. Таким чином ви debugging shellcode.

Сторінка github із releases містить zip-файли зі скомпільованими releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Трохи змінену версію Blobrunner можна знайти за наведеним нижче посиланням. Щоб скомпілювати її, просто **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) дуже схожий на blobrunner. Він **allocate** **shellcode** у ділянці пам’яті та запускає **eternal loop**. Потім потрібно **attach the debugger** до процесу, **play start wait 2-5 secs and press stop**, і ви опинитеся всередині **eternal loop**. Перейдіть до наступної інструкції eternal loop, оскільки це буде виклик shellcode, і зрештою ви почнете виконувати shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it дуже схожий на blobrunner. Він allocate shellcode у ділянці пам’яті та запускає...](<../../images/image (509).png>)

Скомпільовану версію [jmp2it можна завантажити на сторінці releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) — це GUI для radare. За допомогою Cutter можна емулювати shellcode та досліджувати його динамічно.

Зверніть увагу, що Cutter дає змогу **Open File** і **Open Shellcode**. У моєму випадку, коли я відкрив shellcode як file, він decompiled correctly, але коли я відкрив його як shellcode, цього не сталося:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Зверніть увагу, що Cutter дає змогу "Open File" і "Open Shellcode". У моєму випадку, коли я відкрив shellcode як file, він...](<../../images/image (562).png>)

Щоб почати emulation у потрібному місці, встановіть там bp, і, схоже, Cutter автоматично почне emulation із цього місця:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Щоб почати emulation у потрібному місці, встановіть там bp, і, схоже, Cutter автоматично почне emulation із цього місця](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Щоб почати emulation у потрібному місці, встановіть там bp, і, схоже, Cutter автоматично почне emulation із цього місця](<../../images/image (387).png>)

Наприклад, stack можна переглянути всередині hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Наприклад, stack можна переглянути всередині hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Спробуйте [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Він повідомить такі відомості, як **які функції** використовує shellcode і чи **decoding** він себе в пам’яті.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg також має графічний launcher, у якому можна вибрати потрібні параметри та виконати shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg також має графічний launcher, у якому можна вибрати потрібні параметри та...](<../../images/image (258).png>)

Опція **Create Dump** збереже фінальний shellcode, якщо під час виконання до shellcode динамічно вносилися зміни в пам'яті (корисно для завантаження декодованого shellcode). Параметр **start offset** може бути корисним для запуску shellcode з певного offset. Опція **Debug Shell** корисна для налагодження shellcode за допомогою термінала scDbg (однак для цього я вважаю кращими будь-які з описаних вище варіантів, оскільки ви зможете використовувати Ida або x64dbg).

### Дизасемблювання за допомогою CyberChef

Завантажте файл shellcode як вхідні дані та використайте наведений нижче recipe для його декомпіляції: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Деобфускація MBA-обфускації

Обфускація **Mixed Boolean-Arithmetic (MBA)** приховує прості вирази, як-от `x + y`, за формулами, що поєднують арифметичні (`+`, `-`, `*`) і побітові оператори (`&`, `|`, `^`, `~`, зсуви). Важливо, що ці тотожності зазвичай правильні лише в умовах **арифметики за модулем із фіксованою розрядністю**, тому перенесення та переповнення мають значення:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Якщо спростити такий вираз за допомогою загальних algebra tooling, можна легко отримати неправильний результат, оскільки семантику bit-width було проігноровано.<sup>[[1]](#references)</sup>

### Практичний workflow

1. **Зберігайте початкову bit-width** із lifted code/IR/decompiler output (`8/16/32/64` бітів).
2. **Класифікуйте вираз** перед спробою його спростити:
- **Linear**: зважені суми bitwise atoms
- **Semilinear**: linear плюс constant masks, такі як `x & 0xFF`
- **Polynomial**: присутні добутки
- **Mixed**: добутки та bitwise logic чергуються, часто з повторюваними subexpressions
3. **Перевіряйте кожне candidate rewrite** за допомогою random testing або SMT proof. Якщо еквівалентність неможливо довести, залишайте початковий вираз замість припущень.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) — це практичний MBA simplifier для malware analysis і protected-binary reversing. Він класифікує вираз і спрямовує його через спеціалізовані pipelines замість застосування одного загального rewrite pass до всього.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA обчислює вираз на Boolean inputs, виводить signature і запускає кілька методів відновлення, як-от pattern matching, ANF conversion та coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms перебудовуються за допомогою реконструкції з розподілом за бітами, щоб замасковані області залишалися коректними.
- **Polynomial/Mixed MBA**: добутки розкладаються на cores, а повторювані підвирази можна винести у temporaries перед спрощенням зовнішнього співвідношення.

Приклад mixed identity, яку зазвичай варто спробувати відновити:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Це можна звести до:
```c
x * y
```
### Нотатки з реверсингу

- Надавайте перевагу запуску CoBRA на **піднятих IR-виразах** або виводі decompiler після ізоляції точного обчислення.
- Явно використовуйте `--bitwidth`, якщо вираз походить від masked arithmetic або вузьких регістрів.
- Якщо потрібен сильніший крок доведення, перегляньте локальні нотатки щодо Z3 тут:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA також постачається як **плагін pass для LLVM** (`libCobraPass.so`), що корисно, коли потрібно нормалізувати насичений MBA LLVM IR перед подальшими проходами аналізу.
- Непідтримувані залишкові вирази зі змішаними доменами, чутливі до переносу, слід розглядати як сигнал до збереження оригінального виразу та ручного аналізу шляху переносу.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Цей obfuscator **модифікує всі інструкції для `mov`** (так, справді круто). Він також використовує переривання для зміни потоків виконання. Докладніше про принцип його роботи:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Якщо вам пощастить, [demovfuscator](https://github.com/kirschju/demovfuscator) деобфускує binary. Він має кілька залежностей
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
І [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Якщо ви граєте в **CTF, цей workaround для пошуку flag** може бути дуже корисним: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Щоб знайти **entry point**, виконайте пошук функцій за `::main`, як показано нижче:

![Movfuscator - Rust: Щоб знайти entry point, виконайте пошук функцій за ::main, як показано нижче](<../../images/image (1080).png>)

У цьому випадку бінарний файл називався authenticator, тому цілком очевидно, що це цікава main-функція.\
Знаючи **назви** викликаних **функцій**, шукайте їх в **Інтернеті**, щоб дізнатися про їхні **вхідні** та **вихідні дані**.

### Відновлення рядків Rust з ELF firmware

У бінарних файлах **Rust ELF** багато статичних рядків не представлені як вказівники на рядки у стилі C, завершені NUL. Поширений формат `rustc` — це кортеж pointer/length усередині **`.data.rel.ro`**, який вказує на справжній блок рядків, що зберігається в **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Це означає, що `strings` або стандартний аналіз Ghidra може об'єднати суміжні рядки чи взагалі пропустити перехресні посилання.<sup>[[3]](#references)</sup>

Швидкий робочий процес:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Отримайте віртуальну адресу та розмір **`.rodata`**.
2. Перерахуйте **`.data.rel.ro`** по одному слову.
3. Розглядайте будь-яке значення в діапазоні адрес `.rodata` як кандидат на вказівник на рядок.
4. Розглядайте наступне слово як кандидат на довжину.
5. Застосуйте sanity-фільтри (наприклад, залишайте довжини від **4** до **100** байтів).
6. Зчитуйте з `.rodata` рівно `length` байтів замість сканування до `0x00`.

Мінімальна логіка екстрактора:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Це особливо корисно під час reversing firmware, оскільки відновлені Rust strings часто розкривають **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers і auth-related logic**.

Якщо Ghidra не знаходить такі strings, запустіть custom script/plugin, який застосовує ту саму heuristic і створює string data за вказаними `.rodata` offsets. Опубліковані інструменти `rust-strings` і `RustStrings.py` від Pen Test Partners є хорошими reference для адаптації цієї ідеї до інших **word sizes, endianness і section layouts**.<sup>[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Для Delphi compiled binaries можна використати [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Якщо потрібно виконати reverse engineering Delphi binary, рекомендую використати IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Просто натисніть **ATL+f7** (імпорт python plugin в IDA) і виберіть python plugin.

Цей plugin запустить binary і динамічно визначить імена функцій на початку debugging. Після початку debugging знову натисніть кнопку Start (зелену або f9), і breakpoint спрацює на початку реального коду.

Це також дуже цікаво, оскільки якщо натиснути кнопку в графічному застосунку, debugger зупиниться у функції, яка виконується цією кнопкою.

## Golang

Якщо потрібно виконати reverse engineering Golang binary, рекомендую використати IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Просто натисніть **ATL+f7** (імпорт python plugin в IDA) і виберіть python plugin.

Це визначить імена функцій.

## Compiled Python

На цій сторінці описано, як отримати python code з ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Якщо ви отримали **binary** GBA game, можна використати різні інструменти для його **emulate** і **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Завантажте debug version_) - Містить debugger з interface
- [**mgba** ](https://mgba.io)- Містить CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

У [**no$gba**](https://problemkaputt.de/gba.htm), у _**Options --> Emulation Setup --> Controls**_** ** можна переглянути, як натискати **buttons** Game Boy Advance

![конфігурація керування no$gba із відображенням кнопок Game Boy Advance](<../../images/image (581).png>)

Після натискання кожна **key has a value**, за яким її можна ідентифікувати:
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
Знайдено цей код:
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
Остання умова **`if`** перевіряє, чи є **`uVar4`** в **last Keys**, але не є поточною клавішею; це також називається відпусканням кнопки (поточна клавіша зберігається в **`uVar1`**).
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
У попередньому коді видно, що ми порівнюємо **uVar1** (місце, де знаходиться **значення натиснутої кнопки**) з деякими значеннями:

- Спочатку воно порівнюється зі **значенням 4** (кнопка **SELECT**): у challenge ця кнопка очищає екран
- Потім воно порівнюється зі **значенням 8** (кнопка **START**): у challenge це перевіряє, чи є код дійсним для отримання flag.
- У цьому випадку var **`DAT_030000d8`** порівнюється з 0xf3, і якщо значення збігається, виконується певний код.
- В усіх інших випадках перевіряється певний лічильник (`DAT_030000d4`). Це лічильник, оскільки одразу після введення коду до нього додається 1.\
**Я**кщо його значення менше 8, виконується певна операція, що включає **додавання** значень до **`DAT_030000d8`** (по суті, значення натиснутих клавіш додаються до цієї змінної, доки лічильник менший за 8).

Отже, у цьому challenge, знаючи значення кнопок, потрібно було **натиснути комбінацію довжиною менше 8, сума якої дорівнює 0xf3.**

**Reference for this tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
