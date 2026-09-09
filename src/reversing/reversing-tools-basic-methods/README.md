# Інструменти reversing і базові методи

{{#include ../../banners/hacktricks-training.md}}

## Інструменти reversing на базі ImGui

Програмне забезпечення:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Декомпілятор Wasm / компілятор Wat

Онлайн:

- Використовуйте [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), щоб **декомпілювати** wasm (бінарний формат) у wat (текстовий формат)
- Використовуйте [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), щоб **скомпілювати** wat у wasm
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

dotPeek — це декомпілятор, який **декомпілює та аналізує декілька форматів**, зокрема **бібліотеки** (.dll), **файли метаданих Windows** (.winmd) та **виконувані файли** (.exe). Після декомпіляції збірку можна зберегти як проєкт Visual Studio (.csproj).

Перевага полягає в тому, що якщо втрачений вихідний код потрібно відновити зі застарілої збірки, це може заощадити час. Крім того, dotPeek забезпечує зручну навігацію декомпільованим кодом, що робить його одним із найкращих інструментів для **аналізу алгоритмів Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Завдяки комплексній моделі add-in та API, яке розширює інструмент відповідно до ваших потреб, .NET Reflector заощаджує час і спрощує розробку. Розгляньмо численні можливості reverse engineering, які надає цей інструмент:

- Дає змогу зрозуміти, як дані проходять через бібліотеку або компонент
- Дає змогу зрозуміти реалізацію та використання мов і фреймворків .NET
- Знаходить недокументовану та недоступну функціональність, щоб отримати більше можливостей від використовуваних API і технологій.
- Знаходить залежності та різні збірки
- Визначає точне розташування помилок у вашому коді, сторонніх компонентах і бібліотеках.
- Виконує debug вихідного коду всього коду .NET, з яким ви працюєте.

### [ILSpy](https://github.com/icsharpcode/ILSpy) та [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Плагін ILSpy для Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): його можна використовувати в будь-якій OS (його можна встановити безпосередньо з VSCode, не потрібно завантажувати git. Натисніть **Extensions** і **знайдіть ILSpy**).\
Якщо вам потрібно **декомпілювати**, **змінити** та знову **скомпілювати**, можна використати [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) або його fork, який активно підтримується, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Клацніть правою кнопкою миші -> Modify Method**, щоб змінити щось усередині функції).

### Логування DNSpy

Щоб **DNSpy записував певну інформацію у файл**, можна використати цей фрагмент:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Налагодження в DNSpy

Щоб налагоджувати code за допомогою DNSpy, потрібно:

Спочатку змініть **атрибути Assembly**, пов’язані з **налагодженням**:

![DNSpy Logging - DNSpy Debugging: Спочатку змініть атрибути Assembly, пов’язані з налагодженням](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Потім збережіть новий файл через _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Це необхідно, оскільки в іншому разі під час **runtime** до коду буде застосовано кілька **оптимізацій**, і може статися так, що під час налагодження **break-point ніколи не буде досягнуто** або деякі **змінні не існуватимуть**.

Потім, якщо ваш .NET-застосунок **запущено** через **IIS**, його можна **перезапустити** за допомогою:
```
iisreset /noforce
```
Потім, щоб почати debugging, слід закрити всі відкриті файли та всередині **Debug Tab** вибрати **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Потім, щоб почати debugging, слід закрити всі відкриті файли та всередині вкладки Debug вибрати Attach to Process](<../../images/image (318).png>)

Потім виберіть **w3wp.exe**, щоб під’єднатися до **IIS server**, і натисніть **attach**:

![DNSpy Logging - DNSpy Debugging: Потім виберіть w3wp.exe, щоб під’єднатися до IIS server, і натисніть attach](<../../images/image (113).png>)

Тепер, коли ми debugging process, настав час зупинити його та завантажити всі модулі. Спочатку натисніть _Debug >> Break All_, а потім _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Тепер, коли ми debugging process, настав час зупинити його та завантажити всі модулі. Спочатку натисніть Debug Break All, а потім Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Тепер, коли ми debugging process, настав час зупинити його та завантажити всі модулі. Спочатку натисніть Debug Break All, а потім Debug Windows Modules](<../../images/image (834).png>)

Натисніть будь-який модуль у **Modules** і виберіть **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Натисніть будь-який модуль у Modules і виберіть Open All Modules](<../../images/image (922).png>)

Клацніть правою кнопкою миші будь-який модуль в **Assembly Explorer** і натисніть **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Клацніть правою кнопкою миші будь-який модуль в Assembly Explorer і натисніть Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Використання IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Виберіть **Windbg** debugger
- Виберіть "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Виберіть " Suspend on library load/unload "](<../../images/image (868).png>)

- Налаштуйте **parameters** виконання, вказавши **path to the DLL** і функцію, яку потрібно викликати:

![Debugging DLLs - Using IDA: Налаштуйте parameters виконання, вказавши path to the DLL і функцію, яку потрібно викликати](<../../images/image (704).png>)

Потім, коли ви почнете debugging, **виконання буде зупинено під час завантаження кожної DLL**, а коли rundll32 завантажить вашу DLL, виконання буде зупинено.

Цей метод зупиняється на подіях завантаження модулів, але досягнення entry point завантаженої DLL є менш прямим, ніж у наведеному нижче workflow для x64dbg.

### Використання x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) і вкажіть path до dll та функцію, яку потрібно викликати, наприклад: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Змініть _Options --> Settings_ і виберіть "**DLL Entry**".
- Потім **start the execution**, debugger зупинятиметься на кожному dll main, і в певний момент ви **зупинитеся на dll Entry вашої dll**. Після цього просто знайдіть місця, де потрібно встановити breakpoint.

Зверніть увагу, що коли виконання зупинено з будь-якої причини у win64dbg, ви можете побачити, **у якому коді перебуваєте**, подивившись **у верхній частині вікна win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Зверніть увагу, що коли виконання зупинено з будь-якої причини у win64dbg, ви можете побачити, у якому коді перебуваєте, у верхній частині вікна win64dbg](<../../images/image (842).png>)

Цей індикатор підтверджує, що виконання зупинилося всередині DLL, яку ви хочете debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) — корисна програма для пошуку місць, де важливі значення зберігаються в пам’яті запущеної гри, і їх зміни. Більше інформації:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) — front-end/reverse engineering tool для GNU Project Debugger (GDB), орієнтований на ігри. Однак його можна використовувати для будь-яких завдань, пов’язаних із reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) — web front-end для низки decompiler. Цей web service дає змогу порівнювати результати різних decompiler на невеликих executable.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging shellcode за допомогою blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) виділяє **shellcode**, виводить його **memory address** і призупиняє виконання.\
Під’єднайте debugger, наприклад IDA або x64dbg, встановіть breakpoint за виведеною адресою та відновіть виконання, щоб debug shellcode.

На github page релізів містяться zip-файли зі скомпільованими релізами: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Трохи змінену версію Blobrunner можна знайти за наведеним нижче посиланням. Щоб скомпілювати її, просто **створіть C/C++ project у Visual Studio Code, скопіюйте та вставте код і виконайте build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging shellcode за допомогою jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) працює подібно до BlobRunner. Він виділяє shellcode і входить у нескінченний loop. Під’єднайте debugger, відновіть виконання на **2–5 секунд**, призупиніть його всередині цього loop і виконайте step до наступного call, який передає виконання виділеному shellcode.

![Debugger paused in jmp2it's infinite loop immediately before the call to the allocated shellcode](<../../images/image (509).png>)

Ви можете завантажити скомпільовану версію [jmp2it на сторінці релізів](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode за допомогою Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) — це GUI для radare. За допомогою Cutter можна емулювати shellcode і досліджувати його динамічно.

Зверніть увагу, що Cutter дає змогу використовувати **Open File** і **Open Shellcode**. У моєму випадку, коли я відкрив shellcode як файл, він правильно декомпілювався, але коли я відкрив його як shellcode, цього не сталося:

![Cutter showing different analysis results when opening the same bytes as a file or as shellcode](<../../images/image (562).png>)

Щоб почати емуляцію в потрібному місці, встановіть там bp, і, схоже, Cutter автоматично почне емуляцію з цього місця:

![Setting a breakpoint at the desired shellcode entry before starting Cutter emulation](<../../images/image (589).png>)

![Cutter emulator paused at the selected shellcode breakpoint](<../../images/image (387).png>)

Наприклад, ви можете переглянути stack усередині hex dump:

![Viewing the emulated shellcode stack in Cutter's hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Спробуйте [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Він повідомить такі відомості, як **які функції** використовує shellcode і чи **декодує** shellcode себе в пам’яті.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg також має графічний launcher, де можна вибрати потрібні опції та виконати shellcode

![Графічний launcher scDbg для вибору опцій емуляції та трасування shellcode](<../../images/image (258).png>)

Опція **Create Dump** збереже фінальний shellcode, якщо під час виконання до shellcode динамічно вносилися зміни в пам'яті (корисно для завантаження декодованого shellcode). **start offset** може бути корисним для запуску shellcode із певного offset. Опція **Debug Shell** корисна для debug shellcode за допомогою термінала scDbg (однак я вважаю, що будь-яка з описаних вище опцій підходить для цього краще, оскільки ви зможете використовувати Ida або x64dbg).

### Disassembling за допомогою CyberChef

Завантажте файл shellcode як input і використайте наступний recipe, щоб декомпілювати його: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation приховує прості вирази, такі як `x + y`, за формулами, що поєднують арифметичні (`+`, `-`, `*`) і побітові оператори (`&`, `|`, `^`, `~`, зсуви). Важливо, що ці тотожності зазвичай правильні лише в умовах **модульної арифметики з фіксованою розрядністю**, тому переноси та переповнення мають значення:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Якщо спростити такий вираз за допомогою універсальних алгебраїчних інструментів, можна легко отримати неправильний результат, оскільки семантику розрядності було проігноровано.<sup>[[1]](#references)</sup>

### Практичний робочий процес

1. **Зберігайте початкову розрядність** із піднятого коду/IR/виводу decompiler (`8/16/32/64` бітів).
2. **Класифікуйте вираз** перед спробою його спростити:
- **Лінійний**: зважені суми побітових атомів
- **Напівлінійний**: лінійний вираз плюс константні маски, такі як `x & 0xFF`
- **Поліноміальний**: наявні добутки
- **Змішаний**: добутки та побітова логіка чергуються, часто з повторюваними підвиразами
3. **Перевіряйте кожне потенційне перетворення** за допомогою random testing або SMT-доведення. Якщо еквівалентність неможливо довести, залиште початковий вираз замість припущень.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) — практичний MBA simplifier для аналізу malware та reversing захищених бінарних файлів. Він класифікує вираз і спрямовує його через спеціалізовані pipeline замість застосування одного універсального проходу перезапису до всього.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA обчислює вираз на Boolean inputs, виводить сигнатуру та запускає наввипередки кілька методів відновлення, зокрема зіставлення шаблонів, перетворення в ANF і інтерполяцію коефіцієнтів.
- **Semilinear MBA**: атоми з constant mask відновлюються за допомогою реконструкції з розбиттям на біти, тому замасковані ділянки залишаються коректними.
- **Polynomial/Mixed MBA**: добутки розкладаються на ядра, а повторювані підвирази можна винести у temporaries перед спрощенням зовнішнього співвідношення.

Приклад змішаної тотожності, яку часто варто спробувати відновити:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Це можна звести до:
```c
x * y
```
### Нотатки з реверсингу

- Надавайте перевагу запуску CoBRA на **lifted IR expressions** або виводі decompiler після ізоляції точної операції.
- Явно використовуйте `--bitwidth`, коли expression походить від masked arithmetic або вузьких регістрів.
- Якщо потрібен сильніший крок доведення, перегляньте локальні нотатки щодо Z3 тут:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA також постачається як **LLVM pass plugin** (`libCobraPass.so`), що корисно, коли потрібно нормалізувати насичений MBA LLVM IR перед подальшими етапами аналізу.
- Непідтримувані залишкові вирази зі змішаними доменами, чутливі до перенесення, слід розглядати як сигнал зберегти оригінальний expression і вручну проаналізувати шлях перенесення.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Цей obfuscator замінює операції програми на послідовності інструкцій на основі `mov` і використовує обробку сигналів/винятків для зміни control flow. Детальніше:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Для підтримуваних бінарників [demovfuscator](https://github.com/kirschju/demovfuscator) може деобфускувати результат. Він має кілька залежностей.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
І [встановіть keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Якщо ви граєте в **CTF, цей спосіб пошуку flag** може бути дуже корисним: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Щоб знайти **entry point**, шукайте функції за `::main`, як показано нижче:

![Пошук entry point Rust у Ghidra за назвами функцій із подвійною двокрапкою перед main](<../../images/image (1080).png>)

У цьому випадку binary називався authenticator, тож досить очевидно, що це потрібна main-функція.\
Знаючи **назви** **функцій**, які викликаються, шукайте їх в **Internet**, щоб дізнатися про їхні **вхідні** та **вихідні дані**.

### Відновлення рядків Rust із ELF firmware

У binary **Rust ELF** багато статичних рядків не представлені як вказівники у стилі C із завершенням NUL. Поширений layout `rustc` містить кортеж **вказівник/довжина** всередині **`.data.rel.ro`**, який вказує на фактичний blob рядків, що зберігається в **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Це означає, що `strings` або стандартний аналіз Ghidra можуть об’єднати суміжні рядки або повністю пропустити перехресні посилання.<sup>[[3]](#references)</sup>

Швидкий робочий процес:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Отримайте віртуальну адресу та розмір **`.rodata`**.
2. Перерахуйте **`.data.rel.ro`** по одному слову.
3. Розглядайте будь-яке значення в діапазоні адрес `.rodata` як кандидат на вказівник на рядок.
4. Розглядайте наступне слово як кандидат на довжину.
5. Застосуйте фільтри перевірки коректності (наприклад, залишайте довжини від **4** до **100** байтів).
6. Зчитайте з `.rodata` рівно `length` байтів замість сканування до `0x00`.

Мінімальна логіка extractor:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Це особливо корисно під час reverse engineering firmware, оскільки відновлені рядки Rust часто розкривають **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers та auth-related logic**.

Якщо Ghidra не знаходить ці рядки, запустіть custom script/plugin, який застосовує ту саму heuristic і створює string data за вказаними offsets у `.rodata`. Опубліковані інструменти `rust-strings` і `RustStrings.py` від Pen Test Partners є хорошими прикладами для адаптації цієї ідеї до інших **word sizes, endianness та section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Для Delphi compiled binaries можна використовувати [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Якщо потрібно виконати reverse engineering Delphi binary, рекомендую використовувати IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Натисніть **Alt+F7** в IDA, щоб завантажити Python plugin, а потім виберіть файл plugin.

Цей plugin запустить binary і динамічно визначить назви функцій на початку debugging. Після запуску debugging знову натисніть кнопку Start (зелену або f9), і breakpoint спрацює на початку реального коду.

Якщо натиснути кнопку в graphical application, debugger може зупинитися у функції, викликаній цією кнопкою.

## Golang

Якщо потрібно виконати reverse engineering Golang binary, рекомендую використовувати IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Натисніть **Alt+F7** в IDA, щоб завантажити Python plugin, а потім виберіть файл plugin.

Це визначить назви функцій.

## Compiled Python

На цій сторінці можна знайти інформацію про отримання python-коду з ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Якщо ви отримали **binary** гри для GBA, можна використовувати різні інструменти для її **emulate** та **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Завантажте debug-версію_) - Містить debugger з інтерфейсом
- [**mgba** ](https://mgba.io)- Містить CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

У [**no$gba**](https://problemkaputt.de/gba.htm), у _**Options --> Emulation Setup --> Controls**_** ** можна побачити, як натискати **buttons** Game Boy Advance

![конфігурація керування no$gba з відображенням кнопок Game Boy Advance](<../../images/image (581).png>)

Після натискання кожна **key має значення**, яке її ідентифікує:
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
Останній `if` перевіряє, чи міститься **`uVar4`** в **останньому наборі Keys** і чи це не поточний key; це також називають відпусканням кнопки (поточний key зберігається в **`uVar1`**).
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

- Спочатку воно порівнюється зі **значенням 4** (кнопка **SELECT**): у цьому challenge ця кнопка очищає екран
- Потім значення порівнюється з **8** (кнопка **START**); у цьому challenge цей шлях перевіряє, чи є введений код дійсним.
- У цьому випадку змінна **`DAT_030000d8`** порівнюється з 0xf3, і якщо значення збігається, виконується певний код.
- В усіх інших випадках перевіряється та збільшується лічильник (`DAT_030000d4`).\
Поки лічильник менший за 8, значення натиснутих клавіш накопичуються в `DAT_030000d8`.

Отже, у цьому challenge, знаючи значення кнопок, потрібно було **натиснути комбінацію довжиною менше 8, сума якої дорівнює 0xf3.**

**Джерело для цього tutorial:** [архівований writeup Nostalgia challenge](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Курси

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (бінарна деобфускація)

## References

- [1] [Спрощення MBA-обфускації за допомогою CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Репозиторій Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Декодування рядків Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial з reversing для GBA (архівований)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
