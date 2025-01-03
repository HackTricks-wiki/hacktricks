# Інструменти реверсування та основні методи

{{#include ../../banners/hacktricks-training.md}}

## Інструменти реверсування на базі ImGui

Програмне забезпечення:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Декомпіллятор Wasm / Компилятор Wat

Онлайн:

- Використовуйте [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) для **декомпілляції** з wasm (бінарний) в wat (чистий текст)
- Використовуйте [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) для **компіляції** з wat в wasm
- ви також можете спробувати використовувати [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) для декомпілляції

Програмне забезпечення:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Декомпіллятор .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek - це декомпіллятор, який **декомпіллює та аналізує кілька форматів**, включаючи **бібліотеки** (.dll), **файли метаданих Windows** (.winmd) та **виконувані файли** (.exe). Після декомпілляції збірка може бути збережена як проект Visual Studio (.csproj).

Перевага полягає в тому, що якщо втраченому вихідному коду потрібно відновлення з застарілої збірки, ця дія може заощадити час. Крім того, dotPeek забезпечує зручну навігацію по декомпільованому коду, що робить його одним з ідеальних інструментів для **аналізу алгоритмів Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

З комплексною моделлю додатків та API, який розширює інструмент відповідно до ваших точних потреб, .NET Reflector заощаджує час і спрощує розробку. Давайте розглянемо безліч послуг з реверсного інжинірингу, які надає цей інструмент:

- Надає уявлення про те, як дані проходять через бібліотеку або компонент
- Надає уявлення про реалізацію та використання мов і фреймворків .NET
- Знаходить не задокументовану та не виставлену функціональність, щоб отримати більше з API та технологій, що використовуються.
- Знаходить залежності та різні збірки
- Відстежує точне місце помилок у вашому коді, сторонніх компонентах та бібліотеках.
- Відлагоджує до джерела всього коду .NET, з яким ви працюєте.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Плагін ILSpy для Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Ви можете мати його в будь-якій ОС (ви можете встановити його безпосередньо з VSCode, немає потреби завантажувати git. Натисніть на **Розширення** та **пошук ILSpy**).\
Якщо вам потрібно **декомпіллювати**, **модифікувати** та **знову компілювати**, ви можете використовувати [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) або активно підтримуваний форк, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Правий клік -> Модифікувати метод**, щоб змінити щось всередині функції).

### Логування DNSpy

Щоб **DNSpy записував деяку інформацію в файл**, ви можете використовувати цей фрагмент:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Щоб налагодити код за допомогою DNSpy, вам потрібно:

По-перше, змініть **атрибути збірки**, пов'язані з **налагодженням**:

![](<../../images/image (973).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
На:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
І натисніть на **compile**:

![](<../../images/image (314) (1).png>)

Потім збережіть новий файл через _**File >> Save module...**_:

![](<../../images/image (602).png>)

Це необхідно, оскільки якщо ви цього не зробите, під час **runtime** до коду буде застосовано кілька **optimisations**, і може статися так, що під час налагодження **break-point ніколи не буде досягнуто** або деякі **змінні не існують**.

Потім, якщо ваша .NET програма виконується через **IIS**, ви можете **перезапустити** її за допомогою:
```
iisreset /noforce
```
Тоді, щоб почати налагодження, вам слід закрити всі відкриті файли і в **Debug Tab** вибрати **Attach to Process...**:

![](<../../images/image (318).png>)

Потім виберіть **w3wp.exe**, щоб підключитися до **IIS server** і натисніть **attach**:

![](<../../images/image (113).png>)

Тепер, коли ми налагоджуємо процес, час зупинити його і завантажити всі модулі. Спочатку натисніть на _Debug >> Break All_, а потім натисніть на _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Натисніть на будь-який модуль у **Modules** і виберіть **Open All Modules**:

![](<../../images/image (922).png>)

Клацніть правою кнопкою миші на будь-якому модулі в **Assembly Explorer** і натисніть **Sort Assemblies**:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Налагодження DLL

### Використання IDA

- **Завантажте rundll32** (64 біти в C:\Windows\System32\rundll32.exe і 32 біти в C:\Windows\SysWOW64\rundll32.exe)
- Виберіть **Windbg** налагоджувач
- Виберіть "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Налаштуйте **параметри** виконання, вказавши **шлях до DLL** і функцію, яку ви хочете викликати:

![](<../../images/image (704).png>)

Тоді, коли ви почнете налагодження, **виконання буде зупинено, коли кожна DLL завантажується**, потім, коли rundll32 завантажить вашу DLL, виконання буде зупинено.

Але як ви можете дістатися до коду DLL, яка була завантажена? Використовуючи цей метод, я не знаю як.

### Використання x64dbg/x32dbg

- **Завантажте rundll32** (64 біти в C:\Windows\System32\rundll32.exe і 32 біти в C:\Windows\SysWOW64\rundll32.exe)
- **Змініть командний рядок** (_File --> Change Command Line_) і встановіть шлях до dll і функцію, яку ви хочете викликати, наприклад: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Змініть _Options --> Settings_ і виберіть "**DLL Entry**".
- Потім **почніть виконання**, налагоджувач зупиниться на кожному основному dll, в якийсь момент ви **зупинитеся на вході dll вашої dll**. Звідти просто шукайте точки, де ви хочете поставити точку зупинки.

Зверніть увагу, що коли виконання зупинено з будь-якої причини в win64dbg, ви можете побачити **в якому коді ви** знаходитесь, подивившись на **верхній частині вікна win64dbg**:

![](<../../images/image (842).png>)

Тоді, дивлячись на це, ви можете побачити, коли виконання було зупинено в dll, яку ви хочете налагоджувати.

## GUI Apps / Відеоігри

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) - це корисна програма для знаходження місць, де важливі значення зберігаються в пам'яті працюючої гри, і їх зміни. Більше інформації в:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) - це фронт-енд/інструмент реверс-інжинірингу для GNU Project Debugger (GDB), зосереджений на іграх. Однак його можна використовувати для будь-яких завдань, пов'язаних з реверс-інжинірингом.

[**Decompiler Explorer**](https://dogbolt.org/) - це веб-фронт-енд для кількох декомпіляторів. Ця веб-служба дозволяє вам порівнювати вихідні дані різних декомпіляторів на малих виконуваних файлах.

## ARM & MIPS

{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Налагодження shellcode з blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **виділить** **shellcode** в області пам'яті, **вкаже** вам **адресу пам'яті**, де був виділений shellcode, і **зупинить** виконання.\
Потім вам потрібно **підключити налагоджувач** (Ida або x64dbg) до процесу і поставити **точку зупинки на вказаній адресі пам'яті** і **продовжити** виконання. Таким чином, ви будете налагоджувати shellcode.

Сторінка релізів на github містить zip-архіви з компільованими релізами: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Ви можете знайти трохи модифіковану версію Blobrunner за наступним посиланням. Щоб скомпілювати її, просто **створіть проект C/C++ у Visual Studio Code, скопіюйте та вставте код і збудуйте його**.

{{#ref}}
blobrunner.md
{{#endref}}

### Налагодження shellcode з jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) дуже схожий на blobrunner. Він **виділить** **shellcode** в області пам'яті і запустить **вічний цикл**. Вам потрібно **підключити налагоджувач** до процесу, **натиснути старт, почекати 2-5 секунд і натиснути стоп**, і ви опинитеся всередині **вічного циклу**. Перейдіть до наступної інструкції вічного циклу, оскільки це буде виклик до shellcode, і врешті-решт ви опинитеся виконуючи shellcode.

![](<../../images/image (509).png>)

Ви можете завантажити скомпільовану версію [jmp2it на сторінці релізів](https://github.com/adamkramer/jmp2it/releases/).

### Налагодження shellcode за допомогою Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) - це GUI для radare. Використовуючи cutter, ви можете емуляціювати shellcode і динамічно його перевіряти.

Зверніть увагу, що Cutter дозволяє вам "Відкрити файл" і "Відкрити shellcode". У моєму випадку, коли я відкрив shellcode як файл, він декомпілював його правильно, але коли я відкрив його як shellcode, він цього не зробив:

![](<../../images/image (562).png>)

Щоб почати емуляцію в потрібному вам місці, встановіть там точку зупинки, і, очевидно, cutter автоматично почне емуляцію з цього місця:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Ви можете бачити стек, наприклад, всередині шістнадцяткового дампу:

![](<../../images/image (186).png>)

### Деобфускація shellcode і отримання виконуваних функцій

Вам слід спробувати [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Він скаже вам такі речі, як **які функції** використовує shellcode і чи **декодує** shellcode сам себе в пам'яті.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg також має графічний лаунчер, де ви можете вибрати потрібні опції та виконати shellcode

![](<../../images/image (258).png>)

Опція **Create Dump** створить дамп фінального shellcode, якщо в shellcode будуть внесені зміни динамічно в пам'яті (корисно для завантаження декодованого shellcode). **start offset** може бути корисним для початку shellcode з конкретного зсуву. Опція **Debug Shell** корисна для налагодження shellcode за допомогою терміналу scDbg (однак я вважаю, що будь-яка з раніше пояснених опцій краща для цього, оскільки ви зможете використовувати Ida або x64dbg).

### Дизасемблювання за допомогою CyberChef

Завантажте файл вашого shellcode як вхідні дані та використовуйте наступний рецепт для декомпіляції: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Цей обфускатор **модифікує всі інструкції для `mov`** (так, дійсно круто). Він також використовує переривання для зміни потоків виконання. Для отримання додаткової інформації про те, як це працює:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Якщо вам пощастить, [demovfuscator](https://github.com/kirschju/demovfuscator) розобфускує бінарний файл. Він має кілька залежностей
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
І [встановіть keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Якщо ви граєте в **CTF, це обхідний шлях для знаходження прапора** може бути дуже корисним: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Щоб знайти **точку входу**, шукайте функції за `::main`, як у:

![](<../../images/image (1080).png>)

У цьому випадку бінарний файл називався authenticator, тому очевидно, що це цікава основна функція.\
Маючи **назви** викликаних **функцій**, шукайте їх в **Інтернеті**, щоб дізнатися про їх **вхідні** та **вихідні** дані.

## **Delphi**

Для скомпільованих бінарних файлів Delphi ви можете використовувати [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Якщо вам потрібно зворотно інженерити бінарний файл Delphi, я б порадив використовувати плагін IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Просто натисніть **ATL+f7** (імпортувати плагін python в IDA) і виберіть плагін python.

Цей плагін виконає бінарний файл і динамічно розв'яже назви функцій на початку налагодження. Після початку налагодження знову натисніть кнопку Start (зелену або f9), і точка зупинки спрацює на початку реального коду.

Це також дуже цікаво, тому що якщо ви натиснете кнопку в графічному додатку, налагоджувач зупиниться на функції, виконуваній цією кнопкою.

## Golang

Якщо вам потрібно зворотно інженерити бінарний файл Golang, я б порадив використовувати плагін IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Просто натисніть **ATL+f7** (імпортувати плагін python в IDA) і виберіть плагін python.

Це розв'яже назви функцій.

## Скомпільований Python

На цій сторінці ви можете знайти, як отримати код python з ELF/EXE скомпільованого бінарного файлу python:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Якщо ви отримали **бінарний файл** гри GBA, ви можете використовувати різні інструменти для **емуляції** та **налагодження**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Завантажте версію для налагодження_) - Містить налагоджувач з інтерфейсом
- [**mgba** ](https://mgba.io)- Містить CLI налагоджувач
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Плагін Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Плагін Ghidra

У [**no$gba**](https://problemkaputt.de/gba.htm), у _**Options --> Emulation Setup --> Controls**_\*\* \*\* ви можете побачити, як натискати кнопки Game Boy Advance **кнопки**

![](<../../images/image (581).png>)

Коли натискається, кожна **клавіша має значення** для її ідентифікації:
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
Отже, у такій програмі цікавою частиною буде **як програма обробляє введення користувача**. За адресою **0x4000130** ви знайдете загальновживану функцію: **KEYINPUT**.

![](<../../images/image (447).png>)

На попередньому зображенні ви можете побачити, що функція викликається з **FUN_080015a8** (адреси: _0x080015fa_ та _0x080017ac_).

У цій функції, після деяких ініціалізаційних операцій (без жодного значення):
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
Цей код знайдено:
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
Останнє if перевіряє, чи **`uVar4`** знаходиться в **останніх ключах** і не є поточним ключем, також це називається відпусканням кнопки (поточний ключ зберігається в **`uVar1`**).
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
У попередньому коді ви можете побачити, що ми порівнюємо **uVar1** (місце, де знаходиться **значення натиснутої кнопки**) з деякими значеннями:

- По-перше, його порівнюють з **значенням 4** (**SELECT** кнопка): У завданні ця кнопка очищає екран.
- Потім його порівнюють з **значенням 8** (**START** кнопка): У завданні це перевіряє, чи є код дійсним для отримання прапора.
- У цьому випадку змінна **`DAT_030000d8`** порівнюється з 0xf3, і якщо значення однакове, виконується деякий код.
- У будь-яких інших випадках перевіряється деякий лічильник (`DAT_030000d4`). Це лічильник, оскільки він додає 1 відразу після входу в код.\
**Якщо** менше 8, виконується щось, що пов'язане з **додаванням** значень до \*\*`DAT_030000d8` \*\* (в основному це додає значення натиснуті клавіші в цю змінну, поки лічильник менше 8).

Отже, у цьому завданні, знаючи значення кнопок, вам потрібно було **натиснути комбінацію з довжиною менше 8, щоб отримана сума дорівнювала 0xf3.**

**Посилання на цей підручник:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Курси

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Бінарна деобфускація)

{{#include ../../banners/hacktricks-training.md}}
