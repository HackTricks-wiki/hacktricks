{{#include ../../banners/hacktricks-training.md}}

# Посібник з декомпіляції Wasm та компіляції Wat

У сфері **WebAssembly** інструменти для **декомпіляції** та **компіляції** є необхідними для розробників. Цей посібник представляє деякі онлайн-ресурси та програмне забезпечення для роботи з **Wasm (бінарний формат WebAssembly)** та **Wat (текстовий формат WebAssembly)** файлами.

## Онлайн-інструменти

- Для **декомпіляції** Wasm у Wat зручно використовувати інструмент на [демо wasm2wat від Wabt](https://webassembly.github.io/wabt/demo/wasm2wat/index.html).
- Для **компіляції** Wat назад у Wasm підходить [демо wat2wasm від Wabt](https://webassembly.github.io/wabt/demo/wat2wasm/).
- Інший варіант декомпіляції можна знайти на [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Програмні рішення

- Для більш надійного рішення [JEB від PNF Software](https://www.pnfsoftware.com/jeb/demo) пропонує розширені функції.
- Відкритий проект [wasmdec](https://github.com/wwwg/wasmdec) також доступний для завдань декомпіляції.

# Ресурси для декомпіляції .Net

Декомпіляцію .Net збірок можна виконати за допомогою таких інструментів:

- [ILSpy](https://github.com/icsharpcode/ILSpy), який також пропонує [плагін для Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), що дозволяє крос-платформне використання.
- Для завдань, пов'язаних з **декомпіляцією**, **модифікацією** та **рекомпіляцією**, рекомендується [dnSpy](https://github.com/0xd4d/dnSpy/releases). **Клацання правою кнопкою** на методі та вибір **Modify Method** дозволяє вносити зміни в код.
- [dotPeek від JetBrains](https://www.jetbrains.com/es-es/decompiler/) є ще одним альтернативним інструментом для декомпіляції .Net збірок.

## Покращення налагодження та ведення журналів з DNSpy

### Ведення журналів DNSpy

Щоб записати інформацію у файл за допомогою DNSpy, включіть наступний фрагмент коду .Net:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### Налагодження DNSpy

Для ефективного налагодження з DNSpy рекомендується виконати ряд кроків для налаштування **атрибутів збірки** для налагодження, щоб оптимізації, які можуть заважати налагодженню, були вимкнені. Цей процес включає зміну налаштувань `DebuggableAttribute`, рекомпіляцію збірки та збереження змін.

Крім того, щоб налагодити .Net додаток, запущений через **IIS**, виконання `iisreset /noforce` перезапускає IIS. Щоб приєднати DNSpy до процесу IIS для налагодження, посібник інструктує про вибір процесу **w3wp.exe** в DNSpy та початок сесії налагодження.

Для всебічного перегляду завантажених модулів під час налагодження рекомендується отримати доступ до вікна **Modules** в DNSpy, після чого відкрити всі модулі та відсортувати збірки для легшої навігації та налагодження.

Цей посібник охоплює суть декомпіляції WebAssembly та .Net, пропонуючи шлях для розробників, щоб легко виконувати ці завдання.

## **Java Декомпілятор**

Для декомпіляції Java байт-коду ці інструменти можуть бути дуже корисними:

- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Налагодження DLL**

### Використання IDA

- **Rundll32** завантажується з конкретних шляхів для 64-бітних та 32-бітних версій.
- **Windbg** обирається як налагоджувач з можливістю призупинення при завантаженні/вивантаженні бібліотеки.
- Параметри виконання включають шлях до DLL та ім'я функції. Ця конфігурація зупиняє виконання при кожному завантаженні DLL.

### Використання x64dbg/x32dbg

- Подібно до IDA, **rundll32** завантажується з модифікаціями командного рядка для вказівки DLL та функції.
- Налаштування коригуються для зупинки на вході DLL, що дозволяє встановлювати точки зупинки на бажаній точці входу DLL.

### Зображення

- Точки зупинки виконання та конфігурації ілюструються через скріншоти.

## **ARM & MIPS**

- Для емуляції [arm_now](https://github.com/nongiach/arm_now) є корисним ресурсом.

## **Shellcodes**

### Техніки налагодження

- **Blobrunner** та **jmp2it** є інструментами для виділення shellcodes в пам'яті та їх налагодження з Ida або x64dbg.
- Blobrunner [випуски](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [скомпільована версія](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** пропонує емуляцію shellcode на основі GUI та інспекцію, підкреслюючи відмінності в обробці shellcode як файлу в порівнянні з прямим shellcode.

### Деобфускація та аналіз

- **scdbg** надає інформацію про функції shellcode та можливості деобфускації.
%%%bash
scdbg.exe -f shellcode # Основна інформація
scdbg.exe -f shellcode -r # Звіт з аналізу
scdbg.exe -f shellcode -i -r # Інтерактивні хуки
scdbg.exe -f shellcode -d # Вивантажити декодований shellcode
scdbg.exe -f shellcode /findsc # Знайти початковий зсув
scdbg.exe -f shellcode /foff 0x0000004D # Виконати з зсуву
%%%

- **CyberChef** для дизасемблювання shellcode: [рецепт CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**

- Обфускатор, який замінює всі інструкції на `mov`.
- Корисні ресурси включають [пояснення на YouTube](https://www.youtube.com/watch?v=2VF_wPkiBJY) та [PDF слайди](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** може скасувати обфускацію movfuscator, вимагаючи залежностей, таких як `libcapstone-dev` та `libz3-dev`, а також встановлення [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**

- Для Delphi бінарників рекомендується [IDR](https://github.com/crypto2011/IDR).

# Курси

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Деобфускація бінарників\)

{{#include ../../banners/hacktricks-training.md}}
