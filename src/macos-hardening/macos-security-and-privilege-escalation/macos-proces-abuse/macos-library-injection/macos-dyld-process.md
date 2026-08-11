# Процес Dyld у macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Основна інформація

Справжньою **точкою входу** Mach-o binary є dynamic linker, визначений у `LC_LOAD_DYLINKER`; зазвичай це `/usr/lib/dyld`.<sup>[[3]](#references)</sup>

Цей linker має знайти всі libraries executable-файлу, відобразити їх у пам'ять і зв'язати всі non-lazy libraries. Лише після цього процесу буде виконано entry-point binary.

Звісно, **`dyld`** не має залежностей (він використовує syscalls і фрагменти libSystem).

> [!CAUTION]
> Якщо цей linker містить вразливість, оскільки він виконується до запуску будь-якого binary (навіть із високими привілеями), це може дозволити **підвищити привілеї**.

### Процес виконання

Dyld буде завантажено через **`dyldboostrap::start`**, який також завантажить такі елементи, як **stack canary**. Це відбувається тому, що ця функція отримує у своєму векторі аргументів **`apple`** це та інші **чутливі** **значення**.<sup>[[1]](#references)</sup>

**`dyls::_main()`** є entry point dyld, і його першим завданням є запуск `configureProcessRestrictions()`, яка зазвичай обмежує змінні середовища **`DYLD_*`**, описані в:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Потім він відображає shared cache dyld, який попередньо зв'язує всі важливі системні libraries, після чого відображає libraries, від яких залежить binary, і продовжує рекурсивно, доки не буде завантажено всі необхідні libraries. Отже:

1. він починає завантажувати inserted libraries через `DYLD_INSERT_LIBRARIES` (якщо дозволено)
2. Потім libraries зі shared cache
3. Потім imported libraries
1. Потім продовжує рекурсивно імпортувати libraries

Після завантаження всіх libraries запускаються їхні **initialisers**. Вони кодуються за допомогою **`__attribute__((constructor))`**, визначеного в `LC_ROUTINES[_64]` (тепер deprecated), або через pointer у section, позначеній `S_MOD_INIT_FUNC_POINTERS` (зазвичай: **`__DATA.__MOD_INIT_FUNC`**).

Terminators кодуються за допомогою **`__attribute__((destructor))`** і розташовані в section, позначеній `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Усі binaries у macOS динамічно зв'язані. Тому вони містять sections зі stubs, які допомагають binary переходити до правильного коду на різних машинах і в різних контекстах. Саме dyld під час виконання binary відповідає за розв'язання цих адрес (принаймні non-lazy).

Деякі stub sections у binary:

- **`__TEXT.__[auth_]stubs`**: Pointers із sections `__DATA`
- **`__TEXT.__stub_helper`**: Невеликий код, який викликає dynamic linking з інформацією про функцію, яку потрібно викликати
- **`__DATA.__[auth_]got`**: Global Offset Table (адреси imported functions, після розв'язання bound під час завантаження, оскільки позначені прапорцем `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Non-lazy symbol pointers (bound під час завантаження, оскільки позначені прапорцем `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Lazy symbols pointers (bound під час першого доступу)

> [!WARNING]
> Зверніть увагу, що pointers із префіксом "auth\_" використовують один in-process encryption key для їх захисту (PAC). Крім того, можна використовувати інструкцію arm64 `BLRA[A/B]`, щоб перевірити pointer перед переходом за ним. А `RETA\[A/B]` можна використовувати замість RET address.\
> Фактично код у **`__TEXT.__auth_stubs`** використовує **`braa`** замість **`bl`**, щоб викликати потрібну функцію та автентифікувати pointer.
>
> Також зверніть увагу, що поточні версії dyld завантажують **усе як non-lazy**.

### Пошук lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Цікава частина дизасемблювання:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Можна побачити, що перехід для виклику printf спрямовується до **`__TEXT.__stubs`**:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
У дизасемблюванні секції **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
ви можете бачити, що ми **переходимо за адресою GOT**, яка в цьому випадку визначається non-lazy і міститиме адресу функції printf.

В інших ситуаціях замість безпосереднього переходу до GOT може виконуватися перехід до **`__DATA.__la_symbol_ptr`**, що завантажить значення, яке представляє функцію, яку система намагається завантажити, а потім перейде до **`__TEXT.__stub_helper`**, який переходить до **`__DATA.__nl_symbol_ptr`**, що містить адресу **`dyld_stub_binder`**. Ця функція отримує як параметри номер функції та адресу.\
Ця остання функція, знайшовши адресу шуканої функції, записує її у відповідне місце в **`__TEXT.__stub_helper`**, щоб у майбутньому не виконувати пошук повторно.

> [!TIP]
> Однак зверніть увагу, що поточні версії dyld завантажують усе як non-lazy.

#### Dyld opcodes

Нарешті, **`dyld_stub_binder`** має знайти вказану функцію та записати її за належною адресою, щоб більше не шукати її повторно. Для цього вона використовує opcodes (скінченний автомат) усередині dyld.

## apple\[] argument vector

У macOS головна функція фактично отримує 4 аргументи замість 3. Четвертий називається apple, і кожен його елемент має формат `key=value`. Наприклад:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Результат:
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
> [!TIP]
> До моменту, коли ці значення досягають main function, конфіденційну інформацію з них уже видалено, інакше це був би data leak.

можна побачити всі ці цікаві значення під час debugging перед входом у main за допомогою:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld_all_image_infos

Це структура, експортована dyld, з інформацією про стан dyld, яку можна знайти у [**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html). Вона містить такі дані, як версія, вказівник на масив dyld_image_info, вказівник на dyld_image_notifier, інформацію про те, чи від’єднаний proc від shared cache, чи був викликаний initializer libSystem, вказівник на власний Mach header dyld, вказівник на рядок версії dyld тощо...<sup>[[4]](#references)</sup>

## dyld env variables

### debug dyld

Цікаві env variables, які допомагають зрозуміти, що робить dyld:

- **DYLD_PRINT_LIBRARIES**

Перевіряє кожну завантажену library:
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
- **DYLD_PRINT_SEGMENTS**

Перевірте, як завантажується кожна бібліотека:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
- **DYLD_PRINT_INITIALIZERS**

Виводить повідомлення під час запуску кожного ініціалізатора бібліотеки:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Інші

- `DYLD_BIND_AT_LAUNCH`: Lazy bindings вирішуються разом із non-lazy bindings
- `DYLD_DISABLE_PREFETCH`: Вимкнути попереднє отримання вмісту \_\_DATA і \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Однорівневі bindings
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Шляхи resolution
- `DYLD_INSERT_LIBRARIES`: Завантажити конкретну library
- `DYLD_PRINT_TO_FILE`: Записувати debug-інформацію dyld у файл
- `DYLD_PRINT_APIS`: Виводити виклики API libdyld
- `DYLD_PRINT_APIS_APP`: Виводити виклики API libdyld, виконані main
- `DYLD_PRINT_BINDINGS`: Виводити symbols під час binding
- `DYLD_WEAK_BINDINGS`: Виводити лише weak symbols під час binding
- `DYLD_PRINT_CODE_SIGNATURES`: Виводити операції реєстрації code signature
- `DYLD_PRINT_DOFS`: Виводити секції D-Trace object format під час завантаження
- `DYLD_PRINT_ENV`: Виводити env, який бачить dyld
- `DYLD_PRINT_INTERPOSTING`: Виводити операції interposing
- `DYLD_PRINT_LIBRARIES`: Виводити завантажені libraries
- `DYLD_PRINT_OPTS`: Виводити параметри завантаження
- `DYLD_REBASING`: Виводити операції rebasing symbols
- `DYLD_RPATHS`: Виводити розгортання `@rpath`
- `DYLD_PRINT_SEGMENTS`: Виводити mappings сегментів Mach-O
- `DYLD_PRINT_STATISTICS`: Виводити статистику часу
- `DYLD_PRINT_STATISTICS_DETAILS`: Виводити детальну статистику часу
- `DYLD_PRINT_WARNINGS`: Виводити попередження
- `DYLD_SHARED_CACHE_DIR`: Шлях для використання shared library cache
- `DYLD_SHARED_REGION`: `"use"`, `"private"`, `"avoid"`
- `DYLD_USE_CLOSURES`: Увімкнути closures

Більше параметрів можна знайти за допомогою чогось на кшталт:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Або завантаживши проєкт dyld з [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) і виконавши всередині папки:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp` (шлях запуску процесу)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (конфігурація процесу/безпеки)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (сторона ядра `execve`, завантаження dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (структура `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
