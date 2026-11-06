# Процес Dyld у macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Основна інформація

Справжнім **entrypoint** Mach-o-бінарного файла є динамічний лінкер, визначений у `LC_LOAD_DYLINKER`. Зазвичай це `/usr/lib/dyld`.<sup>[[3]](#references)</sup>

Цей лінкер має знайти всі бібліотеки виконуваних файлів, відобразити їх у пам’яті та зв’язати всі non-lazy бібліотеки. Лише після цього буде виконано entrypoint бінарного файла.

Звісно, **`dyld`** не має залежностей (він використовує системні виклики та фрагменти libSystem).

> [!CAUTION]
> Якщо в цьому лінкері є вразливість, оскільки він виконується перед запуском будь-якого бінарного файла (навіть із високими привілеями), можна буде **підвищити привілеї**.

### Послідовність виконання

Dyld завантажує **`dyldboostrap::start`**, яка також завантажує такі речі, як **stack canary**. Це тому, що ця функція отримує у своєму векторі аргументів **`apple`** це та інші **чутливі** **значення**.<sup>[[1]](#references)</sup>

**`dyls::_main()`** — це entry point dyld, і першим її завданням є запуск `configureProcessRestrictions()`, яка зазвичай обмежує змінні середовища **`DYLD_*`**, описані тут:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Потім вона відображає dyld shared cache, який попередньо зв’язує всі важливі системні бібліотеки, після чого відображає бібліотеки, від яких залежить бінарний файл, і рекурсивно продовжує, доки не завантажить усі потрібні бібліотеки. Отже:

1. спочатку вона завантажує вставлені бібліотеки за допомогою `DYLD_INSERT_LIBRARIES` (якщо це дозволено)
2. Потім — бібліотеки зі shared cache
3. Потім — імпортовані бібліотеки
   1. Далі рекурсивно імпортує бібліотеки

Після завантаження всіх бібліотек запускаються їхні **ініціалізатори**. Їх визначають за допомогою **`__attribute__((constructor))`** у `LC_ROUTINES[_64]` (тепер застаріло) або вказівника в секції з прапорцем `S_MOD_INIT_FUNC_POINTERS` (зазвичай: **`__DATA.__MOD_INIT_FUNC`**).

Термінатори визначаються за допомогою **`__attribute__((destructor))`** і розташовані в секції з прапорцем `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

Див. також: [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

### Stubs

Усі бінарні файли в macOS динамічно зв’язуються. Тому вони містять секції stubs, які допомагають бінарному файлу переходити до потрібного коду на різних машинах і в різних контекстах. Під час запуску бінарного файла саме dyld має визначити ці адреси (принаймні non-lazy).

Деякі секції stubs у бінарному файлі:

- **`__TEXT.__[auth_]stubs`**: вказівники на секції `__DATA`
- **`__TEXT.__stub_helper`**: невеликий фрагмент коду, що викликає динамічне зв’язування та містить інформацію про функцію, яку потрібно викликати
- **`__DATA.__[auth_]got`**: Global Offset Table (адреси імпортованих функцій; після визначення вони зв’язуються під час завантаження, оскільки позначені прапорцем `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: вказівники на non-lazy символи (зв’язуються під час завантаження, оскільки позначені прапорцем `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: вказівники на lazy символи (зв’язуються під час першого звернення)

> [!WARNING]
> Зверніть увагу, що вказівники з префіксом "auth\_" захищені ключем шифрування, спільним для процесу (PAC). Крім того, можна використовувати інструкцію arm64 `BLRA[A/B]`, щоб перевірити вказівник перед переходом за ним. Також замість адреси RET можна використовувати RETA\[A/B].\
> Насправді код у **`__TEXT.__auth_stubs`** використовує **`braa`** замість **`bl`** для виклику потрібної функції та автентифікації вказівника.
>
> Також зверніть увагу, що поточні версії dyld завантажують **усе як non-lazy**.

### Пошук lazy символів

```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    printf("Hi\n");
}
```

Цікавий фрагмент дизасемблювання:

```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```

Можна побачити, що перехід до виклику printf веде до **`__TEXT.__stubs`**:

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

Під час дизасемблювання секції **`__stubs`**:

```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```

можна побачити, що ми **переходимо за адресою GOT**, яка в цьому випадку розв’язується не ліниво й міститиме адресу функції printf.

В інших ситуаціях замість прямого переходу до GOT перехід може вести до **`__DATA.__la_symbol_ptr`**, звідки завантажується значення, що представляє функцію, яку намагаються завантажити. Потім відбувається перехід до **`__TEXT.__stub_helper`**, звідки перехід веде до **`__DATA.__nl_symbol_ptr``, що містить адресу **`dyld_stub_binder`**, яка приймає як параметри номер функції та адресу.\
Binder розв’язує символ і оновлює його слот **`__DATA.__la_symbol_ptr`**. Під час наступних викликів stub використовує цей розв’язаний вказівник; він не переписується в **`__TEXT.__stub_helper`**.<sup>[[5]](#references)</sup>

> [!TIP]
> Однак зверніть увагу, що поточні версії dyld завантажують усе не ліниво.

#### Опкоди dyld

Зрештою, **`dyld_stub_binder`** має знайти вказану функцію й записати її за відповідною адресою, щоб не шукати її знову. Для цього він використовує опкоди (скінченний автомат) у dyld.

## apple\[] вектор аргументів

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
> На момент, коли ці значення доходять до функції main, з них уже видалено конфіденційну інформацію, інакше це був би витік даних.

Усі ці цікаві значення можна побачити під час налагодження до входу у функцію main:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

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

Це структура, яку експортує dyld і яка містить відомості про стан dyld. Її можна знайти у [**вихідному коді**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html). Вона містить такі дані, як версія, вказівник на масив dyld_image_info, на dyld_image_notifier, інформація про те, чи від’єднаний процес від shared cache, чи було викликано ініціалізатор libSystem, вказівник на власний Mach header dyld, вказівник на рядок версії dyld тощо.<sup>[[4]](#references)</sup>

## Змінні середовища dyld

### Налагодження dyld

Цікаві змінні середовища, які допомагають зрозуміти, що робить dyld:

- **DYLD_PRINT_LIBRARIES**

Перевірити кожну завантажену бібліотеку:

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

Виводить повідомлення під час виконання ініціалізатора кожної бібліотеки:

```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```

### Відстеження розв’язання бібліотек під час виконання

Для запуску, який ви контролюєте, відстежте кандидата `@rpath` або weak-library до розміщення замінної dylib. `DYLD_PRINT_SEARCHING` повідомляє шляхи, які розглядає dyld, а `DYLD_PRINT_LIBRARIES` показує фактично завантажені образи. `DYLD_PRINT_LOADERS` дає змогу відрізнити `JustInTimeLoader` від `PrebuiltLoader` і повідомляє про використання набору prebuilt loader.<sup>[[6]](#references)</sup>

```bash
DYLD_PRINT_SEARCHING=1 DYLD_PRINT_LOADERS=1 DYLD_PRINT_LIBRARIES=1 /path/to/binary 2>&1 | tee /tmp/dyld-search.log
```

Шукайте рядок `LC_RPATH`, який указує на образ, що надав шлях пошуку, а потім порівняйте кандидатні шляхи `possible path(...)` зі значеннями `found: dylib-from-disk`, `found: dylib-from-cache` або відмовою. Кандидатний шлях **не** є доказом того, що dylib завантажено. Перший придатний шлях на диску перед очікуваною бібліотекою — це шлях, для якого слід перевірити права на запис і [обмеження library validation](./#library-validation).<sup>[[7]](#references)</sup>

Попередньо зібраний завантажувач може повторно використовувати збережені дані про залежності, не виконуючи повний пошук шляхів знову. Тому розріджений вивід пошуку не свідчить про те, що образ не має залежностей; перевірте його команди завантаження за допомогою `otool -l` і порівняйте список бібліотек.<sup>[[8]](#references)</sup> Для цих діагностичних повідомлень також потрібен дозвіл dyld на виведення змінних, тож захищена ціль може їх повністю ігнорувати.<sup>[[2]](#references)</sup> Фактичні передумови для заміни бібліотеки див. у розділі [Dylib Hijacking](./#dylib-hijacking).

### Інше

Деякі наведені нижче перемикачі підтримуються лише старішими випусками dyld. Перевірте їхню підтримку у версії цільової системи, а не припускайте, що кожна змінна досі працює.<sup>[[2]](#references)[[9]](#references)</sup>

- `DYLD_BIND_AT_LAUNCH`: Відкладені прив’язки розв’язуються разом із невідкладеними
- `DYLD_DISABLE_PREFETCH`: Вимкнути попереднє завантаження вмісту \_\_DATA та \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Прив’язки в однорівневому просторі імен
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Шляхи пошуку
- `DYLD_INSERT_LIBRARIES`: Завантажити певну бібліотеку
- `DYLD_PRINT_TO_FILE`: Записати налагоджувальну інформацію dyld у файл
- `DYLD_PRINT_APIS`: Вивести виклики API libdyld
- `DYLD_PRINT_APIS_APP`: Вивести виклики API libdyld, зроблені головною програмою
- `DYLD_PRINT_BINDINGS`: Вивести символи під час прив’язування
- `DYLD_PRINT_WEAK_BINDINGS` (dyld2): Вивести прив’язки слабких символів
- `DYLD_PRINT_CODE_SIGNATURES`: Вивести операції реєстрації підписів коду
- `DYLD_PRINT_DOFS`: Вивести секції формату об’єктів D-Trace під час завантаження
- `DYLD_PRINT_ENV`: Вивести змінні середовища, видимі dyld
- `DYLD_PRINT_INTERPOSING`: Вивести операції перехоплення
- `DYLD_PRINT_LIBRARIES`: Вивести завантажені бібліотеки
- `DYLD_PRINT_OPTS`: Вивести параметри завантаження
- `DYLD_PRINT_REBASINGS` (dyld2): Вивести операції зміни базових адрес символів
- `DYLD_PRINT_RPATHS` (dyld2): Вивести розгортання `@rpath`
- `DYLD_PRINT_SEGMENTS`: Вивести відображення сегментів Mach-O
- `DYLD_PRINT_STATISTICS`: Вивести статистику часу виконання
- `DYLD_PRINT_STATISTICS_DETAILS`: Вивести детальну статистику часу виконання
- `DYLD_PRINT_WARNINGS`: Вивести попередження
- `DYLD_SHARED_CACHE_DIR`: Шлях до кешу спільних бібліотек
- `DYLD_SHARED_REGION`: «use», «private», «avoid»
- `DYLD_USE_CLOSURES`: Увімкнути closures

Більше параметрів можна знайти, наприклад, за допомогою:

```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```

Або завантаживши проєкт dyld з [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) і запустивши команду в цій папці:

```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```



## References

- [1] [dyld — `dyld/dyldMain.cpp` (шлях запуску процесу)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (конфігурація процесу/безпеки)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (частина ядра для `execve`, завантаження dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (структура `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
- [5] [fishhook — прив’язування покажчиків на відкладені та невідкладені символи](https://github.com/meta/fishhook)
- [6] [dyld(1) — діагностика динамічного компонувальника](https://github.com/apple-oss-distributions/dyld/blob/main/doc/man/man1/dyld.1)
- [7] [dyld — пошук шляхів до бібліотек під час виконання](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp)
- [8] [dyld4 — попередньо створені та JIT-завантажувачі](https://github.com/apple-oss-distributions/dyld/blob/main/doc/dyld4.md)
- [9] [dyld2 — застарілі назви діагностичних змінних](https://github.com/apple-oss-distributions/dyld/blob/dyld-852.2/src/dyld2.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
