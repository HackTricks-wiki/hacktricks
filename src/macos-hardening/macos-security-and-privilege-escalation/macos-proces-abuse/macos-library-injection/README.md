# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Код **dyld є відкритим вихідним кодом** і його можна знайти за адресою [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) і завантажити у форматі tar за допомогою **URL, такого як** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Подивіться, як Dyld завантажує бібліотеки всередині бінарних файлів у:

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Це схоже на [**LD_PRELOAD на Linux**](../../../../linux-hardening/privilege-escalation/#ld_preload). Це дозволяє вказати процес, який буде запущено, щоб завантажити конкретну бібліотеку з шляху (якщо змінна середовища увімкнена)

Цю техніку також можна **використовувати як техніку ASEP**, оскільки кожен встановлений додаток має plist під назвою "Info.plist", який дозволяє **призначати змінні середовища** за допомогою ключа `LSEnvironmental`.

> [!NOTE]
> З 2012 року **Apple значно зменшила потужність** **`DYLD_INSERT_LIBRARIES`**.
>
> Перейдіть до коду і **перевірте `src/dyld.cpp`**. У функції **`pruneEnvironmentVariables`** ви можете побачити, що **`DYLD_*`** змінні видаляються.
>
> У функції **`processRestricted`** встановлюється причина обмеження. Перевіряючи цей код, ви можете побачити, що причини такі:
>
> - Бінарний файл є `setuid/setgid`
> - Наявність секції `__RESTRICT/__restrict` у бінарному файлі macho.
> - Програмне забезпечення має права (посилена середа виконання) без прав [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>   - Перевірте **права** бінарного файлу за допомогою: `codesign -dv --entitlements :- </path/to/bin>`
>
> У більш нових версіях ви можете знайти цю логіку в другій частині функції **`configureProcessRestrictions`.** Однак те, що виконується в новіших версіях, - це **початкові перевірки функції** (ви можете видалити умови, пов'язані з iOS або емуляцією, оскільки вони не будуть використовуватися в macOS).

### Library Validation

Навіть якщо бінарний файл дозволяє використовувати змінну середовища **`DYLD_INSERT_LIBRARIES`**, якщо бінарний файл перевіряє підпис бібліотеки для завантаження, він не завантажить кастомну бібліотеку.

Щоб завантажити кастомну бібліотеку, бінарний файл повинен мати **одне з наступних прав**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

або бінарний файл **не повинен** мати **прапор посиленої середовища виконання** або **прапор перевірки бібліотек**.

Ви можете перевірити, чи має бінарний файл **посилену середу виконання** за допомогою `codesign --display --verbose <bin>`, перевіряючи прапор runtime в **`CodeDirectory`** так: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Ви також можете завантажити бібліотеку, якщо вона **підписана тим же сертифікатом, що й бінарний файл**.

Знайдіть приклад, як (зловживати) цим і перевірте обмеження в:

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Пам'ятайте, що **попередні обмеження перевірки бібліотек також застосовуються** для виконання атак на викрадення Dylib.

Як і в Windows, в MacOS ви також можете **викрадати dylibs**, щоб змусити **додатки** **виконувати** **произвольний** **код** (насправді, для звичайного користувача це може бути неможливо, оскільки вам може знадобитися дозвіл TCC, щоб записати в пакет `.app` і викрасти бібліотеку).\
Однак спосіб, яким **додатки MacOS** **завантажують** бібліотеки, є **більш обмеженим**, ніж у Windows. Це означає, що **розробники шкідливого ПЗ** все ще можуть використовувати цю техніку для **прихованості**, але ймовірність того, що вони зможуть **зловживати цим для ескалації привілеїв, значно нижча**.

По-перше, **більш поширено** знаходити, що **бінарні файли MacOS вказують повний шлях** до бібліотек для завантаження. По-друге, **MacOS ніколи не шукає** в папках **$PATH** для бібліотек.

**Основна** частина **коду**, пов'язана з цією функціональністю, знаходиться в **`ImageLoader::recursiveLoadLibraries`** у `ImageLoader.cpp`.

Існує **4 різні команди заголовка**, які бінарний файл macho може використовувати для завантаження бібліотек:

- **`LC_LOAD_DYLIB`** - це звичайна команда для завантаження dylib.
- **`LC_LOAD_WEAK_DYLIB`** - команда працює як попередня, але якщо dylib не знайдено, виконання продовжується без жодної помилки.
- **`LC_REEXPORT_DYLIB`** - команда проксі (або повторно експортує) символи з іншої бібліотеки.
- **`LC_LOAD_UPWARD_DYLIB`** - команда використовується, коли дві бібліотеки залежать одна від одної (це називається _вгору залежність_).

Однак існує **2 типи викрадення dylib**:

- **Відсутні слабко пов'язані бібліотеки**: Це означає, що додаток спробує завантажити бібліотеку, яка не існує, налаштовану з **LC_LOAD_WEAK_DYLIB**. Тоді, **якщо зловмисник помістить dylib туди, де її очікують, вона буде завантажена**.
- Той факт, що зв'язок "слабкий", означає, що додаток продовжить працювати, навіть якщо бібліотека не знайдена.
- **Код, пов'язаний** з цим, знаходиться у функції `ImageLoaderMachO::doGetDependentLibraries` у `ImageLoaderMachO.cpp`, де `lib->required` є лише `false`, коли `LC_LOAD_WEAK_DYLIB` є true.
- **Знайдіть слабко пов'язані бібліотеки** в бінарних файлах за допомогою (у вас пізніше буде приклад, як створити бібліотеки для викрадення):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Налаштовано з @rpath**: Бінарні файли Mach-O можуть мати команди **`LC_RPATH`** та **`LC_LOAD_DYLIB`**. На основі **значень** цих команд **бібліотеки** будуть **завантажені** з **різних директорій**.
- **`LC_RPATH`** містить шляхи до деяких папок, які використовуються для завантаження бібліотек бінарним файлом.
- **`LC_LOAD_DYLIB`** містить шлях до конкретних бібліотек для завантаження. Ці шляхи можуть містити **`@rpath`**, який буде **замінений** значеннями в **`LC_RPATH`**. Якщо в **`LC_RPATH`** є кілька шляхів, всі вони будуть використані для пошуку бібліотеки для завантаження. Приклад:
- Якщо **`LC_LOAD_DYLIB`** містить `@rpath/library.dylib`, а **`LC_RPATH`** містить `/application/app.app/Contents/Framework/v1/` та `/application/app.app/Contents/Framework/v2/`. Обидві папки будуть використані для завантаження `library.dylib`**.** Якщо бібліотека не існує в `[...]/v1/`, зловмисник може помістити її туди, щоб викрасти завантаження бібліотеки в `[...]/v2/`, оскільки порядок шляхів у **`LC_LOAD_DYLIB`** дотримується.
- **Знайдіть шляхи rpath і бібліотеки** в бінарних файлах за допомогою: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Це **шлях** до директорії, що містить **основний виконуваний файл**.
>
> **`@loader_path`**: Це **шлях** до **директорії**, що містить **Mach-O бінарний файл**, який містить команду завантаження.
>
> - Коли використовується в виконуваному файлі, **`@loader_path`** фактично є **тим же**, що й **`@executable_path`**.
> - Коли використовується в **dylib**, **`@loader_path`** дає **шлях** до **dylib**.

Спосіб **ескалації привілеїв**, зловживаючи цією функціональністю, буде в рідкісному випадку, коли **додаток**, що виконується **root**, **шукає** якусь **бібліотеку в якійсь папці, де зловмисник має права на запис.**

> [!TIP]
> Гарний **сканер** для знаходження **відсутніх бібліотек** в додатках - це [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) або [**CLI версія**](https://github.com/pandazheng/DylibHijack).\
> Гарний **звіт з технічними деталями** про цю техніку можна знайти [**тут**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Приклад**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Пам'ятайте, що **попередні обмеження перевірки бібліотек також застосовуються** для виконання атак на викрадення Dlopen.

З **`man dlopen`**:

- Коли шлях **не містить символа косої риски** (тобто це лише ім'я), **dlopen() буде шукати**. Якщо **`$DYLD_LIBRARY_PATH`** було встановлено під час запуску, dyld спочатку **шукатиме в цій директорії**. Далі, якщо викликаючий mach-o файл або основний виконуваний файл вказують **`LC_RPATH`**, тоді dyld **шукатиме в цих** директоріях. Далі, якщо процес **необмежений**, dyld буде шукати в **поточній робочій директорії**. Нарешті, для старих бінарних файлів dyld спробує деякі резервні варіанти. Якщо **`$DYLD_FALLBACK_LIBRARY_PATH`** було встановлено під час запуску, dyld буде шукати в **цих директоріях**, інакше dyld буде шукати в **`/usr/local/lib/`** (якщо процес необмежений), а потім у **`/usr/lib/`** (ця інформація була взята з **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(якщо необмежений)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (якщо необмежений)
6. `/usr/lib/`

> [!CAUTION]
> Якщо немає косих рисок в імені, існує 2 способи здійснити викрадення:
>
> - Якщо будь-який **`LC_RPATH`** є **записуваним** (але підпис перевіряється, тому для цього вам також потрібно, щоб бінарний файл був необмеженим)
> - Якщо бінарний файл є **необмеженим**, тоді можливо завантажити щось з CWD (або зловживаючи однією з згаданих змінних середовища)

- Коли шлях **схожий на шлях фреймворка** (наприклад, `/stuff/foo.framework/foo`), якщо **`$DYLD_FRAMEWORK_PATH`** було встановлено під час запуску, dyld спочатку шукає в цій директорії для **часткового шляху фреймворка** (наприклад, `foo.framework/foo`). Далі dyld спробує **вказаний шлях як є** (використовуючи поточну робочу директорію для відносних шляхів). Нарешті, для старих бінарних файлів dyld спробує деякі резервні варіанти. Якщо **`$DYLD_FALLBACK_FRAMEWORK_PATH`** було встановлено під час запуску, dyld буде шукати в цих директоріях. Інакше він буде шукати в **`/Library/Frameworks`** (на macOS, якщо процес необмежений), потім **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. вказаний шлях (використовуючи поточну робочу директорію для відносних шляхів, якщо необмежений)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (якщо необмежений)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Якщо шлях фреймворка, спосіб його викрадення буде:
>
> - Якщо процес є **необмеженим**, зловживаючи **відносним шляхом з CWD** та згаданими змінними середовища (навіть якщо в документації не сказано, що якщо процес обмежений, змінні середовища DYLD_* видаляються)

- Коли шлях **містить косу риску, але не є шляхом фреймворка** (тобто повний шлях або частковий шлях до dylib), dlopen() спочатку шукає (якщо встановлено) в **`$DYLD_LIBRARY_PATH`** (з частиною шляху). Далі dyld **пробує вказаний шлях** (використовуючи поточну робочу директорію для відносних шляхів (але лише для необмежених процесів)). Нарешті, для старих бінарних файлів dyld спробує резервні варіанти. Якщо **`$DYLD_FALLBACK_LIBRARY_PATH`** було встановлено під час запуску, dyld буде шукати в цих директоріях, інакше dyld буде шукати в **`/usr/local/lib/`** (якщо процес необмежений), а потім у **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. вказаний шлях (використовуючи поточну робочу директорію для відносних шляхів, якщо необмежений)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (якщо необмежений)
5. `/usr/lib/`

> [!CAUTION]
> Якщо в імені є косі риски і це не фреймворк, спосіб його викрадення буде:
>
> - Якщо бінарний файл є **необмеженим**, тоді можливо завантажити щось з CWD або `/usr/local/lib` (або зловживаючи однією з згаданих змінних середовища)

> [!NOTE]
> Примітка: Немає **конфігураційних файлів**, щоб **контролювати пошук dlopen**.
>
> Примітка: Якщо основний виконуваний файл є **set\[ug]id бінарним файлом або підписаним з правами**, тоді **всі змінні середовища ігноруються**, і можна використовувати лише повний шлях ([перевірте обмеження DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) для більш детальної інформації)
>
> Примітка: Платформи Apple використовують "універсальні" файли для об'єднання 32-бітних і 64-бітних бібліотек. Це означає, що немає **окремих 32-бітних і 64-бітних шляхів пошуку**.
>
> Примітка: На платформах Apple більшість OS dylibs **об'єднані в кеш dyld** і не існують на диску. Тому виклик **`stat()`** для попередньої перевірки, чи існує OS dylib, **не спрацює**. Однак **`dlopen_preflight()`** використовує ті ж кроки, що й **`dlopen()`**, щоб знайти сумісний mach-o файл.

**Перевірте шляхи**

Давайте перевіримо всі варіанти за допомогою наступного коду:
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Якщо ви скомпілюєте та виконаєте це, ви зможете побачити **де кожна бібліотека була безуспішно знайдена**. Також ви могли б **фільтрувати журнали FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Відносне викрадення шляху

Якщо **привілейований бінар/додаток** (наприклад, SUID або якийсь бінар з потужними правами) **завантажує бібліотеку з відносним шляхом** (наприклад, використовуючи `@executable_path` або `@loader_path`) і має **відключену валідацію бібліотек**, можливо, перемістити бінар у місце, де зловмисник може **модифікувати бібліотеку з відносним шляхом**, і зловживати цим для ін'єкції коду в процес.

## Очищення змінних середовища `DYLD_*` та `LD_LIBRARY_PATH`

У файлі `dyld-dyld-832.7.1/src/dyld2.cpp` можна знайти функцію **`pruneEnvironmentVariables`**, яка видалить будь-яку змінну середовища, що **починається з `DYLD_`** та **`LD_LIBRARY_PATH=`**.

Вона також встановить в **null** конкретно змінні середовища **`DYLD_FALLBACK_FRAMEWORK_PATH`** та **`DYLD_FALLBACK_LIBRARY_PATH`** для **suid** та **sgid** бінарів.

Ця функція викликається з функції **`_main`** того ж файлу, якщо націлена на OSX таким чином:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
і ці булеві прапори встановлюються в тому ж файлі в коді:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
Що в основному означає, що якщо бінарний файл є **suid** або **sgid**, або має сегмент **RESTRICT** у заголовках, або був підписаний з прапором **CS_RESTRICT**, тоді **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** є істинним, і змінні середовища обрізаються.

Зверніть увагу, що якщо CS_REQUIRE_LV є істинним, тоді змінні не будуть обрізані, але валідація бібліотеки перевірить, чи використовують вони той же сертифікат, що й оригінальний бінарний файл.

## Перевірка обмежень

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Розділ `__RESTRICT` з сегментом `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Створіть новий сертифікат у Keychain і використайте його для підписання бінарного файлу:
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
> [!CAUTION]
> Зверніть увагу, що навіть якщо є бінарні файли, підписані з прапорами **`0x0(none)`**, вони можуть отримати прапор **`CS_RESTRICT`** динамічно під час виконання, і тому ця техніка не спрацює в них.
>
> Ви можете перевірити, чи має процес цей прапор за допомогою (отримати [**csops тут**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> а потім перевірити, чи увімкнено прапор 0x800.

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
