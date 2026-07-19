# Ін’єкція бібліотек у macOS

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Код **dyld є open source** і його можна знайти за адресою [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) та завантажити як tar-архів за **URL-адресою, наприклад** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Процес Dyld**

Ознайомтеся з тим, як Dyld завантажує бібліотеки всередині бінарних файлів:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Це аналог [**LD_PRELOAD у Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Він дозволяє вказати процесу, який буде запущено, завантажити певну бібліотеку із заданого шляху (якщо змінну середовища увімкнено).

Цю техніку також можна **використовувати як ASEP technique**, оскільки кожен встановлений застосунок має plist із назвою "Info.plist", який дозволяє **призначати змінні середовища** за допомогою ключа `LSEnvironmental`.

> [!TIP]
> Починаючи з 2012 року, **Apple суттєво зменшила можливості** **`DYLD_INSERT_LIBRARIES`**.
>
> Перейдіть до коду та **перевірте `src/dyld.cpp`**. У функції **`pruneEnvironmentVariables`** видно, що змінні **`DYLD_*`** видаляються.
>
> У функції **`processRestricted`** встановлюється причина обмеження. Перевіривши цей код, можна побачити, що причинами є:
>
> - Бінарний файл має `setuid/setgid`
> - Наявність секції `__RESTRICT/__restrict` у macho-бінарному файлі.
> - Програмне забезпечення має entitlements (hardened runtime) без entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>  - Перевірити **entitlements** бінарного файлу можна за допомогою: `codesign -dv --entitlements :- </path/to/bin>`
>
> У новіших версіях цю логіку можна знайти в другій частині функції **`configureProcessRestrictions`.** Однак у новіших версіях виконується **початкова перевірка функції** (можна видалити if, пов’язані з iOS або simulation, оскільки вони не використовуються в macOS).

### Library Validation

Навіть якщо бінарний файл дозволяє використовувати змінну середовища **`DYLD_INSERT_LIBRARIES`**, якщо він перевіряє підпис бібліотеки перед завантаженням, він не завантажить custom бібліотеку.

Щоб завантажити custom бібліотеку, бінарний файл повинен мати **один із таких entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

або бінарний файл **не повинен** мати **hardened runtime flag** чи **library validation flag**.

Перевірити, чи має бінарний файл **hardened runtime**, можна за допомогою `codesign --display --verbose <bin>`, перевіривши runtime flag у **`CodeDirectory`**, наприклад: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Також можна завантажити бібліотеку, якщо її **підписано тим самим сертифікатом, що й бінарний файл**.

Приклад того, як (зловмисно) використати це та перевірити обмеження, наведено тут:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Пам’ятайте, що **попередні обмеження Library Validation також застосовуються** під час виконання атак Dylib hijacking.

Як і у Windows, у MacOS також можна **перехоплювати dylib**, щоб змусити **застосунки** **виконувати** **довільний** **код** (насправді, для звичайного користувача це може бути неможливо, оскільки може знадобитися дозвіл TCC для запису всередину `.app` bundle та перехоплення бібліотеки).\
Однак спосіб, у який **MacOS**-застосунки **завантажують** бібліотеки, є **більш обмеженим**, ніж у Windows. Це означає, що розробники **malware** усе ще можуть використовувати цю техніку для **stealth**, але ймовірність **зловживання нею для підвищення привілеїв набагато нижча**.

По-перше, набагато **частіше** можна побачити, що **MacOS-бінарні файли вказують повний шлях** до бібліотек, які потрібно завантажити. По-друге, **MacOS ніколи не шукає** бібліотеки в каталогах із **$PATH**.

**Основна** частина **коду**, пов’язаного з цією функціональністю, міститься у **`ImageLoader::recursiveLoadLibraries`** у `ImageLoader.cpp`.

Існує **4 різні header Commands**, які macho-бінарний файл може використовувати для завантаження бібліотек:

- Команда **`LC_LOAD_DYLIB`** є стандартною командою для завантаження dylib.
- Команда **`LC_LOAD_WEAK_DYLIB`** працює як попередня, але якщо dylib не знайдено, виконання продовжується без помилки.
- Команда **`LC_REEXPORT_DYLIB`** проксує (або повторно експортує) symbols з іншої бібліотеки.
- Команда **`LC_LOAD_UPWARD_DYLIB`** використовується, коли дві бібліотеки залежать одна від одної (це називається _upward dependency_).

Однак існує **2 типи dylib hijacking**:

- **Missing weak linked libraries**: це означає, що застосунок спробує завантажити бібліотеку, якої не існує, налаштовану за допомогою **LC_LOAD_WEAK_DYLIB**. Потім, **якщо attacker розмістить dylib у місці, де її очікують, її буде завантажено**.
- Той факт, що link є "weak", означає, що застосунок продовжить працювати, навіть якщо бібліотеку не знайдено.
- **Код, пов’язаний** із цим, міститься у функції `ImageLoaderMachO::doGetDependentLibraries` у `ImageLoaderMachO.cpp`, де `lib->required` має значення `false` лише тоді, коли **LC_LOAD_WEAK_DYLIB** має значення true.
- **Знаходити weak linked libraries** у бінарних файлах можна за допомогою (нижче наведено приклад створення hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Налаштовані за допомогою @rpath**: Mach-O-бінарні файли можуть містити команди **`LC_RPATH`** та **`LC_LOAD_DYLIB`**. На основі **значень** цих команд **бібліотеки** завантажуватимуться з **різних каталогів**.
- **`LC_RPATH`** містить шляхи до каталогів, які бінарний файл використовує для завантаження бібліотек.
- **`LC_LOAD_DYLIB`** містить шлях до конкретних бібліотек, які потрібно завантажити. Ці шляхи можуть містити **`@rpath`**, який буде **замінено** значеннями в **`LC_RPATH`**. Якщо в **`LC_RPATH`** є кілька шляхів, усі вони використовуватимуться для пошуку бібліотеки. Приклад:
- Якщо **`LC_LOAD_DYLIB`** містить `@rpath/library.dylib`, а **`LC_RPATH`** містить `/application/app.app/Contents/Framework/v1/` і `/application/app.app/Contents/Framework/v2/`, для завантаження `library.dylib` буде використано обидва каталоги**.** Якщо бібліотеки немає в `[...]/v1/`, attacker може розмістити її там, щоб перехопити завантаження бібліотеки з `[...]/v2/`, оскільки порядок шляхів у **`LC_LOAD_DYLIB`** зберігається.
- **Знаходити rpath paths та libraries** у бінарних файлах можна за допомогою: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Це **шлях** до каталогу, що містить **основний виконуваний файл**.
>
> **`@loader_path`**: Це **шлях** до **каталогу**, що містить **Mach-O-бінарний файл**, у якому міститься load command.
>
> - Якщо використовується у виконуваному файлі, **`@loader_path`** фактично є тим самим, що й **`@executable_path`**.
> - Якщо використовується у **dylib**, **`@loader_path`** вказує **шлях** до **dylib**.

Підвищення **привілеїв** із використанням цієї функціональності можливе в рідкісному випадку, коли **застосунок**, який виконується від імені **root**, **шукає** якусь **бібліотеку в каталозі, до якого attacker має права запису**.

> [!TIP]
> Зручним **scanner** для пошуку **відсутніх бібліотек** у застосунках є [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) або [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Хороший **звіт із технічними деталями** про цю техніку можна знайти [**тут**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Приклад**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Пам’ятайте, що **попередні обмеження Library Validation також застосовуються** під час виконання атак Dlopen hijacking.

З **`man dlopen`**:

- Якщо шлях **не містить символу слеша** (тобто є лише leaf name), **dlopen() виконуватиме пошук**. Якщо під час запуску було встановлено **`$DYLD_LIBRARY_PATH`**, dyld спочатку **шукатиме в цьому каталозі**. Далі, якщо викликач mach-o-файлу або основний виконуваний файл вказує **`LC_RPATH`**, dyld **шукатиме в цих** каталогах. Потім, якщо процес є **unrestricted**, dyld шукатиме в **поточному робочому каталозі**. Нарешті, для старих бінарних файлів dyld спробує кілька fallback-шляхів. Якщо під час запуску було встановлено **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld шукатиме в **цих каталогах**, інакше dyld шукатиме в **`/usr/local/lib/`** (якщо процес є unrestricted), а потім у **`/usr/lib/`** (цю інформацію взято з **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(якщо unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (якщо unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Якщо в імені немає слешів, існує 2 способи виконати hijacking:
>
> - Якщо будь-який **`LC_RPATH`** доступний для запису (але signature перевіряється, тому для цього також потрібно, щоб бінарний файл був unrestricted)
> - Якщо бінарний файл є **unrestricted**, тоді можна завантажити щось із CWD (або зловжити однією із зазначених змінних середовища)

- Якщо шлях **має вигляд** шляху до framework (наприклад, `/stuff/foo.framework/foo`), і під час запуску було встановлено **`$DYLD_FRAMEWORK_PATH`**, dyld спочатку шукатиме в цьому каталозі **частковий шлях framework** (наприклад, `foo.framework/foo`). Далі dyld спробує **наданий шлях як є** (для відносних шляхів використовуючи поточний робочий каталог). Нарешті, для старих бінарних файлів dyld спробує кілька fallback-шляхів. Якщо під час запуску було встановлено **`$DYLD_FALLBACK_FRAMEWORK_PATH`**, dyld шукатиме в цих каталогах. Інакше він шукатиме в **`/Library/Frameworks`** (у macOS, якщо процес є unrestricted), а потім у **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. наданий шлях (для відносних шляхів використовується поточний робочий каталог, якщо процес є unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (якщо unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Якщо шлях є шляхом до framework, hijack можна виконати так:
>
> - Якщо процес є **unrestricted**, зловживаючи **відносним шляхом із CWD** або зазначеними змінними середовища (навіть якщо в документації це не зазначено, для restricted-процесу змінні середовища DYLD\_\* видаляються)

- Якщо шлях **містить слеш, але не є шляхом до framework** (тобто повним або частковим шляхом до dylib), dlopen() спочатку шукає (якщо встановлено) у **`$DYLD_LIBRARY_PATH`** (із leaf part шляху). Далі dyld **намагається використати наданий шлях** (для відносних шляхів використовуючи поточний робочий каталог, але лише для unrestricted-процесів). Нарешті, для старіших бінарних файлів dyld спробує fallback-шляхи. Якщо під час запуску було встановлено **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld шукатиме в цих каталогах, інакше dyld шукатиме в **`/usr/local/lib/`** (якщо процес є unrestricted), а потім у **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. наданий шлях (для відносних шляхів використовується поточний робочий каталог, якщо процес є unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (якщо unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Якщо ім’я містить слеші й не є framework, hijack можна виконати так:
>
> - Якщо бінарний файл є **unrestricted**, тоді можна завантажити щось із CWD або `/usr/local/lib` (чи зловжити однією із зазначених змінних середовища)

> [!TIP]
> Примітка: не існує конфігураційних файлів для **керування пошуком dlopen**.
>
> Примітка: якщо основний виконуваний файл є **set\[ug]id binary** або підписаний кодом із entitlements, тоді **всі змінні середовища ігноруються**, і можна використовувати лише повний шлях ([перевірте обмеження DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions), щоб отримати детальнішу інформацію)
>
> Примітка: платформи Apple використовують "universal" files для об’єднання 32-бітних і 64-бітних бібліотек. Це означає, що **окремих шляхів пошуку для 32-бітних і 64-бітних файлів не існує**.
>
> Примітка: на платформах Apple більшість OS dylibs **об’єднано в dyld cache**, і на диску їх не існує. Тому виклик **`stat()`** для попередньої перевірки наявності OS dylib **не працюватиме**. Однак **`dlopen_preflight()`** використовує ті самі кроки, що й **`dlopen()`**, для пошуку сумісного mach-o-файлу.

**Перевірка шляхів**

Перевіримо всі варіанти за допомогою такого коду:
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
Якщо скомпілювати та виконати це, можна побачити, **де безуспішно шукали кожну бібліотеку**. Також можна **відфільтрувати FS logs**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Якщо **privileged binary/app** (наприклад, SUID або будь-який binary із потужними entitlements) **завантажує бібліотеку за відносним шляхом** (наприклад, використовуючи `@executable_path` або `@loader_path`) і для нього вимкнено **Library Validation**, може бути можливо перемістити binary у місце, де attacker зможе **змінити бібліотеку, завантажену за відносним шляхом**, і використати це для ін'єкції коду в процес.

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

У файлі `dyld-dyld-832.7.1/src/dyld2.cpp` можна знайти функцію **`pruneEnvironmentVariables`**, яка видаляє будь-яку env variable, що **починається з `DYLD_`** або має значення **`LD_LIBRARY_PATH=`**.

Вона також встановлює значення **`null`** саме для env variables **`DYLD_FALLBACK_FRAMEWORK_PATH`** і **`DYLD_FALLBACK_LIBRARY_PATH`** для **suid** і **sgid** binaries.

Ця функція викликається з функції **`_main`** того самого файлу під час targeting OSX, як показано нижче:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
і ці boolean flags встановлюються в тому самому файлі в коді:
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
Що, по суті, означає: якщо binary має **suid** або **sgid**, містить сегмент **RESTRICT** у заголовках або його було підписано з прапором **CS_RESTRICT**, тоді **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** має значення true, і env variables видаляються.

Зверніть увагу: якщо CS_REQUIRE_LV має значення true, змінні не видалятимуться, але library validation перевірить, чи використовують вони той самий certificate, що й оригінальний binary.

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
### Секція `__RESTRICT` із сегментом `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Створіть новий сертифікат у Keychain і використайте його для підпису бінарного файлу:
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
> Зверніть увагу, що навіть бінарні файли, підписані з flags **`0x0(none)`**, під час виконання можуть динамічно отримати flag **`CS_RESTRICT`**, тому ця техніка не працюватиме з ними.
>
> Перевірити, чи має proc цей flag, можна за допомогою ([**csops тут**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> після чого перевірте, чи ввімкнено flag 0x800.

## Посилання

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
