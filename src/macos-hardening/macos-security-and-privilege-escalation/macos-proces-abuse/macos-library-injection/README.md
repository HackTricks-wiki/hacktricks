# Ін’єкція бібліотек macOS

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Код **dyld є open source** і його можна знайти за адресою [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) та завантажити у форматі tar за **URL, наприклад** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Процес Dyld**

Ознайомтеся з тим, як Dyld завантажує бібліотеки всередині бінарних файлів:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Це аналог [**LD_PRELOAD у Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Він дозволяє вказати процесу, який буде запущено, завантажити певну бібліотеку із заданого шляху (якщо env var увімкнено)<sup>[[4]](#references)</sup>

Цю техніку також можна **використовувати як техніку ASEP**, оскільки кожна встановлена application має plist із назвою "Info.plist", який дозволяє **призначати environmental variables** за допомогою ключа `LSEnvironmental`.

> [!TIP]
> Починаючи з 2012 року **Apple суттєво зменшила можливості** **`DYLD_INSERT_LIBRARIES`**. Процес вважається **restricted** — після чого `dyld` видаляє всі змінні `DYLD_*` з його environment — якщо виконується будь-яка з таких умов:
>
> - Бінарний файл має `setuid/setgid`
> - Mach-O має секцію **`__RESTRICT/__restrict`**
> - Бінарний файл підписано з hardened runtime, а AMFI не надає йому дозволів "path/print variables", тобто в ньому відсутній [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Перевірити **entitlements** бінарного файла можна за допомогою: `codesign -dv --entitlements :- </path/to/bin>`
>
> У поточній версії `dyld` це більше не визначається лише `dyld`: `ProcessConfig::Security::Security()` запитує **AMFI** через `amfi_check_dyld_policy_self()`, а потім викликає `pruneEnvVars()`. Точний код розглянуто нижче в розділі [Prune `DYLD_*` env variables](#prune-dyld_-env-variables).

### Library Validation

Навіть якщо бінарний файл дозволяє env var **`DYLD_INSERT_LIBRARIES`**, він не завантажить custom library, якщо перевіряє підпис бібліотеки.

Щоб завантажити custom library, бінарний файл повинен мати **один із наведених entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

або бінарний файл **не повинен** мати **hardened runtime flag** чи **library validation flag**.

Перевірити, чи має бінарний файл **hardened runtime**, можна за допомогою `codesign --display --verbose <bin>`, перевіривши runtime flag у **`CodeDirectory`**, наприклад: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Також можна завантажити бібліотеку, якщо її **підписано тим самим сертифікатом, що й бінарний файл**.

Приклад того, як це (зловмисно) використати та перевірити обмеження, наведено в:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Пам’ятайте, що **попередні обмеження Library Validation також застосовуються** під час виконання атак Dylib hijacking.

Як і у Windows, у macOS також можна **перехоплювати dylib**, щоб змусити **applications** **виконувати** **довільний** **код** (насправді для звичайного користувача це може бути неможливо, оскільки може знадобитися дозвіл TCC для запису всередину `.app` bundle та hijack бібліотеки).\
Однак спосіб, у який **MacOS** applications **завантажують** бібліотеки, є **більш обмеженим**, ніж у Windows. Це означає, що розробники **malware** все ще можуть використовувати цю техніку для **stealth**, але ймовірність використати її для **ескалації привілеїв** набагато нижча.

По-перше, **бінарні файли MacOS частіше містять повний шлях** до бібліотек, які потрібно завантажити. По-друге, **MacOS ніколи не шукає** бібліотеки в папках із **$PATH**.

Основна частина **коду**, пов’язаного з цією функціональністю, знаходиться в **`ImageLoader::recursiveLoadLibraries`** у `ImageLoader.cpp`.

Існує **4 різні header Commands**, які macho-бінарний файл може використовувати для завантаження бібліотек:

- Команда **`LC_LOAD_DYLIB`** є стандартною командою для завантаження dylib.
- Команда **`LC_LOAD_WEAK_DYLIB`** працює як попередня, але якщо dylib не знайдено, виконання продовжується без помилки.
- Команда **`LC_REEXPORT_DYLIB`** проксіює (або повторно експортує) symbols з іншої бібліотеки.
- Команда **`LC_LOAD_UPWARD_DYLIB`** використовується, коли дві бібліотеки залежать одна від одної (це називається _upward dependency_).

Однак існує **2 типи dylib hijacking**:

- **Missing weak linked libraries**: це означає, що application намагатиметься завантажити бібліотеку, якої не існує, налаштовану за допомогою **LC_LOAD_WEAK_DYLIB**. Тоді **якщо attacker розмістить dylib там, де її очікують, її буде завантажено**.
- Те, що link є "weak", означає, що application продовжить працювати, навіть якщо бібліотеку не знайдено.
- **Код, пов’язаний** із цим, знаходиться у функції `ImageLoaderMachO::doGetDependentLibraries` у `ImageLoaderMachO.cpp`, де `lib->required` має значення `false` лише тоді, коли **LC_LOAD_WEAK_DYLIB** має значення true.
- **Знайти weak linked libraries** у бінарних файлах можна за допомогою (нижче наведено приклад створення hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O-бінарні файли можуть містити команди **`LC_RPATH`** і **`LC_LOAD_DYLIB`**. На основі **значень** цих команд **libraries** завантажуватимуться з **різних директорій**.
- **`LC_RPATH`** містить шляхи до деяких папок, які бінарний файл використовує для завантаження libraries.
- **`LC_LOAD_DYLIB`** містить шлях до конкретних libraries, які потрібно завантажити. Ці шляхи можуть містити **`@rpath`**, який буде **замінено** значеннями з **`LC_RPATH`**. Якщо в **`LC_RPATH`** є кілька шляхів, усі вони використовуватимуться для пошуку library, яку потрібно завантажити. Приклад:
- Якщо **`LC_LOAD_DYLIB`** містить `@rpath/library.dylib`, а **`LC_RPATH`** містить `/application/app.app/Contents/Framework/v1/` і `/application/app.app/Contents/Framework/v2/`, обидві папки використовуватимуться для завантаження `library.dylib`**.** Якщо library не існує в `[...]/v1/`, attacker може розмістити її там і hijack завантаження library з `[...]/v2/`, оскільки порядок шляхів у **`LC_LOAD_DYLIB`** зберігається.
- **Знайти rpath paths і libraries** у бінарних файлах можна за допомогою: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: це **шлях** до директорії, що містить **main executable file**.
>
> **`@loader_path`**: це **шлях** до **директорії**, що містить **Mach-O binary**, який містить load command.
>
> - Під час використання у executable **`@loader_path`** фактично є тим самим, що й **`@executable_path`**.
> - Під час використання у **dylib** **`@loader_path`** вказує на **шлях** до **dylib**.

Ескалація привілеїв за допомогою цієї функціональності можлива в рідкісному випадку, коли **application**, який виконується від імені **root**, **шукає** якусь **library у папці, до якої attacker має права на запис**.

> [!TIP]
> Хорошим **scanner** для пошуку **missing libraries** в applications є [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) або [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Хороший [**звіт із технічними деталями**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) про цю техніку можна знайти [**тут**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Приклад**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Пам’ятайте, що **попередні обмеження Library Validation також застосовуються** під час виконання атак Dlopen hijacking.

З **`man dlopen`**:

- Якщо path **не містить символу slash** (тобто це лише leaf name), **dlopen() виконує пошук**. Якщо під час запуску було встановлено **`$DYLD_LIBRARY_PATH`**, dyld спочатку **шукатиме в цій director**y. Далі, якщо calling mach-o file або main executable визначає **`LC_RPATH`**, dyld **шукатиме в цих** directories. Потім, якщо process є **unrestricted**, dyld шукатиме в **current working directory**. Нарешті, для старих бінарних файлів dyld спробує деякі fallbacks. Якщо під час запуску було встановлено **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld шукатиме в **цих directories**, інакше dyld шукатиме в **`/usr/local/lib/`** (якщо process є unrestricted), а потім у **`/usr/lib/`** (цю інформацію взято з **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(якщо unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (якщо unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Якщо ім’я не містить slash, hijacking можна виконати двома способами:
>
> - Якщо будь-який **`LC_RPATH`** доступний для запису (але signature перевіряється, тому для цього бінарний файл також має бути unrestricted)
> - Якщо бінарний файл є **unrestricted**, тоді можна завантажити щось із CWD (або зловживши однією із зазначених env variables)

- Якщо path **схожий на шлях до framework** (наприклад, `/stuff/foo.framework/foo`), і під час запуску було встановлено **`$DYLD_FRAMEWORK_PATH`**, dyld спочатку шукатиме в цій директорії **частковий шлях framework** (наприклад, `foo.framework/foo`). Далі dyld спробує **наданий path як є** (використовуючи current working directory для relative paths). Нарешті, для старих бінарних файлів dyld спробує деякі fallbacks. Якщо під час запуску було встановлено **`$DYLD_FALLBACK_FRAMEWORK_PATH`**, dyld шукатиме у цих directories. Інакше він шукатиме в **`/Library/Frameworks`** (у macOS, якщо process є unrestricted), а потім у **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (з використанням current working directory для relative paths, якщо unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (якщо unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Якщо це framework path, hijack можна виконати так:
>
> - Якщо process є **unrestricted**, зловживаючи **relative path від CWD** або зазначеними env variables (навіть якщо це не вказано в документації, для restricted process env vars DYLD\_\* видаляються)

- Якщо path **містить slash, але не є framework path** (тобто full path або partial path до dylib), dlopen() спочатку шукає (якщо встановлено) в **`$DYLD_LIBRARY_PATH`** (із leaf part від path). Далі dyld **намагається використати наданий path** (з використанням current working directory для relative paths (але лише для unrestricted processes)). Нарешті, для старіших бінарних файлів dyld спробує fallbacks. Якщо під час запуску було встановлено **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld шукатиме в цих directories, інакше dyld шукатиме в **`/usr/local/lib/`** (якщо process є unrestricted), а потім у **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (з використанням current working directory для relative paths, якщо unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (якщо unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Якщо ім’я містить slash і це не framework, hijack можна виконати так:
>
> - Якщо бінарний файл є **unrestricted**, тоді можна завантажити щось із CWD або `/usr/local/lib` (чи зловжити однією із зазначених env variables)

> [!TIP]
> Примітка: **не існує** configuration files для **керування пошуком dlopen**.
>
> Примітка: якщо main executable є **set\[ug]id binary** або codesigned with entitlements, тоді **всі environment variables ігноруються**, і можна використовувати лише full path ([перевірте обмеження DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions), щоб отримати докладнішу інформацію)
>
> Примітка: Apple platforms використовують "universal" files для об’єднання 32-bit і 64-bit libraries. Це означає, що **не існує окремих 32-bit і 64-bit search paths**.
>
> Примітка: на Apple platforms більшість OS dylibs **об’єднано в dyld cache** і вони не існують на диску. Тому виклик **`stat()`** для попередньої перевірки існування OS dylib **не працюватиме**. Однак **`dlopen_preflight()`** використовує ті самі кроки, що й **`dlopen()`**, для пошуку сумісного mach-o file.

**Перевірка paths**

Перевірмо всі options за допомогою наведеного коду:
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
Якщо скомпілювати та виконати його, можна побачити, **де безуспішно шукали кожну бібліотеку**. Також можна **фільтрувати журнали FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Якщо **privileged binary/app** (наприклад, SUID або binary із потужними entitlements) **завантажує бібліотеку за відносним шляхом** (наприклад, використовуючи `@executable_path` або `@loader_path`) і має **Library Validation disabled**, може бути можливо перемістити binary у місце, де attacker зможе **змінити бібліотеку, завантажену за відносним шляхом**, і використати це для inject коду в процес.

## Prune `DYLD_*` env variables

Старіші версії `dyld` (`dyld2.cpp`) визначали це внутрішньо за допомогою `issetugid()`, `hasRestrictedSegment()` і `csops(CS_OPS_STATUS)`. У **поточній версії `dyld` це рішення делеговано AMFI**, а код знаходиться в `ProcessConfig::Security::Security()` у `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
```cpp
const uint64_t amfiFlags = getAMFI(process, syscall);
this->allowAtPaths              = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_AT_PATH);
this->allowEnvVarsPrint         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS);
this->allowEnvVarsPath          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS);
this->allowEnvVarsSharedCache   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE);
this->allowClassicFallbackPaths = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS);
this->allowInsertFailures       = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION);
this->allowInterposing          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING);
this->allowEmbeddedVars         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS);
this->allowDevelopmentVars      = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_DEVELOPMENT_VARS);
this->allowLibSystemOverrides   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBSYSTEM_OVERRIDE);
...
// env vars are only pruned on macOS
switch ( process.platform.value() ) {
case PLATFORM_MACOS:
case PLATFORM_IOSMAC:
case PLATFORM_DRIVERKIT:
break;
default:
return;
}

// env vars are only pruned when process is restricted
if ( this->allowEnvVarsPrint || this->allowEnvVarsPath || this->allowEnvVarsSharedCache )
return;

this->pruneEnvVars(process);
```
З цього варто виділити дві речі:

- Pruning відбувається лише на **macOS / Mac Catalyst / DriverKit** — і лише тоді, коли AMFI не надав жодного з `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- Запит AMFI отримує власні властивості executable:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
де `isRestricted()` буквально є перевіркою сегмента `__RESTRICT` (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` потім видаляє **кожну** змінну, назва якої починається з `DYLD_`, і зсуває параметри `apple[]` вниз, тому дочірні процеси обмеженого процесу також їх не успадковують:
```cpp
// For security, setuid programs ignore DYLD_* environment variables.
// Additionally, the DYLD_* environment variables are removed
// from the environment, so that any child processes doesn't see them.
for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
if ( strncmp(*s, "DYLD_", 5) != 0 ) {
*d++ = *s;
}
...
```
> [!TIP]
> Практичний наслідок: **`DYLD_*` видаляється, коли процес обмежений** — setuid/setgid, секцією `__RESTRICT/__restrict` або бінарними файлами з hardened runtime/entitlements, яким AMFI відмовляється надавати прапорці path/print. Якщо натомість процес має лише **library validation** (`CS_REQUIRE_LV`), змінні зберігаються, але вставлена dylib має бути підписана тим самим **Team ID** (або Apple), тож для фактичного виконання коду потрібен один із entitlements, що вимикають library validation.

Оскільки тепер рішення ухвалює AMFI, найшвидший спосіб дізнатися, що отримає конкретний бінарний файл, — перевірити, на що спирається AMFI: entitlements і signing flags, а не сам `dyld`:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## Перевірка обмежень

### SUID та SGID
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
### Захищене середовище виконання

Створіть новий сертифікат у Keychain і використайте його для підписання бінарного файлу:
```bash
# Apply runtime protection
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
> Зверніть увагу, що навіть якщо існують binaries, підписані з flags **`0x0(none)`**, під час виконання вони можуть динамічно отримати flag **`CS_RESTRICT`**, тому ця техніка не працюватиме з ними.
>
> Перевірити, чи має proc цей flag, можна за допомогою (див. [**csops тут**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> після чого перевірте, чи увімкнено flag 0x800.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (process startup and library insertion)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
