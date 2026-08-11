# Ін’єкція бібліотек macOS

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Код **dyld є open source** і його можна знайти за адресою [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) та завантажити у форматі tar за **URL-адресою, наприклад** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Процес Dyld**

Ознайомтеся з тим, як Dyld завантажує бібліотеки всередині binary-файлів:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Це аналог [**LD_PRELOAD у Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Він дозволяє вказати процесу, який буде запущено, завантажити конкретну бібліотеку з певного шляху (якщо env var увімкнено)<sup>[[4]](#references)</sup>

Цю техніку також можна **використовувати як техніку ASEP**, оскільки кожен встановлений application має plist із назвою "Info.plist", який дає змогу **призначати environmental variables** за допомогою ключа `LSEnvironmental`.

> [!TIP]
> Починаючи з 2012 року, **Apple суттєво зменшила можливості** **`DYLD_INSERT_LIBRARIES`**. Процес вважається **restricted** — після чого `dyld` видаляє всі змінні `DYLD_*` з його environment — якщо виконується будь-яка з наведених умов:
>
> - Binary є `setuid/setgid`
> - Mach-O має секцію **`__RESTRICT/__restrict`**
> - Binary підписаний із hardened runtime, а AMFI не надає йому дозволів "path/print variables", тобто йому бракує [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Перевірити **entitlements** binary можна командою: `codesign -dv --entitlements :- </path/to/bin>`
>
> У поточному `dyld` це більше не визначається лише `dyld`: `ProcessConfig::Security::Security()` звертається до **AMFI** через `amfi_check_dyld_policy_self()`, а потім викликає `pruneEnvVars()`. Точний код розглянуто нижче в розділі [Prune `DYLD_*` env variables](#prune-dyld_-env-variables).

### Library Validation

Навіть якщо binary дозволяє **`DYLD_INSERT_LIBRARIES`** env var, він не завантажить custom library, якщо перевіряє підпис бібліотеки.

Щоб завантажити custom library, binary повинен мати **одне з наведених entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

або binary **не повинен мати** **hardened runtime flag** чи **library validation flag**.

Перевірити, чи має binary **hardened runtime**, можна за допомогою `codesign --display --verbose <bin>`, перевіривши runtime flag у **`CodeDirectory`**, наприклад: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Також можна завантажити бібліотеку, якщо її **підписано тим самим сертифікатом, що й binary**.

Приклад того, як (зловживати) цим і перевірити обмеження, наведено тут:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Пам’ятайте, що **попередні обмеження Library Validation також застосовуються** під час виконання атак Dylib hijacking.

Як і у Windows, у macOS можна **перехоплювати dylib**, щоб змусити **applications виконувати довільний code**. Зі звичайного user account це може бути неможливо, оскільки для запису всередину `.app` bundle з метою перехоплення бібліотеки може знадобитися дозвіл TCC.\
Однак спосіб, у який **applications macOS** **завантажують** бібліотеки, є **більш обмеженим**, ніж у Windows. Розробники malware усе ще можуть використовувати цю техніку для **stealth**, але зловживання нею для privilege escalation значно менш імовірне.

По-перше, набагато **частіше** можна виявити, що **binary-файли macOS вказують повний шлях** до бібліотек, які потрібно завантажити. По-друге, **macOS ніколи не шукає** бібліотеки в папках **$PATH**.

**Основна** частина **code**, пов’язаного з цією функціональністю, знаходиться у **`ImageLoader::recursiveLoadLibraries`** у `ImageLoader.cpp`.

Існує **4 різні header Commands**, які macho binary може використовувати для завантаження бібліотек:

- Команда **`LC_LOAD_DYLIB`** є стандартною командою для завантаження dylib.
- Команда **`LC_LOAD_WEAK_DYLIB`** працює як попередня, але якщо dylib не знайдено, виконання продовжується без помилки.
- Команда **`LC_REEXPORT_DYLIB`** проксіює (або повторно експортує) symbols з іншої бібліотеки.
- Команда **`LC_LOAD_UPWARD_DYLIB`** використовується, коли дві бібліотеки залежать одна від одної (це називається _upward dependency_).

Однак існує **2 типи dylib hijacking**:

- **Missing weak linked libraries**: це означає, що application спробує завантажити бібліотеку, якої не існує, налаштовану за допомогою **`LC_LOAD_WEAK_DYLIB`**. Тоді **якщо attacker розмістить dylib там, де її очікують, її буде завантажено**.
- Те, що link є "weak", означає, що application продовжить виконання, навіть якщо бібліотеку не знайдено.
- **Code, пов’язаний** із цим, знаходиться у функції `ImageLoaderMachO::doGetDependentLibraries` файлу `ImageLoaderMachO.cpp`, де `lib->required` має значення `false` лише тоді, коли `LC_LOAD_WEAK_DYLIB` має значення true.
- **Знайти weak linked libraries** у binary можна за допомогою (далі наведено приклад створення hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O binary може містити commands **`LC_RPATH`** і **`LC_LOAD_DYLIB`**. На основі **значень** цих commands **libraries** завантажуватимуться з **різних директорій**.
- **`LC_RPATH`** містить шляхи до деяких папок, які binary використовує для завантаження libraries.
- **`LC_LOAD_DYLIB`** містить шлях до конкретних libraries, які потрібно завантажити. Ці шляхи можуть містити **`@rpath`**, який буде **замінено** значеннями з **`LC_RPATH`**. Якщо в **`LC_RPATH`** є кілька шляхів, усі вони використовуватимуться для пошуку library, яку потрібно завантажити. Приклад:
- Якщо **`LC_LOAD_DYLIB`** містить `@rpath/library.dylib`, а **`LC_RPATH`** містить `/application/app.app/Contents/Framework/v1/` і `/application/app.app/Contents/Framework/v2/`. Обидві папки використовуватимуться для завантаження `library.dylib`**.** Якщо library не існує в `[...]/v1/`, attacker може розмістити її там, щоб перехопити завантаження library з `[...]/v2/`, оскільки порядок шляхів у **`LC_LOAD_DYLIB`** буде дотримано.
- **Знайти rpath paths і libraries** у binary можна за допомогою: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: це **шлях** до директорії, яка містить **main executable file**.
>
> **`@loader_path`**: це **шлях** до **директорії**, яка містить **Mach-O binary**, що містить load command.
>
> - У разі використання у executable **`@loader_path`** фактично є **таким самим**, як **`@executable_path`**.
> - У разі використання у **dylib** **`@loader_path`** вказує **шлях** до **dylib**.

Зловживання цією функціональністю для **privilege escalation** було б можливим у рідкісному випадку, коли **application**, який виконується **root**, **шукає** певну **library у папці, до якої attacker має права на запис.**

Корисним **scanner** для пошуку **missing libraries** в applications є [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) або [**CLI version**](https://github.com/pandazheng/DylibHijack).\
Корисний [**звіт із технічними деталями**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) про цю техніку можна знайти [**тут**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Приклад**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Пам’ятайте, що **попередні обмеження Library Validation також застосовуються** під час виконання атак Dlopen hijacking.

З **`man dlopen`**:

- Коли path **не містить символу slash** (тобто це лише leaf name), **dlopen() виконуватиме пошук**. Якщо під час запуску було встановлено **`$DYLD_LIBRARY_PATH`**, dyld спочатку **шукатиме в цій директорії**. Далі, якщо calling mach-o file або main executable вказує **`LC_RPATH`**, dyld **шукатиме в цих** директоріях. Потім, якщо process **unrestricted**, dyld шукатиме в поточній робочій директорії. Нарешті, для старих binary dyld спробує fallback paths. Якщо під час запуску було встановлено **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld шукатиме в **цих директоріях**, інакше dyld перегляне **`/usr/local/lib/`** (якщо process unrestricted), а потім **`/usr/lib/`** (цю інформацію взято з **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Якщо в name немає slashes, hijacking можна виконати двома способами:
>
> - Якщо будь-який **`LC_RPATH`** доступний для запису (але signature перевіряється, тому для цього binary також має бути unrestricted)
> - Якщо binary є **unrestricted**, і тоді можна завантажити щось із CWD (або зловжити однією зі згаданих env variables)

- Коли path **має вигляд path до framework** (наприклад, `/stuff/foo.framework/foo`), якщо під час запуску було встановлено **`$DYLD_FRAMEWORK_PATH`**, dyld спочатку шукатиме в цій директорії **partial path framework** (наприклад, `foo.framework/foo`). Далі dyld спробує **вказаний path як є** (використовуючи поточну робочу директорію для relative paths). Нарешті, для старих binary dyld спробує fallback paths. Якщо під час запуску було встановлено **`$DYLD_FALLBACK_FRAMEWORK_PATH`**, dyld шукатиме у цих директоріях. Інакше він шукатиме в **`/Library/Frameworks`** (у macOS, якщо process unrestricted), а потім у **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Якщо це framework path, hijack можна виконати так:
>
> - Якщо process є **unrestricted**, зловживаючи **relative path з CWD** і згаданими env variables (навіть якщо в документації не зазначено, що для restricted process env vars DYLD\_\* видаляються)

- Коли path **містить slash, але не є framework path** (тобто повний path або partial path до dylib), dlopen() спочатку шукає (якщо встановлено) в **`$DYLD_LIBRARY_PATH`** (використовуючи leaf part з path). Далі dyld **намагається використати вказаний path** (використовуючи поточну робочу директорію для relative paths (але лише для unrestricted processes)). Нарешті, для старіших binary dyld спробує fallback paths. Якщо під час запуску було встановлено **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld шукатиме в цих директоріях, інакше dyld перевірить **`/usr/local/lib/`** (якщо process unrestricted), а потім **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Якщо name містить slashes і не є framework, hijack можна виконати так:
>
> - Якщо binary є **unrestricted**, тоді можна завантажити щось із CWD або `/usr/local/lib` (чи зловжити однією зі згаданих env variables)

> [!TIP]
> Примітка: не існує configuration files для **керування пошуком dlopen**.
>
> Примітка: якщо main executable є **set\[ug]id binary** або codesigned із entitlements, усі environment variables ігноруються, і можна використовувати лише full path ([перевірте обмеження DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions), щоб отримати докладнішу інформацію)
>
> Примітка: Apple platforms використовують "universal" files для об’єднання 32-bit і 64-bit libraries. Це означає, що **окремих 32-bit і 64-bit search paths не існує**.
>
> Примітка: На Apple platforms більшість OS dylibs **об’єднано в dyld cache**, і вони не існують на диску. Тому виклик **`stat()`** для попередньої перевірки наявності OS dylib **не працюватиме**. Однак **`dlopen_preflight()`** використовує ті самі кроки, що й **`dlopen()`**, для пошуку сумісного mach-o file.

**Перевірка шляхів**

Перевірмо всі варіанти за допомогою такого code:
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
Якщо скомпілювати та виконати це, можна побачити, **де безуспішно шукали кожну бібліотеку**. Також можна **відфільтрувати логи FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Якщо **привілейований binary/app** (наприклад, SUID або будь-який binary із потужними entitlements) **завантажує бібліотеку за відносним шляхом** (наприклад, використовуючи `@executable_path` або `@loader_path`) і має вимкнену **Library Validation**, може бути можливо перемістити binary у місце, де attacker зможе **змінити бібліотеку, завантажену за відносним шляхом**, і використати це для інжекції коду в процес.

## Очищення змінних середовища `DYLD_*`

Старіші версії `dyld` (`dyld2.cpp`) визначали це всередині процесу за допомогою `issetugid()`, `hasRestrictedSegment()` і `csops(CS_OPS_STATUS)`. У **поточному `dyld` це рішення делеговано AMFI**, а код розташований у `ProcessConfig::Security::Security()` у `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
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
Із цього варто виокремити дві речі:

- Pruning відбувається лише на **macOS / Mac Catalyst / DriverKit** — і лише тоді, коли AMFI не надав жодного з `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- Запит AMFI отримує власні властивості executable-файлу:
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
`pruneEnvVars()` потім видаляє **кожну** змінну, назва якої починається з `DYLD_`, і переміщує параметри `apple[]` вниз, тож дочірні процеси обмеженого процесу також їх не успадковують:
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
> Практичний наслідок: **`DYLD_*` видаляються, коли процес обмежений** — setuid/setgid, секцією `__RESTRICT/__restrict` або бінарними файлами з hardened-runtime/entitlements, яким AMFI відмовляє у наданні path/print flags. Якщо ж процес має лише **library validation** (`CS_REQUIRE_LV`), змінні зберігаються, але вставлена dylib має бути підписана тим самим **Team ID** (або Apple), тому для фактичного впровадження коду потрібен один із entitlements, що вимикають library validation.

Оскільки тепер рішення приймає AMFI, найшвидший спосіб визначити, що отримає конкретний бінарний файл, — перевірити, на що спирається AMFI: entitlements і signing flags, а не сам `dyld`:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## Перевірка обмежень

### SUID і SGID
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

Створіть новий сертифікат у Keychain і використайте його для підпису бінарного файлу:
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
> Зверніть увагу, що навіть бінарні файли, підписані з прапорцями **`0x0(none)`**, можуть динамічно отримати прапорець **`CS_RESTRICT`** під час виконання, і тому ця техніка не працюватиме з ними.
>
> Перевірити, чи має proc цей прапорець, можна за допомогою (див. [**csops тут**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> після чого перевірте, чи увімкнено прапорець 0x800.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (перевірка `isRestricted()` / `__RESTRICT`)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (запуск процесу та вставка бібліотеки)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
