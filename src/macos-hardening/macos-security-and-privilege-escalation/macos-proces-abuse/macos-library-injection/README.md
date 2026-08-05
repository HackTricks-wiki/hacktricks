# Ін’єкція бібліотек у macOS

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Код **dyld** є open source і доступний за адресою [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/), а також його можна завантажити у форматі tar за **URL, таким як** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Процес Dyld**

Ознайомтеся з тим, як Dyld завантажує бібліотеки всередині бінарних файлів:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Це аналог [**LD_PRELOAD у Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Він дозволяє вказати процесу, який буде запущено, завантажити певну бібліотеку із заданого шляху (якщо змінну середовища увімкнено).

Цю техніку також можна **використовувати як техніку ASEP**, оскільки кожен встановлений застосунок має plist під назвою "Info.plist", який дозволяє **призначати змінні середовища** за допомогою ключа `LSEnvironmental`.

> [!TIP]
> Починаючи з 2012 року **Apple суттєво зменшила можливості** **`DYLD_INSERT_LIBRARIES`**. Процес вважається **restricted** — після чого `dyld` видаляє всі змінні `DYLD_*` з його середовища, — якщо виконується будь-яка з наведених умов:
>
> - Бінарний файл має `setuid/setgid`
> - Mach-O має секцію **`__RESTRICT/__restrict`**
> - Бінарний файл підписаний із hardened runtime, а AMFI не надає йому дозволів "path/print variables", тобто в ньому відсутній [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[3]</sup>
>   - Перевірити **entitlements** бінарного файла можна командою: `codesign -dv --entitlements :- </path/to/bin>`
>
> У сучасному `dyld` це більше не визначається лише самим `dyld`: `ProcessConfig::Security::Security()` звертається до **AMFI** через `amfi_check_dyld_policy_self()`, а потім викликає `pruneEnvVars()`. Точний код розглянуто нижче, у розділі [Prune `DYLD_*` env variables](#prune-dyld_-env-variables).

### Library Validation

Навіть якщо бінарний файл дозволяє використовувати змінну середовища **`DYLD_INSERT_LIBRARIES`**, якщо він перевіряє підпис бібліотеки перед завантаженням, він не завантажить custom бібліотеку.

Щоб завантажити custom бібліотеку, бінарний файл повинен мати **один із наведених entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

або бінарний файл **не повинен мати** **hardened runtime flag** чи **library validation flag**.

Перевірити, чи має бінарний файл **hardened runtime**, можна за допомогою `codesign --display --verbose <bin>`, перевіривши runtime flag у **`CodeDirectory`**, наприклад: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Також можна завантажити бібліотеку, якщо її **підписано тим самим сертифікатом, що й бінарний файл**.

Приклад того, як (зловмисно) використати це та перевірити обмеження, наведено тут:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Пам’ятайте, що **попередні обмеження Library Validation також застосовуються** під час виконання атак Dylib hijacking.

Як і у Windows, у MacOS також можна **виконати hijacking dylib**, щоб змусити **застосунки** **виконувати** **довільний** **код** (щоправда, для звичайного користувача це може бути неможливо, оскільки може знадобитися дозвіл TCC на запис усередині пакета `.app` і hijack бібліотеки).\
Однак спосіб, у який застосунки **MacOS** **завантажують** бібліотеки, є **більш обмеженим**, ніж у Windows. Це означає, що розробники **malware** все ще можуть використовувати цю техніку для **прихованості**, але ймовірність використати її для escalation privileges є значно нижчою.

По-перше, у **MacOS** **бінарні файли частіше містять повний шлях** до бібліотек, які потрібно завантажити. По-друге, **MacOS ніколи не шукає** бібліотеки в папках із **$PATH**.

**Основна** частина **коду**, пов’язаного з цією функціональністю, міститься в **`ImageLoader::recursiveLoadLibraries`** у `ImageLoader.cpp`.

Існує **4 різні header Commands**, які macho-бінарний файл може використовувати для завантаження бібліотек:

- Команда **`LC_LOAD_DYLIB`** є стандартною командою для завантаження dylib.
- Команда **`LC_LOAD_WEAK_DYLIB`** працює як попередня, але якщо dylib не знайдено, виконання продовжується без помилки.
- Команда **`LC_REEXPORT_DYLIB`** проксіює (або повторно експортує) symbols з іншої бібліотеки.
- Команда **`LC_LOAD_UPWARD_DYLIB`** використовується, коли дві бібліотеки залежать одна від одної (це називається _upward dependency_).

Однак існує **2 типи Dylib hijacking**:

- **Відсутні weak linked libraries**: це означає, що застосунок спробує завантажити неіснуючу бібліотеку, налаштовану за допомогою **LC_LOAD_WEAK_DYLIB**. Тоді, **якщо attacker розмістить dylib там, де її очікують, її буде завантажено**.
- Те, що link є "weak", означає, що застосунок продовжить працювати, навіть якщо бібліотеку не знайдено.
- **Код, пов’язаний** із цим, міститься у функції `ImageLoaderMachO::doGetDependentLibraries` з `ImageLoaderMachO.cpp`, де `lib->required` має значення `false` лише тоді, коли `LC_LOAD_WEAK_DYLIB` має значення true.
- **Знайти weak linked libraries** у бінарних файлах можна за допомогою (нижче наведено приклад створення hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Налаштовані через @rpath**: Mach-O-бінарні файли можуть містити команди **`LC_RPATH`** і **`LC_LOAD_DYLIB`**. На основі **значень** цих команд **бібліотеки** **завантажуватимуться** з **різних директорій**.
- **`LC_RPATH`** містить шляхи до папок, які бінарний файл використовує для завантаження бібліотек.
- **`LC_LOAD_DYLIB`** містить шлях до конкретних бібліотек, які потрібно завантажити. Ці шляхи можуть містити **`@rpath`**, який буде **замінено** значеннями з **`LC_RPATH`**. Якщо в **`LC_RPATH`** є кілька шляхів, усі вони використовуватимуться для пошуку бібліотеки. Приклад:
- Якщо **`LC_LOAD_DYLIB`** містить `@rpath/library.dylib`, а **`LC_RPATH`** містить `/application/app.app/Contents/Framework/v1/` і `/application/app.app/Contents/Framework/v2/`, обидві папки використовуватимуться для завантаження `library.dylib`**.** Якщо бібліотека не існує у `[...]/v1/`, attacker може розмістити її там і перехопити завантаження бібліотеки з `[...]/v2/`, оскільки порядок шляхів у **`LC_LOAD_DYLIB`** зберігається.
- **Знайти rpath paths і libraries** у бінарних файлах можна за допомогою: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Це **шлях** до директорії, що містить **основний виконуваний файл**.
>
> **`@loader_path`**: Це **шлях** до **директорії**, що містить **Mach-O-бінарний файл**, у якому є команда load.
>
> - Під час використання у виконуваному файлі **`@loader_path`** фактично збігається з **`@executable_path`**.
> - Під час використання у **dylib** **`@loader_path`** вказує **шлях** до **dylib**.

Спосіб **підвищити привілеї**, зловживаючи цією функціональністю, можливий у рідкісному випадку, коли **застосунок**, який запускається від імені **root**, **шукає** якусь **бібліотеку в папці, до якої attacker має права запису**.

> [!TIP]
> Хорошим **scanner** для пошуку **відсутніх бібліотек** у застосунках є [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) або [**CLI-версія**](https://github.com/pandazheng/DylibHijack).\
> Хороший **звіт із технічними деталями** про цю техніку можна знайти [**тут**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Приклад**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Пам’ятайте, що **попередні обмеження Library Validation також застосовуються** під час виконання атак Dlopen hijacking.

З **`man dlopen`**:

- Якщо шлях **не містить символу слеша** (тобто це лише leaf name), **dlopen() виконуватиме пошук**. Якщо під час запуску було встановлено **`$DYLD_LIBRARY_PATH`**, dyld спочатку **шукатиме в цій директорії**. Далі, якщо calling mach-o file або main executable визначає **`LC_RPATH`**, dyld **шукатиме в цих** директоріях. Потім, якщо процес **unrestricted**, dyld шукатиме в **поточній робочій директорії**. Нарешті, для старих бінарних файлів dyld спробує деякі fallback-шляхи. Якщо під час запуску було встановлено **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld шукатиме в **цих директоріях**, інакше dyld шукатиме в **`/usr/local/lib/`** (якщо процес unrestricted), а потім у **`/usr/lib/`** (цю інформацію взято з **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(якщо unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (якщо unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Якщо ім’я не містить слешів, існує 2 способи виконати hijacking:
>
> - Якщо будь-який **`LC_RPATH`** доступний для запису (але підпис перевіряється, тому для цього бінарний файл також має бути unrestricted)
> - Якщо бінарний файл є **unrestricted**, тоді можна завантажити щось із CWD (або зловживати однією зі згаданих змінних середовища)

- Якщо шлях **схожий на шлях до framework** (наприклад, `/stuff/foo.framework/foo`), і під час запуску було встановлено **`$DYLD_FRAMEWORK_PATH`**, dyld спочатку шукатиме в цій директорії **частковий шлях до framework** (наприклад, `foo.framework/foo`). Далі dyld спробує **наданий шлях як є** (для відносних шляхів використовуючи поточну робочу директорію). Нарешті, для старих бінарних файлів dyld спробує деякі fallback-шляхи. Якщо під час запуску було встановлено **`$DYLD_FALLBACK_FRAMEWORK_PATH`**, dyld шукатиме у вказаних директоріях. Інакше він шукатиме в **`/Library/Frameworks`** (у macOS, якщо процес unrestricted), а потім у **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. наданий шлях (для відносних шляхів використовується поточна робоча директорія, якщо процес unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (якщо unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Якщо це шлях до framework, hijack можна виконати так:
>
> - Якщо процес **unrestricted**, зловживаючи **відносним шляхом із CWD** або згаданими змінними середовища (навіть якщо в документації це не зазначено, для restricted-процесу змінні середовища DYLD\_\* видаляються)

- Якщо шлях **містить слеш, але не є шляхом до framework** (тобто повний або частковий шлях до dylib), dlopen() спочатку шукає (якщо встановлено) у **`$DYLD_LIBRARY_PATH`** (використовуючи leaf part із шляху). Далі dyld **намагається використати наданий шлях** (для відносних шляхів використовуючи поточну робочу директорію, але лише для unrestricted-процесів). Нарешті, для старих бінарних файлів dyld спробує fallback-шляхи. Якщо під час запуску було встановлено **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld шукатиме в цих директоріях, інакше dyld шукатиме в **`/usr/local/lib/`** (якщо процес unrestricted), а потім у **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. наданий шлях (для відносних шляхів використовується поточна робоча директорія, якщо процес unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (якщо unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Якщо ім’я містить слеші, але це не framework, hijack можна виконати так:
>
> - Якщо бінарний файл є **unrestricted**, тоді можна завантажити щось із CWD або `/usr/local/lib` (або зловживати однією зі згаданих змінних середовища)

> [!TIP]
> Примітка: не існує конфігураційних файлів для **керування пошуком dlopen**.
>
> Примітка: якщо основний виконуваний файл є **set\[ug]id-бінарним файлом або підписаний codesign із entitlements**, усі змінні середовища ігноруються, і можна використовувати лише повний шлях ([перевірте обмеження DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions), щоб отримати докладнішу інформацію)
>
> Примітка: платформи Apple використовують "universal" файли для об’єднання 32-бітних і 64-бітних бібліотек. Це означає, що **окремих шляхів пошуку для 32-бітних і 64-бітних бібліотек не існує**.
>
> Примітка: на платформах Apple більшість системних dylib **об’єднано в dyld cache**, і на диску вони не існують. Тому виклик **`stat()`** для попередньої перевірки наявності системної dylib **не працюватиме**. Однак **`dlopen_preflight()`** використовує ті самі кроки, що й **`dlopen()`**, для пошуку сумісного mach-o-файла.

**Перевірка шляхів**

Перевірмо всі варіанти за допомогою такого коду:
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
Якщо скомпілювати та виконати його, можна побачити, **де безуспішно шукали кожну бібліотеку**. Також можна **відфільтрувати логи FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Якщо **привілейований бінарний файл/застосунок** (наприклад, SUID або бінарний файл із потужними entitlements) **завантажує бібліотеку за відносним шляхом** (наприклад, використовуючи `@executable_path` або `@loader_path`) і має вимкнену **Library Validation**, може бути можливо перемістити бінарний файл у місце, де атакер зможе **змінити бібліотеку, завантажену за відносним шляхом**, і використати це для ін'єкції коду в процес.

## Очищення змінних середовища `DYLD_*`

Старіші версії `dyld` (`dyld2.cpp`) визначали це всередині процесу за допомогою `issetugid()`, `hasRestrictedSegment()` і `csops(CS_OPS_STATUS)`. У **поточному `dyld` це рішення делеговано AMFI**, а код розташований у `ProcessConfig::Security::Security()` у `dyld/DyldProcessConfig.cpp`:<sup>[1]</sup>
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

- Pruning відбувається лише на **macOS / Mac Catalyst / DriverKit** — і лише тоді, коли AMFI не надав жодного з дозволів `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- Запит AMFI отримує власні властивості executable:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
де `isRestricted()` буквально є перевіркою сегмента `__RESTRICT` (`mach_o/UnsafeHeader.cpp`):<sup>[2]</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` після цього видаляє **кожну** змінну, назва якої починається з `DYLD_`, і зсуває параметри `apple[]` вниз, тому дочірні процеси обмеженого процесу також їх не успадковують:
```cpp
// For security, setuid programs ignore DYLD_* environment variables.
// Additionally, the DYLD_* enviroment variables are removed
// from the environment, so that any child processes doesn't see them.
for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
if ( strncmp(*s, "DYLD_", 5) != 0 ) {
*d++ = *s;
}
...
```
> [!TIP]
> Практичний наслідок: **`DYLD_*` видаляється, коли процес обмежений** — setuid/setgid, секцією `__RESTRICT/__restrict` або hardened-runtime/entitled бінарниками, яким AMFI відмовляє у наданні path/print flags. Якщо натомість процес має лише **library validation** (`CS_REQUIRE_LV`), змінні зберігаються, але вставлена dylib має бути підписана тим самим **Team ID** (або Apple), тож для фактичного впровадження коду потрібен один із entitlements, що вимикають library validation.

Оскільки рішення тепер приймає AMFI, найшвидший спосіб визначити, що отримає конкретний бінарник, — перевірити, на що спирається AMFI: entitlements і signing flags, а не сам `dyld`:
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
> Зверніть увагу, що навіть бінарні файли, підписані з flags **`0x0(none)`**, можуть динамічно отримати flag **`CS_RESTRICT`** під час виконання, тому ця техніка для них не працюватиме.
>
> Перевірити, чи має proc цей flag, можна за допомогою (отримати [**csops тут**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> після чого перевірити, чи увімкнено flag 0x800.

## Посилання

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (перевірка `isRestricted()` / `__RESTRICT`)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (запуск процесу та вставлення бібліотек)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
