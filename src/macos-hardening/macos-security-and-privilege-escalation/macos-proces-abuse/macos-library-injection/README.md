# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Der Code von **dyld ist Open Source** und ist unter [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) zu finden und kann als tar über eine **URL wie** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) heruntergeladen werden.

## **Dyld Process**

Sieh dir an, wie Dyld Libraries innerhalb von Binaries lädt:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Dies entspricht [**LD_PRELOAD unter Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Damit kann für einen auszuführenden Prozess angegeben werden, eine bestimmte Library aus einem Pfad zu laden (wenn die Umgebungsvariable aktiviert ist).

Diese Technik kann auch als **ASEP-Technik verwendet werden**, da jede installierte Anwendung eine plist namens "Info.plist" besitzt, die das **Zuweisen von Umgebungsvariablen** über einen Schlüssel namens `LSEnvironmental` ermöglicht.

> [!TIP]
> Seit 2012 hat **Apple die Möglichkeiten von** **`DYLD_INSERT_LIBRARIES`** **drastisch reduziert**.
>
> Gehe zum Code und **überprüfe `src/dyld.cpp`**. In der Funktion **`pruneEnvironmentVariables`** ist zu sehen, dass **`DYLD_*`**-Variablen entfernt werden.
>
> In der Funktion **`processRestricted`** wird der Grund für die Einschränkung festgelegt. Bei der Überprüfung dieses Codes ist zu sehen, dass die Gründe folgende sind:
>
> - Das Binary ist `setuid/setgid`
> - Vorhandensein eines Abschnitts `__RESTRICT/__restrict` im Mach-O-Binary.
> - Die Software besitzt Entitlements (hardened runtime), aber kein [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)-Entitlement
>  - Überprüfe die **Entitlements** eines Binaries mit: `codesign -dv --entitlements :- </path/to/bin>`
>
> In aktuelleren Versionen ist diese Logik im zweiten Teil der Funktion **`configureProcessRestrictions`** zu finden. In neueren Versionen wird jedoch die **Prüfung am Anfang der Funktion** ausgeführt (die ifs für iOS oder die Simulation können entfernt werden, da sie unter macOS nicht verwendet werden).

### Library Validation

Selbst wenn das Binary die Umgebungsvariable **`DYLD_INSERT_LIBRARIES`** verwenden darf, wird es keine eigene Library laden, wenn das Binary die Signatur der zu ladenden Library überprüft.

Um eine eigene Library zu laden, muss das Binary **eines der folgenden Entitlements** besitzen:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

oder das Binary darf **nicht** das **hardened runtime flag** oder das **library validation flag** besitzen.

Du kannst prüfen, ob ein Binary **hardened runtime** besitzt, mit `codesign --display --verbose <bin>`, indem du das Runtime-Flag in **`CodeDirectory`** überprüfst, zum Beispiel: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Du kannst eine Library auch laden, wenn sie mit demselben Zertifikat wie das Binary signiert ist.

Ein Beispiel dafür, wie dies (miss)braucht werden kann und wie die Einschränkungen überprüft werden, findest du unter:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Denke daran, dass die **zuvor genannten Einschränkungen der Library Validation ebenfalls** für Dylib Hijacking-Angriffe gelten.

Wie unter Windows kannst du auch unter macOS **dylibs hijacken**, damit **Anwendungen** **beliebigen** **Code ausführen** (tatsächlich ist dies als normaler Benutzer möglicherweise nicht möglich, da du eventuell eine TCC-Berechtigung benötigst, um in ein `.app`-Bundle zu schreiben und eine Library zu hijacken).\
Allerdings ist die Art, wie **macOS**-Anwendungen Libraries **laden**, stärker eingeschränkt als unter Windows. Das bedeutet, dass **Malware**-Entwickler diese Technik weiterhin für **Stealth** verwenden können, die Wahrscheinlichkeit, sie zur **Privilege Escalation** zu missbrauchen, jedoch deutlich geringer ist.

Erstens ist es **häufiger**, dass **macOS-Binaries den vollständigen Pfad** zu den zu ladenden Libraries angeben. Zweitens sucht **macOS niemals** in den Ordnern von **$PATH** nach Libraries.

Der **wichtigste** Teil des **Codes** für diese Funktion befindet sich in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Es gibt **4 verschiedene Header Commands**, die ein Mach-O-Binary zum Laden von Libraries verwenden kann:

- Der **`LC_LOAD_DYLIB`**-Befehl ist der übliche Befehl zum Laden einer dylib.
- Der **`LC_LOAD_WEAK_DYLIB`**-Befehl funktioniert wie der vorherige, aber wenn die dylib nicht gefunden wird, wird die Ausführung ohne Fehler fortgesetzt.
- Der **`LC_REEXPORT_DYLIB`**-Befehl proxied (oder re-exportiert) die Symbole einer anderen Library.
- Der **`LC_LOAD_UPWARD_DYLIB`**-Befehl wird verwendet, wenn zwei Libraries voneinander abhängen (dies wird als _upward dependency_ bezeichnet).

Es gibt jedoch **2 Arten von Dylib Hijacking**:

- **Fehlende weak linked Libraries**: Das bedeutet, dass die Anwendung versucht, eine nicht vorhandene Library zu laden, die mit **LC_LOAD_WEAK_DYLIB** konfiguriert ist. Wenn ein **Angreifer eine dylib an der erwarteten Stelle platziert, wird sie geladen**.
- Dass der Link "weak" ist, bedeutet, dass die Anwendung auch dann weiterläuft, wenn die Library nicht gefunden wird.
- Der **zugehörige Code** befindet sich in der Funktion `ImageLoaderMachO::doGetDependentLibraries` von `ImageLoaderMachO.cpp`, wobei `lib->required` nur dann `false` ist, wenn `LC_LOAD_WEAK_DYLIB` true ist.
- **Finde weak linked Libraries** in Binaries mit (weiter unten findest du ein Beispiel zum Erstellen von Hijacking-Libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Mit @rpath konfiguriert**: Mach-O-Binaries können die Commands **`LC_RPATH`** und **`LC_LOAD_DYLIB`** enthalten. Abhängig von den **Werten** dieser Commands werden **Libraries** aus **unterschiedlichen Verzeichnissen** geladen.
- **`LC_RPATH`** enthält die Pfade einiger Ordner, die vom Binary zum Laden von Libraries verwendet werden.
- **`LC_LOAD_DYLIB`** enthält den Pfad zu bestimmten zu ladenden Libraries. Diese Pfade können **`@rpath`** enthalten, das durch die Werte in **`LC_RPATH`** ersetzt wird. Wenn es mehrere Pfade in **`LC_RPATH`** gibt, werden alle verwendet, um nach der zu ladenden Library zu suchen. Beispiel:
- Wenn **`LC_LOAD_DYLIB`** `@rpath/library.dylib` enthält und **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` sowie `/application/app.app/Contents/Framework/v2/` enthält, werden beide Ordner zum Laden von `library.dylib` verwendet**.** Wenn die Library in `[...]/v1/` nicht existiert und ein Angreifer sie dort platzieren kann, kann er das Laden der Library in `[...]/v2/` hijacken, da die Reihenfolge der Pfade in **`LC_LOAD_DYLIB`** befolgt wird.
- **Finde rpath-Pfade und Libraries** in Binaries mit: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Ist der **Pfad** zum Verzeichnis, das die **Haupt-Executable-Datei** enthält.
>
> **`@loader_path`**: Ist der **Pfad** zum **Verzeichnis**, das das **Mach-O-Binary** enthält, welches den Load Command enthält.
>
> - Bei Verwendung in einer Executable ist **`@loader_path`** effektiv dasselbe wie **`@executable_path`**.
> - Bei Verwendung in einer **dylib** liefert **`@loader_path`** den **Pfad** zur **dylib**.

Eine **Privilege Escalation** durch Missbrauch dieser Funktion wäre in dem seltenen Fall möglich, dass eine **von** **root** ausgeführte **Anwendung** nach einer **Library in einem Ordner sucht, für den der Angreifer Schreibberechtigungen besitzt.**

Ein guter **Scanner**, um **fehlende Libraries** in Anwendungen zu finden, ist [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) oder eine [**CLI-Version**](https://github.com/pandazheng/DylibHijack).\
Einen guten **Bericht mit technischen Details** zu dieser Technik findest du [**hier**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Beispiel**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Denke daran, dass die **zuvor genannten Einschränkungen der Library Validation ebenfalls** für Dlopen Hijacking-Angriffe gelten.

Aus **`man dlopen`**:

- Wenn der Pfad **kein Slash-Zeichen enthält** (also nur aus einem Blattnamen besteht), führt **dlopen() eine Suche durch**. Wenn **`$DYLD_LIBRARY_PATH`** beim Start gesetzt war, sucht dyld zuerst **in diesem Verzeichnis**. Wenn die aufrufende Mach-O-Datei oder die Haupt-Executable ein **`LC_RPATH`** angibt, sucht dyld anschließend **in diesen** Verzeichnissen. Wenn der Prozess **unrestricted** ist, sucht dyld danach im aktuellen Arbeitsverzeichnis. Bei älteren Binaries versucht dyld zuletzt einige Fallbacks. Wenn **`$DYLD_FALLBACK_LIBRARY_PATH`** beim Start gesetzt war, sucht dyld in **diesen Verzeichnissen**, andernfalls sucht dyld in **`/usr/local/lib/`** (wenn der Prozess unrestricted ist) und anschließend in **`/usr/lib/`** (diese Information stammt aus **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Wenn der Name keine Slashes enthält, gibt es 2 Möglichkeiten für ein Hijacking:
>
> - Wenn ein **`LC_RPATH`** **beschreibbar** ist (die Signatur wird jedoch überprüft, daher muss das Binary hierfür ebenfalls unrestricted sein)
> - Wenn das Binary **unrestricted** ist und daher etwas aus dem CWD geladen werden kann (oder eine der genannten Umgebungsvariablen missbraucht wird)

- Wenn der Pfad wie ein **Framework**-Pfad aussieht (z. B. `/stuff/foo.framework/foo`), sucht dyld zuerst in dem Verzeichnis nach dem **partiellen Framework-Pfad** (z. B. `foo.framework/foo`), wenn **`$DYLD_FRAMEWORK_PATH`** beim Start gesetzt war. Anschließend versucht dyld den **bereitgestellten Pfad unverändert** (für relative Pfade wird das aktuelle Arbeitsverzeichnis verwendet). Bei älteren Binaries versucht dyld zuletzt einige Fallbacks. Wenn **`$DYLD_FALLBACK_FRAMEWORK_PATH`** beim Start gesetzt war, sucht dyld in diesen Verzeichnissen. Andernfalls sucht es in **`/Library/Frameworks`** (unter macOS, wenn der Prozess unrestricted ist) und anschließend in **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Wenn es sich um einen Framework-Pfad handelt, wäre ein Hijacking folgendermaßen möglich:
>
> - Wenn der Prozess **unrestricted** ist, durch Missbrauch des **relativen Pfads aus dem CWD** und der genannten Umgebungsvariablen (auch wenn dies nicht in der Dokumentation steht, werden bei einem restricted Prozess DYLD\_\*-Umgebungsvariablen entfernt)

- Wenn der Pfad einen Slash enthält, aber kein Framework-Pfad ist (also ein vollständiger oder partieller Pfad zu einer dylib), sucht dlopen zunächst (falls gesetzt) in **`$DYLD_LIBRARY_PATH`** (mit dem Leaf-Teil des Pfads). Danach **versucht dyld den bereitgestellten Pfad** (für relative Pfade wird das aktuelle Arbeitsverzeichnis verwendet, jedoch nur für unrestricted Prozesse). Bei älteren Binaries versucht dyld zuletzt einige Fallbacks. Wenn **`$DYLD_FALLBACK_LIBRARY_PATH`** beim Start gesetzt war, sucht dyld in diesen Verzeichnissen, andernfalls sucht dyld in **`/usr/local/lib/`** (wenn der Prozess unrestricted ist) und anschließend in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Wenn der Name Slashes enthält und kein Framework ist, wäre ein Hijacking folgendermaßen möglich:
>
> - Wenn das Binary **unrestricted** ist und daher etwas aus dem CWD oder **`/usr/local/lib`** geladen werden kann (oder eine der genannten Umgebungsvariablen missbraucht wird)

> [!TIP]
> Hinweis: Es gibt **keine** Konfigurationsdateien zur **Steuerung der dlopen-Suche**.
>
> Hinweis: Wenn die Haupt-Executable ein **set\[ug]id-Binary** ist oder mit Entitlements codesigniert wurde, werden **alle Umgebungsvariablen ignoriert** und es kann nur ein vollständiger Pfad verwendet werden ([überprüfe die DYLD_INSERT_LIBRARIES-Einschränkungen](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) für detailliertere Informationen).
>
> Hinweis: Apple-Plattformen verwenden "universelle" Dateien, um 32-Bit- und 64-Bit-Libraries zu kombinieren. Daher gibt es **keine separaten 32-Bit- und 64-Bit-Suchpfade**.
>
> Hinweis: Auf Apple-Plattformen sind die meisten OS-dylibs im **dyld cache** kombiniert und existieren nicht auf der Festplatte. Daher funktioniert ein Aufruf von **`stat()`**, um vorab zu prüfen, ob eine OS-dylib existiert, **nicht**. **`dlopen_preflight()`** verwendet jedoch dieselben Schritte wie **`dlopen()`**, um eine kompatible Mach-O-Datei zu finden.

**Pfade überprüfen**

Überprüfen wir alle Optionen mit dem folgenden Code:
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
Wenn du es kompilierst und ausführst, kannst du sehen, **wo nach jeder Bibliothek erfolglos gesucht wurde**. Außerdem könntest du die **FS-Logs filtern**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Wenn ein **privileged binary/app** (wie ein SUID- oder ein Binary mit leistungsfähigen Entitlements) eine Library über einen **relativen Pfad** lädt (beispielsweise mithilfe von `@executable_path` oder `@loader_path`) und **Library Validation deaktiviert** ist, könnte es möglich sein, das Binary an einen Ort zu verschieben, an dem der Angreifer die über den relativen Pfad geladene Library **modifizieren** kann, und dies zum Injizieren von Code in den Prozess zu missbrauchen.

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

In der Datei `dyld-dyld-832.7.1/src/dyld2.cpp` kann die Funktion **`pruneEnvironmentVariables`** gefunden werden, die alle Umgebungsvariablen entfernt, die **mit `DYLD_` beginnen** oder **`LD_LIBRARY_PATH=`** entsprechen.

Außerdem setzt sie speziell die Umgebungsvariablen **`DYLD_FALLBACK_FRAMEWORK_PATH`** und **`DYLD_FALLBACK_LIBRARY_PATH`** für **suid**- und **sgid**-Binaries auf **null**.

Diese Funktion wird aus der **`_main`**-Funktion derselben Datei aufgerufen, wenn OSX als Ziel verwendet wird, etwa so:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
und diese Boolean-Flags werden im Code in derselben Datei gesetzt:
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
Das bedeutet im Grunde, dass **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** wahr ist und die Umgebungsvariablen entfernt werden, wenn die Binary **suid** oder **sgid** ist, ein **RESTRICT**-Segment in den Headern enthält oder mit dem Flag **CS_RESTRICT** signiert wurde.

Beachte, dass die Variablen nicht entfernt werden, wenn CS_REQUIRE_LV wahr ist. Die Library validation überprüft jedoch, ob sie dasselbe Zertifikat wie die ursprüngliche Binary verwenden.

## Restrictions prüfen

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
### Abschnitt `__RESTRICT` mit Segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened Runtime

Erstellen Sie ein neues Zertifikat im Keychain und verwenden Sie es, um das Binary zu signieren:
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
> Beachte, dass selbst Binaries, die mit den Flags **`0x0(none)`** signiert sind, beim Ausführen dynamisch das Flag **`CS_RESTRICT`** erhalten können. Daher funktioniert diese Technik bei ihnen nicht.
>
> Du kannst mit (siehe [**csops hier**](https://github.com/axelexic/CSOps)) überprüfen, ob ein proc dieses Flag besitzt:
>
> ```bash
> csops -status <pid>
> ```
>
> und anschließend prüfen, ob das Flag 0x800 aktiviert ist.

## Referenzen

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
