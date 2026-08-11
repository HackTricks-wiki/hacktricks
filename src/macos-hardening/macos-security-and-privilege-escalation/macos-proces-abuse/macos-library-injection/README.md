# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Der Code von **dyld ist Open Source** und kann unter [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) gefunden und als Tar-Archiv über eine **URL wie** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) heruntergeladen werden.

## **Dyld Process**

Sieh dir an, wie Dyld Libraries innerhalb von Binaries lädt:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Dies entspricht [**LD_PRELOAD unter Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Damit kann ein Prozess, der ausgeführt werden soll, angewiesen werden, eine bestimmte Library aus einem Pfad zu laden (falls die Umgebungsvariable aktiviert ist)<sup>[[4]](#references)</sup>.

Diese Technik kann auch als **ASEP-Technik verwendet werden**, da jede installierte Anwendung eine plist namens "Info.plist" besitzt, die das **Zuweisen von Umgebungsvariablen** über einen Schlüssel namens `LSEnvironmental` ermöglicht.

> [!TIP]
> Seit 2012 hat **Apple die Möglichkeiten von** **`DYLD_INSERT_LIBRARIES`** **drastisch eingeschränkt**. Ein Prozess gilt als **restricted** — woraufhin `dyld` jede `DYLD_*`-Variable aus seiner Umgebung löscht — wenn eine der folgenden Bedingungen erfüllt ist:
>
> - Das Binary ist `setuid/setgid`
> - Das Mach-O besitzt einen Abschnitt **`__RESTRICT/__restrict`**
> - Das Binary ist mit der hardened runtime signiert und AMFI gewährt ihm nicht die Berechtigungen "path/print variables", d. h., es fehlt [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - **Entitlements** eines Binaries mit folgendem Befehl prüfen: `codesign -dv --entitlements :- </path/to/bin>`
>
> In aktuellem `dyld` wird dies nicht mehr ausschließlich von `dyld` entschieden: `ProcessConfig::Security::Security()` fragt AMFI über `amfi_check_dyld_policy_self()` ab und ruft anschließend `pruneEnvVars()` auf. Der genaue Code wird weiter unten unter [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) erläutert.

### Library Validation

Auch wenn das Binary die Umgebungsvariable **`DYLD_INSERT_LIBRARIES`** erlaubt, wird es keine benutzerdefinierte Library laden, wenn es die Signatur der Library validiert.

Um eine benutzerdefinierte Library zu laden, muss das Binary **eines der folgenden Entitlements** besitzen:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

oder das Binary darf **nicht** über das **hardened runtime flag** oder das **library validation flag** verfügen.

Ob ein Binary über **hardened runtime** verfügt, kannst du mit `codesign --display --verbose <bin>` prüfen, indem du in **`CodeDirectory`** nach dem runtime-Flag suchst, zum Beispiel: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Du kannst eine Library auch laden, wenn sie mit demselben Zertifikat wie das Binary signiert ist.

Ein Beispiel dafür, wie dies (miss)braucht werden kann und wie die Einschränkungen geprüft werden, findest du unter:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Denke daran, dass die **zuvor genannten Library-Validation-Einschränkungen ebenfalls** für Dylib hijacking attacks gelten.

Wie unter Windows kannst du auch unter MacOS **dylibs hijacken**, damit **Anwendungen** **beliebigen** **Code** **ausführen** (tatsächlich wäre dies für einen normalen Benutzer nicht möglich, da möglicherweise eine TCC-Berechtigung erforderlich ist, um in ein `.app`-Bundle zu schreiben und eine Library zu hijacken).\
Allerdings ist die Art, wie **MacOS**-Anwendungen Libraries **laden**, stärker eingeschränkt als unter Windows. Das bedeutet, dass **Malware**-Entwickler diese Technik weiterhin für **Stealth** einsetzen können, die Wahrscheinlichkeit, sie zur **Privilege Escalation** zu missbrauchen, jedoch deutlich geringer ist.

Erstens ist es **häufiger**, dass **MacOS-Binaries den vollständigen Pfad** zu den zu ladenden Libraries angeben. Zweitens sucht **MacOS niemals** in den Ordnern von **$PATH** nach Libraries.

Der **wichtigste** Teil des **Codes**, der sich auf diese Funktionalität bezieht, befindet sich in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Ein Mach-O-Binary kann vier verschiedene Header Commands zum Laden von Libraries verwenden:

- Der **`LC_LOAD_DYLIB`**-Befehl ist der übliche Befehl zum Laden einer dylib.
- Der **`LC_LOAD_WEAK_DYLIB`**-Befehl funktioniert wie der vorherige, aber wenn die dylib nicht gefunden wird, wird die Ausführung ohne Fehler fortgesetzt.
- Der **`LC_REEXPORT_DYLIB`**-Befehl stellt die Symbole einer anderen Library als Proxy bereit (oder exportiert sie erneut).
- Der **`LC_LOAD_UPWARD_DYLIB`**-Befehl wird verwendet, wenn zwei Libraries voneinander abhängen (dies wird als _upward dependency_ bezeichnet).

Es gibt jedoch **zwei Arten von Dylib hijacking**:

- **Fehlende weak linked libraries**: Das bedeutet, dass die Anwendung versucht, eine nicht vorhandene Library zu laden, die mit **LC_LOAD_WEAK_DYLIB** konfiguriert ist. Wenn ein Angreifer anschließend eine dylib an der erwarteten Stelle platziert, wird sie geladen.
- Die Tatsache, dass der Link "weak" ist, bedeutet, dass die Anwendung auch dann weiterläuft, wenn die Library nicht gefunden wird.
- Der **zugehörige Code** befindet sich in der Funktion `ImageLoaderMachO::doGetDependentLibraries` von `ImageLoaderMachO.cpp`, wo `lib->required` nur dann `false` ist, wenn `LC_LOAD_WEAK_DYLIB` true ist.
- **Weak linked libraries** lassen sich in Binaries folgendermaßen finden (weiter unten gibt es ein Beispiel zum Erstellen von hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Mit @rpath konfiguriert**: Mach-O-Binaries können die Commands **`LC_RPATH`** und **`LC_LOAD_DYLIB`** enthalten. Abhängig von den **Werten** dieser Commands werden **Libraries** aus **verschiedenen Verzeichnissen** geladen.
- **`LC_RPATH`** enthält die Pfade bestimmter Ordner, die vom Binary zum Laden von Libraries verwendet werden.
- **`LC_LOAD_DYLIB`** enthält den Pfad zu bestimmten zu ladenden Libraries. Diese Pfade können **`@rpath`** enthalten, das durch die Werte in **`LC_RPATH`** ersetzt wird. Wenn mehrere Pfade in **`LC_RPATH`** vorhanden sind, werden alle zur Suche nach der zu ladenden Library verwendet. Beispiel:
- Wenn **`LC_LOAD_DYLIB`** `@rpath/library.dylib` und **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` sowie `/application/app.app/Contents/Framework/v2/` enthält, werden beide Ordner zum Laden von `library.dylib` verwendet**.** Wenn die Library in `[...]/v1/` nicht existiert und ein Angreifer sie dort platzieren kann, kann er den Ladevorgang der Library in `[...]/v2/` hijacken, da die Reihenfolge der Pfade in **`LC_LOAD_DYLIB`** eingehalten wird.
- **Rpath-Pfade und Libraries** lassen sich in Binaries folgendermaßen finden: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Ist der **Pfad** zu dem Verzeichnis, das die **main executable file** enthält.
>
> **`@loader_path`**: Ist der **Pfad** zu dem **Verzeichnis**, das das **Mach-O-Binary** enthält, welches den load command enthält.
>
> - Bei Verwendung in einem Executable ist **`@loader_path`** effektiv dasselbe wie **`@executable_path`**.
> - Bei Verwendung in einer **dylib** verweist **`@loader_path`** auf den **Pfad** zur **dylib**.

Eine **Privilege Escalation** durch den Missbrauch dieser Funktionalität wäre in dem seltenen Fall möglich, dass eine von **root** ausgeführte **Anwendung** nach einer **Library in einem Ordner sucht, für den der Angreifer Schreibberechtigungen besitzt.**

Ein guter **Scanner**, um **fehlende Libraries** in Anwendungen zu finden, ist [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) oder eine [**CLI-Version**](https://github.com/pandazheng/DylibHijack).\
Einen guten [**Bericht mit technischen Details**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) zu dieser Technik findest du [**hier**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Beispiel**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Denke daran, dass die **zuvor genannten Library-Validation-Einschränkungen ebenfalls** für Dlopen hijacking attacks gelten.

Aus **`man dlopen`**:

- Wenn der Pfad **kein Slash-Zeichen enthält** (d. h. nur ein Leaf-Name ist), führt **dlopen() eine Suche** durch. Wenn **`$DYLD_LIBRARY_PATH`** beim Start gesetzt war, sucht dyld zuerst **in diesem Verzeichnis**. Wenn die aufrufende Mach-O-Datei oder das Main-Executable anschließend ein **`LC_RPATH`** angibt, sucht dyld in diesen Verzeichnissen. Wenn der Prozess **unrestricted** ist, sucht dyld danach im aktuellen Arbeitsverzeichnis. Bei älteren Binaries versucht dyld zuletzt einige Fallbacks. Wenn **`$DYLD_FALLBACK_LIBRARY_PATH`** beim Start gesetzt war, sucht dyld in **diesen Verzeichnissen**, andernfalls sucht dyld in **`/usr/local/lib/`** (wenn der Prozess unrestricted ist) und danach in **`/usr/lib/`** (diese Information stammt aus **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (wenn unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (wenn unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Wenn der Name keine Slashes enthält, gibt es zwei Möglichkeiten für ein Hijacking:
>
> - Wenn ein **`LC_RPATH`** **beschreibbar** ist (die Signatur wird jedoch geprüft, daher muss das Binary hierfür ebenfalls unrestricted sein)
> - Wenn das Binary **unrestricted** ist und dadurch etwas aus dem CWD geladen werden kann (oder eine der genannten Umgebungsvariablen missbraucht wird)

- Wenn der Pfad wie ein **Framework**-Pfad aussieht (z. B. `/stuff/foo.framework/foo`), sucht dyld zuerst in dem Verzeichnis nach dem **partiellen Framework-Pfad** (z. B. `foo.framework/foo`), wenn **`$DYLD_FRAMEWORK_PATH`** beim Start gesetzt war. Danach versucht dyld den **bereitgestellten Pfad unverändert** (für relative Pfade wird das aktuelle Arbeitsverzeichnis verwendet). Bei älteren Binaries versucht dyld zuletzt einige Fallbacks. Wenn **`$DYLD_FALLBACK_FRAMEWORK_PATH`** beim Start gesetzt war, sucht dyld in diesen Verzeichnissen. Andernfalls sucht es in **`/Library/Frameworks`** (unter macOS, wenn der Prozess unrestricted ist) und anschließend in **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. bereitgestellter Pfad (für relative Pfade wird das aktuelle Arbeitsverzeichnis verwendet, wenn der Prozess unrestricted ist)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (wenn unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Wenn es sich um einen Framework-Pfad handelt, wäre ein Hijacking folgendermaßen möglich:
>
> - Wenn der Prozess **unrestricted** ist, kann der **relative Pfad vom CWD** oder eine der genannten Umgebungsvariablen missbraucht werden (auch wenn in der Dokumentation nicht erwähnt wird, dass bei einem restricted Prozess die DYLD\_\*-Umgebungsvariablen entfernt werden)

- Wenn der Pfad **einen Slash enthält, aber kein Framework-Pfad** ist (d. h. ein vollständiger oder partieller Pfad zu einer dylib), sucht dlopen() zuerst (falls gesetzt) in **`$DYLD_LIBRARY_PATH`** (mit dem Leaf-Teil des Pfads). Danach **versucht dyld den bereitgestellten Pfad** (für relative Pfade wird das aktuelle Arbeitsverzeichnis verwendet, jedoch nur bei unrestricted Prozessen). Bei älteren Binaries versucht dyld zuletzt einige Fallbacks. Wenn **`$DYLD_FALLBACK_LIBRARY_PATH`** beim Start gesetzt war, sucht dyld in diesen Verzeichnissen, andernfalls sucht dyld in **`/usr/local/lib/`** (wenn der Prozess unrestricted ist) und anschließend in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. bereitgestellter Pfad (für relative Pfade wird das aktuelle Arbeitsverzeichnis verwendet, wenn unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (wenn unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Wenn der Name Slashes enthält und kein Framework bezeichnet, wäre ein Hijacking folgendermaßen möglich:
>
> - Wenn das Binary **unrestricted** ist, kann etwas aus dem CWD oder aus `/usr/local/lib` geladen werden (oder eine der genannten Umgebungsvariablen missbraucht werden)

> [!TIP]
> Hinweis: Es gibt **keine** Konfigurationsdateien zur **Steuerung der dlopen-Suche**.
>
> Hinweis: Wenn das Main-Executable ein **set\[ug]id-Binary** ist oder mit **Entitlements codesigned** wurde, werden **alle Umgebungsvariablen ignoriert**, und es kann nur ein vollständiger Pfad verwendet werden ([check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) enthält weitere Informationen).
>
> Hinweis: Apple-Plattformen verwenden "universal"-Dateien, um 32-Bit- und 64-Bit-Libraries zu kombinieren. Daher gibt es **keine getrennten Suchpfade für 32-Bit und 64-Bit**.
>
> Hinweis: Auf Apple-Plattformen sind die meisten OS-dylibs im **dyld cache** zusammengefasst und existieren nicht auf dem Datenträger. Daher funktioniert ein Aufruf von **`stat()`**, um vorab zu prüfen, ob eine OS-dylib existiert, **nicht**. **`dlopen_preflight()`** verwendet jedoch dieselben Schritte wie **`dlopen()`**, um eine kompatible Mach-O-Datei zu finden.

**Pfade prüfen**

Prüfen wir alle Optionen mit dem folgenden Code:
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
Wenn du es kompilierst und ausführst, kannst du sehen, **wo nach jeder Library erfolglos gesucht wurde**. Außerdem könntest du **die FS logs filtern**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Wenn eine **privilegierte Binary/App** (wie eine SUID- oder eine Binary mit mächtigen Entitlements) eine Library über einen **relativen Pfad** lädt (zum Beispiel über `@executable_path` oder `@loader_path`) und **Library Validation deaktiviert** ist, könnte es möglich sein, die Binary an einen Ort zu verschieben, an dem der Angreifer die über den relativen Pfad geladene Library **modifizieren** kann, und sie zum Einschleusen von Code in den Prozess zu missbrauchen.

## `DYLD_*`-Umgebungsvariablen bereinigen

Ältere `dyld`-Versionen (`dyld2.cpp`) trafen diese Entscheidung innerhalb des Prozesses mit `issetugid()`, `hasRestrictedSegment()` und `csops(CS_OPS_STATUS)`. In **aktuellen `dyld`-Versionen wird die Entscheidung an AMFI delegiert**, und der Code befindet sich in `ProcessConfig::Security::Security()` in `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
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
Zwei Dinge sind daraus hervorzuheben:

- Pruning findet nur unter **macOS / Mac Catalyst / DriverKit** statt – und nur, wenn AMFI keine der Berechtigungen `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache` gewährt hat.
- Die AMFI-Abfrage erhält die eigenen Eigenschaften der ausführbaren Datei:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
wobei `isRestricted()` wörtlich die Prüfung des Segments `__RESTRICT` ist (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` entfernt anschließend **jede** Variable, deren Name mit `DYLD_` beginnt, und verschiebt die `apple[]`-Parameter nach unten, sodass auch die untergeordneten Prozesse eines eingeschränkten Prozesses sie nicht erben:
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
> Praktische Konsequenz: **`DYLD_*` wird entfernt, wenn der Prozess eingeschränkt ist** — durch setuid/setgid, einen `__RESTRICT/__restrict`-Abschnitt oder durch Binaries mit hardened-runtime/Entitlements, denen AMFI die Pfad-/Print-Flags nicht gewährt. Wenn der Prozess stattdessen nur über **library validation** (`CS_REQUIRE_LV`) verfügt, bleiben die Variablen erhalten, aber die eingefügte dylib muss mit derselben **Team ID** (oder von Apple) signiert sein. Daher benötigst du eines der library-validation-deaktivierenden Entitlements, damit tatsächlich Code geladen wird.

Da die Entscheidung nun bei AMFI liegt, lässt sich am schnellsten feststellen, was ein bestimmtes Binary erhält, indem man prüft, worauf AMFI seine Entscheidung stützt — Entitlements und Signatur-Flags — und nicht `dyld` selbst:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## Einschränkungen prüfen

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
### Hardened runtime

Erstelle ein neues Zertifikat im Keychain und verwende es, um die Binary zu signieren:
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
> Beachte, dass selbst Binaries, die mit Flags **`0x0(none)`** signiert wurden, das Flag **`CS_RESTRICT`** dynamisch erhalten können, wenn sie ausgeführt werden. Daher funktioniert diese Technik bei ihnen nicht.
>
> Du kannst mit (hier findest du [**csops**](https://github.com/axelexic/CSOps)) prüfen, ob ein Proc dieses Flag besitzt:
>
> ```bash
> csops -status <pid>
> ```
>
> und anschließend prüfen, ob das Flag 0x800 aktiviert ist.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT`-Prüfung)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (Prozessstart und Einfügen von Libraries)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
