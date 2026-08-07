# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Der Code von **dyld ist Open Source** und kann unter [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) gefunden und als tar über eine **URL wie** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) heruntergeladen werden.

## **Dyld Process**

Sieh dir an, wie Dyld Libraries innerhalb von Binaries lädt:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Dies entspricht [**LD_PRELOAD unter Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Damit kann einem Prozess, der ausgeführt werden soll, angegeben werden, eine bestimmte Library aus einem Pfad zu laden (wenn die Umgebungsvariable aktiviert ist)<sup>[[4]](#references)</sup>.

Diese Technik kann auch **als ASEP-Technik verwendet werden**, da jede installierte Anwendung eine plist namens "Info.plist" besitzt, die das **Zuweisen von Umgebungsvariablen** über einen Schlüssel namens `LSEnvironmental` ermöglicht.

> [!TIP]
> Seit 2012 hat **Apple die Fähigkeiten von** **`DYLD_INSERT_LIBRARIES`** **drastisch eingeschränkt**. Ein Prozess gilt als **restricted** — und `dyld` löscht anschließend jede `DYLD_*`-Variable aus seiner Umgebung — wenn eine der folgenden Bedingungen erfüllt ist:
>
> - Das Binary ist `setuid/setgid`
> - Das Mach-O besitzt einen **`__RESTRICT/__restrict`**-Abschnitt
> - Das Binary ist mit der hardened runtime signiert und AMFI gewährt ihm nicht die Berechtigungen "path/print variables", d. h. ihm fehlt [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - **Entitlements** eines Binarys mit folgendem Befehl prüfen: `codesign -dv --entitlements :- </path/to/bin>`
>
> In aktuellem `dyld` wird dies nicht mehr allein von `dyld` entschieden: `ProcessConfig::Security::Security()` fragt AMFI über `amfi_check_dyld_policy_self()` ab und ruft anschließend `pruneEnvVars()` auf. Der genaue Code wird weiter unten unter [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) erläutert.

### Library Validation

Selbst wenn das Binary die Verwendung der **`DYLD_INSERT_LIBRARIES`**-Umgebungsvariable erlaubt, wird es keine benutzerdefinierte Library laden, wenn das Binary die Signatur der zu ladenden Library überprüft.

Um eine benutzerdefinierte Library zu laden, muss das Binary **eines der folgenden Entitlements** besitzen:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

oder das Binary darf **nicht** das **hardened runtime flag** oder das **library validation flag** besitzen.

Ob ein Binary über **hardened runtime** verfügt, kann mit `codesign --display --verbose <bin>` geprüft werden, indem das runtime-Flag in **`CodeDirectory`** kontrolliert wird, beispielsweise: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Eine Library kann auch geladen werden, wenn sie mit demselben Zertifikat wie das Binary signiert wurde.

Ein Beispiel dafür, wie dies (miss)braucht und die Einschränkungen geprüft werden können, findest du unter:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Denke daran, dass die **zuvor genannten Einschränkungen von Library Validation ebenfalls** für Dylib hijacking attacks gelten.

Wie unter Windows können auch unter MacOS **dylibs hijacked** werden, damit **Anwendungen** **beliebigen** **Code** **ausführen** (tatsächlich wäre dies für einen normalen Benutzer möglicherweise nicht möglich, da eventuell eine TCC-Berechtigung erforderlich ist, um in ein `.app`-Bundle zu schreiben und eine Library zu hijacken).\
Allerdings ist die Art, wie **MacOS**-Anwendungen Libraries **laden**, **stärker eingeschränkt** als unter Windows. Das bedeutet, dass **Malware**-Entwickler diese Technik weiterhin für **Stealth** verwenden können, die Wahrscheinlichkeit, dies zur **Privilege Escalation** zu missbrauchen, jedoch deutlich **geringer** ist.

Erstens ist es **häufiger**, dass **MacOS-Binaries den vollständigen Pfad** zu den zu ladenden Libraries angeben. Zweitens sucht **MacOS niemals** in den Ordnern von **$PATH** nach Libraries.

Der **wichtigste** Teil des **Codes**, der sich auf diese Funktionalität bezieht, befindet sich in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Es gibt **4 verschiedene Header Commands**, die ein Mach-O-Binary zum Laden von Libraries verwenden kann:

- Der **`LC_LOAD_DYLIB`**-Befehl ist der übliche Befehl zum Laden einer dylib.
- Der **`LC_LOAD_WEAK_DYLIB`**-Befehl funktioniert wie der vorherige, aber wenn die dylib nicht gefunden wird, wird die Ausführung ohne Fehler fortgesetzt.
- Der **`LC_REEXPORT_DYLIB`**-Befehl proxied (oder re-exportiert) die Symbole einer anderen Library.
- Der **`LC_LOAD_UPWARD_DYLIB`**-Befehl wird verwendet, wenn zwei Libraries voneinander abhängen (dies wird als _upward dependency_ bezeichnet).

Es gibt jedoch **2 Arten von Dylib Hijacking**:

- **Missing weak linked libraries**: Das bedeutet, dass die Anwendung versucht, eine nicht existierende Library zu laden, die mit **LC_LOAD_WEAK_DYLIB** konfiguriert wurde. Wenn ein **Angreifer dann eine dylib an der erwarteten Stelle platziert, wird sie geladen**.
- Die Tatsache, dass der Link "weak" ist, bedeutet, dass die Anwendung auch dann weiterläuft, wenn die Library nicht gefunden wird.
- Der **dazugehörige Code** befindet sich in der Funktion `ImageLoaderMachO::doGetDependentLibraries` von `ImageLoaderMachO.cpp`, wobei `lib->required` nur dann `false` ist, wenn `LC_LOAD_WEAK_DYLIB` true ist.
- **Weak linked libraries** in Binaries mit folgendem Befehl finden (weiter unten gibt es ein Beispiel zum Erstellen von Hijacking-Libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Mit @rpath konfiguriert**: Mach-O-Binaries können die Commands **`LC_RPATH`** und **`LC_LOAD_DYLIB`** enthalten. Abhängig von den **Werten** dieser Commands werden **Libraries** aus **verschiedenen Verzeichnissen** geladen.
- **`LC_RPATH`** enthält die Pfade einiger Ordner, die vom Binary zum Laden von Libraries verwendet werden.
- **`LC_LOAD_DYLIB`** enthält den Pfad zu den zu ladenden Libraries. Diese Pfade können **`@rpath`** enthalten, das durch die Werte in **`LC_RPATH`** ersetzt wird. Wenn mehrere Pfade in **`LC_RPATH`** vorhanden sind, werden alle zur Suche nach der zu ladenden Library verwendet. Beispiel:
- Wenn **`LC_LOAD_DYLIB`** `@rpath/library.dylib` und **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` sowie `/application/app.app/Contents/Framework/v2/` enthält, werden beide Ordner zum Laden von `library.dylib` verwendet**.** Wenn die Library in `[...]/v1/` nicht existiert und ein Angreifer sie dort platzieren kann, kann er das Laden der Library in `[...]/v2/` hijacken, da die Reihenfolge der Pfade in **`LC_LOAD_DYLIB`** eingehalten wird.
- **Rpath-Pfade und Libraries** in Binaries mit folgendem Befehl finden: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Ist der **Pfad** zu dem Verzeichnis, das die **main executable file** enthält.
>
> **`@loader_path`**: Ist der **Pfad** zu dem **Verzeichnis**, das das Mach-O-Binary enthält, welches den load command enthält.
>
> - Bei Verwendung in einem Executable ist **`@loader_path`** effektiv dasselbe wie **`@executable_path`**.
> - Bei Verwendung in einer **dylib** liefert **`@loader_path`** den **Pfad** zur **dylib**.

Eine **Privilege Escalation** durch Missbrauch dieser Funktionalität wäre in dem seltenen Fall möglich, dass eine von **root** ausgeführte **Anwendung** nach einer **Library in einem Ordner sucht, für den der Angreifer Schreibberechtigungen besitzt**.

> [!TIP]
> Ein nützlicher **Scanner**, um **fehlende Libraries** in Anwendungen zu finden, ist [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) oder eine [**CLI-Version**](https://github.com/pandazheng/DylibHijack).\
> Einen guten **Bericht mit technischen Details** zu dieser Technik findest du [**hier**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Beispiel**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Denke daran, dass die **zuvor genannten Einschränkungen von Library Validation ebenfalls** für Dlopen hijacking attacks gelten.

Aus **`man dlopen`**:

- Wenn der Pfad **kein Slash-Zeichen enthält** (d. h. nur aus einem Leaf-Namen besteht), führt **dlopen() eine Suche durch**. Wenn **`$DYLD_LIBRARY_PATH`** beim Start gesetzt war, sucht dyld zuerst in diesem **Verzeichnis**. Wenn anschließend die aufrufende Mach-O-Datei oder das main executable ein **`LC_RPATH`** angibt, sucht dyld in diesen Verzeichnissen. Wenn der Prozess danach **unrestricted** ist, sucht dyld im aktuellen Arbeitsverzeichnis. Bei älteren Binaries versucht dyld zuletzt einige Fallbacks. Wenn **`$DYLD_FALLBACK_LIBRARY_PATH`** beim Start gesetzt war, sucht dyld in **diesen Verzeichnissen**, andernfalls sucht dyld in **`/usr/local/lib/`** (wenn der Prozess unrestricted ist) und anschließend in **`/usr/lib/`** (diese Information stammt aus **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(wenn unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (wenn unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Wenn der Name keine Slashes enthält, gibt es **2 Möglichkeiten für ein Hijacking**:
>
> - Wenn ein **`LC_RPATH`** **beschreibbar** ist (die Signatur wird jedoch geprüft, daher muss das Binary hierfür ebenfalls unrestricted sein)
> - Wenn das Binary **unrestricted** ist und es dadurch möglich ist, etwas aus dem CWD zu laden (oder eine der genannten Umgebungsvariablen zu missbrauchen)

- Wenn der Pfad wie ein **Framework**-Pfad aussieht (z. B. `/stuff/foo.framework/foo`), sucht dyld zuerst in dem Verzeichnis nach dem **partiellen Framework-Pfad** (z. B. `foo.framework/foo`), wenn **`$DYLD_FRAMEWORK_PATH`** beim Start gesetzt war. Danach versucht dyld den **angegebenen Pfad unverändert** (für relative Pfade wird das aktuelle Arbeitsverzeichnis verwendet). Bei älteren Binaries versucht dyld zuletzt einige Fallbacks. Wenn **`$DYLD_FALLBACK_FRAMEWORK_PATH`** beim Start gesetzt war, sucht dyld in diesen Verzeichnissen. Andernfalls sucht es in **`/Library/Frameworks`** (unter macOS, wenn der Prozess unrestricted ist) und anschließend in **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. angegebener Pfad (für relative Pfade wird das aktuelle Arbeitsverzeichnis verwendet, wenn unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (wenn unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Wenn es sich um einen Framework-Pfad handelt, wäre ein Hijacking folgendermaßen möglich:
>
> - Wenn der Prozess **unrestricted** ist, durch Missbrauch des **relativen Pfads aus dem CWD** oder der genannten Umgebungsvariablen (auch wenn in der Dokumentation nicht erwähnt wird, dass bei einem restricted Prozess DYLD\_\*-Umgebungsvariablen entfernt werden)

- Wenn der Pfad **einen Slash enthält, aber kein Framework-Pfad** ist (d. h. ein vollständiger oder partieller Pfad zu einer dylib), sucht dlopen() zuerst (falls gesetzt) in **`$DYLD_LIBRARY_PATH`** (mit dem Leaf-Teil des Pfads). Anschließend versucht dyld den **angegebenen Pfad** (für relative Pfade wird das aktuelle Arbeitsverzeichnis verwendet, jedoch nur für unrestricted Prozesse). Bei älteren Binaries versucht dyld zuletzt einige Fallbacks. Wenn **`$DYLD_FALLBACK_LIBRARY_PATH`** beim Start gesetzt war, sucht dyld in diesen Verzeichnissen, andernfalls sucht dyld in **`/usr/local/lib/`** (wenn der Prozess unrestricted ist) und anschließend in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. angegebener Pfad (für relative Pfade wird das aktuelle Arbeitsverzeichnis verwendet, wenn unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (wenn unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Wenn der Name Slashes enthält und kein Framework ist, wäre ein Hijacking folgendermaßen möglich:
>
> - Wenn das Binary **unrestricted** ist und es dadurch möglich ist, etwas aus dem CWD oder aus `/usr/local/lib` zu laden (oder eine der genannten Umgebungsvariablen zu missbrauchen)

> [!TIP]
> Hinweis: Es gibt **keine** Konfigurationsdateien, um die **dlopen-Suche zu steuern**.
>
> Hinweis: Wenn das main executable ein **set\[ug]id-Binary** ist oder mit **Entitlements codesigned** wurde, werden **alle Umgebungsvariablen ignoriert**, und es kann nur ein vollständiger Pfad verwendet werden ([check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) für ausführlichere Informationen).
>
> Hinweis: Apple-Plattformen verwenden "universal"-Dateien, um 32-Bit- und 64-Bit-Libraries zu kombinieren. Daher gibt es **keine getrennten 32-Bit- und 64-Bit-Suchpfade**.
>
> Hinweis: Auf Apple-Plattformen sind die meisten OS-dylibs im **dyld cache** zusammengefasst und nicht auf der Festplatte vorhanden. Daher funktioniert der Aufruf von **`stat()`**, um vorab zu prüfen, ob eine OS-dylib existiert, **nicht**. **`dlopen_preflight()`** verwendet jedoch dieselben Schritte wie **`dlopen()`**, um eine kompatible Mach-O-Datei zu finden.

**Pfade prüfen**

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
Wenn du es kompilierst und ausführst, kannst du sehen, **wo nach jeder Library erfolglos gesucht wurde**. Außerdem könntest du **die FS-Logs filtern**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Wenn eine **privilegierte Binary/App** (wie eine SUID- oder eine Binary mit mächtigen Entitlements) eine Library über einen **relativen Pfad** lädt (zum Beispiel mit `@executable_path` oder `@loader_path`) und **Library Validation deaktiviert** ist, könnte es möglich sein, die Binary an einen Ort zu verschieben, an dem der Angreifer die über den relativen Pfad geladene Library **ändern** kann, und dies zu missbrauchen, um Code in den Prozess zu injizieren.

## `DYLD_*`-Umgebungsvariablen beschneiden

Ältere `dyld`-Releases (`dyld2.cpp`) entschieden dies innerhalb des Prozesses mithilfe von `issetugid()`, `hasRestrictedSegment()` und `csops(CS_OPS_STATUS)`. In **aktuellem `dyld` wird die Entscheidung an AMFI delegiert**, und der Code befindet sich in `ProcessConfig::Security::Security()` in `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
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
Aus diesem Abschnitt sind zwei Dinge besonders wichtig:

- Das **Pruning** findet nur unter **macOS / Mac Catalyst / DriverKit** statt — und nur, wenn AMFI **keine** der Berechtigungen `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache` gewährt hat.
- Die AMFI-Abfrage erhält die eigenen Eigenschaften der ausführbaren Datei:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
wobei `isRestricted()` wörtlich die Prüfung des `__RESTRICT`-Segments ist (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` entfernt anschließend **jede** Variable, deren Name mit `DYLD_` beginnt, und verschiebt die `apple[]`-Parameter nach unten, sodass auch die Kindprozesse eines eingeschränkten Prozesses sie nicht erben:
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
> Praktische Konsequenz: **`DYLD_*` wird entfernt, wenn der Prozess eingeschränkt ist** — bei setuid/setgid, einem Abschnitt `__RESTRICT/__restrict` oder hardened-runtime/entitled binaries, denen AMFI die path/print-Flags nicht gewährt. Wenn der Prozess stattdessen nur über **library validation** (`CS_REQUIRE_LV`) verfügt, bleiben die Variablen erhalten, aber die eingefügte dylib muss mit derselben **Team ID** (oder von Apple) signiert sein. Daher benötigst du eine der library-validation-disabling entitlements, damit tatsächlich Code eingeschleust wird.

Da die Entscheidung nun bei AMFI liegt, lässt sich am schnellsten feststellen, was ein bestimmtes Binary erhält, indem man prüft, worauf AMFI basiert — entitlements und signing flags — und nicht `dyld` selbst:
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
### Hardened Runtime

Erstelle ein neues Zertifikat im Keychain und verwende es, um das binary zu signieren:
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
> Beachte, dass selbst Binaries, die mit Flags **`0x0(none)`** signiert wurden, beim Ausführen dynamisch das **`CS_RESTRICT`**-Flag erhalten können. Daher funktioniert diese Technik bei ihnen nicht.
>
> Du kannst mit folgendem Befehl prüfen, ob ein Prozess dieses Flag besitzt (siehe [**csops here**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> Prüfe anschließend, ob das Flag 0x800 aktiviert ist.

## Referenzen

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT`-Prüfung)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (Prozessstart und Einfügen von Libraries)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
