# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Der Code von **dyld ist Open Source** und kann unter [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) gefunden werden und kann als tar mit einer **URL wie** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) heruntergeladen werden.

## **Dyld-Prozess**

Schauen Sie sich an, wie Dyld Bibliotheken in Binaries lädt in:

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Dies ist wie das [**LD_PRELOAD unter Linux**](../../../../linux-hardening/privilege-escalation/index.html#ld_preload). Es ermöglicht, einen Prozess anzugeben, der ausgeführt werden soll, um eine bestimmte Bibliothek von einem Pfad zu laden (wenn die Umgebungsvariable aktiviert ist).

Diese Technik kann auch **als ASEP-Technik verwendet werden**, da jede installierte Anwendung eine plist namens "Info.plist" hat, die die **Zuweisung von Umgebungsvariablen** mit einem Schlüssel namens `LSEnvironmental` ermöglicht.

> [!NOTE]
> Seit 2012 hat **Apple die Macht von `DYLD_INSERT_LIBRARIES` drastisch reduziert**.
>
> Gehen Sie zum Code und **prüfen Sie `src/dyld.cpp`**. In der Funktion **`pruneEnvironmentVariables`** können Sie sehen, dass **`DYLD_*`** Variablen entfernt werden.
>
> In der Funktion **`processRestricted`** wird der Grund für die Einschränkung festgelegt. Wenn Sie diesen Code überprüfen, können Sie sehen, dass die Gründe sind:
>
> - Das Binary ist `setuid/setgid`
> - Existenz des `__RESTRICT/__restrict` Abschnitts im Macho-Binary.
> - Die Software hat Berechtigungen (hardened runtime) ohne die Berechtigung [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>   - Überprüfen Sie die **Berechtigungen** eines Binaries mit: `codesign -dv --entitlements :- </path/to/bin>`
>
> In neueren Versionen finden Sie diese Logik im zweiten Teil der Funktion **`configureProcessRestrictions`**. Was in neueren Versionen jedoch ausgeführt wird, sind die **Anfangsprüfungen der Funktion** (Sie können die ifs, die sich auf iOS oder Simulation beziehen, entfernen, da diese in macOS nicht verwendet werden).

### Bibliotheksvalidierung

Selbst wenn das Binary die Verwendung der **`DYLD_INSERT_LIBRARIES`** Umgebungsvariable erlaubt, wird es eine benutzerdefinierte Bibliothek nicht laden, wenn das Binary die Signatur der zu ladenden Bibliothek überprüft.

Um eine benutzerdefinierte Bibliothek zu laden, muss das Binary **eine der folgenden Berechtigungen** haben:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

oder das Binary **sollte nicht** das **hardened runtime-Flag** oder das **Bibliotheksvalidierungs-Flag** haben.

Sie können überprüfen, ob ein Binary **hardened runtime** hat mit `codesign --display --verbose <bin>` und das Flag runtime in **`CodeDirectory`** überprüfen wie: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Sie können auch eine Bibliothek laden, wenn sie **mit demselben Zertifikat wie das Binary signiert ist**.

Finden Sie ein Beispiel, wie man dies (miss)braucht und überprüfen Sie die Einschränkungen in:

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib-Hijacking

> [!CAUTION]
> Denken Sie daran, dass **frühere Bibliotheksvalidierungseinschränkungen ebenfalls gelten**, um Dylib-Hijacking-Angriffe durchzuführen.

Wie unter Windows können Sie auch unter macOS **dylibs hijacken**, um **Anwendungen** dazu zu bringen, **willkürlichen** **Code** auszuführen (nun, tatsächlich könnte dies von einem regulären Benutzer nicht möglich sein, da Sie möglicherweise eine TCC-Berechtigung benötigen, um in ein `.app`-Bundle zu schreiben und eine Bibliothek zu hijacken).\
Die Art und Weise, wie **macOS**-Anwendungen **Bibliotheken laden**, ist jedoch **stärker eingeschränkt** als unter Windows. Dies bedeutet, dass **Malware**-Entwickler diese Technik weiterhin für **Stealth** verwenden können, aber die Wahrscheinlichkeit, dass sie dies zur Eskalation von Berechtigungen missbrauchen können, ist viel geringer.

Zunächst ist es **häufiger**, dass **macOS-Binaries den vollständigen Pfad** zu den zu ladenden Bibliotheken angeben. Und zweitens, **macOS sucht niemals** in den Ordnern des **$PATH** nach Bibliotheken.

Der **Hauptteil** des **Codes**, der mit dieser Funktionalität zusammenhängt, befindet sich in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Es gibt **4 verschiedene Header-Befehle**, die ein Macho-Binary verwenden kann, um Bibliotheken zu laden:

- Der **`LC_LOAD_DYLIB`** Befehl ist der gängige Befehl zum Laden einer dylib.
- Der **`LC_LOAD_WEAK_DYLIB`** Befehl funktioniert wie der vorherige, aber wenn die dylib nicht gefunden wird, wird die Ausführung ohne Fehler fortgesetzt.
- Der **`LC_REEXPORT_DYLIB`** Befehl proxy (oder re-exportiert) die Symbole von einer anderen Bibliothek.
- Der **`LC_LOAD_UPWARD_DYLIB`** Befehl wird verwendet, wenn zwei Bibliotheken voneinander abhängen (dies wird als _aufwärts gerichtete Abhängigkeit_ bezeichnet).

Es gibt jedoch **2 Arten von Dylib-Hijacking**:

- **Fehlende schwach verlinkte Bibliotheken**: Das bedeutet, dass die Anwendung versuchen wird, eine Bibliothek zu laden, die nicht existiert und mit **LC_LOAD_WEAK_DYLIB** konfiguriert ist. Dann, **wenn ein Angreifer eine dylib an dem Ort platziert, an dem sie erwartet wird, wird sie geladen**.
- Die Tatsache, dass der Link "schwach" ist, bedeutet, dass die Anwendung weiterhin ausgeführt wird, auch wenn die Bibliothek nicht gefunden wird.
- Der **Code, der damit zusammenhängt**, befindet sich in der Funktion `ImageLoaderMachO::doGetDependentLibraries` von `ImageLoaderMachO.cpp`, wo `lib->required` nur `false` ist, wenn `LC_LOAD_WEAK_DYLIB` wahr ist.
- **Finden Sie schwach verlinkte Bibliotheken** in Binaries mit (Sie haben später ein Beispiel, wie man Hijacking-Bibliotheken erstellt):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Konfiguriert mit @rpath**: Mach-O-Binaries können die Befehle **`LC_RPATH`** und **`LC_LOAD_DYLIB`** haben. Basierend auf den **Werten** dieser Befehle werden **Bibliotheken** aus **verschiedenen Verzeichnissen** geladen.
- **`LC_RPATH`** enthält die Pfade einiger Ordner, die zum Laden von Bibliotheken durch das Binary verwendet werden.
- **`LC_LOAD_DYLIB`** enthält den Pfad zu spezifischen Bibliotheken, die geladen werden sollen. Diese Pfade können **`@rpath`** enthalten, das durch die Werte in **`LC_RPATH`** ersetzt wird. Wenn es mehrere Pfade in **`LC_RPATH`** gibt, wird jeder verwendet, um die zu ladende Bibliothek zu suchen. Beispiel:
- Wenn **`LC_LOAD_DYLIB`** `@rpath/library.dylib` enthält und **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` und `/application/app.app/Contents/Framework/v2/` enthält. Beide Ordner werden verwendet, um `library.dylib` zu laden. Wenn die Bibliothek nicht in `[...]/v1/` existiert und ein Angreifer sie dort platzieren könnte, um das Laden der Bibliothek in `[...]/v2/` zu hijacken, da die Reihenfolge der Pfade in **`LC_LOAD_DYLIB`** befolgt wird.
- **Finden Sie rpath-Pfade und Bibliotheken** in Binaries mit: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Ist der **Pfad** zum Verzeichnis, das die **Hauptausführungsdatei** enthält.
>
> **`@loader_path`**: Ist der **Pfad** zum **Verzeichnis**, das die **Mach-O-Binary** enthält, die den Ladebefehl enthält.
>
> - Wenn in einem ausführbaren Programm verwendet, ist **`@loader_path`** effektiv dasselbe wie **`@executable_path`**.
> - Wenn in einer **dylib** verwendet, gibt **`@loader_path`** den **Pfad** zur **dylib** an.

Die Möglichkeit, **Berechtigungen zu eskalieren**, indem man diese Funktionalität missbraucht, wäre im seltenen Fall, dass eine **Anwendung**, die **von** **root** ausgeführt wird, **nach** einer **Bibliothek in einem Ordner sucht, in dem der Angreifer Schreibberechtigungen hat.**

> [!TIP]
> Ein schöner **Scanner**, um **fehlende Bibliotheken** in Anwendungen zu finden, ist der [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) oder eine [**CLI-Version**](https://github.com/pandazheng/DylibHijack).\
> Ein schöner **Bericht mit technischen Details** zu dieser Technik kann [**hier**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) gefunden werden.

**Beispiel**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen-Hijacking

> [!CAUTION]
> Denken Sie daran, dass **frühere Bibliotheksvalidierungseinschränkungen ebenfalls gelten**, um Dlopen-Hijacking-Angriffe durchzuführen.

Aus **`man dlopen`**:

- Wenn der Pfad **kein Schrägstrichzeichen enthält** (d.h. es ist nur ein Blattname), wird **dlopen() eine Suche durchführen**. Wenn **`$DYLD_LIBRARY_PATH`** beim Start gesetzt wurde, wird dyld zuerst **in diesem Verzeichnis suchen**. Als nächstes, wenn die aufrufende Mach-O-Datei oder die Hauptausführungsdatei ein **`LC_RPATH`** angibt, wird dyld **in diesen** Verzeichnissen suchen. Als nächstes, wenn der Prozess **uneingeschränkt** ist, wird dyld im **aktuellen Arbeitsverzeichnis** suchen. Schließlich wird dyld für alte Binaries einige Fallbacks versuchen. Wenn **`$DYLD_FALLBACK_LIBRARY_PATH`** beim Start gesetzt wurde, wird dyld in **diesen Verzeichnissen** suchen, andernfalls wird dyld in **`/usr/local/lib/`** suchen (wenn der Prozess uneingeschränkt ist) und dann in **`/usr/lib/`** (diese Informationen stammen aus **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (wenn uneingeschränkt)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (wenn uneingeschränkt)
6. `/usr/lib/`

> [!CAUTION]
> Wenn keine Schrägstriche im Namen vorhanden sind, gibt es 2 Möglichkeiten, ein Hijacking durchzuführen:
>
> - Wenn irgendein **`LC_RPATH`** **beschreibbar** ist (aber die Signatur überprüft wird, also dafür muss das Binary auch uneingeschränkt sein)
> - Wenn das Binary **uneingeschränkt** ist und dann ist es möglich, etwas aus dem CWD zu laden (oder einen der erwähnten Umgebungsvariablen zu missbrauchen)

- Wenn der Pfad **wie ein Framework-Pfad aussieht** (z.B. `/stuff/foo.framework/foo`), wenn **`$DYLD_FRAMEWORK_PATH`** beim Start gesetzt wurde, wird dyld zuerst in diesem Verzeichnis nach dem **Framework-Teilpfad** (z.B. `foo.framework/foo`) suchen. Als nächstes wird dyld den **angegebenen Pfad unverändert** versuchen (unter Verwendung des aktuellen Arbeitsverzeichnisses für relative Pfade). Schließlich wird dyld für alte Binaries einige Fallbacks versuchen. Wenn **`$DYLD_FALLBACK_FRAMEWORK_PATH`** beim Start gesetzt wurde, wird dyld in diesen Verzeichnissen suchen. Andernfalls wird es in **`/Library/Frameworks`** suchen (auf macOS, wenn der Prozess uneingeschränkt ist), dann in **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. angegebener Pfad (unter Verwendung des aktuellen Arbeitsverzeichnisses für relative Pfade, wenn uneingeschränkt)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (wenn uneingeschränkt)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Wenn es sich um einen Framework-Pfad handelt, wäre die Möglichkeit, ihn zu hijacken:
>
> - Wenn der Prozess **uneingeschränkt** ist, indem die **relative Pfad vom CWD** und die erwähnten Umgebungsvariablen missbraucht werden (auch wenn es in den Dokumenten nicht gesagt wird, wenn der Prozess eingeschränkt ist, werden DYLD_* Umgebungsvariablen entfernt)

- Wenn der Pfad **einen Schrägstrich enthält, aber kein Framework-Pfad ist** (d.h. ein vollständiger Pfad oder ein Teilpfad zu einer dylib), sucht dlopen() zuerst (wenn gesetzt) in **`$DYLD_LIBRARY_PATH`** (mit dem Blattteil vom Pfad). Als nächstes versucht dyld **den angegebenen Pfad** (unter Verwendung des aktuellen Arbeitsverzeichnisses für relative Pfade, aber nur für uneingeschränkte Prozesse). Schließlich wird dyld für ältere Binaries einige Fallbacks versuchen. Wenn **`$DYLD_FALLBACK_LIBRARY_PATH`** beim Start gesetzt wurde, wird dyld in diesen Verzeichnissen suchen, andernfalls wird dyld in **`/usr/local/lib/`** suchen (wenn der Prozess uneingeschränkt ist) und dann in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. angegebener Pfad (unter Verwendung des aktuellen Arbeitsverzeichnisses für relative Pfade, wenn uneingeschränkt)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (wenn uneingeschränkt)
5. `/usr/lib/`

> [!CAUTION]
> Wenn Schrägstriche im Namen vorhanden sind und es sich nicht um ein Framework handelt, wäre die Möglichkeit, es zu hijacken:
>
> - Wenn das Binary **uneingeschränkt** ist und dann ist es möglich, etwas aus dem CWD oder `/usr/local/lib` zu laden (oder einen der erwähnten Umgebungsvariablen zu missbrauchen)

> [!NOTE]
> Hinweis: Es gibt **keine** Konfigurationsdateien, um **die Suche von dlopen zu steuern**.
>
> Hinweis: Wenn die Hauptausführungsdatei ein **set\[ug]id-Binary oder codesigned mit Berechtigungen** ist, werden **alle Umgebungsvariablen ignoriert**, und es kann nur ein vollständiger Pfad verwendet werden ([prüfen Sie die Einschränkungen von DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) für detailliertere Informationen)
>
> Hinweis: Apple-Plattformen verwenden "universelle" Dateien, um 32-Bit- und 64-Bit-Bibliotheken zu kombinieren. Das bedeutet, dass es **keine separaten 32-Bit- und 64-Bit-Suchpfade** gibt.
>
> Hinweis: Auf Apple-Plattformen sind die meisten OS-Dylibs **im dyld-Cache kombiniert** und existieren nicht auf der Festplatte. Daher wird der Aufruf von **`stat()`** zur Vorabprüfung, ob eine OS-Dylib existiert, **nicht funktionieren**. Allerdings verwendet **`dlopen_preflight()`** die gleichen Schritte wie **`dlopen()`**, um eine kompatible Mach-O-Datei zu finden.

**Überprüfen Sie die Pfade**

Lassen Sie uns alle Optionen mit dem folgenden Code überprüfen:
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
Wenn Sie es kompilieren und ausführen, können Sie **sehen, wo nach jeder Bibliothek erfolglos gesucht wurde**. Außerdem könnten Sie **die FS-Protokolle filtern**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Wenn ein **privilegiertes Binary/App** (wie ein SUID oder ein Binary mit mächtigen Berechtigungen) eine **relative Pfad**-Bibliothek lädt (zum Beispiel mit `@executable_path` oder `@loader_path`) und **Library Validation deaktiviert** ist, könnte es möglich sein, das Binary an einen Ort zu verschieben, an dem der Angreifer die **relative Pfad geladene Bibliothek** **modifizieren** und missbrauchen kann, um Code in den Prozess einzuschleusen.

## Prune `DYLD_*` und `LD_LIBRARY_PATH` Umgebungsvariablen

In der Datei `dyld-dyld-832.7.1/src/dyld2.cpp` ist es möglich, die Funktion **`pruneEnvironmentVariables`** zu finden, die jede Umgebungsvariable entfernt, die **mit `DYLD_`** und **`LD_LIBRARY_PATH=`** beginnt.

Es wird auch die Umgebungsvariable **`DYLD_FALLBACK_FRAMEWORK_PATH`** und **`DYLD_FALLBACK_LIBRARY_PATH`** speziell für **suid** und **sgid** Binaries auf **null** gesetzt.

Diese Funktion wird aus der **`_main`** Funktion derselben Datei aufgerufen, wenn OSX wie folgt angesprochen wird:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
und diese booleschen Flags werden in derselben Datei im Code gesetzt:
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
Was im Grunde bedeutet, dass wenn die Binärdatei **suid** oder **sgid** ist, oder ein **RESTRICT**-Segment in den Headern hat oder mit dem **CS_RESTRICT**-Flag signiert wurde, dann **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** wahr ist und die Umgebungsvariablen entfernt werden.

Beachten Sie, dass wenn CS_REQUIRE_LV wahr ist, die Variablen nicht entfernt werden, aber die Bibliotheksvalidierung überprüft, ob sie dasselbe Zertifikat wie die ursprüngliche Binärdatei verwenden.

## Überprüfen der Einschränkungen

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

Erstellen Sie ein neues Zertifikat in der Schlüsselbund und verwenden Sie es, um die Binärdatei zu signieren:
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
> Beachten Sie, dass selbst wenn es Binärdateien gibt, die mit den Flags **`0x0(none)`** signiert sind, sie beim Ausführen dynamisch das **`CS_RESTRICT`**-Flag erhalten können und diese Technik daher nicht bei ihnen funktioniert.
>
> Sie können überprüfen, ob ein Prozess dieses Flag hat mit (holen Sie sich [**csops hier**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> und dann überprüfen, ob das Flag 0x800 aktiviert ist.

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
