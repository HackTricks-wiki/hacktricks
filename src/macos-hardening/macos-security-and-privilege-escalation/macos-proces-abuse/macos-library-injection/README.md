# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Der Code von **dyld ist Open Source** und unter [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) verfügbar. Er kann als Tar-Archiv heruntergeladen werden, zum Beispiel über eine **URL wie** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Sieh dir an, wie Dyld Bibliotheken in Binärdateien lädt:


{{#ref}}
macos-dyld-process.md
{{#endref}}

Siehe auch: [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

## **DYLD_INSERT_LIBRARIES**

Dies ist vergleichbar mit [**LD_PRELOAD unter Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Damit kann für einen auszuführenden Prozess angegeben werden, dass er eine bestimmte Bibliothek aus einem Pfad lädt (wenn die Umgebungsvariable aktiviert ist)<sup>[[4]](#references)</sup>

Diese Technik kann auch **als ASEP-Technik verwendet werden**, da jede installierte Anwendung eine plist namens „Info.plist“ hat, die über einen Schlüssel namens `LSEnvironmental` die **Zuweisung von Umgebungsvariablen** ermöglicht.

> [!TIP]
> Seit 2012 hat **Apple die Möglichkeiten von** **`DYLD_INSERT_LIBRARIES`** **drastisch eingeschränkt**. Ein Prozess gilt als **eingeschränkt** – und `dyld` löscht dann alle `DYLD_*`-Variablen aus seiner Umgebung –, wenn eine der folgenden Bedingungen zutrifft:
>
> - Die Binärdatei ist `setuid/setgid`
> - Das Mach-O enthält einen **`__RESTRICT/__restrict`**-Abschnitt
> - Die Binärdatei ist mit der gehärteten Laufzeit signiert und AMFI gewährt ihr nicht die Berechtigungen „path/print variables“, d. h., ihr fehlt [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Prüfe die **Entitlements** einer Binärdatei mit: `codesign -dv --entitlements :- </path/to/bin>`
>
> In aktuellen `dyld`-Versionen wird dies nicht mehr allein von `dyld` entschieden: `ProcessConfig::Security::Security()` fragt **AMFI** über `amfi_check_dyld_policy_self()` ab und ruft anschließend `pruneEnvVars()` auf. Der genaue Code wird weiter unten unter [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) erläutert.

### Library Validation

Auch wenn die Binärdatei die Umgebungsvariable **`DYLD_INSERT_LIBRARIES`** zulässt, lädt sie keine benutzerdefinierte Bibliothek, wenn sie die Signatur der Bibliothek überprüft.

Damit eine benutzerdefinierte Bibliothek geladen werden kann, benötigt die Binärdatei **eine der folgenden Entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

oder die Binärdatei darf **weder das Flag für die gehärtete Laufzeit** noch das **Flag für die Library Validation** besitzen.

Du kannst prüfen, ob eine Binärdatei die **gehärtete Laufzeit** verwendet, indem du `codesign --display --verbose <bin>` ausführst und das Runtime-Flag in **`CodeDirectory`** überprüfst, zum Beispiel: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Du kannst eine Bibliothek auch laden, wenn sie **mit demselben Zertifikat wie die Binärdatei signiert ist**.

Ein Beispiel für den (Miss-)Gebrauch dieser Technik und eine Übersicht der Einschränkungen findest du hier:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Beachte, dass **auch die zuvor genannten Einschränkungen der Library Validation** für Dylib-Hijacking-Angriffe gelten.

Wie unter Windows kannst du unter macOS **dylibs hijacken**, damit **Anwendungen beliebigen Code ausführen**. Über ein reguläres Benutzerkonto ist dies möglicherweise nicht möglich, da zum Schreiben in ein `.app`-Bundle, um eine Bibliothek zu hijacken, eine TCC-Berechtigung erforderlich sein kann.\
Die Art und Weise, wie **macOS**-Anwendungen Bibliotheken **laden**, ist jedoch **stärker eingeschränkt** als unter Windows. Malware-Entwickler können diese Technik weiterhin zur **Verschleierung** einsetzen, aber sie zur Rechteausweitung zu missbrauchen, ist deutlich unwahrscheinlicher.

Erstens geben **macOS-Binärdateien häufiger** den vollständigen Pfad zu den zu ladenden Bibliotheken an. Zweitens sucht **macOS niemals** in den Ordnern von **$PATH** nach Bibliotheken.

Der **Hauptteil des Codes**, der diese Funktionalität implementiert, befindet sich in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Es gibt **4 verschiedene Header Commands**, mit denen eine Mach-O-Binärdatei Bibliotheken laden kann:

- Der Befehl **`LC_LOAD_DYLIB`** ist der übliche Befehl zum Laden einer dylib.
- Der Befehl **`LC_LOAD_WEAK_DYLIB`** funktioniert wie der vorherige, aber wenn die dylib nicht gefunden wird, wird die Ausführung ohne Fehler fortgesetzt.
- Der Befehl **`LC_REEXPORT_DYLIB`** leitet die Symbole einer anderen Bibliothek weiter (oder exportiert sie erneut).
- Der Befehl **`LC_LOAD_UPWARD_DYLIB`** wird verwendet, wenn zwei Bibliotheken voneinander abhängen (dies wird als _upward dependency_ bezeichnet).

Es gibt jedoch **2 Arten von Dylib Hijacking**:

- **Fehlende weak linked libraries**: Das bedeutet, dass die Anwendung versucht, eine nicht vorhandene Bibliothek zu laden, die mit **LC_LOAD_WEAK_DYLIB** konfiguriert ist. Wenn ein Angreifer dann eine dylib an dem erwarteten Speicherort ablegt, **wird sie geladen**.
  - Dass die Verknüpfung „weak“ ist, bedeutet, dass die Anwendung auch dann weiterläuft, wenn die Bibliothek nicht gefunden wird.
  - Der **zugehörige Code** befindet sich in der Funktion `ImageLoaderMachO::doGetDependentLibraries` von `ImageLoaderMachO.cpp`. Dort ist `lib->required` nur dann `false`, wenn `LC_LOAD_WEAK_DYLIB` zutrifft.
  - **Finde weak linked libraries** in Binärdateien mit folgendem Befehl (weiter unten findest du ein Beispiel zum Erstellen von Hijacking-Bibliotheken):
    - ```bash
      otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
      cmdsize 56
      name /var/tmp/lib/libUtl.1.dylib (offset 24)
      time stamp 2 Wed Jun 21 12:23:31 1969
      current version 1.0.0
      compatibility version 1.0.0
      ```
- **Configured with @rpath**: Mach-O binaries can have the commands **`LC_RPATH`** and **`LC_LOAD_DYLIB`**. Base on the **values** of those commands, **libraries** are going to be **loaded** from **different directories**.
  - **`LC_RPATH`** contains the paths of some folders used to load libraries by the binary.
  - **`LC_LOAD_DYLIB`** contains the path to specific libraries to load. These paths can contain **`@rpath`**, which will be **replaced** by the values in **`LC_RPATH`**. If there are several paths in **`LC_RPATH`** everyone will be used to search the library to load. Example:
    - If **`LC_LOAD_DYLIB`** contains `@rpath/library.dylib` and **`LC_RPATH`** contains `/application/app.app/Contents/Framework/v1/` and `/application/app.app/Contents/Framework/v2/`. Both folders are going to be used to load `library.dylib`**.** If the library doesn't exist in `[...]/v1/` and attacker could place it there to hijack the load of the library in `[...]/v2/` as the order of paths in **`LC_LOAD_DYLIB`** is followed.
  - **Find rpath paths and libraries** in binaries with: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Is the **path** to the directory containing the **main executable file**.
>
> **`@loader_path`**: Is the **path** to the **directory** containing the **Mach-O binary** which contains the load command.
>
> - When used in an executable, **`@loader_path`** is effectively the **same** as **`@executable_path`**.
> - When used in a **dylib**, **`@loader_path`** gives the **path** to the **dylib**.

The way to **escalate privileges** abusing this functionality would be in the rare case that an **application** being executed **by** **root** is **looking** for some **library in some folder where the attacker has write permissions.**

> [!TIP]
> A nice **scanner** to find **missing libraries** in applications is [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) or a [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> A nice **report with technical details** about this technique can be found [**here**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Remember that **previous Library Validation restrictions also apply** to perform Dlopen hijacking attacks.

From **`man dlopen`**:

- When path **does not contain a slash character** (i.e. it is just a leaf name), **dlopen() will do searching**. If **`$DYLD_LIBRARY_PATH`** was set at launch, dyld will first **look in that director**y. Next, if the calling mach-o file or the main executable specify an **`LC_RPATH`**, then dyld will **look in those** directories. Next, if the process is **unrestricted**, dyld will search in the **current working directory**. Lastly, for old binaries, dyld will try some fallbacks. If **`$DYLD_FALLBACK_LIBRARY_PATH`** was set at launch, dyld will search in **those directories**, otherwise, dyld will look in **`/usr/local/lib/`** (if the process is unrestricted), and then in **`/usr/lib/`** (this info was taken from **`man dlopen`**).
  1. `$DYLD_LIBRARY_PATH`
  2. `LC_RPATH`
  3. `CWD`(if unrestricted)
  4. `$DYLD_FALLBACK_LIBRARY_PATH`
  5. `/usr/local/lib/` (if unrestricted)
  6. `/usr/lib/`

> [!CAUTION]
> If no slashes in the name, there would be 2 ways to do an hijacking:
>
> - If any **`LC_RPATH`** is **writable** (but signature is checked, so for this you also need the binary to be unrestricted)
> - If the binary is **unrestricted** and then it's possible to load something from the CWD (or abusing one of the mentioned env variables)

- When path **looks like a framework** path (e.g. `/stuff/foo.framework/foo`), if **`$DYLD_FRAMEWORK_PATH`** was set at launch, dyld will first look in that directory for the **framework partial path** (e.g. `foo.framework/foo`). Next, dyld will try the **supplied path as-is** (using current working directory for relative paths). Lastly, for old binaries, dyld will try some fallbacks. If **`$DYLD_FALLBACK_FRAMEWORK_PATH`** was set at launch, dyld will search those directories. Otherwise, it will search **`/Library/Frameworks`** (on macOS if process is unrestricted), then **`/System/Library/Frameworks`**.
  1. `$DYLD_FRAMEWORK_PATH`
  2. supplied path (using current working directory for relative paths if unrestricted)
  3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
  4. `/Library/Frameworks` (if unrestricted)
  5. `/System/Library/Frameworks`

> [!CAUTION]
> If a framework path, the way to hijack it would be:
>
> - If the process is **unrestricted**, abusing the **relative path from CWD** the mentioned env variables (even if it's not said in the docs if the process is restricted DYLD\_\* env vars are removed)

- When path **contains a slash but is not a framework path** (i.e. a full path or a partial path to a dylib), dlopen() first looks in (if set) in **`$DYLD_LIBRARY_PATH`** (with leaf part from path ). Next, dyld **tries the supplied path** (using current working directory for relative paths (but only for unrestricted processes)). Lastly, for older binaries, dyld will try fallbacks. If **`$DYLD_FALLBACK_LIBRARY_PATH`** was set at launch, dyld will search in those directories, otherwise, dyld will look in **`/usr/local/lib/`** (if the process is unrestricted), and then in **`/usr/lib/`**.
  1. `$DYLD_LIBRARY_PATH`
  2. supplied path (using current working directory for relative paths if unrestricted)
  3. `$DYLD_FALLBACK_LIBRARY_PATH`
  4. `/usr/local/lib/` (if unrestricted)
  5. `/usr/lib/`

> [!CAUTION]
> If slashes in the name and not a framework, the way to hijack it would be:
>
> - If the binary is **unrestricted** and then it's possible to load something from the CWD or `/usr/local/lib` (or abusing one of the mentioned env variables)

> [!TIP]
> Note: There are **no** configuration files to **control dlopen searching**.
>
> Note: If the main executable is a **set\[ug]id binary or codesigned with entitlements**, then **all environment variables are ignored**, and only a full path can be used ([check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) for more detailed info)
>
> Note: Apple platforms use "universal" files to combine 32-bit and 64-bit libraries. This means there are **no separate 32-bit and 64-bit search paths**.
>
> Note: On Apple platforms most OS dylibs are **combined into the dyld cache** and do not exist on disk. Therefore, calling **`stat()`** to preflight if an OS dylib exists **won't work**. However, **`dlopen_preflight()`** uses the same steps as **`dlopen()`** to find a compatible mach-o file.

**Check paths**

Lets check all the options with the following code:

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

If you compile and execute it you can see **where each library was unsuccessfully searched for**. Also, you could **filter the FS logs**:

```bash
sudo fs_usage | grep "dlopentest"
```

## Relative Path Hijacking

If a **privileged binary/app** (like a SUID or some binary with powerful entitlements) is **loading a relative path** library (for example using `@executable_path` or `@loader_path`) and has **Library Validation disabled**, it could be possible to move the binary to a location where the attacker could **modify the relative path loaded library**, and abuse it to inject code on the process.

## Prune `DYLD_*` env variables

Older `dyld` releases (`dyld2.cpp`) decided this in-process with `issetugid()`, `hasRestrictedSegment()` and `csops(CS_OPS_STATUS)`. In **current `dyld` the decision is delegated to AMFI**, and the code lives in `ProcessConfig::Security::Security()` in `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>

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

Two things are worth extracting from this:

- Pruning only happens on **macOS / Mac Catalyst / DriverKit** — and only when AMFI granted **none** of `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- The AMFI query is fed the executable's own properties:

```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
                                   proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```

where `isRestricted()` is literally the `__RESTRICT` segment check (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>

```cpp
bool UnsafeHeader::isRestricted() const
{
    return this->hasSection("__RESTRICT", "__restrict");
}
```

`pruneEnvVars()` then strips **every** variable whose name begins with `DYLD_` and slides the `apple[]` parameters down, so the children of a restricted process don't inherit them either:

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
> Practical consequence: **`DYLD_*` is pruned when the process is restricted** — setuid/setgid, a `__RESTRICT/__restrict` section, or hardened-runtime/entitled binaries that AMFI refuses to grant the path/print flags to. If instead the process only has **library validation** (`CS_REQUIRE_LV`), the variables survive but the inserted dylib must be signed by the **same Team ID** (or by Apple), so you need one of the library-validation-disabling entitlements to actually land code.

Because the decision is now AMFI's, the fastest way to know what a given binary will get is to look at what AMFI keys off — entitlements and signing flags — rather than at `dyld` itself:

```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
  egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```

## Check Restrictions

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

### Section `__RESTRICT` with segment `__restrict`

```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```

### Hardened runtime

Create a new certificate in the Keychain and use it to sign the binary:

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
> Note that even if there are binaries signed with flags **`0x0(none)`**, they can get the **`CS_RESTRICT`** flag dynamically when executed and therefore this technique won't work in them.
>
> You can check if a proc has this flag with (get [**csops here**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> and then check if the flag 0x800 is enabled.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (process startup and library insertion)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
