# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Die kode van **dyld is open source** en kan gevind word by [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) en as ’n tar-lêer afgelaai word vanaf ’n **URL soos** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Kyk hoe Dyld libraries binne binaries laai by:


{{#ref}}
macos-dyld-process.md
{{#endref}}

Sien ook: [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

## **DYLD_INSERT_LIBRARIES**

Dit werk soos [**LD_PRELOAD op Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Dit laat jou toe om aan te dui dat ’n proses wat gaan loop ’n spesifieke library vanaf ’n pad moet laai (as die env-var geaktiveer is)<sup>[[4]](#references)</sup>

Hierdie tegniek kan ook **as ’n ASEP-tegniek gebruik word**, aangesien elke geïnstalleerde toepassing ’n plist genaamd "Info.plist" het wat toelaat dat **environment variables toegewys word** met ’n sleutel genaamd `LSEnvironmental`.

> [!TIP]
> Sedert 2012 het **Apple die werking van** **`DYLD_INSERT_LIBRARIES`** drasties beperk. ’n Proses word as **restricted** beskou — waarna `dyld` elke `DYLD_*`-veranderlike uit sy omgewing verwyder — wanneer enige van die volgende geld:
>
> - Die binary is `setuid/setgid`
> - Die Mach-O het ’n **`__RESTRICT/__restrict`**-afdeling
> - Die binary is met die hardened runtime onderteken en AMFI verleen nie die "path/print variables"-toestemmings daaraan nie; dit wil sê, dit het nie [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup> nie
>   - Gaan ’n binary se **entitlements** na met: `codesign -dv --entitlements :- </path/to/bin>`
>
> In huidige `dyld` word dit nie meer deur `dyld` alleen bepaal nie: `ProcessConfig::Security::Security()` vra **AMFI** via `amfi_check_dyld_policy_self()` en roep dan `pruneEnvVars()` aan. Die presiese kode word hieronder deurgegaan in [Prune `DYLD_*` env variables](#prune-dyld_-env-variables).

### Library Validation

Selfs al laat die binary die **`DYLD_INSERT_LIBRARIES`**-environment variable toe, sal dit nie ’n custom library laai as dit die library se handtekening valideer nie.

Om ’n custom library te laai, moet die binary **een van die volgende entitlements** hê:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

of die binary **mag nie** die **hardened runtime-flag** of die **library validation-flag** hê nie.

Jy kan nagaan of ’n binary **hardened runtime** het met `codesign --display --verbose <bin>` deur die runtime-flag in **`CodeDirectory`** na te gaan, soos: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Jy kan ook ’n library laai as dit **met dieselfde sertifikaat as die binary onderteken is**.

Vind ’n voorbeeld van hoe om dit te (mis)bruik en gaan die beperkings na by:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Onthou dat die **vorige Library Validation-beperkings ook geld** vir Dylib hijacking-aanvalle.

Soos op Windows, kan jy op macOS **dylibs hijack** om **toepassings arbitrêre kode te laat uitvoer**. Dit is moontlik nie vanaf ’n gewone gebruikersrekening nie, omdat die skryf van ’n library binne ’n `.app`-bundel om dit te hijack ’n TCC-toestemming kan vereis.\
Die manier waarop **macOS**-toepassings egter libraries **laai**, is **meer beperk** as op Windows. Malware-ontwikkelaars kan steeds hierdie tegniek vir **stealth** gebruik, maar dit is baie minder waarskynlik dat hulle dit kan misbruik om voorregte te eskaleer.

Eerstens is dit **meer algemeen** dat **MacOS-binaries die volledige pad** na die libraries wat gelaai moet word, aandui. Tweedens soek **MacOS nooit** na libraries in die vouers van **$PATH** nie.

Die **hoofgedeelte** van die **kode** wat met hierdie funksionaliteit verband hou, is in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Daar is **4 verskillende header Commands** wat ’n macho-binary kan gebruik om libraries te laai:

- Die **`LC_LOAD_DYLIB`**-command is die gewone command om ’n dylib te laai.
- Die **`LC_LOAD_WEAK_DYLIB`**-command werk soos die vorige een, maar as die dylib nie gevind word nie, gaan uitvoering voort sonder enige fout.
- Die **`LC_REEXPORT_DYLIB`**-command stuur die simbole van ’n ander library deur (of voer hulle weer uit).
- Die **`LC_LOAD_UPWARD_DYLIB`**-command word gebruik wanneer twee libraries van mekaar afhanklik is (dit word ’n _upward dependency_ genoem).

Daar is egter **2 tipes dylib hijacking**:

- **Ontbrekende weak-linked libraries**: Dit beteken dat die toepassing ’n library sal probeer laai wat nie bestaan nie, maar met **LC_LOAD_WEAK_DYLIB** opgestel is. Dan, **as ’n aanvaller ’n dylib plaas waar dit verwag word, sal dit gelaai word**.
  - Die feit dat die skakel "weak" is, beteken dat die toepassing sal aanhou loop selfs as die library nie gevind word nie.
  - Die **verwante kode** is in die funksie `ImageLoaderMachO::doGetDependentLibraries` van `ImageLoaderMachO.cpp`, waar `lib->required` slegs `false` is wanneer `LC_LOAD_WEAK_DYLIB` waar is.
  - **Vind weak-linked libraries** in binaries met (’n voorbeeld van hoe om hijacking-libraries te skep, volg verderaan):
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
