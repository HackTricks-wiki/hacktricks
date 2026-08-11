# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Die kode van **dyld is open source** en kan gevind word by [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) en kan as 'n tar afgelaai word met 'n **URL soos** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Kyk hoe Dyld libraries binne binaries laai by:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Dit is soos [**LD_PRELOAD on Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Dit laat jou toe om aan te dui dat 'n process wat gaan hardloop, 'n spesifieke library vanaf 'n path moet laai (indien die env var geaktiveer is)<sup>[[4]](#references)</sup>

Hierdie tegniek kan ook **as 'n ASEP-tegniek gebruik word**, aangesien elke geïnstalleerde application 'n plist genaamd "Info.plist" het wat die **toewysing van environmental variables** met behulp van 'n key genaamd `LSEnvironmental` moontlik maak.

> [!TIP]
> Sedert 2012 het **Apple die krag van** **`DYLD_INSERT_LIBRARIES`** **drasties verminder**. 'n Process word as **restricted** beskou — en dan verwyder `dyld` elke `DYLD_*` variable uit sy environment — wanneer enige van die volgende waar is:
>
> - Die binary is `setuid/setgid`
> - Die Mach-O het 'n **`__RESTRICT/__restrict`** section
> - Die binary is met die hardened runtime gesign en AMFI gee dit nie die "path/print variables"-permissions nie, d.w.s. dit het nie [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup> nie
>   - Kontroleer **entitlements** van 'n binary met: `codesign -dv --entitlements :- </path/to/bin>`
>
> In huidige `dyld` word dit nie meer net deur `dyld` bepaal nie: `ProcessConfig::Security::Security()` vra **AMFI** via `amfi_check_dyld_policy_self()` en roep daarna `pruneEnvVars()` aan. Die presiese kode word hieronder in [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) deurgegaan.

### Library Validation

Selfs al laat die binary die **`DYLD_INSERT_LIBRARIES`** env variable toe, sal dit nie 'n custom library laai indien dit die library se signature valideer nie.

Om 'n custom library te laai, moet die binary **een van die volgende entitlements** hê:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

of die binary **moet nie** die **hardened runtime flag** of die **library validation flag** hê nie.

Jy kan kontroleer of 'n binary **hardened runtime** het met `codesign --display --verbose <bin>` deur die runtime flag in **`CodeDirectory`** na te gaan, soos: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Jy kan ook 'n library laai indien dit **met dieselfde certificate as die binary gesign** is.

Vind 'n voorbeeld van hoe om dit te (ab)useer en die restrictions te kontroleer by:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Onthou dat **vorige Library Validation restrictions ook van toepassing is** om Dylib hijacking attacks uit te voer.

Soos in Windows, kan jy in MacOS ook **dylibs hijack** om **applications** **arbitrary** **code** te laat **execute** (wel, eintlik sou dit vanaf 'n gewone user nie moontlik wees nie, aangesien jy moontlik 'n TCC-permission nodig het om binne 'n `.app` bundle te skryf en 'n library te hijack).\
Die manier waarop **MacOS**-applications libraries **laai**, is egter **meer restricted** as in Windows. Dit impliseer dat **malware**-developers steeds hierdie tegniek vir **stealth** kan gebruik, maar die waarskynlikheid om dit te **abuseer om privileges te eskaleer**, is baie laer.

Eerstens is dit **meer algemeen** om te vind dat **MacOS-binaries die volledige path** na die libraries wat gelaai moet word, aandui. Tweedens **soek MacOS nooit** in die folders van die **$PATH** vir libraries nie.

Die **hoofdeel** van die **code** wat met hierdie funksionaliteit verband hou, is in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Daar is **4 verskillende header Commands** wat 'n macho binary kan gebruik om libraries te laai:

- Die **`LC_LOAD_DYLIB`** command is die algemene command om 'n dylib te laai.
- Die **`LC_LOAD_WEAK_DYLIB`** command werk soos die vorige een, maar indien die dylib nie gevind word nie, gaan execution voort sonder enige error.
- Die **`LC_REEXPORT_DYLIB`** command proxy (of re-export) die symbols vanaf 'n ander library.
- Die **`LC_LOAD_UPWARD_DYLIB`** command word gebruik wanneer twee libraries van mekaar afhanklik is (dit word 'n _upward dependency_ genoem).

Daar is egter **2 tipes dylib hijacking**:

- **Missing weak linked libraries**: Dit beteken dat die application sal probeer om 'n library te laai wat nie bestaan nie en met **LC_LOAD_WEAK_DYLIB** gekonfigureer is. Daarna, **indien 'n attacker 'n dylib plaas waar dit verwag word, sal dit gelaai word**.
- Die feit dat die link "weak" is, beteken dat die application sal aanhou loop selfs indien die library nie gevind word nie.
- Die **code wat hiermee verband hou**, is in die function `ImageLoaderMachO::doGetDependentLibraries` van `ImageLoaderMachO.cpp`, waar `lib->required` slegs `false` is wanneer `LC_LOAD_WEAK_DYLIB` true is.
- **Vind weak linked libraries** in binaries met (jy kry later 'n voorbeeld van hoe om hijacking libraries te skep):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O-binaries kan die commands **`LC_RPATH`** en **`LC_LOAD_DYLIB`** hê. Gebaseer op die **waardes** van hierdie commands, gaan **libraries** vanaf **verskillende directories** gelaai word.
- **`LC_RPATH`** bevat die paths van sommige folders wat deur die binary gebruik word om libraries te laai.
- **`LC_LOAD_DYLIB`** bevat die path na spesifieke libraries om te laai. Hierdie paths kan **`@rpath`** bevat, wat deur die waardes in **`LC_RPATH`** vervang sal word. Indien daar verskeie paths in **`LC_RPATH`** is, sal elkeen gebruik word om die library wat gelaai moet word, te soek. Voorbeeld:
- Indien **`LC_LOAD_DYLIB`** `@rpath/library.dylib` bevat en **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` en `/application/app.app/Contents/Framework/v2/` bevat, gaan albei folders gebruik word om `library.dylib` te laai**.** Indien die library nie in `[...]/v1/` bestaan nie en 'n attacker dit daar kan plaas, kan hy die laai van die library in `[...]/v2/` hijack, aangesien die volgorde van paths in **`LC_LOAD_DYLIB`** gevolg word.
- **Vind rpath paths en libraries** in binaries met: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Is die **path** na die directory wat die **main executable file** bevat.
>
> **`@loader_path`**: Is die **path** na die **directory** wat die **Mach-O binary** bevat wat die load command bevat.
>
> - Wanneer dit in 'n executable gebruik word, is **`@loader_path`** effektief dieselfde as **`@executable_path`**.
> - Wanneer dit in 'n **dylib** gebruik word, gee **`@loader_path`** die **path** na die **dylib**.

Die manier om **privileges te eskaleer** deur hierdie funksionaliteit te abuse, sou wees in die rare geval waar 'n **application** wat **deur** **root** uitgevoer word, **na** 'n **library in 'n folder waar die attacker write permissions het**, **soek**.

> [!TIP]
> 'n Goeie **scanner** om **missing libraries** in applications te vind, is [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) of 'n [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> 'n Goeie **report met tegniese details** oor hierdie tegniek kan [**hier**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) gevind word.

**Voorbeeld**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Onthou dat **vorige Library Validation restrictions ook van toepassing is** om Dlopen hijacking attacks uit te voer.

Vanaf **`man dlopen`**:

- Wanneer path **nie 'n slash-karakter bevat nie** (d.w.s. dit is slegs 'n leaf name), sal **dlopen() soek**. Indien **`$DYLD_LIBRARY_PATH`** tydens launch gestel is, sal dyld eers **in daardie directory kyk**. Vervolgens, indien die calling mach-o file of die main executable 'n **`LC_RPATH`** spesifiseer, sal dyld **in daardie** directories **kyk**. Daarna, indien die process **unrestricted** is, sal dyld in die **current working directory** soek. Laastens sal dyld, vir ou binaries, sommige fallbacks probeer. Indien **`$DYLD_FALLBACK_LIBRARY_PATH`** tydens launch gestel is, sal dyld in **daardie directories** soek; anders sal dyld in **`/usr/local/lib/`** kyk (indien die process unrestricted is), en daarna in **`/usr/lib/`** (hierdie info is uit **`man dlopen`** geneem).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Indien daar geen slashes in die name is nie, sou daar 2 maniere wees om 'n hijacking uit te voer:
>
> - Indien enige **`LC_RPATH`** **writable** is (maar die signature word gekontroleer, dus moet die binary hiervoor ook unrestricted wees)
> - Indien die binary **unrestricted** is, waarna dit moontlik is om iets vanaf die CWD te laai (of een van die genoemde env variables te abuse)

- Wanneer die path soos 'n framework path lyk (bv. `/stuff/foo.framework/foo`), indien **`$DYLD_FRAMEWORK_PATH`** tydens launch gestel is, sal dyld eers in daardie directory vir die **framework partial path** (`foo.framework/foo`) kyk. Vervolgens sal dyld die **supplied path as-is** probeer (met die current working directory vir relative paths). Laastens sal dyld, vir ou binaries, sommige fallbacks probeer. Indien **`$DYLD_FALLBACK_FRAMEWORK_PATH`** tydens launch gestel is, sal dyld in daardie directories soek. Andersins sal dit in **`/Library/Frameworks`** (op macOS indien die process unrestricted is) en daarna in **`/System/Library/Frameworks`** soek.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Indien dit 'n framework path is, sou die manier om dit te hijack wees:
>
> - Indien die process **unrestricted** is, deur die **relative path vanaf CWD** en die genoemde env variables te abuse (selfs al word dit nie in die docs genoem nie, word DYLD\_\*-env variables verwyder indien die process restricted is)

- Wanneer die path **'n slash bevat maar nie 'n framework path is nie** (d.w.s. 'n volledige path of 'n partial path na 'n dylib), kyk dlopen() eerste (indien gestel) in **`$DYLD_LIBRARY_PATH`** (met die leaf-deel vanaf path). Vervolgens **probeer dyld die supplied path** (met die current working directory vir relative paths (maar slegs vir unrestricted processes)). Laastens sal dyld, vir ouer binaries, fallbacks probeer. Indien **`$DYLD_FALLBACK_LIBRARY_PATH`** tydens launch gestel is, sal dyld in daardie directories soek; anders sal dyld in **`/usr/local/lib/`** kyk (indien die process unrestricted is), en daarna in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Indien daar slashes in die name is en dit nie 'n framework is nie, sou die manier om dit te hijack wees:
>
> - Indien die binary **unrestricted** is, waarna dit moontlik is om iets vanaf die CWD of `/usr/local/lib` te laai (of een van die genoemde env variables te abuse)

> [!TIP]
> Nota: Daar is **geen** configuration files om **dlopen searching te beheer** nie.
>
> Nota: Indien die main executable 'n **set\[ug]id binary** is of met **entitlements** codesigned is, word **alle environment variables geïgnoreer**, en slegs 'n volledige path kan gebruik word ([check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) vir meer gedetailleerde info)
>
> Nota: Apple-platforms gebruik "universal"-files om 32-bit- en 64-bit-libraries te kombineer. Dit beteken dat daar **geen aparte 32-bit- en 64-bit-search paths** is nie.
>
> Nota: Op Apple-platforms word die meeste OS-dylibs **in die dyld cache gekombineer** en bestaan hulle nie op disk nie. Daarom sal die gebruik van **`stat()`** om vooraf te kontroleer of 'n OS-dylib bestaan **nie werk nie**. **`dlopen_preflight()`** gebruik egter dieselfde stappe as **`dlopen()`** om 'n compatible mach-o file te vind.

**Kontroleer paths**

Kom ons kontroleer al die opsies met die volgende code:
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
As jy dit compile en uitvoer, kan jy sien **waar daar onsuksesvol na elke library gesoek is**. Jy kan ook **die FS logs filter**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

As ’n **privileged binary/app** (soos ’n SUID of een of ander binary met kragtige entitlements) ’n **relative path**-library laai (byvoorbeeld deur `@executable_path` of `@loader_path` te gebruik) en **Library Validation** gedeaktiveer is, kan dit moontlik wees om die binary te skuif na ’n ligging waar die aanvaller die **relative path**-library wat gelaai word, kan **modify**, en dit te misbruik om code in die proses te inject.

## Snoei `DYLD_*` env variables

Ouer `dyld`-releases (`dyld2.cpp`) het dit binne die proses bepaal met `issetugid()`, `hasRestrictedSegment()` en `csops(CS_OPS_STATUS)`. In **current `dyld` word die besluit aan AMFI gedelegeer**, en die code is in `ProcessConfig::Security::Security()` in `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
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
Twee dinge is die moeite werd om hieruit te haal:

- Pruning gebeur slegs op **macOS / Mac Catalyst / DriverKit** — en slegs wanneer AMFI **geen** van `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache` toegestaan het nie.
- Die AMFI-navraag kry die uitvoerbare lêer se eie eienskappe:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
waar `isRestricted()` letterlik die `__RESTRICT`-segmentkontrole is (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` verwyder daarna **elke** veranderlike waarvan die naam met `DYLD_` begin en skuif die `apple[]`-parameters af, sodat die kindprosesse van ’n beperkte proses dit ook nie oorneem nie:
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
> Praktiese gevolg: **`DYLD_*` word verwyder wanneer die proses beperk is** — setuid/setgid, ’n `__RESTRICT/__restrict`-afdeling, of hardened-runtime/entitled binaries waaraan AMFI weier om die path/print flags toe te staan. As die proses slegs **library validation** (`CS_REQUIRE_LV`) het, bly die veranderlikes bestaan, maar die ingevoegde dylib moet deur dieselfde Team ID (of deur Apple) onderteken wees; daarom het jy een van die library-validation-disabling entitlements nodig om werklik code uit te voer.

Omdat die besluit nou AMFI s’n is, is die vinnigste manier om te weet wat ’n gegewe binary sal kry, om te kyk waarop AMFI steun — entitlements en signing flags — eerder as na `dyld` self:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## Kontroleer beperkings

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
### Seksie `__RESTRICT` met segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened Runtime

Skep ’n nuwe sertifikaat in die Keychain en gebruik dit om die binary te onderteken:
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
> Let daarop dat selfs al is daar binaries wat met flags **`0x0(none)`** gesign is, hulle die **`CS_RESTRICT`** flag dinamies kan kry wanneer dit uitgevoer word en hierdie tegniek dus nie daarin sal werk nie.
>
> Jy kan nagaan of ’n proc hierdie flag het met (kry [**csops hier**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> en kyk dan of die flag 0x800 geaktiveer is.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (proses-opstart en library-invoeging)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
