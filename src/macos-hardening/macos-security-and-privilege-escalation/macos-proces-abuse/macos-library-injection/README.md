# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Die kode van **dyld is open source** en kan gevind word by [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) en kan as 'n tar afgelaai word met 'n **URL soos** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Kyk hoe Dyld biblioteke binne binaries laai by:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Dit is soos [**LD_PRELOAD on Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Dit laat jou toe om vir 'n process wat uitgevoer gaan word aan te dui dat dit 'n spesifieke library vanaf 'n path moet laai (indien die env var geaktiveer is).

Hierdie tegniek kan ook **as 'n ASEP-tegniek gebruik word**, aangesien elke geïnstalleerde application 'n plist genaamd "Info.plist" het wat die **toewysing van omgewingsveranderlikes** moontlik maak deur 'n key genaamd `LSEnvironmental` te gebruik.

> [!TIP]
> Sedert 2012 het **Apple die krag van** **`DYLD_INSERT_LIBRARIES`** **drasties verminder**.
>
> Gaan na die kode en **kontroleer `src/dyld.cpp`**. In die function **`pruneEnvironmentVariables`** kan jy sien dat **`DYLD_*`**-veranderlikes verwyder word.
>
> In die function **`processRestricted`** word die rede vir die beperking gestel. Deur daardie kode te kontroleer, kan jy sien dat die redes is:
>
> - Die binary is `setuid/setgid`
> - Die bestaan van 'n `__RESTRICT/__restrict`-section in die macho binary.
> - Die software het entitlements (hardened runtime) sonder die [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)-entitlement
>  - Kontroleer die **entitlements** van 'n binary met: `codesign -dv --entitlements :- </path/to/bin>`
>
> In meer onlangse weergawes kan jy hierdie logika in die tweede deel van die function **`configureProcessRestrictions`** vind. Wat in nuwer weergawes uitgevoer word, is egter die **begin-kontroles van die function** (jy kan die ifs wat met iOS of simulation verband hou verwyder, aangesien hulle nie in macOS gebruik sal word nie).

### Library Validation

Selfs al laat die binary die **`DYLD_INSERT_LIBRARIES`**-env variable toe, sal dit nie 'n custom library laai as die binary die signature van die library kontroleer nie.

Om 'n custom library te laai, moet die binary **een van die volgende entitlements** hê:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

of die binary **moet nie** die **hardened runtime flag** of die **library validation flag** hê nie.

Jy kan kontroleer of 'n binary **hardened runtime** het met `codesign --display --verbose <bin>` deur die runtime flag in **`CodeDirectory`** te kontroleer, soos: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Jy kan ook 'n library laai as dit **met dieselfde certificate as die binary gesign** is.

Vind 'n voorbeeld van hoe om dit te (ab)use en die restrictions te kontroleer by:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Onthou dat **vorige Library Validation-restrictions ook van toepassing is** om Dylib hijacking attacks uit te voer.

Soos in Windows, kan jy in MacOS ook **dylibs hijack** om **applications** **arbitrary** **code** te laat **execute** (wel, eintlik sal dit vanaf 'n gewone user nie moontlik wees nie, aangesien jy moontlik 'n TCC-permission nodig het om binne 'n `.app`-bundle te skryf en 'n library te hijack).\
Die manier waarop **MacOS**-applications libraries **laai**, is egter **meer beperk** as in Windows. Dit beteken dat **malware**-developers steeds hierdie tegniek vir **stealth** kan gebruik, maar die waarskynlikheid om dit te **abuse om privileges te eskaleer**, is baie laer.

Eerstens is dit **meer algemeen** om te vind dat **MacOS-binaries die volledige path** na die libraries wat gelaai moet word, aandui. Tweedens soek **MacOS nooit** in die folders van die **$PATH** vir libraries nie.

Die **hoofgedeelte** van die **code** wat met hierdie funksionaliteit verband hou, is in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Daar is **4 verskillende header Commands** wat 'n macho binary kan gebruik om libraries te laai:

- Die **`LC_LOAD_DYLIB`**-command is die algemene command om 'n dylib te laai.
- Die **`LC_LOAD_WEAK_DYLIB`**-command werk soos die vorige een, maar as die dylib nie gevind word nie, gaan execution voort sonder enige error.
- Die **`LC_REEXPORT_DYLIB`**-command proxy (of re-export) die symbols vanaf 'n ander library.
- Die **`LC_LOAD_UPWARD_DYLIB`**-command word gebruik wanneer twee libraries van mekaar afhanklik is (dit word 'n _upward dependency_ genoem).

Daar is egter **2 tipes dylib hijacking**:

- **Missing weak linked libraries**: Dit beteken dat die application sal probeer om 'n library te laai wat nie bestaan nie en met **LC_LOAD_WEAK_DYLIB** gekonfigureer is. Dan, **as 'n attacker 'n dylib plaas waar dit verwag word, sal dit gelaai word**.
- Die feit dat die link "weak" is, beteken dat die application sal voortgaan om te loop selfs al word die library nie gevind nie.
- Die **code wat hiermee verband hou** is in die function `ImageLoaderMachO::doGetDependentLibraries` van `ImageLoaderMachO.cpp`, waar `lib->required` slegs `false` is wanneer `LC_LOAD_WEAK_DYLIB` true is.
- **Vind weak linked libraries** in binaries met (later is daar 'n voorbeeld van hoe om hijacking-libraries te skep):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Gekonfigureer met @rpath**: Mach-O-binaries kan die commands **`LC_RPATH`** en **`LC_LOAD_DYLIB`** hê. Gebaseer op die **waardes** van hierdie commands, gaan **libraries** vanaf **verskillende directories** gelaai word.
- **`LC_RPATH`** bevat die paths van sommige folders wat deur die binary gebruik word om libraries te laai.
- **`LC_LOAD_DYLIB`** bevat die path na spesifieke libraries wat gelaai moet word. Hierdie paths kan **`@rpath`** bevat, wat deur die waardes in **`LC_RPATH`** vervang sal word. As daar verskeie paths in **`LC_RPATH`** is, sal elkeen gebruik word om na die library wat gelaai moet word te soek. Voorbeeld:
- As **`LC_LOAD_DYLIB`** `@rpath/library.dylib` bevat en **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` en `/application/app.app/Contents/Framework/v2/` bevat, gaan albei folders gebruik word om `library.dylib` te laai**.** As die library nie in `[...]/v1/` bestaan nie en 'n attacker dit daar kan plaas, kan die attacker die laai van die library in `[...]/v2/` hijack, aangesien die volgorde van paths in **`LC_LOAD_DYLIB`** gevolg word.
- **Vind rpath paths en libraries** in binaries met: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Is die **path** na die directory wat die **main executable file** bevat.
>
> **`@loader_path`**: Is die **path** na die **directory** wat die **Mach-O binary** bevat wat die load command insluit.
>
> - Wanneer dit in 'n executable gebruik word, is **`@loader_path`** effektief dieselfde as **`@executable_path`**.
> - Wanneer dit in 'n **dylib** gebruik word, gee **`@loader_path`** die **path** na die **dylib**.

Die manier om **privileges te eskaleer** deur hierdie funksionaliteit te abuse, sou in die seldsame geval wees waar 'n **application** wat **deur** **root** uitgevoer word, **na** 'n **library in 'n folder kyk waar die attacker skryftoestemmings het.**

'n Goeie **scanner** om **missing libraries** in applications te vind, is [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) of 'n [**CLI version**](https://github.com/pandazheng/DylibHijack).\
'n Goeie **report met tegniese besonderhede** oor hierdie tegniek kan [**hier**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) gevind word.

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Onthou dat **vorige Library Validation-restrictions ook van toepassing is** om Dlopen hijacking attacks uit te voer.

Vanaf **`man dlopen`**:

- Wanneer die path **nie 'n slash-karakter bevat nie** (dit wil sê, dit is slegs 'n leaf name), sal **dlopen() soek**. As **`$DYLD_LIBRARY_PATH`** tydens launch gestel is, sal dyld eers **in daardie directory kyk**. Vervolgens, as die calling mach-o file of die main executable 'n **`LC_RPATH`** spesifiseer, sal dyld **in daardie** directories kyk. Vervolgens, as die process **unrestricted** is, sal dyld in die **current working directory** soek. Laastens, vir old binaries, sal dyld sommige fallbacks probeer. As **`$DYLD_FALLBACK_LIBRARY_PATH`** tydens launch gestel is, sal dyld in **daardie directories** soek; anders sal dyld in **`/usr/local/lib/`** kyk (as die process unrestricted is), en daarna in **`/usr/lib/`** (hierdie info is uit **`man dlopen`** geneem).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> As daar geen slashes in die naam is nie, is daar 2 maniere om 'n hijacking uit te voer:
>
> - As enige **`LC_RPATH`** **writable** is (maar signature word gekontroleer, dus moet die binary hiervoor ook unrestricted wees)
> - As die binary **unrestricted** is, waarna dit moontlik is om iets vanaf die CWD te laai (of een van die genoemde env variables te abuse)

- Wanneer die path soos 'n framework-path lyk (bv. `/stuff/foo.framework/foo`), as **`$DYLD_FRAMEWORK_PATH`** tydens launch gestel is, sal dyld eers in daardie directory na die **framework partial path** kyk (bv. `foo.framework/foo`). Vervolgens sal dyld die **supplied path as-is** probeer (deur die current working directory vir relatiewe paths te gebruik). Laastens, vir old binaries, sal dyld sommige fallbacks probeer. As **`$DYLD_FALLBACK_FRAMEWORK_PATH`** tydens launch gestel is, sal dyld in daardie directories soek. Andersins sal dit in **`/Library/Frameworks`** soek (op macOS indien die process unrestricted is), en daarna in **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> As dit 'n framework-path is, sou die manier om dit te hijack wees:
>
> - As die process **unrestricted** is, deur die **relative path from CWD** en die genoemde env variables te abuse (selfs al word dit nie in die docs genoem nie, word DYLD\_\*-env variables verwyder as die process restricted is)

- Wanneer die path **'n slash bevat maar nie 'n framework-path is nie** (dit wil sê, 'n full path of 'n partial path na 'n dylib), kyk dlopen() eers (indien gestel) in **`$DYLD_LIBRARY_PATH`** (met die leaf part vanaf die path). Vervolgens **probeer dyld die supplied path** (deur die current working directory vir relatiewe paths te gebruik (maar slegs vir unrestricted processes)). Laastens, vir ouer binaries, sal dyld fallbacks probeer. As **`$DYLD_FALLBACK_LIBRARY_PATH`** tydens launch gestel is, sal dyld in daardie directories soek; anders sal dyld in **`/usr/local/lib/`** kyk (as die process unrestricted is), en daarna in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> As daar slashes in die naam is en dit nie 'n framework is nie, sou die manier om dit te hijack wees:
>
> - As die binary **unrestricted** is, waarna dit moontlik is om iets vanaf die CWD of `/usr/local/lib` te laai (of een van die genoemde env variables te abuse)

> [!TIP]
> Nota: Daar is **geen** configuration files om **dlopen searching te beheer** nie.
>
> Nota: As die main executable 'n **set\[ug]id binary** is of met entitlements codesigned is, word **alle environment variables geïgnoreer**, en slegs 'n full path kan gebruik word ([check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) vir meer gedetailleerde info).
>
> Nota: Apple-platforms gebruik "universal"-files om 32-bit- en 64-bit-libraries te kombineer. Dit beteken dat daar **geen afsonderlike 32-bit- en 64-bit-search paths** is nie.
>
> Nota: Op Apple-platforms word die meeste OS-dylibs **in die dyld cache gekombineer** en bestaan hulle nie op disk nie. Daarom sal dit nie werk om **`stat()`** te roep om vooraf te kontroleer of 'n OS-dylib bestaan nie. **`dlopen_preflight()`** gebruik egter dieselfde stappe as **`dlopen()`** om 'n compatible mach-o file te vind.

**Kontroleer paths**

Kom ons kontroleer al die opsies met die volgende kode:
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
As jy dit compile en execute, kan jy sien waar daar onsuksesvol na elke library gesoek is. Jy kan ook die FS logs filter:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

As 'n **privileged binary/app** (soos 'n SUID- of een of ander binary met kragtige entitlements) 'n library vanaf 'n **relative path** laai (byvoorbeeld met `@executable_path` of `@loader_path`) en **Library Validation disabled** is, kan dit moontlik wees om die binary na 'n ligging te verskuif waar die aanvaller die **library wat vanaf die relative path gelaai word**, kan **modify**, en dit te misbruik om code in die proses te inject.

## Verwyder `DYLD_*`- en `LD_LIBRARY_PATH`-env variables

In die lêer `dyld-dyld-832.7.1/src/dyld2.cpp` is dit moontlik om die funksie **`pruneEnvironmentVariables`** te vind, wat enige env variable sal verwyder wat **met `DYLD_` begin** en **`LD_LIBRARY_PATH=`** is.

Dit sal ook spesifiek die env variables **`DYLD_FALLBACK_FRAMEWORK_PATH`** en **`DYLD_FALLBACK_LIBRARY_PATH`** op **null** stel vir **suid**- en **sgid**-binaries.

Hierdie funksie word vanuit die **`_main`**-funksie van dieselfde lêer geroep indien daar op OSX geteiken word, soos volg:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
en daardie boolean-vlae word in dieselfde lêer in die kode gestel:
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
Wat basies beteken dat indien die binary **suid** of **sgid** is, of ’n **RESTRICT**-segment in die headers het, of met die **CS_RESTRICT**-flag onderteken is, **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** waar is en die omgewingsveranderlikes verwyder word.

Let daarop dat indien CS_REQUIRE_LV waar is, die veranderlikes nie verwyder sal word nie, maar die library validation sal kontroleer of hulle dieselfde sertifikaat as die oorspronklike binary gebruik.

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
### Afdeling `__RESTRICT` met segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Skep ’n nuwe sertifikaat in die Keychain en gebruik dit om die binary te sign:
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
> Let daarop dat selfs indien daar binaries is wat met flags **`0x0(none)`** onderteken is, hulle die **`CS_RESTRICT`**-flag dinamies kan kry wanneer hulle uitgevoer word, en daarom sal hierdie tegniek nie daarin werk nie.
>
> Jy kan met (kry [**csops hier**](https://github.com/axelexic/CSOps)) kontroleer of ’n proc hierdie flag het:
>
> ```bash
> csops -status <pid>
> ```
>
> en kontroleer dan of die flag 0x800 geaktiveer is.

## Verwysings

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
