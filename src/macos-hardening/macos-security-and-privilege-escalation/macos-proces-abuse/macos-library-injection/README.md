# macOS Biblioteek Inspuiting

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Die kode van **dyld is oopbron** en kan gevind word op [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) en kan afgelaai word as 'n tar met 'n **URL soos** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Proses**

Kyk hoe Dyld biblioteke binne binêre laai in:

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Dit is soos die [**LD_PRELOAD op Linux**](../../../../linux-hardening/privilege-escalation/index.html#ld_preload). Dit laat jou toe om 'n proses aan te dui wat gaan loop om 'n spesifieke biblioteek van 'n pad te laai (as die omgewing veranderlike geaktiveer is).

Hierdie tegniek kan ook **gebruik word as 'n ASEP tegniek** aangesien elke toepassing wat geïnstalleer is 'n plist genaamd "Info.plist" het wat die **toewysing van omgewingsveranderlikes** met 'n sleutel genaamd `LSEnvironmental` toelaat.

> [!NOTE]
> Sedert 2012 het **Apple drasties die mag** van die **`DYLD_INSERT_LIBRARIES`** verminder.
>
> Gaan na die kode en **kontroleer `src/dyld.cpp`**. In die funksie **`pruneEnvironmentVariables`** kan jy sien dat **`DYLD_*`** veranderlikes verwyder word.
>
> In die funksie **`processRestricted`** word die rede vir die beperking gestel. Deur daardie kode te kontroleer kan jy sien dat die redes is:
>
> - Die binêre is `setuid/setgid`
> - Bestaans van `__RESTRICT/__restrict` afdeling in die macho binêre.
> - Die sagteware het regte (hardened runtime) sonder [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) regte
>   - Kontroleer **regte** van 'n binêre met: `codesign -dv --entitlements :- </path/to/bin>`
>
> In meer opgedateerde weergawes kan jy hierdie logika in die tweede deel van die funksie **`configureProcessRestrictions`** vind. Wat egter in nuwer weergawes uitgevoer word, is die **begin kontroles van die funksie** (jy kan die ifs wat verband hou met iOS of simulasie verwyder, aangesien dit nie in macOS gebruik sal word nie).

### Biblioteek Validasie

Selfs as die binêre die **`DYLD_INSERT_LIBRARIES`** omgewing veranderlike toelaat, as die binêre die handtekening van die biblioteek kontroleer om dit te laai, sal dit nie 'n pasgemaakte laai nie.

Om 'n pasgemaakte biblioteek te laai, moet die binêre **een van die volgende regte** hê:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

of die binêre **moet nie** die **hardened runtime vlag** of die **biblioteek validasie vlag** hê nie.

Jy kan kontroleer of 'n binêre **hardened runtime** het met `codesign --display --verbose <bin>` deur die vlag runtime in **`CodeDirectory`** te kontroleer soos: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Jy kan ook 'n biblioteek laai as dit **onderteken is met dieselfde sertifikaat as die binêre**.

Vind 'n voorbeeld van hoe om (ab) te gebruik en die beperkings te kontroleer in:

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Onthou dat **vorige Biblioteek Validasie beperkings ook van toepassing is** om Dylib hijacking aanvalle uit te voer.

Soos in Windows, kan jy ook in MacOS **dylibs** **hijack** om **toepassings** **arbitraire** **kode** te **laat uitvoer** (wel, eintlik kan dit nie moontlik wees vanaf 'n gewone gebruiker nie, aangesien jy dalk 'n TCC toestemming nodig het om binne 'n `.app` bundel te skryf en 'n biblioteek te hijack).\
Echter, die manier waarop **MacOS** toepassings **biblioteke laai** is **meer beperk** as in Windows. Dit impliseer dat **malware** ontwikkelaars steeds hierdie tegniek vir **stealth** kan gebruik, maar die waarskynlikheid om dit te kan **misbruik om regte te verhoog is baie laer**.

Eerstens, is dit **meer algemeen** om te vind dat **MacOS binêre die volle pad** na die biblioteke om te laai aandui. En tweedens, **MacOS soek nooit** in die vouers van die **$PATH** vir biblioteke nie.

Die **hoof** deel van die **kode** wat met hierdie funksionaliteit verband hou, is in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Daar is **4 verskillende kopkommando's** wat 'n macho binêre kan gebruik om biblioteke te laai:

- **`LC_LOAD_DYLIB`** opdrag is die algemene opdrag om 'n dylib te laai.
- **`LC_LOAD_WEAK_DYLIB`** opdrag werk soos die vorige een, maar as die dylib nie gevind word nie, gaan die uitvoering voort sonder enige fout.
- **`LC_REEXPORT_DYLIB`** opdrag proxy (of her-exporteer) die simbole van 'n ander biblioteek.
- **`LC_LOAD_UPWARD_DYLIB`** opdrag word gebruik wanneer twee biblioteke op mekaar afhanklik is (dit word 'n _opwaartse afhanklikheid_ genoem).

Echter, daar is **2 tipes dylib hijacking**:

- **Ontbrekende swak gekoppelde biblioteke**: Dit beteken dat die toepassing sal probeer om 'n biblioteek te laai wat nie bestaan nie, geconfigureer met **LC_LOAD_WEAK_DYLIB**. Dan, **as 'n aanvaller 'n dylib plaas waar dit verwag word, sal dit gelaai word**.
- Die feit dat die skakel "swak" is, beteken dat die toepassing sal voortgaan om te loop selfs al word die biblioteek nie gevind nie.
- Die **kode wat hiermee verband hou** is in die funksie `ImageLoaderMachO::doGetDependentLibraries` van `ImageLoaderMachO.cpp` waar `lib->required` slegs `false` is wanneer `LC_LOAD_WEAK_DYLIB` waar is.
- **Vind swak gekoppelde biblioteke** in binêre met (jy het later 'n voorbeeld van hoe om hijacking biblioteke te skep):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Geconfigureer met @rpath**: Mach-O binêre kan die opdragte **`LC_RPATH`** en **`LC_LOAD_DYLIB`** hê. Gebaseer op die **waardes** van daardie opdragte, sal **biblioteke** van **verskillende gidse** gelaai word.
- **`LC_RPATH`** bevat die pades van sommige vouers wat gebruik word om biblioteke deur die binêre te laai.
- **`LC_LOAD_DYLIB`** bevat die pad na spesifieke biblioteke om te laai. Hierdie pades kan **`@rpath`** bevat, wat vervang sal word deur die waardes in **`LC_RPATH`**. As daar verskeie pades in **`LC_RPATH`** is, sal almal gebruik word om die biblioteek te laai. Voorbeeld:
- As **`LC_LOAD_DYLIB`** `@rpath/library.dylib` bevat en **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` en `/application/app.app/Contents/Framework/v2/` bevat. Beide vouers gaan gebruik word om `library.dylib` te laai. As die biblioteek nie in `[...]/v1/` bestaan nie en 'n aanvaller dit daar kan plaas om die laai van die biblioteek in `[...]/v2/` te hijack, soos die volgorde van pades in **`LC_LOAD_DYLIB`** gevolg word.
- **Vind rpath pades en biblioteke** in binêre met: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Is die **pad** na die gids wat die **hoofd uitvoerbare lêer** bevat.
>
> **`@loader_path`**: Is die **pad** na die **gids** wat die **Mach-O binêre** bevat wat die laai opdrag bevat.
>
> - Wanneer dit in 'n uitvoerbare gebruik word, is **`@loader_path`** effektief die **dieselfde** as **`@executable_path`**.
> - Wanneer dit in 'n **dylib** gebruik word, gee **`@loader_path`** die **pad** na die **dylib**.

Die manier om **regte te verhoog** deur hierdie funksionaliteit te misbruik, sou in die seldsame geval wees dat 'n **toepassing** wat **deur** **root** uitgevoer word, **soek** na 'n **biblioteek in 'n gids waar die aanvaller skryfrechten het.**

> [!TIP]
> 'n Goeie **scanner** om **ontbrekende biblioteke** in toepassings te vind, is [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) of 'n [**CLI weergawe**](https://github.com/pandazheng/DylibHijack).\
> 'n Goeie **verslag met tegniese besonderhede** oor hierdie tegniek kan gevind word [**hier**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Voorbeeld**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Onthou dat **vorige Biblioteek Validasie beperkings ook van toepassing is** om Dlopen hijacking aanvalle uit te voer.

Van **`man dlopen`**:

- Wanneer die pad **nie 'n skuinsstreep bevat nie** (d.w.s. dit is net 'n blaarnaam), **sal dlopen() soek**. As **`$DYLD_LIBRARY_PATH`** by die lansering gestel is, sal dyld eers **in daardie gids** kyk. Volgende, as die aanroepende mach-o lêer of die hoofd uitvoerbare 'n **`LC_RPATH`** spesifiseer, sal dyld dan **in daardie** gidse kyk. Laastens, as die proses **onbeperk** is, sal dyld in die **huidige werk gids** soek. Laastens, vir ouer binêre, sal dyld 'n paar terugval probeer. As **`$DYLD_FALLBACK_LIBRARY_PATH`** by die lansering gestel is, sal dyld in **daardie gidse** soek, anders sal dyld in **`/usr/local/lib/`** kyk (as die proses onbeperk is), en dan in **`/usr/lib/`** (hierdie inligting is geneem van **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(as onbeperk)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (as onbeperk)
6. `/usr/lib/`

> [!CAUTION]
> As daar geen skuinsstrepe in die naam is nie, sal daar 2 maniere wees om 'n hijacking te doen:
>
> - As enige **`LC_RPATH`** **skryfbaar** is (maar die handtekening word gekontroleer, so hiervoor moet die binêre ook onbeperk wees)
> - As die binêre **onbeperk** is en dan is dit moontlik om iets van die CWD te laai (of een van die genoemde omgewing veranderlikes te misbruik)

- Wanneer die pad **soos 'n raamwerk** pad lyk (bv. `/stuff/foo.framework/foo`), as **`$DYLD_FRAMEWORK_PATH`** by die lansering gestel is, sal dyld eers in daardie gids kyk vir die **raamwerk gedeeltelike pad** (bv. `foo.framework/foo`). Volgende, sal dyld die **verskafde pad soos dit is** probeer (met die huidige werk gids vir relatiewe pades). Laastens, vir ouer binêre, sal dyld 'n paar terugval probeer. As **`$DYLD_FALLBACK_FRAMEWORK_PATH`** by die lansering gestel is, sal dyld in daardie gidse soek. Andersins, sal dit in **`/Library/Frameworks`** soek (op macOS as die proses onbeperk is), dan **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. verskafde pad (met die huidige werk gids vir relatiewe pades as onbeperk)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (as onbeperk)
5. `/System/Library/Frameworks`

> [!CAUTION]
> As 'n raamwerk pad, sal die manier om dit te hijack:
>
> - As die proses **onbeperk** is, deur die **relatiewe pad van CWD** die genoemde omgewing veranderlikes te misbruik (selfs al word dit nie in die dokumentasie gesê nie, as die proses beperk is, word DYLD\_\* omgewing veranderlikes verwyder)

- Wanneer die pad **'n skuinsstreep bevat maar nie 'n raamwerk pad is nie** (d.w.s. 'n volle pad of 'n gedeeltelike pad na 'n dylib), kyk dlopen() eers (as gestel) in **`$DYLD_LIBRARY_PATH`** (met die blaardeel van die pad). Volgende, probeer dyld **die verskafde pad** (met die huidige werk gids vir relatiewe pades (maar slegs vir onbeperkte prosesse)). Laastens, vir ouer binêre, sal dyld terugval probeer. As **`$DYLD_FALLBACK_LIBRARY_PATH`** by die lansering gestel is, sal dyld in daardie gidse soek, anders sal dyld in **`/usr/local/lib/`** kyk (as die proses onbeperk is), en dan in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. verskafde pad (met die huidige werk gids vir relatiewe pades as onbeperk)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (as onbeperk)
5. `/usr/lib/`

> [!CAUTION]
> As daar skuinsstrepe in die naam is en dit nie 'n raamwerk is nie, sal die manier om dit te hijack:
>
> - As die binêre **onbeperk** is en dan is dit moontlik om iets van die CWD of `/usr/local/lib` te laai (of een van die genoemde omgewing veranderlikes te misbruik)

> [!NOTE]
> Nota: Daar is **geen** konfigurasie lêers om **dlopen soek** te **beheer** nie.
>
> Nota: As die hoofd uitvoerbare 'n **set\[ug]id binêre of codesigned met regte** is, dan **word alle omgewing veranderlikes geïgnoreer**, en slegs 'n volle pad kan gebruik word ([kontroleer DYLD_INSERT_LIBRARIES beperkings](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) vir meer gedetailleerde inligting)
>
> Nota: Apple platforms gebruik "universele" lêers om 32-bis en 64-bis biblioteke te kombineer. Dit beteken daar is **geen aparte 32-bis en 64-bis soekpades** nie.
>
> Nota: Op Apple platforms is die meeste OS dylibs **gecombineer in die dyld kas** en bestaan nie op skyf nie. Daarom sal die oproep **`stat()`** om vooraf te kontroleer of 'n OS dylib bestaan **nie werk nie**. Maar, **`dlopen_preflight()`** gebruik dieselfde stappe as **`dlopen()`** om 'n geskikte mach-o lêer te vind.

**Kontroleer pades**

Kom ons kyk na al die opsies met die volgende kode:
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
As jy dit saamstel en uitvoer, kan jy **waar elke biblioteek onsuksesvol gesoek is** sien. Jy kan ook **die FS-logs filter**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relatiewe Pad Hijacking

As 'n **privileged binary/app** (soos 'n SUID of 'n binêre met kragtige regte) 'n **relatiewe pad** biblioteek laai (byvoorbeeld deur `@executable_path` of `@loader_path` te gebruik) en **Biblioteekvalidasie gedeaktiveer** is, kan dit moontlik wees om die binêre na 'n plek te skuif waar die aanvaller die **relatiewe pad gelaaide biblioteek** kan **wysig**, en dit te misbruik om kode in die proses in te spuit.

## Snoei `DYLD_*` en `LD_LIBRARY_PATH` omgewingsveranderlikes

In die lêer `dyld-dyld-832.7.1/src/dyld2.cpp` is dit moontlik om die funksie **`pruneEnvironmentVariables`** te vind, wat enige omgewingsveranderlike wat **begin met `DYLD_`** en **`LD_LIBRARY_PATH=`** sal verwyder.

Dit sal ook spesifiek die omgewingsveranderlikes **`DYLD_FALLBACK_FRAMEWORK_PATH`** en **`DYLD_FALLBACK_LIBRARY_PATH`** vir **suid** en **sgid** binêre op **null** stel.

Hierdie funksie word vanaf die **`_main`** funksie van dieselfde lêer aangeroep as daar op OSX geteiken word soos volg:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
en daardie boolean vlae word in dieselfde lêer in die kode gestel:
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
Wat basies beteken dat as die binêre **suid** of **sgid** is, of 'n **RESTRICT** segment in die koppe het of dit met die **CS_RESTRICT** vlag gesertifiseer is, dan is **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** waar en die omgewing veranderlikes word verwyder.

Let daarop dat as CS_REQUIRE_LV waar is, dan sal die veranderlikes nie verwyder word nie, maar die biblioteekvalidasie sal nagaan of hulle dieselfde sertifikaat as die oorspronklike binêre gebruik.

## Kontroleer Beperkings

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
### Hardened runtime

Skep 'n nuwe sertifikaat in die Sleutelketting en gebruik dit om die binêre te teken:
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
> Let daarop dat selfs al is daar binaries wat met vlae **`0x0(none)`** onderteken is, kan hulle die **`CS_RESTRICT`** vlag dinamies kry wanneer dit uitgevoer word en daarom sal hierdie tegniek nie in hulle werk nie.
>
> Jy kan nagaan of 'n proses hierdie vlag het met (kry [**csops hier**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> en dan nagaan of die vlag 0x800 geaktiveer is.

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
