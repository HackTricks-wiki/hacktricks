# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Msimbo wa **dyld ni wa chanzo wazi** na unaweza kupatikana katika [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) na unaweza kupakuliwa kama tar kwa kutumia **URL kama** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Angalia jinsi Dyld inavyopakia maktaba ndani ya binaries katika:

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Hii ni kama [**LD_PRELOAD kwenye Linux**](../../../../linux-hardening/privilege-escalation/#ld_preload). Inaruhusu kuashiria mchakato utakaotekelezwa kupakia maktaba maalum kutoka kwa njia (ikiwa variable ya env imewezeshwa)

Teknolojia hii inaweza pia **kutumika kama mbinu ya ASEP** kwani kila programu iliyosakinishwa ina plist inayoitwa "Info.plist" ambayo inaruhusu **kuweka variables za mazingira** kwa kutumia ufunguo unaoitwa `LSEnvironmental`.

> [!NOTE]
> Tangu 2012 **Apple imepunguza kwa kiasi kikubwa nguvu** ya **`DYLD_INSERT_LIBRARIES`**.
>
> Nenda kwenye msimbo na **angalia `src/dyld.cpp`**. Katika kazi **`pruneEnvironmentVariables`** unaweza kuona kuwa **`DYLD_*`** variables zimeondolewa.
>
> Katika kazi **`processRestricted`** sababu ya kizuizi imewekwa. Ukikagua msimbo huo unaweza kuona kuwa sababu ni:
>
> - Binary ni `setuid/setgid`
> - Uwepo wa sehemu `__RESTRICT/__restrict` katika binary ya macho.
> - Programu ina haki (runtime iliyohardishwa) bila [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) haki
>   - Angalia **haki** za binary na: `codesign -dv --entitlements :- </path/to/bin>`
>
> Katika toleo za kisasa zaidi unaweza kupata mantiki hii katika sehemu ya pili ya kazi **`configureProcessRestrictions`.** Hata hivyo, kile kinachotekelezwa katika toleo jipya ni **ukaguzi wa mwanzo wa kazi** (unaweza kuondoa ifs zinazohusiana na iOS au simulation kwani hizo hazitatumika katika macOS.

### Library Validation

Hata kama binary inaruhusu kutumia variable ya mazingira **`DYLD_INSERT_LIBRARIES`**, ikiwa binary inakagua saini ya maktaba ili kuipakia haitapakia maktaba ya kawaida.

Ili kupakia maktaba ya kawaida, binary inahitaji kuwa na **moja ya haki zifuatazo**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

au binary **haipaswi** kuwa na **bendera ya runtime iliyohardishwa** au **bendera ya uthibitishaji wa maktaba**.

Unaweza kuangalia ikiwa binary ina **runtime iliyohardishwa** kwa kutumia `codesign --display --verbose <bin>` ukikagua bendera ya runtime katika **`CodeDirectory`** kama: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Unaweza pia kupakia maktaba ikiwa ime **sainiwa kwa cheti sawa na binary**.

Pata mfano wa jinsi ya (ku) kutumia hii na kuangalia vizuizi katika:

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Kumbuka kwamba **vizuizi vya awali vya Uthibitishaji wa Maktaba pia vinatumika** kufanya mashambulizi ya Dylib hijacking.

Kama ilivyo katika Windows, katika MacOS unaweza pia **kuchukua dylibs** ili kufanya **programu** **kutekeleza** **msimbo** **wowote** (vizuri, kwa kweli kutoka kwa mtumiaji wa kawaida hii inaweza isiwezekane kwani unaweza kuhitaji ruhusa ya TCC kuandika ndani ya kifurushi cha `.app` na kuchukua maktaba).\
Hata hivyo, njia ambayo **programu za MacOS** **zinapakia** maktaba ni **zaidi ya kizuizi** kuliko katika Windows. Hii ina maana kwamba **waendelezaji wa malware** bado wanaweza kutumia mbinu hii kwa **kujificha**, lakini uwezekano wa kuweza **kuabudu hii ili kupandisha mamlaka ni mdogo sana**.

Kwanza kabisa, ni **ya kawaida zaidi** kupata kwamba **binaries za MacOS zinaonyesha njia kamili** za maktaba za kupakia. Na pili, **MacOS kamwe haitafuta** katika folda za **$PATH** kwa ajili ya maktaba.

Sehemu **kuu** ya **msimbo** unaohusiana na kazi hii iko katika **`ImageLoader::recursiveLoadLibraries`** katika `ImageLoader.cpp`.

Kuna **amri 4 tofauti za kichwa** ambazo binary ya macho inaweza kutumia kupakia maktaba:

- Amri ya **`LC_LOAD_DYLIB`** ni amri ya kawaida ya kupakia dylib.
- Amri ya **`LC_LOAD_WEAK_DYLIB`** inafanya kazi kama ile ya awali, lakini ikiwa dylib haipatikani, utekelezaji unaendelea bila kosa lolote.
- Amri ya **`LC_REEXPORT_DYLIB`** inafanya proxy (au inarejesha) alama kutoka maktaba tofauti.
- Amri ya **`LC_LOAD_UPWARD_DYLIB`** inatumika wakati maktaba mbili zinategemeana (hii inaitwa _upward dependency_).

Hata hivyo, kuna **aina 2 za dylib hijacking**:

- **Maktaba za dhaifu zilizokosekana**: Hii ina maana kwamba programu itajaribu kupakia maktaba ambayo haipo iliyowekwa na **LC_LOAD_WEAK_DYLIB**. Kisha, **ikiwa mshambuliaji anaweka dylib mahali inatarajiwa itapakiwa**.
- Ukweli kwamba kiungo ni "dhaifu" ina maana kwamba programu itaendelea kufanya kazi hata kama maktaba haipatikani.
- **Msimbo unaohusiana** na hii uko katika kazi `ImageLoaderMachO::doGetDependentLibraries` ya `ImageLoaderMachO.cpp` ambapo `lib->required` ni tu `false` wakati `LC_LOAD_WEAK_DYLIB` ni kweli.
- **Pata maktaba dhaifu zilizokosekana** katika binaries na (una mfano baadaye wa jinsi ya kuunda maktaba za kuchukua):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Iliyowekwa na @rpath**: Binaries za Mach-O zinaweza kuwa na amri **`LC_RPATH`** na **`LC_LOAD_DYLIB`**. Kulingana na **maadili** ya amri hizo, **maktaba** zitapakiwa kutoka **folda tofauti**.
- **`LC_RPATH`** ina njia za baadhi ya folda zinazotumika kupakia maktaba na binary.
- **`LC_LOAD_DYLIB`** ina njia za maktaba maalum za kupakia. Njia hizi zinaweza kuwa na **`@rpath`**, ambayo itabadilishwa na maadili katika **`LC_RPATH`**. Ikiwa kuna njia kadhaa katika **`LC_RPATH`** kila mmoja atatumika kutafuta maktaba ya kupakia. Mfano:
- Ikiwa **`LC_LOAD_DYLIB`** ina `@rpath/library.dylib` na **`LC_RPATH`** ina `/application/app.app/Contents/Framework/v1/` na `/application/app.app/Contents/Framework/v2/`. Folda zote mbili zitatumika kupakia `library.dylib`**.** Ikiwa maktaba haipo katika `[...]/v1/` na mshambuliaji anaweza kuiweka hapo ili kuchukua upakiaji wa maktaba katika `[...]/v2/` kwani mpangilio wa njia katika **`LC_LOAD_DYLIB`** unafuata.
- **Pata njia za rpath na maktaba** katika binaries na: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Ni **njia** ya folda inayoshikilia **faili kuu ya kutekeleza**.
>
> **`@loader_path`**: Ni **njia** ya **folda** inayoshikilia **binary ya Mach-O** ambayo ina amri ya upakiaji.
>
> - Inapotumika katika executable, **`@loader_path`** ni kwa ufanisi **sawa** na **`@executable_path`**.
> - Inapotumika katika **dylib**, **`@loader_path`** inatoa **njia** kwa **dylib**.

Njia ya **kupandisha mamlaka** kwa kutumia kazi hii itakuwa katika kesi nadra ambapo **programu** inayotekelezwa **na** **root** inatafuta **maktaba katika folda ambayo mshambuliaji ana ruhusa za kuandika.**

> [!TIP]
> Scanner mzuri wa kupata **maktaba zilizokosekana** katika programu ni [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) au [**toleo la CLI**](https://github.com/pandazheng/DylibHijack).\
> Ripoti nzuri yenye maelezo ya kiufundi kuhusu mbinu hii inaweza kupatikana [**hapa**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Mfano**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Kumbuka kwamba **vizuizi vya awali vya Uthibitishaji wa Maktaba pia vinatumika** kufanya mashambulizi ya Dlopen hijacking.

Kutoka **`man dlopen`**:

- Wakati njia **haijumuishi tabia ya slash** (yaani ni jina tu la majani), **dlopen() itafanya utafutaji**. Ikiwa **`$DYLD_LIBRARY_PATH`** ilipangwa wakati wa uzinduzi, dyld kwanza **itaangalia katika folda hiyo**. Kisha, ikiwa faili ya macho inayopiga simu au executable kuu inabainisha **`LC_RPATH`**, basi dyld itatafuta katika folda hizo. Kisha, ikiwa mchakato ni **usio na kizuizi**, dyld itatafuta katika **folda ya kazi ya sasa**. Mwishowe, kwa binaries za zamani, dyld itajaribu baadhi ya njia mbadala. Ikiwa **`$DYLD_FALLBACK_LIBRARY_PATH`** ilipangwa wakati wa uzinduzi, dyld itatafuta katika **folda hizo**, vinginevyo, dyld itatafuta katika **`/usr/local/lib/`** (ikiwa mchakato ni usio na kizuizi), na kisha katika **`/usr/lib/`** (habari hii ilichukuliwa kutoka **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(ikiwa haina kizuizi)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (ikiwa haina kizuizi)
6. `/usr/lib/`

> [!CAUTION]
> Ikiwa hakuna slashes katika jina, kutakuwa na njia 2 za kufanya hijacking:
>
> - Ikiwa **`LC_RPATH`** yoyote ni **ya kuandika** (lakini saini inakaguliwa, hivyo kwa hili unahitaji pia binary kuwa isiyo na kizuizi)
> - Ikiwa binary ni **isiyo na kizuizi** na kisha inawezekana kupakia kitu kutoka CWD (au kutumia moja ya variable za env zilizotajwa)

- Wakati njia **inaonekana kama njia ya framework** (kwa mfano, `/stuff/foo.framework/foo`), ikiwa **`$DYLD_FRAMEWORK_PATH`** ilipangwa wakati wa uzinduzi, dyld kwanza itaangalia katika folda hiyo kwa **njia ya sehemu ya framework** (kwa mfano, `foo.framework/foo`). Kisha, dyld itajaribu **njia iliyotolewa kama ilivyo** (ikitumika folda ya kazi ya sasa kwa njia za kulinganisha). Mwishowe, kwa binaries za zamani, dyld itajaribu baadhi ya njia mbadala. Ikiwa **`$DYLD_FALLBACK_FRAMEWORK_PATH`** ilipangwa wakati wa uzinduzi, dyld itatafuta katika folda hizo. Vinginevyo, itatafuta **`/Library/Frameworks`** (katika macOS ikiwa mchakato ni usio na kizuizi), kisha **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. njia iliyotolewa (ikitumika folda ya kazi ya sasa kwa njia za kulinganisha ikiwa haina kizuizi)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (ikiwa haina kizuizi)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Ikiwa ni njia ya framework, njia ya kuichukua itakuwa:
>
> - Ikiwa mchakato ni **usio na kizuizi**, kutumia **njia ya kulinganisha kutoka CWD** variable za env zilizotajwa (hata kama haijasemwa katika nyaraka ikiwa mchakato umewekwa kizuizi DYLD\_\* variable za env zimeondolewa)

- Wakati njia **ina slashes lakini si njia ya framework** (yaani, njia kamili au njia ya sehemu kwa dylib), dlopen() kwanza inatafuta (ikiwa imewekwa) katika **`$DYLD_LIBRARY_PATH`** (ikiwa na sehemu ya majani kutoka kwa njia). Kisha, dyld **inajaribu njia iliyotolewa** (ikitumika folda ya kazi ya sasa kwa njia za kulinganisha (lakini tu kwa michakato isiyo na kizuizi)). Mwishowe, kwa binaries za zamani, dyld itajaribu njia mbadala. Ikiwa **`$DYLD_FALLBACK_LIBRARY_PATH`** ilipangwa wakati wa uzinduzi, dyld itatafuta katika folda hizo, vinginevyo, dyld itatafuta katika **`/usr/local/lib/`** (ikiwa mchakato ni usio na kizuizi), na kisha katika **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. njia iliyotolewa (ikitumika folda ya kazi ya sasa kwa njia za kulinganisha ikiwa haina kizuizi)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (ikiwa haina kizuizi)
5. `/usr/lib/`

> [!CAUTION]
> Ikiwa kuna slashes katika jina na si framework, njia ya kuichukua itakuwa:
>
> - Ikiwa binary ni **isiyo na kizuizi** na kisha inawezekana kupakia kitu kutoka CWD au `/usr/local/lib` (au kutumia moja ya variable za env zilizotajwa)

> [!NOTE]
> Kumbuka: Hakuna **faili za usanidi** za **kudhibiti utafutaji wa dlopen**.
>
> Kumbuka: Ikiwa executable kuu ni **set\[ug]id binary au codesigned na haki**, basi **variable zote za mazingira zinapuuziliwa mbali**, na njia kamili pekee inaweza kutumika ([angalia vizuizi vya DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) kwa maelezo zaidi)
>
> Kumbuka: Mifumo ya Apple hutumia faili "za ulimwengu" kuunganisha maktaba za 32-bit na 64-bit. Hii ina maana hakuna **njia tofauti za utafutaji za 32-bit na 64-bit**.
>
> Kumbuka: Katika mifumo ya Apple, maktaba nyingi za OS **zimeunganishwa katika cache ya dyld** na hazipo kwenye diski. Kwa hivyo, kuita **`stat()`** ili kuangalia ikiwa maktaba ya OS ipo **haitafanya kazi**. Hata hivyo, **`dlopen_preflight()`** inatumia hatua sawa na **`dlopen()`** kutafuta faili ya mach-o inayofaa.

**Angalia njia**

Tukague chaguzi zote na msimbo ufuatao:
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
Ikiwa unakusanya na kutekeleza, unaweza kuona **mahali kila maktaba ilitafutwa bila mafanikio**. Pia, unaweza **kuchuja kumbukumbu za FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Ikiwa **binary/app yenye mamlaka** (kama SUID au binary fulani yenye haki kubwa) in **pakiwa maktaba ya njia ya uhusiano** (kwa mfano kutumia `@executable_path` au `@loader_path`) na ina **Library Validation imezimwa**, inaweza kuwa inawezekana kuhamasisha binary kwenye eneo ambapo mshambuliaji anaweza **kubadilisha maktaba ya njia ya uhusiano iliyopakiwa**, na kuitumia kuingiza msimbo kwenye mchakato.

## Prune `DYLD_*` na `LD_LIBRARY_PATH` env variables

Katika faili `dyld-dyld-832.7.1/src/dyld2.cpp` inawezekana kupata kazi **`pruneEnvironmentVariables`**, ambayo itafuta kila variable ya env ambayo **inaanza na `DYLD_`** na **`LD_LIBRARY_PATH=`**.

Pia itaweka **null** hasa variable za env **`DYLD_FALLBACK_FRAMEWORK_PATH`** na **`DYLD_FALLBACK_LIBRARY_PATH`** kwa **suid** na **sgid** binaries.

Kazi hii inaitwa kutoka kwa kazi **`_main`** ya faili hiyo hiyo ikiwa inalenga OSX kama hii:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
na bendera hizo boolean zimewekwa katika faili hiyo hiyo katika msimbo:
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
Ambayo kwa msingi inamaanisha kwamba ikiwa binary ni **suid** au **sgid**, au ina sehemu ya **RESTRICT** katika vichwa au ilisainiwa na bendera ya **CS_RESTRICT**, basi **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** ni kweli na mabadiliko ya mazingira yanakatwa.

Kumbuka kwamba ikiwa CS_REQUIRE_LV ni kweli, basi mabadiliko hayataondolewa lakini uthibitishaji wa maktaba utaangalia wanatumia cheti sawa na binary ya awali.

## Angalia Vikwazo

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
### Sehemu `__RESTRICT` na segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Unda mpya cheti katika Keychain na utumie kusaini binary:
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
> Kumbuka kwamba hata kama kuna binaries zilizotiwa saini na bendera **`0x0(none)`**, zinaweza kupata bendera **`CS_RESTRICT`** kwa njia ya kidinamikia zinapotekelezwa na kwa hivyo mbinu hii haitafanya kazi kwao.
>
> Unaweza kuangalia kama proc ina bendera hii kwa (pata [**csops hapa**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> na kisha angalia kama bendera 0x800 imewezeshwa.

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
