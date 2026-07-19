# Library Injection ya macOS

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Code ya **dyld ni open source** na inaweza kupatikana kwenye [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) na inaweza kupakuliwa kama tar kupitia **URL kama** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Mchakato wa Dyld**

Angalia jinsi Dyld inavyopakia libraries ndani ya binaries kwenye:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Hii ni kama [**LD_PRELOAD kwenye Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Inaruhusu kubainisha process itakayoendeshwa ili ipakie library maalum kutoka kwenye path (ikiwa env var imewezeshwa).

Technique hii pia inaweza **kutumika kama technique ya ASEP**, kwa kuwa kila application iliyosakinishwa ina plist inayoitwa "Info.plist", inayoruhusu **kuweka environmental variables** kwa kutumia key inayoitwa `LSEnvironmental`.

> [!TIP]
> Tangu 2012, **Apple imepunguza kwa kiasi kikubwa uwezo** wa **`DYLD_INSERT_LIBRARIES`**.
>
> Nenda kwenye code na **uangalie `src/dyld.cpp`**. Katika function **`pruneEnvironmentVariables`** unaweza kuona kwamba variables za **`DYLD_*`** zinaondolewa.
>
> Katika function **`processRestricted`**, sababu ya restriction inawekwa. Ukikagua code hiyo, unaweza kuona kwamba sababu hizo ni:
>
> - Binary ni `setuid/setgid`
> - Uwepo wa section ya `__RESTRICT/__restrict` kwenye macho binary.
> - Software ina entitlements (hardened runtime) bila entitlement ya [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>  - Kagua **entitlements** za binary kwa: `codesign -dv --entitlements :- </path/to/bin>`
>
> Katika versions zilizosasishwa zaidi, unaweza kupata logic hii katika sehemu ya pili ya function **`configureProcessRestrictions`.** Hata hivyo, kinachotekelezwa katika versions mpya ni **ukaguzi wa mwanzo wa function** (unaweza kuondoa ifs zinazohusiana na iOS au simulation kwa kuwa hazitatumika kwenye macOS).

### Library Validation

Hata kama binary inaruhusu kutumia env variable ya **`DYLD_INSERT_LIBRARIES`**, ikiwa binary inakagua signature ya library itakayopekia, haitapakia custom library.

Ili kupakia custom library, binary inahitaji kuwa na **moja ya entitlements** zifuatazo:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

au binary **haipaswi** kuwa na **hardened runtime flag** au **library validation flag**.

Unaweza kukagua ikiwa binary ina **hardened runtime** kwa `codesign --display --verbose <bin>` na kuangalia runtime flag katika **`CodeDirectory`**, kama vile: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Unaweza pia kupakia library ikiwa **imesainiwa kwa certificate ileile kama binary**.

Pata mfano wa jinsi ya kutumia hii (ab) na kukagua restrictions kwenye:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Kumbuka kwamba **restrictions za awali za Library Validation pia zinatumika** kutekeleza mashambulizi ya Dylib hijacking.

Kama ilivyo kwenye Windows, kwenye MacOS unaweza pia **kuhijack dylibs** ili kufanya **applications** **itekeleze** **code** yoyote (kwa kweli, hii huenda isiwezekane kwa regular user kwa sababu unaweza kuhitaji TCC permission ya kuandika ndani ya `.app` bundle na kuhijack library).\
Hata hivyo, jinsi applications za **MacOS** **zinavyopakia** libraries ina restrictions zaidi kuliko Windows. Hii ina maana kwamba developers wa **malware** bado wanaweza kutumia technique hii kwa **stealth**, lakini uwezekano wa **kutumia vibaya hii kwa privilege escalation ni mdogo zaidi**.

Kwanza, ni **kawaida zaidi** kukuta kwamba **MacOS binaries zinaonyesha full path** ya libraries za kupakia. Pili, **MacOS haitafuti kamwe** libraries katika folders za **$PATH**.

Sehemu **kuu** ya **code** inayohusiana na functionality hii iko katika **`ImageLoader::recursiveLoadLibraries`** kwenye `ImageLoader.cpp`.

Kuna **header Commands 4 tofauti** ambazo macho binary inaweza kutumia kupakia libraries:

- **`LC_LOAD_DYLIB`** command ndiyo command ya kawaida ya kupakia dylib.
- **`LC_LOAD_WEAK_DYLIB`** command hufanya kazi kama iliyotangulia, lakini ikiwa dylib haipatikani, execution inaendelea bila error yoyote.
- **`LC_REEXPORT_DYLIB`** command hu-proxy (au hu-re-export) symbols kutoka library tofauti.
- **`LC_LOAD_UPWARD_DYLIB`** command hutumika wakati libraries mbili zinategemeana (hii huitwa _upward dependency_).

Hata hivyo, kuna **aina 2 za dylib hijacking**:

- **Missing weak linked libraries**: Hii inamaanisha kwamba application itajaribu kupakia library ambayo haipo, iliyosanidiwa kwa **LC_LOAD_WEAK_DYLIB**. Kisha, **ikiwa attacker ataweka dylib mahali inapotarajiwa, itapakiwa**.
- Maana ya link kuwa "weak" ni kwamba application itaendelea kufanya kazi hata kama library haipatikani.
- **Code inayohusiana** na hii iko katika function `ImageLoaderMachO::doGetDependentLibraries` ya `ImageLoaderMachO.cpp`, ambapo `lib->required` huwa `false` pekee wakati `LC_LOAD_WEAK_DYLIB` ni true.
- **Tafuta weak linked libraries** kwenye binaries kwa (baadaye una mfano wa jinsi ya kuunda hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O binaries zinaweza kuwa na commands **`LC_RPATH`** na **`LC_LOAD_DYLIB`**. Kulingana na **values** za commands hizo, **libraries** zitapakiwa kutoka **directories tofauti**.
- **`LC_RPATH`** ina paths za baadhi ya folders zinazotumiwa na binary kupakia libraries.
- **`LC_LOAD_DYLIB`** ina path ya libraries maalum za kupakia. Paths hizi zinaweza kuwa na **`@rpath`**, ambayo **itabadilishwa** na values zilizomo kwenye **`LC_RPATH`**. Ikiwa kuna paths kadhaa katika **`LC_RPATH`**, zote zitatumika kutafuta library ya kupakia. Mfano:
- Ikiwa **`LC_LOAD_DYLIB`** ina `@rpath/library.dylib` na **`LC_RPATH`** ina `/application/app.app/Contents/Framework/v1/` na `/application/app.app/Contents/Framework/v2/`. Folders zote mbili zitatumika kupakia `library.dylib`**.** Ikiwa library haipo katika `[...]/v1/` na attacker anaweza kuiweka hapo, anaweza kuhijack upakiaji wa library katika `[...]/v2/`, kwa kuwa mpangilio wa paths katika **`LC_LOAD_DYLIB`** unafuatwa.
- **Tafuta rpath paths na libraries** kwenye binaries kwa: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Ni **path** ya directory iliyo na **main executable file**.
>
> **`@loader_path`**: Ni **path** ya **directory** iliyo na **Mach-O binary** inayobeba load command.
>
> - Inapotumika kwenye executable, **`@loader_path`** kwa ufanisi ni **sawa** na **`@executable_path`**.
> - Inapotumika kwenye **dylib**, **`@loader_path`** hutoa **path** ya **dylib**.

Njia ya **ku-escalate privileges** kwa kutumia vibaya functionality hii ingekuwa katika hali adimu ambapo **application** inayoendeshwa **na** **root** **inatafuta** **library katika folder ambayo attacker ana write permissions.**

> [!TIP]
> **Scanner** nzuri ya kutafuta **missing libraries** katika applications ni [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) au [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Ripoti nzuri yenye **technical details** kuhusu technique hii inaweza kupatikana [**hapa**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Mfano**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Kumbuka kwamba **restrictions za awali za Library Validation pia zinatumika** kutekeleza mashambulizi ya Dlopen hijacking.

Kutoka **`man dlopen`**:

- Wakati path **haina slash character** (yaani ni leaf name pekee), **dlopen() itafanya searching**. Ikiwa **`$DYLD_LIBRARY_PATH`** iliwekwa wakati wa launch, dyld itatafuta kwanza **katika directory hiyo**. Kisha, ikiwa calling mach-o file au main executable imebainisha **`LC_RPATH`**, dyld **itataka katika** directories hizo. Kisha, ikiwa process **haijawekewa restrictions**, dyld itatafuta katika current working directory. Mwisho, kwa binaries za zamani, dyld itajaribu fallbacks. Ikiwa **`$DYLD_FALLBACK_LIBRARY_PATH`** iliwekwa wakati wa launch, dyld itatafuta katika **directories hizo**, vinginevyo, dyld itatafuta katika **`/usr/local/lib/`** (ikiwa process haijawekewa restrictions), na kisha katika **`/usr/lib/`** (taarifa hii ilichukuliwa kutoka **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Ikiwa hakuna slashes katika jina, kuna njia 2 za kufanya hijacking:
>
> - Ikiwa **`LC_RPATH`** yoyote inaweza kuandikwa (lakini signature hukaguliwa, kwa hiyo kwa hili unahitaji pia binary isiwe na restrictions)
> - Ikiwa binary **haina restrictions**, basi inawezekana kupakia kitu kutoka CWD (au kutumia vibaya mojawapo ya env variables zilizotajwa)

- Wakati path **inaonekana kama** path ya framework (kwa mfano `/stuff/foo.framework/foo`), ikiwa **`$DYLD_FRAMEWORK_PATH`** iliwekwa wakati wa launch, dyld itatafuta kwanza katika directory hiyo **framework partial path** (kwa mfano `foo.framework/foo`). Kisha, dyld itajaribu path **iliyotolewa kama ilivyo** (ikitumia current working directory kwa relative paths). Mwisho, kwa binaries za zamani, dyld itajaribu fallbacks. Ikiwa **`$DYLD_FALLBACK_FRAMEWORK_PATH`** iliwekwa wakati wa launch, dyld itatafuta katika directories hizo. Vinginevyo, itatafuta katika **`/Library/Frameworks`** (kwenye macOS ikiwa process haijawekewa restrictions), kisha **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Ikiwa ni framework path, njia ya ku-hijack ni:
>
> - Ikiwa process **haina restrictions**, kutumia vibaya **relative path kutoka CWD** na env variables zilizotajwa (hata kama haijasemwa kwenye docs, ikiwa process ina restrictions, env vars za DYLD\_\* huondolewa)

- Wakati path **ina slash lakini si framework path** (yaani full path au partial path ya dylib), dlopen() kwanza hutafuta (ikiwa imewekwa) katika **`$DYLD_LIBRARY_PATH`** (ikiwa na leaf part kutoka path). Kisha, dyld **hujaribu path iliyotolewa** (ikitumia current working directory kwa relative paths (lakini kwa processes zisizo na restrictions pekee)). Mwisho, kwa binaries za zamani, dyld itajaribu fallbacks. Ikiwa **`$DYLD_FALLBACK_LIBRARY_PATH`** iliwekwa wakati wa launch, dyld itatafuta katika directories hizo, vinginevyo, dyld itatafuta katika **`/usr/local/lib/`** (ikiwa process haina restrictions), na kisha katika **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Ikiwa kuna slashes katika jina na si framework, njia ya ku-hijack ni:
>
> - Ikiwa binary **haina restrictions**, basi inawezekana kupakia kitu kutoka CWD au `/usr/local/lib` (au kutumia vibaya mojawapo ya env variables zilizotajwa)

> [!TIP]
> Kumbuka: Hakuna configuration files za **kudhibiti dlopen searching**.
>
> Kumbuka: Ikiwa main executable ni **set\[ug]id binary** au imesainiwa kwa entitlements, basi **environment variables zote hupuuziwa**, na full path pekee ndiyo inaweza kutumika ([angalia DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) kwa maelezo zaidi).
>
> Kumbuka: Apple platforms hutumia files za "universal" kuunganisha libraries za 32-bit na 64-bit. Hii inamaanisha kwamba hakuna **separate 32-bit and 64-bit search paths**.
>
> Kumbuka: Kwenye Apple platforms, dylibs nyingi za OS **huunganishwa katika dyld cache** na hazipo kwenye disk. Kwa hiyo, kuita **`stat()`** ili kukagua awali kama OS dylib ipo **hakutafanya kazi**. Hata hivyo, **`dlopen_preflight()`** hutumia steps zilezile kama **`dlopen()`** kutafuta compatible mach-o file.

**Kagua paths**

Hebu tukague options zote kwa kutumia code ifuatayo:
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
Uki-compile na ku-execute, unaweza kuona **mahali ambapo kila library ilitafutwa bila mafanikio**. Pia, unaweza **kufilter FS logs**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Ikiwa **privileged binary/app** (kama SUID au binary yenye entitlements zenye nguvu) **inapakia** library ya **relative path** (kwa mfano ikitumia `@executable_path` au `@loader_path`) na **Library Validation disabled**, huenda ikawezekana kuhamisha binary hiyo hadi eneo ambalo attacker anaweza **kurekebisha relative path library inayopakiwa**, na kuitumia vibaya kuingiza code kwenye process.

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

Katika file `dyld-dyld-832.7.1/src/dyld2.cpp` inawezekana kupata function **`pruneEnvironmentVariables`**, ambayo itaondoa env variable yoyote inayo **anza na `DYLD_`** na **`LD_LIBRARY_PATH=`**.

Pia itaweka kuwa **null** env variables **`DYLD_FALLBACK_FRAMEWORK_PATH`** na **`DYLD_FALLBACK_LIBRARY_PATH`** haswa kwa binary za **suid** na **sgid**.

Function hii inaitwa kutoka kwenye function ya **`_main`** ya file hiyo hiyo ikiwa inalenga OSX kama ifuatavyo:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
na hizo boolean flags huwekwa katika faili hilo hilo kwenye code:
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
Ambayo kimsingi inamaanisha kwamba ikiwa binary ni **suid** au **sgid**, au ina segment ya **RESTRICT** kwenye headers, au ilisainiwa kwa flag ya **CS_RESTRICT**, basi **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** ni true na env variables huondolewa.

Kumbuka kwamba ikiwa CS_REQUIRE_LV ni true, basi variables hazitaondolewa, lakini library validation itathibitisha kwamba zinatumia certificate ileile kama binary ya awali.

## Kagua Restrictions

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
### Sehemu `__RESTRICT` yenye segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Unda cheti kipya katika Keychain na uitumie kusaini binary:
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
> Kumbuka kwamba hata kama kuna binaries zilizosainiwa kwa flags **`0x0(none)`**, zinaweza kupata flag ya **`CS_RESTRICT`** dynamically zinapo-executed na kwa hivyo technique hii haitafanya kazi ndani yake.
>
> Unaweza kuangalia ikiwa proc ina flag hii kwa kutumia (pata [**csops hapa**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> kisha uangalie ikiwa flag 0x800 imewezeshwa.

## Marejeleo

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
