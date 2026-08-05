# Library Injection ya macOS

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Code ya **dyld ni open source** na inaweza kupatikana kwenye [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) na inaweza kupakuliwa kama tar kwa kutumia **URL kama** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Angalia jinsi Dyld inavyopakia libraries ndani ya binaries kwenye:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Hii ni kama [**LD_PRELOAD on Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Inaruhusu kuashiria process itakayoendeshwa ili ipakie library maalum kutoka kwenye path (ikiwa env var imewezeshwa).

Technique hii pia inaweza **kutumika kama ASEP technique**, kwa sababu kila application iliyosakinishwa ina plist inayoitwa "Info.plist", ambayo inaruhusu **kuweka environmental variables** kwa kutumia key inayoitwa `LSEnvironmental`.

> [!TIP]
> Tangu 2012, **Apple imepunguza kwa kiasi kikubwa uwezo** wa **`DYLD_INSERT_LIBRARIES`**. Process inachukuliwa kuwa **restricted** — na kisha `dyld` hufuta kila variable ya `DYLD_*` kutoka kwenye environment yake — wakati mojawapo ya masharti yafuatayo yanapotimia:
>
> - Binary ni `setuid/setgid`
> - Mach-O ina section ya **`__RESTRICT/__restrict`**
> - Binary imesainiwa kwa hardened runtime na AMFI haijapewa permissions za "path/print variables", yaani haina [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Kagua **entitlements** za binary kwa: `codesign -dv --entitlements :- </path/to/bin>`
>
> Katika `dyld` ya sasa, hili haliamuliwi tena na `dyld` pekee: `ProcessConfig::Security::Security()` huuliza **AMFI** kupitia `amfi_check_dyld_policy_self()` na kisha kuita `pruneEnvVars()`. Code kamili imeelezwa katika [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) hapa chini.

### Library Validation

Hata kama binary inaruhusu kutumia env variable ya **`DYLD_INSERT_LIBRARIES`**, ikiwa binary inakagua signature ya library itakayopakiwa, haitapakia custom library.

Ili kupakia custom library, binary inahitaji kuwa na **mojawapo ya entitlements** zifuatazo:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

au binary **haipaswi kuwa na** **hardened runtime flag** au **library validation flag**.

Unaweza kukagua ikiwa binary ina **hardened runtime** kwa `codesign --display --verbose <bin>` kwa kuangalia runtime flag ndani ya **`CodeDirectory`**, kama vile: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Pia unaweza kupakia library ikiwa **imesainiwa kwa certificate ileile na binary**.

Pata mfano wa jinsi ya kutumia hii vibaya na kukagua restrictions kwenye:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Kumbuka kuwa **Library Validation restrictions zilizotajwa hapo awali pia zinatumika** kufanya Dylib hijacking attacks.

Kama ilivyo kwenye Windows, kwenye MacOS unaweza pia **kuhijack dylibs** ili kufanya **applications** **zi-execute** **arbitrary** **code** (kwa kweli, kwa regular user hii huenda isiwezekane kwa sababu unaweza kuhitaji TCC permission ili kuandika ndani ya `.app` bundle na kuhijack library).\
Hata hivyo, jinsi **MacOS** applications **zinavyopakia** libraries ina restrictions zaidi kuliko Windows. Hii ina maana kwamba developers wa **malware** bado wanaweza kutumia technique hii kwa **stealth**, lakini uwezekano wa **kuitumia vibaya ili ku-escalate privileges ni mdogo zaidi**.

Kwanza, ni **kawaida zaidi** kukuta kwamba **MacOS binaries zinaonyesha full path** ya libraries za kupakia. Pili, **MacOS haitafuti kamwe** libraries kwenye folders za **$PATH**.

Sehemu **kuu** ya **code** inayohusiana na functionality hii iko kwenye **`ImageLoader::recursiveLoadLibraries`** ndani ya `ImageLoader.cpp`.

Kuna **Header Commands 4 tofauti** ambazo macho binary inaweza kutumia kupakia libraries:

- Command ya **`LC_LOAD_DYLIB`** ndiyo command ya kawaida ya kupakia dylib.
- Command ya **`LC_LOAD_WEAK_DYLIB`** hufanya kazi kama iliyotangulia, lakini ikiwa dylib haipatikani, execution inaendelea bila error yoyote.
- Command ya **`LC_REEXPORT_DYLIB`** hu-proxy (au ku-re-export) symbols kutoka kwenye library nyingine.
- Command ya **`LC_LOAD_UPWARD_DYLIB`** hutumika wakati libraries mbili zinategemeana (hii huitwa _upward dependency_).

Hata hivyo, kuna **aina 2 za dylib hijacking**:

- **Missing weak linked libraries**: Hii inamaanisha application itajaribu kupakia library ambayo haipo, ikiwa ime-configure-ishwa kwa **LC_LOAD_WEAK_DYLIB**. Kisha, **ikiwa attacker ataweka dylib mahali ilipotarajiwa, itapakiwa**.
- Ukweli kwamba link ni "weak" unamaanisha kwamba application itaendelea kufanya kazi hata kama library haipatikani.
- **Code inayohusiana** na hii iko kwenye function `ImageLoaderMachO::doGetDependentLibraries` ya `ImageLoaderMachO.cpp`, ambapo `lib->required` huwa `false` tu wakati `LC_LOAD_WEAK_DYLIB` ni true.
- **Tafuta weak linked libraries** kwenye binaries kwa (baadaye kuna mfano wa jinsi ya kuunda hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O binaries zinaweza kuwa na commands **`LC_RPATH`** na **`LC_LOAD_DYLIB`**. Kulingana na **values** za commands hizo, **libraries** zitapakiwa kutoka kwenye **directories tofauti**.
- **`LC_RPATH`** ina paths za baadhi ya folders zinazotumiwa na binary kupakia libraries.
- **`LC_LOAD_DYLIB`** ina path ya libraries maalum za kupakia. Paths hizi zinaweza kuwa na **`@rpath`**, ambayo **itabadilishwa** na values zilizo kwenye **`LC_RPATH`**. Ikiwa kuna paths kadhaa kwenye **`LC_RPATH`**, zote zitatumika kutafuta library ya kupakia. Mfano:
- Ikiwa **`LC_LOAD_DYLIB`** ina `@rpath/library.dylib` na **`LC_RPATH`** ina `/application/app.app/Contents/Framework/v1/` na `/application/app.app/Contents/Framework/v2/`. Folders zote mbili zitatumika kupakia `library.dylib`**.** Ikiwa library haipo kwenye `[...]/v1/` na attacker anaweza kuiweka hapo, anaweza kuhijack upakiaji wa library kwenye `[...]/v2/`, kwa sababu mpangilio wa paths kwenye **`LC_LOAD_DYLIB`** unafuatwa.
- **Tafuta rpath paths na libraries** kwenye binaries kwa: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Ni **path** ya directory iliyo na **main executable file**.
>
> **`@loader_path`**: Ni **path** ya **directory** iliyo na **Mach-O binary** inayokuwa na load command.
>
> - Inapotumika kwenye executable, **`@loader_path`** huwa kwa ufanisi **sawa na** **`@executable_path`**.
> - Inapotumika kwenye **dylib**, **`@loader_path`** hutoa **path** ya **dylib**.

Njia ya **ku-escalate privileges** kwa kutumia vibaya functionality hii ingekuwa katika hali adimu ambapo **application** inayoendeshwa **na** **root** **inatafuta** **library kwenye folder ambalo attacker ana write permissions**.

> [!TIP]
> **Scanner** nzuri ya kutafuta **missing libraries** kwenye applications ni [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) au [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> **Report nzuri yenye technical details** kuhusu technique hii inaweza kupatikana [**hapa**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Mfano**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Kumbuka kuwa **Library Validation restrictions zilizotajwa hapo awali pia zinatumika** kufanya Dlopen hijacking attacks.

Kutoka kwenye **`man dlopen`**:

- Wakati path **haina slash character** (yaani ni leaf name pekee), **dlopen() itafanya searching**. Ikiwa **`$DYLD_LIBRARY_PATH`** iliwekwa wakati wa launch, dyld itaanza **kutafuta kwenye directory hiyo**. Kisha, ikiwa calling mach-o file au main executable imeainisha **`LC_RPATH`**, dyld **itatfuta kwenye** directories hizo. Kisha, ikiwa process ni **unrestricted**, dyld itatafuta kwenye current working directory. Mwisho, kwa old binaries, dyld itajaribu fallbacks fulani. Ikiwa **`$DYLD_FALLBACK_LIBRARY_PATH`** iliwekwa wakati wa launch, dyld itatafuta kwenye **directories hizo**, vinginevyo, dyld itatafuta kwenye **`/usr/local/lib/`** (ikiwa process ni unrestricted), na kisha kwenye **`/usr/lib/`** (taarifa hii ilichukuliwa kutoka **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Ikiwa jina halina slashes, kuna njia 2 za kufanya hijacking:
>
> - Ikiwa **`LC_RPATH`** yoyote inaweza kuandikwa (lakini signature inakaguliwa, kwa hiyo kwa hili pia unahitaji binary iwe unrestricted)
> - Ikiwa binary ni **unrestricted**, hivyo inawezekana kupakia kitu kutoka CWD (au kutumia vibaya mojawapo ya env variables zilizotajwa)

- Wakati path **inaonekana kama** framework path (mfano, `/stuff/foo.framework/foo`), ikiwa **`$DYLD_FRAMEWORK_PATH`** iliwekwa wakati wa launch, dyld itaanza kutafuta kwenye directory hiyo kwa **framework partial path** (mfano, `foo.framework/foo`). Kisha, dyld itajaribu **supplied path kama ilivyo** (ikitumia current working directory kwa relative paths). Mwisho, kwa old binaries, dyld itajaribu fallbacks fulani. Ikiwa **`$DYLD_FALLBACK_FRAMEWORK_PATH`** iliwekwa wakati wa launch, dyld itatafuta kwenye directories hizo. Vinginevyo, itatafuta kwenye **`/Library/Frameworks`** (kwenye macOS ikiwa process ni unrestricted), kisha **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (ikitumia current working directory kwa relative paths ikiwa unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Ikiwa ni framework path, njia ya kuihijack itakuwa:
>
> - Ikiwa process ni **unrestricted**, kutumia vibaya **relative path kutoka CWD** na env variables zilizotajwa (hata kama docs hazisemi hivyo, ikiwa process ni restricted, DYLD\_\* env vars huondolewa)

- Wakati path **ina slash lakini si framework path** (yaani full path au partial path ya dylib), dlopen() huanza kutafuta kwenye (ikiwa imewekwa) **`$DYLD_LIBRARY_PATH`** (ikitumia leaf part kutoka kwenye path). Kisha, dyld **hujaribu supplied path** (ikitumia current working directory kwa relative paths (lakini kwa unrestricted processes pekee)). Mwisho, kwa older binaries, dyld itajaribu fallbacks. Ikiwa **`$DYLD_FALLBACK_LIBRARY_PATH`** iliwekwa wakati wa launch, dyld itatafuta kwenye directories hizo, vinginevyo, dyld itatafuta kwenye **`/usr/local/lib/`** (ikiwa process ni unrestricted), na kisha kwenye **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (ikitumia current working directory kwa relative paths ikiwa unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Ikiwa jina lina slashes na si framework, njia ya kuihijack itakuwa:
>
> - Ikiwa binary ni **unrestricted**, hivyo inawezekana kupakia kitu kutoka CWD au `/usr/local/lib` (au kutumia vibaya mojawapo ya env variables zilizotajwa)

> [!TIP]
> Kumbuka: Hakuna configuration files za **kudhibiti dlopen searching**.
>
> Kumbuka: Ikiwa main executable ni **set\[ug]id binary au codesigned yenye entitlements**, environment variables zote zinapuuzwa, na ni full path pekee inayoweza kutumika ([check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) kwa maelezo zaidi)
>
> Kumbuka: Apple platforms hutumia files za "universal" kuunganisha 32-bit na 64-bit libraries. Hii inamaanisha hakuna search paths tofauti za 32-bit na 64-bit.
>
> Kumbuka: Kwenye Apple platforms, OS dylibs nyingi **zimeunganishwa kwenye dyld cache** na hazipo kwenye disk. Kwa hiyo, kuita **`stat()`** ku-preflight ikiwa OS dylib ipo **hakutafanya kazi**. Hata hivyo, **`dlopen_preflight()`** hutumia steps zilezile kama **`dlopen()`** kutafuta compatible mach-o file.

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
Ukicompile na kui-execute unaweza kuona **mahali ambapo kila library ilitafutwa bila mafanikio**. Pia, unaweza **kuchuja FS logs**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Ikiwa **privileged binary/app** (kama SUID au binary yenye entitlements zenye nguvu) **inapakia** library ya relative path (kwa mfano ikitumia `@executable_path` au `@loader_path`) na **Library Validation imezimwa**, huenda ikawezekana kuhamisha binary hiyo hadi eneo ambalo attacker anaweza **kurekebisha library inayopakiwa kupitia relative path**, na kuitumia kuingiza code kwenye process.

## Prune `DYLD_*` env variables

Matoleo ya zamani ya `dyld` (`dyld2.cpp`) yaliamua hili ndani ya process kwa kutumia `issetugid()`, `hasRestrictedSegment()` na `csops(CS_OPS_STATUS)`. Katika **dyld ya sasa, uamuzi huu umekabidhiwa kwa AMFI**, na code hiyo inapatikana kwenye `ProcessConfig::Security::Security()` katika `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
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
Mambo mawili yanafaa kutolewa hapa:

- **Pruning** hutokea tu kwenye **macOS / Mac Catalyst / DriverKit** — na tu wakati AMFI haikutoa ruhusa yoyote kati ya `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- Hoja ya AMFI hupewa properties za executable yenyewe:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
ambapo `isRestricted()` ni ukaguzi halisi wa segment ya `__RESTRICT` (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` kisha huondoa **kila** kigezo ambacho jina lake huanza na `DYLD_` na kusogeza vigezo vya `apple[]` chini, hivyo child processes wa process yenye vizuizi pia hawazirithi:
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
> Matokeo ya kiutendaji: **`DYLD_*` huondolewa wakati mchakato umewekewa vizuizi** — setuid/setgid, sehemu ya `__RESTRICT/__restrict`, au binaries zenye hardened-runtime/entitled ambazo AMFI inakataa kuzipa path/print flags. Ikiwa badala yake mchakato una **library validation** pekee (`CS_REQUIRE_LV`), variables hubaki lakini dylib iliyoingizwa lazima iwe signed na **Team ID** hiyo hiyo (au na Apple), kwa hivyo unahitaji mojawapo ya entitlements zinazozima library validation ili code iingizwe.

Kwa kuwa uamuzi sasa unafanywa na AMFI, njia ya haraka zaidi ya kujua kile binary fulani itapata ni kuangalia vitu ambavyo AMFI hutumia kama msingi — entitlements na signing flags — badala ya kuangalia `dyld` yenyewe:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## Kagua Vizuizi

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

Unda cheti kipya katika Keychain na ukitumie kusaini binary:
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
> Kumbuka kwamba hata kama kuna binaries zilizosainiwa kwa flags **`0x0(none)`**, zinaweza kupata flag ya **`CS_RESTRICT`** dynamically zinapoendeshwa, na kwa hiyo technique hii haitafanya kazi ndani yao.
>
> Unaweza kuangalia ikiwa proc ina flag hii kwa kutumia (pata [**csops hapa**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> kisha uangalie ikiwa flag 0x800 imewezeshwa.

## Marejeleo

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / ukaguzi wa `__RESTRICT`)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (kuanzisha process na kuingiza library)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
