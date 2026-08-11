# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Code ya **dyld ni open source** na inaweza kupatikana kwenye [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) na inaweza kupakuliwa kama tar kupitia **URL kama** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Angalia jinsi Dyld inavyopakia libraries ndani ya binaries kwenye:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Hii ni kama [**LD_PRELOAD on Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Inaruhusu kuonyesha process itakayoendeshwa ili ipakie library maalum kutoka kwenye path (ikiwa env var imewezeshwa)<sup>[[4]](#references)</sup>

Technique hii pia inaweza **kutumika kama ASEP technique**, kwa sababu kila application iliyosakinishwa ina plist inayoitwa "Info.plist" inayoruhusu **kupewa environmental variables** kwa kutumia key inayoitwa `LSEnvironmental`.

> [!TIP]
> Tangu 2012 **Apple imepunguza kwa kiasi kikubwa uwezo** wa **`DYLD_INSERT_LIBRARIES`**. Process huchukuliwa kuwa **restricted** — na hivyo `dyld` hufuta kila `DYLD_*` variable kutoka kwenye environment yake — wakati mojawapo ya masharti haya inatimia:
>
> - Binary ni `setuid/setgid`
> - Mach-O ina section ya **`__RESTRICT/__restrict`**
> - Binary imesainiwa kwa hardened runtime na AMFI haijairuhusu kutumia ruhusa za "path/print variables", yaani haina [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Kagua **entitlements** za binary kwa: `codesign -dv --entitlements :- </path/to/bin>`
>
> Katika `dyld` za sasa, hili halijaamuliwa tena na `dyld` pekee: `ProcessConfig::Security::Security()` huuliza **AMFI** kupitia `amfi_check_dyld_policy_self()` kisha huita `pruneEnvVars()`. Code halisi imeelezwa kwenye [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) hapa chini.

### Library Validation

Hata kama binary inaruhusu **`DYLD_INSERT_LIBRARIES`** environment variable, haitapakia library maalum ikiwa inathibitisha signature ya library hiyo.

Ili ipakie library maalum, binary inahitaji kuwa na mojawapo ya **entitlements** zifuatazo:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

au binary **haipaswi** kuwa na **hardened runtime flag** au **library validation flag**.

Unaweza kuangalia kama binary ina **hardened runtime** kwa `codesign --display --verbose <bin>` na kukagua runtime flag ndani ya **`CodeDirectory`**, kama vile: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Pia unaweza kupakia library ikiwa **imesainiwa kwa certificate ileile kama binary**.

Pata mfano wa jinsi ya kutumia vibaya hili na kukagua restrictions kwenye:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Kumbuka kwamba **Library Validation restrictions zilizotajwa awali pia zinatumika** wakati wa kufanya Dylib hijacking attacks.

Kama ilivyo kwenye Windows, kwenye macOS unaweza **kuhijack dylibs** ili kufanya **applications zitekeleze arbitrary code**. Kutoka kwenye regular user account huenda isiwezekane, kwa sababu kuandika ndani ya `.app` bundle ili kuhijack library kunaweza kuhitaji TCC permission.\
Hata hivyo, jinsi **macOS** applications **zinavyopakia** libraries ina restrictions zaidi kuliko Windows. Malware developers bado wanaweza kutumia technique hii kwa **stealth**, lakini kuitumia kuongeza privileges kuna uwezekano mdogo zaidi.

Kwanza, ni **kawaida zaidi** kupata kwamba **MacOS binaries zinaonyesha full path** ya libraries za kupakia. Pili, **MacOS haitafuti kamwe** libraries kwenye folders za **$PATH**.

Sehemu **kuu** ya **code** inayohusiana na functionality hii iko kwenye **`ImageLoader::recursiveLoadLibraries`** ndani ya `ImageLoader.cpp`.

Kuna **header Commands 4 tofauti** ambazo macho binary inaweza kutumia kupakia libraries:

- **`LC_LOAD_DYLIB`** command ndiyo command ya kawaida ya kupakia dylib.
- **`LC_LOAD_WEAK_DYLIB`** command hufanya kazi kama iliyotangulia, lakini ikiwa dylib haipatikani, execution inaendelea bila error yoyote.
- **`LC_REEXPORT_DYLIB`** command hu-proxy (au ku-re-export) symbols kutoka library tofauti.
- **`LC_LOAD_UPWARD_DYLIB`** command hutumika wakati libraries mbili zinategemeana (hii huitwa _upward dependency_).

Hata hivyo, kuna **aina 2 za dylib hijacking**:

- **Missing weak linked libraries**: Hii inamaanisha application itajaribu kupakia library ambayo haipo, ikiwa imesanidiwa kwa **LC_LOAD_WEAK_DYLIB**. Kisha, **ikiwa attacker ataweka dylib mahali inapotarajiwa, itapakiwa**.
- Ukweli kwamba link ni "weak" unamaanisha application itaendelea kufanya kazi hata kama library haipatikani.
- **Code inayohusiana** na hili iko kwenye function `ImageLoaderMachO::doGetDependentLibraries` ya `ImageLoaderMachO.cpp`, ambapo `lib->required` huwa `false` tu wakati `LC_LOAD_WEAK_DYLIB` ni true.
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
- **`LC_LOAD_DYLIB`** ina path ya libraries maalum za kupakia. Paths hizi zinaweza kuwa na **`@rpath`**, ambayo **itabadilishwa** na values zilizoko kwenye **`LC_RPATH`**. Ikiwa kuna paths kadhaa kwenye **`LC_RPATH`**, zote zitatumiwa kutafuta library ya kupakia. Mfano:
- Ikiwa **`LC_LOAD_DYLIB`** ina `@rpath/library.dylib` na **`LC_RPATH`** ina `/application/app.app/Contents/Framework/v1/` na `/application/app.app/Contents/Framework/v2/`. Folders zote mbili zitatumiwa kupakia `library.dylib`**.** Ikiwa library haipo kwenye `[...]/v1/` na attacker anaweza kuiweka hapo, anaweza kuhijack library inayopakiwa kutoka `[...]/v2/`, kwa sababu mpangilio wa paths kwenye **`LC_LOAD_DYLIB`** unafuatwa.
- **Tafuta rpath paths na libraries** kwenye binaries kwa: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Ni **path** ya directory iliyo na **main executable file**.
>
> **`@loader_path`**: Ni **path** ya **directory** iliyo na **Mach-O binary** yenye load command.
>
> - Inapotumiwa kwenye executable, **`@loader_path`** kwa ufanisi ni **sawa na** **`@executable_path`**.
> - Inapotumiwa kwenye **dylib**, **`@loader_path`** hutoa **path** ya **dylib**.

Njia ya **kuongeza privileges** kwa kutumia vibaya functionality hii ingekuwa katika hali adimu ambapo **application** inayoendeshwa **na** **root** **inatafuta** **library fulani kwenye folder ambayo attacker ana write permissions.**

> [!TIP]
> **Scanner** nzuri ya kupata **missing libraries** kwenye applications ni [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) au [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Ripoti nzuri yenye **technical details** kuhusu technique hii inaweza kupatikana [**hapa**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Kumbuka kwamba **Library Validation restrictions zilizotajwa awali pia zinatumika** wakati wa kufanya Dlopen hijacking attacks.

Kutoka kwenye **`man dlopen`**:

- Wakati path **haina slash character** (yaani ni leaf name pekee), **dlopen() itafanya searching**. Ikiwa **`$DYLD_LIBRARY_PATH`** iliwekwa wakati wa launch, dyld itatafuta kwanza kwenye director**y** hiyo. Kisha, ikiwa calling mach-o file au main executable imeainisha **`LC_RPATH`**, dyld **itatfuta kwenye** directories hizo. Kisha, ikiwa process **haijazuiwa**, dyld itatafuta kwenye current working directory. Mwishowe, kwa old binaries, dyld itajaribu fallbacks. Ikiwa **`$DYLD_FALLBACK_LIBRARY_PATH`** iliwekwa wakati wa launch, dyld itatafuta kwenye **directories hizo**, vinginevyo, dyld itatafuta kwenye **`/usr/local/lib/`** (ikiwa process haijazuiwa), na kisha kwenye **`/usr/lib/`** (taarifa hii ilichukuliwa kutoka **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Ikiwa jina halina slashes, kuna njia 2 za kufanya hijacking:
>
> - Ikiwa **`LC_RPATH`** yoyote inaweza kuandikwa (lakini signature hukaguliwa, kwa hiyo pia unahitaji binary isiwe restricted)
> - Ikiwa binary **haijazuiwa**, hivyo inawezekana kupakia kitu kutoka kwenye CWD (au kutumia vibaya mojawapo ya env variables zilizotajwa)

- Wakati path **inaonekana kama** framework path (kwa mfano, `/stuff/foo.framework/foo`), ikiwa **`$DYLD_FRAMEWORK_PATH`** iliwekwa wakati wa launch, dyld itatafuta kwanza kwenye directory hiyo kwa **framework partial path** (kwa mfano, `foo.framework/foo`). Kisha, dyld itajaribu path iliyotolewa kama ilivyo (ikitumia current working directory kwa relative paths). Mwishowe, kwa old binaries, dyld itajaribu fallbacks. Ikiwa **`$DYLD_FALLBACK_FRAMEWORK_PATH`** iliwekwa wakati wa launch, dyld itatafuta kwenye directories hizo. Vinginevyo, itatafuta kwenye **`/Library/Frameworks`** (kwenye macOS ikiwa process haijazuiwa), kisha **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Ikiwa ni framework path, njia ya kuihijack ingekuwa:
>
> - Ikiwa process **haijazuiwa**, kutumia vibaya **relative path kutoka CWD** na env variables zilizotajwa (hata kama docs hazisemi ikiwa process imezuiwa, DYLD\_\* env vars huondolewa)

- Wakati path **ina slash lakini si framework path** (yaani full path au partial path ya dylib), dlopen() kwanza hutafuta (ikiwa imewekwa) kwenye **`$DYLD_LIBRARY_PATH`** (ikitumia leaf part kutoka path). Kisha, dyld **hujaribu path iliyotolewa** (ikitumia current working directory kwa relative paths (lakini kwa unrestricted processes pekee)). Mwishowe, kwa older binaries, dyld itajaribu fallbacks. Ikiwa **`$DYLD_FALLBACK_LIBRARY_PATH`** iliwekwa wakati wa launch, dyld itatafuta kwenye directories hizo, vinginevyo, dyld itatafuta kwenye **`/usr/local/lib/`** (ikiwa process haijazuiwa), na kisha kwenye **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Ikiwa jina lina slashes na si framework, njia ya kuihijack ingekuwa:
>
> - Ikiwa binary **haijazuiwa**, basi inawezekana kupakia kitu kutoka CWD au `/usr/local/lib` (au kutumia vibaya mojawapo ya env variables zilizotajwa)

> [!TIP]
> Kumbuka: Hakuna configuration files za **kudhibiti dlopen searching**.
>
> Kumbuka: Ikiwa main executable ni **set\[ug]id binary** au imesainiwa kwa entitlements, basi **environment variables zote hupuuzwa**, na full path pekee inaweza kutumika ([kagua DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) kwa maelezo zaidi)
>
> Kumbuka: Apple platforms hutumia files za "universal" kuunganisha 32-bit na 64-bit libraries. Hii inamaanisha kuwa hakuna **32-bit na 64-bit search paths** tofauti.
>
> Kumbuka: Kwenye Apple platforms, OS dylibs nyingi **huunganishwa kwenye dyld cache** na hazipo kwenye disk. Kwa hiyo, kutumia **`stat()`** kuangalia mapema kama OS dylib ipo **hakutafanya kazi**. Hata hivyo, **`dlopen_preflight()`** hutumia hatua zilezile kama **`dlopen()`** kutafuta compatible mach-o file.

**Check paths**

Tukague options zote kwa kutumia code ifuatayo:
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
Uki-**compile** na kui-**execute**, unaweza kuona **ni wapi kila library ilitafutwa bila mafanikio**. Pia, unaweza **kuchuja FS logs**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Hijacking ya Relative Path

Ikiwa **privileged binary/app** (kama SUID au binary yenye entitlements zenye nguvu) **inapakia** library yenye **relative path** (kwa mfano kwa kutumia `@executable_path` au `@loader_path`) na **Library Validation imezimwa**, huenda ikawezekana kuhamisha binary hiyo hadi mahali ambapo attacker anaweza **kubadilisha library inayopakiwa kupitia relative path**, na kuitumia kuingiza code kwenye process.

## Ondoa `DYLD_*` env variables

Matoleo ya zamani ya `dyld` (`dyld2.cpp`) yaliamua hili ndani ya process kwa kutumia `issetugid()`, `hasRestrictedSegment()` na `csops(CS_OPS_STATUS)`. Kwenye **dyld ya sasa, uamuzi umekabidhiwa AMFI**, na code hiyo iko kwenye `ProcessConfig::Security::Security()` katika `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
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

- Pruning hutokea tu kwenye **macOS / Mac Catalyst / DriverKit** — na pale tu AMFI ilipotoa **hakuna** kati ya `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- Hoja ya AMFI hutumia properties za executable yenyewe:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
ambapo `isRestricted()` ni ukaguzi wa segment ya `__RESTRICT` kihalisi (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` kisha huondoa **kila** variable ambayo jina lake linaanza na `DYLD_` na kusogeza chini vigezo vya `apple[]`, hivyo watoto wa process iliyowekewa vikwazo pia hawazirithi:
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
> Matokeo ya kivitendo: **`DYLD_*` huondolewa wakati process imewekewa vikwazo** — setuid/setgid, section ya `__RESTRICT/__restrict`, au binaries za hardened-runtime/entitled ambazo AMFI inakataa kuzipa path/print flags. Ikiwa badala yake process ina **library validation** pekee (`CS_REQUIRE_LV`), variables hubaki, lakini dylib iliyoingizwa lazima iwe signed na **Team ID** ileile (au na Apple), kwa hiyo unahitaji mojawapo ya entitlements zinazozima library-validation ili code ifike na kutekelezwa.

Kwa kuwa uamuzi sasa unafanywa na AMFI, njia ya haraka zaidi ya kujua binary fulani itapata nini ni kuangalia vitu ambavyo AMFI hutumia kama msingi — entitlements na signing flags — badala ya kuangalia `dyld` yenyewe:
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

Unda certificate mpya katika Keychain na uitumie kusaini binary:
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
> Kumbuka kwamba hata kama kuna binaries zilizosainiwa kwa flags **`0x0(none)`**, zinaweza kupata flag ya **`CS_RESTRICT`** dynamically zinapoendeshwa, na kwa hiyo mbinu hii haitafanya kazi ndani yake.
>
> Unaweza kuangalia kama proc ina flag hii kwa kutumia (pata [**csops hapa**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> kisha uangalie kama flag 0x800 imewezeshwa.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (mchakato kuanza na kuingiza library)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
