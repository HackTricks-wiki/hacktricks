# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld का code open source है और इसे [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) पर पाया जा सकता है और इसे **URL जैसे** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) का उपयोग करके tar के रूप में download किया जा सकता है।

## **Dyld Process**

देखें कि Dyld binaries के अंदर libraries को कैसे load करता है:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

यह [**Linux पर LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload) जैसा है। यह किसी run होने वाली process को किसी path से एक specific library load करने के लिए indicate करने की अनुमति देता है (यदि env var enabled हो)<sup>[[4]](#references)</sup>

इस technique का उपयोग **ASEP technique के रूप में भी किया जा सकता है**, क्योंकि install की गई प्रत्येक application में "Info.plist" नाम की एक plist होती है, जो `LSEnvironmental` नामक key का उपयोग करके **environmental variables assign** करने की अनुमति देती है।

> [!TIP]
> 2012 से **Apple ने `DYLD_INSERT_LIBRARIES` की power को काफी कम कर दिया है**। किसी process को **restricted** माना जाता है — और तब `dyld` उसके environment से हर `DYLD_*` variable delete कर देता है — जब इनमें से कोई भी condition पूरी होती है:
>
> - Binary `setuid/setgid` है
> - Mach-O में **`__RESTRICT/__restrict`** section है
> - Binary hardened runtime के साथ signed है और AMFI उसे "path/print variables" permissions प्रदान नहीं करता, अर्थात उसमें [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) मौजूद नहीं है<sup>[[3]](#references)</sup>
>   - किसी binary के **entitlements** को इस command से check करें: `codesign -dv --entitlements :- </path/to/bin>`
>
> वर्तमान `dyld` में यह निर्णय केवल `dyld` द्वारा नहीं लिया जाता: `ProcessConfig::Security::Security()` `amfi_check_dyld_policy_self()` के माध्यम से **AMFI** से पूछता है और फिर `pruneEnvVars()` call करता है। इसका exact code नीचे [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) में समझाया गया है।

### Library Validation

भले ही binary **`DYLD_INSERT_LIBRARIES`** environment variable को allow करता हो, लेकिन यदि वह library के signature को validate करता है, तो वह custom library load नहीं करेगा।

Custom library load करने के लिए binary में निम्नलिखित entitlements में से **एक होना चाहिए**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

या binary में **hardened runtime flag** अथवा **library validation flag** नहीं होना चाहिए।

आप `codesign --display --verbose <bin>` से check कर सकते हैं कि binary में **hardened runtime** है या नहीं। इसके लिए **`CodeDirectory`** में runtime flag देखें, जैसे: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

यदि library binary के समान certificate से **signed** है, तो आप उसे भी load कर सकते हैं।

इसे (ab)use करने और restrictions check करने का example यहां देखें:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> याद रखें कि **पिछली Library Validation restrictions भी** Dylib hijacking attacks करने पर लागू होती हैं।

Windows की तरह, MacOS में भी आप **dylibs hijack** कर सकते हैं, ताकि **applications** **arbitrary code** **execute** करें (वास्तव में, regular user से यह संभव नहीं हो सकता, क्योंकि `.app` bundle के अंदर लिखने और library hijack करने के लिए आपको TCC permission की आवश्यकता हो सकती है)।\
हालांकि, **MacOS** applications द्वारा libraries को **load** करने का तरीका Windows की तुलना में अधिक restricted है। इसका अर्थ है कि **malware** developers इस technique का उपयोग अभी भी **stealth** के लिए कर सकते हैं, लेकिन privileges escalate करने के लिए इसका **abuse** कर पाना काफी कम probable है।

सबसे पहले, यह अधिक common है कि **MacOS binaries load की जाने वाली libraries का full path indicate करती हैं**। दूसरा, **MacOS libraries के लिए कभी भी `$PATH` के folders में search नहीं करता**।

इस functionality से संबंधित **code** का मुख्य भाग `ImageLoader.cpp` में **`ImageLoader::recursiveLoadLibraries`** के अंदर है।

किसी macho binary में libraries load करने के लिए 4 अलग-अलग header Commands हो सकते हैं:

- **`LC_LOAD_DYLIB`** command dylib load करने के लिए common command है।
- **`LC_LOAD_WEAK_DYLIB`** command पिछले command की तरह काम करता है, लेकिन यदि dylib नहीं मिलती, तो execution बिना किसी error के जारी रहती है।
- **`LC_REEXPORT_DYLIB`** command किसी अलग library के symbols को proxy (या re-export) करता है।
- **`LC_LOAD_UPWARD_DYLIB`** command का उपयोग तब किया जाता है जब दो libraries एक-दूसरे पर depend करती हैं (इसे _upward dependency_ कहा जाता है)।

हालांकि, dylib hijacking के **2 types** होते हैं:

- **Missing weak linked libraries**: इसका अर्थ है कि application ऐसी library load करने का प्रयास करेगी जो मौजूद नहीं है और **LC_LOAD_WEAK_DYLIB** के साथ configured है। फिर, **यदि attacker अपेक्षित स्थान पर dylib रखता है, तो वह load हो जाएगी**।
- Link के **"weak"** होने का अर्थ है कि library न मिलने पर भी application चलती रहेगी।
- इससे संबंधित **code** `ImageLoaderMachO.cpp` के `ImageLoaderMachO::doGetDependentLibraries` function में है, जहां `lib->required` केवल तभी `false` होता है जब `LC_LOAD_WEAK_DYLIB` true हो।
- Binaries में **weak linked libraries** को इस command से खोजें (बाद में hijacking libraries बनाने का example दिया गया है):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O binaries में **`LC_RPATH`** और **`LC_LOAD_DYLIB`** commands हो सकते हैं। इन commands की **values** के आधार पर **libraries** अलग-अलग directories से **load** की जाएंगी।
- **`LC_RPATH`** में binary द्वारा libraries load करने के लिए उपयोग किए जाने वाले कुछ folders के paths होते हैं।
- **`LC_LOAD_DYLIB`** में load की जाने वाली specific libraries का path होता है। इन paths में **`@rpath`** हो सकता है, जिसे **`LC_RPATH`** की values से replace किया जाएगा। यदि **`LC_RPATH`** में कई paths हों, तो library load करने के लिए उन सभी से search किया जाएगा। Example:
- यदि **`LC_LOAD_DYLIB`** में `@rpath/library.dylib` और **`LC_RPATH`** में `/application/app.app/Contents/Framework/v1/` तथा `/application/app.app/Contents/Framework/v2/` हों, तो दोनों folders का उपयोग `library.dylib` load करने के लिए किया जाएगा**।** यदि library `[...]/v1/` में मौजूद नहीं है और attacker वहां उसे place कर सकता है, तो वह `[...]/v2/` से library load होने को hijack कर सकता है, क्योंकि **`LC_LOAD_DYLIB`** में paths का order follow किया जाता है।
- Binaries में **rpath paths और libraries** को इस command से खोजें: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: यह उस directory का **path** है जिसमें **main executable file** मौजूद है।
>
> **`@loader_path`**: यह उस **directory** का **path** है जिसमें वह **Mach-O binary** मौजूद है जिसमें load command है।
>
> - Executable में उपयोग किए जाने पर **`@loader_path`**, प्रभावी रूप से **`@executable_path`** के समान होता है।
> - Dylib में उपयोग किए जाने पर **`@loader_path`**, dylib का **path** देता है।

इस functionality का abuse करके **privileges escalate** करने का तरीका वह rare case होगा जिसमें **root द्वारा execute की जा रही application** ऐसी **library को किसी ऐसे folder में खोज रही हो जहां attacker के पास write permissions हों**।

> [!TIP]
> Applications में **missing libraries** खोजने के लिए एक अच्छा **scanner** [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) या इसका [**CLI version**](https://github.com/pandazheng/DylibHijack) है।\
> इस technique के बारे में technical details वाली एक अच्छी **report** [**यहां**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) मिल सकती है।

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> याद रखें कि **पिछली Library Validation restrictions भी** Dlopen hijacking attacks करने पर लागू होती हैं।

**`man dlopen`** से:

- जब path में slash character **नहीं होता** (अर्थात वह केवल leaf name होता है), तो **dlopen() searching करेगा**। यदि launch के समय **`$DYLD_LIBRARY_PATH`** set था, तो dyld पहले उस **directory** में देखेगा। इसके बाद, यदि calling mach-o file या main executable ने **`LC_RPATH`** specify किया है, तो dyld उन directories में देखेगा। इसके बाद, यदि process **unrestricted** है, तो dyld current working directory में search करेगा। अंत में, पुराने binaries के लिए dyld कुछ fallbacks आजमाएगा। यदि launch के समय **`$DYLD_FALLBACK_LIBRARY_PATH`** set था, तो dyld उन directories में search करेगा; अन्यथा dyld **`/usr/local/lib/`** में देखेगा (यदि process unrestricted है), और फिर **`/usr/lib/`** में (यह जानकारी **`man dlopen`** से ली गई है)।
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> यदि name में slashes नहीं हैं, तो hijacking करने के 2 तरीके होंगे:
>
> - यदि कोई **`LC_RPATH`** **writable** है (लेकिन signature check किया जाता है, इसलिए इसके लिए binary का unrestricted होना भी आवश्यक है)
> - यदि binary **unrestricted** है, तो CWD से कुछ load करना संभव है (या बताए गए env variables में से किसी का abuse करना)

- जब path framework path जैसा दिखता है (जैसे `/stuff/foo.framework/foo`), तो यदि launch के समय **`$DYLD_FRAMEWORK_PATH`** set था, dyld सबसे पहले उस directory में **framework partial path** (जैसे `foo.framework/foo`) को खोजेगा। इसके बाद dyld दिए गए path को as-is आजमाएगा (relative paths के लिए current working directory का उपयोग करते हुए)। अंत में, पुराने binaries के लिए dyld कुछ fallbacks आजमाएगा। यदि launch के समय **`$DYLD_FALLBACK_FRAMEWORK_PATH`** set था, तो dyld उन directories में search करेगा। अन्यथा, यह पहले **`/Library/Frameworks`** (macOS पर, यदि process unrestricted है), फिर **`/System/Library/Frameworks`** में search करेगा।
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> यदि framework path हो, तो उसे hijack करने का तरीका होगा:
>
> - यदि process **unrestricted** है, तो CWD से relative path और बताए गए env variables का abuse करना (भले ही docs में यह न कहा गया हो, restricted process में DYLD\_\* env vars remove कर दिए जाते हैं)

- जब path में slash हो लेकिन वह framework path न हो (अर्थात dylib का full path या partial path हो), तो dlopen() सबसे पहले (यदि set हो) **`$DYLD_LIBRARY_PATH`** में देखता है (path के leaf part के साथ)। इसके बाद dyld दिए गए path को try करता है (relative paths के लिए current working directory का उपयोग करते हुए, लेकिन केवल unrestricted processes के लिए)। अंत में, पुराने binaries के लिए dyld fallbacks आजमाएगा। यदि launch के समय **`$DYLD_FALLBACK_LIBRARY_PATH`** set था, तो dyld उन directories में search करेगा; अन्यथा dyld **`/usr/local/lib/`** में देखेगा (यदि process unrestricted है), और फिर **`/usr/lib/`** में।
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> यदि name में slashes हों और वह framework न हो, तो उसे hijack करने का तरीका होगा:
>
> - यदि binary **unrestricted** है, तो CWD या `/usr/local/lib` से कुछ load करना संभव है (या बताए गए env variables में से किसी का abuse करना)

> [!TIP]
> Note: **dlopen searching को control करने के लिए कोई configuration files नहीं होती हैं**।
>
> Note: यदि main executable **set\[ug]id binary** है या entitlements के साथ codesigned है, तो **सभी environment variables ignore** कर दिए जाते हैं और केवल full path का उपयोग किया जा सकता है ([अधिक detailed info के लिए DYLD_INSERT_LIBRARIES restrictions check करें](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions))
>
> Note: Apple platforms 32-bit और 64-bit libraries को combine करने के लिए "universal" files का उपयोग करते हैं। इसका अर्थ है कि **अलग 32-bit और 64-bit search paths नहीं होते**।
>
> Note: Apple platforms पर अधिकांश OS dylibs **dyld cache में combined** होती हैं और disk पर मौजूद नहीं होतीं। इसलिए किसी OS dylib के मौजूद होने की जांच के लिए **`stat()`** call करना **काम नहीं करेगा**। हालांकि, **`dlopen_preflight()`**, compatible mach-o file खोजने के लिए **`dlopen()`** जैसे ही steps का उपयोग करता है।

**Check paths**

आइए निम्नलिखित code से सभी options को check करें:
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
यदि आप इसे compile और execute करते हैं, तो आप देख सकते हैं कि **प्रत्येक library को कहाँ unsuccessfully search किया गया**। साथ ही, आप **FS logs को filter** कर सकते हैं:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

यदि कोई **privileged binary/app** (जैसे SUID या powerful entitlements वाला कोई binary) **relative path** वाली library लोड कर रहा हो (उदाहरण के लिए `@executable_path` या `@loader_path` का उपयोग करके) और उसमें **Library Validation disabled** हो, तो binary को ऐसी location पर ले जाना संभव हो सकता है जहाँ attacker **relative path** से लोड की गई library को **modify** कर सके और process में code inject करने के लिए उसका दुरुपयोग कर सके।

## Prune `DYLD_*` env variables

पुराने `dyld` releases (`dyld2.cpp`) में यह निर्णय `issetugid()`, `hasRestrictedSegment()` और `csops(CS_OPS_STATUS)` का उपयोग करके in-process लिया जाता था। **current `dyld` में यह निर्णय AMFI को delegated है**, और code `dyld/DyldProcessConfig.cpp` में `ProcessConfig::Security::Security()` के अंदर मौजूद है:<sup>[[1]](#references)</sup>
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
इससे दो बातें निकालना उचित है:

- **macOS / Mac Catalyst / DriverKit** पर ही pruning होती है — और केवल तब, जब AMFI ने `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache` में से किसी को भी grant न किया हो।
- AMFI query को executable की अपनी properties दी जाती हैं:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
जहाँ `isRestricted()` वास्तव में `__RESTRICT` segment check (`mach_o/UnsafeHeader.cpp`) है:<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` फिर `DYLD_` से शुरू होने वाले **हर** variable को हटा देता है और `apple[]` parameters को नीचे खिसका देता है, इसलिए restricted process के child processes भी इन्हें inherit नहीं करते:
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
> Practical consequence: **`DYLD_*` को तब prune कर दिया जाता है जब process restricted हो** — setuid/setgid, एक `__RESTRICT/__restrict` section, या hardened-runtime/entitled binaries जिन्हें AMFI path/print flags देने से इनकार करता है। यदि इसके बजाय process में केवल **library validation** (`CS_REQUIRE_LV`) है, तो variables बने रहते हैं, लेकिन inserted dylib पर **same Team ID** (या Apple) का signature होना आवश्यक है, इसलिए code को वास्तव में land कराने के लिए आपको library-validation-disabling entitlements में से किसी एक की आवश्यकता होती है।

क्योंकि अब निर्णय AMFI का है, इसलिए यह जानने का सबसे तेज़ तरीका कि किसी दिए गए binary को क्या मिलेगा, `dyld` को देखने के बजाय उन चीज़ों को देखना है जिन पर AMFI निर्भर करता है — entitlements और signing flags:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## प्रतिबंध जाँचें

### SUID और SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### अनुभाग `__RESTRICT` जिसमें segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Keychain में एक नया certificate बनाएं और binary को sign करने के लिए इसका उपयोग करें:
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
> ध्यान दें कि भले ही कुछ binaries **`0x0(none)`** flags के साथ signed हों, execution के दौरान उनमें **`CS_RESTRICT`** flag dynamically जोड़ा जा सकता है और इसलिए यह technique उनमें काम नहीं करेगी।
>
> आप जाँच सकते हैं कि किसी proc में यह flag है या नहीं (यहाँ से [**csops** प्राप्त करें](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> और फिर जाँचें कि flag 0x800 enabled है या नहीं।

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (process startup और library insertion)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
