# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld का code open source है** और इसे [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) पर पाया जा सकता है और **URL जैसे** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) से tar के रूप में download किया जा सकता है।

## **Dyld Process**

Dyld binaries के अंदर libraries कैसे load करता है, यह देखें:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

यह [**Linux पर LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload) जैसा है। यह run किए जाने वाले process को किसी path से एक specific library load करने के लिए indicate करने की अनुमति देता है (यदि env var enabled हो)।

इस technique का **ASEP technique के रूप में भी उपयोग किया जा सकता है**, क्योंकि installed प्रत्येक application में "Info.plist" नाम की plist होती है, जो `LSEnvironmental` नामक key का उपयोग करके **environmental variables assign** करने की अनुमति देती है।

> [!TIP]
> 2012 से **Apple ने `DYLD_INSERT_LIBRARIES` की power को काफी कम कर दिया है**।
>
> Code पर जाएं और **`src/dyld.cpp` check करें**। **`pruneEnvironmentVariables`** function में आप देख सकते हैं कि **`DYLD_*`** variables remove कर दिए जाते हैं।
>
> **`processRestricted`** function में restriction का कारण set किया जाता है। उस code को check करने पर आप देख सकते हैं कि कारण हैं:
>
> - Binary `setuid/setgid` है
> - Mach-O binary में `__RESTRICT/__restrict` section मौजूद है।
> - Software में [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) entitlement के बिना entitlements (hardened runtime) हैं
>  - इस command से binary के **entitlements** check करें: `codesign -dv --entitlements :- </path/to/bin>`
>
> अधिक updated versions में आप यह logic **`configureProcessRestrictions`** function के दूसरे भाग में पा सकते हैं। हालांकि, नए versions में जो execute होता है, वह function के **शुरुआती checks** हैं (आप iOS या simulation से संबंधित ifs को remove कर सकते हैं, क्योंकि वे macOS में उपयोग नहीं होंगे।

### Library Validation

भले ही binary **`DYLD_INSERT_LIBRARIES`** env variable के उपयोग की अनुमति देता हो, यदि binary load की जाने वाली library का signature check करता है, तो वह custom library load नहीं करेगा।

Custom library load करने के लिए binary में निम्नलिखित entitlements में से **एक होना चाहिए**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

या binary में **hardened runtime flag** अथवा **library validation flag** नहीं होना चाहिए।

आप `codesign --display --verbose <bin>` से check कर सकते हैं कि binary में **hardened runtime** है या नहीं। इसके लिए **`CodeDirectory`** में runtime flag check करें, जैसे: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

आप किसी library को तब भी load कर सकते हैं, जब वह binary के समान certificate से **signed** हो।

इसका (ab)use करने और restrictions check करने का example यहां देखें:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> याद रखें कि **पिछली Library Validation restrictions भी Dylib hijacking attacks** करने पर लागू होती हैं।

Windows की तरह, MacOS में भी आप **dylibs hijack** करके **applications** से **arbitrary** **code execute** करवा सकते हैं (हालांकि, regular user से यह संभव नहीं हो सकता, क्योंकि `.app` bundle के अंदर write करने और library hijack करने के लिए TCC permission की आवश्यकता हो सकती है)।\
हालांकि, **MacOS** applications द्वारा libraries **load** करने का तरीका Windows की तुलना में **अधिक restricted** है। इसका अर्थ है कि **malware** developers इस technique का उपयोग **stealth** के लिए कर सकते हैं, लेकिन privileges escalate करने के लिए इसका **abuse** कर पाना काफी कम probable है।

सबसे पहले, **MacOS binaries में load की जाने वाली libraries का full path indicate** किया हुआ मिलना अधिक common है। दूसरा, **MacOS libraries के लिए `$PATH` के folders में कभी search नहीं करता**।

इस functionality से संबंधित **code** का **मुख्य** भाग `ImageLoader.cpp` में **`ImageLoader::recursiveLoadLibraries`** के अंदर है।

किसी Mach-O binary में libraries load करने के लिए **4 अलग-अलग header Commands** उपयोग किए जा सकते हैं:

- **`LC_LOAD_DYLIB`** command dylib load करने के लिए common command है।
- **`LC_LOAD_WEAK_DYLIB`** command पिछले command की तरह काम करता है, लेकिन यदि dylib नहीं मिलती, तो execution बिना किसी error के जारी रहती है।
- **`LC_REEXPORT_DYLIB`** command किसी अलग library के symbols को proxy (या re-export) करता है।
- **`LC_LOAD_UPWARD_DYLIB`** command तब उपयोग किया जाता है जब दो libraries एक-दूसरे पर depend करती हैं (इसे _upward dependency_ कहा जाता है)।

हालांकि, dylib hijacking के **2 प्रकार** हैं:

- **Missing weak linked libraries**: इसका अर्थ है कि application `LC_LOAD_WEAK_DYLIB` से configured ऐसी library load करने का प्रयास करेगी, जो मौजूद नहीं है। फिर, **यदि attacker उस स्थान पर dylib रखता है जहां इसकी अपेक्षा है, तो वह load हो जाएगी**।
- Link के "weak" होने का अर्थ है कि library न मिलने पर भी application चलती रहेगी।
- इससे संबंधित **code** `ImageLoader.cpp` के `ImageLoaderMachO::doGetDependentLibraries` function में है, जहां `lib->required` केवल तभी `false` होता है जब `LC_LOAD_WEAK_DYLIB` true हो।
- Binaries में **weak linked libraries** खोजें (बाद में hijacking libraries create करने का example दिया गया है):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpath से configured**: Mach-O binaries में **`LC_RPATH`** और **`LC_LOAD_DYLIB`** commands हो सकते हैं। इन commands की **values** के आधार पर **libraries** अलग-अलग directories से **load** की जाएंगी।
- **`LC_RPATH`** में binary द्वारा libraries load करने के लिए उपयोग किए जाने वाले कुछ folders के paths होते हैं।
- **`LC_LOAD_DYLIB`** में load की जाने वाली specific libraries का path होता है। इन paths में **`@rpath`** हो सकता है, जिसे **`LC_RPATH`** की values से replace किया जाएगा। यदि **`LC_RPATH`** में कई paths हों, तो library load करने के लिए सभी का उपयोग किया जाएगा। Example:
- यदि **`LC_LOAD_DYLIB`** में `@rpath/library.dylib` और **`LC_RPATH`** में `/application/app.app/Contents/Framework/v1/` तथा `/application/app.app/Contents/Framework/v2/` हों, तो दोनों folders का उपयोग `library.dylib` load करने के लिए किया जाएगा**।** यदि library `[...]/v1/` में मौजूद नहीं है और attacker उसे वहां place कर सकता है, तो `[...]/v2/` में मौजूद library का load hijack किया जा सकता है, क्योंकि **`LC_LOAD_DYLIB`** में paths का order follow किया जाता है।
- Binaries में **rpath paths और libraries** खोजें: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: यह **उस directory का path** है जिसमें **main executable file** मौजूद है।
>
> **`@loader_path`**: यह उस **directory का path** है जिसमें वह **Mach-O binary** मौजूद है, जिसमें load command है।
>
> - Executable में उपयोग किए जाने पर **`@loader_path`**, प्रभावी रूप से **`@executable_path`** के समान होता है।
> - Dylib में उपयोग किए जाने पर **`@loader_path`**, dylib का **path** देता है।

इस functionality का abuse करके **privileges escalate** करने का तरीका उस rare case में होगा, जब **root द्वारा execute किया जा रहा application** ऐसी **library को किसी ऐसे folder में खोज रहा हो जहां attacker के पास write permissions हों**।

> [!TIP]
> Applications में **missing libraries** खोजने के लिए एक अच्छा **scanner** [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) या इसका [**CLI version**](https://github.com/pandazheng/DylibHijack) है।\
> इस technique के बारे में technical details वाली एक अच्छी **report** [**यहां**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) मिल सकती है।

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> याद रखें कि **पिछली Library Validation restrictions भी Dlopen hijacking attacks** करने पर लागू होती हैं।

**`man dlopen`** से:

- जब path में **slash character नहीं होता** (अर्थात यह केवल एक leaf name होता है), तो **dlopen() searching करेगा**। यदि launch के समय **`$DYLD_LIBRARY_PATH`** set था, तो dyld पहले उस **directory** में देखेगा। इसके बाद, यदि calling Mach-O file या main executable **`LC_RPATH`** specify करता है, तो dyld उन directories में देखेगा। फिर, यदि process **unrestricted** है, तो dyld current working directory में search करेगा। अंत में, पुराने binaries के लिए dyld कुछ fallbacks try करेगा। यदि launch के समय **`$DYLD_FALLBACK_LIBRARY_PATH`** set था, तो dyld उन **directories** में search करेगा; अन्यथा dyld पहले **`/usr/local/lib/`** (यदि process unrestricted है), और फिर **`/usr/lib/`** में देखेगा (यह जानकारी **`man dlopen`** से ली गई है)।
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> यदि name में slashes नहीं हैं, तो hijacking के **2 तरीके** होंगे:
>
> - यदि कोई **`LC_RPATH`** **writable** है (लेकिन signature check किया जाता है, इसलिए इसके लिए binary का unrestricted होना भी आवश्यक है)
> - यदि binary **unrestricted** है और तब CWD से कुछ load करना संभव है (या उल्लिखित env variables में से किसी का abuse करना)

- जब path **framework** path जैसा दिखता है (जैसे `/stuff/foo.framework/foo`), यदि launch के समय **`$DYLD_FRAMEWORK_PATH`** set था, तो dyad पहले उस directory में **framework partial path** (जैसे `foo.framework/foo`) खोजेगा। इसके बाद, dyld **दिए गए path को as-is** try करेगा (relative paths के लिए current working directory का उपयोग करके)। अंत में, पुराने binaries के लिए dyld कुछ fallbacks try करेगा। यदि launch के समय **`$DYLD_FALLBACK_FRAMEWORK_PATH`** set था, तो dyld उन directories में search करेगा। अन्यथा, यह पहले **`/Library/Frameworks`** (macOS पर यदि process unrestricted है), फिर **`/System/Library/Frameworks`** में search करेगा।
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> यदि framework path है, तो इसे hijack करने का तरीका होगा:
>
> - यदि process **unrestricted** है, तो CWD से relative path और उल्लिखित env variables का abuse करना (भले ही docs में यह न कहा गया हो, यदि process restricted है तो DYLD\_\* env vars remove कर दिए जाते हैं)

- जब path में slash हो लेकिन वह framework path न हो (अर्थात dylib का full path या partial path हो), तो dlopen() पहले (यदि set हो) **`$DYLD_LIBRARY_PATH`** में देखता है (path के leaf part के साथ)। इसके बाद, dyld **दिए गए path** को try करता है (relative paths के लिए current working directory का उपयोग करके, लेकिन केवल unrestricted processes के लिए)। अंत में, पुराने binaries के लिए dyld fallbacks try करेगा। यदि launch के समय **`$DYLD_FALLBACK_LIBRARY_PATH`** set था, तो dyld उन directories में search करेगा; अन्यथा dyld पहले **`/usr/local/lib/`** (यदि process unrestricted है), और फिर **`/usr/lib/`** में देखेगा।
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> यदि name में slashes हैं और वह framework नहीं है, तो इसे hijack करने का तरीका होगा:
>
> - यदि binary **unrestricted** है, तो CWD या `/usr/local/lib` से कुछ load करना संभव है (या उल्लिखित env variables में से किसी का abuse करना)

> [!TIP]
> Note: **dlopen searching को control करने वाली कोई configuration files नहीं हैं**।
>
> Note: यदि main executable **set\[ug]id binary** है या entitlements के साथ codesigned है, तो **सभी environment variables ignore** किए जाते हैं और केवल full path का उपयोग किया जा सकता है ([अधिक detailed information के लिए DYLD_INSERT_LIBRARIES restrictions check करें](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions))
>
> Note: Apple platforms 32-bit और 64-bit libraries को combine करने के लिए "universal" files का उपयोग करते हैं। इसका अर्थ है कि **अलग 32-bit और 64-bit search paths नहीं हैं**।
>
> Note: Apple platforms पर अधिकांश OS dylibs **dyld cache में combine** की जाती हैं और disk पर मौजूद नहीं होतीं। इसलिए यह preflight करने के लिए **`stat()`** call करना कि कोई OS dylib मौजूद है या नहीं, काम नहीं करेगा। हालांकि, **`dlopen_preflight()`** compatible Mach-O file खोजने के लिए **`dlopen()`** जैसे ही steps का उपयोग करता है।

**Check paths**

आइए निम्नलिखित code से सभी options check करते हैं:
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
यदि आप इसे compile और execute करते हैं, तो आप देख सकते हैं कि **प्रत्येक library को कहाँ unsuccessfully search किया गया था**। इसके अलावा, आप **FS logs को filter** कर सकते हैं:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

यदि कोई **privileged binary/app** (जैसे SUID या powerful entitlements वाला कोई binary) **relative path** library को load कर रहा है (उदाहरण के लिए `@executable_path` या `@loader_path` का उपयोग करके) और **Library Validation disabled** है, तो binary को ऐसी location पर ले जाना संभव हो सकता है जहाँ attacker **relative path loaded library** को **modify** कर सके और process में code inject करने के लिए उसका दुरुपयोग कर सके।

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

`dyld-dyld-832.7.1/src/dyld2.cpp` file में **`pruneEnvironmentVariables`** function को ढूँढना संभव है, जो **`DYLD_`** से **शुरू होने वाले** और **`LD_LIBRARY_PATH=`** वाले किसी भी env variable को remove कर देगा।

यह **suid** और **sgid** binaries के लिए विशेष रूप से **`DYLD_FALLBACK_FRAMEWORK_PATH`** और **`DYLD_FALLBACK_LIBRARY_PATH`** env variables को **null** पर भी set करेगा।

यदि OSX को target किया जा रहा हो, तो इसी file के **`_main`** function से इस function को इस तरह call किया जाता है:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
और वे boolean flags code में उसी file में set किए जाते हैं:
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
जिसका मूल रूप से अर्थ है कि यदि binary **suid** या **sgid** है, या headers में **RESTRICT** segment है, या उसे **CS_RESTRICT** flag के साथ signed किया गया है, तो **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** true होता है और env variables को prune कर दिया जाता है।

ध्यान दें कि यदि CS_REQUIRE_LV true है, तो variables को prune नहीं किया जाएगा, लेकिन library validation यह जाँच करेगी कि वे original binary वाले ही certificate का उपयोग कर रहे हैं।

## Restrictions जाँचें

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
### `__restrict` segment वाला `__RESTRICT` अनुभाग
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Keychain में एक नया certificate बनाएं और binary को sign करने के लिए इसका उपयोग करें:
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
> ध्यान दें कि भले ही कुछ binaries **`0x0(none)`** flags के साथ signed हों, execution के दौरान उनमें **`CS_RESTRICT`** flag dynamically जोड़ा जा सकता है और इसलिए यह technique उनमें काम नहीं करेगी।
>
> आप यह जाँच सकते हैं कि किसी proc में यह flag है या नहीं (यहाँ [**csops** प्राप्त करें](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> इसके बाद जाँचें कि 0x800 flag enabled है या नहीं।

## संदर्भ

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
