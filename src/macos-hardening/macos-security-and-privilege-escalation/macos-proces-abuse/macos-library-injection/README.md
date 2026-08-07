# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld kodu açık kaynaklıdır** ve [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) adresinde bulunabilir; ayrıca [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) gibi bir **URL kullanılarak** tar dosyası olarak indirilebilir.

## **Dyld Process**

Dyld'ın binary'lerin içindeki library'leri nasıl yüklediğine göz atın:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Bu, [**Linux'taki LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload) gibidir. Çalıştırılacak bir process'in bir path'ten belirli bir library'yi yüklemesini belirtmeye olanak tanır (env var etkinse)<sup>[[4]](#references)</sup>

Bu technique ayrıca bir **ASEP technique olarak da kullanılabilir**, çünkü yüklenen her application'ın, `LSEnvironmental` adlı bir key kullanarak **environmental variable'ların atanmasına** olanak tanıyan "Info.plist" adlı bir plist'i vardır.

> [!TIP]
> 2012'den beri **Apple, `DYLD_INSERT_LIBRARIES`'in gücünü büyük ölçüde azalttı**. Aşağıdakilerden herhangi biri geçerliyse bir process **restricted** olarak kabul edilir — ve ardından `dyld`, tüm `DYLD_*` variable'larını environment'ından siler:
>
> - Binary `setuid/setgid`'dir
> - Mach-O'da bir **`__RESTRICT/__restrict`** section'ı vardır
> - Binary hardened runtime ile imzalanmıştır ve AMFI ona "path/print variables" izinlerini vermemiştir; yani [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) entitlement'ı eksiktir<sup>[[3]](#references)</sup>
>   - Bir binary'nin **entitlement**'larını şu komutla kontrol edin: `codesign -dv --entitlements :- </path/to/bin>`
>
> Güncel `dyld` sürümünde bu işlem artık yalnızca `dyld` tarafından belirlenmez: `ProcessConfig::Security::Security()`, `amfi_check_dyld_policy_self()` aracılığıyla **AMFI**'ye sorar ve ardından `pruneEnvVars()` fonksiyonunu çağırır. Kesin kod akışı aşağıda [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) bölümünde açıklanmıştır.

### Library Validation

Binary **`DYLD_INSERT_LIBRARIES`** env variable'ını kullanmaya izin verse bile, yükleyeceği library'nin signature'ını kontrol ediyorsa custom bir library yüklenmez.

Custom bir library yüklemek için binary'nin aşağıdaki entitlement'lardan **birine** sahip olması gerekir:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

veya binary'de **hardened runtime flag** ya da **library validation flag** bulunmamalıdır.

Bir binary'de **hardened runtime** olup olmadığını `codesign --display --verbose <bin>` ile, **`CodeDirectory`** içindeki runtime flag'ini kontrol ederek görebilirsiniz; örneğin: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Ayrıca binary ile aynı certificate ile imzalanmış bir library'yi de yükleyebilirsiniz.

Bunun nasıl (ab)use edileceğine ve restrictions'ların nasıl kontrol edileceğine dair bir örneği burada bulabilirsiniz:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> **Önceki Library Validation restrictions'larının Dylib hijacking attack'lerini gerçekleştirmek için de geçerli olduğunu** unutmayın.

Windows'ta olduğu gibi MacOS'ta da **dylib'leri hijack ederek** **application'ların** **arbitrary** **code** çalıştırmasını sağlayabilirsiniz (aslında normal bir user için bu mümkün olmayabilir; çünkü bir `.app` bundle'ına yazmak ve bir library'yi hijack etmek için TCC izni gerekebilir).\
Bununla birlikte, **MacOS** application'larının library'leri **yükleme** şekli Windows'a göre daha restricted'dır. Bu, **malware** geliştiricilerinin bu technique'i hâlâ **stealth** amacıyla kullanabileceği, ancak bunu **privilege escalation** için kötüye kullanma olasılığının çok daha düşük olduğu anlamına gelir.

İlk olarak, **MacOS binary'lerinin yükleyeceği library'lerin tam path'ini belirtmesi** daha yaygındır. İkinci olarak, **MacOS library'ler için** hiçbir zaman **$PATH** klasörlerinde arama yapmaz.

Bu işlevsellikle ilgili **code**'un **ana** bölümü `ImageLoader.cpp` içindeki **`ImageLoader::recursiveLoadLibraries`** fonksiyonundadır.

Bir macho binary'nin library yüklemek için kullanabileceği **4 farklı header Command** vardır:

- **`LC_LOAD_DYLIB`** command'i dylib yüklemek için kullanılan yaygın command'dir.
- **`LC_LOAD_WEAK_DYLIB`** command'i öncekiyle aynı şekilde çalışır; ancak dylib bulunamazsa execution herhangi bir error olmadan devam eder.
- **`LC_REEXPORT_DYLIB`** command'i farklı bir library'deki symbol'leri proxy'ler (veya yeniden export eder).
- **`LC_LOAD_UPWARD_DYLIB`** command'i iki library birbirine bağlı olduğunda kullanılır (buna _upward dependency_ denir).

Bununla birlikte, **2 tür dylib hijacking** vardır:

- **Missing weak linked libraries**: Bu, application'ın **LC_LOAD_WEAK_DYLIB** ile yapılandırılmış ve mevcut olmayan bir library'yi yüklemeye çalışacağı anlamına gelir. Ardından, **bir attacker beklenen yere bir dylib yerleştirirse bu dylib yüklenir**.
- Link'in "weak" olması, library bulunamasa bile application'ın çalışmaya devam edeceği anlamına gelir.
- Bununla **ilgili code**, `ImageLoader.cpp` içindeki `ImageLoaderMachO::doGetDependentLibraries` fonksiyonundadır; burada `lib->required`, yalnızca `LC_LOAD_WEAK_DYLIB` true olduğunda `false` olur.
- Binary'lerde **weak linked libraries**'leri şu komutla bulun:
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpath ile yapılandırılmış**: Mach-O binary'leri **`LC_RPATH`** ve **`LC_LOAD_DYLIB`** command'lerine sahip olabilir. Bu command'lerin **değerlerine** göre **library'ler** farklı directory'lerden **yüklenir**.
- **`LC_RPATH`**, binary tarafından library yüklemek için kullanılan bazı folder'ların path'lerini içerir.
- **`LC_LOAD_DYLIB`**, yüklenecek belirli library'lerin path'ini içerir. Bu path'ler, **`LC_RPATH`** değerleriyle değiştirilecek **`@rpath`** içerebilir. **`LC_RPATH`** içinde birden fazla path varsa library'yi aramak için tümü kullanılır. Örnek:
- **`LC_LOAD_DYLIB`** `@rpath/library.dylib` içeriyor ve **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` ile `/application/app.app/Contents/Framework/v2/` içeriyorsa, her iki folder da `library.dylib` yüklenirken kullanılır**.** Library `[...]/v1/` içinde mevcut değilse ve attacker buraya bir library yerleştirebiliyorsa, **`LC_LOAD_DYLIB`** içindeki path sırası izlendiğinden `[...]/v2/` içindeki library'nin yüklenmesini hijack edebilir.
- Binary'lerde **rpath path'lerini ve library'leri** şu komutla bulun: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file**'ı içeren directory'nin **path**'idir.
>
> **`@loader_path`**: load command'i içeren **Mach-O binary**'sini içeren **directory**'nin **path**'idir.
>
> - Bir executable'da kullanıldığında **`@loader_path`**, işlevsel olarak **`@executable_path`** ile aynıdır.
> - Bir **dylib** içinde kullanıldığında **`@loader_path`**, **dylib**'nin **path**'ini verir.

Bu işlevselliği abuse ederek **privilege escalation** gerçekleştirmenin yolu, **root** tarafından çalıştırılan bir **application**'ın attacker'ın yazma iznine sahip olduğu bir folder'da bir **library araması** gibi nadir bir durumun gerçekleşmesidir.

> [!TIP]
> Application'larda **missing libraries** bulmak için iyi bir **scanner**, [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) veya [**CLI version**](https://github.com/pandazheng/DylibHijack)'dır.\
> Bu technique hakkında teknik ayrıntılar içeren iyi bir **report** [**burada**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) bulunabilir.

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> **Önceki Library Validation restrictions'larının Dlopen hijacking attack'lerini gerçekleştirmek için de geçerli olduğunu** unutmayın.

**`man dlopen`** sayfasından:

- Path **slash character içermiyorsa** (yani yalnızca bir leaf name ise), **dlopen() arama yapar**. Launch sırasında **`$DYLD_LIBRARY_PATH`** ayarlanmışsa, dyld önce **bu directory'ye** bakar. Ardından, çağıran mach-o file veya main executable bir **`LC_RPATH`** belirtiyorsa dyld **bu** directory'lerde arama yapar. Sonra process **unrestricted** ise dyld current working directory'de arama yapar. Son olarak eski binary'ler için dyld bazı fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlanmışsa dyld **bu directory'lerde** arama yapar; aksi takdirde dyld **`/usr/local/lib/`** (process unrestricted ise) ve ardından **`/usr/lib/`** içinde arama yapar (bu bilgi **`man dlopen`** sayfasından alınmıştır).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Name içinde slash yoksa hijacking yapmanın 2 yolu vardır:
>
> - Herhangi bir **`LC_RPATH`** writable ise (ancak signature kontrol edilir; dolayısıyla bunun için binary'nin unrestricted olması da gerekir)
> - Binary **unrestricted** ise ve CWD'den bir şey yüklemek mümkünse (veya belirtilen env variable'lardan biri abuse edilirse)

- Path **framework** path'i gibi görünüyorsa (ör. `/stuff/foo.framework/foo`), launch sırasında **`$DYLD_FRAMEWORK_PATH`** ayarlanmışsa dyld önce framework'ün **partial path**'i için (ör. `foo.framework/foo`) bu directory'de arama yapar. Ardından dyld sağlanan path'i olduğu gibi dener (relative path'ler için current working directory kullanılır). Son olarak eski binary'ler için dyld bazı fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_FRAMEWORK_PATH`** ayarlanmışsa dyld bu directory'lerde arama yapar. Aksi takdirde **`/Library/Frameworks`** (macOS'ta process unrestricted ise) ve ardından **`/System/Library/Frameworks`** içinde arama yapar.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Bir framework path'i söz konusuysa hijack yöntemi şudur:
>
> - Process **unrestricted** ise, **CWD**'den gelen relative path'i ve belirtilen env variable'ları abuse etmek (process restricted ise `DYLD\_\*` env variable'larının kaldırıldığı docs'ta belirtilmese bile geçerlidir)

- Path **slash içeriyor ancak framework path'i değilse** (yani bir dylib'e giden full path veya partial path ise), dlopen() önce (ayarlanmışsa) **`$DYLD_LIBRARY_PATH`** içinde arama yapar (path'ten leaf part alınır). Ardından dyld sağlanan path'i dener (relative path'ler için current working directory kullanılır; ancak yalnızca unrestricted process'ler için). Son olarak eski binary'ler için dyld fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlanmışsa dyld bu directory'lerde arama yapar; aksi takdirde dyld **`/usr/local/lib/`** (process unrestricted ise) ve ardından **`/usr/lib/`** içinde arama yapar.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Name içinde slash varsa ve bu bir framework değilse hijack yöntemi şudur:
>
> - Binary **unrestricted** ise CWD'den veya `/usr/local/lib`'den bir şey yüklemek (ya da belirtilen env variable'lardan birini abuse etmek)

> [!TIP]
> Not: **dlopen aramasını kontrol etmek için configuration file yoktur**.
>
> Not: Main executable bir **set\[ug]id binary** ise veya entitlement'larla codesign edilmişse, **tüm environment variable'lar yok sayılır** ve yalnızca full path kullanılabilir ([daha ayrıntılı bilgi için DYLD_INSERT_LIBRARIES restrictions'ını kontrol edin](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions))
>
> Not: Apple platform'ları 32-bit ve 64-bit library'leri birleştirmek için "universal" file'lar kullanır. Bu nedenle ayrı 32-bit ve 64-bit search path'leri yoktur.
>
> Not: Apple platform'larında çoğu OS dylib'i **dyld cache** içine birleştirilir ve diskte bulunmaz. Bu nedenle bir OS dylib'inin mevcut olup olmadığını önceden kontrol etmek için **`stat()`** çağırmak işe yaramaz. Ancak **`dlopen_preflight()`**, uyumlu bir mach-o file bulmak için **`dlopen()`** ile aynı adımları kullanır.

**Check paths**

Aşağıdaki code ile tüm seçenekleri kontrol edelim:
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
Derleyip çalıştırırsanız **her bir library'nin nerede başarısız bir şekilde arandığını** görebilirsiniz. Ayrıca **FS log'larını filtreleyebilirsiniz**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Bir **privileged binary/app** (SUID veya güçlü entitlements içeren herhangi bir binary gibi) **relative path** üzerinden bir library yüklüyorsa (örneğin `@executable_path` veya `@loader_path` kullanarak) ve **Library Validation** devre dışıysa, binary'yi attacker'ın relative path üzerinden yüklenen library'yi **modify** edebileceği bir konuma taşımak ve bunu process'e code inject etmek için abuse etmek mümkün olabilir.

## `DYLD_*` env variables'ını ayıklama

Daha eski `dyld` sürümleri (`dyld2.cpp`) bu kararı process içinde `issetugid()`, `hasRestrictedSegment()` ve `csops(CS_OPS_STATUS)` ile veriyordu. **Güncel `dyld` sürümlerinde karar AMFI'ye devredilmiştir** ve kod `dyld/DyldProcessConfig.cpp` içindeki `ProcessConfig::Security::Security()` bölümünde yer alır:<sup>[[1]](#references)</sup>
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
Bundan çıkarılmaya değer iki nokta var:

- **macOS / Mac Catalyst / DriverKit** üzerinde ve yalnızca AMFI `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache` değerlerinin hiçbirine izin vermediğinde pruning gerçekleşir.
- AMFI query, executable'ın kendi özellikleriyle beslenir:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
burada `isRestricted()`, tam olarak `__RESTRICT` segmenti kontrolüdür (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` ardından adı `DYLD_` ile başlayan **her** değişkeni kaldırır ve `apple[]` parametrelerini aşağı kaydırır; böylece kısıtlı bir process'in child process'leri de bunları devralmaz:
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
> Pratik sonuç: **`DYLD_*`, işlem kısıtlandığında temizlenir** — setuid/setgid, bir `__RESTRICT/__restrict` bölümü veya AMFI'nin path/print flag'lerini vermeyi reddettiği hardened-runtime/entitled binary'ler nedeniyle. İşlemde yalnızca **library validation** (`CS_REQUIRE_LV`) varsa değişkenler korunur; ancak eklenen dylib'in **aynı Team ID** tarafından (veya Apple tarafından) imzalanmış olması gerekir. Bu nedenle kodun gerçekten yüklenmesi için library-validation'ı devre dışı bırakan entitlement'lerden birine ihtiyacınız vardır.

Karar artık AMFI'ye ait olduğundan, belirli bir binary'nin ne alacağını öğrenmenin en hızlı yolu `dyld`'in kendisine bakmak yerine AMFI'nin dayandığı unsurları — entitlement'leri ve signing flag'lerini — incelemektir:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## Kısıtlamaları Kontrol Et

### SUID ve SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### `__restrict` segmentine sahip `__RESTRICT` bölümü
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Keychain'de yeni bir sertifika oluşturun ve binary'yi imzalamak için bunu kullanın:
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
> `**0x0(none)**` flags ile imzalanmış binary'ler olsa bile, çalıştırıldıklarında dinamik olarak **`CS_RESTRICT`** flag'ini alabilirler; bu nedenle bu technique bunlarda çalışmaz.
>
> Bir proc'un bu flag'e sahip olup olmadığını şu şekilde kontrol edebilirsiniz ([**csops buradan**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> ardından 0x800 flag'inin etkin olup olmadığını kontrol edin.

## Referanslar

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (process startup and library insertion)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
