# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld** kodu open source'tur ve [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) adresinde bulunabilir ve [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) gibi bir **URL kullanılarak** tar olarak indirilebilir.

## **Dyld Process**

Dyld'in binary'lerin içindeki library'leri nasıl yüklediğine göz atın:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Bu, [**Linux'taki LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload) gibidir. Çalıştırılacak bir process'in, bir path'teki belirli bir library'yi yüklemesini belirtmeye olanak tanır (env var etkinse)<sup>[[4]](#references)</sup>

Bu technique ayrıca **ASEP technique olarak da kullanılabilir**, çünkü kurulu her application, `LSEnvironmental` adlı bir key kullanarak **environmental variable'ların atanmasına** izin veren "Info.plist" adlı bir plist'e sahiptir.

> [!TIP]
> **Apple, 2012'den beri** **`DYLD_INSERT_LIBRARIES`**'ın gücünü **büyük ölçüde azalttı**. Aşağıdakilerden herhangi biri geçerli olduğunda bir process **restricted** olarak kabul edilir — ve ardından `dyld`, tüm `DYLD_*` variable'larını environment'ından siler:
>
> - Binary `setuid/setgid`'dir
> - Mach-O'da bir **`__RESTRICT/__restrict`** section'ı vardır
> - Binary hardened runtime ile imzalanmıştır ve AMFI ona "path/print variables" izinlerini vermemektedir; yani [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) eksiktir<sup>[[3]](#references)</sup>
>   - Bir binary'nin **entitlements** bilgisini şu komutla kontrol edin: `codesign -dv --entitlements :- </path/to/bin>`
>
> Güncel `dyld` sürümlerinde buna artık yalnızca `dyld` karar vermez: `ProcessConfig::Security::Security()`, `amfi_check_dyld_policy_self()` aracılığıyla **AMFI'ye** danışır ve ardından `pruneEnvVars()` fonksiyonunu çağırır. Bununla ilgili kodun tamamı aşağıdaki [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) bölümünde açıklanmıştır.

### Library Validation

Binary **`DYLD_INSERT_LIBRARIES`** environment variable'ına izin verse bile library'nin signature'ını doğruluyorsa custom bir library yüklemez.

Custom bir library yüklemek için binary'nin aşağıdaki entitlement'lerden **birine** sahip olması gerekir:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

veya binary'de **hardened runtime flag'i** ya da **library validation flag'i** bulunmamalıdır.

Bir binary'de **hardened runtime** olup olmadığını `codesign --display --verbose <bin>` komutuyla, **`CodeDirectory`** içindeki runtime flag'ini kontrol ederek anlayabilirsiniz; örneğin: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Ayrıca bir library, binary ile aynı certificate ile imzalanmışsa da yüklenebilir.

Bunun nasıl (kötüye) kullanılacağına ve restriction'ların nasıl kontrol edileceğine dair bir örneği burada bulabilirsiniz:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> **Önceki Library Validation restriction'larının**, Dylib hijacking saldırılarını gerçekleştirmek için de geçerli olduğunu unutmayın.

Windows'ta olduğu gibi macOS'ta da **dylib'leri hijack ederek** **application'ların arbitrary code çalıştırmasını** sağlayabilirsiniz. Normal bir user account'undan bu mümkün olmayabilir; çünkü bir library'yi hijack etmek için `.app` bundle'ının içine yazmak bir TCC izni gerektirebilir.\
Ancak **macOS** application'larının library'leri **yükleme şekli**, Windows'a kıyasla **daha restricted**'dır. Malware developer'ları bu technique'i hâlâ **stealth** amacıyla kullanabilir, ancak privilege escalation için kötüye kullanılması çok daha düşük bir ihtimaldir.

İlk olarak, **MacOS binary'lerinin yüklenecek library'lerin full path'ini belirttiğini** görmek **daha yaygındır**. İkinci olarak, **MacOS library'ler için** `$PATH` klasörlerinde **asla arama yapmaz**.

Bu işlevsellikle ilgili **code**'un **ana** kısmı `ImageLoader.cpp` içindeki **`ImageLoader::recursiveLoadLibraries`** içerisindedir.

Bir macho binary'nin library yüklemek için kullanabileceği **4 farklı header Command** vardır:

- **`LC_LOAD_DYLIB`** command, bir dylib yüklemek için kullanılan yaygın command'dır.
- **`LC_LOAD_WEAK_DYLIB`** command, önceki gibi çalışır; ancak dylib bulunamazsa execution herhangi bir error olmadan devam eder.
- **`LC_REEXPORT_DYLIB`** command, farklı bir library'deki symbol'leri proxy'ler (veya yeniden export eder).
- **`LC_LOAD_UPWARD_DYLIB`** command, iki library birbirine bağlı olduğunda kullanılır (buna _upward dependency_ denir).

Bununla birlikte, **2 tür dylib hijacking** vardır:

- **Missing weak linked libraries**: Bu, application'ın **LC_LOAD_WEAK_DYLIB** ile yapılandırılmış ve mevcut olmayan bir library'yi yüklemeye çalışacağı anlamına gelir. Ardından, **bir attacker beklenen yere bir dylib yerleştirirse bu library yüklenir**.
- Link'in "weak" olması, library bulunamasa bile application'ın çalışmaya devam edeceği anlamına gelir.
- Bununla **ilgili code**, `ImageLoader.cpp` içindeki `ImageLoaderMachO::doGetDependentLibraries` function'ındadır; burada `lib->required`, yalnızca `LC_LOAD_WEAK_DYLIB` true olduğunda `false` olur.
- Binary'lerde **weak linked libraries**'yi şu komutla bulun (aşağıda hijacking library'lerinin nasıl oluşturulacağına dair bir örnek bulunmaktadır):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpath ile yapılandırılmış**: Mach-O binary'leri **`LC_RPATH`** ve **`LC_LOAD_DYLIB`** command'larına sahip olabilir. Bu command'ların **değerlerine** göre **library'ler** farklı directory'lerden **yüklenecektir**.
- **`LC_RPATH`**, binary tarafından library yüklemek için kullanılan bazı folder'ların path'lerini içerir.
- **`LC_LOAD_DYLIB`**, yüklenecek belirli library'lerin path'ini içerir. Bu path'ler, **`LC_RPATH`** içindeki değerlerle **değiştirilecek** olan **`@rpath`** içerebilir. **`LC_RPATH`** içinde birden fazla path varsa library'yi aramak için her biri kullanılır. Örnek:
- **`LC_LOAD_DYLIB`** `@rpath/library.dylib` içeriyor ve **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` ile `/application/app.app/Contents/Framework/v2/` içeriyorsa, her iki folder da `library.dylib`'yi yüklemek için kullanılacaktır**.** Library `[...]/v1/` içinde mevcut değilse ve attacker onu buraya yerleştirebiliyorsa, **`LC_LOAD_DYLIB`** içindeki path sırasına uyulduğundan `[...]/v2/` içindeki library'nin yüklenmesini hijack edebilir.
- Binary'lerde **rpath path'lerini ve library'leri** şu komutla bulun: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file'ı** içeren directory'nin **path'idir**.
>
> **`@loader_path`**: load command'ı içeren **Mach-O binary'sini** barındıran **directory'nin path'idir**.
>
> - Bir executable içinde kullanıldığında **`@loader_path`**, işlevsel olarak **`@executable_path`** ile aynıdır.
> - Bir **dylib** içinde kullanıldığında **`@loader_path`**, **dylib'in path'ini** verir.

Bu işlevselliği kötüye kullanarak **privilege escalation** gerçekleştirmenin yolu, **root tarafından çalıştırılan** bir **application'ın**, attacker'ın write permission'ına sahip olduğu bir folder'da **bir library aradığı** nadir durum olacaktır.

> [!TIP]
> Application'larda **missing library'leri** bulmak için iyi bir **scanner**, [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) veya bunun bir [**CLI version**'ıdır](https://github.com/pandazheng/DylibHijack).\
> Bu technique hakkında technical details içeren iyi bir [**report**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) bulabilirsiniz.

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> **Önceki Library Validation restriction'larının**, Dlopen hijacking saldırılarını gerçekleştirmek için de geçerli olduğunu unutmayın.

**`man dlopen`** sayfasından:

- Path **slash karakteri içermediğinde** (yani yalnızca bir leaf name olduğunda), **dlopen() arama yapar**. Launch sırasında **`$DYLD_LIBRARY_PATH`** ayarlanmışsa dyld önce bu director**y** içinde arama yapar. Ardından, çağıran mach-o file veya main executable bir **`LC_RPATH`** belirtiyorsa dyld bu directory'lerde arama yapar. Sonra process **unrestricted** ise dyld current working directory içinde arama yapar. Son olarak, old binary'ler için dyld bazı fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlanmışsa dyld bu **directory'lerde** arama yapar; aksi takdirde dyld **`/usr/local/lib/`** içinde (process unrestricted ise), ardından **`/usr/lib/`** içinde arama yapar (bu bilgi **`man dlopen`** sayfasından alınmıştır).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> İsimde slash yoksa hijacking yapmanın 2 yolu vardır:
>
> - Herhangi bir **`LC_RPATH`** **writable** ise (ancak signature kontrol edilir; bu nedenle binary'nin unrestricted olması da gerekir)
> - Binary **unrestricted** ise ve böylece CWD'den bir şey yüklemek mümkünse (veya belirtilen env variable'lardan biri kötüye kullanılırsa)

- Path **framework** path'i gibi göründüğünde (örneğin `/stuff/foo.framework/foo`), launch sırasında **`$DYLD_FRAMEWORK_PATH`** ayarlanmışsa dyld önce framework partial path'i (`foo.framework/foo` gibi) bu directory'de arar. Ardından dyld verilen path'i olduğu gibi dener (relative path'ler için current working directory kullanılır). Son olarak, old binary'ler için dyld bazı fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_FRAMEWORK_PATH`** ayarlanmışsa dyld bu directory'lerde arama yapar. Aksi takdirde önce **`/Library/Frameworks`** içinde (macOS'ta process unrestricted ise), ardından **`/System/Library/Frameworks`** içinde arama yapar.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Bir framework path'i varsa onu hijack etmenin yolu şu olacaktır:
>
> - Process **unrestricted** ise, CWD'den gelen **relative path'i** ve belirtilen env variable'ları kötüye kullanmak (process restricted ise DYLD\_\* env variable'larının kaldırıldığı documentation'da belirtilmese bile)

- Path **slash içeriyor ancak framework path'i değilse** (yani bir dylib'e giden full path veya partial path ise), `dlopen()` önce (ayarlanmışsa) **`$DYLD_LIBRARY_PATH`** içinde arama yapar (path'teki leaf part ile). Ardından dyld verilen path'i dener (relative path'ler için current working directory kullanılır; ancak yalnızca unrestricted process'ler için). Son olarak, older binary'ler için dyld fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlanmışsa dyld bu directory'lerde arama yapar; aksi takdirde dyld **`/usr/local/lib/`** içinde (process unrestricted ise), ardından **`/usr/lib/`** içinde arama yapar.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> İsimde slash varsa ve bu bir framework değilse, onu hijack etmenin yolu şu olacaktır:
>
> - Binary **unrestricted** ise ve böylece CWD'den veya `/usr/local/lib` içinden bir şey yüklemek mümkünse (ya da belirtilen env variable'lardan biri kötüye kullanılırsa)

> [!TIP]
> Not: **dlopen aramasını kontrol etmek** için herhangi bir configuration file yoktur.
>
> Not: Main executable bir **set\[ug]id binary'si** ise veya entitlements ile codesigned edilmişse, **tüm environment variable'lar yok sayılır** ve yalnızca full path kullanılabilir ([daha ayrıntılı bilgi için DYLD_INSERT_LIBRARIES restriction'larını kontrol edin](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions))
>
> Not: Apple platform'ları, 32-bit ve 64-bit library'leri birleştirmek için "universal" file'lar kullanır. Bu, ayrı 32-bit ve 64-bit search path'leri olmadığı anlamına gelir.
>
> Not: Apple platform'larında çoğu OS dylib'i **dyld cache** içinde birleştirilir ve disk üzerinde bulunmaz. Bu nedenle bir OS dylib'inin mevcut olup olmadığını önceden kontrol etmek için **`stat()`** çağırmak **çalışmaz**. Ancak **`dlopen_preflight()`**, uyumlu bir mach-o file bulmak için **`dlopen()`** ile aynı adımları kullanır.

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
Derleyip çalıştırırsanız, **her kütüphanenin nerede başarısız şekilde arandığını** görebilirsiniz. Ayrıca **FS loglarını filtreleyebilirsiniz**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Bir **privileged binary/app** (SUID veya güçlü entitlements'lara sahip bir binary gibi) **relative path** bir library yüklüyorsa (örneğin `@executable_path` veya `@loader_path` kullanarak) ve **Library Validation** devre dışı bırakılmışsa, binary'yi attacker'ın **relative path** ile yüklenen library'yi **modify** edebileceği bir konuma taşımak ve bunu process'e code inject etmek için abuse etmek mümkün olabilir.

## `DYLD_*` env değişkenlerini ayıklama

Daha eski `dyld` sürümleri (`dyld2.cpp`) bu kararı `issetugid()`, `hasRestrictedSegment()` ve `csops(CS_OPS_STATUS)` kullanarak process içinde veriyordu. **Güncel `dyld` sürümlerinde karar AMFI'ye devredilir** ve kod `dyld/DyldProcessConfig.cpp` içindeki `ProcessConfig::Security::Security()` bölümünde bulunur:<sup>[[1]](#references)</sup>
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
Bundan çıkarılmaya değer iki nokta vardır:

- Pruning yalnızca **macOS / Mac Catalyst / DriverKit** üzerinde gerçekleşir — ayrıca yalnızca AMFI, `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache` seçeneklerinin hiçbirine izin vermediğinde.
- AMFI sorgusuna çalıştırılabilir dosyanın kendi özellikleri aktarılır:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
burada `isRestricted()`, kelimesi kelimesine `__RESTRICT` segment kontrolüdür (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` ardından adı `DYLD_` ile başlayan **her** değişkeni kaldırır ve `apple[]` parametrelerini aşağı kaydırır; böylece kısıtlı bir sürecin alt süreçleri de bunları devralmaz:
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
> Pratik sonuç: **`DYLD_*`, process kısıtlandığında temizlenir** — setuid/setgid, bir `__RESTRICT/__restrict` section'ı veya AMFI'nin path/print flag'lerini vermeyi reddettiği hardened-runtime/entitled binary'ler nedeniyle. Bunun yerine process yalnızca **library validation** (`CS_REQUIRE_LV`) özelliğine sahipse değişkenler korunur; ancak eklenen dylib'in **aynı Team ID** tarafından (veya Apple tarafından) imzalanmış olması gerekir. Bu nedenle kodun gerçekten yüklenebilmesi için library validation'ı devre dışı bırakan entitlement'lerden birine ihtiyacınız vardır.

Karar artık AMFI tarafından verildiğinden, belirli bir binary'nin ne alacağını öğrenmenin en hızlı yolu `dyld`'in kendisine değil, AMFI'nin dayandığı değerlere — entitlement'lere ve signing flag'lerine — bakmaktır:
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
> `**0x0(none)**` flag'leriyle imzalanmış binary'ler olsa bile, çalıştırıldıklarında dinamik olarak **`CS_RESTRICT`** flag'ini alabilirler; bu nedenle bu teknik bunlarda çalışmaz.
>
> Bir proc'un bu flag'e sahip olup olmadığını ([**csops here**](https://github.com/axelexic/CSOps)) kullanarak kontrol edebilirsiniz:
>
> ```bash
> csops -status <pid>
> ```
>
> ardından 0x800 flag'inin etkin olup olmadığını kontrol edin.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (process başlatma ve library ekleme)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
