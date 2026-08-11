# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld kodu açık kaynaklıdır** ve [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) adresinde bulunabilir ve **[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) gibi bir URL** kullanılarak tar olarak indirilebilir.

## **Dyld Process**

Dyld'in binary'ler içindeki library'leri nasıl yüklediğine göz atın:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Bu, [**Linux'taki LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload) gibidir. Çalıştırılacak bir process'in bir path'ten belirli bir library'yi yüklemesini belirtmeye olanak tanır (env var etkinse)<sup>[[4]](#references)</sup>

Bu teknik, **ASEP tekniği olarak da kullanılabilir**; çünkü yüklenen her application, `LSEnvironmental` adlı bir key kullanarak **environmental variable'ların atanmasına** olanak tanıyan "Info.plist" adlı bir plist'e sahiptir.

> [!TIP]
> 2012'den beri **Apple, `DYLD_INSERT_LIBRARIES`'ın gücünü büyük ölçüde azaltmıştır**. Aşağıdakilerden herhangi biri geçerli olduğunda bir process **restricted** olarak kabul edilir — ve ardından `dyld` ortamındaki tüm `DYLD_*` variable'larını siler:
>
> - Binary `setuid/setgid`'dir
> - Mach-O, bir **`__RESTRICT/__restrict`** section'ına sahiptir
> - Binary hardened runtime ile imzalanmıştır ve AMFI ona "path/print variables" permission'larını vermemiştir; yani [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup> entitlement'ından yoksundur
>   - Bir binary'nin **entitlements** bilgilerini şu komutla kontrol edin: `codesign -dv --entitlements :- </path/to/bin>`
>
> Güncel `dyld` içinde bu durum artık yalnızca `dyld` tarafından belirlenmez: `ProcessConfig::Security::Security()`, `amfi_check_dyld_policy_self()` aracılığıyla **AMFI**'ye sorar ve ardından `pruneEnvVars()` çağrısını yapar. Kesin kod akışı aşağıda [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) bölümünde açıklanmıştır.

### Library Validation

Binary **`DYLD_INSERT_LIBRARIES`** environment variable'ına izin verse bile library'nin signature'ını doğruluyorsa custom bir library yüklemez.

Custom bir library yüklemek için binary aşağıdaki **entitlements**'lardan **birine** sahip olmalıdır:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

veya binary'de **hardened runtime flag'i** ya da **library validation flag'i** bulunmamalıdır.

Bir binary'de **hardened runtime** olup olmadığını `codesign --display --verbose <bin>` ile, **`CodeDirectory`** içindeki runtime flag'ini kontrol ederek anlayabilirsiniz; örneğin: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Ayrıca bir library, **binary ile aynı certificate kullanılarak imzalanmışsa** da yüklenebilir.

Bunun nasıl (kötüye) kullanılacağına ve restriction'ların nasıl kontrol edileceğine dair bir örneği burada bulabilirsiniz:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> **Önceki Library Validation restriction'larının**, Dylib hijacking saldırıları gerçekleştirilirken de geçerli olduğunu unutmayın.

Windows'ta olduğu gibi MacOS'ta da **dylib'leri hijack ederek** **application'ların** **arbitrary** **code** çalıştırmasını sağlayabilirsiniz (aslında normal bir user için bu mümkün olmayabilir; çünkü bir `.app` bundle'ı içine yazmak ve bir library'yi hijack etmek için TCC permission'ı gerekebilir).\
Ancak **MacOS** application'larının library'leri **yükleme** biçimi Windows'a göre **daha restricted**'dır. Bu, **malware** geliştiricilerinin bu tekniği hâlâ **stealth** amacıyla kullanabileceği, ancak bunu privilege escalation için **kötüye kullanabilme olasılığının çok daha düşük** olduğu anlamına gelir.

İlk olarak, **MacOS binary'lerinin**, yüklenecek library'lerin tam path'ini belirttiği durumla karşılaşmak **daha yaygındır**. İkinci olarak, **MacOS library'ler için** hiçbir zaman **$PATH** klasörlerinde arama yapmaz.

Bu işlevsellikle ilgili **code**'un **ana** bölümü `ImageLoader.cpp` içindeki **`ImageLoader::recursiveLoadLibraries`** içerisindedir.

Bir macho binary'sinin library yüklemek için kullanabileceği **4 farklı header Command** vardır:

- **`LC_LOAD_DYLIB`** command'i bir dylib yüklemek için kullanılan yaygın command'dir.
- **`LC_LOAD_WEAK_DYLIB`** command'i önceki gibi çalışır, ancak dylib bulunamazsa execution herhangi bir error olmadan devam eder.
- **`LC_REEXPORT_DYLIB`** command'i farklı bir library'deki symbol'leri proxy'ler (veya yeniden export eder).
- **`LC_LOAD_UPWARD_DYLIB`** command'i iki library birbirine bağımlı olduğunda kullanılır (buna _upward dependency_ adı verilir).

Bununla birlikte, **2 tür dylib hijacking** vardır:

- **Missing weak linked libraries**: Bu, application'ın **LC_LOAD_WEAK_DYLIB** ile yapılandırılmış ve mevcut olmayan bir library'yi yüklemeye çalışacağı anlamına gelir. Ardından, **bir attacker beklenen yere bir dylib yerleştirirse bu dylib yüklenir**.
- Link'in **"weak"** olması, library bulunamasa bile application'ın çalışmaya devam edeceği anlamına gelir.
- Bununla **ilgili code**, `ImageLoader.cpp` dosyasındaki `ImageLoaderMachO::doGetDependentLibraries` function'ındadır; burada `LC_LOAD_WEAK_DYLIB` true olduğunda `lib->required` yalnızca `false` olur.
- Binary'lerdeki **weak linked libraries**'leri şu komutla bulun (daha sonra hijacking library'lerinin nasıl oluşturulacağına dair bir örnek bulunmaktadır):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpath ile yapılandırılmış**: Mach-O binary'leri **`LC_RPATH`** ve **`LC_LOAD_DYLIB`** command'lerine sahip olabilir. Bu command'lerin **değerlerine** bağlı olarak **library'ler** **farklı directory'lerden** yüklenir.
- **`LC_RPATH`**, binary tarafından library yüklemek için kullanılan bazı klasörlerin path'lerini içerir.
- **`LC_LOAD_DYLIB`**, yüklenecek belirli library'lerin path'ini içerir. Bu path'ler, **`LC_RPATH`** içindeki değerlerle değiştirilecek olan **`@rpath`** ifadesini içerebilir. **`LC_RPATH`** içinde birden fazla path varsa library'yi aramak için hepsi kullanılır. Örnek:
- **`LC_LOAD_DYLIB`** `@rpath/library.dylib` içeriyor ve **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` ile `/application/app.app/Contents/Framework/v2/` içeriyorsa, her iki klasör de `library.dylib`'yi yüklemek için kullanılır**.** Library `[...]/v1/` içinde mevcut değilse ve attacker buraya bir library yerleştirebiliyorsa, **`LC_LOAD_DYLIB`** içindeki path sırası takip edildiğinden `[...]/v2/` içindeki library'nin load edilmesini hijack edebilir.
- Binary'lerdeki **rpath path'lerini ve library'leri** şu komutla bulun: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file'ı** içeren directory'nin **path'idir**.
>
> **`@loader_path`**: load command'i içeren **Mach-O binary'sini** barındıran **directory'nin** **path'idir**.
>
> - Bir executable içinde kullanıldığında **`@loader_path`**, işlevsel olarak **`@executable_path`** ile aynıdır.
> - Bir **dylib** içinde kullanıldığında **`@loader_path`**, **dylib'in** **path'ini** verir.

Bu işlevselliği kullanarak privilege escalation gerçekleştirmenin yolu, **root tarafından** çalıştırılan bir **application'ın**, attacker'ın yazma permission'ına sahip olduğu bir klasörde bir **library aradığı** nadir durumdur.

> [!TIP]
> Application'lardaki **missing libraries**'leri bulmak için iyi bir **scanner**, [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) veya bir [**CLI version**](https://github.com/pandazheng/DylibHijack)'dır.\
> Bu teknik hakkında teknik ayrıntıları içeren iyi bir [**rapor**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) **burada** bulunabilir.

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> **Önceki Library Validation restriction'larının**, Dlopen hijacking saldırıları gerçekleştirilirken de geçerli olduğunu unutmayın.

**`man dlopen`** çıktısından:

- Path **slash character içermediğinde** (yani yalnızca bir leaf name olduğunda), **dlopen() arama yapar**. Launch sırasında **`$DYLD_LIBRARY_PATH`** ayarlanmışsa dyld önce bu directory'ye **bakar**. Ardından, çağıran mach-o file veya main executable bir **`LC_RPATH`** belirtiyorsa dyld bu directory'lere **bakar**. Sonra process **unrestricted** ise dyld current working directory'de arama yapar. Son olarak, eski binary'ler için dyld bazı fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlanmışsa dyld bu **directory'lerde** arama yapar; aksi takdirde dyld (process unrestricted ise) **`/usr/local/lib/`** içinde, ardından **`/usr/lib/`** içinde arama yapar (bu bilgi **`man dlopen`**'dan alınmıştır).
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
> - Binary **unrestricted** ise ve CWD'den bir şey yüklemek mümkünse (veya belirtilen env variable'larından biri kötüye kullanılırsa)

- Path **framework** path'i gibi görünüyorsa (ör. `/stuff/foo.framework/foo`), launch sırasında **`$DYLD_FRAMEWORK_PATH`** ayarlanmışsa dyld önce bu directory'de **framework partial path**'ini (ör. `foo.framework/foo`) arar. Sonra dyld **sağlanan path'i olduğu gibi** dener (relative path'ler için current working directory'yi kullanarak). Son olarak, eski binary'ler için dyld bazı fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_FRAMEWORK_PATH`** ayarlanmışsa dyld bu directory'lerde arama yapar. Aksi takdirde önce **`/Library/Frameworks`** (process unrestricted ise macOS'ta), ardından **`/System/Library/Frameworks`** içinde arama yapar.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Bir framework path'i varsa bunu hijack etmenin yolu:
>
> - Process **unrestricted** ise, CWD'den gelen relative path'i ve belirtilen env variable'larını kötüye kullanmak (process restricted ise DYLD\_\* env variable'larının kaldırıldığı docs'ta belirtilmemiş olsa bile)

- Path **slash içeriyor ancak framework path'i değilse** (yani bir dylib'e giden full path veya partial path ise), `dlopen()` önce (ayarlanmışsa) **`$DYLD_LIBRARY_PATH`** içinde path'in leaf kısmını kullanarak arama yapar. Ardından dyld **sağlanan path'i** dener (relative path'ler için current working directory'yi kullanır; ancak yalnızca unrestricted process'ler için). Son olarak, daha eski binary'ler için dyld fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlanmışsa dyld bu directory'lerde arama yapar; aksi takdirde dyld (process unrestricted ise) **`/usr/local/lib/`** içinde, ardından **`/usr/lib/`** içinde arama yapar.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Name içinde slash varsa ve bu bir framework değilse hijack etmenin yolu:
>
> - Binary **unrestricted** ise CWD'den veya `/usr/local/lib`'den bir şey yüklemek (ya da belirtilen env variable'larından birini kötüye kullanmak)

> [!TIP]
> Not: **dlopen aramasını kontrol etmek** için **configuration file bulunmaz**.
>
> Not: Main executable bir **set\[ug]id binary** ise veya entitlements ile codesign edilmişse, **tüm environment variable'ları yok sayılır** ve yalnızca full path kullanılabilir ([daha ayrıntılı bilgi için DYLD_INSERT_LIBRARIES restriction'larını kontrol edin](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions))
>
> Not: Apple platformları 32-bit ve 64-bit library'leri birleştirmek için "universal" file'lar kullanır. Bu, **ayrı 32-bit ve 64-bit search path'lerinin bulunmadığı** anlamına gelir.
>
> Not: Apple platformlarında çoğu OS dylib'i **dyld cache** içinde birleştirilir ve diskte mevcut olmaz. Bu nedenle, bir OS dylib'inin mevcut olup olmadığını önceden kontrol etmek için **`stat()`** çağrısı yapmak **çalışmaz**. Ancak **`dlopen_preflight()`**, uyumlu bir mach-o file'ı bulmak için **`dlopen()`** ile aynı adımları kullanır.

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
Derleyip çalıştırırsanız **her kütüphanenin nerede başarısız bir şekilde arandığını görebilirsiniz**. Ayrıca **FS loglarını filtreleyebilirsiniz**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Eğer bir **privileged binary/app** (örneğin bir SUID veya güçlü entitlements değerlerine sahip bir binary) **relative path** üzerinden bir library yüklüyorsa (örneğin `@executable_path` veya `@loader_path` kullanarak) ve **Library Validation** devre dışıysa, binary'yi saldırganın **relative path** üzerinden yüklenen library'yi **değiştirebileceği** bir konuma taşımak ve bunu process'e code inject etmek için kötüye kullanmak mümkün olabilir.

## `DYLD_*` env değişkenlerini budama

Daha eski `dyld` sürümleri (`dyld2.cpp`) bu kararı process içinde `issetugid()`, `hasRestrictedSegment()` ve `csops(CS_OPS_STATUS)` ile veriyordu. **Güncel `dyld` sürümünde karar AMFI'ye devredilmiştir** ve kod `dyld/DyldProcessConfig.cpp` içindeki `ProcessConfig::Security::Security()` bölümünde yer alır:<sup>[[1]](#references)</sup>
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
Bundan çıkarılması gereken iki nokta var:

- Pruning yalnızca **macOS / Mac Catalyst / DriverKit** üzerinde gerçekleşir — ve yalnızca AMFI, `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache` izinlerinin hiçbirini vermediğinde.
- AMFI sorgusuna executable'ın kendi özellikleri aktarılır:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
burada `isRestricted()`, (`mach_o/UnsafeHeader.cpp`) içindeki `__RESTRICT` segment denetimidir:<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` ardından adı `DYLD_` ile başlayan **her** değişkeni çıkarır ve `apple[]` parametrelerini aşağı kaydırır; böylece kısıtlı bir sürecin alt süreçleri de bunları devralmaz:
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
> Pratik sonuç: **`DYLD_*`, process kısıtlandığında ayıklanır** — setuid/setgid, bir `__RESTRICT/__restrict` bölümü veya AMFI'nin path/print flags vermeyi reddettiği hardened-runtime/entitled binary'ler. Bunun yerine process yalnızca **library validation** (`CS_REQUIRE_LV`) özelliğine sahipse değişkenler korunur; ancak eklenen dylib'in **aynı Team ID** tarafından (veya Apple tarafından) imzalanmış olması gerekir. Bu nedenle kodun gerçekten yüklenebilmesi için library validation'ı devre dışı bırakan entitlement'lerden birine ihtiyaç duyarsınız.

Karar artık AMFI'ye ait olduğundan, belirli bir binary'nin ne alacağını öğrenmenin en hızlı yolu `dyld`'e değil, AMFI'nin dayandığı unsurlara — entitlements ve signing flags — bakmaktır:
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
### Section `__RESTRICT` with segment `__restrict`
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
> İmzalanmış binary'lerde **`0x0(none)`** flag'leri olsa bile, çalıştırıldıklarında dinamik olarak **`CS_RESTRICT`** flag'ini alabileceklerini ve bu nedenle bu tekniğin bunlarda çalışmayacağını unutmayın.
>
> Bir proc'un bu flag'e sahip olup olmadığını şununla kontrol edebilirsiniz ([**csops burada**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> ardından 0x800 flag'inin etkin olup olmadığını kontrol edin.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` kontrolü)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (process başlangıcı ve library ekleme)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
