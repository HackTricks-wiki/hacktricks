# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld kodu open source** olup [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) adresinde bulunabilir ve [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) gibi bir **URL** kullanılarak tar olarak indirilebilir.

## **Dyld Process**

Dyld'in binary'ler içindeki library'leri nasıl yüklediğine şuradan göz atın:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Bu, [**Linux'taki LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload) gibidir. Çalıştırılacak bir process'in, bir path'ten belirli bir library'yi yüklemesini belirtmeye olanak tanır (env var etkinse).

Bu teknik, **ASEP tekniği olarak da kullanılabilir**; çünkü yüklenen her application, `LSEnvironmental` adlı bir key kullanarak **environmental variable'ların atanmasına** olanak tanıyan "Info.plist" adlı bir plist'e sahiptir.

> [!TIP]
> 2012'den beri **Apple, `DYLD_INSERT_LIBRARIES`'in gücünü büyük ölçüde azaltmıştır**. Aşağıdakilerden herhangi biri geçerli olduğunda bir process **restricted** kabul edilir — ve ardından `dyld` tüm `DYLD_*` variable'larını environment'ından siler:
>
> - Binary `setuid/setgid`'dir.
> - Mach-O, **`__RESTRICT/__restrict`** section'ına sahiptir.
> - Binary hardened runtime ile imzalanmıştır ve AMFI ona "path/print variables" izinlerini vermemiştir; yani [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup> eksiktir.
>   - Bir binary'nin **entitlements** bilgisini şu komutla kontrol edin: `codesign -dv --entitlements :- </path/to/bin>`
>
> Güncel `dyld` içinde bu karar artık yalnızca `dyld` tarafından verilmez: `ProcessConfig::Security::Security()`, `amfi_check_dyld_policy_self()` aracılığıyla **AMFI**'ye danışır ve ardından `pruneEnvVars()` çağrısını yapar. Kesin kod akışı aşağıda [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) bölümünde açıklanmıştır.

### Library Validation

Binary, **`DYLD_INSERT_LIBRARIES`** env variable'ının kullanımına izin verse bile, yüklenecek library'nin signature'ını kontrol ediyorsa custom bir library yüklemez.

Custom bir library yüklemek için binary'nin aşağıdaki entitlements'lardan **birine** sahip olması gerekir:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

veya binary'de **hardened runtime flag'i** ya da **library validation flag'i** bulunmamalıdır.

Bir binary'nin **hardened runtime** özelliğine sahip olup olmadığını `codesign --display --verbose <bin>` ile, **`CodeDirectory`** içindeki runtime flag'ini kontrol ederek görebilirsiniz; örneğin: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Bir library'yi, binary ile aynı certificate ile imzalanmışsa da yükleyebilirsiniz.

Bunun nasıl (kötüye) kullanılabileceğine ve kısıtlamaların nasıl kontrol edileceğine dair bir örneği şurada bulabilirsiniz:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Önceki Library Validation kısıtlamalarının Dylib hijacking saldırıları gerçekleştirmek için de geçerli olduğunu unutmayın.

Windows'ta olduğu gibi MacOS'ta da **dylib'leri hijack ederek** **application'ların** **arbitrary** **code** çalıştırmasını sağlayabilirsiniz (aslında normal bir user için bu mümkün olmayabilir; çünkü bir `.app` bundle'ının içine yazmak ve bir library'yi hijack etmek için TCC izni gerekebilir).\
Bununla birlikte **MacOS** application'larının library'leri **yükleme** şekli Windows'a göre **daha kısıtlıdır**. Bu, **malware** geliştiricilerinin bu tekniği **stealth** amacıyla hâlâ kullanabilmesi, ancak bunu privilege escalation için **kötüye kullanma olasılığının çok daha düşük** olması anlamına gelir.

Her şeyden önce, **MacOS binary'lerinin yüklenecek library'lerin full path'ini belirtmesi daha yaygındır**. İkinci olarak, **MacOS library'ler için** hiçbir zaman **$PATH** klasörlerinde arama yapmaz.

Bu işlevle ilgili **code**'un **ana** bölümü `ImageLoader.cpp` içindeki **`ImageLoader::recursiveLoadLibraries`** içerisindedir.

Bir macho binary'nin library yüklemek için kullanabileceği **4 farklı header Command** vardır:

- **`LC_LOAD_DYLIB`** command, bir dylib yüklemek için kullanılan standart command'dir.
- **`LC_LOAD_WEAK_DYLIB`** command öncekiyle aynı şekilde çalışır; ancak dylib bulunamazsa execution herhangi bir error olmadan devam eder.
- **`LC_REEXPORT_DYLIB`** command, farklı bir library'deki symbol'leri proxy'ler (veya yeniden export eder).
- **`LC_LOAD_UPWARD_DYLIB`** command, iki library birbirine bağlı olduğunda kullanılır (buna _upward dependency_ denir).

Bununla birlikte **2 tür dylib hijacking** vardır:

- **Missing weak linked libraries**: Application'ın **LC_LOAD_WEAK_DYLIB** ile yapılandırılmış ve mevcut olmayan bir library'yi yüklemeye çalışacağı anlamına gelir. Ardından, **bir attacker beklenen yere bir dylib yerleştirirse bu dylib yüklenir**.
- Link'in **"weak"** olması, library bulunamasa bile application'ın çalışmaya devam edeceği anlamına gelir.
- Bununla **ilgili code**, `ImageLoader.cpp` içindeki `ImageLoaderMachO::doGetDependentLibraries` function'ındadır; burada `lib->required`, yalnızca `LC_LOAD_WEAK_DYLIB` true olduğunda `false` olur.
- Binary'lerde **weak linked libraries**'yi şu komutla bulun (daha sonra hijacking libraries oluşturma örneği verilmiştir):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpath ile yapılandırılmış**: Mach-O binary'leri **`LC_RPATH`** ve **`LC_LOAD_DYLIB`** command'lerine sahip olabilir. Bu command'lerin **değerlerine** bağlı olarak **library'ler** farklı directory'lerden **yüklenir**.
- **`LC_RPATH`**, binary tarafından library yüklemek için kullanılan bazı folder'ların path'lerini içerir.
- **`LC_LOAD_DYLIB`**, yüklenecek belirli library'lerin path'ini içerir. Bu path'ler, **`LC_RPATH`** değerleriyle değiştirilecek olan **`@rpath`** içerebilir. **`LC_RPATH`** içinde birden fazla path varsa library'yi aramak için hepsi kullanılır. Örnek:
- **`LC_LOAD_DYLIB`** `@rpath/library.dylib` içeriyor ve **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` ile `/application/app.app/Contents/Framework/v2/` içeriyorsa, her iki folder da `library.dylib` yüklenirken kullanılır**.** Library `[...]/v1/` içinde mevcut değilse ve attacker buraya bir library yerleştirebiliyorsa, **`LC_LOAD_DYLIB`** içindeki path sırası takip edildiğinden `[...]/v2/` içindeki library'nin yüklenmesini hijack edebilir.
- Binary'lerde **rpath path'lerini ve library'leri** şu komutla bulun: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file'ı** içeren directory'nin **path'idir**.
>
> **`@loader_path`**: load command'ı içeren **Mach-O binary'sini** içeren **directory'nin path'idir**.
>
> - Bir executable içinde kullanıldığında **`@loader_path`**, pratikte **`@executable_path`** ile aynıdır.
> - Bir **dylib** içinde kullanıldığında **`@loader_path`**, **dylib'nin bulunduğu path'i** verir.

Bu işlevi kötüye kullanarak **privilege escalation** gerçekleştirmenin yolu, **root tarafından çalıştırılan bir application'ın**, attacker'ın write permission'ına sahip olduğu bir folder'da **bir library aradığı nadir durum** olacaktır.

> [!TIP]
> Application'larda **missing libraries** bulmak için iyi bir **scanner**, [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) veya bir [**CLI version**](https://github.com/pandazheng/DylibHijack)'dır.\
> Bu teknik hakkında technical details içeren iyi bir **report** [**burada**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) bulunabilir.

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Önceki Library Validation kısıtlamalarının Dlopen hijacking saldırıları gerçekleştirmek için de geçerli olduğunu unutmayın.

**`man dlopen`** sayfasından:

- Path **slash karakteri içermiyorsa** (yani yalnızca bir leaf name ise), **dlopen() arama yapar**. Launch sırasında **`$DYLD_LIBRARY_PATH`** ayarlanmışsa dyld önce o **directory**'ye bakar. Ardından, çağıran mach-o file veya main executable bir **`LC_RPATH`** belirtiyorsa dyld bu directory'lerde arama yapar. Sonra process **unrestricted** ise dyld **current working directory** içinde arama yapar. Son olarak, eski binary'ler için dyld bazı fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlanmışsa dyld bu **directory'lerde** arama yapar; aksi halde dyld **`/usr/local/lib/`** (process unrestricted ise) ve ardından **`/usr/lib/`** içinde arama yapar (bu bilgi **`man dlopen`** sayfasından alınmıştır).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Name içinde slash yoksa hijacking yapmanın 2 yolu vardır:
>
> - Herhangi bir **`LC_RPATH`** writable ise (ancak signature kontrol edilir; bu nedenle binary'nin unrestricted olması da gerekir).
> - Binary **unrestricted** ise ve ardından CWD'den bir şey yüklemek mümkünse (veya belirtilen env variable'ların biri kötüye kullanılırsa).

- Path bir **framework** path'i gibi görünüyorsa (örneğin `/stuff/foo.framework/foo`), launch sırasında **`$DYLD_FRAMEWORK_PATH`** ayarlanmışsa dyld önce bu directory'de **framework partial path**'i (örneğin `foo.framework/foo`) arar. Ardından dyld verilen path'i olduğu gibi dener (relative path'ler için current working directory'yi kullanır). Son olarak, eski binary'ler için dyld bazı fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_FRAMEWORK_PATH`** ayarlanmışsa dyld bu directory'lerde arama yapar. Aksi halde önce **`/Library/Frameworks`** (macOS'ta process unrestricted ise), ardından **`/System/Library/Frameworks`** içinde arama yapar.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Bir framework path'i varsa bunu hijack etmenin yolu:
>
> - Process **unrestricted** ise, **CWD'den relative path'i** ve belirtilen env variable'ları kötüye kullanmak (process restricted ise DYLD\_\* env variable'larının kaldırıldığı dokümantasyonda belirtilmemiş olsa bile).

- Path bir slash **içeriyor ancak framework path'i değilse** (yani dylib'ye full path veya partial path ise), dlopen() önce (ayarlanmışsa) **`$DYLD_LIBRARY_PATH`** içinde arama yapar (path'ten leaf kısmıyla). Ardından dyld verilen path'i dener (relative path'ler için current working directory'yi kullanır; ancak yalnızca unrestricted process'lerde). Son olarak, daha eski binary'ler için dyld fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlanmışsa dyld bu directory'lerde arama yapar; aksi halde dyld **`/usr/local/lib/`** (process unrestricted ise) ve ardından **`/usr/lib/`** içinde arama yapar.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Name içinde slash varsa ve bu bir framework değilse hijack yöntemi şudur:
>
> - Binary **unrestricted** ise CWD'den veya `/usr/local/lib`'den bir şey yüklemek (ya da belirtilen env variable'lardan birini kötüye kullanmak).

> [!TIP]
> Not: **dlopen aramasını kontrol eden configuration file bulunmaz**.
>
> Not: Main executable bir **set\[ug]id binary** ise veya entitlements ile codesigned edilmişse **tüm environment variable'lar yok sayılır** ve yalnızca full path kullanılabilir ([DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) bölümünü daha ayrıntılı bilgi için inceleyin).
>
> Not: Apple platformları, 32-bit ve 64-bit library'leri birleştirmek için "universal" file'lar kullanır. Bu nedenle **ayrı 32-bit ve 64-bit search path'leri yoktur**.
>
> Not: Apple platformlarında çoğu OS dylib'i **dyld cache** içine birleştirilmiştir ve diskte bulunmaz. Bu nedenle bir OS dylib'inin mevcut olup olmadığını önceden kontrol etmek için **`stat()`** çağırmak **çalışmaz**. Ancak **`dlopen_preflight()`**, uyumlu bir mach-o file bulmak için **`dlopen()`** ile aynı adımları kullanır.

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
Derleyip çalıştırırsanız **her kitaplığın hangi konumlarda başarısız bir şekilde arandığını görebilirsiniz**. Ayrıca **FS günlüklerini filtreleyebilirsiniz**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Eğer bir **privileged binary/app** (SUID gibi veya güçlü entitlements değerlerine sahip bir binary) **relative path** üzerinden bir library yüklüyorsa (örneğin `@executable_path` veya `@loader_path` kullanarak) ve **Library Validation** devre dışıysa, binary'yi saldırganın relative path üzerinden yüklenen library'yi **değiştirebileceği** bir konuma taşımak ve bunu process'e code inject etmek için kötüye kullanmak mümkün olabilir.

## `DYLD_*` env değişkenlerini ayıklama

Daha eski `dyld` sürümleri (`dyld2.cpp`) bu kararı process içinde `issetugid()`, `hasRestrictedSegment()` ve `csops(CS_OPS_STATUS)` kullanarak veriyordu. **Güncel `dyld` sürümünde karar AMFI'ye devredilmiştir** ve ilgili kod `dyld/DyldProcessConfig.cpp` içindeki `ProcessConfig::Security::Security()` bölümünde bulunur:<sup>[[1]](#references)</sup>
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

- Pruning yalnızca **macOS / Mac Catalyst / DriverKit** üzerinde gerçekleşir ve yalnızca AMFI `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache` izinlerinin hiçbirini vermediğinde uygulanır.
- AMFI query, executable'ın kendi özellikleriyle beslenir:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
burada `isRestricted()`, kelimenin tam anlamıyla `__RESTRICT` segmenti kontrolüdür (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` ardından adı `DYLD_` ile başlayan **her** değişkeni çıkarır ve `apple[]` parametrelerini aşağı kaydırır; böylece kısıtlı bir sürecin alt süreçleri de bunları devralmaz:
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
> Pratik sonuç: **`DYLD_*`, süreç kısıtlandığında ayıklanır** — setuid/setgid, bir `__RESTRICT/__restrict` section'ı veya AMFI'nin path/print flag'lerini vermeyi reddettiği hardened-runtime/entitled binary'ler söz konusu olduğunda. Bunun yerine süreç yalnızca **library validation** (`CS_REQUIRE_LV`) özelliğine sahipse değişkenler korunur; ancak eklenen dylib'in **aynı Team ID** tarafından (veya Apple tarafından) imzalanmış olması gerekir. Bu nedenle kodun gerçekten yüklenebilmesi için library validation'ı devre dışı bırakan entitlement'lerden birine ihtiyacınız vardır.

Karar artık AMFI tarafından verildiğinden, belirli bir binary'nin ne elde edeceğini öğrenmenin en hızlı yolu `dyld`'in kendisine bakmak yerine AMFI'nin hangi bilgilere dayandığını — entitlement'ler ve signing flag'leri — incelemektir:
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
### Segmenti `__restrict` olan `__RESTRICT` Section
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
> `0x0(none)` flag'leriyle imzalanmış binary'ler olsa bile, çalıştırıldıklarında dinamik olarak **`CS_RESTRICT`** flag'ini alabilirler; bu nedenle bu technique bunlarda çalışmaz.
>
> Bir proc'un bu flag'e sahip olup olmadığını [**csops burada**](https://github.com/axelexic/CSOps) ile kontrol edebilirsiniz:
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
