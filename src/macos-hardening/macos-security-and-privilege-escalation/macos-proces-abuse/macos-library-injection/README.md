# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld kodu açık kaynaklıdır** ve [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) adresinde bulunabilir ve [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) gibi bir **URL kullanılarak** tar dosyası olarak indirilebilir.

## **Dyld Process**

Dyld'in binary'ler içinde kütüphaneleri nasıl yüklediğine şu adresten göz atın:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Bu, [**Linux'taki LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload) gibidir. Çalıştırılacak bir process'in bir path'ten belirli bir kütüphaneyi yüklemesini belirtmeye olanak tanır (env var etkinse).

Bu teknik, **ASEP tekniği olarak da kullanılabilir**; çünkü yüklenen her uygulama, `LSEnvironmental` adlı bir key kullanarak **environmental variable'ların atanmasına** olanak tanıyan "Info.plist" adlı bir plist'e sahiptir.

> [!TIP]
> 2012'den beri **Apple, `DYLD_INSERT_LIBRARIES`'in gücünü büyük ölçüde azaltmıştır**.
>
> Koda gidin ve **`src/dyld.cpp` dosyasını kontrol edin**. **`pruneEnvironmentVariables`** fonksiyonunda **`DYLD_*`** değişkenlerinin kaldırıldığını görebilirsiniz.
>
> **`processRestricted`** fonksiyonunda restriction nedeni ayarlanır. Bu kodu kontrol ettiğinizde nedenlerin şunlar olduğunu görebilirsiniz:
>
> - Binary `setuid/setgid`
> - Mach-O binary'sinde `__RESTRICT/__restrict` section'ının bulunması.
> - Software'ın [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) entitlement'ı olmadan entitlement'lara (hardened runtime) sahip olması
>  - Bir binary'nin **entitlement**'larını şu komutla kontrol edin: `codesign -dv --entitlements :- </path/to/bin>`
>
> Daha güncel versiyonlarda bu mantığı **`configureProcessRestrictions`** fonksiyonunun ikinci kısmında bulabilirsiniz. Ancak daha yeni versiyonlarda çalıştırılan şey, fonksiyonun **başlangıç kontrolleridir** (iOS veya simulation ile ilgili `if` ifadelerini kaldırabilirsiniz; bunlar macOS'ta kullanılmaz).

### Library Validation

Binary, **`DYLD_INSERT_LIBRARIES`** env variable'ının kullanımına izin verse bile kütüphanenin signature'ını kontrol ediyorsa custom bir kütüphaneyi yüklemez.

Custom bir kütüphaneyi yüklemek için binary'nin aşağıdaki entitlement'lardan **birine** sahip olması gerekir:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

veya binary'de **hardened runtime flag'i** ya da **library validation flag'i** bulunmamalıdır.

Bir binary'de **hardened runtime** olup olmadığını `codesign --display --verbose <bin>` komutuyla, **`CodeDirectory`** içindeki runtime flag'ini kontrol ederek görebilirsiniz; örneğin: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Bir kütüphaneyi, binary ile aynı certificate ile **signed** ise de yükleyebilirsiniz.

Bunun nasıl (kötüye) kullanılacağına ve restriction'ların nasıl kontrol edileceğine dair bir örneği şu adreste bulabilirsiniz:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> **Daha önce belirtilen Library Validation restriction'larının**, Dylib hijacking saldırılarını gerçekleştirmek için de geçerli olduğunu unutmayın.

Windows'ta olduğu gibi MacOS'ta da **dylib'leri hijack ederek** **uygulamaların** **arbitrary** **code** **execute** etmesini sağlayabilirsiniz (aslında normal bir user için bu mümkün olmayabilir; çünkü bir `.app` bundle'ı içine yazmak ve bir kütüphaneyi hijack etmek için TCC permission gerekebilir).\
Ancak **MacOS** uygulamalarının kütüphaneleri **yükleme** şekli Windows'a göre daha kısıtlıdır. Bu, **malware** geliştiricilerinin bu tekniği hâlâ **stealth** amacıyla kullanabileceği, ancak bunu **privileges escalate** etmek için kötüye kullanabilme olasılığının çok daha düşük olduğu anlamına gelir.

Öncelikle, **MacOS binary'lerinin yüklenecek kütüphanelerin full path'ini belirttiğini** görmek daha yaygındır. İkinci olarak, **MacOS kütüphaneler için** hiçbir zaman **$PATH** klasörlerinde arama yapmaz.

Bu işlevsellikle ilgili **code**'un **ana** kısmı `ImageLoader.cpp` içindeki **`ImageLoader::recursiveLoadLibraries`** fonksiyonundadır.

Bir Mach-O binary'sinin kütüphaneleri yüklemek için kullanabileceği **4 farklı header Command** vardır:

- **`LC_LOAD_DYLIB`** command, bir dylib yüklemek için kullanılan yaygın command'dır.
- **`LC_LOAD_WEAK_DYLIB`** command, öncekiyle aynı şekilde çalışır; ancak dylib bulunamazsa execution herhangi bir error olmadan devam eder.
- **`LC_REEXPORT_DYLIB`** command, farklı bir kütüphanedeki symbol'leri proxy'ler (veya yeniden export eder).
- **`LC_LOAD_UPWARD_DYLIB`** command, iki kütüphane birbirine bağlı olduğunda kullanılır (buna _upward dependency_ denir).

Ancak **2 tür dylib hijacking** vardır:

- **Missing weak linked libraries**: Bu, uygulamanın **LC_LOAD_WEAK_DYLIB** ile yapılandırılmış ve mevcut olmayan bir kütüphaneyi yüklemeye çalışacağı anlamına gelir. Ardından, **bir attacker beklenen yere bir dylib yerleştirirse bu dylib yüklenir**.
- Link'in "weak" olması, kütüphane bulunamasa bile uygulamanın çalışmaya devam edeceği anlamına gelir.
- Bununla ilgili **code**, `ImageLoader.cpp` içindeki `ImageLoaderMachO::doGetDependentLibraries` fonksiyonundadır; burada `lib->required`, yalnızca `LC_LOAD_WEAK_DYLIB` true olduğunda `false` olur.
- Binary'lerde **weak linked libraries**'i bulmak için (daha sonra hijacking libraries oluşturma örneği verilmiştir):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpath ile yapılandırılmış**: Mach-O binary'leri **`LC_RPATH`** ve **`LC_LOAD_DYLIB`** command'larına sahip olabilir. Bu command'ların **değerlerine** göre **kütüphaneler** farklı directory'lerden **yüklenecektir**.
- **`LC_RPATH`**, binary tarafından kütüphaneleri yüklemek için kullanılan bazı folder'ların path'lerini içerir.
- **`LC_LOAD_DYLIB`**, yüklenecek belirli kütüphanelerin path'ini içerir. Bu path'ler **`@rpath`** içerebilir; bunlar **`LC_RPATH`** içindeki değerlerle değiştirilir. **`LC_RPATH`** içinde birden fazla path varsa kütüphaneyi yüklemek için hepsi aranır. Örnek:
- **`LC_LOAD_DYLIB`** `@rpath/library.dylib` içeriyor ve **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` ile `/application/app.app/Contents/Framework/v2/` içeriyorsa, her iki folder da `library.dylib`'i yüklemek için kullanılacaktır**.** Kütüphane `[...]/v1/` içinde yoksa ve attacker buraya yerleştirebilirse, **`LC_LOAD_DYLIB`** içindeki path sırası takip edildiğinden `[...]/v2/` içindeki kütüphanenin yüklenmesini hijack edebilir.
- Binary'lerde rpath path'lerini ve kütüphaneleri şu komutla bulun: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file**'ı içeren directory'nin **path'idir**.
>
> **`@loader_path`**: load command'ı içeren **Mach-O binary'sini** barındıran **directory'nin path'idir**.
>
> - Bir executable içinde kullanıldığında **`@loader_path`**, pratikte **`@executable_path`** ile aynıdır.
> - Bir **dylib** içinde kullanıldığında **`@loader_path`**, **dylib'in path'ini** verir.

Bu işlevselliği kötüye kullanarak **privileges escalate** etmenin yolu, **root tarafından** çalıştırılan bir **uygulamanın**, attacker'ın yazma permission'ına sahip olduğu bir folder'da bir **kütüphane araması** gibi nadir bir durumda mümkün olur.

> [!TIP]
> Uygulamalarda **missing libraries** bulmak için iyi bir **scanner**, [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) veya bir [**CLI version**](https://github.com/pandazheng/DylibHijack)'dır.\
> Bu teknik hakkında technical details içeren iyi bir **report** [**burada**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) bulunabilir.

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> **Daha önce belirtilen Library Validation restriction'larının**, Dlopen hijacking saldırılarını gerçekleştirmek için de geçerli olduğunu unutmayın.

**`man dlopen`** içinden:

- Path **slash character içermediğinde** (yani yalnızca bir leaf name olduğunda), **dlopen() arama yapar**. Launch sırasında **`$DYLD_LIBRARY_PATH`** ayarlanmışsa, dyld önce o **directory** içinde arar. Ardından, çağıran Mach-O file veya main executable bir **`LC_RPATH`** belirtiyorsa dyld bu directory'lerde arar. Sonra process **unrestricted** ise dyld current working directory içinde arar. Son olarak eski binary'ler için dyld bazı fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlanmışsa dyld bu **directory'lerde** arar; aksi takdirde dyld **`/usr/local/lib/`** içinde (process unrestricted ise), ardından **`/usr/lib/`** içinde arar (bu bilgi **`man dlopen`**'dan alınmıştır).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Name içinde slash yoksa hijacking yapmak için 2 yol vardır:
>
> - Herhangi bir **`LC_RPATH`** writable ise (ancak signature kontrol edildiğinden bunun için binary'nin unrestricted olması da gerekir)
> - Binary **unrestricted** ise; bu durumda CWD'den bir şey yüklemek (veya belirtilen env variable'larından birini kötüye kullanmak) mümkün olur

- Path bir framework path'i gibi göründüğünde (ör. `/stuff/foo.framework/foo`), launch sırasında **`$DYLD_FRAMEWORK_PATH`** ayarlanmışsa dyld önce o directory içinde **framework partial path**'ini (ör. `foo.framework/foo`) arar. Ardından dyld verilen path'i olduğu gibi dener (relative path'ler için current working directory'yi kullanır). Son olarak eski binary'ler için dyld bazı fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_FRAMEWORK_PATH`** ayarlanmışsa dyld bu directory'lerde arar. Aksi takdirde önce **`/Library/Frameworks`** içinde (process unrestricted ise macOS'ta), ardından **`/System/Library/Frameworks`** içinde arar.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Path bir framework path'i ise hijack yöntemi şudur:
>
> - Process **unrestricted** ise, CWD'den gelen relative path'i veya belirtilen env variable'larını kötüye kullanmak (process restricted ise DYLD\_\* env var'larının kaldırıldığı docs'ta belirtilmese bile)

- Path slash içeriyor ancak framework path'i değilse (yani bir dylib'e giden full path veya partial path ise), dlopen() önce (ayarlanmışsa) **`$DYLD_LIBRARY_PATH`** içinde arar (path'teki leaf part ile). Ardından dyld verilen path'i dener (relative path'ler için current working directory'yi kullanır; ancak yalnızca unrestricted process'ler için). Son olarak daha eski binary'ler için dyld fallback'leri dener. Launch sırasında **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlanmışsa dyld bu directory'lerde arar; aksi takdirde dyld **`/usr/local/lib/`** içinde (process unrestricted ise), ardından **`/usr/lib/`** içinde arar.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Name içinde slash varsa ve framework değilse hijack yöntemi şudur:
>
> - Binary **unrestricted** ise CWD'den veya `/usr/local/lib` içinden bir şey yüklemek (ya da belirtilen env variable'larından birini kötüye kullanmak)

> [!TIP]
> Not: **dlopen aramasını kontrol etmek** için **configuration file** yoktur.
>
> Not: Main executable bir **set\[ug]id binary** ise veya entitlement'larla codesign edilmişse, **tüm environment variable'ları yok sayılır** ve yalnızca full path kullanılabilir ([daha ayrıntılı bilgi için DYLD_INSERT_LIBRARIES restriction'larını kontrol edin](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions)).
>
> Not: Apple platformları, 32-bit ve 64-bit kütüphaneleri birleştirmek için "universal" file'lar kullanır. Bu, ayrı 32-bit ve 64-bit search path'lerinin olmadığı anlamına gelir.
>
> Not: Apple platformlarında çoğu OS dylib'i **dyld cache** içinde birleştirilmiştir ve disk üzerinde mevcut değildir. Bu nedenle bir OS dylib'inin mevcut olup olmadığını önceden kontrol etmek için **`stat()`** çağrısı yapmak işe yaramaz. Ancak **`dlopen_preflight()`**, uyumlu bir Mach-O file bulmak için **`dlopen()`** ile aynı adımları kullanır.

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
Derleyip çalıştırırsanız, her kitaplığın **nerede başarısız olarak arandığını** görebilirsiniz. Ayrıca **FS loglarını filtreleyebilirsiniz**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Eğer bir **privileged binary/app** (SUID veya güçlü entitlements'lara sahip bir binary gibi) **relative path** üzerinden bir library yüklüyorsa (örneğin `@executable_path` veya `@loader_path` kullanarak) ve **Library Validation** devre dışı bırakılmışsa, binary'yi attacker'ın **relative path** üzerinden yüklenen library'yi **modify** edebileceği bir konuma taşımak ve bunu process'e code inject etmek için abuse etmek mümkün olabilir.

## `DYLD_*` ve `LD_LIBRARY_PATH` env variables'larını prune etme

`dyld-dyld-832.7.1/src/dyld2.cpp` dosyasında, **`DYLD_` ile başlayan** ve **`LD_LIBRARY_PATH=`** olan tüm env variables'larını kaldıran **`pruneEnvironmentVariables`** function'ını bulmak mümkündür.

Ayrıca **suid** ve **sgid** binary'leri için özellikle **`DYLD_FALLBACK_FRAMEWORK_PATH`** ve **`DYLD_FALLBACK_LIBRARY_PATH`** env variables'larını **null** olarak ayarlar.

OSX hedefleniyorsa bu function, aynı dosyanın **`_main`** function'ından şu şekilde çağrılır:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
ve bu boolean flag'ler kodda aynı dosyada ayarlanır:
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
Bu temel olarak, binary **suid** veya **sgid** ise ya da başlıklarda bir **RESTRICT** segmentine sahipse veya **CS_RESTRICT** flag'iyle imzalanmışsa, **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** ifadesinin true olduğu ve env değişkenlerinin temizlendiği anlamına gelir.

CS_REQUIRE_LV true ise değişkenlerin temizlenmeyeceğini, ancak library validation işleminin aynı certificate'ı kullandıklarını kontrol edeceğini unutmayın.

## Kısıtlamaları Kontrol Et

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
### `__restrict` segment'ine sahip `__RESTRICT` bölümü
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
> İmzalanmış binary'lerde **`0x0(none)`** flag'i bulunsa bile, çalıştırıldıklarında dinamik olarak **`CS_RESTRICT`** flag'ini alabileceklerini ve bu nedenle bu tekniğin bunlarda çalışmayacağını unutmayın.
>
> Bir proc'un bu flag'e sahip olup olmadığını şu komutla kontrol edebilirsiniz ([**csops burada**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> ardından 0x800 flag'inin etkin olup olmadığını kontrol edin.

## Referanslar

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
