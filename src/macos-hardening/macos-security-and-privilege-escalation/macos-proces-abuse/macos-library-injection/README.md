# macOS Kütüphane Enjeksiyonu

{{#include ../../../../banners/hacktricks-training.md}}

> [!DİKKAT]
> **dyld kodu açık kaynaklıdır** ve [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) adresinde bulunabilir ve **şu URL gibi** bir tar ile indirilebilir: [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Süreci**

Dyld'in ikili dosyalar içinde kütüphaneleri nasıl yüklediğine bakın:

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Bu, [**Linux'taki LD_PRELOAD**](../../../../linux-hardening/privilege-escalation/#ld_preload) gibidir. Bir sürecin çalıştırılacağını belirtmek için belirli bir kütüphaneyi bir yoldan yüklemesine izin verir (eğer env değişkeni etkinse).

Bu teknik ayrıca **ASEP tekniği olarak da kullanılabilir** çünkü her kurulu uygulamanın "Info.plist" adında bir plist'i vardır ve bu, `LSEnvironmental` adında bir anahtar kullanarak **çevresel değişkenlerin atanmasına** izin verir.

> [!NOT]
> 2012'den beri **Apple, `DYLD_INSERT_LIBRARIES`** gücünü önemli ölçüde azaltmıştır.
>
> Koda gidin ve **`src/dyld.cpp`** dosyasını kontrol edin. **`pruneEnvironmentVariables`** fonksiyonunda **`DYLD_*`** değişkenlerinin kaldırıldığını görebilirsiniz.
>
> **`processRestricted`** fonksiyonunda kısıtlamanın nedeni belirlenir. O kodu kontrol ederek nedenlerin şunlar olduğunu görebilirsiniz:
>
> - İkili dosya `setuid/setgid`
> - Macho ikili dosyasında `__RESTRICT/__restrict` bölümünün varlığı.
> - Yazılımın [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) yetkisi olmadan yetkilendirmeleri (hardened runtime) vardır.
>   - Bir ikilinin **yetkilendirmelerini** kontrol etmek için: `codesign -dv --entitlements :- </path/to/bin>`
>
> Daha güncel sürümlerde bu mantığı **`configureProcessRestrictions`** fonksiyonunun ikinci kısmında bulabilirsiniz. Ancak, daha yeni sürümlerde yürütülen şey, fonksiyonun **başlangıç kontrolleridir** (iOS veya simülasyonla ilgili if'leri kaldırabilirsiniz çünkü bunlar macOS'ta kullanılmayacaktır).

### Kütüphane Doğrulaması

İkili dosya **`DYLD_INSERT_LIBRARIES`** env değişkenini kullanmaya izin verse bile, eğer ikili dosya yüklenecek kütüphanenin imzasını kontrol ediyorsa, özel bir kütüphaneyi yüklemeyecektir.

Özel bir kütüphaneyi yüklemek için, ikili dosyanın **aşağıdaki yetkilendirmelerden birine** sahip olması gerekir:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

veya ikili dosya **hardened runtime bayrağına** veya **kütüphane doğrulama bayrağına** sahip **olmamalıdır**.

Bir ikilinin **hardened runtime** olup olmadığını kontrol etmek için `codesign --display --verbose <bin>` komutunu kullanarak **`CodeDirectory`** içindeki bayrağı kontrol edebilirsiniz: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Ayrıca, bir kütüphaneyi **ikili dosyayla aynı sertifika ile imzalanmışsa** yükleyebilirsiniz.

Bunu nasıl (kötüye) kullanacağınızı ve kısıtlamaları kontrol etmek için bir örnek bulun:

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Ele Geçirme

> [!DİKKAT]
> Dylib ele geçirme saldırıları gerçekleştirmek için **önceki Kütüphane Doğrulama kısıtlamalarının da geçerli olduğunu** unutmayın.

Windows'ta olduğu gibi, MacOS'ta da **dylib'leri ele geçirebilirsiniz** ve **uygulamaların** **rastgele** **kod** **çalıştırmasını** sağlayabilirsiniz (aslında, normal bir kullanıcıdan bu mümkün olmayabilir çünkü bir `.app` paketinin içine yazmak ve bir kütüphaneyi ele geçirmek için bir TCC iznine ihtiyacınız olabilir).\
Ancak, **MacOS** uygulamalarının kütüphaneleri **yükleme** şekli **Windows'tan daha kısıtlıdır**. Bu, **kötü amaçlı yazılım** geliştiricilerinin bu tekniği **gizlilik** için kullanabileceği anlamına gelir, ancak **yetkileri artırmak için bunu kötüye kullanma olasılığı çok daha düşüktür**.

Öncelikle, **MacOS ikililerinin kütüphaneleri yüklemek için tam yolu belirtmesi** daha yaygındır. İkincisi, **MacOS asla** kütüphaneler için **$PATH** klasörlerinde arama yapmaz.

Bu işlevselliğe ilişkin **kodun** ana kısmı **`ImageLoader::recursiveLoadLibraries`** içinde `ImageLoader.cpp` dosyasındadır.

Bir macho ikili dosyası kütüphaneleri yüklemek için **4 farklı başlık Komutu** kullanabilir:

- **`LC_LOAD_DYLIB`** komutu, bir dylib yüklemek için yaygın komuttur.
- **`LC_LOAD_WEAK_DYLIB`** komutu, önceki gibi çalışır, ancak dylib bulunamazsa, yürütme hatasız devam eder.
- **`LC_REEXPORT_DYLIB`** komutu, farklı bir kütüphaneden sembolleri proxy'ler (veya yeniden ihraç eder).
- **`LC_LOAD_UPWARD_DYLIB`** komutu, iki kütüphanenin birbirine bağımlı olduğu durumlarda kullanılır (bu, _yukarı bağımlılık_ olarak adlandırılır).

Ancak, **2 tür dylib ele geçirme** vardır:

- **Eksik zayıf bağlantılı kütüphaneler**: Bu, uygulamanın **LC_LOAD_WEAK_DYLIB** ile yapılandırılmış bir kütüphaneyi yüklemeye çalışacağı anlamına gelir. Sonra, **bir saldırgan bir dylibi beklenen yere yerleştirirse, yüklenir**.
- Bağlantının "zayıf" olması, kütüphane bulunmasa bile uygulamanın çalışmaya devam edeceği anlamına gelir.
- Bununla ilgili **kod**, `ImageLoaderMachO::doGetDependentLibraries` fonksiyonundadır ve burada `lib->required` yalnızca `LC_LOAD_WEAK_DYLIB` doğru olduğunda `false` olur.
- **Zayıf bağlantılı kütüphaneleri** ikililerde bulmak için (sonra ele geçirme kütüphaneleri oluşturma örneğiniz var):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpath ile yapılandırılmış**: Mach-O ikilileri **`LC_RPATH`** ve **`LC_LOAD_DYLIB`** komutlarına sahip olabilir. Bu komutların **değerlerine** dayanarak, **kütüphaneler** **farklı dizinlerden** **yüklenir**.
- **`LC_RPATH`**, ikili dosya tarafından kütüphaneleri yüklemek için kullanılan bazı klasörlerin yollarını içerir.
- **`LC_LOAD_DYLIB`**, yüklenmesi gereken belirli kütüphanelerin yolunu içerir. Bu yollar **`@rpath`** içerebilir ve bu, **`LC_RPATH`** içindeki değerlerle **değiştirilecektir**. Eğer **`LC_RPATH`** içinde birden fazla yol varsa, her biri yüklenmesi gereken kütüphaneyi aramak için kullanılacaktır. Örnek:
- Eğer **`LC_LOAD_DYLIB`** `@rpath/library.dylib` içeriyorsa ve **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` ve `/application/app.app/Contents/Framework/v2/` içeriyorsa. Her iki klasör de `library.dylib` yüklemek için kullanılacaktır. Eğer kütüphane `[...]/v1/` içinde yoksa, bir saldırgan oraya yerleştirerek `[...]/v2/` içindeki kütüphanenin yüklenmesini ele geçirebilir çünkü **`LC_LOAD_DYLIB`** içindeki yolların sırası takip edilir.
- **İkili dosyalarda rpath yollarını ve kütüphaneleri bulmak için**: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOT] > **`@executable_path`**: **Ana yürütülebilir dosyanın** bulunduğu dizinin **yoludur**.
>
> **`@loader_path`**: **Yükleme komutunu içeren** **Mach-O ikilisinin** bulunduğu **dizinin yoludur**.
>
> - Bir yürütülebilir dosyada kullanıldığında, **`@loader_path`** etkili bir şekilde **`@executable_path`** ile **aynıdır**.
> - Bir **dylib** içinde kullanıldığında, **`@loader_path`** **dylib'in** **yolunu** verir.

Bu işlevselliği kötüye kullanarak **yetkileri artırmanın** yolu, **root** tarafından **çalıştırılan** bir **uygulamanın**, saldırganın yazma izinlerine sahip olduğu bir **klasörde** bazı **kütüphaneleri arıyor olması** durumunda olacaktır.

> [!İPUCU]
> Uygulamalardaki **eksik kütüphaneleri** bulmak için güzel bir **tarayıcı** [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) veya bir [**CLI versiyonu**](https://github.com/pandazheng/DylibHijack).\
> Bu teknikle ilgili **teknik detaylar** içeren güzel bir **rapor** [**burada**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) bulunabilir.

**Örnek**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Ele Geçirme

> [!DİKKAT]
> Dlopen ele geçirme saldırıları gerçekleştirmek için **önceki Kütüphane Doğrulama kısıtlamalarının da geçerli olduğunu** unutmayın.

**`man dlopen`**'dan:

- Yol **bir eğik çizgi karakteri** içermiyorsa (yani sadece bir yaprak adıysa), **dlopen() arama yapacaktır**. Eğer **`$DYLD_LIBRARY_PATH`** başlatıldığında ayarlandıysa, dyld önce **o dizinde** **bakacaktır**. Sonra, eğer çağrılan mach-o dosyası veya ana yürütülebilir dosya bir **`LC_RPATH`** belirtiyorsa, dyld **o dizinlerde** **bakacaktır**. Sonra, eğer süreç **kısıtlı değilse**, dyld **geçerli çalışma dizininde** arama yapacaktır. Son olarak, eski ikililer için, dyld bazı yedeklemeleri deneyecektir. Eğer **`$DYLD_FALLBACK_LIBRARY_PATH`** başlatıldığında ayarlandıysa, dyld **o dizinlerde** arama yapacaktır, aksi takdirde dyld **`/usr/local/lib/`** içinde (eğer süreç kısıtlı değilse) ve sonra **`/usr/lib/`** içinde arama yapacaktır (bu bilgi **`man dlopen`**'dan alınmıştır).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(eğer kısıtlı değilse)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (eğer kısıtlı değilse)
6. `/usr/lib/`

> [!DİKKAT]
> Eğer isimde eğik çizgi yoksa, ele geçirme yapmak için 2 yol olacaktır:
>
> - Eğer herhangi bir **`LC_RPATH`** **yazılabilir** ise (ancak imza kontrol edilir, bu nedenle bunun için ikilinin de kısıtlı olmaması gerekir)
> - Eğer ikili dosya **kısıtlı değilse** ve o zaman CWD'den (veya bahsedilen env değişkenlerinden birini kötüye kullanarak) bir şey yüklemek mümkündür.

- Yol **bir çerçeve** yolu gibi görünüyorsa (örneğin, `/stuff/foo.framework/foo`), eğer **`$DYLD_FRAMEWORK_PATH`** başlatıldığında ayarlandıysa, dyld önce **çerçevenin kısmi yolu** için o dizinde bakacaktır (örneğin, `foo.framework/foo`). Sonra, dyld **sağlanan yolu olduğu gibi** deneyecektir (göreceli yollar için geçerli çalışma dizinini kullanarak). Son olarak, eski ikililer için, dyld bazı yedeklemeleri deneyecektir. Eğer **`$DYLD_FALLBACK_FRAMEWORK_PATH`** başlatıldığında ayarlandıysa, dyld o dizinlerde arama yapacaktır. Aksi takdirde, **`/Library/Frameworks`** içinde arama yapacaktır (macOS'ta süreç kısıtlı değilse), sonra **`/System/Library/Frameworks`** içinde arama yapacaktır.
1. `$DYLD_FRAMEWORK_PATH`
2. sağlanan yol (eğer kısıtlı değilse göreceli yollar için geçerli çalışma dizinini kullanarak)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (eğer kısıtlı değilse)
5. `/System/Library/Frameworks`

> [!DİKKAT]
> Eğer bir çerçeve yolu ise, ele geçirmenin yolu:
>
> - Eğer süreç **kısıtlı değilse**, bahsedilen env değişkenlerinden **CWD'den göreceli yolu** kötüye kullanarak (belgelere göre süreç kısıtlıysa DYLD\_\* env değişkenleri kaldırılır)

- Yol **bir eğik çizgi içeriyorsa ama bir çerçeve yolu değilse** (yani bir dylib'e tam veya kısmi bir yol), dlopen() önce (eğer ayarlandıysa) **`$DYLD_LIBRARY_PATH`** içinde (yolun yaprak kısmıyla) bakar. Sonra, dyld **sağlanan yolu dener** (eğer kısıtlı değilse göreceli yollar için geçerli çalışma dizinini kullanarak). Son olarak, eski ikililer için, dyld yedeklemeleri deneyecektir. Eğer **`$DYLD_FALLBACK_LIBRARY_PATH`** başlatıldığında ayarlandıysa, dyld o dizinlerde arama yapacaktır, aksi takdirde dyld **`/usr/local/lib/`** içinde (eğer süreç kısıtlı değilse) ve sonra **`/usr/lib/`** içinde arama yapacaktır.
1. `$DYLD_LIBRARY_PATH`
2. sağlanan yol (eğer kısıtlı değilse göreceli yollar için geçerli çalışma dizinini kullanarak)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (eğer kısıtlı değilse)
5. `/usr/lib/`

> [!DİKKAT]
> Eğer isimde eğik çizgi varsa ve çerçeve değilse, ele geçirmenin yolu:
>
> - Eğer ikili dosya **kısıtlı değilse** ve o zaman CWD'den veya `/usr/local/lib`'den bir şey yüklemek mümkündür (veya bahsedilen env değişkenlerinden birini kötüye kullanarak)

> [!NOT]
> Not: **dlopen aramasını kontrol etmek için** yapılandırma dosyası **yoktur**.
>
> Not: Eğer ana yürütülebilir dosya bir **set\[ug]id ikilisi veya yetkilendirmelerle kod imzalanmışsa**, o zaman **tüm çevresel değişkenler yok sayılır** ve yalnızca tam yol kullanılabilir ([daha ayrıntılı bilgi için DYLD_INSERT_LIBRARIES kısıtlamalarını kontrol edin](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions)).
>
> Not: Apple platformları, 32-bit ve 64-bit kütüphaneleri birleştirmek için "evrensel" dosyalar kullanır. Bu, **ayrı 32-bit ve 64-bit arama yolları** olmadığı anlamına gelir.
>
> Not: Apple platformlarında çoğu OS dylib **dyld önbelleğine** **birleştirilmiştir** ve disk üzerinde mevcut değildir. Bu nedenle, bir OS dylib'in var olup olmadığını önceden kontrol etmek için **`stat()`** çağrısı **çalışmaz**. Ancak, **`dlopen_preflight()`**, uyumlu bir mach-o dosyasını bulmak için **`dlopen()`** ile aynı adımları kullanır.

**Yolları Kontrol Et**

Aşağıdaki kod ile tüm seçenekleri kontrol edelim:
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
Eğer bunu derleyip çalıştırırsanız, **her bir kütüphanenin nerede başarısız bir şekilde arandığını** görebilirsiniz. Ayrıca, **FS günlüklerini filtreleyebilirsiniz**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Göreli Yol Hijacking

Eğer bir **ayrılmış ikili/uygulama** (örneğin bir SUID veya güçlü yetkilere sahip bir ikili) **göreli yol** kütüphanesini (örneğin `@executable_path` veya `@loader_path` kullanarak) **yükliyorsa** ve **Kütüphane Doğrulaması devre dışıysa**, saldırganın **göreli yol yüklenen kütüphaneyi** değiştirebileceği ve sürece kod enjekte etmek için bunu kötüye kullanabileceği bir durum söz konusu olabilir.

## `DYLD_*` ve `LD_LIBRARY_PATH` çevre değişkenlerini temizle

`dyld-dyld-832.7.1/src/dyld2.cpp` dosyasında **`pruneEnvironmentVariables`** fonksiyonunu bulmak mümkündür; bu fonksiyon **`DYLD_`** ile **başlayan** ve **`LD_LIBRARY_PATH=`** olan herhangi bir çevre değişkenini kaldıracaktır.

Ayrıca, **suid** ve **sgid** ikilileri için **`DYLD_FALLBACK_FRAMEWORK_PATH`** ve **`DYLD_FALLBACK_LIBRARY_PATH`** çevre değişkenlerini **null** olarak ayarlayacaktır.

Bu fonksiyon, OSX hedef alındığında aynı dosyanın **`_main`** fonksiyonundan şu şekilde çağrılır:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
ve bu boolean bayrakları kodda aynı dosyada ayarlanır:
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
Bu, temelde eğer ikili dosya **suid** veya **sgid** ise, ya da başlıklarda bir **RESTRICT** segmenti varsa ya da **CS_RESTRICT** bayrağı ile imzalanmışsa, o zaman **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** doğru olur ve çevre değişkenleri temizlenir.

Eğer CS_REQUIRE_LV doğruysa, o zaman değişkenler temizlenmeyecek ancak kütüphane doğrulaması, bunların orijinal ikili dosya ile aynı sertifikayı kullandığını kontrol edecektir.

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
### Bölüm `__RESTRICT` ile segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Sertifikalı çalışma zamanı

Anahtarlıkta yeni bir sertifika oluşturun ve bunu ikili dosyayı imzalamak için kullanın:
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
> **`0x0(none)`** bayrakları ile imzalanmış ikili dosyalar olsa bile, çalıştırıldıklarında dinamik olarak **`CS_RESTRICT`** bayrağını alabileceklerini unutmayın ve bu nedenle bu teknik onlarda çalışmayacaktır.
>
> Bir işlemin bu bayrağa sahip olup olmadığını kontrol edebilirsiniz (get [**csops here**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> ve ardından 0x800 bayrağının etkin olup olmadığını kontrol edin.

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
