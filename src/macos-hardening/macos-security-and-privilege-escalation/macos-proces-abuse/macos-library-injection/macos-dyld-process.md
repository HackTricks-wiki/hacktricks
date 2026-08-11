# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Bir Mach-o binary'sinin gerçek **entrypoint**'i, dinamik linker tarafından tanımlanır ve `LC_LOAD_DYLINKER` içinde genellikle `/usr/lib/dyld` olarak belirtilir.<sup>[[3]](#references)</sup>

Bu linker'ın tüm executable library'lerini bulması, bunları memory'ye map etmesi ve lazy olmayan tüm library'leri linklemesi gerekir. Binary'nin entry-point'i ancak bu işlemden sonra çalıştırılır.

Elbette **`dyld`**'in herhangi bir dependency'si yoktur (syscall'ları ve libSystem parçalarını kullanır).

> [!CAUTION]
> Bu linker herhangi bir vulnerability içeriyorsa, herhangi bir binary çalıştırılmadan önce (yüksek ayrıcalıklı olanlar dahil) çalıştırıldığı için **privilege escalation** mümkün olabilir.

### Flow

Dyld, **`dyldboostrap::start`** tarafından yüklenecek ve bu fonksiyon aynı zamanda **stack canary** gibi şeyleri de yükleyecektir. Bunun nedeni, bu fonksiyonun **`apple`** argument vector'ü içinde bunu ve diğer **sensitive** **values** değerlerini almasıdır.<sup>[[1]](#references)</sup>

**`dyls::_main()`**, dyld'in entry point'idir ve ilk görevi, genellikle:<sup>[[2]](#references)</sup> bölümünde açıklanan **`DYLD_*`** environment variable'larını kısıtlayan `configureProcessRestrictions()` fonksiyonunu çalıştırmaktır:


{{#ref}}
./
{{#endref}}

Daha sonra tüm önemli system library'lerini prelink eden dyld shared cache'i map eder; ardından binary'nin dependency'si olan library'leri map eder ve gerekli tüm library'ler yüklenene kadar recursive olarak devam eder. Bu nedenle:

1. İzin veriliyorsa `DYLD_INSERT_LIBRARIES` ile eklenen library'leri yüklemeye başlar
2. Ardından shared cache içindeki library'leri yükler
3. Ardından import edilen library'leri yükler
1. Daha sonra library'leri recursive olarak import etmeye devam eder

Hepsi yüklendikten sonra bu library'lerin **initialiser**'ları çalıştırılır. Bunlar, `LC_ROUTINES[_64]` içinde (artık deprecated) tanımlanan veya `S_MOD_INIT_FUNC_POINTERS` ile işaretlenmiş bir section'daki pointer'lar aracılığıyla (genellikle: **`__DATA.__MOD_INIT_FUNC`**) tanımlanan **`__attribute__((constructor))`** kullanılarak kodlanır.

Terminator'lar **`__attribute__((destructor))`** ile kodlanır ve `S_MOD_TERM_FUNC_POINTERS` ile işaretlenmiş bir section'da (**`__DATA.__mod_term_func`**) bulunur.

### Stubs

macOS'taki tüm binary'ler dynamically linked'dir. Bu nedenle farklı machine'larda ve context'lerde binary'nin doğru code'a atlamasına yardımcı olan bazı stub section'ları içerirler. Binary çalıştırıldığında bu address'leri çözümlemesi gereken bileşen (en azından lazy olmayanlar için) dyld'dir.

Binary'deki bazı stub section'ları:

- **`__TEXT.__[auth_]stubs`**: `__DATA` section'larından gelen pointer'lar
- **`__TEXT.__stub_helper`**: Çağrılacak function hakkındaki bilgilerle dynamic linking'i çağıran küçük code
- **`__DATA.__[auth_]got`**: Global Offset Table (import edilen function'ların address'leri; çözümlendiğinde, `S_NON_LAZY_SYMBOL_POINTERS` flag'iyle işaretlendiği için load time'da bound edilir)
- **`__DATA.__nl_symbol_ptr`**: Non-lazy symbol pointer'ları (`S_NON_LAZY_SYMBOL_POINTERS` flag'iyle işaretlendiği için load time'da bound edilir)
- **`__DATA.__la_symbol_ptr`**: Lazy symbol pointer'ları (ilk access sırasında bound edilir)

> [!WARNING]
> "auth_" prefix'ine sahip pointer'ların, onları korumak için process içi tek bir encryption key (PAC) kullandığına dikkat edin. Ayrıca pointer'ı takip etmeden önce doğrulamak için arm64 instruction'ı olan `BLRA[A/B]` kullanılabilir. RET address yerine RETA\[A/B] de kullanılabilir.\
> Aslında **`__TEXT.__auth_stubs`** içindeki code, pointer'ı authenticate etmek amacıyla istenen function'ı çağırmak için **`bl`** yerine **`braa`** kullanır.
>
> Ayrıca güncel dyld version'larının her şeyi **non-lazy** olarak yüklediğine dikkat edin.

### Finding lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
İlginç disassembly kısmı:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
printf çağrısına yapılan atlamanın **`__TEXT.__stubs`** adresine gittiği görülebilir:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
**`__stubs`** bölümünün disassembly çıktısında:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
GOT adresine **atladığımızı** görebilirsiniz; bu durumda GOT non-lazy olarak çözümlenir ve `printf` işlevinin adresini içerir.

Diğer durumlarda doğrudan GOT'a atlamak yerine **`__DATA.__la_symbol_ptr`** adresine atlanabilir. Bu, yüklenmeye çalışılan işlevi temsil eden bir değer yükler; ardından **`__TEXT.__stub_helper`** adresine atlar. Bu da **`dyld_stub_binder`** adresini içeren **`__DATA.__nl_symbol_ptr`** adresine atlar. `dyld_stub_binder`, parametre olarak işlevin numarasını ve bir adresi alır.\
Bu son işlev, aranan işlevin adresini bulduktan sonra gelecekte tekrar arama yapılmasını önlemek için bu adresi **`__TEXT.__stub_helper`** içindeki ilgili konuma yazar.

> [!TIP]
> Ancak güncel dyld sürümlerinin her şeyi non-lazy olarak yüklediğine dikkat edin.

#### Dyld opcodes

Son olarak, **`dyld_stub_binder`** belirtilen işlevi bulmalı ve tekrar aramamak için uygun adrese yazmalıdır. Bunu yapmak için dyld içinde opcodes (sonlu durum makinesi) kullanır.

## apple\[] argument vector

macOS'ta main işlevi aslında 3 yerine 4 argüman alır. Dördüncü argümana apple adı verilir ve her giriş `key=value` biçimindedir. Örneğin:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Çevrilecek İngilizce metin sağlanmamış.
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
> [!TIP]
> Bu değerler main function'a ulaştığında, hassas bilgiler zaten bunlardan kaldırılmıştır; aksi takdirde bu bir data leak olurdu.

main'e girmeden önce debugging yaparak tüm bu ilginç değerleri görmek mümkündür:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld_all_image_infos

Bu, dyld tarafından export edilen ve dyld durumu hakkında bilgiler içeren bir structure'dır. [**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) içinde bulunabilir. Bu bilgiler arasında version, dyld_image_info array'ine pointer, dyld_image_notifier'a pointer, proc'un shared cache'ten ayrılıp ayrılmadığı, libSystem initializer'ın çağrılıp çağrılmadığı, dyld'in kendi Mach header'ına pointer, dyld version string'i ve daha fazlası yer alır.<sup>[[4]](#references)</sup>

## dyld ortam değişkenleri

### debug dyld

dyld'in ne yaptığını anlamaya yardımcı olan ilginç ortam değişkenleri:

- **DYLD_PRINT_LIBRARIES**

Yüklenen her library'yi kontrol eder:
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
- **DYLD_PRINT_SEGMENTS**

Her kütüphanenin nasıl yüklendiğini kontrol edin:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
- **DYLD_PRINT_INITIALIZERS**

Her kitaplık başlatıcısı çalıştırıldığında yazdırır:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Diğerleri

- `DYLD_BIND_AT_LAUNCH`: Lazy bindings, non-lazy bindings ile çözümlenir
- `DYLD_DISABLE_PREFETCH`: \_\_DATA ve \_\_LINKEDIT içeriği için pre-fetch işlemini devre dışı bırakır
- `DYLD_FORCE_FLAT_NAMESPACE`: Tek seviyeli bindings
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Çözümleme yolları
- `DYLD_INSERT_LIBRARIES`: Belirli bir library yükler
- `DYLD_PRINT_TO_FILE`: dyld debug çıktısını bir dosyaya yazar
- `DYLD_PRINT_APIS`: libdyld API çağrılarını yazdırır
- `DYLD_PRINT_APIS_APP`: main tarafından yapılan libdyld API çağrılarını yazdırır
- `DYLD_PRINT_BINDINGS`: Bind edildiğinde symbols öğelerini yazdırır
- `DYLD_WEAK_BINDINGS`: Bind edildiğinde yalnızca weak symbols öğelerini yazdırır
- `DYLD_PRINT_CODE_SIGNATURES`: Code signature kayıt işlemlerini yazdırır
- `DYLD_PRINT_DOFS`: Yüklendikçe D-Trace object format bölümlerini yazdırır
- `DYLD_PRINT_ENV`: dyld tarafından görülen env öğesini yazdırır
- `DYLD_PRINT_INTERPOSTING`: Interposting işlemlerini yazdırır
- `DYLD_PRINT_LIBRARIES`: Yüklenen library öğelerini yazdırır
- `DYLD_PRINT_OPTS`: Load options öğelerini yazdırır
- `DYLD_REBASING`: Symbol rebasing işlemlerini yazdırır
- `DYLD_RPATHS`: @rpath genişletmelerini yazdırır
- `DYLD_PRINT_SEGMENTS`: Mach-O segments eşlemelerini yazdırır
- `DYLD_PRINT_STATISTICS`: Zamanlama istatistiklerini yazdırır
- `DYLD_PRINT_STATISTICS_DETAILS`: Ayrıntılı zamanlama istatistiklerini yazdırır
- `DYLD_PRINT_WARNINGS`: Uyarı mesajlarını yazdırır
- `DYLD_SHARED_CACHE_DIR`: Shared library cache için kullanılacak yol
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Closures özelliğini etkinleştirir

Şuna benzer bir yöntemle daha fazlasını bulmak mümkündür:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Veya dyld projesini [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) adresinden indirip klasör içinde şunu çalıştırarak:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp` (process başlangıç yolu)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (process/güvenlik yapılandırması)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (`execve`'in kernel tarafı, dyld yükleme)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (`dyld_all_image_infos` yapısı)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
