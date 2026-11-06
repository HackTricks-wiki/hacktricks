# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Mach-o ikilisinin gerçek **entrypoint**'i, `LC_LOAD_DYLINKER` içinde tanımlanan ve genellikle `/usr/lib/dyld` olan dinamik bağlayıcıdır.<sup>[[3]](#references)</sup>

Bu bağlayıcının tüm yürütülebilir dosya kütüphanelerini bulması, belleğe eşlemesi ve lazy olmayan tüm kütüphaneleri bağlaması gerekir. İkili dosyanın entry-point'i ancak bu işlemden sonra yürütülür.

Elbette **`dyld`**'nin hiçbir bağımlılığı yoktur (syscall'ları ve libSystem alıntılarını kullanır).

> [!CAUTION]
> Bu bağlayıcıda herhangi bir güvenlik açığı varsa, herhangi bir ikili dosya (yüksek ayrıcalıklı olanlar da dahil) yürütülmeden önce çalıştırıldığından **ayrıcalık yükseltmek** mümkün olabilir.

### Akış

Dyld, **stack canary** gibi şeyleri de yükleyen **`dyldboostrap::start`** tarafından yüklenir. Bunun nedeni, bu işlevin **`apple`** argüman vektöründe bu ve diğer **hassas** **değerleri** almasıdır.<sup>[[1]](#references)</sup>

Dyld'nin entry point'i olan **`dyls::_main()`**'in ilk görevi, genellikle aşağıda açıklanan **`DYLD_*`** ortam değişkenlerini kısıtlayan `configureProcessRestrictions()` işlevini çalıştırmaktır:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Ardından, önemli sistem kütüphanelerini önceden bağlayan dyld shared cache'i eşler; sonrasında ikili dosyanın bağımlı olduğu kütüphaneleri eşler ve gereken tüm kütüphaneler yüklenene kadar özyinelemeli olarak devam eder. Dolayısıyla:

1. izin veriliyorsa `DYLD_INSERT_LIBRARIES` ile eklenen kütüphaneleri yüklemeye başlar
2. Ardından shared cache'tekileri yükler
3. Ardından içe aktarılanları yükler
   1. Sonra kütüphaneleri özyinelemeli olarak içe aktarmaya devam eder

Tümü yüklendikten sonra bu kütüphanelerin **initialiser** işlevleri çalıştırılır. Bunlar, `LC_ROUTINES[_64]` içinde tanımlanan (artık kullanımdan kaldırılmıştır) veya `S_MOD_INIT_FUNC_POINTERS` bayrağı bulunan bir bölümdeki işaretçiyle (genellikle: **`__DATA.__MOD_INIT_FUNC`**) tanımlanan **`__attribute__((constructor))`** kullanılarak kodlanır.

Terminator işlevleri **`__attribute__((destructor))`** ile kodlanır ve `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**) bayrağı bulunan bir bölümde yer alır.

Ayrıca bkz.: [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

### Stubs

macOS'taki tüm ikililer dinamik olarak bağlanır. Bu nedenle, ikililer farklı makinelerde ve bağlamlarda doğru koda dallanmaya yardımcı olan bazı stub bölümleri içerir. İkili dosya yürütüldüğünde bu adresleri çözümlemesi gereken bileşen dyld'dir (en azından lazy olmayanları).

İkili dosyadaki bazı stub bölümleri:

- **`__TEXT.__[auth_]stubs`**: `__DATA` bölümlerinden gelen işaretçiler
- **`__TEXT.__stub_helper`**: Çağrılacak işlevle ilgili bilgileri kullanarak dinamik bağlamayı çağıran küçük bir kod parçası
- **`__DATA.__[auth_]got`**: Global Offset Table (içe aktarılan işlevlerin adresleri; çözümlendikten sonra, `S_NON_LAZY_SYMBOL_POINTERS` bayrağıyla işaretlendiğinden yükleme sırasında bağlanır)
- **`__DATA.__nl_symbol_ptr`**: Lazy olmayan sembol işaretçileri (`S_NON_LAZY_SYMBOL_POINTERS` bayrağıyla işaretlendiğinden yükleme sırasında bağlanır)
- **`__DATA.__la_symbol_ptr`**: Lazy sembol işaretçileri (ilk erişimde bağlanır)

> [!WARNING]
> "auth\_" önekine sahip işaretçilerin, onları korumak için süreç içi şifreleme anahtarı (PAC) kullandığını unutmayın. Ayrıca işaretçiyi izlemeye geçmeden önce doğrulamak için arm64 `BLRA[A/B]` komutunu kullanmak mümkündür. RET adresi yerine RETA\[A/B] kullanılabilir.\
> Aslında **`__TEXT.__auth_stubs`** içindeki kod, istenen işlevi çağırırken işaretçinin kimliğini doğrulamak için **`bl`** yerine **`braa`** kullanır.
>
> Ayrıca mevcut dyld sürümlerinin **her şeyi lazy olmayan şekilde** yüklediğini unutmayın.

### Lazy sembolleri bulma

```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    printf("Hi\n");
}
```

İlginç disassembly bölümü:

```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```

printf çağrısına yapılan atlamanın **`__TEXT.__stubs`** bölümüne gittiği görülebilir:

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

GOT'un adresine **atladığımızı** görebilirsiniz. Bu durumda adres lazy olmayan şekilde çözümlenir ve `printf` fonksiyonunun adresini içerir.

Bazı durumlarda doğrudan GOT'a atlamak yerine **`__DATA.__la_symbol_ptr`**'a atlanabilir. Bu, yüklenmeye çalışılan fonksiyonu temsil eden bir değeri yükler. Ardından **`__TEXT.__stub_helper`**'a atlar; o da **`dyld_stub_binder`** adresini içeren **`__DATA.__nl_symbol_ptr`**'a atlar. `dyld_stub_binder`, parametre olarak fonksiyonun numarasını ve bir adresi alır.\
Binder, sembolü çözümler ve **`__DATA.__la_symbol_ptr`** yuvasını günceller. Stub, sonraki çağrılarda çözümlenmiş bu işaretçiyi kullanır; işaretçi **`__TEXT.__stub_helper`** içinde yeniden yazılmaz.<sup>[[5]](#references)</sup>

> [!TIP]
> Ancak mevcut dyld sürümlerinin her şeyi lazy olmayan şekilde yüklediğine dikkat edin.

#### Dyld opcode'ları

Son olarak **`dyld_stub_binder`**, belirtilen fonksiyonu bulup onu uygun adrese yazmalıdır; böylece fonksiyonu yeniden araması gerekmez. Bunu yapmak için dyld içindeki opcode'ları (sonlu durum makinesi) kullanır.

## apple\[] argüman vektörü

macOS'ta main fonksiyonu aslında 3 yerine 4 argüman alır. Dördüncüsüne apple denir ve her girdi `key=value` biçimindedir. Örneğin:

```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    for (int i=0; apple[i]; i++)
        printf("%d: %s\n", i, apple[i])
}
```

Sonuç:

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
> Bu değerler main function'a ulaştığında, hassas bilgiler bu değerlerden zaten kaldırılmış olur; aksi hâlde bu bir data leak olurdu.

main'e ulaşmadan önce debugging yaparak bu ilginç değerlerin tümünü görmek mümkündür:

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

Bu, dyld tarafından dışa aktarılan ve dyld durumuyla ilgili bilgileri içeren bir yapıdır. [**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) içinde bulunabilir ve sürüm, dyld_image_info dizisine işaretçi, dyld_image_notifier'a işaretçi, proc'un shared cache'ten ayrılıp ayrılmadığı, libSystem initializer'ın çağrılıp çağrılmadığı, dyld'nin kendi Mach header'ına işaretçi, dyld sürüm dizgesi gibi bilgileri içerir...<sup>[[4]](#references)</sup>

## dyld env variables

### dyld debugging

dyld'nin ne yaptığını anlamaya yardımcı olan ilginç env variables:

- **DYLD_PRINT_LIBRARIES**

Yüklenen her library'yi kontrol edin:

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

Her kütüphane başlatıcısı çalışırken yazdır:

```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```

### Çalışma zamanı library çözümlemesini izleme

Kontrol edebildiğiniz bir başlatma için, replacement dylib yerleştirmeden önce bir `@rpath` veya weak-library adayını izleyin. `DYLD_PRINT_SEARCHING`, dyld tarafından değerlendirilen yolları bildirirken `DYLD_PRINT_LIBRARIES` gerçekten yüklenen image'ları gösterir. `DYLD_PRINT_LOADERS`, `JustInTimeLoader` ile `PrebuiltLoader` arasındaki farkı belirtir ve prebuilt loader set kullanımını bildirir.<sup>[[6]](#references)</sup>

```bash
DYLD_PRINT_SEARCHING=1 DYLD_PRINT_LOADERS=1 DYLD_PRINT_LIBRARIES=1 /path/to/binary 2>&1 | tee /tmp/dyld-search.log
```

`LC_RPATH` satırında run path sağlayan image'ı bulun, ardından `possible path(...)` adaylarını `found: dylib-from-disk`, `found: dylib-from-cache` veya bir ret mesajıyla karşılaştırın. Bir aday path, dylib'in yüklendiğinin **kanıtı değildir**. Beklenen library'den önceki ilk kullanılabilir disk path'inde yazma erişimini ve [library-validation kısıtlamalarını](./#library-validation) test edin.<sup>[[7]](#references)</sup>

Önceden derlenmiş bir loader, tam path aramasını tekrarlamak yerine kaydedilmiş bağımlılık bilgilerini yeniden kullanabilir. Bu nedenle, seyrek arama çıktısı bir image'ın bağımlılığı olmadığı anlamına gelmez; yükleme komutlarını `otool -l` ile inceleyip library listesini karşılaştırın.<sup>[[8]](#references)</sup> Bu tanılamalar ayrıca dyld'nin print-variable iznini gerektirir; dolayısıyla korumalı bir hedef bunları tamamen yok sayabilir.<sup>[[2]](#references)</sup> Gerçek replacement-library ön koşulları için [Dylib Hijacking](./#dylib-hijacking) bölümüne bakın.

### Diğerleri

Aşağıdaki bazı switch'ler eski dyld sürümlerine özgüdür. Her değişkenin hâlâ çalıştığını varsaymak yerine, hedef sürümde desteklenip desteklenmediğini kontrol edin.<sup>[[2]](#references)[[9]](#references)</sup>

- `DYLD_BIND_AT_LAUNCH`: Lazy binding'ler non-lazy binding'lerle birlikte çözülür
- `DYLD_DISABLE_PREFETCH`: \_\_DATA ve \_\_LINKEDIT içeriğinin önceden getirilmesini devre dışı bırakır
- `DYLD_FORCE_FLAT_NAMESPACE`: Tek seviyeli binding'ler
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Çözümleme path'leri
- `DYLD_INSERT_LIBRARIES`: Belirli bir library'yi yükler
- `DYLD_PRINT_TO_FILE`: dyld hata ayıklama çıktısını bir dosyaya yazar
- `DYLD_PRINT_APIS`: libdyld API çağrılarını yazdırır
- `DYLD_PRINT_APIS_APP`: main tarafından yapılan libdyld API çağrılarını yazdırır
- `DYLD_PRINT_BINDINGS`: Binding sırasında sembolleri yazdırır
- `DYLD_PRINT_WEAK_BINDINGS` (dyld2): Weak symbol binding'lerini yazdırır
- `DYLD_PRINT_CODE_SIGNATURES`: Code signature kayıt işlemlerini yazdırır
- `DYLD_PRINT_DOFS`: Yüklenirken D-Trace object format bölümlerini yazdırır
- `DYLD_PRINT_ENV`: dyld'nin gördüğü ortamı yazdırır
- `DYLD_PRINT_INTERPOSING`: Interposing işlemlerini yazdırır
- `DYLD_PRINT_LIBRARIES`: Yüklenen library'leri yazdırır
- `DYLD_PRINT_OPTS`: Yükleme seçeneklerini yazdırır
- `DYLD_PRINT_REBASINGS` (dyld2): Symbol rebasing işlemlerini yazdırır
- `DYLD_PRINT_RPATHS` (dyld2): `@rpath` genişletmelerini yazdırır
- `DYLD_PRINT_SEGMENTS`: Mach-O segmentlerinin eşlemelerini yazdırır
- `DYLD_PRINT_STATISTICS`: Zamanlama istatistiklerini yazdırır
- `DYLD_PRINT_STATISTICS_DETAILS`: Ayrıntılı zamanlama istatistiklerini yazdırır
- `DYLD_PRINT_WARNINGS`: Uyarı mesajlarını yazdırır
- `DYLD_SHARED_CACHE_DIR`: Shared library cache için kullanılacak path
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Closures'ı etkinleştirir

Şuna benzer bir yöntemle daha fazlasını bulmak mümkündür:

```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```

Ya da [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) adresinden dyld projesini indirip klasörün içinde çalıştırarak:

```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```



## References

- [1] [dyld — `dyld/dyldMain.cpp` (süreç başlangıç yolu)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (süreç/güvenlik yapılandırması)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (`execve` işleminin kernel tarafı, dyld yükleme)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (`dyld_all_image_infos` yapısı)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
- [5] [fishhook — lazy ve non-lazy sembol işaretçisi bağlama](https://github.com/meta/fishhook)
- [6] [dyld(1) — dinamik bağlayıcı tanılamaları](https://github.com/apple-oss-distributions/dyld/blob/main/doc/man/man1/dyld.1)
- [7] [dyld — çalışma zamanı kütüphane yolu araması](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp)
- [8] [dyld4 — önceden derlenmiş ve just-in-time yükleyiciler](https://github.com/apple-oss-distributions/dyld/blob/main/doc/dyld4.md)
- [9] [dyld2 — eski tanılama değişkeni adları](https://github.com/apple-oss-distributions/dyld/blob/dyld-852.2/src/dyld2.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
