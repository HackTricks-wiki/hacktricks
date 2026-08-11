# mchakato wa Dyld wa macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

**`entrypoint`** halisi ya binary ya Mach-o ni dynamic linked, iliyofafanuliwa katika `LC_LOAD_DYLINKER`, ambayo kwa kawaida huwa `/usr/lib/dyld`.<sup>[[3]](#references)</sup>

Linker hii inahitaji kutafuta libraries zote za executable, kuziweka kwenye memory na ku-link libraries zote zisizo lazy. Ni baada tu ya mchakato huu ndipo entry-point ya binary itatekelezwa.

Bila shaka, **`dyld`** haina dependencies zozote (inatumia syscalls na excerpts za libSystem).

> [!CAUTION]
> Ikiwa linker hii ina vulnerability yoyote, kwa kuwa inatekelezwa kabla ya binary yoyote kutekelezwa (hata zile zenye privileges za juu), itawezekana **ku-escalate privileges**.

### Mtiririko

Dyld itapakiwa na **`dyldboostrap::start`**, ambayo pia itapakia vitu kama **stack canary**. Hii ni kwa sababu function hii itapokea katika vector yake ya **`apple`** argument hii pamoja na **values** nyingine **sensitive**.<sup>[[1]](#references)</sup>

**`dyls::_main()`** ni entry point ya dyld, na kazi yake ya kwanza ni kuendesha `configureProcessRestrictions()`, ambayo kwa kawaida huzuia environment variables za **`DYLD_*`** zilizoelezwa katika:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Kisha, ina-map dyld shared cache ambayo hu-prelink system libraries zote muhimu, halafu ina-map libraries ambazo binary inategemea na kuendelea recursively hadi libraries zote zinazohitajika ziwe zimepakiwa. Kwa hiyo:

1. inaanza kupakia libraries zilizoingizwa kwa `DYLD_INSERT_LIBRARIES` (ikiwa inaruhusiwa)
2. Kisha zile za shared cache
3. Kisha zile zilizo-importiwa
1. Kisha inaendelea ku-import libraries recursively

Baada ya zote kupakiwa, **initialisers** za libraries hizi huendeshwa. Hizi huandikwa kwa kutumia **`__attribute__((constructor))`**, iliyofafanuliwa katika `LC_ROUTINES[_64]` (ambayo sasa imepitwa na wakati), au kwa pointer katika section iliyo na flag `S_MOD_INIT_FUNC_POINTERS` (kwa kawaida: **`__DATA.__MOD_INIT_FUNC`**).

Terminators huandikwa kwa **`__attribute__((destructor))`** na hupatikana katika section iliyo na flag `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Binaries zote za macOS zina dynamic linking. Kwa hiyo, zina sections za stubs zinazosaidia binary kuruka hadi kwenye code sahihi kwenye machines na contexts tofauti. Ni dyld, wakati binary inatekelezwa, ndiyo inayohusika na kutatua addresses hizi (angalau zile zisizo lazy).

Baadhi ya sections za stubs katika binary:

- **`__TEXT.__[auth_]stubs`**: Pointers kutoka kwenye sections za `__DATA`
- **`__TEXT.__stub_helper`**: Code ndogo inayotumia dynamic linking ikiwa na taarifa kuhusu function itakayoitwa
- **`__DATA.__[auth_]got`**: Global Offset Table (addresses za functions zilizo-importiwa, zinapotatuliwa, (hufungwa wakati wa load time kwa kuwa zimewekewa flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Non-lazy symbol pointers (hufungwa wakati wa load time kwa kuwa zimewekewa flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Lazy symbols pointers (hufungwa wakati wa access ya kwanza)

> [!WARNING]
> Kumbuka kwamba pointers zilizo na prefix "auth_" zinatumia encryption key moja ya in-process kuzilinda (PAC). Zaidi ya hayo, inawezekana kutumia instruction ya arm64 `BLRA[A/B]` ili ku-verify pointer kabla ya kuifuata. Na RETA\[A/B] inaweza kutumika badala ya RET address.\
> Kwa kweli, code iliyo katika **`__TEXT.__auth_stubs`** itatumia **`braa`** badala ya **`bl`** kuita function iliyoombwa na ku-authenticate pointer.
>
> Pia kumbuka kwamba versions za sasa za dyld hupakia kila kitu kama non-lazy.

### Kutafuta lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Sehemu ya kuvutia ya disassembly:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Inawezekana kuona kwamba jump ya kuita printf inaelekea kwenye **`__TEXT.__stubs`**:
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
Katika disassemble ya sehemu ya **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
unaweza kuona kwamba **tunarukia anwani ya GOT**, ambayo katika hali hii imetatuliwa bila kucheleweshwa na itakuwa na anwani ya function ya printf.

Katika hali nyingine, badala ya kurukia moja kwa moja GOT, inaweza kurukia **`__DATA.__la_symbol_ptr`**, ambayo itapakia value inayowakilisha function inayojaribu kupakia, kisha irukie **`__TEXT.__stub_helper`**, ambayo hurukia **`__DATA.__nl_symbol_ptr`** yenye anwani ya **`dyld_stub_binder`**, inayopokea kama parameters nambari ya function na anwani.\
Function hii ya mwisho, baada ya kupata anwani ya function iliyotafutwa, huiandika katika eneo linalolingana ndani ya **`__TEXT.__stub_helper`** ili kuepuka kufanya lookups siku zijazo.

> [!TIP]
> Hata hivyo, tambua kwamba matoleo ya sasa ya dyld hupakia kila kitu bila kucheleweshwa.

#### Dyld opcodes

Mwishowe, **`dyld_stub_binder`** inahitaji kupata function iliyoonyeshwa na kuiandika katika anwani sahihi ili isaitafute tena. Ili kufanya hivyo, hutumia opcodes (finite state machine) ndani ya dyld.

## apple\[] argument vector

Katika macOS, function kuu hupokea arguments 4 badala ya 3. Ya nne huitwa apple, na kila entry iko katika muundo wa `key=value`. Kwa mfano:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Tafadhali tuma maandishi ya Kiingereza unayotaka yatafsiriwe.
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
> Kufikia wakati thamani hizi zinafikia function kuu, taarifa nyeti huwa tayari zimeondolewa ndani yake au vingekuwa data leak.

inawezekana kuona thamani hizi zote za kuvutia kwa kutumia debugging kabla ya kuingia kwenye main kwa:

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

Hii ni structure inayotolewa na dyld yenye taarifa kuhusu hali ya dyld, ambayo inaweza kupatikana kwenye [**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html), ikiwa na taarifa kama vile version, pointer ya dyld_image_info array, ya dyld_image_notifier, ikiwa proc imetenganishwa na shared cache, ikiwa libSystem initializer iliitwa, pointer ya Mach header ya dyld yenyewe, pointer ya dyld version string...<sup>[[4]](#references)</sup>

## dyld env variables

### debug dyld

env variables zinazovutia zinazosaidia kuelewa dyld inafanya nini:

- **DYLD_PRINT_LIBRARIES**

Kagua kila library inayopakiwa:
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

Angalia jinsi kila library inavyopakiwa:
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

Chapisha wakati kila library initializer inaendeshwa:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Zingine

- `DYLD_BIND_AT_LAUNCH`: Lazy bindings hutatuliwa pamoja na non lazy bindings
- `DYLD_DISABLE_PREFETCH`: Lemaza pre-fetching ya maudhui ya \_\_DATA na \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Bindings za kiwango kimoja
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Njia za utatuzi
- `DYLD_INSERT_LIBRARIES`: Pakia library maalum
- `DYLD_PRINT_TO_FILE`: Andika debug ya dyld kwenye faili
- `DYLD_PRINT_APIS`: Chapisha miito ya libdyld API
- `DYLD_PRINT_APIS_APP`: Chapisha miito ya libdyld API iliyofanywa na main
- `DYLD_PRINT_BINDINGS`: Chapisha symbols zinapofungwa
- `DYLD_WEAK_BINDINGS`: Chapisha tu weak symbols zinapofungwa
- `DYLD_PRINT_CODE_SIGNATURES`: Chapisha utendaji wa usajili wa code signature
- `DYLD_PRINT_DOFS`: Chapisha sehemu za D-Trace object format zinapopakiwa
- `DYLD_PRINT_ENV`: Chapisha env inayoonekana na dyld
- `DYLD_PRINT_INTERPOSTING`: Chapisha utendaji wa interposting
- `DYLD_PRINT_LIBRARIES`: Chapisha libraries zilizopakiwa
- `DYLD_PRINT_OPTS`: Chapisha chaguo za upakiaji
- `DYLD_REBASING`: Chapisha utendaji wa symbol rebasing
- `DYLD_RPATHS`: Chapisha upanuzi wa @rpath
- `DYLD_PRINT_SEGMENTS`: Chapisha mappings za Mach-O segments
- `DYLD_PRINT_STATISTICS`: Chapisha takwimu za muda
- `DYLD_PRINT_STATISTICS_DETAILS`: Chapisha takwimu za kina za muda
- `DYLD_PRINT_WARNINGS`: Chapisha ujumbe wa maonyo
- `DYLD_SHARED_CACHE_DIR`: Njia ya kutumia kwa shared library cache
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Wezesha closures

Inawezekana kupata zaidi kwa kitu kama:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Au kupakua mradi wa dyld kutoka [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) na kuendesha ndani ya folda:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp` (njia ya kuanzisha process)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (usanidi wa process/security)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (upande wa kernel wa `execve`, kupakia dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (muundo wa `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
