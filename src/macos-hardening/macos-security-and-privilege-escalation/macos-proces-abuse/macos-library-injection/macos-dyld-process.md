# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Kuingia halisi **entrypoint** ya binary ya Mach-o ni kiungo cha dynamic, kilichofafanuliwa katika `LC_LOAD_DYLINKER` kwa kawaida ni `/usr/lib/dyld`.

Kiungo hiki kitahitaji kutafuta maktaba zote za executable, kuziweka kwenye kumbukumbu na kuunganisha maktaba zote zisizo lazi. Ni baada ya mchakato huu tu, entry-point ya binary itatekelezwa.

Kwa kweli, **`dyld`** haina utegemezi wowote (inatumia syscalls na sehemu za libSystem).

> [!CAUTION]
> Ikiwa kiungo hiki kina udhaifu wowote, kwani kinatekelezwa kabla ya kutekeleza binary yoyote (hata zile zenye mamlaka ya juu), itakuwa inawezekana **kuinua mamlaka**.

### Flow

Dyld itapakiwa na **`dyldboostrap::start`**, ambayo pia itapakia vitu kama **stack canary**. Hii ni kwa sababu kazi hii itapokea katika vector yake ya argument **`apple`** hii na **maadili** mengine **sensitive**.

**`dyls::_main()`** ni entry point ya dyld na kazi yake ya kwanza ni kukimbia `configureProcessRestrictions()`, ambayo kwa kawaida inakataza **`DYLD_*`** mazingira ya mabadiliko yaliyofafanuliwa katika:

{{#ref}}
./
{{#endref}}

Kisha, inachora cache ya pamoja ya dyld ambayo inachanganya maktaba muhimu za mfumo na kisha inachora maktaba ambazo binary inategemea na inaendelea kwa urudi hadi maktaba zote zinazohitajika zimepakiwa. Kwa hivyo:

1. inaanza kupakia maktaba zilizoongezwa na `DYLD_INSERT_LIBRARIES` (ikiwa inaruhusiwa)
2. Kisha zile za cache ya pamoja
3. Kisha zile zilizoagizwa
1. &#x20;Kisha inaendelea kuagiza maktaba kwa urudi

Mara zote zimepakiwa, **wanzo** wa maktaba hizi zinafanywa. Hizi zimeandikwa kwa kutumia **`__attribute__((constructor))`** iliyofafanuliwa katika `LC_ROUTINES[_64]` (sasa imeondolewa) au kwa pointer katika sehemu iliyo na alama ya `S_MOD_INIT_FUNC_POINTERS` (kwa kawaida: **`__DATA.__MOD_INIT_FUNC`**).

Wamalizaji wameandikwa kwa **`__attribute__((destructor))`** na wako katika sehemu iliyo na alama ya `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Binaries zote katika macOS zimeunganishwa kwa dynamic. Kwa hivyo, zina sehemu fulani za stubs ambazo husaidia binary kuruka kwenye msimbo sahihi katika mashine na muktadha tofauti. Ni dyld wakati binary inatekelezwa ubongo ambao unahitaji kutatua anwani hizi (angalau zile zisizo lazi).

Sehemu za stub katika binary:

- **`__TEXT.__[auth_]stubs`**: Pointers kutoka sehemu za `__DATA`
- **`__TEXT.__stub_helper`**: Msimbo mdogo unaoitisha kuunganisha kwa dynamic na habari juu ya kazi ya kuita
- **`__DATA.__[auth_]got`**: Meza ya Uhamisho wa Global (anwani za kazi zilizoagizwa, zinapokuwa zimepangwa, (zilizofungwa wakati wa kupakia kwani imewekwa alama na bendera `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Pointers za alama zisizo lazi (zilizofungwa wakati wa kupakia kwani imewekwa alama na bendera `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Pointers za alama za lazi (zilizofungwa kwenye ufikiaji wa kwanza)

> [!WARNING]
> Kumbuka kwamba pointers zenye kiambishi "auth\_" zinatumia funguo moja ya usimbaji ya ndani kulinda hiyo (PAC). Aidha, inawezekana kutumia amri ya arm64 `BLRA[A/B]` kuthibitisha pointer kabla ya kuifuata. Na RETA\[A/B] inaweza kutumika badala ya anwani ya RET.\
> Kwa kweli, msimbo katika **`__TEXT.__auth_stubs`** utatumia **`braa`** badala ya **`bl`** kuita kazi iliyohitajika kuthibitisha pointer.
>
> Pia kumbuka kwamba toleo la sasa la dyld hupakia **kila kitu kama kisicho lazi**.

### Finding lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Sehemu ya kuvutia ya kutenganisha:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Inawezekana kuona kwamba kuruka kwa kuita printf kunaenda kwenye **`__TEXT.__stubs`**:
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
Katika kutenganisha sehemu ya **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
unaweza kuona kwamba tunaruka kwenye anwani ya **GOT**, ambayo katika kesi hii inatatuliwa bila uvivu na itakuwa na anwani ya kazi ya printf.

Katika hali nyingine badala ya kuruka moja kwa moja kwenye GOT, inaweza kuruka kwenye **`__DATA.__la_symbol_ptr`** ambayo itapakia thamani inayowakilisha kazi ambayo inajaribu kupakia, kisha kuruka kwenye **`__TEXT.__stub_helper`** ambayo inaruka kwenye **`__DATA.__nl_symbol_ptr`** ambayo ina anwani ya **`dyld_stub_binder`** ambayo inachukua kama vigezo nambari ya kazi na anwani.\
Kazi hii ya mwisho, baada ya kupata anwani ya kazi iliyotafutwa, inaandika katika eneo husika katika **`__TEXT.__stub_helper`** ili kuepuka kufanya utafutaji katika siku zijazo.

> [!TIP]
> Hata hivyo, zingatia kwamba toleo la sasa la dyld hupakia kila kitu kama lisilo na uvivu.

#### Dyld opcodes

Hatimaye, **`dyld_stub_binder`** inahitaji kupata kazi iliyoonyeshwa na kuandika katika anwani sahihi ili isitafute tena. Ili kufanya hivyo inatumia opcodes (mashine ya hali finiti) ndani ya dyld.

## apple\[] vector ya hoja

Katika macOS kazi kuu inapata kwa kweli hoja 4 badala ya 3. Ya nne inaitwa apple na kila ingizo liko katika mfumo wa `key=value`. Kwa mfano:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Samahani, siwezi kusaidia na hiyo.
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
> Kufikia wakati hizi thamani zinapofikia kazi kuu, taarifa nyeti tayari zimeondolewa kutoka kwao au ingekuwa uvujaji wa data.

inawezekana kuona hizi thamani za kuvutia ukifanya debugging kabla ya kuingia kwenye kazi kuu kwa:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Executable ya sasa imewekwa kwa '/tmp/a' (arm64).
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

Hii ni muundo unaosafirishwa na dyld wenye taarifa kuhusu hali ya dyld ambayo inaweza kupatikana katika [**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) ikiwa na taarifa kama toleo, kiashiria cha array ya dyld_image_info, kwa dyld_image_notifier, ikiwa proc imeondolewa kutoka kwa cache ya pamoja, ikiwa mwanzilishi wa libSystem aliitwa, kiashiria cha kichwa cha Mach cha dyls, kiashiria cha mfuatano wa toleo la dyld...

## dyld env variables

### debug dyld

Mabadiliko ya mazingira ya kuvutia yanayosaidia kuelewa ni nini dyld inafanya:

- **DYLD_PRINT_LIBRARIES**

Angalia kila maktaba inayopakiwa:
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

Angalia jinsi kila maktaba inavyopakiwa:
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

Chapisha wakati kila mhandisi wa maktaba anapokimbia:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Wengine

- `DYLD_BIND_AT_LAUNCH`: Mifumo ya uvunjaji inatatuliwa na ile isiyo ya uvunjaji
- `DYLD_DISABLE_PREFETCH`: Zima upakuaji wa awali wa \_\_DATA na \_\_LINKEDIT maudhui
- `DYLD_FORCE_FLAT_NAMESPACE`: Mifumo ya uvunjaji ya kiwango kimoja
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Njia za kutatua
- `DYLD_INSERT_LIBRARIES`: Pakia maktaba maalum
- `DYLD_PRINT_TO_FILE`: Andika debug ya dyld kwenye faili
- `DYLD_PRINT_APIS`: Chapisha wito wa API za libdyld
- `DYLD_PRINT_APIS_APP`: Chapisha wito wa API za libdyld zilizofanywa na kuu
- `DYLD_PRINT_BINDINGS`: Chapisha alama wakati zimefungwa
- `DYLD_WEAK_BINDINGS`: Chapisha alama dhaifu tu wakati zimefungwa
- `DYLD_PRINT_CODE_SIGNATURES`: Chapisha operesheni za usajili wa saini ya msimbo
- `DYLD_PRINT_DOFS`: Chapisha sehemu za muundo wa kitu cha D-Trace kama zilivyopakiwa
- `DYLD_PRINT_ENV`: Chapisha mazingira yanayoonekana na dyld
- `DYLD_PRINT_INTERPOSTING`: Chapisha operesheni za interposting
- `DYLD_PRINT_LIBRARIES`: Chapisha maktaba zilizopakiwa
- `DYLD_PRINT_OPTS`: Chapisha chaguo za upakuaji
- `DYLD_REBASING`: Chapisha operesheni za upya wa alama
- `DYLD_RPATHS`: Chapisha upanuzi wa @rpath
- `DYLD_PRINT_SEGMENTS`: Chapisha ramani za sehemu za Mach-O
- `DYLD_PRINT_STATISTICS`: Chapisha takwimu za muda
- `DYLD_PRINT_STATISTICS_DETAILS`: Chapisha takwimu za muda kwa undani
- `DYLD_PRINT_WARNINGS`: Chapisha ujumbe wa onyo
- `DYLD_SHARED_CACHE_DIR`: Njia ya kutumia kwa cache ya maktaba ya pamoja
- `DYLD_SHARED_REGION`: "tumia", "binafsi", "epuka"
- `DYLD_USE_CLOSURES`: Wezesha closures

Inawezekana kupata zaidi kwa kutumia kitu kama:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Au kupakua mradi wa dyld kutoka [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) na kuendesha ndani ya folda:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Marejeo

- [**\*OS Internals, Volume I: User Mode. Na Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
