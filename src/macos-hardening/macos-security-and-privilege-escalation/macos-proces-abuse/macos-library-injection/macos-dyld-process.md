# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

Die werklike **entrypoint** van 'n Mach-o-binêre lêer is die dinamies gekoppelde linker, wat in `LC_LOAD_DYLINKER` gedefinieer word en gewoonlik `/usr/lib/dyld` is.<sup>[[3]](#references)</sup>

Hierdie linker moet al die uitvoerbare lêers se biblioteke opspoor, dit in die geheue karteer en al die nie-lui biblioteke koppel. Slegs ná hierdie proses sal die binêre lêer se entrypoint uitgevoer word.

Natuurlik het **`dyld`** geen afhanklikhede nie (dit gebruik syscalls en uittreksels uit libSystem).

> [!CAUTION]
> As hierdie linker enige kwesbaarheid bevat, aangesien dit uitgevoer word voordat enige binêre lêer (selfs hoogs bevoorregte lêers) uitgevoer word, sou dit moontlik wees om **voorregte te eskaleer**.

### Vloei

Dyld sal deur **`dyldboostrap::start`** gelaai word, wat ook dinge soos die **stack canary** sal laai. Dit is omdat hierdie funksie in sy **`apple`**-argumentvektor hierdie en ander **sensitiewe** **waardes** sal ontvang.<sup>[[1]](#references)</sup>

**`dyls::_main()`** is die entrypoint van dyld en sy eerste taak is om `configureProcessRestrictions()` uit te voer, wat gewoonlik **`DYLD_*`**-omgewingsveranderlikes beperk, soos verduidelik in:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Daarna karteer dit die dyld shared cache, wat al die belangrike stelselbiblioteke vooraf koppel, en dan karteer dit die biblioteke waarvan die binêre lêer afhanklik is en gaan dit rekursief voort totdat al die nodige biblioteke gelaai is. Daarom:

1. dit begin om ingevoegde biblioteke met `DYLD_INSERT_LIBRARIES` te laai (indien toegelaat)
2. Dan dié in die shared cache
3. Dan die ingevoerde biblioteke
1. Gaan dan voort om biblioteke rekursief in te voer

Sodra almal gelaai is, word die **initialisers** van hierdie biblioteke uitgevoer. Dit word gekodeer met **`__attribute__((constructor))`**, gedefinieer in `LC_ROUTINES[_64]` (nou deprecated), of deur 'n pointer in 'n seksie met die vlag `S_MOD_INIT_FUNC_POINTERS` (gewoonlik: **`__DATA.__MOD_INIT_FUNC`**).

Terminators word met **`__attribute__((destructor))`** gekodeer en is geleë in 'n seksie met die vlag `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Alle binaries in macOS is dinamies gekoppel. Daarom bevat hulle sommige stub-seksies wat die binêre lêer help om na die korrekte kode op verskillende masjiene en in verskillende kontekste te spring. Wanneer die binêre lêer uitgevoer word, is dit dyld se taak om hierdie adresse op te los (ten minste die nie-lui adresse).

Sommige stub-seksies in die binêre lêer:

- **`__TEXT.__[auth_]stubs`**: Pointers vanaf `__DATA`-seksies
- **`__TEXT.__stub_helper`**: Klein kode wat dynamic linking oproep met inligting oor die funksie wat geroep moet word
- **`__DATA.__[auth_]got`**: Global Offset Table (adresse na ingevoerde funksies, wanneer dit opgelos is, (gebind tydens laaityd omdat dit met die vlag `S_NON_LAZY_SYMBOL_POINTERS` gemerk is)
- **`__DATA.__nl_symbol_ptr`**: Nie-lui simboolpointers (gebind tydens laaityd omdat dit met die vlag `S_NON_LAZY_SYMBOL_POINTERS` gemerk is)
- **`__DATA.__la_symbol_ptr`**: Lui simboolpointers (gebind tydens die eerste toegang)

> [!WARNING]
> Let daarop dat die pointers met die voorvoegsel "auth\_" een in-process encryption key gebruik om dit te beskerm (PAC). Dit is ook moontlik om die arm64-instruksie `BLRA[A/B]` te gebruik om die pointer te verifieer voordat dit gevolg word. En RETA\[A/B] kan in plaas van 'n RET-adres gebruik word.\
> Die kode in **`__TEXT.__auth_stubs`** sal eintlik **`braa`** in plaas van **`bl`** gebruik om die aangevraagde funksie te roep en die pointer te autentiseer.
>
> Let ook daarop dat huidige dyld-weergawes alles as nie-lui laai.

### Vind van lui simbole
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Interessante disassembleringsgedeelte:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Dit is moontlik om te sien dat die sprong om printf aan te roep na **`__TEXT.__stubs`** gaan:
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
In die disassembly van die **`__stubs`**-afdeling:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
jy kan sien dat ons **na die adres van die GOT spring**, wat in hierdie geval non-lazy opgelos word en die adres van die printf-funksie sal bevat.

In ander situasies kan dit, in plaas daarvan om direk na die GOT te spring, na **`__DATA.__la_symbol_ptr`** spring, wat ’n waarde sal laai wat die funksie verteenwoordig wat dit probeer laai. Daarna spring dit na **`__TEXT.__stub_helper`**, wat na **`__DATA.__nl_symbol_ptr`** spring. Dit bevat die adres van **`dyld_stub_binder`**, wat die nommer van die funksie en ’n adres as parameters aanvaar.\
Hierdie laaste funksie skryf, nadat dit die adres van die gesoekte funksie gevind het, die adres daarvan na die ooreenstemmende ligging in **`__TEXT.__stub_helper`** om te voorkom dat daar in die toekoms weer opsoekings gedoen word.

> [!TIP]
> Let egter daarop dat huidige dyld-weergawes alles as non-lazy laai.

#### Dyld opcodes

Laastens moet **`dyld_stub_binder`** die aangeduide funksie vind en dit by die korrekte adres skryf sodat dit nie weer daarna hoef te soek nie. Om dit te doen, gebruik dit opcodes (’n eindige toestandsmasjien) binne dyld.

## apple\[] argumentvektor

In macOS ontvang die hooffunksie eintlik 4 argumente in plaas van 3. Die vierde word apple genoem, en elke inskrywing het die vorm `key=value`. Byvoorbeeld:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Geen Engelse bronteks is verskaf om te vertaal nie.
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
> Teen die tyd dat hierdie waardes die main function bereik, is sensitiewe inligting reeds daaruit verwyder, anders sou dit ’n data leak gewees het.

dit is moontlik om al hierdie interessante waardes te sien deur te debug voordat main betree word met:

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

Dit is ’n struktuur wat deur dyld uitgevoer word met inligting oor die dyld-toestand, wat in die [**bronkode**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) gevind kan word. Dit bevat inligting soos die weergawe, ’n wyser na die dyld_image_info-array, ’n wyser na dyld_image_notifier, of proc van die shared cache losgemaak is, of die libSystem-initialiseerder geroep is, ’n wyser na dyld se eie Mach-header, ’n wyser na die dyld-weergawe-string...<sup>[[4]](#references)</sup>

## dyld env-veranderlikes

### debug dyld

Interessante env-veranderlikes wat help om te verstaan wat dyld doen:

- **DYLD_PRINT_LIBRARIES**

Kontroleer elke library wat gelaai word:
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

Kyk hoe elke library gelaai word:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: reusing existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
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

Druk af wanneer elke library initializer loop:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Ander

- `DYLD_BIND_AT_LAUNCH`: Lazy bindings word met non-lazy bindings opgelos
- `DYLD_DISABLE_PREFETCH`: Deaktiveer vooraf haal van \_\_DATA- en \_\_LINKEDIT-inhoud
- `DYLD_FORCE_FLAT_NAMESPACE`: Enkelvlak-bindings
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Resolusiepaaie
- `DYLD_INSERT_LIBRARIES`: Laai ’n spesifieke library
- `DYLD_PRINT_TO_FILE`: Skryf dyld-debug-inligting na ’n lêer
- `DYLD_PRINT_APIS`: Druk libdyld API calls af
- `DYLD_PRINT_APIS_APP`: Druk libdyld API calls af wat deur die hoofprogram gemaak word
- `DYLD_PRINT_BINDINGS`: Druk simbole af wanneer hulle gebind word
- `DYLD_WEAK_BINDINGS`: Druk slegs weak simbole af wanneer hulle gebind word
- `DYLD_PRINT_CODE_SIGNATURES`: Druk code signature-registrasiebedrywighede af
- `DYLD_PRINT_DOFS`: Druk D-Trace object format-afdelings af soos hulle gelaai word
- `DYLD_PRINT_ENV`: Druk die omgewing af wat deur dyld gesien word
- `DYLD_PRINT_INTERPOSTING`: Druk interposting-bedrywighede af
- `DYLD_PRINT_LIBRARIES`: Druk libraries af wat gelaai is
- `DYLD_PRINT_OPTS`: Druk load options af
- `DYLD_REBASING`: Druk simbool-rebasing-bedrywighede af
- `DYLD_RPATHS`: Druk uitbreidings van @rpath af
- `DYLD_PRINT_SEGMENTS`: Druk mappings van Mach-O-segmente af
- `DYLD_PRINT_STATISTICS`: Druk tydsberekeningstatistieke af
- `DYLD_PRINT_STATISTICS_DETAILS`: Druk gedetailleerde tydsberekeningstatistieke af
- `DYLD_PRINT_WARNINGS`: Druk waarskuwingsboodskappe af
- `DYLD_SHARED_CACHE_DIR`: Pad wat vir die shared library cache gebruik moet word
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Aktiveer closures

Dit is moontlik om meer te vind met iets soos:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Of deur die dyld-projek van [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) af te laai en die volgende binne die vouer uit te voer:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp` (beginpad vir prosesse)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (proses/sekuriteitskonfigurasie)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (kernelkant van `execve`, laai van dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (`dyld_all_image_infos`-struktuur)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
