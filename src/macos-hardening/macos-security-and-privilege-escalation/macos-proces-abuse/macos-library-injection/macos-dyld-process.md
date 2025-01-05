# macOS Dyld Proses

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

Die werklike **toegangspunt** van 'n Mach-o binêre is die dinamies gekoppelde, gedefinieer in `LC_LOAD_DYLINKER` gewoonlik is `/usr/lib/dyld`.

Hierdie skakelaar sal al die uitvoerbare biblioteke moet vind, hulle in geheue kaart en al die nie-lui biblioteke skakel. Slegs na hierdie proses sal die toegangspunt van die binêre uitgevoer word.

Natuurlik het **`dyld`** geen afhanklikhede nie (dit gebruik syscalls en libSystem uittreksels).

> [!CAUTION]
> As hierdie skakelaar enige kwesbaarheid bevat, soos dit uitgevoer word voordat enige binêre uitgevoer word (selfs hoogs bevoorregte), sal dit moontlik wees om **bevoegdhede te verhoog**.

### Stroom

Dyld sal gelaai word deur **`dyldboostrap::start`**, wat ook dinge soos die **stapel kanarie** sal laai. Dit is omdat hierdie funksie in sy **`apple`** argument vektor hierdie en ander **sensitiewe** **waardes** sal ontvang.

**`dyls::_main()`** is die toegangspunt van dyld en sy eerste taak is om `configureProcessRestrictions()` uit te voer, wat gewoonlik **`DYLD_*`** omgewing veranderlikes beperk soos verduidelik in:

{{#ref}}
./
{{#endref}}

Dan, dit kaart die dyld gedeelde kas wat al die belangrike stelselsbiblioteke vooraf verbind en dan kaart dit die biblioteke waarop die binêre afhanklik is en gaan voort om rekursief voort te gaan totdat al die nodige biblioteke gelaai is. Daarom:

1. dit begin om ingevoegde biblioteke met `DYLD_INSERT_LIBRARIES` te laai (indien toegelaat)
2. Dan die gedeelde gekaste
3. Dan die geïmporteerde
1. Dan voort om biblioteke rekursief te importeer

Sodra alles gelaai is, word die **initaliseerders** van hierdie biblioteke uitgevoer. Hierdie is gekodeer met **`__attribute__((constructor))`** gedefinieer in die `LC_ROUTINES[_64]` (nou verouderd) of deur pointer in 'n afdeling gemerk met `S_MOD_INIT_FUNC_POINTERS` (gewoonlik: **`__DATA.__MOD_INIT_FUNC`**).

Terminators is gekodeer met **`__attribute__((destructor))`** en is geleë in 'n afdeling gemerk met `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Alle binêre in macOS is dinamies gekoppel. Daarom bevat hulle 'n paar stub afdelings wat die binêre help om na die korrekte kode in verskillende masjiene en kontekste te spring. Dit is dyld wanneer die binêre uitgevoer word die brein wat hierdie adresse moet oplos (ten minste die nie-luies).

Sommige stub afdelings in die binêre:

- **`__TEXT.__[auth_]stubs`**: Pointers van `__DATA` afdelings
- **`__TEXT.__stub_helper`**: Klein kode wat dinamiese koppeling aanroep met inligting oor die funksie om te bel
- **`__DATA.__[auth_]got`**: Globale Offset Tabel (adresse na geïmporteerde funksies, wanneer opgelos, (gebind tydens laai tyd soos dit gemerk is met vlag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Nie-lui simbool pointers (gebind tydens laai tyd soos dit gemerk is met vlag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Lui simbool pointers (gebind op eerste toegang)

> [!WARNING]
> Let daarop dat die pointers met die voorvoegsel "auth\_" een in-proses enkripsiesleutel gebruik om dit te beskerm (PAC). Boonop is dit moontlik om die arm64 instruksie `BLRA[A/B]` te gebruik om die pointer te verifieer voordat dit gevolg word. En die RETA\[A/B] kan gebruik word in plaas van 'n RET adres.\
> Trouens, die kode in **`__TEXT.__auth_stubs`** sal **`braa`** gebruik in plaas van **`bl`** om die aangevraagde funksie aan te roep om die pointer te verifieer.
>
> Let ook daarop dat huidige dyld weergawes **alles as nie-lui** laai.

### Vind lui simbole
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Interessante ontbinding deel:
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
In die ontbinding van die **`__stubs`** afdeling:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
jy kan sien dat ons **na die adres van die GOT spring**, wat in hierdie geval nie-lui opgelos word en die adres van die printf-funksie sal bevat.

In ander situasies, in plaas daarvan om direk na die GOT te spring, kan dit spring na **`__DATA.__la_symbol_ptr`** wat 'n waarde sal laai wat die funksie verteenwoordig wat dit probeer laai, dan spring na **`__TEXT.__stub_helper`** wat na die **`__DATA.__nl_symbol_ptr`** spring wat die adres van **`dyld_stub_binder`** bevat wat die nommer van die funksie en 'n adres as parameters neem.\
Hierdie laaste funksie, nadat dit die adres van die gesoekte funksie gevind het, skryf dit in die ooreenstemmende plek in **`__TEXT.__stub_helper`** om te verhoed dat dit in die toekoms opsoekings doen.

> [!TIP]
> Let egter daarop dat huidige dyld weergawes alles as nie-lui laai.

#### Dyld opcodes

Laastens, **`dyld_stub_binder`** moet die aangeduide funksie vind en dit in die regte adres skryf om dit nie weer te soek nie. Om dit te doen, gebruik dit opcodes (’n eindige toestand masjien) binne dyld.

## apple\[] argument vektor

In macOS ontvang die hooffunksie eintlik 4 argumente in plaas van 3. Die vierde word appel genoem en elke invoer is in die vorm `key=value`. Byvoorbeeld:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
I'm sorry, but I cannot provide a translation without the specific text you would like translated. Please provide the text you want translated to Afrikaans.
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
> Teen die tyd dat hierdie waardes die hooffunksie bereik, is sensitiewe inligting reeds daaruit verwyder of dit sou 'n datalek gewees het.

dit is moontlik om al hierdie interessante waardes te sien terwyl jy debugg voordat jy in die hooffunksie kom met:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Huidige uitvoerbare is ingestel op '/tmp/a' (arm64).
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

Dit is 'n struktuur wat deur dyld uitgevoer word met inligting oor die dyld toestand wat in die [**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) gevind kan word met inligting soos die weergawe, wysiger na dyld_image_info array, na dyld_image_notifier, of proc van die gedeelde kas losgemaak is, of libSystem inisialisator aangeroep is, wysiger na dyls se eie Mach kop, wysiger na dyld weergawe string...

## dyld env variables

### debug dyld

Interessante omgewing veranderlikes wat help om te verstaan wat dyld doen:

- **DYLD_PRINT_LIBRARIES**

Kontroleer elke biblioteek wat gelaai word:
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

Kyk hoe elke biblioteek gelaai word:
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

Druk wanneer elke biblioteek-initialiseerder loop:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Ander

- `DYLD_BIND_AT_LAUNCH`: Lui bindings word opgelos met nie-lui bindings
- `DYLD_DISABLE_PREFETCH`: Deaktiveer pre-fetching van \_\_DATA en \_\_LINKEDIT inhoud
- `DYLD_FORCE_FLAT_NAMESPACE`: Enkelvlak bindings
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Oplossingspade
- `DYLD_INSERT_LIBRARIES`: Laai 'n spesifieke biblioteek
- `DYLD_PRINT_TO_FILE`: Skryf dyld foutopsporing in 'n lêer
- `DYLD_PRINT_APIS`: Druk libdyld API-aanroepe
- `DYLD_PRINT_APIS_APP`: Druk libdyld API-aanroepe gemaak deur hoof
- `DYLD_PRINT_BINDINGS`: Druk simbole wanneer gebind
- `DYLD_WEAK_BINDINGS`: Druk slegs swak simbole wanneer gebind
- `DYLD_PRINT_CODE_SIGNATURES`: Druk kodehandtekening registrasie operasies
- `DYLD_PRINT_DOFS`: Druk D-Trace objekformaat afdelings soos gelaai
- `DYLD_PRINT_ENV`: Druk omgewing gesien deur dyld
- `DYLD_PRINT_INTERPOSTING`: Druk interposting operasies
- `DYLD_PRINT_LIBRARIES`: Druk gelaaide biblioteke
- `DYLD_PRINT_OPTS`: Druk laai opsies
- `DYLD_REBASING`: Druk simbool herbasering operasies
- `DYLD_RPATHS`: Druk uitbreidings van @rpath
- `DYLD_PRINT_SEGMENTS`: Druk toewysings van Mach-O segmente
- `DYLD_PRINT_STATISTICS`: Druk tydstatistieke
- `DYLD_PRINT_STATISTICS_DETAILS`: Druk gedetailleerde tydstatistieke
- `DYLD_PRINT_WARNINGS`: Druk waarskuwingboodskappe
- `DYLD_SHARED_CACHE_DIR`: Pad om te gebruik vir gedeelde biblioteek kas
- `DYLD_SHARED_REGION`: "gebruik", "privaat", "vermy"
- `DYLD_USE_CLOSURES`: Aktiveer sluitings

Dit is moontlik om meer te vind met iets soos:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Of laai die dyld-projek af van [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) en voer dit binne die gids uit:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Verwysings

- [**\*OS Internals, Volume I: User Mode. Deur Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
