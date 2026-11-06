# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese inligting

Die werklike **entrypoint** van ’n Mach-o-binêr is die dynamic linker, wat in `LC_LOAD_DYLINKER` gedefinieer word en gewoonlik `/usr/lib/dyld` is.<sup>[[3]](#references)</sup>

Hierdie linker moet al die uitvoerbare biblioteke opspoor, hulle in die geheue karteer en al die non-lazy-biblioteke koppel. Eers nadat hierdie proses voltooi is, word die binêr se entry-point uitgevoer.

Natuurlik het **`dyld`** geen afhanklikhede nie (dit gebruik syscalls en uittreksels van libSystem).

> [!CAUTION]
> As hierdie linker ’n kwesbaarheid bevat, sal dit moontlik wees om **voorregte te eskaleer**, aangesien dit uitgevoer word voordat enige binêr (selfs hoogs bevoorregte binaries) uitgevoer word.

### Vloei

Dyld word deur **`dyldboostrap::start`** gelaai, wat ook dinge soos die **stack canary** sal laai. Dit is omdat hierdie funksie dit en ander **sensitiewe** **waardes** in sy **`apple`**-argumentvektor ontvang.<sup>[[1]](#references)</sup>

**`dyls::_main()`** is die entry point van dyld en sy eerste taak is om `configureProcessRestrictions()` uit te voer, wat gewoonlik **`DYLD_*`**-omgewingsveranderlikes beperk, soos verduidelik in:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Daarna karteer dit die dyld shared cache, wat al die belangrike stelselbiblioteke vooraf koppel. Vervolgens karteer dit die biblioteke waarvan die binêr afhanklik is en gaan rekursief voort totdat al die nodige biblioteke gelaai is. Dus:

1. dit begin met die laai van ingevoegde biblioteke met `DYLD_INSERT_LIBRARIES` (indien toegelaat)
2. Daarna die biblioteke in die shared cache
3. Daarna die ingevoerde biblioteke
   1. Gaan dan voort om biblioteke rekursief in te voer

Sodra alles gelaai is, word die **initialisers** van hierdie biblioteke uitgevoer. Dit word met **`__attribute__((constructor))`** gekodeer, gedefinieer in `LC_ROUTINES[_64]` (nou afgekeur) of deur ’n wyser in ’n afdeling met die vlag `S_MOD_INIT_FUNC_POINTERS` (gewoonlik: **`__DATA.__MOD_INIT_FUNC`**).

Terminators word met **`__attribute__((destructor))`** gekodeer en is in ’n afdeling met die vlag `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

Sien ook: [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

### Stubs

Alle binaries in macOS is dinamies gekoppel. Daarom bevat hulle stub-afdelings wat die binêr help om na die korrekte kode op verskillende masjiene en in verskillende kontekste te spring. Wanneer die binêr uitgevoer word, is dit dyld wat die adresse moet oplos (ten minste dié van die non-lazy-simbole).

Enkele stub-afdelings in die binêr:

- **`__TEXT.__[auth_]stubs`**: Pointers vanaf `__DATA`-afdelings
- **`__TEXT.__stub_helper`**: Klein stukkie kode wat dynamic linking aanroep, met inligting oor die funksie wat opgeroep moet word
- **`__DATA.__[auth_]got`**: Global Offset Table (adresse van ingevoerde funksies; wanneer dit opgelos is, word dit tydens laaityd gebind omdat dit met die vlag `S_NON_LAZY_SYMBOL_POINTERS` gemerk is)
- **`__DATA.__nl_symbol_ptr`**: Non-lazy-simboolwysers (word tydens laaityd gebind omdat dit met die vlag `S_NON_LAZY_SYMBOL_POINTERS` gemerk is)
- **`__DATA.__la_symbol_ptr`**: Lazy-simboolwysers (word by die eerste toegang gebind)

> [!WARNING]
> Let daarop dat wysers met die voorvoegsel "auth\_" ’n enkripsiesleutel binne die proses gebruik om hulle te beskerm (PAC). Verder is dit moontlik om die arm64-instruksie `BLRA[A/B]` te gebruik om die wyser te verifieer voordat dit gevolg word. En RETA\[A/B] kan in plaas van ’n RET-adres gebruik word.\
> Die kode in **`__TEXT.__auth_stubs`** gebruik inderdaad **`braa`** in plaas van **`bl`** om die aangevraagde funksie aan te roep en die wyser te outentiseer.
>
> Let ook daarop dat huidige dyld-weergawes **alles as non-lazy** laai.

### Lazy-simbole vind

```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    printf("Hi\n");
}
```

Interessante disassembly-deel:

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

In ander situasies kan dit, in plaas daarvan om direk na die GOT te spring, na **`__DATA.__la_symbol_ptr`** spring, wat ’n waarde sal laai wat die funksie verteenwoordig wat dit probeer laai. Daarna spring dit na **`__TEXT.__stub_helper`**, wat na **`__DATA.__nl_symbol_ptr`** spring, wat die adres van **`dyld_stub_binder`** bevat. Dié ontvang die funksienommer en ’n adres as parameters.\
Die binder los die simbool op en werk sy **`__DATA.__la_symbol_ptr`**-gleuf by. Die stub gebruik daardie opgeloste wyser in latere oproepe; dit word nie in `__TEXT.__stub_helper` herskryf nie.<sup>[[5]](#references)</sup>

> [!TIP]
> Let egter daarop dat huidige weergawes van dyld alles as non-lazy laai.

#### Dyld-opkodes

Uiteindelik moet **`dyld_stub_binder`** die aangeduide funksie vind en dit by die korrekte adres skryf, sodat dit nie weer daarna hoef te soek nie. Hiervoor gebruik dit opkodes (’n eindige-toestandmasjien) binne dyld.

## apple\[]-argumentvektor

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

Resultaat:

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
> Teen die tyd dat hierdie waardes die main-funksie bereik, is sensitiewe inligting reeds daaruit verwyder, anders sou dit 'n data leak gewees het.

Dit is moontlik om al hierdie interessante waardes te sien terwyl jy debug, voordat jy main bereik:

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
0x16fdffd9b: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
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

Dit is 'n struktuur wat deur dyld uitgevoer word en inligting oor die dyld-toestand bevat. Dit kan in die [**bronkode**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) gevind word en bevat inligting soos die weergawe, 'n wyser na die dyld_image_info-skikking, na dyld_image_notifier, of proc van die gedeelde kas ontkoppel is, of die libSystem-inisialiseerder geroep is, 'n wyser na dyld se eie Mach-header, 'n wyser na die dyld-weergawe-string...<sup>[[4]](#references)</sup>

## dyld env variables

### debug dyld

Interessante omgewingsveranderlikes wat help om te verstaan wat dyld doen:

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

Druk af wanneer elke biblioteekinitialiseerder uitgevoer word:

```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```

### Spoor runtime-biblioteekresolusie na

Vir ’n proses wat jy kan beheer, spoor ’n `@rpath`- of weak-library-kandidaat na voordat jy ’n vervangende dylib plaas. `DYLD_PRINT_SEARCHING` rapporteer paaie wat deur dyld oorweeg word, terwyl `DYLD_PRINT_LIBRARIES` die beelde wys wat werklik gelaai is. `DYLD_PRINT_LOADERS` onderskei tussen ’n `JustInTimeLoader` en ’n `PrebuiltLoader`, en rapporteer die gebruik van ’n voorafgeboude loader-stel.<sup>[[6]](#references)</sup>

```bash
DYLD_PRINT_SEARCHING=1 DYLD_PRINT_LOADERS=1 DYLD_PRINT_LIBRARIES=1 /path/to/binary 2>&1 | tee /tmp/dyld-search.log
```

Soek die `LC_RPATH`-reël wat die image identifiseer wat ’n run path verskaf het, en vergelyk die `possible path(...)`-kandidate met `found: dylib-from-disk`, `found: dylib-from-cache` of ’n verwerping. ’n Kandidaatpad is **nie** bewys dat die dylib gelaai is nie. Die eerste bruikbare disk-pad vóór die verwagte library is die een waarvoor jy skryftoegang en [library-validation-beperkings](./#library-validation) moet toets.<sup>[[7]](#references)</sup>

’n Voorafgeboude loader kan aangetekende afhanklikheidsinligting hergebruik in plaas daarvan om ’n volledige padsoektog te herhaal. Skaars soekuitvoer is dus nie bewys dat ’n image geen afhanklikhede het nie; inspekteer sy load commands met `otool -l` en vergelyk die library-lys.<sup>[[8]](#references)</sup> Hierdie diagnostiek vereis ook dyld se toestemming om veranderlikes te druk, so ’n beskermde teiken kan dit heeltemal ignoreer.<sup>[[2]](#references)</sup> Sien [Dylib Hijacking](./#dylib-hijacking) vir die voorvereistes vir die werklike vervangings-library.

### Ander

Sommige skakelaars hieronder is spesifiek vir ouer dyld-vrystellings. Gaan die ondersteuning op die teikenweergawe na eerder as om aan te neem dat elke veranderlike steeds werk.<sup>[[2]](#references)[[9]](#references)</sup>

- `DYLD_BIND_AT_LAUNCH`: Lazy bindings word saam met non-lazy bindings opgelos
- `DYLD_DISABLE_PREFETCH`: Deaktiveer voorafhaal van \_\_DATA en \_\_LINKEDIT-inhoud
- `DYLD_FORCE_FLAT_NAMESPACE`: Bindings op enkelvlak
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Resolusiepaaie
- `DYLD_INSERT_LIBRARIES`: Laai ’n spesifieke library
- `DYLD_PRINT_TO_FILE`: Skryf dyld-ontfouting na ’n lêer
- `DYLD_PRINT_APIS`: Druk libdyld API-oproepe
- `DYLD_PRINT_APIS_APP`: Druk libdyld API-oproepe wat deur die hoofprogram gemaak word
- `DYLD_PRINT_BINDINGS`: Druk simbole wanneer hulle gebind word
- `DYLD_PRINT_WEAK_BINDINGS` (dyld2): Druk weak symbol-bindings
- `DYLD_PRINT_CODE_SIGNATURES`: Druk code signature-registrasiehandelinge
- `DYLD_PRINT_DOFS`: Druk D-Trace object format-afdelings soos hulle gelaai word
- `DYLD_PRINT_ENV`: Druk die omgewing wat deur dyld gesien word
- `DYLD_PRINT_INTERPOSING`: Druk interposing-handelinge
- `DYLD_PRINT_LIBRARIES`: Druk libraries wat gelaai is
- `DYLD_PRINT_OPTS`: Druk laai-opsies
- `DYLD_PRINT_REBASINGS` (dyld2): Druk simbool-rebasing-handelinge
- `DYLD_PRINT_RPATHS` (dyld2): Druk uitbreidings van `@rpath`
- `DYLD_PRINT_SEGMENTS`: Druk kartering van Mach-O-segmente
- `DYLD_PRINT_STATISTICS`: Druk tydstatistieke
- `DYLD_PRINT_STATISTICS_DETAILS`: Druk gedetailleerde tydstatistieke
- `DYLD_PRINT_WARNINGS`: Druk waarskuwingsboodskappe
- `DYLD_SHARED_CACHE_DIR`: Pad om vir die shared library cache te gebruik
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Aktiveer closures

Dit is moontlik om meer te vind met iets soos:

```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```

Of deur die dyld-projek af te laai vanaf [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) en dit binne die gids uit te voer:

```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```



## References

- [1] [dyld — `dyld/dyldMain.cpp` (proses-opstartpad)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (proses-/sekuriteitskonfigurasie)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (kernelkant van `execve`, laai dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (`dyld_all_image_infos`-struktuur)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
- [5] [fishhook — lazy en nie-lazy simboolwyserbinding](https://github.com/meta/fishhook)
- [6] [dyld(1) — dinamiese skakelaar-diagnostiek](https://github.com/apple-oss-distributions/dyld/blob/main/doc/man/man1/dyld.1)
- [7] [dyld — soektog na looptyd-biblioteekpaaie](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp)
- [8] [dyld4 — voorafgeboude en net-betyds-laaiers](https://github.com/apple-oss-distributions/dyld/blob/main/doc/dyld4.md)
- [9] [dyld2 — verouderde diagnostiese veranderlikename](https://github.com/apple-oss-distributions/dyld/blob/dyld-852.2/src/dyld2.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
