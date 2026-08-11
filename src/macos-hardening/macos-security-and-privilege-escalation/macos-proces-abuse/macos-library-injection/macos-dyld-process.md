# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

Pravi **entrypoint** Mach-o binarnog fajla je dynamic linker, definisan u `LC_LOAD_DYLINKER`, a obično je to `/usr/lib/dyld`.<sup>[[3]](#references)</sup>

Ovaj linker mora da pronađe sve biblioteke izvršnog fajla, mapira ih u memoriju i poveže sve non-lazy biblioteke. Tek nakon ovog procesa izvršava se entry-point binarnog fajla.

Naravno, **`dyld`** nema nikakve dependencies (koristi syscalls i delove libSystem-a).

> [!CAUTION]
> Ako ovaj linker sadrži bilo kakvu ranjivost, pošto se izvršava pre izvršavanja bilo kog binarnog fajla (čak i onih sa visokim privilegijama), bilo bi moguće **escalate privileges**.

### Tok

Dyld učitava **`dyldboostrap::start`**, koji takođe učitava stvari kao što je **stack canary**. To je zato što će ova funkcija u svom **`apple`** argument vector-u primiti ovu i druge **sensitive** **values**.<sup>[[1]](#references)</sup>

**`dyls::_main()`** je entry point dyld-a, a njegov prvi zadatak je pokretanje funkcije `configureProcessRestrictions()`, koja obično ograničava **`DYLD_*`** environment variables objašnjene u:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Zatim mapira dyld shared cache, koji prelinkuje sve važne sistemske biblioteke, a potom mapira biblioteke od kojih binarni fajl zavisi i nastavlja rekurzivno dok se ne učitaju sve potrebne biblioteke. Dakle:

1. počinje učitavanje ubačenih biblioteka pomoću `DYLD_INSERT_LIBRARIES` (ako je dozvoljeno)
2. Zatim učitava one iz shared cache-a
3. Zatim učitava imported biblioteke
1. Zatim nastavlja sa rekurzivnim importovanjem biblioteka

Kada se sve učitaju, pokreću se **initialisers** ovih biblioteka. Oni se kodiraju pomoću **`__attribute__((constructor))`**, definisanog u `LC_ROUTINES[_64]` (sada deprecated), ili pomoću pokazivača u sekciji označenoj sa `S_MOD_INIT_FUNC_POINTERS` (obično: **`__DATA.__MOD_INIT_FUNC`**).

Terminators se kodiraju pomoću **`__attribute__((destructor))`** i nalaze se u sekciji označenoj sa `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stub-ovi

Svi binarni fajlovi na macOS-u su dynamically linked. Zato sadrže određene stub sekcije koje pomažu binarnom fajlu da pređe na odgovarajući kod na različitim mašinama i u različitim kontekstima. Kada se binarni fajl izvrši, dyld je zadužen za rešavanje ovih adresa (barem non-lazy adresa).

Neke stub sekcije u binarnom fajlu:

- **`__TEXT.__[auth_]stubs`**: Pokazivači iz `__DATA` sekcija
- **`__TEXT.__stub_helper`**: Mali kod koji poziva dynamic linking sa informacijama o funkciji koju treba pozvati
- **`__DATA.__[auth_]got`**: Global Offset Table (adrese imported funkcija, kada se razreše, (bound tokom učitavanja jer su označene flag-om `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Non-lazy symbol pointers (bound tokom učitavanja jer su označene flag-om `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Lazy symbols pointers (bound pri prvom pristupu)

> [!WARNING]
> Imajte na umu da pointers sa prefiksom "auth\_" koriste jedan in-process encryption key za njihovu zaštitu (PAC). Takođe je moguće koristiti arm64 instrukciju `BLRA[A/B]` za proveru pointer-a pre njegovog praćenja. `RETA\[A/B]` se može koristiti umesto RET adrese.\
> Zapravo, kod u **`__TEXT.__auth_stubs`** koristi **`braa`** umesto **`bl`** za pozivanje zahtevane funkcije radi autentifikacije pointer-a.
>
> Takođe imajte na umu da aktuelne dyld verzije učitavaju **sve** kao non-lazy.

### Pronalaženje lazy simbola
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Zanimljiv deo disasembliranog koda:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Moguće je videti da skok ka pozivu `printf` vodi do **`__TEXT.__stubs`**:
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
Prilikom disasembliranja odeljka **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
možete videti da **skačemo na adresu GOT-a**, koja je u ovom slučaju razrešena non-lazy i sadržaće adresu funkcije printf.

U drugim situacijama, umesto direktnog skoka na GOT, moglo bi se skočiti na **`__DATA.__la_symbol_ptr`**, što će učitati vrednost koja predstavlja funkciju koju pokušava da učita, a zatim skočiti na **`__TEXT.__stub_helper`**, koji skače na **`__DATA.__nl_symbol_ptr`**, a koji sadrži adresu funkcije **`dyld_stub_binder`**. Ona kao parametre prima broj funkcije i adresu.\
Ova poslednja funkcija, nakon pronalaženja adrese tražene funkcije, upisuje je na odgovarajuću lokaciju u **`__TEXT.__stub_helper`** kako bi se izbeglo ponovno pretraživanje u budućnosti.

> [!TIP]
> Međutim, imajte na umu da trenutne verzije dyld-a sve učitavaju kao non-lazy.

#### Dyld opcodes

Na kraju, **`dyld_stub_binder`** mora da pronađe navedenu funkciju i upiše je na odgovarajuću adresu kako je ne bi ponovo tražio. Za to koristi opcodes (konačni automat) unutar dyld-a.

## apple\[] vektor argumenata

U macOS-u glavna funkcija zapravo prima 4 argumenta umesto 3. Četvrti se zove apple, a svaki unos je u obliku `key=value`. Na primer:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Nije dostavljen tekst za prevođenje.
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
> Dok ove vrednosti stignu do glavne funkcije, iz njih su već uklonjene osetljive informacije ili bi došlo do data leak-a.

moguće je videti sve ove zanimljive vrednosti tokom debugovanja, pre ulaska u main, pomoću:

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

Ovo je struktura koju eksportuje dyld, sa informacijama o stanju dyld-a. Može se pronaći u [**izvornom kodu**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html), a sadrži informacije kao što su verzija, pokazivač na niz dyld_image_info, pokazivač na dyld_image_notifier, informacija da li je proc odvojen od shared cache-a, informacija da li je inicijalizator libSystem-a pozvan, pokazivač na sopstveno Mach zaglavlje dyld-a, pokazivač na string sa verzijom dyld-a...<sup>[[4]](#references)</sup>

## dyld env variables

### debug dyld

Zanimljive env promenljive koje pomažu da se razume šta dyld radi:

- **DYLD_PRINT_LIBRARIES**

Proverava svaku biblioteku koja se učita:
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

Proverite kako se svaka biblioteka učitava:
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

Ispisuje kada se pokreće svaki inicijalizator biblioteke:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Ostalo

- `DYLD_BIND_AT_LAUNCH`: Lazy bindings se razrešavaju zajedno sa non-lazy bindings
- `DYLD_DISABLE_PREFETCH`: Onemogućava pre-fetching sadržaja \_\_DATA i \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Bindings na jednom nivou
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Putanje za razrešavanje
- `DYLD_INSERT_LIBRARIES`: Učitava određenu library
- `DYLD_PRINT_TO_FILE`: Upisuje dyld debug u fajl
- `DYLD_PRINT_APIS`: Ispisuje pozive libdyld API-ja
- `DYLD_PRINT_APIS_APP`: Ispisuje pozive libdyld API-ja koje izvršava main
- `DYLD_PRINT_BINDINGS`: Ispisuje simbole prilikom binding-a
- `DYLD_WEAK_BINDINGS`: Ispisuje samo weak simbole prilikom binding-a
- `DYLD_PRINT_CODE_SIGNATURES`: Ispisuje operacije registracije code signature-a
- `DYLD_PRINT_DOFS`: Ispisuje sekcije D-Trace object formata prilikom učitavanja
- `DYLD_PRINT_ENV`: Ispisuje env koji dyld vidi
- `DYLD_PRINT_INTERPOSTING`: Ispisuje interposting operacije
- `DYLD_PRINT_LIBRARIES`: Ispisuje učitane libraries
- `DYLD_PRINT_OPTS`: Ispisuje opcije učitavanja
- `DYLD_REBASING`: Ispisuje operacije rebasing-a simbola
- `DYLD_RPATHS`: Ispisuje proširenja za @rpath
- `DYLD_PRINT_SEGMENTS`: Ispisuje mapiranja Mach-O segmenata
- `DYLD_PRINT_STATISTICS`: Ispisuje statistiku vremena
- `DYLD_PRINT_STATISTICS_DETAILS`: Ispisuje detaljnu statistiku vremena
- `DYLD_PRINT_WARNINGS`: Ispisuje poruke upozorenja
- `DYLD_SHARED_CACHE_DIR`: Putanja koja se koristi za shared library cache
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Omogućava closures

Moguće je pronaći još opcija pomoću nečega poput:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Ili preuzimanjem dyld projekta sa [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) i pokretanjem unutar fascikle:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp` (putanja pokretanja procesa)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (konfiguracija procesa/bezbednosti)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (kernel strana `execve`, učitavanje dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (struktura `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
