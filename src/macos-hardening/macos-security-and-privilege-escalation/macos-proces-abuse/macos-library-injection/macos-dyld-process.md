# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

Pravi **ulaz** Mach-o binarnog fajla je dinamički linkovan, definisan u `LC_LOAD_DYLINKER`, obično je to `/usr/lib/dyld`.

Ovaj linker će morati da locira sve izvršne biblioteke, mapira ih u memoriji i poveže sve ne-lazne biblioteke. Tek nakon ovog procesa, ulazna tačka binarnog fajla će biti izvršena.

Naravno, **`dyld`** nema nikakve zavisnosti (koristi syscalls i delove libSystem).

> [!CAUTION]
> Ako ovaj linker sadrži neku ranjivost, pošto se izvršava pre nego što se izvrši bilo koji binarni fajl (čak i visoko privilegovani), bilo bi moguće **povećati privilegije**.

### Tok

Dyld će biti učitan od strane **`dyldboostrap::start`**, koji će takođe učitati stvari kao što je **stack canary**. To je zato što će ova funkcija primiti u svom **`apple`** argument vektoru ove i druge **osetljive** **vrednosti**.

**`dyls::_main()`** je ulazna tačka dyld-a i njegov prvi zadatak je da pokrene `configureProcessRestrictions()`, koja obično ograničava **`DYLD_*`** promenljive okruženja objašnjene u:

{{#ref}}
./
{{#endref}}

Zatim, mapira dyld deljenu keš memoriju koja prelinkuje sve važne sistemske biblioteke, a zatim mapira biblioteke na kojima binarni fajl zavisi i nastavlja rekurzivno dok se ne učitaju sve potrebne biblioteke. Stoga:

1. počinje sa učitavanjem umetnutih biblioteka sa `DYLD_INSERT_LIBRARIES` (ako je dozvoljeno)
2. Zatim deljene keširane
3. Zatim uvezene
1. &#x20;Zatim nastavlja sa rekurzivnim uvozom biblioteka

Kada su sve učitane, **inicijalizatori** ovih biblioteka se izvršavaju. Ove su kodirane koristeći **`__attribute__((constructor))`** definisane u `LC_ROUTINES[_64]` (sada zastarelo) ili putem pokazivača u sekciji označenoj sa `S_MOD_INIT_FUNC_POINTERS` (obično: **`__DATA.__MOD_INIT_FUNC`**).

Terminatori su kodirani sa **`__attribute__((destructor))`** i nalaze se u sekciji označenoj sa `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubovi

Svi binarni fajlovi u macOS-u su dinamički linkovani. Stoga, sadrže neke stub sekcije koje pomažu binarnom fajlu da skoči na pravi kod na različitim mašinama i u različitim kontekstima. To je dyld kada se izvršava binarni fajl mozak koji treba da reši ove adrese (barem one ne-lazne).

Neke stub sekcije u binarnom fajlu:

- **`__TEXT.__[auth_]stubs`**: Pokazivači iz `__DATA` sekcija
- **`__TEXT.__stub_helper`**: Mali kod koji poziva dinamičko linkovanje sa informacijama o funkciji koja se poziva
- **`__DATA.__[auth_]got`**: Globalna tabela ofseta (adrese do uvezenih funkcija, kada se reše, (vezane tokom vremena učitavanja jer je označena sa oznakom `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Pokazivači na ne-lazne simbole (vezani tokom vremena učitavanja jer je označena sa oznakom `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Pokazivači na lenje simbole (vezani pri prvom pristupu)

> [!WARNING]
> Imajte na umu da pokazivači sa prefiksom "auth\_" koriste jedan ključ za enkripciju u procesu kako bi ga zaštitili (PAC). Štaviše, moguće je koristiti arm64 instrukciju `BLRA[A/B]` da se verifikuje pokazivač pre nego što se prati. A RETA\[A/B] se može koristiti umesto RET adrese.\
> U stvari, kod u **`__TEXT.__auth_stubs`** će koristiti **`braa`** umesto **`bl`** da pozove traženu funkciju kako bi autentifikovao pokazivač.
>
> Takođe, imajte na umu da trenutne verzije dyld učitavaju **sve kao ne-lazne**.

### Pronalaženje lenjih simbola
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Zanimljiv deo disassembliranja:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Moguće je videti da skakanje na poziv printf ide na **`__TEXT.__stubs`**:
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
U disassembliranju sekcije **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
možete videti da **skakačemo na adresu GOT**, koja se u ovom slučaju rešava non-lazy i sadrži adresu printf funkcije.

U drugim situacijama umesto direktnog skakanja na GOT, može skakati na **`__DATA.__la_symbol_ptr`** koji će učitati vrednost koja predstavlja funkciju koju pokušava da učita, zatim skakati na **`__TEXT.__stub_helper`** koji skakuće na **`__DATA.__nl_symbol_ptr`** koji sadrži adresu **`dyld_stub_binder`** koja prima kao parametre broj funkcije i adresu.\
Ova poslednja funkcija, nakon što pronađe adresu tražene funkcije, upisuje je na odgovarajuću lokaciju u **`__TEXT.__stub_helper`** kako bi izbegla pretrage u budućnosti.

> [!TIP]
> Međutim, primetite da trenutne dyld verzije učitavaju sve kao non-lazy.

#### Dyld opkodi

Na kraju, **`dyld_stub_binder`** treba da pronađe naznačenu funkciju i upiše je na odgovarajuću adresu kako ne bi ponovo tražio. Da bi to uradio, koristi opkode (konačna stanja) unutar dyld-a.

## apple\[] argument vektor

U macOS glavna funkcija zapravo prima 4 argumenta umesto 3. Četvrti se zove apple i svaki unos je u formatu `key=value`. Na primer:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Rezultat:
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
> Kada ovi vrednosti stignu do glavne funkcije, osetljive informacije su već uklonjene iz njih ili bi došlo do curenja podataka.

moguće je videti sve ove zanimljive vrednosti tokom debagovanja pre nego što se uđe u main sa:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Trenutni izvršni program postavljen na '/tmp/a' (arm64).
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

Ovo je struktura koju izlaže dyld sa informacijama o dyld stanju koja se može naći u [**izvor kodu**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) sa informacijama kao što su verzija, pokazivač na dyld_image_info niz, na dyld_image_notifier, da li je proc odvojen od zajedničkog keša, da li je libSystem inicijalizator pozvan, pokazivač na Mach header dyld-a, pokazivač na dyld verziju string...

## dyld env variables

### debug dyld

Zanimljive env promenljive koje pomažu da se razume šta dyld radi:

- **DYLD_PRINT_LIBRARIES**

Proverite svaku biblioteku koja se učitava:
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

Štampa kada se svaki inicijalizator biblioteke pokreće:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Drugo

- `DYLD_BIND_AT_LAUNCH`: Lenje vezivanje se rešava sa nelaznim
- `DYLD_DISABLE_PREFETCH`: Onemogući pre-fetching \_\_DATA i \_\_LINKEDIT sadržaja
- `DYLD_FORCE_FLAT_NAMESPACE`: Jednokratna vezivanja
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Putanje za rešavanje
- `DYLD_INSERT_LIBRARIES`: Učitaj specifičnu biblioteku
- `DYLD_PRINT_TO_FILE`: Zapiši dyld debug u datoteku
- `DYLD_PRINT_APIS`: Ispiši libdyld API pozive
- `DYLD_PRINT_APIS_APP`: Ispiši libdyld API pozive koje je napravio main
- `DYLD_PRINT_BINDINGS`: Ispiši simbole kada su vezani
- `DYLD_WEAK_BINDINGS`: Ispiši samo slabe simbole kada su vezani
- `DYLD_PRINT_CODE_SIGNATURES`: Ispiši operacije registracije potpisa koda
- `DYLD_PRINT_DOFS`: Ispiši D-Trace format sekcija objekta kao učitane
- `DYLD_PRINT_ENV`: Ispiši env viđen od strane dyld
- `DYLD_PRINT_INTERPOSTING`: Ispiši interposting operacije
- `DYLD_PRINT_LIBRARIES`: Ispiši učitane biblioteke
- `DYLD_PRINT_OPTS`: Ispiši opcije učitavanja
- `DYLD_REBASING`: Ispiši operacije ponovnog vezivanja simbola
- `DYLD_RPATHS`: Ispiši ekspanzije @rpath
- `DYLD_PRINT_SEGMENTS`: Ispiši mape Mach-O segmenata
- `DYLD_PRINT_STATISTICS`: Ispiši statistiku vremena
- `DYLD_PRINT_STATISTICS_DETAILS`: Ispiši detaljnu statistiku vremena
- `DYLD_PRINT_WARNINGS`: Ispiši poruke upozorenja
- `DYLD_SHARED_CACHE_DIR`: Putanja za korišćenje za keš zajedničkih biblioteka
- `DYLD_SHARED_REGION`: "koristi", "privatno", "izbegavaj"
- `DYLD_USE_CLOSURES`: Omogući zatvaranja

Moguće je pronaći više sa nečim poput:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Ili preuzimanje dyld projekta sa [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) i pokretanje unutar foldera:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Reference

- [**\*OS Internals, Volume I: User Mode. Autor: Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
