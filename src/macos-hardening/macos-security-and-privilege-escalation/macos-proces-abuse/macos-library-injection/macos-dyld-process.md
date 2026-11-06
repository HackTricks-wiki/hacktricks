# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

Pravi **entrypoint** Mach-o binarnog fajla je dinamički linker, definisan u `LC_LOAD_DYLINKER`, a obično je to `/usr/lib/dyld`.<sup>[[3]](#references)</sup>

Ovaj linker mora da pronađe sve biblioteke izvršnog fajla, mapira ih u memoriju i poveže sve non-lazy biblioteke. Tek nakon ovog procesa izvršava se ulazna tačka binarnog fajla.

Naravno, **`dyld`** nema zavisnosti (koristi syscalls i izvode iz libSystem-a).

> [!CAUTION]
> Ako ovaj linker sadrži ranjivost, pošto se izvršava pre pokretanja bilo kog binarnog fajla (čak i onih sa visokim privilegijama), bilo bi moguće **eskalirati privilegije**.

### Tok

Dyld učitava **`dyldboostrap::start`**, koji takođe učitava stvari kao što je **stack canary**. To je zato što ova funkcija u svom argumentu **`apple`** prima tu i druge **osetljive** **vrednosti**.<sup>[[1]](#references)</sup>

**`dyls::_main()`** je ulazna tačka dyld-a, a njegov prvi zadatak je da pokrene `configureProcessRestrictions()`, koji obično ograničava **`DYLD_*`** promenljive okruženja objašnjene u:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Zatim mapira dyld shared cache, koji unapred povezuje sve važne sistemske biblioteke, pa mapira biblioteke od kojih binarni fajl zavisi i nastavlja rekurzivno dok se ne učitaju sve potrebne biblioteke. Dakle:

1. počinje učitavanjem ubačenih biblioteka pomoću `DYLD_INSERT_LIBRARIES` (ako je dozvoljeno)
2. Zatim učitava one iz shared cache-a
3. Zatim učitava uvezene biblioteke
   1. Zatim nastavlja da uvozi biblioteke rekurzivno

Kada se sve učitaju, pokreću se **inicijalizatori** ovih biblioteka. Oni se kodiraju pomoću **`__attribute__((constructor))`**, definisanog u `LC_ROUTINES[_64]` (sada zastarelom) ili preko pokazivača u sekciji označenoj sa `S_MOD_INIT_FUNC_POINTERS` (obično: **`__DATA.__MOD_INIT_FUNC`**).

Terminatori se kodiraju pomoću **`__attribute__((destructor))`** i nalaze se u sekciji označenoj sa `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

Pogledajte i: [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

### Stubs

Svi binarni fajlovi u macOS-u su dinamički povezani. Zato sadrže sekcije sa stubovima koje pomažu binarnom fajlu da skoči na odgovarajući kod na različitim mašinama i u različitim kontekstima. Kada se binarni fajl izvrši, dyld je zadužen za razrešavanje ovih adresa (barem onih non-lazy).

Neke sekcije sa stubovima u binarnom fajlu:

- **`__TEXT.__[auth_]stubs`**: Pokazivači iz sekcija `__DATA`
- **`__TEXT.__stub_helper`**: Kratak kod koji poziva dinamičko povezivanje i sadrži informacije o funkciji koju treba pozvati
- **`__DATA.__[auth_]got`**: Global Offset Table (adrese uvezenih funkcija koje se, kada se razreše, povezuju tokom učitavanja jer su označene zastavicom `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Pokazivači na non-lazy simbole (povezuju se tokom učitavanja jer su označeni zastavicom `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Pokazivači na lazy simbole (povezuju se pri prvom pristupu)

> [!WARNING]
> Imajte na umu da pokazivači sa prefiksom „auth_“ koriste jedan ključ za šifrovanje unutar procesa kako bi bili zaštićeni (PAC). Pored toga, moguće je upotrebiti arm64 instrukciju `BLRA[A/B]` za proveru pokazivača pre nego što se prati. Umesto RET adrese može se koristiti i RETA\[A/B].\
> Zapravo, kod u **`__TEXT.__auth_stubs`** koristiće **`braa`** umesto **`bl`** za pozivanje tražene funkcije i autentifikaciju pokazivača.
>
> Imajte na umu i da aktuelne verzije dyld-a sve učitavaju kao non-lazy.

### Pronalaženje lazy simbola

```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    printf("Hi\n");
}
```

Zanimljiv deo disasembliranja:

```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```

Moguće je videti da skok za poziv funkcije printf ide ka **`__TEXT.__stubs`**:

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

Pri disasembliranju sekcije **`__stubs`**:

```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```

možete da vidite da **skačemo na adresu GOT-a**, koja je u ovom slučaju razrešena kao non-lazy i sadržaće adresu funkcije printf.

U drugim situacijama, umesto da direktno skoči na GOT, može da skoči na **`__DATA.__la_symbol_ptr`**, koji učitava vrednost koja predstavlja funkciju koju pokušava da učita, a zatim da skoči na **`__TEXT.__stub_helper`**, koji skače na **`__DATA.__nl_symbol_ptr`**, gde se nalazi adresa funkcije **`dyld_stub_binder`**. Ona kao parametre prima broj funkcije i adresu.\
Binder razrešava simbol i ažurira njegov slot u **`__DATA.__la_symbol_ptr`**. Stub zatim koristi taj razrešeni pokazivač pri narednim pozivima; on se ne prepisuje u **`__TEXT.__stub_helper`**.<sup>[[5]](#references)</sup>

> [!TIP]
> Međutim, imajte na umu da trenutne verzije dyld-a sve učitavaju kao non-lazy.

#### Dyld opcodes

Na kraju, funkcija **`dyld_stub_binder`** mora da pronađe naznačenu funkciju i upiše je na odgovarajuću adresu kako je ne bi ponovo tražila. Da bi to uradila, koristi opcodes (konačni automat stanja) unutar dyld-a.

## Vektor argumenata apple[]

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
> Do trenutka kada ove vrednosti stignu do glavne funkcije, osetljive informacije su već uklonjene iz njih; u suprotnom bi došlo do curenja podataka.

Moguće je videti sve ove zanimljive vrednosti tokom debagovanja, pre nego što se uđe u main:

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

Ovo je struktura koju izvozi dyld, sa informacijama o stanju dyld-a. Može se pronaći u [**izvornom kodu**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html), a sadrži informacije kao što su verzija, pokazivač na niz dyld_image_info, na dyld_image_notifier, da li je proc odvojen od shared cache-a, da li je pozvan libSystem initializer, pokazivač na sopstveno Mach zaglavlje za dyld, pokazivač na nisku verzije dyld-a...<sup>[[4]](#references)</sup>

## dyld env variables

### debagovanje dyld-a

Zanimljive env promenljive koje pomažu da se razume šta dyld radi:

- **DYLD_PRINT_LIBRARIES**

Proverite svaku učitanu biblioteku:

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

Proverite kako se učitava svaka biblioteka:

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

Ispisuje kada se pokreće inicijalizator svake biblioteke:

```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```

### Praćenje razrešavanja biblioteka tokom izvršavanja

Za pokretanje koje možete da kontrolišete, pratite kandidata `@rpath` ili weak-library pre nego što postavite zamenski dylib. `DYLD_PRINT_SEARCHING` prijavljuje putanje koje dyld razmatra, dok `DYLD_PRINT_LIBRARIES` prikazuje stvarno učitane images. `DYLD_PRINT_LOADERS` razlikuje `JustInTimeLoader` od `PrebuiltLoader` i prijavljuje upotrebu prebuilt loader seta.<sup>[[6]](#references)</sup>

```bash
DYLD_PRINT_SEARCHING=1 DYLD_PRINT_LOADERS=1 DYLD_PRINT_LIBRARIES=1 /path/to/binary 2>&1 | tee /tmp/dyld-search.log
```

Potražite red `LC_RPATH` koji identifikuje image koji je obezbedio putanju za pretragu, a zatim uporedite kandidate `possible path(...)` sa rezultatima `found: dylib-from-disk`, `found: dylib-from-cache` ili odbijanjem. Putanja kandidata **nije** dokaz da je dylib učitan. Prvu upotrebljivu putanju na disku pre očekivane biblioteke treba proveriti u pogledu dozvole za upis i [ograničenja library-validation](./#library-validation).<sup>[[7]](#references)</sup>

Unapred izgrađeni loader može ponovo da koristi zabeležene informacije o zavisnostima umesto da ponavlja kompletnu pretragu putanja. Zato oskudan izlaz pretrage nije dokaz da image nema zavisnosti; pregledajte njegove load komande pomoću `otool -l` i uporedite listu biblioteka.<sup>[[8]](#references)</sup> Ova dijagnostika takođe zahteva dyld dozvolu za ispis promenljivih, pa je zaštićeni cilj može u potpunosti ignorisati.<sup>[[2]](#references)</sup> Pogledajte [Dylib Hijacking](./#dylib-hijacking) za preduslove za zamenu biblioteke.

### Ostalo

Neki prekidači u nastavku specifični su za starija izdanja dyld. Proverite da li ih podržava ciljna verzija umesto da pretpostavite da svaka promenljiva i dalje radi.<sup>[[2]](#references)[[9]](#references)</sup>

- `DYLD_BIND_AT_LAUNCH`: Lazy vezivanja se razrešavaju zajedno sa non-lazy vezivanjima
- `DYLD_DISABLE_PREFETCH`: Onemogući prefetch sadržaja \_\_DATA i \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Vezivanja na jednom nivou
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Putanje za razrešavanje
- `DYLD_INSERT_LIBRARIES`: Učitaj određenu biblioteku
- `DYLD_PRINT_TO_FILE`: Zapiši dyld debug izlaz u datoteku
- `DYLD_PRINT_APIS`: Ispiši pozive libdyld API-ja
- `DYLD_PRINT_APIS_APP`: Ispiši pozive libdyld API-ja koje izvršava glavni program
- `DYLD_PRINT_BINDINGS`: Ispiši simbole prilikom vezivanja
- `DYLD_PRINT_WEAK_BINDINGS` (dyld2): Ispiši vezivanja slabih simbola
- `DYLD_PRINT_CODE_SIGNATURES`: Ispiši operacije registracije potpisa koda
- `DYLD_PRINT_DOFS`: Ispiši odeljke D-Trace object formata prilikom učitavanja
- `DYLD_PRINT_ENV`: Ispiši okruženje koje dyld vidi
- `DYLD_PRINT_INTERPOSING`: Ispiši operacije interposing-a
- `DYLD_PRINT_LIBRARIES`: Ispiši učitane biblioteke
- `DYLD_PRINT_OPTS`: Ispiši opcije učitavanja
- `DYLD_PRINT_REBASINGS` (dyld2): Ispiši operacije pomeranja simbola
- `DYLD_PRINT_RPATHS` (dyld2): Ispiši proširenja `@rpath`
- `DYLD_PRINT_SEGMENTS`: Ispiši mapiranja Mach-O segmenata
- `DYLD_PRINT_STATISTICS`: Ispiši statistiku vremena izvršavanja
- `DYLD_PRINT_STATISTICS_DETAILS`: Ispiši detaljnu statistiku vremena izvršavanja
- `DYLD_PRINT_WARNINGS`: Ispiši poruke upozorenja
- `DYLD_SHARED_CACHE_DIR`: Putanja koja se koristi za keš deljenih biblioteka
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Omogući closures

Više ih možete pronaći pomoću nečega poput:

```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```

Ili preuzimanjem projekta dyld sa [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) i pokretanjem unutar fascikle:

```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```



## References

- [1] [dyld — `dyld/dyldMain.cpp` (putanja pokretanja procesa)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (konfiguracija procesa/bezbednosti)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (deo kernela za `execve`, učitavanje dyld-a)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (struktura `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
- [5] [fishhook — vezivanje pokazivača na lazy i non-lazy simbole](https://github.com/meta/fishhook)
- [6] [dyld(1) — dijagnostika dinamičkog linker-a](https://github.com/apple-oss-distributions/dyld/blob/main/doc/man/man1/dyld.1)
- [7] [dyld — pretraga putanja do biblioteka tokom izvršavanja](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp)
- [8] [dyld4 — unapred izgrađeni i just-in-time loader-i](https://github.com/apple-oss-distributions/dyld/blob/main/doc/dyld4.md)
- [9] [dyld2 — nazivi zastarelih dijagnostičkih promenljivih](https://github.com/apple-oss-distributions/dyld/blob/dyld-852.2/src/dyld2.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
