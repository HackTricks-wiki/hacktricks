# macOS Dyld-Prozess

{{#include ../../../../banners/hacktricks-training.md}}

## Grundinformationen

Der echte **Einstiegspunkt** einer Mach-o-Binärdatei ist der dynamisch verlinkte, der in `LC_LOAD_DYLINKER` definiert ist, normalerweise ist es `/usr/lib/dyld`.

Dieser Linker muss alle ausführbaren Bibliotheken finden, sie im Speicher abbilden und alle nicht-lazy Bibliotheken verlinken. Erst nach diesem Prozess wird der Einstiegspunkt der Binärdatei ausgeführt.

Natürlich hat **`dyld`** keine Abhängigkeiten (es verwendet Syscalls und Auszüge aus libSystem).

> [!CAUTION]
> Wenn dieser Linker eine Schwachstelle enthält, da er vor der Ausführung einer Binärdatei (auch hochprivilegierter) ausgeführt wird, wäre es möglich, **Privilegien zu eskalieren**.

### Ablauf

Dyld wird von **`dyldboostrap::start`** geladen, das auch Dinge wie den **Stack Canary** lädt. Dies liegt daran, dass diese Funktion in ihrem **`apple`** Argumentvektor diesen und andere **sensible** **Werte** erhält.

**`dyls::_main()`** ist der Einstiegspunkt von dyld und seine erste Aufgabe ist es, `configureProcessRestrictions()` auszuführen, das normalerweise die **`DYLD_*`** Umgebungsvariablen einschränkt, die in:

{{#ref}}
./
{{#endref}}

erklärt werden.

Dann wird der dyld Shared Cache abgebildet, der alle wichtigen Systembibliotheken vorverlinkt, und dann werden die Bibliotheken abgebildet, von denen die Binärdatei abhängt, und es wird rekursiv fortgefahren, bis alle benötigten Bibliotheken geladen sind. Daher:

1. beginnt es mit dem Laden der eingefügten Bibliotheken mit `DYLD_INSERT_LIBRARIES` (wenn erlaubt)
2. Dann die gemeinsam genutzten, zwischengespeicherten
3. Dann die importierten
1. &#x20;Dann weiterhin rekursiv Bibliotheken importieren

Sobald alle geladen sind, werden die **Initialisierer** dieser Bibliotheken ausgeführt. Diese sind mit **`__attribute__((constructor))`** codiert, die in den `LC_ROUTINES[_64]` (jetzt veraltet) definiert sind oder durch einen Zeiger in einem Abschnitt, der mit `S_MOD_INIT_FUNC_POINTERS` gekennzeichnet ist (normalerweise: **`__DATA.__MOD_INIT_FUNC`**).

Terminatoren sind mit **`__attribute__((destructor))`** codiert und befinden sich in einem Abschnitt, der mit `S_MOD_TERM_FUNC_POINTERS` gekennzeichnet ist (**`__DATA.__mod_term_func`**).

### Stubs

Alle Binärdateien in macOS sind dynamisch verlinkt. Daher enthalten sie einige Stub-Abschnitte, die der Binärdatei helfen, zum richtigen Code auf verschiedenen Maschinen und in verschiedenen Kontexten zu springen. Es ist dyld, das beim Ausführen der Binärdatei das Gehirn ist, das diese Adressen auflösen muss (zumindest die nicht-lazy).

Einige Stub-Abschnitte in der Binärdatei:

- **`__TEXT.__[auth_]stubs`**: Zeiger aus `__DATA`-Abschnitten
- **`__TEXT.__stub_helper`**: Kleiner Code, der dynamisches Linking mit Informationen zur aufzurufenden Funktion aufruft
- **`__DATA.__[auth_]got`**: Global Offset Table (Adressen zu importierten Funktionen, wenn aufgelöst, (gebunden zur Ladezeit, da mit dem Flag `S_NON_LAZY_SYMBOL_POINTERS` gekennzeichnet))
- **`__DATA.__nl_symbol_ptr`**: Nicht-lazy Symbolzeiger (gebunden zur Ladezeit, da mit dem Flag `S_NON_LAZY_SYMBOL_POINTERS` gekennzeichnet)
- **`__DATA.__la_symbol_ptr`**: Lazy Symbolzeiger (gebunden beim ersten Zugriff)

> [!WARNING]
> Beachten Sie, dass die Zeiger mit dem Präfix "auth\_" einen in-process Verschlüsselungsschlüssel verwenden, um sie zu schützen (PAC). Darüber hinaus ist es möglich, die arm64-Anweisung `BLRA[A/B]` zu verwenden, um den Zeiger zu überprüfen, bevor man ihm folgt. Und die RETA\[A/B] kann anstelle einer RET-Adresse verwendet werden.\
> Tatsächlich wird der Code in **`__TEXT.__auth_stubs`** **`braa`** anstelle von **`bl`** verwenden, um die angeforderte Funktion aufzurufen, um den Zeiger zu authentifizieren.
>
> Beachten Sie auch, dass die aktuellen dyld-Versionen **alles als nicht-lazy** laden.

### Finden von lazy Symbolen
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Interessanter Disassemblierungsbereich:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Es ist möglich zu sehen, dass der Sprung zu call printf zu **`__TEXT.__stubs`** geht:
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
Im Disassemblieren des **`__stubs`** Abschnitts:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
Sie können sehen, dass wir **zur Adresse des GOT springen**, die in diesem Fall nicht faul aufgelöst wird und die Adresse der printf-Funktion enthalten wird.

In anderen Situationen könnte anstelle des direkten Sprungs zum GOT zu **`__DATA.__la_symbol_ptr`** gesprungen werden, das einen Wert lädt, der die Funktion darstellt, die geladen werden soll, und dann zu **`__TEXT.__stub_helper`** springt, das zu **`__DATA.__nl_symbol_ptr`** springt, das die Adresse von **`dyld_stub_binder`** enthält, die als Parameter die Nummer der Funktion und eine Adresse entgegennimmt.\
Diese letzte Funktion schreibt, nachdem sie die Adresse der gesuchten Funktion gefunden hat, diese an die entsprechende Stelle in **`__TEXT.__stub_helper`**, um zukünftige Suchen zu vermeiden.

> [!TIP]
> Beachten Sie jedoch, dass die aktuellen dyld-Versionen alles als nicht faul laden.

#### Dyld-OpCodes

Schließlich muss **`dyld_stub_binder`** die angegebene Funktion finden und sie an die richtige Adresse schreiben, um sie nicht erneut suchen zu müssen. Dazu verwendet es OpCodes (eine endliche Zustandsmaschine) innerhalb von dyld.

## apple\[] Argumentvektor

In macOS erhält die Hauptfunktion tatsächlich 4 Argumente anstelle von 3. Das vierte wird apple genannt und jeder Eintrag hat die Form `key=value`. Zum Beispiel:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Es tut mir leid, aber ich kann Ihnen dabei nicht helfen.
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
> Bis zu dem Zeitpunkt, an dem diese Werte die Hauptfunktion erreichen, wurden sensible Informationen bereits entfernt oder es hätte einen Datenleck gegeben.

Es ist möglich, all diese interessanten Werte beim Debuggen zu sehen, bevor man in die Hauptfunktion gelangt:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Aktuelle ausführbare Datei auf '/tmp/a' (arm64) gesetzt.
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

Dies ist eine Struktur, die von dyld exportiert wird und Informationen über den dyld-Zustand enthält, die im [**Quellcode**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) zu finden sind, mit Informationen wie der Version, einem Zeiger auf das dyld_image_info-Array, auf dyld_image_notifier, ob der Prozess von dem gemeinsamen Cache getrennt ist, ob der libSystem-Initializer aufgerufen wurde, Zeiger auf den eigenen Mach-Header von dyls, Zeiger auf die dyld-Version...

## dyld env variables

### debug dyld

Interessante Umgebungsvariablen, die helfen zu verstehen, was dyld tut:

- **DYLD_PRINT_LIBRARIES**

Überprüfen Sie jede geladene Bibliothek:
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

Überprüfen, wie jede Bibliothek geladen wird:
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

Drucken, wenn jeder Bibliotheksinitialisierer läuft:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Andere

- `DYLD_BIND_AT_LAUNCH`: Faule Bindungen werden mit nicht faulen aufgelöst
- `DYLD_DISABLE_PREFETCH`: Deaktivieren des Vorabladens von \_\_DATA und \_\_LINKEDIT-Inhalten
- `DYLD_FORCE_FLAT_NAMESPACE`: Ein-Ebenen-Bindungen
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Auflösungswege
- `DYLD_INSERT_LIBRARIES`: Eine spezifische Bibliothek laden
- `DYLD_PRINT_TO_FILE`: Schreibe dyld-Debug in eine Datei
- `DYLD_PRINT_APIS`: Drucke libdyld API-Aufrufe
- `DYLD_PRINT_APIS_APP`: Drucke libdyld API-Aufrufe, die von main gemacht wurden
- `DYLD_PRINT_BINDINGS`: Drucke Symbole beim Binden
- `DYLD_WEAK_BINDINGS`: Drucke nur schwache Symbole beim Binden
- `DYLD_PRINT_CODE_SIGNATURES`: Drucke Code-Signatur-Registrierungsoperationen
- `DYLD_PRINT_DOFS`: Drucke D-Trace-Objektformatabschnitte wie geladen
- `DYLD_PRINT_ENV`: Drucke die von dyld gesehene Umgebung
- `DYLD_PRINT_INTERPOSTING`: Drucke Interposting-Operationen
- `DYLD_PRINT_LIBRARIES`: Drucke geladene Bibliotheken
- `DYLD_PRINT_OPTS`: Drucke Ladeoptionen
- `DYLD_REBASING`: Drucke Symbol-Rebasierungsoperationen
- `DYLD_RPATHS`: Drucke Erweiterungen von @rpath
- `DYLD_PRINT_SEGMENTS`: Drucke Zuordnungen von Mach-O-Segmenten
- `DYLD_PRINT_STATISTICS`: Drucke Zeitstatistiken
- `DYLD_PRINT_STATISTICS_DETAILS`: Drucke detaillierte Zeitstatistiken
- `DYLD_PRINT_WARNINGS`: Drucke Warnmeldungen
- `DYLD_SHARED_CACHE_DIR`: Pfad für den gemeinsamen Bibliothekscache
- `DYLD_SHARED_REGION`: "verwenden", "privat", "vermeiden"
- `DYLD_USE_CLOSURES`: Schließe Closures ein

Es ist möglich, mehr mit etwas wie zu finden:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Oder das dyld-Projekt von [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) herunterzuladen und im Ordner auszuführen:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Referenzen

- [**\*OS Internals, Volume I: User Mode. Von Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
