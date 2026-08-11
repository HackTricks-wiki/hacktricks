# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Der tatsächliche **entrypoint** einer Mach-o-Binary ist der dynamisch gelinkte Linker, der in `LC_LOAD_DYLINKER` definiert ist und normalerweise auf `/usr/lib/dyld` verweist.<sup>[[3]](#references)</sup>

Dieser Linker muss alle Libraries der ausführbaren Datei finden, sie in den Speicher abbilden und alle nicht-lazy Libraries linken. Erst nach diesem Prozess wird der Entry-Point der Binary ausgeführt.

Natürlich hat **`dyld`** keine Dependencies (es verwendet Syscalls und Ausschnitte aus libSystem).

> [!CAUTION]
> Falls dieser Linker eine Vulnerability enthält, wäre es möglich, **Privileges zu eskalieren**, da er vor der Ausführung jeder Binary (einschließlich hochprivilegierter) ausgeführt wird.

### Ablauf

Dyld wird von **`dyldboostrap::start`** geladen, das außerdem Dinge wie den **Stack Canary** lädt. Das liegt daran, dass diese Funktion in ihrem **`apple`**-Argumentvektor diesen und andere **sensitive** **Werte** erhält.<sup>[[1]](#references)</sup>

**`dyls::_main()`** ist der Entry-Point von dyld. Seine erste Aufgabe besteht darin, `configureProcessRestrictions()` auszuführen, das normalerweise die **`DYLD_*`**-Umgebungsvariablen einschränkt, die hier erklärt werden:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Danach bildet es den dyld Shared Cache ab, der alle wichtigen System-Libraries vorab linkt. Anschließend bildet es die Libraries ab, von denen die Binary abhängig ist, und fährt rekursiv fort, bis alle benötigten Libraries geladen sind. Daher:

1. Es beginnt mit dem Laden eingefügter Libraries über `DYLD_INSERT_LIBRARIES` (falls erlaubt)
2. Danach die aus dem Shared Cache
3. Danach die importierten
1. Danach fährt es rekursiv mit dem Importieren von Libraries fort

Sobald alle geladen sind, werden die **Initialisierer** dieser Libraries ausgeführt. Diese werden mit **`__attribute__((constructor))`** codiert und entweder in `LC_ROUTINES[_64]` (inzwischen veraltet) definiert oder durch einen Pointer in einer Section angegeben, die mit `S_MOD_INIT_FUNC_POINTERS` gekennzeichnet ist (normalerweise: **`__DATA.__MOD_INIT_FUNC`**).

Terminatoren werden mit **`__attribute__((destructor))`** codiert und befinden sich in einer Section, die mit `S_MOD_TERM_FUNC_POINTERS` gekennzeichnet ist (**`__DATA.__mod_term_func`**).

### Stubs

Alle Binaries unter macOS sind dynamisch gelinkt. Daher enthalten sie einige Stub-Sections, die der Binary helfen, auf verschiedenen Maschinen und in unterschiedlichen Kontexten zum korrekten Code zu springen. Beim Ausführen der Binary ist dyld dafür verantwortlich, diese Adressen aufzulösen (zumindest die nicht-lazy Adressen).

Einige Stub-Sections in der Binary:

- **`__TEXT.__[auth_]stubs`**: Pointer aus `__DATA`-Sections
- **`__TEXT.__stub_helper`**: Kleiner Code, der Dynamic Linking mit Informationen über die aufzurufende Funktion ausführt
- **`__DATA.__[auth_]got`**: Global Offset Table (Adressen importierter Funktionen, die bei der Auflösung zur Ladezeit gebunden werden, da sie mit dem Flag `S_NON_LAZY_SYMBOL_POINTERS` gekennzeichnet ist)
- **`__DATA.__nl_symbol_ptr`**: Non-lazy Symbol Pointers (werden zur Ladezeit gebunden, da sie mit dem Flag `S_NON_LAZY_SYMBOL_POINTERS` gekennzeichnet sind)
- **`__DATA.__la_symbol_ptr`**: Lazy Symbol Pointers (werden beim ersten Zugriff gebunden)

> [!WARNING]
> Beachte, dass die Pointer mit dem Präfix "auth_" einen prozessinternen Verschlüsselungsschlüssel verwenden, um sie zu schützen (PAC). Außerdem ist es möglich, die arm64-Instruktion `BLRA[A/B]` zu verwenden, um den Pointer vor dem Folgen zu verifizieren. Und `RETA\[A/B]` kann anstelle einer RET-Adresse verwendet werden.\
> Tatsächlich verwendet der Code in **`__TEXT.__auth_stubs`** **`braa`** anstelle von **`bl`**, um die angeforderte Funktion aufzurufen und den Pointer zu authentifizieren.
>
> Beachte außerdem, dass aktuelle dyld-Versionen **alles als non-lazy** laden.

### Lazy Symbols finden
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Interessanter Disassembly-Abschnitt:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Es ist zu sehen, dass der Sprung zum Aufruf von printf zu **`__TEXT.__stubs`** führt:
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
In der Disassemblierung des **`__stubs`**-Abschnitts:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
Sie sehen, dass wir **zur Adresse der GOT springen**, die in diesem Fall non-lazy aufgelöst wird und die Adresse der printf-Funktion enthält.

In anderen Situationen könnte statt eines direkten Sprungs zur GOT zu **`__DATA.__la_symbol_ptr`** gesprungen werden. Dort wird ein Wert geladen, der die Funktion repräsentiert, die geladen werden soll. Anschließend wird zu **`__TEXT.__stub_helper`** gesprungen, das zu **`__DATA.__nl_symbol_ptr`** springt. Dieses enthält die Adresse von **`dyld_stub_binder`**, die als Parameter die Nummer der Funktion und eine Adresse entgegennimmt.\
Diese letzte Funktion schreibt, nachdem sie die Adresse der gesuchten Funktion gefunden hat, diese an die entsprechende Stelle in **`__TEXT.__stub_helper`**, um zukünftige Lookups zu vermeiden.

> [!TIP]
> Beachten Sie jedoch, dass aktuelle dyld-Versionen alles als non-lazy laden.

#### Dyld opcodes

Schließlich muss **`dyld_stub_binder`** die angegebene Funktion finden und sie an die richtige Adresse schreiben, damit sie nicht erneut gesucht werden muss. Dazu verwendet sie opcodes (eine endliche Zustandsmaschine) innerhalb von dyld.

## apple\[] argument vector

In macOS empfängt die main-Funktion tatsächlich 4 Argumente statt 3. Das vierte wird apple genannt, und jeder Eintrag hat die Form `key=value`. Zum Beispiel:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Keine zu übersetzenden Inhalte bereitgestellt.
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
> Wenn diese Werte die main function erreichen, wurden sensible Informationen bereits aus ihnen entfernt, andernfalls wäre es zu einem data leak gekommen.

Es ist möglich, all diese interessanten Werte vor dem Eintritt in main mit debugging zu sehen:

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

Dies ist eine von dyld exportierte Struktur mit Informationen über den Zustand von dyld. Sie ist im [**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) zu finden und enthält unter anderem die Version, einen Pointer auf das dyld_image_info-Array und auf dyld_image_notifier, Informationen darüber, ob proc vom shared cache getrennt ist, ob der libSystem-Initializer aufgerufen wurde, einen Pointer auf den eigenen Mach-Header von dyld sowie einen Pointer auf den Versions-String von dyld ...<sup>[[4]](#references)</sup>

## dyld env variables

### dyld debuggen

Interessante env variables, die dabei helfen zu verstehen, was dyld tut:

- **DYLD_PRINT_LIBRARIES**

Jede geladene library überprüfen:
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

Überprüfe, wie jede Bibliothek geladen wird:
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

Gibt aus, wann der Initializer jeder Bibliothek ausgeführt wird:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Andere

- `DYLD_BIND_AT_LAUNCH`: Lazy bindings werden zusammen mit non-lazy bindings aufgelöst
- `DYLD_DISABLE_PREFETCH`: Pre-Fetching von \_\_DATA- und \_\_LINKEDIT-Inhalten deaktivieren
- `DYLD_FORCE_FLAT_NAMESPACE`: Bindings auf einer Ebene
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Auflösungspfade
- `DYLD_INSERT_LIBRARIES`: Eine bestimmte Library laden
- `DYLD_PRINT_TO_FILE`: dyld-Debug-Ausgaben in eine Datei schreiben
- `DYLD_PRINT_APIS`: libdyld-API-Aufrufe ausgeben
- `DYLD_PRINT_APIS_APP`: Von der Hauptanwendung ausgeführte libdyld-API-Aufrufe ausgeben
- `DYLD_PRINT_BINDINGS`: Symbole beim Binden ausgeben
- `DYLD_WEAK_BINDINGS`: Beim Binden nur weak symbols ausgeben
- `DYLD_PRINT_CODE_SIGNATURES`: Vorgänge zur Registrierung von Code-Signaturen ausgeben
- `DYLD_PRINT_DOFS`: D-Trace object format sections beim Laden ausgeben
- `DYLD_PRINT_ENV`: Die von dyld ermittelte Umgebung ausgeben
- `DYLD_PRINT_INTERPOSTING`: Interposting-Vorgänge ausgeben
- `DYLD_PRINT_LIBRARIES`: Geladene Libraries ausgeben
- `DYLD_PRINT_OPTS`: Ladeoptionen ausgeben
- `DYLD_REBASING`: Vorgänge zum Rebasing von Symbolen ausgeben
- `DYLD_RPATHS`: Erweiterungen von @rpath ausgeben
- `DYLD_PRINT_SEGMENTS`: Zuordnungen von Mach-O-Segmenten ausgeben
- `DYLD_PRINT_STATISTICS`: Zeitstatistiken ausgeben
- `DYLD_PRINT_STATISTICS_DETAILS`: Detaillierte Zeitstatistiken ausgeben
- `DYLD_PRINT_WARNINGS`: Warnmeldungen ausgeben
- `DYLD_SHARED_CACHE_DIR`: Zu verwendender Pfad für den Shared-Library-Cache
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Closures aktivieren

Weitere Variablen lassen sich beispielsweise mit Folgendem finden:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Oder das dyld-Projekt von [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) herunterladen und im Ordner ausführen:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp` (Prozessstartpfad)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (Prozess-/Sicherheitskonfiguration)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (Kernel-Seite von `execve`, Laden von dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (Struktur `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
