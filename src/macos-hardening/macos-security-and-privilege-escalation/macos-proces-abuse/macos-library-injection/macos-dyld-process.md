# Processo Dyld di macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

Il vero **entrypoint** di un binario Mach-o è il linker dinamico, definito in `LC_LOAD_DYLINKER`, che solitamente è `/usr/lib/dyld`.<sup>[[3]](#references)</sup>

Questo linker deve individuare tutte le librerie dell'eseguibile, mapparle in memoria e collegare tutte le librerie non lazy. Solo dopo questo processo verrà eseguito l'entry-point del binario.

Naturalmente, **`dyld`** non ha dipendenze (utilizza syscall ed estratti di libSystem).

> [!CAUTION]
> Se questo linker contenesse una vulnerabilità, poiché viene eseguito prima dell'esecuzione di qualsiasi binario (anche quelli altamente privilegiati), sarebbe possibile **escalare i privilegi**.

### Flusso

Dyld verrà caricato da **`dyldboostrap::start`**, che caricherà anche elementi come lo **stack canary**. Questo perché questa funzione riceverà nel suo vettore di argomenti **`apple`** questo e altri **valori** **sensibili**.<sup>[[1]](#references)</sup>

**`dyls::_main()`** è l'entry point di dyld e il suo primo compito è eseguire `configureProcessRestrictions()`, che solitamente limita le variabili d'ambiente **`DYLD_*`** spiegate in:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Successivamente, mappa la dyld shared cache, che pre-collega tutte le librerie di sistema importanti, quindi mappa le librerie da cui dipende il binario e continua ricorsivamente finché tutte le librerie necessarie non sono state caricate. Pertanto:

1. inizia a caricare le librerie inserite con `DYLD_INSERT_LIBRARIES` (se consentito)
2. Poi quelle nella shared cache
3. Poi quelle importate
1. Poi continua a importare ricorsivamente le librerie

Una volta caricate tutte, vengono eseguiti gli **initialiser** di queste librerie. Questi sono codificati usando **`__attribute__((constructor))`**, definito in `LC_ROUTINES[_64]` (ora deprecato), oppure tramite un puntatore in una sezione contrassegnata con `S_MOD_INIT_FUNC_POINTERS` (solitamente: **`__DATA.__MOD_INIT_FUNC`**).

I terminator sono codificati con **`__attribute__((destructor))`** e si trovano in una sezione contrassegnata con `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stub

Tutti i binari su macOS sono collegati dinamicamente. Pertanto, contengono alcune sezioni di stub che aiutano il binario a saltare al codice corretto su macchine e contesti diversi. Quando il binario viene eseguito, è dyld il componente che deve risolvere questi indirizzi (almeno quelli non lazy).

Alcune sezioni di stub nel binario:

- **`__TEXT.__[auth_]stubs`**: puntatori dalle sezioni `__DATA`
- **`__TEXT.__stub_helper`**: piccolo codice che invoca il linking dinamico con informazioni sulla funzione da chiamare
- **`__DATA.__[auth_]got`**: Global Offset Table (indirizzi delle funzioni importate, quando risolti, associati durante il load time poiché contrassegnati con il flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: puntatori ai simboli non lazy (associati durante il load time poiché contrassegnati con il flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: puntatori ai simboli lazy (associati al primo accesso)

> [!WARNING]
> Nota che i puntatori con il prefisso "auth\_" utilizzano una chiave di crittografia in-process per proteggerli (PAC). Inoltre, è possibile utilizzare l'istruzione arm64 `BLRA[A/B]` per verificare il puntatore prima di seguirlo. E RETA\[A/B] può essere utilizzato al posto di un indirizzo RET.\
> In realtà, il codice in **`__TEXT.__auth_stubs`** utilizzerà **`braa`** invece di **`bl`** per chiamare la funzione richiesta e autenticare il puntatore.
>
> Nota inoltre che le versioni attuali di dyld caricano tutto come non lazy.

### Individuazione dei simboli lazy
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Parte interessante del disassemblaggio:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
È possibile vedere che il salto per chiamare printf è diretto a **`__TEXT.__stubs`**:
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
Nel disassemblaggio della sezione **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
puoi vedere che stiamo **saltando all'indirizzo della GOT**, che in questo caso viene risolto in modalità non-lazy e conterrà l'indirizzo della funzione printf.

In altre situazioni, invece di saltare direttamente alla GOT, potrebbe saltare a **`__DATA.__la_symbol_ptr`**, che caricherà un valore che rappresenta la funzione che sta cercando di caricare, per poi saltare a **`__TEXT.__stub_helper`**, che salta a **`__DATA.__nl_symbol_ptr`**, contenente l'indirizzo di **`dyld_stub_binder`**, che accetta come parametri il numero della funzione e un indirizzo.\
Quest'ultima funzione, dopo aver trovato l'indirizzo della funzione cercata, lo scrive nella posizione corrispondente in **`__TEXT.__stub_helper`** per evitare di dover effettuare lookup in futuro.

> [!TIP]
> Tuttavia, nota che le versioni attuali di dyld caricano tutto come non-lazy.

#### Opcode di Dyld

Infine, **`dyld_stub_binder`** deve trovare la funzione indicata e scriverla all'indirizzo corretto per non doverla cercare nuovamente. A questo scopo utilizza opcode (una macchina a stati finiti) all'interno di dyld.

## vettore degli argomenti apple\[]

In macOS la funzione principale riceve in realtà 4 argomenti invece di 3. Il quarto è chiamato apple e ogni voce ha la forma `key=value`. Ad esempio:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Nessun testo da tradurre è stato fornito.
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
> Quando questi valori raggiungono la funzione principale, le informazioni sensibili sono già state rimosse oppure si sarebbe verificato un data leak.

è possibile visualizzare tutti questi valori interessanti eseguendo il debugging prima di entrare nella funzione main con:

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

Questa è una struttura esportata da dyld contenente informazioni sullo stato di dyld, disponibile nel [**codice sorgente**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html), con informazioni come la versione, il puntatore all'array dyld_image_info, a dyld_image_notifier, l'eventuale separazione del processo dalla shared cache, l'eventuale chiamata all'inizializzatore di libSystem, il puntatore al Mach header di dyld, la stringa della versione di dyld...<sup>[[4]](#references)</sup>

## variabili d'ambiente di dyld

### debug dyld

Variabili d'ambiente interessanti che aiutano a capire cosa sta facendo dyld:

- **DYLD_PRINT_LIBRARIES**

Controlla ogni libreria caricata:
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

Controlla come viene caricata ogni libreria:
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

Stampa quando viene esegializzato ogni initializer della libreria:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Altri

- `DYLD_BIND_AT_LAUNCH`: I lazy bindings vengono risolti con quelli non lazy
- `DYLD_DISABLE_PREFETCH`: Disabilita il pre-fetch dei contenuti \_\_DATA e \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Bindings a livello singolo
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Percorsi di risoluzione
- `DYLD_INSERT_LIBRARIES`: Carica una libreria specifica
- `DYLD_PRINT_TO_FILE`: Scrive il debug di dyld in un file
- `DYLD_PRINT_APIS`: Stampa le chiamate alle API di libdyld
- `DYLD_PRINT_APIS_APP`: Stampa le chiamate alle API di libdyld effettuate dal processo principale
- `DYLD_PRINT_BINDINGS`: Stampa i simboli durante il binding
- `DYLD_WEAK_BINDINGS`: Stampa solo i simboli weak durante il binding
- `DYLD_PRINT_CODE_SIGNATURES`: Stampa le operazioni di registrazione delle firme del codice
- `DYLD_PRINT_DOFS`: Stampa le sezioni D-Trace object format durante il caricamento
- `DYLD_PRINT_ENV`: Stampa l'ambiente visto da dyld
- `DYLD_PRINT_INTERPOSTING`: Stampa le operazioni di interposting
- `DYLD_PRINT_LIBRARIES`: Stampa le librerie caricate
- `DYLD_PRINT_OPTS`: Stampa le opzioni di caricamento
- `DYLD_REBASING`: Stampa le operazioni di rebasing dei simboli
- `DYLD_RPATHS`: Stampa le espansioni di @rpath
- `DYLD_PRINT_SEGMENTS`: Stampa i mapping dei segmenti Mach-O
- `DYLD_PRINT_STATISTICS`: Stampa le statistiche sui tempi
- `DYLD_PRINT_STATISTICS_DETAILS`: Stampa le statistiche dettagliate sui tempi
- `DYLD_PRINT_WARNINGS`: Stampa i messaggi di avviso
- `DYLD_SHARED_CACHE_DIR`: Percorso da utilizzare per la cache delle librerie condivise
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Abilita le closures

È possibile trovarne altri con qualcosa come:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Oppure scaricando il progetto dyld da [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) ed eseguendo all'interno della cartella:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp` (percorso di avvio del processo)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (configurazione del processo e della sicurezza)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (lato kernel di `execve`, caricamento di dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (struttura `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
