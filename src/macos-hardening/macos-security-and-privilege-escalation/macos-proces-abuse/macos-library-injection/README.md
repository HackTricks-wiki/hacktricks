# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Il codice di **dyld è open source** e può essere trovato in [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) e può essere scaricato come tar utilizzando un **URL come** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Dai un'occhiata a come Dyld carica le librerie all'interno dei binari in:

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Questo è simile a [**LD_PRELOAD su Linux**](../../../../linux-hardening/privilege-escalation/#ld_preload). Permette di indicare a un processo che sta per essere eseguito di caricare una libreria specifica da un percorso (se la variabile di ambiente è abilitata)

Questa tecnica può essere anche **utilizzata come tecnica ASEP** poiché ogni applicazione installata ha un plist chiamato "Info.plist" che consente di **assegnare variabili ambientali** utilizzando una chiave chiamata `LSEnvironmental`.

> [!NOTE]
> Dal 2012 **Apple ha drasticamente ridotto il potere** di **`DYLD_INSERT_LIBRARIES`**.
>
> Vai al codice e **controlla `src/dyld.cpp`**. Nella funzione **`pruneEnvironmentVariables`** puoi vedere che le variabili **`DYLD_*`** vengono rimosse.
>
> Nella funzione **`processRestricted`** viene impostato il motivo della restrizione. Controllando quel codice puoi vedere che i motivi sono:
>
> - Il binario è `setuid/setgid`
> - Esistenza della sezione `__RESTRICT/__restrict` nel binario macho.
> - Il software ha diritti (runtime rinforzato) senza il diritto [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>   - Controlla i **diritti** di un binario con: `codesign -dv --entitlements :- </path/to/bin>`
>
> Nelle versioni più aggiornate puoi trovare questa logica nella seconda parte della funzione **`configureProcessRestrictions`.** Tuttavia, ciò che viene eseguito nelle versioni più recenti sono i **controlli iniziali della funzione** (puoi rimuovere gli if relativi a iOS o simulazione poiché non verranno utilizzati in macOS.

### Validazione della Libreria

Anche se il binario consente di utilizzare la variabile di ambiente **`DYLD_INSERT_LIBRARIES`**, se il binario controlla la firma della libreria da caricare non caricherà una personalizzata.

Per caricare una libreria personalizzata, il binario deve avere **uno dei seguenti diritti**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

oppure il binario **non dovrebbe** avere il **flag di runtime rinforzato** o il **flag di validazione della libreria**.

Puoi controllare se un binario ha **runtime rinforzato** con `codesign --display --verbose <bin>` controllando il flag runtime in **`CodeDirectory`** come: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Puoi anche caricare una libreria se è **firmata con lo stesso certificato del binario**.

Trova un esempio su come (ab)usare questo e controlla le restrizioni in:

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Ricorda che **le precedenti restrizioni sulla validazione delle librerie si applicano anche** per eseguire attacchi di Dylib hijacking.

Come in Windows, anche in MacOS puoi **hijackare dylibs** per far **eseguire** **codice** **arbitrario** alle **applicazioni** (beh, in realtà da un utente normale questo potrebbe non essere possibile poiché potresti aver bisogno di un permesso TCC per scrivere all'interno di un pacchetto `.app` e hijackare una libreria).\
Tuttavia, il modo in cui le applicazioni **MacOS** **caricano** le librerie è **più ristretto** rispetto a Windows. Ciò implica che gli sviluppatori di **malware** possono comunque utilizzare questa tecnica per il **furtivo**, ma la probabilità di poter **abusare di questo per elevare i privilegi è molto più bassa**.

Prima di tutto, è **più comune** trovare che i **binari MacOS indicano il percorso completo** alle librerie da caricare. E in secondo luogo, **MacOS non cerca mai** nelle cartelle del **$PATH** per le librerie.

La parte **principale** del **codice** relativa a questa funzionalità si trova in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Ci sono **4 diversi comandi header** che un binario macho può utilizzare per caricare librerie:

- Il comando **`LC_LOAD_DYLIB`** è il comando comune per caricare un dylib.
- Il comando **`LC_LOAD_WEAK_DYLIB`** funziona come il precedente, ma se il dylib non viene trovato, l'esecuzione continua senza alcun errore.
- Il comando **`LC_REEXPORT_DYLIB`** proxy (o riesporta) i simboli da una libreria diversa.
- Il comando **`LC_LOAD_UPWARD_DYLIB`** viene utilizzato quando due librerie dipendono l'una dall'altra (questo è chiamato una _dipendenza ascendente_).

Tuttavia, ci sono **2 tipi di dylib hijacking**:

- **Librerie debolmente collegate mancanti**: Questo significa che l'applicazione cercherà di caricare una libreria che non esiste configurata con **LC_LOAD_WEAK_DYLIB**. Poi, **se un attaccante posiziona un dylib dove ci si aspetta che venga caricato**.
- Il fatto che il link sia "debole" significa che l'applicazione continuerà a funzionare anche se la libreria non viene trovata.
- Il **codice relativo** a questo si trova nella funzione `ImageLoaderMachO::doGetDependentLibraries` di `ImageLoaderMachO.cpp` dove `lib->required` è solo `false` quando `LC_LOAD_WEAK_DYLIB` è true.
- **Trova librerie debolmente collegate** nei binari con (hai successivamente un esempio su come creare librerie di hijacking):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configurato con @rpath**: I binari Mach-O possono avere i comandi **`LC_RPATH`** e **`LC_LOAD_DYLIB`**. Basato sui **valori** di quei comandi, le **librerie** verranno **caricate** da **diverse directory**.
- **`LC_RPATH`** contiene i percorsi di alcune cartelle utilizzate per caricare librerie dal binario.
- **`LC_LOAD_DYLIB`** contiene il percorso a librerie specifiche da caricare. Questi percorsi possono contenere **`@rpath`**, che verrà **sostituito** dai valori in **`LC_RPATH`**. Se ci sono più percorsi in **`LC_RPATH`**, tutti verranno utilizzati per cercare la libreria da caricare. Esempio:
- Se **`LC_LOAD_DYLIB`** contiene `@rpath/library.dylib` e **`LC_RPATH`** contiene `/application/app.app/Contents/Framework/v1/` e `/application/app.app/Contents/Framework/v2/`. Entrambe le cartelle verranno utilizzate per caricare `library.dylib`**.** Se la libreria non esiste in `[...]/v1/` e un attaccante potrebbe posizionarla lì per hijackare il caricamento della libreria in `[...]/v2/` poiché l'ordine dei percorsi in **`LC_LOAD_DYLIB`** è seguito.
- **Trova percorsi rpath e librerie** nei binari con: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: È il **percorso** alla directory contenente il **file eseguibile principale**.
>
> **`@loader_path`**: È il **percorso** alla **directory** contenente il **binario Mach-O** che contiene il comando di caricamento.
>
> - Quando utilizzato in un eseguibile, **`@loader_path`** è effettivamente **lo stesso** di **`@executable_path`**.
> - Quando utilizzato in un **dylib**, **`@loader_path`** fornisce il **percorso** al **dylib**.

Il modo per **elevare i privilegi** abusando di questa funzionalità sarebbe nel raro caso in cui un **applicazione** venga eseguita **da** **root** e stia **cercando** qualche **libreria in qualche cartella dove l'attaccante ha permessi di scrittura.**

> [!TIP]
> Un bel **scanner** per trovare **librerie mancanti** nelle applicazioni è [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) o una [**versione CLI**](https://github.com/pandazheng/DylibHijack).\
> Un bel **report con dettagli tecnici** su questa tecnica può essere trovato [**qui**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Esempio**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Ricorda che **le precedenti restrizioni sulla validazione delle librerie si applicano anche** per eseguire attacchi di Dlopen hijacking.

Da **`man dlopen`**:

- Quando il percorso **non contiene un carattere slash** (cioè è solo un nome foglia), **dlopen() cercherà**. Se **`$DYLD_LIBRARY_PATH`** è stato impostato all'avvio, dyld cercherà prima **in quella directory**. Successivamente, se il file macho chiamante o l'eseguibile principale specificano un **`LC_RPATH`**, allora dyld cercherà **in quelle** directory. Successivamente, se il processo è **non ristretto**, dyld cercherà nella **directory di lavoro corrente**. Infine, per i vecchi binari, dyld proverà alcuni fallback. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** è stato impostato all'avvio, dyld cercherà in **quelle directory**, altrimenti, dyld cercherà in **`/usr/local/lib/`** (se il processo è non ristretto), e poi in **`/usr/lib/`** (queste informazioni sono state prese da **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(se non ristretto)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (se non ristretto)
6. `/usr/lib/`

> [!CAUTION]
> Se non ci sono slash nel nome, ci sarebbero 2 modi per fare un hijacking:
>
> - Se qualche **`LC_RPATH`** è **scrivibile** (ma la firma viene controllata, quindi per questo hai anche bisogno che il binario sia non ristretto)
> - Se il binario è **non ristretto** e quindi è possibile caricare qualcosa dalla CWD (o abusare di una delle variabili di ambiente menzionate)

- Quando il percorso **sembra un percorso di framework** (ad es. `/stuff/foo.framework/foo`), se **`$DYLD_FRAMEWORK_PATH`** è stato impostato all'avvio, dyld cercherà prima in quella directory per il **percorso parziale del framework** (ad es. `foo.framework/foo`). Successivamente, dyld proverà il **percorso fornito così com'è** (utilizzando la directory di lavoro corrente per i percorsi relativi). Infine, per i vecchi binari, dyld proverà alcuni fallback. Se **`$DYLD_FALLBACK_FRAMEWORK_PATH`** è stato impostato all'avvio, dyld cercherà in quelle directory. Altrimenti, cercherà in **`/Library/Frameworks`** (su macOS se il processo è non ristretto), poi in **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. percorso fornito (utilizzando la directory di lavoro corrente per i percorsi relativi se non ristretto)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (se non ristretto)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Se un percorso di framework, il modo per hijackarlo sarebbe:
>
> - Se il processo è **non ristretto**, abusando del **percorso relativo dalla CWD** le variabili di ambiente menzionate (anche se non è detto nella documentazione se il processo è ristretto le variabili di ambiente DYLD\_\* vengono rimosse)

- Quando il percorso **contiene uno slash ma non è un percorso di framework** (cioè un percorso completo o un percorso parziale a un dylib), dlopen() prima cerca (se impostato) in **`$DYLD_LIBRARY_PATH`** (con la parte foglia del percorso). Successivamente, dyld **prova il percorso fornito** (utilizzando la directory di lavoro corrente per i percorsi relativi (ma solo per i processi non ristretti)). Infine, per i binari più vecchi, dyld proverà fallback. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** è stato impostato all'avvio, dyld cercherà in quelle directory, altrimenti, dyld cercherà in **`/usr/local/lib/`** (se il processo è non ristretto), e poi in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. percorso fornito (utilizzando la directory di lavoro corrente per i percorsi relativi se non ristretto)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (se non ristretto)
5. `/usr/lib/`

> [!CAUTION]
> Se ci sono slash nel nome e non è un framework, il modo per hijackarlo sarebbe:
>
> - Se il binario è **non ristretto** e quindi è possibile caricare qualcosa dalla CWD o `/usr/local/lib` (o abusare di una delle variabili di ambiente menzionate)

> [!NOTE]
> Nota: Non ci sono **file di configurazione** per **controllare la ricerca di dlopen**.
>
> Nota: Se l'eseguibile principale è un **binario set\[ug]id o firmato con diritti**, allora **tutte le variabili di ambiente vengono ignorate**, e può essere utilizzato solo un percorso completo ([controlla le restrizioni di DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) per ulteriori informazioni dettagliate)
>
> Nota: Le piattaforme Apple utilizzano file "universali" per combinare librerie a 32 bit e 64 bit. Ciò significa che non ci sono **percorsi di ricerca separati per 32 bit e 64 bit**.
>
> Nota: Su piattaforme Apple, la maggior parte delle librerie OS dylib sono **combinati nel cache dyld** e non esistono su disco. Pertanto, chiamare **`stat()`** per preflight se un dylib OS esiste **non funzionerà**. Tuttavia, **`dlopen_preflight()`** utilizza gli stessi passaggi di **`dlopen()`** per trovare un file mach-o compatibile.

**Controlla i percorsi**

Controlliamo tutte le opzioni con il seguente codice:
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Se compili e esegui, puoi vedere **dove ogni libreria è stata cercata senza successo**. Inoltre, potresti **filtrare i log del FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Hijacking del Percorso Relativo

Se un **binary/app privilegiato** (come un SUID o qualche binary con potenti autorizzazioni) sta **caricando una libreria a percorso relativo** (ad esempio usando `@executable_path` o `@loader_path`) e ha **disabilitata la Validazione della Libreria**, potrebbe essere possibile spostare il binary in una posizione dove l'attaccante potrebbe **modificare la libreria caricata a percorso relativo**, e abusarne per iniettare codice nel processo.

## Potare le variabili d'ambiente `DYLD_*` e `LD_LIBRARY_PATH`

Nel file `dyld-dyld-832.7.1/src/dyld2.cpp` è possibile trovare la funzione **`pruneEnvironmentVariables`**, che rimuoverà qualsiasi variabile d'ambiente che **inizia con `DYLD_`** e **`LD_LIBRARY_PATH=`**.

Imposterà anche a **null** specificamente le variabili d'ambiente **`DYLD_FALLBACK_FRAMEWORK_PATH`** e **`DYLD_FALLBACK_LIBRARY_PATH`** per i binary **suid** e **sgid**.

Questa funzione viene chiamata dalla funzione **`_main`** dello stesso file se si mira a OSX in questo modo:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
e quei flag booleani sono impostati nello stesso file nel codice:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
Il che significa fondamentalmente che se il binario è **suid** o **sgid**, o ha un segmento **RESTRICT** negli header o è stato firmato con il flag **CS_RESTRICT**, allora **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** è vero e le variabili di ambiente vengono eliminate.

Nota che se CS_REQUIRE_LV è vero, allora le variabili non verranno eliminate ma la validazione della libreria controllerà che stiano utilizzando lo stesso certificato del binario originale.

## Controlla le Restrizioni

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Sezione `__RESTRICT` con segmento `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Runtime rinforzato

Crea un nuovo certificato nel Portachiavi e usalo per firmare il binario:
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
> [!CAUTION]
> Nota che anche se ci sono binari firmati con i flag **`0x0(none)`**, possono ottenere dinamicamente il flag **`CS_RESTRICT`** quando vengono eseguiti e quindi questa tecnica non funzionerà su di essi.
>
> Puoi controllare se un proc ha questo flag con (get [**csops here**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> e poi controllare se il flag 0x800 è abilitato.

## Riferimenti

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
