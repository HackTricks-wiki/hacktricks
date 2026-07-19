# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Il codice di **dyld è open source** e può essere trovato in [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) e può essere scaricato come tar usando un **URL come** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Dai un'occhiata a come Dyld carica le librerie all'interno dei binary in:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

È simile a [**LD_PRELOAD su Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Permette di indicare a un processo che sta per essere eseguito di caricare una libreria specifica da un path (se la env var è abilitata).

Questa tecnica può essere anche **usata come tecnica ASEP**, poiché ogni applicazione installata ha un plist chiamato "Info.plist" che permette di **assegnare environmental variables** usando una key chiamata `LSEnvironmental`.

> [!TIP]
> Dal 2012 **Apple ha drasticamente ridotto il potere** di **`DYLD_INSERT_LIBRARIES`**.
>
> Vai al codice e **controlla `src/dyld.cpp`**. Nella funzione **`pruneEnvironmentVariables`** puoi vedere che le variabili **`DYLD_*`** vengono rimosse.
>
> Nella funzione **`processRestricted`** viene impostata la ragione della restrizione. Controllando quel codice puoi vedere che le ragioni sono:
>
> - Il binary è `setuid/setgid`
> - Esistenza della sezione `__RESTRICT/__restrict` nel binary macho.
> - Il software ha entitlements (hardened runtime) senza l'entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>  - Controlla gli **entitlements** di un binary con: `codesign -dv --entitlements :- </path/to/bin>`
>
> Nelle versioni più aggiornate puoi trovare questa logica nella seconda parte della funzione **`configureProcessRestrictions`.** Tuttavia, nelle versioni più recenti viene eseguito l'inizio dei controlli della funzione (puoi rimuovere gli if relativi a iOS o alla simulazione, poiché non verranno usati in macOS.

### Library Validation

Anche se il binary permette di usare la env var **`DYLD_INSERT_LIBRARIES`**, se il binary controlla la signature della libreria da caricare, non caricherà una custom library.

Per caricare una custom library, il binary deve avere **uno dei seguenti entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

oppure il binary **non deve** avere il **hardened runtime flag** o il **library validation flag**.

Puoi controllare se un binary ha il **hardened runtime** con `codesign --display --verbose <bin>`, controllando il runtime flag in **`CodeDirectory`**, ad esempio: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Puoi anche caricare una libreria se è **firmata con lo stesso certificate del binary**.

Trova un esempio su come abusare di questa tecnica e controllare le restrizioni in:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Ricorda che le **precedenti restrizioni di Library Validation** si applicano anche all'esecuzione di attacchi di Dylib hijacking.

Come in Windows, anche in MacOS puoi **hijackare le dylib** per fare in modo che le **applications** **eseguano** **arbitrary** **code** (in realtà, da un regular user questo potrebbe non essere possibile, poiché potrebbe essere necessaria una permission TCC per scrivere all'interno di un bundle `.app` e hijackare una libreria).\
Tuttavia, il modo in cui le applications **MacOS** **caricano** le librerie è **più restrittivo** rispetto a Windows. Ciò implica che gli sviluppatori di **malware** possono comunque usare questa tecnica per lo **stealth**, ma la probabilità di poterla **abusare per effettuare privilege escalation è molto più bassa**.

Innanzitutto, è **più comune** trovare che i **binary MacOS indichino il path completo** delle librerie da caricare. Inoltre, **MacOS non cerca mai** nelle cartelle del **$PATH** le librerie.

La parte **principale** del **code** relativa a questa funzionalità si trova in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Esistono **4 diversi header Commands** che un binary macho può usare per caricare librerie:

- Il command **`LC_LOAD_DYLIB`** è il command comune per caricare una dylib.
- Il command **`LC_LOAD_WEAK_DYLIB`** funziona come il precedente, ma se la dylib non viene trovata, l'esecuzione continua senza errori.
- Il command **`LC_REEXPORT_DYLIB`** fa da proxy (o re-export) per i symbols di una libreria diversa.
- Il command **`LC_LOAD_UPWARD_DYLIB`** viene usato quando due librerie dipendono l'una dall'altra (questa viene chiamata _upward dependency_).

Tuttavia, esistono **2 tipi di dylib hijacking**:

- **Missing weak linked libraries**: significa che l'application tenterà di caricare una libreria inesistente configurata con **LC_LOAD_WEAK_DYLIB**. Quindi, **se un attacker posiziona una dylib dove previsto, questa verrà caricata**.
- Il fatto che il link sia "weak" significa che l'application continuerà a funzionare anche se la libreria non viene trovata.
- Il **code correlato** si trova nella funzione `ImageLoaderMachO::doGetDependentLibraries` di `ImageLoaderMachO.cpp`, dove `lib->required` è `false` solo quando `LC_LOAD_WEAK_DYLIB` è true.
- **Trova le weak linked libraries** nei binary con (più avanti è disponibile un esempio su come creare librerie per il hijacking):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configurati con @rpath**: i binary Mach-O possono avere i commands **`LC_RPATH`** e **`LC_LOAD_DYLIB`**. In base ai **values** di questi commands, le **libraries** verranno **caricate** da **directories diverse**.
- **`LC_RPATH`** contiene i paths di alcune cartelle usate dal binary per caricare le librerie.
- **`LC_LOAD_DYLIB`** contiene il path di specifiche librerie da caricare. Questi paths possono contenere **`@rpath`**, che verrà sostituito dai values in **`LC_RPATH`**. Se ci sono diversi paths in **`LC_RPATH`**, tutti verranno usati per cercare la libreria da caricare. Esempio:
- Se **`LC_LOAD_DYLIB`** contiene `@rpath/library.dylib` e **`LC_RPATH`** contiene `/application/app.app/Contents/Framework/v1/` e `/application/app.app/Contents/Framework/v2/`. Entrambe le cartelle verranno usate per caricare `library.dylib`**.** Se la libreria non esiste in `[...]/v1/` e un attacker può posizionarla lì, può hijackare il caricamento della libreria in `[...]/v2/`, poiché viene seguito l'ordine dei paths in **`LC_LOAD_DYLIB`**.
- **Trova i rpath paths e le librerie** nei binary con: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: è il **path** della directory contenente il **main executable file**.
>
> **`@loader_path`**: è il **path** della **directory** contenente il **binary Mach-O** che include il load command.
>
> - Quando viene usato in un executable, **`@loader_path`** è di fatto uguale a **`@executable_path`**.
> - Quando viene usato in una **dylib**, **`@loader_path`** fornisce il **path** della **dylib**.

Il modo per effettuare una **privilege escalation** abusando di questa funzionalità si verificherebbe nel raro caso in cui un'**application** eseguita da **root** stia **cercando** una **library in una cartella in cui l'attacker ha permessi di scrittura.**

> [!TIP]
> Un buon **scanner** per trovare **missing libraries** nelle applications è [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) o una [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Un buon **report con dettagli tecnici** su questa tecnica è disponibile [**qui**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Esempio**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Ricorda che le **precedenti restrizioni di Library Validation** si applicano anche all'esecuzione di attacchi di Dlopen hijacking.

Da **`man dlopen`**:

- Quando il path **non contiene un carattere slash** (cioè è solo un leaf name), **dlopen() eseguirà una ricerca**. Se **`$DYLD_LIBRARY_PATH`** era impostata al momento dell'avvio, dyld cercherà prima in quella director**y**. Successivamente, se il file mach-o chiamante o il main executable specificano un **`LC_RPATH`**, dyld cercherà in quelle directories. Poi, se il processo è **unrestricted**, dyld cercherà nella current working directory. Infine, per i binary meno recenti, dyld proverà alcuni fallback. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** era impostata al momento dell'avvio, dyld cercherà in **quelle directories**, altrimenti dyld cercherà in **`/usr/local/lib/`** (se il processo è unrestricted), e poi in **`/usr/lib/`** (queste informazioni sono tratte da **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Se nel name non ci sono slash, esistono 2 modi per effettuare un hijacking:
>
> - Se un qualsiasi **`LC_RPATH`** è **writable** (ma la signature viene controllata, quindi per questo è inoltre necessario che il binary sia unrestricted)
> - Se il binary è **unrestricted**, è quindi possibile caricare qualcosa dalla CWD (o abusando di una delle env variables menzionate)

- Quando il path **sembra un path di framework** (ad esempio `/stuff/foo.framework/foo`), se **`$DYLD_FRAMEWORK_PATH`** era impostata al momento dell'avvio, dyld cercherà prima in quella directory il **framework partial path** (ad esempio `foo.framework/foo`). Successivamente, dyld proverà il path fornito così com'è (usando la current working directory per i paths relativi). Infine, per i binary meno recenti, dyld proverà alcuni fallback. Se **`$DYLD_FALLBACK_FRAMEWORK_PATH`** era impostata al momento dell'avvio, dyld cercherà in quelle directories. Altrimenti, cercherà in **`/Library/Frameworks`** (su macOS se il processo è unrestricted), poi in **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Se si tratta di un framework path, il modo per effettuare l'hijack sarebbe:
>
> - Se il processo è **unrestricted**, abusare del **relative path dalla CWD** o delle env variables menzionate (anche se non è indicato nella documentazione, se il processo è restricted le env vars DYLD\_\* vengono rimosse)

- Quando il path **contiene uno slash ma non è un framework path** (cioè un full path o un partial path verso una dylib), dlopen() cerca prima (se impostato) in **`$DYLD_LIBRARY_PATH`** (con la leaf part del path). Successivamente, dyld **prova il path fornito** (usando la current working directory per i paths relativi, ma solo per processi unrestricted). Infine, per i binary meno recenti, dyld proverà alcuni fallback. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** era impostata al momento dell'avvio, dyld cercherà in quelle directories, altrimenti dyld cercherà in **`/usr/local/lib/`** (se il processo è unrestricted), e poi in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Se il name contiene slash e non è un framework, il modo per effettuare l'hijack sarebbe:
>
> - Se il binary è **unrestricted**, è quindi possibile caricare qualcosa dalla CWD o da `/usr/local/lib` (o abusando di una delle env variables menzionate)

> [!TIP]
> Nota: non esistono **configuration files per controllare la ricerca di dlopen**.
>
> Nota: se il main executable è un **set\[ug]id binary o è codesigned con entitlements**, tutte le environment variables vengono ignorate e può essere usato solo un full path ([controlla le restrizioni di DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) per informazioni più dettagliate).
>
> Nota: le platforms Apple usano file "universal" per combinare librerie a 32 e 64 bit. Ciò significa che non esistono **search paths separati a 32 e 64 bit**.
>
> Nota: sulle platforms Apple la maggior parte delle OS dylibs viene combinata nella **dyld cache** e non esiste sul disco. Pertanto, chiamare **`stat()`** per verificare in anticipo se una OS dylib esiste **non funzionerà**. Tuttavia, **`dlopen_preflight()`** usa gli stessi passaggi di **`dlopen()`** per trovare un file mach-o compatibile.

**Controlla i paths**

Controlliamo tutte le options con il seguente code:
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
Se lo compili ed esegui, puoi vedere **dove è stata cercata senza successo ciascuna libreria**. Inoltre, potresti **filtrare i log del FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Se un **privileged binary/app** (come un SUID o un binary con entitlements potenti) sta **caricando una libreria con percorso relativo** (ad esempio usando `@executable_path` o `@loader_path`) e ha **Library Validation disabilitata**, potrebbe essere possibile spostare il binary in una posizione in cui l'attacker possa **modificare la libreria caricata tramite percorso relativo** e sfruttarla per iniettare codice nel processo.

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

Nel file `dyld-dyld-832.7.1/src/dyld2.cpp` è possibile trovare la funzione **`pruneEnvironmentVariables`**, che rimuoverà qualsiasi variabile d'ambiente che **inizia con `DYLD_`** e **`LD_LIBRARY_PATH=`**.

Imposterà inoltre specificamente a **null** le variabili d'ambiente **`DYLD_FALLBACK_FRAMEWORK_PATH`** e **`DYLD_FALLBACK_LIBRARY_PATH`** per i binary **suid** e **sgid**.

Questa funzione viene chiamata dalla funzione **`_main`** dello stesso file quando si esegue il targeting di OSX, in questo modo:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
e questi flag booleani vengono impostati nello stesso file nel codice:
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
Il che significa sostanzialmente che, se il binario è **suid** o **sgid**, oppure ha un segmento **RESTRICT** negli header, oppure è stato firmato con il flag **CS_RESTRICT**, allora **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** è true e le variabili d'ambiente vengono eliminate.

Nota che, se CS_REQUIRE_LV è true, le variabili non verranno eliminate, ma la validazione delle librerie verificherà che utilizzino lo stesso certificato del binario originale.

## Verifica delle restrizioni

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
### Hardened runtime

Crea un nuovo certificato nel Keychain e utilizzalo per firmare il binario:
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
> Nota che, anche se esistono binary firmati con i flag **`0x0(none)`**, questi possono ottenere dinamicamente il flag **`CS_RESTRICT`** quando vengono eseguiti e pertanto questa tecnica non funzionerà su di essi.
>
> Puoi verificare se un processo dispone di questo flag con (ottieni [**csops qui**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> quindi verifica se il flag 0x800 è abilitato.

## Riferimenti

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
