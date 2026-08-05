# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Il codice di **dyld è open source** e può essere trovato in [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) e può essere scaricato come tar usando un **URL come** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Processo Dyld**

Dai un'occhiata a come Dyld carica le librerie all'interno dei binari in:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

È simile a [**LD_PRELOAD su Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Permette di indicare a un processo che sta per essere eseguito di caricare una libreria specifica da un percorso (se la env var è abilitata).

Questa tecnica può essere anche **usata come tecnica ASEP**, poiché ogni applicazione installata ha un plist chiamato "Info.plist" che consente di **assegnare variabili d'ambiente** usando una chiave chiamata `LSEnvironmental`.

> [!TIP]
> Dal 2012 **Apple ha ridotto drasticamente il potere** di **`DYLD_INSERT_LIBRARIES`**. Un processo è considerato **restricted** — e quindi `dyld` elimina ogni variabile `DYLD_*` dal suo ambiente — quando una qualsiasi di queste condizioni è soddisfatta:
>
> - Il binario è `setuid/setgid`
> - Il Mach-O contiene una sezione **`__RESTRICT/__restrict`**
> - Il binario è firmato con l'hardened runtime e AMFI non gli concede i permessi "path/print variables", cioè non dispone di [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[3]</sup>
>   - Controlla gli **entitlements** di un binario con: `codesign -dv --entitlements :- </path/to/bin>`
>
> Nelle versioni attuali di `dyld` questa decisione non viene più presa esclusivamente da `dyld`: `ProcessConfig::Security::Security()` interroga **AMFI** tramite `amfi_check_dyld_policy_self()` e poi chiama `pruneEnvVars()`. Il codice esatto è analizzato in [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) qui sotto.

### Library Validation

Anche se il binario consente di usare la env var **`DYLD_INSERT_LIBRARIES`**, se il binario controlla la firma della libreria da caricare, non caricherà una libreria personalizzata.

Per caricare una libreria personalizzata, il binario deve avere **uno dei seguenti entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

oppure il binario **non deve avere** l'**hardened runtime flag** o il **library validation flag**.

Puoi verificare se un binario dispone dell'**hardened runtime** con `codesign --display --verbose <bin>`, controllando il runtime flag in **`CodeDirectory`**, come in: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Puoi anche caricare una libreria se è **firmata con lo stesso certificato del binario**.

Trovi un esempio su come (ab)usare questa tecnica e verificare le restrizioni in:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Ricorda che le **precedenti restrizioni di Library Validation si applicano anche** agli attacchi di Dylib hijacking.

Come in Windows, anche su MacOS puoi **hijackare le dylib** per fare in modo che le **applicazioni** **eseguano** **codice** **arbitrario** (in realtà, da un utente normale questo potrebbe non essere possibile, poiché potrebbe essere necessario un permesso TCC per scrivere all'interno di un bundle `.app` e hijackare una libreria).\
Tuttavia, il modo in cui le applicazioni **MacOS** **caricano** le librerie è **più limitato** rispetto a Windows. Ciò implica che gli sviluppatori di **malware** possono ancora usare questa tecnica per lo **stealth**, ma la probabilità di poterla **abusare per fare privilege escalation è molto più bassa**.

Innanzitutto, è **più comune** trovare binari **MacOS** che indicano il percorso completo delle librerie da caricare. In secondo luogo, **MacOS non cerca mai** le librerie nelle cartelle del **$PATH**.

La parte **principale** del **codice** relativa a questa funzionalità si trova in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Un binario macho può usare **4 diversi header Commands** per caricare le librerie:

- Il comando **`LC_LOAD_DYLIB`** è il comando comune per caricare una dylib.
- Il comando **`LC_LOAD_WEAK_DYLIB`** funziona come quello precedente, ma se la dylib non viene trovata, l'esecuzione continua senza errori.
- Il comando **`LC_REEXPORT_DYLIB`** fa da proxy (o riesporta) per i simboli di una libreria diversa.
- Il comando **`LC_LOAD_UPWARD_DYLIB`** viene usato quando due librerie dipendono l'una dall'altra (questa situazione è chiamata _upward dependency_).

Tuttavia, esistono **2 tipi di Dylib hijacking**:

- **Missing weak linked libraries**: significa che l'applicazione tenterà di caricare una libreria inesistente configurata con **LC_LOAD_WEAK_DYLIB**. Quindi, **se un attacker posiziona una dylib nel percorso previsto, questa verrà caricata**.
- Il fatto che il link sia "weak" significa che l'applicazione continuerà a funzionare anche se la libreria non viene trovata.
- Il **codice relativo** si trova nella funzione `ImageLoaderMachO::doGetDependentLibraries` di `ImageLoaderMachO.cpp`, dove `lib->required` è `false` solo quando `LC_LOAD_WEAK_DYLIB` è true.
- **Trova le librerie weak linked** nei binari con (più avanti trovi un esempio su come creare librerie per il hijacking):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: i binari Mach-O possono contenere i comandi **`LC_RPATH`** e **`LC_LOAD_DYLIB`**. In base ai **valori** di questi comandi, le **librerie** verranno **caricate** da **directory diverse**.
- **`LC_RPATH`** contiene i percorsi di alcune cartelle usate dal binario per caricare le librerie.
- **`LC_LOAD_DYLIB`** contiene il percorso delle librerie specifiche da caricare. Questi percorsi possono contenere **`@rpath`**, che verrà **sostituito** dai valori presenti in **`LC_RPATH`**. Se in **`LC_RPATH`** sono presenti più percorsi, tutti verranno usati per cercare la libreria da caricare. Esempio:
- Se **`LC_LOAD_DYLIB`** contiene `@rpath/library.dylib` e **`LC_RPATH`** contiene `/application/app.app/Contents/Framework/v1/` e `/application/app.app/Contents/Framework/v2/`. Entrambe le cartelle verranno usate per caricare `library.dylib`**.** Se la libreria non esiste in `[...]/v1/` e un attacker può posizionarla lì, può hijackare il caricamento della libreria in `[...]/v2/`, poiché viene seguito l'ordine dei percorsi in **`LC_LOAD_DYLIB`**.
- **Trova i percorsi rpath e le librerie** nei binari con: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: è il **percorso** della directory contenente il **file eseguibile principale**.
>
> **`@loader_path`**: è il **percorso** della **directory** contenente il **binario Mach-O** che include il load command.
>
> - Quando viene usato in un eseguibile, **`@loader_path`** è di fatto uguale a **`@executable_path`**.
> - Quando viene usato in una **dylib**, **`@loader_path`** fornisce il **percorso** della **dylib**.

Il modo per fare **privilege escalation** abusando di questa funzionalità si verifica nel raro caso in cui un'**applicazione** eseguita da **root** cerchi una **libreria in una cartella in cui l'attacker dispone dei permessi di scrittura**.

> [!TIP]
> Un ottimo **scanner** per trovare **librerie mancanti** nelle applicazioni è [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) oppure una [**versione CLI**](https://github.com/pandazheng/DylibHijack).\
> Un ottimo **report con dettagli tecnici** su questa tecnica è disponibile [**qui**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Esempio**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Ricorda che le **precedenti restrizioni di Library Validation si applicano anche** agli attacchi di Dlopen hijacking.

Da **`man dlopen`**:

- Quando il percorso **non contiene un carattere slash** (cioè è solo un leaf name), **dlopen() eseguirà una ricerca**. Se **`$DYLD_LIBRARY_PATH`** era impostata all'avvio, dyld cercherà prima in quella director**y**. Successivamente, se il file mach-o chiamante o l'eseguibile principale specificano un **`LC_RPATH`**, dyld cercherà in quelle directory. Poi, se il processo è **unrestricted**, dyld cercherà nella directory di lavoro corrente. Infine, per i binari obsoleti, dyld proverà alcuni fallback. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** era impostata all'avvio, dyld cercherà in **quelle directory**, altrimenti cercherà in **`/usr/local/lib/`** (se il processo è unrestricted) e poi in **`/usr/lib/`** (questa informazione è stata presa da **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Se nel nome non sono presenti slash, esistono 2 modi per eseguire un hijacking:
>
> - Se un qualsiasi **`LC_RPATH`** è **scrivibile** (ma la firma viene verificata, quindi in questo caso è anche necessario che il binario sia unrestricted)
> - Se il binario è **unrestricted**, è quindi possibile caricare qualcosa dalla CWD (oppure abusare di una delle env var menzionate)

- Quando il percorso **sembra essere** il percorso di un framework (ad es. `/stuff/foo.framework/foo`), se **`$DYLD_FRAMEWORK_PATH`** era impostata all'avvio, dyld cercherà prima in quella directory il **percorso parziale del framework** (ad es. `foo.framework/foo`). Successivamente, dyld proverà il percorso fornito così com'è (usando la directory di lavoro corrente per i percorsi relativi). Infine, per i binari obsoleti, dyld proverà alcuni fallback. Se **`$DYLD_FALLBACK_FRAMEWORK_PATH`** era impostata all'avvio, dyld cercherà in quelle directory. Altrimenti, cercherà in **`/Library/Frameworks`** (su macOS se il processo è unrestricted) e poi in **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Se il percorso è di un framework, il modo per hijackarlo sarebbe:
>
> - Se il processo è **unrestricted**, abusando del **percorso relativo dalla CWD** o delle env var menzionate (anche se non è specificato nella documentazione, se il processo è restricted le env var DYLD\_\* vengono rimosse)

- Quando il percorso **contiene uno slash ma non è il percorso di un framework** (cioè un percorso completo o parziale verso una dylib), dlopen() cerca prima (se impostata) in **`$DYLD_LIBRARY_PATH`** (usando la parte leaf del percorso). Successivamente, dyld **prova il percorso fornito** (usando la directory di lavoro corrente per i percorsi relativi (ma solo per i processi unrestricted)). Infine, per i binari più vecchi, dyld proverà alcuni fallback. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** era impostata all'avvio, dyld cercherà in quelle directory; altrimenti cercherà in **`/usr/local/lib/`** (se il processo è unrestricted) e poi in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Se nel nome sono presenti slash e non si tratta di un framework, il modo per hijackarlo sarebbe:
>
> - Se il binario è **unrestricted**, è quindi possibile caricare qualcosa dalla CWD o da `/usr/local/lib` (oppure abusare di una delle env var menzionate)

> [!TIP]
> Nota: non esistono file di configurazione per **controllare la ricerca di dlopen**.
>
> Nota: se l'eseguibile principale è un binario `set\[ug]id` o è codesigned con entitlements, tutte le variabili d'ambiente vengono ignorate e può essere usato solo un percorso completo ([controlla le restrizioni di DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) per maggiori dettagli).
>
> Nota: le piattaforme Apple usano file "universal" per combinare librerie a 32 e 64 bit. Ciò significa che non esistono percorsi di ricerca separati per 32 e 64 bit.
>
> Nota: sulle piattaforme Apple la maggior parte delle dylib del sistema operativo è combinata nella **dyld cache** e non esiste sul disco. Pertanto, chiamare **`stat()`** per verificare in anticipo se una dylib del sistema operativo esiste **non funzionerà**. Tuttavia, **`dlopen_preflight()`** usa gli stessi passaggi di **`dlopen()`** per trovare un file mach-o compatibile.

**Controlla i percorsi**

Verifichiamo tutte le opzioni con il seguente codice:
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
Se lo compili e lo esegui, puoi vedere **dove è stata cercata senza successo ciascuna libreria**. Inoltre, potresti **filtrare i log del FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Se un **privileged binary/app** (come un SUID o un binario con entitlements potenti) sta **caricando una libreria tramite un percorso relativo** (ad esempio usando `@executable_path` o `@loader_path`) e ha **Library Validation disabilitata**, potrebbe essere possibile spostare il binario in una posizione in cui l'attaccante possa **modificare la libreria caricata tramite il percorso relativo** e sfruttarla per iniettare codice nel processo.

## Eliminazione delle variabili d'ambiente `DYLD_*`

Le versioni precedenti di `dyld` (`dyld2.cpp`) prendevano questa decisione in-process usando `issetugid()`, `hasRestrictedSegment()` e `csops(CS_OPS_STATUS)`. Nell'**attuale `dyld`, la decisione è delegata ad AMFI** e il codice si trova in `ProcessConfig::Security::Security()` in `dyld/DyldProcessConfig.cpp`:<sup>[1]</sup>
```cpp
const uint64_t amfiFlags = getAMFI(process, syscall);
this->allowAtPaths              = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_AT_PATH);
this->allowEnvVarsPrint         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS);
this->allowEnvVarsPath          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS);
this->allowEnvVarsSharedCache   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE);
this->allowClassicFallbackPaths = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS);
this->allowInsertFailures       = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION);
this->allowInterposing          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING);
this->allowEmbeddedVars         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS);
this->allowDevelopmentVars      = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_DEVELOPMENT_VARS);
this->allowLibSystemOverrides   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBSYSTEM_OVERRIDE);
...
// env vars are only pruned on macOS
switch ( process.platform.value() ) {
case PLATFORM_MACOS:
case PLATFORM_IOSMAC:
case PLATFORM_DRIVERKIT:
break;
default:
return;
}

// env vars are only pruned when process is restricted
if ( this->allowEnvVarsPrint || this->allowEnvVarsPath || this->allowEnvVarsSharedCache )
return;

this->pruneEnvVars(process);
```
Due aspetti meritano di essere estratti da questo:

- Il pruning avviene solo su **macOS / Mac Catalyst / DriverKit** e solo quando AMFI non ha concesso nessuno tra `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- La query AMFI riceve le proprietà proprie dell'eseguibile:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
dove `isRestricted()` è letteralmente il controllo del segmento `__RESTRICT` (`mach_o/UnsafeHeader.cpp`):<sup>[2]</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` quindi rimuove **ogni** variabile il cui nome inizia con `DYLD_` e fa scorrere verso il basso i parametri `apple[]`, così anche i processi figli di un processo soggetto a restrizioni non li ereditano:
```cpp
// For security, setuid programs ignore DYLD_* environment variables.
// Additionally, the DYLD_* enviroment variables are removed
// from the environment, so that any child processes doesn't see them.
for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
if ( strncmp(*s, "DYLD_", 5) != 0 ) {
*d++ = *s;
}
...
```
> [!TIP]
> Conseguenza pratica: **`DYLD_*` viene rimosso quando il processo è sottoposto a restrizioni** — setuid/setgid, una sezione `__RESTRICT/__restrict` o binari con hardened-runtime/entitlements a cui AMFI rifiuta di concedere i flag path/print. Se invece il processo dispone solo di **library validation** (`CS_REQUIRE_LV`), le variabili rimangono, ma la dylib inserita deve essere firmata dallo **stesso Team ID** (oppure da Apple); quindi serve uno degli entitlements che disabilitano la library validation affinché il codice venga effettivamente caricato.

Poiché ora la decisione spetta ad AMFI, il modo più rapido per sapere cosa otterrà un determinato binario è verificare i parametri utilizzati da AMFI — entitlements e signing flags — anziché `dyld` stesso:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
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

Crea un nuovo certificato nel Keychain e usalo per firmare il binario:
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
> Nota che, anche se esistono binari firmati con i flag **`0x0(none)`**, possono ottenere dinamicamente il flag **`CS_RESTRICT`** quando vengono eseguiti e pertanto questa tecnica non funzionerà su di essi.
>
> Puoi verificare se un processo ha questo flag con (vedi [**csops qui**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> e quindi verificare se il flag 0x800 è abilitato.

## Riferimenti

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (controllo `isRestricted()` / `__RESTRICT`)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (avvio del processo e inserimento della libreria)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
