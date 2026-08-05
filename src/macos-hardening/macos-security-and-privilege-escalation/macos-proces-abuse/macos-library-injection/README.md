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

È simile a [**LD_PRELOAD su Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Consente di indicare a un processo che sta per essere eseguito di caricare una libreria specifica da un path (se la env var è abilitata)

Questa tecnica può essere anche **usata come tecnica ASEP**, poiché ogni applicazione installata ha un plist chiamato "Info.plist" che consente di **assegnare environmental variables** usando una chiave chiamata `LSEnvironmental`.

> [!TIP]
> Dal 2012 **Apple ha drasticamente ridotto il potere** di **`DYLD_INSERT_LIBRARIES`**. Un processo è considerato **restricted** — e quindi `dyld` elimina ogni variabile `DYLD_*` dal suo environment — quando vale una qualsiasi delle seguenti condizioni:
>
> - Il binary è `setuid/setgid`
> - Il Mach-O ha una sezione **`__RESTRICT/__restrict`**
> - Il binary è firmato con l'hardened runtime e AMFI non gli concede i permessi "path/print variables", ovvero manca [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Controlla gli **entitlements** di un binary con: `codesign -dv --entitlements :- </path/to/bin>`
>
> Nell'attuale `dyld` questo non viene più deciso solo da `dyld`: `ProcessConfig::Security::Security()` interroga **AMFI** tramite `amfi_check_dyld_policy_self()` e quindi chiama `pruneEnvVars()`. Il codice esatto è illustrato in [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) qui sotto.

### Library Validation

Anche se il binary consente di usare la env var **`DYLD_INSERT_LIBRARIES`**, se il binary controlla la signature della libreria da caricare, non caricherà una custom library.

Per caricare una custom library, il binary deve avere **uno dei seguenti entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

oppure il binary **non deve** avere il **hardened runtime flag** o il **library validation flag**.

Puoi verificare se un binary ha l'**hardened runtime** con `codesign --display --verbose <bin>`, controllando il runtime flag in **`CodeDirectory`**, ad esempio: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Puoi anche caricare una libreria se è **firmata con lo stesso certificato del binary**.

Trovi un esempio su come effettuare (ab)use di questa tecnica e verificare le restrizioni in:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Ricorda che le **precedenti restrizioni di Library Validation si applicano anche** per eseguire attacchi di Dylib hijacking.

Come su Windows, anche su MacOS puoi fare **hijack delle dylib** per fare in modo che le **applicazioni** **eseguano** **codice** **arbitrary** (in realtà, da un utente regular questo potrebbe non essere possibile, poiché potrebbe essere necessario un permesso TCC per scrivere all'interno di un bundle `.app` e fare hijack di una libreria).\
Tuttavia, il modo in cui le applicazioni **MacOS** **caricano** le librerie è **più restricted** rispetto a Windows. Ciò implica che gli sviluppatori di **malware** possono comunque usare questa tecnica per lo **stealth**, ma la probabilità di poterla **abusare per fare privilege escalation è molto più bassa**.

Innanzitutto, è **più comune** trovare binary **MacOS** che indicano il full path delle librerie da caricare. Inoltre, **MacOS non cerca mai** nelle cartelle del **$PATH** le librerie.

La parte **principale** del **code** relativa a questa funzionalità si trova in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Esistono **4 diversi header Commands** che un binary macho può usare per caricare librerie:

- Il comando **`LC_LOAD_DYLIB`** è il comando comune per caricare una dylib.
- Il comando **`LC_LOAD_WEAK_DYLIB`** funziona come quello precedente, ma se la dylib non viene trovata, l'esecuzione continua senza errori.
- Il comando **`LC_REEXPORT_DYLIB`** fa da proxy (o re-esporta) per i symbols di una libreria diversa.
- Il comando **`LC_LOAD_UPWARD_DYLIB`** viene usato quando due librerie dipendono l'una dall'altra (questa è chiamata _upward dependency_).

Tuttavia, esistono **2 tipi di Dylib hijacking**:

- **Missing weak linked libraries**: significa che l'applicazione proverà a caricare una libreria inesistente configurata con **LC_LOAD_WEAK_DYLIB**. Quindi, **se un attacker posiziona una dylib dove previsto, questa verrà caricata**.
- Il fatto che il link sia "weak" significa che l'applicazione continuerà a funzionare anche se la libreria non viene trovata.
- Il **code correlato** si trova nella funzione `ImageLoaderMachO::doGetDependentLibraries` di `ImageLoaderMachO.cpp`, dove `lib->required` è `false` solo quando `LC_LOAD_WEAK_DYLIB` è true.
- **Trova le weak linked libraries** nei binary con (di seguito è riportato un esempio su come creare librerie per il hijacking):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configurate con @rpath**: i binary Mach-O possono avere i comandi **`LC_RPATH`** e **`LC_LOAD_DYLIB`**. In base ai **values** di questi comandi, le **librerie** verranno **caricate** da **directory diverse**.
- **`LC_RPATH`** contiene i path di alcune cartelle usate dal binary per caricare le librerie.
- **`LC_LOAD_DYLIB`** contiene il path delle librerie specifiche da caricare. Questi path possono contenere **`@rpath`**, che verrà **sostituito** dai values presenti in **`LC_RPATH`**. Se in **`LC_RPATH`** sono presenti diversi path, tutti verranno usati per cercare la libreria da caricare. Esempio:
- Se **`LC_LOAD_DYLIB`** contiene `@rpath/library.dylib` e **`LC_RPATH`** contiene `/application/app.app/Contents/Framework/v1/` e `/application/app.app/Contents/Framework/v2/`, entrambe le cartelle verranno usate per caricare `library.dylib`**.** Se la libreria non esiste in `[...]/v1/` e un attacker potesse posizionarla lì, potrebbe fare hijack del caricamento della libreria in `[...]/v2/`, poiché viene rispettato l'ordine dei path in **`LC_LOAD_DYLIB`**.
- **Trova i rpath path e le librerie** nei binary con: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: è il **path** della directory contenente il **main executable file**.
>
> **`@loader_path`**: è il **path** della **directory** contenente il **Mach-O binary** che include il load command.
>
> - Quando viene usato in un executable, **`@loader_path`** è di fatto uguale a **`@executable_path`**.
> - Quando viene usato in una **dylib**, **`@loader_path`** indica il **path** della **dylib**.

Il modo per fare **privilege escalation** abusando di questa funzionalità si verificherebbe nel raro caso in cui un'**applicazione** eseguita da **root** stia **cercando** una **libreria in una cartella in cui l'attacker dispone di permessi di scrittura**.

> [!TIP]
> Un buon **scanner** per trovare **missing libraries** nelle applicazioni è [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) oppure una [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Un buon **report con technical details** su questa tecnica è disponibile [**qui**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Ricorda che le **precedenti restrizioni di Library Validation si applicano anche** per eseguire attacchi di Dlopen hijacking.

Da **`man dlopen`**:

- Quando il path **non contiene uno slash** (ovvero è solo un leaf name), **dlopen() effettuerà una ricerca**. Se **`$DYLD_LIBRARY_PATH`** era impostato al launch, dyld cercherà prima in quella director**y**. Poi, se il file mach-o chiamante o il main executable specificano un **`LC_RPATH`**, dyld cercherà in quelle directory. Successivamente, se il processo è **unrestricted**, dyld cercherà nella current working directory. Infine, per i binary più vecchi, dyld proverà alcuni fallback. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** era impostato al launch, dyld cercherà in **quelle directory**, altrimenti cercherà in **`/usr/local/lib/`** (se il processo è unrestricted) e poi in **`/usr/lib/`** (queste informazioni sono tratte da **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Se il nome non contiene slash, esistono 2 modi per effettuare un hijacking:
>
> - Se un **`LC_RPATH`** è **writable** (ma la signature viene controllata, quindi in questo caso è anche necessario che il binary sia unrestricted)
> - Se il binary è **unrestricted**, rendendo possibile caricare qualcosa dalla CWD (oppure abusare di una delle env vars menzionate)

- Quando il path **ha l'aspetto di un** framework path (ad esempio `/stuff/foo.framework/foo`), se **`$DYLD_FRAMEWORK_PATH`** era impostato al launch, dyld cercherà prima in quella directory il **partial path del framework** (ad esempio `foo.framework/foo`). Poi, dyld proverà il path fornito così com'è (usando la current working directory per i path relativi). Infine, per i binary più vecchi, dyld proverà alcuni fallback. Se **`$DYLD_FALLBACK_FRAMEWORK_PATH`** era impostato al launch, dyld cercherà in quelle directory. Altrimenti, cercherà in **`/Library/Frameworks`** (su macOS se il processo è unrestricted) e poi in **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Se si tratta di un framework path, il modo per effettuare l'hijack sarebbe:
>
> - Se il processo è **unrestricted**, abusare del **relative path dalla CWD** o delle env vars menzionate (anche se non è indicato nella documentazione, se il processo è restricted le env vars DYLD\_\* vengono rimosse)

- Quando il path **contiene uno slash ma non è un framework path** (ovvero un full path o un partial path verso una dylib), dlopen() cerca prima (se impostato) in **`$DYLD_LIBRARY_PATH`** (usando la leaf part del path). Poi, dyld **prova il path fornito** (usando la current working directory per i path relativi (ma solo per i processi unrestricted)). Infine, per i binary più vecchi, dyld proverà alcuni fallback. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** era impostato al launch, dyld cercherà in quelle directory, altrimenti cercherà in **`/usr/local/lib/`** (se il processo è unrestricted) e poi in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Se il nome contiene slash e non è un framework, il modo per effettuare l'hijack sarebbe:
>
> - Se il binary è **unrestricted**, rendendo possibile caricare qualcosa dalla CWD o da `/usr/local/lib` (oppure abusare di una delle env vars menzionate)

> [!TIP]
> Nota: non esistono file di configurazione per **controllare la ricerca di dlopen**.
>
> Nota: se il main executable è un binary `set\[ug]id` o è codesigned con entitlements, tutte le env vars vengono ignorate e può essere usato solo un full path ([controlla le restrizioni di DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) per informazioni più dettagliate)
>
> Nota: le piattaforme Apple usano file "universal" per combinare librerie a 32-bit e 64-bit. Ciò significa che non esistono search path separati per 32-bit e 64-bit.
>
> Nota: sulle piattaforme Apple, la maggior parte delle dylib del sistema operativo è **combined nel dyld cache** e non esiste su disco. Pertanto, chiamare **`stat()`** per verificare in anticipo se una dylib del sistema operativo esiste **non funzionerà**. Tuttavia, **`dlopen_preflight()`** usa gli stessi passaggi di **`dlopen()`** per trovare un file mach-o compatibile.

**Check paths**

Verifichiamo tutte le opzioni con il seguente code:
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

If a **privileged binary/app** (like a SUID or some binary with powerful entitlements) is **loading a relative path** library (for example using `@executable_path` or `@loader_path`) and has **Library Validation disabled**, it could be possible to move the binary to a location where the attacker could **modify the relative path loaded library**, and abuse it to inject code on the process.

## Prune `DYLD_*` env variables

Older `dyld` releases (`dyld2.cpp`) decided this in-process with `issetugid()`, `hasRestrictedSegment()` and `csops(CS_OPS_STATUS)`. In **current `dyld` the decision is delegated to AMFI**, and the code lives in `ProcessConfig::Security::Security()` in `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
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
Due elementi meritano di essere estratti da questo:

- Il pruning avviene solo su **macOS / Mac Catalyst / DriverKit** — e solo quando AMFI non ha concesso nessuno tra `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- La query AMFI utilizza le proprietà dell'eseguibile stesso:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
dove `isRestricted()` è letteralmente il controllo del segmento `__RESTRICT` (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` rimuove quindi **ogni** variabile il cui nome inizia con `DYLD_` e fa scorrere verso il basso i parametri `apple[]`, così anche i processi figli di un processo con restrizioni non li ereditano:
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
> Conseguenza pratica: **`DYLD_*` viene rimosso quando il processo è soggetto a restrizioni** — setuid/setgid, una sezione `__RESTRICT/__restrict` oppure binari con hardened-runtime/entitlements a cui AMFI rifiuta di concedere i flag path/print. Se invece il processo dispone solo di **library validation** (`CS_REQUIRE_LV`), le variabili restano disponibili, ma la dylib inserita deve essere firmata dallo **stesso Team ID** (o da Apple), quindi è necessario uno degli entitlements che disabilitano la library validation affinché il codice venga effettivamente eseguito.

Poiché ora la decisione spetta ad AMFI, il modo più rapido per sapere cosa otterrà un determinato binario consiste nel verificare su cosa si basa AMFI — entitlements e signing flags — invece di esaminare direttamente `dyld`:
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
### Runtime hardened

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
> Nota che anche se esistono binary firmati con i flag **`0x0(none)`**, possono ottenere dinamicamente il flag **`CS_RESTRICT`** quando vengono eseguiti e pertanto questa tecnica non funzionerà su di essi.
>
> Puoi verificare se un proc presenta questo flag con (trovi [**csops qui**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> quindi verifica se il flag 0x800 è abilitato.

## Riferimenti

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (controllo `isRestricted()` / `__RESTRICT`)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (avvio del processo e inserimento delle librerie)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
