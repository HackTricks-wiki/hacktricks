# Quick Look Generators w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Quick Look to **framework podglądu plików** w macOS. Gdy użytkownik zaznaczy plik w Finderze, naciśnie Spację, najedzie na niego kursorem lub wyświetli katalog z włączonymi miniaturami, Quick Look **automatycznie ładuje plugin generatora**, aby przeanalizować plik i wyrenderować wizualny podgląd.<sup>[1]</sup>

Quick Look generators to **bundles** (`.qlgenerator`), które rejestrują się dla określonych **Uniform Type Identifiers (UTIs)**. Gdy macOS potrzebuje podglądu pliku pasującego do danego UTI, ładuje generator do sandboxowanego procesu pomocniczego (`QuickLookSatellite` lub `qlmanage`) i wywołuje jego funkcję generatora.

### Dlaczego ma to znaczenie dla bezpieczeństwa

> [!WARNING]
> Quick Look generators są uruchamiane przez **samo zaznaczenie lub wyświetlenie pliku** — nie jest wymagane działanie „Open”. Dzięki temu stanowią potężny **pasywny wektor exploitation**: użytkownik musi jedynie przejść do katalogu zawierającego złośliwy plik.

**Attack surface:**
- Generators **analizują dowolną zawartość plików** z dysku, downloads, załączników email lub network shares
- Spreparowany plik może wykorzystać **podatności podczas parsowania** (buffer overflows, format strings, type confusion) w kodzie generatora
- Renderowanie podglądu odbywa się **automatycznie** — wystarczy wyświetlić folder Downloads, w którym znalazł się złośliwy plik
- Quick Look działa w **sandboxowanym procesie pomocniczym**, ale udokumentowano sandbox escapes z tego kontekstu

## Architektura
```
User selects file in Finder
↓
Finder → QuickLookSatellite (sandboxed helper)
↓
Generator plugin loaded (.qlgenerator bundle)
↓
Plugin parses file content → Returns preview image/HTML
↓
Preview displayed to user
```
## Enumeracja

### Lista zainstalowanych generatorów
```bash
# List all Quick Look generators with their UTI registrations
qlmanage -m plugins 2>&1

# Find generator bundles on the system
find / -name "*.qlgenerator" -type d 2>/dev/null

# Common locations
ls /Library/QuickLook/
ls ~/Library/QuickLook/
ls /System/Library/QuickLook/

# Check a generator's Info.plist for UTI registrations
defaults read /path/to/Generator.qlgenerator/Contents/Info.plist 2>/dev/null
```
### Korzystanie ze skanera
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Scenariusze ataku

### Eksploatacja oparta na plikach

Quick Look generator firmy zewnętrznej, który parsuje złożone formaty plików (modele 3D, dane naukowe, formaty archiwów), jest idealnym celem:
```bash
# 1. Identify a third-party generator and its UTI
qlmanage -m plugins 2>&1 | grep -v "com.apple" | head -20

# 2. Find what file types it handles
defaults read /Library/QuickLook/SomeGenerator.qlgenerator/Contents/Info.plist \
CFBundleDocumentTypes 2>/dev/null

# 3. Craft a malicious file matching that UTI
# (fuzzer output or hand-crafted malformed file)

# 4. Place the file where the user will preview it
cp malicious.xyz ~/Downloads/

# 5. When user opens Downloads in Finder → preview triggers → exploit fires
```
### Drive-By przez Downloads
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Podmiana generatora innej firmy

Jeśli pakiet generatora Quick Look jest zainstalowany w **lokalizacji zapisywalnej przez użytkownika** (`~/Library/QuickLook/`), można go podmienić:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Zdalne wyzwalanie Quick Look
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Kwestie dotyczące sandboxa

Quick Look generators działają wewnątrz procesu pomocniczego objętego sandboxem. Profil sandboxa ogranicza:
- Dostęp do systemu plików (w większości tylko do odczytu pliku będącego podglądem)
- Dostęp do sieci (ograniczony)
- IPC (ograniczone `mach-lookup`)

Jednak sandbox ma znane wektory ucieczki:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## Rzeczywiste CVE

| CVE | Opis |
|---|---|
| CVE-2019-8741 | Uszkodzenie pamięci podglądu Quick Look za pomocą spreparowanego pliku |
| CVE-2018-4293 | Ucieczka z sandboxa generatora Quick Look |
| CVE-2020-9963 | Ujawnienie informacji podczas przetwarzania podglądu Quick Look |
| CVE-2021-30876 | Uszkodzenie pamięci podczas generowania miniatur |

## Fuzzing generatorów Quick Look
```bash
# Basic fuzzing approach for a Quick Look generator:

# 1. Identify the target generator and its file format
qlmanage -m plugins 2>&1 | grep "target-uti"

# 2. Collect seed corpus of valid files
find / -name "*.targetext" -size -1M 2>/dev/null | head -100

# 3. Mutate files and trigger preview
for f in /tmp/fuzz_corpus/*; do
# Mutate the file (using radamsa, honggfuzz, etc.)
radamsa "$f" > /tmp/fuzz_input.targetext

# Trigger Quick Look (with timeout to catch hangs)
timeout 5 qlmanage -t /tmp/fuzz_input.targetext 2>&1

# Check if QuickLookSatellite crashed
log show --last 5s --predicate 'process == "QuickLookSatellite" AND eventMessage CONTAINS "crash"' 2>/dev/null
done
```
## Odnośniki

- [1] [Apple Developer — Przewodnik programowania Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple Security Updates — CVE dotyczące Quick Look](https://support.apple.com/en-us/HT201222)
- [3] [Objective-See — Powierzchnia ataku Quick Look](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
