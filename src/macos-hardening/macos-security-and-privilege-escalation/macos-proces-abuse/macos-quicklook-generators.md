# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Quick Look to macOSowy **framework do podglądu plików**. Gdy użytkownik wybierze plik w Finderze, naciśnie Space, najedzie na niego kursorem lub przegląda katalog z włączonymi miniaturami, Quick Look **automatycznie ładuje wtyczkę generatora** do parsowania pliku i wygenerowania wizualnego podglądu.

Quick Look generators są **bundlami** (`.qlgenerator`), które rejestrują się dla konkretnych **Uniform Type Identifiers (UTIs)**. Gdy macOS potrzebuje podglądu pliku pasującego do tej UTI, ładuje generator do odizolowanego procesu pomocniczego sandbox (`QuickLookSatellite` lub `qlmanage`) i wywołuje jego funkcję generatora.

### Why This Matters for Security

> [!WARNING]
> Quick Look generators są wywoływane przez **po prostu wybranie lub obejrzenie pliku** — nie jest wymagana żadna akcja "Open". To czyni je potężnym **passive exploitation vector**: użytkownik musi jedynie przejść do katalogu zawierającego złośliwy plik.

**Attack surface:**
- Generatory **parsują dowolną zawartość pliku** z dysku, Downloads, załączników e-mail lub udziałów sieciowych
- Spreparowany plik może wykorzystać **parsing vulnerabilities** (buffer overflows, format strings, type confusion) w kodzie generatora
- Renderowanie podglądu dzieje się **automatycznie** — wystarczy obejrzenie katalogu Downloads, w którym znalazł się złośliwy plik
- Quick Look działa w **sandboxed helper**, jednak wykazano przypadki sandbox escapes z tego kontekstu

## Architecture
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
### Używanie skanera
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

Zewnętrzny generator Quick Look, który parsuje złożone formaty plików (modele 3D, dane naukowe, formaty archiwów), jest idealnym celem:
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
### Drive-By via Downloads
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Zastąpienie generatora firm trzecich

Jeśli pakiet generatora Quick Look jest zainstalowany w **lokalizacji zapisywalnej przez użytkownika** (`~/Library/QuickLook/`), można go zastąpić:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Wywołaj Quick Look zdalnie
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Uwagi dotyczące sandboxu

Generatory Quick Look działają wewnątrz sandboxowanego procesu pomocniczego. Profil sandboxu ogranicza:
- Dostęp do systemu plików (głównie dostęp tylko do odczytu do podglądanego pliku)
- Dostęp do sieci (ograniczony)
- IPC (ograniczone mach-lookup)

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
| CVE-2019-8741 | Quick Look preview memory corruption przez spreparowany plik |
| CVE-2018-4293 | Quick Look generator sandbox escape |
| CVE-2020-9963 | information disclosure podczas przetwarzania podglądu Quick Look |
| CVE-2021-30876 | generowanie miniatur memory corruption |

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
## Źródła

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
