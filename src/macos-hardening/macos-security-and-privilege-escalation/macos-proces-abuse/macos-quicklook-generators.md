# Generatori Quick Look di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

Quick Look è il **framework di anteprima dei file** di macOS. Quando un utente seleziona un file in Finder, preme Space, ci passa sopra con il cursore o visualizza una directory con le miniature abilitate, Quick Look **carica automaticamente un plugin generator** per analizzare il file e renderizzare un'anteprima visiva.

I generatori Quick Look sono **bundle** (`.qlgenerator`) che si registrano per specifici **Uniform Type Identifiers (UTIs)**. Quando macOS ha bisogno di un'anteprima per un file che corrisponde a quell'UTI, carica il generator nel processo helper sandboxed (`QuickLookSatellite` o `qlmanage`) e chiama la sua funzione generator.

### Perché questo è importante per la sicurezza

> [!WARNING]
> I generatori Quick Look vengono attivati **semplicemente selezionando o visualizzando un file** — non è richiesta un'azione "Open". Questo li rende un potente **vettore di sfruttamento passivo**: l'utente deve solo navigare in una directory che contiene un file malevolo.

**Superficie d'attacco:**
- I generatori **analizzano contenuti di file arbitrari** da disco, downloads, allegati email o condivisioni di rete
- Un file appositamente costruito può sfruttare **vulnerabilità di parsing** (buffer overflows, format strings, type confusion) nel codice del generatore
- Il rendering dell'anteprima avviene **automaticamente** — è sufficiente visualizzare la cartella Downloads dove un file malevolo è stato posizionato
- Quick Look viene eseguito in un **helper sandboxed**, ma sono state dimostrate escape dalla sandbox in questo contesto

## Architettura
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
## Enumerazione

### Elenco dei generatori installati
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
### Uso dello scanner
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Scenari di attacco

### File-Based Exploitation

Un Quick Look generator di terze parti che esegue il parsing di formati di file complessi (modelli 3D, dati scientifici, formati di archivio) è un obiettivo primario:
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
### Drive-By tramite download
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Sostituzione di generatori di terze parti

Se un Quick Look generator bundle è installato in una **posizione scrivibile dall'utente** (`~/Library/QuickLook/`), può essere sostituito:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Attivare Quick Look da remoto
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Considerazioni sulla sandbox

I generatori di Quick Look vengono eseguiti all'interno di un processo helper in sandbox. Il profilo della sandbox limita:
- Accesso al file system (principalmente in sola lettura sul file in anteprima)
- Accesso di rete (ristretto)
- IPC (mach-lookup limitato)

Tuttavia, la sandbox presenta vettori di escape noti:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVE reali

| CVE | Description |
|---|---|
| CVE-2019-8741 | Quick Look preview memory corruption tramite file appositamente creato |
| CVE-2018-4293 | Quick Look generator sandbox escape |
| CVE-2020-9963 | Quick Look preview processing information disclosure |
| CVE-2021-30876 | Thumbnail generation memory corruption |

## Fuzzing dei Quick Look Generators
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
## Riferimenti

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
