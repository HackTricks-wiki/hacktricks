# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Quick Look είναι το macOS's **file preview framework**. Όταν ένας χρήστης επιλέγει ένα αρχείο στο Finder, πατάει Space, αιωρεί τον δείκτη πάνω του, ή προβάλλει έναν κατάλογο με ενεργοποιημένες μικρογραφίες, το Quick Look **φορτώνει αυτόματα ένα generator plugin** για να αναλύσει το αρχείο και να αποδώσει μια οπτική προεπισκόπηση.

Τα Quick Look generators είναι **bundles** (`.qlgenerator`) που εγγράφονται για συγκεκριμένα **Uniform Type Identifiers (UTIs)**. Όταν το macOS χρειάζεται προεπισκόπηση για ένα αρχείο που ταιριάζει σε αυτό το UTI, φορτώνει τον generator σε μια sandboxed βοηθητική διεργασία (`QuickLookSatellite` ή `qlmanage`) και καλεί τη λειτουργία του generator.

### Γιατί Αυτό Έχει Σημασία για την Ασφάλεια

> [!WARNING]
> Οι Quick Look generators ενεργοποιούνται με **απλή επιλογή ή προβολή ενός αρχείου** — δεν απαιτείται ενέργεια "Open". Αυτό τα καθιστά ένα ισχυρό **παθητικό διάνυσμα εκμετάλλευσης**: ο χρήστης απλώς πρέπει να πλοηγηθεί σε έναν κατάλογο που περιέχει ένα κακόβουλο αρχείο.

**Επιφάνεια επίθεσης:**
- Οι generators **αναλύουν αυθαίρετο περιεχόμενο αρχείων** από το δίσκο, λήψεις, συνημμένα email ή κοινόχρηστους δικτυακούς φακέλους
- Ένα crafted αρχείο μπορεί να εκμεταλλευτεί **ευπάθειες στην ανάλυση** (parsing vulnerabilities) (buffer overflows, format strings, type confusion) στον κώδικα του generator
- Η απόδοση της προεπισκόπησης γίνεται **αυτόματα** — η προβολή ενός φακέλου Downloads όπου έχει προστεθεί ένα κακόβουλο αρχείο είναι αρκετή
- Το Quick Look τρέχει σε μια **sandboxed helper** διεργασία, αλλά έχουν επιδειχθεί διαφυγές από το sandbox σε αυτό το πλαίσιο

## Αρχιτεκτονική
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
## Απογραφή

### Λίστα Εγκατεστημένων Generators
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
### Χρήση του Scanner
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Σενάρια Επιθέσεων

### Εκμετάλλευση μέσω αρχείων

Ένας Quick Look generator τρίτου μέρους που αναλύει πολύπλοκες μορφές αρχείων (3D μοντέλα, επιστημονικά δεδομένα, μορφές αρχειοθέτησης) αποτελεί έναν πρωταρχικό στόχο:
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
### Drive-By μέσω λήψεων
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Αντικατάσταση γεννήτριας τρίτου μέρους

Εάν ένα Quick Look generator bundle είναι εγκατεστημένο σε **τοποθεσία εγγράψιμη από τον χρήστη** (`~/Library/QuickLook/`), μπορεί να αντικατασταθεί:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Προκαλέστε Quick Look απομακρυσμένα
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Παρατηρήσεις για το sandbox

Οι Quick Look generators εκτελούνται μέσα σε μια βοηθητική sandboxed διεργασία. Το προφίλ του sandbox περιορίζει:
- Πρόσβαση στο σύστημα αρχείων (κυρίως μόνο για ανάγνωση στο αρχείο που προβάλλεται)
- Πρόσβαση στο δίκτυο (περιορισμένη)
- IPC (περιορισμένο mach-lookup)

Ωστόσο, το sandbox έχει γνωστές διαδρομές διαφυγής:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVE του πραγματικού κόσμου

| CVE | Περιγραφή |
|---|---|
| CVE-2019-8741 | Quick Look preview memory corruption via crafted file |
| CVE-2018-4293 | Quick Look generator sandbox escape |
| CVE-2020-9963 | Quick Look preview processing information disclosure |
| CVE-2021-30876 | Thumbnail generation memory corruption |

## Fuzzing Quick Look Generators
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
## Αναφορές

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
