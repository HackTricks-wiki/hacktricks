# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το Quick Look είναι το **framework προεπισκόπησης αρχείων** του macOS. Όταν ένας χρήστης επιλέγει ένα αρχείο στο Finder, πατά Space, τοποθετεί τον δείκτη πάνω του ή προβάλλει έναν κατάλογο με ενεργοποιημένες τις μικρογραφίες, το Quick Look **φορτώνει αυτόματα ένα generator plugin** για την ανάλυση του αρχείου και την απόδοση μιας οπτικής προεπισκόπησης.<sup>[[1]](#references)</sup>

Τα Quick Look generators είναι **bundles** (`.qlgenerator`) που κάνουν register για συγκεκριμένα **Uniform Type Identifiers (UTIs)**. Όταν το macOS χρειάζεται προεπισκόπηση για ένα αρχείο που αντιστοιχεί σε αυτό το UTI, φορτώνει το generator σε μια βοηθητική διαδικασία που εκτελείται σε sandbox (`QuickLookSatellite` ή `qlmanage`) και καλεί τη συνάρτηση του generator.

### Γιατί έχει σημασία για την ασφάλεια

> [!WARNING]
> Τα Quick Look generators ενεργοποιούνται με **την απλή επιλογή ή προβολή ενός αρχείου** — δεν απαιτείται ενέργεια "Open". Αυτό τα καθιστά ένα ισχυρό **passive exploitation vector**: ο χρήστης χρειάζεται απλώς να περιηγηθεί σε έναν κατάλογο που περιέχει ένα κακόβουλο αρχείο.

**Attack surface:**
- Τα generators **αναλύουν αυθαίρετο περιεχόμενο αρχείων** από τον δίσκο, downloads, συνημμένα email ή network shares
- Ένα ειδικά διαμορφωμένο αρχείο μπορεί να εκμεταλλευτεί **parsing vulnerabilities** (buffer overflows, format strings, type confusion) στον κώδικα του generator
- Η απόδοση της προεπισκόπησης πραγματοποιείται **αυτόματα** — αρκεί η προβολή ενός φακέλου Downloads στον οποίο έχει καταλήξει ένα κακόβουλο αρχείο
- Το Quick Look εκτελείται σε έναν **sandboxed helper**, όμως έχουν καταδειχθεί sandbox escapes από αυτό το context

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
## Απαρίθμηση

### Λίστα εγκατεστημένων Generators
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
## Σενάρια Επίθεσης

### Εκμετάλλευση μέσω Αρχείων

Ένας third-party Quick Look generator που αναλύει σύνθετες μορφές αρχείων (3D models, επιστημονικά δεδομένα, μορφές αρχειοθέτησης) αποτελεί κύριο στόχο:
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
### Drive-By μέσω Λήψεων
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Αντικατάσταση generator τρίτων

Εάν ένα bundle generator του Quick Look είναι εγκατεστημένο σε **τοποθεσία εγγράψιμη από τον χρήστη** (`~/Library/QuickLook/`), μπορεί να αντικατασταθεί:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Απομακρυσμένη ενεργοποίηση του Quick Look
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Ζητήματα Sandbox

Οι Quick Look generators εκτελούνται μέσα σε μια helper process που βρίσκεται σε sandbox. Το sandbox profile περιορίζει:
- Πρόσβαση στο file system (κυρίως μόνο για ανάγνωση του file που γίνεται preview)
- Πρόσβαση στο network (περιορισμένη)
- IPC (περιορισμένο mach-lookup)

Ωστόσο, το sandbox έχει γνωστά escape vectors:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVE σε πραγματικές συνθήκες<sup>[[2]](#references)</sup>

| CVE | Περιγραφή |
|---|---|
| CVE-2019-8741 | Καταστροφή μνήμης στην προεπισκόπηση Quick Look μέσω ειδικά διαμορφωμένου αρχείου |
| CVE-2018-4293 | Διαφυγή από το sandbox του Quick Look generator |
| CVE-2020-9963 | Αποκάλυψη πληροφοριών κατά την επεξεργασία προεπισκόπησης Quick Look |
| CVE-2021-30876 | Καταστροφή μνήμης κατά τη δημιουργία thumbnail |

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
## References

- [1] [Apple Developer — Οδηγός προγραμματισμού του Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
{{#include ../../../banners/hacktricks-training.md}}
