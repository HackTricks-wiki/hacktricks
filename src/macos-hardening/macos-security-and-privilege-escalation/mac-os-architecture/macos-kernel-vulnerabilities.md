# Ευπάθειες Kernel του macOS

{{#include ../../../banners/hacktricks-training.md}}

Η πρόσφατη εκμετάλλευση του kernel του macOS αφορά λιγότερο το «φόρτωσε ένα trivial unsigned kext και απέκτησε ring-0» και περισσότερο την κατάχρηση **Mach/MIG parsers**, **IOKit user clients**, **data-only races μέσα στο XNU** και **specially entitled daemons**, οι οποίοι μπορούν ακόμη να ανοίξουν ξανά attack surface στον kernel. Για το reversing των συγκεκριμένων interfaces, δείτε επίσης τις σελίδες σχετικά με [**IOKit**](macos-iokit.md) και [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces που εξακολουθούν να έχουν σημασία

- **Mach/MIG handlers** σε system daemons και υπηρεσίες που επικοινωνούν με τον kernel: malformed descriptors, out-of-line (OOL) data και stateful multi-message flows.
- **IOKit user clients**: selector-specific parsing, entitlement-gated methods και wrapper libraries/daemons που αποκρύπτουν το πραγματικό call graph.
- **XNU data-only primitives**: races γύρω από credentials, SMR-protected pointers, read-only zones και άλλα σημεία όπου η corruption αλλάζει την policy χωρίς να απαιτείται πρώτα ο έλεγχος του RIP/PC.
- **Third-party / auxiliary kernel code**: τα legacy kexts είναι σπανιότερα, αλλά τα enterprise fleets, τα reduced-security συστήματα Apple Silicon και τα vendor `.fs` / helper bundles εξακολουθούν να δημιουργούν paths υψηλής αξίας, γειτονικά στον kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Στην [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) συνδυάζονται αρκετά bugs του OTA/update-chain για την επίτευξη kernel compromise μέσω κατάχρησης του software update pipeline και δυνατοτήτων που σχετίζονται με το rootless.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Τα [**March 2024 macOS security releases**](https://support.apple.com/en-us/120895) της Apple διόρθωσαν δύο issues που είχαν **actively exploited**:

- **CVE-2024-23225 – Kernel**: ένα memory-corruption bug όπου ένας attacker με arbitrary kernel read/write μπορούσε να παρακάμψει τα kernel memory protections.
- **CVE-2024-23296 – RTKit**: ένα δεύτερο memory-corruption bug με την ίδια public impact statement.

Οι public root-cause details παραμένουν περιορισμένες, αλλά το ζεύγος αποτελεί καλή υπενθύμιση ότι τα σύγχρονα Apple exploit chains συχνά απαιτούν **περισσότερα από «απλώς» kernel R/W**: το post-exploitation work ενάντια σε memory protections, σε coprocessor-adjacent code ή σε secondary trust boundaries είναι συχνά το σημείο όπου σταθεροποιείται το πραγματικό chain.

Γρήγορο patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Το [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) του Joseph Ravichandran αποτελεί μια πολύ καλή σύγχρονη μελέτη περίπτωσης του XNU, επειδή **δεν** πρόκειται για κλασικό buffer overflow:

- Το `proc_ro.p_ucred` είναι ένας **SMR-protected pointer** αποθηκευμένος σε ένα **read-only** αντικείμενο `proc_ro`.
- Οι writers πρέπει να ενημερώνουν αυτόν τον pointer **ατομικά**.
- Η `kauth_cred_proc_update()` χρησιμοποιούσε το `zalloc_ro_mut(...)` για να τροποποιήσει το `p_ucred`. Στο x86_64, αυτή η διαδρομή καταλήγει τελικά στα `memcpy` / `rep movsb`, επομένως ένας ταυτόχρονος reader μπορεί να παρατηρήσει έναν **torn pointer**.
- Το bug μετατρέπεται σε **data-only privilege escalation**: αν ο corrupted credential pointer επιλύεται σε ένα διαφορετικό έγκυρο credential object, το τρέχον thread μπορεί να κληρονομήσει πιο privileged state χωρίς να χρειαστεί πρώτα να πετύχει ένα προφανές control-flow hijack.

Ελάχιστο trigger pattern:
```c
// writer thread: force frequent credential swaps
while (1) {
setgid(real_gid);
setgid(saved_or_effective_gid);
}

// reader thread: repeatedly dereference current credentials
while (1) {
(void)getgid();
}
```
Χρήσιμη heuristic για audit: κάθε φορά που ένα kernel path συνδυάζει **SMR readers**, **read-only zone mutation** και **credential ή task metadata**, επαληθεύστε ότι οι ενημερώσεις χρησιμοποιούν τις atomic παραλλαγές `zalloc_ro_mut_*` αντί για copy-based helpers.

---

## 2024-2025: SIP bypass που ανοίγει ξανά kernel loading paths (CVE-2024-44243)

Η Microsoft έδειξε ότι το `storagekitd` μπορούσε να γίνει αντικείμενο abuse για **bypass του SIP** και στη συνέχεια να καταστήσει ξανά relevant τον κώδικα kernel τρίτων κατασκευαστών σε μηχανήματα που διαφορετικά θα φαίνονταν ως "post-kext". Η βασική ιδέα είναι:

1. Απόθεση ή overwrite ενός κακόβουλου `.fs` bundle στο `/Library/Filesystems`.
2. Ενεργοποίηση του `storagekitd` μέσω του Disk Utility ή του `diskutil`.
3. Εκτέλεση των executables του bundle από το daemon με τα ειδικά entitlements **χωρίς σωστή αφαίρεση privileges / επικύρωση του path**.
4. Χρήση του SIP bypass που προκύπτει για τροποποίηση προστατευμένης κατάστασης του file system και, στην επίδειξη της Microsoft, override της λίστας αποκλεισμού kernel extensions.

Για τους kernel researchers, το σημαντικό συμπέρασμα είναι ότι **το kernel attack surface μπορεί να επανεισαχθεί από userland management daemons**, ακόμη και όταν η απευθείας φόρτωση kexts τρίτων κατασκευαστών είναι αυστηρά περιορισμένη.

Χρήσιμο triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing και workflow έρευνας

Αν αναζητάτε ενεργά αυτή την κατηγορία bugs, η πρόσφατη δημόσια έρευνα δείχνει προς την ίδια κατεύθυνση:

- Το [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) παραμένει μία από τις καλύτερες αναφορές για kernel research στην εποχή του Apple Silicon. Χρησιμοποιεί **static binary rewriting** για να ανακτήσει coverage, απενεργοποιεί διαδρομές που απαιτούν **entitlement** κατά τη διάρκεια των δοκιμών και συμπεραίνει τη δομή των interfaces από userspace wrappers.
- Το Project Zero, στο [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html), παρουσιάζει ένα ιδιαίτερα πρακτικό workflow για το **rebasing ενός kext / fileset σε userspace**, ώστε ο parser-heavy κώδικας να μπορεί να υποβληθεί σε fuzzing με πολύ μεγαλύτερη ταχύτητα πριν από την αναπαραγωγή του on-device.
- Για targets που βασίζονται έντονα στο Mach, δημιουργήστε harnesses γύρω από **real message layouts και multi-call state machines**, όχι μόνο γύρω από single selector blobs. Πρόσφατη έρευνα του Project Zero πάνω σε CoreAudio/Mach και conference talks όπως το **Fuzzing at Mach Speed** δείχνουν γιατί οι stateful message sequences εξακολουθούν να αποδίδουν.

Γρήγορες local εντολές που θα χρησιμοποιείτε πραγματικά συχνά:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Γρήγορο Enumeration Cheatsheet
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## Αναφορές

* Joseph Ravichandran. «TRAVERTINE: CVE-2025-24118.» https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. «Ανάλυση του CVE-2024-44243, ενός macOS System Integrity Protection bypass μέσω kernel extensions.» https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
