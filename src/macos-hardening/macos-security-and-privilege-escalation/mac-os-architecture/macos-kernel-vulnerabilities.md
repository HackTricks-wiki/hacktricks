# Ευπάθειες Kernel του macOS

{{#include ../../../banners/hacktricks-training.md}}

Η πρόσφατη εκμετάλλευση του macOS kernel αφορά λιγότερο το "load ενός trivial unsigned kext και απόκτηση ring-0" και περισσότερο την κατάχρηση **Mach/MIG parsers**, **IOKit user clients**, **data-only races μέσα στο XNU** και **ειδικά entitled daemons** που μπορούν ακόμη να ανοίξουν ξανά attack surface στον kernel. Για την ανάλυση των συγκεκριμένων interfaces, δείτε επίσης τις σελίδες για το [**IOKit**](macos-iokit.md) και τα [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces που εξακολουθούν να έχουν σημασία

- **Mach/MIG handlers** σε system daemons και kernel-facing services: malformed descriptors, out-of-line (OOL) data και stateful multi-message flows.
- **IOKit user clients**: selector-specific parsing, entitlement-gated methods και wrapper libraries/daemons που αποκρύπτουν το πραγματικό call graph.
- **XNU data-only primitives**: races γύρω από credentials, SMR-protected pointers, read-only zones και άλλα σημεία όπου η corruption αλλάζει την policy χωρίς να απαιτείται πρώτα ο έλεγχος του RIP/PC.
- **Third-party / auxiliary kernel code**: τα legacy kexts είναι σπανιότερα, όμως enterprise fleets, reduced-security Apple Silicon systems και vendor `.fs` / helper bundles εξακολουθούν να δημιουργούν paths υψηλής αξίας που σχετίζονται με τον kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Σε [**αυτή την αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) συνδυάζονται αρκετά bugs του OTA/update chain για την επίτευξη compromise του kernel, μέσω κατάχρησης του software update pipeline και δυνατοτήτων που σχετίζονται με το rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild chain παράκαμψης kernel protection (CVE-2024-23225 & CVE-2024-23296)

Τα [**macOS security releases του Μαρτίου 2024**](https://support.apple.com/en-us/120895) της Apple διόρθωσαν δύο issues που ήταν **actively exploited**:<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**: ένα memory-corruption bug όπου ένας attacker με arbitrary kernel read/write μπορούσε να παρακάμψει τις kernel memory protections.
- **CVE-2024-23296 – RTKit**: ένα δεύτερο memory-corruption bug με την ίδια δημόσια δήλωση impact.

Οι public λεπτομέρειες για το root cause παραμένουν περιορισμένες, όμως το ζεύγος αποτελεί καλή υπενθύμιση ότι τα σύγχρονα Apple exploit chains συχνά χρειάζονται **περισσότερα από "απλώς" kernel R/W**: η post-exploitation εργασία ενάντια σε memory protections, coprocessor-adjacent code ή secondary trust boundaries είναι συχνά το σημείο όπου σταθεροποιείται το πραγματικό chain.

Γρήγορο patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Το [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) του Joseph Ravichandran αποτελεί μια πολύ καλή σύγχρονη μελέτη περίπτωσης του XNU, επειδή **δεν** πρόκειται για κλασικό buffer overflow:<sup>[[1]](#references)</sup>

- Το `proc_ro.p_ucred` είναι ένας **SMR-protected pointer** αποθηκευμένος σε ένα **read-only** αντικείμενο `proc_ro`.
- Οι writers πρέπει να ενημερώνουν αυτόν τον pointer **atomically**.
- Η `kauth_cred_proc_update()` χρησιμοποιούσε το `zalloc_ro_mut(...)` για να τροποποιήσει το `p_ucred`· στο x86_64 αυτή η διαδρομή καταλήγει τελικά στα `memcpy` / `rep movsb`, επομένως ένας ταυτόχρονος reader μπορεί να παρατηρήσει έναν **torn pointer**.
- Το bug μετατρέπεται σε **data-only privilege escalation**: αν ο corrupted credential pointer επιλύεται σε ένα διαφορετικό έγκυρο credential object, το τρέχον thread μπορεί να κληρονομήσει περισσότερο privileged state χωρίς προηγουμένως να πετύχει ένα προφανές control-flow hijack.

Minimal trigger pattern:
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
Χρήσιμη heuristics για audit: κάθε φορά που ένα kernel path συνδυάζει **SMR readers**, **read-only zone mutation** και **credential ή task metadata**, επαληθεύστε ότι οι ενημερώσεις χρησιμοποιούν τις atomic `zalloc_ro_mut_*` variants αντί για copy-based helpers.

---

## 2024-2025: SIP bypass που ανοίγει ξανά kernel loading paths (CVE-2024-44243)

Η Microsoft έδειξε ότι το `storagekitd` μπορούσε να γίνει αντικείμενο abuse για **bypass του SIP** και, στη συνέχεια, να καταστήσει ξανά relevant τον third-party kernel code σε μηχανήματα που διαφορετικά θα φαίνονταν "post-kext". Η βασική ιδέα είναι:<sup>[[2]](#references)</sup>

1. Κάντε drop ή overwrite ένα malicious `.fs` bundle στο `/Library/Filesystems`.
2. Κάντε trigger το `storagekitd` μέσω του Disk Utility ή του `diskutil`.
3. Αφήστε τον specially entitled daemon να κάνει spawn bundle executables **χωρίς να κάνει σωστά drop των privileges / validate το path**.
4. Χρησιμοποιήστε το resulting SIP bypass για να τροποποιήσετε protected file-system state και, στο demonstration της Microsoft, να κάνετε override τη kernel extension exclusion list.

Για τους kernel researchers, το σημαντικό lesson είναι ότι το **kernel attack surface μπορεί να επανεισαχθεί από userland management daemons**, ακόμη και όταν το direct third-party kext loading είναι heavily restricted.

Χρήσιμο triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing και ροή εργασίας έρευνας

Αν κάνετε ενεργά hunting για αυτή την κατηγορία bugs, η πρόσφατη δημόσια έρευνα δείχνει προς την ίδια κατεύθυνση:

- Το [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) παραμένει ένα από τα καλύτερα references για kernel research στην εποχή του Apple Silicon. Χρησιμοποιεί **static binary rewriting** για να ανακτήσει κάλυψη, απενεργοποιεί paths που απαιτούν **entitlement** κατά το testing και συμπεραίνει τη δομή των interfaces από userspace wrappers.<sup>[[4]](#references)</sup>
- Το [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) της Project Zero παρουσιάζει ένα πολύ πρακτικό workflow για το **rebasing ενός kext / fileset σε userspace**, ώστε ο parser-heavy κώδικας να μπορεί να γίνει fuzzing με πολύ μεγαλύτερη ταχύτητα, πριν από την αναπαραγωγή του on-device.<sup>[[5]](#references)</sup>
- Για targets που βασίζονται σε μεγάλο βαθμό στο Mach, δημιουργήστε harnesses γύρω από **real message layouts και multi-call state machines**, όχι μόνο γύρω από single selector blobs. Πρόσφατη έρευνα σε CoreAudio/Mach από την Project Zero και conference talks όπως το **Fuzzing at Mach Speed** δείχνουν γιατί οι stateful message sequences συνεχίζουν να αποδίδουν.

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
## Σύντομο Cheatsheet για Enumeration
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

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Ανάλυση του CVE-2024-44243, ενός macOS System Integrity Protection bypass μέσω kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Ο εφιάλτης του OTA Update της Apple: Bypassing του Signature Verification και Pwning του Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing macOS Kernel EXTensions σε Apple Silicon μέσω Exploiting Mitigations (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Απλό macOS kernel extension fuzzing σε userspace με IDA και TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [Σχετικά με το περιεχόμενο ασφάλειας του macOS Sonoma 14.4 - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
