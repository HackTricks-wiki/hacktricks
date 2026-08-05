# Ευπάθειες Kernel στο macOS

{{#include ../../../banners/hacktricks-training.md}}

Το πρόσφατο kernel exploitation στο macOS αφορά λιγότερο το «φόρτωσε ένα trivial unsigned kext και απέκτησε ring-0» και περισσότερο την κατάχρηση **Mach/MIG parsers**, **IOKit user clients**, **data-only races μέσα στο XNU** και **daemons με ειδικά entitlements**, οι οποίοι μπορούν ακόμη να επαναφέρουν attack surface στον kernel. Για το reversing των συγκεκριμένων interfaces, δείτε επίσης τις σελίδες σχετικά με [**IOKit**](macos-iokit.md) και [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces που εξακολουθούν να έχουν σημασία

- **Mach/MIG handlers** σε system daemons και kernel-facing services: malformed descriptors, out-of-line (OOL) data και stateful multi-message flows.
- **IOKit user clients**: selector-specific parsing, entitlement-gated methods και wrapper libraries/daemons που αποκρύπτουν το πραγματικό call graph.
- **XNU data-only primitives**: races γύρω από credentials, SMR-protected pointers, read-only zones και άλλα σημεία όπου η corruption αλλάζει την policy χωρίς να απαιτείται πρώτα ο έλεγχος του RIP/PC.
- **Third-party / auxiliary kernel code**: τα legacy kexts είναι πλέον σπανιότερα, όμως τα enterprise fleets, τα reduced-security Apple Silicon systems και τα vendor `.fs` / helper bundles εξακολουθούν να δημιουργούν paths υψηλής αξίας δίπλα στον kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Στο [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) συνδυάζονται αρκετά OTA/update-chain bugs για την επίτευξη kernel compromise, μέσω κατάχρησης του software update pipeline και δυνατοτήτων που σχετίζονται με το rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Οι [**March 2024 macOS security releases**](https://support.apple.com/en-us/120895) της Apple διόρθωσαν δύο issues που είχαν **actively exploited**:

- **CVE-2024-23225 – Kernel**: ένα memory-corruption bug όπου ένας attacker με arbitrary kernel read/write μπορούσε να παρακάμψει τα kernel memory protections.
- **CVE-2024-23296 – RTKit**: ένα δεύτερο memory-corruption bug με την ίδια δημόσια δήλωση επιπτώσεων.

Οι public λεπτομέρειες για την root cause παραμένουν περιορισμένες, όμως το ζεύγος αποτελεί καλή υπενθύμιση ότι τα σύγχρονα Apple exploit chains συχνά απαιτούν κάτι περισσότερο από «απλώς» kernel R/W: το post-exploitation ενάντια σε memory protections, coprocessor-adjacent code ή secondary trust boundaries είναι συχνά το σημείο όπου σταθεροποιείται το πραγματικό chain.

Γρήγορο patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Το [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) του Joseph Ravichandran αποτελεί ένα πολύ καλό σύγχρονο case study του XNU, επειδή **δεν** είναι ένα κλασικό buffer overflow:<sup>[[1]](#references)</sup>

- Το `proc_ro.p_ucred` είναι ένας **SMR-protected pointer** αποθηκευμένος σε ένα **read-only** αντικείμενο `proc_ro`.
- Οι writers πρέπει να ενημερώνουν αυτόν τον pointer **ατομικά**.
- Η `kauth_cred_proc_update()` χρησιμοποιούσε `zalloc_ro_mut(...)` για να τροποποιήσει το `p_ucred`. Στο x86_64, αυτή η διαδρομή τελικά καταλήγει σε `memcpy` / `rep movsb`, οπότε ένας concurrent reader μπορεί να παρατηρήσει έναν **torn pointer**.
- Το bug μετατρέπεται σε **data-only privilege escalation**: αν ο corrupted credential pointer επιλύεται σε ένα διαφορετικό έγκυρο credential object, το τρέχον thread μπορεί να κληρονομήσει περισσότερο privileged state χωρίς να χρειαστεί πρώτα να πετύχει ένα προφανές control-flow hijack.

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
Χρήσιμη heuristic για audit: κάθε φορά που ένα kernel path συνδυάζει **SMR readers**, **read-only zone mutation** και **credential ή task metadata**, επαληθεύστε ότι οι ενημερώσεις χρησιμοποιούν τις atomic `zalloc_ro_mut_*` variants αντί για copy-based helpers.

---

## 2024-2025: SIP bypass που ανοίγει ξανά kernel loading paths (CVE-2024-44243)

Η Microsoft έδειξε ότι το `storagekitd` θα μπορούσε να γίνει αντικείμενο abuse για **bypass του SIP** και, στη συνέχεια, να καταστήσει ξανά relevant τον third-party kernel code σε μηχανήματα που διαφορετικά θα φαίνονταν "post-kext". Η βασική ιδέα είναι:<sup>[[2]](#references)</sup>

1. Κάντε drop ή overwrite ένα malicious `.fs` bundle στο `/Library/Filesystems`.
2. Κάντε trigger το `storagekitd` μέσω του Disk Utility ή του `diskutil`.
3. Αφήστε τον specially entitled daemon να κάνει spawn bundle executables **χωρίς να κάνει σωστό drop privileges / validate το path**.
4. Χρησιμοποιήστε το resulting SIP bypass για να τροποποιήσετε protected file-system state και, στην επίδειξη της Microsoft, να κάνετε override τη kernel extension exclusion list.

Για τους kernel researchers, το σημαντικό lesson είναι ότι το **kernel attack surface μπορεί να επανεισαχθεί από userland management daemons**, ακόμη και όταν το direct third-party kext loading είναι heavily restricted.

Χρήσιμο triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing & workflow έρευνας

Αν κάνετε ενεργά hunting για αυτή την κατηγορία bugs, η πρόσφατη δημόσια έρευνα κινείται προς την ίδια κατεύθυνση:

- Το [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) παραμένει μία από τις καλύτερες αναφορές για kernel research στην εποχή του Apple Silicon. Χρησιμοποιεί **static binary rewriting** για να ανακτήσει coverage, απενεργοποιεί paths που απαιτούν **entitlement** κατά το testing και συμπεραίνει τη δομή των interfaces από wrappers του userspace.<sup>[[4]](#references)</sup>
- Το Project Zero [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) παρουσιάζει ένα πολύ πρακτικό workflow για το **rebasing ενός kext / fileset στο userspace**, ώστε ο κώδικας με πολλούς parsers να μπορεί να γίνει fuzzing με πολύ μεγαλύτερη ταχύτητα, πριν από την αναπαραγωγή του on-device.<sup>[[5]](#references)</sup>
- Για targets με έντονη χρήση του Mach, δημιουργήστε harnesses γύρω από **real message layouts και multi-call state machines**, όχι μόνο γύρω από single selector blobs. Η πρόσφατη έρευνα σε CoreAudio/Mach από το Project Zero και ομιλίες σε συνέδρια, όπως το **Fuzzing at Mach Speed**, δείχνουν γιατί οι stateful ακολουθίες μηνυμάτων συνεχίζουν να αποδίδουν.

Γρήγορες τοπικές εντολές που θα χρησιμοποιείτε συχνά:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Γρήγορο Cheatsheet για Enumeration
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
- [2] [Microsoft Security Blog - Ανάλυση του CVE-2024-44243, ενός bypass του macOS System Integrity Protection μέσω kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Ο εφιάλτης του OTA Update της Apple: Bypassing του Signature Verification και Pwning του Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing macOS Kernel EXTensions στο Apple Silicon μέσω Exploiting Mitigations (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Απλό fuzzing macOS kernel extensions σε userspace με IDA και TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
