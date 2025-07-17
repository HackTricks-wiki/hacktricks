# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**Σε αυτή την αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) εξηγούνται αρκετές ευπάθειες που επέτρεψαν την παραβίαση του πυρήνα, παραβιάζοντας τον ενημερωτή λογισμικού.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild Kernel 0-days (CVE-2024-23225 & CVE-2024-23296)

Η Apple διόρθωσε δύο σφάλματα διαφθοράς μνήμης που εκμεταλλεύονταν ενεργά κατά του iOS και macOS τον Μάρτιο του 2024 (διορθώθηκε στο macOS 14.4/13.6.5/12.7.4).

* **CVE-2024-23225 – Kernel**
• Η εγγραφή εκτός ορίων στο υποσύστημα εικονικής μνήμης XNU επιτρέπει σε μια διαδικασία χωρίς προνόμια να αποκτήσει αυθαίρετη ανάγνωση/εγγραφή στον χώρο διευθύνσεων του πυρήνα, παρακάμπτοντας το PAC/KTRR.
• Προκαλείται από το userspace μέσω ενός κατασκευασμένου μηνύματος XPC που υπερχειλίζει ένα buffer στο `libxpc`, και στη συνέχεια μεταβαίνει στον πυρήνα όταν αναλύεται το μήνυμα.
* **CVE-2024-23296 – RTKit**
• Διαφθορά μνήμης στο Apple Silicon RTKit (πραγματικού χρόνου συν-επεξεργαστής).
• Οι αλυσίδες εκμετάλλευσης που παρατηρήθηκαν χρησιμοποίησαν το CVE-2024-23225 για R/W του πυρήνα και το CVE-2024-23296 για να ξεφύγουν από το sandbox του ασφαλούς συν-επεξεργαστή και να απενεργοποιήσουν το PAC.

Patch level detection:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
Αν η αναβάθμιση δεν είναι δυνατή, μετριάστε απενεργοποιώντας τις ευάλωτες υπηρεσίες:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG Type-Confusion – CVE-2023-41075

`mach_msg()` αιτήματα που αποστέλλονται σε έναν μη προνομιούχο πελάτη IOKit οδηγούν σε μια **σύγχυση τύπου** στον κωδικό συγκόλλησης που παράγεται από το MIG. Όταν το μήνυμα απάντησης επαναερμηνεύεται με έναν μεγαλύτερο εκτός γραμμής περιγραφέα από αυτόν που είχε αρχικά κατανεμηθεί, ένας επιτιθέμενος μπορεί να επιτύχει έναν ελεγχόμενο **OOB write** σε ζώνες σωρού πυρήνα και τελικά να
αναβαθμιστεί σε `root`.

Primitive outline (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Public exploits weaponise the bug by:
1. Spraying `ipc_kmsg` buffers with active port pointers.
2. Overwriting `ip_kobject` of a dangling port.
3. Jumping to shellcode mapped at a PAC-forged address using `mprotect()`.

---

## 2024-2025: SIP Bypass through Third-party Kexts – CVE-2024-44243 (aka “Sigma”)

Οι ερευνητές ασφαλείας από τη Microsoft έδειξαν ότι ο υψηλά προνομιούχος δαίμονας `storagekitd` μπορεί να αναγκαστεί να φορτώσει μια **μη υπογεγραμμένη επέκταση πυρήνα** και έτσι να απενεργοποιήσει εντελώς την **Προστασία Ακεραιότητας Συστήματος (SIP)** σε πλήρως ενημερωμένο macOS (πριν από την έκδοση 15.2). Η ροή της επίθεσης είναι:

1. Κατάχρηση του ιδιωτικού δικαιώματος `com.apple.storagekitd.kernel-management` για να δημιουργηθεί ένας βοηθός υπό τον έλεγχο του επιτιθέμενου.
2. Ο βοηθός καλεί `IOService::AddPersonalitiesFromKernelModule` με ένα κατασκευασμένο λεξικό πληροφοριών που δείχνει σε ένα κακόβουλο πακέτο kext.
3. Επειδή οι έλεγχοι εμπιστοσύνης SIP εκτελούνται *μετά* που το kext έχει σταλεί από το `storagekitd`, ο κώδικας εκτελείται σε ring-0 πριν από την επικύρωση και η SIP μπορεί να απενεργοποιηθεί με `csr_set_allow_all(1)`.

Detection tips:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
Άμεση αποκατάσταση είναι η ενημέρωση σε macOS Sequoia 15.2 ή νεότερη έκδοση.

---

### Γρήγορο Φύλλο Συμβουλών Αρίθμησης
```bash
uname -a                          # Kernel build
kmutil showloaded                 # List loaded kernel extensions
kextstat | grep -v com.apple      # Legacy (pre-Catalina) kext list
sysctl kern.kaslr_enable          # Verify KASLR is ON (should be 1)
csrutil status                    # Check SIP from RecoveryOS
spctl --status                    # Confirms Gatekeeper state
```
---

## Fuzzing & Research Tools

* **Luftrauser** – Mach message fuzzer που στοχεύει σε MIG subsystems (`github.com/preshing/luftrauser`).
* **oob-executor** – IPC out-of-bounds primitive generator που χρησιμοποιείται στην έρευνα CVE-2024-23225.
* **kmutil inspect** – Ενσωματωμένο εργαλείο της Apple (macOS 11+) για στατική ανάλυση kexts πριν τη φόρτωση: `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “About the security content of macOS Sonoma 14.4.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
