# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

Η **Skeleton Key attack** είναι μια τεχνική που επιτρέπει σε επιτιθέμενους να **bypass Active Directory authentication** με **injecting a master password** στη διεργασία LSASS κάθε domain controller. Μετά την injection, το master password (προεπιλογή **`mimikatz`**) μπορεί να χρησιμοποιηθεί για να authenticate ως **any domain user** ενώ τα πραγματικά τους passwords εξακολουθούν να λειτουργούν.

Key facts:

- Απαιτεί **Domain Admin/SYSTEM + SeDebugPrivilege** σε κάθε DC και πρέπει να **εφαρμοστεί ξανά μετά από κάθε επανεκκίνηση**.
- Επηρεάζει τις διαδρομές επικύρωσης **NTLM** και **Kerberos RC4 (etype 0x17)**· περιοχές μόνο με AES ή λογαριασμοί που επιβάλλουν AES **δεν θα αποδεχτούν το skeleton key**.
- Μπορεί να συγκρούεται με third‑party LSA authentication packages ή πρόσθετους smart‑card / MFA providers.
- Το Mimikatz module δέχεται τον προαιρετικό switch `/letaes` για να αποφύγει την επαφή με τα Kerberos/AES hooks σε περίπτωση προβλημάτων συμβατότητας.

### Εκτέλεση

Κλασικό LSASS χωρίς προστασία PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Εάν **LSASS is running as PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), απαιτείται kernel driver για να αφαιρεθεί η προστασία πριν από το patching του LSASS:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
After injection, authenticate with any domain account but use password `mimikatz` (or the value set by the operator). Remember to repeat on **all DCs** in multi‑DC environments.

## Μέτρα αντιμετώπισης

- **Παρακολούθηση καταγραφών**
- System **Event ID 7045** (service/driver install) για unsigned drivers όπως `mimidrv.sys`.
- **Sysmon**: Event ID 7 (driver load) για `mimidrv.sys`; Event ID 10 για ύποπτη πρόσβαση στο `lsass.exe` από non‑system processes.
- Security **Event ID 4673/4611** για χρήση ευαίσθητων προνομίων ή ανωμαλίες στην εγγραφή LSA authentication package; συσχετίστε με απροσδόκητα 4624 logons που χρησιμοποιούν RC4 (etype 0x17) από DCs.
- **Σκληρυνση LSASS**
- Διατηρήστε ενεργοποιημένα τα **RunAsPPL/Credential Guard/Secure LSASS** στους DCs για να αναγκάσετε τους επιτιθέμενους σε kernel‑mode driver deployment (περισσότερη τηλεμετρία, δυσκολότερη εκμετάλλευση).
- Απενεργοποιήστε το legacy **RC4** όπου είναι δυνατόν· ο περιορισμός των Kerberos tickets σε AES αποτρέπει το RC4 hook path που χρησιμοποιεί το skeleton key.
- Γρήγοροι έλεγχοι PowerShell:
- Detect unsigned kernel driver installs: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Hunt for Mimikatz driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Επιβεβαιώστε ότι το PPL επιβάλλεται μετά από επανεκκίνηση: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

For additional credential‑hardening guidance check [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## Αναφορές

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
