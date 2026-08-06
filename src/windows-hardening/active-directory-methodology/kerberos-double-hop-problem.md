# Πρόβλημα Kerberos Double Hop

{{#include ../../banners/hacktricks-training.md}}


## Εισαγωγή

Το πρόβλημα "Double Hop" του Kerberos εμφανίζεται όταν ένας attacker προσπαθεί να χρησιμοποιήσει **Kerberos authentication σε δύο** **hops**, για παράδειγμα χρησιμοποιώντας **PowerShell**/**WinRM**.

Όταν πραγματοποιείται **authentication** μέσω **Kerberos**, τα **credentials** **δεν** αποθηκεύονται προσωρινά στη **memory.** Επομένως, αν εκτελέσετε το mimikatz, **δεν θα βρείτε credentials** του χρήστη στο machine, ακόμη κι αν εκτελεί processes.

Αυτό συμβαίνει επειδή κατά τη σύνδεση με Kerberos ακολουθούνται τα εξής βήματα:<sup>[[1]](#references)</sup>

1. Ο User1 παρέχει credentials και ο **domain controller** επιστρέφει ένα Kerberos **TGT** στον User1.
2. Ο User1 χρησιμοποιεί το **TGT** για να ζητήσει ένα **service ticket** ώστε να **συνδεθεί** στο Server1.
3. Ο User1 **συνδέεται** στο **Server1** και παρέχει το **service ticket**.
4. Ο **Server1** **δεν έχει** αποθηκευμένα τα **credentials** του User1 ούτε το **TGT** του User1. Επομένως, όταν ο User1 από το Server1 προσπαθεί να κάνει login σε δεύτερο server, **δεν μπορεί να κάνει authentication**.

### Unconstrained Delegation

Αν έχει ενεργοποιηθεί το **unconstrained delegation** στο PC, αυτό δεν θα συμβεί, καθώς ο **Server** θα **λαμβάνει** ένα **TGT** για κάθε χρήστη που αποκτά πρόσβαση σε αυτόν. Επιπλέον, αν χρησιμοποιείται unconstrained delegation, πιθανότατα μπορείτε να **compromise το Domain Controller** από αυτό.\
[**Περισσότερες πληροφορίες στη σελίδα unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Ένας ακόμη τρόπος αποφυγής αυτού του προβλήματος, ο οποίος είναι [**ιδιαίτερα μη ασφαλής**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), είναι το **Credential Security Support Provider**. Από τη Microsoft:

> Το authentication μέσω CredSSP μεταβιβάζει τα credentials του χρήστη από τον local computer σε έναν remote computer. Αυτή η πρακτική αυξάνει τον κίνδυνο ασφαλείας της remote operation. Αν ο remote computer έχει γίνει compromised, όταν τα credentials μεταβιβαστούν σε αυτόν, μπορούν να χρησιμοποιηθούν για τον έλεγχο του network session.

Συνιστάται ιδιαίτερα να είναι απενεργοποιημένο το **CredSSP** σε production systems, ευαίσθητα networks και παρόμοια environments λόγω ανησυχιών ασφαλείας. Για να προσδιορίσετε αν το **CredSSP** είναι ενεργοποιημένο, μπορείτε να εκτελέσετε την εντολή `Get-WSManCredSSP`. Αυτή η εντολή επιτρέπει τον **έλεγχο της κατάστασης του CredSSP** και μπορεί ακόμη και να εκτελεστεί remotely, υπό την προϋπόθεση ότι το **WinRM** είναι ενεργοποιημένο.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

Το **Remote Credential Guard** διατηρεί το TGT του χρήστη στον originating workstation, ενώ εξακολουθεί να επιτρέπει στη συνεδρία RDP να ζητά νέα Kerberos service tickets στο επόμενο hop. Ενεργοποιήστε το **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** και επιλέξτε **Require Remote Credential Guard**. Στη συνέχεια, συνδεθείτε με `mstsc.exe /remoteGuard /v:server1` αντί να καταφύγετε στο CredSSP.

Η Microsoft προκάλεσε πρόβλημα στο RCG για multi-hop access στα Windows 11 22H2+ μέχρι τα **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894). Εγκαταστήστε τα updates στον client και στον intermediary server, διαφορετικά το second hop θα εξακολουθήσει να αποτυγχάνει.<sup>[[5]](#references)</sup> Γρήγορος έλεγχος για το hotfix:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Με αυτά τα builds εγκατεστημένα, το RDP hop μπορεί να ικανοποιεί τα downstream Kerberos challenges χωρίς να εκθέτει reusable secrets στον πρώτο server.

## Workarounds

### Invoke Command

Για την αντιμετώπιση του double hop issue, παρουσιάζεται μια μέθοδος που περιλαμβάνει ένα nested `Invoke-Command`. Αυτό δεν επιλύει άμεσα το πρόβλημα, αλλά προσφέρει ένα workaround χωρίς να απαιτούνται ειδικές ρυθμίσεις. Η προσέγγιση επιτρέπει την εκτέλεση μιας εντολής (`hostname`) σε έναν secondary server μέσω μιας PowerShell εντολής που εκτελείται από ένα αρχικό attacking machine ή μέσω ενός previously established PS-Session με τον πρώτο server. Η διαδικασία είναι η εξής:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Εναλλακτικά, προτείνεται η δημιουργία ενός PS-Session με τον πρώτο server και η εκτέλεση του `Invoke-Command` χρησιμοποιώντας το `$cred` για τη συγκεντροποίηση των tasks.

### Καταχώριση PSSession Configuration

Μια λύση για την παράκαμψη του προβλήματος του double hop περιλαμβάνει τη χρήση των `Register-PSSessionConfiguration` και `Enter-PSSession`. Αυτή η μέθοδος απαιτεί διαφορετική προσέγγιση από το `evil-winrm` και επιτρέπει μια session που δεν περιορίζεται από τον περιορισμό του double hop.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Για τους local administrators σε έναν ενδιάμεσο στόχο, το port forwarding επιτρέπει την αποστολή requests σε έναν τελικό server. Με τη χρήση του `netsh`, μπορεί να προστεθεί ένας κανόνας για port forwarding, μαζί με έναν κανόνα του Windows firewall που επιτρέπει το forwarded port.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

Το `winrs.exe` μπορεί να χρησιμοποιηθεί για forwarding αιτημάτων WinRM, ως ενδεχομένως λιγότερο ανιχνεύσιμη επιλογή αν το PowerShell monitoring αποτελεί ανησυχία.<sup>[[2]](#references)</sup> Η παρακάτω εντολή δείχνει τη χρήση του:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Η εγκατάσταση του OpenSSH στον πρώτο server επιτρέπει μια λύση για το double-hop issue, ιδιαίτερα χρήσιμη σε σενάρια jump box. Αυτή η μέθοδος απαιτεί εγκατάσταση και ρύθμιση του OpenSSH για Windows μέσω CLI. Όταν ρυθμιστεί για Password Authentication, επιτρέπει στον ενδιάμεσο server να αποκτήσει ένα TGT εκ μέρους του χρήστη.<sup>[[2]](#references)</sup>

#### Βήματα εγκατάστασης OpenSSH

1. Κατεβάστε και μετακινήστε το πιο πρόσφατο zip release του OpenSSH στον target server.
2. Αποσυμπιέστε το και εκτελέστε το script `Install-sshd.ps1`.
3. Προσθέστε έναν firewall rule για να ανοίξετε τη θύρα 22 και επαληθεύστε ότι τα SSH services εκτελούνται.

Για την επίλυση σφαλμάτων `Connection reset`, ενδέχεται να χρειαστεί ενημέρωση των permissions, ώστε να επιτρέπεται σε όλους πρόσβαση read και execute στον κατάλογο OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Προχωρημένο)

**LSA Whisperer** (2024) εκθέτει το package call `msv1_0!CacheLogon`, ώστε να μπορείτε να seedάρετε ένα υπάρχον *network logon* με ένα γνωστό NT hash, αντί να δημιουργείτε ένα νέο session με το `LogonUser`. Με την εισαγωγή του hash στο logon session που το WinRM/PowerShell έχει ήδη ανοίξει στο hop #1, αυτός ο host μπορεί να κάνει authenticate στο hop #2 χωρίς να αποθηκεύει explicit credentials ή να δημιουργεί επιπλέον 4624 events.<sup>[[6]](#references)</sup>

1. Αποκτήστε code execution μέσα στο LSASS (είτε απενεργοποιώντας/καταχρώμενοι το PPL είτε εκτελώντας το σε ένα lab VM που ελέγχετε).
2. Κάντε enumerate τα logon sessions (π.χ. `lsa.exe sessions`) και καταγράψτε το LUID που αντιστοιχεί στο remoting context σας.
3. Υπολογίστε εκ των προτέρων το NT hash και περάστε το στο `CacheLogon`, έπειτα κάντε clear όταν ολοκληρώσετε.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Μετά το cache seed, εκτελέστε ξανά τα `Invoke-Command`/`New-PSSession` από το hop #1: το LSASS θα επαναχρησιμοποιήσει το injected hash για να ικανοποιήσει τις προκλήσεις Kerberos/NTLM για το δεύτερο hop, παρακάμπτοντας αποτελεσματικά τον περιορισμό του double hop. Το μειονέκτημα είναι η αυξημένη telemetry (εκτέλεση κώδικα στο LSASS), επομένως χρησιμοποιήστε το σε περιβάλλοντα με υψηλές απαιτήσεις, όπου τα CredSSP/RCG δεν επιτρέπονται.

## Αναφορές

- [1] [Κατανόηση του Kerberos Double Hop - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Παρακάμψεις του Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/)
- [3] [Μια άλλη λύση για το multi-hop PowerShell remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Επίλυση του προβλήματος multi-hop του PowerShell χωρίς χρήση CredSSP](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [9 Απριλίου 2024—KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}
