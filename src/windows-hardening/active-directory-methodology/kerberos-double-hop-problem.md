# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Εισαγωγή

Το Kerberos "Double Hop" πρόβλημα εμφανίζεται όταν ένας επιτιθέμενος προσπαθεί να χρησιμοποιήσει **την πιστοποίηση Kerberos σε δύο** **hops**, για παράδειγμα χρησιμοποιώντας **PowerShell**/**WinRM**.

Όταν γίνεται **πιστοποίηση** μέσω **Kerberos**, τα **διαπιστευτήρια** **δεν** αποθηκεύονται στην **μνήμη.** Επομένως, αν τρέξετε mimikatz δεν θα **βρείτε διαπιστευτήρια** του χρήστη στη μηχανή ακόμα κι αν τρέχει διεργασίες.

Αυτό συμβαίνει επειδή κατά τη σύνδεση με Kerberos τα βήματα είναι τα εξής:

1. User1 παρέχει διαπιστευτήρια και ο **domain controller** επιστρέφει ένα Kerberos **TGT** στον User1.
2. User1 χρησιμοποιεί το **TGT** για να ζητήσει ένα **service ticket** για να **συνδεθεί** στο Server1.
3. User1 **συνδέεται** στο **Server1** και παρέχει το **service ticket**.
4. **Server1** **δεν** έχει αποθηκευμένα στα cache τα **διαπιστευτήρια** του User1 ούτε το **TGT** του User1. Συνεπώς, όταν ο User1 από το Server1 προσπαθήσει να συνδεθεί σε δεύτερο server, **δεν μπορεί να πιστοποιηθεί**.

### Unconstrained Delegation

Αν η **unconstrained delegation** είναι ενεργοποιημένη στον PC, αυτό δεν θα συμβεί καθώς ο **Server** θα **λάβει** ένα **TGT** για κάθε χρήστη που τον προσπελαύνει. Επιπλέον, αν χρησιμοποιηθεί unconstrained delegation πιθανότατα μπορείτε να **συμβιβάσετε τον Domain Controller** μέσω αυτής.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Another way to avoid this problem which is [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is **Credential Security Support Provider**. Από τη Microsoft:

> Η πιστοποίηση CredSSP μεταβιβάζει τα διαπιστευτήρια του χρήστη από τον τοπικό υπολογιστή σε έναν απομακρυσμένο υπολογιστή. Αυτή η πρακτική αυξάνει τον κίνδυνο ασφαλείας της απομακρυσμένης λειτουργίας. Εάν ο απομακρυσμένος υπολογιστής είναι συμβιβασμένος, όταν τα διαπιστευτήρια μεταβιβαστούν σε αυτόν, τα διαπιστευτήρια μπορούν να χρησιμοποιηθούν για να ελέγξουν τη συνεδρία δικτύου.

Συνιστάται έντονα το **CredSSP** να είναι απενεργοποιημένο σε παραγωγικά συστήματα, ευαίσθητα δίκτυα και παρόμοια περιβάλλοντα λόγω ανησυχιών ασφαλείας. Για να προσδιορίσετε αν το **CredSSP** είναι ενεργό, μπορεί να εκτελεστεί η εντολή `Get-WSManCredSSP`. Αυτή η εντολή επιτρέπει τον **έλεγχο της κατάστασης CredSSP** και μπορεί ακόμη να εκτελεστεί απομακρυσμένα, εφόσον το **WinRM** είναι ενεργοποιημένο.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** διατηρεί το TGT του χρήστη στον αρχικό workstation ενώ παράλληλα επιτρέπει στη συνεδρία RDP να ζητήσει νέα Kerberos service tickets στο επόμενο hop. Ενεργοποιήστε Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers και επιλέξτε Require Remote Credential Guard, στη συνέχεια συνδεθείτε με `mstsc.exe /remoteGuard /v:server1` αντί να επιστρέψετε σε CredSSP.

Microsoft διέκοψε το RCG για multi-hop access σε Windows 11 22H2+ μέχρι τα April 2024 cumulative updates (KB5036896/KB5036899/KB5036894). Κάντε patch τον client και τον intermediary server, αλλιώς το δεύτερο hop θα αποτύχει. Quick hotfix check:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Με αυτές τις builds εγκατεστημένες, το RDP hop μπορεί να ικανοποιήσει τις επόμενες προκλήσεις Kerberos χωρίς να εκθέτει επαναχρησιμοποιήσιμα μυστικά στον πρώτο διακομιστή.

## Εναλλακτικές λύσεις

### Invoke Command

Για να αντιμετωπιστεί το πρόβλημα του double hop, παρουσιάζεται μια μέθοδος που χρησιμοποιεί εσωτερικό `Invoke-Command`. Αυτό δεν λύνει άμεσα το ζήτημα αλλά προσφέρει μια παράκαμψη χωρίς ανάγκη ειδικών ρυθμίσεων. Η προσέγγιση επιτρέπει την εκτέλεση μιας εντολής (`hostname`) σε δευτερεύοντα διακομιστή μέσω μιας εντολής PowerShell που τρέχει από την αρχική μηχανή επίθεσης ή μέσω μιας προϋπάρχουσας PS-Session με τον πρώτο διακομιστή. Έτσι γίνεται:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Εναλλακτικά, προτείνεται η δημιουργία μιας PS-Session με τον πρώτο διακομιστή και η εκτέλεση του `Invoke-Command` χρησιμοποιώντας το `$cred` για την κεντρικοποίηση των εργασιών.

### Register PSSession Configuration

Μια λύση για την παράκαμψη του προβλήματος double hop περιλαμβάνει τη χρήση του `Register-PSSessionConfiguration` μαζί με το `Enter-PSSession`. Αυτή η μέθοδος απαιτεί διαφορετική προσέγγιση από το `evil-winrm` και επιτρέπει μια συνεδρία που δεν υποφέρει από τον περιορισμό του double hop.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Για τοπικούς διαχειριστές σε έναν ενδιάμεσο στόχο, το port forwarding επιτρέπει την αποστολή αιτήσεων σε έναν τελικό διακομιστή. Χρησιμοποιώντας `netsh`, μπορεί να προστεθεί ένας κανόνας για το port forwarding, μαζί με έναν κανόνα του Windows firewall για να επιτραπεί η προωθούμενη θύρα.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` μπορεί να χρησιμοποιηθεί για προώθηση αιτήσεων WinRM, ενδεχομένως ως μια λιγότερο ανιχνεύσιμη επιλογή αν υπάρχει παρακολούθηση PowerShell. Η εντολή παρακάτω δείχνει τη χρήση του:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Η εγκατάσταση του OpenSSH στον πρώτο server παρέχει μια λύση-παρακάμψη για το πρόβλημα double-hop, ιδιαίτερα χρήσιμη σε σενάρια jump box. Αυτή η μέθοδος απαιτεί εγκατάσταση μέσω CLI και ρύθμιση του OpenSSH για Windows. Όταν ρυθμιστεί για Password Authentication, αυτό επιτρέπει στον ενδιάμεσο server να αποκτήσει ένα TGT εκ μέρους του χρήστη.

#### Βήματα εγκατάστασης του OpenSSH

1. Κατεβάστε και μεταφέρετε το πιο πρόσφατο αρχείο zip του OpenSSH στον στοχευόμενο server.
2. Αποσυμπιέστε και εκτελέστε το script `Install-sshd.ps1`.
3. Προσθέστε κανόνα firewall για άνοιγμα της θύρας 22 και επιβεβαιώστε ότι οι υπηρεσίες SSH τρέχουν.

Για να επιλυθούν τα σφάλματα `Connection reset`, ίσως χρειαστεί να ενημερωθούν τα δικαιώματα ώστε να επιτρέπουν σε όλους ανάγνωση και εκτέλεση στον κατάλογο OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Για προχωρημένους)

**LSA Whisperer** (2024) αποκαλύπτει την κλήση πακέτου `msv1_0!CacheLogon` ώστε να μπορείτε να σπείρετε ένα υπάρχον *network logon* με γνωστό NT hash αντί να δημιουργήσετε νέα συνεδρία με το `LogonUser`. Εισάγοντας το hash στη συνεδρία σύνδεσης που το WinRM/PowerShell έχει ήδη ανοίξει στο hop #1, ο συγκεκριμένος host μπορεί να αυθεντικοποιηθεί στο hop #2 χωρίς να αποθηκεύει ρητά διαπιστευτήρια ή να δημιουργεί επιπλέον events 4624.

1. Αποκτήστε εκτέλεση κώδικα μέσα στο LSASS (είτε απενεργοποιώντας/κακοποιώντας το PPL είτε εκτελώντας σε ένα lab VM που ελέγχετε).
2. Καταγράψτε τις συνεδρίες logon (π.χ. `lsa.exe sessions`) και συλλάβετε το LUID που αντιστοιχεί στο remoting context σας.
3. Προ-υπολογίστε το NT hash και τροφοδοτήστε το στο `CacheLogon`, και μετά διαγράψτε το όταν τελειώσετε.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Μετά την αρχικοποίηση της cache, εκτελέστε ξανά `Invoke-Command`/`New-PSSession` από το hop #1: το LSASS θα ξαναχρησιμοποιήσει το εγχυμένο hash για να ικανοποιήσει τις προκλήσεις Kerberos/NTLM για το δεύτερο hop, παρακάμπτοντας κομψά τον περιορισμό του double hop. Το αντίτιμο είναι αυξημένη τηλεμετρία (εκτέλεση κώδικα στο LSASS), οπότε κρατήστε αυτήν την τεχνική για περιβάλλοντα υψηλής τριβής όπου το CredSSP/RCG απαγορεύεται.

## Αναφορές

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
