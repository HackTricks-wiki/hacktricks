# Πρόβλημα Kerberos Double Hop

{{#include ../../banners/hacktricks-training.md}}


## Εισαγωγή

Το πρόβλημα "Double Hop" του Kerberos εμφανίζεται όταν ένας επιτιθέμενος προσπαθεί να χρησιμοποιήσει **Kerberos authentication across two** **hops**, για παράδειγμα χρησιμοποιώντας **PowerShell**/**WinRM**.

Όταν συμβαίνει μια **authentication** μέσω **Kerberos**, οι **credentials** **δεν** αποθηκεύονται στη **μνήμη.** Επομένως, αν τρέξετε το mimikatz **δεν θα βρείτε credentials** του χρήστη στη μηχανή ακόμα και αν εκτελεί διαδικασίες.

Αυτό συμβαίνει επειδή όταν συνδέεστε με Kerberos, αυτά είναι τα βήματα:

1. Ο Χρήστης1 παρέχει credentials και ο **domain controller** επιστρέφει ένα Kerberos **TGT** στον Χρήστη1.
2. Ο Χρήστης1 χρησιμοποιεί το **TGT** για να ζητήσει ένα **service ticket** για να **connect** στον Server1.
3. Ο Χρήστης1 **connects** στον **Server1** και παρέχει το **service ticket**.
4. Ο **Server1** **δεν** έχει **credentials** του Χρήστη1 αποθηκευμένα ή το **TGT** του Χρήστη1. Επομένως, όταν ο Χρήστης1 από τον Server1 προσπαθεί να συνδεθεί σε έναν δεύτερο server, **δεν μπορεί να αυθεντικοποιηθεί**.

### Απεριόριστη Αντιπροσώπευση

Αν είναι ενεργοποιημένη η **unconstrained delegation** στον υπολογιστή, αυτό δεν θα συμβεί καθώς ο **Server** θα **get** ένα **TGT** κάθε χρήστη που τον προσπελάσει. Επιπλέον, αν χρησιμοποιηθεί η απεριόριστη αντιπροσώπευση, πιθανώς μπορείτε να **compromise the Domain Controller** από αυτό.\
[**Περισσότερες πληροφορίες στη σελίδα της απεριόριστης αντιπροσώπευσης**](unconstrained-delegation.md).

### CredSSP

Ένας άλλος τρόπος για να αποφευχθεί αυτό το πρόβλημα, το οποίο είναι [**ιδιαίτερα ανασφαλές**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), είναι ο **Credential Security Support Provider**. Από τη Microsoft:

> Η αυθεντικοποίηση CredSSP αντιπροσωπεύει τα credentials του χρήστη από τον τοπικό υπολογιστή σε έναν απομακρυσμένο υπολογιστή. Αυτή η πρακτική αυξάνει τον κίνδυνο ασφαλείας της απομακρυσμένης λειτουργίας. Αν ο απομακρυσμένος υπολογιστής παραβιαστεί, όταν τα credentials μεταφέρονται σε αυτόν, τα credentials μπορούν να χρησιμοποιηθούν για τον έλεγχο της δικτυακής συνεδρίας.

Συνιστάται έντονα να είναι απενεργοποιημένο το **CredSSP** σε παραγωγικά συστήματα, ευαίσθητα δίκτυα και παρόμοια περιβάλλοντα λόγω ανησυχιών ασφαλείας. Για να προσδιορίσετε αν είναι ενεργοποιημένο το **CredSSP**, μπορεί να εκτελεστεί η εντολή `Get-WSManCredSSP`. Αυτή η εντολή επιτρέπει τον **έλεγχο της κατάστασης του CredSSP** και μπορεί να εκτελεστεί ακόμη και απομακρυσμένα, εφόσον είναι ενεργοποιημένο το **WinRM**.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

Για να αντιμετωπιστεί το πρόβλημα του διπλού hop, παρουσιάζεται μια μέθοδος που περιλαμβάνει ένα εσωτερικό `Invoke-Command`. Αυτό δεν λύνει το πρόβλημα άμεσα αλλά προσφέρει μια εναλλακτική λύση χωρίς να απαιτούνται ειδικές ρυθμίσεις. Η προσέγγιση επιτρέπει την εκτέλεση μιας εντολής (`hostname`) σε έναν δευτερεύοντα διακομιστή μέσω μιας εντολής PowerShell που εκτελείται από μια αρχική επιτιθέμενη μηχανή ή μέσω μιας προηγουμένως καθορισμένης PS-Session με τον πρώτο διακομιστή. Να πώς γίνεται:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Εναλλακτικά, προτείνεται η δημιουργία μιας PS-Session με τον πρώτο διακομιστή και η εκτέλεση του `Invoke-Command` χρησιμοποιώντας το `$cred` για την κεντρικοποίηση των εργασιών.

### Εγγραφή Ρύθμισης PSSession

Μια λύση για την παράκαμψη του προβλήματος διπλού άλματος περιλαμβάνει τη χρήση του `Register-PSSessionConfiguration` με το `Enter-PSSession`. Αυτή η μέθοδος απαιτεί μια διαφορετική προσέγγιση από το `evil-winrm` και επιτρέπει μια συνεδρία που δεν υποφέρει από τον περιορισμό του διπλού άλματος.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Για τοπικούς διαχειριστές σε έναν ενδιάμεσο στόχο, η προώθηση θυρών επιτρέπει την αποστολή αιτημάτων σε έναν τελικό διακομιστή. Χρησιμοποιώντας το `netsh`, μπορεί να προστεθεί ένας κανόνας για την προώθηση θυρών, μαζί με έναν κανόνα τείχους προστασίας των Windows για να επιτραπεί η προωθημένη θύρα.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` μπορεί να χρησιμοποιηθεί για την προώθηση αιτημάτων WinRM, πιθανώς ως μια λιγότερο ανιχνεύσιμη επιλογή αν η παρακολούθηση του PowerShell είναι ανησυχητική. Η παρακάτω εντολή δείχνει τη χρήση του:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Η εγκατάσταση του OpenSSH στον πρώτο διακομιστή επιτρέπει μια λύση για το πρόβλημα του double-hop, ιδιαίτερα χρήσιμη για σενάρια jump box. Αυτή η μέθοδος απαιτεί εγκατάσταση και ρύθμιση του OpenSSH για Windows μέσω CLI. Όταν ρυθμιστεί για Αυθεντικοποίηση με Κωδικό, αυτό επιτρέπει στον ενδιάμεσο διακομιστή να αποκτήσει ένα TGT εκ μέρους του χρήστη.

#### Βήματα Εγκατάστασης OpenSSH

1. Κατεβάστε και μεταφέρετε το τελευταίο zip του OpenSSH στον στόχο διακομιστή.
2. Αποσυμπιέστε και εκτελέστε το σενάριο `Install-sshd.ps1`.
3. Προσθέστε έναν κανόνα τείχους προστασίας για να ανοίξετε την πόρτα 22 και επαληθεύστε ότι οι υπηρεσίες SSH εκτελούνται.

Για να επιλυθούν τα σφάλματα `Connection reset`, οι άδειες ενδέχεται να χρειαστεί να ενημερωθούν ώστε να επιτρέπουν σε όλους πρόσβαση ανάγνωσης και εκτέλεσης στον κατάλογο OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Αναφορές

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)


{{#include ../../banners/hacktricks-training.md}}
