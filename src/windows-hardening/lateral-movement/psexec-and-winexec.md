# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργούν

Η διαδικασία περιγράφεται στα παρακάτω βήματα, απεικονίζοντας πώς οι δυαδικοί κωδικοί υπηρεσιών χειρίζονται για να επιτευχθεί απομακρυσμένη εκτέλεση σε μια στοχοθετημένη μηχανή μέσω SMB:

1. **Αντιγραφή ενός δυαδικού κωδικού υπηρεσίας στο ADMIN$ share μέσω SMB** πραγματοποιείται.
2. **Δημιουργία μιας υπηρεσίας στη απομακρυσμένη μηχανή** γίνεται με την αναφορά στον δυαδικό κωδικό.
3. Η υπηρεσία **ξεκινά απομακρυσμένα**.
4. Με την έξοδο, η υπηρεσία **σταματά και ο δυαδικός κωδικός διαγράφεται**.

### **Διαδικασία Χειροκίνητης Εκτέλεσης PsExec**

Υποθέτοντας ότι υπάρχει ένα εκτελέσιμο payload (δημιουργημένο με msfvenom και κρυμμένο χρησιμοποιώντας Veil για να αποφευχθεί η ανίχνευση από antivirus), ονόματι 'met8888.exe', που αντιπροσωπεύει ένα payload meterpreter reverse_http, ακολουθούνται τα εξής βήματα:

- **Αντιγραφή του δυαδικού κωδικού**: Ο εκτελέσιμος κωδικός αντιγράφεται στο ADMIN$ share από μια γραμμή εντολών, αν και μπορεί να τοποθετηθεί οπουδήποτε στο σύστημα αρχείων για να παραμείνει κρυμμένος.
- Αντί να αντιγραφεί ο δυαδικός κωδικός, είναι επίσης δυνατό να χρησιμοποιηθεί ένας δυαδικός κωδικός LOLBAS όπως το `powershell.exe` ή το `cmd.exe` για να εκτελούνται εντολές απευθείας από τα επιχειρήματα. Π.χ. `sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"`
- **Δημιουργία μιας υπηρεσίας**: Χρησιμοποιώντας την εντολή `sc` των Windows, η οποία επιτρέπει την αναζήτηση, δημιουργία και διαγραφή υπηρεσιών Windows απομακρυσμένα, δημιουργείται μια υπηρεσία ονόματι "meterpreter" που δείχνει στον ανεβασμένο δυαδικό κωδικό.
- **Έναρξη της υπηρεσίας**: Το τελευταίο βήμα περιλαμβάνει την εκκίνηση της υπηρεσίας, η οποία πιθανότατα θα έχει ως αποτέλεσμα ένα σφάλμα "time-out" λόγω του ότι ο δυαδικός κωδικός δεν είναι γνήσιος δυαδικός κωδικός υπηρεσίας και αποτυγχάνει να επιστρέψει τον αναμενόμενο κωδικό απόκρισης. Αυτό το σφάλμα είναι ασήμαντο καθώς ο κύριος στόχος είναι η εκτέλεση του δυαδικού κωδικού.

Η παρατήρηση του listener του Metasploit θα αποκαλύψει ότι η συνεδρία έχει ξεκινήσει επιτυχώς.

[Μάθετε περισσότερα για την εντολή `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Βρείτε πιο λεπτομερή βήματα στο: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

- Μπορείτε επίσης να χρησιμοποιήσετε τον **δυαδικό κωδικό PsExec.exe των Windows Sysinternals**:

![](<../../images/image (928).png>)

Ή να έχετε πρόσβαση μέσω webddav:
```bash
\\live.sysinternals.com\tools\PsExec64.exe -accepteula
```
- Μπορείτε επίσης να χρησιμοποιήσετε [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- Μπορείτε επίσης να χρησιμοποιήσετε [**SharpMove**](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Μπορείτε επίσης να χρησιμοποιήσετε **Impacket's `psexec` και `smbexec.py`**.


{{#include ../../banners/hacktricks-training.md}}
