# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/image (48).png" alt=""><figcaption></figcaption></figure>

Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** που υποστηρίζονται από τα **πιο προηγμένα** εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Πώς λειτουργούν

Η διαδικασία περιγράφεται στα παρακάτω βήματα, απεικονίζοντας πώς οι δυαδικοί κωδικοί υπηρεσιών χειρίζονται για να επιτευχθεί απομακρυσμένη εκτέλεση σε μια στοχευμένη μηχανή μέσω SMB:

1. **Αντιγραφή ενός δυαδικού κωδικού υπηρεσίας στο ADMIN$ share μέσω SMB** πραγματοποιείται.
2. **Δημιουργία μιας υπηρεσίας στη απομακρυσμένη μηχανή** γίνεται με την αναφορά στον δυαδικό κωδικό.
3. Η υπηρεσία **ξεκινά απομακρυσμένα**.
4. Με την έξοδο, η υπηρεσία **σταματά και ο δυαδικός κωδικός διαγράφεται**.

### **Διαδικασία Χειροκίνητης Εκτέλεσης PsExec**

Υποθέτοντας ότι υπάρχει ένα εκτελέσιμο payload (δημιουργημένο με msfvenom και κρυμμένο χρησιμοποιώντας Veil για να αποφευχθεί η ανίχνευση από το antivirus), ονόματι 'met8888.exe', που αντιπροσωπεύει ένα payload meterpreter reverse_http, ακολουθούνται τα εξής βήματα:

- **Αντιγραφή του δυαδικού κωδικού**: Ο εκτελέσιμος κωδικός αντιγράφεται στο ADMIN$ share από μια γραμμή εντολών, αν και μπορεί να τοποθετηθεί οπουδήποτε στο σύστημα αρχείων για να παραμείνει κρυμμένος.

- **Δημιουργία μιας υπηρεσίας**: Χρησιμοποιώντας την εντολή `sc` των Windows, η οποία επιτρέπει την αναζήτηση, δημιουργία και διαγραφή υπηρεσιών Windows απομακρυσμένα, δημιουργείται μια υπηρεσία ονόματι "meterpreter" που δείχνει στον ανεβασμένο δυαδικό κωδικό.

- **Έναρξη της υπηρεσίας**: Το τελευταίο βήμα περιλαμβάνει την εκκίνηση της υπηρεσίας, η οποία πιθανότατα θα έχει ως αποτέλεσμα ένα σφάλμα "time-out" λόγω του ότι ο δυαδικός κωδικός δεν είναι γνήσιος δυαδικός κωδικός υπηρεσίας και αποτυγχάνει να επιστρέψει τον αναμενόμενο κωδικό απόκρισης. Αυτό το σφάλμα είναι ασήμαντο καθώς ο κύριος στόχος είναι η εκτέλεση του δυαδικού κωδικού.

Η παρατήρηση του listener του Metasploit θα αποκαλύψει ότι η συνεδρία έχει ξεκινήσει επιτυχώς.

[Μάθετε περισσότερα για την εντολή `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Βρείτε πιο λεπτομερή βήματα στο: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Μπορείτε επίσης να χρησιμοποιήσετε τον δυαδικό κωδικό PsExec.exe των Windows Sysinternals:**

![](<../../images/image (165).png>)

Μπορείτε επίσης να χρησιμοποιήσετε [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
<figure><img src="/images/image (48).png" alt=""><figcaption></figcaption></figure>

Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τη βοήθεια των **πιο προηγμένων** εργαλείων της κοινότητας.\
Αποκτήστε Πρόσβαση Σήμερα:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{{#include ../../banners/hacktricks-training.md}}
