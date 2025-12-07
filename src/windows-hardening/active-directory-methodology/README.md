# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

**Active Directory** λειτουργεί ως βασική τεχνολογία, επιτρέποντας σε **διαχειριστές δικτύου** να δημιουργούν και να διαχειρίζονται αποδοτικά **domains**, **users**, και **objects** μέσα σε ένα δίκτυο. Έχει σχεδιαστεί για να κλιμακώνεται, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμες **groups** και **subgroups**, ενώ ελέγχει τα **access rights** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία κύρια επίπεδα: **domains**, **trees**, και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή αντικειμένων, όπως **users** ή **devices**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι ομάδες αυτών των domains συνδεδεμένα με κοινή δομή, και ένα **forest** αντιπροσωπεύει τη συλλογή πολλαπλών trees, διασυνδεδεμένων μέσω **trust relationships**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Συγκεκριμένα **access** και **communication rights** μπορούν να οριστούν σε κάθε ένα από αυτά τα επίπεδα.

Βασικές έννοιες στο **Active Directory** περιλαμβάνουν:

1. **Directory** – Φιλοξενεί όλες τις πληροφορίες που αφορούν τα Active Directory objects.
2. **Object** – Αναφέρεται σε οντότητες μέσα στον κατάλογο, περιλαμβανομένων **users**, **groups**, ή **shared folders**.
3. **Domain** – Λειτουργεί ως δοχείο για αντικείμενα του directory, με δυνατότητα πολλαπλών domains εντός ενός **forest**, καθένα με τη δική του συλλογή αντικειμένων.
4. **Tree** – Ομάδα domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Η κορυφή της οργανωτικής δομής στο Active Directory, αποτελούμενη από διάφορα trees με **trust relationships** μεταξύ τους.

**Active Directory Domain Services (AD DS)** περιλαμβάνει σειρά υπηρεσιών κρίσιμων για την κεντρική διαχείριση και επικοινωνία μέσα σε ένα δίκτυο. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Κεντρικοποιεί την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **users** και **domains**, συμπεριλαμβανομένης της **authentication** και των λειτουργιών **search**.
2. **Certificate Services** – Επιβλέπει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει εφαρμογές που χρησιμοποιούν τον κατάλογο μέσω του πρωτοκόλλου **LDAP**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για την αυθεντικοποίηση χρηστών σε πολλαπλές web εφαρμογές σε μία συνεδρία.
5. **Rights Management** – Βοηθά στην προστασία υλικού με πνευματικά δικαιώματα ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Κρίσιμο για την επίλυση **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθετε πώς να επιτεθείτε σε ένα **AD** πρέπει να κατανοήσετε πολύ καλά τη διαδικασία αυθεντικοποίησης **Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Μπορείτε να επισκεφθείτε το [https://wadcoms.github.io/](https://wadcoms.github.io) για μια γρήγορη επισκόπηση των εντολών που μπορείτε να τρέξετε για να enumerate/exploit ένα AD.

> [!WARNING]
> Η Kerberos επικοινωνία **απαιτεί πλήρες όνομα υποδοχής (FQDN)** για την εκτέλεση ενεργειών. Αν προσπαθήσετε να προσπελάσετε μια μηχανή μέσω της διεύθυνσης IP, **θα χρησιμοποιήσει NTLM και όχι Kerberos**.

## Recon Active Directory (No creds/sessions)

Αν έχετε πρόσβαση σε ένα περιβάλλον AD αλλά δεν έχετε διαπιστευτήρια/sessions μπορείτε να:

- **Pentest the network:**
- Σκανάρετε το δίκτυο, βρείτε μηχανές και ανοιχτές θύρες και δοκιμάστε να **exploit vulnerabilities** ή να **extract credentials** από αυτές (για παράδειγμα, [printers could be very interesting targets](ad-information-in-printers.md)).
- Η αναγνώριση DNS μπορεί να δώσει πληροφορίες για βασικούς servers στο domain όπως web, printers, shares, vpn, media, κλπ.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Ρίξτε μια ματιά στην Γενική [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνετε.
- **Check for null and Guest access on smb services** (αυτό δεν θα δουλέψει σε σύγχρονες εκδόσεις Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Μια πιο λεπτομερής οδηγία για το πώς να enumerate έναν SMB server μπορεί να βρεθεί εδώ:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Μια πιο λεπτομερής οδηγία για το πώς να enumerate LDAP μπορεί να βρεθεί εδώ (δώστε **ειδική προσοχή στην anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Συλλέξτε credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Προσπελάστε host [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συλλέξτε credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξάγετε usernames/ονοματεπώνυμα από εσωτερικά έγγραφα, social media, υπηρεσίες (κυρίως web) εντός των domain περιβαλλόντων αλλά και από δημόσια διαθέσιμες πηγές.
- Αν βρείτε τα πλήρη ονόματα εργαζομένων της εταιρείας, μπορείτε να δοκιμάσετε διαφορετικές AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο κοινές conventions είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Δείτε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητηθεί **invalid username** ο server θα απαντήσει με τον **Kerberos error** κωδικό _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να προσδιορίσουμε ότι το username ήταν άκυρο. **Valid usernames** θα επισείρουν είτε το **TGT σε ένα AS-REP** response είτε το λάθος _KRB5KDC_ERR_PREAUTH_REQUIRED_, υποδεικνύοντας ότι ο χρήστης απαιτείται να εκτελέσει pre-authentication.
- **No Authentication against MS-NRPC**: Χρησιμοποιώντας auth-level = 1 (No authentication) ενάντια στην MS-NRPC (Netlogon) διεπαφή στους domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` αφού γίνει binding στην MS-NRPC διεπαφή για να ελέγξει αν ο χρήστης ή ο υπολογιστής υπάρχει χωρίς κανένα credentials. Το εργαλείο [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτό το είδος enumeration. Η έρευνα μπορεί να βρεθεί [εδώ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Αν βρήκατε έναν από αυτούς τους διακομιστές στο δίκτυο, μπορείτε επίσης να πραγματοποιήσετε **user enumeration** εναντίον του. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Μπορείτε να βρείτε λίστες με usernames στο [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) και σε αυτό ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Ωστόσο, θα πρέπει να έχετε το **όνομα των ανθρώπων που δουλεύουν στην εταιρεία** από το recon βήμα που θα έπρεπε να έχετε εκτελέσει πριν από αυτό. Με το όνομα και το επίθετο μπορείτε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανούς έγκυρους usernames.

### Knowing one or several usernames

Εντάξει, ξέρετε ότι έχετε ήδη ένα έγκυρο username αλλά δεν έχετε passwords... Τότε δοκιμάστε:

- [**ASREPRoast**](asreproast.md): Αν ένας χρήστης **δεν έχει** το attribute _DONT_REQ_PREAUTH_ μπορείτε να **request a AS_REP message** για αυτόν τον χρήστη που θα περιέχει κάποια δεδομένα κρυπτογραφημένα από μια παράγωγο του password του χρήστη.
- [**Password Spraying**](password-spraying.md): Δοκιμάστε τα πιο **συνηθισμένα passwords** με καθένα από τους ανακαλυφθέντες users, ίσως κάποιος χρήστης χρησιμοποιεί ένα κακό password (να έχετε υπόψη σας το password policy!).
- Σημειώστε ότι μπορείτε επίσης να **spray OWA servers** για να προσπαθήσετε να αποκτήσετε πρόσβαση στους mail servers των χρηστών.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ίσως μπορέσετε να **αποκτήσετε** κάποια challenge **hashes** για να τα crackάρετε με το **poisoning** κάποιων πρωτοκόλλων του **δικτύου**:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Αν καταφέρετε να enumerάρετε την Active Directory θα έχετε **περισσότερα emails και μια καλύτερη κατανόηση του δικτύου**. Μπορεί να καταφέρετε να αναγκάσετε NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) για να αποκτήσετε πρόσβαση στο AD env.

### Steal NTLM Creds

Αν μπορείτε να **έχετε πρόσβαση σε άλλους PCs ή shares** με τον **null or guest user** θα μπορούσατε να **τοποθετήσετε αρχεία** (όπως ένα SCF file) που αν ανοιχτούν με κάποιο τρόπο θα **εξαπολύσουν μια NTLM authentication εναντίον σας** ώστε να μπορείτε να **κλέψετε** το **NTLM challenge** για να το crackάρετε:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Για αυτή τη φάση χρειάζεται να έχετε **compromised τα credentials ή μια session ενός έγκυρου domain account.** Αν έχετε κάποια έγκυρα credentials ή ένα shell ως domain user, **να θυμάστε ότι οι επιλογές που δόθηκαν πριν παραμένουν επιλογές για να compromisetάτε άλλους users**.

Πριν ξεκινήσετε την authenticated enumeration θα πρέπει να ξέρετε τι είναι το **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Το να έχετε compromised έναν λογαριασμό είναι ένα **μεγάλο βήμα για να ξεκινήσετε να compromisete ολόκληρο το domain**, γιατί θα μπορείτε να ξεκινήσετε την **Active Directory Enumeration:**

Αναφορικά με [**ASREPRoast**](asreproast.md) τώρα μπορείτε να βρείτε κάθε πιθανό ευάλωτο χρήστη, και αναφορικά με [**Password Spraying**](password-spraying.md) μπορείτε να πάρετε μια **λίστα όλων των usernames** και να δοκιμάσετε το password του compromised account, κενά passwords και νέα ελπιδοφόρα passwords.

- Μπορείτε να χρησιμοποιήσετε το [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Μπορείτε επίσης να χρησιμοποιήσετε [**powershell for recon**](../basic-powershell-for-pentesters/index.html) που θα είναι πιο stealthy
- Μπορείτε επίσης να [**use powerview**](../basic-powershell-for-pentesters/powerview.md) για να εξάγετε πιο λεπτομερείς πληροφορίες
- Ένα ακόμα εξαιρετικό εργαλείο για recon σε Active Directory είναι το [**BloodHound**](bloodhound.md). Δεν είναι **πολύ stealthy** (ανάλογα με τις μεθόδους συλλογής που θα χρησιμοποιήσετε), αλλά **αν δεν σας νοιάζει** για αυτό, αξίζει σίγουρα μια δοκιμή. Βρείτε που οι users μπορούν να κάνουν RDP, βρείτε paths προς άλλες ομάδες, κλπ.
- **Άλλα αυτοματοποιημένα εργαλεία AD enumeration είναι:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) καθώς μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες.
- Ένα **εργαλείο με GUI** που μπορείτε να χρησιμοποιήσετε για να enumerάρετε τον directory είναι το **AdExplorer.exe** από τη **SysInternal** Suite.
- Μπορείτε επίσης να κάνετε αναζήτηση στη LDAP βάση με **ldapsearch** για να ψάξετε για credentials στα πεδία _userPassword_ & _unixUserPassword_, ή ακόμα και στο _Description_. βλ. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) για άλλες μεθόδους.
- Αν χρησιμοποιείτε **Linux**, μπορείτε επίσης να enumerάρετε το domain χρησιμοποιώντας [**pywerview**](https://github.com/the-useless-one/pywerview).
- Μπορείτε επίσης να δοκιμάσετε αυτοματοποιημένα εργαλεία όπως:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Είναι πολύ εύκολο να λάβετε όλα τα domain usernames από τα Windows (`net user /domain` ,`Get-DomainUser` ή `wmic useraccount get name,sid`). Σε Linux, μπορείτε να χρησιμοποιήσετε: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ή `enum4linux -a -u "user" -p "password" <DC IP>`

> Ακόμα και αν αυτή η ενότητα Enumeration φαίνεται μικρή, είναι το πιο σημαντικό μέρος από όλα. Επισκεφτείτε τους συνδέσμους (κυρίως αυτούς για cmd, powershell, powerview και BloodHound), μάθετε πώς να enumerάρετε ένα domain και εξασκηθείτε μέχρι να νιώσετε άνετα. Κατά τη διάρκεια μιας αξιολόγησης, αυτή θα είναι η κρίσιμη στιγμή για να βρείτε τον δρόμο σας προς DA ή για να αποφασίσετε ότι δεν μπορεί να γίνει τίποτα.

### Kerberoast

Kerberoasting περιλαμβάνει την απόκτηση **TGS tickets** που χρησιμοποιούνται από services συνδεδεμένα με user accounts και το cracking της κρυπτογράφησής τους — η οποία βασίζεται στα user passwords — **offline**.

Περισσότερα για αυτό στο:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Μόλις αποκτήσετε κάποια credentials μπορείτε να ελέγξετε αν έχετε πρόσβαση σε κάποια **μηχανή**. Για αυτό το σκοπό, μπορείτε να χρησιμοποιήσετε το **CrackMapExec** για να επιχειρήσετε σύνδεση σε πολλούς servers με διαφορετικά πρωτόκολλα, ανάλογα με τα port scans σας.

### Local Privilege Escalation

Αν έχετε compromised credentials ή μια session ως κανονικός domain user και έχετε **πρόσβαση** με αυτόν τον χρήστη σε **οποιαδήποτε μηχανή στο domain** θα πρέπει να προσπαθήσετε να βρείτε τρόπο να escalάρετε δικαιώματα τοπικά και να ψάξετε για credentials. Αυτό επειδή μόνο με local administrator privileges θα μπορείτε να **dump hashes** άλλων χρηστών από τη μνήμη (LSASS) και τοπικά (SAM).

Υπάρχει μια ολοκληρωμένη σελίδα σε αυτό το βιβλίο για [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) και ένα [**checklist**](../checklist-windows-privilege-escalation.md). Επίσης, μην ξεχάσετε να χρησιμοποιήσετε [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Είναι πολύ **απίθανο** να βρείτε **tickets** στον τρέχοντα χρήστη που να σας δίνουν άδεια να αποκτήσετε πρόσβαση σε απροσδόκητους πόρους, αλλά μπορείτε να ελέγξετε:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **περισσότερα emails και καλύτερη κατανόηση του δικτύου**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Now that you have some basic credentials you should check if you can **βρείτε** any **ενδιαφέροντα αρχεία που μοιράζονται μέσα στο AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεψε σε οποιοδήποτε επαληθευμένο χρήστη να **παραβιάσει τον domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Για τις ακόλουθες τεχνικές ένας συνηθισμένος domain user δεν αρκεί — χρειάζεστε κάποια ειδικά privileges/credentials για να εκτελέσετε αυτές τις επιθέσεις.**

### Hash extraction

Ελπίζουμε ότι καταφέρατε να **παραβιάσετε κάποιον local admin** λογαριασμό χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Στη συνέχεια, είναι ώρα να κάνετε dump όλα τα hashes από τη μνήμη και τοπικά.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Αν έχετε το **hash** ή το **password** ενός **local administrato**r, θα πρέπει να προσπαθήσετε να **login locally** σε άλλους **PCs** με αυτό.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **θορυβώδες** και το **LAPS** θα το **μειώσει**.

### MSSQL Abuse & Trusted Links

Αν ένας χρήστης έχει προνόμια για **access MSSQL instances**, μπορεί να το χρησιμοποιήσει για να **execute commands** στον MSSQL host (αν τρέχει ως SA), να **steal** το NetNTLM **hash** ή ακόμα και να εκτελέσει μια **relay** **attack**.\
Επίσης, αν μια MSSQL instance εμπιστεύεται (database link) μια διαφορετική MSSQL instance. Αν ο χρήστης έχει δικαιώματα στην trusted database, θα μπορεί να **use the trust relationship to execute queries also in the other instance**. Αυτές οι εμπιστοσύνες μπορούν να αλυσιδωθούν και σε κάποιο σημείο ο χρήστης ίσως βρει μια λάθος ρυθμισμένη βάση όπου μπορεί να εκτελέσει εντολές.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites συχνά αποκαλύπτουν ισχυρές διαδρομές προς credentials και code execution. Δείτε:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Αν βρείτε οποιοδήποτε Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε domain privileges στον υπολογιστή, θα μπορείτε να κάνετε dump TGTs από τη μνήμη κάθε χρήστη που κάνει login στον υπολογιστή.\
Έτσι, εάν ένας **Domain Admin logins onto the computer**, θα μπορείτε να κάνετε dump το TGT του και να τον μιμηθείτε χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στην constrained delegation θα μπορούσατε ακόμα και να **automatically compromise a Print Server** (ελπίζουμε να είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας χρήστης ή υπολογιστής έχει επιτρέψει "Constrained Delegation" θα μπορεί να **impersonate any user to access some services in a computer**.\
Τότε, αν **compromise the hash** αυτού του χρήστη/υπολογιστή θα μπορείτε να **impersonate any user** (ακόμα και domain admins) για να αποκτήσετε πρόσβαση σε κάποια services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Το να έχετε **WRITE** προνόμιο σε ένα Active Directory object ενός απομακρυσμένου υπολογιστή επιτρέπει την επίτευξη code execution με **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ο συμβιβασμένος χρήστης μπορεί να έχει μερικά **interesting privileges over some domain objects** που θα σας επιτρέψουν να **move** lateral/**escalate** privileges αργότερα.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Η ανακάλυψη μιας **Spool service listening** μέσα στο domain μπορεί να **be abused** για να **acquire new credentials** και να **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Αν **other users** **access** τη **compromised** μηχανή, είναι πιθανό να **gather credentials from memory** και ακόμα να **inject beacons in their processes** για να τους μιμηθείτε.\
Συνήθως οι χρήστες θα έχουν πρόσβαση μέσω RDP, οπότε εδώ έχετε πώς να εκτελέσετε μερικές επιθέσεις πάνω σε third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα για τη διαχείριση του **local Administrator password** σε domain-joined computers, διασφαλίζοντας ότι είναι **randomized**, μοναδικό και συχνά **changed**. Αυτοί οι κωδικοί αποθηκεύονται σε Active Directory και η πρόσβαση ελέγχεται μέσω ACLs σε εξουσιοδοτημένους χρήστες μόνο. Με επαρκή δικαιώματα για πρόσβαση σε αυτούς τους κωδικούς, το pivoting προς άλλους υπολογιστές γίνεται δυνατό.

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Το **gathering certificates** από τη συμβιβασμένη μηχανή θα μπορούσε να είναι ένας τρόπος για **escalate privileges** μέσα στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Αν υπάρχουν **vulnerable templates** ρυθμισμένα, είναι δυνατό να τα καταχραστείτε για να αυξήσετε προνόμια:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Μόλις αποκτήσετε **Domain Admin** ή ακόμα καλύτερα **Enterprise Admin** προνόμια, μπορείτε να **dump** τη **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Μερικές από τις τεχνικές που συζητήθηκαν νωρίτερα μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα μπορείτε:

- Να κάνετε χρήστες ευάλωτους σε [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Να κάνετε χρήστες ευάλωτους σε [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Να δώσετε [**DCSync**](#dcsync) privileges σε έναν χρήστη

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Η **Silver Ticket attack** δημιουργεί ένα **legitimate Ticket Granting Service (TGS) ticket** για ένα συγκεκριμένο service χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash of the PC account**). Αυτή η μέθοδος χρησιμοποιείται για να **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Μια **Golden Ticket attack** περιλαμβάνει έναν επιτιθέμενο που αποκτά πρόσβαση στο **NTLM hash of the krbtgt account** σε ένα Active Directory (AD) περιβάλλον. Αυτός ο λογαριασμός είναι ειδικός επειδή χρησιμοποιείται για να υπογράφει όλα τα **Ticket Granting Tickets (TGTs)**, τα οποία είναι απαραίτητα για την αυθεντικοποίηση στο AD δίκτυο.

Μόλις ο επιτιθέμενος αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιλέξει (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά είναι σαν golden tickets που πλαστογραφούνται με τρόπο που **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Το **having certificates of an account or being able to request them** είναι ένας πολύ καλός τρόπος για να παραμείνετε persist στο λογαριασμό ενός χρήστη (ακόμα και αν αλλάξει ο κωδικός):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

Η **using certificates** είναι επίσης δυνατή για να παραμείνετε με υψηλά προνόμια μέσα στο domain:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το αντικείμενο **AdminSDHolder** στο Active Directory διασφαλίζει την ασφάλεια των **privileged groups** (όπως Domain Admins και Enterprise Admins) εφαρμόζοντας ένα πρότυπο **Access Control List (ACL)** σε αυτές τις ομάδες για να αποτρέψει μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να εκμεταλλευτεί· αν ένας επιτιθέμενος τροποποιήσει την ACL του AdminSDHolder για να δώσει πλήρη πρόσβαση σε έναν κοινό χρήστη, αυτός ο χρήστης αποκτά εκτεταμένο έλεγχο πάνω σε όλες τις privileged groups. Αυτό το μέτρο ασφάλειας, που προορίζεται να προστατεύει, μπορεί έτσι να γυρίσει εις βάρος, επιτρέποντας μη δικαιολογημένη πρόσβαση εκτός αν παρακολουθείται στενά.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Σε κάθε **Domain Controller (DC)** υπάρχει ένας **local administrator** λογαριασμός. Αποκτώντας admin rights σε μια τέτοια μηχανή, το local Administrator hash μπορεί να εξαχθεί χρησιμοποιώντας **mimikatz**. Στη συνέχεια απαιτείται μια τροποποίηση στο registry για να **enable the use of this password**, επιτρέποντας απομακρυσμένη πρόσβαση στον local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Μπορείτε να **δώσετε** μερικά **special permissions** σε έναν **user** πάνω σε συγκεκριμένα domain objects που θα επιτρέψουν στον χρήστη να **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Τα **security descriptors** χρησιμοποιούνται για να **store** τα **permissions** που ένα **object** έχει **over** ένα **object**. Αν μπορείτε να κάνετε μια **μικρή αλλαγή** στο **security descriptor** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα προνόμια πάνω σε αυτό το αντικείμενο χωρίς να χρειάζεται να είστε μέλος μιας privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Τροποποιήστε **LSASS** στη μνήμη για να ορίσετε έναν **universal password**, παρέχοντας πρόσβαση σε όλους τους domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **own SSP** σας για να **capture** σε **clear text** τα **credentials** που χρησιμοποιούνται για πρόσβαση στη μηχανή.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταχωρεί έναν **new Domain Controller** στο AD και τον χρησιμοποιεί για να **push attributes** (SIDHistory, SPNs...) σε καθορισμένα αντικείμενα **without** να αφήνει logs σχετικά με τις **modifications**. Χρειάζεστε DA privileges και να είστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λάθος δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Νωρίτερα συζητήσαμε πώς να αυξήσετε προνόμια αν έχετε **enough permission to read LAPS passwords**. Ωστόσο, αυτοί οι κωδικοί μπορούν επίσης να χρησιμοποιηθούν για **maintain persistence**.\
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως το security boundary. Αυτό σημαίνει ότι **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφάλειας που επιτρέπει σε έναν χρήστη από ένα **domain** να αποκτήσει πρόσβαση σε πόρους σε ένα άλλο **domain**. Ουσιαστικά δημιουργεί έναν σύνδεσμο ανάμεσα στα authentication systems των δύο domains, επιτρέποντας την ομαλή ροή των επαληθεύσεων αυθεντικοποίησης. Όταν τα domains ρυθμίζουν ένα trust, ανταλλάσσουν και διατηρούν συγκεκριμένα **keys** μέσα στους **Domain Controllers (DCs)** τους, που είναι κρίσιμα για την ακεραιότητα της εμπιστοσύνης.

Σε ένα τυπικό σενάριο, αν ένας χρήστης θέλει να έχει πρόσβαση σε ένα service σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket γνωστό ως **inter-realm TGT** από το DC του δικού του domain. Αυτό το TGT κρυπτογραφείται με ένα κοινό **key** που και τα δύο domains έχουν συμφωνήσει. Ο χρήστης στη συνέχεια παρουσιάζει αυτό το TGT στο **DC of the trusted domain** για να πάρει ένα service ticket (**TGS**). Μετά την επιτυχή επαλήθευση του inter-realm TGT από το DC του trusted domain, αυτό εκδίδει ένα TGS, δίνοντας στον χρήστη πρόσβαση στο service.

**Βήματα**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από τον **Domain Controller (DC1)** του.
2. Το DC1 εκδίδει ένα νέο TGT αν ο client αυθεντικοποιηθεί επιτυχώς.
3. Ο client ζητά ένα **inter-realm TGT** από το DC1, το οποίο είναι απαραίτητο για πρόσβαση σε πόρους στο **Domain 2**.
4. Το inter-realm TGT κρυπτογραφείται με ένα **trust key** κοινό μεταξύ DC1 και DC2 ως μέρος της two-way domain trust.
5. Ο client παίρνει το inter-realm TGT στο **Domain 2's Domain Controller (DC2)**.
6. Το DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το κοινό trust key και, αν είναι έγκυρο, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 που ο client θέλει να προσπελάσει.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, το οποίο είναι κρυπτογραφημένο με το account hash του server, για να αποκτήσει πρόσβαση στο service στο Domain 2.

### Different trusts

Είναι σημαντικό να σημειωθεί ότι **a trust can be 1 way or 2 ways**. Στην επιλογή 2 ways, και τα δύο domains θα εμπιστεύονται το ένα το άλλο, αλλά στη **1 way** trust σχέση ένα από τα domains θα είναι το **trusted** και το άλλο το **trusting** domain. Στη δεύτερη περίπτωση, **you will only be able to access resources inside the trusting domain from the trusted one**.

Αν Domain A trusts Domain B, το A είναι το trusting domain και το B το trusted. Επιπλέον, στο **Domain A**, αυτό θα είναι ένα **Outbound trust**· και στο **Domain B**, αυτό θα είναι ένα **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Συνήθης ρύθμιση εντός του ίδιου forest, όπου ένα child domain έχει αυτόματα μια two-way transitive trust με το parent domain. Ουσιαστικά αυτό σημαίνει ότι τα authentication requests μπορούν να ρέουν ομαλά μεταξύ του parent και του child.
- **Cross-link Trusts**: Αναφέρονται ως "shortcut trusts", αυτές δημιουργούνται μεταξύ child domains για να επιταχύνουν τις διαδικασίες referral. Σε πολύπλοκα forests, οι authentication referrals συνήθως πρέπει να ταξιδέψουν έως τη ρίζα του forest και μετά να κατέβουν στο target domain. Δημιουργώντας cross-links, η διαδρομή μειώνεται, κάτι που είναι ιδιαίτερα χρήσιμο σε γεωγραφικά διασκορπισμένα περιβάλλοντα.
- **External Trusts**: Αυτές ρυθμίζονται μεταξύ διαφορετικών, μη σχετιζόμενων domains και είναι από τη φύση τους non-transitive. Σύμφωνα με την [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για πρόσβαση σε πόρους σε ένα domain έξω από το τρέχον forest που δεν είναι συνδεδεμένο μέσω forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτές οι trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός νεοπροστιθέμενου tree root. Αν και δεν συναντώνται συχνά, οι tree-root trusts είναι σημαντικές για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρήσουν ένα μοναδικό domain name και εξασφαλίζοντας two-way transitivity. Περισσότερες πληροφορίες υπάρχουν στο [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι μια two-way transitive trust μεταξύ δύο forest root domains, επίσης επιβάλλοντας SID filtering για να ενισχύσει τα μέτρα ασφάλειας.
- **MIT Trusts**: Αυτές οι trusts δημιουργούνται με non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Οι MIT trusts είναι λίγο πιο εξειδικευμένες και προσανατολίζονται σε περιβάλλοντα που απαιτούν ενσωμάτωση με Kerberos-based συστήματα εκτός του Windows οικοσυστήματος.

#### Other differences in **trusting relationships**

- Μια trust relationship μπορεί επίσης να είναι **transitive** (A trust B, B trust C, τότε A trust C) ή **non-transitive**.
- Μια trust relationship μπορεί να ρυθμιστεί ως **bidirectional trust** (και τα δύο εμπιστεύονται το ένα το άλλο) ή ως **one-way trust** (μόνο ένα εμπιστεύεται το άλλο).

### Attack Path

1. **Enumerate** τις trusting relationships
2. Έλεγχος αν οποιοδήποτε **security principal** (user/group/computer) έχει **access** σε πόρους του **other domain**, ίσως μέσω ACE entries ή μέσω συμμετοχής σε groups του άλλου domain. Ψάξτε για **relationships across domains** (η trust πιθανώς δημιουργήθηκε γι' αυτό).
1. kerberoast σε αυτή την περίπτωση θα μπορούσε να είναι μια άλλη επιλογή.
3. **Compromise** τους **accounts** που μπορούν να **pivot** μέσω των domains.

Οι επιτιθέμενοι μπορούν να έχουν πρόσβαση σε πόρους σε άλλο domain μέσω τριών κύριων μηχανισμών:

- **Local Group Membership**: Principals μπορεί να προστεθούν σε τοπικές ομάδες σε μηχανές, όπως η ομάδα “Administrators” σε έναν server, παρέχοντάς τους σημαντικό έλεγχο πάνω σε αυτή τη μηχανή.
- **Foreign Domain Group Membership**: Principals μπορούν επίσης να είναι μέλη groups εντός του foreign domain. Ωστόσο, η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση της trust και το scope της group.
- **Access Control Lists (ACLs)**: Principals μπορεί να αναφέρονται σε ένα **ACL**, ιδιαίτερα ως οντότητες σε **ACEs** μέσα σε ένα **DACL**, παρέχοντάς τους πρόσβαση σε συγκεκριμένους πόρους. Για όσους θέλουν να εμβαθύνουν στους μηχανισμούς των ACLs, DACLs και ACEs, το whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” είναι πολύτιμος πόρος.

### Find external users/groups with permissions

Μπορείτε να ελέγξετε **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να βρείτε foreign security principals στο domain. Αυτοί θα είναι χρήστες/groups από **an external domain/forest**.

Μπορείτε να το ελέγξετε αυτό σε **Bloodhound** ή χρησιμοποιώντας powerview:
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
> Υπάρχουν **2 trusted keys**, μία για _Child --> Parent_ και άλλη για _Parent_ --> _Child_.\
> Μπορείτε να δείτε ποια χρησιμοποιείται από το τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ανεβάστε προνόμια σε Enterprise admin στο child/parent domain εκμεταλλευόμενοι τη σχέση trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Είναι κρίσιμο να κατανοήσετε πώς μπορεί να εκμεταλλευτεί το Configuration Naming Context (NC). Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο για δεδομένα διαμόρφωσης σε ένα forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα αναπαράγονται σε κάθε Domain Controller (DC) μέσα στο forest, με τους writable DCs να διατηρούν μια εγγράψιμη αντιγραφή του Configuration NC. Για να το εκμεταλλευτείτε, απαιτούνται **SYSTEM privileges on a DC**, κατά προτίμηση σε child DC.

**Link GPO to root DC site**

Το container Sites του Configuration NC περιλαμβάνει πληροφορίες σχετικά με τα sites όλων των domain-joined computers μέσα στο AD forest. Λειτουργώντας με SYSTEM privileges σε οποιονδήποτε DC, οι επιτιθέμενοι μπορούν να συνδέσουν GPOs στα root DC sites. Αυτή η ενέργεια ενδέχεται να θέσει σε κίνδυνο το root domain χειραγωγώντας τις πολιτικές που εφαρμόζονται σε αυτά τα sites.

Για πιο λεπτομερείς πληροφορίες, μπορείτε να εξερευνήσετε την έρευνα για [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Ένας φορέας επίθεσης αφορά το στόχευσμα privileged gMSAs εντός του domain. Το KDS Root key, απαραίτητο για τον υπολογισμό των κωδικών των gMSAs, αποθηκεύεται στο Configuration NC. Με SYSTEM privileges σε οποιονδήποτε DC, είναι δυνατόν να αποκτήσετε πρόσβαση στο KDS Root key και να υπολογίσετε τους κωδικούς για οποιοδήποτε gMSA σε όλο το forest.

Λεπτομερείς αναλύσεις και βήμα-βήμα οδηγίες υπάρχουν στο:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Συμπληρωματική delegated MSA επίθεση (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Επιπρόσθετη εξωτερική έρευνα: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Αυτή η μέθοδος απαιτεί υπομονή, περιμένοντας τη δημιουργία νέων privileged AD objects. Με SYSTEM privileges, ένας επιτιθέμενος μπορεί να τροποποιήσει το AD Schema για να χορηγήσει σε οποιονδήποτε χρήστη πλήρη έλεγχο σε όλες τις κλάσεις. Αυτό μπορεί να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο των νεοδημιουργηθέντων AD objects.

Περισσότερα μπορείτε να διαβάσετε στο [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει στον έλεγχο αντικειμένων της Public Key Infrastructure (PKI) για τη δημιουργία ενός certificate template που επιτρέπει authentication ως οποιοσδήποτε χρήστης εντός του forest. Καθώς τα PKI objects βρίσκονται στο Configuration NC, ο συμβιβασμός ενός writable child DC επιτρέπει την εκτέλεση ESC5 attacks.

Για περισσότερες λεπτομέρειες δείτε [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Σε περιπτώσεις απουσίας ADCS, ο επιτιθέμενος έχει τη δυνατότητα να δημιουργήσει τα απαραίτητα components, όπως συζητείται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Σε αυτό το σενάριο **το domain σας εμπιστεύεται** ένα external domain, δίνοντάς σας **απροσδιόριστα permissions** επ' αυτού. Θα χρειαστεί να βρείτε **ποιοι principals του domain σας έχουν ποια access επί του external domain** και στη συνέχεια να προσπαθήσετε να το exploit:

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
Σε αυτό το σενάριο το **domain σας** εμπιστεύεται κάποια **privileges** σε έναν **principal** από ένα **διαφορετικό domain**.

Ωστόσο, όταν ένα **domain is trusted** από το trusting domain, το trusted domain **creates a user** με ένα **predictable name** που χρησιμοποιεί ως **password the trusted password**. Αυτό σημαίνει ότι είναι δυνατόν να **access a user from the trusting domain to get inside the trusted one** για να το αναγνωρίσουμε και να προσπαθήσουμε να ανεβάσουμε περισσότερα προνόμια:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Μια άλλη μέθοδος για να compromize το trusted domain είναι να βρεθεί ένας [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί στην **opposite direction** της domain trust (κάτι που δεν είναι πολύ συνηθισμένο).

Μια άλλη μέθοδος για να compromize το trusted domain είναι να παραμείνει ο attacker σε μια μηχανή όπου ένας **user from the trusted domain can access** για να κάνει login μέσω **RDP**. Στη συνέχεια, ο attacker μπορεί να εισάγει κώδικα στη διαδικασία της RDP session και να **access the origin domain of the victim** από εκεί.\
Επιπλέον, αν ο **victim mounted his hard drive**, από τη διαδικασία της **RDP session** ο attacker θα μπορούσε να αποθηκεύσει **backdoors** στο **startup folder of the hard drive**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που εκμεταλλεύονται το SID history attribute σε forest trusts μειώνεται από το SID Filtering, το οποίο είναι ενεργοποιημένο εξ ορισμού σε όλες τις inter-forest trusts. Αυτό βασίζεται στην υπόθεση ότι οι intra-forest trusts είναι ασφαλείς, θεωρώντας το forest — αντί για το domain — ως το όριο ασφάλειας, σύμφωνα με τη θέση της Microsoft.
- Ωστόσο, υπάρχει ένα πρόβλημα: το SID filtering μπορεί να διαταράξει εφαρμογές και πρόσβαση χρηστών, οδηγώντας μερικές φορές στην απενεργοποίησή του.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση του Selective Authentication διασφαλίζει ότι χρήστες από τα δύο forests δεν αυθεντικοποιούνται αυτόματα. Αντίθετα, απαιτούνται ρητές άδειες για να έχουν οι χρήστες πρόσβαση σε domains και servers εντός του trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του writable Configuration Naming Context (NC) ή επιθέσεις στον trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) επανυλοποιεί bloodyAD-style LDAP primitives ως x64 Beacon Object Files που τρέχουν εξ ολοκλήρου μέσα σε ένα on-host implant (π.χ., Adaptix C2). Οι operators κάνουν compile το πακέτο με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν `ldap.axs`, και μετά καλούν `ldap <subcommand>` από το beacon. Όλη η κίνηση χρησιμοποιεί το τρέχον logon security context πάνω από LDAP (389) με signing/sealing ή LDAPS (636) με auto certificate trust, οπότε δεν απαιτούνται socks proxies ή disk artifacts.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` επιλύουν short names/OU paths σε πλήρη DNs και κάνoυν dump τα αντίστοιχα objects.
- `get-object`, `get-attribute`, and `get-domaininfo` τραβούν αυθαίρετα attributes (συμπεριλαμβανομένων security descriptors) καθώς και τα forest/domain metadata από το `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` αποκαλύπτουν roasting candidates, delegation settings, και υπάρχοντες [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors απευθείας από LDAP.
- `get-acl` και `get-writable --detailed` αναλύουν τη DACL για να απαριθμήσουν trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), και inheritance, δίνοντας άμεσα στόχους για ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives για escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον operator να τοποθετεί νέους principals ή machine accounts όπου υπάρχουν OU rights. `add-groupmember`, `set-password`, `add-attribute`, και `set-attribute` αρπάζουν απευθείας targets μόλις εντοπιστούν write-property rights.
- ACL-focused εντολές όπως `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, και `add-dcsync` μεταφράζουν WriteDACL/WriteOwner σε οποιοδήποτε AD object σε password resets, έλεγχο group membership, ή DCSync replication privileges χωρίς να αφήνουν PowerShell/ADSI artifacts. Τα αντίστοιχα `remove-*` καθαρίζουν τα injected ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` κάνουν άμεσα έναν compromised χρήστη Kerberoastable; `add-asreproastable` (UAC toggle) τον μαρκάρει για AS-REP roasting χωρίς να πειράξει το password.
- Τα delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) ξαναγράφουν `msDS-AllowedToDelegateTo`, UAC flags, ή `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, ενεργοποιώντας constrained/unconstrained/RBCD attack paths και εξαλείφοντας την ανάγκη για remote PowerShell ή RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` εγχέει privileged SIDs στο SID history ενός ελεγχόμενου principal (βλέπε [SID-History Injection](sid-history-injection.md)), παρέχοντας stealthy access inheritance πλήρως μέσω LDAP/LDAPS.
- `move-object` αλλάζει το DN/OU computers ή users, επιτρέποντας σε attacker να μεταφέρει assets σε OUs όπου υπάρχουν ήδη delegated rights πριν από την κατάχρηση `set-password`, `add-groupmember`, ή `add-spn`.
- Στενά scoped removal εντολές (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, κ.λπ.) επιτρέπουν γρήγορο rollback αφού ο operator συγκομίσει credentials ή persistence, ελαχιστοποιώντας telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Μερικές Γενικές Άμυνες

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Συνιστάται οι Domain Admins να επιτρέπεται να κάνουν login μόνο σε Domain Controllers, αποφεύγοντας τη χρήση τους σε άλλα hosts.
- **Service Account Privileges**: Services δεν πρέπει να τρέχουν με Domain Admin (DA) privileges για να διατηρηθεί η ασφάλεια.
- **Temporal Privilege Limitation**: Για εργασίες που απαιτούν DA privileges, πρέπει να περιορίζεται η διάρκεια τους. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Η υλοποίηση deception περιλαμβάνει τοποθέτηση παγίδων, όπως decoy users ή computers, με χαρακτηριστικά όπως passwords που δεν λήγουν ή είναι μαρκαρισμένα ως Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει δημιουργία χρηστών με συγκεκριμένα rights ή προσθήκη τους σε high privilege groups.
- Ένα πρακτικό παράδειγμα χρησιμοποιεί εργαλεία όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερα για την ανάπτυξη deception techniques στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Υποπτά indicators περιλαμβάνουν atypical ObjectSID, σπάνιες logons, creation dates, και χαμηλά bad password counts.
- **General Indicators**: Η σύγκριση attributes πιθανών decoy objects με εκείνα των πραγματικών μπορεί να αποκαλύψει ασυνέπειες. Εργαλεία όπως [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στην ανίχνευση τέτοιας deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Αποφυγή session enumeration σε Domain Controllers για να μην ενεργοποιηθεί ATA detection.
- **Ticket Impersonation**: Η χρήση aes keys για δημιουργία ticket βοηθά στην αποφυγή detection μη υποβαθμίζοντας σε NTLM.
- **DCSync Attacks**: Εκτέλεση από μη-Domain Controller συνιστάται για να αποφευχθεί ATA detection, καθώς άμεση εκτέλεση από Domain Controller θα προκαλέσει alerts.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
