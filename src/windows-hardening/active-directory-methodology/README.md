# Active Directory Μεθοδολογία

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

**Active Directory** λειτουργεί ως θεμελιώδης τεχνολογία, επιτρέποντας σε **διαχειριστές δικτύου** να δημιουργούν και να διαχειρίζονται αποδοτικά **domains**, **users** και **objects** μέσα σε ένα δίκτυο. Έχει σχεδιαστεί για κλιμάκωση, διευκολύνοντας την οργάνωση ενός μεγάλου αριθμού χρηστών σε διαχειρίσιμες **groups** και **subgroups**, ενώ ελέγχει τα **access rights** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία κύρια επίπεδα: **domains**, **trees**, και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή αντικειμένων, όπως **users** ή **devices**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι ομάδες αυτών των domains συνδεδεμένες με κοινή δομή, και ένα **forest** αντιπροσωπεύει τη συλλογή πολλαπλών trees, διασυνδεδεμένων μέσω **trust relationships**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Στο καθένα από αυτά τα επίπεδα μπορούν να οριστούν ειδικά δικαιώματα **access** και **communication rights**.

Κύριες έννοιες μέσα στο **Active Directory** περιλαμβάνουν:

1. **Directory** – Φιλοξενεί όλες τις πληροφορίες που αφορούν τα Active Directory objects.
2. **Object** – Δείχνει οντότητες μέσα στον directory, συμπεριλαμβανομένων **users**, **groups**, ή **shared folders**.
3. **Domain** – Υπηρετεί ως container για directory objects, με τη δυνατότητα πολλαπλά domains να συνυπάρχουν μέσα σε ένα **forest**, το καθένα διατηρώντας τη δική του συλλογή αντικειμένων.
4. **Tree** – Ομαδοποίηση domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Η κορυφή της οργανωτικής δομής στο Active Directory, αποτελούμενη από αρκετά trees με **trust relationships** μεταξύ τους.

**Active Directory Domain Services (AD DS)** περιλαμβάνει ένα σύνολο υπηρεσιών κρίσιμων για την κεντρική διαχείριση και την επικοινωνία μέσα σε ένα δίκτυο. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Κεντρικοποιεί την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **users** και **domains**, συμπεριλαμβανομένων των λειτουργιών **authentication** και **search**.
2. **Certificate Services** – Επιβλέπει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει εφαρμογές που αξιοποιούν directory μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για την πιστοποίηση χρηστών σε πολλαπλές web εφαρμογές σε μια ενιαία συνεδρία.
5. **Rights Management** – Βοηθά στην προστασία υλικού που διέπεται από πνευματικά δικαιώματα, ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση.
6. **DNS Service** – Κρίσιμο για την επίλυση **domain names**.

Για περισσότερη ανάλυση δείτε: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθετε πώς να **επιτίθεστε σε ένα AD** χρειάζεται να κατανοήσετε πολύ καλά τη διαδικασία **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Μπορείτε να ρίξετε μια ματιά στο [https://wadcoms.github.io/](https://wadcoms.github.io) για μια γρήγορη εικόνα των εντολών που μπορείτε να εκτελέσετε για να enumerate/exploit ένα AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Αν έχετε μόνο πρόσβαση σε ένα περιβάλλον AD αλλά δεν έχετε credentials/sessions, μπορείτε:

- **Pentest the network:**
- Σκανάρετε το δίκτυο, βρείτε μηχανήματα και ανοιχτές θύρες και προσπαθήστε να **exploit vulnerabilities** ή να **extract credentials** από αυτά (π.χ. [printers could be very interesting targets](ad-information-in-printers.md)).
- Η απογραφή του DNS μπορεί να δώσει πληροφορίες για βασικούς servers στο domain όπως web, printers, shares, vpn, media κ.λπ.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Ρίξτε μια ματιά στη Γενική [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνετε αυτό.
- **Check for null and Guest access on smb services** (αυτό δεν θα δουλέψει σε σύγχρονες εκδόσεις Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Ένας πιο λεπτομερής οδηγός για το πώς να enumerate έναν SMB server μπορεί να βρεθεί εδώ:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Ένας πιο λεπτομερής οδηγός για το πώς να enumerate LDAP μπορεί να βρεθεί εδώ (δώστε **ειδική προσοχή στην anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Συλλέξτε credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Πρόσβαση σε host εκμεταλλευόμενοι [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συλλέξτε credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξαγάγετε usernames/ονόματα από εσωτερικά έγγραφα, social media, υπηρεσίες (κυρίως web) εντός του domain περιβάλλοντος και επίσης από δημόσια διαθέσιμα.
- Αν βρείτε τα πλήρη ονόματα εργαζομένων της εταιρείας, μπορείτε να δοκιμάσετε διάφορες AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο κοινές συμβάσεις είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3 γράμματα από κάθε), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Εργαλεία:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Απαρίθμηση χρηστών

- **Anonymous SMB/LDAP enum:** Δείτε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητείται ένα **invalid username** ο server θα απαντήσει χρησιμοποιώντας τον **Kerberos error** κωδικό _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να προσδιορίσουμε ότι το username ήταν άκυρο. **Valid usernames** θα προκαλέσουν είτε το **TGT σε ένα AS-REP** response είτε το σφάλμα _KRB5KDC_ERR_PREAUTH_REQUIRED_, υποδεικνύοντας ότι ο χρήστης απαιτείται να εκτελέσει pre-authentication.
- **No Authentication against MS-NRPC**: Χρησιμοποιώντας auth-level = 1 (No authentication) απέναντι στην MS-NRPC (Netlogon) διεπαφή στους domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` μετά το binding της MS-NRPC διεπαφής για να ελέγξει αν ο χρήστης ή ο υπολογιστής υπάρχει χωρίς οποιαδήποτε credentials. Το εργαλείο [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτόν τον τύπο enumeration. Η έρευνα βρίσκεται [εδώ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Διακομιστής**

Αν βρήκατε έναν από αυτούς τους διακομιστές στο δίκτυο, μπορείτε επίσης να εκτελέσετε **user enumeration** εναντίον του. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

Εντάξει, γνωρίζεις ήδη έναν έγκυρο username αλλά δεν έχεις passwords... Τότε δοκίμασε:

- [**ASREPRoast**](asreproast.md): Αν ένας user **δεν έχει** το attribute _DONT_REQ_PREAUTH_ μπορείς να **αιτηθείς ένα AS_REP message** για αυτόν τον user που θα περιέχει δεδομένα κρυπτογραφημένα με παράγωγο του password του user.
- [**Password Spraying**](password-spraying.md): Δοκίμασε τα πιο **κοινά passwords** με κάθε έναν από τους ανακαλυφθέντες users, ίσως κάποιος χρήστης χρησιμοποιεί ένα κακό password (να θυμάσαι την password policy!).
- Σημείωση: μπορείς επίσης να **spray OWA servers** για να προσπαθήσεις να αποκτήσεις πρόσβαση στους mail servers των users.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Μπορεί να είσαι σε θέση να **αποκτήσεις** κάποια challenge **hashes** για να τα **crack-άρεις** μέσω poisoning κάποιων πρωτοκόλλων του **δικτύου**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Αν έχεις καταφέρει να enumerate το Active Directory θα έχεις **περισσότερα emails και καλύτερη κατανόηση του δικτύου**. Ίσως να μπορείς να αναγκάσεις NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) για να αποκτήσεις πρόσβαση στο AD env.

### Steal NTLM Creds

Αν μπορείς να **πρόσβασης σε άλλα PCs ή shares** με τον **null ή guest user** μπορείς να **τοποθετήσεις αρχεία** (π.χ. ένα SCF file) που αν πρόσβαμένος με κάποιο τρόπο θα **ενεργοποιήσουν μια NTLM authentication προς εσένα** ώστε να **κλέψεις** την **NTLM challenge** για να την crack-άρεις:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Για αυτή τη φάση χρειάζεται να έχεις **compromised τα credentials ή μια session ενός έγκυρου domain account.** Αν έχεις κάποια έγκυρα credentials ή ένα shell ως domain user, **πρέπει να θυμάσαι ότι οι επιλογές που αναφέρθηκαν πριν παραμένουν επιλογές για να compromize-άρεις άλλους users.**

Πριν ξεκινήσεις το authenticated enumeration πρέπει να γνωρίζεις τι είναι το **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Το να έχεις compromized έναν account είναι ένα **μεγάλο βήμα για να αρχίσεις να compromize-άρεις ολόκληρο το domain**, γιατί θα μπορείς να ξεκινήσεις την **Active Directory Enumeration:**

Σε σχέση με [**ASREPRoast**](asreproast.md) τώρα μπορείς να βρεις κάθε πιθανό ευάλωτο user, και σε σχέση με [**Password Spraying**](password-spraying.md) μπορείς να πάρεις μια **λίστα με όλα τα usernames** και να δοκιμάσεις το password του compromised account, κενά passwords και νέα υποσχόμενα passwords.

- Μπορείς να χρησιμοποιήσεις την [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Μπορείς επίσης να χρησιμοποιήσεις [**powershell for recon**](../basic-powershell-for-pentesters/index.html) που θα είναι πιο stealthy
- Μπορείς επίσης να [**use powerview**](../basic-powershell-for-pentesters/powerview.md) για να εξάγεις πιο λεπτομερείς πληροφορίες
- Ένα ακόμα καταπληκτικό εργαλείο για recon σε Active Directory είναι το [**BloodHound**](bloodhound.md). Δεν είναι **πολύ stealthy** (ανάλογα με τις μεθόδους συλλογής που χρησιμοποιείς), αλλά **αν δεν σε νοιάζει** αξίζει σίγουρα μια δοκιμή. Βρες που users μπορούν RDP, βρες paths προς άλλες groups, κ.λπ.
- **Άλλα αυτοματοποιημένα εργαλεία AD enumeration είναι:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) καθώς μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες.
- Ένα **GUI εργαλείο** που μπορείς να χρησιμοποιήσεις για να enumerate-άρεις τον directory είναι **AdExplorer.exe** από το **SysInternal** Suite.
- Μπορείς επίσης να αναζητήσεις στη βάση LDAP με **ldapsearch** για credentials σε fields _userPassword_ & _unixUserPassword_, ή ακόμα και για _Description_. βλ. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) για άλλες μεθόδους.
- Αν χρησιμοποιείς **Linux**, μπορείς επίσης να enumerate-άρεις το domain χρησιμοποιώντας [**pywerview**](https://github.com/the-useless-one/pywerview).
- Μπορείς επίσης να δοκιμάσεις αυτοματοποιημένα εργαλεία όπως:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Είναι πολύ εύκολο να πάρεις όλα τα domain usernames από Windows (`net user /domain` ,`Get-DomainUser` ή `wmic useraccount get name,sid`). Σε Linux, μπορείς να χρησιμοποιήσεις: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ή `enum4linux -a -u "user" -p "password" <DC IP>`

> Ακόμη και αν αυτή η ενότητα Enumeration φαίνεται μικρή, είναι το πιο σημαντικό κομμάτι από όλα. Μπες στους συνδέσμους (κυρίως αυτούς της cmd, powershell, powerview και BloodHound), μάθε πώς να enumerate-άρεις ένα domain και κάνε πρακτική μέχρι να νιώσεις άνετα. Κατά τη διάρκεια μιας αξιολόγησης, αυτή θα είναι η καθοριστική στιγμή για να βρεις το δρόμο προς DA ή για να αποφασίσεις ότι δεν μπορεί να γίνει τίποτα.

### Kerberoast

Kerberoasting περιλαμβάνει την απόκτηση **TGS tickets** που χρησιμοποιούνται από services δεμένα με user accounts και τη ραγίση (cracking) της κρυπτογράφησής τους — η οποία βασίζεται σε user passwords — **offline**.

Περισσότερα γι' αυτό εδώ:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Μόλις έχεις αποκτήσει κάποια credentials μπορείς να ελέγξεις αν έχεις πρόσβαση σε κάποια **μηχανή**. Για αυτό μπορείς να χρησιμοποιήσεις το **CrackMapExec** για να προσπαθήσεις σύνδεση σε πολλούς servers με διάφορα πρωτόκολλα, σύμφωνα με τα port scans σου.

### Local Privilege Escalation

Αν έχεις compromized credentials ή μια session ως κανονικός domain user και έχεις **πρόσβαση** με αυτόν τον user σε **οποιαδήποτε μηχανή στο domain**, πρέπει να προσπαθήσεις να βρεις τρόπο να **ανεβάσεις privileges τοπικά και να loot-άρεις για credentials**. Αυτό γιατί μόνο με local administrator privileges θα μπορέσεις να **dump-άς hashes άλλων users** στη μνήμη (LSASS) και τοπικά (SAM).

Υπάρχει μια ολοκληρωμένη σελίδα σε αυτό το βιβλίο για [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) και ένα [**checklist**](../checklist-windows-privilege-escalation.md). Επίσης, μην ξεχάσεις να χρησιμοποιήσεις [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Είναι πολύ **ασυνήθιστο** να βρεις **tickets** στον τρέχοντα user που να σου δίνουν άδεια για πρόσβαση σε απρόσμενους πόρους, αλλά μπορείς να ελέγξεις:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Αν καταφέρεις να εντοπίσεις το Active Directory θα έχεις **περισσότερα emails και καλύτερη κατανόηση του δικτύου**. Μπορεί να καταφέρεις να αναγκάσεις NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Αναζήτηση Creds σε Computer Shares | SMB Shares

Τώρα που έχεις μερικές βασικές credentials πρέπει να ελέγξεις αν μπορείς να **βρεις** οποιαδήποτε **ενδιαφέροντα αρχεία που κοινοποιούνται μέσα στο AD**. Μπορείς να το κάνεις χειροκίνητα αλλά είναι μια πολύ βαρετή και επαναλαμβανόμενη εργασία (και περισσότερο αν βρεις εκατοντάδες docs που πρέπει να ελέγξεις).

[**Ακολούθησε αυτό το σύνδεσμο για να μάθεις για τα εργαλεία που μπορείς να χρησιμοποιήσεις.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Αν μπορείς να **έχεις πρόσβαση σε άλλους PCs ή shares** μπορείς να **τοποθετήσεις αρχεία** (π.χ. ένα SCF file) που αν ανοιχτούν θα **προκαλέσουν ένα NTLM authentication εναντίον σου**, ώστε να μπορείς να **κλέψεις** το **NTLM challenge** για να το crackάρεις:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεπε σε οποιονδήποτε authenticated χρήστη να **αναλάβει τον έλεγχο του domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Ανάβαθμιση προνομίων στο Active Directory ΜΕ privileged credentials/session

**Για τις παρακάτω τεχνικές ένας απλός domain χρήστης δεν αρκεί — χρειάζεσαι ειδικά privileges/credentials για να εκτελέσεις αυτές τις επιθέσεις.**

### Hash extraction

Ελπίζουμε να κατάφερες να **παραβιάσεις κάποιο local admin** account χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (συμπεριλαμβανομένου relaying), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Στη συνέχεια, ήρθε η ώρα να κάνεις dump όλα τα hashes από τη μνήμη και τοπικά.  
[**Διάβασε αυτή τη σελίδα για διαφορετικούς τρόπους απόκτησης των hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις έχεις το hash ενός χρήστη**, μπορείς να το χρησιμοποιήσεις για να **υποδυθείς** αυτόν.  
Πρέπει να χρησιμοποιήσεις κάποιο **tool** που θα **εκτελέσει** την **NTLM authentication χρησιμοποιώντας** εκείνο το **hash**, **ή** μπορείς να δημιουργήσεις ένα νέο **sessionlogon** και να **εγχύσεις** εκείνο το **hash** μέσα στο **LSASS**, έτσι ώστε όταν πραγματοποιηθεί οποιαδήποτε **NTLM authentication**, εκείνο το **hash θα χρησιμοποιηθεί.** Η τελευταία επιλογή είναι αυτό που κάνει το mimikatz.  
[**Διάβασε αυτή τη σελίδα για περισσότερες πληροφορίες.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η επίθεση στοχεύει να **χρησιμοποιήσει το user NTLM hash για να ζητήσει Kerberos tickets**, ως εναλλακτική στην κοινή Pass The Hash μέσω NTLM πρωτοκόλλου. Επομένως, αυτό μπορεί να είναι ιδιαίτερα **χρήσιμο σε δίκτυα όπου το NTLM protocol είναι απενεργοποιημένο** και επιτρέπεται μόνο **Kerberos** ως πρωτόκολλο authentication.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στη μέθοδο επίθεσης **Pass The Ticket (PTT)**, οι επιτιθέμενοι **κλέβουν το authentication ticket ενός χρήστη** αντί για τον κωδικό ή τις τιμές hash. Το κλεμμένο ticket χρησιμοποιείται στη συνέχεια για να **υποδυθούν τον χρήστη**, αποκτώντας μη εξουσιοδοτημένη πρόσβαση σε πόρους και υπηρεσίες μέσα σε ένα δίκτυο.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Αν έχεις το **hash** ή το **password** ενός **local administrator** πρέπει να δοκιμάσεις να **συνδεθείς τοπικά** σε άλλους **PCs** με αυτό.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **θορυβώδες** και το **LAPS** θα το **μετριάσει**.

### MSSQL Abuse & Trusted Links

Αν ένας χρήστης έχει προνόμια να **προσπελάσει MSSQL instances**, θα μπορούσε να τα χρησιμοποιήσει για να **εκτελέσει εντολές** στον MSSQL host (αν τρέχει ως SA), να **κλέψει** το NetNTLM **hash** ή ακόμα και να πραγματοποιήσει μια **relay** **επίθεση**.\
Επίσης, αν μια MSSQL instance είναι trusted (database link) από μια διαφορετική MSSQL instance και ο χρήστης έχει προνόμια πάνω στην trusted βάση, θα μπορεί να **χρησιμοποιήσει τη σχέση εμπιστοσύνης για να εκτελέσει ερωτήματα και στην άλλη instance**. Αυτές οι εμπιστοσύνες μπορούν να αλυσοδεθούν και σε κάποιο σημείο ο χρήστης μπορεί να βρει μια λανθασμένα ρυθμισμένη βάση όπου μπορεί να εκτελέσει εντολές.\
**Οι σύνδεσμοι μεταξύ βάσεων δεδομένων λειτουργούν ακόμη και μέσω forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites συχνά εκθέτουν ισχυρά μονοπάτια προς credentials και code execution. Δείτε:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Αν βρείτε κάποιο Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε domain προνόμια στον υπολογιστή, θα μπορείτε να dumpάρετε TGTs από τη μνήμη κάθε χρήστη που κάνει login στον υπολογιστή.\
Έτσι, αν ένας **Domain Admin κάνει login στον υπολογιστή**, θα μπορείτε να dumpάρετε το TGT του και να τον impersonate χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στο constrained delegation θα μπορούσατε ακόμη και **αυτόματα να συμβιβάσετε έναν Print Server** (ελπίζοντας να είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας χρήστης ή υπολογιστής επιτρέπεται για "Constrained Delegation" θα μπορεί να **υποδυθεί οποιονδήποτε χρήστη για να προσπελάσει κάποιες υπηρεσίες σε έναν υπολογιστή**.\
Τότε, αν **συμβιβάσετε το hash** αυτού του χρήστη/υπολογιστή θα μπορείτε να **υποδυθείτε οποιονδήποτε χρήστη** (ακόμα και domain admins) για να προσπελάσετε κάποιες υπηρεσίες.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Η κατοχή **WRITE** προνομίου σε ένα Active Directory αντικείμενο ενός απομακρυσμένου υπολογιστή επιτρέπει την επίτευξη code execution με **ανυψωμένα προνόμια**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ο συμβιβασμένος χρήστης μπορεί να έχει κάποια **ενδιαφέροντα προνόμια πάνω σε κάποια domain objects** που θα μπορούσαν να σας επιτρέψουν να **μετακινηθείτε lateral/να ανεβάσετε προνόμια**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Η ανακάλυψη μιας **Spool service που ακούει** μέσα στο domain μπορεί να **κακοποιηθεί** για να **αποκτήσει νέες διαπιστευτήριες** και να **ανεβάσει προνόμια**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Αν **άλλοι χρήστες** **προσπελάζουν** το **συμβιβασμένο** μηχάνημα, είναι πιθανό να **συλλέξετε credentials από τη μνήμη** και ακόμα να **ενέχετε beacons στις διεργασίες τους** για να τους impersonate.\
Συνήθως οι χρήστες προσπελαύνουν το σύστημα μέσω RDP, οπότε εδώ έχετε πώς να πραγματοποιήσετε μερικές επιθέσεις πάνω σε τρίτες RDP συνεδρίες:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα για τη διαχείριση του **local Administrator password** σε domain-joined computers, διασφαλίζοντας ότι είναι **τυχαίο**, μοναδικό και συχνά **αλλαγμένο**. Αυτοί οι κωδικοί αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs μόνο σε εξουσιοδοτημένους χρήστες. Με επαρκή δικαιώματα για πρόσβαση σε αυτούς τους κωδικούς, γίνεται δυνατή η pivoting σε άλλους υπολογιστές.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Το **συλλέγειν certificates** από το συμβιβασμένο μηχάνημα θα μπορούσε να είναι ένας τρόπος για να ανεβάσετε προνόμια μέσα στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Αν **ευάλωτα templates** είναι ρυθμισμένα, είναι πιθανό να τα εκμεταλλευτείτε για να ανεβάσετε προνόμια:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Μόλις αποκτήσετε **Domain Admin** ή ακόμα καλύτερα **Enterprise Admin** προνόμια, μπορείτε να **dumpάρετε** τη **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Μερικές από τις τεχνικές που συζητήθηκαν προηγουμένως μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα μπορείτε να:

- Κάνετε χρήστες ευάλωτους στο [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Κάνετε χρήστες ευάλωτους στο [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Χορηγήσετε [**DCSync**](#dcsync) προνόμια σε έναν χρήστη

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Η **Silver Ticket attack** δημιουργεί ένα **νόμιμο Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη υπηρεσία χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash του PC account**). Αυτή η μέθοδος χρησιμοποιείται για να **προσπελάσει τα προνόμια της υπηρεσίας**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Μια **Golden Ticket attack** περιλαμβάνει έναν επιτιθέμενο να αποκτήσει πρόσβαση στο **NTLM hash του krbtgt account** σε ένα Active Directory (AD) περιβάλλον. Αυτός ο λογαριασμός είναι ειδικός διότι χρησιμοποιείται για την υπογραφή όλων των **Ticket Granting Tickets (TGTs)**, που είναι απαραίτητα για την αυθεντικοποίηση μέσα στο AD δίκτυο.

Μόλις ο επιτιθέμενος αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιλέξει (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά μοιάζουν με golden tickets που πλαστογραφούνται με τρόπο που **παρακάμπτει κοινούς μηχανισμούς ανίχνευσης golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Το **να έχετε certificates ενός account ή να μπορείτε να τα αιτηθείτε** είναι ένας πολύ καλός τρόπος για να επιμείνετε σε έναν χρήστη (ακόμα κι αν αλλάξει το password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Η χρήση certificates είναι επίσης δυνατή για να παραμείνετε με υψηλά προνόμια μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το αντικείμενο **AdminSDHolder** στο Active Directory εξασφαλίζει την ασφάλεια των **privileged groups** (όπως Domain Admins και Enterprise Admins) εφαρμόζοντας ένα τυποποιημένο **Access Control List (ACL)** σε αυτές τις ομάδες για να αποτρέψει μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να εκμεταλλευτεί· αν ένας επιτιθέμενος τροποποιήσει το ACL του AdminSDHolder ώστε να δώσει πλήρη πρόσβαση σε έναν απλό χρήστη, εκείνος ο χρήστης αποκτά εκτενή έλεγχο σε όλες τις privileged ομάδες. Αυτό το μέτρο ασφαλείας, που σκοπό έχει την προστασία, μπορεί επομένως να γυρίσει μπούμερανγκ, επιτρέποντας ανεπιθύμητη πρόσβαση εκτός αν παρακολουθείται στενά.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Σε κάθε **Domain Controller (DC)** υπάρχει ένας **local administrator** λογαριασμός. Αποκτώντας admin rights σε τέτοιο μηχάνημα, το hash του local Administrator μπορεί να εξαχθεί χρησιμοποιώντας **mimikatz**. Κατόπιν απαιτείται μια τροποποίηση στο registry για να **ενεργοποιηθεί η χρήση αυτού του κωδικού**, επιτρέποντας απομακρυσμένη πρόσβαση στον τοπικό Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Μπορείτε να **δώσετε** κάποια **ειδικά δικαιώματα** σε έναν **χρήστη** πάνω σε συγκεκριμένα domain objects που θα του επιτρέψουν να **ανεβάσει προνόμια στο μέλλον**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Οι **security descriptors** χρησιμοποιούνται για να **αποθηκεύουν** τα **permissions** που έχει ένα **αντικείμενο** πάνω σε ένα **αντικείμενο**. Αν μπορείτε απλά να **κάνετε** μια **μικρή αλλαγή** στον **security descriptor** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα προνόμια πάνω σε εκείνο το αντικείμενο χωρίς να χρειάζεται να είστε μέλος μιας privileged ομάδας.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Τροποποιήστε το **LSASS** στη μνήμη για να καθιερώσετε έναν **universal password**, δίνοντας πρόσβαση σε όλους τους domain λογαριασμούς.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **capture** σε **clear text** τα **credentials** που χρησιμοποιούνται για την πρόσβαση στη μηχανή.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταχωρεί έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **pushάρει attributes** (SIDHistory, SPNs...) σε συγκεκριμένα αντικείμενα **χωρίς** να αφήνει **logs** σχετικά με τις **τροποποιήσεις**. Χρειάζεστε DA προνόμια και να είστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να ανεβάσετε προνόμια αν έχετε **αρκετή άδεια να διαβάζετε LAPS passwords**. Ωστόσο, αυτοί οι κωδικοί μπορούν επίσης να χρησιμοποιηθούν για να **διατηρήσετε persistence**.\
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως το όριο ασφάλειας. Αυτό συνεπάγεται ότι **ο συμβιβασμός ενός μόνο domain θα μπορούσε ενδεχομένως να οδηγήσει στον συμβιβασμό ολόκληρου του Forest**.

### Basic Information

Ένα [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφάλειας που επιτρέπει σε έναν χρήστη από ένα **domain** να προσπελάσει πόρους σε ένα άλλο **domain**. Ουσιαστικά δημιουργεί μια σύνδεση μεταξύ των συστημάτων αυθεντικοποίησης των δύο domains, επιτρέποντας στη ροή επαληθεύσεων αυθεντικοποίησης να συμβεί ομαλά. Όταν τα domains δημιουργούν μια trust, ανταλλάσσουν και διατηρούν συγκεκριμένα **κλειδιά** μέσα στους **Domain Controllers (DCs)** τους, τα οποία είναι κρίσιμα για την ακεραιότητα της trust.

Σε ένα τυπικό σενάριο, αν ένας χρήστης θέλει να προσπελάσει μια υπηρεσία σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό tiket γνωστό ως **inter-realm TGT** από τον DC του δικού του domain. Αυτό το TGT είναι κρυπτογραφημένο με ένα κοινό **κλειδί** που και τα δύο domains έχουν συμφωνήσει. Ο χρήστης στη συνέχεια παρουσιάζει αυτό το TGT στον **DC του trusted domain** για να πάρει ένα service ticket (**TGS**). Μετά την επιτυχή επικύρωση του inter-realm TGT από τον DC του trusted domain, αυτός εκδίδει ένα TGS, χορηγώντας στον χρήστη πρόσβαση στην υπηρεσία.

**Βήματα**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από τον **Domain Controller (DC1)** του.
2. Ο DC1 εκδίδει ένα νέο TGT αν ο client αυθεντικοποιηθεί με επιτυχία.
3. Ο client ζητά έπειτα ένα **inter-realm TGT** από τον DC1, που είναι απαραίτητο για την πρόσβαση σε πόρους στο **Domain 2**.
4. Το inter-realm TGT είναι κρυπτογραφημένο με ένα **trust key** που μοιράζονται ο DC1 και ο DC2 ως μέρος της αμφίδρομης domain trust.
5. Ο client παίρνει το inter-realm TGT στον **Domain Controller (DC2)** του Domain 2.
6. Ο DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το κοινό trust key και, αν είναι έγκυρο, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 που ο client θέλει να προσπελάσει.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, που είναι κρυπτογραφημένο με το hash του account του server, για να αποκτήσει πρόσβαση στην υπηρεσία στο Domain 2.

### Different trusts

Είναι σημαντικό να σημειωθεί ότι **μια trust μπορεί να είναι μονόδρομη ή αμφίδρομη**. Στην επιλογή των 2 ways, και τα δύο domains θα εμπιστεύονται το ένα το άλλο, αλλά στη **1 way** σχέση εμπιστοσύνης το ένα από τα domains θα είναι το **trusted** και το άλλο το **trusting** domain. Στην τελευταία περίπτωση, **θα μπορείτε μόνο να προσπελάσετε πόρους μέσα στο trusting domain από το trusted**.

Αν το Domain A εμπιστεύεται το Domain B, το A είναι το trusting domain και το B είναι το trusted. Επιπλέον, στο **Domain A**, αυτό θα είναι ένα **Outbound trust**· και στο **Domain B**, αυτό θα είναι ένα **Inbound trust**.

**Διαφορετικές σχέσεις εμπιστοσύνης**

- **Parent-Child Trusts**: Αυτό είναι μια κοινή ρύθμιση εντός του ίδιου forest, όπου ένα child domain έχει αυτόματα μια αμφίδρομη transitive trust με το parent domain του. Ουσιαστικά, αυτό σημαίνει ότι τα αιτήματα αυθεντικοποίησης μπορούν να ρέουν ομαλά ανάμεσα στον parent και τον child.
- **Cross-link Trusts**: Αναφέρονται ως "shortcut trusts," και εγκαθίστανται μεταξύ child domains για να επισπεύσουν τις διαδικασίες αναφοράς. Σε πολύπλοκα forests, οι παραπομπές αυθεντικοποίησης συνήθως πρέπει να ταξιδέψουν μέχρι τη ρίζα του forest και μετά προς τα κάτω στο target domain. Δημιουργώντας cross-links, η διαδρομή συντομεύει, κάτι που είναι ιδιαίτερα χρήσιμο σε γεωγραφικά διασκορπισμένα περιβάλλοντα.
- **External Trusts**: Αυτές ρυθμίζονται μεταξύ διαφορετικών, μη σχετιζόμενων domains και είναι per φύση non-transitive. Σύμφωνα με την τεκμηρίωση της [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), οι external trusts είναι χρήσιμες για πρόσβαση σε πόρους σε ένα domain έξω από το τρέχον forest που δεν συνδέεται με forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτές οι trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και μιας νεοεισαχθείσας tree root. Αν και δεν συναντώνται συχνά, οι tree-root trusts είναι σημαντικές για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρούν ένα μοναδικό domain name και εξασφαλίζοντας αμφίδρομη transitivity. Περισσότερες πληροφορίες μπορείτε να βρείτε στον [οδηγό της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι μια αμφίδρομη transitive trust μεταξύ δύο forest root domains, επιβάλλοντας επίσης SID filtering για την ενίσχυση των μέτρων ασφαλείας.
- **MIT Trusts**: Αυτές οι trusts εγκαθίστανται με non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Οι MIT trusts είναι πιο εξειδικευμένες και απευθύνονται σε περιβάλλοντα που απαιτούν ενσωμάτωση με Kerberos-based συστήματα εκτός του Windows οικοσυστήματος.

#### Other differences in **trusting relationships**

- Μια σχέση trust μπορεί επίσης να είναι **transitive** (A trust B, B trust C, τότε A trust C) ή **non-transitive**.
- Μια σχέση trust μπορεί να ρυθμιστεί ως **bidirectional trust** (και οι δύο εμπιστεύονται ο ένας τον άλλον) ή ως **one-way trust** (μόνο ο ένας εμπιστεύεται τον άλλο).

### Attack Path

1. **Καταγράψτε** τις σχέσεις εμπιστοσύνης
2. Ελέγξτε αν κάποιος **security principal** (user/group/computer) έχει **πρόσβαση** σε πόρους του **άλλου domain**, ίσως μέσω ACE entries ή με το να είναι σε groups του άλλου domain. Ψάξτε για **σχέσεις ανάμεσα σε domains** (η trust δημιουργήθηκε πιθανώς γι' αυτό).
1. kerberoast σε αυτή την περίπτωση θα μπορούσε να είναι άλλη επιλογή.
3. **Συμβιβάστε** τους **λογαριασμούς** οι οποίοι μπορούν να **pivot** ανάμεσα στα domains.

Οι επιτιθέμενοι που έχουν πρόσβαση σε πόρους σε άλλο domain μπορούν να το κάνουν μέσω τριών κύριων μηχανισμών:

- **Local Group Membership**: Principals μπορεί να προστεθούν σε local groups σε μηχανήματα, όπως η “Administrators” group σε έναν server, δίνοντάς τους σημαντικό έλεγχο πάνω σε αυτό το μηχάνημα.
- **Foreign Domain Group Membership**: Principals μπορούν επίσης να είναι μέλη groups εντός του ξένου domain. Ωστόσο, η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση της trust και το scope του group.
- **Access Control Lists (ACLs)**: Principals μπορεί να δηλωθούν σε ένα **ACL**, ιδιαίτερα ως entities σε **ACEs** μέσα σε ένα **DACL**, παρέχοντάς τους πρόσβαση σε συγκεκριμένους πόρους. Για όσους θέλουν να εμβαθύνουν στους μηχανισμούς των ACLs, DACLs και ACEs, το whitepaper με τίτλο “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” είναι ανεκτίμητο πόρο.

### Find external users/groups with permissions

Μπορείτε να ελέγξετε **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να βρείτε foreign security principals στο domain. Αυτοί θα είναι χρήστες/groups από **ένα εξωτερικό domain/forest**.

Μπορείτε να ελέγξετε αυτό στο **Bloodhound** ή χρησιμοποιώντας το powerview:
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
Άλλοι τρόποι για να απαριθμήσετε domain trusts:
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
> Μπορείτε να δείτε ποια χρησιμοποιεί το τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ανεβάστε προνόμια ως Enterprise admin στο child/parent domain εκμεταλλευόμενοι το trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Η κατανόηση του πώς μπορεί να εκμεταλλευτεί το Configuration Naming Context (NC) είναι κρίσιμη. Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο για δεδομένα ρυθμίσεων σε ένα forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα αναπαράγονται σε κάθε Domain Controller (DC) εντός του forest, με τους writable DCs να διατηρούν ένα εγγράψιμο αντίγραφο του Configuration NC. Για να το εκμεταλλευτεί κανείς, πρέπει να έχει **SYSTEM privileges on a DC**, κατά προτίμηση σε child DC.

**Link GPO to root DC site**

Το Sites container του Configuration NC περιλαμβάνει πληροφορίες για τις τοποθεσίες όλων των domain-joined υπολογιστών εντός του AD forest. Χρησιμοποιώντας SYSTEM privileges σε οποιονδήποτε DC, οι επιτιθέμενοι μπορούν να συνδέσουν GPOs στις root DC sites. Αυτή η ενέργεια ενδέχεται να υπονομεύσει το root domain με την παραποίηση των πολιτικών που εφαρμόζονται σε αυτές τις τοποθεσίες.

Για λεπτομερείς πληροφορίες, μπορείτε να δείτε έρευνα για [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Ένας διεισδυτικός άξονας στοχεύει privileged gMSAs εντός του domain. Το KDS Root key, απαραίτητο για τον υπολογισμό των κωδικών των gMSAs, αποθηκεύεται στο Configuration NC. Με SYSTEM privileges σε οποιονδήποτε DC, είναι δυνατή η πρόσβαση στο KDS Root key και ο υπολογισμός των κωδικών για οποιοδήποτε gMSA σε όλο το forest.

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

Αυτή η μέθοδος απαιτεί υπομονή, αναμένοντας τη δημιουργία νέων privileged AD objects. Με SYSTEM privileges, ένας επιτιθέμενος μπορεί να τροποποιήσει το AD Schema για να χορηγήσει σε οποιονδήποτε χρήστη πλήρη έλεγχο σε όλες τις κλάσεις. Αυτό μπορεί να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο σε νεοδημιουργημένα AD objects.

Για περαιτέρω ανάγνωση δείτε [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Το ADCS ESC5 vulnerability στοχεύει τον έλεγχο πάνω σε Public Key Infrastructure (PKI) objects για να δημιουργήσει ένα certificate template που επιτρέπει authentication ως οποιοσδήποτε χρήστης εντός του forest. Καθώς τα PKI objects βρίσκονται στο Configuration NC, η παραβίαση ενός writable child DC επιτρέπει την εκτέλεση ESC5 attacks.

Περισσότερες λεπτομέρειες μπορείτε να διαβάσετε στο [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Σε σενάρια χωρίς ADCS, ο επιτιθέμενος έχει τη δυνατότητα να στήσει τα απαραίτητα components, όπως συζητείται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Σε αυτό το σενάριο **το domain σας εμπιστεύεται** από ένα εξωτερικό, δίνοντάς σας **απροσδιόριστες άδειες** πάνω σε αυτό. Θα χρειαστεί να βρείτε **ποιοι principals του domain σας έχουν ποια πρόσβαση στο εξωτερικό domain** και στη συνέχεια να προσπαθήσετε να τα εκμεταλλευτείτε:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Εξωτερικό Forest Domain - Μονομερές (Εξερχόμενο)
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

Ωστόσο, όταν ένα **domain is trusted** από το trusting domain, το trusted domain **creates a user** με ένα **predictable name** που χρησιμοποιεί ως **password the trusted password**. Αυτό σημαίνει ότι είναι δυνατό να **access a user from the trusting domain to get inside the trusted one** για να το καταγράψουμε (enumerate) και να προσπαθήσουμε να ανεβάσουμε περισσότερα privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος για να συμβιβαστεί το trusted domain είναι να βρεθεί ένας [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί στην **απευθείας αντίθετη κατεύθυνση** του domain trust (κάτι που δεν είναι πολύ κοινό).

Ένας άλλος τρόπος για να συμβιβαστεί το trusted domain είναι να περιμένει ο attacker σε μια μηχανή όπου ένας **user from the trusted domain can access** για να συνδεθεί μέσω **RDP**. Τότε, ο attacker θα μπορούσε να εισάγει κώδικα στη διεργασία της RDP session και να **access the origin domain of the victim** από εκεί.\
Επιπλέον, αν ο **victim mounted his hard drive**, από τη διεργασία της **RDP session** ο attacker θα μπορούσε να τοποθετήσει **backdoors** στον **startup folder of the hard drive**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Μείωση κατάχρησης domain trust

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που αξιοποιούν το SID history attribute σε forest trusts μειώνεται από το SID Filtering, το οποίο είναι ενεργοποιημένο από προεπιλογή σε όλα τα inter-forest trusts. Αυτό βασίζεται στην υπόθεση ότι τα intra-forest trusts είναι ασφαλή, θεωρώντας το forest, αντί για το domain, ως το όριο ασφάλειας σύμφωνα με τη θέση της Microsoft.
- Ωστόσο, υπάρχει ένα ζήτημα: το SID filtering μπορεί να διαταράξει εφαρμογές και πρόσβαση χρηστών, οδηγώντας σε περιστασιακή απενεργοποίησή του.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση του Selective Authentication εξασφαλίζει ότι οι χρήστες από τα δύο forests δεν πιστοποιούνται αυτόματα. Αντίθετα, απαιτούνται ρητές άδειες για να έχουν οι χρήστες πρόσβαση σε domains και servers εντός του trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του writable Configuration Naming Context (NC) ούτε από επιθέσεις στον trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Γενικά Μέτρα Άμυνας

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Αμυντικά Μέτρα για την Προστασία Διαπιστευτηρίων**

- **Domain Admins Restrictions**: Συνιστάται οι Domain Admins να επιτρέπεται να κάνουν login μόνο σε Domain Controllers, αποφεύγοντας τη χρήση τους σε άλλους hosts.
- **Service Account Privileges**: Οι υπηρεσίες δεν πρέπει να τρέχουν με Domain Admin (DA) προνόμια για να διατηρείται η ασφάλεια.
- **Temporal Privilege Limitation**: Για εργασίες που απαιτούν DA προνόμια, η διάρκεια τους θα πρέπει να είναι περιορισμένη. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Εφαρμογή τεχνικών Αποπλάνησης (Deception)**

- Η εφαρμογή deception περιλαμβάνει τη δημιουργία παγίδων, όπως decoy users ή computers, με χαρακτηριστικά όπως passwords που δεν λήγουν ή που είναι markάρισμενα ως Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία χρηστών με συγκεκριμένα δικαιώματα ή την προσθήκη τους σε ομάδες υψηλών προνομίων.
- Ένα πρακτικό παράδειγμα περιλαμβάνει τη χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερα για την ανάπτυξη deception τεχνικών μπορείτε να βρείτε στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Ανίχνευση Deception**

- **Για User Objects**: Ενδείξεις ύποπτης δραστηριότητας περιλαμβάνουν ασυνήθιστο ObjectSID, σπάνιες συνδέσεις (infrequent logons), ημερομηνίες δημιουργίας και χαμηλούς μετρητές bad password.
- **Γενικοί Δείκτες**: Η σύγκριση των attributes πιθανών decoy αντικειμένων με αυτά των πραγματικών μπορεί να αποκαλύψει ασυνέπειες. Εργαλεία όπως το [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στον εντοπισμό τέτοιων deception.

### **Παράκαμψη Συστημάτων Ανίχνευσης**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Αποφυγή enumeration συνεδριών σε Domain Controllers για να μην ενεργοποιηθεί το ATA.
- **Ticket Impersonation**: Η χρήση **aes** keys για τη δημιουργία ticket βοηθάει στην αποφυγή ανίχνευσης μην υποβαθμίζοντας σε NTLM.
- **DCSync Attacks**: Συνιστάται η εκτέλεση από μη-Domain Controller για να αποφευχθεί η ανίχνευση από ATA, καθώς η άμεση εκτέλεση από Domain Controller θα προκαλέσει ειδοποιήσεις.

## Αναφορές

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
