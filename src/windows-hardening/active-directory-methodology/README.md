# Active Directory Μεθοδολογία

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

**Active Directory** λειτουργεί ως θεμελιώδης τεχνολογία, επιτρέποντας στους **network administrators** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **domains**, **users**, και **objects** μέσα σε ένα δίκτυο. Έχει σχεδιαστεί για να κλιμακώνεται, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμες **groups** και **subgroups**, ενώ ελέγχει τα **access rights** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία κύρια επίπεδα: **domains**, **trees**, και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή αντικειμένων, όπως **users** ή **devices**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι ομάδες αυτών των domains που συνδέονται με κοινή δομή, και ένα **forest** αντιπροσωπεύει τη συλλογή πολλαπλών trees, διασυνδεδεμένων μέσω **trust relationships**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Συγκεκριμένα **access** και **communication rights** μπορούν να οριστούν σε κάθε ένα από αυτά τα επίπεδα.

Κύριες έννοιες εντός του **Active Directory** περιλαμβάνουν:

1. **Directory** – Περιέχει όλες τις πληροφορίες που αφορούν τα αντικείμενα του Active Directory.
2. **Object** – Αναφέρεται σε οντότητες μέσα στο directory, συμπεριλαμβανομένων **users**, **groups**, ή **shared folders**.
3. **Domain** – Λειτουργεί ως container για directory objects, με τη δυνατότητα πολλαπλά domains να συνυπάρχουν μέσα σε ένα **forest**, το καθένα διατηρώντας τη δική του συλλογή αντικειμένων.
4. **Tree** – Ομαδοποίηση domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Η κορυφή της οργανωτικής δομής στο Active Directory, απαρτιζόμενη από διάφορα trees με **trust relationships** μεταξύ τους.

Το **Active Directory Domain Services (AD DS)** περιλαμβάνει ένα σύνολο υπηρεσιών κρίσιμων για την κεντρική διαχείριση και επικοινωνία μέσα σε ένα δίκτυο. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Κεντρική αποθήκευση δεδομένων και διαχείριση των αλληλεπιδράσεων μεταξύ **users** και **domains**, συμπεριλαμβανομένων των **authentication** και **search** λειτουργιών.
2. **Certificate Services** – Επιβλέπει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει directory-enabled εφαρμογές μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει **single-sign-on** δυνατότητες για την authentication χρηστών σε πολλαπλές web εφαρμογές σε μία συνεδρία.
5. **Rights Management** – Βοηθά στην προστασία υλικού πνευματικών δικαιωμάτων ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Κρίσιμο για την επίλυση **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Συνοπτικός οδηγός

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Αν έχετε πρόσβαση σε ένα AD περιβάλλον αλλά δεν έχετε credentials/sessions μπορείτε να:

- **Pentest the network:**
- Σαρώστε το δίκτυο, εντοπίστε μηχανήματα και ανοιχτές θύρες και προσπαθήστε να **exploit vulnerabilities** ή να **extract credentials** από αυτά (για παράδειγμα, [printers could be very interesting targets](ad-information-in-printers.md).
- Η enumerating DNS μπορεί να δώσει πληροφορίες σχετικά με βασικούς servers στο domain όπως web, printers, shares, vpn, media, κ.λπ.
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
- Συλλέξτε credentials **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Πρόσβαση σε host by [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συλλέξτε credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξάγετε usernames/ονοματεπώνυμα από εσωτερικά έγγραφα, social media, υπηρεσίες (κυρίως web) μέσα στο domain περιβάλλον και επίσης από δημόσια διαθέσιμες πηγές.
- Αν βρείτε τα πλήρη ονόματα εργαζομένων της εταιρείας, μπορείτε να δοκιμάσετε διαφορετικές AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο κοινές συμβάσεις είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Check the [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) and [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages.
- **Kerbrute enum**: When an **invalid username is requested** the server will respond using the **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, allowing us to determine that the username was invalid. **Valid usernames** will illicit either the **TGT in a AS-REP** response or the error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicating that the user is required to perform pre-authentication.
- **No Authentication against MS-NRPC**: Using auth-level = 1 (No authentication) against the MS-NRPC (Netlogon) interface on domain controllers. The method calls the `DsrGetDcNameEx2` function after binding MS-NRPC interface to check if the user or computer exists without any credentials. The [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implements this type of enumeration. The research can be found [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Διακομιστής**

Αν βρείτε έναν από αυτούς τους διακομιστές στο δίκτυο, μπορείτε επίσης να εκτελέσετε **user enumeration against it**. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Μπορείτε να βρείτε λίστες usernames στο [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) και σε αυτό ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Ωστόσο, θα πρέπει να έχετε τα **ονόματα των ανθρώπων που εργάζονται στην εταιρεία** από το στάδιο recon που θα έπρεπε να έχετε εκτελέσει πριν από αυτό. Με το όνομα και το επώνυμο μπορείτε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανούς έγκυρους usernames.

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Μπορεί να καταφέρετε να **αποκτήσετε** κάποια challenge **hashes** για να τα crackάρετε μέσω **poisoning** κάποιων πρωτοκόλλων του **δικτύου**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Για αυτή τη φάση χρειάζεται να έχετε **αποκτήσει τα credentials ή μια session ενός έγκυρου domain account.** Αν έχετε κάποια έγκυρα credentials ή ένα shell ως domain user, **πρέπει να θυμάστε ότι οι επιλογές που δόθηκαν πριν είναι ακόμη επιλογές για να παραβιάσετε άλλους χρήστες**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Το να έχετε αποκτήσει έναν λογαριασμό είναι ένα **μεγάλο βήμα για να ξεκινήσετε την παραβίαση ολόκληρου του domain**, γιατί θα μπορείτε να ξεκινήσετε την **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting περιλαμβάνει την απόκτηση **TGS tickets** που χρησιμοποιούνται από services δεμένα σε user accounts και το cracking της κρυπτογράφησής τους — η οποία βασίζεται σε user passwords — **offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Μόλις έχετε αποκτήσει κάποια credentials μπορείτε να ελέγξετε αν έχετε πρόσβαση σε κάποια **machine**. Για αυτό το λόγο μπορείτε να χρησιμοποιήσετε το **CrackMapExec** για να επιχειρήσετε σύνδεση σε πολλούς servers με διαφορετικά πρωτόκολλα, σύμφωνα με τις port scans σας.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Είναι πολύ **απίθανο** να βρείτε **tickets** στον τρέχοντα χρήστη που να σας δίνουν άδεια για πρόσβαση σε απροσδόκητους πόρους, αλλά μπορείτε να ελέγξετε:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Αν καταφέρετε να enumerate το Active Directory θα έχετε **περισσότερα emails και καλύτερη κατανόηση του δικτύου**. Ίσως να καταφέρετε να αναγκάσετε NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Τώρα που έχετε κάποια βασικά διαπιστευτήρια θα πρέπει να ελέγξετε αν μπορείτε να **βρείτε** οποιαδήποτε **ενδιαφέροντα αρχεία που μοιράζονται μέσα στο AD**. Μπορείτε να το κάνετε χειροκίνητα αλλά είναι μια πολύ βαρετή επαναλαμβανόμενη εργασία (και ακόμα περισσότερο αν βρείτε εκατοντάδες docs που πρέπει να ελέγξετε).

[**Ακολουθήστε αυτόν τον σύνδεσμο για να μάθετε για τα εργαλεία που μπορείτε να χρησιμοποιήσετε.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Αν μπορείτε να **έχετε access σε άλλους PCs ή shares** μπορείτε να **τοποθετήσετε αρχεία** (π.χ. ένα SCF file) που αν κάποιος τα ανοίξει θα **προκαλέσουν μια NTLM authentication εναντίον σας**, ώστε να μπορείτε να **κλέψετε** το **NTLM challenge** για να το crackάρετε:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεπε σε οποιονδήποτε επαληθευμένο χρήστη να **παραβιάσει τον domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Για τις παρακάτω τεχνικές ένας κανονικός domain user δεν αρκεί, χρειάζεστε κάποια ειδικά προνόμια/διαπιστευτήρια για να πραγματοποιήσετε αυτές τις επιθέσεις.**

### Hash extraction

Ελπίζουμε να καταφέρατε να **παραβιάσετε κάποιον local admin** account χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) συμπεριλαμβανομένου relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Στη συνέχεια, είναι καιρός να dumpάρετε όλα τα hashes από τη μνήμη και τοπικά.\
[**Διαβάστε αυτή τη σελίδα για διαφορετικούς τρόπους απόκτησης των hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις έχετε το hash ενός χρήστη**, μπορείτε να το χρησιμοποιήσετε για να τον impersonate.\
Πρέπει να χρησιμοποιήσετε κάποιο εργαλείο που θα εκτελέσει την NTLM authentication χρησιμοποιώντας αυτό το hash, **ή** μπορείτε να δημιουργήσετε ένα νέο **sessionlogon** και να **injectάρετε** αυτό το **hash** μέσα στο **LSASS**, ώστε όταν γίνει οποιαδήποτε **NTLM authentication**, να χρησιμοποιηθεί αυτό το **hash.** Η τελευταία επιλογή είναι αυτή που κάνει το mimikatz.\
[**Διαβάστε αυτή τη σελίδα για περισσότερες πληροφορίες.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η επίθεση στοχεύει να χρησιμοποιήσει το NTLM hash του χρήστη για να ζητήσει Kerberos tickets, ως εναλλακτική στο κοινό Pass The Hash πάνω από το NTLM πρωτόκολλο. Επομένως, αυτό μπορεί να είναι ιδιαίτερα χρήσιμο σε δίκτυα όπου το NTLM πρωτόκολλο είναι απενεργοποιημένο και επιτρέπεται μόνο το Kerberos ως πρωτόκολλο authentication.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στην μέθοδο επίθεσης Pass The Ticket (PTT), οι επιτιθέμενοι κλέβουν το authentication ticket ενός χρήστη αντί για τον κωδικό ή τις τιμές hash του. Το κλεμμένο ticket στη συνέχεια χρησιμοποιείται για να impersonate τον χρήστη, αποκτώντας μη εξουσιοδοτημένη πρόσβαση σε πόρους και υπηρεσίες εντός ενός δικτύου.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Εάν έχετε το hash ή τον password ενός local administrator θα πρέπει να προσπαθήσετε να κάνετε τοπικό login σε άλλους PCs με αυτό.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **θορυβώδες** και το **LAPS** θα το **ελάττωνε**.

### MSSQL Abuse & Trusted Links

Εάν ένας χρήστης έχει προνόμια για **access MSSQL instances**, θα μπορούσε να το χρησιμοποιήσει για να **εκτελέσει εντολές** στον MSSQL host (αν τρέχει ως SA), να **κλέψει** το NetNTLM **hash** ή ακόμη να πραγματοποιήσει επίθεση **relay**.\
Επιπλέον, αν ένα MSSQL instance είναι trusted (database link) από ένα διαφορετικό MSSQL instance και ο χρήστης έχει προνόμια πάνω στην trusted βάση, θα μπορεί να **χρησιμοποιήσει τη trust relationship για να εκτελέσει queries και στην άλλη instance**. Αυτές οι trusts μπορούν να αλυσιδωθούν και σε κάποιο σημείο ο χρήστης μπορεί να βρει μια λανθασμένα ρυθμισμένη βάση δεδομένων όπου μπορεί να εκτελέσει εντολές.\
**Οι συνδέσεις μεταξύ βάσεων δεδομένων λειτουργούν ακόμα και μέσω forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Τρίτα εργαλεία inventory και deployment συχνά αποκαλύπτουν ισχυρά μονοπάτια προς credentials και εκτέλεση κώδικα. Δείτε:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Εάν βρείτε κάποιο Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε domain privileges στον υπολογιστή, θα μπορείτε να εξάγετε TGTs από τη μνήμη κάθε χρήστη που κάνει login στον υπολογιστή.\
Έτσι, εάν ένας **Domain Admin** κάνει login στον υπολογιστή, θα μπορείτε να εξάγετε το TGT του και να τον impersonate χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στο constrained delegation μπορείτε ακόμα να **compromise έναν Print Server** (ελπίζουμε να είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Εάν ένας χρήστης ή υπολογιστής έχει ενεργοποιημένο το "Constrained Delegation", θα μπορεί να **impersonate οποιονδήποτε χρήστη για να προσπελάσει ορισμένες υπηρεσίες σε έναν υπολογιστή**.\
Στη συνέχεια, αν **αποκτήσετε το hash** αυτού του χρήστη/υπολογιστή θα μπορείτε να **impersonate οποιονδήποτε χρήστη** (ακόμα και Domain Admins) για να προσπελάσετε αυτές τις υπηρεσίες.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Το να έχετε δικαίωμα **WRITE** σε ένα Active Directory object ενός απομακρυσμένου υπολογιστή επιτρέπει την επίτευξη code execution με **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ο compromised χρήστης μπορεί να έχει κάποια **ενδιαφέροντα προνόμια πάνω σε domain objects** που θα μπορούσαν να σας επιτρέψουν να **μετακινηθείτε lateral** ή να **escalate privileges**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Η ανακάλυψη μιας **Spool service που 'ακούει'** εντός του domain μπορεί να **καταχραστεί** για να **αποκτήσει νέες credentials** και να **ανυψώσει προνόμια**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Εάν **άλλοι χρήστες** **πρόσβαση** στη **compromised** μηχανή, είναι δυνατό να **συλλεχθούν credentials από τη μνήμη** και ακόμα **να εγχυθούν beacons στις διεργασίες τους** για να τους impersonate.\
Συνήθως οι χρήστες θα προσπελαύνουν το σύστημα μέσω RDP, οπότε εδώ υπάρχει πώς να πραγματοποιήσετε μερικές επιθέσεις πάνω σε τρίτες RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα για τη διαχείριση του **local Administrator password** σε domain-joined computers, διασφαλίζοντας ότι είναι **randomized**, μοναδικό και συχνά **changed**. Αυτά τα passwords αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs μόνο σε εξουσιοδοτημένους χρήστες. Με επαρκή permissions για πρόσβαση σε αυτά τα passwords, το pivoting σε άλλους υπολογιστές γίνεται δυνατό.

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Η **συλλογή certificates** από τη compromised μηχανή μπορεί να είναι ένας τρόπος για escalation privileges μέσα στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Εάν έχουν ρυθμιστεί **ευάλωτα templates**, είναι δυνατό να τα καταχραστείτε για να ανεβάσετε προνόμια:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Μόλις αποκτήσετε προνόμια **Domain Admin** ή ακόμα καλύτερα **Enterprise Admin**, μπορείτε να **dump** τη **domain database**: _ntds.dit_.

[**Περισσότερες πληροφορίες για την επίθεση DCSync εδώ**](dcsync.md).

[**Περισσότερες πληροφορίες για το πώς να κλέψετε το NTDS.dit εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

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

Η επίθεση **Silver Ticket** δημιουργεί ένα νόμιμο Ticket Granting Service (TGS) ticket για μια συγκεκριμένη υπηρεσία χρησιμοποιώντας το **NTLM hash** (π.χ. το **hash του PC account**). Αυτή η μέθοδος χρησιμοποιείται για να αποκτήσει τα προνόμια της υπηρεσίας.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Μια επίθεση **Golden Ticket** περιλαμβάνει έναν επιτιθέμενο που αποκτά πρόσβαση στο **NTLM hash του krbtgt account** σε ένα περιβάλλον Active Directory (AD). Αυτός ο λογαριασμός είναι ιδιαίτερος επειδή χρησιμοποιείται για την υπογραφή όλων των **Ticket Granting Tickets (TGTs)**, που είναι ουσιώδη για authentication μέσα στο AD δίκτυο.

Μόλις ο επιτιθέμενος αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιλέξει (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά μοιάζουν με golden tickets, αλλά πλαστογραφημένα με τρόπο που **παρακάμπτει κοινικούς μηχανισμούς ανίχνευσης golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Το να έχετε certificates ενός λογαριασμού ή να μπορείτε να τα αιτηθείτε** είναι πολύ καλός τρόπος για να διατηρήσετε persistence στον λογαριασμό του χρήστη (ακόμα κι αν αλλάξει το password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Η χρήση certificates επίσης επιτρέπει persistence με υψηλά προνόμια μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το αντικείμενο **AdminSDHolder** στο Active Directory εξασφαλίζει την προστασία των **privileged groups** (όπως Domain Admins και Enterprise Admins) εφαρμόζοντας ένα σταθερό **Access Control List (ACL)** σε αυτές τις ομάδες για να αποτρέψει μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να καταχραστεί· αν ένας επιτιθέμενος τροποποιήσει το ACL του AdminSDHolder ώστε να δίνει πλήρη πρόσβαση σε έναν απλό χρήστη, αυτός ο χρήστης αποκτά εκτεταμένο έλεγχο πάνω σε όλες τις privileged groups. Αυτό το μέτρο ασφαλείας, που προορίζεται να προστατεύει, μπορεί έτσι να αντιστραφεί και να επιτρέψει ανεπιθύμητη πρόσβαση εκτός αν παρακολουθείται στενά.

[**Περισσότερες πληροφορίες για το AdminSDHolder Group εδώ.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Σε κάθε **Domain Controller (DC)** υπάρχει ένας **τοπικός administrator** λογαριασμός. Αποκτώντας admin δικαιώματα σε μια τέτοια μηχανή, το τοπικό Administrator hash μπορεί να εξαχθεί χρησιμοποιώντας **mimikatz**. Στη συνέχεια απαιτείται μια τροποποίηση μητρώου για να **επιτραπεί η χρήση αυτού του password**, επιτρέποντας απομακρυσμένη πρόσβαση στον τοπικό Administrator λογαριασμό.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Μπορείτε να **δώσετε** μερικά **ειδικά permissions** σε έναν **χρήστη** πάνω σε συγκεκριμένα domain objects που θα του επιτρέψουν να **escalate privileges στο μέλλον**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Οι **security descriptors** χρησιμοποιούνται για να **αποθηκεύουν** τα **permissions** που έχει ένα **object**. Αν μπορείτε να κάνετε μια **μικρή αλλαγή** στο **security descriptor** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα προνόμια πάνω σε αυτό το αντικείμενο χωρίς να χρειάζεται να είστε μέλος μιας privileged ομάδας.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Τροποποιήστε τη **LSASS** στη μνήμη για να ορίσετε έναν **universal password**, παρέχοντας πρόσβαση σε όλους τους domain λογαριασμούς.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Μάθετε τι είναι ένα SSP (Security Support Provider) εδώ.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **capture σε clear text** τα **credentials** που χρησιμοποιούνται για την πρόσβαση στη μηχανή.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταχωρεί έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **push attributes** (SIDHistory, SPNs...) σε συγκεκριμένα αντικείμενα **χωρίς** να αφήνει logs σχετικά με τις **τροποποιήσεις**. Χρειάζεστε DA privileges και να βρίσκεστε στο root domain.\
Σημειώστε ότι αν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να ανεβάσετε προνόμια αν έχετε **αρκετά permissions για να διαβάσετε LAPS passwords**. Ωστόσο, αυτά τα passwords μπορούν επίσης να χρησιμοποιηθούν για **διατήρηση persistence**.\
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως το όριο ασφαλείας. Αυτό σημαίνει ότι **η παραβίαση ενός μόνο domain μπορεί ενδεχομένως να οδηγήσει σε παραβίαση ολόκληρου του Forest**.

### Basic Information

Ένα [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφαλείας που επιτρέπει σε έναν χρήστη από ένα **domain** να προσπελάσει πόρους σε ένα άλλο **domain**. Δημιουργεί μια σύνδεση μεταξύ των συστημάτων authentication των δύο domains, επιτρέποντας την ομαλή ροή ελέγχων authentication. Όταν τα domains δημιουργούν ένα trust, ανταλλάσσουν και αποθηκεύουν συγκεκριμένα **keys** στους **Domain Controllers (DCs)** τους, τα οποία είναι κρίσιμα για την ακεραιότητα του trust.

Σε ένα τυπικό σενάριο, αν ένας χρήστης θέλει να προσπελάσει μια υπηρεσία σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket γνωστό ως **inter-realm TGT** από τον δικό του Domain Controller. Αυτό το TGT κρυπτογραφείται με ένα κοινό **key** που έχουν συμφωνήσει και τα δύο domains. Ο χρήστης παρουσιάζει αυτό το inter-realm TGT στον **DC του trusted domain** για να λάβει ένα service ticket (**TGS**). Εφόσον το inter-realm TGT επαληθευτεί επιτυχώς από τον DC του trusted domain, αυτός εκδίδει ένα TGS, χορηγώντας στον χρήστη πρόσβαση στην υπηρεσία.

**Βήματα**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από τον **Domain Controller (DC1)** του.
2. Ο DC1 εκδίδει ένα νέο TGT εάν ο client πιστοποιηθεί επιτυχώς.
3. Ο client στη συνέχεια ζητά ένα **inter-realm TGT** από τον DC1, το οποίο χρειάζεται για πρόσβαση σε πόρους στο **Domain 2**.
4. Το inter-realm TGT κρυπτογραφείται με ένα **trust key** που μοιράζονται ο DC1 και ο DC2 ως μέρος του two-way domain trust.
5. Ο client παίρνει το inter-realm TGT στον **Domain Controller του Domain 2 (DC2)**.
6. Ο DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το κοινό trust key και, αν είναι έγκυρο, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 που θέλει να προσπελάσει ο client.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, το οποίο είναι κρυπτογραφημένο με το hash του λογαριασμού του server, για να αποκτήσει πρόσβαση στην υπηρεσία στο Domain 2.

### Different trusts

Είναι σημαντικό να σημειωθεί ότι **ένα trust μπορεί να είναι μονομερές ή αμφίδρομο**. Στην επιλογή two-way, και τα δύο domains εμπιστεύονται το ένα το άλλο, ενώ σε μια **one-way** σχέση trust, το ένα domain είναι το **trusted** και το άλλο το **trusting**. Στην τελευταία περίπτωση, **θα μπορείτε μόνο να προσπελάσετε πόρους στο trusting domain από το trusted domain**.

Αν το Domain A εμπιστεύεται το Domain B, το A είναι το trusting domain και το B είναι το trusted. Επιπλέον, στο **Domain A**, αυτό θα εμφανίζεται ως **Outbound trust**· και στο **Domain B**, αυτό θα είναι **Inbound trust**.

**Διαφορετικές σχέσεις trusting**

- **Parent-Child Trusts**: Συνηθισμένη ρύθμιση μέσα στο ίδιο forest, όπου ένα child domain έχει αυτόματα two-way transitive trust με το parent domain. Αυτό σημαίνει ότι τα authentication requests μπορούν να ρέουν ομαλά μεταξύ parent και child.
- **Cross-link Trusts**: Αναφέρονται ως "shortcut trusts" και δημιουργούνται μεταξύ child domains για να επιταχύνουν τις διαδικασίες παραπομπής. Σε πολύπλοκα forests, οι παραπομπές authentication συνήθως πρέπει να ανέβουν μέχρι τη ρίζα του forest και στη συνέχεια να κατέβουν στο target domain. Δημιουργώντας cross-links, η διαδρομή συντομεύει, κάτι που είναι χρήσιμο ιδιαίτερα σε γεωγραφικά διασκορπισμένα περιβάλλοντα.
- **External Trusts**: Αυτά ρυθμίζονται μεταξύ διαφορετικών, μη σχετιζόμενων domains και είναι per φύση non-transitive. Σύμφωνα με την [εγχειρίδιο της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για πρόσβαση σε πόρους σε ένα domain έξω από το τρέχον forest που δεν συνδέεται με forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτά τα trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός νεοπροστιθέμενου tree root. Αν και δεν είναι συχνά, τα tree-root trusts είναι σημαντικά για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρούν μοναδικό domain name και εξασφαλίζοντας two-way transitivity. Περισσότερες πληροφορίες είναι διαθέσιμες στην [οδηγία της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτό το είδος trust είναι ένα two-way transitive trust μεταξύ δύο forest root domains, εφαρμόζοντας επίσης SID filtering για ενίσχυση της ασφάλειας.
- **MIT Trusts**: Αυτά τα trusts δημιουργούνται με μη-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Τα MIT trusts είναι πιο εξειδικευμένα και προορίζονται για περιβάλλοντα που χρειάζονται ενσωμάτωση με Kerberos-based συστήματα εκτός του Windows οικοσυστήματος.

#### Other differences in **trusting relationships**

- Μια σχέση trust μπορεί επίσης να είναι **transitive** (A trust B, B trust C, άρα A trust C) ή **non-transitive**.
- Μια σχέση trust μπορεί να ρυθμιστεί ως **bidirectional trust** (και τα δύο εμπιστεύονται το ένα το άλλο) ή ως **one-way trust** (μόνο το ένα εμπιστεύεται το άλλο).

### Attack Path

1. **Enumerate** τις trusting relationships
2. Ελέγξτε αν οποιοδήποτε **security principal** (user/group/computer) έχει **access** σε πόρους του **άλλου domain**, ίσως μέσω ACE entries ή με το να είναι σε groups του άλλου domain. Ψάξτε για **relationships across domains** (το trust πιθανώς δημιουργήθηκε γι' αυτό).
1. kerberoast σε αυτή την περίπτωση μπορεί να είναι μια άλλη επιλογή.
3. **Compromise** τους **accounts** που μπορούν να **pivot** μεταξύ domains.

Επιτιθέμενοι μπορούν να αποκτήσουν πρόσβαση σε πόρους σε άλλο domain μέσω τριών κύριων μηχανισμών:

- **Local Group Membership**: Principals μπορούν να προστεθούν σε local groups σε μηχανές, όπως η “Administrators” group σε έναν server, δίνοντάς τους σημαντικό έλεγχο πάνω στη μηχανή.
- **Foreign Domain Group Membership**: Principals μπορούν επίσης να είναι μέλη groups εντός του ξένου domain. Ωστόσο, η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση του trust και το scope της ομάδας.
- **Access Control Lists (ACLs)**: Principals μπορεί να καθορίζονται σε ένα **ACL**, ιδιαίτερα ως οντότητες σε **ACEs** μέσα σε μια **DACL**, παρέχοντας τους πρόσβαση σε συγκεκριμένους πόρους. Για όσους θέλουν να εμβαθύνουν στους μηχανισμούς των ACLs, DACLs και ACEs, το whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” είναι ανεκτίμητο.

### Find external users/groups with permissions

Μπορείτε να ελέγξετε **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να βρείτε foreign security principals στο domain. Αυτοί θα είναι χρήστες/ομάδες από **ένα εξωτερικό domain/forest**.

Μπορείτε να το ελέγξετε αυτό στο **Bloodhound** ή χρησιμοποιώντας **powerview**:
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
Άλλοι τρόποι για την καταγραφή των domain trusts:
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
> Μπορείτε να δείτε ποια χρησιμοποιείται από τον τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Αναβαθμίστε σε Enterprise admin στον child/parent domain εκμεταλλευόμενοι το trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Η κατανόηση του πώς μπορεί να εκμεταλλευτεί το Configuration Naming Context (NC) είναι κρίσιμη. Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο για δεδομένα ρύθμισης σε όλο το forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα αναπαράγονται σε κάθε Domain Controller (DC) στο forest, με τους writable DCs να διατηρούν ένα εγγράψιμο αντίγραφο του Configuration NC. Για να το εκμεταλλευτεί κάποιος, απαιτούνται **SYSTEM privileges σε DC**, κατά προτίμηση σε child DC.

**Link GPO to root DC site**

Το Sites container του Configuration NC περιλαμβάνει πληροφορίες για τις τοποθεσίες όλων των domain-joined computers στο AD forest. Λειτουργώντας με SYSTEM privileges σε οποιονδήποτε DC, οι επιτιθέμενοι μπορούν να συνδέσουν GPOs στις root DC sites. Αυτή η ενέργεια μπορεί εν δυνάμει να συμβιβάσει το root domain χειριζόμενοι τις πολιτικές που εφαρμόζονται σε αυτές τις τοποθεσίες.

Για λεπτομερείς πληροφορίες, μπορεί κανείς να εξερευνήσει την έρευνα στο [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Ένας διανυσματικός τρόπος επίθεσης περιλαμβάνει το στόχευση privileged gMSAs εντός του domain. Το KDS Root key, απαραίτητο για τον υπολογισμό των κωδικών των gMSAs, αποθηκεύεται στο Configuration NC. Με SYSTEM privileges σε οποιονδήποτε DC, είναι δυνατό να αποκτήσει κανείς πρόσβαση στο KDS Root key και να υπολογίσει τους κωδικούς για οποιοδήποτε gMSA σε όλο το forest.

Λεπτομερής ανάλυση και βήμα-προς-βήμα οδηγίες υπάρχουν στο:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Συμπληρωματική delegated MSA επίθεση (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Επιπρόσθετη εξωτερική έρευνα: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Αυτή η μέθοδος απαιτεί υπομονή, αναμένοντας τη δημιουργία νέων privileged AD objects. Με SYSTEM privileges, ένας επιτιθέμενος μπορεί να τροποποιήσει το AD Schema προκειμένου να δώσει σε οποιονδήποτε χρήστη πλήρη έλεγχο σε όλες τις classes. Αυτό μπορεί να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο επί νεοδημιουργούμενων AD objects.

Περισσότερη ανάγνωση διαθέσιμη στο [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει τον έλεγχο επί Public Key Infrastructure (PKI) objects για να δημιουργήσει ένα certificate template που επιτρέπει authentication ως οποιοσδήποτε χρήστης εντός του forest. Εφόσον τα PKI objects κατοικούν στο Configuration NC, ο συμβιβασμός ενός writable child DC επιτρέπει την εκτέλεση ESC5 attacks.

Περισσότερες λεπτομέρειες μπορείτε να βρείτε στο [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Σε σενάρια χωρίς ADCS, ο επιτιθέμενος έχει τη δυνατότητα να στήσει τα απαραίτητα components, όπως συζητείται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Εξωτερικό Forest Domain - Μονόδρομος (Inbound) ή αμφίδρομος
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
Σε αυτό το σενάριο **το domain σας εμπιστεύεται** ένα εξωτερικό, δίνοντάς σας **απροσδιόριστα δικαιώματα** πάνω σε αυτό. Θα χρειαστεί να βρείτε **ποιοι principals του domain σας έχουν ποια πρόσβαση στο εξωτερικό domain** και στη συνέχεια να προσπαθήσετε να τα εκμεταλλευτείτε:


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
Σε αυτό το σενάριο **το domain σας** εμπιστεύεται κάποια **privileges** σε έναν principal από **διαφορετικά domains**.

Ωστόσο, όταν ένα **domain is trusted** από το trusting domain, το trusted domain **creates a user** με ένα **predictable name** που χρησιμοποιεί ως **password the trusted password**. Αυτό σημαίνει ότι είναι δυνατό να **access a user from the trusting domain to get inside the trusted one** για να το αναγνωρίσει κανείς (enumerate) και να προσπαθήσει να κλιμακώσει περισσότερα privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος για να παραβιαστεί το trusted domain είναι να βρεθεί ένας [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί στην **αντίθετη κατεύθυνση** του domain trust (κάτι που δεν είναι πολύ συνηθισμένο).

Ένας επιπλέον τρόπος για να παραβιαστεί το trusted domain είναι να περιμένει ο attacker σε ένα μηχάνημα όπου ένας **user από το trusted domain μπορεί να έχει πρόσβαση** για να συνδεθεί μέσω **RDP**. Έπειτα, ο attacker μπορεί να εγχύσει κώδικα στη διεργασία της RDP session και να **access the origin domain of the victim** από εκεί.\
Επιπλέον, εάν ο **victim mounted his hard drive**, από τη διεργασία της **RDP session** ο attacker θα μπορούσε να αποθηκεύσει **backdoors** στον **startup folder of the hard drive**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που εκμεταλλεύονται το SID history attribute μέσω forest trusts μετριάζεται από το **SID Filtering**, το οποίο είναι ενεργοποιημένο εξ ορισμού σε όλα τα inter-forest trusts. Αυτό βασίζεται στην υπόθεση ότι τα intra-forest trusts είναι ασφαλή, θεωρώντας το forest, αντί για το domain, ως το όριο ασφαλείας σύμφωνα με τη θέση της Microsoft.
- Ωστόσο, υπάρχει ένα ζήτημα: το SID filtering μπορεί να διαταράξει εφαρμογές και πρόσβαση χρηστών, οδηγώντας σε περιστασιακή απενεργοποίησή του.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση της **Selective Authentication** εξασφαλίζει ότι οι χρήστες από τα δύο forests δεν αυθεντικοποιούνται αυτόματα. Αντίθετα, απαιτούνται ρητές άδειες ώστε οι χρήστες να έχουν πρόσβαση σε domains και servers εντός του trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του writable Configuration Naming Context (NC) ή από επιθέσεις στον trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Συνιστάται οι Domain Admins να επιτρέπεται να συνδέονται μόνο σε Domain Controllers, αποφεύγοντας τη χρήση τους σε άλλους hosts.
- **Service Account Privileges**: Οι υπηρεσίες δεν θα πρέπει να τρέχουν με Domain Admin (DA) privileges για να διατηρείται η ασφάλεια.
- **Temporal Privilege Limitation**: Για εργασίες που απαιτούν DA privileges, η διάρκεια τους θα πρέπει να περιορίζεται. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Η υλοποίηση deception περιλαμβάνει την τοποθέτηση παγίδων, όπως decoy users ή computers, με χαρακτηριστικά όπως κωδικούς που δεν λήγουν ή που είναι επισημασμένοι ως Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία χρηστών με συγκεκριμένα δικαιώματα ή την προσθήκη τους σε ομάδες υψηλών προνομίων.
- Ένα πρακτικό παράδειγμα περιλαμβάνει τη χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερα για την ανάπτυξη deception τεχνικών βρίσκονται στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Ύποπτοι δείκτες περιλαμβάνουν μη τυπικό ObjectSID, σπάνιες συνδέσεις (infrequent logons), ημερομηνίες δημιουργίας και χαμηλό αριθμό αποτυχημένων κωδικών (bad password counts).
- **General Indicators**: Η σύγκριση χαρακτηριστικών πιθανών decoy objects με εκείνα των αυθεντικών μπορεί να αποκαλύψει ασυνέπειες. Εργαλεία όπως το [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στον εντοπισμό τέτοιων deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Αποφεύγοντας την enumeration των sessions σε Domain Controllers για να μην ενεργοποιηθεί το ATA detection.
- **Ticket Impersonation**: Η χρήση **aes** keys για τη δημιουργία tickets βοηθά στην αποφυγή ανίχνευσης, καθώς δεν γίνεται downgrade σε NTLM.
- **DCSync Attacks**: Η εκτέλεση από μη Domain Controller για να αποφευχθεί το ATA detection συνιστάται, καθώς η άμεση εκτέλεση από έναν Domain Controller θα προκαλέσει ειδοποιήσεις.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
