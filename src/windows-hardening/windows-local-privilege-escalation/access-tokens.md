# Tokens de Acesso

{{#include ../../banners/hacktricks-training.md}}

## Tokens de Acesso

Cada **usuário conectado** ao sistema **possui um access token com informações de segurança** para essa sessão de logon. O sistema cria um access token quando o usuário faz logon. **Cada processo executado** em nome do usuário **possui uma cópia do access token**. O token identifica o usuário, os grupos do usuário e os privilégios do usuário. Um token também contém um logon SID (Security Identifier) que identifica a sessão de logon atual.

Você pode visualizar essas informações executando `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
ou usando _Process Explorer_ da Sysinternals (selecione o processo e acesse a aba "Security"):

![Access Tokens - Access Tokens: ou usando Process Explorer da Sysinternals (selecione o processo e acesse a aba "Security")](<../../images/image (772).png>)

### Administrador local

Quando um administrador local faz login, **dois access tokens são criados**: um com direitos de administrador e outro com direitos normais. **Por padrão**, quando esse usuário executa um processo, aquele com **direitos** **regulares** (não administrativos) é usado. Quando esse usuário tenta **executar** algo **como administrador** (por exemplo, "Run as Administrator"), o **UAC** será usado para solicitar permissão.\
Se quiser [**saber mais sobre o UAC, leia esta página**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

Na prática, isso significa que um **shell de administrador não elevado geralmente é executado com um token filtrado**. Por isso, `whoami /groups` geralmente mostra **`BUILTIN\Administrators` como `Deny only`** até que o processo seja elevado. Internamente, o Windows mantém um **token elevado vinculado** (`TokenLinkedToken`) e acompanha o estado usando campos como `TokenElevationType`.

### Impersonação de usuário com credenciais

Se você tiver **credenciais válidas de qualquer outro usuário**, poderá **criar** uma **nova sessão de logon** com essas credenciais:
```
runas /user:domain\username cmd.exe
```
O **access token** também possui uma **referência** às sessões de logon dentro do **LSASS**, o que é útil caso o processo precise acessar alguns objetos da rede.\
Você pode iniciar um processo que **use credenciais diferentes para acessar serviços de rede** usando:
```
runas /user:domain\username /netonly cmd.exe
```
Isso é útil se você tiver credenciais válidas para acessar objetos na rede, mas essas credenciais não forem válidas dentro do host atual, pois serão usadas apenas na rede (no host atual, os privilégios do usuário atual serão utilizados).

#### detalhes de `runas /netonly`

`runas /netonly` (e auxiliares de C2, como `make_token`) cria um token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Isso é muito útil para entender durante o movimento lateral porque:<sup>[[3]](#references)</sup>

- **Localmente**, o novo processo mantém a **mesma identidade local**, os grupos, o nível de integridade e a maioria das mesmas decisões de acesso do token atual.
- **Remotamente**, a autenticação de saída pode usar as **credenciais fornecidas** para SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Portanto, `whoami` ainda pode mostrar o **usuário local original**, enquanto o acesso à rede ocorre como a **conta alternativa**.

Essa é uma ótima opção quando as credenciais são válidas no domínio ou em outro host, mas o usuário **não pode ou não deve fazer logon localmente** na máquina atual.

### Tipos de tokens

Há dois tipos de tokens disponíveis:

- **Token Primário**: serve como representação das credenciais de segurança de um processo. A criação e a associação de tokens primários a processos são ações que exigem privilégios elevados, reforçando o princípio da separação de privilégios. Normalmente, um serviço de autenticação é responsável pela criação do token, enquanto um serviço de logon cuida de sua associação ao shell do sistema operacional do usuário. Vale observar que os processos herdam o token primário de seu processo pai no momento da criação.
- **Token de Impersonation**: permite que uma aplicação de servidor adote temporariamente a identidade do cliente para acessar objetos protegidos. Esse mecanismo é dividido em quatro níveis de operação:
- **Anonymous**: concede ao servidor um acesso semelhante ao de um usuário não identificado.
- **Identification**: permite que o servidor verifique a identidade do cliente sem utilizá-la para acessar objetos.
- **Impersonation**: permite que o servidor opere usando a identidade do cliente.
- **Delegation**: semelhante a Impersonation, mas também permite estender essa adoção de identidade para sistemas remotos com os quais o servidor interage, garantindo a preservação das credenciais.

#### Impersonate Tokens

Usando o módulo _**incognito**_ do metasploit, se você tiver privilégios suficientes, poderá facilmente **listar** e **impersonate** outros **tokens**. Isso pode ser útil para executar **ações como se você fosse o outro usuário**. Você também poderia **escalar privilégios** com essa técnica.

Algumas observações práticas que são fáceis de esquecer durante a operação:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** exige **`SeImpersonatePrivilege`** no chamador, e o novo processo será executado na **sessão do chamador**.
- **`CreateProcessAsUserW`** é o fallback usual quando `CreateProcessWithTokenW` falha com `1314`, ou quando é necessário iniciar o processo na **sessão referenciada pelo token**.
- Se um token vier de **`LogonUser(LOGON32_LOGON_NETWORK)`**, normalmente ele será um **token de impersonation**; portanto, é necessário executar **`DuplicateTokenEx(..., TokenPrimary, ...)`** antes de tentar iniciar um processo com ele.
- Nem todo token de impersonation é igualmente útil: **`SecurityIdentification`** permite inspecionar o usuário, mas **não agir como ele**. Se uma primitiva de coerção ou um cliente de pipe/RPC fornecer apenas um token de nível de identificação, verifique **`TokenImpersonationLevel`** e mude para uma primitiva que produza **`SecurityImpersonation`** ou algo superior.

#### Roubo de token sem tocar no LSASS

Se você já tiver um contexto de **serviço** ou **SYSTEM** e um **usuário privilegiado estiver conectado**, roubar ou duplicar o token desse usuário costuma ser mais discreto do que fazer dump do **LSASS**. Em muitas intrusões reais, isso é suficiente para:<sup>[[2]](#references)</sup>

- executar ações locais como esse usuário
- acessar recursos remotos como esse usuário
- executar operações de AD sem antes extrair credenciais reutilizáveis

Para ver exemplos de **sequestro de tokens de sessão/usuário** a partir de um contexto privilegiado, consulte [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Lembre-se de que APIs como **`WTSQueryUserToken`** destinam-se a **serviços altamente confiáveis** e normalmente exigem **`LocalSystem` + `SeTcbPrivilege`**, portanto são principalmente úteis quando você já controla um contexto no nível de serviço. Para conhecer formas específicas de obter **SYSTEM** primeiro, consulte as páginas abaixo.

### Privilégios de token

Saiba quais **privilégios de token podem ser abusados para escalar privilégios:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Confira [**todos os privilégios de token possíveis e algumas definições nesta página externa**](https://github.com/gtworek/Priv2Admin).

## Referências

- [1] [Compreendendo e abusando de Access Tokens — Parte II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusando dos tokens do Windows para comprometer o Active Directory sem tocar no LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Desmistificando o comando "make_token" do Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
