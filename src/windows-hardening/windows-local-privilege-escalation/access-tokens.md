# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Cada **usuário logado** no sistema **possui um access token com informações de segurança** para essa sessão de logon. O sistema cria um access token quando o usuário faz logon. **Todo processo executado** em nome do usuário **tem uma cópia do access token**. O token identifica o usuário, os grupos do usuário e os privilégios do usuário. Um token também contém um logon SID (Security Identifier) que identifica a sessão de logon atual.

Você pode ver essas informações executando `whoami /all`
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
ou usando _Process Explorer_ do Sysinternals (selecione o processo e acesse a aba "Security"):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Local administrator

Quando um administrador local faz login, **dois access tokens são criados**: um com privilégios de admin e outro com privilégios normais. **Por padrão**, quando esse usuário executa um processo, é usado o token com privilégios **regulares** (não administrador). Quando esse usuário tenta **executar** algo **como administrador** ("Run as Administrator", por exemplo), o **UAC** será usado para pedir permissão.\
Se você quiser [**saber mais sobre o UAC, leia esta página**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

Na prática, isso significa que um **shell de admin não elevado normalmente é executado com um token filtrado**. É por isso que `whoami /groups` frequentemente mostra **`BUILTIN\Administrators` como `Deny only`** até que o processo seja elevado. Internamente, o Windows mantém um **linked elevated token** (`TokenLinkedToken`) e acompanha o estado com campos como `TokenElevationType`.

### Credentials user impersonation

Se você tiver **credenciais válidas de qualquer outro usuário**, você pode **criar** uma **nova sessão de logon** com essas credenciais :
```
runas /user:domain\username cmd.exe
```
O **access token** também tem uma **reference** das logon sessions dentro do **LSASS**, isso é útil se o processo precisar acessar alguns objetos da rede.\
Você pode iniciar um processo que **usa diferentes credentials para acessar network services** usando:
```
runas /user:domain\username /netonly cmd.exe
```
Isso é útil se você tiver credenciais válidas para acessar objetos na rede, mas essas credenciais não forem válidas dentro do host atual, pois elas serão usadas apenas na rede (no host atual, serão usadas as permissões do seu usuário atual).

#### `runas /netonly` details

`runas /netonly` (e helpers de C2 como `make_token`) cria um token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Isso é muito útil de entender durante lateral movement porque:

- **Localmente**, o novo processo mantém a **mesma identidade local**, grupos, nível de integridade e a maioria das mesmas decisões de acesso do token atual.
- **Remotamente**, a autenticação de saída pode usar as **credenciais fornecidas** para SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Portanto, `whoami` pode ainda mostrar o **usuário local original** enquanto o acesso à rede acontece como a **conta alternativa**.

Essa é uma ótima opção quando as credenciais são válidas no domínio ou em outro host, mas o usuário **não pode ou não deve fazer logon localmente** na máquina atual.

### Types of tokens

Existem dois tipos de tokens disponíveis:

- **Primary Token**: Ele serve como uma representação das credenciais de segurança de um processo. A criação e associação de primary tokens com processos são ações que exigem privilégios elevados, enfatizando o princípio da separação de privilégios. Normalmente, um serviço de autenticação é responsável pela criação do token, enquanto um serviço de logon cuida da sua associação com o shell do sistema operacional do usuário. Vale notar que processos herdam o primary token do seu processo pai na criação.
- **Impersonation Token**: Permite que uma aplicação de servidor adote temporariamente a identidade do cliente para acessar objetos seguros. Esse mecanismo é dividido em quatro níveis de operação:
- **Anonymous**: Concede acesso ao servidor de forma semelhante ao de um usuário não identificado.
- **Identification**: Permite que o servidor verifique a identidade do cliente sem utilizá-la para acesso a objetos.
- **Impersonation**: Permite que o servidor opere sob a identidade do cliente.
- **Delegation**: Semelhante a Impersonation, mas inclui a capacidade de estender essa suposição de identidade a sistemas remotos com os quais o servidor interage, garantindo a preservação das credenciais.

#### Impersonate Tokens

Usando o módulo _**incognito**_ do metasploit, se você tiver privilégios suficientes, você pode facilmente **listar** e **impersonate** outros **tokens**. Isso pode ser útil para realizar **ações como se você fosse o outro usuário**. Você também pode **escalar privilégios** com essa técnica.

Algumas observações práticas que são fáceis de esquecer أثناء operar:

- **`CreateProcessWithTokenW`** requer **`SeImpersonatePrivilege`** no chamador e o novo processo será executado na **sessão do chamador**.
- **`CreateProcessAsUserW`** é o fallback usual quando `CreateProcessWithTokenW` falha com `1314`, ou quando você precisa iniciar na **sessão referenciada pelo token**.
- Se um token vier de **`LogonUser(LOGON32_LOGON_NETWORK)`**, ele geralmente é um **impersonation token**, então você precisa de **`DuplicateTokenEx(..., TokenPrimary, ...)`** antes de tentar criar um processo com ele.
- Nem todo impersonation token é igualmente útil: **`SecurityIdentification`** permite inspecionar o usuário, mas **não agir como ele**. Se um primitive de coercion ou um client de pipe/RPC fornecer apenas um token em nível de identificação, verifique **`TokenImpersonationLevel`** e troque para um primitive que gere **`SecurityImpersonation`** ou melhor.

#### Token theft without touching LSASS

Se você já tem um contexto de **service** ou **SYSTEM** e um **usuário privilegiado está logado**, roubar ou duplicar o token desse usuário costuma ser mais silencioso do que fazer dump do **LSASS**. Em muitas intrusões reais, isso é suficiente para:

- executar ações locais como esse usuário
- acessar recursos remotos como esse usuário
- לבצע operações de AD sem extrair credenciais reutilizáveis primeiro

Para exemplos de **session/user token hijacking** a partir de um contexto privilegiado, veja [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Lembre-se de que APIs como **`WTSQueryUserToken`** são destinadas a **serviços altamente confiáveis** e normalmente exigem **`LocalSystem` + `SeTcbPrivilege`**, então elas são principalmente úteis quando você já controla um contexto em nível de serviço. Para formas específicas de privilégio de obter **SYSTEM** primeiro, veja as páginas abaixo.

### Token Privileges

Aprenda quais **token privileges podem ser abusados para escalar privilégios:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Dê uma olhada em [**todos os possíveis token privileges e algumas definições nesta página externa**](https://github.com/gtworek/Priv2Admin).

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
