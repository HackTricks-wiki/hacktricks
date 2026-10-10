# Tokens de Acesso

{{#include ../../banners/hacktricks-training.md}}

## Tokens de Acesso

Todo processo tem um **token de acesso primário** que define seu contexto de segurança. Uma thread normalmente usa esse token, mas também pode ter temporariamente um **token de impersonação**. Os tokens contêm o SID do usuário, os SIDs dos grupos, privilégios, informações de integridade e um SID de logon para a sessão de logon. Em geral, os processos herdam uma referência ao token primário do processo pai; eles não recebem uma cópia independente de seu conteúdo.<sup>[[4]](#references)</sup>

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

ou usando _Process Explorer_ do Sysinternals (selecione o processo e acesse a guia "Security"):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Administrador local

Quando o **UAC Admin Approval Mode** se aplica a um administrador, o logon interativo cria um token de administrador completo e um token filtrado. O Explorer e os processos filhos comuns usam o token filtrado por padrão. Uma solicitação de elevação, como **Run as administrator**, pede ao UAC para iniciar o programa com o token completo. O comportamento exato varia para a conta interna Administrator e quando o Admin Approval Mode está desabilitado.<sup>[[5]](#references)</sup>

Leia a [**página dedicada ao UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) para conhecer técnicas de bypass e detalhes das políticas.

Na prática, isso significa que um **shell de administrador não elevado geralmente é executado com um token filtrado**. Por isso, `whoami /groups` costuma mostrar **`BUILTIN\Administrators` como `Deny only`** até que o processo seja elevado. Internamente, o Windows mantém um **token elevado vinculado** (`TokenLinkedToken`) e acompanha o estado com campos como `TokenElevationType`.

### Representação de usuário com credenciais

Se você tiver **credenciais válidas de qualquer outro usuário**, poderá **criar** uma **nova sessão de logon** com essas credenciais:

```
runas /user:domain\username cmd.exe
```

O **access token** também tem uma **referência** às sessões de logon dentro do **LSASS**; isso é útil se o processo precisar acessar alguns objetos da rede.\
Você pode iniciar um processo que **usa credenciais diferentes para acessar serviços de rede** usando:

```
runas /user:domain\username /netonly cmd.exe
```

Isso é útil se você tiver credenciais válidas para acessar objetos na rede, mas essas credenciais não forem válidas no host atual, pois serão usadas apenas na rede (no host atual, serão usados os privilégios do usuário atual).

#### Detalhes de `runas /netonly`

`runas /netonly` (e helpers de C2, como `make_token`) cria um token **`LOGON32_LOGON_NEW_CREDENTIALS`**. É muito útil entender isso durante o movimento lateral porque:<sup>[[3]](#references)</sup>

- **Localmente**, o novo processo mantém a **mesma identidade local**, os mesmos grupos, o mesmo nível de integridade e a maioria das mesmas decisões de acesso do token atual.
- **Remotamente**, a autenticação de saída pode usar as **credenciais fornecidas** para SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Portanto, `whoami` ainda pode mostrar o **usuário local original**, enquanto o acesso à rede ocorre como a **conta alternativa**.

Essa é uma ótima opção quando as credenciais são válidas no domínio ou em outro host, mas o usuário **não pode ou não deve fazer logon localmente** na máquina atual.

### Tipos de tokens

Há dois tipos de tokens disponíveis:<sup>[[4]](#references)[[6]](#references)</sup>

- **Token primário**: Representa o contexto de segurança de um processo. Normalmente, um processo filho herda o token primário do processo pai, enquanto as APIs de criação de processos com token explícito impõem seus próprios requisitos de acesso ao token e privilégios do chamador.
- **Token de impersonação**: Permite que uma thread do servidor use temporariamente o contexto de segurança de um cliente para verificações de acesso. Seus quatro níveis são:
  - **Anônimo**: Concede ao servidor um acesso semelhante ao de um usuário não identificado.
  - **Identificação**: Permite que o servidor verifique a identidade do cliente sem utilizá-la para acesso a objetos.
  - **Impersonação**: Permite que o servidor opere sob a identidade do cliente.
  - **Delegação**: Permite que o servidor faça impersonação do cliente em sistemas remotos quando o mecanismo de autenticação e a configuração da conta permitem a delegação.

#### Faça a triagem de um token capturado antes de usá-lo

Não escolha um token apenas pelo nome de usuário. A mesma conta pode ter vários tokens com diferentes sessões de logon, SIDs de serviço, privilégios, níveis de integridade, restrições e credenciais de rede.<sup>[[9]](#references)</sup> Consulte pelo menos **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** e **`TokenStatistics.AuthenticationId`** usando `GetTokenInformation`.<sup>[[7]](#references)</sup>

Um token restrito pode conter SIDs somente para negação, privilégios removidos e SIDs de restrição. Quando há SIDs de restrição, o Windows realiza uma verificação de acesso com os SIDs habilitados e outra com os SIDs de restrição; **ambas as verificações devem permitir o acesso**. Portanto, um SID de usuário atraente ou um grupo habilitado na saída não prova, por si só, que o token pode acessar o objeto de destino.<sup>[[8]](#references)</sup>

Use este fluxo de decisão para os requisitos documentados de token e criação de processos:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Um **token primário** precisa de um handle com `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` antes de poder ser fornecido a `CreateProcessWithTokenW` ou `CreateProcessAsUserW`.
2. Converta um **token de impersonação** com `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Tokens de nível de identificação podem expor dados de identidade, mas não podem realizar verificações de acesso como o cliente.
3. `CreateProcessWithTokenW` precisa de `SeImpersonatePrivilege` e inicia o processo filho na sessão do chamador. Já `CreateProcessAsUserW` usa a sessão do token, mas normalmente precisa de `SeIncreaseQuotaPrivilege` e pode precisar de `SeAssignPrimaryTokenPrivilege`. Se houver credenciais disponíveis e esses privilégios estiverem ausentes, `CreateProcessWithLogonW` é a alternativa documentada.

#### Procure handles de token, não apenas proprietários de processos

Abrir o token primário de cada processo pode não detectar **tokens de impersonação mantidos como handles comuns** em serviços e processos broker. Um fluxo de trabalho reutilizável para tabelas de handles consiste em enumerar os handles do sistema, filtrar objetos de token, abrir cada proprietário com `PROCESS_DUP_HANDLE`, duplicar o handle candidato para o processo atual e, em seguida, consultar os campos acima. Confirme se o handle duplicado inclui `TOKEN_QUERY` e `TOKEN_DUPLICATE`; encontrar um handle de token não significa que ele possa ser duplicado para se tornar um token primário utilizável. Processos protegidos e DACLs de processos ainda podem impedir o acesso ao handle do processo proprietário.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatiza a enumeração de tokens primários de processos e de handles de token retidos. `list_token` mantém um candidato preferencial por nome de usuário, enquanto `list_all_token` exibe todos os candidatos. Um PID limita a enumeração a um único processo proprietário.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Para inspeção manual e verificação de acesso, **TokenUniverse** pode abrir tokens de processo/thread, procurar handles de token existentes, inspecionar restrições e sessões de logon, duplicar tokens e testar vários métodos de criação de processos.<sup>[[13]](#references)</sup> Para saber mais sobre a primitiva subjacente de handle entre processos, consulte:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Personificar Tokens

Usando o módulo _**incognito**_ do Metasploit, se você tiver privilégios suficientes, poderá **listar** e **personificar** facilmente outros **tokens**. Isso pode ser útil para realizar **ações como se você fosse outro usuário**. Você também pode **escalar privilégios** com essa técnica.

Algumas observações práticas que é fácil esquecer durante a operação:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** exige **`SeImpersonatePrivilege`** no processo chamador, e o novo processo será executado na **sessão do processo chamador**.
- **`CreateProcessAsUserW`** é uma alternativa possível quando `CreateProcessWithTokenW` falha com `1314`, mas somente se o processo chamador atender aos requisitos de privilégio. Também é a opção correta quando o processo filho precisa ser executado na **sessão referenciada pelo token**.<sup>[[9]](#references)[[10]](#references)</sup>
- Se um token vier de **`LogonUser(LOGON32_LOGON_NETWORK)`**, geralmente será um **token de impersonation**, portanto você precisará de **`DuplicateTokenEx(..., TokenPrimary, ...)`** antes de tentar iniciar um processo com ele.
- Nem todos os tokens de impersonation são igualmente úteis: **`SecurityIdentification`** permite inspecionar o usuário, mas **não agir como ele**. Se uma primitiva de coerção ou um cliente de pipe/RPC fornecer apenas um token de nível de identificação, verifique **`TokenImpersonationLevel`** e use uma primitiva que forneça **`SecurityImpersonation`** ou um nível superior.

#### Roubo de tokens sem tocar no LSASS

Se você já tiver um contexto de **serviço** ou **SYSTEM** e um **usuário privilegiado estiver conectado**, roubar ou duplicar o token desse usuário costuma ser uma opção mais discreta do que despejar o **LSASS**. Em muitas intrusões reais, isso basta para:<sup>[[2]](#references)</sup>

- executar ações locais como esse usuário
- acessar recursos remotos como esse usuário
- realizar operações no AD sem antes extrair credenciais reutilizáveis

Para exemplos de **sequestro de tokens de sessão/usuário** a partir de um contexto privilegiado, consulte [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Lembre-se de que APIs como **`WTSQueryUserToken`** destinam-se a **serviços altamente confiáveis** e normalmente exigem **`LocalSystem` + `SeTcbPrivilege`**; portanto, são úteis principalmente quando você já controla um contexto de nível de serviço. Para conhecer maneiras de obter **SYSTEM** primeiro que dependem de privilégios específicos, consulte as páginas abaixo.

### Privilégios de Token

Saiba quais **privilégios de token podem ser abusados para escalar privilégios:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Consulte [**a lista completa de possíveis privilégios de token e algumas definições nesta página externa**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Compreendendo e abusando de tokens de acesso — Parte II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusando dos tokens do Windows para comprometer o Active Directory sem tocar no LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Desmistificando o comando "make_token" do Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Tokens de Acesso - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Como funciona o Controle de Conta de Usuário - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Níveis de Impersonation - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Enumeração TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Tokens restritos - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Função CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Função CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Função DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
