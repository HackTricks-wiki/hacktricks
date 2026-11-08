# Tokens de Acesso

{{#include ../../banners/hacktricks-training.md}}

## Tokens de Acesso

Cada processo tem um **token de acesso primário** que define seu contexto de segurança. Uma thread normalmente usa esse token, mas também pode ter temporariamente um **token de impersonation**. Os tokens contêm o SID do usuário, SIDs dos grupos, privilégios, informações de integridade e um SID de logon para a sessão de logon. Em geral, os processos herdam uma referência ao token primário do processo pai; eles não recebem uma cópia independente do conteúdo dele.<sup>[[4]](#references)</sup>

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

ou usando o _Process Explorer_ da Sysinternals (selecione o processo e acesse a guia "Security"):

![Access Tokens - Access Tokens: ou usando o Process Explorer da Sysinternals (selecione o processo e acesse a guia "Security")](<../../images/image (772).png>)

### Administrador local

Quando o **UAC Admin Approval Mode** se aplica a um administrador, o logon interativo cria um token de administrador completo e um token filtrado. O Explorer e os processos filhos comuns usam o token filtrado por padrão. Uma solicitação de elevação, como **Run as administrator**, pede ao UAC para iniciar o programa com o token completo. O comportamento exato varia para a conta interna Administrator e quando o Admin Approval Mode está desabilitado.<sup>[[5]](#references)</sup>

Consulte a [**página do UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) dedicada para ver técnicas de bypass e detalhes das políticas.

Na prática, isso significa que um **shell de administrador não elevado geralmente é executado com um token filtrado**. Por isso, `whoami /groups` costuma mostrar **`BUILTIN\Administrators` como `Deny only`** até que o processo seja elevado. Internamente, o Windows mantém um **token elevado vinculado** (`TokenLinkedToken`) e acompanha o estado com campos como `TokenElevationType`.

### Impersonação de usuário com credenciais

Se você tiver **credenciais válidas de qualquer outro usuário**, poderá **criar** uma **nova sessão de logon** com essas credenciais :

```
runas /user:domain\username cmd.exe
```

O **access token** também possui uma **referência** às sessões de logon dentro do **LSASS**; isso é útil se o processo precisar acessar alguns objetos da rede.\
Você pode iniciar um processo que **usa credenciais diferentes para acessar serviços de rede** usando:

```
runas /user:domain\username /netonly cmd.exe
```

Isso é útil se você tiver credenciais válidas para acessar objetos na rede, mas elas não forem válidas no host atual, pois serão usadas apenas na rede (no host atual, serão usados os privilégios do usuário atual).

#### detalhes de `runas /netonly`

`runas /netonly` (e helpers de C2, como `make_token`) cria um token **`LOGON32_LOGON_NEW_CREDENTIALS`**. É muito útil entender isso durante o lateral movement porque:<sup>[[3]](#references)</sup>

- **Localmente**, o novo processo mantém a **mesma identidade local**, os mesmos grupos, o mesmo nível de integridade e a maioria das mesmas decisões de acesso do token atual.
- **Remotamente**, a autenticação de saída pode usar as **credenciais fornecidas** para SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Portanto, `whoami` ainda pode mostrar o **usuário local original**, enquanto o acesso à rede ocorre como a **conta alternativa**.

Essa é uma ótima opção quando as credenciais são válidas no domínio ou em outro host, mas o usuário **não pode ou não deve fazer logon localmente** na máquina atual.

### Tipos de tokens

Há dois tipos de tokens disponíveis:<sup>[[4]](#references)[[6]](#references)</sup>

- **Token primário**: Representa o contexto de segurança de um processo. Normalmente, um processo filho herda o token primário do pai, enquanto as APIs de criação de processos com token explícito impõem seus próprios requisitos de acesso ao token e de privilégios do chamador.
- **Token de impersonation**: Permite que uma thread do servidor use temporariamente o contexto de segurança de um cliente para verificações de acesso. Seus quatro níveis são:
  - **Anonymous**: Concede ao servidor acesso semelhante ao de um usuário não identificado.
  - **Identification**: Permite que o servidor verifique a identidade do cliente sem usá-la para acessar objetos.
  - **Impersonation**: Permite que o servidor opere usando a identidade do cliente.
  - **Delegation**: Permite que o servidor represente o cliente em sistemas remotos quando o mecanismo de autenticação e a configuração da conta oferecem suporte à delegação.

#### Faça a triagem de um token capturado antes de usá-lo

Não selecione um token apenas pelo nome de usuário. A mesma conta pode ter vários tokens com diferentes sessões de logon, SIDs de serviço, privilégios, níveis de integridade, restrições e credenciais de rede.<sup>[[9]](#references)</sup> Consulte pelo menos **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** e **`TokenStatistics.AuthenticationId`** com `GetTokenInformation`.<sup>[[7]](#references)</sup>

Um token restrito pode conter SIDs somente para negação, privilégios removidos e SIDs de restrição. Quando há SIDs de restrição, o Windows realiza uma verificação de acesso com os SIDs habilitados e outra com os SIDs de restrição; **ambas as verificações precisam permitir o acesso**. Portanto, um SID de usuário aparentemente vantajoso ou um grupo habilitado na saída não comprova, por si só, que o token pode acessar o objeto de destino.<sup>[[8]](#references)</sup>

Use este fluxo de decisão para os requisitos documentados de token e criação de processos:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Um **token primário** precisa de um handle com `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` antes de poder ser fornecido a `CreateProcessWithTokenW` ou `CreateProcessAsUserW`.
2. Converta um **token de impersonation** com `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Tokens de nível Identification podem expor dados de identidade, mas não podem realizar verificações de acesso como esse cliente.
3. `CreateProcessWithTokenW` precisa do `SeImpersonatePrivilege` e inicia o processo filho na sessão do chamador. Já `CreateProcessAsUserW` usa a sessão do token, mas normalmente precisa do `SeIncreaseQuotaPrivilege` e pode precisar do `SeAssignPrimaryTokenPrivilege`. Se houver credenciais disponíveis e esses privilégios estiverem ausentes, `CreateProcessWithLogonW` é a alternativa documentada.

#### Procure handles de token, não apenas proprietários de processos

Abrir o token primário de cada processo pode não encontrar **tokens de impersonation mantidos como handles comuns** em serviços e processos broker. Um fluxo reutilizável para tabelas de handles consiste em enumerar os handles do sistema, filtrar objetos de token, abrir cada processo proprietário com `PROCESS_DUP_HANDLE`, duplicar o handle candidato no processo atual e, em seguida, consultar os campos acima. Confirme que o handle duplicado inclui `TOKEN_QUERY` e `TOKEN_DUPLICATE`; encontrar um handle de token não significa que ele possa ser duplicado em um token primário utilizável. Processos protegidos e DACLs de processos ainda podem impedir o acesso ao handle do processo proprietário.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatiza a enumeração de tokens primários de processos e de handles de token mantidos. `list_token` mantém um candidato preferencial por nome de usuário, enquanto `list_all_token` exibe todos os candidatos. Um PID limita a enumeração a um único processo proprietário.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Para inspeção manual e verificação de acesso, **TokenUniverse** pode abrir tokens de processos/threads, pesquisar handles de token existentes, inspecionar restrições e sessões de logon, duplicar tokens e testar vários métodos de criação de processos.<sup>[[13]](#references)</sup> Para ver a primitiva subjacente de handle entre processos, consulte:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### Procure tokens de impersonation em threads ativas

Uma thread de serviço pode impersonar temporariamente um cliente mesmo quando o **token primário do processo** pertence à conta do serviço; por isso, verificações de proprietário do processo podem não detectar o contexto do cliente.<sup>[[4]](#references)</sup> TokenUniverse pode listar tokens acessíveis de processos/threads; no System Informer, inspecione a aba **Threads** de um processo e a coluna **Impersonation** para encontrar threads candidatas.<sup>[[13]](#references)[[14]](#references)</sup>

Para uma verificação direcionada via API, obtenha um snapshot `TH32CS_SNAPTHREAD`, filtre `THREADENTRY32.th32OwnerProcessID` pelo PID do serviço e, em seguida, chame `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` e `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)` para cada thread acessível.<sup>[[15]](#references)[[16]](#references)</sup> `TRUE` faz com que a verificação de acesso para abrir o token use o contexto de **processo** do chamador, o que importa se o próprio scanner estiver impersonando no nível de identificação.<sup>[[17]](#references)</sup> Consulte o usuário, o tipo, o nível de impersonation e o ID de logon do token antes de tentar o fluxo de duplicação/criação de processos acima.<sup>[[7]](#references)</sup> Uma thread pode parar de impersonar entre a enumeração e a abertura; a ausência de token, tokens anônimos, threads protegidas, DACLs de thread e DACLs de token podem impedir a coleta.<sup>[[16]](#references)[[17]](#references)</sup> Ao contrário da verificação de handles de token retidos por um serviço, isso testa o **token atualmente atribuído à thread**.

Para um caminho de ataque que obtém um token de thread fazendo com que um cliente privilegiado se conecte ao seu pipe, em vez de verificar threads existentes, consulte [impersonation de cliente por named pipe](named-pipe-client-impersonation.md).

#### Impersonar tokens

Usando o módulo _**incognito**_ do metasploit, se você tiver privilégios suficientes, poderá facilmente **listar** e **impersonar** outros **tokens**. Isso pode ser útil para executar **ações como se você fosse o outro usuário**. Você também pode **escalar privilégios** com essa técnica.

Algumas observações práticas que são fáceis de esquecer durante a operação:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** exige **`SeImpersonatePrivilege`** do chamador, e o novo processo será executado na **sessão do chamador**.
- **`CreateProcessAsUserW`** é uma alternativa possível quando `CreateProcessWithTokenW` falha com `1314`, mas somente se o chamador atender aos requisitos de privilégios. Também é a opção correta quando o processo filho precisa ser executado na **sessão referenciada pelo token**.<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`** retorna um **token de impersonation**. Converta-o com **`DuplicateTokenEx(..., TokenPrimary, ...)`** antes de criar o processo. Mesmo após a conversão, o processo resultante não poderá usar esse logon de rede para acessar compartilhamentos ou impressoras remotos autenticados: esse tipo de logon não armazena credenciais em cache. Use um logon interativo ou de texto não criptografado pela rede quando tiver credenciais e precisar de acesso subsequente à rede; não confunda isso com `LOGON32_LOGON_NEW_CREDENTIALS` (`runas /netonly`), que mantém a identidade local enquanto fornece credenciais de saída.<sup>[[18]](#references)</sup>
- Nem todo token de impersonation é igualmente útil: **`SecurityIdentification`** permite inspecionar o usuário, mas **não agir como ele**. Se uma primitiva de coerção ou um cliente de pipe/RPC fornecer apenas um token no nível de identificação, verifique **`TokenImpersonationLevel`** e use uma primitiva que produza **`SecurityImpersonation`** ou superior.

#### Roubo de tokens sem tocar no LSASS

Se você já tem um contexto de **serviço** ou **SYSTEM** e um **usuário privilegiado está conectado**, roubar ou duplicar o token desse usuário costuma ser mais discreto do que despejar o **LSASS**. Em muitas invasões reais, isso basta para:<sup>[[2]](#references)</sup>

- executar ações locais como esse usuário
- acessar recursos remotos como esse usuário
- realizar operações no AD sem primeiro extrair credenciais reutilizáveis

Para exemplos de **sequestro de tokens de sessão/usuário** a partir de um contexto privilegiado, consulte [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Lembre-se de que APIs como **`WTSQueryUserToken`** destinam-se a **serviços altamente confiáveis** e normalmente exigem **`LocalSystem` + `SeTcbPrivilege`**, portanto são úteis principalmente quando você já controla um contexto de nível de serviço. Para conhecer métodos específicos de privilégios para obter **SYSTEM** primeiro, consulte as páginas abaixo.

### Privilégios de token

Saiba quais **privilégios de token podem ser abusados para escalar privilégios:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Veja [**todos os privilégios de token possíveis e algumas definições nesta página externa**](https://github.com/gtworek/Priv2Admin).



## References

- [1] [Entendendo e abusando de Access Tokens — Parte II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusando dos tokens do Windows para comprometer o Active Directory sem tocar no LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Desmistificando o comando "make_token" do Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Como o User Account Control funciona - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Níveis de impersonation - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Enumeração TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Tokens restritos - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Função CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Função CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Função DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [Solicitação de recurso de token de thread do System Informer](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [Percorrendo a lista de threads - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
