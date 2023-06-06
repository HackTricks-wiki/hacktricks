## Tokens de Acesso

Cada **usuário logado** no sistema **possui um token de acesso com informações de segurança** para aquela sessão de logon. O sistema cria um token de acesso quando o usuário faz o login. **Cada processo executado** em nome do usuário **tem uma cópia do token de acesso**. O token identifica o usuário, os grupos do usuário e os privilégios do usuário. Um token também contém um SID (Identificador de Segurança) de logon que identifica a sessão de logon atual.

Você pode ver essas informações executando `whoami /all`.
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
ou usando o _Process Explorer_ da Sysinternals (selecione o processo e acesse a guia "Segurança"):

![](<../../.gitbook/assets/image (321).png>)

### Administrador local

Quando um administrador local faz login, **dois tokens de acesso são criados**: um com direitos de administrador e outro com direitos normais. **Por padrão**, quando esse usuário executa um processo, o token com **direitos regulares** (não administrativos) é usado. Quando esse usuário tenta **executar** algo **como administrador** ("Executar como Administrador", por exemplo), o **UAC** será usado para solicitar permissão.\
Se você quiser [**saber mais sobre o UAC, leia esta página**](../authentication-credentials-uac-and-efs.md#uac)**.**

### Impersonação de usuário de credenciais

Se você tiver **credenciais válidas de qualquer outro usuário**, você pode **criar** uma **nova sessão de logon** com essas credenciais:
```
runas /user:domain\username cmd.exe
```
O **token de acesso** também possui uma **referência** das sessões de logon dentro do **LSASS**, o que é útil se o processo precisar acessar alguns objetos da rede.\
Você pode iniciar um processo que **usa credenciais diferentes para acessar serviços de rede** usando:
```
runas /user:domain\username /netonly cmd.exe
```
Isso é útil se você tiver credenciais úteis para acessar objetos na rede, mas essas credenciais não são válidas dentro do host atual, pois elas só serão usadas na rede (no host atual, as suas atuais privilégios de usuário serão usados).

### Tipos de tokens

Existem dois tipos de tokens disponíveis:

* **Token primário**: Os tokens primários só podem ser **associados a processos** e representam o assunto de segurança de um processo. A criação de tokens primários e sua associação a processos são operações privilegiadas, exigindo dois privilégios diferentes em nome da separação de privilégios - o cenário típico vê o serviço de autenticação criando o token e um serviço de logon associando-o ao shell do sistema operacional do usuário. Os processos herdam inicialmente uma cópia do token primário do processo pai.
* **Token de impersonação**: A impersonação é um conceito de segurança implementado no Windows NT que **permite** que um aplicativo de servidor **temporariamente** "**seja**" **o cliente** em termos de acesso a objetos seguros. A impersonação tem **quatro níveis possíveis**:

    * **anônimo**, dando ao servidor o acesso de um usuário anônimo/não identificado
    * **identificação**, permitindo que o servidor inspecione a identidade do cliente, mas não use essa identidade para acessar objetos
    * **impersonação**, permitindo que o servidor atue em nome do cliente
    * **delegação**, o mesmo que a impersonação, mas estendido a sistemas remotos aos quais o servidor se conecta (por meio da preservação de credenciais).

    O cliente pode escolher o nível máximo de impersonação (se houver) disponível para o servidor como um parâmetro de conexão. A delegação e a impersonação são operações privilegiadas (a impersonação inicialmente não era, mas a negligência histórica na implementação das APIs do cliente que falhavam em restringir o nível padrão para "identificação", permitindo que um servidor não privilegiado se passasse por um cliente privilegiado não disposto, exigiu isso). **Os tokens de impersonação só podem ser associados a threads** e representam o assunto de segurança de um processo do cliente. Os tokens de impersonação são geralmente criados e associados ao thread atual implicitamente, por mecanismos IPC como DCE RPC, DDE e named pipes.

#### Tokens de Impersonação

Usando o módulo _**incognito**_\*\* do metasploit, se você tiver privilégios suficientes, pode facilmente **listar** e **impersonar** outros **tokens**. Isso pode ser útil para realizar **ações como se você fosse o outro usuário**. Você também pode **escalar privilégios** com essa técnica.

### Privilégios de Token

Aprenda quais **privilégios de token podem ser abusados para escalar privilégios:**

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

Dê uma olhada em [**todos os possíveis privilégios de token e algumas definições nesta página externa**](https://github.com/gtworek/Priv2Admin).

## Referências

Saiba mais sobre tokens nestes tutoriais: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) e [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
