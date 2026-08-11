# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Wenn der Windows Telephony-Dienst (TapiSrv, `tapisrv.dll`) als **TAPI server** konfiguriert ist, stellt er authentifizierten SMB clients das **`tapsrv` MSRPC interface über die Named Pipe `\pipe\tapsrv`** bereit. CVE-2026-20931 in der asynchronen Ereigniszustellung ermöglicht es einem Angreifer, einen vermeintlichen Mailslot-Handle in einen **kontrollierten 4-Byte-Schreibvorgang in eine bereits vorhandene Datei, die für `NETWORK SERVICE` beschreibbar ist,** umzuwandeln. Die veröffentlichte chain überschreibt die Telephony-Administratorenliste und erreicht anschließend einen Administrator-only DLL load, der als `NETWORK SERVICE` ausgeführt wird.<sup>[[1]](#references)[[2]](#references)</sup>

## Attack Surface

- **Remote exposure nur bei Aktivierung**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` muss sharing erlauben (oder über `TapiMgmt.msc` / `tcmsetup /c <server>` konfiguriert sein). Standardmäßig ist `tapsrv` nur lokal verfügbar.
- Interface: MS-TRP (`tapsrv`) über **SMB named pipe**, daher benötigt der Angreifer eine gültige SMB authentication.
- Service account: `NETWORK SERVICE` (manual start, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` initialisiert die asynchrone Ereigniszustellung. Im pull mode führt der Dienst Folgendes aus:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
ohne zu validieren, dass `pszDomainUser` ein Mailslot-Pfad (`\\*\MAILSLOT\...`) ist. Jeder **vorhandene filesystem path**, in den `NETWORK SERVICE` schreiben kann, wird akzeptiert.
- Jeder async event write speichert ein einzelnes **`DWORD` = `InitContext`** (vom Angreifer im nachfolgenden `Initialize` request kontrolliert) in den geöffneten Handle und ermöglicht dadurch **write-what/write-where (4 bytes)**.<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Zieldatei öffnen**: `ClientAttach` mit `pszDomainUser = <existing writable path>` (z. B. `C:\Windows\TAPI\tsec.ini`).
2. Für jedes zu schreibende `DWORD` diese RPC sequence gegen `ClientRequest` ausführen:
- `Initialize` (`Req_Func 47`): `InitContext = <4-byte value>` und `pszModuleName = DIALER.EXE` (oder einen anderen oberen Eintrag in der per-user priority list) setzen.
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registriert die line app und berechnet den Empfänger mit der höchsten priority neu).
- `TRequestMakeCall` (`Req_Func 121`): erzwingt `NotifyHighestPriorityRequestRecipient` und generiert das async event.
- `GetAsyncEvents` (`Req_Func 0`): dequeue/completes den write.
- Erneut `LRegisterRequestRecipient` mit `bEnable = 0` ausführen (unregister).
- `Shutdown` (`Req_Func 86`) zum Beenden der line app.
- Priority control: Der Empfänger mit der “highest priority” wird ausgewählt, indem `pszModuleName` mit `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` verglichen wird (beim impersonating des clients gelesen). Falls erforderlich, den module name über `LSetAppPriority` (`Req_Func 69`) einfügen.
- Die Datei **muss bereits vorhanden sein**, da `OPEN_EXISTING` verwendet wird. Häufige für `NETWORK SERVICE` beschreibbare Kandidaten: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **Sich selbst Telephony-„admin“-Rechte gewähren**: `C:\Windows\TAPI\tsec.ini` als Ziel verwenden und mit den oben beschriebenen 4-byte writes `[TapiAdministrators]\r\n<DOMAIN\\user>=1` anhängen. Eine **neue** session starten (`ClientAttach`), damit der Dienst die INI erneut liest und `ptClient->dwFlags |= 9` für das eigene Konto setzt.
2. **Admin-only DLL load**: `GetUIDllName` mit `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` senden und über `dwProviderFilenameOffset` einen Pfad angeben. Für admins führt der Dienst `LoadLibrary(path)` aus und ruft anschließend den Export `TSPI_providerUIIdentify` auf:
- Funktioniert mit UNC paths zu einem echten Windows SMB share; einige Angreifer-SMB-server schlagen mit `ERROR_SMB_GUEST_LOGON_BLOCKED` fehl.
- Alternative: Eine lokale DLL langsam mit derselben 4-byte write primitive ablegen und anschließend laden.
3. **Payload**: Der Export wird unter `NETWORK SERVICE` ausgeführt. Eine minimale DLL kann `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` ausführen und einen non-zero value (z. B. `0x1337`) zurückgeben, sodass der Dienst die DLL entlädt und damit die execution bestätigt.<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- Das Microsoft security update für CVE-2026-20931 installieren. TAPI server mode unabhängig davon deaktivieren, sofern er nicht benötigt wird, und remote access auf `\pipe\tapsrv` blockieren.
- Vor dem Öffnen von client-supplied paths eine Mailslot namespace validation (`\\*\MAILSLOT\`) erzwingen.
- ACLs von `C:\Windows\TAPI\tsec.ini` einschränken und Änderungen überwachen; bei `GetUIDllName`-Aufrufen, die non-default paths laden, einen alert auslösen.<sup>[[1]](#references)</sup>

## References

- [1] [Wer ist in der Leitung? RCE im Windows Telephony Service ausnutzen (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
