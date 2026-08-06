# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Wenn der Windows-Telefoniedienst (TapiSrv, `tapisrv.dll`) als **TAPI server** konfiguriert ist, stellt er authentifizierten SMB-Clients die **`tapsrv`-MSRPC-Schnittstelle über die Named Pipe `\pipe\tapsrv`** zur Verfügung. Ein Designfehler bei der asynchronen Ereignisübermittlung für Remote-Clients ermöglicht es einem Angreifer, ein Mailslot-Handle in einen **kontrollierten 4-Byte-Schreibzugriff auf jede bereits vorhandene Datei umzuwandeln, in die `NETWORK SERVICE` schreiben darf**. Dieses Primitive kann verkettet werden, um die Telephony-Administratorenliste zu überschreiben und einen **nur für Administratoren verfügbaren beliebigen DLL-Load** auszunutzen, um Code als `NETWORK SERVICE` auszuführen.<sup>[[1]](#references)</sup>

## Angriffsfläche

- **Remote-Zugriff nur bei Aktivierung**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` muss die Freigabe erlauben (oder über `TapiMgmt.msc` / `tcmsetup /c <server>` konfiguriert sein). Standardmäßig ist `tapsrv` nur lokal verfügbar.
- Schnittstelle: MS-TRP (`tapsrv`) über **SMB named pipe**, daher benötigt der Angreifer eine gültige SMB-Authentifizierung.
- Dienstkonto: `NETWORK SERVICE` (manueller Start, bei Bedarf).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` initialisiert die asynchrone Ereignisübermittlung. Im Pull-Modus führt der Dienst Folgendes aus:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
ohne zu validieren, dass `pszDomainUser` ein Mailslot-Pfad (`\\*\MAILSLOT\...`) ist. Jeder **vorhandene Dateisystempfad**, in den `NETWORK SERVICE` schreiben darf, wird akzeptiert.
- Jeder asynchrone Ereignisschreibvorgang speichert einen einzelnen **`DWORD` = `InitContext`** (vom Angreifer im nachfolgenden `Initialize`-Request kontrolliert) in das geöffnete Handle und ermöglicht dadurch **write-what/write-where (4 bytes)**.<sup>[[1]](#references)</sup>

## Erzwingen deterministischer Schreibvorgänge
1. **Zieldatei öffnen**: `ClientAttach` mit `pszDomainUser = <existing writable path>` (z. B. `C:\Windows\TAPI\tsec.ini`).
2. Für jeden zu schreibenden `DWORD` die folgende RPC-Sequenz gegenüber `ClientRequest` ausführen:
- `Initialize` (`Req_Func 47`): `InitContext = <4-byte value>` setzen und `pszModuleName = DIALER.EXE` (oder einen anderen oberen Eintrag in der benutzerbezogenen Prioritätsliste) verwenden.
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registriert die Line-App und berechnet den Empfänger mit der höchsten Priorität neu).
- `TRequestMakeCall` (`Req_Func 121`): erzwingt `NotifyHighestPriorityRequestRecipient` und erzeugt das asynchrone Ereignis.
- `GetAsyncEvents` (`Req_Func 0`): entfernt das Ereignis aus der Warteschlange und schließt den Schreibvorgang ab.
- `LRegisterRequestRecipient` erneut mit `bEnable = 0` (Registrierung aufheben).
- `Shutdown` (`Req_Func 86`), um die Line-App zu beenden.
- Prioritätssteuerung: Der Empfänger mit der „höchsten Priorität“ wird ausgewählt, indem `pszModuleName` mit `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` verglichen wird (beim Identitätswechsel zum Client gelesen). Falls erforderlich, den Modulnamen über `LSetAppPriority` (`Req_Func 69`) einfügen.
- Die Datei **muss bereits vorhanden sein**, da `OPEN_EXISTING` verwendet wird. Häufige Kandidaten mit Schreibrechten für `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## Vom DWORD Write zu RCE innerhalb von TapiSrv
1. **Sich selbst „admin“-Rechte für Telephony gewähren**: `C:\Windows\TAPI\tsec.ini` als Ziel verwenden und mit den oben beschriebenen 4-Byte-Schreibvorgängen `[TapiAdministrators]\r\n<DOMAIN\\user>=1` anhängen. Eine **neue** Sitzung (`ClientAttach`) starten, damit der Dienst die INI-Datei erneut einliest und für das Konto `ptClient->dwFlags |= 9` setzt.
2. **Nur für Administratoren verfügbarer DLL-Load**: `GetUIDllName` mit `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` senden und über `dwProviderFilenameOffset` einen Pfad angeben. Für Administratoren führt der Dienst `LoadLibrary(path)` aus und ruft anschließend den Export `TSPI_providerUIIdentify` auf:
- UNC-Pfade zu einer echten Windows-SMB-Freigabe funktionieren; bei einigen Angreifer-SMB-Servern tritt `ERROR_SMB_GUEST_LOGON_BLOCKED` auf.
- Alternative: Mit demselben 4-Byte-Schreibprimitive langsam eine lokale DLL schreiben und sie anschließend laden.
3. **Payload**: Der Export wird unter `NETWORK SERVICE` ausgeführt. Eine minimale DLL kann `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` ausführen und einen Wert ungleich null (z. B. `0x1337`) zurückgeben, damit der Dienst die DLL entlädt und die Ausführung bestätigt.<sup>[[1]](#references)</sup>

## Hinweise zu Hardening / Detection
- Den TAPI server mode deaktivieren, sofern er nicht benötigt wird; den Remote-Zugriff auf `\pipe\tapsrv` blockieren.
- Die Validierung des Mailslot-Namespace (`\\*\MAILSLOT\`) erzwingen, bevor vom Client bereitgestellte Pfade geöffnet werden.
- Die ACLs von `C:\Windows\TAPI\tsec.ini` einschränken und Änderungen überwachen; bei `GetUIDllName`-Aufrufen, die nicht standardmäßige Pfade laden, einen Alert auslösen.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
