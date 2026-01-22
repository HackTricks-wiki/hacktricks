# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Wenn der Windows Telephony service (TapiSrv, `tapisrv.dll`) als **TAPI server** konfiguriert ist, exponiert er die **`tapsrv` MSRPC interface über die `\pipe\tapsrv` named pipe** für authentifizierte SMB-Clients. Ein Designfehler in der asynchronen Event-Zustellung für entfernte Clients erlaubt es einem Angreifer, einen mailslot-Handle in einen **kontrollierten 4-Byte-Schreibzugriff auf jede bereits vorhandene Datei, die von `NETWORK SERVICE` beschreibbar ist**, zu verwandeln. Dieses Primitive kann verkettet werden, um die Telephony-Admin-Liste zu überschreiben und eine **Admin-only arbitrary DLL load** auszunutzen, um Code als `NETWORK SERVICE` auszuführen.

## Attack Surface
- **Remote-Zugriff nur wenn aktiviert**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` muss Sharing erlauben (oder über `TapiMgmt.msc` / `tcmsetup /c <server>` konfiguriert sein). Standardmäßig ist `tapsrv` nur lokal.
- Interface: MS-TRP (`tapsrv`) über **SMB named pipe**, daher benötigt der Angreifer gültige SMB-Authentifizierung.
- Service-Konto: `NETWORK SERVICE` (manuell startbar, on-demand).

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` initialisiert die asynchrone Event-Zustellung. Im Pull-Modus führt der Service:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
aus, ohne zu prüfen, dass `pszDomainUser` ein mailslot-Pfad (`\\*\MAILSLOT\...`) ist. Jeder **existierende Dateisystempfad**, der von `NETWORK SERVICE` beschreibbar ist, wird akzeptiert.
- Jeder asynchrone Event-Schreibvorgang schreibt ein einzelnes **`DWORD` = `InitContext`** (angreiferkontrolliert im nachfolgenden `Initialize`-Request) in den geöffneten Handle und ergibt damit einen **write-what/write-where (4 bytes)**.

## Forcing Deterministic Writes
1. **Ziel-Datei öffnen**: `ClientAttach` mit `pszDomainUser = <existing writable path>` (z. B. `C:\Windows\TAPI\tsec.ini`).
2. Für jedes zu schreibende `DWORD` führe die folgende RPC-Sequenz gegen `ClientRequest` aus:
- `Initialize` (`Req_Func 47`): setze `InitContext = <4-byte value>` und `pszModuleName = DIALER.EXE` (oder einen anderen Top-Eintrag in der per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registriert die line app, rekalkuliert den highest priority recipient).
- `TRequestMakeCall` (`Req_Func 121`): erzwingt `NotifyHighestPriorityRequestRecipient`, was das asynchrone Event erzeugt.
- `GetAsyncEvents` (`Req_Func 0`): deqeuue/complete des Schreibvorgangs.
- `LRegisterRequestRecipient` erneut mit `bEnable = 0` (unregistrieren).
- `Shutdown` (`Req_Func 86`) um die line app abzubauen.
- Priority-Kontrolle: Der “highest priority” recipient wird durch Vergleich von `pszModuleName` mit `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` bestimmt (gelesen während der Impersonation des Clients). Falls nötig, füge deinen Modulnamen via `LSetAppPriority` (`Req_Func 69`) ein.
- Die Datei **muss bereits existieren**, weil `OPEN_EXISTING` verwendet wird. Übliche von `NETWORK SERVICE` beschreibbare Kandidaten: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.

## From DWORD Write to RCE inside TapiSrv
1. **Sich selbst Telephony “admin”rechte geben**: Ziel `C:\Windows\TAPI\tsec.ini` und anhängen von `[TapiAdministrators]\r\n<DOMAIN\\user>=1` mittels der oben beschriebenen 4-Byte-Schreibvorgänge. Starte eine **neue** Session (`ClientAttach`), sodass der Service die INI neu einliest und `ptClient->dwFlags |= 9` für dein Konto setzt.
2. **Admin-only DLL load**: sende `GetUIDllName` mit `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` und übergebe einen Pfad über `dwProviderFilenameOffset`. Für Admins führt der Service `LoadLibrary(path)` aus und ruft dann den Export `TSPI_providerUIIdentify` auf:
- Funktioniert mit UNC-Pfaden zu einem echten Windows SMB-Share; einige böse SMB-Server des Angreifers schlagen mit `ERROR_SMB_GUEST_LOGON_BLOCKED` fehl.
- Alternative: lege langsam eine lokale DLL mit demselben 4-Byte-Write-Primitive ab und lade diese.
3. **Payload**: Der Export läuft unter `NETWORK SERVICE`. Eine minimale DLL kann `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` ausführen und einen non-zero Rückgabewert (z. B. `0x1337`) zurückgeben, sodass der Service die DLL entlädt — damit ist die Ausführung bestätigt.

## Hardening / Detection Notes
- Deaktiviere TAPI server mode, sofern nicht benötigt; blockiere Remote-Zugriff auf `\pipe\tapsrv`.
- Validiere die mailslot-Namespace (`\\*\MAILSLOT\...`) bevor client-seitig gelieferte Pfade geöffnet werden.
- Schütze die ACLs von `C:\Windows\TAPI\tsec.ini` und überwache Änderungen; löse Alerts bei `GetUIDllName`-Aufrufen aus, die non-default Pfade laden.

## References
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
