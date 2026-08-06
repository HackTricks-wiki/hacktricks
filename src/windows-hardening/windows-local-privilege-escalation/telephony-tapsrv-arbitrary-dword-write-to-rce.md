# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Gdy usługa Windows Telephony (TapiSrv, `tapisrv.dll`) jest skonfigurowana jako **TAPI server**, udostępnia interfejs **`tapsrv` MSRPC przez named pipe `\pipe\tapsrv`** uwierzytelnionym klientom SMB. Błąd projektowy w asynchronicznym dostarczaniu zdarzeń dla klientów zdalnych pozwala atakującemu zamienić uchwyt mailslotu w **kontrolowany zapis 4 bajtów do dowolnego istniejącego pliku, do którego `NETWORK SERVICE` ma uprawnienia zapisu**. Ten primitive można połączyć z nadpisaniem listy administratorów Telephony i wykorzystaniem dostępnego wyłącznie dla administratora mechanizmu ładowania dowolnej DLL w celu wykonania kodu jako `NETWORK SERVICE`.<sup>[[1]](#references)</sup>

## Powierzchnia ataku

- **Zdalna ekspozycja tylko po włączeniu**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` musi zezwalać na udostępnianie (lub musi ono zostać skonfigurowane przez `TapiMgmt.msc` / `tcmsetup /c <server>`). Domyślnie `tapsrv` jest dostępny tylko lokalnie.
- Interface: MS-TRP (`tapsrv`) przez **SMB named pipe**, dlatego atakujący potrzebuje prawidłowego uwierzytelnienia SMB.
- Konto usługi: `NETWORK SERVICE` (uruchamianie ręczne, na żądanie).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` inicjalizuje asynchroniczne dostarczanie zdarzeń. W trybie pull usługa wykonuje:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
bez sprawdzania, czy `pszDomainUser` jest ścieżką mailslotu (`\\*\MAILSLOT\...`). Akceptowana jest dowolna istniejąca ścieżka systemu plików, do której `NETWORK SERVICE` ma uprawnienia zapisu.
- Każdy zapis zdarzenia asynchronicznego zapisuje do otwartego uchwytu pojedynczy **`DWORD` = `InitContext`** (kontrolowany przez atakującego w kolejnym żądaniu `Initialize`), zapewniając primitive **write-what/write-where (4 bytes)**.<sup>[[1]](#references)</sup>

## Wymuszanie deterministycznych zapisów
1. **Otwórz plik docelowy**: `ClientAttach` z `pszDomainUser = <existing writable path>` (np. `C:\Windows\TAPI\tsec.ini`).
2. Dla każdego zapisywanego `DWORD` wykonaj następującą sekwencję RPC względem `ClientRequest`:
- `Initialize` (`Req_Func 47`): ustaw `InitContext = <4-byte value>` oraz `pszModuleName = DIALER.EXE` (lub inną pozycję z początku listy priorytetów per-user).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (rejestruje aplikację linii i ponownie oblicza odbiorcę o najwyższym priorytecie).
- `TRequestMakeCall` (`Req_Func 121`): wymusza `NotifyHighestPriorityRequestRecipient`, generując zdarzenie asynchroniczne.
- `GetAsyncEvents` (`Req_Func 0`): usuwa zdarzenie z kolejki i kończy zapis.
- Ponownie `LRegisterRequestRecipient` z `bEnable = 0` (wyrejestrowanie).
- `Shutdown` (`Req_Func 86`) w celu usunięcia aplikacji linii.
- Kontrola priorytetu: odbiorca o „najwyższym priorytecie” jest wybierany przez porównanie `pszModuleName` z `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (odczytywanym podczas impersonacji klienta). W razie potrzeby wstaw swoją nazwę modułu za pomocą `LSetAppPriority` (`Req_Func 69`).
- Plik **musi już istnieć**, ponieważ używane jest `OPEN_EXISTING`. Typowe pliki, do których `NETWORK SERVICE` ma uprawnienia zapisu: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## Od DWORD Write do RCE wewnątrz TapiSrv
1. **Nadaj sobie uprawnienia Telephony „admin”**: wskaż `C:\Windows\TAPI\tsec.ini` i dopisz `[TapiAdministrators]\r\n<DOMAIN\\user>=1` za pomocą opisanych powyżej zapisów 4-bajtowych. Rozpocznij **nową** sesję (`ClientAttach`), aby usługa ponownie odczytała plik INI i ustawiła `ptClient->dwFlags |= 9` dla twojego konta.
2. **Ładowanie DLL dostępne tylko dla administratora**: wyślij `GetUIDllName` z `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` i przekaż ścieżkę za pomocą `dwProviderFilenameOffset`. W przypadku administratorów usługa wykonuje `LoadLibrary(path)`, a następnie wywołuje export `TSPI_providerUIIdentify`:
- Działa ze ścieżkami UNC do rzeczywistego udziału SMB systemu Windows; niektóre serwery SMB atakującego kończą się błędem `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternatywa: powoli upuść lokalną DLL za pomocą tego samego primitive zapisu 4 bajtów, a następnie ją załaduj.
3. **Payload**: export wykonuje się w kontekście `NETWORK SERVICE`. Minimalna DLL może uruchomić `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` i zwrócić wartość różną od zera (np. `0x1337`), aby usługa wyładowała DLL, potwierdzając wykonanie.<sup>[[1]](#references)</sup>

## Uwagi dotyczące hardeningu / wykrywania
- Wyłącz TAPI server mode, jeśli nie jest wymagany; zablokuj zdalny dostęp do `\pipe\tapsrv`.
- Wymuś walidację namespace mailslotu (`\\*\MAILSLOT\`) przed otwarciem ścieżek podanych przez klienta.
- Ogranicz ACL dla `C:\Windows\TAPI\tsec.ini` i monitoruj zmiany; generuj alerty dotyczące wywołań `GetUIDllName`, które ładują ścieżki inne niż domyślne.<sup>[[1]](#references)</sup>

## References

- [1] [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
