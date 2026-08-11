# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Gdy usługa Windows Telephony (TapiSrv, `tapisrv.dll`) jest skonfigurowana jako **TAPI server**, udostępnia interfejs **`tapsrv` MSRPC przez named pipe `\pipe\tapsrv`** uwierzytelnionym klientom SMB. CVE-2026-20931 w mechanizmie asynchronicznego dostarczania zdarzeń pozwala atakującemu zamienić rzekomy uchwyt mailslotu na **kontrolowany zapis 4 bajtów do istniejącego pliku, do którego `NETWORK SERVICE` ma uprawnienia zapisu**. Opublikowany chain nadpisuje listę administratorów Telephony, a następnie uzyskuje dostęp do ładowania DLL dostępnego tylko dla administratorów i wykonuje kod jako `NETWORK SERVICE`.<sup>[[1]](#references)[[2]](#references)</sup>

## Powierzchnia ataku

- **Zdalna ekspozycja tylko po włączeniu**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` musi zezwalać na udostępnianie (lub musi ono być skonfigurowane przez `TapiMgmt.msc` / `tcmsetup /c <server>`). Domyślnie `tapsrv` działa tylko lokalnie.
- Interfejs: MS-TRP (`tapsrv`) przez **SMB named pipe**, więc atakujący potrzebuje prawidłowego uwierzytelnienia SMB.
- Konto usługi: `NETWORK SERVICE` (uruchamianie ręczne, na żądanie).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` inicjalizuje asynchroniczne dostarczanie zdarzeń. W trybie pull usługa wykonuje:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
bez sprawdzania, czy `pszDomainUser` jest ścieżką mailslotu (`\\*\MAILSLOT\...`). Akceptowana jest dowolna istniejąca ścieżka systemu plików, do której `NETWORK SERVICE` ma uprawnienia zapisu.
- Każdy zapis zdarzenia asynchronicznego przechowuje pojedynczy **`DWORD` = `InitContext`** (kontrolowany przez atakującego w kolejnym żądaniu `Initialize`) do otwartego uchwytu, zapewniając **write-what/write-where (4 bytes)**.<sup>[[1]](#references)</sup>

## Wymuszanie deterministycznych zapisów
1. **Otwórz plik docelowy**: `ClientAttach` z `pszDomainUser = <existing writable path>` (np. `C:\Windows\TAPI\tsec.ini`).
2. Aby zapisać każdy `DWORD`, wykonaj następującą sekwencję RPC względem `ClientRequest`:
- `Initialize` (`Req_Func 47`): ustaw `InitContext = <4-byte value>` oraz `pszModuleName = DIALER.EXE` (lub inną pozycję z początku listy priorytetów per-user).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (rejestruje aplikację linii i ponownie oblicza odbiorcę o najwyższym priorytecie).
- `TRequestMakeCall` (`Req_Func 121`): wymusza `NotifyHighestPriorityRequestRecipient`, generując zdarzenie asynchroniczne.
- `GetAsyncEvents` (`Req_Func 0`): pobiera z kolejki i kończy zapis.
- Ponownie `LRegisterRequestRecipient` z `bEnable = 0` (wyrejestrowuje).
- `Shutdown` (`Req_Func 86`) w celu zamknięcia aplikacji linii.
- Kontrola priorytetu: odbiorca o „najwyższym priorytecie” jest wybierany przez porównanie `pszModuleName` z `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (odczytywanym podczas impersonation klienta). W razie potrzeby wstaw nazwę swojego modułu za pomocą `LSetAppPriority` (`Req_Func 69`).
- Plik **musi już istnieć**, ponieważ używane jest `OPEN_EXISTING`. Typowe pliki, do których `NETWORK SERVICE` ma uprawnienia zapisu: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## Od DWORD Write do RCE wewnątrz TapiSrv
1. **Nadaj sobie uprawnienia „admin” Telephony**: wskaż `C:\Windows\TAPI\tsec.ini` i dopisz `[TapiAdministrators]\r\n<DOMAIN\\user>=1` za pomocą opisanych wyżej zapisów 4-bajtowych. Rozpocznij **nową** sesję (`ClientAttach`), aby usługa ponownie odczytała plik INI i ustawiła `ptClient->dwFlags |= 9` dla Twojego konta.
2. **Ładowanie DLL dostępne tylko dla administratorów**: wyślij `GetUIDllName` z `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` i podaj ścieżkę przez `dwProviderFilenameOffset`. W przypadku administratorów usługa wykonuje `LoadLibrary(path)`, a następnie wywołuje export `TSPI_providerUIIdentify`:
- Działa ze ścieżkami UNC do rzeczywistego udziału Windows SMB; niektóre serwery SMB atakującego kończą się błędem `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternatywnie można powoli zapisać lokalną DLL za pomocą tego samego primitive 4-byte write, a następnie ją załadować.
3. **Payload**: export wykonuje się jako `NETWORK SERVICE`. Minimalna DLL może uruchomić `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` i zwrócić wartość różną od zera (np. `0x1337`), aby usługa wyładowała DLL, potwierdzając wykonanie.<sup>[[1]](#references)</sup>

## Uwagi dotyczące hardeningu / detekcji
- Zainstaluj security update Microsoft dla CVE-2026-20931. Niezależnie wyłącz tryb TAPI server, chyba że jest wymagany, i blokuj zdalny dostęp do `\pipe\tapsrv`.
- Wymuś walidację namespace mailslotu (`\\*\MAILSLOT\`) przed otwarciem ścieżek dostarczonych przez klienta.
- Ogranicz uprawnienia ACL do `C:\Windows\TAPI\tsec.ini` i monitoruj zmiany; generuj alerty dotyczące wywołań `GetUIDllName`, które ładują ścieżki inne niż domyślne.<sup>[[1]](#references)</sup>

## References

- [1] [Kto jest na linii? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
