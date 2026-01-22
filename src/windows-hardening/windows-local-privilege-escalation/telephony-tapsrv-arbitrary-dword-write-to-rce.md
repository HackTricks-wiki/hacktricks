# Telephony tapsrv — довільний запис DWORD до RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Коли Windows Telephony service (TapiSrv, `tapisrv.dll`) налаштовано як **TAPI server**, він експонує **`tapsrv` MSRPC interface over the `\pipe\tapsrv` named pipe** для автентифікованих SMB клієнтів. Помилка в дизайні механізму асинхронної доставки подій для віддалених клієнтів дозволяє нападнику перетворити дескриптор mailslot на **контрольований 4-байтовий запис у будь-який існуючий файл, доступний для запису `NETWORK SERVICE`**. Цей примітив можна зв'язати, щоб перезаписати список адміністраторів Telephony і зловживати **завантаженням довільного DLL, доступним лише для адміністраторів**, щоб виконати код від імені `NETWORK SERVICE`.

## Поверхня атаки
- **Віддалений доступ лише коли увімкнено**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` має дозволяти спільний доступ (або налаштовано через `TapiMgmt.msc` / `tcmsetup /c <server>`). За замовчуванням `tapsrv` доступний лише локально.
- Інтерфейс: MS-TRP (`tapsrv`) через **SMB named pipe**, тому нападнику потрібна дійсна SMB аутентифікація.
- Обліковий запис сервісу: `NETWORK SERVICE` (ручний запуск, за вимогою).

## Примітив: плутанина шляху mailslot → довільний запис DWORD
- `ClientAttach(pszDomainUser, pszMachine, ...)` ініціалізує доставку асинхронних подій. У pull-режимі сервіс виконує:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
не перевіряючи, що `pszDomainUser` є шляхом до mailslot (`\\*\MAILSLOT\...`). Приймається будь-який **існуючий шлях у файловій системі**, доступний для запису `NETWORK SERVICE`.
- Кожен асинхронний запис події зберігає один **`DWORD` = `InitContext`** (керований нападником у наступному запиті `Initialize`) у відкритий дескриптор, що дає примітив **write-what/write-where (4 bytes)**.

## Примусове детерміноване записування
1. **Відкрийте цільовий файл**: `ClientAttach` з `pszDomainUser = <existing writable path>` (наприклад, `C:\Windows\TAPI\tsec.ini`).
2. Для кожного `DWORD`, який потрібно записати, виконайте цю послідовність RPC проти `ClientRequest`:
- `Initialize` (`Req_Func 47`): встановіть `InitContext = <4-byte value>` і `pszModuleName = DIALER.EXE` (або інший верхній запис у per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (реєструє line app, перераховує отримувача з найвищим пріоритетом).
- `TRequestMakeCall` (`Req_Func 121`): примушує `NotifyHighestPriorityRequestRecipient`, генеруючи асинхронну подію.
- `GetAsyncEvents` (`Req_Func 0`): витягує/завершує запис.
- `LRegisterRequestRecipient` знову з `bEnable = 0` (скасовує реєстрацію).
- `Shutdown` (`Req_Func 86`) щоб згорнути line app.
- Контроль пріоритету: отримувач із «найвищим пріоритетом» обирається порівнянням `pszModuleName` з `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (читається під час успадкування контексту клієнта). За потреби вставте ім'я вашого модуля через `LSetAppPriority` (`Req_Func 69`).
- Файл **повинен уже існувати**, оскільки використовується `OPEN_EXISTING`. Типові кандидати, доступні для запису `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.

## Від запису DWORD до RCE всередині TapiSrv
1. **Надати собі права Telephony “admin”**: ціль — `C:\Windows\TAPI\tsec.ini`, додайте `[TapiAdministrators]\r\n<DOMAIN\\user>=1` використовуючи вищенаведені 4-байтові записи. Розпочніть **нову** сесію (`ClientAttach`), щоб сервіс перечитав INI і встановив `ptClient->dwFlags |= 9` для вашого облікового запису.
2. **Завантаження DLL тільки для адміністраторів**: надішліть `GetUIDllName` з `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` і передайте шлях через `dwProviderFilenameOffset`. Для адміністраторів сервіс виконає `LoadLibrary(path)`, а потім викличе експорт `TSPI_providerUIIdentify`:
- Працює з UNC-шляхами до реального Windows SMB share; деякі зловмисні SMB-сервери повертають `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Альтернатива: повільно створити локальний DLL за допомогою того самого примітива 4-байтового запису, а потім завантажити його.
3. **Payload**: експорт виконується під привілеями `NETWORK SERVICE`. Мінімальний DLL може виконати `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` і повернути ненульове значення (наприклад, `0x1337`), щоб сервіс розвантажив DLL, підтверджуючи виконання.

## Заходи захисту та виявлення
- Вимкніть TAPI server mode, якщо він не потрібен; блокпостійте віддалений доступ до `\pipe\tapsrv`.
- Перевіряйте namespace mailslot (`\\*\MAILSLOT\`) перед відкриттям шляхів, переданих клієнтом.
- Жорстко обмежте ACL для `C:\Windows\TAPI\tsec.ini` і моніторте зміни; сповіщуйте при викликах `GetUIDllName`, що завантажують шляхи, відмінні від стандартних.

## Джерела
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
