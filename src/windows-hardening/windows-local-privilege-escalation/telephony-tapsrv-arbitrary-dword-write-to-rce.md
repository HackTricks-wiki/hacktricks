# Telephony tapsrv: довільний запис DWORD до RCE (режим TAPI Server)

{{#include ../../banners/hacktricks-training.md}}

Коли службу Windows Telephony (TapiSrv, `tapisrv.dll`) налаштовано як **TAPI server**, вона надає **інтерфейс `tapsrv` MSRPC через іменований канал `\pipe\tapsrv`** автентифікованим SMB-клієнтам. Помилка проєктування в асинхронній доставці подій для віддалених клієнтів дає зловмиснику змогу перетворити handle mailslot на **контрольований 4-байтовий запис у будь-який попередньо наявний файл, доступний для запису користувачу `NETWORK SERVICE`**. Цю примітивну операцію можна об'єднати з перезаписом списку адміністраторів Telephony та використанням **довільного завантаження DLL, доступного лише адміністраторам**, щоб виконати код від імені `NETWORK SERVICE`.<sup>[[1]](#references)</sup>

## Attack Surface

- **Віддалена доступність лише коли функцію ввімкнено**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` має дозволяти спільний доступ (або це налаштовано через `TapiMgmt.msc` / `tcmsetup /c <server>`). Типово `tapsrv` доступний лише локально.
- Інтерфейс: MS-TRP (`tapsrv`) через **SMB named pipe**, тому зловмиснику потрібні дійсні облікові дані SMB.
- Обліковий запис служби: `NETWORK SERVICE` (ручний запуск, за запитом).<sup>[[1]](#references)</sup>

## Primitive: плутанина шляхів Mailslot → довільний запис DWORD
- `ClientAttach(pszDomainUser, pszMachine, ...)` ініціалізує асинхронну доставку подій. У pull mode служба виконує:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
без перевірки, що `pszDomainUser` є шляхом mailslot (`\\*\MAILSLOT\...`). Приймається будь-який **наявний шлях у файловій системі**, доступний для запису користувачу `NETWORK SERVICE`.
- Під час кожного запису асинхронної події до відкритого handle записується одне значення **`DWORD` = `InitContext`** (контрольоване зловмисником у наступному запиті `Initialize`), що забезпечує примітив **write-what/write-where (4 байти)**.<sup>[[1]](#references)</sup>

## Примусове виконання детермінованих записів
1. **Відкрити цільовий файл**: виконати `ClientAttach` із `pszDomainUser = <existing writable path>` (наприклад, `C:\Windows\TAPI\tsec.ini`).
2. Для кожного `DWORD`, який потрібно записати, виконати таку RPC-послідовність через `ClientRequest`:
- `Initialize` (`Req_Func 47`): встановити `InitContext = <4-byte value>` і `pszModuleName = DIALER.EXE` (або інший верхній запис у списку пріоритетів для користувача).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (реєструє line app і повторно обчислює отримувача з найвищим пріоритетом).
- `TRequestMakeCall` (`Req_Func 121`): примусово викликає `NotifyHighestPriorityRequestRecipient`, генеруючи асинхронну подію.
- `GetAsyncEvents` (`Req_Func 0`): вилучає подію та завершує запис.
- Повторно виконати `LRegisterRequestRecipient` із `bEnable = 0` (скасувати реєстрацію).
- `Shutdown` (`Req_Func 86`) для завершення роботи line app.
- Керування пріоритетом: отримувач із “найвищим пріоритетом” обирається шляхом порівняння `pszModuleName` із `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (значення зчитується під час impersonation клієнта). За потреби додайте ім'я свого модуля через `LSetAppPriority` (`Req_Func 69`).
- Файл **має вже існувати**, оскільки використовується `OPEN_EXISTING`. Поширені кандидати, доступні для запису `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## Від запису DWORD до RCE всередині TapiSrv
1. **Надати собі Telephony “admin”**: вибрати `C:\Windows\TAPI\tsec.ini` як цільовий файл і додати `[TapiAdministrators]\r\n<DOMAIN\\user>=1` за допомогою наведених 4-байтових записів. Почати **нову** сесію (`ClientAttach`), щоб служба повторно прочитала INI та встановила `ptClient->dwFlags |= 9` для вашого облікового запису.
2. **Завантаження DLL, доступне лише адміністраторам**: надіслати `GetUIDllName` із `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` і передати шлях через `dwProviderFilenameOffset`. Для адміністраторів служба виконує `LoadLibrary(path)`, а потім викликає export `TSPI_providerUIIdentify`:
- Працює з UNC-шляхами до справжнього Windows SMB share; деякі SMB-сервери зловмисника завершують роботу з `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Альтернатива: повільно створити локальну DLL за допомогою того самого примітиву запису 4 байтів, а потім завантажити її.
3. **Payload**: export виконується від імені `NETWORK SERVICE`. Мінімальна DLL може запустити `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` і повернути ненульове значення (наприклад, `0x1337`), щоб служба вивантажила DLL, підтвердивши виконання.<sup>[[1]](#references)</sup>

## Нотатки щодо Hardening / Detection
- Вимикайте режим TAPI server, якщо він не потрібен; блокуйте віддалений доступ до `\pipe\tapsrv`.
- Реалізуйте перевірку простору імен mailslot (`\\*\MAILSLOT\`) перед відкриттям шляхів, наданих клієнтом.
- Обмежте ACL для `C:\Windows\TAPI\tsec.ini` і відстежуйте зміни; створюйте сповіщення про виклики `GetUIDllName`, які завантажують нестандартні шляхи.<sup>[[1]](#references)</sup>

## References

- [1] [Хто на лінії? Експлуатація RCE у Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
