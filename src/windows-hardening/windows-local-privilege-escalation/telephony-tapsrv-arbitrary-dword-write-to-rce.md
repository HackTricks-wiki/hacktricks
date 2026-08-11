# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Коли службу Windows Telephony (TapiSrv, `tapisrv.dll`) налаштовано як **TAPI server**, вона надає автентифікованим SMB-клієнтам **інтерфейс `tapsrv` MSRPC через іменований канал `\pipe\tapsrv`**. CVE-2026-20931 в асинхронній доставці подій дає змогу зловмиснику перетворити нібито дескриптор mailslot на **контрольований 4-байтовий запис у вже наявний файл, доступний для запису користувачу `NETWORK SERVICE`**. Опублікований ланцюжок змінює список адміністраторів Telephony, після чого досягає завантаження DLL, доступного лише адміністраторам, і виконує код від імені `NETWORK SERVICE`.<sup>[[1]](#references)[[2]](#references)</sup>

## Поверхня атаки

- **Віддалена доступність лише після ввімкнення**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` має дозволяти спільний доступ (або це має бути налаштовано через `TapiMgmt.msc` / `tcmsetup /c <server>`). За замовчуванням `tapsrv` доступний лише локально.
- Інтерфейс: MS-TRP (`tapsrv`) через **іменований канал SMB**, тому зловмиснику потрібна дійсна автентифікація SMB.
- Обліковий запис служби: `NETWORK SERVICE` (ручний запуск, за запитом).<sup>[[1]](#references)</sup>

## Примітив: плутанина шляхів Mailslot → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` ініціалізує асинхронну доставку подій. У режимі pull служба виконує:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
без перевірки, що `pszDomainUser` є шляхом до mailslot (`\\*\MAILSLOT\...`). Приймається будь-який **наявний шлях у файловій системі**, доступний для запису користувачу `NETWORK SERVICE`.
- Під час кожного запису асинхронної події до відкритого дескриптора записується одне значення **`DWORD` = `InitContext`** (контрольоване зловмисником у наступному запиті `Initialize`), що забезпечує **write-what/write-where (4 bytes)**.<sup>[[1]](#references)</sup>

## Забезпечення детермінованих записів
1. **Відкрити цільовий файл**: викликати `ClientAttach` із `pszDomainUser = <existing writable path>` (наприклад, `C:\Windows\TAPI\tsec.ini`).
2. Для кожного `DWORD`, який потрібно записати, виконати таку послідовність RPC проти `ClientRequest`:
- `Initialize` (`Req_Func 47`): встановити `InitContext = <4-byte value>` і `pszModuleName = DIALER.EXE` (або інший модуль із верхньої частини списку пріоритетів для користувача).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (реєструє line app і повторно обчислює отримувача з найвищим пріоритетом).
- `TRequestMakeCall` (`Req_Func 121`): примусово викликає `NotifyHighestPriorityRequestRecipient`, генеруючи асинхронну подію.
- `GetAsyncEvents` (`Req_Func 0`): вилучає подію та завершує запис.
- Повторно викликати `LRegisterRequestRecipient` із `bEnable = 0` (скасувати реєстрацію).
- `Shutdown` (`Req_Func 86`) для завершення роботи line app.
- Керування пріоритетом: отримувач із “найвищим пріоритетом” обирається шляхом порівняння `pszModuleName` із `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (значення читається під час impersonation клієнта). За потреби додайте ім’я свого модуля через `LSetAppPriority` (`Req_Func 69`).
- Файл **має вже існувати**, оскільки використовується `OPEN_EXISTING`. Поширені кандидати, доступні для запису користувачу `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## Від DWORD Write до RCE всередині TapiSrv
1. **Надати собі права “admin” у Telephony**: вибрати `C:\Windows\TAPI\tsec.ini` і додати `[TapiAdministrators]\r\n<DOMAIN\\user>=1` за допомогою описаних вище 4-байтових записів. Почати **нову** сесію (`ClientAttach`), щоб служба повторно прочитала INI та встановила `ptClient->dwFlags |= 9` для вашого облікового запису.
2. **Завантаження DLL лише для адміністраторів**: надіслати `GetUIDllName` із `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` і передати шлях через `dwProviderFilenameOffset`. Для адміністраторів служба виконує `LoadLibrary(path)`, а потім викликає export `TSPI_providerUIIdentify`:
- Працює з UNC-шляхами до справжньої Windows SMB share; деякі SMB-сервери зловмисника завершують роботу з `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Альтернатива: повільно створити локальну DLL за допомогою того самого примітиву 4-байтового запису, а потім завантажити її.
3. **Payload**: export виконується від імені `NETWORK SERVICE`. Мінімальна DLL може запустити `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` і повернути ненульове значення (наприклад, `0x1337`), щоб служба вивантажила DLL, підтверджуючи виконання.<sup>[[1]](#references)</sup>

## Примітки щодо Hardening / Detection
- Встановіть оновлення безпеки Microsoft для CVE-2026-20931. Окремо вимкніть TAPI server mode, якщо він не потрібен, і заблокуйте віддалений доступ до `\pipe\tapsrv`.
- Реалізуйте перевірку простору імен mailslot (`\\*\MAILSLOT\`) перед відкриттям шляхів, наданих клієнтом.
- Обмежте ACL для `C:\Windows\TAPI\tsec.ini` і відстежуйте зміни; створюйте сповіщення про виклики `GetUIDllName`, які завантажують нестандартні шляхи.<sup>[[1]](#references)</sup>

## References

- [1] [Хто на лінії? Exploiting RCE у Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
