# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Це короткий виклад допису [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Перегляньте його для отримання додаткових деталей!**<sup>[1]</sup>

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Встановлення Debugging-сесії** <a href="#net-core-debugging" id="net-core-debugging"></a>

Обробка комунікації між debugger і debuggee у .NET здійснюється за допомогою [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Цей компонент налаштовує два іменовані канали для кожного .NET-процесу, як показано в [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), які ініціалізуються через [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Ці канали мають суфікси **`-in`** і **`-out`**.

Перейшовши до **`$TMPDIR`** користувача, можна знайти FIFO для Debugging .Net-застосунків.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) відповідає за керування комунікацією від debugger. Щоб ініціювати нову Debugging-сесію, debugger має надіслати повідомлення через канал `out`, яке починається зі структури `MessageHeader`, описаної у вихідному коді .NET:
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
Щоб запросити нову сесію, цю структуру заповнюють таким чином, встановлюючи тип повідомлення `MT_SessionRequest` і поточну версію протоколу:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Потім цей заголовок надсилається до цільової системи за допомогою системного виклику `write`, після чого передається структура `sessionRequestData`, що містить GUID сесії:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Операція читання з каналу `out` підтверджує успішне або невдале встановлення сеансу налагодження:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Читання пам’яті

Після встановлення сеансу налагодження пам’ять можна читати за допомогою типу повідомлення [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Функція readMemory детально описує необхідні кроки для надсилання запиту на читання та отримання відповіді:
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

## Запис у пам’ять

Так само пам’ять можна записувати за допомогою функції `writeMemory`. Процес передбачає встановлення типу повідомлення `MT_WriteMemory`, указання адреси та довжини даних, а потім надсилання даних:
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

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Щоб виконати код, потрібно ідентифікувати ділянку пам’яті з дозволами rwx. Це можна зробити за допомогою vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Пошук місця для перезапису вказівника на функцію є необхідним, і в .NET Core це можна зробити, націлившись на **Dynamic Function Table (DFT)**. Ця таблиця, описана в [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), використовується runtime для допоміжних функцій JIT-компіляції.

Для x64-систем можна використати пошук сигнатур, щоб знайти посилання на символ `_hlpDynamicFuncTable` у `libcorclr.dll`.

Функція debugger `MT_GetDCB` надає корисну інформацію, зокрема адресу допоміжної функції `m_helperRemoteStartAddr`, яка вказує на розташування `libcorclr.dll` у пам'яті процесу. Потім ця адреса використовується для початку пошуку DFT і перезапису вказівника на функцію адресою shellcode.

Повний код POC для ін'єкції в PowerShell доступний [тут](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## References

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
