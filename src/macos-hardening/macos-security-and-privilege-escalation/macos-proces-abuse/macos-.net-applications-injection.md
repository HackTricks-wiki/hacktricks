# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Це резюме посту [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Перевірте його для отримання додаткових деталей!**

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Встановлення сесії налагодження** <a href="#net-core-debugging" id="net-core-debugging"></a>

Обробка зв'язку між налагоджувачем і налагоджуваним у .NET управляється [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Цей компонент налаштовує два іменовані канали для кожного процесу .NET, як видно в [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), які ініціюються через [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Ці канали мають суфікси **`-in`** та **`-out`**.

Відвідавши **`$TMPDIR`** користувача, можна знайти FIFOs для налагодження .Net додатків.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) відповідає за управління зв'язком з налагоджувачем. Щоб ініціювати нову сесію налагодження, налагоджувач повинен надіслати повідомлення через `out` канал, починаючи з структури `MessageHeader`, детально описаної в вихідному коді .NET:
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
Щоб запитати нову сесію, ця структура заповнюється наступним чином, встановлюючи тип повідомлення на `MT_SessionRequest` і версію протоколу на поточну версію:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Цей заголовок потім надсилається на ціль за допомогою системного виклику `write`, за яким слідує структура `sessionRequestData`, що містить GUID для сесії:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Операція читання з каналу `out` підтверджує успіх або невдачу встановлення сеансу налагодження:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Читання пам'яті

Once a debugging session is established, memory can be read using the [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message type. The function readMemory is detailed, performing the necessary steps to send a read request and retrieve the response:
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
Повний доказ концепції (POC) доступний [тут](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Запис пам'яті

Аналогічно, пам'ять можна записувати за допомогою функції `writeMemory`. Процес включає встановлення типу повідомлення на `MT_WriteMemory`, вказівку адреси та довжини даних, а потім відправку даних:
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
Пов'язаний POC доступний [тут](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Щоб виконати код, потрібно визначити область пам'яті з правами rwx, що можна зробити за допомогою vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Знаходження місця для перезапису вказівника функції є необхідним, і в .NET Core це можна зробити, націлившись на **Dynamic Function Table (DFT)**. Ця таблиця, детально описана в [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), використовується середовищем виконання для допоміжних функцій JIT-компіляції.

Для систем x64 можна використовувати підхід підбору підписів для знаходження посилання на символ `_hlpDynamicFuncTable` у `libcorclr.dll`.

Функція налагодження `MT_GetDCB` надає корисну інформацію, включаючи адресу допоміжної функції `m_helperRemoteStartAddr`, що вказує на місцезнаходження `libcorclr.dll` у пам'яті процесу. Ця адреса потім використовується для початку пошуку DFT і перезапису вказівника функції адресою shellcode.

Повний код POC для ін'єкції в PowerShell доступний [тут](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Посилання

- [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
