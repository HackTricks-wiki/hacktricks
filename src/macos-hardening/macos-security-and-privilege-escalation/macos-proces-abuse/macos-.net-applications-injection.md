# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Це короткий виклад публікації [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Перегляньте її для отримання додаткових відомостей!**<sup>[[1]](#references)</sup>

## Налагодження .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Встановлення сеансу налагодження** <a href="#net-core-debugging" id="net-core-debugging"></a>

Обробкою зв'язку між debugger і debuggee у .NET керує [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Цей компонент налаштовує два іменовані канали для кожного .NET процесу, як показано в [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), які ініціалізуються через [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Ці канали мають суфікси **`-in`** і **`-out`**.

Перейшовши до **`$TMPDIR`** користувача, можна знайти FIFO для налагодження, доступні для налагодження .Net applications.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) відповідає за керування зв'язком із debugger. Щоб ініціювати новий сеанс налагодження, debugger має надіслати повідомлення через канал `out`, яке починається зі структури `MessageHeader`, описаної у вихідному коді .NET:
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
Для запиту нового сеансу цю структуру заповнюють так, встановлюючи тип повідомлення `MT_SessionRequest` і поточну версію протоколу:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Цей заголовок потім надсилається до цілі за допомогою syscall `write`, після чого передається структура `sessionRequestData`, що містить GUID сесії:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Операція читання з каналу `out` підтверджує успішне або невдале встановлення debugging session:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Читання пам'яті

Після встановлення debugging session пам'ять можна читати за допомогою типу повідомлення [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Функція readMemory описує необхідні кроки для надсилання запиту на читання та отримання відповіді:
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

## Запис у пам'ять

Так само пам'ять можна записувати за допомогою функції `writeMemory`. Процес передбачає встановлення типу повідомлення в `MT_WriteMemory`, визначення адреси та довжини даних, а потім надсилання даних:
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

Для виконання коду потрібно ідентифікувати область пам’яті з дозволами rwx. Це можна зробити за допомогою vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Пошук місця для перезапису function pointer є необхідним, і в .NET Core це можна зробити, націлившись на **Dynamic Function Table (DFT)**. Ця таблиця, детально описана в [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), використовується runtime для helper-функцій JIT-компіляції.

У x64-системах для пошуку посилання на символ `_hlpDynamicFuncTable` у `libcorclr.dll` можна використовувати signature hunting.

Debugger-функція `MT_GetDCB` надає корисну інформацію, зокрема адресу helper-функції `m_helperRemoteStartAddr`, яка вказує на розташування `libcorclr.dll` у пам'яті процесу. Потім ця адреса використовується для початку пошуку DFT і перезапису function pointer адресою shellcode.

Повний код POC для ін'єкції в PowerShell доступний [тут](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Посилання

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
