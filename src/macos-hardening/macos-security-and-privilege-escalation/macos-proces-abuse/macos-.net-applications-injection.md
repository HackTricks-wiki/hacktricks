# Injection aplikacji .Net w macOS

{{#include ../../../banners/hacktricks-training.md}}

**To podsumowanie wpisu [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Więcej szczegółów znajdziesz w oryginale!**<sup>[[1]](#references)</sup>

## Debugowanie .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Nawiązywanie sesji debugowania** <a href="#net-core-debugging" id="net-core-debugging"></a>

Obsługa komunikacji między debuggerem a debugowanym procesem w .NET jest zarządzana przez [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Ten komponent konfiguruje dwa named pipes dla każdego procesu .NET, jak pokazano w [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), które są inicjowane za pośrednictwem [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Te pipes mają przyrostki **`-in`** oraz **`-out`**.

Przechodząc do **`$TMPDIR`** użytkownika, można znaleźć FIFO debugowania dostępne do debugowania aplikacji .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) odpowiada za zarządzanie komunikacją z debuggera. Aby zainicjować nową sesję debugowania, debugger musi wysłać wiadomość przez pipe `out`, rozpoczynającą się od struktury `MessageHeader`, opisanej w kodzie źródłowym .NET:
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
Aby zażądać nowej sesji, ta struktura jest wypełniana w następujący sposób, ustawiając typ wiadomości na `MT_SessionRequest` oraz wersję protokołu na bieżącą wersję:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Ten nagłówek jest następnie wysyłany do celu za pomocą syscall `write`, po czym następuje struktura `sessionRequestData` zawierająca GUID sesji:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Operacja odczytu z potoku `out` potwierdza pomyślne lub nieudane ustanowienie sesji debugowania:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Odczytywanie pamięci

Po ustanowieniu sesji debugowania pamięć można odczytać za pomocą typu komunikatu [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Funkcja readMemory została szczegółowo opisana i wykonuje niezbędne kroki w celu wysłania żądania odczytu oraz pobrania odpowiedzi:
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
Kompletny proof of concept (POC) jest dostępny [tutaj](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Zapisywanie pamięci

Podobnie pamięć można zapisywać za pomocą funkcji `writeMemory`. Proces obejmuje ustawienie typu wiadomości na `MT_WriteMemory`, określenie adresu i długości danych, a następnie wysłanie danych:
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
Powiązany POC jest dostępny [tutaj](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## Wykonywanie kodu .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Aby wykonać kod, należy zidentyfikować region pamięci z uprawnieniami rwx, co można zrobić za pomocą vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Znalezienie miejsca, w którym można nadpisać wskaźnik funkcji, jest konieczne, a w .NET Core można to zrobić, celując w **Dynamic Function Table (DFT)**. Tabela ta, opisana w pliku [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), jest używana przez runtime do obsługi funkcji pomocniczych kompilacji JIT.

W systemach x64 można użyć signature hunting, aby znaleźć odwołanie do symbolu `_hlpDynamicFuncTable` w pliku `libcorclr.dll`.

Funkcja debuggera `MT_GetDCB` dostarcza przydatnych informacji, w tym adres funkcji pomocniczej `m_helperRemoteStartAddr`, wskazujący lokalizację `libcorclr.dll` w pamięci procesu. Adres ten jest następnie używany do rozpoczęcia wyszukiwania DFT i nadpisania wskaźnika funkcji adresem shellcode.

Pełny kod POC umożliwiający injection do PowerShell jest dostępny [tutaj](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## References

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
