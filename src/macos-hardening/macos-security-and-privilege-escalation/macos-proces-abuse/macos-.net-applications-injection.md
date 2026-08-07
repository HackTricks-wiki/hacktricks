# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) gönderisinin bir özetidir. Daha fazla ayrıntı için gönderiyi inceleyin!**<sup>[[1]](#references)</sup>

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Bir Debugging Session Oluşturma** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET'te debugger ile debuggee arasındaki iletişimin yönetimi [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) tarafından gerçekleştirilir. Bu bileşen, [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) içinde görüldüğü üzere her .NET process'i için iki adet named pipe oluşturur; bu pipe'lar [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) üzerinden başlatılır. Bu pipe'ların sonuna **`-in`** ve **`-out`** eklenir.

Kullanıcının **`$TMPDIR`** dizinine gidildiğinde, .Net applications için kullanılabilir debugging FIFO'ları bulunabilir.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259), debugger'dan gelen iletişimi yönetmekten sorumludur. Yeni bir debugging session başlatmak için debugger, `MessageHeader` struct'ı ile başlayan bir mesajı `out` pipe üzerinden göndermelidir; bu struct .NET source code'da ayrıntılı olarak açıklanmıştır:
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
Yeni bir session talep etmek için bu struct, message type `MT_SessionRequest` ve protocol version güncel sürüm olarak ayarlanarak aşağıdaki şekilde doldurulur:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Bu header daha sonra `write` syscall kullanılarak hedefe gönderilir; bunu, oturum için bir GUID içeren `sessionRequestData` struct'ı izler:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` pipe'ı üzerindeki bir okuma işlemi, debugging session establishment işleminin başarılı olup olmadığını doğrular:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Memory Okuma

Bir debugging session oluşturulduktan sonra, [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message type kullanılarak memory okunabilir. Gerekli adımları gerçekleştirerek bir read request gönderen ve response'u alan readMemory function aşağıda ayrıntılı olarak açıklanmıştır:
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
Tam proof of concept (POC) [burada](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) mevcuttur.

## Bellek Yazma

Benzer şekilde, `writeMemory` function kullanılarak belleğe veri yazılabilir. İşlem, mesaj türünün `MT_WriteMemory` olarak ayarlanmasını, verinin adresi ve uzunluğunun belirtilmesini ve ardından verinin gönderilmesini içerir:
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
İlgili POC'ye [buradan](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5) ulaşabilirsiniz.

## .NET Core Kod Çalıştırma <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Kod çalıştırmak için rwx izinlerine sahip bir memory region belirlemek gerekir; bu işlem vmmap -pages kullanılarak yapılabilir:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Bir function pointer'ı overwrite edebileceğiniz bir konum bulmak gereklidir ve .NET Core'da bu işlem **Dynamic Function Table (DFT)** hedeflenerek gerçekleştirilebilir. [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) dosyasında ayrıntılı olarak açıklanan bu tablo, runtime tarafından JIT compilation helper functions için kullanılır.

x64 sistemlerde, `libcorclr.dll` içindeki `_hlpDynamicFuncTable` sembolüne bir referans bulmak için signature hunting kullanılabilir.

`MT_GetDCB` debugger function'ı, `m_helperRemoteStartAddr` adlı bir helper function'ın adresi de dahil olmak üzere yararlı bilgiler sağlar. Bu adres, process memory içindeki `libcorclr.dll` konumunu gösterir. Ardından bu adres, DFT için arama başlatmak ve bir function pointer'ı shellcode adresiyle overwrite etmek amacıyla kullanılır.

PowerShell'e injection için tam POC koduna [buradan](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) erişilebilir.

## Referanslar

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
