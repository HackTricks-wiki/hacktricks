# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**これは [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) の投稿の概要です。詳細については投稿を確認してください！**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 以降では、`DOTNET_STARTUP_HOOKS` 環境変数がサポートされています。各パスは、`public static void Initialize()` メソッドを持つグローバルな `StartupHook` 型を含む managed assembly を指定する必要があります。ホストはアプリケーションの `Main` エントリポイントの前にアセンブリを読み込み、その初期化子を同期的に呼び出します。これにより、環境を制御でき、読み取り可能な DLL を使った pre-main コード実行プリミティブが直接提供されます。<sup>[[2]](#references)</sup>
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
Hook assembly は、アプリケーションの runtime および dependencies と互換性がなければなりません。directory separator を含む relative path は拒否されるため、absolute path、または default load context から解決可能な assembly name を使用してください。Startup hooks は trimmed applications ではデフォルトで無効になっており、custom native hosts は environment を継承する代わりに runtime properties を直接指定する場合があります。<sup>[[2]](#references)</sup>

Defensive launchers は `DOTNET_STARTUP_HOOKS` をクリアし、application および shared assembly paths への untrusted writes を防止し、self-contained deployment と trimmed deployment を個別にテストすべきです。

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Debugging Session の確立** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET における debugger と debuggee 間の communication は、[**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) によって管理されます。この component は、[dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) に示されているように、各 .NET process 用に 2 つの named pipes を設定します。これらは [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) を介して初期化されます。これらの pipes には **`-in`** および **`-out`** という suffix が付けられます。

ユーザーの **`$TMPDIR`** を確認すると、.Net applications の debugging に使用可能な debugging FIFOs を見つけることができます。

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) は、debugger からの communication の管理を担当します。新しい debugging session を開始するには、debugger は `MessageHeader` struct で始まる message を `out` pipe 経由で送信する必要があります。.NET source code では、次のように詳細が説明されています。
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
新しいセッションを要求するには、この struct に次のように値を設定し、message type を `MT_SessionRequest`、protocol version を現在のバージョンに設定します。
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
このヘッダーはその後、`write` syscall を使用して target に送信され、続いてセッション用の GUID を含む `sessionRequestData` struct が送信されます。
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` pipe の read operation により、debugging session の確立の成否を確認できます：
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## メモリの読み取り

デバッグセッションが確立されると、[`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message typeを使用してメモリを読み取れます。関数 readMemoryでは、読み取りリクエストを送信してレスポンスを取得するために必要な手順が詳しく説明されています:
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
完全な proof of concept（POC）は[こちら](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b)で確認できます。

## メモリへの書き込み

同様に、`writeMemory` functionを使用してメモリに書き込むことができます。このプロセスでは、メッセージタイプを`MT_WriteMemory`に設定し、データのアドレスと長さを指定してから、データを送信します。
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
関連するPOCは[こちら](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)で利用できます。

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

codeを実行するには、rw​​x permissionsを持つmemory regionを特定する必要があります。これはvmmap -pages:を使用して実行できます。
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
関数ポインターを上書きする場所を特定する必要があり、.NET Coreでは **Dynamic Function Table (DFT)** をターゲットにすることでこれを実行できます。このテーブルは [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) に詳しく記載されており、JITコンパイルのヘルパー関数のためにruntimeで使用されます。

x64システムでは、signature huntingを使用して `libcorclr.dll` 内のシンボル `_hlpDynamicFuncTable` への参照を見つけることができます。

`MT_GetDCB` debugger functionは、ヘルパー関数 `m_helperRemoteStartAddr` のアドレスなど、有用な情報を提供します。これは、プロセスメモリ内における `libcorclr.dll` の位置を示します。このアドレスを使用してDFTの検索を開始し、関数ポインターをshellcodeのアドレスで上書きします。

PowerShellへのinjection用の完全なPOC codeは[こちら](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)から入手できます。

## References

- [1] [Adam Chester (xpnsec) - Third Party Frameworks経由のmacOS Injection](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [.NET runtime host startup hookの設計](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
