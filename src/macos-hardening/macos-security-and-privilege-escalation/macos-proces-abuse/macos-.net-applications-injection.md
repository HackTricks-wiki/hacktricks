# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**これは投稿 [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) の概要です。詳細については投稿を確認してください！**<sup>[[1]](#references)</sup>

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **デバッグセッションの確立** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET における debugger と debuggee 間の通信処理は、[**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) によって管理されます。このコンポーネントは、[dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) に示されているように、各 .NET process に対して2つの named pipe を設定します。これらは [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) を介して初期化されます。これらの pipe には **`-in`** および **`-out`** というサフィックスが付加されます。

ユーザーの **`$TMPDIR`** にアクセスすると、.Net applications の debugging に利用できる debugging FIFO を見つけられます。

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) は、debugger からの通信を管理します。新しい debugging session を開始するには、debugger は `MessageHeader` struct で始まる message を `out` pipe 経由で送信する必要があります。その詳細は .NET source code に記載されています。
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
新しいセッションをリクエストするには、以下のようにこの struct に値を設定し、message type を `MT_SessionRequest` に、protocol version を現行バージョンに設定します。
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
この header は次に `write` syscall を使用して target に送信され、その後に session の GUID を含む `sessionRequestData` struct が続きます：
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` pipeでのread操作により、debugging sessionの確立が成功したか失敗したかを確認できます。
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## メモリの読み取り

debugging sessionが確立されると、[`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message typeを使用してメモリを読み取れます。function readMemoryでは、read requestを送信してresponseを取得するために必要な手順が詳しく説明されています：
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
完全な proof of concept (POC) は[こちら](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b)で確認できます。

## メモリへの書き込み

同様に、`writeMemory` function を使用してメモリに書き込むことができます。このプロセスでは、message type を `MT_WriteMemory` に設定し、data の address と length を指定してから、data を送信します。
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
関連する POC は[こちら](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)で確認できます。

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

コードを実行するには、rwx 権限を持つメモリ領域を特定する必要があります。これは vmmap -pages: を使用して実行できます。
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
関数ポインタを overwrite する場所を特定する必要があります。.NET Core では、**Dynamic Function Table (DFT)** を対象にすることでこれを実行できます。このテーブルは [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) で詳しく説明されており、runtime が JIT compilation の helper functions に使用します。

x64 システムでは、signature hunting を使用して `libcorclr.dll` 内のシンボル `_hlpDynamicFuncTable` への参照を見つけることができます。

デバッガ関数 `MT_GetDCB` は、helper function のアドレスを含む有用な情報を提供します。`m_helperRemoteStartAddr` は、プロセスのメモリ内における `libcorclr.dll` の位置を示します。このアドレスを使用して DFT の検索を開始し、function pointer を shellcode のアドレスで overwrite します。

PowerShell への injection に使用する完全な POC code は[こちら](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)から利用できます。

## 参考資料

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
