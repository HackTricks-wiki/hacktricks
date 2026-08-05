# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**これは[https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)の記事の概要です。詳細については、こちらを確認してください！**<sup>[1]</sup>

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Debugging Sessionの確立** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NETにおけるdebuggerとdebuggee間の通信処理は、[**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp)によって管理されます。このコンポーネントは、[dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127)に示されているように、各.NETプロセスに2つの名前付きパイプを設定します。これらは[twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27)を介して開始されます。これらのパイプには**`-in`**および**`-out`**というサフィックスが付加されます。

ユーザーの**`$TMPDIR`**を確認すると、.Net applicationsのdebuggingに利用可能なdebugging FIFOを見つけることができます。

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259)は、debuggerからの通信を管理します。新しいdebugging sessionを開始するには、debuggerは、.NET source codeで詳しく説明されている`MessageHeader` structで始まるmessageを`out` pipe経由で送信する必要があります。
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
新しいセッションを要求するには、この struct に以下のように値を設定し、message type を `MT_SessionRequest` に、protocol version を現在のバージョンに設定します。
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
このヘッダーは、セッションのGUIDを含む`sessionRequestData`構造体に続いて、`write` syscallを使用してtargetに送信されます。
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` pipeのread操作により、デバッグセッションの確立の成否を確認できます。
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## メモリの読み取り

debugging session が確立されると、[`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message type を使用してメモリを読み取れます。関数 `readMemory` では、read request を送信して response を取得するために必要な手順が詳しく説明されています。
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
関連するPOCは[こちら](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)で確認できます。

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

コードを実行するには、rwx権限を持つメモリ領域を特定する必要があります。これは`vmmap -pages`を使用して実行できます：
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
関数ポインタを上書きする場所を特定する必要があります。.NET Core では、**Dynamic Function Table (DFT)** をターゲットにすることでこれを実行できます。このテーブルは [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) に詳しく記載されており、runtime が JIT compilation helper functions に使用します。

x64 systems では、signature hunting を使用して `libcorclr.dll` 内のシンボル `_hlpDynamicFuncTable` への参照を見つけることができます。

`MT_GetDCB` debugger function は、helper function である `m_helperRemoteStartAddr` のアドレスなど、有用な情報を提供します。これは、process memory 内にある `libcorclr.dll` の位置を示します。このアドレスを使用して DFT の検索を開始し、function pointer を shellcode のアドレスで上書きします。

PowerShell への injection 用の完全な POC code は[こちら](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)から利用できます。

## References

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
