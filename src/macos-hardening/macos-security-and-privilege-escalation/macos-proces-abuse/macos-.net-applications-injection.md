# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**これは投稿の要約です [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)。詳細はそちらをご覧ください！**

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **デバッグセッションの確立** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NETにおけるデバッガとデバッグ対象間の通信の処理は、[**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp)によって管理されています。このコンポーネントは、[dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127)に見られるように、各.NETプロセスごとに2つの名前付きパイプを設定します。これらは[twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27)を介して開始されます。これらのパイプは**`-in`**および**`-out`**で接尾辞が付けられています。

ユーザーの**`$TMPDIR`**を訪れることで、.Netアプリケーションのデバッグに利用可能なFIFOを見つけることができます。

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259)は、デバッガからの通信を管理する責任があります。新しいデバッグセッションを開始するには、デバッガは`out`パイプを介して`MessageHeader`構造体で始まるメッセージを送信する必要があります。この構造体の詳細は.NETのソースコードに記載されています。
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
新しいセッションをリクエストするために、この構造体は次のように設定され、メッセージタイプを `MT_SessionRequest` に、プロトコルバージョンを現在のバージョンに設定します：
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
このヘッダーは、その後、`write` システムコールを使用してターゲットに送信され、セッションの GUID を含む `sessionRequestData` 構造体が続きます：
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` パイプの読み取り操作は、デバッグセッションの確立の成功または失敗を確認します:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## メモリの読み取り

デバッグセッションが確立されると、[`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) メッセージタイプを使用してメモリを読み取ることができます。関数 readMemory は詳細に説明されており、読み取り要求を送信し、応答を取得するために必要な手順を実行します：
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
完全な概念実証（POC）は[こちら](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b)で入手できます。

## メモリの書き込み

同様に、`writeMemory`関数を使用してメモリに書き込むことができます。このプロセスは、メッセージタイプを`MT_WriteMemory`に設定し、データのアドレスと長さを指定し、データを送信することを含みます：
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
関連するPOCは[こちら](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)で入手できます。

## .NET Core コード実行 <a href="#net-core-code-execution" id="net-core-code-execution"></a>

コードを実行するには、rwx権限を持つメモリ領域を特定する必要があります。これはvmmap -pagesを使用して行うことができます。
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
関数ポインタを上書きする場所を特定することは必要であり、.NET Coreでは、**Dynamic Function Table (DFT)**をターゲットにすることでこれを行うことができます。このテーブルは、[`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h)に詳述されており、JITコンパイルヘルパー関数のためにランタイムによって使用されます。

x64システムでは、シグネチャハンティングを使用して`libcorclr.dll`内のシンボル`_hlpDynamicFuncTable`への参照を見つけることができます。

`MT_GetDCB`デバッガ関数は、ヘルパー関数のアドレス`m_helperRemoteStartAddr`を含む有用な情報を提供し、プロセスメモリ内の`libcorclr.dll`の位置を示します。このアドレスは、その後DFTの検索を開始し、関数ポインタをシェルコードのアドレスで上書きするために使用されます。

PowerShellへの注入のための完全なPOCコードは[こちら](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)でアクセス可能です。

## 参考文献

- [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
