# macOS 敏感位置与有趣的守护进程

{{#include ../../../banners/hacktricks-training.md}}

## 密码

### 隐藏密码

隐藏密码与用户的配置一起存储在位于 **`/var/db/dslocal/nodes/Default/users/`** 的 plist 文件中。\
以下单行命令可用于转储 **所有用户的信息**（包括哈希信息）：
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**像这样的脚本**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) 或 [**这个**](https://github.com/octomagon/davegrohl.git) 可以用来将哈希转换为 **hashcat** **格式**。

一个替代的一行命令将以 hashcat 格式 `-m 7100`（macOS PBKDF2-SHA512）转储所有非服务账户的凭据：
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
另一种获取用户 `ShadowHashData` 的方法是使用 `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

此文件**仅在**系统以**单用户模式**运行时使用（因此不太频繁）。

### Keychain Dump

请注意，当使用 security 二进制文件**解密并转储密码**时，会有几个提示要求用户允许此操作。
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
> 根据这个评论 [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)，这些工具在 Big Sur 中似乎不再有效。

### Keychaindump 概述

一个名为 **keychaindump** 的工具被开发出来以从 macOS 钥匙串中提取密码，但在像 Big Sur 这样的较新 macOS 版本上面临限制，如在 [讨论](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) 中所述。使用 **keychaindump** 需要攻击者获得访问权限并提升到 **root** 权限。该工具利用了钥匙串在用户登录时默认解锁的事实，以方便应用程序访问，而无需用户重复输入密码。然而，如果用户选择在每次使用后锁定他们的钥匙串，**keychaindump** 将变得无效。

**Keychaindump** 通过针对一个特定的进程 **securityd** 来操作，Apple 将其描述为一个用于授权和加密操作的守护进程，对于访问钥匙串至关重要。提取过程涉及识别一个从用户登录密码派生的 **Master Key**。这个密钥对于读取钥匙串文件是必不可少的。为了找到 **Master Key**，**keychaindump** 使用 `vmmap` 命令扫描 **securityd** 的内存堆，寻找标记为 `MALLOC_TINY` 的区域中的潜在密钥。以下命令用于检查这些内存位置：
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
在识别潜在的主密钥后，**keychaindump** 在堆中搜索特定模式 (`0x0000000000000018`)，这表明是主密钥的候选者。进一步的步骤，包括去混淆，都是利用此密钥所必需的，正如 **keychaindump** 的源代码中所述。专注于该领域的分析师应注意，解密钥匙串的关键数据存储在 **securityd** 进程的内存中。运行 **keychaindump** 的示例命令是：
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) 可用于以法医可靠的方式从OSX钥匙串中提取以下类型的信息：

- 哈希钥匙串密码，适合使用 [hashcat](https://hashcat.net/hashcat/) 或 [John the Ripper](https://www.openwall.com/john/) 破解
- 互联网密码
- 通用密码
- 私钥
- 公钥
- X509证书
- 安全笔记
- Appleshare密码

给定钥匙串解锁密码、使用 [volafox](https://github.com/n0fate/volafox) 或 [volatility](https://github.com/volatilityfoundation/volatility) 获得的主密钥，或如SystemKey的解锁文件，Chainbreaker还将提供明文密码。

如果没有这些解锁钥匙串的方法，Chainbreaker将显示所有其他可用信息。

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **使用 SystemKey 转储钥匙串密钥（带密码）**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **转储钥匙串密钥（带密码）破解哈希**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **通过内存转储转储钥匙串密钥（带密码）**

[按照这些步骤](../#dumping-memory-with-osxpmem) 执行 **内存转储**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **使用用户密码转储钥匙串密钥（带密码）**

如果您知道用户的密码，您可以使用它来**转储和解密属于用户的钥匙串**。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword** 文件是一个保存 **用户登录密码** 的文件，但仅在系统所有者 **启用自动登录** 的情况下。因此，用户将自动登录，而无需输入密码（这并不是很安全）。

密码存储在文件 **`/etc/kcpassword`** 中，使用密钥 **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** 进行异或加密。如果用户的密码长度超过密钥，密钥将被重复使用。\
这使得密码相对容易恢复，例如使用像 [**这个**](https://gist.github.com/opshope/32f65875d45215c3677d) 的脚本。

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

大多数有趣的信息将位于 **blob** 中。因此，您需要 **提取** 该内容并 **转换** 为 **人类** **可读** 格式，或者使用 **`strings`**。要访问它，您可以执行：
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### 备注

用户的 **notes** 可以在 `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` 找到
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Preferences

在 macOS 应用中，偏好设置位于 **`$HOME/Library/Preferences`**，而在 iOS 中则位于 `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`。

在 macOS 中，可以使用 cli 工具 **`defaults`** 来 **修改偏好设置文件**。

**`/usr/sbin/cfprefsd`** 声称 XPC 服务 `com.apple.cfprefsd.daemon` 和 `com.apple.cfprefsd.agent`，并可以被调用以执行诸如修改偏好设置等操作。

## OpenDirectory permissions.plist

文件 `/System/Library/OpenDirectory/permissions.plist` 包含应用于节点属性的权限，并受到 SIP 保护。\
该文件通过 UUID（而不是 uid）授予特定用户权限，以便他们能够访问特定的敏感信息，如 `ShadowHashData`、`HeimdalSRPKey` 和 `KerberosKeys` 等。
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

主要的通知守护进程是 **`/usr/sbin/notifyd`**。为了接收通知，客户端必须通过 `com.apple.system.notification_center` Mach 端口注册（使用 `sudo lsmp -p <pid notifyd>` 检查它们）。该守护进程可以通过文件 `/etc/notify.conf` 进行配置。

用于通知的名称是唯一的反向 DNS 表示法，当发送通知到其中一个名称时，已指明可以处理该通知的客户端将接收到它。

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
### 分布式通知中心

**分布式通知中心**的主要二进制文件是**`/usr/sbin/distnoted`**，这是发送通知的另一种方式。它暴露了一些XPC服务，并执行一些检查以尝试验证客户端。

### 苹果推送通知 (APN)

在这种情况下，应用程序可以注册**主题**。客户端将通过**`apsd`**联系苹果的服务器生成一个令牌。\
然后，提供者也将生成一个令牌，并能够连接到苹果的服务器向客户端发送消息。这些消息将由**`apsd`**本地接收，并将通知转发给等待它的应用程序。

首选项位于`/Library/Preferences/com.apple.apsd.plist`。

在macOS中，消息的本地数据库位于`/Library/Application\ Support/ApplePushService/aps.db`，在iOS中位于`/var/mobile/Library/ApplePushService`。它有3个表：`incoming_messages`，`outgoing_messages`和`channel`。
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
也可以使用以下命令获取有关守护进程和连接的信息：
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## 用户通知

这些是用户应该在屏幕上看到的通知：

- **`CFUserNotification`**：这个 API 提供了一种在屏幕上显示带有消息的弹出窗口的方法。
- **公告板**：这在 iOS 上显示一个会消失的横幅，并将存储在通知中心。
- **`NSUserNotificationCenter`**：这是 MacOS 中的 iOS 公告板。通知的数据库位于 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

{{#include ../../../banners/hacktricks-training.md}}
