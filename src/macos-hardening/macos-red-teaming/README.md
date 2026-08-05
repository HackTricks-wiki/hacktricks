# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Abusing MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

如果你能够**获取管理员凭据**以访问管理平台，就可以通过在计算机中分发 malware，**潜在地攻陷所有计算机**。

对于 MacOS 环境中的 red teaming，强烈建议了解 MDM 的工作方式：


{{#ref}}
macos-mdm/
{{#endref}}

### Using MDM as a C2

MDM 将拥有安装、查询或移除 profiles，安装 applications，创建本地管理员账户，设置 firmware password，更改 FileVault key 等权限……

要运行自己的 MDM，你需要让**你的 CSR 由 vendor 签名**，可以尝试通过 [**https://mdmcert.download/**](https://mdmcert.download/) 获取。要为 Apple 设备运行自己的 MDM，可以使用 [**MicroMDM**](https://github.com/micromdm/micromdm)。

但是，要在已 enrolled 的设备中安装 application，仍然需要由 developer account 对其进行签名……不过，在 MDM enrolment 时，**设备会将 MDM 的 SSL cert 添加为受信任的 CA**，因此现在你可以对任何内容进行签名。<sup>[4]</sup>

要将设备 enrolled 到 MDM 中，你需要以 root 身份安装一个 **`mobileconfig`** 文件，该文件可以通过 **pkg** 文件传送（你可以将其压缩为 zip，并且从 Safari 下载时它会自动解压）。

**Mythic agent Orthrus** 使用了此技术。

### Abusing JAMF PRO

JAMF 可以运行**自定义 scripts**（由 sysadmin 开发的 scripts）、**原生 payloads**（创建本地账户、设置 EFI password、文件/进程监控……）以及 **MDM**（设备 configurations、设备 certificates……）。<sup>[5]</sup>

#### JAMF self-enrolment

访问类似 `https://<company-name>.jamfcloud.com/enroll/` 的页面，查看其是否启用了 **self-enrolment**。如果启用，页面可能会**要求凭据才能访问**。

你可以使用 [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) 执行 password spraying attack。

此外，在找到有效凭据后，你可以使用下方的 form 对其他 usernames 进行 brute-force：

![Abusing JAMF PRO - JAMF self-enrolment: Moreover, after finding proper credentials you could be able to brute-force other usernames with the next form](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

发现时，**`jamf`** binary 中包含用于打开 keychain 的 secret，该 secret 当时由所有人**共享**，其值为：**`jk23ucnq91jfu9aj`**。<sup>[5]</sup>\
此外，jamf 会作为 **LaunchDaemon** 持久化于 **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

**JSS**（Jamf Software Server）的 **URL** 位于 **`/Library/Preferences/com.jamfsoftware.jamf.plist`**，**`jamf`** 将使用该 URL。\
该文件基本上包含以下 URL：
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://subdomain-company.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
因此，攻击者可以投放一个恶意软件包（`pkg`），该软件包在安装时**覆盖此文件**，将 **URL 设置为 Typhon agent 的 Mythic C2 listener**，从而能够滥用 JAMF 作为 C2。
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

为了**伪装设备与 JMF 之间的通信**，你需要：

- 设备的 **UUID**：`ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- 位于 `/Library/Application\ Support/Jamf/JAMF.keychain` 的 **JAMF keychain**，其中包含设备证书

利用这些信息，**创建一个 VM**，使用**窃取的**硬件 **UUID**，并且**禁用 SIP**，放入 **JAMF keychain**，对 Jamf **agent** 进行 **hook**，并窃取其信息。

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

你还可以监控 `/Library/Application Support/Jamf/tmp/` 位置，因为管理员可能希望通过 Jamf 执行**自定义脚本**；这些脚本会被**放置于此、执行后删除**。这些脚本**可能包含凭据**。

不过，**凭据**也可能作为**参数**传递给这些脚本，因此你需要监控 `ps aux | grep -i jamf`（甚至无需 root 权限）。

脚本 [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) 可以监听新添加的文件以及新的进程参数。

### macOS 远程访问

以及关于 MacOS 的“特殊”**网络** **协议**：


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

在某些情况下，你会发现 **MacOS 计算机已连接到 AD**。在此场景中，你应像平时一样尝试对 Active Directory 进行**枚举**。以下页面提供了一些**帮助**：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

某些可能对你有帮助的 **本地 MacOS 工具**是 `dscl`：
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
此外，还有一些为 MacOS 准备的工具，可用于自动枚举 AD 并使用 kerberos：

- [**Machound**](https://github.com/XMCyber/MacHound)：MacHound 是 Bloodhound auditing 工具的扩展，允许在 MacOS 主机上收集并导入 Active Directory 关系。<sup>[2]</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost)：Bifrost 是一个 Objective-C 项目，旨在与 macOS 上的 Heimdal krb5 APIs 交互。该项目的目标是使用原生 APIs，在 macOS 设备上实现更完善的 Kerberos security testing，而无需目标系统上的任何其他 framework 或 packages。
- [**Orchard**](https://github.com/its-a-feature/Orchard)：用于执行 Active Directory 枚举的 JavaScript for Automation (JXA) 工具。

### Domain Information
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### 用户

MacOS 用户分为三种类型：

- **本地用户** — 由本地 OpenDirectory 服务管理，与 Active Directory 没有任何连接。
- **网络用户** — 临时的 Active Directory 用户，需要连接到 DC 服务器进行身份验证。
- **移动用户** — Active Directory 用户，其凭据和文件在本地具有备份。

用户和组的本地信息存储在 _/var/db/dslocal/nodes/Default._ 文件夹中。\
例如，名为 _mark_ 的用户信息存储在 _/var/db/dslocal/nodes/Default/users/mark.plist_ 中，而 _admin_ 组的信息存储在 _/var/db/dslocal/nodes/Default/groups/admin.plist_ 中。

除了使用 HasSession 和 AdminTo edges 外，**MacHound 还向 Bloodhound 数据库添加了三个新的 edges**：<sup>[2]</sup>

- **CanSSH** - 允许通过 SSH 连接到主机的实体
- **CanVNC** - 允许通过 VNC 连接到主机的实体
- **CanAE** - 允许在主机上执行 AppleEvent scripts 的实体
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
更多信息请参阅 [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ 密码

使用以下方式获取密码：
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
可以在 System keychain 中访问 **`Computer$`** 密码。

### Over-Pass-The-Hash

为特定用户和服务获取 TGT：
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
获取 TGT 后，可以使用以下方式将其注入当前会话：
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
利用已获取的 service tickets，可以尝试访问其他计算机上的共享：
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## 访问 Keychain

Keychain 很可能包含敏感信息。如果在访问时无需生成提示，就可能帮助推进 red team exercise：


{{#ref}}
macos-keychain.md
{{#endref}}

## 外部服务

macOS Red Teaming 与常规的 Windows Red Teaming 不同，因为 **macOS 通常会直接集成多个外部平台**。macOS 的一种常见配置是使用 **OneLogin synchronised credentials 访问计算机，并通过 OneLogin 访问多个外部服务**（如 github、aws 等）。

## Misc Red Team techniques

### Safari

在 Safari 中下载文件时，如果文件属于“安全”文件，就会被**自动打开**。例如，如果你**下载一个 zip 文件**，它会被自动解压：

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
