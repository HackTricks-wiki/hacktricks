# macOS 红队演练

{{#include ../../banners/hacktricks-training.md}}


## 滥用 MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

如果你成功**获取管理员凭据**并访问管理平台，就可以通过向设备分发恶意软件，**潜在地攻陷所有计算机**。

在 macOS 环境中进行红队演练时，强烈建议了解 MDM 的工作方式：


{{#ref}}
macos-mdm/
{{#endref}}

### 将 MDM 用作 C2

MDM 有权安装、查询或移除配置描述文件、安装应用程序、创建本地管理员帐户、设置固件密码、更改 FileVault 密钥……

要运行自己的 MDM，你需要**让供应商为你的 CSR 签名**，可以尝试通过 [**https://mdmcert.download/**](https://mdmcert.download/) 获取。要为 Apple 设备运行自己的 MDM，可以使用 [**MicroMDM**](https://github.com/micromdm/micromdm)。

MDM 注册**不会**自动将管理服务器的 TLS 证书设为受信任的 CA，也不会授予应用签名身份。如果服务器使用私有 CA，则必须在注册描述文件或单独的信任描述文件中提供其根证书和中间证书。用于 MDM 身份验证的客户端身份是另一张证书。<sup>[[7]](#references)</sup>

下载的 MDM 注册描述文件（`.mobileconfig`）必须在**系统设置 → 通用 → 设备管理**中打开并批准。仅将其放入由 root 安装的 `.pkg` 或通过 Safari 打开的 ZIP 文件中，并不能让当前版本的 Mac 静默注册。请参阅[配置描述文件行为](../macos-auto-start-locations.md#configuration-profiles-mobileconfig)。<sup>[[8]](#references)</sup>

设置助理中的自动设备注册是另一种独立流程。有关其不同的前提条件，请参阅[流氓注册其他组织的设备](macos-mdm/enrolling-devices-in-other-organisations.md)。<sup>[[9]](#references)</sup>

**Mythic agent Orthrus** 使用了这种技术。

### 通过受控 MDM 部署软件包

在运行 macOS 26 或更高版本的**受监管 Mac**上，控制 MDM 服务即可在系统范围内使用 `com.apple.configuration.package` 声明。<sup>[[10]](#references)</sup> 软件包必须带有设备能够验证的签名，但其中的应用程序不需要单独的 Developer ID 签名：Gatekeeper 不会检查通过设备管理安装的应用程序。<sup>[[11]](#references)</sup> 受信任的服务器 TLS 证书本身并不会向操作者提供该软件包签名所需的私钥或签名用途。<sup>[[11]](#references)[[12]](#references)</sup>

构建一个已签名的测试软件包，计算其摘要，并通过 HTTPS 发布软件包和 `ManifestURL` plist。清单需要包含一个带有 URL 和 SHA-256 的 `software-package` 资源，以及唯一的 `bundle-identifier` 和 `bundle-version`。<sup>[[11]](#references)</sup> 然后发送包含该清单 URL 的软件包声明，并将 `InstallBehavior.Install` 设为 `Required`；检查 `package.list` 状态项，确认安装状态或错误。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

通过 MDM 服务提交的最简必需安装声明如下（替换 URL 和两个 UUID）。<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### 滥用 JAMF PRO

JAMF 可以运行**自定义脚本**（由 sysadmin 开发的脚本）、**原生 payload**（创建本地账户、设置 EFI 密码、监控文件/进程……）和 **MDM**（设备配置、设备证书……）。<sup>[[5]](#references)</sup>

#### JAMF 自助注册

访问 `https://<company-name>.jamfcloud.com/enroll/` 之类的页面，检查是否启用了**自助注册**。如果启用了，可能会**要求提供凭据才能访问**。

你可以使用脚本 [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) 执行 password spraying attack。

此外，找到有效凭据后，你可能可以使用以下表单对其他用户名进行 brute-force：

![滥用 JAMF PRO - JAMF 自助注册：此外，找到有效凭据后，你可能可以使用以下表单对其他用户名进行 brute-force](<../../images/image (107).png>)

#### JAMF 设备身份验证

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** 二进制文件中包含用于打开钥匙串的密钥；在发现该密钥时，**所有人共用**该密钥，具体为：**`jk23ucnq91jfu9aj`**。<sup>[[5]](#references)</sup>\
此外，jamf 会作为 **LaunchDaemon** 持久化在 **`/Library/LaunchAgents/com.jamf.management.agent.plist`** 中。

#### JAMF 设备接管

**`jamf`** 将使用的 **JSS**（Jamf Software Server）**URL** 位于 **`/Library/Preferences/com.jamfsoftware.jamf.plist`** 中。\
该文件基本上包含这个 URL：

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

因此，攻击者可以投放一个恶意安装包（`pkg`），在安装时**覆盖此文件**，将 **Typhon agent 的 Mythic C2 listener URL** 设置为指定地址，从而能够滥用 JAMF 作为 C2。

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF Impersonation

要**冒充设备与 JMF 之间的通信**，你需要：

- 设备的 **UUID**：`ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- 来自 `/Library/Application\ Support/Jamf/JAMF.keychain` 的 **JAMF keychain**，其中包含设备证书

利用这些信息，使用**被盗的**硬件 **UUID** 创建一台 **VM**，并**禁用 SIP**，放入 **JAMF keychain**，对 Jamf **agent** 进行 **hook**，并窃取其信息。

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

你也可以监控 `/Library/Application Support/Jamf/tmp/`，留意管理员可能想通过 Jamf 执行的**自定义脚本**：这些脚本会被放到这里、执行，然后删除。这些脚本**可能包含凭据**。

不过，**凭据**也可能作为**参数**传递给这些脚本，因此你需要监控 `ps aux | grep -i jamf`（即使不是 root 也可以）。

脚本 [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) 可以监听新增文件和新的进程参数。

### macOS 远程访问

以及关于 **MacOS** “特殊”的**网络协议**：


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

有时你会发现 **MacOS 计算机已连接到 AD**。在这种情况下，你应该像平常一样尝试**枚举** Active Directory。以下页面提供了一些**帮助**：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

可能对你有帮助的 **MacOS 本地工具**还有 `dscl`：

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

此外，还有一些为 MacOS 准备的工具，可自动枚举 AD 并进行 Kerberos 操作：

- [**Machound**](https://github.com/XMCyber/MacHound)：MacHound 是 Bloodhound 审计工具的扩展，可在 MacOS 主机上收集并导入 Active Directory 关系。<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost)：Bifrost 是一个 Objective-C 项目，旨在与 macOS 上的 Heimdal krb5 API 交互。该项目的目标是使用原生 API，在 macOS 设备上更好地进行 Kerberos 安全测试，而无需在目标上使用任何其他框架或软件包。
- [**Orchard**](https://github.com/its-a-feature/Orchard)：用于 Active Directory 枚举的 JavaScript for Automation (JXA) 工具。

### 域信息

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### 用户

MacOS 用户分为三种类型：

- **本地用户** — 由本地 OpenDirectory 服务管理，与 Active Directory 没有任何连接。
- **网络用户** — 临时的 Active Directory 用户，需要连接到 DC 服务器才能进行身份验证。
- **移动用户** — Active Directory 用户，其凭据和文件有本地备份。

用户和组的本地信息存储在文件夹 _/var/db/dslocal/nodes/Default._ 中。\
例如，名为 _mark_ 的用户信息存储在 _/var/db/dslocal/nodes/Default/users/mark.plist_ 中，_admin_ 组的信息存储在 _/var/db/dslocal/nodes/Default/groups/admin.plist_ 中。

除了使用 HasSession 和 AdminTo 边之外，**MacHound 还会向 Bloodhound 数据库添加三个新边**：<sup>[[2]](#references)</sup>

- **CanSSH** - 获准通过 SSH 连接到主机的实体
- **CanVNC** - 获准通过 VNC 连接到主机的实体
- **CanAE** - 获准在主机上执行 AppleEvent 脚本的实体

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

更多信息请参阅 [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Computer$ 密码

使用以下方法获取密码：

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

收集到 TGT 后，可以使用以下方式将其注入当前会话：

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

获得 service tickets 后，可以尝试访问其他计算机上的共享资源：

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## 访问 Keychain

Keychain 很可能包含敏感信息。如果无需触发提示即可访问这些信息，就能帮助推进 Red Team 演练：


{{#ref}}
macos-keychain.md
{{#endref}}

## 外部服务

MacOS Red Teaming 与常规 Windows Red Teaming 不同，因为 **MacOS 通常直接集成多个外部平台**。MacOS 的一种常见配置是使用 **OneLogin 同步的凭据**访问计算机，并通过 OneLogin 访问多个外部服务（如 github、aws 等）。

## 其他 Red Team 技术

### Safari

在 Safari 中下载文件时，如果该文件属于“安全”文件，就会**自动打开**。例如，如果你**下载一个 zip 文件**，它就会自动解压：<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Gone Apple Pickin'：2021 年 MacOS 环境 Red Teaming - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [介绍 MacHound：针对基于 macOS Active Directory 攻击的解决方案](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - 域枚举命令（dscl / net / ldapsearch 等效命令）](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [欢迎来到黑暗面，我们有苹果：让 macOS 管理变得邪恶](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0：“从攻击者视角看 Jamf 配置” - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [使用 Mac 进行 Active Directory 发现 - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — 管理设备管理服务和设备的证书](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — 在 Mac 上使用配置描述文件](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — 部署设备管理注册描述文件](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — 软件包声明](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — 安装软件包](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — 身份](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
