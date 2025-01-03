# 清单 - 本地 Windows 提权

{{#include ../banners/hacktricks-training.md}}

### **查找 Windows 本地提权向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [系统信息](windows-local-privilege-escalation/#system-info)

- [ ] 获取 [**系统信息**](windows-local-privilege-escalation/#system-info)
- [ ] 搜索 **内核** [**利用脚本**](windows-local-privilege-escalation/#version-exploits)
- [ ] 使用 **Google 搜索** 内核 **利用**
- [ ] 使用 **searchsploit 搜索** 内核 **利用**
- [ ] [**环境变量**](windows-local-privilege-escalation/#environment) 中有趣的信息？
- [ ] [**PowerShell 历史**](windows-local-privilege-escalation/#powershell-history) 中的密码？
- [ ] [**互联网设置**](windows-local-privilege-escalation/#internet-settings) 中有趣的信息？
- [ ] [**驱动器**](windows-local-privilege-escalation/#drives)？
- [ ] [**WSUS 利用**](windows-local-privilege-escalation/#wsus)？
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)？

### [日志/AV 枚举](windows-local-privilege-escalation/#enumeration)

- [ ] 检查 [**审计**](windows-local-privilege-escalation/#audit-settings) 和 [**WEF**](windows-local-privilege-escalation/#wef) 设置
- [ ] 检查 [**LAPS**](windows-local-privilege-escalation/#laps)
- [ ] 检查 [**WDigest**](windows-local-privilege-escalation/#wdigest) 是否处于活动状态
- [ ] [**LSA 保护**](windows-local-privilege-escalation/#lsa-protection)？
- [ ] [**凭据保护**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
- [ ] [**缓存凭据**](windows-local-privilege-escalation/#cached-credentials)？
- [ ] 检查是否有任何 [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker 策略**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**用户权限**](windows-local-privilege-escalation/#users-and-groups)
- [ ] 检查 [**当前**] 用户 [**权限**](windows-local-privilege-escalation/#users-and-groups)
- [ ] 你是 [**任何特权组的成员**](windows-local-privilege-escalation/#privileged-groups)吗？
- [ ] 检查你是否启用了 [这些令牌](windows-local-privilege-escalation/#token-manipulation)：**SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**用户会话**](windows-local-privilege-escalation/#logged-users-sessions)？
- [ ] 检查 [**用户主目录**](windows-local-privilege-escalation/#home-folders)（访问？）
- [ ] 检查 [**密码策略**](windows-local-privilege-escalation/#password-policy)
- [ ] [**剪贴板**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard) 中有什么？

### [网络](windows-local-privilege-escalation/#network)

- [ ] 检查 **当前** [**网络** **信息**](windows-local-privilege-escalation/#network)
- [ ] 检查 **隐藏的本地服务** 是否限制外部访问

### [运行中的进程](windows-local-privilege-escalation/#running-processes)

- [ ] 进程二进制 [**文件和文件夹权限**](windows-local-privilege-escalation/#file-and-folder-permissions)
- [ ] [**内存密码挖掘**](windows-local-privilege-escalation/#memory-password-mining)
- [ ] [**不安全的 GUI 应用**](windows-local-privilege-escalation/#insecure-gui-apps)
- [ ] 通过 `ProcDump.exe` 偷取 **有趣进程** 的凭据？（firefox, chrome 等 ...）

### [服务](windows-local-privilege-escalation/#services)

- [ ] [你能 **修改任何服务** 吗？](windows-local-privilege-escalation/#permissions)
- [ ] [你能 **修改** 任何 **服务** 执行的 **二进制文件** 吗？](windows-local-privilege-escalation/#modify-service-binary-path)
- [ ] [你能 **修改** 任何 **服务** 的 **注册表** 吗？](windows-local-privilege-escalation/#services-registry-modify-permissions)
- [ ] [你能利用任何 **未加引号的服务** 二进制 **路径** 吗？](windows-local-privilege-escalation/#unquoted-service-paths)

### [**应用程序**](windows-local-privilege-escalation/#applications)

- [ ] **写入** [**已安装应用程序的权限**](windows-local-privilege-escalation/#write-permissions)
- [ ] [**启动应用程序**](windows-local-privilege-escalation/#run-at-startup)
- [ ] **易受攻击的** [**驱动程序**](windows-local-privilege-escalation/#drivers)

### [DLL 劫持](windows-local-privilege-escalation/#path-dll-hijacking)

- [ ] 你能 **在 PATH 中的任何文件夹写入** 吗？
- [ ] 是否有任何已知的服务二进制文件 **尝试加载任何不存在的 DLL**？
- [ ] 你能 **在任何二进制文件夹中写入** 吗？

### [网络](windows-local-privilege-escalation/#network)

- [ ] 枚举网络（共享、接口、路由、邻居等...）
- [ ] 特别关注监听在本地主机（127.0.0.1）上的网络服务

### [Windows 凭据](windows-local-privilege-escalation/#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials) 凭据
- [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) 凭据你可以使用？
- [ ] 有趣的 [**DPAPI 凭据**](windows-local-privilege-escalation/#dpapi)？
- [ ] 保存的 [**Wifi 网络**](windows-local-privilege-escalation/#wifi) 密码？
- [ ] [**保存的 RDP 连接**](windows-local-privilege-escalation/#saved-rdp-connections) 中有趣的信息？
- [ ] [**最近运行的命令**](windows-local-privilege-escalation/#recently-run-commands) 中的密码？
- [ ] [**远程桌面凭据管理器**](windows-local-privilege-escalation/#remote-desktop-credential-manager) 密码？
- [ ] [**AppCmd.exe** 存在](windows-local-privilege-escalation/#appcmd-exe)吗？凭据？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)？DLL 侧加载？

### [文件和注册表（凭据）](windows-local-privilege-escalation/#files-and-registry-credentials)

- [ ] **Putty:** [**凭据**](windows-local-privilege-escalation/#putty-creds) **和** [**SSH 主机密钥**](windows-local-privilege-escalation/#putty-ssh-host-keys)
- [ ] [**注册表中的 SSH 密钥**](windows-local-privilege-escalation/#ssh-keys-in-registry)？
- [ ] [**无人值守文件**](windows-local-privilege-escalation/#unattended-files) 中的密码？
- [ ] 有任何 [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) 备份吗？
- [ ] [**云凭据**](windows-local-privilege-escalation/#cloud-credentials)？
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) 文件？
- [ ] [**缓存的 GPP 密码**](windows-local-privilege-escalation/#cached-gpp-pasword)？
- [ ] [**IIS Web 配置文件**](windows-local-privilege-escalation/#iis-web-config) 中的密码？
- [ ] [**网络日志**](windows-local-privilege-escalation/#logs) 中有趣的信息？
- [ ] 你想要 [**向用户请求凭据**](windows-local-privilege-escalation/#ask-for-credentials) 吗？
- [ ] [**回收站中的有趣文件**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)？
- [ ] 其他 [**包含凭据的注册表**](windows-local-privilege-escalation/#inside-the-registry)？
- [ ] [**浏览器数据**](windows-local-privilege-escalation/#browsers-history) 中（数据库、历史记录、书签等）？
- [ ] [**通用密码搜索**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) 在文件和注册表中
- [ ] [**工具**](windows-local-privilege-escalation/#tools-that-search-for-passwords) 自动搜索密码

### [泄露的处理程序](windows-local-privilege-escalation/#leaked-handlers)

- [ ] 你是否可以访问由管理员运行的任何进程的处理程序？

### [管道客户端冒充](windows-local-privilege-escalation/#named-pipe-client-impersonation)

- [ ] 检查你是否可以利用它

{{#include ../banners/hacktricks-training.md}}
