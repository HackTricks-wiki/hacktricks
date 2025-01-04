# 检查清单 - 本地 Windows 权限提升

{{#include ../banners/hacktricks-training.md}}

### **查找 Windows 本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [系统信息](windows-local-privilege-escalation/index.html#system-info)

- [ ] 获取 [**系统信息**](windows-local-privilege-escalation/index.html#system-info)
- [ ] 使用脚本搜索 **内核** [**漏洞**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] 使用 **Google 搜索** 内核 **漏洞**
- [ ] 使用 **searchsploit 搜索** 内核 **漏洞**
- [ ] [**环境变量**](windows-local-privilege-escalation/index.html#environment) 中有趣的信息？
- [ ] [**PowerShell 历史**](windows-local-privilege-escalation/index.html#powershell-history) 中的密码？
- [ ] [**Internet 设置**](windows-local-privilege-escalation/index.html#internet-settings) 中有趣的信息？
- [ ] [**驱动器**](windows-local-privilege-escalation/index.html#drives)？
- [ ] [**WSUS 漏洞**](windows-local-privilege-escalation/index.html#wsus)？
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)？

### [日志/AV 枚举](windows-local-privilege-escalation/index.html#enumeration)

- [ ] 检查 [**审计**](windows-local-privilege-escalation/index.html#audit-settings) 和 [**WEF**](windows-local-privilege-escalation/index.html#wef) 设置
- [ ] 检查 [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] 检查 [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) 是否处于活动状态
- [ ] [**LSA 保护**](windows-local-privilege-escalation/index.html#lsa-protection)？
- [ ] [**凭据保护**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**缓存凭据**](windows-local-privilege-escalation/index.html#cached-credentials)？
- [ ] 检查是否有任何 [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker 策略**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**用户权限**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 检查 [**当前**] 用户 [**权限**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 你是 [**任何特权组的成员**](windows-local-privilege-escalation/index.html#privileged-groups)吗？
- [ ] 检查你是否启用了 [这些令牌](windows-local-privilege-escalation/index.html#token-manipulation)：**SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**用户会话**](windows-local-privilege-escalation/index.html#logged-users-sessions)？
- [ ] 检查 [**用户主目录**](windows-local-privilege-escalation/index.html#home-folders)（访问？）
- [ ] 检查 [**密码策略**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] [**剪贴板**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) 中有什么？

### [网络](windows-local-privilege-escalation/index.html#network)

- [ ] 检查 **当前** [**网络** **信息**](windows-local-privilege-escalation/index.html#network)
- [ ] 检查 **隐藏的本地服务** 是否限制外部访问

### [运行中的进程](windows-local-privilege-escalation/index.html#running-processes)

- [ ] 进程二进制文件 [**文件和文件夹权限**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**内存密码挖掘**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**不安全的 GUI 应用程序**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] 通过 `ProcDump.exe` 偷取 **有趣进程** 的凭据？（firefox, chrome 等 ...）

### [服务](windows-local-privilege-escalation/index.html#services)

- [ ] [你能 **修改任何服务** 吗？](windows-local-privilege-escalation/index.html#permissions)
- [ ] [你能 **修改** 任何 **服务** 执行的 **二进制文件** 吗？](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [你能 **修改** 任何 **服务** 的 **注册表** 吗？](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [你能利用任何 **未加引号的服务** 二进制 **路径** 吗？](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**应用程序**](windows-local-privilege-escalation/index.html#applications)

- [ ] **写入** [**已安装应用程序的权限**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**启动应用程序**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **易受攻击的** [**驱动程序**](windows-local-privilege-escalation/index.html#drivers)

### [DLL 劫持](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] 你能 **在 PATH 中的任何文件夹中写入** 吗？
- [ ] 是否有任何已知的服务二进制文件 **尝试加载任何不存在的 DLL**？
- [ ] 你能 **在任何二进制文件夹中写入** 吗？

### [网络](windows-local-privilege-escalation/index.html#network)

- [ ] 枚举网络（共享、接口、路由、邻居等...）
- [ ] 特别关注在本地主机（127.0.0.1）上监听的网络服务

### [Windows 凭据](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials) 凭据
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) 中你可以使用的凭据？
- [ ] 有趣的 [**DPAPI 凭据**](windows-local-privilege-escalation/index.html#dpapi)？
- [ ] 保存的 [**Wifi 网络**](windows-local-privilege-escalation/index.html#wifi) 中的密码？
- [ ] [**保存的 RDP 连接**](windows-local-privilege-escalation/index.html#saved-rdp-connections) 中有趣的信息？
- [ ] [**最近运行的命令**](windows-local-privilege-escalation/index.html#recently-run-commands) 中的密码？
- [ ] [**远程桌面凭据管理器**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) 密码？
- [ ] [**AppCmd.exe** 存在](windows-local-privilege-escalation/index.html#appcmd-exe)吗？凭据？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)？DLL 侧加载？

### [文件和注册表（凭据）](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**凭据**](windows-local-privilege-escalation/index.html#putty-creds) **和** [**SSH 主机密钥**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**注册表中的 SSH 密钥**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)？
- [ ] [**无人值守文件**](windows-local-privilege-escalation/index.html#unattended-files) 中的密码？
- [ ] 任何 [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) 备份？
- [ ] [**云凭据**](windows-local-privilege-escalation/index.html#cloud-credentials)？
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) 文件？
- [ ] [**缓存的 GPP 密码**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)？
- [ ] [**IIS Web 配置文件**](windows-local-privilege-escalation/index.html#iis-web-config) 中的密码？
- [ ] [**Web 日志**](windows-local-privilege-escalation/index.html#logs) 中有趣的信息？
- [ ] 你想要 [**向用户请求凭据**](windows-local-privilege-escalation/index.html#ask-for-credentials) 吗？
- [ ] [**回收站**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) 中有趣的文件？
- [ ] 其他 [**包含凭据的注册表**](windows-local-privilege-escalation/index.html#inside-the-registry)？
- [ ] [**浏览器数据**](windows-local-privilege-escalation/index.html#browsers-history) 中（数据库、历史记录、书签等）？
- [ ] [**通用密码搜索**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) 在文件和注册表中
- [ ] [**工具**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) 自动搜索密码

### [泄露的处理程序](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 你是否可以访问由管理员运行的任何进程的处理程序？

### [管道客户端冒充](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 检查你是否可以利用它

{{#include ../banners/hacktricks-training.md}}
