# 清单 - Windows 本地权限提升

{{#include ../banners/hacktricks-training.md}}

### **查找 Windows 本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [系统信息](windows-local-privilege-escalation/index.html#system-info)

- [ ] 获取[**系统信息**](windows-local-privilege-escalation/index.html#system-info)
- [ ] [**使用脚本**](windows-local-privilege-escalation/index.html#version-exploits)查找 **kernel** **exploit**
- [ ] 使用 **Google 搜索** kernel **exploit**
- [ ] 使用 **searchsploit 搜索** kernel **exploit**
- [ ] [**环境变量**](windows-local-privilege-escalation/index.html#environment)中有有趣的信息吗？
- [ ] [**PowerShell 历史记录**](windows-local-privilege-escalation/index.html#powershell-history)中有密码吗？
- [ ] [**Internet 设置**](windows-local-privilege-escalation/index.html#internet-settings)中有有趣的信息吗？
- [ ] [**驱动器**](windows-local-privilege-escalation/index.html#drives)？
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)？
- [ ] [**第三方 agent 自动更新程序 / IPC 滥用**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)？

### [日志记录/AV 枚举](windows-local-privilege-escalation/index.html#enumeration)

- [ ] 检查 [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)和 [**WEF** ](windows-local-privilege-escalation/index.html#wef)设置
- [ ] 检查 [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] 检查 [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)是否已启用
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)？
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[？](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**缓存的凭据**](windows-local-privilege-escalation/index.html#cached-credentials)？
- [ ] 检查是否存在任何 [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker 策略**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**管理员保护 / UIAccess 静默提权**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)？<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop 辅助功能注册表传播 (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)？<sup>[[2]](#references)</sup>
- [ ] [**用户权限**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 检查当前用户的[**权限**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 你是[**任何特权组的成员**](windows-local-privilege-escalation/index.html#privileged-groups)吗？
- [ ] 检查是否启用了[这些 token 中的任何一个](windows-local-privilege-escalation/index.html#token-manipulation)：**SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**？
- [ ] 检查是否拥有 [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)，以读取原始卷并绕过文件 ACL
- [ ] [**用户会话**](windows-local-privilege-escalation/index.html#logged-users-sessions)？
- [ ] 检查[**用户主目录**](windows-local-privilege-escalation/index.html#home-folders)（能否访问？）
- [ ] 检查[**密码策略**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] [**剪贴板中有什么**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)？

### [网络](windows-local-privilege-escalation/index.html#network)

- [ ] 检查当前[**网络** **信息**](windows-local-privilege-escalation/index.html#network)
- [ ] 检查限制外部访问的**隐藏本地服务**

### [运行中的进程](windows-local-privilege-escalation/index.html#running-processes)

- [ ] 进程二进制文件的[**文件和文件夹权限**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**从内存中挖掘密码**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**不安全的 GUI 应用**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] 能否通过 `ProcDump.exe` 从**有趣的进程**中窃取凭据？（firefox、chrome 等）

### [服务](windows-local-privilege-escalation/index.html#services)

- [ ] [你能**修改任何服务**吗？](windows-local-privilege-escalation/index.html#permissions)
- [ ] [你能**修改**任何**服务**所**执行**的**二进制文件**吗？](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [你能**修改**任何**服务**的**注册表**吗？](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [你能利用任何**未加引号的服务二进制文件路径**吗？](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [服务触发器：枚举并触发特权服务](windows-local-privilege-escalation/service-triggers.md)

### [**应用程序**](windows-local-privilege-escalation/index.html#applications)

- [ ] 已安装应用程序的[**写入** **权限**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**启动应用程序**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **易受攻击的**[**驱动程序**](windows-local-privilege-escalation/index.html#drivers)

### [DLL 劫持](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] 你能在 PATH 中的任何文件夹里**写入**吗？
- [ ] 是否有已知服务二进制文件会**尝试加载不存在的 DLL**？
- [ ] 你能在任何**二进制文件文件夹**中**写入**吗？

### [网络](windows-local-privilege-escalation/index.html#network)

- [ ] 枚举网络（共享、接口、路由、邻居等）
- [ ] 特别检查监听 localhost (127.0.0.1) 的网络服务

### [Windows 凭据](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)凭据
- [ ] 是否有可用的 [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) 凭据？
- [ ] 是否有有用的 [**DPAPI 凭据**](windows-local-privilege-escalation/index.html#dpapi)？
- [ ] 已保存的 [**Wifi 网络**](windows-local-privilege-escalation/index.html#wifi)密码？
- [ ] [**已保存的 RDP 连接**](windows-local-privilege-escalation/index.html#saved-rdp-connections)中有有趣的信息吗？
- [ ] [**最近运行的命令**](windows-local-privilege-escalation/index.html#recently-run-commands)中有密码吗？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)中的密码？
- [ ] 是否存在 [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)？凭据？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)？DLL Side Loading？

### [文件和注册表（凭据）](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty：**[**凭据**](windows-local-privilege-escalation/index.html#putty-creds) **和** [**SSH 主机密钥**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**注册表中的 SSH 密钥**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)？
- [ ] [**无人值守文件**](windows-local-privilege-escalation/index.html#unattended-files)中有密码吗？
- [ ] 是否有 [**SAM 和 SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) 备份？
- [ ] 如果存在 [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)，尝试读取原始卷中的 `SAM`、`SYSTEM`、DPAPI 材料和 `MachineKeys`
- [ ] [**Cloud 凭据**](windows-local-privilege-escalation/index.html#cloud-credentials)？
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) 文件？
- [ ] [**缓存的 GPP 密码**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)？
- [ ] [**IIS Web 配置文件**](windows-local-privilege-escalation/index.html#iis-web-config)中的密码？
- [ ] [**Web** **日志**](windows-local-privilege-escalation/index.html#logs)中有有趣的信息吗？
- [ ] 你想向用户[**索要凭据**](windows-local-privilege-escalation/index.html#ask-for-credentials)吗？
- [ ] [**回收站中的文件**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)中有有趣内容吗？
- [ ] 其他[**包含凭据的注册表项**](windows-local-privilege-escalation/index.html#inside-the-registry)？
- [ ] [**浏览器数据**](windows-local-privilege-escalation/index.html#browsers-history)中有内容吗（数据库、历史记录、书签等）？
- [ ] 在文件和注册表中进行[**通用密码搜索**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] 用于自动搜索密码的[**工具**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 你能访问由管理员运行的进程的任何 handler 吗？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 检查是否可以滥用它

## References

- [1] [Project Zero - 通过滥用 UI Access 绕过管理员保护](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
