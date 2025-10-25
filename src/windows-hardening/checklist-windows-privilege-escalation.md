# 检查清单 - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **用于查找 Windows local privilege escalation 向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [系统信息](windows-local-privilege-escalation/index.html#system-info)

- [ ] 获取 [**系统信息**](windows-local-privilege-escalation/index.html#system-info)
- [ ] 搜索 **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] 使用 **Google** 搜索 kernel **exploits**
- [ ] 使用 **searchsploit** 搜索 kernel **exploits**
- [ ] 在 [**环境变量**](windows-local-privilege-escalation/index.html#environment) 中有有趣的信息？
- [ ] 在 [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) 中有密码？
- [ ] 在 [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) 中有有趣的信息？
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)？
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)？
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)？

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] 检查 [**Audit**](windows-local-privilege-escalation/index.html#audit-settings) 和 [**WEF**](windows-local-privilege-escalation/index.html#wef) 设置
- [ ] 检查 [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] 检查 [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) 是否启用
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)？
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)？（参见 [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)）
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)？
- [ ] 检查是否有任何 [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 检查当前用户的 **privileges** (权限) (参见 [**Users and Groups**](windows-local-privilege-escalation/index.html#users-and-groups))
- [ ] 你是否为 [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)？
- [ ] 检查是否启用了以下任一 token（tokens）：**SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**？
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)？
- [ ] 检查[ **users homes**](windows-local-privilege-escalation/index.html#home-folders)（访问权限？）
- [ ] 检查 [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] 剪贴板里有什么？（参见 [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)）

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 检查当前的 [**network information**](windows-local-privilege-escalation/index.html#network)
- [ ] 检查对外有限制但可被本地访问的隐藏本地服务

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] 进程二进制文件的 [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] 使用 `ProcDump.exe` 从有趣的进程窃取凭证？（例如 firefox, chrome 等）

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] 能否 **修改任何 service**？(参见 [permissions](windows-local-privilege-escalation/index.html#permissions))
- [ ] 能否 **修改任何 service 所执行的 binary**？(参见 [modify-service-binary-path](windows-local-privilege-escalation/index.html#modify-service-binary-path))
- [ ] 能否 **修改任何 service 的 registry**？(参见 [services-registry-modify-permissions](windows-local-privilege-escalation/index.html#services-registry-modify-permissions))
- [ ] 能否利用 **unquoted service binary path**？
- [ ] Service Triggers：枚举并触发有特权的服务（参见 windows-local-privilege-escalation/service-triggers.md）

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] 已安装应用是否有 **写入权限**？(参见 [write-permissions](windows-local-privilege-escalation/index.html#write-permissions))
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] 能否在 PATH 中的任何文件夹写入？
- [ ] 是否有已知的 service binary 会尝试加载任何不存在的 DLL？
- [ ] 能否写入任何 **binaries folder**？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 枚举网络（shares, interfaces, routes, neighbours, ...）
- [ ] 特别注意监听在 localhost (127.0.0.1) 的网络服务

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials) 凭证
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) 中有可用的凭证吗？
- [ ] 有趣的 [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)？
- [ ] 保存的 [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) 的密码？
- [ ] 在 [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) 中有有趣的信息？
- [ ] 在 [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) 中有密码？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) 密码？
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)？凭证？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)？DLL Side Loading？

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] Putty： [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) 和 [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)？
- [ ] 在 [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) 中有密码？
- [ ] 是否有任何 [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) 备份？
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)？
- [ ] 有 [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) 文件？
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)？
- [ ] 在 [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) 中的密码？
- [ ] 在 [**web logs**](windows-local-privilege-escalation/index.html#logs) 中有有趣的信息？
- [ ] 想要向用户[**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials)吗？
- [ ] 回收站中的有趣文件（参见 [**credentials-in-the-recyclebin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)）？
- [ ] 其他包含凭证的 [**registry**](windows-local-privilege-escalation/index.html#inside-the-registry)？
- [ ] 在 [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) 中（dbs, history, bookmarks, ...）？
- [ ] 在文件和注册表中进行 [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] 使用 [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) 自动搜索密码

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 你能否访问由管理员运行的进程的任何 handler？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 检查是否可以滥用它

{{#include ../banners/hacktricks-training.md}}
