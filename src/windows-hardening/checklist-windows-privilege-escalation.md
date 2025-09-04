# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] 获取 [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] 搜索 **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] 使用 Google 搜索 kernel **exploits**
- [ ] 使用 searchsploit 搜索 kernel **exploits**
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) 中有有趣信息吗？
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) 中有密码吗？
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) 中有有趣信息吗？
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)？
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)？
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)？

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] 检查 [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) 和 [**WEF** ](windows-local-privilege-escalation/index.html#wef) 设置
- [ ] 检查 [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] 检查 [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) 是否启用
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)？
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)？
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)？
- [ ] 检查是否有任何 [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 检查当前用户的 **privileges** (权限) (查看 [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups))
- [ ] 你是 [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups) 吗？
- [ ] 检查是否拥有 [any of these tokens enabled](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)？
- [ ] 检查 [**users homes**](windows-local-privilege-escalation/index.html#home-folders)（访问权限？）
- [ ] 检查 [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] 查看剪贴板中有什么内容 [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 检查当前的 [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] 检查对外受限的 **hidden local services**

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] 进程二进制文件和文件夹的 [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] 使用 `ProcDump.exe` 从有价值的进程窃取凭据？（firefox, chrome 等）

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] 能否 **modify any service**？(修改任何服务？) (查看权限)
- [ ] 能否 **modify** 服务所 **执行的 binary**？(修改服务执行的二进制文件？)
- [ ] 能否 **modify** 任何服务的 **registry**？(修改服务注册表？)
- [ ] 能否利用任何 **unquoted service** binary **path**？(未引用的服务路径？)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] 安装的应用是否有 **write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] 你能否 **write in any folder inside PATH**？
- [ ] 是否有已知的服务二进制会尝试加载不存在的 DLL？
- [ ] 你能否 **write** 到任何 **binaries folder**？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 枚举网络（shares, interfaces, routes, neighbours, ...）
- [ ] 特别关注监听在 localhost (127.0.0.1) 的网络服务

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) 凭据
- [ ] 有可用的 [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) 凭据吗？
- [ ] 有有价值的 [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) 吗？
- [ ] 保存的 [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) 的密码？
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) 中有有趣信息吗？
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) 中有密码吗？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) 的密码？
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)？凭据？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)？DLL Side Loading？

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] 注册表中有 [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)？
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) 中有密码吗？
- [ ] 有任何 [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) 备份吗？
- [ ] 有 [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials) 吗？
- [ ] 有 [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) 文件吗？
- [ ] 有 [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword) 吗？
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) 中有密码吗？
- [ ] 日志中有有趣信息吗？[**web** **logs**](windows-local-privilege-escalation/index.html#logs)
- [ ] 想要向用户请求凭据吗？[**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials)
- [ ] 回收站中的有趣文件？[**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)
- [ ] 其他包含凭据的 [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)
- [ ] 浏览器数据中有有价值信息吗？[**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)
- [ ] 在文件和注册表中进行 [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] 使用可以自动搜索密码的 [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 你能访问由管理员运行的进程的任何 handler 吗？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 检查是否可以滥用

{{#include ../banners/hacktricks-training.md}}
