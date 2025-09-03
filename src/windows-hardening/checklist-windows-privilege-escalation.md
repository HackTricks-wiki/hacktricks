# 检查表 - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] 获取 [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] 搜索 **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] 使用 **Google to search** 查找 kernel **exploits**
- [ ] 使用 **searchsploit to search** 查找 kernel **exploits**
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) 中有有趣的信息吗？
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) 中有密码吗？
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) 中有有趣信息吗？
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)？
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)？
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)？

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] 检查 [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) 和 [**WEF** ](windows-local-privilege-escalation/index.html#wef) 设置
- [ ] 检查 [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] 检查 [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) 是否激活
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)？
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)？
- [ ] 检查是否有任何 [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 检查 [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 你是否为 [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)？
- [ ] 检查你是否启用以下任何 token: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)？
- [ ] 检查 [**users homes**](windows-local-privilege-escalation/index.html#home-folders)（访问？）
- [ ] 检查 [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] 剪贴板中有什么？ [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 检查 **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] 检查受限于外部的隐藏本地服务

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] 检查进程二进制的 [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] 通过 `ProcDump.exe` 使用 **interesting processes** 窃取凭据？(firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Can you **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] 你可以在 PATH 的任何文件夹中写入吗？
- [ ] 是否存在任何已知服务二进制尝试加载不存在的 DLL？
- [ ] 你可以在任何 **binaries folder** 中写入吗？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 枚举网络（shares, interfaces, routes, neighbours, ...）
- [ ] 特别关注监听在 localhost (127.0.0.1) 的网络服务

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) 凭据
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) 中可用的凭据？
- [ ] 有趣的 [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)？
- [ ] 已保存的 [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) 密码？
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) 中有有趣信息？
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) 中有密码？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) 密码？
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)？
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) 中有密码？
- [ ] 是否有任何 [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) 备份？
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)？
- [ ] 有 **McAfee SiteList.xml** 文件吗？([**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml))
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)？
- [ ] 在 [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) 中有密码？
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) 中有有趣信息？
- [ ] 想要向用户 [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) 吗？
- [ ] 回收站中的有趣 [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)？
- [ ] 其他包含凭据的 [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)？
- [ ] 浏览器数据中（dbs, history, bookmarks, ...）有内容？ [**inside Browser data**](windows-local-privilege-escalation/index.html#browsers-history)
- [ ] 在文件和注册表中进行 [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] 使用 [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) 自动搜索密码

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 你是否可以访问由管理员运行的进程的任何句柄？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 检查是否可以滥用它

{{#include ../banners/hacktricks-training.md}}
