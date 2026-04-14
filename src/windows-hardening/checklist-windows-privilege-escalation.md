# Checklist - 本地 Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **查找 Windows 本地 privilege escalation 向量的最佳工具:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] 获取 [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] 使用脚本搜索 **kernel** [**exploits**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] 使用 **Google** 搜索 kernel **exploits**
- [ ] 使用 **searchsploit** 搜索 kernel **exploits**
- [ ] **env vars** 中是否有有趣信息？(windows-local-privilege-escalation/index.html#environment)?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) 中是否有密码？
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) 中是否有有趣信息？
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] 检查 [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)和 [**WEF** ](windows-local-privilege-escalation/index.html#wef)设置
- [ ] 检查 [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] 检查 [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)是否已启用
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] 检查是否有任何 [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 检查当前用户的 [**privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 你是否属于任何 [**privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] 检查你是否启用了这些 token 中的任何一个：**SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] 检查你是否有 [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) 以读取 raw volumes 并绕过 file ACLs
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] 检查 [**users homes**](windows-local-privilege-escalation/index.html#home-folders)（可访问性？）
- [ ] 检查 [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] [**Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) 里有什么？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 检查当前 [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] 检查对外部受限的隐藏本地服务

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries 的 [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] 通过 `ProcDump.exe` 从 **interesting processes** 中窃取凭据？(firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] 能否 **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] 能否 **modify** 任意 **service** 执行的 **binary**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] 能否 **modify** 任意 **service** 的 **registry**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] 能否利用任何 **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] 已安装应用程序上的 **Write** [**permissions**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] 存在 **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] 你能在 PATH 内的任何文件夹中 **write** 吗？
- [ ] 是否有已知的 service binary 会尝试加载任何不存在的 DLL？
- [ ] 你能在任何 **binaries** 文件夹中 **write** 吗？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 枚举网络（shares, interfaces, routes, neighbours, ...）
- [ ] 特别关注在 localhost (127.0.0.1) 上监听的网络服务

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)凭据
- [ ] 你可以使用的 [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) 凭据？
- [ ] 有趣的 [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] 已保存 [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) 的密码？
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) 中是否有有趣信息？
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) 中的密码？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) 的密码？
- [ ] [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe) 是否存在？凭据？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) 中有密码？
- [ ] 是否有任何 [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) 备份？
- [ ] 如果存在 [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)，尝试 raw-volume 读取 `SAM`、`SYSTEM`、DPAPI material 和 `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) 文件？
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) 中的密码？
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) 中是否有有趣信息？
- [ ] 你想向用户 [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) 吗？
- [ ] [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) 中是否有有趣文件？
- [ ] 其他包含凭据的 [**registry**](windows-local-privilege-escalation/index.html#inside-the-registry)？
- [ ] 在 [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) 里（dbs, history, bookmarks, ...）？
- [ ] 在文件和 registry 中进行 [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] 用于自动搜索密码的 [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 你是否能访问由 administrator 运行的进程的任何 handler？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 检查你是否可以滥用它



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
