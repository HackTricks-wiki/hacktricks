# Checklist - Windows 本地提权

{{#include ../banners/hacktricks-training.md}}

### **查找 Windows 本地提权 vectors 的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [系统信息](windows-local-privilege-escalation/index.html#system-info)

- [ ] 获取[**系统信息**](windows-local-privilege-escalation/index.html#system-info)
- [ ] 使用[**脚本查找 kernel exploits**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] 使用 **Google 搜索** kernel **exploits**
- [ ] 使用 **searchsploit 搜索** kernel **exploits**
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) 中是否有有趣的信息？
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) 中是否有密码？
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) 中是否有有趣的信息？
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)？
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)？
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)？

### [Logging/AV 枚举](windows-local-privilege-escalation/index.html#enumeration)

- [ ] 检查 [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)和 [**WEF** ](windows-local-privilege-escalation/index.html#wef)设置
- [ ] 检查 [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] 检查 [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)是否处于 active 状态
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)？
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[？](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)？
- [ ] 检查是否存在任何 [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)？<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)？<sup>[[2]](#references)</sup>
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 检查[**当前**]用户的[**privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 你是否是任何[**privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)的成员？
- [ ] 检查你是否启用了[这些 tokens](windows-local-privilege-escalation/index.html#token-manipulation)中的任意一个：**SeImpersonatePrivilege、SeAssignPrimaryPrivilege、SeTcbPrivilege、SeBackupPrivilege、SeRestorePrivilege、SeCreateTokenPrivilege、SeLoadDriverPrivilege、SeTakeOwnershipPrivilege、SeDebugPrivilege**？
- [ ] 检查你是否拥有 [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)，以读取 raw volumes 并绕过文件 ACL
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)？
- [ ] 检查[ **users homes**](windows-local-privilege-escalation/index.html#home-folders)（是否可访问？）
- [ ] 检查 [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] [**Clipboard 中有什么内容**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)？

### [网络](windows-local-privilege-escalation/index.html#network)

- [ ] 检查**当前**[**网络** **信息**](windows-local-privilege-escalation/index.html#network)
- [ ] 检查限制外部访问的**隐藏本地服务**

### [运行中的进程](windows-local-privilege-escalation/index.html#running-processes)

- [ ] 进程二进制文件的[**文件和文件夹权限**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] 使用 `ProcDump.exe` 从**有趣的进程**中窃取 credentials？（firefox、chrome 等……）

### [服务](windows-local-privilege-escalation/index.html#services)

- [ ] [你能**修改任何服务**吗？](windows-local-privilege-escalation/index.html#permissions)
- [ ] [你能**修改**任何**服务**所**执行**的**二进制文件**吗？](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [你能**修改**任何**服务**的**registry**吗？](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [你能利用任何**未加引号的服务**二进制**路径**吗？](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: 枚举并触发 privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**应用程序**](windows-local-privilege-escalation/index.html#applications)

- [ ] **已安装应用程序上**的[**写入权限**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [存在**vulnerable**的 **Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] 你能**写入 PATH 中的任何文件夹**吗？
- [ ] 是否存在任何已知的服务二进制文件，**尝试加载不存在的 DLL**？
- [ ] 你能**写入**任何**二进制文件夹**吗？

### [网络](windows-local-privilege-escalation/index.html#network)

- [ ] 枚举网络（shares、interfaces、routes、neighbours……）
- [ ] 特别关注监听 localhost（127.0.0.1）的网络服务

### [Windows 凭据](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] 是否存在可以使用的 [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials？
- [ ] 有趣的 [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)？
- [ ] 已保存的 [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) 的密码？
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) 中是否有有趣的信息？
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) 中是否有密码？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) 密码？
- [ ] [**AppCmd.exe exists**](windows-local-privilege-escalation/index.html#appcmd-exe)？Credentials？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)？DLL Side Loading？

### [文件和 Registry（Credentials）](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty：**[**Creds**](windows-local-privilege-escalation/index.html#putty-creds)**和**[**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)？
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) 中是否有密码？
- [ ] 是否有任何 [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup？
- [ ] 如果存在 [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)，尝试读取 raw volume 中的 `SAM`、`SYSTEM`、DPAPI material 和 `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)？
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) 文件？
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)？
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) 中的密码？
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) 中是否有有趣的信息？
- [ ] 你想向用户[**索要 credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials)吗？
- [ ] [**Recycle Bin 中的文件**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) 中是否有有趣的信息？
- [ ] 其他[**包含 credentials 的 registry**](windows-local-privilege-escalation/index.html#inside-the-registry)？
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) 中（dbs、history、bookmarks……）？
- [ ] 在文件和 registry 中进行[**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] 用于自动搜索密码的[**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 你是否可以访问由 administrator 运行的进程的 handler？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 检查你是否可以 abuse 它

## References

- [1] [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
