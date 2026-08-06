# Checklist - ローカル Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探す最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info) を取得
- [ ] [**scripts を使用して kernel exploits**](windows-local-privilege-escalation/index.html#version-exploits) を検索
- [ ] **Google を使用して** kernel **exploits** を検索
- [ ] **searchsploit を使用して** kernel **exploits** を検索
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) に興味深い情報はあるか？
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history) に passwords はあるか？
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) に興味深い情報はあるか？
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)？
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)？
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)？

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)および [**WEF** ](windows-local-privilege-escalation/index.html#wef) settings を確認
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) を確認
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)が active か確認
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)？
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)？
- [ ] [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) の有無を確認
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)？<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)？<sup>[[2]](#references)</sup>
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**current** user の **privileges**](windows-local-privilege-escalation/index.html#users-and-groups) を確認
- [ ] [**privileged group の member**](windows-local-privilege-escalation/index.html#privileged-groups) か？
- [ ] 次の [tokens enabled](windows-local-privilege-escalation/index.html#token-manipulation) があるか確認: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**？
- [ ] raw volumes を読み取り file ACLs を bypass するための [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) があるか確認
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)？
- [ ] [ **users homes**](windows-local-privilege-escalation/index.html#home-folders)（access？）を確認
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) を確認
- [ ] [ **Clipboard の内部**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)には何があるか？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] **current** [**network** **information**](windows-local-privilege-escalation/index.html#network) を確認
- [ ] 外部からの access が制限された **hidden local services** を確認

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries の [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe` を使用して **interesting processes** から credentials を盗めるか？（firefox、chrome など...）

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [**any service を modify** できるか？](windows-local-privilege-escalation/index.html#permissions)
- [ ] [any **service** によって **executed** される **binary** を **modify** できるか？](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [any **service** の **registry** を **modify** できるか？](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [**unquoted service** binary **path** を利用できるか？](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **installed applications の** [**write permissions**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] **PATH 内の任意の folder に write** できるか？
- [ ] **存在しない DLL を load しようとする**既知の service binary はあるか？
- [ ] 任意の **binaries folder に write** できるか？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] network を enumerate（shares、interfaces、routes、neighbours など）
- [ ] localhost（127.0.0.1）で listening している network services を特に確認

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] 使用できる [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials はあるか？
- [ ] 興味深い [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)？
- [ ] 保存された [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) の passwords？
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) に興味深い情報はあるか？
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) に passwords はあるか？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) passwords？
- [ ] [**AppCmd.exe exists**](windows-local-privilege-escalation/index.html#appcmd-exe)？Credentials？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)？DLL Side Loading？

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **および** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)？
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) に passwords はあるか？
- [ ] [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) の backup はあるか？
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) が存在する場合、`SAM`、`SYSTEM`、DPAPI material、`MachineKeys` の raw-volume reads を試す
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)？
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file？
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)？
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) に Password はあるか？
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs) に興味深い情報はあるか？
- [ ] user に [**credentials を ask**](windows-local-privilege-escalation/index.html#ask-for-credentials) するか？
- [ ] [**Recycle Bin 内の files**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) に興味深いものはあるか？
- [ ] その他の [**credentials を含む registry**](windows-local-privilege-escalation/index.html#inside-the-registry)？
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) の内部（dbs、history、bookmarks など）？
- [ ] files と registry 内での [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] passwords を自動検索する [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] administrator が実行している process の handler に access できるか？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] abuse できるか確認

## References

- [1] [Project Zero - UI Access を abuse した Administrator Protection の bypass](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
