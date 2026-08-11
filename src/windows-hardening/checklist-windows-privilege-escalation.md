# Checklist - WindowsローカルPrivilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **WindowsローカルPrivilege Escalationのvectorを探す最適なtool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info)を取得
- [ ] [**scriptsを使用してkernel exploitsを検索**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] **kernel exploitsを検索するためにGoogleを使用**
- [ ] **kernel exploitsを検索するためにsearchsploitを使用**
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment)に興味深い情報はあるか？
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)にpasswordsはあるか？
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)に興味深い情報はあるか？
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)？
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)？
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)？

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)および[**WEF** ](windows-local-privilege-escalation/index.html#wef)settingsを確認
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps)を確認
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)がactiveか確認
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)？
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[？](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)？
- [ ] [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)が存在するか確認
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)？
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)？<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)？<sup>[[2]](#references)</sup>
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**current**] userの[**privileges**](windows-local-privilege-escalation/index.html#users-and-groups)を確認
- [ ] [**privileged groupのmember**](windows-local-privilege-escalation/index.html#privileged-groups)か？
- [ ] [これらのtokensのいずれかがenabledか確認](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**？
- [ ] raw volumesを読み取り、file ACLsをbypassするための[**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)があるか確認
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)？
- [ ] [ **users homes**](windows-local-privilege-escalation/index.html#home-folders)を確認（access？）
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)を確認
- [ ] [ **Clipboardの中身**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)は何か？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)を確認
- [ ] 外部から制限されている**hidden local services**を確認

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binariesの[**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe`を使用して**interesting processes**からcredentialsを窃取？（firefox、chromeなど...）

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [**any serviceをmodifyできるか**？](windows-local-privilege-escalation/index.html#permissions)
- [ ] [任意の**service**によって**executed**される**binary**を**modifyできるか？](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [任意の**service**の**registry**を**modifyできるか？](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [**unquoted service**のbinary **path**を利用できるか？](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: privileged servicesをenumerateしてtrigger](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **installed applicationsの** [**write permissions**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] **PATH内の任意のfolderにwriteできるか？**
- [ ] **non-existent DLLをloadしようとする**既知のservice binaryはあるか？
- [ ] **binaries folder**に**write**できるか？

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] networkをenumerate（shares、interfaces、routes、neighboursなど）
- [ ] localhost（127.0.0.1）でlisteningしているnetwork servicesを特に確認

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] 使用できる[**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentialsはあるか？
- [ ] 興味深い[**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)？
- [ ] 保存された[**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)のpasswords？
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)に興味深い情報はあるか？
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)にpasswordsはあるか？
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) passwords？
- [ ] [**AppCmd.exe exists**](windows-local-privilege-escalation/index.html#appcmd-exe)？credentialsはあるか？
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)？DLL Side Loading？

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)？
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)にpasswordsはあるか？
- [ ] [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backupはあるか？
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)が存在する場合、`SAM`、`SYSTEM`、DPAPI material、`MachineKeys`のraw-volume readsを試す
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)？
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file？
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)？
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)にPassword？
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs)に興味深い情報はあるか？
- [ ] userに[**credentialsを要求**](windows-local-privilege-escalation/index.html#ask-for-credentials)するか？
- [ ] [**Recycle Bin内のfiles**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)に興味深いものはあるか？
- [ ] その他の[**credentialsを含むregistry**](windows-local-privilege-escalation/index.html#inside-the-registry)？
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history)内（dbs、history、bookmarksなど）？
- [ ] filesとregistry内での[**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] passwordsを自動的に検索する[**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] administratorがrunしたprocessのhandlerにaccessできるか？

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] abuseできるか確認

## References

- [1] [Project Zero - Administrator ProtectionをUI Accessのabuseによってbypass](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
