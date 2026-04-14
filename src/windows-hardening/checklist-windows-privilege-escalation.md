# Checklist - Τοπική Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για να εντοπίσεις Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Απόκτησε [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Αναζήτησε [**kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Χρησιμοποίησε το **Google για αναζήτηση** kernel **exploits**
- [ ] Χρησιμοποίησε το **searchsploit για αναζήτηση** kernel **exploits**
- [ ] Ενδιαφέρουσες πληροφορίες σε [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Κωδικοί πρόσβασης στο [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Ενδιαφέρουσες πληροφορίες σε [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Έλεγξε τις ρυθμίσεις [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)και [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Έλεγξε το [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Έλεγξε αν το [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)είναι ενεργό
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Έλεγξε αν υπάρχει κάποιο [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Έλεγξε τα [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Είσαι [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Έλεγξε αν έχεις ενεργοποιημένα κάποιο από αυτά τα tokens: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Έλεγξε αν έχεις το [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) για να διαβάσεις raw volumes και να παρακάμψεις file ACLs
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Έλεγξε [**users homes**](windows-local-privilege-escalation/index.html#home-folders) (access?)
- [ ] Έλεγξε το [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Τι υπάρχει [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Έλεγξε τις **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Έλεγξε τις **hidden local services** restricted to the outside

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Δικαιώματα [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) των binaries των processes
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Κλέψε credentials με **interesting processes** μέσω `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Μπορείς να **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Μπορείς να **modify** το **binary** που **executed** από κάποιο **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Μπορείς να **modify** το **registry** κάποιου **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Μπορείς να εκμεταλλευτείς κάποιο **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Μπορείς να **write in any folder inside PATH**?
- [ ] Υπάρχει κάποιο γνωστό service binary που **tries to load any non-existant DLL**?
- [ ] Μπορείς να **write** σε οποιονδήποτε **binaries folder**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerate το network (shares, interfaces, routes, neighbours, ...)
- [ ] Δώσε ιδιαίτερη προσοχή σε network services που ακούνε στο localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] credentials του [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) που μπορείς να χρησιμοποιήσεις?
- [ ] Ενδιαφέροντα [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Κωδικοί πρόσβασης αποθηκευμένων [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Ενδιαφέρουσες πληροφορίες σε [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Κωδικοί πρόσβασης σε [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Passwords στο [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Υπάρχει το [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **και** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Κωδικοί πρόσβασης σε [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Κάποιο backup του [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Αν υπάρχει το [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), δοκίμασε raw-volume reads για `SAM`, `SYSTEM`, DPAPI material και `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Αρχείο [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Password σε [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Ενδιαφέρουσες πληροφορίες σε [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Θες να [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) από τον χρήστη?
- [ ] Ενδιαφέροντα [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Άλλα [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Στο [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) σε files και registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) για αυτόματη αναζήτηση passwords

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Έχεις πρόσβαση σε κάποιο handler process που εκτελείται από administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Έλεγξε αν μπορείς να το abuse



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
