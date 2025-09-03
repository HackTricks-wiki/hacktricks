# Checklist - Local Windows Privilege Esccalation

{{#include ../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Λάβετε [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Αναζητήστε **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Χρησιμοποιήστε **Google to search** για kernel **exploits**
- [ ] Χρησιμοποιήστε **searchsploit to search** για kernel **exploits**
- [ ] Ενδιαφέροντα στοιχεία στα [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Κωδικοί στο [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Ενδιαφέροντα στοιχεία στις [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Ελέγξτε τις ρυθμίσεις [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)και [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Ελέγξτε [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Ελέγξτε αν [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)είναι ενεργό
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Ελέγξτε αν υπάρχει κάποιο [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Ελέγξτε τα [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Είστε [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Ελέγξτε αν έχετε [any of these tokens enabled](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Ελέγξτε [ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (πρόσβαση?)
- [ ] Ελέγξτε την [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Τι υπάρχει [ **inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Ελέγξτε τις **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Ελέγξτε **hidden local services** περιορισμένες προς το εξωτερικό

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Δικαιώματα αρχείων των binaries των processes [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Κλέψτε διαπιστευτήρια με **ενδιαφέρουσες διεργασίες** μέσω `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] Μπορείτε να **modify any service**? (μπορείτε να τροποποιήσετε κάποια υπηρεσία;)
- [ ] Μπορείτε να **modify** το **binary** που **εκτελείται** από κάποια **service**? (modify the binary path)
- [ ] Μπορείτε να **modify** το **registry** κάποιας **service**? (services-registry-modify-permissions)
- [ ] Μπορείτε να εκμεταλλευτείτε κάποιο **unquoted service** binary **path**?

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Εγγραφή** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Μπορείτε να **write in any folder inside PATH**?
- [ ] Υπάρχει κάποιο γνωστό service binary που **tries to load any non-existant DLL**?
- [ ] Μπορείτε να **write** σε κάποιο **binaries folder**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Απογράψτε το δίκτυο (shares, interfaces, routes, neighbours, ...)
- [ ] Δώστε ιδιαίτερη προσοχή σε network services που ακούνε στο localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials που θα μπορούσατε να χρησιμοποιήσετε?
- [ ] Ενδιαφέροντα [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Κωδικοί αποθηκευμένων [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Ενδιαφέροντα στοιχεία σε [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Κωδικοί σε [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) κωδικοί?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Κωδικοί σε [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Κάποιο backup των [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) αρχείο?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Κωδικός στο [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Ενδιαφέροντα στοιχεία σε [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Θέλετε να [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) από τον χρήστη;
- [ ] Ενδιαφέροντα [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Άλλο [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Μέσα σε [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) σε αρχεία και registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) για αυτόματη αναζήτηση κωδικών

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Έχετε πρόσβαση σε κάποιο handler διαδικασίας που τρέχει από administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Ελέγξτε αν μπορείτε να το εκμεταλλευτείτε

{{#include ../banners/hacktricks-training.md}}
