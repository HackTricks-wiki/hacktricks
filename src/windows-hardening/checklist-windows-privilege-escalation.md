# Checklist - Τοπική Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Καλύτερο tool για την αναζήτηση vectors τοπικής Windows privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Πληροφορίες συστήματος](windows-local-privilege-escalation/index.html#system-info)

- [ ] Λήψη [**πληροφοριών συστήματος**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Αναζήτηση για **kernel** [**exploits με χρήση scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Χρήση του **Google για αναζήτηση** **kernel exploits**
- [ ] Χρήση του **searchsploit για αναζήτηση** **kernel exploits**
- [ ] Ενδιαφέρουσες πληροφορίες σε [**env vars**](windows-local-privilege-escalation/index.html#environment);
- [ ] Κωδικοί πρόσβασης στο [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history);
- [ ] Ενδιαφέρουσες πληροφορίες στις [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings);
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives);
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus);
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated);

### [Enumeration Logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Έλεγχος των ρυθμίσεων [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)και [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Έλεγχος του [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Έλεγχος αν το [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)είναι ενεργό
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection);
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[;](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials);
- [ ] Έλεγχος για οποιοδήποτε [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy);
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md);<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md);<sup>[[2]](#references)</sup>
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Έλεγχος των **privileges** του [**τρέχοντος** χρήστη](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Είστε [**μέλος οποιουδήποτε privileged group**](windows-local-privilege-escalation/index.html#privileged-groups);
- [ ] Έλεγχος αν έχετε [οποιαδήποτε από αυτά τα tokens ενεργοποιημένα](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ;
- [ ] Έλεγχος αν έχετε το [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) για ανάγνωση raw volumes και παράκαμψη των file ACLs
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions);
- [ ] Έλεγχος των[ **user homes**](windows-local-privilege-escalation/index.html#home-folders) (πρόσβαση;)
- [ ] Έλεγχος του [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Τι υπάρχει[ **μέσα στο Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard);

### [Δίκτυο](windows-local-privilege-escalation/index.html#network)

- [ ] Έλεγχος των **τρέχοντων** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Έλεγχος των **hidden local services** που περιορίζονται εξωτερικά

### [Εκτελούμενες διεργασίες](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**File και folder permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) των binaries των διεργασιών
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Κλοπή credentials με **interesting processes** μέσω `ProcDump.exe`; (firefox, chrome κ.λπ. ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Μπορείτε να **τροποποιήσετε οποιοδήποτε service**;](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Μπορείτε να **τροποποιήσετε το** **binary** που **εκτελείται** από οποιοδήποτε **service**;](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Μπορείτε να **τροποποιήσετε το** **registry** οποιουδήποτε **service**;](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Μπορείτε να εκμεταλλευτείτε οποιοδήποτε **unquoted service** binary **path**;](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumeration και trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Εφαρμογές**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions σε εγκατεστημένες εφαρμογές**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Μπορείτε να κάνετε **write σε οποιονδήποτε φάκελο μέσα στο PATH**;
- [ ] Υπάρχει κάποιο γνωστό service binary που **προσπαθεί να φορτώσει οποιοδήποτε ανύπαρκτο DLL**;
- [ ] Μπορείτε να κάνετε **write** σε οποιονδήποτε φάκελο **binaries**;

### [Δίκτυο](windows-local-privilege-escalation/index.html#network)

- [ ] Enumeration του network (shares, interfaces, routes, neighbours, ...)
- [ ] Ιδιαίτερη προσοχή στα network services που ακούν στο localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credentials του [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Credentials του [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) που θα μπορούσατε να χρησιμοποιήσετε;
- [ ] Ενδιαφέροντα [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi);
- [ ] Κωδικοί πρόσβασης αποθηκευμένων [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi);
- [ ] Ενδιαφέρουσες πληροφορίες στις [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections);
- [ ] Κωδικοί πρόσβασης σε [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands);
- [ ] Κωδικοί πρόσβασης του [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager);
- [ ] [**AppCmd.exe exists**](windows-local-privilege-escalation/index.html#appcmd-exe); Credentials;
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm); DLL Side Loading;

### [Αρχεία και Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **και** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys στο registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry);
- [ ] Κωδικοί πρόσβασης σε [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files);
- [ ] Οποιοδήποτε backup των [**SAM και SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups);
- [ ] Αν υπάρχει το [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), δοκιμή raw-volume reads για `SAM`, `SYSTEM`, υλικό DPAPI και `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials);
- [ ] Αρχείο [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml);
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword);
- [ ] Κωδικός πρόσβασης σε [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config);
- [ ] Ενδιαφέρουσες πληροφορίες σε [**web** **logs**](windows-local-privilege-escalation/index.html#logs);
- [ ] Θέλετε να [**ζητήσετε credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) από τον χρήστη;
- [ ] Ενδιαφέροντα [**αρχεία μέσα στον Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin);
- [ ] Άλλα [**registry που περιέχουν credentials**](windows-local-privilege-escalation/index.html#inside-the-registry);
- [ ] Μέσα στα [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...);
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) σε αρχεία και registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) για αυτόματη αναζήτηση κωδικών πρόσβασης

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Έχετε πρόσβαση σε οποιονδήποτε handler μιας διεργασίας που εκτελείται από administrator;

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Έλεγχος αν μπορείτε να το εκμεταλλευτείτε

## Αναφορές

- [1] [Project Zero - Παράκαμψη του Administrator Protection μέσω κατάχρησης του UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
