# Checklist - Τοπική κλιμάκωση προνομίων στα Windows

{{#include ../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση vectors τοπικής κλιμάκωσης προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Πληροφορίες συστήματος](windows-local-privilege-escalation/index.html#system-info)

- [ ] Λήψη [**πληροφοριών συστήματος**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Αναζήτηση για **kernel** [**exploits με χρήση scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Χρήση του **Google για αναζήτηση** **kernel exploits**
- [ ] Χρήση του **searchsploit για αναζήτηση** **kernel exploits**
- [ ] Ενδιαφέρουσες πληροφορίες σε [**env vars**](windows-local-privilege-escalation/index.html#environment);
- [ ] Κωδικοί πρόσβασης στο [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history);
- [ ] Ενδιαφέρουσες πληροφορίες στις [**ρυθμίσεις Internet**](windows-local-privilege-escalation/index.html#internet-settings);
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives);
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus);
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated);

### [Enumeration Logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Έλεγχος των ρυθμίσεων [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)και [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Έλεγχος του [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Έλεγχος αν το [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)είναι ενεργό
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection);
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials);
- [ ] Έλεγχος αν υπάρχει κάποιο [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy);
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md);<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md);<sup>[[2]](#references)</sup>
- [ ] [**Προνόμια χρηστών**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Έλεγχος των [**προνομίων**](windows-local-privilege-escalation/index.html#users-and-groups) του **τρέχοντος** χρήστη
- [ ] Είστε [**μέλος κάποιας privileged group**](windows-local-privilege-escalation/index.html#privileged-groups);
- [ ] Έλεγχος αν έχετε [ενεργοποιημένα κάποιο από αυτά τα tokens](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ;
- [ ] Έλεγχος αν έχετε το [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) για ανάγνωση raw volumes και παράκαμψη των file ACLs
- [ ] [**Συνεδρίες χρηστών**](windows-local-privilege-escalation/index.html#logged-users-sessions);
- [ ] Έλεγχος των[ **home directories των χρηστών**](windows-local-privilege-escalation/index.html#home-folders) (πρόσβαση;)
- [ ] Έλεγχος της [**Πολιτικής κωδικών πρόσβασης**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Τι υπάρχει[ **μέσα στο Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard);

### [Δίκτυο](windows-local-privilege-escalation/index.html#network)

- [ ] Έλεγχος των **τρέχοντων** [**πληροφοριών ** **δικτύου**](windows-local-privilege-escalation/index.html#network)
- [ ] Έλεγχος των **κρυφών local services** που είναι περιορισμένες εξωτερικά

### [Εκτελούμενες διεργασίες](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Δικαιώματα αρχείων και φακέλων**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) των binaries των διεργασιών
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Κλοπή credentials από **ενδιαφέρουσες διεργασίες** μέσω του `ProcDump.exe`; (firefox, chrome, κ.λπ. ...)

### [Υπηρεσίες](windows-local-privilege-escalation/index.html#services)

- [ ] [Μπορείτε να **τροποποιήσετε κάποια υπηρεσία**;](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Μπορείτε να **τροποποιήσετε το** **binary** που **εκτελείται** από κάποια **υπηρεσία**;](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Μπορείτε να **τροποποιήσετε το** **registry** κάποιας **υπηρεσίας**;](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Μπορείτε να εκμεταλλευτείτε κάποιο **unquoted service** **path** binary;](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumeration και ενεργοποίηση privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Εφαρμογές**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Δικαιώματα εγγραφής** στις [**εγκατεστημένες εφαρμογές**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Εφαρμογές εκκίνησης**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Ευάλωτοι** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Μπορείτε να κάνετε **write σε οποιονδήποτε φάκελο μέσα στο PATH**;
- [ ] Υπάρχει κάποιο γνωστό service binary που **προσπαθεί να φορτώσει ανύπαρκτο DLL**;
- [ ] Μπορείτε να κάνετε **write** σε οποιονδήποτε φάκελο με **binaries**;

### [Δίκτυο](windows-local-privilege-escalation/index.html#network)

- [ ] Enumeration του δικτύου (shares, interfaces, routes, neighbours, ...)
- [ ] Ιδιαίτερη προσοχή στις network services που ακούν στο localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credentials του [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Credentials του [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) που θα μπορούσατε να χρησιμοποιήσετε;
- [ ] Ενδιαφέροντα [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi);
- [ ] Κωδικοί πρόσβασης αποθηκευμένων [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi);
- [ ] Ενδιαφέρουσες πληροφορίες στις [**αποθηκευμένες RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections);
- [ ] Κωδικοί πρόσβασης σε [**πρόσφατα εκτελεσμένες εντολές**](windows-local-privilege-escalation/index.html#recently-run-commands);
- [ ] Κωδικοί πρόσβασης του [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager);
- [ ] Υπάρχει το [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe); Credentials;
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm); DLL Side Loading;

### [Αρχεία και Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **και** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys στο registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry);
- [ ] Κωδικοί πρόσβασης σε [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files);
- [ ] Υπάρχει κάποιο backup των [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups);
- [ ] Αν υπάρχει το [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), δοκιμάστε raw-volume reads για `SAM`, `SYSTEM`, υλικό DPAPI και `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials);
- [ ] Αρχείο [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml);
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword);
- [ ] Κωδικός πρόσβασης στο [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config);
- [ ] Ενδιαφέρουσες πληροφορίες στα [**web** **logs**](windows-local-privilege-escalation/index.html#logs);
- [ ] Θέλετε να [**ζητήσετε credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) από τον χρήστη;
- [ ] Ενδιαφέροντα [**αρχεία μέσα στον Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin);
- [ ] Άλλο [**registry που περιέχει credentials**](windows-local-privilege-escalation/index.html#inside-the-registry);
- [ ] Μέσα στα [**δεδομένα του Browser**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...);
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) σε αρχεία και registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) για αυτόματη αναζήτηση κωδικών πρόσβασης

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Έχετε πρόσβαση σε κάποιο handler μιας διεργασίας που εκτελείται από administrator;

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Ελέγξτε αν μπορείτε να το εκμεταλλευτείτε

## References

- [1] [Project Zero - Παράκαμψη του Administrator Protection μέσω κατάχρησης του UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
