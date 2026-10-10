# Checklist - Τοπική κλιμάκωση προνομίων στα Windows

{{#include ../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση διανυσμάτων τοπικής κλιμάκωσης προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Πληροφορίες συστήματος](windows-local-privilege-escalation/index.html#system-info)

- [ ] Λάβετε [**πληροφορίες συστήματος**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Αναζητήστε **kernel** [**exploits με χρήση scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Χρησιμοποιήστε το **Google για να αναζητήσετε** **exploits** για kernel
- [ ] Χρησιμοποιήστε το **searchsploit για να αναζητήσετε** **exploits** για kernel
- [ ] Υπάρχουν ενδιαφέρουσες πληροφορίες στις [**env vars**](windows-local-privilege-escalation/index.html#environment);
- [ ] Υπάρχουν κωδικοί πρόσβασης στο [**ιστορικό του PowerShell**](windows-local-privilege-escalation/index.html#powershell-history);
- [ ] Υπάρχουν ενδιαφέρουσες πληροφορίες στις [**ρυθμίσεις Internet**](windows-local-privilege-escalation/index.html#internet-settings);
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives);
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus);
- [ ] [**Auto-updaters τρίτων agent / κατάχρηση IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated);

### [Καταγραφή/απογραφή AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Ελέγξτε τις ρυθμίσεις [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)και [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Ελέγξτε το [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Ελέγξτε αν είναι ενεργό το [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection);
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[;](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials);
- [ ] Ελέγξτε αν υπάρχει κάποιο [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Πολιτική AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy);
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Προστασία διαχειριστή / σιωπηλή ανύψωση μέσω UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md);<sup>[[1]](#references)</sup>
- [ ] [**Διάδοση μητρώου προσβασιμότητας Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md);<sup>[[2]](#references)</sup>
- [ ] [**Προνόμια χρήστη**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Ελέγξτε τα [**προνόμια**](windows-local-privilege-escalation/index.html#users-and-groups) του **τρέχοντος** χρήστη
- [ ] Είστε [**μέλος κάποιας προνομιούχας ομάδας**](windows-local-privilege-escalation/index.html#privileged-groups);
- [ ] Ελέγξτε αν έχετε ενεργοποιημένα [κάποια από αυτά τα tokens](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**;
- [ ] Ελέγξτε αν έχετε το [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) για να διαβάζετε raw volumes και να παρακάμπτετε ACLs αρχείων
- [ ] [**Συνεδρίες χρηστών**](windows-local-privilege-escalation/index.html#logged-users-sessions);
- [ ] Ελέγξτε τους [**οικιακούς φακέλους χρηστών**](windows-local-privilege-escalation/index.html#home-folders) (πρόσβαση;)
- [ ] Ελέγξτε την [**πολιτική κωδικών πρόσβασης**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Τι υπάρχει[ **μέσα στο Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard);

### [Δίκτυο](windows-local-privilege-escalation/index.html#network)

- [ ] Ελέγξτε τις [**πληροφορίες δικτύου**](windows-local-privilege-escalation/index.html#network) του **τρέχοντος** συστήματος
- [ ] Ελέγξτε για **κρυφές τοπικές υπηρεσίες** με πρόσβαση περιορισμένη εκτός συστήματος

### [Διεργασίες σε εκτέλεση](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Δικαιώματα [**αρχείων και φακέλων**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) των εκτελέσιμων αρχείων διεργασιών
- [ ] [**Εξόρυξη κωδικών πρόσβασης από τη μνήμη**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Μη ασφαλείς εφαρμογές GUI**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Κλέψτε διαπιστευτήρια από **ενδιαφέρουσες διεργασίες** μέσω του `ProcDump.exe` ; (firefox, chrome, κ.λπ. ...)

### [Υπηρεσίες](windows-local-privilege-escalation/index.html#services)

- [ ] [Μπορείτε να **τροποποιήσετε κάποια υπηρεσία**;](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Μπορείτε να **τροποποιήσετε** το **binary** που **εκτελείται** από κάποια **υπηρεσία**;](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Μπορείτε να **τροποποιήσετε** το **μητρώο** κάποιας **υπηρεσίας**;](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Μπορείτε να εκμεταλλευτείτε κάποιο **unquoted service** **path** binary;](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: απαρίθμηση και ενεργοποίηση προνομιούχων υπηρεσιών](windows-local-privilege-escalation/service-triggers.md)

### [**Εφαρμογές**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Δικαιώματα εγγραφής** σε [**εγκατεστημένες εφαρμογές**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Εφαρμογές εκκίνησης**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Ευάλωτοι** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Μπορείτε να **γράψετε σε κάποιον φάκελο μέσα στο PATH**;
- [ ] Υπάρχει γνωστό binary υπηρεσίας που **προσπαθεί να φορτώσει κάποιο ανύπαρκτο DLL**;
- [ ] Μπορείτε να **γράψετε** σε κάποιον **φάκελο binaries**;

### [Δίκτυο](windows-local-privilege-escalation/index.html#network)

- [ ] Απαριθμήστε το δίκτυο (shares, interfaces, routes, neighbours, ...)
- [ ] Εξετάστε ιδιαίτερα τις υπηρεσίες δικτύου που ακούν στο localhost (127.0.0.1)

### [Διαπιστευτήρια Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Διαπιστευτήρια [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Υπάρχουν διαπιστευτήρια [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) που μπορείτε να χρησιμοποιήσετε;
- [ ] Υπάρχουν ενδιαφέροντα [**διαπιστευτήρια DPAPI**](windows-local-privilege-escalation/index.html#dpapi);
- [ ] Κωδικοί πρόσβασης αποθηκευμένων [**δικτύων Wifi**](windows-local-privilege-escalation/index.html#wifi);
- [ ] Υπάρχουν ενδιαφέρουσες πληροφορίες στις [**αποθηκευμένες συνδέσεις RDP**](windows-local-privilege-escalation/index.html#saved-rdp-connections);
- [ ] Κωδικοί πρόσβασης σε [**εντολές που εκτελέστηκαν πρόσφατα**](windows-local-privilege-escalation/index.html#recently-run-commands);
- [ ] Κωδικοί πρόσβασης στο [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager);
- [ ] Υπάρχει το [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe); Διαπιστευτήρια;
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm); DLL Side Loading;

### [Αρχεία και μητρώο (διαπιστευτήρια)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**διαπιστευτήρια**](windows-local-privilege-escalation/index.html#putty-creds) **και** [**κλειδιά SSH host**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Κλειδιά SSH στο μητρώο**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry);
- [ ] Κωδικοί πρόσβασης σε [**unattended αρχεία**](windows-local-privilege-escalation/index.html#unattended-files);
- [ ] Υπάρχει κάποιο αντίγραφο ασφαλείας [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups);
- [ ] Αν υπάρχει το [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), δοκιμάστε αναγνώσεις raw volumes για `SAM`, `SYSTEM`, υλικό DPAPI και `MachineKeys`
- [ ] [**Διαπιστευτήρια cloud**](windows-local-privilege-escalation/index.html#cloud-credentials);
- [ ] Υπάρχει αρχείο [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml);
- [ ] [**Αποθηκευμένος κωδικός GPP**](windows-local-privilege-escalation/index.html#cached-gpp-pasword);
- [ ] Υπάρχει κωδικός πρόσβασης στο [**αρχείο ρυθμίσεων IIS Web**](windows-local-privilege-escalation/index.html#iis-web-config);
- [ ] Υπάρχουν ενδιαφέρουσες πληροφορίες στα [**web logs**](windows-local-privilege-escalation/index.html#logs);
- [ ] Θέλετε να [**ζητήσετε διαπιστευτήρια**](windows-local-privilege-escalation/index.html#ask-for-credentials) από τον χρήστη;
- [ ] Υπάρχουν ενδιαφέροντα [**αρχεία στον Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin);
- [ ] Άλλα [**κλειδιά μητρώου που περιέχουν διαπιστευτήρια**](windows-local-privilege-escalation/index.html#inside-the-registry);
- [ ] Υπάρχουν διαπιστευτήρια στα [**δεδομένα του Browser**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, ιστορικό, σελιδοδείκτες, ...);
- [ ] [**Γενική αναζήτηση κωδικών πρόσβασης**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) σε αρχεία και μητρώο
- [ ] [**Εργαλεία**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) για αυτόματη αναζήτηση κωδικών πρόσβασης

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Έχετε πρόσβαση σε κάποιο handler διεργασίας που εκτελείται από διαχειριστή;

### [Πλαστοπροσωπία client named pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Ελέγξτε αν μπορείτε να το καταχραστείτε

## References

- [1] [Project Zero - Παράκαμψη της προστασίας διαχειριστή μέσω κατάχρησης του UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
