# Λίστα Ελέγχου - Τοπική Ανύψωση Δικαιωμάτων Windows

{{#include ../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για αναζήτηση τοπικών διαδρομών ανύψωσης δικαιωμάτων Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Πληροφορίες Συστήματος](windows-local-privilege-escalation/index.html#system-info)

- [ ] Αποκτήστε [**Πληροφορίες συστήματος**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Αναζητήστε **exploits πυρήνα** [**χρησιμοποιώντας scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Χρησιμοποιήστε **Google για αναζήτηση** exploits πυρήνα
- [ ] Χρησιμοποιήστε **searchsploit για αναζήτηση** exploits πυρήνα
- [ ] Ενδιαφέρουσες πληροφορίες σε [**env vars**](windows-local-privilege-escalation/index.html#environment);
- [ ] Κωδικοί πρόσβασης στην [**ιστορία PowerShell**](windows-local-privilege-escalation/index.html#powershell-history);
- [ ] Ενδιαφέρουσες πληροφορίες στις [**Ρυθμίσεις Διαδικτύου**](windows-local-privilege-escalation/index.html#internet-settings);
- [ ] [**Δίσκοι**](windows-local-privilege-escalation/index.html#drives);
- [ ] [**Exploits WSUS**](windows-local-privilege-escalation/index.html#wsus);
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated);

### [Καταγραφή/Αναγνώριση AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Ελέγξτε τις ρυθμίσεις [**Audit**](windows-local-privilege-escalation/index.html#audit-settings) και [**WEF**](windows-local-privilege-escalation/index.html#wef)
- [ ] Ελέγξτε το [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Ελέγξτε αν είναι ενεργό το [**WDigest**](windows-local-privilege-escalation/index.html#wdigest)
- [ ] [**Προστασία LSA**](windows-local-privilege-escalation/index.html#lsa-protection);
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials);
- [ ] Ελέγξτε αν υπάρχει κάποιο [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Πολιτική AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy);
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Δικαιώματα Χρήστη**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Ελέγξτε τα [**τρέχοντα**] δικαιώματα **χρήστη**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Είστε [**μέλος κάποιας προνομιούχας ομάδας**](windows-local-privilege-escalation/index.html#privileged-groups);
- [ ] Ελέγξτε αν έχετε [κάποια από αυτά τα tokens ενεργοποιημένα](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**;
- [ ] [**Συνεδρίες Χρηστών**](windows-local-privilege-escalation/index.html#logged-users-sessions);
- [ ] Ελέγξτε [**τα σπίτια χρηστών**](windows-local-privilege-escalation/index.html#home-folders) (πρόσβαση;)
- [ ] Ελέγξτε την [**Πολιτική Κωδικών Πρόσβασης**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Τι υπάρχει [**μέσα στο Πρόχειρο**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard);

### [Δίκτυο](windows-local-privilege-escalation/index.html#network)

- [ ] Ελέγξτε τις **τρέχουσες** [**πληροφορίες δικτύου**](windows-local-privilege-escalation/index.html#network)
- [ ] Ελέγξτε τις **κρυφές τοπικές υπηρεσίες** που περιορίζονται από το εξωτερικό

### [Διεργασίες σε Εκτέλεση](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Δικαιώματα [**αρχείων και φακέλων διεργασιών**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Εξόρυξη Κωδικών Πρόσβασης Μνήμης**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Ανασφαλείς GUI εφαρμογές**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Κλέψτε διαπιστευτήρια με **ενδιαφέρουσες διεργασίες** μέσω `ProcDump.exe` ? (firefox, chrome, κ.λπ ...)

### [Υπηρεσίες](windows-local-privilege-escalation/index.html#services)

- [ ] [Μπορείτε να **τροποποιήσετε κάποια υπηρεσία**;](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Μπορείτε να **τροποποιήσετε** το **δυαδικό** που **εκτελείται** από κάποια **υπηρεσία**;](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Μπορείτε να **τροποποιήσετε** το **μητρώο** οποιασδήποτε **υπηρεσίας**;](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Μπορείτε να εκμεταλλευτείτε οποιαδήποτε **μη αναφερόμενη υπηρεσία** δυαδική **διαδρομή**;](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Εφαρμογές**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Γράψτε** [**δικαιώματα σε εγκατεστημένες εφαρμογές**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Εφαρμογές Εκκίνησης**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Ευάλωτοι** [**Οδηγοί**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Μπορείτε να **γράψετε σε οποιονδήποτε φάκελο μέσα στο PATH**;
- [ ] Υπάρχει κάποια γνωστή δυαδική υπηρεσία που **προσπαθεί να φορτώσει οποιαδήποτε ανύπαρκτη DLL**;
- [ ] Μπορείτε να **γράψετε** σε οποιονδήποτε **φάκελο δυαδικών**;

### [Δίκτυο](windows-local-privilege-escalation/index.html#network)

- [ ] Αναγνωρίστε το δίκτυο (κοινές χρήσεις, διεπαφές, διαδρομές, γείτονες, ...)
- [ ] Δώστε προσοχή στις υπηρεσίες δικτύου που ακούνε στο localhost (127.0.0.1)

### [Διαπιστευτήρια Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Διαπιστευτήρια Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] [**Διαπιστευτήρια Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) που θα μπορούσατε να χρησιμοποιήσετε;
- [ ] Ενδιαφέροντα [**DPAPI διαπιστευτήρια**](windows-local-privilege-escalation/index.html#dpapi);
- [ ] Κωδικοί πρόσβασης αποθηκευμένων [**Wifi δικτύων**](windows-local-privilege-escalation/index.html#wifi);
- [ ] Ενδιαφέρουσες πληροφορίες σε [**αποθηκευμένες RDP Συνδέσεις**](windows-local-privilege-escalation/index.html#saved-rdp-connections);
- [ ] Κωδικοί πρόσβασης σε [**πρόσφατα εκτελούμενες εντολές**](windows-local-privilege-escalation/index.html#recently-run-commands);
- [ ] [**Διαπιστευτήρια Διαχειριστή Απομακρυσμένης Επιφάνειας Εργασίας**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) κωδικοί πρόσβασης;
- [ ] [**AppCmd.exe** υπάρχει](windows-local-privilege-escalation/index.html#appcmd-exe); Διαπιστευτήρια;
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm); DLL Side Loading;

### [Αρχεία και Μητρώο (Διαπιστευτήρια)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **και** [**κλειδιά SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Κλειδιά SSH στο μητρώο**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry);
- [ ] Κωδικοί πρόσβασης σε [**unattended αρχεία**](windows-local-privilege-escalation/index.html#unattended-files);
- [ ] Οποιοδήποτε [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) αντίγραφο;
- [ ] [**Διαπιστευτήρια Cloud**](windows-local-privilege-escalation/index.html#cloud-credentials);
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) αρχείο;
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword);
- [ ] Κωδικός πρόσβασης στο [**IIS Web config αρχείο**](windows-local-privilege-escalation/index.html#iis-web-config);
- [ ] Ενδιαφέρουσες πληροφορίες σε [**web** **logs**](windows-local-privilege-escalation/index.html#logs);
- [ ] Θέλετε να [**ζητήσετε διαπιστευτήρια**](windows-local-privilege-escalation/index.html#ask-for-credentials) από τον χρήστη;
- [ ] Ενδιαφέροντα [**αρχεία μέσα στον Κάδο Ανακύκλωσης**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin);
- [ ] Άλλο [**μητρώο που περιέχει διαπιστευτήρια**](windows-local-privilege-escalation/index.html#inside-the-registry);
- [ ] Μέσα σε [**Δεδομένα Περιηγητή**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, ιστορικό, σελιδοδείκτες, ...) ;
- [ ] [**Γενική αναζήτηση κωδικών πρόσβασης**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) σε αρχεία και μητρώο
- [ ] [**Εργαλεία**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) για αυτόματη αναζήτηση κωδικών πρόσβασης

### [Διαρροές Χειριστών](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Έχετε πρόσβαση σε οποιονδήποτε χειριστή διεργασίας που εκτελείται από διαχειριστή;

### [Αυτοπροσωποποίηση Πελάτη Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Ελέγξτε αν μπορείτε να το εκμεταλλευτείτε

{{#include ../banners/hacktricks-training.md}}
