# Λίστα Ελέγχου - Τοπική Ανύψωση Δικαιωμάτων Windows

{{#include ../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για αναζήτηση τοπικών διαδρομών ανύψωσης δικαιωμάτων Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Πληροφορίες Συστήματος](windows-local-privilege-escalation/#system-info)

- [ ] Αποκτήστε [**Πληροφορίες συστήματος**](windows-local-privilege-escalation/#system-info)
- [ ] Αναζητήστε **kernel** [**exploits χρησιμοποιώντας scripts**](windows-local-privilege-escalation/#version-exploits)
- [ ] Χρησιμοποιήστε **Google για αναζήτηση** για kernel **exploits**
- [ ] Χρησιμοποιήστε **searchsploit για αναζήτηση** για kernel **exploits**
- [ ] Ενδιαφέρουσες πληροφορίες σε [**env vars**](windows-local-privilege-escalation/#environment)?
- [ ] Κωδικοί πρόσβασης στην [**ιστορία PowerShell**](windows-local-privilege-escalation/#powershell-history)?
- [ ] Ενδιαφέρουσες πληροφορίες στις [**ρυθμίσεις Internet**](windows-local-privilege-escalation/#internet-settings)?
- [ ] [**Δίσκοι**](windows-local-privilege-escalation/#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Καταγραφή/Αναγνώριση AV](windows-local-privilege-escalation/#enumeration)

- [ ] Ελέγξτε τις ρυθμίσεις [**Audit**](windows-local-privilege-escalation/#audit-settings) και [**WEF**](windows-local-privilege-escalation/#wef)
- [ ] Ελέγξτε το [**LAPS**](windows-local-privilege-escalation/#laps)
- [ ] Ελέγξτε αν είναι ενεργό το [**WDigest**](windows-local-privilege-escalation/#wdigest)
- [ ] [**LSA Protection**](windows-local-privilege-escalation/#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/#cached-credentials)?
- [ ] Ελέγξτε αν υπάρχει κάποιο [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Δικαιώματα Χρήστη**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Ελέγξτε τα [**τρέχοντα**] δικαιώματα **χρήστη**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Είστε [**μέλος κάποιας προνομιούχας ομάδας**](windows-local-privilege-escalation/#privileged-groups)?
- [ ] Ελέγξτε αν έχετε [κάποια από αυτά τα tokens ενεργοποιημένα](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Συνεδρίες Χρηστών**](windows-local-privilege-escalation/#logged-users-sessions)?
- [ ] Ελέγξτε [**τα σπίτια χρηστών**](windows-local-privilege-escalation/#home-folders) (πρόσβαση?)
- [ ] Ελέγξτε την [**Πολιτική Κωδικών Πρόσβασης**](windows-local-privilege-escalation/#password-policy)
- [ ] Τι υπάρχει [**μέσα στο Clipboard**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Δίκτυο](windows-local-privilege-escalation/#network)

- [ ] Ελέγξτε τις **τρέχουσες** [**πληροφορίες δικτύου**](windows-local-privilege-escalation/#network)
- [ ] Ελέγξτε τις **κρυφές τοπικές υπηρεσίες** που περιορίζονται από το εξωτερικό

### [Τρέχουσες Διαδικασίες](windows-local-privilege-escalation/#running-processes)

- [ ] Δικαιώματα [**αρχείων και φακέλων διαδικασιών**](windows-local-privilege-escalation/#file-and-folder-permissions)
- [ ] [**Mining Κωδικών Πρόσβασης Μνήμης**](windows-local-privilege-escalation/#memory-password-mining)
- [ ] [**Ανασφαλείς εφαρμογές GUI**](windows-local-privilege-escalation/#insecure-gui-apps)
- [ ] Κλέψτε διαπιστευτήρια με **ενδιαφέρουσες διαδικασίες** μέσω `ProcDump.exe` ? (firefox, chrome, κ.λπ ...)

### [Υπηρεσίες](windows-local-privilege-escalation/#services)

- [ ] [Μπορείτε να **τροποποιήσετε κάποια υπηρεσία**;](windows-local-privilege-escalation/#permissions)
- [ ] [Μπορείτε να **τροποποιήσετε** το **δυαδικό** που εκτελείται από κάποια **υπηρεσία**;](windows-local-privilege-escalation/#modify-service-binary-path)
- [ ] [Μπορείτε να **τροποποιήσετε** το **μητρώο** οποιασδήποτε **υπηρεσίας**;](windows-local-privilege-escalation/#services-registry-modify-permissions)
- [ ] [Μπορείτε να εκμεταλλευτείτε οποιαδήποτε **μη αναφερόμενη διαδρομή** δυαδικής υπηρεσίας;](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Εφαρμογές**](windows-local-privilege-escalation/#applications)

- [ ] **Γράψτε** [**δικαιώματα σε εγκατεστημένες εφαρμογές**](windows-local-privilege-escalation/#write-permissions)
- [ ] [**Εφαρμογές Εκκίνησης**](windows-local-privilege-escalation/#run-at-startup)
- [ ] **Ευάλωτοι** [**Οδηγοί**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

- [ ] Μπορείτε να **γράψετε σε οποιονδήποτε φάκελο μέσα στο PATH**?
- [ ] Υπάρχει κάποια γνωστή δυαδική υπηρεσία που **προσπαθεί να φορτώσει οποιαδήποτε ανύπαρκτη DLL**?
- [ ] Μπορείτε να **γράψετε** σε οποιονδήποτε **φάκελο δυαδικών**?

### [Δίκτυο](windows-local-privilege-escalation/#network)

- [ ] Αναγνωρίστε το δίκτυο (κοινές χρήσεις, διεπαφές, διαδρομές, γείτονες, ...)
- [ ] Δώστε ιδιαίτερη προσοχή στις υπηρεσίες δικτύου που ακούνε στο localhost (127.0.0.1)

### [Διαπιστευτήρια Windows](windows-local-privilege-escalation/#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials) διαπιστευτήρια
- [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) διαπιστευτήρια που θα μπορούσατε να χρησιμοποιήσετε?
- [ ] Ενδιαφέροντα [**DPAPI διαπιστευτήρια**](windows-local-privilege-escalation/#dpapi)?
- [ ] Κωδικοί πρόσβασης αποθηκευμένων [**Wifi δικτύων**](windows-local-privilege-escalation/#wifi)?
- [ ] Ενδιαφέρουσες πληροφορίες σε [**αποθηκευμένες συνδέσεις RDP**](windows-local-privilege-escalation/#saved-rdp-connections)?
- [ ] Κωδικοί πρόσβασης σε [**πρόσφατα εκτελούμενες εντολές**](windows-local-privilege-escalation/#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/#remote-desktop-credential-manager) κωδικοί πρόσβασης?
- [ ] [**AppCmd.exe** υπάρχει](windows-local-privilege-escalation/#appcmd-exe)? Διαπιστευτήρια?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Side Loading?

### [Αρχεία και Μητρώο (Διαπιστευτήρια)](windows-local-privilege-escalation/#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/#putty-creds) **και** [**κλειδιά SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
- [ ] [**Κλειδιά SSH στο μητρώο**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
- [ ] Κωδικοί πρόσβασης σε [**unattended αρχεία**](windows-local-privilege-escalation/#unattended-files)?
- [ ] Οποιοδήποτε [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) αντίγραφο ασφαλείας?
- [ ] [**Cloud διαπιστευτήρια**](windows-local-privilege-escalation/#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) αρχείο?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/#cached-gpp-pasword)?
- [ ] Κωδικός πρόσβασης στο [**IIS Web config αρχείο**](windows-local-privilege-escalation/#iis-web-config)?
- [ ] Ενδιαφέρουσες πληροφορίες σε [**web** **logs**](windows-local-privilege-escalation/#logs)?
- [ ] Θέλετε να [**ζητήσετε διαπιστευτήρια**](windows-local-privilege-escalation/#ask-for-credentials) από τον χρήστη?
- [ ] Ενδιαφέροντα [**αρχεία μέσα στον Κάδο Ανακύκλωσης**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
- [ ] Άλλο [**μητρώο που περιέχει διαπιστευτήρια**](windows-local-privilege-escalation/#inside-the-registry)?
- [ ] Μέσα σε [**Δεδομένα Περιηγητή**](windows-local-privilege-escalation/#browsers-history) (dbs, ιστορικό, σελιδοδείκτες, ...)?
- [ ] [**Γενική αναζήτηση κωδικών πρόσβασης**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) σε αρχεία και μητρώο
- [ ] [**Εργαλεία**](windows-local-privilege-escalation/#tools-that-search-for-passwords) για αυτόματη αναζήτηση κωδικών πρόσβασης

### [Διαρροές Χειριστών](windows-local-privilege-escalation/#leaked-handlers)

- [ ] Έχετε πρόσβαση σε οποιονδήποτε χειριστή διαδικασίας που εκτελείται από διαχειριστή;

### [Αυτοπροσωποποίηση Πελάτη Pipe](windows-local-privilege-escalation/#named-pipe-client-impersonation)

- [ ] Ελέγξτε αν μπορείτε να το εκμεταλλευτείτε

{{#include ../banners/hacktricks-training.md}}
