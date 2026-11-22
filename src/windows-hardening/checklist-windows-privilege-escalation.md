# Λίστα ελέγχου - Κλιμάκωση τοπικών δικαιωμάτων στα Windows

{{#include ../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση vector κλιμάκωσης τοπικών δικαιωμάτων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Πληροφορίες συστήματος](windows-local-privilege-escalation/index.html#system-info)

- [ ] Λήψη [**πληροφοριών συστήματος**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Αναζήτηση για **kernel exploits με χρήση scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Χρήση του **Google για αναζήτηση** **kernel exploits**
- [ ] Χρήση του **searchsploit για αναζήτηση** **kernel exploits**
- [ ] Υπάρχουν ενδιαφέρουσες πληροφορίες στις [**env vars**](windows-local-privilege-escalation/index.html#environment);
- [ ] Υπάρχουν κωδικοί πρόσβασης στο [**ιστορικό PowerShell**](windows-local-privilege-escalation/index.html#powershell-history);
- [ ] Υπάρχουν ενδιαφέρουσες πληροφορίες στις [**ρυθμίσεις Internet**](windows-local-privilege-escalation/index.html#internet-settings);
- [ ] [**Μονάδες δίσκου**](windows-local-privilege-escalation/index.html#drives);
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus);
- [ ] [**Αυτόματοι ενημερωτές agent τρίτων / κατάχρηση IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated);

### [Καταγραφή/απαρίθμηση AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Έλεγχος των ρυθμίσεων [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)και [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Έλεγχος του [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Έλεγχος αν είναι ενεργό το [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)
- [ ] [**Προστασία LSA**](windows-local-privilege-escalation/index.html#lsa-protection);
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Αποθηκευμένα διαπιστευτήρια**](windows-local-privilege-escalation/index.html#cached-credentials);
- [ ] Έλεγχος για τυχόν [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Πολιτική AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy);
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Προστασία διαχειριστή / σιωπηλή ανύψωση UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md);<sup>[[1]](#references)</sup>
- [ ] [**Διάδοση μητρώου προσβασιμότητας Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md);<sup>[[2]](#references)</sup>
- [ ] [**Προνόμια χρήστη**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Έλεγχος των [**προνομίων** του **τρέχοντος** χρήστη](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Είστε [**μέλος κάποιας προνομιούχας ομάδας**](windows-local-privilege-escalation/index.html#privileged-groups);
- [ ] Έλεγχος αν υπάρχουν αυτά τα [προνόμια στο τρέχον token](windows-local-privilege-escalation/access-tokens.md), ακόμη κι αν εμφανίζονται ως **Disabled**: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**. Ένα απενεργοποιημένο προνόμιο μπορεί να ενεργοποιηθεί μόνο αν υπάρχει ήδη στο token.<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] Έλεγχος για το [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) ως δικαίωμα συντήρησης τόμων. Από μόνο του δεν παρέχει πρόσβαση ανάγνωσης στον ακατέργαστο τόμο· το άνοιγμα δίσκου ή τόμου έχει επίσης ξεχωριστές απαιτήσεις πρόσβασης.<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] [**Συνεδρίες χρηστών**](windows-local-privilege-escalation/index.html#logged-users-sessions);
- [ ] Έλεγχος των [**προσωπικών φακέλων χρηστών**](windows-local-privilege-escalation/index.html#home-folders) (πρόσβαση;)
- [ ] Έλεγχος της [**πολιτικής κωδικών πρόσβασης**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Τι υπάρχει [**στο Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard);

### [Δίκτυο](windows-local-privilege-escalation/index.html#network)

- [ ] Έλεγχος των [**πληροφοριών δικτύου**](windows-local-privilege-escalation/index.html#network) **του τρέχοντος** συστήματος
- [ ] Έλεγχος για **κρυφές τοπικές υπηρεσίες** με περιορισμένη πρόσβαση από το εξωτερικό

### [Εκτελούμενες διεργασίες](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Δικαιώματα [**αρχείων και φακέλων**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) των binaries των διεργασιών
- [ ] [**Εξόρυξη κωδικών πρόσβασης από τη μνήμη**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Μη ασφαλείς εφαρμογές GUI**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Κλοπή διαπιστευτηρίων από **ενδιαφέρουσες διεργασίες** μέσω `ProcDump.exe` ; (firefox, chrome, κ.λπ.)

### [Υπηρεσίες](windows-local-privilege-escalation/index.html#services)

- [ ] [Μπορείτε να **τροποποιήσετε κάποια υπηρεσία**;](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Μπορείτε να **τροποποιήσετε** το **binary** που **εκτελείται** από κάποια **υπηρεσία**;](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Μπορείτε να **τροποποιήσετε** το **μητρώο** κάποιας **υπηρεσίας**;](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Μπορείτε να εκμεταλλευτείτε κάποιο **unquoted service binary path**;](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Triggers υπηρεσιών: απαρίθμηση και ενεργοποίηση προνομιούχων υπηρεσιών](windows-local-privilege-escalation/service-triggers.md)

### [**Εφαρμογές**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Δικαιώματα εγγραφής** σε [**εγκατεστημένες εφαρμογές**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Εφαρμογές εκκίνησης**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Ευάλωτοι** [**drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Μπορείτε να **γράψετε σε κάποιον φάκελο μέσα στο PATH**;
- [ ] Υπάρχει γνωστό binary υπηρεσίας που **προσπαθεί να φορτώσει ανύπαρκτο DLL**;
- [ ] Μπορείτε να **γράψετε** σε κάποιον **φάκελο binaries**;

### [Δίκτυο](windows-local-privilege-escalation/index.html#network)

- [ ] Απαριθμήστε το δίκτυο (shares, interfaces, routes, γειτονικοί υπολογιστές, ...)
- [ ] Εξετάστε προσεκτικά τις υπηρεσίες δικτύου που ακούν στο localhost (127.0.0.1)

### [Διαπιστευτήρια Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Διαπιστευτήρια [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Υπάρχουν διαπιστευτήρια [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) που θα μπορούσατε να χρησιμοποιήσετε;
- [ ] Υπάρχουν ενδιαφέροντα [**διαπιστευτήρια DPAPI**](windows-local-privilege-escalation/index.html#dpapi);
- [ ] Κωδικοί πρόσβασης για αποθηκευμένα [**δίκτυα Wifi**](windows-local-privilege-escalation/index.html#wifi);
- [ ] Υπάρχουν ενδιαφέρουσες πληροφορίες στις [**αποθηκευμένες συνδέσεις RDP**](windows-local-privilege-escalation/index.html#saved-rdp-connections);
- [ ] Κωδικοί πρόσβασης στις [**εντολές που εκτελέστηκαν πρόσφατα**](windows-local-privilege-escalation/index.html#recently-run-commands);
- [ ] Κωδικοί πρόσβασης στο [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager);
- [ ] [Υπάρχει το **AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe); Διαπιστευτήρια;
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm); DLL Side Loading;

### [Αρχεία και μητρώο (διαπιστευτήρια)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**διαπιστευτήρια**](windows-local-privilege-escalation/index.html#putty-creds) **και** [**κλειδιά SSH host**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] Υπάρχουν [**κλειδιά SSH στο μητρώο**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry);
- [ ] Υπάρχουν κωδικοί πρόσβασης σε [**unattended αρχεία**](windows-local-privilege-escalation/index.html#unattended-files);
- [ ] Υπάρχει κάποιο αντίγραφο ασφαλείας [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups);
- [ ] Αν επιτρέπεται ανεξάρτητα η πρόσβαση ανάγνωσης σε raw-volume handle, αξιολογήστε την πιθανή έκθεση των `SAM`, `SYSTEM`, υλικού DPAPI και `MachineKeys`· μην θεωρείτε ότι αυτή η πρόσβαση παρέχεται μόνο από το **SeManageVolumePrivilege**.<sup>[[5]](#references)</sup>
- [ ] Υπάρχουν [**διαπιστευτήρια Cloud**](windows-local-privilege-escalation/index.html#cloud-credentials);
- [ ] Υπάρχει το αρχείο [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml);
- [ ] Υπάρχει [**αποθηκευμένος κωδικός GPP**](windows-local-privilege-escalation/index.html#cached-gpp-pasword);
- [ ] Υπάρχει κωδικός πρόσβασης στο [**αρχείο ρυθμίσεων IIS Web**](windows-local-privilege-escalation/index.html#iis-web-config);
- [ ] Υπάρχουν ενδιαφέρουσες πληροφορίες στα [**web logs**](windows-local-privilege-escalation/index.html#logs);
- [ ] Θέλετε να [**ζητήσετε διαπιστευτήρια**](windows-local-privilege-escalation/index.html#ask-for-credentials) από τον χρήστη;
- [ ] Υπάρχουν ενδιαφέροντα [**αρχεία στον Κάδο Ανακύκλωσης**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin);
- [ ] Υπάρχουν άλλα [**κλειδιά μητρώου που περιέχουν διαπιστευτήρια**](windows-local-privilege-escalation/index.html#inside-the-registry);
- [ ] Υπάρχουν μέσα στα [**δεδομένα του browser**](windows-local-privilege-escalation/index.html#browsers-history) (βάσεις δεδομένων, ιστορικό, σελιδοδείκτες, ...);
- [ ] [**Γενική αναζήτηση κωδικών πρόσβασης**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) σε αρχεία και μητρώο
- [ ] [**Εργαλεία**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) για αυτόματη αναζήτηση κωδικών πρόσβασης

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Έχετε πρόσβαση σε κάποιο handler διεργασίας που εκτελείται από διαχειριστή;

### [Πλαστοπροσωπία πελάτη Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Ελέγξτε αν μπορείτε να το καταχραστείτε



## References

- [1] [Project Zero - Παράκαμψη της προστασίας διαχειριστή μέσω κατάχρησης του UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft - Προνόμια](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft - Αλλαγή προνομίων σε token](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft - CreateFile για φυσικούς δίσκους και τόμους](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft - Διαχείριση προνομίων σε σύστημα αρχείων](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
