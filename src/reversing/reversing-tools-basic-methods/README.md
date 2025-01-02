# Outils de Reversing & Méthodes de Base

{{#include ../../banners/hacktricks-training.md}}

## Outils de Reversing Basés sur ImGui

Logiciel :

- ReverseKit : [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Décompilateur Wasm / Compilateur Wat

En ligne :

- Utilisez [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) pour **décompiler** de wasm (binaire) à wat (texte clair)
- Utilisez [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) pour **compiler** de wat à wasm
- vous pouvez également essayer d'utiliser [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) pour décompiler

Logiciel :

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Décompilateur .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek est un décompilateur qui **décompile et examine plusieurs formats**, y compris **bibliothèques** (.dll), **fichiers de métadonnées Windows** (.winmd), et **exécutables** (.exe). Une fois décompilé, un assembly peut être enregistré en tant que projet Visual Studio (.csproj).

L'avantage ici est que si un code source perdu nécessite une restauration à partir d'un assembly hérité, cette action peut faire gagner du temps. De plus, dotPeek fournit une navigation pratique à travers le code décompilé, ce qui en fait l'un des outils parfaits pour **l'analyse d'algorithmes Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Avec un modèle d'add-in complet et une API qui étend l'outil pour répondre à vos besoins exacts, .NET Reflector fait gagner du temps et simplifie le développement. Jetons un œil à la pléthore de services d'ingénierie inverse que cet outil fournit :

- Fournit un aperçu de la façon dont les données circulent à travers une bibliothèque ou un composant
- Fournit un aperçu de l'implémentation et de l'utilisation des langages et frameworks .NET
- Trouve des fonctionnalités non documentées et non exposées pour tirer le meilleur parti des API et des technologies utilisées.
- Trouve des dépendances et différents assemblies
- Localise exactement les erreurs dans votre code, les composants tiers et les bibliothèques.
- Débogue dans la source de tout le code .NET avec lequel vous travaillez.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy pour Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) : Vous pouvez l'avoir sur n'importe quel OS (vous pouvez l'installer directement depuis VSCode, pas besoin de télécharger le git. Cliquez sur **Extensions** et **cherchez ILSpy**).\
Si vous avez besoin de **décompiler**, **modifier** et **recompiler** à nouveau, vous pouvez utiliser [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou un fork activement maintenu de celui-ci, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic Droit -> Modifier la Méthode** pour changer quelque chose à l'intérieur d'une fonction).

### Journalisation DNSpy

Pour faire en sorte que **DNSpy enregistre certaines informations dans un fichier**, vous pouvez utiliser ce snippet :
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Débogage DNSpy

Pour déboguer du code en utilisant DNSpy, vous devez :

Tout d'abord, changer les **attributs d'assemblage** liés au **débogage** :

![](<../../images/image (973).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
À :
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Et cliquez sur **compiler** :

![](<../../images/image (314) (1).png>)

Ensuite, enregistrez le nouveau fichier via _**Fichier >> Enregistrer le module...**_ :

![](<../../images/image (602).png>)

C'est nécessaire car si vous ne le faites pas, à **l'exécution**, plusieurs **optimisations** seront appliquées au code et il pourrait être possible que lors du débogage un **point d'arrêt ne soit jamais atteint** ou que certaines **variables n'existent pas**.

Ensuite, si votre application .NET est **exécutée** par **IIS**, vous pouvez **la redémarrer** avec :
```
iisreset /noforce
```
Ensuite, pour commencer le débogage, vous devez fermer tous les fichiers ouverts et dans l'**onglet Débogage**, sélectionnez **Attacher au processus...** :

![](<../../images/image (318).png>)

Ensuite, sélectionnez **w3wp.exe** pour vous attacher au **serveur IIS** et cliquez sur **attacher** :

![](<../../images/image (113).png>)

Maintenant que nous déboguons le processus, il est temps de l'arrêter et de charger tous les modules. Cliquez d'abord sur _Déboguer >> Tout interrompre_ puis cliquez sur _**Déboguer >> Fenêtres >> Modules**_ :

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Cliquez sur n'importe quel module dans **Modules** et sélectionnez **Ouvrir tous les modules** :

![](<../../images/image (922).png>)

Cliquez avec le bouton droit sur n'importe quel module dans **Explorateur d'assemblage** et cliquez sur **Trier les assemblages** :

![](<../../images/image (339).png>)

## Décompilateur Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Débogage des DLL

### Utilisation d'IDA

- **Charger rundll32** (64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- Sélectionnez le débogueur **Windbg**
- Sélectionnez "**Suspendre lors du chargement/déchargement de la bibliothèque**"

![](<../../images/image (868).png>)

- Configurez les **paramètres** de l'exécution en mettant le **chemin vers la DLL** et la fonction que vous souhaitez appeler :

![](<../../images/image (704).png>)

Ensuite, lorsque vous commencez à déboguer, **l'exécution sera arrêtée lorsque chaque DLL est chargée**, puis, lorsque rundll32 charge votre DLL, l'exécution sera arrêtée.

Mais, comment pouvez-vous accéder au code de la DLL qui a été chargée ? En utilisant cette méthode, je ne sais pas comment.

### Utilisation de x64dbg/x32dbg

- **Charger rundll32** (64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- **Changer la ligne de commande** (_Fichier --> Changer la ligne de commande_) et définir le chemin de la dll et la fonction que vous souhaitez appeler, par exemple : "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Changez _Options --> Paramètres_ et sélectionnez "**Entrée DLL**".
- Ensuite, **démarrez l'exécution**, le débogueur s'arrêtera à chaque entrée principale de dll, à un moment donné vous **vous arrêterez dans l'entrée de votre dll**. À partir de là, il suffit de rechercher les points où vous souhaitez mettre un point d'arrêt.

Remarquez que lorsque l'exécution est arrêtée pour une raison quelconque dans win64dbg, vous pouvez voir **dans quel code vous êtes** en regardant **en haut de la fenêtre win64dbg** :

![](<../../images/image (842).png>)

Ensuite, en regardant cela, vous pouvez voir quand l'exécution a été arrêtée dans la dll que vous souhaitez déboguer.

## Applications GUI / Jeux vidéo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où des valeurs importantes sont enregistrées dans la mémoire d'un jeu en cours d'exécution et les modifier. Plus d'infos dans :

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) est un outil de front-end/reverse engineering pour le débogueur GNU Project (GDB), axé sur les jeux. Cependant, il peut être utilisé pour tout ce qui est lié au reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) est un front-end web pour un certain nombre de décompilateurs. Ce service web vous permet de comparer la sortie de différents décompilateurs sur de petits exécutables.

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Débogage d'un shellcode avec blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) va **allouer** le **shellcode** dans un espace de mémoire, va **vous indiquer** l'**adresse mémoire** où le shellcode a été alloué et va **arrêter** l'exécution.\
Ensuite, vous devez **attacher un débogueur** (Ida ou x64dbg) au processus et mettre un **point d'arrêt à l'adresse mémoire indiquée** et **reprendre** l'exécution. De cette façon, vous déboguerez le shellcode.

La page des versions github contient des zips contenant les versions compilées : [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Vous pouvez trouver une version légèrement modifiée de Blobrunner dans le lien suivant. Pour le compiler, il suffit de **créer un projet C/C++ dans Visual Studio Code, de copier et coller le code et de le construire**.

{{#ref}}
blobrunner.md
{{#endref}}

### Débogage d'un shellcode avec jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) est très similaire à blobrunner. Il va **allouer** le **shellcode** dans un espace de mémoire et démarrer une **boucle éternelle**. Vous devez ensuite **attacher le débogueur** au processus, **jouer démarrer attendre 2-5 secondes et appuyer sur arrêter** et vous vous retrouverez dans la **boucle éternelle**. Sautez à l'instruction suivante de la boucle éternelle car ce sera un appel au shellcode, et enfin vous vous retrouverez à exécuter le shellcode.

![](<../../images/image (509).png>)

Vous pouvez télécharger une version compilée de [jmp2it sur la page des versions](https://github.com/adamkramer/jmp2it/releases/).

### Débogage de shellcode avec Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) est l'interface graphique de radare. En utilisant Cutter, vous pouvez émuler le shellcode et l'inspecter dynamiquement.

Notez que Cutter vous permet d'"Ouvrir un fichier" et "Ouvrir un shellcode". Dans mon cas, lorsque j'ai ouvert le shellcode en tant que fichier, il l'a décompilé correctement, mais quand je l'ai ouvert en tant que shellcode, il ne l'a pas fait :

![](<../../images/image (562).png>)

Pour commencer l'émulation à l'endroit que vous souhaitez, définissez un point d'arrêt là et apparemment Cutter commencera automatiquement l'émulation à partir de là :

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Vous pouvez voir la pile par exemple à l'intérieur d'un dump hexadécimal :

![](<../../images/image (186).png>)

### Déobfuscation de shellcode et récupération des fonctions exécutées

Vous devriez essayer [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Il vous dira des choses comme **quelles fonctions** le shellcode utilise et si le shellcode **se décode** lui-même en mémoire.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg dispose également d'un lanceur graphique où vous pouvez sélectionner les options que vous souhaitez et exécuter le shellcode.

![](<../../images/image (258).png>)

L'option **Create Dump** va dumper le shellcode final si des modifications sont apportées au shellcode dynamiquement en mémoire (utile pour télécharger le shellcode décodé). L'**offset de départ** peut être utile pour démarrer le shellcode à un offset spécifique. L'option **Debug Shell** est utile pour déboguer le shellcode en utilisant le terminal scDbg (cependant, je trouve que les options expliquées précédemment sont meilleures pour cela car vous pourrez utiliser Ida ou x64dbg).

### Désassemblage avec CyberChef

Téléchargez votre fichier shellcode en tant qu'entrée et utilisez la recette suivante pour le décompiler : [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Cet obfuscateur **modifie toutes les instructions pour `mov`** (ouais, vraiment cool). Il utilise également des interruptions pour changer les flux d'exécution. Pour plus d'informations sur son fonctionnement :

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Si vous avez de la chance, [demovfuscator](https://github.com/kirschju/demovfuscator) déobfusquera le binaire. Il a plusieurs dépendances.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Et [installez keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si vous jouez à un **CTF, cette solution pour trouver le drapeau** pourrait être très utile : [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Pour trouver le **point d'entrée**, recherchez les fonctions par `::main` comme dans :

![](<../../images/image (1080).png>)

Dans ce cas, le binaire s'appelait authenticator, donc il est assez évident que c'est la fonction principale intéressante.\
Ayant le **nom** des **fonctions** appelées, recherchez-les sur **Internet** pour en apprendre davantage sur leurs **entrées** et **sorties**.

## **Delphi**

Pour les binaires compilés Delphi, vous pouvez utiliser [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si vous devez inverser un binaire Delphi, je vous suggérerais d'utiliser le plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Il suffit d'appuyer sur **ATL+f7** (importer le plugin python dans IDA) et de sélectionner le plugin python.

Ce plugin exécutera le binaire et résoudra les noms de fonction dynamiquement au début du débogage. Après avoir démarré le débogage, appuyez à nouveau sur le bouton Démarrer (le vert ou f9) et un point d'arrêt sera atteint au début du vrai code.

C'est également très intéressant car si vous appuyez sur un bouton dans l'application graphique, le débogueur s'arrêtera dans la fonction exécutée par ce bouton.

## Golang

Si vous devez inverser un binaire Golang, je vous suggérerais d'utiliser le plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Il suffit d'appuyer sur **ATL+f7** (importer le plugin python dans IDA) et de sélectionner le plugin python.

Cela résoudra les noms des fonctions.

## Python compilé

Sur cette page, vous pouvez trouver comment obtenir le code python à partir d'un binaire python compilé ELF/EXE :

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Si vous obtenez le **binaire** d'un jeu GBA, vous pouvez utiliser différents outils pour **émuler** et **déboguer** :

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Téléchargez la version de débogage_) - Contient un débogueur avec interface
- [**mgba** ](https://mgba.io)- Contient un débogueur CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

Dans [**no$gba**](https://problemkaputt.de/gba.htm), dans _**Options --> Configuration de l'émulation --> Contrôles**_\*\* \*\* vous pouvez voir comment appuyer sur les **boutons** de la Game Boy Advance

![](<../../images/image (581).png>)

Lorsqu'ils sont pressés, chaque **touche a une valeur** pour l'identifier :
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
Donc, dans ce type de programme, la partie intéressante sera **comment le programme traite l'entrée de l'utilisateur**. À l'adresse **0x4000130**, vous trouverez la fonction couramment rencontrée : **KEYINPUT**.

![](<../../images/image (447).png>)

Dans l'image précédente, vous pouvez voir que la fonction est appelée depuis **FUN_080015a8** (adresses : _0x080015fa_ et _0x080017ac_).

Dans cette fonction, après quelques opérations d'initialisation (sans aucune importance) :
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
Il a trouvé ce code :
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
Le dernier if vérifie si **`uVar4`** est dans les **dernières clés** et n'est pas la clé actuelle, également appelée relâcher un bouton (la clé actuelle est stockée dans **`uVar1`**).
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
Dans le code précédent, vous pouvez voir que nous comparons **uVar1** (l'endroit où se trouve **la valeur du bouton pressé**) avec certaines valeurs :

- Tout d'abord, il est comparé avec la **valeur 4** (bouton **SELECT**) : Dans le défi, ce bouton efface l'écran.
- Ensuite, il est comparé avec la **valeur 8** (bouton **START**) : Dans le défi, cela vérifie si le code est valide pour obtenir le drapeau.
- Dans ce cas, la var **`DAT_030000d8`** est comparée à 0xf3 et si la valeur est la même, un certain code est exécuté.
- Dans tous les autres cas, un cont (`DAT_030000d4`) est vérifié. C'est un cont car il ajoute 1 juste après être entré dans le code.\
**Si** moins de 8, quelque chose qui implique **d'ajouter** des valeurs à **`DAT_030000d8`** est fait (en gros, cela ajoute les valeurs des touches pressées dans cette variable tant que le cont est inférieur à 8).

Donc, dans ce défi, en connaissant les valeurs des boutons, vous deviez **appuyer sur une combinaison d'une longueur inférieure à 8 dont l'addition résultante est 0xf3.**

**Référence pour ce tutoriel :** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Cours

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Déobfuscation binaire)

{{#include ../../banners/hacktricks-training.md}}
