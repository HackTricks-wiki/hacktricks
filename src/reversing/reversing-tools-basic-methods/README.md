# Outils de reversing et méthodes de base

{{#include ../../banners/hacktricks-training.md}}

## Outils de reversing basés sur ImGui

Logiciel :

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Décompilateur Wasm / compilateur Wat

En ligne :

- Utilisez [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) pour **décompiler** du wasm (binaire) vers du wat (texte lisible)
- Utilisez [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) pour **compiler** du wat vers du wasm
- Vous pouvez également essayer [web-wasmdec](https://wwwg.github.io/web-wasmdec/) pour la décompilation.

Logiciel :

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Décompilateur .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek est un décompilateur qui **décompile et examine plusieurs formats**, notamment les **bibliothèques** (.dll), les **fichiers de métadonnées Windows** (.winmd) et les **exécutables** (.exe). Une fois décompilée, une assembly peut être enregistrée en tant que projet Visual Studio (.csproj).

L'intérêt ici est que si le code source perdu d'une assembly legacy doit être restauré, cette action peut faire gagner du temps. De plus, dotPeek fournit une navigation pratique dans le code décompilé, ce qui en fait l'un des outils parfaits pour l'**analyse d'algorithmes Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grâce à un modèle complet d'add-ins et à une API qui étend l'outil pour répondre précisément à vos besoins, .NET Reflector fait gagner du temps et simplifie le développement. Examinons la multitude de services de reverse engineering fournis par cet outil :

- Donne un aperçu de la manière dont les données circulent dans une bibliothèque ou un composant
- Donne un aperçu de l'implémentation et de l'utilisation des langages et frameworks .NET
- Trouve les fonctionnalités non documentées et non exposées afin de tirer davantage parti des API et technologies utilisées.
- Trouve les dépendances et les différentes assemblies
- Localise précisément les erreurs dans votre code, vos composants tiers et vos bibliothèques.
- Permet de déboguer le code source de tout le code .NET avec lequel vous travaillez.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) : Vous pouvez l'utiliser sur n'importe quel OS (vous pouvez l'installer directement depuis VSCode, sans avoir besoin de télécharger le dépôt git. Cliquez sur **Extensions** et **recherchez ILSpy**).\
Si vous devez **décompiler**, **modifier** puis **recompiler**, vous pouvez utiliser [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou un fork maintenu activement, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic droit -> Modify Method** pour modifier quelque chose à l'intérieur d'une fonction).

### Journalisation DNSpy

Pour que **DNSpy enregistre certaines informations dans un fichier**, vous pouvez utiliser ce snippet :
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Pour déboguer du code à l’aide de DNSpy, vous devez :

Tout d’abord, modifier les **Assembly attributes** liés au **debugging** :

![DNSpy Logging - DNSpy Debugging : tout d’abord, modifier les Assembly attributes liés au debugging](<../../images/image (973).png>)

De :
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
Et cliquez sur **compile** :

![DNSpy Logging - DNSpy Debugging : cliquez sur compile](<../../images/image (314) (1).png>)

Ensuite, enregistrez le nouveau fichier via _**File >> Save module...**_ :

![DNSpy Logging - DNSpy Debugging : enregistrez ensuite le nouveau fichier via File Save module](<../../images/image (602).png>)

Ceci est nécessaire, car si vous ne le faites pas, plusieurs **optimisations** seront appliquées au code lors de l'**exécution**, et il pourrait arriver qu'un **point d'arrêt ne soit jamais atteint** pendant le debugging ou que certaines **variables n'existent pas**.

Ensuite, si votre application .NET est **exécutée** par **IIS**, vous pouvez la **redémarrer** avec :
```
iisreset /noforce
```
Ensuite, afin de commencer le debugging, vous devez fermer tous les fichiers ouverts et, dans l'onglet **Debug Tab**, sélectionner **Attach to Process...** :

![DNSpy Logging - DNSpy Debugging : Ensuite, afin de commencer le debugging, vous devez fermer tous les fichiers ouverts et, dans l'onglet Debug Tab, sélectionner Attach to Process](<../../images/image (318).png>)

Sélectionnez ensuite **w3wp.exe** pour vous attacher au **serveur IIS**, puis cliquez sur **attach** :

![DNSpy Logging - DNSpy Debugging : Sélectionnez ensuite w3wp.exe pour vous attacher au serveur IIS, puis cliquez sur attach](<../../images/image (113).png>)

Maintenant que nous debugguons le process, il est temps de l'arrêter et de charger tous les modules. Cliquez d'abord sur _Debug >> Break All_, puis cliquez sur _**Debug >> Windows >> Modules**_ :

![DNSpy Logging - DNSpy Debugging : Maintenant que nous debugguons le process, il est temps de l'arrêter et de charger tous les modules. Cliquez d'abord sur Debug Break All, puis cliquez sur Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging : Maintenant que nous debugguons le process, il est temps de l'arrêter et de charger tous les modules. Cliquez d'abord sur Debug Break All, puis cliquez sur Debug Windows Modules](<../../images/image (834).png>)

Cliquez sur n'importe quel module dans **Modules** et sélectionnez **Open All Modules** :

![DNSpy Logging - DNSpy Debugging : Cliquez sur n'importe quel module dans Modules et sélectionnez Open All Modules](<../../images/image (922).png>)

Faites un clic droit sur n'importe quel module dans **Assembly Explorer** et cliquez sur **Sort Assemblies** :

![DNSpy Logging - DNSpy Debugging : Faites un clic droit sur n'importe quel module dans Assembly Explorer, puis cliquez sur Sort Assemblies](<../../images/image (339).png>)

## Décompilateur Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging de DLLs

### Avec IDA

- **Chargez rundll32** (64bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- Sélectionnez le debugger **Windbg**
- Sélectionnez "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA : Sélectionnez " Suspend on library load/unload "](<../../images/image (868).png>)

- Configurez les **paramètres** de l'exécution en indiquant le **chemin vers la DLL** et la fonction que vous souhaitez appeler :

![Debugging DLLs - Using IDA : Configurez les paramètres de l'exécution en indiquant le chemin vers la DLL et la fonction que vous souhaitez appeler](<../../images/image (704).png>)

Ensuite, lorsque vous commencez le debugging, **l'exécution sera arrêtée lorsque chaque DLL sera chargée** ; lorsque rundll32 chargera votre DLL, l'exécution sera donc arrêtée.

Cette méthode s'arrête lors des événements de chargement des modules, mais atteindre le point d'entrée de la DLL chargée est moins direct qu'avec le workflow x64dbg ci-dessous.

### Avec x64dbg/x32dbg

- **Chargez rundll32** (64bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- **Modifiez la Command Line** ( _File --> Change Command Line_ ) et définissez le chemin de la dll ainsi que la fonction que vous souhaitez appeler, par exemple : "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Modifiez _Options --> Settings_ et sélectionnez "**DLL Entry**".
- Ensuite, **démarrez l'exécution** ; le debugger s'arrêtera sur chaque dll main et, à un moment donné, vous **vous arrêterez sur l'Entry de votre DLL**. À partir de là, recherchez simplement les endroits où vous souhaitez placer un breakpoint.

Notez que lorsque l'exécution est interrompue pour quelque raison que ce soit dans win64dbg, vous pouvez voir **dans quel code vous vous trouvez** en regardant **en haut de la fenêtre win64dbg** :

![Using IDA - Using x64dbg/x32dbg : Notez que lorsque l'exécution est interrompue pour quelque raison que ce soit dans win64dbg, vous pouvez voir dans quel code vous vous trouvez en regardant en haut de la fenêtre win64dbg](<../../images/image (842).png>)

Cet indicateur confirme que l'exécution s'est arrêtée à l'intérieur de la DLL que vous souhaitez debugger.

## Applications GUI / Jeux vidéo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où sont enregistrées les valeurs importantes dans la mémoire d'un jeu en cours d'exécution et les modifier. Plus d'informations dans :

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) est un front-end/outil de reverse engineering pour le GNU Project Debugger (GDB), spécialisé dans les jeux. Cependant, il peut être utilisé pour toute activité liée au reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) est un front-end web pour plusieurs décompilateurs. Ce service web vous permet de comparer la sortie de différents décompilateurs sur de petits exécutables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging d'un shellcode avec blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alloue le **shellcode**, affiche son **adresse mémoire** et met l'exécution en pause.\
Attachez un debugger tel qu'IDA ou x64dbg, placez un breakpoint à l'adresse affichée, puis reprenez l'exécution pour debugger le shellcode.

La page GitHub des releases contient des zips comprenant les releases compilées : [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Vous trouverez une version légèrement modifiée de Blobrunner dans le lien suivant. Pour la compiler, il suffit de **créer un projet C/C++ dans Visual Studio Code, de copier-coller le code et de le compiler**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging d'un shellcode avec jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) est similaire à BlobRunner. Il alloue le shellcode et entre dans une boucle infinie. Attachez le debugger, reprenez l'exécution pendant **2 à 5 secondes**, mettez-la en pause à l'intérieur de cette boucle, puis avancez jusqu'à l'appel suivant qui transfère l'exécution au shellcode alloué.

![Debugger en pause dans la boucle infinie de jmp2it, immédiatement avant l'appel vers le shellcode alloué](<../../images/image (509).png>)

Vous pouvez télécharger une version compilée de [jmp2it sur la page des releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging d'un shellcode avec Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) est l'interface graphique de radare. Avec Cutter, vous pouvez émuler le shellcode et l'inspecter dynamiquement.

Notez que Cutter permet d'« Open File » et d'« Open Shellcode ». Dans mon cas, lorsque j'ai ouvert le shellcode en tant que fichier, il l'a correctement décompilé, mais lorsque je l'ai ouvert en tant que shellcode, ce ne fut pas le cas :

![Cutter affichant des résultats d'analyse différents lors de l'ouverture des mêmes octets en tant que fichier ou shellcode](<../../images/image (562).png>)

Pour commencer l'émulation à l'endroit souhaité, définissez-y un bp ; apparemment, Cutter commencera automatiquement l'émulation à partir de cet endroit :

![Définition d'un breakpoint à l'entrée souhaitée du shellcode avant de démarrer l'émulation de Cutter](<../../images/image (589).png>)

![Émulateur de Cutter en pause au breakpoint sélectionné du shellcode](<../../images/image (387).png>)

Vous pouvez par exemple voir la stack dans un dump hexadécimal :

![Affichage de la stack du shellcode émulé dans le dump hexadécimal de Cutter](<../../images/image (186).png>)

### Déobfuscation d'un shellcode et récupération des fonctions exécutées

Vous devriez essayer [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Il vous indiquera notamment **quelles fonctions** le shellcode utilise et si le shellcode se **décode** lui-même en mémoire.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg dispose également d’un launcher graphique permettant de sélectionner les options souhaitées et d’exécuter le shellcode

![Launcher graphique de scDbg permettant de sélectionner les options d’émulation et de traçage du shellcode](<../../images/image (258).png>)

L’option **Create Dump** sauvegarde le shellcode final si une modification est effectuée dynamiquement en mémoire (utile pour télécharger le shellcode décodé). Le **start offset** peut être utile pour démarrer le shellcode à un offset spécifique. L’option **Debug Shell** permet de debugger le shellcode à l’aide du terminal scDbg (je trouve toutefois que les options expliquées précédemment sont plus adaptées à cette tâche, car elles permettent d’utiliser Ida ou x64dbg).

### Désassemblage avec CyberChef

Téléversez votre fichier de shellcode comme entrée et utilisez la recette suivante pour le désassembler : [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

L’obfuscation **Mixed Boolean-Arithmetic (MBA)** dissimule des expressions simples telles que `x + y` derrière des formules qui combinent des opérations arithmétiques (`+`, `-`, `*`) et des opérateurs bit à bit (`&`, `|`, `^`, `~`, décalages). L’élément important est que ces identités ne sont généralement correctes que dans le cadre d’une **arithmétique modulaire à largeur fixe** : les retenues et les dépassements de capacité sont donc importants :
```c
(x ^ y) + 2 * (x & y) == x + y
```
Si vous simplifiez ce type d’expression avec des outils algébriques génériques, vous pouvez facilement obtenir un résultat incorrect, car la sémantique de la largeur en bits a été ignorée.<sup>[[1]](#references)</sup>

### Workflow pratique

1. **Conservez la largeur en bits d’origine** du code/IR/decompiler output relevé (`8/16/32/64` bits).
2. **Classez l’expression** avant d’essayer de la simplifier :
- **Linéaire** : sommes pondérées d’atomes bitwise
- **Semilinéaire** : expression linéaire plus des masques constants tels que `x & 0xFF`
- **Polynomiale** : des produits apparaissent
- **Mixte** : produits et logique bitwise sont imbriqués, souvent avec des sous-expressions répétées
3. **Vérifiez chaque réécriture candidate** avec des tests aléatoires ou une preuve SMT. Si l’équivalence ne peut pas être prouvée, conservez l’expression d’origine au lieu de deviner.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) est un simplificateur MBA pratique pour l’analyse de malware et le reversing de binaires protégés. Il classe l’expression et l’achemine vers des pipelines spécialisés au lieu d’appliquer une seule passe de réécriture générique à tout.<sup>[[2]](#references)</sup>

Utilisation rapide :
```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```
Cas utiles :

- **Linear MBA** : CoBRA évalue l’expression sur des entrées booléennes, dérive une signature et lance en parallèle plusieurs méthodes de récupération, telles que le pattern matching, la conversion en ANF et l’interpolation des coefficients.
- **Semilinear MBA** : les atomes masqués par des constantes sont reconstruits avec une reconstruction partitionnée par bits, afin que les régions masquées restent correctes.
- **Polynomial/Mixed MBA** : les produits sont décomposés en cores, et les sous-expressions répétées peuvent être déplacées dans des temporaires avant de simplifier la relation externe.

Exemple d’identité mixte qu’il vaut souvent la peine d’essayer de récupérer :
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Cela peut se résumer à :
```c
x * y
```
### Notes de reversing

- Privilégiez l'exécution de CoBRA sur des **expressions IR liftées** ou sur la sortie du décompilateur après avoir isolé le calcul exact.
- Utilisez explicitement `--bitwidth` lorsque l'expression provient d'opérations arithmétiques masquées ou de registres étroits.
- Si vous avez besoin d'une étape de preuve plus solide, consultez les notes locales sur Z3 ici :

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA est également fourni sous forme de **plugin de pass LLVM** (`libCobraPass.so`), ce qui est utile lorsque vous souhaitez normaliser un LLVM IR fortement chargé en MBA avant les passes d'analyse ultérieures.
- Les résidus mixtes sensibles aux retenues et non pris en charge doivent être considérés comme un signal indiquant qu'il faut conserver l'expression d'origine et raisonner manuellement sur le chemin de propagation de la retenue.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Cet obfuscateur remplace les opérations du programme par des séquences d'instructions basées sur `mov` et utilise la gestion des signaux/exceptions pour modifier le flux de contrôle. Pour plus de détails :

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Pour les binaires pris en charge, [demovfuscator](https://github.com/kirschju/demovfuscator) peut désobfusquer le résultat. Il possède plusieurs dépendances.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Et [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si vous participez à un **CTF, cette méthode de contournement pour trouver le flag** pourrait être très utile : [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Pour trouver le **point d’entrée**, recherchez les fonctions avec `::main`, comme dans :

![Recherche d’un point d’entrée Rust dans Ghidra en recherchant les noms de fonctions contenant un double deux-points suivi de main](<../../images/image (1080).png>)

Dans ce cas, le binaire s’appelait authenticator, il est donc assez évident qu’il s’agit de la fonction main intéressante.\
En disposant du **nom** des **fonctions** appelées, recherchez-les sur **Internet** pour en apprendre davantage sur leurs **entrées** et leurs **sorties**.

### Récupération des chaînes Rust depuis un firmware ELF

Dans les binaires **ELF Rust**, de nombreuses chaînes statiques ne sont pas référencées par des pointeurs terminés par un NUL comme en C. Une disposition courante de `rustc` est un **tuple pointeur/longueur** dans **`.data.rel.ro`** pointant vers le véritable bloc de chaînes stocké dans **`.rodata`** :
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Cela signifie que `strings` ou l’analyse par défaut de Ghidra peut fusionner des chaînes adjacentes ou manquer complètement les références croisées.<sup>[[3]](#references)</sup>

Workflow rapide :
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Obtenir l’adresse virtuelle et la taille de **`.rodata`**.
2. Énumérer **`.data.rel.ro`** un mot à la fois.
3. Considérer toute valeur comprise dans la plage d’adresses de `.rodata` comme un pointeur potentiel vers une chaîne.
4. Considérer le mot suivant comme la longueur potentielle.
5. Appliquer des filtres de cohérence (par exemple, conserver les longueurs comprises entre **4** et **100** octets).
6. Lire exactement `length` octets depuis `.rodata` au lieu de parcourir les données jusqu’à `0x00`.

Logique minimale de l’extracteur :
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Ceci est particulièrement utile pour le reversing de firmware, car les chaînes Rust récupérées révèlent souvent des **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers et auth-related logic**.

Si Ghidra ne détecte pas ces chaînes, exécutez un script/plugin personnalisé qui applique la même heuristique et crée des données de type chaîne aux offsets `.rodata` référencés. Les outils `rust-strings` et `RustStrings.py` publiés par Pen Test Partners constituent de bonnes références pour adapter cette approche à d'autres **word sizes, endianness et section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Pour les binaires compilés Delphi, vous pouvez utiliser [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si vous devez effectuer le reversing d'un binaire Delphi, je vous conseille d'utiliser le plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Appuyez sur **Alt+F7** dans IDA pour charger un plugin Python, puis sélectionnez le fichier du plugin.

Ce plugin exécutera le binaire et résoudra dynamiquement les noms des fonctions au début du debugging. Après avoir démarré le debugging, appuyez à nouveau sur le bouton Start (le bouton vert ou f9) et un breakpoint sera atteint au début du code réel.

Si vous appuyez sur un bouton dans l'application graphique, le debugger peut s'arrêter dans la fonction appelée par ce bouton.

## Golang

Si vous devez effectuer le reversing d'un binaire Golang, je vous conseille d'utiliser le plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Appuyez sur **Alt+F7** dans IDA pour charger un plugin Python, puis sélectionnez le fichier du plugin.

Cela résoudra les noms des fonctions.

## Python compilé

Sur cette page, vous trouverez comment récupérer le code Python depuis un binaire ELF/EXE Python compilé :


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Si vous obtenez le **binary** d'un jeu GBA, vous pouvez utiliser différents outils pour l'**emulate** et le **debugger** :

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Contient un debugger avec interface
- [**mgba** ](https://mgba.io)- Contient un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

Dans [**no$gba**](https://problemkaputt.de/gba.htm), dans _**Options --> Emulation Setup --> Controls**_** **, vous pouvez voir comment appuyer sur les **buttons** de la Game Boy Advance

![configuration des contrôles de no$gba montrant les correspondances des boutons de la Game Boy Advance](<../../images/image (581).png>)

Lorsqu'elle est pressée, chaque **key has a value** permettant de l'identifier :
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
Ainsi, dans ce type de programme, la partie intéressante sera **la manière dont le programme traite les entrées utilisateur**. À l’adresse **0x4000130**, vous trouverez la fonction couramment rencontrée : **KEYINPUT**.

![Vue de Ghidra d’un binaire GBA faisant référence à KEYINPUT à l’adresse 0x4000130](<../../images/image (447).png>)

Dans l’image précédente, vous pouvez voir que la fonction est appelée depuis **FUN_080015a8** (adresses : _0x080015fa_ et _0x080017ac_).

Dans cette fonction, après quelques opérations d’init (sans importance) :
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
Ce code a été trouvé :
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
Le dernier **`if`** vérifie que **`uVar4`** se trouve dans les dernières **Keys** et qu’il ne s’agit pas de la touche actuelle, ce qui correspond également au relâchement d’un bouton (la touche actuelle est stockée dans **`uVar1`**).
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
Dans le code précédent, vous pouvez voir que nous comparons **uVar1** (l’emplacement où se trouve la **valeur du bouton pressé**) avec certaines valeurs :

- Tout d’abord, il est comparé à la **valeur 4** (bouton **SELECT**) : dans le challenge, ce bouton efface l’écran.
- Ensuite, la valeur est comparée à **8** (bouton **START**) ; dans ce challenge, ce chemin vérifie si le code saisi est valide.
- Dans ce cas, la var **`DAT_030000d8`** est comparée à 0xf3 et, si la valeur est identique, du code est exécuté.
- Dans tous les autres cas, un compteur (`DAT_030000d4`) est vérifié et incrémenté.\
Tant que le compteur est inférieur à 8, les valeurs des touches pressées sont accumulées dans `DAT_030000d8`.

Ainsi, dans ce challenge, connaissant les valeurs des boutons, vous deviez **appuyer sur une combinaison de longueur inférieure à 8 dont la somme résultante est égale à 0xf3.**

**Référence pour ce tutoriel :** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cours

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Simplification de l’obfuscation MBA avec CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Dépôt CoBRA de Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Décodage des chaînes Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutoriel de reversing GBA (archivé)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
