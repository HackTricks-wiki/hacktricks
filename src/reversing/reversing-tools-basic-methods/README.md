# Outils de Reversing et méthodes de base

{{#include ../../banners/hacktricks-training.md}}

## Outils de Reversing basés sur ImGui

Software :

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Décompilateur Wasm / compilateur Wat

En ligne :

- Utilisez [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) pour **décompiler** du wasm (binaire) vers du wat (texte clair)
- Utilisez [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) pour **compiler** du wat vers du wasm
- vous pouvez également essayer d'utiliser [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) pour décompiler

Software :

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Décompilateur .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek est un décompilateur qui **décompile et examine plusieurs formats**, notamment les **bibliothèques** (.dll), les **fichiers de métadonnées Windows** (.winmd) et les **exécutables** (.exe). Une fois décompilée, une assembly peut être enregistrée en tant que projet Visual Studio (.csproj).

L'intérêt ici est que si le code source perdu d'une assembly legacy doit être restauré, cette action peut faire gagner du temps. De plus, dotPeek fournit une navigation pratique dans le code décompilé, ce qui en fait l'un des outils parfaits pour l'**analyse d'algorithmes Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Avec un modèle d'add-in complet et une API qui étend l'outil pour répondre précisément à vos besoins, .NET reflector permet de gagner du temps et simplifie le développement. Examinons la multitude de services de reverse engineering fournis par cet outil :

- Fournit une vue d'ensemble de la manière dont les données circulent à travers une bibliothèque ou un composant
- Fournit des informations sur l'implémentation et l'utilisation des langages et frameworks .NET
- Trouve les fonctionnalités non documentées et non exposées afin de tirer davantage parti des APIs et technologies utilisées.
- Trouve les dépendances et les différentes assemblies
- Identifie l'emplacement exact des erreurs dans votre code, les composants tiers et les bibliothèques.
- Effectue le debugging dans le code source de tout le code .NET avec lequel vous travaillez.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy pour Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) : Vous pouvez l'utiliser sur n'importe quel OS (vous pouvez l'installer directement depuis VSCode, sans avoir besoin de télécharger le git. Cliquez sur **Extensions** et **recherchez ILSpy**).\
Si vous devez **décompiler**, **modifier** et **recompiler** à nouveau, vous pouvez utiliser [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou un fork activement maintenu de celui-ci, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic droit -> Modify Method** pour modifier quelque chose à l'intérieur d'une fonction).

### Journalisation DNSpy

Afin de faire en sorte que **DNSpy journalise certaines informations dans un fichier**, vous pouvez utiliser ce snippet :
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Débogage avec DNSpy

Pour déboguer du code à l’aide de DNSpy, vous devez :

Tout d’abord, modifier les **attributs de l’Assembly** liés au **débogage** :

![DNSpy Logging - Débogage avec DNSpy : tout d’abord, modifier les attributs de l’Assembly liés au débogage](<../../images/image (973).png>)

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

C'est nécessaire, car si vous ne le faites pas, plusieurs **optimisations** seront appliquées au code à l'**runtime**, et il est possible que, lors du debugging, un **break-point** ne soit jamais atteint ou que certaines **variables** n'existent pas.

Ensuite, si votre application .NET est **exécutée** par **IIS**, vous pouvez la **redémarrer** avec :
```
iisreset /noforce
```
Ensuite, afin de commencer le debugging, vous devez fermer tous les fichiers ouverts et, dans l’onglet **Debug**, sélectionner **Attach to Process...** :

![DNSpy Logging - DNSpy Debugging : Ensuite, afin de commencer le debugging, vous devez fermer tous les fichiers ouverts et, dans l’onglet Debug, sélectionner Attach to Process](<../../images/image (318).png>)

Sélectionnez ensuite **w3wp.exe** pour l’attacher au **IIS server**, puis cliquez sur **attach** :

![DNSpy Logging - DNSpy Debugging : Sélectionnez ensuite w3wp.exe pour l’attacher au IIS server, puis cliquez sur attach](<../../images/image (113).png>)

Maintenant que nous faisons le debugging du process, il est temps de l’arrêter et de charger tous les modules. Cliquez d’abord sur _Debug >> Break All_, puis cliquez sur _**Debug >> Windows >> Modules**_ :

![DNSpy Logging - DNSpy Debugging : Maintenant que nous faisons le debugging du process, il est temps de l’arrêter et de charger tous les modules. Cliquez d’abord sur Debug Break All, puis cliquez sur Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging : Maintenant que nous faisons le debugging du process, il est temps de l’arrêter et de charger tous les modules. Cliquez d’abord sur Debug Break All, puis cliquez sur Debug Windows Modules](<../../images/image (834).png>)

Cliquez sur n’importe quel module dans **Modules** et sélectionnez **Open All Modules** :

![DNSpy Logging - DNSpy Debugging : Cliquez sur n’importe quel module dans Modules et sélectionnez Open All Modules](<../../images/image (922).png>)

Faites un clic droit sur n’importe quel module dans **Assembly Explorer** et cliquez sur **Sort Assemblies** :

![DNSpy Logging - DNSpy Debugging : Faites un clic droit sur n’importe quel module dans Assembly Explorer et cliquez sur Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- Sélectionnez le debugger **Windbg**
- Sélectionnez "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA : Sélectionnez « Suspend on library load/unload »](<../../images/image (868).png>)

- Configurez les **parameters** de l’exécution en indiquant le **path to the DLL** et la fonction que vous souhaitez appeler :

![Debugging DLLs - Using IDA : Configurez les parameters de l’exécution en indiquant le path to the DLL et la fonction que vous souhaitez appeler](<../../images/image (704).png>)

Ensuite, lorsque vous démarrez le debugging, **l’exécution sera arrêtée au chargement de chaque DLL** ; lorsque rundll32 chargera votre DLL, l’exécution sera donc arrêtée.

Mais comment accéder au code de la DLL qui a été chargée ? Avec cette méthode, je ne sais pas comment faire.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) et définissez le path de la dll ainsi que la fonction que vous souhaitez appeler, par exemple : "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Modifiez _Options --> Settings_ et sélectionnez "**DLL Entry**".
- Ensuite, **start the execution** ; le debugger s’arrêtera sur chaque dll main. À un moment donné, vous serez **stoppé dans le dll Entry de votre dll**. À partir de là, recherchez simplement les points où vous souhaitez placer un breakpoint.

Notez que lorsque l’exécution est arrêtée pour quelque raison que ce soit dans win64dbg, vous pouvez voir **dans quel code vous vous trouvez** en regardant **en haut de la fenêtre win64dbg** :

![Using IDA - Using x64dbg/x32dbg : Notez que lorsque l’exécution est arrêtée pour quelque raison que ce soit dans win64dbg, vous pouvez voir dans quel code vous vous trouvez en regardant en haut de la fenêtre win64dbg](<../../images/image (842).png>)

Ainsi, vous pouvez voir quand l’exécution a été arrêtée dans la dll que vous souhaitez debugger.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où sont sauvegardées les valeurs importantes dans la mémoire d’un jeu en cours d’exécution et les modifier. Plus d’informations dans :

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) est un front-end/reverse engineering tool pour le GNU Project Debugger (GDB), orienté vers les jeux. Cependant, il peut être utilisé pour toute tâche liée au reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) est un front-end web pour plusieurs decompilers. Ce service web vous permet de comparer la sortie de différents decompilers sur de petits exécutables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) va **allocate** le **shellcode** dans un espace mémoire, vous **indiquera** l’**memory address** à laquelle le shellcode a été alloué et **arrêtera** l’exécution.\
Vous devez ensuite **attach a debugger** (Ida ou x64dbg) au process, placer un **breakpoint à l’adresse mémoire indiquée**, puis **resume** l’exécution. Vous pourrez ainsi faire le debugging du shellcode.

La page github des releases contient des fichiers zip avec les releases compilées : [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Vous trouverez une version légèrement modifiée de Blobrunner sur le lien suivant. Pour la compiler, il suffit de **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) est très similaire à blobrunner. Il va **allocate** le **shellcode** dans un espace mémoire et démarrer une **boucle infinie**. Vous devez ensuite **attach the debugger** au process, **play start wait 2-5 secs and press stop**, et vous vous retrouverez dans la **boucle infinie**. Passez à l’instruction suivante de la boucle infinie, car il s’agira d’un appel au shellcode ; vous finirez par exécuter le shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it : jmp2it est très similaire à blobrunner. Il va allocate le shellcode dans un espace mémoire et démarrer une...](<../../images/image (509).png>)

Vous pouvez télécharger une version compilée de [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) est la GUI de radare. Avec Cutter, vous pouvez émuler le shellcode et l’inspecter dynamiquement.

Notez que Cutter permet d’« Open File » et d’« Open Shellcode ». Dans mon cas, lorsque j’ai ouvert le shellcode en tant que fichier, il a été correctement décompilé, mais lorsque je l’ai ouvert en tant que shellcode, ce n’était pas le cas :

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter : Notez que Cutter permet d’« Open File » et d’« Open Shellcode ». Dans mon cas, lorsque j’ai ouvert le shellcode en tant que fichier, il...](<../../images/image (562).png>)

Pour démarrer l’émulation à l’endroit souhaité, définissez un bp à cet endroit ; apparemment, Cutter démarrera automatiquement l’émulation depuis celui-ci :

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter : Pour démarrer l’émulation à l’endroit souhaité, définissez un bp à cet endroit ; apparemment, Cutter démarrera automatiquement...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter : Pour démarrer l’émulation à l’endroit souhaité, définissez un bp à cet endroit ; apparemment, Cutter démarrera automatiquement...](<../../images/image (387).png>)

Vous pouvez par exemple voir la stack dans un hex dump :

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter : Vous pouvez par exemple voir la stack dans un hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Vous devriez essayer [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Il vous indiquera notamment **quelles fonctions** le shellcode utilise et si le shellcode se **decode** lui-même en mémoire.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg dispose également d’un lanceur graphique permettant de sélectionner les options souhaitées et d’exécuter le shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg dispose également d’un lanceur graphique permettant de sélectionner les options souhaitées et...](<../../images/image (258).png>)

L’option **Create Dump** extrait le shellcode final si une modification est effectuée dynamiquement dans le shellcode en mémoire (utile pour télécharger le shellcode décodé). Le **start offset** peut être utile pour démarrer le shellcode à un offset spécifique. L’option **Debug Shell** permet de déboguer le shellcode à l’aide du terminal scDbg (je trouve toutefois que l’une des options expliquées précédemment est préférable pour cela, car elle permet d’utiliser Ida ou x64dbg).

### Désassembler avec CyberChef

Téléversez votre fichier de shellcode comme entrée et utilisez la recette suivante pour le décompiler : [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Déobfuscation de l’obfuscation MBA

L’obfuscation **Mixed Boolean-Arithmetic (MBA)** masque des expressions simples telles que `x + y` derrière des formules qui combinent des opérations arithmétiques (`+`, `-`, `*`) et des opérateurs bit à bit (`&`, `|`, `^`, `~`, shifts). L’élément important est que ces identités ne sont généralement correctes que dans le cadre d’une **arithmétique modulaire à largeur fixe**, de sorte que les retenues et les débordements sont importants :
```c
(x ^ y) + 2 * (x & y) == x + y
```
Si vous simplifiez ce type d’expression avec des outils algébriques génériques, vous pouvez facilement obtenir un résultat incorrect, car la sémantique de la largeur en bits a été ignorée.<sup>[[1]](#references)</sup>

### Workflow pratique

1. **Conservez la largeur en bits d’origine** provenant du code/IR/de la sortie du décompilateur (`8/16/32/64` bits).
2. **Classez l’expression** avant d’essayer de la simplifier :
- **Linéaire** : sommes pondérées d’atomes bitwise
- **Semilinéaire** : expression linéaire plus des masques constants tels que `x & 0xFF`
- **Polynomiale** : des produits sont présents
- **Mixte** : les produits et la logique bitwise sont imbriqués, souvent avec des sous-expressions répétées
3. **Vérifiez chaque réécriture candidate** avec des tests aléatoires ou une preuve SMT. Si l’équivalence ne peut pas être prouvée, conservez l’expression d’origine au lieu de deviner.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) est un simplificateur MBA pratique destiné à l’analyse de malware et au reversing de binaires protégés. Il classe l’expression et la fait passer par des pipelines spécialisés au lieu d’appliquer une passe de réécriture générique à tout le contenu.<sup>[[2]](#references)</sup>

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

- **Linear MBA** : CoBRA évalue l’expression sur des entrées booléennes, en déduit une signature et lance en parallèle plusieurs méthodes de récupération, telles que la reconnaissance de motifs, la conversion en ANF et l’interpolation des coefficients.
- **Semilinear MBA** : les atomes masqués par des constantes sont reconstruits avec une reconstruction partitionnée par bits afin de préserver la correction des régions masquées.
- **Polynomial/Mixed MBA** : les produits sont décomposés en composants fondamentaux et les sous-expressions répétées peuvent être extraites dans des variables temporaires avant de simplifier la relation externe.

Exemple d’identité mixte qu’il peut être utile de tenter de récupérer :
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Cela peut se réduire à :
```c
x * y
```
### Notes de reversing

- Préférez exécuter CoBRA sur des **expressions IR levées** ou sur la sortie du décompilateur après avoir isolé le calcul exact.
- Utilisez explicitement `--bitwidth` lorsque l’expression provient d’une arithmétique masquée ou de registres étroits.
- Si vous avez besoin d’une étape de preuve plus robuste, consultez les notes locales sur Z3 ici :


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA est également fourni sous forme de **plugin de passe LLVM** (`libCobraPass.so`), ce qui est utile lorsque vous souhaitez normaliser un LLVM IR riche en MBA avant les passes d’analyse ultérieures.
- Les résidus mixtes non pris en charge et sensibles aux retenues doivent être considérés comme un signal indiquant qu’il faut conserver l’expression originale et raisonner manuellement sur le chemin de retenue.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Cet obfuscateur **modifie toutes les instructions `mov`** (oui, vraiment cool). Il utilise également des interruptions pour modifier les flux d’exécution. Pour plus d’informations sur son fonctionnement :

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Si vous avez de la chance, [demovfuscator](https://github.com/kirschju/demovfuscator) désobfusquera le binaire. Il possède plusieurs dépendances
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Et [installez keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si vous participez à un **CTF, ce contournement pour trouver le flag** peut être très utile : [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Pour trouver le **point d'entrée**, recherchez les fonctions avec `::main`, comme dans :

![Movfuscator - Rust : Pour trouver le point d'entrée, recherchez les fonctions avec ::main, comme dans](<../../images/image (1080).png>)

Dans ce cas, le binaire s'appelait authenticator, il est donc assez évident qu'il s'agit de la fonction main intéressante.\
À partir du **nom** des **fonctions** appelées, recherchez-les sur **Internet** afin d'en apprendre davantage sur leurs **entrées** et leurs **sorties**.

### Récupération des chaînes Rust depuis un firmware ELF

Dans les binaires **Rust ELF**, de nombreuses chaînes statiques ne sont pas référencées par des pointeurs terminés par NUL de style C. Une disposition courante de `rustc` est un tuple pointeur/longueur à l'intérieur de **`.data.rel.ro`**, pointant vers le véritable bloc de chaînes stocké dans **`.rodata`** :
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Cela signifie que `strings` ou l’analyse Ghidra par défaut peuvent fusionner des chaînes adjacentes ou manquer complètement les références croisées.<sup>[[3]](#references)</sup>

Workflow rapide :
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Obtenir l’adresse virtuelle et la taille de **`.rodata`**.
2. Énumérer **`.data.rel.ro`** un mot à la fois.
3. Traiter toute valeur située dans la plage d’adresses de `.rodata` comme un pointeur de chaîne candidat.
4. Traiter le mot suivant comme la longueur candidate.
5. Appliquer des filtres de cohérence (par exemple, conserver les longueurs comprises entre **4** et **100** octets).
6. Lire exactement `length` octets depuis `.rodata` au lieu de chercher jusqu’à `0x00`.

Logique minimale de l’extracteur :
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Ceci est particulièrement utile lors du reverse engineering de firmware, car les chaînes Rust récupérées révèlent souvent des **routes HTTP, des noms RPC, des messages de journalisation, des assertions, des noms de fichiers, des clés de configuration, des gestionnaires de commandes et de la logique liée à l’authentification**.

Si Ghidra ne détecte pas ces chaînes, exécutez un script/plugin personnalisé qui applique la même heuristique et crée des données de type chaîne aux offsets `.rodata` référencés. Les outils `rust-strings` et `RustStrings.py` publiés par Pen Test Partners constituent de bonnes références pour adapter cette idée à d’autres **tailles de mots, endianness et dispositions de sections**.<sup>[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Pour les binaires compilés en Delphi, vous pouvez utiliser [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si vous devez effectuer le reverse engineering d’un binaire Delphi, je vous conseille d’utiliser le plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Appuyez simplement sur **ATL+f7** (importer un plugin Python dans IDA) et sélectionnez le plugin Python.

Ce plugin exécutera le binaire et résoudra dynamiquement les noms des fonctions au début du debugging. Après avoir démarré le debugging, appuyez à nouveau sur le bouton Start (le bouton vert ou f9) et un breakpoint sera déclenché au début du véritable code.

C’est également très intéressant, car si vous appuyez sur un bouton de l’application graphique, le debugger s’arrêtera dans la fonction exécutée par ce bouton.

## Golang

Si vous devez effectuer le reverse engineering d’un binaire Golang, je vous conseille d’utiliser le plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Appuyez simplement sur **ATL+f7** (importer un plugin Python dans IDA) et sélectionnez le plugin Python.

Cela résoudra les noms des fonctions.

## Python compilé

Sur cette page, vous trouverez comment récupérer le code Python à partir d’un binaire ELF/EXE compilé en Python :


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Si vous obtenez le **binaire** d’un jeu GBA, vous pouvez utiliser différents outils pour l’**émuler** et le **debugger** :

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Téléchargez la version de debugging_) - Contient un debugger avec interface
- [**mgba** ](https://mgba.io)- Contient un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

Dans [**no$gba**](https://problemkaputt.de/gba.htm), dans _**Options --> Emulation Setup --> Controls**_** **, vous pouvez voir comment appuyer sur les **boutons** de la Game Boy Advance

![configuration des contrôles de no$gba montrant les affectations des boutons de la Game Boy Advance](<../../images/image (581).png>)

Lorsqu’une touche est enfoncée, chaque **touche possède une valeur** permettant de l’identifier :
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
Ainsi, dans ce type de programme, la partie intéressante sera **la manière dont le programme traite l'entrée utilisateur**. À l'adresse **0x4000130**, vous trouverez la fonction couramment rencontrée : **KEYINPUT**.

![Vue de Ghidra d'un binaire GBA référençant KEYINPUT à l'adresse 0x4000130](<../../images/image (447).png>)

Dans l'image précédente, vous pouvez voir que la fonction est appelée depuis **FUN_080015a8** (adresses : _0x080015fa_ et _0x080017ac_).

Dans cette fonction, après quelques opérations d'initialisation (sans importance) :
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
Le dernier `if` vérifie que **`uVar4`** se trouve dans les **dernières touches** et qu'il ne s'agit pas de la touche actuelle, ce qui revient également à relâcher un bouton (la touche actuelle est stockée dans **`uVar1`**).
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
Dans le code précédent, vous pouvez voir que nous comparons **uVar1** (l'emplacement où se trouve la **value of the pressed button**) avec certaines valeurs :

- Tout d'abord, elle est comparée à la **value 4** (bouton **SELECT**) : dans le challenge, ce bouton efface l'écran
- Ensuite, elle est comparée à la **value 8** (bouton **START**) : dans le challenge, cela vérifie si le code est valide pour obtenir le flag.
- Dans ce cas, la var **`DAT_030000d8`** est comparée à 0xf3 et, si la value est identique, du code est exécuté.
- Dans les autres cas, un compteur (`DAT_030000d4`) est vérifié. C'est un compteur, car il est incrémenté de 1 juste après l'entrée dans le code.\
**S**'il est inférieur à 8, une opération impliquant l'**addition** de values à **`DAT_030000d8`** est effectuée (en résumé, les values des touches pressées sont additionnées dans cette variable tant que le compteur est inférieur à 8).

Ainsi, dans ce challenge, en connaissant les values des boutons, vous deviez **presser une combinaison d'une longueur inférieure à 8 dont la somme obtenue est égale à 0xf3.**

**Référence pour ce tutorial :** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cours

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## Références

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
