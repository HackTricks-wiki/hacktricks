# Outils de reversing et méthodes de base

{{#include ../../banners/hacktricks-training.md}}

## Outils de reversing basés sur ImGui

Logiciel :

- ReverseKit : [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Débogage du kernel Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Décompilateur Wasm / compilateur Wat

En ligne :

- Utilisez [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) pour **décompiler** du wasm (binaire) vers du wat (texte lisible)
- Utilisez [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) pour **compiler** du wat vers du wasm
- Vous pouvez également essayer [web-wasmdec](https://wwwg.github.io/web-wasmdec/) pour la décompilation.

Logiciels :

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode mis en cache de Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Décompilateur .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek est un décompilateur qui **décompile et examine plusieurs formats**, notamment les **bibliothèques** (.dll), les **fichiers de métadonnées Windows** (.winmd) et les **exécutables** (.exe). Une fois décompilé, un assembly peut être enregistré en tant que projet Visual Studio (.csproj).

L’intérêt de cet outil est qu’il peut faire gagner du temps lorsqu’il faut restaurer un code source perdu à partir d’un assembly ancien. De plus, dotPeek permet de naviguer facilement dans le code décompilé, ce qui en fait l’un des outils parfaits pour l’**analyse d’algorithmes Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grâce à son modèle de modules complémentaires complet et à une API qui étend l’outil pour répondre précisément à vos besoins, .NET Reflector fait gagner du temps et simplifie le développement. Voyons la multitude de services de reverse engineering proposés par cet outil :

- Donne un aperçu de la circulation des données dans une bibliothèque ou un composant
- Donne un aperçu de l’implémentation et de l’utilisation des langages et frameworks .NET
- Repère les fonctionnalités non documentées et non exposées pour tirer davantage parti des API et des technologies utilisées.
- Repère les dépendances et les différents assemblys
- Identifie l’emplacement exact des erreurs dans votre code, les composants tiers et les bibliothèques.
- Permet de déboguer le code source de tout le code .NET avec lequel vous travaillez.

### [ILSpy](https://github.com/icsharpcode/ILSpy) et [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy pour Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) : vous pouvez l’utiliser sur n’importe quel OS (vous pouvez l’installer directement depuis VSCode, sans avoir besoin de télécharger le dépôt git. Cliquez sur **Extensions** et **recherchez ILSpy**).\
Si vous devez **décompiler**, **modifier** et **recompiler**, vous pouvez utiliser [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou son fork activement maintenu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic droit -> Modify Method** pour modifier quelque chose dans une fonction).

### Journalisation avec DNSpy

Pour que **DNSpy consigne des informations dans un fichier**, vous pouvez utiliser cet extrait de code :

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Débogage avec DNSpy

Pour déboguer du code avec DNSpy, vous devez :

Tout d’abord, modifier les **attributs de l’assembly** liés au **débogage** :

![Journalisation DNSpy - Débogage avec DNSpy : Tout d’abord, modifier les attributs de l’assembly liés au débogage](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Enregistrez ensuite le nouveau fichier via _**File >> Save module...**_ :

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

C’est nécessaire, car si vous ne le faites pas, plusieurs **optimisations** seront appliquées au code à **l’exécution**. Il est alors possible qu’un **point d’arrêt ne soit jamais atteint** pendant le débogage ou que certaines **variables n’existent pas**.

Ensuite, si votre application .NET est **exécutée** par **IIS**, vous pouvez la **redémarrer** avec :

```
iisreset /noforce
```

Ensuite, pour commencer le débogage, fermez tous les fichiers ouverts et, dans l’onglet **Debug**, sélectionnez **Attach to Process...** :

![DNSpy Logging - DNSpy Debugging : Ensuite, pour commencer le débogage, fermez tous les fichiers ouverts et, dans l’onglet Debug, sélectionnez Attach to Process](<../../images/image (318).png>)

Sélectionnez ensuite **w3wp.exe** pour vous attacher au **serveur IIS**, puis cliquez sur **Attach** :

![DNSpy Logging - DNSpy Debugging : Sélectionnez ensuite w3wp.exe pour vous attacher au serveur IIS, puis cliquez sur Attach](<../../images/image (113).png>)

Maintenant que nous déboguons le processus, arrêtons-le et chargeons tous les modules. Cliquez d’abord sur _Debug >> Break All_, puis sur _**Debug >> Windows >> Modules**_ :

![DNSpy Logging - DNSpy Debugging : Maintenant que nous déboguons le processus, arrêtons-le et chargeons tous les modules. Cliquez d’abord sur Debug Break All, puis sur Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging : Maintenant que nous déboguons le processus, arrêtons-le et chargeons tous les modules. Cliquez d’abord sur Debug Break All, puis sur Debug Windows Modules](<../../images/image (834).png>)

Cliquez sur n’importe quel module dans **Modules**, puis sélectionnez **Open All Modules** :

![DNSpy Logging - DNSpy Debugging : Cliquez sur n’importe quel module dans Modules, puis sélectionnez Open All Modules](<../../images/image (922).png>)

Faites un clic droit sur n’importe quel module dans **Assembly Explorer**, puis cliquez sur **Sort Assemblies** :

![DNSpy Logging - DNSpy Debugging : Faites un clic droit sur n’importe quel module dans Assembly Explorer, puis cliquez sur Sort Assemblies](<../../images/image (339).png>)

## Décompilateur Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Débogage de DLL

### Avec IDA

- **Chargez rundll32** (64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- Sélectionnez le débogueur **Windbg**
- Sélectionnez "**Suspend on library load/unload**"

![Debugging DLLs - Avec IDA : Sélectionnez « Suspend on library load/unload »](<../../images/image (868).png>)

- Configurez les **paramètres** d’exécution en indiquant le **chemin de la DLL** et la fonction que vous souhaitez appeler :

![Debugging DLLs - Avec IDA : Configurez les paramètres d’exécution en indiquant le chemin de la DLL et la fonction que vous souhaitez appeler](<../../images/image (704).png>)

Ensuite, lorsque vous démarrez le débogage, **l’exécution s’arrête au chargement de chaque DLL**. Ainsi, lorsque rundll32 charge votre DLL, l’exécution s’arrête.

Cette méthode s’arrête lors des événements de chargement de module, mais atteindre le point d’entrée de la DLL chargée est moins direct qu’avec le workflow x64dbg ci-dessous.

### Avec x64dbg/x32dbg

- **Chargez rundll32** (64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- **Modifiez la ligne de commande** ( _File --> Change Command Line_ ) et indiquez le chemin de la dll ainsi que la fonction à appeler, par exemple : "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Dans _Options --> Settings_, sélectionnez "**DLL Entry**".
- **Démarrez ensuite l’exécution**. Le débogueur s’arrêtera à chaque dll main et, à un moment donné, **s’arrêtera au point d’entrée de votre DLL**. À partir de là, recherchez les endroits où vous souhaitez placer un breakpoint.

Notez que lorsque l’exécution est interrompue pour une raison quelconque dans win64dbg, vous pouvez voir **dans quel code vous vous trouvez** en regardant **en haut de la fenêtre win64dbg** :

![Using IDA - Avec x64dbg/x32dbg : Notez que lorsque l’exécution est interrompue pour une raison quelconque dans win64dbg, vous pouvez voir dans quel code vous vous trouvez en regardant en haut de la fenêtre win64dbg](<../../images/image (842).png>)

Cet indicateur confirme que l’exécution est interrompue dans la DLL que vous souhaitez déboguer.

## Applications GUI / jeux vidéo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où les valeurs importantes sont enregistrées dans la mémoire d’un jeu en cours d’exécution et les modifier. Plus d’informations dans :

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) est une interface graphique/un outil de reverse engineering pour le GNU Project Debugger (GDB), conçu pour les jeux. Il peut toutefois servir à tout type de reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) est une interface web donnant accès à plusieurs décompilateurs. Ce service web vous permet de comparer les résultats de différents décompilateurs sur de petits exécutables.

## ARM & MIPS

{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Déboguer un shellcode avec blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alloue le **shellcode**, affiche son **adresse mémoire** et met l’exécution en pause.\
Attachez un débogueur tel qu’IDA ou x64dbg, définissez un breakpoint à l’adresse affichée, puis reprenez l’exécution pour déboguer le shellcode.

La page des releases GitHub contient des fichiers zip avec les versions compilées : [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Vous trouverez une version légèrement modifiée de Blobrunner au lien suivant. Pour la compiler, **créez simplement un projet C/C++ dans Visual Studio Code, copiez-collez le code, puis compilez-le**.

{{#ref}}
blobrunner.md
{{#endref}}

### Déboguer un shellcode avec jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) est similaire à BlobRunner. Il alloue le shellcode et entre dans une boucle infinie. Attachez le débogueur, reprenez l’exécution pendant **2 à 5 secondes**, interrompez-la dans cette boucle, puis avancez jusqu’à l’appel suivant, qui transfère l’exécution au shellcode alloué.

![Débogueur en pause dans la boucle infinie de jmp2it, juste avant l’appel au shellcode alloué](<../../images/image (509).png>)

Vous pouvez télécharger une version compilée de [jmp2it dans la page des releases](https://github.com/adamkramer/jmp2it/releases/).

### Déboguer un shellcode avec Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) est l’interface graphique de radare. Avec Cutter, vous pouvez émuler le shellcode et l’inspecter dynamiquement.

Notez que Cutter permet de choisir « Open File » ou « Open Shellcode ». Dans mon cas, lorsque j’ai ouvert le shellcode en tant que fichier, il l’a décompilé correctement, mais pas lorsque je l’ai ouvert en tant que shellcode :

![Cutter affichant différents résultats d’analyse après avoir ouvert les mêmes octets comme fichier ou comme shellcode](<../../images/image (562).png>)

Pour démarrer l’émulation à l’endroit souhaité, définissez-y un bp ; apparemment, Cutter démarrera automatiquement l’émulation à partir de là :

![Définition d’un breakpoint à l’entrée souhaitée du shellcode avant de démarrer l’émulation de Cutter](<../../images/image (589).png>)

![Émulateur Cutter en pause au breakpoint choisi dans le shellcode](<../../images/image (387).png>)

Vous pouvez, par exemple, afficher la stack dans un vidage hexadécimal :

![Affichage de la stack du shellcode émulé dans le vidage hexadécimal de Cutter](<../../images/image (186).png>)

### Déobfusquer un shellcode et récupérer les fonctions exécutées

Essayez [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Il vous indiquera notamment **quelles fonctions** le shellcode utilise et s’il se **décode** lui-même en mémoire.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg dispose également d’un lanceur graphique qui vous permet de sélectionner les options souhaitées et d’exécuter le shellcode

![Lanceur graphique de scDbg permettant de sélectionner les options d’émulation et de traçage du shellcode](<../../images/image (258).png>)

L’option **Create Dump** crée un dump du shellcode final si celui-ci est modifié dynamiquement en mémoire (utile pour télécharger le shellcode décodé). Le **start offset** peut être utile pour démarrer le shellcode à un offset précis. L’option **Debug Shell** permet de déboguer le shellcode à l’aide du terminal scDbg (cependant, je trouve que les options expliquées précédemment sont plus adaptées, car elles permettent d’utiliser Ida ou x64dbg).

### Désassembler avec CyberChef

Chargez votre fichier shellcode en entrée et utilisez la recette suivante pour le désassembler : [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Déobfuscation de l’obfuscation MBA

L’obfuscation **Mixed Boolean-Arithmetic (MBA)** masque des expressions simples comme `x + y` derrière des formules qui combinent des opérateurs arithmétiques (`+`, `-`, `*`) et des opérateurs bit à bit (`&`, `|`, `^`, `~`, shifts). L’essentiel est que ces identités ne sont généralement valides qu’avec une **arithmétique modulaire de largeur fixe** ; les retenues et les dépassements de capacité sont donc importants :

```c
(x ^ y) + 2 * (x & y) == x + y
```

Si vous simplifiez ce type d’expression avec des outils d’algèbre génériques, vous pouvez facilement obtenir un résultat erroné, car la sémantique de la largeur des bits a été ignorée.<sup>[[1]](#references)</sup>

### Workflow pratique

1. **Conservez la largeur de bits d’origine** du code/IR désassemblé ou de la sortie du décompilateur (`8/16/32/64` bits).
2. **Classez l’expression** avant d’essayer de la simplifier :
   - **Linéaire** : sommes pondérées d’atomes bit à bit
   - **Semi-linéaire** : expression linéaire plus des masques constants tels que `x & 0xFF`
   - **Polynomiale** : présence de produits
   - **Mixte** : produits et logique bit à bit sont entremêlés, souvent avec des sous-expressions répétées
3. **Vérifiez chaque réécriture candidate** par des tests aléatoires ou une preuve SMT. Si l’équivalence ne peut pas être prouvée, conservez l’expression d’origine au lieu de faire une supposition.

### Contourner un flot de contrôle aplati avec une tranche d’exécution réduite

Il est souvent inutile de reconstruire le graphe de flot de contrôle complet. En présence d’aplatissement du flot de contrôle, de prédicats opaques, de grands répartiteurs ou de code riche en MBA, suivez les références depuis les blobs chiffrés et les buffers de sortie jusqu’à la plus petite routine qui les transforme. Reproduisez ensuite uniquement cette tranche de flux de données, ou exécutez-la indépendamment ; le répartiteur ne fait pas partie de la solution requise si l’état pertinent peut être initialisé directement.<sup>[[7]](#references)</sup>

Un workflow pratique est le suivant :<sup>[[7]](#references)</sup>

1. Inventoriez les sections exécutables et de données, les relocalisations et les références croisées. Extrayez les tables candidates depuis `.rodata` en préservant leur ordre des octets et la largeur de leurs éléments.
2. Identifiez la dernière routine qui écrit le texte en clair ou le buffer de sortie. Notez ses entrées, les tables référencées, les appels importés et l’état global requis.
3. Ne transposez que ces opérations dans un modèle Python à largeur fixe. Si la tranche dépend encore d’un état trop important, appelez la routine avec Unicorn, QEMU ou un débogueur et interceptez les imports non pertinents au lieu d’émuler tout le programme.
4. Vérifiez que l’extracteur dérive réellement sa sortie du binaire fourni : supprimez les solutions de repli silencieuses, recherchez-y des réponses intégrées et testez-le sur des builds inconnus avec des chaînes, clés, identifiants, layouts et seeds d’obfuscation modifiés.

Voici quelques commandes utiles pour une première analyse :<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Détecter les expressions MBA qui dissimulent des constantes

Une expression d’octet apparemment dépendante de l’entrée peut annuler complètement son entrée. Après avoir extrait ses tables, évaluez l’expression sur l’ensemble du domaine des 8 bits ; un ensemble de sorties réduit à une seule valeur prouve que cet octet est constant, sans qu’il soit nécessaire de retrouver la machine à états environnante.<sup>[[7]](#references)</sup>

```python
def mba(a, b, c, d, e, x):
    return ((((a | (~x & 0xff)) & c) +
             ((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
    outputs = {mba(*row, x) for x in range(256)}
    if len(outputs) != 1:
        raise ValueError("expression depends on x")
    decoded.append(outputs.pop())
print(decoded)
```

Conservez le masque final, car l’addition d’origine entraîne un débordement modulo la largeur d’un octet. Pour un domaine plus large, demandez à un solveur SMT si `f(x1) != f(x2)` est satisfiable pour deux entrées symboliques de même largeur : `unsat` prouve l’invariance, tandis que `sat` fournit un contre-exemple et signifie que l’entrée ne peut pas être écartée.<sup>[[7]](#references)</sup>

#### Reconnaître le décodage lié à l’environnement

Les vérifications anti-analyse n’ont pas besoin de provoquer un branchement ou un crash. Un décodeur peut intégrer le résultat d’un capteur à un bit de clé, à une constante de prédicat opaque ou à l’état d’un dispatcher aplati, continuer normalement et produire un texte en clair plausible, mais erroné, dans un émulateur. Par conséquent, corriger uniquement les branches d’échec visibles ne suffit pas ; tracez les dépendances des données depuis les sondes de l’environnement jusqu’à l’état du décodeur, comparez la même tranche sur l’appareil authentique et l’émulateur, puis vérifiez comment le forçage de chaque résultat de capteur modifie le buffer final.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) est un simplificateur MBA pratique pour l’analyse de malware et le reversing de binaires protégés. Il classe l’expression et l’oriente vers des pipelines spécialisés au lieu d’appliquer une passe de réécriture générique à tout.<sup>[[2]](#references)</sup>

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

- **Linear MBA** : CoBRA évalue l’expression sur des entrées booléennes, en déduit une signature et met en concurrence plusieurs méthodes de récupération, comme le pattern matching, la conversion en ANF et l’interpolation des coefficients.
- **Semilinear MBA** : les atomes masqués par des constantes sont reconstruits par partitionnement des bits, afin de préserver l’exactitude des régions masquées.
- **Polynomial/Mixed MBA** : les produits sont décomposés en éléments fondamentaux et les sous-expressions répétées peuvent être isolées dans des variables temporaires avant de simplifier la relation externe.

Exemple d’identité mixte qu’il vaut souvent la peine de retrouver :

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Cela peut se réduire à :

```c
x * y
```

### Notes sur le reversing

- Privilégiez l’exécution de CoBRA sur des **expressions IR lifted** ou sur la sortie du décompilateur, après avoir isolé le calcul exact.
- Utilisez explicitement `--bitwidth` lorsque l’expression provient d’opérations masquées ou de registres de largeur réduite.
- Si vous avez besoin d’une étape de preuve plus rigoureuse, consultez les notes locales sur Z3 ici :


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA est également fourni sous forme de **plugin LLVM pass** (`libCobraPass.so`), utile pour normaliser le LLVM IR chargé en MBA avant les passes d’analyse ultérieures.
- Les résidus mixtes de domaines sensibles aux retenues non pris en charge doivent vous inciter à conserver l’expression d’origine et à raisonner manuellement sur le chemin des retenues.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Cet obfuscateur remplace les opérations du programme par des séquences d’instructions basées sur `mov` et utilise la gestion des signaux et des exceptions pour modifier le flux de contrôle. Pour plus de détails :

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Pour les binaires pris en charge, [demovfuscator](https://github.com/kirschju/demovfuscator) peut déobfusquer le résultat. Il dépend de plusieurs composants.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Et [installez keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si vous participez à un **CTF, cette méthode de contournement pour trouver le flag** peut être très utile : [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Pour trouver le **point d’entrée**, recherchez les fonctions contenant `::main`, comme dans cet exemple :

![Trouver un point d’entrée Rust dans Ghidra en recherchant les noms de fonctions contenant deux-points deux fois](<../../images/image (1080).png>)

Dans ce cas, le binaire s’appelait authenticator ; il est donc évident que cette fonction main est intéressante.\
À partir du **nom** des **fonctions** appelées, recherchez-les sur **Internet** pour en savoir plus sur leurs **entrées** et leurs **sorties**.

### Récupérer les chaînes Rust depuis un firmware ELF

Dans les binaires **ELF Rust**, de nombreuses chaînes statiques ne sont pas référencées par des pointeurs terminés par un octet nul, comme en C. Une disposition courante de `rustc` utilise un **tuple pointeur/longueur** dans **`.data.rel.ro`**, qui pointe vers le véritable bloc de chaînes stocké dans **`.rodata`** :

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Cela signifie que `strings` ou l’analyse par défaut de Ghidra peuvent fusionner des chaînes adjacentes ou manquer entièrement des références croisées.<sup>[[3]](#references)</sup>

Flux de travail rapide :

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Récupérez l’adresse virtuelle et la taille de **`.rodata`**.
2. Énumérez **`.data.rel.ro`** mot par mot.
3. Considérez toute valeur située dans la plage d’adresses de `.rodata` comme un pointeur de chaîne potentiel.
4. Considérez le mot suivant comme la longueur potentielle.
5. Appliquez des filtres de cohérence (par exemple, ne gardez que les longueurs comprises entre **4** et **100** octets).
6. Lisez exactement `length` octets depuis `.rodata` au lieu de parcourir la mémoire jusqu’à `0x00`.

Logique minimale de l’extracteur :

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

C'est particulièrement utile pour le reversing de firmware, car les chaînes Rust récupérées révèlent souvent les **routes HTTP, les noms RPC, les messages de journalisation, les assertions, les noms de fichiers, les clés de configuration, les gestionnaires de commandes et la logique liée à l'authentification**.

Si Ghidra ne détecte pas ces chaînes, exécutez un script ou un plugin personnalisé qui applique la même heuristique et crée des données de chaîne aux offsets `.rodata` référencés. Les outils `rust-strings` et `RustStrings.py` publiés par Pen Test Partners sont de bonnes références pour adapter cette idée à d'autres **tailles de mots, ordres des octets et dispositions de sections**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Pour les binaires compilés avec Delphi, vous pouvez utiliser [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si vous devez analyser un binaire Delphi, je vous conseille d'utiliser le plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Appuyez sur **Alt+F7** dans IDA pour charger un plugin Python, puis sélectionnez le fichier du plugin.

Ce plugin exécute le binaire et résout dynamiquement les noms de fonctions au début du debugging. Une fois le debugging lancé, appuyez de nouveau sur le bouton Start (le bouton vert ou f9) ; un breakpoint sera déclenché au début du code réel.

Si vous appuyez sur un bouton dans l'application graphique, le debugger peut s'arrêter dans la fonction appelée par ce bouton.

## Golang

Pour les binaires Go ordinaires, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) peut récupérer les structures d'exécution et améliorer les noms de fonctions dans IDA. Chargez son plugin Python avec **Alt+F7**.

### Récupérer les métadonnées sans la table des symboles

Un exécutable Go dépouillé a toujours besoin des métadonnées d'exécution pour associer les compteurs de programme aux fonctions. [GoReSym](https://github.com/mandiant/GoReSym) localise et analyse des structures telles que `pclntab` et `moduledata` à l'aide de code dérivé du runtime Go. Il peut récupérer les limites des fonctions, leurs noms, les chemins sources, les types et les détails de compilation sans dépendre de la table des symboles conventionnelle.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Un obfuscateur peut laisser ces structures utilisables tout en remplaçant les noms récupérés. Garble, par exemple, hache les identifiants et les chemins des packages et supprime les informations de build, de module et de debug.<sup>[[12]](#references)</sup> Le token de package obfusqué doit rester cohérent entre les fonctions de ce package. Regroupez les fonctions selon le token répété, déduisez un package à partir de ses fonctions appelées, de ses chaînes et de ses API, puis appliquez le label de ce package à tout le groupe.<sup>[[13]](#references)</sup>

### Récupérer les noms Garble avec GoResolver

[GoResolver](https://github.com/volexity/GoResolver) combine l’extraction de symboles du runtime avec la génération de références propres et la correspondance de graphes de flux de contrôle (CFG). Suivez cette séquence :<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifiez la version du compilateur.** Essayez d’abord `BuildInfo` et les chaînes de version intégrées. Si l’obfuscateur les a supprimées, comparez des portions du runtime Go inclus avec des runtimes de référence versionnés. Dans les tests de Volexity, environ `2%` du runtime suffisait à distinguer les versions majeures de Go. Considérez cela comme une optimisation empirique, et non comme un seuil universel.<sup>[[13]](#references)</sup>
2. **Générez des références correspondantes.** Générez des binaires propres pour la version de Go identifiée, l’architecture cible et les bibliothèques probables. Faire correspondre la chaîne d’outils réduit les différences de CFG générées par le compilateur.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Comparez les fonctions.** GoGrapher compare les CFG des fonctions et produit des scores normalisés de `0.0` à `1.0`. La correspondance des blocs de base repose sur une comparaison pondérée d’instructions similaires. Les correspondances hautement fiables associent les fonctions randomisées à l’implémentation propre. Les correspondances moins fiables peuvent tout de même identifier un package ou un module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Validez et importez.** Confirmez les noms proposés à l’aide des relations d’appel, des constantes, des chaînes et des effets de bord, puis importez le rapport JSON avec le plugin GoResolver pour IDA ou Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Installez la chaîne d’outils et lancez l’extracteur et le comparateur de graphes combinés :<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

Le seuil de correspondance significative par défaut est `0.9`. Les options `--extract` et `--graph` permettent d’isoler chaque étape, tandis que le comportement par défaut exécute les deux, car les métadonnées d’exécution récupérées et les éléments de preuve du CFG se complètent.<sup>[[10]](#references)</sup> Les scores du CFG sont heuristiques : l’inlining, les options de compilation, l’architecture et les différences de version des bibliothèques peuvent modifier la structure du graphe. Il vaut donc mieux conserver les fonctions non résolues que de leur attribuer des noms avec un faible niveau de confiance.<sup>[[13]](#references)</sup>

## Python compilé

Sur cette page, vous trouverez comment récupérer le code Python à partir d’un binaire ELF/EXE compilé en Python :

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Si vous obtenez le **binaire** d’un jeu GBA, vous pouvez utiliser différents outils pour l’**émuler** et le **déboguer** :

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Téléchargez la version de débogage_) - Comprend un débogueur avec interface
- [**mgba** ](https://mgba.io)- Comprend un débogueur CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

Dans [**no$gba**](https://problemkaputt.de/gba.htm), dans _**Options --> Emulation Setup --> Controls**_** **, vous pouvez voir comment appuyer sur les **boutons** de la Game Boy Advance.

![Configuration des commandes de no$gba indiquant les correspondances des boutons de la Game Boy Advance](<../../images/image (581).png>)

Lorsque vous appuyez sur une **touche**, elle possède une valeur qui permet de l’identifier :

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

Ainsi, dans ce type de programme, la partie intéressante sera **la façon dont le programme traite l’entrée utilisateur**. À l’adresse **0x4000130**, vous trouverez la fonction courante : **KEYINPUT**.

![Vue de Ghidra d’un binaire GBA faisant référence à KEYINPUT à l’adresse 0x4000130](<../../images/image (447).png>)

Dans l’image précédente, vous pouvez voir que la fonction est appelée depuis **FUN_080015a8** (adresses : _0x080015fa_ et _0x080017ac_).

Dans cette fonction, après quelques opérations d’initialisation (sans importance) :

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

On trouve ce code :

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

Le dernier if vérifie que **`uVar4`** se trouve parmi les dernières touches et qu’il ne s’agit pas de la touche actuelle, ce qui correspond également au relâchement d’un bouton (la touche actuelle est stockée dans **`uVar1`**).

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

Dans le code précédent, on peut voir que nous comparons **uVar1** (l’endroit où se trouve la **valeur du bouton enfoncé**) à certaines valeurs :

- D’abord, on le compare à la **valeur 4** (bouton **SELECT**) : dans le défi, ce bouton efface l’écran.
- Ensuite, on compare sa valeur à **8** (bouton **START**) ; dans ce défi, ce chemin vérifie si le code saisi est valide.
  - Dans ce cas, la variable **`DAT_030000d8`** est comparée à 0xf3 et, si les valeurs sont identiques, du code est exécuté.
- Dans tous les autres cas, un compteur (`DAT_030000d4`) est vérifié et incrémenté.\
  Tant que le compteur est inférieur à 8, les valeurs des touches enfoncées sont cumulées dans `DAT_030000d8`.

Ainsi, dans ce défi, connaissant les valeurs des boutons, il fallait **appuyer sur une combinaison de moins de 8 boutons dont la somme obtenue est 0xf3.**

**Référence pour ce tutoriel :** [article archivé sur le défi Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cours

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Désobfuscation de binaires)

## References

- [1] [Simplification de l’obfuscation MBA avec CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Dépôt CoBRA de Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Décodage des chaînes Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - chaînes Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutoriel de reversing sur GBA (archivé)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Vaincre la rétro-ingénierie assistée par l’IA, ou du moins essayer](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Une méthode de comparaison des graphes de flot de contrôle basée sur la correspondance des blocs de base](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mécanisme d’obfuscation de Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver : utiliser la similarité des graphes de flot de contrôle pour désobfusquer automatiquement les binaires Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
