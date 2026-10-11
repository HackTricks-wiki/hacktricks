# Outils de reverse engineering basés sur ImGui

{{#include ../../banners/hacktricks-training.md}}

## Outils logiciels

- ReverseKit : [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Débogage du noyau Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Décompilateur Wasm / compilateur Wat

En ligne :

- Utilisez [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) pour **décompiler** du wasm (binaire) en wat (texte clair)
- Utilisez [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) pour **compiler** du wat en wasm
- Vous pouvez aussi essayer [web-wasmdec](https://wwwg.github.io/web-wasmdec/) pour la décompilation.

Logiciels :

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode mis en cache de Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Décompilateur .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek est un décompilateur qui **décompile et examine plusieurs formats**, notamment les **bibliothèques** (.dll), les **fichiers de métadonnées Windows** (.winmd) et les **exécutables** (.exe). Après la décompilation, un assembly peut être enregistré en tant que projet Visual Studio (.csproj).

L’intérêt de cet outil est qu’il peut faire gagner du temps lorsqu’il faut restaurer du code source perdu à partir d’un assembly ancien. De plus, dotPeek facilite la navigation dans le code décompilé, ce qui en fait l’un des outils parfaits pour **l’analyse d’algorithmes Xamarin**.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grâce à son modèle complet de modules complémentaires et à une API qui permet d’adapter l’outil à vos besoins précis, .NET Reflector fait gagner du temps et simplifie le développement. Voici les nombreux services de reverse engineering proposés par cet outil :

- Donne un aperçu de la circulation des données dans une bibliothèque ou un composant
- Donne un aperçu de l’implémentation et de l’utilisation des langages et frameworks .NET
- Repère les fonctionnalités non documentées et non exposées afin de tirer davantage parti des API et des technologies utilisées.
- Repère les dépendances et les différents assemblies
- Identifie l’emplacement exact des erreurs dans votre code, les composants tiers et les bibliothèques.
- Permet de déboguer le code source de tout le code .NET avec lequel vous travaillez.

### [ILSpy](https://github.com/icsharpcode/ILSpy) et [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy pour Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) : vous pouvez l’utiliser sur n’importe quel OS (vous pouvez l’installer directement depuis VSCode, sans avoir à télécharger le dépôt Git. Cliquez sur **Extensions**, puis **recherchez ILSpy**).\
Si vous devez **décompiler**, **modifier** puis **recompiler**, vous pouvez utiliser [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou l’un de ses forks activement maintenus, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic droit -> Modify Method** pour modifier quelque chose dans une fonction).

### Journalisation DNSpy

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

Et cliquez sur **Compiler** :

![Journalisation DNSpy - Débogage DNSpy : cliquez sur Compiler](<../../images/image (314) (1).png>)

Enregistrez ensuite le nouveau fichier via _**Fichier >> Enregistrer le module...**_ :

![Journalisation DNSpy - Débogage DNSpy : enregistrez ensuite le nouveau fichier via Fichier Enregistrer le module](<../../images/image (602).png>)

C'est nécessaire, car si vous ne le faites pas, plusieurs **optimisations** seront appliquées au code au **runtime**, et il se peut qu'un **point d'arrêt ne soit jamais atteint** pendant le débogage ou que certaines **variables n'existent pas**.

Ensuite, si votre application .NET est **exécutée** par **IIS**, vous pouvez la **redémarrer** avec :

```
iisreset /noforce
```

Then, pour commencer le débogage, vous devez fermer tous les fichiers ouverts et sélectionner **Attach to Process...** dans l’onglet **Debug** :

![DNSpy Logging - DNSpy Debugging : Pour commencer le débogage, vous devez fermer tous les fichiers ouverts et sélectionner Attach to Process dans l’onglet Debug](<../../images/image (318).png>)

Sélectionnez ensuite **w3wp.exe** pour vous attacher au **serveur IIS**, puis cliquez sur **attach** :

![DNSpy Logging - DNSpy Debugging : Sélectionnez w3wp.exe pour vous attacher au serveur IIS, puis cliquez sur attach](<../../images/image (113).png>)

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

![Débogage de DLL - Avec IDA : Sélectionnez « Suspend on library load/unload »](<../../images/image (868).png>)

- Configurez les **paramètres** de l’exécution en indiquant le **chemin de la DLL** et la fonction que vous souhaitez appeler :

![Débogage de DLL - Avec IDA : Configurez les paramètres de l’exécution en indiquant le chemin de la DLL et la fonction que vous souhaitez appeler](<../../images/image (704).png>)

Ensuite, lorsque vous démarrez le débogage, **l’exécution s’arrête au chargement de chaque DLL**. Ainsi, lorsque rundll32 chargera votre DLL, l’exécution sera interrompue.

Cette méthode s’arrête lors des événements de chargement de module, mais atteindre le point d’entrée de la DLL chargée est moins direct qu’avec le workflow x64dbg ci-dessous.

### Avec x64dbg/x32dbg

- **Chargez rundll32** (64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- **Modifiez la ligne de commande** ( _File --> Change Command Line_ ) et indiquez le chemin de la dll et la fonction que vous souhaitez appeler, par exemple : "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Dans _Options --> Settings_, sélectionnez "**DLL Entry**".
- **Démarrez ensuite l’exécution**. Le débogueur s’arrêtera à chaque dll main ; à un moment donné, vous **vous arrêterez à l’entrée de votre DLL**. Cherchez ensuite les points où vous souhaitez placer un breakpoint.

Notez que lorsque l’exécution est interrompue pour une raison quelconque dans win64dbg, vous pouvez voir **dans quel code vous vous trouvez** en regardant **en haut de la fenêtre win64dbg** :

![Avec IDA - Avec x64dbg/x32dbg : Lorsque l’exécution est interrompue pour une raison quelconque dans win64dbg, vous pouvez voir dans quel code vous vous trouvez en regardant en haut de la fenêtre win64dbg](<../../images/image (842).png>)

Cet indicateur confirme que l’exécution s’est arrêtée dans la DLL que vous souhaitez déboguer.

## Applications GUI / jeux vidéo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où les valeurs importantes sont enregistrées dans la mémoire d’un jeu en cours d’exécution et les modifier. Plus d’informations dans :

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) est une interface graphique et un outil de reverse engineering pour le GNU Project Debugger (GDB), axé sur les jeux. Il peut toutefois être utilisé pour toute activité liée au reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) est une interface web pour plusieurs décompilateurs. Ce service web vous permet de comparer les résultats de différents décompilateurs sur de petits exécutables.

## ARM et MIPS

{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Déboguer un shellcode avec blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alloue le **shellcode**, affiche son **adresse mémoire** et met l’exécution en pause.\
Attachez un débogueur comme IDA ou x64dbg, placez un breakpoint à l’adresse affichée et reprenez l’exécution pour déboguer le shellcode.

La page GitHub des releases contient des archives zip avec les versions compilées : [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Vous trouverez une version légèrement modifiée de Blobrunner au lien suivant. Pour la compiler, **créez simplement un projet C/C++ dans Visual Studio Code, copiez-collez le code et compilez-le**.

{{#ref}}
blobrunner.md
{{#endref}}

### Déboguer un shellcode avec jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) est similaire à BlobRunner. Il alloue le shellcode et entre dans une boucle infinie. Attachez le débogueur, reprenez l’exécution pendant **2 à 5 secondes**, interrompez-la dans cette boucle, puis avancez jusqu’à l’appel suivant, qui transfère l’exécution au shellcode alloué.

![Débogueur en pause dans la boucle infinie de jmp2it, juste avant l’appel au shellcode alloué](<../../images/image (509).png>)

Vous pouvez télécharger une version compilée de [jmp2it sur la page des releases](https://github.com/adamkramer/jmp2it/releases/).

### Déboguer un shellcode avec Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) est l’interface graphique de radare. Cutter permet d’émuler le shellcode et de l’inspecter dynamiquement.

Notez que Cutter propose les options « Open File » et « Open Shellcode ». Dans mon cas, l’ouverture du shellcode en tant que fichier l’a correctement décompilé, mais son ouverture en tant que shellcode n’a pas fonctionné :

![Cutter affiche des résultats d’analyse différents selon que les mêmes octets sont ouverts comme fichier ou comme shellcode](<../../images/image (562).png>)

Pour démarrer l’émulation à l’endroit souhaité, placez-y un bp ; apparemment, Cutter démarrera automatiquement l’émulation à partir de cet endroit :

![Placement d’un breakpoint à l’entrée souhaitée du shellcode avant de démarrer l’émulation de Cutter](<../../images/image (589).png>)

![L’émulateur de Cutter est en pause au breakpoint sélectionné dans le shellcode](<../../images/image (387).png>)

Vous pouvez, par exemple, afficher la stack dans un dump hexadécimal :

![Affichage de la stack du shellcode émulé dans le dump hexadécimal de Cutter](<../../images/image (186).png>)

### Désobfuscation du shellcode et récupération des fonctions exécutées

Vous pouvez essayer [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Il vous indiquera notamment **quelles fonctions** le shellcode utilise et s’il se **décode** lui-même en mémoire.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg dispose également d’un lanceur graphique qui permet de sélectionner les options souhaitées et d’exécuter le shellcode

![Lanceur graphique de scDbg permettant de sélectionner les options d’émulation et de traçage du shellcode](<../../images/image (258).png>)

L’option **Create Dump** permet de sauvegarder le shellcode final si celui-ci est modifié dynamiquement en mémoire (utile pour télécharger le shellcode décodé). Le **start offset** peut être utile pour démarrer le shellcode à un offset précis. L’option **Debug Shell** permet de déboguer le shellcode à l’aide du terminal de scDbg (je trouve toutefois que les options expliquées précédemment sont préférables, car elles permettent d’utiliser Ida ou x64dbg).

### Désassembler avec CyberChef

Importez votre fichier shellcode en entrée et utilisez la recette suivante pour le désassembler : [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Déobfuscation de l’obfuscation MBA

L’obfuscation **Mixed Boolean-Arithmetic (MBA)** masque des expressions simples telles que `x + y` derrière des formules qui combinent des opérations arithmétiques (`+`, `-`, `*`) et des opérateurs bit à bit (`&`, `|`, `^`, `~`, décalages). L’élément important est que ces identités ne sont généralement correctes qu’avec une **arithmétique modulaire à largeur fixe** : les retenues et les débordements comptent.

```c
(x ^ y) + 2 * (x & y) == x + y
```

Si vous simplifiez ce type d’expression avec des outils d’algèbre génériques, vous pouvez facilement obtenir un résultat erroné, car la sémantique de la largeur en bits a été ignorée.<sup>[[1]](#references)</sup>

### Procédure pratique

1. **Conservez la largeur en bits d’origine** du code/IR/de la sortie du décompilateur (`8/16/32/64` bits).
2. **Classez l’expression** avant d’essayer de la simplifier :
   - **Linéaire** : sommes pondérées d’atomes bit à bit
   - **Semi-linéaire** : expression linéaire avec des masques constants, tels que `x & 0xFF`
   - **Polynomiale** : présence de produits
   - **Mixte** : produits et logique bit à bit entremêlés, souvent avec des sous-expressions répétées
3. **Vérifiez chaque réécriture candidate** par des tests aléatoires ou une preuve SMT. Si l’équivalence ne peut pas être prouvée, conservez l’expression d’origine au lieu de deviner.

### Contourner le flux de contrôle aplati avec une tranche d’exécution étroite

Il est souvent inutile de reconstituer le graphe de flot de contrôle complet. En présence d’un aplatissement du flux de contrôle, de prédicats opaques, de grands répartiteurs ou de code riche en MBA, suivez les références depuis les blobs chiffrés et les buffers de sortie jusqu’à la routine la plus réduite qui les transforme. Reproduisez ensuite uniquement cette tranche du flux de données, ou exécutez-la indépendamment ; le répartiteur ne fait pas partie de la solution nécessaire si l’état pertinent peut être initialisé directement.<sup>[[7]](#references)</sup>

Voici une procédure pratique :<sup>[[7]](#references)</sup>

1. Répertoriez les sections exécutables et de données, les relocalisations et les références croisées. Extrayez les tables candidates de `.rodata` en préservant leur ordre des octets et la largeur de leurs éléments.
2. Identifiez la dernière routine qui écrit dans le buffer de texte en clair ou de sortie. Notez ses entrées, les tables référencées, les appels importés et l’état global requis.
3. Transposez uniquement ces opérations dans un modèle Python à largeur fixe. Si la tranche dépend encore d’un état trop important, invoquez la routine avec Unicorn, QEMU ou un débogueur, et interceptez les imports sans intérêt au lieu d’émuler le programme entier.
4. Vérifiez que l’extracteur dérive réellement sa sortie du binaire fourni : supprimez les solutions de repli silencieuses, recherchez-y des réponses intégrées et testez-le sur des builds inédits avec des chaînes, clés, identifiants, dispositions et graines d’obfuscation modifiés.

Voici quelques commandes utiles pour une première analyse :<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Détecter les expressions MBA dissimulant des constantes

Une expression d’octet apparemment dépendante de l’entrée peut annuler complètement celle-ci. Après avoir extrait ses tables, évaluez l’expression sur l’ensemble du domaine 8 bits ; un ensemble de sorties réduit à une seule valeur prouve que cet octet est constant, sans qu’il soit nécessaire de retrouver la machine à états qui l’entoure.<sup>[[7]](#references)</sup>

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

Conservez le masque final, car l’addition d’origine entraîne un débordement avec retour à zéro sur la largeur d’un octet. Pour un domaine plus large, demandez à un solveur SMT si `f(x1) != f(x2)` est satisfaisable pour deux entrées symboliques de même largeur : `unsat` prouve l’invariance, tandis que `sat` fournit un contre-exemple et signifie que l’entrée ne peut pas être écartée.<sup>[[7]](#references)</sup>

#### Reconnaître un décodage lié à l’environnement

Les vérifications anti-analyse n’entraînent pas nécessairement un branchement ou un crash. Un décodeur peut intégrer le résultat d’un capteur dans un bit de clé, une constante de prédicat opaque ou l’état d’un répartiteur aplati, poursuivre normalement et produire un texte en clair plausible mais erroné dans un émulateur. Par conséquent, corriger uniquement les branches d’échec visibles ne suffit pas ; suivez les dépendances des données depuis les sondes d’environnement jusqu’à l’état du décodeur, comparez la même tranche sur l’appareil authentique et dans l’émulateur, et vérifiez comment le forçage du résultat de chaque capteur modifie le tampon final.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) est un simplificateur MBA pratique pour l’analyse de malware et la rétro-ingénierie de binaires protégés. Il classe l’expression et l’oriente vers des pipelines spécialisés, au lieu d’appliquer une passe de réécriture générique à tout.<sup>[[2]](#references)</sup>

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

- **Linear MBA** : CoBRA évalue l’expression sur des entrées booléennes, en dérive une signature et lance en parallèle plusieurs méthodes de récupération, comme le pattern matching, la conversion ANF et l’interpolation des coefficients.
- **Semilinear MBA** : les atomes masqués par des constantes sont reconstruits par partitionnement en bits afin de préserver la justesse des régions masquées.
- **Polynomial/Mixed MBA** : les produits sont décomposés en noyaux, et les sous-expressions répétées peuvent être extraites dans des temporaires avant de simplifier la relation externe.

Exemple d’identité mixte dont la récupération vaut souvent la peine :

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Cela peut se réduire à :

```c
x * y
```

### Notes de reverse engineering

- Préférez exécuter CoBRA sur des **expressions IR relevées** ou sur la sortie du décompilateur après avoir isolé le calcul exact.
- Utilisez explicitement `--bitwidth` lorsque l’expression provient d’opérations masquées ou de registres de largeur réduite.
- Si vous avez besoin d’une étape de preuve plus robuste, consultez les notes locales sur Z3 ici :

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA est également fourni sous forme de **plugin de passe LLVM** (`libCobraPass.so`), utile pour normaliser un IR LLVM riche en MBA avant les passes d’analyse ultérieures.
- Les résidus mixtes entre domaines, sensibles aux retenues et non pris en charge, doivent être considérés comme un signal invitant à conserver l’expression d’origine et à raisonner manuellement sur le chemin des retenues.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Cet obfuscateur remplace les opérations du programme par des séquences d’instructions basées sur `mov` et utilise la gestion des signaux et des exceptions pour modifier le flux de contrôle. Pour plus de détails :

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Pour les binaires pris en charge, [demovfuscator](https://github.com/kirschju/demovfuscator) peut déobfusquer le résultat. Il nécessite plusieurs dépendances.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Et [installez keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si vous participez à un **CTF, cette méthode de contournement pour trouver le flag** peut être très utile : [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Pour trouver le **point d’entrée**, recherchez les fonctions contenant `::main`, comme dans cet exemple :

![Trouver un point d’entrée Rust dans Ghidra en recherchant les noms de fonctions contenant deux-points doubles suivis de main](<../../images/image (1080).png>)

Dans cet exemple, le binaire s’appelait authenticator ; il est donc assez évident que c’est la fonction main intéressante.\
Avec le **nom** des **fonctions** appelées, recherchez-les sur **Internet** pour connaître leurs **entrées** et leurs **sorties**.

### Récupération de chaînes Rust à partir d’un firmware ELF

Dans les binaires **ELF Rust**, de nombreuses chaînes statiques ne sont pas référencées par des pointeurs terminés par NUL, comme en C. Une disposition courante de `rustc` utilise un **tuple pointeur/longueur** dans **`.data.rel.ro`**, qui pointe vers le véritable bloc de chaînes stocké dans **`.rodata`** :

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
2. Énumérez **`.data.rel.ro`** un mot à la fois.
3. Traitez toute valeur comprise dans la plage d’adresses de `.rodata` comme un pointeur de chaîne candidat.
4. Traitez le mot suivant comme la longueur candidate.
5. Appliquez des filtres de plausibilité (par exemple, conservez les longueurs comprises entre **4** et **100** octets).
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

C’est particulièrement utile pour le reversing de firmware, car les chaînes Rust récupérées révèlent souvent des **routes HTTP, des noms RPC, des messages de journalisation, des assertions, des noms de fichiers, des clés de configuration, des gestionnaires de commandes et de la logique liée à l’authentification**.

Si Ghidra ne détecte pas ces chaînes, exécutez un script ou un plugin personnalisé qui applique la même heuristique et crée des données de type chaîne aux offsets `.rodata` référencés. Les outils `rust-strings` et `RustStrings.py` publiés par Pen Test Partners sont de bonnes références pour adapter cette approche à d’autres **tailles de mot, ordres des octets et organisations de sections**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Pour les binaires compilés avec Delphi, vous pouvez utiliser [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si vous devez faire le reversing d’un binaire Delphi, je vous conseille d’utiliser le plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Appuyez sur **Alt+F7** dans IDA pour charger un plugin Python, puis sélectionnez le fichier du plugin.

Ce plugin exécutera le binaire et résoudra dynamiquement les noms des fonctions au début du débogage. Une fois le débogage lancé, appuyez de nouveau sur le bouton Start (le bouton vert ou f9) : un breakpoint sera déclenché au début du code réel.

Si vous appuyez sur un bouton dans l’application graphique, le debugger peut s’arrêter dans la fonction appelée par ce bouton.

## Golang

Si vous devez faire le reversing d’un binaire Golang, je vous conseille d’utiliser le plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Appuyez sur **Alt+F7** dans IDA pour charger un plugin Python, puis sélectionnez le fichier du plugin.

Cela résoudra les noms des fonctions.

## Python compilé

Sur cette page, vous trouverez comment récupérer le code Python à partir d’un binaire ELF/EXE compilé en Python :


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Si vous obtenez le **binaire** d’un jeu GBA, vous pouvez utiliser différents outils pour l’**émuler** et le **déboguer** :

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Téléchargez la version debug_) - Contient un debugger avec interface
- [**mgba** ](https://mgba.io)- Contient un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

Dans [**no$gba**](https://problemkaputt.de/gba.htm), vous pouvez voir comment appuyer sur les **boutons** de la Game Boy Advance dans _**Options --> Emulation Setup --> Controls**_** **

![Configuration des commandes de no$gba affichant les correspondances des boutons de la Game Boy Advance](<../../images/image (581).png>)

Lorsqu’on appuie dessus, chaque **touche a une valeur** qui permet de l’identifier :

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

Le dernier if vérifie que **`uVar4`** figure parmi les **dernières touches** et qu'il ne s'agit pas de la touche actuelle, ce qui signifie qu'un bouton est relâché (la touche actuelle est stockée dans **`uVar1`**).

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

Dans le code précédent, on voit que **uVar1** (l’emplacement où se trouve la **valeur du bouton appuyé**) est comparé à certaines valeurs :

- D’abord, il est comparé à la **valeur 4** (bouton **SELECT**) : dans le challenge, ce bouton efface l’écran.
- Ensuite, la valeur est comparée à **8** (bouton **START**) ; dans ce challenge, ce chemin vérifie si le code saisi est valide.
  - Dans ce cas, la variable **`DAT_030000d8`** est comparée à 0xf3 et, si sa valeur correspond, du code est exécuté.
- Dans tous les autres cas, un compteur (`DAT_030000d4`) est vérifié puis incrémenté.\
  Tant que le compteur est inférieur à 8, les valeurs des touches appuyées sont accumulées dans `DAT_030000d8`.

Ainsi, dans ce challenge, connaissant les valeurs des boutons, il fallait **appuyer sur une combinaison de moins de 8 touches dont la somme obtenue est 0xf3.**

**Référence pour ce tutoriel :** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Formations

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (désobfuscation binaire)

## References

- [1] [Simplifier l’obfuscation MBA avec CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Dépôt CoBRA de Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Décoder les chaînes Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutoriel de reversing GBA (archivé)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Vaincre le reverse engineering assisté par l’IA, ou du moins essayer](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
