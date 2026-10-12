# Outils de rétro-ingénierie et méthodes de base

{{#include ../../banners/hacktricks-training.md}}

## Outils de rétro-ingénierie basés sur ImGui

Logiciels :

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

## Charges utiles virtualisées et machines virtuelles personnalisées

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Décompilateur .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek est un décompilateur qui **décompile et examine plusieurs formats**, notamment les **bibliothèques** (.dll), les **fichiers de métadonnées Windows** (.winmd) et les **exécutables** (.exe). Une fois décompilée, un assembly peut être enregistré sous forme de projet Visual Studio (.csproj).

Son intérêt est de pouvoir gagner du temps si le code source perdu d'un assembly ancien doit être restauré. De plus, dotPeek facilite la navigation dans le code décompilé, ce qui en fait l'un des outils parfaits pour l'**analyse d'algorithmes Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grâce à son modèle complet de modules complémentaires et à son API, qui permet d'adapter l'outil à vos besoins précis, .NET Reflector fait gagner du temps et simplifie le développement. Voici les nombreux services de rétro-ingénierie proposés par cet outil :

- Permet de comprendre comment les données circulent dans une bibliothèque ou un composant
- Permet de comprendre l'implémentation et l'utilisation des langages et frameworks .NET
- Repère les fonctionnalités non documentées et non exposées pour tirer davantage parti des API et des technologies utilisées.
- Repère les dépendances et les différents assemblies
- Identifie l'emplacement exact des erreurs dans votre code, les composants tiers et les bibliothèques.
- Permet de déboguer le code source de tout le code .NET avec lequel vous travaillez.

### [ILSpy](https://github.com/icsharpcode/ILSpy) et [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Module ILSpy pour Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) : vous pouvez l'utiliser sur n'importe quel système d'exploitation (vous pouvez l'installer directement depuis VSCode, sans avoir besoin de télécharger le dépôt git. Cliquez sur **Extensions** et **recherchez ILSpy**).\
Si vous devez **décompiler**, **modifier** puis **recompiler**, vous pouvez utiliser [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou son fork activement maintenu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic droit -> Modify Method** pour modifier quelque chose dans une fonction).

### Journalisation avec DNSpy

Pour que **DNSpy consigne des informations dans un fichier**, vous pouvez utiliser cet extrait :

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Débogage avec DNSpy

Pour déboguer du code avec DNSpy, vous devez :

Tout d'abord, modifier les **attributs d'assembly** liés au **débogage** :

![DNSpy Logging - Débogage avec DNSpy : tout d'abord, modifier les attributs d'assembly liés au débogage](<../../images/image (973).png>)

Depuis :

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

![DNSpy Logging - DNSpy Debugging : et cliquez sur compiler](<../../images/image (314) (1).png>)

Enregistrez ensuite le nouveau fichier via _**Fichier >> Enregistrer le module...**_ :

![DNSpy Logging - DNSpy Debugging : enregistrez ensuite le nouveau fichier via Fichier Enregistrer le module](<../../images/image (602).png>)

C’est nécessaire, car sinon, à **l’exécution**, plusieurs **optimisations** seront appliquées au code. Il est alors possible qu’un **point d’arrêt ne soit jamais atteint** pendant le débogage ou que certaines **variables n’existent pas**.

Ensuite, si votre application .NET est **exécutée** par **IIS**, vous pouvez la **redémarrer** avec :

```
iisreset /noforce
```

Ensuite, pour commencer le débogage, vous devez fermer tous les fichiers ouverts et sélectionner **Attach to Process...** dans l’onglet **Debug** :

![DNSpy Logging - DNSpy Debugging : Ensuite, pour commencer le débogage, vous devez fermer tous les fichiers ouverts et sélectionner Attach to Process dans l’onglet Debug](<../../images/image (318).png>)

Sélectionnez ensuite **w3wp.exe** pour l’attacher au **serveur IIS**, puis cliquez sur **attach** :

![DNSpy Logging - DNSpy Debugging : Sélectionnez ensuite w3wp.exe pour l’attacher au serveur IIS, puis cliquez sur attach](<../../images/image (113).png>)

Maintenant que nous déboguons le processus, il est temps de l’interrompre et de charger tous les modules. Cliquez d’abord sur _Debug >> Break All_, puis sur _**Debug >> Windows >> Modules**_ :

![DNSpy Logging - DNSpy Debugging : Maintenant que nous déboguons le processus, il est temps de l’interrompre et de charger tous les modules. Cliquez d’abord sur Debug Break All, puis sur Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging : Maintenant que nous déboguons le processus, il est temps de l’interrompre et de charger tous les modules. Cliquez d’abord sur Debug Break All, puis sur Debug Windows Modules](<../../images/image (834).png>)

Cliquez sur n’importe quel module dans **Modules**, puis sélectionnez **Open All Modules** :

![DNSpy Logging - DNSpy Debugging : Cliquez sur n’importe quel module dans Modules, puis sélectionnez Open All Modules](<../../images/image (922).png>)

Faites un clic droit sur n’importe quel module dans **Assembly Explorer**, puis cliquez sur **Sort Assemblies** :

![DNSpy Logging - DNSpy Debugging : Faites un clic droit sur n’importe quel module dans Assembly Explorer, puis cliquez sur Sort Assemblies](<../../images/image (339).png>)

## Décompilateur Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Déboguer des DLL

### Avec IDA

- **Charger rundll32** (64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- Sélectionner le débogueur **Windbg**
- Sélectionner "**Suspend on library load/unload**"

![Debugging DLLs - Avec IDA : Sélectionnez « Suspend on library load/unload »](<../../images/image (868).png>)

- Configurer les **paramètres** d’exécution en indiquant le **chemin de la DLL** et la fonction que vous souhaitez appeler :

![Debugging DLLs - Avec IDA : Configurez les paramètres d’exécution en indiquant le chemin de la DLL et la fonction que vous souhaitez appeler](<../../images/image (704).png>)

Ensuite, lorsque vous démarrez le débogage, **l’exécution s’interrompt au chargement de chaque DLL**. Ainsi, lorsque rundll32 charge votre DLL, l’exécution s’interrompt.

Cette méthode s’interrompt lors des événements de chargement de module, mais atteindre le point d’entrée de la DLL chargée est moins direct qu’avec le workflow x64dbg ci-dessous.

### Avec x64dbg/x32dbg

- **Charger rundll32** (64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- **Modifier la ligne de commande** ( _File --> Change Command Line_ ) et indiquer le chemin de la DLL et la fonction que vous souhaitez appeler, par exemple : "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Modifier _Options --> Settings_ et sélectionner "**DLL Entry**".
- **Démarrer ensuite l’exécution** : le débogueur s’interrompra à chaque DLL main. À un moment donné, vous **vous arrêterez dans le point d’entrée de votre DLL**. À partir de là, recherchez simplement les endroits où vous souhaitez placer un breakpoint.

Notez que lorsque l’exécution est interrompue pour une raison quelconque dans win64dbg, vous pouvez voir **dans quel code vous vous trouvez** en regardant **en haut de la fenêtre win64dbg** :

![Avec IDA - Avec x64dbg/x32dbg : Notez que lorsque l’exécution est interrompue pour une raison quelconque dans win64dbg, vous pouvez voir dans quel code vous vous trouvez en regardant en haut de la fenêtre win64dbg](<../../images/image (842).png>)

Cet indicateur confirme que l’exécution s’est interrompue dans la DLL que vous souhaitez déboguer.

## Applications GUI / jeux vidéo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où sont enregistrées les valeurs importantes dans la mémoire d’un jeu en cours d’exécution et les modifier. Plus d’informations dans :


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) est une interface front-end/un outil de reverse engineering pour le GNU Project Debugger (GDB), axé sur les jeux. Il peut toutefois être utilisé pour toute tâche liée au reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) est une interface web regroupant plusieurs décompilateurs. Ce service web vous permet de comparer les résultats de différents décompilateurs sur de petits exécutables.

## ARM et MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Déboguer un shellcode avec blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alloue le **shellcode**, affiche son **adresse mémoire** et suspend l’exécution.\
Attachez un débogueur tel qu’IDA ou x64dbg, placez un breakpoint à l’adresse affichée et reprenez l’exécution pour déboguer le shellcode.

La page des releases sur GitHub contient des fichiers ZIP avec les versions compilées : [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Vous trouverez une version légèrement modifiée de Blobrunner dans le lien suivant. Pour la compiler, **créez simplement un projet C/C++ dans Visual Studio Code, copiez-collez le code et compilez-le**.


{{#ref}}
blobrunner.md
{{#endref}}

### Déboguer un shellcode avec jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) est similaire à BlobRunner. Il alloue le shellcode et entre dans une boucle infinie. Attachez le débogueur, reprenez l’exécution pendant **2 à 5 secondes**, interrompez-la dans cette boucle, puis avancez jusqu’à l’appel suivant qui transfère l’exécution au shellcode alloué.

![Débogueur interrompu dans la boucle infinie de jmp2it, juste avant l’appel au shellcode alloué](<../../images/image (509).png>)

Vous pouvez télécharger une version compilée de [jmp2it sur la page des releases](https://github.com/adamkramer/jmp2it/releases/).

### Déboguer un shellcode avec Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) est l’interface graphique de radare. Cutter permet d’émuler le shellcode et de l’inspecter dynamiquement.

Notez que Cutter permet de choisir « Open File » et « Open Shellcode ». Dans mon cas, lorsque j’ai ouvert le shellcode en tant que fichier, il l’a décompilé correctement, contrairement à l’ouverture en tant que shellcode :

![Cutter affichant différents résultats d’analyse à l’ouverture des mêmes octets en tant que fichier ou shellcode](<../../images/image (562).png>)

Pour démarrer l’émulation à l’endroit souhaité, définissez-y un bp ; apparemment, Cutter démarrera automatiquement l’émulation à cet endroit :

![Définition d’un breakpoint à l’entrée souhaitée du shellcode avant de démarrer l’émulation de Cutter](<../../images/image (589).png>)

![Émulateur Cutter interrompu au breakpoint sélectionné dans le shellcode](<../../images/image (387).png>)

Vous pouvez, par exemple, afficher la pile dans un dump hexadécimal :

![Affichage de la pile du shellcode émulé dans le dump hexadécimal de Cutter](<../../images/image (186).png>)

### Désobfusquer un shellcode et récupérer les fonctions exécutées

Vous pouvez essayer [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Il vous indiquera notamment **quelles fonctions** le shellcode utilise et s’il se **décode** en mémoire.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg dispose également d'un lanceur graphique permettant de sélectionner les options souhaitées et d'exécuter le shellcode

![Lanceur graphique de scDbg permettant de sélectionner les options d'émulation et de traçage du shellcode](<../../images/image (258).png>)

L'option **Create Dump** sauvegarde le shellcode final si celui-ci est modifié dynamiquement en mémoire (utile pour télécharger le shellcode décodé). Le **start offset** peut être utile pour démarrer le shellcode à un décalage précis. L'option **Debug Shell** permet de déboguer le shellcode à l'aide du terminal scDbg (cependant, je trouve que l'une des options expliquées précédemment est préférable, car elle permet d'utiliser Ida ou x64dbg).

### Désassemblage avec CyberChef

Téléversez votre fichier shellcode en entrée et utilisez la recette suivante pour le désassembler : [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Déobfuscation de l'obfuscation MBA

L'obfuscation **Mixed Boolean-Arithmetic (MBA)** dissimule des expressions simples telles que `x + y` derrière des formules qui combinent des opérateurs arithmétiques (`+`, `-`, `*`) et des opérateurs bit à bit (`&`, `|`, `^`, `~`, décalages). L'important est que ces identités ne sont généralement correctes qu'en **arithmétique modulaire à largeur fixe** : les retenues et les dépassements de capacité ont donc leur importance :

```c
(x ^ y) + 2 * (x & y) == x + y
```

Si vous simplifiez ce type d’expression à l’aide d’outils algébriques génériques, vous pouvez facilement obtenir un résultat erroné, car la sémantique de largeur en bits a été ignorée.<sup>[[1]](#references)</sup>

### Flux de travail pratique

1. **Conservez la largeur de bits d’origine** du code/IR décompilé ou transposé (`8/16/32/64` bits).
2. **Classez l’expression** avant d’essayer de la simplifier :
   - **Linéaire** : sommes pondérées d’atomes d’opérations bit à bit
   - **Semi-linéaire** : expression linéaire avec des masques constants tels que `x & 0xFF`
   - **Polynomiale** : présence de produits
   - **Mixte** : produits et logique bit à bit entremêlés, souvent avec des sous-expressions répétées
3. **Vérifiez chaque réécriture candidate** par des tests aléatoires ou une preuve SMT. Si l’équivalence ne peut pas être prouvée, conservez l’expression d’origine au lieu de faire une supposition.

### Contourner le flot de contrôle aplati avec une tranche d’exécution restreinte

Il est souvent inutile de reconstituer le graphe de flot de contrôle complet. En présence d’un aplatissement du flot de contrôle, de prédicats opaques, de grands dispatchers ou de code riche en MBA, suivez les références depuis les blobs chiffrés et les buffers de sortie jusqu’à la plus petite routine qui les transforme. Reproduisez ensuite uniquement cette tranche du flux de données, ou exécutez-la indépendamment ; le dispatcher ne fait pas partie de la solution requise si l’état pertinent peut être initialisé directement.<sup>[[7]](#references)</sup>

Voici un flux de travail pratique :<sup>[[7]](#references)</sup>

1. Répertoriez les sections exécutables et de données, les relocalisations et les références croisées. Extrayez les tables candidates depuis `.rodata` en préservant leur ordre des octets et la largeur de leurs éléments.
2. Identifiez la dernière routine qui écrit le texte en clair ou dans le buffer de sortie. Notez ses entrées, les tables référencées, les appels importés et l’état global requis.
3. Transposez uniquement ces opérations dans un modèle Python à largeur fixe. Si la tranche dépend encore d’un trop grand nombre d’éléments d’état, invoquez la routine avec Unicorn, QEMU ou un débogueur et interceptez les imports non pertinents au lieu d’émuler tout le programme.
4. Vérifiez que l’extracteur dérive réellement sa sortie du binaire fourni : supprimez les solutions de repli silencieuses, recherchez les réponses intégrées et exécutez-le sur des builds inédits comportant des chaînes, clés, identifiants, dispositions et graines d’obfuscation modifiés.

Voici quelques commandes utiles pour une première analyse :<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Détecter les expressions MBA qui dissimulent des constantes

Une expression d’octet apparemment dépendante de l’entrée peut annuler complètement celle-ci. Après avoir extrait ses tables, évaluez l’expression sur tout le domaine 8 bits ; un ensemble de sorties réduit à une seule valeur prouve que cet octet est constant, sans avoir à retrouver la machine à états environnante.<sup>[[7]](#references)</sup>

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

Conservez le masque final, car l’addition d’origine entraîne un bouclage à la largeur d’un octet. Pour un domaine plus large, demandez à un solveur SMT si `f(x1) != f(x2)` est satisfiable pour deux entrées symboliques de même largeur : `unsat` prouve l’invariance, tandis que `sat` fournit un contre-exemple et signifie que l’entrée ne peut pas être écartée.<sup>[[7]](#references)</sup>

#### Reconnaître le décodage lié à l’environnement

Les vérifications anti-analyse n’ont pas nécessairement besoin de provoquer une branche ou un crash. Un décodeur peut intégrer le résultat d’un capteur dans un bit de clé, une constante de prédicat opaque ou l’état d’un répartiteur aplati, continuer normalement et produire un texte en clair plausible mais erroné dans un émulateur. Par conséquent, corriger uniquement les branches d’échec visibles ne suffit pas ; suivez les dépendances des données depuis les sondes de l’environnement jusqu’à l’état du décodeur, comparez la même tranche sur l’appareil authentique et l’émulateur, et testez comment le forçage du résultat de chaque capteur modifie le tampon final.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) est un simplificateur MBA pratique pour l’analyse de malware et le reverse engineering de binaires protégés. Il classe l’expression et la dirige vers des pipelines spécialisés au lieu d’appliquer une passe de réécriture générique à tout.<sup>[[2]](#references)</sup>

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

- **Linear MBA** : CoBRA évalue l’expression sur des entrées booléennes, en déduit une signature et met en concurrence plusieurs méthodes de récupération, telles que le pattern matching, la conversion ANF et l’interpolation des coefficients.
- **Semilinear MBA** : les atomes masqués par des constantes sont reconstruits à l’aide d’une reconstruction par partitions de bits, afin que les régions masquées restent correctes.
- **Polynomial/Mixed MBA** : les produits sont décomposés en noyaux et les sous-expressions répétées peuvent être extraites dans des variables temporaires avant de simplifier la relation externe.

Exemple d’identité mixte qu’il vaut souvent la peine d’essayer de retrouver :

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Cela peut se réduire à :

```c
x * y
```

### Notes de reverse engineering

- Préférez exécuter CoBRA sur des **expressions IR levées** ou sur la sortie du décompilateur après avoir isolé le calcul exact.
- Utilisez explicitement `--bitwidth` lorsque l’expression provient d’opérations masquées ou de registres de faible largeur.
- Si vous avez besoin d’une étape de preuve plus rigoureuse, consultez les notes locales sur Z3 ici :


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA est également fourni sous forme de plugin **LLVM pass** (`libCobraPass.so`), utile pour normaliser du LLVM IR contenant beaucoup de MBA avant les passes d’analyse suivantes.
- Les résidus mixtes entre domaines sensibles aux retenues et non pris en charge doivent être considérés comme un signal indiquant qu’il faut conserver l’expression d’origine et analyser manuellement le chemin des retenues.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Cet obfuscateur remplace les opérations du programme par des séquences d’instructions basées sur `mov` et utilise la gestion des signaux et des exceptions pour modifier le flux de contrôle. Pour plus de détails :

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Pour les binaires pris en charge, [demovfuscator](https://github.com/kirschju/demovfuscator) peut désobfusquer le résultat. Il dépend de plusieurs autres outils.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Et [installez keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si vous participez à un **CTF, cette méthode de contournement pour trouver le flag** pourrait vous être très utile : [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Pour trouver le **point d'entrée**, recherchez les fonctions contenant `::main`, comme dans cet exemple :

![Trouver un point d'entrée Rust dans Ghidra en recherchant les noms de fonctions contenant le double deux-points suivi de main](<../../images/image (1080).png>)

Dans ce cas, le binaire s'appelait authenticator ; il est donc assez évident que c'est la fonction main intéressante.\
À partir du **nom** des **fonctions** appelées, recherchez-les sur **Internet** pour en savoir plus sur leurs **entrées** et leurs **sorties**.

### Récupérer les chaînes Rust depuis un firmware ELF

Dans les binaires **ELF Rust**, de nombreuses chaînes statiques ne sont pas référencées par des pointeurs terminés par NUL au format C. Une disposition courante de `rustc` est un **couple pointeur/longueur** dans **`.data.rel.ro`**, qui pointe vers les données réelles de la chaîne stockées dans **`.rodata`** :

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Cela signifie que `strings` ou l’analyse par défaut de Ghidra peut fusionner des chaînes adjacentes ou ne pas détecter du tout les références croisées.<sup>[[3]](#references)</sup>

Flux de travail rapide :

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Récupérez l’adresse virtuelle et la taille de **`.rodata`**.
2. Parcourez **`.data.rel.ro`** mot par mot.
3. Traitez toute valeur comprise dans la plage d’adresses de `.rodata` comme un pointeur de chaîne potentiel.
4. Traitez le mot suivant comme la longueur potentielle.
5. Appliquez des filtres de cohérence (par exemple, conservez les longueurs comprises entre **4** et **100** octets).
6. Lisez exactement `length` octets dans `.rodata` au lieu de parcourir les données jusqu’à `0x00`.

Logique minimale de l’extracteur :

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

C'est particulièrement utile pour le reverse engineering de firmware, car les chaînes Rust récupérées révèlent souvent des **routes HTTP, des noms RPC, des messages de journalisation, des assertions, des noms de fichiers, des clés de configuration, des gestionnaires de commandes et de la logique liée à l'authentification**.

Si Ghidra ne détecte pas ces chaînes, exécutez un script/plugin personnalisé qui applique la même heuristique et crée des données de type chaîne aux offsets `.rodata` référencés. Les outils `rust-strings` et `RustStrings.py` publiés par Pen Test Partners sont de bonnes références pour adapter cette approche à d'autres **tailles de mots, ordres des octets et organisations de sections**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Pour les binaires compilés avec Delphi, vous pouvez utiliser [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si vous devez faire le reverse engineering d'un binaire Delphi, je vous conseille d'utiliser le plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Appuyez sur **Alt+F7** dans IDA pour charger un plugin Python, puis sélectionnez le fichier du plugin.

Ce plugin exécute le binaire et résout dynamiquement les noms de fonctions au début du débogage. Après avoir démarré le débogage, appuyez de nouveau sur le bouton Start (le bouton vert ou f9) et un point d'arrêt se déclenchera au début du code réel.

Si vous appuyez sur un bouton dans l'application graphique, le débogueur peut s'arrêter dans la fonction appelée par ce bouton.

## Golang

Pour les binaires Go ordinaires, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) peut récupérer les structures du runtime et améliorer les noms de fonctions dans IDA. Chargez son plugin Python avec **Alt+F7**.

### Récupérer les métadonnées sans la table des symboles

Un exécutable Go dépouillé de ses symboles a toujours besoin des métadonnées du runtime pour associer les compteurs de programme aux fonctions. [GoReSym](https://github.com/mandiant/GoReSym) localise et analyse des structures telles que `pclntab` et `moduledata` à l'aide de code dérivé du runtime Go. Cela permet de récupérer les limites des fonctions, les noms, les chemins sources, les types et les détails de compilation sans dépendre de la table des symboles classique.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Un obfuscateur peut laisser ces structures utilisables tout en remplaçant les noms récupérés. Garble, par exemple, hache les identifiants et les chemins de packages, et supprime les informations de build, de module et de débogage.<sup>[[12]](#references)</sup> Le jeton de package obfusqué doit rester identique pour toutes les fonctions de ce package. Regroupez les fonctions selon le jeton répété, déduisez un package à partir de ses fonctions appelées, de ses chaînes et de ses API, puis propagez ce nom de package à l’ensemble du groupe.<sup>[[13]](#references)</sup>

### Récupérer les noms Garble avec GoResolver

[GoResolver](https://github.com/volexity/GoResolver) combine l’extraction des symboles d’exécution, la génération de références non obfusquées et la mise en correspondance des graphes de flot de contrôle (CFG). Suivez ces étapes :<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifiez la version du compilateur.** Essayez d’abord `BuildInfo` et les chaînes de version intégrées. Si l’obfuscateur les a supprimées, comparez des portions du runtime Go embarqué avec des runtimes de référence associés à chaque version. Lors des tests de Volexity, environ `2%` du runtime suffisaient pour distinguer les versions majeures de Go. Considérez cela comme une optimisation empirique, et non comme un seuil universel.<sup>[[13]](#references)</sup>
2. **Créez des références correspondantes.** Générez des binaires non obfusqués pour la version de Go identifiée, l’architecture cible et les bibliothèques probables. Une chaîne d’outils correspondante réduit les différences de CFG générées par le compilateur.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Comparez les fonctions.** GoGrapher met en correspondance les CFG des fonctions et produit des scores normalisés de `0.0` à `1.0`. La mise en correspondance des blocs de base repose sur une comparaison pondérée des instructions similaires. Les correspondances avec un niveau de confiance élevé associent les fonctions dont les noms ont été randomisés à leur implémentation non obfusquée. Des correspondances moins fiables peuvent tout de même identifier un package ou un module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Validez et importez.** Confirmez les noms proposés à l’aide des relations d’appel, des constantes, des chaînes et des effets secondaires, puis importez le rapport JSON avec le plugin GoResolver pour IDA ou Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Installez la chaîne d’outils et exécutez l’extracteur et le comparateur de graphes combinés :<sup>[[10]](#references)</sup>

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

Le seuil de correspondance significative par défaut est `0.9`. Les options `--extract` et `--graph` permettent d’isoler l’une ou l’autre étape, tandis que le comportement par défaut exécute les deux, car les métadonnées d’exécution récupérées et les éléments du CFG se complètent.<sup>[[10]](#references)</sup> Les scores du CFG sont heuristiques : l’inlining, les options de compilation, l’architecture et les différences de version des bibliothèques peuvent modifier la forme du graphe. Il vaut donc mieux conserver les fonctions non résolues que de leur attribuer des noms avec un faible niveau de confiance.<sup>[[13]](#references)</sup>

## Python compilé

Sur cette page, vous pouvez découvrir comment récupérer le code Python à partir d’un binaire ELF/EXE compilé en Python :

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Si vous obtenez le **binaire** d’un jeu GBA, vous pouvez utiliser différents outils pour l’**émuler** et le **déboguer** :

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Téléchargez la version de débogage_) - Inclut un débogueur avec interface
- [**mgba** ](https://mgba.io)- Inclut un débogueur CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

Dans [**no$gba**](https://problemkaputt.de/gba.htm), dans _**Options --> Emulation Setup --> Controls**_** **, vous pouvez voir comment appuyer sur les **boutons** de la Game Boy Advance.

![Configuration des commandes de no$gba affichant les correspondances des boutons de la Game Boy Advance](<../../images/image (581).png>)

Chaque **touche a une valeur** permettant de l’identifier :

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

Ainsi, dans ce type de programme, la partie intéressante sera **la façon dont le programme traite les entrées utilisateur**. À l’adresse **0x4000130**, vous trouverez la fonction courante : **KEYINPUT**.

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

Le dernier if vérifie que **`uVar4`** figure parmi les **dernières touches** et qu’il ne s’agit pas de la touche actuelle, ce qui correspond au relâchement d’un bouton (la touche actuelle est stockée dans **`uVar1`**).

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

Dans le code précédent, on voit que nous comparons **uVar1** (l’emplacement où se trouve la **valeur du bouton pressé**) à certaines valeurs :

- D’abord, on le compare à la **valeur 4** (bouton **SELECT**) : dans le challenge, ce bouton efface l’écran.
- Ensuite, on compare la valeur à **8** (bouton **START**) ; dans ce challenge, ce chemin vérifie si le code saisi est valide.
  - Dans ce cas, la variable **`DAT_030000d8`** est comparée à 0xf3 et, si les valeurs sont identiques, du code est exécuté.
- Dans tous les autres cas, un compteur (`DAT_030000d4`) est vérifié et incrémenté.\
  Tant que le compteur est inférieur à 8, les valeurs des touches pressées sont cumulées dans `DAT_030000d8`.

Ainsi, dans ce challenge, connaissant les valeurs des boutons, il fallait **appuyer sur une combinaison de moins de 8 touches dont la somme obtenue est égale à 0xf3.**

**Référence pour ce tutoriel :** [compte rendu archivé du challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cours

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Désobfuscation de binaires)

## References

- [1] [Simplifier l’obfuscation MBA avec CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Dépôt CoBRA de Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Décoder les chaînes Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - chaînes Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - Tutoriel de reversing GBA (archivé)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Vaincre le reverse engineering assisté par l’IA, ou du moins essayer](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Une approche de comparaison des graphes de flot de contrôle fondée sur la mise en correspondance des blocs de base](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mécanisme d’obfuscation de Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver : utiliser la similarité des graphes de flot de contrôle pour désobfusquer automatiquement les binaires Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
