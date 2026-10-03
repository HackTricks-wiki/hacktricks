# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où sont enregistrées les valeurs importantes dans la mémoire d'un jeu en cours d'exécution et les modifier.\
Lorsque vous le téléchargez et l'exécutez, un **tutorial** vous est **présenté** pour vous apprendre à utiliser l'outil. Si vous voulez apprendre à utiliser l'outil, il est fortement recommandé de le terminer.

## Que recherchez-vous ?

![Cheat Engine - Que recherchez-vous ?: Que recherchez-vous ?](<../../images/image (762).png>)

Cet outil est très utile pour trouver **où une valeur** (généralement un nombre) **est stockée dans la mémoire** d'un programme.\
Les **nombres** sont généralement stockés sous forme de **4bytes**, mais vous pouvez également les trouver aux formats **double** ou **float**, ou rechercher quelque chose de **différent d'un nombre**. Vous devez donc vous assurer de **sélectionner** ce que vous souhaitez **rechercher** :

![Cheat Engine - Que recherchez-vous ?: Les nombres sont généralement stockés sous forme de 4bytes, mais vous pouvez également les trouver aux formats double ou float, ou rechercher quelque chose...](<../../images/image (324).png>)

Vous pouvez également indiquer différents types de **recherches** :

![Cheat Engine - Que recherchez-vous ?: Vous pouvez également indiquer différents types de recherches](<../../images/image (311).png>)

Vous pouvez aussi cocher la case pour **arrêter le jeu pendant l'analyse de la mémoire** :

![Cheat Engine - Que recherchez-vous ?: Vous pouvez aussi cocher la case pour arrêter le jeu pendant l'analyse de la mémoire](<../../images/image (1052).png>)

### Raccourcis clavier

Dans _**Edit --> Settings --> Hotkeys**_, vous pouvez définir différents **raccourcis clavier** pour diverses fonctions, comme **arrêter** le **jeu** (ce qui est très utile si vous souhaitez analyser la mémoire à un moment donné). D'autres options sont disponibles :

![Que recherchez-vous ? - Raccourcis clavier : Dans Edit -- Settings -- Hotkeys, vous pouvez définir différents raccourcis clavier pour diverses fonctions, comme arrêter le jeu (ce qui est très utile si, à un moment donné,...](<../../images/image (864).png>)

## Modification de la valeur

Une fois que vous avez **trouvé** où se trouve la **valeur** que vous **cherchez** (voir les étapes suivantes pour plus d'informations), vous pouvez la **modifier** en double-cliquant dessus, puis en double-cliquant sur sa valeur :

![Raccourcis clavier - Modification de la valeur : Une fois que vous avez trouvé où se trouve la valeur que vous cherchez (voir les étapes suivantes pour plus d'informations), vous pouvez la modifier en double-cliquant dessus, puis en double-cliquant...](<../../images/image (563).png>)

Enfin, **cochez la case** pour appliquer la modification dans la mémoire :

![Raccourcis clavier - Modification de la valeur : Enfin, cochez la case pour appliquer la modification dans la mémoire](<../../images/image (385).png>)

La **modification** de la **mémoire** sera immédiatement **appliquée** (notez que tant que le jeu n'utilise pas à nouveau cette valeur, celle-ci **ne sera pas mise à jour dans le jeu**).

## Recherche de la valeur

Supposons qu'il existe une valeur importante (comme la vie de votre personnage) que vous souhaitez augmenter et que vous recherchez cette valeur en mémoire.

### Grâce à une modification connue

Supposons que vous recherchiez la valeur 100. Vous **effectuez une analyse** en recherchant cette valeur et trouvez de nombreuses correspondances :

![Recherche de la valeur - Grâce à une modification connue : Supposons que vous recherchiez la valeur 100. Vous effectuez une analyse en recherchant cette valeur et trouvez de nombreuses correspondances](<../../images/image (108).png>)

Ensuite, vous faites quelque chose qui **modifie la valeur**, puis vous **arrêtez** le jeu et **effectuez une nouvelle analyse** :

![Recherche de la valeur - Grâce à une modification connue : Ensuite, vous faites quelque chose qui modifie la valeur, puis vous arrêtez le jeu et effectuez une nouvelle analyse](<../../images/image (684).png>)

Cheat Engine recherchera les **valeurs** qui sont **passées de 100 à la nouvelle valeur**. Félicitations, vous avez **trouvé** l'**adresse** de la valeur recherchée ; vous pouvez maintenant la modifier.\
_S'il reste plusieurs valeurs, effectuez une nouvelle action pour modifier cette valeur, puis effectuez une autre « nouvelle analyse » afin de filtrer les adresses._

### Valeur inconnue, modification connue

Dans le cas où vous **ne connaissez pas la valeur**, mais savez **comment la modifier** (et même de combien elle est modifiée), vous pouvez rechercher ce nombre.

Commencez par effectuer une analyse de type **« Unknown initial value »** :

![Grâce à une modification connue - Valeur inconnue, modification connue : Commencez par effectuer une analyse de type « Unknown initial value »](<../../images/image (890).png>)

Modifiez ensuite la valeur, indiquez **comment** la **valeur** a **changé** (dans mon cas, elle a diminué de 1), puis effectuez une **nouvelle analyse** :

![Grâce à une modification connue - Valeur inconnue, modification connue : Modifiez ensuite la valeur, indiquez comment la valeur a changé (dans mon cas, elle a diminué de 1), puis effectuez une nouvelle analyse](<../../images/image (371).png>)

Toutes les valeurs qui ont été modifiées de la manière sélectionnée vous seront présentées :

![Grâce à une modification connue - Valeur inconnue, modification connue : Toutes les valeurs qui ont été modifiées de la manière sélectionnée vous seront présentées](<../../images/image (569).png>)

Une fois votre valeur trouvée, vous pouvez la modifier.

Notez qu'il existe **de nombreuses modifications possibles** et que vous pouvez effectuer ces **étapes autant de fois que nécessaire** pour filtrer les résultats :

![Grâce à une modification connue - Valeur inconnue, modification connue : Notez qu'il existe de nombreuses modifications possibles et que vous pouvez effectuer ces étapes autant de fois que nécessaire pour filtrer les résultats](<../../images/image (574).png>)

### Adresse mémoire aléatoire - Trouver le code

Jusqu'à présent, nous avons appris à trouver une adresse qui stocke une valeur, mais il est très probable que **cette adresse se trouve à des emplacements différents de la mémoire lors de différentes exécutions du jeu**. Voyons donc comment toujours trouver cette adresse.

À l'aide de certaines des techniques mentionnées, trouvez l'adresse où votre jeu actuel stocke la valeur importante. Ensuite (en arrêtant le jeu si vous le souhaitez), faites un **clic droit** sur l'**adresse** trouvée et sélectionnez **« Find out what accesses this address »** ou **« Find out what writes to this address »** :

![Valeur inconnue, modification connue - Adresse mémoire aléatoire - Trouver le code : À l'aide de certaines des techniques mentionnées, trouvez l'adresse où votre jeu actuel stocke la valeur importante. Ensuite...](<../../images/image (1067).png>)

La **première option** permet de savoir quelles **parties** du **code** **utilisent** cette **adresse** (ce qui est utile pour d'autres tâches, comme **savoir où vous pouvez modifier le code** du jeu).\
La **seconde option** est plus **spécifique** et sera plus utile dans ce cas, car nous voulons savoir **d'où cette valeur est écrite**.

Après avoir sélectionné l'une de ces options, le **debugger** sera **attaché** au programme et une nouvelle **fenêtre vide** apparaîtra. Jouez maintenant au **jeu** et **modifiez** cette **valeur** (sans redémarrer le jeu). La **fenêtre** devrait se **remplir** avec les **adresses** qui **modifient** la **valeur** :

![Valeur inconnue, modification connue - Adresse mémoire aléatoire - Trouver le code : Après avoir sélectionné l'une de ces options, le debugger sera attaché au programme et une nouvelle fenêtre vide...](<../../images/image (91).png>)

Maintenant que vous avez trouvé l'adresse qui modifie la valeur, vous pouvez **modifier le code à votre guise** (Cheat Engine permet de le modifier très rapidement avec des NOPs) :

![Valeur inconnue, modification connue - Adresse mémoire aléatoire - Trouver le code : Maintenant que vous avez trouvé l'adresse qui modifie la valeur, vous pouvez modifier le code à votre guise (Cheat Engine...](<../../images/image (1057).png>)

Vous pouvez donc le modifier afin que le code n'affecte plus votre nombre ou qu'il l'affecte toujours de manière positive.

### Adresse mémoire aléatoire - Trouver le pointeur

En suivant les étapes précédentes, trouvez où se situe la valeur qui vous intéresse. Ensuite, utilisez **« Find out what writes to this address »** pour déterminer quelle adresse écrit cette valeur, puis double-cliquez dessus afin d'obtenir la vue de désassemblage :

![Adresse mémoire aléatoire - Trouver le code - Adresse mémoire aléatoire - Trouver le pointeur : En suivant les étapes précédentes, trouvez où se situe la valeur qui vous intéresse. Ensuite, utilisez « Find out...](<../../images/image (1039).png>)

Effectuez ensuite une nouvelle analyse en **recherchant la valeur hexadécimale entre "\[]"** (la valeur de $edx dans ce cas) :

![Adresse mémoire aléatoire - Trouver le code - Adresse mémoire aléatoire - Trouver le pointeur : Effectuez ensuite une nouvelle analyse en recherchant la valeur hexadécimale entre « \[] » (la valeur de $edx dans ce cas)](<../../images/image (994).png>)

(_S'il y en a plusieurs, vous devez généralement choisir celle qui possède la plus petite adresse_)\
Nous avons maintenant **trouvé le pointeur qui modifiera la valeur qui nous intéresse**.

Cliquez sur **« Add Address Manually »** :

![Adresse mémoire aléatoire - Trouver le code - Adresse mémoire aléatoire - Trouver le pointeur : Cliquez sur « Add Address Manually »](<../../images/image (990).png>)

Cliquez maintenant sur la case **« Pointer »** et ajoutez l'adresse trouvée dans la zone de texte (dans ce scénario, l'adresse trouvée dans l'image précédente était **« Tutorial-i386.exe»+2426B0** ) :

![Adresse mémoire aléatoire - Trouver le code - Adresse mémoire aléatoire - Trouver le pointeur : Cliquez maintenant sur la case « Pointer » et ajoutez l'adresse trouvée dans la zone de texte (dans ce scénario,...](<../../images/image (392).png>)

(Notez que le premier champ **« Address »** est automatiquement rempli à partir de l'adresse du pointeur que vous avez saisie.)

Cliquez sur OK : un nouveau pointeur sera créé :

![Adresse mémoire aléatoire - Trouver le code - Adresse mémoire aléatoire - Trouver le pointeur : Cliquez sur OK : un nouveau pointeur sera créé](<../../images/image (308).png>)

Désormais, chaque fois que vous modifiez cette valeur, vous **modifiez la valeur importante, même si l'adresse mémoire où elle se trouve est différente**.

### Code Injection

Code injection est une technique qui consiste à injecter un morceau de code dans le processus cible, puis à rediriger l'exécution du code afin qu'elle passe par votre propre code (par exemple, vous donner des points au lieu de vous en retirer).

Supposons que vous ayez trouvé l'adresse qui soustrait 1 à la vie de votre joueur :

![Adresse mémoire aléatoire - Trouver le pointeur - Code Injection : Supposons que vous ayez trouvé l'adresse qui soustrait 1 à la vie de votre joueur](<../../images/image (203).png>)

Cliquez sur **Show disassembler** pour afficher le **code désassemblé**.\
Cliquez ensuite sur **CTRL+a** pour ouvrir la fenêtre Auto assemble et sélectionnez _**Template --> Code Injection**_

![Adresse mémoire aléatoire - Trouver le pointeur - Code Injection : Cliquez ensuite sur CTRL+a pour ouvrir la fenêtre Auto assemble et sélectionnez Template -- Code Injection](<../../images/image (902).png>)

Renseignez l'**adresse de l'instruction que vous souhaitez modifier** (elle est généralement remplie automatiquement) :

![Adresse mémoire aléatoire - Trouver le pointeur - Code Injection : Renseignez l'adresse de l'instruction que vous souhaitez modifier (elle est généralement remplie automatiquement)](<../../images/image (744).png>)

Un template sera généré :

![Adresse mémoire aléatoire - Trouver le pointeur - Code Injection : Un template sera généré](<../../images/image (944).png>)

Insérez votre nouveau code assembly dans la section **« newmem »** et supprimez le code original de **« originalcode »** si vous ne voulez pas qu'il soit exécuté**.** Dans cet exemple, le code injecté ajoutera 2 points au lieu d'en soustraire 1 :

![Adresse mémoire aléatoire - Trouver le pointeur - Code Injection : Insérez votre nouveau code assembly dans la section « newmem » et supprimez le code original de « originalcode » si vous...](<../../images/image (521).png>)

**Cliquez sur execute, puis suivez les étapes suivantes : votre code devrait être injecté dans le programme et modifier le comportement de la fonctionnalité !**

## Code injection indépendant de la relocalisation avec des signatures AOB

Un script qui utilise `game.exe+123456` pour effectuer un hook peut cesser de fonctionner après l'activation d'ASLR ou une mise à jour logicielle. Une **signature Array of Bytes (AOB)** trouve l'instruction à partir du code machine qui l'entoure. Utilisez `aobscanmodule` pour limiter la recherche à un module. La signature doit être suffisamment longue pour ne renvoyer qu'une seule correspondance. Utilisez des wildcards pour les octets de relocalisation, les adresses et les autres octets susceptibles de changer. N'utilisez pas de wildcard pour l'ensemble de l'instruction que vous devez restaurer.<sup>[[4]](#references)</sup>

Dans Memory View, sélectionnez l'instruction et utilisez **Tools → Auto Assemble → Template → AOB Injection**. Le bloc `[DISABLE]` généré est important. Il doit restaurer chaque octet écrasé et libérer l'allocation.<sup>[[4]](#references)</sup>

<details>
<summary>Squelette minimal de code injection AOB x64</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

Avant d’activer le script, vérifiez les points suivants :

1. L’AOB renvoie **une seule** adresse. Ajoutez des instructions stables des deux côtés s’il en renvoie plusieurs.
2. Le jump remplace des instructions complètes. Ne scindez jamais une instruction.
3. La cave allouée est accessible par le jump généré. Sur x64, une allocation éloignée peut nécessiter un jump de 14 octets.
4. Le code injecté préserve les registres, les flags et l’alignement de la stack attendus par la fonction d’origine.
5. Le bloc de désactivation restaure exactement les octets d’origine. Testez plusieurs fois l’activation et la désactivation avant d’enregistrer la table.

## Workflow fiable pour les pointeurs

Un pointeur trouvé lors d’une exécution n’est qu’un candidat. Créez des pointer maps lors de plusieurs exécutions propres et effectuez un rescan avec toutes ces exécutions. Redémarrez la cible entre les captures afin que l’ASLR et les allocations du heap changent. Préférez les chemins dont la base est un module ou un autre symbole stable. Rejetez les chemins qui ne fonctionnent qu’avec une seule sauvegarde, un seul niveau ou une seule instance d’objet.

Le filtre **the pointer must end with specific offsets** et son option de déviation peuvent conserver des chemins utiles lorsqu’un champ proche se déplace entre les builds. La release 7.5 a également ajouté ce contrôle de déviation. Il s’agit d’un filtre, et non d’une preuve qu’une chaîne de pointeurs est stable.<sup>[[1]](#references)</sup>

Lorsqu’une structure se déplace trop souvent pour le pointer scanning, hookez l’instruction qui y accède. Capturez le pointeur vers l’objet actif depuis un registre dans un symbole alloué. Cette méthode est souvent plus fiable pour les listes d’entités et les objets managed.

## Tracer le code au lieu de scanner les valeurs

Utilisez **Find out what writes to this address** lorsque la valeur est directement modifiée. Utilisez **Find out what accesses this address** lorsque vous avez besoin de l’objet propriétaire ou lorsque l’écriture s’effectue via des données copiées. Déclenchez une seule action dans la cible. Comparez ensuite le nombre de hits et l’état des registres.

**Ultimap 2** utilise Intel Processor Trace sur les CPU Intel pris en charge. Il enregistre le control flow exécuté avec moins d’interruptions que le stepping de chaque instruction. Filtrez le code exécuté pendant l’action intéressante et supprimez le code également exécuté lors d’une capture inactive. Intel PT n’est pas une fonctionnalité de stealth. La cible peut toujours détecter le tracing, les changements de timing ou Cheat Engine lui-même.<sup>[[1]](#references)</sup>

Cheat Engine 7.5 a également ajouté une interface Intel PT fournie par Windows. L’ancien mode Ultimap basé sur DBVM et le mode Intel PT ont des exigences matérielles et système différentes. Ne supposez pas qu’un CPU compatible avec DBVM prend en charge Intel PT.<sup>[[1]](#references)</sup>

## Sélection du debugger et des breakpoints

Choisissez le debugger le moins intrusif qui fonctionne :

- **Windows debugger** est simple, mais il crée des événements de debug normaux. Les vérifications d’anti-debugging peuvent le détecter.
- **VEH debugger** gère les breakpoints via un gestionnaire d’exceptions vectorisé. Il évite certaines vérifications de debugger basiques, mais il n’est pas invisible.
- **Hardware breakpoints** ne modifient pas les octets des instructions, mais x86/x64 ne fournit qu’un petit nombre de slots dans les registres de debug.
- **Software breakpoints** remplacent un octet par `INT3`. Ils sont faciles à détecter et peuvent entrer en conflit avec les vérifications d’intégrité.
- **DBVM debugger** déplace certaines opérations sous le guest OS. Il dispose de beaucoup plus de privilèges et peut faire crasher l’host s’il est mal configuré.

Cheat Engine 7.5 peut utiliser un jump d’un octet basé sur un gestionnaire d’exceptions et `INT3` lorsqu’il n’y a pas assez de place pour un jump relatif normal. Considérez-le comme un software breakpoint. Vérifiez le flux des exceptions et ne supposez pas qu’il contourne les vérifications anti-tamper.<sup>[[1]](#references)</sup>

DBVM est un hyperviseur, pas un switch général d’invisibilité. Utilisez-le uniquement dans un lab disposable. N’exposez pas son interface de contrôle à du code non fiable. Les solutions kernel anti-cheat et endpoint peuvent toujours détecter le driver, l’état de l’hyperviseur ou la mémoire modifiée.

## Runtimes managed et fonctionnalités récentes des versions 7.6/7.7

Pour les cibles Mono, IL2CPP, .NET et Java, préférez les métadonnées du runtime aux scans aveugles lorsqu’elles sont disponibles. Ouvrez **Mono → Activate mono features** ou la fenêtre d’informations correspondante du runtime. Localisez d’abord la classe, le champ ou la méthode. Utilisez ensuite le désassemblage natif lorsque la méthode managed est compilée par le JIT.

La branche 7.6 a ajouté `AOBSCANEX` pour les signatures limitées à la mémoire exécutable, une interface de debugger `gdbserver`, l’inspection des métadonnées Java, une énumération IL2CPP plus rapide et une option de pointer scan qui ignore l’octet supérieur du pointeur utilisé par le memory tagging ARM. La branche 7.7 a ajouté des builds Linux natifs, `HOOK`/`UNHOOK`, `aobscanfunction`, une meilleure recherche des méthodes génériques Mono, une prise en charge améliorée des structures PDB et une dissection de base des structures Unreal Engine.<sup>[[3]](#references)</sup>

Ces ajouts permettent le workflow suivant :

1. Résoudre une méthode managed ou un champ static à partir des métadonnées.
2. Tracer ou désassembler le code natif produit pour cette méthode.
3. Utiliser `AOBSCANEX` ou `aobscanfunction` pour localiser une signature exécutable stable.
4. Générer un hook réversible. Conservez les instructions d’origine et validez le chemin de désactivation.
5. Revérifier la signature après chaque mise à jour de la cible. Une correspondance réussie ne garantit pas que la logique environnante conserve la même signification.

## Cibles distantes avec `ceserver`

`ceserver` expose l’énumération des processus, l’accès à la mémoire et le debugging à l’interface graphique de Cheat Engine. Les builds officielles couvrent Linux et Android. Exécutez l’architecture correspondante sur la cible et connectez-vous via l’onglet **Network**. Sur Android, le forwarding du port par défaut évite de l’exposer sur le réseau :<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
Le bridge tiers `frida-ceserver` peut fournir une interface compatible avec Cheat Engine pour les cibles iOS. Il ne s'agit pas du `ceserver` officiel et les opérations prises en charge peuvent différer.<sup>[[2]](#references)</sup>

Supposez que le protocole accorde un accès de niveau débogueur. Liez-le à loopback ou placez-le derrière un tunnel SSH/ADB. N'exposez jamais le port TCP 52736 à un réseau non fiable. Arrêtez le serveur lorsque la session se termine.

## Sécurité opérationnelle

Attachez-vous uniquement à des logiciels dont vous êtes propriétaire ou que vous êtes autorisé à tester. N'exécutez pas Cheat Engine à côté d'un jeu en ligne ou d'un endpoint de production. Les écritures mémoire, le code injecté, les drivers et DBVM peuvent faire crasher ou corrompre la cible.<sup>[[3]](#references)</sup>

Téléchargez les builds depuis le site officiel ou compilez le source publié. Les produits de sécurité classent souvent les memory editors, les debuggers et leurs drivers comme des hack tools. Ne désactivez pas globalement la protection de l'hôte. Utilisez une VM dédiée ou un hôte de laboratoire et vérifiez l'artefact avant de l'exécuter.<sup>[[3]](#references)</sup>



## References

- [1] [Notes de version de Cheat Engine 7.5](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [Bridge frida-ceserver pour les cibles distantes](https://github.com/gmh5225/frida-ceserver)
- [3] [Actualités officielles des versions de Cheat Engine](https://www.cheatengine.org/)
- [4] [Wiki de Cheat Engine : Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
