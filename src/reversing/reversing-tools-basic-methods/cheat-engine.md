# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où des valeurs importantes sont enregistrées dans la mémoire d’un jeu en cours d’exécution et les modifier.\
Lorsque vous le téléchargez et l’exécutez, un **tutorial** vous est **présenté** pour vous apprendre à utiliser l’outil. Si vous souhaitez apprendre à utiliser l’outil, il est fortement recommandé de le terminer.

## Que recherchez-vous ?

![Cheat Engine - Que recherchez-vous ?: Que recherchez-vous ?](<../../images/image (762).png>)

Cet outil est très utile pour trouver **où une valeur** (généralement un nombre) **est stockée dans la mémoire** d’un programme.\
Les **nombres** sont généralement stockés au format **4bytes**, mais vous pouvez également les trouver aux formats **double** ou **float**, ou vouloir rechercher quelque chose de **différent d’un nombre**. Vous devez donc vous assurer de **sélectionner** ce que vous souhaitez **rechercher** :

![Cheat Engine - Que recherchez-vous ?: Les nombres sont généralement stockés au format 4bytes, mais vous pouvez également les trouver aux formats double ou float, ou vouloir rechercher quelque chose...](<../../images/image (324).png>)

Vous pouvez également indiquer différents types de **recherches** :

![Cheat Engine - Que recherchez-vous ?: Vous pouvez également indiquer différents types de recherches](<../../images/image (311).png>)

Vous pouvez aussi cocher la case pour **arrêter le jeu pendant le scan de la mémoire** :

![Cheat Engine - Que recherchez-vous ?: Vous pouvez aussi cocher la case pour arrêter le jeu pendant le scan de la mémoire](<../../images/image (1052).png>)

### Raccourcis clavier

Dans _**Edit --> Settings --> Hotkeys**_, vous pouvez définir différents **raccourcis clavier** pour différentes fonctions, comme **arrêter** le **jeu** (ce qui est très utile si vous souhaitez effectuer un scan de la mémoire à un moment donné). D’autres options sont disponibles :

![Que recherchez-vous ? - Raccourcis clavier : Dans Edit -- Settings -- Hotkeys, vous pouvez définir différents raccourcis clavier pour différentes fonctions, comme arrêter le jeu (ce qui est très utile si, à un moment donné, vous...](<../../images/image (864).png>)

## Modifier la valeur

Une fois que vous avez **trouvé** où se trouve la **valeur** que vous **recherchez** (nous y reviendrons dans les étapes suivantes), vous pouvez la **modifier** en double-cliquant dessus, puis en double-cliquant sur sa valeur :

![Raccourcis clavier - Modifier la valeur : Une fois que vous avez trouvé où se trouve la valeur que vous recherchez (nous y reviendrons dans les étapes suivantes), vous pouvez la modifier en double-cliquant dessus, puis en double-cliquant...](<../../images/image (563).png>)

Enfin, **cochez la case** pour appliquer la modification dans la mémoire :

![Raccourcis clavier - Modifier la valeur : Enfin, cochez la case pour appliquer la modification dans la mémoire](<../../images/image (385).png>)

La **modification** de la **mémoire** sera immédiatement **appliquée** (notez que tant que le jeu n’utilise pas à nouveau cette valeur, celle-ci **ne sera pas mise à jour dans le jeu**).

## Rechercher la valeur

Supposons qu’il existe une valeur importante (comme la vie de votre personnage) que vous souhaitez augmenter et que vous recherchiez cette valeur dans la mémoire.

### À travers une modification connue

Supposons que vous recherchez la valeur 100. Vous **effectuez un scan** en recherchant cette valeur et trouvez de nombreuses correspondances :

![Rechercher la valeur - À travers une modification connue : Supposons que vous recherchez la valeur 100, vous effectuez un scan en recherchant cette valeur et trouvez de nombreuses correspondances](<../../images/image (108).png>)

Ensuite, vous faites quelque chose qui entraîne une **modification de la valeur**, puis vous **arrêtez** le jeu et **effectuez un nouveau scan** :

![Rechercher la valeur - À travers une modification connue : Ensuite, vous faites quelque chose qui entraîne une modification de la valeur, puis vous arrêtez le jeu et effectuez un nouveau scan](<../../images/image (684).png>)

Cheat Engine recherchera les **valeurs** qui sont **passées de 100 à la nouvelle valeur**. Félicitations, vous avez **trouvé** l’**adresse** de la valeur recherchée et pouvez maintenant la modifier.\
_S’il reste plusieurs valeurs, effectuez à nouveau une action pour modifier cette valeur, puis réalisez un autre « next scan » afin de filtrer les adresses._

### Valeur inconnue, modification connue

Dans le cas où vous **ignorez la valeur**, mais savez **comment la faire changer** (et même de combien), vous pouvez rechercher votre nombre.

Commencez par effectuer un scan de type « **Unknown initial value** » :

![À travers une modification connue - Valeur inconnue, modification connue : Commencez par effectuer un scan de type « Unknown initial value »](<../../images/image (890).png>)

Faites ensuite changer la valeur, indiquez **comment** la **valeur** a changé (dans mon cas, elle a diminué de 1), puis effectuez un **nouveau scan** :

![À travers une modification connue - Valeur inconnue, modification connue : Faites ensuite changer la valeur, indiquez comment la valeur a changé (dans mon cas, elle a diminué de 1), puis effectuez un nouveau scan](<../../images/image (371).png>)

Toutes les valeurs qui ont été modifiées de la manière sélectionnée vous seront **présentées** :

![À travers une modification connue - Valeur inconnue, modification connue : Toutes les valeurs qui ont été modifiées de la manière sélectionnée vous seront présentées](<../../images/image (569).png>)

Une fois votre valeur trouvée, vous pouvez la modifier.

Notez qu’il existe de **nombreuses modifications possibles** et que vous pouvez répéter ces **étapes autant de fois que nécessaire** pour filtrer les résultats :

![À travers une modification connue - Valeur inconnue, modification connue : Notez qu’il existe de nombreuses modifications possibles et que vous pouvez répéter ces étapes autant de fois que nécessaire pour filtrer les résultats](<../../images/image (574).png>)

### Adresse mémoire aléatoire - Trouver le code

Jusqu’à présent, nous avons appris à trouver une adresse stockant une valeur, mais il est très probable que **l’adresse soit située à un emplacement différent de la mémoire lors de différentes exécutions du jeu**. Voyons donc comment toujours trouver cette adresse.

À l’aide de certaines des techniques mentionnées, trouvez l’adresse où votre jeu actuel stocke la valeur importante. Ensuite (en arrêtant le jeu si vous le souhaitez), faites un **clic droit** sur l’**adresse** trouvée et sélectionnez « **Find out what accesses this address** » ou « **Find out what writes to this address** » :

![Valeur inconnue, modification connue - Adresse mémoire aléatoire - Trouver le code : À l’aide de certaines des techniques mentionnées, trouvez l’adresse où votre jeu actuel stocke la valeur importante. Ensuite...](<../../images/image (1067).png>)

La **première option** permet de savoir quelles **parties** du **code** utilisent cette **adresse** (ce qui est utile pour d’autres tâches, comme **savoir où modifier le code** du jeu).\
La **seconde option** est plus **spécifique** et sera plus utile dans ce cas, car nous souhaitons savoir **d’où cette valeur est écrite**.

Après avoir sélectionné l’une de ces options, le **debugger** sera **attaché** au programme et une nouvelle **fenêtre vide** apparaîtra. Jouez maintenant au **jeu** et **modifiez** cette **valeur** (sans redémarrer le jeu). La **fenêtre** devrait se **remplir** avec les **adresses** qui **modifient** la **valeur** :

![Valeur inconnue, modification connue - Adresse mémoire aléatoire - Trouver le code : Après avoir sélectionné l’une de ces options, le debugger sera attaché au programme et une nouvelle fenêtre vide...](<../../images/image (91).png>)

Maintenant que vous avez trouvé l’adresse qui modifie la valeur, vous pouvez **modifier le code à votre convenance** (Cheat Engine permet de le modifier très rapidement avec des NOPs) :

![Valeur inconnue, modification connue - Adresse mémoire aléatoire - Trouver le code : Maintenant que vous avez trouvé l’adresse qui modifie la valeur, vous pouvez modifier le code à votre convenance (Cheat Engine...](<../../images/image (1057).png>)

Vous pouvez donc le modifier afin que le code n’affecte pas votre nombre ou l’affecte toujours de manière positive.

### Adresse mémoire aléatoire - Trouver le pointeur

En suivant les étapes précédentes, trouvez où se situe la valeur qui vous intéresse. Ensuite, en utilisant « **Find out what writes to this address** », trouvez quelle adresse écrit cette valeur et double-cliquez dessus pour obtenir la vue du désassemblage :

![Adresse mémoire aléatoire - Trouver le code - Adresse mémoire aléatoire - Trouver le pointeur : En suivant les étapes précédentes, trouvez où se situe la valeur qui vous intéresse. Ensuite, en utilisant « Find out...](<../../images/image (1039).png>)

Effectuez ensuite un nouveau scan en **recherchant la valeur hexadécimale entre « \[] »** (la valeur de $edx dans ce cas) :

![Adresse mémoire aléatoire - Trouver le code - Adresse mémoire aléatoire - Trouver le pointeur : Effectuez ensuite un nouveau scan en recherchant la valeur hexadécimale entre « () » (la valeur de $edx dans ce cas)](<../../images/image (994).png>)

(_Si plusieurs résultats apparaissent, vous devez généralement choisir celui ayant la plus petite adresse_)\
Nous avons maintenant **trouvé le pointeur qui modifiera la valeur qui nous intéresse**.

Cliquez sur « **Add Address Manually** » :

![Adresse mémoire aléatoire - Trouver le code - Adresse mémoire aléatoire - Trouver le pointeur : Cliquez sur « Add Address Manually »](<../../images/image (990).png>)

Cliquez ensuite sur la case « Pointer » et ajoutez l’adresse trouvée dans la zone de texte (dans ce scénario, l’adresse trouvée dans l’image précédente était « Tutorial-i386.exe »+2426B0) :

![Adresse mémoire aléatoire - Trouver le code - Adresse mémoire aléatoire - Trouver le pointeur : Cliquez ensuite sur la case « Pointer » et ajoutez l’adresse trouvée dans la zone de texte (dans ce scénario,...](<../../images/image (392).png>)

(Notez que le premier champ « Address » est automatiquement rempli à partir de l’adresse du pointeur que vous saisissez.)

Cliquez sur OK : un nouveau pointeur sera créé :

![Adresse mémoire aléatoire - Trouver le code - Adresse mémoire aléatoire - Trouver le pointeur : Cliquez sur OK : un nouveau pointeur sera créé](<../../images/image (308).png>)

Désormais, chaque fois que vous modifiez cette valeur, vous **modifiez la valeur importante, même si l’adresse mémoire où elle se trouve est différente**.

### Code Injection

Code injection est une technique qui consiste à injecter un morceau de code dans le processus cible, puis à rediriger l’exécution du code afin qu’elle passe par votre propre code (par exemple, vous attribuer des points au lieu de vous en retirer).

Supposons que vous avez trouvé l’adresse qui soustrait 1 à la vie de votre joueur :

![Adresse mémoire aléatoire - Trouver le pointeur - Code Injection : Supposons que vous avez trouvé l’adresse qui soustrait 1 à la vie de votre joueur](<../../images/image (203).png>)

Cliquez sur Show disassembler pour obtenir le **code désassemblé**.\
Cliquez ensuite sur **CTRL+a** pour ouvrir la fenêtre Auto assemble et sélectionnez _**Template --> Code Injection**_

![Adresse mémoire aléatoire - Trouver le pointeur - Code Injection : Cliquez ensuite sur CTRL+a pour ouvrir la fenêtre Auto assemble et sélectionnez Template -- Code Injection](<../../images/image (902).png>)

Renseignez l’**adresse de l’instruction que vous souhaitez modifier** (ce champ est généralement rempli automatiquement) :

![Adresse mémoire aléatoire - Trouver le pointeur - Code Injection : Renseignez l’adresse de l’instruction que vous souhaitez modifier (ce champ est généralement rempli automatiquement)](<../../images/image (744).png>)

Un template sera généré :

![Adresse mémoire aléatoire - Trouver le pointeur - Code Injection : Un template sera généré](<../../images/image (944).png>)

Insérez donc votre nouveau code assembly dans la section « **newmem** » et supprimez le code original de la section « **originalcode** » si vous ne souhaitez pas qu’il soit exécuté**.** Dans cet exemple, le code injecté ajoutera 2 points au lieu d’en soustraire 1 :

![Adresse mémoire aléatoire - Trouver le pointeur - Code Injection : Insérez donc votre nouveau code assembly dans la section « newmem » et supprimez le code original de la section « originalcode » si vous...](<../../images/image (521).png>)

**Cliquez sur execute, puis sur les options suivantes, et votre code devrait être injecté dans le programme, modifiant le comportement de la fonctionnalité !**

## Fonctionnalités avancées de Cheat Engine 7.x (2023-2025)

Cheat Engine a continué d’évoluer depuis la version 7.0 et plusieurs fonctionnalités d’ergonomie ainsi que des fonctionnalités d’*offensive-reversing* ont été ajoutées. Elles sont extrêmement pratiques lors de l’analyse de logiciels modernes (et pas uniquement de jeux !). Voici un **guide pratique très condensé** des ajouts que vous utiliserez probablement le plus lors de travaux de red-team/CTF.<sup>[[1]](#references)</sup>

### Améliorations de Pointer Scanner 2
* `Pointers must end with specific offsets` et le nouveau curseur **Deviation** (≥7.4) réduisent considérablement les faux positifs lors d’un nouveau scan après une mise à jour. Utilisez-les avec la comparaison multi-cartes (`.PTR` → *Compare results with other saved pointer map*) afin d’obtenir un **base-pointer unique et résilient** en seulement quelques minutes.
* Raccourci de filtrage groupé : après le premier scan, appuyez sur `Ctrl+A → Space` pour tout sélectionner, puis sur `Ctrl+I` (inverser) pour désélectionner les adresses qui ont échoué au nouveau scan.

### Ultimap 3 – traçage Intel PT
*À partir de la version 7.5, l’ancien Ultimap a été réimplémenté au-dessus de **Intel Processor-Trace (IPT)**.* Cela signifie que vous pouvez désormais enregistrer *chaque branche suivie par la cible* **sans effectuer d’exécution pas à pas** (uniquement en user-mode ; cela ne déclenchera pas la plupart des mécanismes anti-debug).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Après quelques secondes, arrêtez la capture et faites un **clic droit → Save execution list to file**. Combinez les adresses des branches avec une session `Find out what addresses this instruction accesses` pour localiser extrêmement rapidement les hotspots de la logique du jeu à haute fréquence.

### Templates `jmp` d’1 octet / auto-patch
La version 7.5 a introduit un stub JMP d’*un octet* (0xEB) qui installe un gestionnaire SEH et place un INT3 à l’emplacement d’origine. Il est généré automatiquement lorsque vous utilisez **Auto Assembler → Template → Code Injection** sur des instructions qui ne peuvent pas être patchées avec un saut relatif de 5 octets. Cela permet de créer des hooks « tight » au sein de routines packées ou limitées en taille.<sup>[[1]](#references)</sup>

### Stealth au niveau kernel avec DBVM (AMD & Intel)
*DBVM* est l’hyperviseur Type-2 intégré à CE. Les builds récentes ont enfin ajouté la prise en charge d’**AMD-V/SVM**, ce qui permet d’exécuter `Driver → Load DBVM` sur des hôtes Ryzen/EPYC. DBVM vous permet de :
1. Créer des hardware breakpoints invisibles pour les vérifications Ring-3/anti-debug.
2. Lire/écrire dans des régions de mémoire kernel paginables ou protégées, même lorsque le driver user-mode est désactivé.
3. Effectuer des contournements d’attaques temporelles sans VM-EXIT (par exemple, interroger `rdtsc` depuis l’hyperviseur).

**Conseil :** DBVM refusera de se charger lorsque HVCI/Memory-Integrity est activé sur Windows 11 → désactivez-le ou démarrez une VM-host dédiée.

### Debugging distant / cross-platform avec **ceserver**
CE fournit désormais une réécriture complète de *ceserver* et peut s’attacher via TCP à des cibles **Linux, Android, macOS & iOS**. Un fork populaire intègre *Frida* afin de combiner l’instrumentation dynamique avec l’interface graphique de CE — idéal lorsque vous devez patcher des jeux Unity ou Unreal exécutés sur un téléphone :
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Pour le bridge Frida, consultez `bb33bb/frida-ceserver` sur GitHub.<sup>[[1]](#references)[[2]](#references)</sup>

### Autres fonctionnalités notables
* **Patch Scanner** (MemView → Tools) – détecte les modifications inattendues du code dans les sections exécutables ; utile pour l’analyse de malware.
* **Structure Dissector 2** – faites glisser une adresse → `Ctrl+D`, puis *Guess fields* pour évaluer automatiquement les structures C.
* **.NET & Mono Dissector** – meilleure prise en charge des jeux Unity ; appelez directement les méthodes depuis la console CE Lua.
* **Big-Endian custom types** – scan/édition avec ordre des octets inversé (utile pour les émulateurs de consoles et les buffers de paquets réseau).
* **Autosave & tabs** pour les fenêtres AutoAssembler/Lua, ainsi que `reassemble()` pour réécrire des instructions sur plusieurs lignes.<sup>[[1]](#references)</sup>

### Notes d’installation et d’OPSEC (2024-2025)
* L’installateur officiel est fourni avec des **offres publicitaires** InnoSetup (`RAV`, etc.). **Cliquez toujours sur *Decline*** *ou compilez depuis les sources* afin d’éviter les PUPs. Les antivirus signaleront toujours `cheatengine.exe` comme un *HackTool*, ce qui est normal.
* Les pilotes anti-cheat modernes (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) détectent la classe de fenêtre de CE, même lorsqu’elle est renommée. Exécutez votre copie de reversing **dans une VM jetable** ou après avoir désactivé le jeu en réseau.
* Si vous avez uniquement besoin d’un accès en user-mode, choisissez **`Settings → Extra → Kernel mode debug = off`** afin d’éviter le chargement du pilote non signé de CE, qui peut provoquer un BSOD sous Windows 11 24H2 avec Secure-Boot.

---

## References

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)

{{#include ../../banners/hacktricks-training.md}}
