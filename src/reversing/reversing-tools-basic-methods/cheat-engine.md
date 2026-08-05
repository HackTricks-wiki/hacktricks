# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où sont enregistrées les valeurs importantes dans la mémoire d'un jeu en cours d'exécution et les modifier.\
Lorsque vous le téléchargez et l'exécutez, un **tutorial** vous est **présenté** pour vous apprendre à utiliser l'outil. Si vous souhaitez apprendre à utiliser l'outil, il est fortement recommandé de le terminer.<sup>[[3]](#references)</sup>

## Que recherchez-vous ?

![Cheat Engine - What are you searching?: What are you searching?](<../../images/image (762).png>)

Cet outil est très utile pour trouver **où une valeur** (généralement un nombre) **est stockée dans la mémoire** d'un programme.\
**Les nombres** sont généralement stockés au format **4bytes**, mais vous pouvez également les trouver aux formats **double** ou **float**, ou vouloir rechercher quelque chose de **différent d'un nombre**. Pour cette raison, vous devez vous assurer de **sélectionner** ce que vous voulez **rechercher** :

![Cheat Engine - What are you searching?: Usually numbers are stored in 4bytes form, but you could also find them in double or float formats, or you may want to look for something...](<../../images/image (324).png>)

Vous pouvez également indiquer différents types de **recherches** :

![Cheat Engine - What are you searching?: Also you can indicate different types of searches](<../../images/image (311).png>)

Vous pouvez aussi cocher la case pour **arrêter le jeu pendant l'analyse de la mémoire** :

![Cheat Engine - What are you searching?: You can also check the box to stop the game while scanning the memory](<../../images/image (1052).png>)

### Raccourcis clavier

Dans _**Edit --> Settings --> Hotkeys**_, vous pouvez définir différents **raccourcis clavier** à diverses fins, comme **arrêter** le **jeu** (ce qui est très utile si, à un moment donné, vous souhaitez analyser la mémoire). D'autres options sont disponibles :

![What are you searching? - Hotkeys: In Edit -- Settings -- Hotkeys you can set different hotkeys for different purposes like stopping the game (which is quiet useful if at some point you...](<../../images/image (864).png>)

## Modifier la valeur

Une fois que vous avez **trouvé** où se trouve la **valeur** que vous **recherchez** (plus d'informations à ce sujet dans les étapes suivantes), vous pouvez la **modifier** en double-cliquant dessus, puis en double-cliquant sur sa valeur :

![Hotkeys - Modifying the value: Once you found where is the value you are looking for (more about this in the following steps) you can modify it double clicking it, then double clicking...](<../../images/image (563).png>)

Enfin, **cochez la case** pour appliquer la modification dans la mémoire :

![Hotkeys - Modifying the value: And finally marking the check to get the modification done in the memory](<../../images/image (385).png>)

La **modification** de la **mémoire** sera immédiatement **appliquée** (notez que tant que le jeu n'utilise pas à nouveau cette valeur, celle-ci **ne sera pas mise à jour dans le jeu**).

## Rechercher la valeur

Supposons qu'il existe une valeur importante (comme la vie de votre personnage) que vous souhaitez améliorer et que vous recherchez cette valeur dans la mémoire.

### À travers une modification connue

Supposons que vous recherchiez la valeur 100. Vous **effectuez un scan** en recherchant cette valeur et trouvez de nombreuses correspondances :

![Searching the value - Through a known change: Supposing you are looking for the value 100, you perform a scan searching for that value and you find a lot of coincidences](<../../images/image (108).png>)

Ensuite, vous faites quelque chose qui **modifie la valeur**, puis vous **arrêtez** le jeu et **effectuez un** **next scan** :

![Searching the value - Through a known change: Then, you do something so that value changes , and you stop the game and perform a next scan](<../../images/image (684).png>)

Cheat Engine recherchera les **valeurs** qui sont **passées de 100 à la nouvelle valeur**. Félicitations, vous avez **trouvé** l'**adresse** de la valeur recherchée et pouvez maintenant la modifier.\
_S'il reste plusieurs valeurs, faites à nouveau quelque chose pour modifier cette valeur, puis effectuez un autre « next scan » afin de filtrer les adresses._

### Valeur inconnue, modification connue

Dans le cas où vous **ne connaissez pas la valeur**, mais savez **comment la modifier** (et même de combien elle change), vous pouvez rechercher votre nombre.

Commencez par effectuer un scan de type « **Unknown initial value** » :

![Through a known change - Unknown Value, known change: So, start by performing a scan of type " Unknown initial value "](<../../images/image (890).png>)

Modifiez ensuite la valeur, indiquez **comment** la **valeur** a **changé** (dans mon cas, elle a diminué de 1), puis effectuez un **next scan** :

![Through a known change - Unknown Value, known change: Then, make the value change, indicate how the value changed (in my case it was decreased by 1) and perform a next scan](<../../images/image (371).png>)

Toutes les valeurs qui ont été modifiées de la manière sélectionnée vous seront **présentées** :

![Through a known change - Unknown Value, known change: You will be presented all the values that were modified in the selected way](<../../images/image (569).png>)

Une fois votre valeur trouvée, vous pouvez la modifier.

Notez qu'il existe **de nombreuses modifications possibles** et que vous pouvez effectuer ces **étapes autant de fois que nécessaire** pour filtrer les résultats :

![Through a known change - Unknown Value, known change: Note that there are a lot of possible changes and you can do these steps as much as you want to filter the results](<../../images/image (574).png>)

### Adresse mémoire aléatoire - Trouver le code

Jusqu'à présent, nous avons appris à trouver une adresse contenant une valeur, mais il est très probable que **cette adresse se trouve à des emplacements différents de la mémoire lors de différentes exécutions du jeu**. Voyons donc comment toujours trouver cette adresse.

À l'aide de certaines des astuces mentionnées, trouvez l'adresse à laquelle votre jeu actuel stocke la valeur importante. Ensuite (en arrêtant le jeu si vous le souhaitez), faites un **clic droit** sur l'**adresse** trouvée et sélectionnez « **Find out what accesses this address** » ou « **Find out what writes to this address** » :

![Unknown Value, known change - Random Memory Address - Finding the code: Using some of the mentioned tricks, find the address where your current game is storing the important value. Then...](<../../images/image (1067).png>)

La **première option** permet de savoir quelles **parties** du **code** **utilisent** cette **adresse** (ce qui est utile pour d'autres tâches, comme **savoir où vous pouvez modifier le code** du jeu).\
La **seconde option** est plus **spécifique** et sera plus utile ici, car nous souhaitons savoir **d'où cette valeur est écrite**.

Après avoir sélectionné l'une de ces options, le **debugger** sera **attaché** au programme et une nouvelle **fenêtre vide** apparaîtra. Jouez maintenant au **jeu** et **modifiez** cette **valeur** (sans redémarrer le jeu). La **fenêtre** devrait se **remplir** avec les **adresses** qui **modifient** la **valeur** :

![Unknown Value, known change - Random Memory Address - Finding the code: Once you have selected one of those options, the debugger will be attached to the program and a new empty window...](<../../images/image (91).png>)

Maintenant que vous avez trouvé l'adresse qui modifie la valeur, vous pouvez **modifier le code à votre convenance** (Cheat Engine permet de le modifier très rapidement pour y placer des NOPs) :

![Unknown Value, known change - Random Memory Address - Finding the code: Now that you found the address it's modifying the value you can modify the code at your pleasure (Cheat Engine...](<../../images/image (1057).png>)

Vous pouvez donc le modifier afin que le code n'affecte plus votre nombre ou l'affecte toujours de manière positive.

### Adresse mémoire aléatoire - Trouver le pointeur

En suivant les étapes précédentes, trouvez où se trouve la valeur qui vous intéresse. Ensuite, à l'aide de « **Find out what writes to this address** », déterminez quelle adresse écrit cette valeur et double-cliquez dessus pour afficher la vue du désassemblage :

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Following the previous steps, find where the value you are interested is. Then, using " Find out...](<../../images/image (1039).png>)

Effectuez ensuite un nouveau scan en **recherchant la valeur hexadécimale entre "\[]"** (la valeur de $edx dans ce cas) :

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Then, perform a new scan searching for the hex value between " ()" (the value of $edx in this case)](<../../images/image (994).png>)

(_Si plusieurs résultats apparaissent, vous devez généralement utiliser celui qui possède la plus petite adresse_)\
Nous avons maintenant **trouvé le pointeur qui modifiera la valeur qui nous intéresse**.

Cliquez sur « **Add Address Manually** » :

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Click on " Add Address Manually "](<../../images/image (990).png>)

Cliquez maintenant sur la case « Pointer » et ajoutez l'adresse trouvée dans la zone de texte (dans ce scénario, l'adresse trouvée dans l'image précédente était « Tutorial-i386.exe »+2426B0) :

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Now, click on the "Pointer" check box and add the found address in the text box (in this scenario,...](<../../images/image (392).png>)

(Notez que le premier champ « Address » est automatiquement renseigné à partir de l'adresse du pointeur que vous avez introduite.)

Cliquez sur OK et un nouveau pointeur sera créé :

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Click OK and a new pointer will be created](<../../images/image (308).png>)

Désormais, chaque fois que vous modifiez cette valeur, vous **modifiez la valeur importante, même si l'adresse mémoire où elle se trouve est différente**.

### Code Injection

Code injection est une technique qui consiste à injecter un morceau de code dans le processus cible, puis à rediriger l'exécution du code afin qu'elle passe par votre propre code (par exemple, vous donner des points au lieu de vous en retirer).

Supposons que vous ayez trouvé l'adresse qui soustrait 1 à la vie de votre joueur :

![Random Memory Address - Finding the pointer - Code Injection: So, imagine you have found the address that is subtracting 1 to the life of your player](<../../images/image (203).png>)

Cliquez sur Show disassembler pour afficher le **code désassemblé**.\
Cliquez ensuite sur **CTRL+a** pour ouvrir la fenêtre Auto assemble et sélectionnez _**Template --> Code Injection**_

![Random Memory Address - Finding the pointer - Code Injection: Then, click CTRL+a to invoke the Auto assemble window and select Template -- Code Injection](<../../images/image (902).png>)

Renseignez l'**adresse de l'instruction que vous souhaitez modifier** (elle est généralement remplie automatiquement) :

![Random Memory Address - Finding the pointer - Code Injection: Fill the address of the instruction you want to modify (this is usually autofilled)](<../../images/image (744).png>)

Un template sera généré :

![Random Memory Address - Finding the pointer - Code Injection: A template will be generated](<../../images/image (944).png>)

Insérez votre nouveau code assembly dans la section « **newmem** » et supprimez le code original de « **originalcode** » si vous ne souhaitez pas qu'il soit exécuté**.** Dans cet exemple, le code injecté ajoutera 2 points au lieu d'en soustraire 1 :

![Random Memory Address - Finding the pointer - Code Injection: So, insert your new assembly code in the " newmem " section and remove the original code from the " originalcode " if you...](<../../images/image (521).png>)

**Cliquez sur execute, puis sur les options suivantes, et votre code devrait être injecté dans le programme, modifiant le comportement de la fonctionnalité !**

## Fonctionnalités avancées de Cheat Engine 7.x (2023-2025)

Cheat Engine a continué d'évoluer depuis la version 7.0 et plusieurs fonctionnalités d'amélioration de l'utilisation et d'*offensive-reversing* ont été ajoutées. Elles sont extrêmement pratiques lors de l'analyse de logiciels modernes (et pas seulement de jeux !). Voici un **guide de terrain très condensé** des ajouts que vous utiliserez probablement le plus lors de travaux de red-team/CTF.<sup>[[1]](#references)</sup>

### Améliorations de Pointer Scanner 2
* `Pointers must end with specific offsets` et le nouveau curseur **Deviation** (≥7.4) réduisent considérablement les faux positifs lorsque vous effectuez un nouveau scan après une mise à jour. Utilisez-les avec la comparaison multi-map (`.PTR` → *Compare results with other saved pointer map*) pour obtenir un **base-pointer unique et résilient** en quelques minutes seulement.
* Raccourci de filtrage en masse : après le premier scan, appuyez sur `Ctrl+A → Space` pour tout sélectionner, puis sur `Ctrl+I` (inverser) pour désélectionner les adresses qui n'ont pas passé le nouveau scan.

### Ultimap 3 – Intel PT tracing
*À partir de la version 7.5, l'ancien Ultimap a été réimplémenté au-dessus de **Intel Processor-Trace (IPT)**.* Cela signifie que vous pouvez désormais enregistrer *chaque branche suivie par la cible* **sans effectuer de single-stepping** (uniquement en user-mode ; cela ne déclenchera pas la plupart des anti-debug gadgets).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Après quelques secondes, arrêtez la capture et utilisez **clic droit → Save execution list to file**. Combinez les adresses des branches avec une session `Find out what addresses this instruction accesses` pour localiser très rapidement les hotspots de la logique du jeu à haute fréquence.

### Templates `jmp` d’1 octet / auto-patch
La version 7.5 a introduit un stub JMP *d’un octet* (0xEB) qui installe un gestionnaire SEH et place un INT3 à l’emplacement d’origine. Il est généré automatiquement lorsque vous utilisez **Auto Assembler → Template → Code Injection** sur des instructions qui ne peuvent pas être patchées avec un saut relatif de 5 octets. Cela permet de créer des hooks « serrés » dans des routines packées ou soumises à des contraintes de taille.

### Stealth au niveau du kernel avec DBVM (AMD & Intel)
*DBVM* est l’hyperviseur Type-2 intégré à CE. Les builds récentes ont enfin ajouté la prise en charge d’**AMD-V/SVM**, ce qui permet d’utiliser `Driver → Load DBVM` sur des hôtes Ryzen/EPYC. DBVM permet de :
1. Créer des hardware breakpoints invisibles pour les vérifications Ring-3/anti-debug.
2. Lire/écrire dans des régions de la mémoire kernel pageable ou protégée, même lorsque le driver en user-mode est désactivé.
3. Effectuer des contournements d’attaques temporelles sans VM-EXIT (par exemple, interroger `rdtsc` depuis l’hyperviseur).

**Astuce :** DBVM refusera de se charger lorsque HVCI/Memory-Integrity est activé sur Windows 11 → désactivez-le ou démarrez une VM-host dédiée.

### Debugging distant / cross-platform avec **ceserver**
CE fournit désormais une réécriture complète de *ceserver* et peut s’attacher via TCP à des cibles **Linux, Android, macOS et iOS**. Un fork populaire intègre *Frida* afin de combiner l’instrumentation dynamique avec l’interface graphique de CE — idéal lorsque vous devez patcher des jeux Unity ou Unreal exécutés sur un téléphone :
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Pour le bridge Frida, voir `bb33bb/frida-ceserver` sur GitHub.<sup>[[2]](#references)</sup>

### Autres fonctionnalités remarquables
* **Patch Scanner** (MemView → Tools) – détecte les modifications inattendues du code dans les sections exécutables ; pratique pour l’analyse de malware.
* **Structure Dissector 2** – faites glisser une adresse → `Ctrl+D`, puis *Guess fields* pour évaluer automatiquement les structures C.
* **.NET & Mono Dissector** – meilleure prise en charge des jeux Unity ; appelez directement les méthodes depuis la console Lua de CE.
* **Big-Endian custom types** – scan/modification avec ordre des octets inversé (utile pour les émulateurs de consoles et les buffers de paquets réseau).
* **Autosave & tabs** pour les fenêtres AutoAssembler/Lua, ainsi que `reassemble()` pour réécrire des instructions sur plusieurs lignes.

### Notes d’installation et d’OPSEC (2024-2025)
* L’installateur officiel est accompagné d’**offres publicitaires** InnoSetup (`RAV`, etc.). **Cliquez toujours sur *Decline*** *ou compilez depuis les sources* pour éviter les PUPs. Les antivirus signaleront tout de même `cheatengine.exe` comme un *HackTool*, ce qui est attendu.
* Les drivers anti-cheat modernes (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) détectent la classe de fenêtre de CE, même lorsqu’elle est renommée. Exécutez votre copie de reversing **dans une VM jetable** ou après avoir désactivé le jeu en réseau.
* Si vous avez uniquement besoin d’un accès en user-mode, choisissez **`Settings → Extra → Kernel mode debug = off`** afin d’éviter de charger le driver non signé de CE, qui peut provoquer un BSOD sous Windows 11 24H2 avec Secure-Boot.

---

## Références

- [1] [Notes de version de Cheat Engine 7.5 (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [bridge cross-platform frida-ceserver](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- [3] Tutoriel Cheat Engine, terminez-le pour apprendre à débuter avec Cheat Engine

{{#include ../../banners/hacktricks-training.md}}
