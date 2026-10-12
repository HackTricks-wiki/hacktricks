# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## Pourquoi le déroulement piloté par les métadonnées peut être usurpé

Certains outils de sécurité macOS délèguent la collecte des piles de threads à `/usr/sbin/spindump` ou font autrement confiance à un dérouleur conventionnel piloté par les métadonnées. Un implant peut exploiter cette limite de confiance en plaçant sur sa pile des enregistrements synthétiques conformes à l’ABI, de sorte qu’une API sensible semble avoir été appelée via des fonctions choisies par l’attaquant dans dyld et les frameworks Apple chargés, plutôt que depuis du code d’implant non adossé à un fichier. Il s’agit d’une tromperie de télémétrie, et non d’une modification de l’exécutable ou de ses métadonnées de déroulement.<sup>[[1]](#references)</sup>

Voir [macOS stackshots and `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) pour le contexte côté collecte.

Un dérouleur ne prouve pas qu’un prologue généré par le compilateur a créé un enregistrement. Il utilise de façon répétée le `PC` courant pour choisir une recette Mach-O, applique cette recette à `SP`, `x29`, `x30`, à la mémoire de la pile et à tous les registres non volatils déclarés, puis utilise le `PC` de l’appelant récupéré pour sélectionner la recette suivante. Si la mémoire contrôlée par l’attaquant satisfait chaque recette sélectionnée, la chaîne obtenue peut être structurellement valide et symbolisable, même si ces appels n’ont jamais eu lieu.<sup>[[1]](#references)</sup>

## État des frames ARM64

La [présentation de l’assembly ARM64](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) décrit le rôle des registres et la convention d’appel. Pour une frame conventionnelle créée avec `stp x29, x30, [sp, #-16]!`, suivi de `mov x29, sp`, l’adresse de frame canonique (CFA), qui représente le `SP` de l’appelant à son entrée, est `FP+0x10` :<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Les enregistrements de frame forment une liste chaînée via `[FP]`, mais suivre cette liste aveuglément ne suffit pas : les fonctions leaf peuvent être dépourvues de frame, les tail calls peuvent supprimer des transitions logiques et les dispositions inhabituelles utilisent le DWARF CFI. La recette déterminée par l’adresse courante indique si le dérouleur de pile lit la chaîne FP.<sup>[[1]](#references)[[4]](#references)</sup>

## Sélectionner une recette d’unwind Mach-O

Les images finales liées stockent les données compactes d’unwind dans `__TEXT,__unwind_info`. L’en-tête de section pointe vers un index de fonctions de premier niveau ; chaque plage d’index pointe vers une page de second niveau régulière (`kind=2`) ou compressée (`kind=3`). Les dispositions que l’unwind compact ne peut pas décrire utilisent un FDE et des instructions call-frame dans `__eh_frame`.<sup>[[1]](#references)[[2]](#references)</sup>

Pour chaque PC d’exécution candidat :<sup>[[1]](#references)[[2]](#references)</sup>

1. Retirer ou normaliser les bits PAC d’ARM64e pour la recherche uniquement.
2. Trouver le Mach-O chargé dont la plage exécutable `__TEXT` contient l’adresse.
3. Calculer `functionOffset = normalizedPC - loadedImageBase` et rejeter les résultats négatifs ou supérieurs à `UINT32_MAX`.
4. Sélectionner la plage de premier niveau qui satisfait `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`.
5. Analyser la page de second niveau référencée, choisir l’entrée la plus proche dont le début ne dépasse pas l’offset, puis vérifier que l’adresse est inférieure au début de l’entrée suivante ou à la fin de la plage de premier niveau.
6. Décoder cette entrée et construire l’état exact qu’elle décrit.

Lorsqu’une adresse provient d’un LR sauvegardé, la recherche peut utiliser `PC-1` afin qu’une adresse située juste après un appel reste dans la plage couverte par l’appelant. Cela modifie la sélection de la recette, pas un offset de pile.<sup>[[1]](#references)</sup>

Un analyseur doit vérifier les limites de chaque en-tête et tableau, exiger la version de section `1`, tenir compte du sentinelle final de premier niveau, rejeter un offset de page de second niveau nul et distinguer les pages régulières des pages compressées. Dans une page régulière, `entryPageOffset` est relatif au début de cette page, tandis que l’offset de page de premier niveau est relatif au début de `__unwind_info`.<sup>[[1]](#references)[[2]](#references)</sup>

Le mode général est `encoding & 0x0F000000`. Les définitions LLVM actuelles incluent les modes suivants ; un analyseur ne doit pas traiter toute valeur autre que DWARF comme une frame classique :<sup>[[1]](#references)[[2]](#references)</sup>

| Mode | Valeur | Récupération de l’appelant |
| --- | --- | --- |
| Aucune recette compacte | `0x00000000` | Arrêter ou utiliser une solution de repli indépendante. |
| Sans frame | `0x02000000` | Ajouter la taille de pile encodée au `SP` courant ; le PC de l’appelant est le LR actif. |
| DWARF | `0x03000000` | Exécuter le FDE/CFI identifié par les 24 bits de poids faible. |
| Frame | `0x04000000` | Lire l’enregistrement de frame conventionnel `x29`. |
| Frame arm64e avec plage de LR authentifiée | `0x05000000` | Gérer `UNWIND_ARM64_MODE_FRAME_PAUTH_LR` ; son champ d’offset situe `pacibsppc` dans la plage couverte. |

En mode sans frame, `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`. En mode frame, les cinq bits de poids faible indiquent les paires de GPR sauvegardées et contiguës, de `x19/x20` à `x27/x28` ; les bits `0x100-0x800` indiquent de la même façon les paires `d8-d15`. Ces registres sauvegardés ne sont pas forcément nécessaires pour trouver le PC suivant, mais un état virtuel d’appelant crédible doit respecter tous les champs reconstruits par le consommateur.<sup>[[1]](#references)[[2]](#references)</sup>

## Construire des enregistrements synthétiques en mode frame

Le processus de construction inverse le fonctionnement du dérouleur de pile au lieu de parcourir la pile à la recherche de valeurs ressemblant à des adresses :<sup>[[1]](#references)</sup>

1. Choisir un PC exécutable réel dans une image actuellement chargée.
2. Décoder la recette couvrant ce PC précis ou l’adresse du site d’appel.
3. Allouer un enregistrement synthétique avec l’alignement et la relation CFA requis.
4. Stocker le FP synthétique suivant à `[FP]`, le PC de l’appelant sauvegardé pour cette frame à `[FP+8]`, ainsi que chaque sauvegarde de GPR/FPR déclarée par l’encodage sous FP.
5. Chaîner plusieurs enregistrements et placer le premier dans le `x29` actif.
6. Organiser le LR actif et le chemin de retour de l’API de sorte que le déroulement de pile emprunte la chaîne choisie, tout en permettant une restauration sûre de l’exécution.

Par exemple, `0x04000001` signifie le mode frame avec la paire `x19/x20`. La transformation d’état correspondante et la mémoire requise sont les suivantes :<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

Une adresse qui semble légitime ne suffit donc pas. Chaque PC récupéré devient la clé de la recherche suivante : une seule adresse dont l’encodage ne correspond pas à la disposition fabriquée rompt la chaîne ou amène le consommateur à reconstruire un état des registres incohérent.<sup>[[1]](#references)</sup>

## Exigences PAC d’ARM64e

PAC stocke une valeur d’intégrité calculée avec une clé dans les bits autrement inutilisés du pointeur ; il ne chiffre pas l’adresse. Le schéma d’adresse de retour arm64e de Clang utilise la clé d’instruction B et le pointeur de pile à l’entrée de la fonction comme discriminateur. Dans une frame conventionnelle, ce `SP` d’entrée est le CFA ; le LR sauvegardé à `[FP+8]` est donc lié à `FP+0x10`.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Chaque LR synthétique doit être signé indépendamment, car déplacer un LR déjà signé vers un frame avec un CFA différent modifie le discriminateur et fait échouer l’authentification. `ptrauth_strip()` convient à la normalisation d’adresses et à la recherche de symboles, mais ne garantit **pas** l’authenticité ; tout retour réel ou branchement indirect authentifié doit utiliser la clé et le modificateur attendus lors de cette transition précise.<sup>[[1]](#references)[[3]](#references)</sup>

Une fonction arm64e typique qui n’est pas une fonction feuille signe LR avant de le stocker et l’authentifie après avoir restauré le SP d’entrée :<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline et bridge de restauration

Les enregistrements synthétiques doivent uniquement satisfaire l’unwinder ; ils ne contiennent pas un contexte d’exécution complet. Un retour direct depuis l’API sensible vers les appelants fabriqués provoquerait normalement un crash. La conception pratique place donc une frame de gadget immédiatement sous l’API : l’API retourne vers du code exécutable dans un framework chargé, et ce gadget effectue un branchement via un registre callee-saved contrôlé vers un bridge de restauration dans l’implant.<sup>[[1]](#references)</sup>

Un gadget utile préserve LR et effectue le transfert via un registre contrôlé, par exemple avec une séquence `br`, `braa` ou `brab` appropriée. Le bridge de restauration doit récupérer les valeurs originales de `x19-x30` et de `SP` avant de reprendre l’exécution de l’implant. Sur arm64e, chaque retour ou branchement authentifié dans le chemin API-gadget, gadget-bridge et bridge-implant nécessite un pointeur signé avec la clé et le discriminateur utilisés par cette instruction.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

Le résultat constitue une importante défaillance de la frontière de confiance pour les détections fondées sur la pile : une chaîne peut ne contenir que des PC mappés et symbolisables de frameworks Apple sans pour autant représenter le flux de contrôle réel. La sortie d’unwind doit donc être corroborée par des éléments indépendants concernant la provenance de la mémoire exécutable du thread et les transitions réelles autour de l’API sensible, plutôt que d’être considérée comme une trace d’exécution.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Internes de la pile ARM64 et obfuscation sur Apple Silicon](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Définitions de l’encodage compact unwind de Mach-O](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Authentification des pointeurs](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Norme d’appel de procédure pour l’architecture Arm 64 bits](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
