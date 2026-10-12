# Sécurité des assistants de preuve et de la vérification formelle

{{#include ../banners/hacktricks-training.md}}

Les assistants de preuve peuvent exécuter un même terme par plusieurs voies : réduction du kernel, interpréteur, code généré, primitives du runtime ou vérificateur externe. Une preuve n’est aussi solide que chacun des composants autorisés à contribuer des résultats considérés comme fiables. Dans Lean, les procédures de décision natives échangent une évaluation plus rapide contre une base informatique de confiance (TCB) plus étendue : le compilateur et les définitions dotées d’implémentations natives deviennent pertinents pour l’intégrité des preuves.<sup>[[3]](#references)</sup>

## Évaluation différentielle entre logique et code natif

Donnez la priorité aux primitives dont l’implémentation exécutable diffère de leur modèle logique (par exemple, les intrinsics du compilateur, les interfaces de fonctions étrangères, les redéfinitions du runtime et les définitions marquées avec `@[implemented_by]`). Évaluez différentiellement le **même terme fermé** par les voies logique et compilée, et considérez tout écart de valeur, d’exception ou de terminaison comme un problème de sécurité.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Les classes de valeurs limites utiles comprennent :<sup>[[1]](#references)[[4]](#references)</sup>

- les index autour de `0`, de la longueur de l’entrée, de la limite des mots machine et les valeurs telles que `2^63` ou supérieures ;
- les plages de zéro ou un octet, `start = end`, `start > end` et les positions bien au-delà de l’objet ;
- les entrées vides et non vides, les chaînes multioctets, les limites invalides et les opérations arithmétiques susceptibles d’être tronquées lors de la compilation ;
- les valeurs allouées sur le tas lorsqu’une primitive native a un comportement de propriété ou d’emprunt absent du modèle logique.

Le motif Lean réduit suivant illustre le problème trouvé dans `String.Pos.Raw.extract` : le code natif vulnérable renvoyait la chaîne d’origine pour une plage d’un octet de taille énorme, tandis que la réduction définitionnelle renvoyait la chaîne vide. Cette divergence sémantique a été corrigée séparément du problème connexe de sécurité mémoire.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

```lean
def value : String := "non-empty"
def startPos : String.Pos.Raw := ⟨2^63⟩
def endPos : String.Pos.Raw := ⟨2^63 + 1⟩

example : False := by
  have logical : String.Pos.Raw.extract value startPos endPos = "" := rfl
  have native : String.Pos.Raw.extract value startPos endPos = value := by
    native_decide
  exact (by decide) (logical.symm.trans native)
```

Ce schéma se généralise au-delà des chaînes de caractères : si l’évaluation logique prouve `E = A` et que l’évaluation native de confiance prouve `E = B`, la transitivité donne `A = B`. Lorsque `A` et `B` sont distincts par observation, cela permet de conclure `False` ; `False.elim` (le principe d’explosion) peut alors prouver n’importe quelle proposition cible. Le kernel n’a pas besoin d’une règle de réduction incorrecte : l’atteinte à l’intégrité survient parce qu’un résultat issu d’un compilateur est entré dans la logique par un axiome.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Audit du TCB étendu dans Lean

Ne vous fiez pas uniquement aux coches de l’éditeur ou à une compilation réussie pour valider une preuve non fiable. Examinez la clôture complète des dépendances de chaque théorème critique pour la sécurité avec `#print axioms` ; les consignes de validation de Lean identifient les noms `_native` comme des dépendances à l’évaluation native, `sorryAx` comme une preuve incomplète et les autres noms non standard comme des axiomes personnalisés.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

Par exemple, une dépendance générée ressemblant à ce qui suit signifie que l’exécution compilée a contribué à un résultat supposé plutôt qu’à une preuve dérivée uniquement par réduction du noyau :<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

Lors de la revue du code source, recherchez les procédures de décision natives et les échappatoires explicites, mais vérifiez le résultat avec `#print axioms`, car les dépendances peuvent être indirectes ou générées :<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Distinguez les différentes couches lors du triage d’un résultat :<sup>[[3]](#references)</sup>

1. **Intégrité de l’énoncé :** vérifiez que la notation, les instances de classes de types, les imports et les définitions expriment bien l’affirmation visée.
2. **Dépendances de la preuve :** rejetez ou examinez explicitement les axiomes inattendus, en particulier les axiomes générés d’évaluation native.
3. **Rejeu par le kernel :** après `lake build`, exécutez `lean4checker --fresh <Module>` pour rejouer les déclarations à partir des fichiers `.olean`.
4. **Validation des preuves hostiles :** construisez le code non fiable dans un sandbox et utilisez `lake comparator` avec des vérificateurs externes, en vous appuyant sur un énoncé de défi fiable.

`lean4checker` apporte une défense en profondeur utile, mais il fait confiance à l’intégrité structurelle des fichiers `.olean`, et l’exécution de méta-code Lean non fiable peut compromettre l’environnement de vérification. Pour les preuves à haut risque, comparator exporte la preuve hors du sandbox, vérifie l’énoncé par rapport à l’énoncé de défi fiable et peut la rejouer avec des vérificateurs implémentés indépendamment ; la diversité des implémentations réduit le risque qu’un défaut de compilateur, d’environnement d’exécution ou de kernel valide partout le même résultat erroné.<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract` : divergence entre le modèle et l’environnement d’exécution, et use-after-free - problème Lean #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [Correction de la divergence entre le modèle et l’environnement d’exécution de `String.Pos.Raw.extract` - PR Lean #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Référence du langage Lean : validation d’une preuve Lean](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [Une « preuve » du dernier théorème de Fermat qui tient dans la marge](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
