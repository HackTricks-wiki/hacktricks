# Test de mutation pour Solidity avec Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Le test de mutation "teste vos tests" en introduisant systématiquement de petites modifications (mutants) dans votre code Solidity et en relançant votre suite de tests. Si un test échoue, le mutant est tué. Si les tests passent toujours, le mutant survit, révélant un point aveugle dans votre suite de tests que la couverture de lignes/branches ne peut pas détecter.

Idée clé : la couverture montre que le code a été exécuté ; le test de mutation montre si le comportement est réellement vérifié.

## Pourquoi la couverture peut être trompeuse

Considérez cette simple vérification de seuil :
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Les tests unitaires qui ne vérifient qu'une valeur en dessous et une valeur au-dessus du seuil peuvent atteindre 100% de couverture ligne/branche tout en omettant d'assertion la frontière d'égalité (==). Un refactor vers `deposit >= 2 ether` réussirait toujours ces tests, brisant silencieusement la logique du protocole.

La mutation testing expose cette faille en mutant la condition et en vérifiant que vos tests échouent.

## Opérateurs de mutation Solidity courants

Le moteur de mutation de Slither applique de nombreuses petites modifications changeant la sémantique, telles que :
- Remplacement d'opérateur : `+` ↔ `-`, `*` ↔ `/`, etc.
- Remplacement d'affectation : `+=` → `=`, `-=` → `=`
- Remplacement de constante : non-zéro → `0`, `true` ↔ `false`
- Négation/remplacement de condition à l'intérieur des `if`/boucles
- Commenter des lignes entières (CR: Comment Replacement)
- Remplacer une ligne par `revert()`
- Échanges de type de données : p.ex., `int128` → `int64`

Objectif : tuer 100% des mutants générés, ou justifier les survivants avec un raisonnement clair.

## Exécuter la mutation testing avec slither-mutate

Prérequis : Slither v0.10.2+.

- Lister les options et les mutators :
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Exemple avec Foundry (capturer les résultats et conserver un journal complet):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Si vous n'utilisez pas Foundry, remplacez `--test-cmd` par la commande que vous utilisez pour exécuter les tests (p. ex., `npx hardhat test`, `npm test`).

Les artifacts et rapports sont stockés dans `./mutation_campaign` par défaut. Les mutants non interceptés (survivants) y sont copiés pour inspection.

### Comprendre la sortie

Les lignes du rapport ressemblent à :
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Le tag entre crochets est l'alias du mutator (e.g., `CR` = Comment Replacement).
- `UNCAUGHT` signifie que les tests sont passés sous le comportement muté → assertion manquante.

## Reducing runtime: prioritize impactful mutants

Les campagnes de mutation peuvent prendre des heures ou des jours. Conseils pour réduire le coût :
- Scope : Commencez par les contrats/répertoires critiques uniquement, puis étendez.
- Prioritize mutators : si un mutant à haute priorité sur une ligne survit (p.ex., ligne entière commentée), vous pouvez ignorer les variantes de moindre priorité pour cette ligne.
- Parallelize tests si votre runner le permet ; mettez en cache dependencies/builds.
- Fail-fast : arrêtez tôt lorsqu'un changement met clairement en évidence une faille d'assertion.

## Triage workflow for surviving mutants

1) Inspect the mutated line and behavior.
- Reproduisez localement en appliquant la ligne mutée et en exécutant un test ciblé.

2) Strengthen tests to assert state, not only return values.
- Ajoutez des vérifications de bornes d'égalité (p.ex., vérifier le seuil `==`).
- Affirmez les post-conditions : soldes, offre totale, effets d'autorisation, et événements émis.

3) Replace overly permissive mocks with realistic behavior.
- Assurez-vous que les mocks imposent les transferts, les chemins d'échec, et les émissions d'événements qui se produisent on-chain.

4) Add invariants for fuzz tests.
- Ex. conservation de la valeur, soldes non négatifs, invariants d'autorisation, offre monotone lorsque applicable.

5) Re-run slither-mutate until survivors are killed or explicitly justified.

## Case study: revealing missing state assertions (Arkis protocol)

Une campagne de mutation lors d'un audit du Arkis DeFi protocol a mis en évidence des survivants tels que :
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commenter l'assignation n'a pas cassé les tests, prouvant l'absence d'assertions sur l'état final. Cause racine : le code faisait confiance à `_cmd.value` contrôlé par l'utilisateur au lieu de valider les transferts de tokens réels. Un attaquant pouvait désynchroniser les transferts attendus et réels pour vider des fonds. Conséquence : risque de haute gravité pour la solvabilité du protocole.

Conseil : Traitez les mutants survivants qui affectent les transferts de valeur, la comptabilité ou le contrôle d'accès comme à haut risque tant qu'ils ne sont pas éliminés.

## Checklist pratique

- Lancez une campagne ciblée :
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Trier les survivants et écrire des tests/invariants qui échoueraient avec le comportement muté.
- Vérifiez les soldes, l'offre totale, les autorisations et les événements.
- Ajoutez des tests limites (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Remplacez les mocks irréalistes ; simulez des modes de défaillance.
- Itérez jusqu'à ce que tous les mutants soient éliminés ou justifiés par des commentaires et une explication.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
