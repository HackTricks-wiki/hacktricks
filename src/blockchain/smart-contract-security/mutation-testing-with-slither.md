# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

La mutation testing « teste vos tests » en introduisant systématiquement de petits changements (mutants) dans votre code Solidity et en relançant votre suite de tests. Si un test échoue, le mutant est tué. Si les tests passent encore, le mutant survit, révélant un point aveugle dans votre suite de tests que la couverture de lignes/branches ne peut pas détecter.

Idée clé : la couverture montre que le code a été exécuté ; la mutation testing montre si le comportement est réellement asserté.

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
Les tests unitaires qui ne vérifient qu'une valeur en dessous et une valeur au‑dessus du seuil peuvent atteindre 100 % de couverture de lignes/branches tout en n'assertant pas la frontière d'égalité (==). Un refactor vers `deposit >= 2 ether` passerait toujours ces tests, cassant silencieusement la logique du protocole.

Mutation testing met en évidence ce vide en modifiant la condition et en vérifiant que vos tests échouent.

## Opérateurs de mutation Solidity courants

Le moteur de mutation de Slither applique de nombreuses petites modifications changeant la sémantique, telles que :
- Remplacement d'opérateur: `+` ↔ `-`, `*` ↔ `/`, etc.
- Remplacement d'affectation: `+=` → `=`, `-=` → `=`
- Remplacement de constantes: non nul → `0`, `true` ↔ `false`
- Négation/remplacement de condition dans les `if`/boucles
- Commenter des lignes entières (CR: Comment Replacement)
- Remplacer une ligne par `revert()`
- Échanges de types de données : p.ex., `int128` → `int64`

Objectif : éliminer 100 % des mutants générés, ou justifier les survivants avec un raisonnement clair.

## Lancer mutation testing avec slither-mutate

Prérequis : Slither v0.10.2+.

- Lister les options et les mutateurs :
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Exemple Foundry (capturer les résultats et conserver un journal complet):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Si vous n'utilisez pas Foundry, remplacez `--test-cmd` par la façon dont vous exécutez les tests (par ex., `npx hardhat test`, `npm test`).

Les artefacts et rapports sont stockés dans `./mutation_campaign` par défaut. Les mutants non capturés (survivants) y sont copiés pour examen.

### Comprendre la sortie

Les lignes du rapport ressemblent à :
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Le tag entre crochets est l'alias du mutateur (par exemple, `CR` = Comment Replacement).
- `UNCAUGHT` signifie que les tests ont réussi sous le comportement muté → assertion manquante.

## Réduction du temps d'exécution : prioriser les mutants ayant un impact

Les campagnes de mutation peuvent durer des heures ou des jours. Conseils pour réduire le coût :
- Périmètre : commencez uniquement par les contrats/répertoires critiques, puis élargissez.
- Prioriser les mutateurs : si un mutant à haute priorité sur une ligne survit (par ex., toute la ligne commentée), vous pouvez ignorer les variantes de moindre priorité pour cette ligne.
- Parallélisez les tests si votre runner le permet ; mettez en cache les dépendances/builds.
- Fail-fast : arrêtez tôt lorsqu'un changement démontre clairement un défaut d'assertion.

## Flux de triage pour les mutants survivants

1) Inspectez la ligne mutée et le comportement.
- Reproduisez localement en appliquant la ligne mutée et en exécutant un test ciblé.

2) Renforcez les tests pour vérifier l'état, pas seulement les valeurs de retour.
- Ajoutez des checks de frontière d'égalité (par ex., test du seuil `==`).
- Affirmez les post-conditions : soldes, total supply, effets d'autorisation et événements émis.

3) Remplacez les mocks trop permissifs par un comportement réaliste.
- Assurez-vous que les mocks imposent les transferts, les chemins d'échec et les émissions d'événements qui se produisent on-chain.

4) Ajoutez des invariants pour les fuzz tests.
- Ex. : conservation de la valeur, soldes non négatifs, invariants d'autorisation, monotonic supply lorsque applicable.

5) Relancez slither-mutate jusqu'à ce que les survivants soient éliminés ou justifiés explicitement.

## Étude de cas : révélant des assertions d'état manquantes (Arkis protocol)

Une campagne de mutation lors d'un audit du Arkis DeFi protocol a fait apparaître des survivants tels que :
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Le fait de commenter l'assignation n'a pas cassé les tests, ce qui prouve l'absence d'assertions post-état. Cause racine : le code faisait confiance à un `_cmd.value` contrôlé par l'utilisateur au lieu de valider les transferts réels de tokens. Un attaquant pourrait désynchroniser les transferts attendus et réels pour siphonner des fonds. Résultat : risque de gravité élevée pour la solvabilité du protocole.

Conseil : Traitez les mutants survivants qui affectent les transferts de valeur, la comptabilité ou le contrôle d'accès comme à haut risque tant qu'ils ne sont pas tués.

## Checklist pratique

- Lancez une campagne ciblée :
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Triez les mutants survivants et écrivez des tests/invariants qui échoueraient sous le comportement muté.
- Vérifiez les soldes, l'offre, les autorisations et les événements.
- Ajoutez des tests de limites (`==`, débordements/sous-dépassements, adresse nulle, montant nul, tableaux vides).
- Remplacez les mocks irréalistes ; simulez les modes de défaillance.
- Itérez jusqu'à ce que tous les mutants soient tués ou justifiés avec des commentaires et une justification.

## Références

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
