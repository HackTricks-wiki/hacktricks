# Test de mutation pour Solidity avec Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Le test de mutation, qui "teste vos tests", consiste à introduire systématiquement de petits changements (mutants) dans votre code Solidity et à relancer votre suite de tests. Si un test échoue, le mutant est tué. Si les tests passent toujours, le mutant survit, révélant une zone aveugle dans votre suite de tests que la couverture de lignes/de branches ne peut pas détecter.

Idée clé : la couverture montre que le code a été exécuté ; le test de mutation montre si le comportement est réellement vérifié.

## Pourquoi la couverture peut être trompeuse

Considérez ce simple contrôle de seuil :
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Les tests unitaires qui ne vérifient qu'une valeur en dessous et une valeur au-dessus du seuil peuvent atteindre 100% de couverture ligne/branchement tout en n'assertant pas la frontière d'égalité (==). Une refactorisation en `deposit >= 2 ether` passerait toujours ces tests, cassant silencieusement la logique du protocole.

Mutation testing expose cette faille en mutant la condition et en vérifiant que vos tests échouent.

## Opérateurs de mutation courants pour Solidity

Slither’s mutation engine applique de nombreuses petites modifications changeant la sémantique, telles que :
- Remplacement d'opérateurs : `+` ↔ `-`, `*` ↔ `/`, etc.
- Remplacement d'affectation : `+=` → `=`, `-=` → `=`
- Remplacement de constantes : non-zéro → `0`, `true` ↔ `false`
- Négation/remplacement de condition à l'intérieur de `if`/boucles
- Mettre en commentaire des lignes entières (CR: Comment Replacement)
- Remplacer une ligne par `revert()`
- Échanges de types de données : p. ex., `int128` → `int64`

Objectif : Éliminer 100 % des mutants générés, ou justifier les survivants par un raisonnement clair.

## Exécution de mutation testing avec slither-mutate

Prérequis : Slither v0.10.2+.

- Lister les options et les mutateurs:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Exemple Foundry (capturer les résultats et conserver un log complet):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Si vous n'utilisez pas Foundry, remplacez `--test-cmd` par la commande que vous utilisez pour exécuter les tests (par ex., `npx hardhat test`, `npm test`).

Les artefacts et les rapports sont stockés dans `./mutation_campaign` par défaut. Les mutants non détectés (survivants) y sont copiés pour inspection.

### Comprendre la sortie

Les lignes du rapport ressemblent à :
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- The tag in brackets is the mutator alias (e.g., `CR` = Remplacement de commentaire).
- `UNCAUGHT` means tests passed under the mutated behavior → assertion manquante.

## Réduire le temps d'exécution : prioriser les mutants ayant un impact

Les campagnes de mutation peuvent prendre des heures ou des jours. Conseils pour réduire les coûts :
- Portée : commencez uniquement par les contrats/répertoires critiques, puis étendez.
- Prioriser les mutateurs : si un mutant à haute priorité sur une ligne survit (p.ex., toute la ligne commentée), vous pouvez ignorer les variantes de moindre priorité pour cette ligne.
- Parallelize tests if your runner allows it; cache dependencies/builds.
- Fail-fast : arrêtez tôt lorsqu'un changement démontre clairement un manque d'assertion.

## Flux de triage pour les mutants survivants

1) Inspecter la ligne mutée et le comportement.
- Reproduire localement en appliquant la ligne mutée et en exécutant un test ciblé.

2) Renforcer les tests pour affirmer l'état, pas seulement les valeurs de retour.
- Ajouter des vérifications de limites d'égalité (p.ex., test threshold `==`).
- Affirmer des post-conditions : soldes, total supply, effets d'autorisation et événements émis.

3) Remplacer les mocks trop permissifs par un comportement réaliste.
- S'assurer que les mocks imposent les transferts, les chemins d'échec et les émissions d'événements qui se produisent on-chain.

4) Ajouter des invariants pour les fuzz tests.
- P.ex., conservation de la valeur, soldes non négatifs, invariants d'autorisation, monotonic supply lorsque applicable.

5) Relancer slither-mutate jusqu'à ce que les survivants soient tués ou explicitement justifiés.

## Étude de cas : révéler les assertions d'état manquantes (protocole Arkis)

Une campagne de mutation lors d'un audit du protocole Arkis DeFi a fait remonter des survivants tels que :
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Le fait de commenter l'affectation n'a pas fait échouer les tests, ce qui prouve l'absence d'assertions sur l'état post-exécution. Cause racine : le code se fiait à `_cmd.value` contrôlé par l'utilisateur au lieu de valider les transferts réels de tokens. Un attaquant pouvait désynchroniser les transferts attendus et réels pour siphonner les fonds. Conséquence : risque de gravité élevée pour la solvabilité du protocole.

Guidance : Traitez les mutants survivants qui affectent les transferts de valeur, la comptabilité ou le contrôle d'accès comme à haut risque tant qu'ils ne sont pas tués.

## Practical checklist

- Run a targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Trier les mutants survivants et écrire des tests/invariants qui échoueraient sous le comportement muté.
- Vérifier les soldes, l'offre (supply), les autorisations et les événements.
- Add boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Remplacer les mocks irréalistes ; simuler des modes de défaillance.
- Itérer jusqu'à ce que tous les mutants soient tués ou explicitement justifiés par des commentaires et des explications.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
