# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Le mutation testing "tests your tests" en introduisant systématiquement de petits changements (mutants) dans le code du contrat puis en relançant la suite de tests. Si un test échoue, le mutant est killed. Si les tests passent toujours, le mutant survives, révélant un angle mort que la line/branch coverage ne peut pas détecter.

Idée clé : la Coverage montre que le code a été exécuté ; le mutation testing montre si le comportement est réellement asserted.

## Pourquoi la coverage peut tromper

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
Les tests unitaires qui vérifient seulement une valeur en dessous et une valeur au-dessus du seuil peuvent atteindre 100 % de coverage ligne/branch tout en ne vérifiant pas la boundary d’égalité (==). Un refactor vers `deposit >= 2 ether` passerait encore de tels tests, cassant silencieusement la logique du protocole.

Le mutation testing expose cette faille en mutating la condition et en vérifiant que les tests échouent.

Pour les smart contracts, les mutants survivants correspondent souvent à des checks manquants autour de :
- Authorization et role boundaries
- Accounting/value-transfer invariants
- Revert conditions et failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## Mutation operators avec le plus fort signal de sécurité

Classes de mutation utiles pour l’audit de contrats :
- **High severity** : remplacer des statements par `revert()` pour exposer les paths non exécutés
- **Medium severity** : commenter des lignes / remove logic pour révéler des side effects non vérifiés
- **Low severity** : swaps subtils d’opérateurs ou de constantes comme `>=` -> `>` ou `+` -> `-`
- Autres modifications courantes : remplacement d’assignation, boolean flips, negation de condition, et changements de type

Objectif pratique : kill all meaningful mutants, et justifier explicitement les survivants qui sont non pertinents ou sémantiquement équivalents.

## Why syntax-aware mutation is better than regex

Les anciens moteurs de mutation reposaient sur des regex ou des réécritures orientées lignes. Cela fonctionne, mais avec des limites importantes :
- Les statements multi-lignes sont difficiles à muter en sécurité
- La structure du langage n’est pas comprise, donc les commentaires/tokens peuvent être ciblés de façon incorrecte
- Générer toutes les variantes possibles sur une ligne faible consomme énormément de runtime

Les outils basés sur AST ou Tree-sitter améliorent cela en ciblant des nœuds structurés plutôt que des lignes brutes :
- **slither-mutate** utilise l’AST Solidity de Slither
- **mewt** utilise Tree-sitter comme core agnostique du langage
- **MuTON** s’appuie sur `mewt` et ajoute un support natif des langages TON comme FunC, Tolk, et Tact

Cela rend les constructs multi-lignes et les mutations au niveau des expressions beaucoup plus fiables que les approches uniquement basées sur regex.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Exemple Foundry (capturer les résultats et conserver un log complet) :
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Si vous n'utilisez pas Foundry, remplacez `--test-cmd` par la commande avec laquelle vous exécutez les tests (par ex. `npx hardhat test`, `npm test`).

Les artifacts sont stockés par défaut dans `./mutation_campaign`. Les mutants non capturés (survivants) y sont copiés pour inspection.

### Comprendre la sortie

Les lignes du rapport ressemblent à :
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Le tag entre crochets est l’alias du mutator (par ex. `CR` = Comment Replacement).
- `UNCAUGHT` signifie que les tests ont réussi sous le comportement muté → assertion manquante.

## Réduire le runtime : prioriser les mutants les plus impactants

Les campagnes de mutation peuvent prendre des heures ou des jours. Conseils pour réduire le coût :
- Scope : commencez uniquement par les contrats/répertoires critiques, puis élargissez.
- Priorisez les mutators : si un mutant à haute priorité sur une ligne survit (par exemple `revert()` ou comment-out), ignorez les variantes de priorité inférieure pour cette ligne.
- Utilisez des campagnes en deux phases : lancez d’abord des tests ciblés/rapides, puis retestez uniquement les mutants `uncaught` avec la suite complète.
- Mappez, si possible, les cibles de mutation à des commandes de test spécifiques (par exemple code auth -> tests auth).
- Limitez les campagnes aux mutants de sévérité élevée/moyenne quand le temps est compté.
- Parallélisez les tests si votre runner le permet ; mettez en cache les dépendances/builds.
- Fail-fast : arrêtez tôt lorsqu’un changement démontre clairement un manque d’assertion.

Le calcul du runtime est brutal : `1000 mutants x 5-minute tests ~= 83 heures`, donc la conception de la campagne compte autant que le mutator lui-même.

## Campagnes persistantes et triage à grande échelle

Une faiblesse des anciens workflows est de ne renvoyer les résultats que vers `stdout`. Pour les longues campagnes, cela rend plus difficiles la pause/reprise, le filtrage et la revue.

`mewt`/`MuTON` améliorent cela en stockant les mutants et leurs résultats dans des campagnes basées sur SQLite. Avantages :
- Mettre en pause et reprendre de longues exécutions sans perdre la progression
- Filtrer uniquement les mutants `uncaught` dans un fichier spécifique ou une classe de mutation
- Exporter/traduire les résultats en SARIF pour les outils de revue
- Donner au triage assisté par IA des ensembles de résultats plus petits et filtrés au lieu de logs bruts de terminal

Les résultats persistants sont particulièrement utiles lorsque la mutation testing devient une partie d’un pipeline d’audit au lieu d’une revue manuelle ponctuelle.

## Workflow de triage pour les mutants survivants

1) Inspectez la ligne mutée et le comportement.
- Reproduisez localement en appliquant la ligne mutée et en exécutant un test ciblé.

2) Renforcez les tests pour vérifier l’état, pas seulement les valeurs de retour.
- Ajoutez des vérifications de bornes d’égalité (par ex. test du seuil `==`).
- Vérifiez les post-conditions : balances, total supply, effets d’autorisation, et events émis.

3) Remplacez les mocks trop permissifs par un comportement réaliste.
- Assurez-vous que les mocks imposent les transferts, les chemins d’échec, et les émissions d’events qui se produisent on-chain.

4) Ajoutez des invariants pour les fuzz tests.
- Par ex. conservation de la valeur, balances non négatives, invariants d’autorisation, supply monotone quand applicable.

5) Séparez les vrais positifs des semantic no-ops.
- Exemple : `x > 0` -> `x != 0` est sans effet lorsque `x` est unsigned.

6) Relancez la campagne jusqu’à ce que les survivants soient éliminés ou explicitement justifiés.

## Étude de cas : révéler des assertions d’état manquantes (Arkis protocol)

Une campagne de mutation pendant un audit du protocole DeFi Arkis a mis au jour des survivants comme :
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commenter l’assignation n’a pas cassé les tests, ce qui prouve l’absence d’assertions post-state. Cause racine : le code faisait confiance à `_cmd.value`, contrôlé par l’utilisateur, au lieu de valider les transferts réels de tokens. Un attaquant pouvait désynchroniser les transferts attendus et réels pour drainer des fonds. Résultat : risque de haute gravité pour la solvabilité du protocole.

Conseil : Traitez les survivants qui affectent les transferts de valeur, la comptabilité ou le contrôle d’accès comme à haut risque tant qu’ils ne sont pas tués.

## Ne générez pas aveuglément des tests pour tuer chaque mutant

La génération de tests guidée par mutation peut se retourner contre vous si l’implémentation actuelle est incorrecte. Exemple : muter `priority >= 2` en `priority > 2` change le comportement, mais la bonne correction n’est pas toujours « écrire un test pour `priority == 2` ». Ce comportement peut lui-même être le bug.

Flux de travail plus sûr :
- Utilisez les mutants survivants pour identifier les exigences ambiguës
- Validez le comportement attendu à partir des specs, de la documentation du protocole ou des reviewers
- Ce n’est qu’ensuite que vous encodez ce comportement en test/invariant

Sinon, vous risquez de figer des accidents d’implémentation dans la suite de tests et d’obtenir une fausse confiance.

## Checklist pratique

- Lancez une campagne ciblée :
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Préférez des mutateurs sensibles à la syntaxe (AST/Tree-sitter) plutôt que des mutations basées uniquement sur des regex quand c’est possible.
- Triez les survivants et écrivez des tests/invariants qui échoueraient face au comportement muté.
- Vérifiez les soldes, l’offre, les autorisations et les événements.
- Ajoutez des tests de bornes (`==`, overflow/underflow, zero-address, zero-amount, tableaux vides).
- Remplacez les mocks irréalistes ; simulez les modes de défaillance.
- Conservez les résultats lorsque l’outil le permet, et filtrez les mutants non détectés avant le triage.
- Utilisez des campagnes en deux phases ou par cible pour garder un runtime gérable.
- Itérez jusqu’à ce que tous les mutants soient tués ou justifiés avec des commentaires et une rationale.

## Références

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
