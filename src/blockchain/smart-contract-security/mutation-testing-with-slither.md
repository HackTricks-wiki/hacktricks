# Mutation Testing pour les Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Le Mutation Testing « teste vos tests » en introduisant systématiquement de petites modifications (mutants) dans le code du contract, puis en réexécutant la suite de tests. Si un test échoue, le mutant est tué. Si les tests réussissent toujours, le mutant survit, révélant un angle mort que la couverture des lignes/blocs ne peut pas détecter.

Idée clé : la couverture montre que le code a été exécuté ; le Mutation Testing montre si le comportement est réellement vérifié.<sup>[[2]](#references)</sup>

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
Les tests unitaires qui vérifient uniquement une valeur inférieure et une valeur supérieure au seuil peuvent atteindre une couverture de 100 % des lignes/branches tout en ne vérifiant pas la limite d'égalité (`==`). Une refactorisation en `deposit >= 2 ether` réussirait tout de même ces tests, rompant silencieusement la logique du protocole.<sup>[[2]](#references)</sup>

Le mutation testing révèle cette lacune en mutant la condition et en vérifiant que les tests échouent.

Pour les smart contracts, les mutants survivants correspondent souvent à des vérifications manquantes autour des éléments suivants :
- Autorisation et limites des rôles
- Invariants de comptabilité/transfert de valeur
- Conditions de revert et chemins d'échec
- Conditions limites (`==`, valeurs nulles, tableaux vides, valeurs max/min)

## Mutation operators avec le meilleur signal de sécurité

Classes de mutations utiles pour l'audit de contrats :<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity** : remplacer les statements par `revert()` pour révéler les chemins non exécutés
- **Medium severity** : commenter des lignes / supprimer de la logique pour révéler les effets de bord non vérifiés
- **Low severity** : substitutions subtiles d'opérateurs ou de constantes, comme `>=` -> `>` ou `+` -> `-`
- Autres modifications courantes : remplacement d'assignation, inversions booléennes, négation de conditions et changements de type

Objectif pratique : éliminer tous les mutants significatifs et justifier explicitement les mutants survivants qui sont sans rapport ou sémantiquement équivalents.

## Pourquoi la mutation prenant en compte la syntaxe est meilleure que les regex

Les anciens moteurs de mutation s'appuyaient sur des regex ou des réécritures orientées lignes. Cela fonctionne, mais présente d'importantes limites :<sup>[[1]](#references)</sup>
- Les statements multilignes sont difficiles à muter de manière sûre
- La structure du langage n'est pas comprise, ce qui peut cibler incorrectement les commentaires/tokens
- Générer toutes les variantes possibles sur une ligne peu pertinente gaspille d'importantes quantités de runtime

Les outils basés sur AST ou Tree-sitter améliorent cela en ciblant des nœuds structurés plutôt que des lignes brutes :<sup>[[1]](#references)</sup>
- **slither-mutate** utilise l'AST Solidity de Slither
- **mewt** utilise Tree-sitter comme core indépendant du langage
- **MuTON** s'appuie sur `mewt` et ajoute un support de première classe pour les langages TON tels que FunC, Tolk et Tact

Cela rend les constructions multilignes et les mutations au niveau des expressions beaucoup plus fiables que les approches reposant uniquement sur les regex.

## Exécuter un mutation testing avec slither-mutate

Prérequis : Slither v0.10.2+.

- Lister les options et mutators :
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Exemple Foundry (capturer les résultats et conserver un journal complet) :<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Si vous n’utilisez pas Foundry, remplacez `--test-cmd` par la commande utilisée pour exécuter vos tests (par exemple, `npx hardhat test`, `npm test`).

Par défaut, les artifacts sont stockés dans `./mutation_campaign`. Les mutants non détectés (survivants) y sont copiés pour inspection.<sup>[[5]](#references)</sup>

### Comprendre la sortie

Les lignes du rapport ressemblent à ceci :
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- La balise entre crochets correspond à l’alias du mutator (par exemple, `CR` = Comment Replacement).
- `UNCAUGHT` signifie que les tests ont réussi avec le comportement muté → assertion manquante.

## Réduire le runtime : donner la priorité aux mutants les plus impactants

Les campagnes de mutation peuvent prendre des heures ou des jours. Conseils pour réduire le coût :<sup>[[1]](#references)[[2]](#references)</sup>
- Périmètre : commencez uniquement par les contrats/répertoires critiques, puis élargissez.
- Donner la priorité aux mutators : si un mutant prioritaire sur une ligne survit (par exemple `revert()` ou comment-out), ignorez les variantes moins prioritaires pour cette ligne.
- Utiliser des campagnes en deux phases : exécutez d’abord des tests ciblés/rapides, puis retestez uniquement les mutants non détectés avec la suite complète.
- Lorsque c’est possible, associez les cibles de mutation à des commandes de test spécifiques (par exemple, code d’authentification -> tests d’authentification).
- Limitez les campagnes aux mutants de gravité élevée/moyenne lorsque le temps est limité.
- Exécutez les tests en parallèle si votre runner l’autorise ; mettez en cache les dépendances/builds.
- Fail-fast : arrêtez rapidement lorsqu’une modification démontre clairement une lacune dans les assertions.

Les calculs de runtime sont brutaux : `1000 mutants x 5-minute tests ~= 83 hours`, la conception de la campagne est donc aussi importante que le mutator lui-même.

## Campagnes persistantes et triage à grande échelle

L’une des faiblesses des anciens workflows est de vider les résultats uniquement vers `stdout`. Pour les longues campagnes, cela rend la mise en pause/reprise, le filtrage et la revue plus difficiles.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` améliorent cela en stockant les mutants et les résultats dans des campagnes basées sur SQLite. Avantages :<sup>[[1]](#references)</sup>
- Mettre en pause et reprendre de longues exécutions sans perdre la progression
- Filtrer uniquement les mutants non détectés dans un fichier ou une classe de mutation spécifique
- Exporter/traduire les résultats en SARIF pour les outils de revue
- Fournir au triage assisté par AI des ensembles de résultats plus petits et filtrés au lieu de logs bruts du terminal

Les résultats persistants sont particulièrement utiles lorsque le mutation testing devient partie intégrante d’un pipeline d’audit plutôt qu’une revue manuelle ponctuelle.

## Workflow de triage des mutants survivants

1) Inspectez la ligne mutée et son comportement.
- Reproduisez localement le problème en appliquant la ligne mutée et en exécutant un test ciblé.

2) Renforcez les tests afin d’asserter l’état, et pas uniquement les valeurs de retour.
- Ajoutez des vérifications des limites d’égalité (par exemple, testez le seuil `==`).
- Assertez les post-conditions : soldes, supply totale, effets de l’autorisation et événements émis.

3) Remplacez les mocks trop permissifs par un comportement réaliste.
- Assurez-vous que les mocks appliquent les transferts, les chemins d’échec et les émissions d’événements qui se produisent on-chain.

4) Ajoutez des invariants aux fuzz tests.
- Par exemple, conservation de la valeur, soldes non négatifs, invariants d’autorisation, supply monotone lorsque cela s’applique.

5) Distinguez les vrais positifs des no-ops sémantiques.
- Exemple : `x > 0` -> `x != 0` n’a aucun sens lorsque `x` est unsigned.

6) Relancez la campagne jusqu’à ce que les survivants soient éliminés ou explicitement justifiés.

## Étude de cas : révéler des assertions d’état manquantes (protocole Arkis)

Une campagne de mutation menée lors d’un audit du protocole DeFi Arkis a révélé des survivants tels que :<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commenter l’affectation n’a pas fait échouer les tests, ce qui prouve l’absence d’assertions sur l’état final. Cause racine : le code faisait confiance à `_cmd.value`, contrôlé par l’utilisateur, au lieu de valider les transferts de tokens réellement effectués. Un attaquant pouvait désynchroniser les transferts attendus des transferts réels afin de drainer les fonds. Résultat : risque de gravité élevée pour la solvabilité du protocole.<sup>[[2]](#references)[[3]](#references)</sup>

Conseil : considérez les mutants survivants qui affectent les transferts de valeur, la comptabilité ou le contrôle d’accès comme présentant un risque élevé jusqu’à leur élimination.

## Ne générez pas aveuglément des tests pour éliminer chaque mutant

La génération de tests guidée par les mutants peut être contre-productive si l’implémentation actuelle est incorrecte. Exemple : muter `priority >= 2` en `priority > 2` modifie le comportement, mais la bonne correction n’est pas toujours d’« écrire un test pour `priority == 2` ». Ce comportement peut lui-même être le bug.<sup>[[1]](#references)</sup>

Workflow plus sûr :
- Utilisez les mutants survivants pour identifier les exigences ambiguës
- Validez le comportement attendu à partir des spécifications, de la documentation du protocole ou des reviewers
- Encodez ensuite seulement le comportement sous forme de test/invariant

Sinon, vous risquez de figer des accidents d’implémentation dans la suite de tests et d’obtenir une fausse confiance.

## Checklist pratique

- Lancez une campagne ciblée :
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Préférez les mutateurs sensibles à la syntaxe (AST/Tree-sitter) aux mutations utilisant uniquement des regex, lorsqu’ils sont disponibles.
- Triez les mutants survivants et écrivez des tests/invariants qui échoueraient avec le comportement muté.
- Vérifiez les soldes, la supply, les autorisations et les événements.
- Ajoutez des tests aux limites (`==`, overflows/underflows, zero-address, zero-amount, tableaux vides).
- Remplacez les mocks irréalistes ; simulez les modes d’échec.
- Conservez les résultats lorsque l’outil le permet et filtrez les mutants non détectés avant le triage.
- Utilisez des campagnes en deux phases ou par cible pour maintenir un temps d’exécution raisonnable.
- Itérez jusqu’à ce que tous les mutants soient éliminés ou justifiés par des commentaires et une explication.

## Références

- [1] [Mutation testing pour l’ère agentique](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Utiliser Mutation testing pour trouver les bugs que vos tests ne détectent pas (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Security Review du Prime Brokerage DeFi d’Arkis (Annexe C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Documentation du Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
