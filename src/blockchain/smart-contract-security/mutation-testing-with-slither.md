# Mutation Testing pour les Smart Contracts (slither-mutate, mewt, MuTON)

La mutation testing « teste vos tests » en introduisant systématiquement de petites modifications (mutants) dans le code du contrat, puis en réexécutant la suite de tests. Si un test échoue, le mutant est tué. Si les tests réussissent toujours, le mutant survit, révélant un angle mort que la couverture des lignes ou des branches ne peut pas détecter.

Idée clé : la couverture montre que le code a été exécuté ; la mutation testing montre si le comportement est réellement vérifié.<sup>[[2]](#references)</sup>

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
Les tests unitaires qui vérifient uniquement une valeur inférieure et une valeur supérieure au seuil peuvent atteindre une couverture de 100 % des lignes/branches tout en omettant de vérifier la limite d’égalité (`==`). Un refactor vers `deposit >= 2 ether` réussirait tout de même ces tests, rompant silencieusement la logique du protocole.<sup>[[2]](#references)</sup>

Le Mutation testing révèle cette lacune en mutant la condition et en vérifiant que les tests échouent.

Pour les smart contracts, les mutants survivants correspondent souvent à des vérifications manquantes autour des éléments suivants :
- Autorisation et limites des rôles
- Invariants de comptabilité/transfert de valeur
- Conditions de revert et chemins d’échec
- Conditions limites (`==`, valeurs nulles, tableaux vides, valeurs max/min)

## Opérateurs de mutation présentant le signal de sécurité le plus élevé

Classes de mutations utiles pour l’audit de contrats :<sup>[[1]](#references)[[2]](#references)</sup>
- **Gravité élevée** : remplacer des instructions par `revert()` pour révéler les chemins non exécutés
- **Gravité moyenne** : commenter des lignes / supprimer de la logique pour révéler les effets secondaires non vérifiés
- **Faible gravité** : remplacements subtils d’opérateurs ou de constantes, comme `>=` -> `>` ou `+` -> `-`
- Autres modifications courantes : remplacement d’affectation, inversion de booléens, négation de conditions et changements de type

Objectif pratique : tuer tous les mutants significatifs et justifier explicitement ceux qui sont sans importance ou sémantiquement équivalents.

## Pourquoi la mutation tenant compte de la syntaxe est meilleure que les regex

Les anciens moteurs de mutation s’appuyaient sur des regex ou des réécritures orientées ligne. Cela fonctionne, mais présente d’importantes limitations :<sup>[[1]](#references)</sup>
- Les instructions multilignes sont difficiles à muter de manière sûre
- La structure du langage n’est pas comprise, de sorte que les commentaires/tokens peuvent être ciblés de manière incorrecte
- Générer toutes les variantes possibles sur une ligne peu pertinente gaspille de grandes quantités de temps d’exécution

Les outils basés sur AST ou Tree-sitter améliorent cela en ciblant des nœuds structurés plutôt que des lignes brutes :<sup>[[1]](#references)</sup>
- **slither-mutate** utilise l’AST Solidity de Slither.<sup>[[4]](#references)</sup>
- **mewt** utilise Tree-sitter comme cœur agnostique du langage.<sup>[[6]](#references)</sup>
- **MuTON** s’appuie sur `mewt` et ajoute une prise en charge native des langages TON tels que FunC, Tolk et Tact.<sup>[[7]](#references)</sup>

Cela rend les constructions multilignes et les mutations au niveau des expressions beaucoup plus fiables que les approches reposant uniquement sur les regex.

## Exécuter un Mutation testing avec slither-mutate

Prérequis : Slither v0.10.2+.

- Lister les options et les mutateurs :
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Exemple Foundry (capturer les résultats et conserver un journal complet):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Si vous n’utilisez pas Foundry, remplacez `--test-cmd` par la commande utilisée pour exécuter vos tests (par exemple, `npx hardhat test`, `npm test`).

Les artifacts sont stockés dans `./mutation_campaign` par défaut. Les mutants non détectés (survivants) y sont copiés pour inspection.<sup>[[5]](#references)</sup>

### Comprendre la sortie

Les lignes du rapport ressemblent à ceci :
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Le tag entre crochets est l’alias du mutateur (par exemple, `CR` = Comment Replacement).
- `UNCAUGHT` signifie que les tests ont réussi avec le comportement muté → assertion manquante.

## Réduire le runtime : prioriser les mutants ayant le plus d’impact

Les campagnes de mutation peuvent prendre des heures ou des jours. Conseils pour réduire les coûts :<sup>[[1]](#references)[[2]](#references)</sup>
- Portée : commencez uniquement par les contrats/répertoires critiques, puis élargissez.
- Prioriser les mutateurs : si un mutant hautement prioritaire sur une ligne survit (par exemple `revert()` ou la mise en commentaire), ignorez les variantes moins prioritaires pour cette ligne.
- Utilisez des campagnes en deux phases : exécutez d’abord des tests ciblés/rapides, puis retestez uniquement les mutants non détectés avec la suite complète.
- Associez les cibles de mutation à des commandes de test spécifiques lorsque cela est possible (par exemple, code d’authentification -> tests d’authentification).
- Limitez les campagnes aux mutants de sévérité élevée/moyenne lorsque le temps est limité.
- Exécutez les tests en parallèle si votre runner l’autorise ; mettez en cache les dépendances/builds.
- Fail-fast : arrêtez rapidement lorsqu’une modification démontre clairement une lacune dans les assertions.

Le calcul du runtime est brutal : `1000 mutants x 5-minute tests ~= 83 hours`, la conception de la campagne est donc aussi importante que le mutateur lui-même.<sup>[[1]](#references)</sup>

## Campagnes persistantes et triage à grande échelle

L’une des faiblesses des anciens workflows est de déverser les résultats uniquement vers `stdout`. Pour les campagnes longues, cela complique la mise en pause/reprise, le filtrage et la revue.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` améliorent cela en stockant les mutants et leurs résultats dans des campagnes reposant sur SQLite. Avantages :<sup>[[1]](#references)</sup>
- Mettre en pause et reprendre les longues exécutions sans perdre la progression
- Filtrer uniquement les mutants non détectés dans un fichier ou une classe de mutation spécifique
- Exporter/traduire les résultats vers SARIF pour les outils de revue
- Fournir au triage assisté par IA des ensembles de résultats plus petits et filtrés au lieu de logs bruts du terminal

Les résultats persistants sont particulièrement utiles lorsque les tests de mutation deviennent une composante d’un pipeline d’audit plutôt qu’une revue manuelle ponctuelle.

## Workflow de triage des mutants survivants

1) Inspecter la ligne et le comportement mutés.
- Reproduisez localement le problème en appliquant la ligne mutée et en exécutant un test ciblé.

2) Renforcer les tests pour vérifier l’état, et pas uniquement les valeurs de retour.
- Ajoutez des vérifications des limites d’égalité (par exemple, testez le seuil `==`).
- Vérifiez les post-conditions : soldes, supply totale, effets de l’autorisation et événements émis.

3) Remplacer les mocks trop permissifs par un comportement réaliste.
- Assurez-vous que les mocks appliquent les transferts, les chemins d’échec et les émissions d’événements qui se produisent on-chain.

4) Ajouter des invariants aux tests fuzz.
- Par exemple, conservation de la valeur, soldes non négatifs, invariants d’autorisation, supply monotone lorsque cela s’applique.

5) Séparer les vrais positifs des no-ops sémantiques.
- Exemple : `x > 0` -> `x != 0` n’a aucune signification lorsque `x` est unsigned.

6) Relancer la campagne jusqu’à ce que les survivants soient éliminés ou explicitement justifiés.

## Étude de cas : révéler des assertions d’état manquantes (protocole Arkis)

Une campagne de mutation menée lors d’un audit du protocole DeFi Arkis a révélé des survivants tels que :<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Désactiver l’affectation n’a pas fait échouer les tests, ce qui prouve l’absence d’assertions sur l’état postérieur. Cause racine : le code faisait confiance à un `_cmd.value` contrôlé par l’utilisateur au lieu de valider les transferts réels de tokens. Un attaquant pouvait désynchroniser les transferts attendus et réels afin de drainer les fonds. Résultat : risque de haute sévérité pour la solvabilité du protocole.<sup>[[2]](#references)[[3]](#references)</sup>

Conseil : considérez les mutants survivants qui affectent les transferts de valeur, la comptabilité ou le contrôle d’accès comme présentant un risque élevé jusqu’à leur élimination.

## Do not blindly generate tests to kill every mutant

La génération de tests pilotée par les mutations peut se retourner contre vous si l’implémentation actuelle est incorrecte. Exemple : faire muter `priority >= 2` en `priority > 2` modifie le comportement, mais la bonne correction n’est pas toujours de « rédiger un test pour `priority == 2` ». Ce comportement peut lui-même être le bug.<sup>[[1]](#references)</sup>

Workflow plus sûr :
- Utiliser les mutants survivants pour identifier les exigences ambiguës
- Valider le comportement attendu à partir des spécifications, de la documentation du protocole ou des reviewers
- Ensuite seulement, encoder le comportement sous forme de test/invariant

Sinon, vous risquez de figer des accidents d’implémentation dans la suite de tests et d’obtenir une fausse confiance.

## Practical checklist

- Lancer une campagne ciblée :
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Privilégier les mutateurs sensibles à la syntaxe (AST/Tree-sitter) plutôt que les mutations reposant uniquement sur des regex lorsqu’ils sont disponibles.
- Examiner les mutants survivants et rédiger des tests/invariants qui échoueraient avec le comportement muté.
- Vérifier les soldes, l’offre, les autorisations et les événements.
- Ajouter des tests de limites (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Remplacer les mocks irréalistes ; simuler les modes d’échec.
- Conserver les résultats lorsque l’outil le permet et filtrer les mutants non interceptés avant l’examen.
- Utiliser des campagnes en deux phases ou par cible afin de maintenir un temps d’exécution raisonnable.
- Itérer jusqu’à ce que tous les mutants soient éliminés ou justifiés par des commentaires et une explication.

## References

- [1] [Les mutation tests à l’ère agentique](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Utiliser les mutation tests pour trouver les bugs que vos tests ne détectent pas (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Revue de sécurité d’Arkis DeFi Prime Brokerage (annexe C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Documentation du mutateur Slither](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
