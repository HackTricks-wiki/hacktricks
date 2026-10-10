# Tests de mutation pour les smart contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Les tests de mutation « testent vos tests » en introduisant systématiquement de petites modifications (mutants) dans le code du contrat, puis en relançant la suite de tests. Si un test échoue, le mutant est éliminé. Si les tests réussissent toujours, le mutant survit, révélant un angle mort que la couverture des lignes ou des branches ne peut pas détecter.

Idée clé : la couverture montre que le code a été exécuté ; les tests de mutation montrent si le comportement a réellement été vérifié.<sup>[[2]](#references)</sup>

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

Les tests unitaires qui vérifient uniquement une valeur inférieure au seuil et une valeur supérieure au seuil peuvent atteindre une couverture de lignes/de branches de 100 % sans vérifier le cas d’égalité (==). Une refactorisation vers `deposit >= 2 ether` réussirait toujours ces tests, tout en rompant silencieusement la logique du protocole.<sup>[[2]](#references)</sup>

Les tests de mutation révèlent cette lacune en mutant la condition et en vérifiant que les tests échouent.

Dans les smart contracts, les mutants survivants correspondent souvent à des vérifications manquantes concernant :
- Les autorisations et les limites des rôles
- Les invariants de comptabilité et de transfert de valeur
- Les conditions de revert et les chemins d’échec
- Les conditions limites (`==`, valeurs nulles, tableaux vides, valeurs maximales/minimales)

## Opérateurs de mutation offrant le meilleur signal de sécurité

Classes de mutation utiles pour l’audit de contrats :<sup>[[1]](#references)[[2]](#references)</sup>
- **Gravité élevée** : remplacer des instructions par `revert()` pour révéler les chemins non exécutés
- **Gravité moyenne** : commenter des lignes / supprimer de la logique pour révéler les effets secondaires non vérifiés
- **Gravité faible** : remplacer subtilement des opérateurs ou des constantes, par exemple `>=` -> `>` ou `+` -> `-`
- Autres modifications courantes : remplacement d’affectation, inversion de booléens, négation de condition et changements de type

Objectif pratique : éliminer tous les mutants significatifs et justifier explicitement ceux qui survivent parce qu’ils sont sans pertinence ou sémantiquement équivalents.

## Pourquoi la mutation tenant compte de la syntaxe est préférable aux expressions régulières

Les anciens moteurs de mutation s’appuyaient sur des expressions régulières ou des réécritures ligne par ligne. Cette méthode fonctionne, mais présente d’importantes limites :<sup>[[1]](#references)</sup>
- Les instructions sur plusieurs lignes sont difficiles à muter sans risque
- La structure du langage n’est pas comprise, ce qui peut cibler les commentaires et les tokens de manière inadaptée
- Générer toutes les variantes possibles sur une ligne peu pertinente gaspille beaucoup de temps d’exécution

Les outils basés sur AST ou Tree-sitter améliorent la méthode en ciblant des nœuds structurés plutôt que des lignes brutes :<sup>[[1]](#references)</sup>
- **slither-mutate** utilise l’AST Solidity de Slither.<sup>[[4]](#references)</sup>
- **mewt** utilise Tree-sitter comme cœur indépendant du langage.<sup>[[6]](#references)</sup>
- **MuTON** s’appuie sur `mewt` et ajoute une prise en charge native des langages TON tels que FunC, Tolk et Tact.<sup>[[7]](#references)</sup>

Les constructions sur plusieurs lignes et les mutations au niveau des expressions sont ainsi beaucoup plus fiables qu’avec les approches reposant uniquement sur les expressions régulières.

## Exécuter des tests de mutation avec slither-mutate

Prérequis : Slither v0.10.2+.

- Lister les options et les mutateurs :

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Exemple avec Foundry (capturer les résultats et conserver un journal complet) :<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- Si vous n’utilisez pas Foundry, remplacez `--test-cmd` par la commande que vous utilisez pour lancer les tests (par exemple, `npx hardhat test`, `npm test`).

Par défaut, les artefacts sont stockés dans `./mutation_campaign`. Les mutants non détectés (survivants) y sont copiés pour inspection.<sup>[[5]](#references)</sup>

### Comprendre la sortie

Les lignes de rapport ressemblent à ceci :

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- La balise entre crochets est l’alias du mutateur (par exemple, `CR` = Comment Replacement).
- `UNCAUGHT` signifie que les tests ont réussi avec le comportement muté → assertion manquante.

## Réduire la durée d’exécution : prioriser les mutants ayant le plus d’impact

Les campagnes de mutation peuvent durer des heures ou des jours. Conseils pour réduire les coûts :<sup>[[1]](#references)[[2]](#references)</sup>
- Limiter le périmètre : commencer par les contrats/répertoires critiques, puis élargir.
- Prioriser les mutateurs : si un mutant prioritaire sur une ligne survit (par exemple, `revert()` ou un commentaire), ignorer les variantes moins prioritaires pour cette ligne.
- Utiliser des campagnes en deux phases : exécuter d’abord des tests ciblés/rapides, puis retester uniquement les mutants non détectés avec la suite complète.
- Dans la mesure du possible, associer les cibles de mutation à des commandes de test spécifiques (par exemple, code d’authentification → tests d’authentification).
- Lorsque le temps manque, limiter les campagnes aux mutants de gravité moyenne ou élevée.
- Exécuter les tests en parallèle si votre runner le permet ; mettre en cache les dépendances et les builds.
- Arrêter dès qu’une modification met clairement en évidence une lacune dans les assertions.

Le calcul de la durée est brutal : `1000 mutants x 5-minute tests ~= 83 hours` ; la conception de la campagne compte donc autant que le mutateur lui-même.<sup>[[1]](#references)</sup>

## Campagnes persistantes et triage à grande échelle

L’une des faiblesses des anciens workflows est que les résultats sont uniquement envoyés vers `stdout`. Pour les campagnes longues, cela complique la mise en pause et la reprise, le filtrage et l’examen des résultats.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` améliorent cet aspect en stockant les mutants et leurs résultats dans des campagnes reposant sur SQLite. Avantages :<sup>[[1]](#references)</sup>
- Mettre en pause et reprendre les longues exécutions sans perdre la progression
- Filtrer les seuls mutants non détectés d’un fichier ou d’une classe de mutation spécifique
- Exporter/traduire les résultats au format SARIF pour les outils d’examen
- Fournir aux outils de triage assistés par l’IA des ensembles de résultats plus petits et filtrés, plutôt que des journaux bruts du terminal

Les résultats persistants sont particulièrement utiles lorsque le mutation testing devient une étape d’un pipeline d’audit, plutôt qu’un examen manuel ponctuel.

## Workflow de triage des mutants survivants

1) Examiner la ligne mutée et son comportement.
   - Reproduire le problème localement en appliquant la ligne mutée et en exécutant un test ciblé.

2) Renforcer les tests pour vérifier l’état, et pas uniquement les valeurs de retour.
   - Ajouter des vérifications aux limites d’égalité (par exemple, tester le seuil `==`).
   - Vérifier les postconditions : soldes, offre totale, effets de l’autorisation et événements émis.

3) Remplacer les mocks trop permissifs par un comportement réaliste.
   - S’assurer que les mocks vérifient les transferts, les cas d’échec et les émissions d’événements qui se produisent on-chain.

4) Ajouter des invariants aux tests fuzz.
   - Par exemple : conservation de la valeur, soldes non négatifs, invariants d’autorisation et offre monotone, le cas échéant.

5) Distinguer les vrais positifs des no-ops sémantiques.
   - Exemple : `x > 0` → `x != 0` n’a aucun effet si `x` est non signé.

6) Relancer la campagne jusqu’à ce que les mutants survivants soient éliminés ou explicitement justifiés.

## Étude de cas : révéler des assertions d’état manquantes (protocole Arkis)

Une campagne de mutation menée pendant un audit du protocole DeFi Arkis a révélé des mutants survivants tels que :<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Commenter l’affectation n’a pas fait échouer les tests, ce qui prouve l’absence d’assertions sur l’état après exécution. Cause racine : le code faisait confiance à `_cmd.value`, contrôlé par l’utilisateur, au lieu de valider les transferts de tokens réellement effectués. Un attaquant pouvait désynchroniser les transferts attendus et réels pour drainer les fonds. Résultat : risque élevé pour la solvabilité du protocole.<sup>[[2]](#references)[[3]](#references)</sup>

Conseil : considérez les mutants survivants qui affectent les transferts de valeur, la comptabilité ou le contrôle d’accès comme présentant un risque élevé tant qu’ils ne sont pas éliminés.

## Ne générez pas aveuglément des tests pour éliminer chaque mutant

La génération de tests guidée par les mutations peut se retourner contre vous si l’implémentation actuelle est incorrecte. Exemple : remplacer `priority >= 2` par `priority > 2` modifie le comportement, mais la bonne correction n’est pas toujours « écrire un test pour `priority == 2` ». Ce comportement peut lui-même être le bug.<sup>[[1]](#references)</sup>

Processus plus sûr :
- Utilisez les mutants survivants pour repérer les exigences ambiguës
- Validez le comportement attendu à partir des spécifications, de la documentation du protocole ou des retours des réviseurs
- Ce n’est qu’ensuite que vous encodez ce comportement sous forme de test ou d’invariant

Sinon, vous risquez de figer des accidents d’implémentation dans la suite de tests et d’acquérir une fausse confiance.

## Liste de contrôle pratique

- Lancez une campagne ciblée :
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- Privilégiez les mutateurs qui tiennent compte de la syntaxe (AST/Tree-sitter) plutôt que ceux qui utilisent uniquement des expressions régulières, lorsqu’ils sont disponibles.
- Triez les mutants survivants et écrivez des tests/invariants qui échoueraient avec le comportement muté.
- Vérifiez les soldes, l’offre, les autorisations et les événements.
- Ajoutez des tests aux limites (`==`, dépassements/sous-dépassements, adresse zéro, montant nul, tableaux vides).
- Remplacez les mocks irréalistes ; simulez les modes de défaillance.
- Conservez les résultats lorsque l’outil le permet et filtrez les mutants non interceptés avant le tri.
- Utilisez des campagnes en deux phases ou par cible pour maîtriser le temps d’exécution.
- Répétez jusqu’à ce que tous les mutants soient éliminés ou justifiés par des commentaires et des arguments.

## References

- [1] [Tests de mutation à l’ère agentique](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Utilisez les tests de mutation pour trouver les bugs que vos tests ne détectent pas (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Examen de sécurité d’Arkis DeFi Prime Brokerage (annexe C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Documentation de Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
