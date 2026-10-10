# DeFi/AMM Exploitation : abus de précision et d’arrondi dans les hooks Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Cette page décrit une catégorie de techniques d’exploitation DeFi/AMM visant les DEX de type Uniswap v4, qui étendent les calculs de base au moyen de hooks personnalisés. Un incident Bunni V2 illustre une défaillance connexe : un bug dans le sens de l’arrondi du calcul des retraits a sous-estimé la liquidité active, et un swap ultérieur a exploité cette sous-estimation dans un sandwich rentable.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Idée clé : si un hook effectue des calculs comptables supplémentaires dépendant d’opérations en virgule fixe, de l’arrondi des ticks et d’une logique de seuil, un attaquant peut concevoir des swaps exactInput qui franchissent des seuils précis, de sorte que les écarts d’arrondi s’accumulent à son avantage. En répétant cette opération, puis en retirant le solde gonflé, il réalise un profit, souvent financé par un flash loan.

## Contexte : hooks Uniswap v4 et déroulement des swaps

- Les hooks sont des contrats que le PoolManager appelle à des étapes précises du cycle de vie (par exemple, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Les pools sont initialisés avec une PoolKey comprenant le contrat du hook. Une adresse de hook non nulle active les callbacks sélectionnés pour ce pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Les hooks peuvent renvoyer des **deltas personnalisés** qui modifient les variations de solde finales d’un swap ou d’une opération de liquidité (comptabilité personnalisée). Ces deltas sont réglés sous forme de soldes nets à la fin de l’appel, de sorte que toute erreur d’arrondi dans les calculs du hook s’accumule avant le règlement.<sup>[[4]](#references)</sup>
- Les calculs de base utilisent des formats en virgule fixe tels que Q64.96 pour sqrtPriceX96, ainsi que l’arithmétique des ticks basée sur 1.0001^tick. Tout calcul personnalisé construit par-dessus doit respecter soigneusement les règles d’arrondi pour éviter une dérive de l’invariant.<sup>[[12]](#references)[[13]](#references)</sup>
- Les swaps peuvent être de type exactInput ou exactOutput. Dans v3/v4, le prix évolue le long des ticks ; franchir une limite de tick peut activer ou désactiver la liquidité d’une plage. Les hooks peuvent implémenter une logique supplémentaire lors du franchissement de seuils ou de ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Archétype de vulnérabilité : dérive de précision et d’arrondi lors du franchissement de seuils

Schéma vulnérable courant dans les hooks personnalisés :

1. Le hook calcule les variations de liquidité ou de solde par swap à l’aide d’une division entière, de mulDiv ou de conversions en virgule fixe (par exemple, conversion entre tokens et liquidité à partir de sqrtPrice et des plages de ticks).
2. Une logique de seuil (par exemple, rééquilibrage, redistribution par étapes ou activation par plage) est déclenchée lorsqu’un volume de swap ou un mouvement de prix franchit une limite interne.
3. L’arrondi est appliqué de manière incohérente (par exemple, troncature vers zéro, arrondi inférieur ou supérieur) entre le calcul aller et le chemin de règlement. Les petits écarts ne s’annulent pas et créditent plutôt l’appelant.
4. Des swaps exactInput, dimensionnés précisément pour franchir ces limites, récoltent de façon répétée le reste positif dû à l’arrondi. L’attaquant retire ensuite le crédit accumulé.

Conditions préalables à l’attaque
- Un pool utilisant un hook v4 personnalisé qui effectue des calculs supplémentaires à chaque swap (par exemple, un LDF/rééquilibreur).
- Au moins un chemin d’exécution où l’arrondi avantage l’initiateur du swap lors du franchissement de seuils.
- La possibilité de répéter de nombreux swaps de manière atomique (les flash loans sont idéaux pour fournir des fonds temporaires et amortir les frais de gas).

## Méthodologie d’attaque pratique

1) Repérer les pools candidats dotés de hooks
- Énumérer les pools v4 et vérifier que PoolKey.hooks != address(0).
- Examiner le bytecode/ABI du hook à la recherche de callbacks : beforeSwap/afterSwap et de méthodes de rééquilibrage personnalisées.
- Repérer les calculs qui effectuent une division par la liquidité, convertissent des montants de tokens en liquidité, ou agrègent BalanceDelta avec arrondi.

2) Modéliser les calculs et les seuils du hook
- Reproduire la formule de liquidité/redistribution du hook : les entrées comprennent généralement sqrtPriceX96, tickLower/Upper, currentTick, le niveau de frais et la liquidité nette.
- Cartographier les fonctions à seuils ou par étapes : ticks, limites de compartiments ou points de rupture LDF. Déterminer de quel côté de chaque limite le delta est arrondi.
- Repérer les conversions entre uint256/int256, l’utilisation de SafeCast ou le recours à mulDiv avec arrondi inférieur implicite.

3) Calibrer les swaps exactInput pour franchir les limites
- Utiliser des simulations Foundry/Hardhat pour calculer le Δin minimal nécessaire pour déplacer le prix juste au-delà d’une limite et déclencher la branche du hook.
- Vérifier que le règlement afterSwap crédite l’appelant d’un montant supérieur au coût, laissant un BalanceDelta positif ou un crédit dans la comptabilité du hook.
- Répéter les swaps pour accumuler le crédit, puis appeler le chemin de retrait/règlement du hook.

Dans v4, la boucle de swap doit s’exécuter depuis un callback d’unlock du PoolManager ; un `amountSpecified` négatif indique un exact input, et `sqrtPriceLimitX96` doit se trouver strictement à l’intérieur de la plage valide. Une limite de prix nulle provoque un revert ; le pseudo-code ci-dessous utilise donc la limite inférieure pour un swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Exemple de banc de test de style Foundry (pseudo-code)
```solidity
function test_precision_rounding_abuse() public {
    // 1) Arrange: set up pool with hook
    PoolKey memory key = PoolKey({
        currency0: USDC,
        currency1: USDT,
        fee: 500, // 0.05%
        tickSpacing: 10,
        hooks: IHooks(address(bunniHook))
    });
    pm.initialize(key, initialSqrtPriceX96);

    // 2) Determine a boundary‑crossing exactInput
    uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

    // 3) Loop swaps to accrue rounding credit
    // This loop runs inside the PoolManager unlockCallback.
    for (uint i; i < N; ++i) {
        pm.swap(
            key,
            SwapParams({
                zeroForOne: true,
                amountSpecified: -int256(exactIn), // exactInput
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1 // allow movement to the lower bound
            }),
            ""
        );
    }

    // 4) Realize inflated credit via hook‑exposed withdrawal
    bunniHook.withdrawCredits(msg.sender);
}
```

Calibrer exactInput
- Calculer la cible avec le TickMath du core : sqrtP_next = sqrtP_current × 1.0001^(Δtick) en valeurs réelles ; le résultat Q64.96 est arrondi par TickMath.<sup>[[13]](#references)</sup>
- Approximer une entrée de token0 (zero-for-one) avec la formule tenant compte de Q64.96 : Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Respecter l’arrondi spécifique à la direction de la routine du core.<sup>[[12]](#references)</sup>
- Ajuster Δin de ±1 wei autour de la limite pour trouver la branche où le hook arrondit en votre faveur.

4) Amplifier avec des prêts flash
- Emprunter un montant notionnel important (p. ex., 3M USDT ou 2000 WETH) afin d’exécuter de nombreuses itérations de façon atomique.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Exécuter la boucle de swap calibrée, puis retirer et rembourser le prêt dans le callback du prêt flash.

Squelette de prêt flash Aave V3
```solidity
function executeOperation(
    address[] calldata assets,
    uint256[] calldata amounts,
    uint256[] calldata premiums,
    address initiator,
    bytes calldata params
) external returns (bool) {
    // run threshold‑crossing swap loop here
    for (uint i; i < N; ++i) {
        _exactInBoundaryCrossingSwap();
    }
    // realize credits / withdraw inflated balances
    bunniHook.withdrawCredits(address(this));
    // repay
    for (uint j; j < assets.length; ++j) {
        IERC20(assets[j]).approve(address(POOL), amounts[j] + premiums[j]);
    }
    return true;
}
```

5) Sortie et réplication inter-chaînes
- Si des hooks sont déployés sur plusieurs chaînes, répétez le même calibrage pour chaque chaîne.
- Lors de l’incident Bunni, la liquidité des flash loans et les routes de bridge différaient selon la chaîne ; tenez donc compte de ces contraintes propres à chaque chaîne lors de la reproduction de l’analyse.<sup>[[1]](#references)[[2]](#references)</sup>

## Causes profondes courantes des erreurs de calcul dans les hooks

- Sémantiques d’arrondi mixtes : mulDiv arrondit vers le bas, tandis que des chemins ultérieurs arrondissent effectivement vers le haut ; ou les conversions entre tokens et liquidité appliquent des règles d’arrondi différentes.
- Erreurs d’alignement des ticks : utilisation de ticks non arrondis dans un chemin et d’un arrondi par espacement des ticks dans un autre.
- Problèmes de signe ou de dépassement de capacité de BalanceDelta lors de la conversion entre int256 et uint256 pendant le règlement.
- Perte de précision lors des conversions Q64.96 (sqrtPriceX96), non reproduite dans le mappage inverse.
- Chemins d’accumulation : les reliquats par swap sont suivis comme des crédits que l’appelant peut retirer, au lieu d’être brûlés ou compensés.

## Comptabilité personnalisée et amplification des deltas

- La comptabilité personnalisée d’Uniswap v4 permet aux hooks de renvoyer des deltas qui ajustent directement ce que l’appelant doit ou reçoit. Si le hook suit les crédits en interne, les résidus d’arrondi peuvent s’accumuler au fil de nombreuses petites opérations **avant** le règlement final.<sup>[[4]](#references)</sup>
- Si le hook expose un chemin de retrait compatible, un attaquant peut alterner `swap → withdraw → swap` au sein du même callback de déverrouillage de PoolManager, forçant le hook à recalculer les deltas sur un état légèrement différent tandis que les soldes restent en attente jusqu’au règlement du déverrouillage.<sup>[[4]](#references)[[10]](#references)</sup>
- Lors de l’analyse de hooks, retracez toujours la production et le règlement de BalanceDelta/HookDelta. Un seul arrondi biaisé dans une branche peut devenir un crédit cumulatif lorsque les deltas sont recalculés à répétition.

## Recommandations de défense

- Tests différentiels : comparez les calculs du hook à une implémentation de référence utilisant une arithmétique rationnelle de haute précision et exigez une égalité ou une erreur bornée qui soit toujours défavorable à l’attaquant (jamais favorable à l’appelant).
- Tests d’invariants/propriétés :
  - La somme des deltas (tokens, liquidité) sur les chemins de swap et les ajustements du hook doit préserver la valeur, hormis les frais.
  - Aucun chemin ne doit créer de crédit net positif pour l’initiateur du swap après des itérations exactInput répétées.
  - Tests des seuils et limites de ticks avec des entrées de ±1 wei pour exactInput et exactOutput.
- Politique d’arrondi : centralisez les fonctions d’arrondi pour qu’elles soient toujours défavorables à l’utilisateur ; éliminez les conversions de types incohérentes et les arrondis implicites vers le bas.
- Affectation des résidus : accumulez les résidus d’arrondi inévitables dans la trésorerie du protocole ou brûlez-les ; ne les attribuez jamais à msg.sender.
- Limites et garde-fous : imposez des tailles de swap minimales pour les déclencheurs de rééquilibrage ; désactivez les rééquilibrages si les deltas sont inférieurs à un wei ; vérifiez que les deltas restent dans les plages attendues.
- Examinez les callbacks du hook dans leur ensemble : beforeSwap/afterSwap et les callbacks avant/après les changements de liquidité doivent appliquer les mêmes règles d’alignement des ticks et d’arrondi des deltas.

## Étude de cas : Bunni V2 (2025‑09‑02)

- Protocole : Bunni V2, un hook Uniswap v4 qui utilise une Liquidity Density Function (LDF) pour calculer la densité des tokens et les estimations de liquidité totale.<sup>[[1]](#references)[[2]](#references)</sup>
- Pools concernés : USDC/USDT sur Ethereum et weETH/ETH sur Unichain, pour un total d’environ 8,4 M$.<sup>[[1]](#references)</sup>
- Étape 1 (variation forcée du prix) : l’attaquant a emprunté environ 3 M USDT via un flash loan et a effectué un swap pour pousser le tick à environ 5000, réduisant le solde **actif** d’USDC à environ 28 wei.<sup>[[1]](#references)</sup>
- Étape 2 (drainage par arrondi) : 44 petits retraits ont exploité l’arrondi vers le bas dans `BunniHubLogic::withdraw()` pour réduire le solde actif d’USDC de 28 wei à 4 wei (-85,7 %), tandis qu’une infime fraction des parts LP seulement était brûlée. La liquidité totale a diminué d’environ 84,4 %.<sup>[[1]](#references)[[2]](#references)</sup>
- Étape 3 (sandwich avec rebond de liquidité) : un gros swap a déplacé le tick à environ 839,189 (1 USDC ≈ 2.77e36 USDT). Les estimations de liquidité se sont inversées et ont augmenté d’environ 16,8 %, permettant un sandwich dans lequel l’attaquant a effectué un swap inverse au prix gonflé et est reparti avec un bénéfice.<sup>[[1]](#references)</sup>
- Correctif identifié dans l’analyse post-mortem : modifier la mise à jour du solde inactif pour arrondir **vers le haut**, afin que les micro-retraits répétés ne fassent plus baisser progressivement le solde actif du pool.<sup>[[1]](#references)</sup>

Ligne vulnérable simplifiée (et correctif post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Liste de vérification pour la chasse

- Le pool utilise-t-il une adresse de hooks non nulle ? Quels callbacks sont activés ?
- Y a-t-il des redistributions/rééquilibrages par swap utilisant des calculs personnalisés ? Une logique de tick/seuil ?
- Où les divisions/mulDiv, conversions Q64.96 ou SafeCast sont-ils utilisés ? Les règles d’arrondi sont-elles cohérentes partout ?
- Pouvez-vous construire un Δin qui franchit tout juste une limite et déclenche une branche d’arrondi avantageuse ? Testez les deux directions, en exactInput comme en exactOutput.
- Le hook suit-il les crédits ou deltas par appelant qui peuvent être retirés ultérieurement ? Assurez-vous que les reliquats sont neutralisés.

## References

- [1] [Analyse post-mortem de l’exploit Bunni (sept. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit Bunni V2 : analyse complète du piratage](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit Bunni V2 : 8,3 M$ drainés à cause d’une faille de liquidité (résumé)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Livre blanc d’Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Contexte d’Uniswap v4 (recherche QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mécanismes de liquidité dans Uniswap v4 Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mécanismes de swap dans Uniswap v4 Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks Uniswap v4 et considérations de sécurité](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol d’Uniswap v4 Core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol d’Uniswap v4 Core](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol d’Uniswap v4 Core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol d’Uniswap v4 Core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
