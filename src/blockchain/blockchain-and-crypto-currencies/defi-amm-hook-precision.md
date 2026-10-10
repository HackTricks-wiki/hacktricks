# DeFi/AMM Exploitation: abus de précision et d’arrondi des hooks Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Cette page décrit une catégorie de techniques d’exploitation DeFi/AMM visant les DEX de type Uniswap v4, qui étendent les calculs de base à l’aide de hooks personnalisés. Un incident impliquant Bunni V2 illustre une défaillance connexe : un bug dans le sens d’arrondi du calcul des retraits a sous-estimé la liquidité active, puis un swap a révélé cette sous-estimation dans le cadre d’un sandwich rentable.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Idée clé : si un hook effectue des calculs comptables supplémentaires reposant sur des calculs à virgule fixe, l’arrondi des ticks et une logique de seuil, un attaquant peut créer des swaps exactInput qui franchissent des seuils précis, de sorte que les écarts d’arrondi s’accumulent à son avantage. En répétant cette opération, puis en retirant le solde gonflé, il réalise un profit, souvent financé par un flash loan.

## Contexte : hooks Uniswap v4 et déroulement des swaps

- Les hooks sont des contrats que le PoolManager appelle à des étapes précises du cycle de vie (par exemple, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Les pools sont initialisés avec une PoolKey qui inclut le contrat du hook. Une adresse de hook non nulle active les callbacks sélectionnés pour ce pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Les hooks peuvent renvoyer des **deltas personnalisés** qui modifient les variations finales de solde d’un swap ou d’une opération de liquidité (comptabilité personnalisée). Ces deltas sont réglés sous forme de soldes nets à la fin de l’appel ; toute erreur d’arrondi dans les calculs du hook s’accumule donc avant le règlement.<sup>[[4]](#references)</sup>
- Les calculs de base utilisent des formats à virgule fixe tels que Q64.96 pour sqrtPriceX96 et l’arithmétique des ticks basée sur 1.0001^tick. Tout calcul personnalisé ajouté par-dessus doit respecter attentivement les règles d’arrondi afin d’éviter une dérive de l’invariant.<sup>[[12]](#references)[[13]](#references)</sup>
- Les swaps peuvent être exactInput ou exactOutput. Dans v3/v4, le prix évolue le long des ticks ; le franchissement d’une limite de tick peut activer ou désactiver la liquidité d’une plage. Les hooks peuvent appliquer une logique supplémentaire lors du franchissement de seuils ou de ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Type de vulnérabilité : dérive de précision/d’arrondi lors du franchissement de seuils

Voici un schéma vulnérable courant dans les hooks personnalisés :

1. Le hook calcule les variations de liquidité ou de solde par swap à l’aide d’une division entière, de mulDiv ou de conversions à virgule fixe (par exemple, conversion entre tokens et liquidité à partir de sqrtPrice et des plages de ticks).
2. Une logique de seuil (par exemple, rééquilibrage, redistribution par étapes ou activation par plage) se déclenche lorsqu’un montant de swap ou un mouvement de prix franchit une limite interne.
3. L’arrondi est appliqué de manière incohérente (par exemple, troncature vers zéro, arrondi inférieur plutôt que supérieur) entre le calcul en amont et le chemin de règlement. Les petits écarts ne s’annulent pas et créditent plutôt l’appelant.
4. Des swaps exactInput, dimensionnés précisément pour franchir ces limites, récoltent à répétition le reste positif dû à l’arrondi. L’attaquant retire ensuite le crédit accumulé.

Conditions préalables à l’attaque
- Un pool utilisant un hook v4 personnalisé qui effectue des calculs supplémentaires à chaque swap (par exemple, un LDF/rééquilibreur).
- Au moins un chemin d’exécution où l’arrondi avantage l’initiateur du swap lors du franchissement de seuils.
- La possibilité de répéter de nombreux swaps de manière atomique (les flash loans sont idéaux pour fournir des fonds temporaires et amortir le gas).

## Méthodologie pratique d’attaque

1) Repérer les pools candidats avec des hooks
- Énumérer les pools v4 et vérifier que PoolKey.hooks != address(0).
- Examiner le bytecode/ABI du hook pour repérer les callbacks : beforeSwap/afterSwap et les méthodes de rééquilibrage personnalisées.
- Rechercher les calculs qui : divisent par la liquidité, convertissent des montants de tokens en liquidité, ou agrègent des BalanceDelta avec arrondi.

2) Modéliser les calculs et les seuils du hook
- Reproduire la formule de liquidité/redistribution du hook : les entrées incluent généralement sqrtPriceX96, tickLower/Upper, currentTick, le niveau de frais et la liquidité nette.
- Cartographier les fonctions à seuil/à étapes : ticks, limites de compartiments ou points de rupture LDF. Déterminer de quel côté de chaque limite le delta est arrondi.
- Repérer les conversions entre uint256/int256, l’utilisation de SafeCast ou le recours à mulDiv avec un arrondi inférieur implicite.

3) Calibrer des swaps exactInput pour franchir les limites
- Utiliser des simulations Foundry/Hardhat pour calculer le Δin minimal nécessaire afin de faire évoluer le prix juste au-delà d’une limite et déclencher la branche du hook.
- Vérifier que le règlement afterSwap crédite l’appelant au-delà du coût, en laissant un BalanceDelta positif ou un crédit dans la comptabilité du hook.
- Répéter les swaps pour accumuler le crédit, puis appeler le chemin de retrait/règlement du hook.

Dans v4, la boucle de swap doit être exécutée depuis un callback de déverrouillage du PoolManager ; `amountSpecified` négatif désigne un exact input, et `sqrtPriceLimitX96` doit se trouver strictement dans la plage valide. Une limite de prix à zéro provoque un revert ; le pseudocode ci-dessous utilise donc la borne inférieure pour un swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Exemple de banc de test de style Foundry (pseudocode)
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

Calibrer le exactInput
- Calculer la cible avec le TickMath du core : sqrtP_next = sqrtP_current × 1.0001^(Δtick) en valeurs réelles ; le résultat Q64.96 est arrondi par TickMath.<sup>[[13]](#references)</sup>
- Approximater un input de token0 (zero-for-one) avec la formule tenant compte de Q64.96 : Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Respecter l’arrondi directionnel de la routine core.<sup>[[12]](#references)</sup>
- Ajuster Δin de ±1 wei autour de la frontière pour trouver la branche où le hook arrondit en votre faveur.

4) Amplifier avec des flash loans
- Emprunter un montant nominal important (par exemple, 3M USDT ou 2000 WETH) pour effectuer de nombreuses itérations de manière atomique.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Exécuter la boucle de swaps calibrée, puis retirer les fonds et rembourser dans le callback du flash loan.

Squelette de flash loan Aave V3
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

5) Sortie et réplication cross-chain
- Si des hooks sont déployés sur plusieurs chaînes, répétez le même calibrage pour chaque chaîne.
- Lors de l’incident Bunni, la liquidité des prêts flash et les routes de bridge différaient selon la chaîne ; tenez donc compte de ces contraintes propres à chaque chaîne lors de la reproduction de l’analyse.<sup>[[1]](#references)[[2]](#references)</sup>

## Causes profondes courantes des erreurs de calcul dans les hooks

- Sémantiques d’arrondi mixtes : mulDiv arrondit vers le bas, tandis que les chemins ultérieurs arrondissent en pratique vers le haut ; ou les conversions entre tokens et liquidité appliquent des arrondis différents.
- Erreurs d’alignement des ticks : utilisation de ticks non arrondis dans un chemin et d’un arrondi selon l’espacement des ticks dans un autre.
- Problèmes de signe ou de dépassement de capacité de BalanceDelta lors de la conversion entre int256 et uint256 pendant le règlement.
- Perte de précision lors des conversions Q64.96 (sqrtPriceX96), sans équivalent dans la conversion inverse.
- Voies d’accumulation : les restes par swap sont comptabilisés comme des crédits que l’appelant peut retirer au lieu d’être brûlés ou compensés à somme nulle.

## Comptabilité personnalisée et amplification des deltas

- La comptabilité personnalisée d’Uniswap v4 permet aux hooks de renvoyer des deltas qui ajustent directement ce que l’appelant doit ou reçoit. Si le hook comptabilise les crédits en interne, les résidus d’arrondi peuvent s’accumuler au fil de nombreuses petites opérations **avant** le règlement final.<sup>[[4]](#references)</sup>
- Si le hook expose une fonction de retrait compatible, un attaquant peut alterner `swap → withdraw → swap` dans le même callback de déverrouillage de PoolManager, forçant le hook à recalculer les deltas à partir d’un état légèrement différent, tandis que les soldes restent en attente jusqu’au règlement du déverrouillage.<sup>[[4]](#references)[[10]](#references)</sup>
- Lors de l’audit de hooks, suivez toujours la production et le règlement de BalanceDelta/HookDelta. Un seul arrondi biaisé dans une branche peut créer un crédit cumulatif si les deltas sont recalculés à répétition.

## Recommandations défensives

- Tests différentiels : comparez les calculs du hook à une implémentation de référence utilisant une arithmétique rationnelle de haute précision et vérifiez l’égalité ou une erreur bornée, toujours défavorable à l’attaquant (jamais en sa faveur).
- Tests d’invariants et de propriétés :
  - La somme des deltas (tokens, liquidité) sur les chemins de swap et les ajustements du hook doit préserver la valeur, hors frais.
  - Aucun chemin ne doit créer de crédit net positif pour l’initiateur du swap après des itérations répétées d’exactInput.
  - Tests des seuils et des limites de ticks avec des entrées de ±1 wei pour exactInput et exactOutput.
- Politique d’arrondi : centralisez les fonctions d’arrondi, qui doivent toujours arrondir au détriment de l’utilisateur ; éliminez les conversions de types incohérentes et les arrondis implicites vers le bas.
- Affectation des résidus : affectez les résidus d’arrondi inévitables à la trésorerie du protocole ou brûlez-les ; ne les attribuez jamais à msg.sender.
- Limites et garde-fous : imposez des tailles minimales de swap pour les déclencheurs de rééquilibrage ; désactivez les rééquilibrages si les deltas sont inférieurs à un wei ; vérifiez la cohérence des deltas avec les plages attendues.
- Examinez les callbacks des hooks dans leur ensemble : beforeSwap/afterSwap et les callbacks avant/après les changements de liquidité doivent appliquer les mêmes règles d’alignement des ticks et d’arrondi des deltas.

## Étude de cas : Bunni V2 (2025‑09‑02)

- Protocole : Bunni V2, un hook Uniswap v4 utilisant une Liquidity Density Function (LDF) pour calculer la densité des tokens et les estimations de liquidité totale.<sup>[[1]](#references)[[2]](#references)</sup>
- Pools concernés : USDC/USDT sur Ethereum et weETH/ETH sur Unichain, pour un total d’environ 8,4 M$.<sup>[[1]](#references)</sup>
- Étape 1 (variation forcée du prix) : l’attaquant a emprunté environ 3 M USDT via un prêt flash et a effectué un swap pour pousser le tick à environ 5000, faisant chuter le solde **actif** d’USDC à environ 28 wei.<sup>[[1]](#references)</sup>
- Étape 2 (drainage par arrondi) : 44 retraits minimes ont exploité l’arrondi vers le bas de `BunniHubLogic::withdraw()` pour faire passer le solde actif d’USDC de 28 wei à 4 wei (-85,7 %), alors qu’une infime fraction des parts LP seulement était brûlée. La liquidité totale a diminué d’environ 84,4 %.<sup>[[1]](#references)[[2]](#references)</sup>
- Étape 3 (sandwich avec rebond de liquidité) : un swap important a déplacé le tick à environ 839,189 (1 USDC ≈ 2.77e36 USDT). Les estimations de liquidité se sont inversées et ont augmenté d’environ 16,8 %, permettant un sandwich dans lequel l’attaquant a effectué le swap inverse à un prix gonflé et est sorti avec un bénéfice.<sup>[[1]](#references)</sup>
- Correctif identifié dans l’analyse post-mortem : modifier la mise à jour du solde inactif pour arrondir **vers le haut**, afin que les micro-retraits répétés ne fassent plus baisser progressivement le solde actif du pool.<sup>[[1]](#references)</sup>

Ligne vulnérable simplifiée (et correctif post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Liste de vérification pour la chasse

- Le pool utilise-t-il une adresse hooks non nulle ? Quels callbacks sont activés ?
- Y a-t-il des redistributions/rééquilibrages à chaque swap utilisant des calculs personnalisés ? Une logique de tick/seuil ?
- Où sont utilisés les divisions/mulDiv, les conversions Q64.96 ou SafeCast ? Les règles d’arrondi sont-elles cohérentes partout ?
- Pouvez-vous construire un Δin qui franchit de justesse une limite et produit une branche d’arrondi favorable ? Testez les deux directions, avec exactInput et exactOutput.
- Le hook suit-il les crédits ou deltas par appelant qui peuvent être retirés ultérieurement ? Assurez-vous que les reliquats sont neutralisés.

## References

- [1] [Rapport post-mortem de l’exploit Bunni (sept. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit Bunni V2 : analyse complète du hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit Bunni V2 : 8,3 M$ drainés à cause d’une faille de liquidité (résumé)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Livre blanc du cœur d’Uniswap v4](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Présentation d’Uniswap v4 (recherche QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mécanismes de liquidité dans le cœur d’Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mécanismes de swap dans le cœur d’Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks Uniswap v4 et considérations de sécurité](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol du cœur d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol du cœur d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol du cœur d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol du cœur d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
