# Exploitation DeFi/AMM : abus de précision/d’arrondi des hooks Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Cette page documente une classe de techniques d’exploitation DeFi/AMM contre les DEX de type Uniswap v4 qui étendent les mathématiques du cœur avec des hooks personnalisés. Un incident Bunni V2 illustre une défaillance connexe : un bug dans le sens d’arrondi du calcul des retraits a sous-évalué la liquidité active, puis un swap ultérieur a exposé cette sous-évaluation dans un sandwich rentable.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Idée principale : si un hook implémente une comptabilité supplémentaire dépendant de calculs en virgule fixe, de l’arrondi des ticks et d’une logique de seuils, un attaquant peut créer des swaps exact-input qui franchissent des seuils précis afin que les écarts d’arrondi s’accumulent en sa faveur. En répétant le schéma, puis en retirant le solde gonflé, il réalise un profit, souvent financé par un flash loan.

## Contexte : hooks Uniswap v4 et déroulement des swaps

- Les hooks sont des contrats que le PoolManager appelle à des points précis du cycle de vie (par exemple, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Les pools sont initialisés avec un PoolKey qui inclut le contrat du hook. Une adresse de hook non nulle active les callbacks sélectionnés pour ce pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Les hooks peuvent renvoyer des **custom deltas** qui modifient les variations finales de solde d’un swap ou d’une action de liquidité (custom accounting). Ces deltas sont réglés comme des soldes nets à la fin de l’appel ; toute erreur d’arrondi dans les calculs du hook s’accumule donc avant le règlement.<sup>[[4]](#references)</sup>
- Les calculs du cœur utilisent des formats en virgule fixe tels que Q64.96 pour sqrtPriceX96 ainsi que l’arithmétique des ticks avec 1.0001^tick. Tout calcul personnalisé ajouté par-dessus doit correspondre soigneusement aux sémantiques d’arrondi afin d’éviter une dérive de l’invariant.<sup>[[12]](#references)[[13]](#references)</sup>
- Les swaps peuvent être de type exactInput ou exactOutput. Dans v3/v4, le prix évolue le long des ticks ; franchir une limite de tick peut activer/désactiver la liquidité d’une plage. Les hooks peuvent implémenter une logique supplémentaire lors des franchissements de seuils/ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Archétype de vulnérabilité : dérive de précision/d’arrondi lors du franchissement de seuils

Schéma typique vulnérable dans les hooks personnalisés :

1. Le hook calcule les deltas de liquidité ou de solde par swap à l’aide d’une division entière, de mulDiv ou de conversions en virgule fixe (par exemple, conversion entre tokens et liquidité à l’aide du sqrtPrice et des plages de ticks).
2. La logique de seuils (par exemple, rééquilibrage, redistribution par étapes ou activation par plage) est déclenchée lorsqu’une taille de swap ou un mouvement de prix franchit une limite interne.
3. L’arrondi est appliqué de manière incohérente (par exemple, troncature vers zéro, floor contre ceil) entre le calcul direct et le chemin de règlement. Les petites différences ne s’annulent pas et créditent au contraire l’appelant.
4. Des swaps exact-input, dimensionnés précisément pour chevaucher ces limites, récupèrent à plusieurs reprises le reste positif dû à l’arrondi. L’attaquant retire ensuite le crédit accumulé.

Conditions préalables de l’attaque
- Un pool utilisant un hook v4 personnalisé qui effectue des calculs supplémentaires à chaque swap (par exemple, un LDF/rebalancer).
- Au moins un chemin d’exécution dans lequel l’arrondi favorise l’initiateur du swap lors des franchissements de seuils.
- La possibilité de répéter de nombreux swaps de manière atomique (les flash loans sont idéaux pour fournir un float temporaire et amortir le gas).

## Méthodologie pratique de l’attaque

1) Identifier les pools candidats avec des hooks
- Énumérer les pools v4 et vérifier que PoolKey.hooks != address(0).
- Examiner le bytecode/l’ABI du hook à la recherche de callbacks : beforeSwap/afterSwap et de toute méthode de rééquilibrage personnalisée.
- Rechercher les calculs qui : divisent par la liquidité, convertissent entre montants de tokens et liquidité, ou agrègent des BalanceDelta avec arrondi.

2) Modéliser les calculs et les seuils du hook
- Reproduire la formule de liquidité/redistribution du hook : les entrées incluent généralement sqrtPriceX96, tickLower/Upper, currentTick, le niveau de frais et la liquidité nette.
- Cartographier les fonctions de seuil/étape : ticks, limites de buckets ou points de rupture LDF. Déterminer de quel côté de chaque limite le delta est arrondi.
- Identifier les endroits où les conversions effectuent un cast entre uint256/int256, utilisent SafeCast ou dépendent d’un floor implicite avec mulDiv.

3) Calibrer les swaps exact-input pour franchir les limites
- Utiliser des simulations Foundry/Hardhat afin de calculer le Δin minimal nécessaire pour déplacer le prix juste au-delà d’une limite et déclencher la branche du hook.
- Vérifier qu’après le règlement afterSwap, le crédit accordé à l’appelant est supérieur au coût, laissant un BalanceDelta ou un crédit positif dans la comptabilité du hook.
- Répéter les swaps pour accumuler le crédit, puis appeler le chemin de retrait/règlement du hook.

Dans v4, la boucle de swap doit s’exécuter depuis un callback unlock du PoolManager ; un `amountSpecified` négatif désigne un exact input, et `sqrtPriceLimitX96` doit être strictement compris dans la plage valide. Une limite de prix nulle provoque un revert ; le pseudocode ci-dessous utilise donc la limite inférieure pour un swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Exemple de harness de test de style Foundry (pseudocode)
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
Calibrage de exactInput
- Calculez la cible avec TickMath du core : sqrtP_next = sqrtP_current × 1.0001^(Δtick) en termes de valeurs réelles ; le résultat Q64.96 est arrondi par TickMath.<sup>[[13]](#references)</sup>
- Approximativement, pour une entrée de token0 (zero-for-one), utilisez la formule compatible avec Q64.96 : Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Respectez l’arrondi spécifique à la direction de la routine du core.<sup>[[12]](#references)</sup>
- Ajustez Δin de ±1 wei autour de la limite afin de trouver la branche où le hook arrondit en votre faveur.

4) Amplifier avec des flash loans
- Empruntez un montant notionnel important (par exemple, 3M USDT ou 2000 WETH) pour exécuter de nombreuses itérations de manière atomique.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Exécutez la boucle de swap calibrée, puis retirez les fonds et remboursez le prêt dans le callback du flash loan.

Structure de flash loan Aave V3
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
- Si des hooks sont déployés sur plusieurs chains, répétez la même calibration pour chaque chain.
- Lors de l’incident Bunni, la liquidité des flash-loans et les routes de bridge différaient selon la chain. Tenez donc compte de ces contraintes propres à chaque chain lors de la reproduction de l’analyse.<sup>[[1]](#references)[[2]](#references)</sup>

## Causes racines courantes dans les calculs des hooks

- Sémantiques d’arrondi mixtes : `mulDiv` arrondit vers le bas, tandis que les chemins suivants arrondissent effectivement vers le haut ; ou les conversions entre tokens/liquidité appliquent des arrondis différents.
- Erreurs d’alignement des ticks : utilisation de ticks non arrondis dans un chemin et d’un arrondi selon l’espacement des ticks dans un autre.
- Problèmes de signe/dépassement de `BalanceDelta` lors de la conversion entre `int256` et `uint256` pendant le settlement.
- Perte de précision dans les conversions Q64.96 (`sqrtPriceX96`) non reproduite dans le mapping inverse.
- Voies d’accumulation : les restes par swap sont suivis comme des crédits pouvant être retirés par le caller au lieu d’être brûlés ou neutralisés.

## Comptabilité personnalisée et amplification des deltas

- La comptabilité personnalisée d’Uniswap v4 permet aux hooks de retourner des deltas qui ajustent directement ce que le caller doit ou reçoit. Si le hook suit les crédits en interne, le résidu d’arrondi peut s’accumuler au fil de nombreuses petites opérations **avant** le settlement final.<sup>[[4]](#references)</sup>
- Si le hook expose une voie de retrait compatible, un attaquant peut alterner `swap → withdraw → swap` au sein du même callback d’unlock de `PoolManager`, forçant le hook à recalculer les deltas sur un état légèrement différent tandis que les balances restent en attente jusqu’au settlement de l’unlock.<sup>[[4]](#references)[[10]](#references)</sup>
- Lors de l’audit des hooks, tracez toujours la manière dont `BalanceDelta`/`HookDelta` est produit et réglé. Un seul arrondi biaisé dans une branche peut devenir un crédit cumulatif lorsque les deltas sont recalculés de manière répétée.

## Recommandations défensives

- Tests différentiels : comparez les calculs du hook à une implémentation de référence utilisant une arithmétique rationnelle haute précision et vérifiez l’égalité ou une erreur bornée qui soit toujours adversariale (jamais favorable au caller).
- Tests d’invariants/propriétés :
- La somme des deltas (tokens, liquidité) sur les chemins de swap et les ajustements du hook doit préserver la valeur, modulo les frais.
- Aucun chemin ne doit créer de crédit net positif pour l’initiateur du swap au fil d’itérations répétées en `exactInput`.
- Tests des seuils/bornes de ticks autour d’entrées de ±1 wei pour `exactInput` et `exactOutput`.
- Politique d’arrondi : centralisez les helpers d’arrondi afin qu’ils arrondissent toujours contre l’utilisateur ; éliminez les casts incohérents et les arrondis vers le bas implicites.
- Destinations de settlement : accumulez le résidu d’arrondi inévitable dans la treasury du protocole ou brûlez-le ; ne l’attribuez jamais à `msg.sender`.
- Rate-limits/garde-fous : tailles minimales de swap pour les triggers de rebalancing ; désactivez les rebalancings si les deltas sont inférieurs au wei ; vérifiez la cohérence des deltas par rapport aux plages attendues.
- Examinez les callbacks des hooks de manière globale : `beforeSwap`/`afterSwap` et les changements de liquidité `before`/`after` doivent utiliser le même alignement des ticks et le même arrondi des deltas.

## Étude de cas : Bunni V2 (2025‑09‑02)

- Protocole : Bunni V2, un hook Uniswap v4 utilisant une Liquidity Density Function (LDF) pour calculer la densité des tokens et les estimations de liquidité totale.<sup>[[1]](#references)[[2]](#references)</sup>
- Pools affectés : USDC/USDT sur Ethereum et weETH/ETH sur Unichain, pour un total d’environ 8,4 M$.<sup>[[1]](#references)</sup>
- Étape 1 (price push) : l’attaquant a emprunté environ 3 M d’USDT via un flash-loan et a effectué un swap pour pousser le tick vers ~5000, réduisant la balance USDC **active** à environ 28 wei.<sup>[[1]](#references)</sup>
- Étape 2 (drain par arrondi) : 44 retraits minuscules ont exploité l’arrondi vers le bas dans `BunniHubLogic::withdraw()` pour réduire la balance USDC active de 28 wei à 4 wei (-85,7 %), alors que seule une infime fraction des parts LP était brûlée. La liquidité totale a diminué d’environ 84,4 %.<sup>[[1]](#references)[[2]](#references)</sup>
- Étape 3 (sandwich avec rebond de liquidité) : un swap important a déplacé le tick vers ~839 189 (1 USDC ≈ 2,77e36 USDT). Les estimations de liquidité se sont inversées et ont augmenté d’environ 16,8 %, permettant un sandwich au cours duquel l’attaquant a effectué le swap inverse à un prix gonflé et est sorti avec un profit.<sup>[[1]](#references)</sup>
- Correctif identifié dans le post-mortem : modifier la mise à jour de la balance inactive afin qu’elle arrondisse **vers le haut**, de sorte que les micro-retraits répétés ne fassent plus baisser progressivement la balance active du pool.<sup>[[1]](#references)</sup>

Ligne vulnérable simplifiée (et correctif du post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Liste de contrôle de hunting

- Le pool utilise-t-il une adresse de hooks non nulle ? Quels callbacks sont activés ?
- Existe-t-il des redistributions/rebalances par swap utilisant des calculs personnalisés ? Une logique de tick/threshold ?
- Où les divisions/mulDiv, les conversions Q64.96 ou SafeCast sont-ils utilisés ? Les sémantiques d’arrondi sont-elles cohérentes globalement ?
- Pouvez-vous construire un Δin qui franchit de justesse une boundary et produit une branche d’arrondi favorable ? Testez les deux directions ainsi que exactInput et exactOutput.
- Le hook suit-il des crédits ou deltas par caller pouvant être retirés ultérieurement ? Assurez-vous que le résidu est neutralisé.

## References

- [1] [Rapport post-mortem de l’exploit Bunni (sept. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit de Bunni V2 : analyse complète du hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit de Bunni V2 : 8,3 M$ drainés via une faille de liquidité (résumé)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper du Core d’Uniswap v4](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Contexte d’Uniswap v4 (recherche de QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mécanismes de liquidité dans le Core d’Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mécanismes de swap dans le Core d’Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks d’Uniswap v4 et considérations de sécurité](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol du Core d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol du Core d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol du Core d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol du Core d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey d’Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
