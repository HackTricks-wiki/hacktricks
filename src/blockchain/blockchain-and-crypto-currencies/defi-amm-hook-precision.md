# Exploitation DeFi/AMM : abus de précision et d’arrondi des Hooks Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Cette page documente une catégorie de techniques d’exploitation DeFi/AMM visant les DEX de type Uniswap v4 qui étendent les mathématiques du cœur avec des hooks personnalisés. Un incident récent dans Bunni V2 a exploité une faille d’arrondi/précision dans une Liquidity Distribution Function (LDF) exécutée à chaque swap, permettant à l’attaquant d’accumuler des crédits positifs et de drainer la liquidité.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

Idée principale : si un hook implémente une comptabilité supplémentaire dépendant de mathématiques en fixed-point, de l’arrondi des ticks et d’une logique de seuils, un attaquant peut concevoir des swaps exact-input qui franchissent des seuils spécifiques afin que les divergences d’arrondi s’accumulent en sa faveur. En répétant ce schéma, puis en retirant le solde gonflé, il réalise un profit, souvent financé par un flash loan.

## Contexte : hooks Uniswap v4 et flux des swaps

- Les hooks sont des contrats que le PoolManager appelle à des points précis du cycle de vie (par exemple, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[3]](#references)[[6]](#references)</sup>
- Les pools sont initialisés avec un PoolKey incluant l’adresse du hook. Si elle est différente de zéro, le PoolManager exécute des callbacks lors de chaque opération concernée.<sup>[[6]](#references)</sup>
- Les hooks peuvent retourner des **custom deltas** qui modifient les variations finales de solde d’un swap ou d’une action de liquidité (custom accounting). Ces deltas sont réglés en tant que soldes nets à la fin de l’appel ; toute erreur d’arrondi à l’intérieur des mathématiques du hook s’accumule donc avant le règlement.<sup>[[5]](#references)</sup>
- Les mathématiques du cœur utilisent des formats fixed-point tels que Q64.96 pour sqrtPriceX96 et des calculs de ticks avec 1.0001^tick. Toute mathématique personnalisée ajoutée par-dessus doit correspondre soigneusement aux règles d’arrondi afin d’éviter une dérive de l’invariant.<sup>[[4]](#references)[[8]](#references)</sup>
- Les swaps peuvent être exactInput ou exactOutput. Dans v3/v4, le prix se déplace le long des ticks ; le franchissement d’une limite de tick peut activer/désactiver la liquidité d’une range. Les hooks peuvent implémenter une logique supplémentaire lors des franchissements de seuils/ticks.<sup>[[5]](#references)</sup>

## Archétype de vulnérabilité : dérive de précision/d’arrondi lors du franchissement de seuils

Un schéma typiquement vulnérable dans les hooks personnalisés :

1. Le hook calcule les variations de liquidité ou de solde par swap à l’aide d’une division entière, de mulDiv ou de conversions fixed-point (par exemple, conversion entre tokens et liquidité à l’aide de sqrtPrice et des limites de ticks).
2. Une logique de seuils (par exemple, rebalancing, redistribution par étapes ou activation par range) est déclenchée lorsqu’une taille de swap ou un mouvement de prix franchit une limite interne.
3. L’arrondi est appliqué de manière incohérente (par exemple, troncature vers zéro, floor contre ceil) entre le calcul direct et le chemin de règlement. Les petites divergences ne s’annulent pas et créditent au contraire l’appelant.
4. Des swaps exact-input, dimensionnés précisément pour chevaucher ces limites, récoltent de manière répétée le reste positif dû à l’arrondi. L’attaquant retire ensuite le crédit accumulé.

Prérequis de l’attaque
- Un pool utilisant un hook v4 personnalisé qui effectue des calculs supplémentaires à chaque swap (par exemple, un LDF/rebalancer).
- Au moins un chemin d’exécution où l’arrondi favorise l’initiateur du swap lors du franchissement de seuils.
- La possibilité de répéter de nombreux swaps de manière atomique (les flash loans sont idéaux pour fournir temporairement les fonds nécessaires et amortir les frais de gas).

## Méthodologie pratique de l’attaque

1) Identifier les pools candidats avec des hooks
- Énumérer les pools v4 et vérifier que PoolKey.hooks != address(0).
- Examiner le bytecode/ABI du hook à la recherche de callbacks : beforeSwap/afterSwap et de toute méthode personnalisée de rebalancing.
- Rechercher les mathématiques qui : divisent par la liquidité, convertissent entre montants de tokens et liquidité, ou agrègent des BalanceDelta avec un arrondi.

2) Modéliser les mathématiques et les seuils du hook
- Reproduire la formule de liquidité/redistribution du hook : les entrées incluent généralement sqrtPriceX96, tickLower/Upper, currentTick, le fee tier et la liquidité nette.
- Cartographier les fonctions de seuil/étape : ticks, limites de buckets ou breakpoints du LDF. Déterminer de quel côté de chaque limite le delta est arrondi.
- Identifier les endroits où des conversions s’effectuent entre uint256/int256, où SafeCast est utilisé ou où mulDiv repose sur un floor implicite.

3) Calibrer des swaps exact-input pour franchir les limites
- Utiliser des simulations Foundry/Hardhat afin de calculer le Δin minimal nécessaire pour déplacer le prix juste au-delà d’une limite et déclencher la branche du hook.
- Vérifier qu’après le règlement du swap, le hook crédite à l’appelant un montant supérieur au coût, en laissant un BalanceDelta positif ou un crédit dans la comptabilité du hook.
- Répéter les swaps pour accumuler le crédit, puis appeler le chemin de withdrawal/settlement du hook.

Exemple de harness de test au format Foundry (pseudocode)
```solidity
function test_precision_rounding_abuse() public {
// 1) Arrange: set up pool with hook
PoolKey memory key = PoolKey({
currency0: USDC,
currency1: USDT,
fee: 500, // 0.05%
tickSpacing: 10,
hooks: address(bunniHook)
});
pm.initialize(key, initialSqrtPriceX96);

// 2) Determine a boundary‑crossing exactInput
uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

// 3) Loop swaps to accrue rounding credit
for (uint i; i < N; ++i) {
pm.swap(
key,
IPoolManager.SwapParams({
zeroForOne: true,
amountSpecified: int256(exactIn), // exactInput
sqrtPriceLimitX96: 0 // allow tick crossing
}),
""
);
}

// 4) Realize inflated credit via hook‑exposed withdrawal
bunniHook.withdrawCredits(msg.sender);
}
```
Calibrage de exactInput
- Calculer ΔsqrtP pour une étape de tick : sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Approximer Δin à l'aide des formules v3/v4 : Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Vérifier que le sens de l'arrondi correspond aux mathématiques du core.
- Ajuster Δin de ±1 wei autour de la limite afin de trouver la branche où le hook arrondit en votre faveur.

4) Amplifier avec des flash loans
- Emprunter un montant notionnel important (par ex. 3M USDT ou 2000 WETH) pour exécuter de nombreuses itérations de manière atomique.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Exécuter la boucle de swap calibrée, puis retirer et rembourser dans le callback du flash loan.

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
5) Exit et réplication cross-chain
- Si des hooks sont déployés sur plusieurs chaînes, répéter la même calibration pour chaque chaîne.
- Bridger les fonds vers la chaîne cible et, éventuellement, les faire transiter via des protocoles de lending pour obfusquer les flux.<sup>[[2]](#references)</sup>

## Causes profondes courantes dans les calculs des hooks

- Sémantiques d’arrondi mixtes : `mulDiv` arrondit vers le bas, tandis que les chemins suivants arrondissent effectivement vers le haut ; ou les conversions entre tokens/liquidité appliquent des arrondis différents.
- Erreurs d’alignement des ticks : utilisation de ticks non arrondis dans un chemin et d’un arrondi basé sur l’espacement des ticks dans un autre.
- Problèmes de signe/dépassement de `BalanceDelta` lors de la conversion entre `int256` et `uint256` pendant le settlement.
- Perte de précision dans les conversions Q64.96 (`sqrtPriceX96`) non reproduite dans le mapping inverse.
- Voies d’accumulation : les reliquats par swap sont suivis comme des crédits pouvant être retirés par le caller au lieu d’être brûlés ou neutralisés.

## Comptabilité personnalisée et amplification des deltas

- La comptabilité personnalisée d’Uniswap v4 permet aux hooks de retourner des deltas qui ajustent directement ce que le caller doit ou reçoit. Si le hook suit les crédits en interne, les résidus d’arrondi peuvent s’accumuler sur de nombreuses petites opérations **avant** le règlement final.<sup>[[5]](#references)</sup>
- Cela renforce les abus des limites et seuils : l’attaquant peut alterner `swap → withdraw → swap` dans la même tx, forçant le hook à recalculer les deltas sur un état légèrement différent alors que tous les soldes sont encore en attente.
- Lors de l’audit des hooks, toujours suivre la manière dont `BalanceDelta`/`HookDelta` est produit puis réglé. Un seul arrondi biaisé dans une branche peut devenir un crédit cumulatif lorsque les deltas sont recalculés à répétition.

## Recommandations défensives

- Tests différentiels : comparer les calculs du hook à une implémentation de référence utilisant une arithmétique rationnelle haute précision et vérifier l’égalité ou une erreur bornée qui soit toujours défavorable à l’attaquant (jamais favorable au caller).
- Tests d’invariants/propriétés :
- La somme des deltas (tokens, liquidité) sur les chemins de swap et les ajustements du hook doit préserver la valeur, modulo les frais.
- Aucun chemin ne doit créer de crédit net positif pour l’initiateur du swap au cours d’itérations répétées en `exactInput`.
- Tests des seuils et limites de ticks autour d’entrées de ±1 wei pour `exactInput` et `exactOutput`.
- Politique d’arrondi : centraliser les helpers d’arrondi afin qu’ils arrondissent toujours contre l’utilisateur ; supprimer les casts incohérents et les arrondis vers le bas implicites.
- Destinations de settlement : accumuler les résidus d’arrondi inévitables dans la treasury du protocole ou les brûler ; ne jamais les attribuer à `msg.sender`.
- Rate limits/garde-fous : tailles minimales de swap pour les déclencheurs de rebalancing ; désactiver les rebalancings si les deltas sont inférieurs au wei ; vérifier la cohérence des deltas par rapport aux plages attendues.
- Examiner globalement les callbacks du hook : `beforeSwap`/`afterSwap` et les modifications de liquidité avant/après doivent être cohérents concernant l’alignement des ticks et l’arrondi des deltas.

## Étude de cas : Bunni V2 (2025-09-02)

- Protocole : Bunni V2 (hook Uniswap v4) avec un LDF appliqué à chaque swap pour effectuer un rebalancing.<sup>[[7]](#references)</sup>
- Pools affectés : USDC/USDT sur Ethereum et weETH/ETH sur Unichain, pour un total d’environ 8,4 M$.<sup>[[1]](#references)[[2]](#references)</sup>
- Étape 1 (price push) : l’attaquant a emprunté environ 3 M d’USDT via un flash loan et a effectué un swap pour pousser le tick à environ 5000, réduisant le solde USDC **actif** à environ 28 wei.<sup>[[7]](#references)</sup>
- Étape 2 (drain par arrondi) : 44 retraits minuscules ont exploité l’arrondi vers le bas dans `BunniHubLogic::withdraw()` pour réduire le solde USDC actif de 28 wei à 4 wei (-85,7 %), alors qu’une fraction minuscule des parts LP seulement était brûlée. La liquidité totale était sous-estimée d’environ 84,4 %.<sup>[[2]](#references)[[7]](#references)</sup>
- Étape 3 (liquidity rebound sandwich) : un swap important a déplacé le tick à environ 839 189 (1 USDC ≈ 2,77e36 USDT). Les estimations de liquidité se sont inversées et ont augmenté d’environ 16,8 %, permettant un sandwich au cours duquel l’attaquant a effectué le swap inverse à un prix gonflé et est sorti avec un profit.<sup>[[7]](#references)</sup>
- Correctif identifié dans le post-mortem : modifier la mise à jour du solde idle afin d’arrondir **vers le haut**, de sorte que des micro-retraits répétés ne puissent pas faire baisser progressivement le solde actif du pool.<sup>[[7]](#references)</sup>

Ligne vulnérable simplifiée (et correctif du post-mortem)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Liste de contrôle de recherche

- Le pool utilise-t-il une adresse de hooks non nulle ? Quels callbacks sont activés ?
- Existe-t-il des redistributions/rebalances par swap utilisant des calculs personnalisés ? Une logique liée aux ticks/seuils ?
- Où sont utilisées les divisions/mulDiv, les conversions Q64.96 ou SafeCast ? Les sémantiques d’arrondi sont-elles cohérentes partout ?
- Pouvez-vous construire un Δin qui franchit à peine une limite et produit une branche d’arrondi favorable ? Testez les deux directions, ainsi que exactInput et exactOutput.
- Le hook suit-il des crédits ou deltas par caller qui peuvent être retirés ultérieurement ? Assurez-vous que le résidu est neutralisé.

## Références

- [1] [Exploit de Bunni V2 : 8,3 M$ drainés via une faille de liquidité (résumé)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Exploit de Bunni V2 : analyse complète du hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Contexte d’Uniswap v4 (recherche de QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Mécanismes de liquidité dans le core d’Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Mécanismes de swap dans le core d’Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Hooks d’Uniswap v4 et considérations de sécurité](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Post-mortem de l’exploit de Bunni (sept. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Livre blanc du core d’Uniswap v4](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
