# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Cette page documente une classe de techniques d’exploitation DeFi/AMM visant les DEXes de type Uniswap v4 qui étendent les mathématiques cœur avec des hooks personnalisés. Un incident récent sur Bunni V2 a exploité un défaut de précision/arrondi dans une Liquidity Distribution Function (LDF) exécutée à chaque swap, permettant à l’attaquant d’accumuler des crédits positifs et de vider la liquidité.

Idée clé : si un hook implémente une comptabilité additionnelle dépendant de mathématiques en fixed‑point, d’arrondis de ticks et d’une logique de seuils, un attaquant peut construire des swaps exact‑input qui franchissent des seuils précis de sorte que les différences d’arrondi s’accumulent en sa faveur. Répéter le schéma puis retirer le solde gonflé réalise le profit, souvent financé par un flash loan.

## Contexte : Uniswap v4 hooks et flux de swap

- Hooks sont des contrats que le PoolManager appelle à des points spécifiques du cycle de vie (par ex., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Les pools sont initialisés avec un PoolKey incluant hooks address. Si non‑zéro, PoolManager effectue des callbacks sur chaque opération pertinente.
- Les hooks peuvent renvoyer des **deltas personnalisés** qui modifient les variations de balance finales d’un swap ou d’une action de liquidité (comptabilité personnalisée). Ces deltas sont soldés en tant que balances nettes à la fin de l’appel, donc toute erreur d’arrondi dans les calculs du hook s’accumule avant le règlement.
- Les mathématiques cœur utilisent des formats fixed‑point tels que Q64.96 pour sqrtPriceX96 et une arithmétique de tick avec 1.0001^tick. Toute mathématique personnalisée superposée doit soigneusement correspondre aux sémantiques d’arrondi pour éviter une dérive de l’invariant.
- Les swaps peuvent être exactInput ou exactOutput. En v3/v4, le prix se déplace le long des ticks ; franchir une frontière de tick peut activer/désactiver la liquidité de plage. Les hooks peuvent implémenter une logique supplémentaire sur les franchissements de seuil/tick.

## Archétype de vulnérabilité : dérive de précision/arrondi au franchissement de seuils

Un schéma vulnérable typique dans les hooks personnalisés :

1. Le hook calcule par‑swap des deltas de liquidité ou de balance en utilisant des divisions entières, mulDiv, ou des conversions fixed‑point (par ex., token ↔ liquidity en utilisant sqrtPrice et des ranges de tick).
2. Une logique de seuil (par ex., rebalancing, redistribution par paliers, ou activation par range) est déclenchée quand la taille d’un swap ou le mouvement de prix franchit une frontière interne.
3. L’arrondi est appliqué de manière inconsistante (par ex., troncature vers zéro, floor versus ceil) entre le calcul « forward » et le chemin de settlement. De petites divergences ne s’annulent pas et créditent au contraire le caller.
4. Des exact‑input swaps, calibrés précisément pour chevaucher ces frontières, récoltent répétitivement le reste positif d’arrondi. L’attaquant retire ensuite le crédit accumulé.

Conditions préalables à l'attaque
- Un pool utilisant un v4 hook qui effectue des calculs additionnels à chaque swap (par ex., un LDF/rebalancer).
- Au moins un chemin d’exécution où l’arrondi avantage le swap initiateur lors de franchissements de seuils.
- Capacité à répéter de nombreux swaps atomiquement (les flash loans sont idéaux pour fournir du float temporaire et amortir le gas).

## Méthodologie pratique d'attaque

1) Identifier les pools candidats avec hooks
- Énumérer les v4 pools et vérifier PoolKey.hooks != address(0).
- Inspecter le bytecode/ABI du hook pour les callbacks : beforeSwap/afterSwap et toute méthode custom de rebalancing.
- Chercher des mathématiques qui : divisent par liquidity, convertissent entre montants de token et liquidity, ou agrègent BalanceDelta avec de l’arrondi.

2) Modéliser les mathématiques et les seuils du hook
- Recréer la formule de liquidité/redistribution du hook : les inputs incluent typiquement sqrtPriceX96, tickLower/Upper, currentTick, fee tier, et net liquidity.
- Cartographier les fonctions de seuil/paliers : ticks, bornes de buckets, ou breakpoints de LDF. Déterminer de quel côté de chaque frontière le delta est arrondi.
- Identifier où les conversions effectuent des cast entre uint256/int256, utilisent SafeCast, ou s’appuient sur mulDiv avec floor implicite.

3) Calibrer des exact‑input swaps pour franchir les frontières
- Utiliser des simulations Foundry/Hardhat pour calculer le Δin minimal nécessaire pour déplacer le prix juste au‑delà d’une frontière et déclencher la branche du hook.
- Vérifier qu’après le settlement afterSwap, le caller est crédité pour plus que le coût, laissant un BalanceDelta positif ou un crédit dans la comptabilité du hook.
- Répéter les swaps pour accumuler le crédit ; puis appeler la voie de retrait/settlement du hook.

Exemple de test Foundry‑style (pseudocode)
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
Calibration de l'exactInput
- Calculer ΔsqrtP pour un pas de tick : sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Approximer Δin en utilisant les formules v3/v4 : Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Veiller à ce que le sens de l'arrondi corresponde aux mathématiques du core.
- Ajuster Δin de ±1 wei autour de la frontière pour trouver la branche où le hook arrondit en votre faveur.

4) Amplifier avec des flash loans
- Emprunter un montant notionnel important (par ex., 3M USDT ou 2000 WETH) pour exécuter de nombreuses itérations atomiquement.
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
5) Exit and cross‑chain replication
- If hooks are deployed on multiple chains, répéter la même calibration par chaîne.
- Bridge proceeds back to the target chain and optionally cycle via lending protocols to obfuscate flows.

## Common root causes in hook math

- Mixed rounding semantics: mulDiv floor() tandis que des chemins ultérieurs arrondissent en pratique vers le haut ; ou des conversions entre token/liquidity appliquent des arrondis différents.
- Tick alignment errors: utilisation de ticks non arrondis dans un chemin et d'un arrondi espacé par tick dans un autre.
- BalanceDelta sign/overflow issues lors de la conversion entre int256 et uint256 pendant le settlement.
- Perte de précision dans les conversions Q64.96 (sqrtPriceX96) non reflétée dans le mapping inverse.
- Accumulation pathways : les restes par swap suivis comme crédits retirables par le caller au lieu d'être brûlés/neutralisés.

## Custom accounting & delta amplification

- Uniswap v4 custom accounting permet aux hooks de retourner des deltas qui ajustent directement ce que le caller doit/reçoit. Si le hook suit des crédits en interne, les résidus d'arrondi peuvent s'accumuler à travers de nombreuses petites opérations **avant** le settlement final.
- Cela renforce l'abus de frontières/seuils : l'attaquant peut alterner `swap → withdraw → swap` dans la même tx, forçant le hook à recomputer des deltas sur un état légèrement différent alors que tous les soldes sont encore en attente.
- Lors de la revue des hooks, tracer toujours comment BalanceDelta/HookDelta est produit et réglé. Un seul arrondi biaisé dans une branche peut devenir un crédit composé lorsque les deltas sont recomputés à répétition.

## Defensive guidance

- Differential testing : refléter la mathématique du hook vs une implémentation de référence en utilisant de l'arithmétique rationnelle haute‑précision et_assert_ l'égalité ou une erreur bornée qui est toujours adversaire (jamais favorable au caller).
- Invariant/property tests :
- La somme des deltas (tokens, liquidity) à travers les chemins de swap et les ajustements du hook doit conserver la valeur modulo fees.
- Aucun chemin ne doit créer un crédit net positif pour l'initiateur du swap lors d'itérations répétées exactInput.
- Tests de seuil/frontière de tick autour de ±1 wei pour both exactInput/exactOutput.
- Rounding policy : centraliser les helpers d'arrondi qui arrondissent toujours contre l'utilisateur ; éliminer les casts incohérents et les floors implicites.
- Settlement sinks : accumuler les résidus d'arrondi inévitables au treasury du protocole ou les brûler ; ne jamais les attribuer à msg.sender.
- Rate‑limits/guardrails : tailles minimales de swap pour les triggers de rebalancing ; désactiver les rebalances si les deltas sont sub‑wei ; sanity‑check des deltas par rapport aux plages attendues.
- Revoir les callbacks de hook de manière holistique : beforeSwap/afterSwap et before/after liquidity changes doivent être d'accord sur l'alignement des ticks et l'arrondi des deltas.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) avec un LDF appliqué par swap pour rebalance.
- Affected pools: USDC/USDT on Ethereum and weETH/ETH on Unichain, totalisant environ $8.4M.
- Step 1 (price push): l'attaquant flash‑borrowed ~3M USDT et a swappé pour pousser le tick à ~5000, réduisant le solde **actif** en USDC à ~28 wei.
- Step 2 (rounding drain): 44 tiny withdrawals ont exploité l'arrondi floor dans `BunniHubLogic::withdraw()` pour réduire le solde actif USDC de 28 wei à 4 wei (‑85.7%) tout en ne brûlant qu'une toute petite fraction des LP shares. La liquidité totale a été sous‑estimée d'environ ~84.4%.
- Step 3 (liquidity rebound sandwich): un large swap a déplacé le tick à ~839,189 (1 USDC ≈ 2.77e36 USDT). Les estimations de liquidité ont basculé et augmenté d'environ ~16.8%, permettant un sandwich où l'attaquant a swappé en sens inverse au prix gonflé et est sorti avec profit.
- Fix identified in the post‑mortem: changer la mise à jour du idle‑balance pour arrondir **vers le haut** afin que des micro‑retraits répétés ne puissent pas descendre le solde actif du pool.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Liste de contrôle pour le hunting

- Le pool utilise‑t‑il une adresse hooks non‑nulle ? Quels callbacks sont activés ?
- Y a‑t‑il des redistributions/rééquilibrages par‑swap utilisant des mathématiques custom ? Une logique de tick/seuil ?
- Où sont utilisés divisions/mulDiv, Q64.96 conversions, ou SafeCast ? Les sémantiques d'arrondi sont‑elles cohérentes globalement ?
- Pouvez‑vous construire Δin qui franchit à peine une frontière et provoque une branche d'arrondi favorable ? Testez les deux directions et à la fois exactInput et exactOutput.
- Le hook suit‑il des crédits par‑appelant ou des deltas pouvant être retirés ensuite ? Assurez‑vous que les résidus sont neutralisés.

## Références

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
