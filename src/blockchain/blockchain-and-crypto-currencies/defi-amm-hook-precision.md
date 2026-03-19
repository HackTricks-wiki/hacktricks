# Exploitation DeFi/AMM : Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



Cette page documente une classe de techniques d’exploitation DeFi/AMM ciblant les DEX de type Uniswap v4 qui étendent les mathématiques de base avec des hooks personnalisés. Un incident récent sur Bunni V2 a tiré parti d’un défaut de précision/arrondi dans une Liquidity Distribution Function (LDF) exécutée à chaque swap, permettant à l’attaquant d’accumuler des crédits positifs et de vider la liquidité.

Idée clé : si un hook implémente une comptabilité additionnelle qui dépend des mathématiques en virgule fixe, du rounding des ticks et d’une logique de seuils, un attaquant peut façonner des swaps exact‑input qui franchissent des seuils précis de sorte que les différences d’arrondi s’accumulent en sa faveur. Répéter le schéma puis retirer le solde gonflé réalise le profit, souvent financé par un flash loan.

## Contexte : hooks Uniswap v4 et flux de swap

- Les hooks sont des contrats que PoolManager appelle à des points de cycle spécifiques (par exemple beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Les pools sont initialisés avec un PoolKey incluant l’adresse hooks. Si non‑zéro, PoolManager effectue des callbacks à chaque opération pertinente.
- Les hooks peuvent retourner des **custom deltas** qui modifient les changements de balance finaux d’un swap ou d’une action de liquidité (comptabilité personnalisée). Ces deltas sont soldés comme des soldes nets à la fin de l’appel, donc toute erreur d’arrondi à l’intérieur des calculs du hook s’accumule avant la compensation.
- Les mathématiques de base utilisent des formats en virgule fixe tels que Q64.96 pour sqrtPriceX96 et une arithmétique de tick avec 1.0001^tick. Toute mathématique personnalisée superposée doit soigneusement matcher la sémantique d’arrondi pour éviter la dérive des invariants.
- Les swaps peuvent être exactInput ou exactOutput. En v3/v4, le prix se déplace le long des ticks ; franchir une frontière de tick peut activer/désactiver la liquidité de range. Les hooks peuvent implémenter une logique supplémentaire sur les franchissements de seuil/tick.

## Archétype de vulnérabilité : dérive de précision/arrondi au franchissement de seuil

Un pattern typique vulnérable dans des hooks personnalisés :

1. Le hook calcule des deltas de liquidité ou de balance par swap en utilisant une division entière, mulDiv, ou des conversions en virgule fixe (par ex. token ↔ liquidity en utilisant sqrtPrice et des ranges de ticks).
2. Une logique de seuil (par ex. rebalancing, redistribution par paliers, ou activation par range) est déclenchée lorsqu’un swap ou un mouvement de prix franchit une limite interne.
3. L’arrondi est appliqué de manière incohérente (par ex. troncature vers zéro, floor vs ceil) entre le calcul avant et le chemin de settlement. De petites divergences ne s’annulent pas et créditent l’initiateur.
4. Des swaps exact‑input, dimensionnés précisément pour chevaucher ces limites, récoltent répétitivement le reste positif d’arrondi. L’attaquant retire ensuite le crédit accumulé.

Conditions préalables à l’attaque
- Un pool utilisant un hook v4 personnalisé qui effectue des calculs supplémentaires à chaque swap (par ex. une LDF / rebalancer).
- Au moins un chemin d’exécution où l’arrondi bénéficie à l’initiateur du swap lors des franchissements de seuil.
- Capacité à répéter de nombreux swaps atomiquement (les flash loans sont idéaux pour fournir le float temporaire et amortir le gas).

## Méthodologie pratique d’attaque

1) Identifier les pools candidats avec hooks
- Énumérer les pools v4 et vérifier PoolKey.hooks != address(0).
- Inspecter le bytecode/ABI du hook pour les callbacks : beforeSwap/afterSwap et toute méthode de rebalancing custom.
- Chercher des mathématiques qui : divisent par liquidity, convertissent entre montants de token et liquidity, ou agrègent BalanceDelta avec arrondi.

2) Modéliser les mathématiques et les seuils du hook
- Recréer la formule de liquidity/redistribution du hook : les entrées incluent typiquement sqrtPriceX96, tickLower/Upper, currentTick, fee tier, et la liquidity nette.
- Cartographier les fonctions de seuil/paliers : ticks, frontières de buckets, ou breakpoints de LDF. Déterminer de quel côté de chaque frontière le delta est arrondi.
- Identifier où les conversions castent entre uint256/int256, utilisent SafeCast, ou reposent sur mulDiv avec floor implicite.

3) Calibrer des swaps exact‑input pour franchir les frontières
- Utiliser Foundry/Hardhat pour simuler et calculer le Δin minimal nécessaire pour déplacer le prix juste au‑delà d’une frontière et déclencher la branche du hook.
- Vérifier qu’après settlement du swap, l’initiateur est crédité plus que le coût, laissant un BalanceDelta ou un crédit positif dans la comptabilité du hook.
- Répéter les swaps pour accumuler le crédit ; puis appeler la voie de retrait/settlement du hook.

Example Foundry‑style test harness (pseudocode)
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
Calibrating the exactInput
- Calculez ΔsqrtP pour un pas de tick : sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Approximez Δin en utilisant les formules v3/v4 : Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Veillez à ce que la direction d'arrondi corresponde aux mathématiques du core.
- Ajustez Δin de ±1 wei autour de la frontière pour trouver la branche où le hook arrondit en votre faveur.

4) Amplifier avec des flash loans
- Empruntez un notional important (p.ex., 3M USDT ou 2000 WETH) pour exécuter de nombreuses itérations atomiquement.
- Exécutez la boucle de swap calibrée, puis retirez et remboursez dans le callback du flash loan.

Aave V3 flash loan skeleton
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
- Si des hooks sont déployés sur plusieurs chaînes, répéter la même calibration par chaîne.
- Bridge les produits vers la chaîne cible et éventuellement cycle via des lending protocols pour obfusquer les flux.

## Common root causes in hook math

- Mixed rounding semantics : mulDiv effectue un floor tandis que d’autres chemins arrondissent en pratique vers le haut ; ou des conversions entre token/liquidity appliquent des arrondis différents.
- Tick alignment errors : utilisation de ticks non arrondis dans un chemin et d’un arrondi espacé par tick dans un autre.
- BalanceDelta sign/overflow issues lors de la conversion entre int256 et uint256 au règlement.
- Perte de précision dans les conversions Q64.96 (sqrtPriceX96) non répercutée dans la cartographie inverse.
- Accumulation pathways : les restes par swap sont suivis comme crédits récupérables par le caller au lieu d’être brûlés/neutralisés.

## Custom accounting & delta amplification

- Uniswap v4 custom accounting permet aux hooks de retourner des deltas qui ajustent directement ce que le caller doit/reçoit. Si le hook suit des crédits en interne, les résidus d’arrondi peuvent s’accumuler sur de nombreuses petites opérations avant le règlement final.
- Cela renforce l’abus des frontières/seuils : l’attaquant peut alterner `swap → withdraw → swap` dans la même tx, forçant le hook à recalculer les deltas sur un état légèrement différent alors que tous les soldes sont encore en attente.
- Lors de la revue des hooks, tracer toujours comment BalanceDelta/HookDelta est produit et réglé. Un simple arrondi biaisé dans une branche peut devenir un crédit composé quand les deltas sont recomputés à répétition.

## Defensive guidance

- Differential testing : refléter la math du hook vs une implémentation de référence utilisant de l’arithmétique rationnelle haute‑précision et assert l’égalité ou une erreur bornée qui soit toujours adverse (jamais favorable au caller).
- Invariant/property tests :
  - La somme des deltas (tokens, liquidity) à travers les chemins de swap et les ajustements du hook doit préserver la valeur modulo les fees.
  - Aucun chemin ne doit créer un crédit net positif pour l’initiateur du swap sur des itérations répétées d’exactInput.
  - Tests aux frontières/seuils de tick autour de ±1 wei pour both exactInput/exactOutput.
- Rounding policy : centraliser des helpers d’arrondi qui arrondissent toujours contre l’utilisateur ; éliminer les casts incohérents et les floors implicites.
- Settlement sinks : accumuler les résidus d’arrondi inévitables dans la treasury du protocole ou les brûler ; ne jamais les attribuer à msg.sender.
- Rate‑limits/guardrails : tailles minimales de swap pour les triggers de rebalancing ; désactiver les rebalances si les deltas sont sub‑wei ; sanity‑check des deltas par rapport aux plages attendues.
- Revoir les callbacks des hooks de manière holistique : beforeSwap/afterSwap et before/after liquidity changes doivent être cohérents sur l’alignement des ticks et l’arrondi des deltas.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol : Bunni V2 (Uniswap v4 hook) avec un LDF appliqué par swap pour rebalancer.
- Affected pools : USDC/USDT sur Ethereum et weETH/ETH sur Unichain, totalisant environ $8.4M.
- Step 1 (price push) : l’attaquant a flash‑borrowed ~3M USDT et swap pour pousser le tick à ~5000, réduisant le solde USDC **actif** à ~28 wei.
- Step 2 (rounding drain) : 44 tiny withdrawals ont exploité le floor rounding dans `BunniHubLogic::withdraw()` pour réduire le solde USDC actif de 28 wei à 4 wei (‑85.7%) alors qu’une toute petite fraction des LP shares était brûlée. La liquidité totale a été sous‑estimée d’environ ~84.4%.
- Step 3 (liquidity rebound sandwich) : un large swap a déplacé le tick à ~839,189 (1 USDC ≈ 2.77e36 USDT). Les estimations de liquidité ont basculé et augmenté d’environ ~16.8%, permettant un sandwich où l’attaquant a swapé de retour au prix gonflé et est sorti avec profit.
- Fix identified in the post‑mortem : changer la mise à jour du idle‑balance pour arrondir **up** afin que des micro‑retraits répétés ne puissent pas faire baisser de façon progressive le solde actif du pool.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Liste de vérification pour la chasse

- Le pool utilise‑t‑il une adresse hooks non nulle ? Quels callbacks sont activés ?
- Y a‑t‑il des redistributions/rebalances par swap utilisant des mathématiques personnalisées ? Une logique de tick/seuil ?
- Où sont utilisées divisions/mulDiv, conversions Q64.96, ou SafeCast ? La sémantique d'arrondi est‑elle globalement cohérente ?
- Pouvez‑vous construire Δin qui dépasse à peine une frontière et engendre une branche d'arrondi favorable ? Testez les deux directions et les deux exactInput et exactOutput.
- Le hook suit‑il des crédits ou des deltas par appelant qui peuvent être retirés plus tard ? Assurez‑vous que les résidus sont neutralisés.

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
