# Exploitation DeFi/AMM : Abus de précision/arrondi des hooks Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Cette page documente une classe de techniques d'exploitation DeFi/AMM visant les DEXes de type Uniswap v4 qui étendent les mathématiques de base avec des hooks personnalisés. Un incident récent sur Bunni V2 a exploité une faille d'arrondi/de précision dans une Liquidity Distribution Function (LDF) exécutée à chaque swap, permettant à l'attaquant d'accumuler des crédits positifs et de drainer la liquidité.

Idée clé : si un hook implémente une comptabilité supplémentaire dépendant de mathématiques en virgule fixe, d'arrondis de tick et de logique de seuils, un attaquant peut construire des swaps exact‑input qui franchissent des seuils spécifiques de sorte que les divergences d'arrondi s'accumulent en sa faveur. Répéter le schéma puis retirer le solde gonflé réalise le profit, souvent financé par un flash loan.

## Contexte : hooks Uniswap v4 et flux de swap

- Les hooks sont des contrats appelés par le PoolManager à des points précis du cycle de vie (par ex., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Les pools sont initialisés avec un PoolKey incluant une adresse hooks. Si non‑zéro, le PoolManager effectue des callbacks pour chaque opération pertinente.
- Core math utilise des formats en virgule fixe tels que Q64.96 pour sqrtPriceX96 et l'arithmétique de tick avec 1.0001^tick. Toute mathématique personnalisée superposée doit soigneusement matcher les sémantiques d'arrondi pour éviter une dérive d'invariant.
- Les swaps peuvent être exactInput ou exactOutput. En v3/v4, le prix se déplace le long des ticks ; franchir une limite de tick peut activer/désactiver la liquidity de range. Les hooks peuvent implémenter une logique additionnelle sur les franchissements de seuil/tick.

## Archétype de vulnérabilité : dérive de précision/arrondi au franchissement de seuil

Un schéma typique vulnérable dans des hooks personnalisés :

1. Le hook calcule des deltas de liquidity ou de balance par swap en utilisant des divisions entières, mulDiv, ou des conversions en virgule fixe (par ex., token ↔ liquidity utilisant sqrtPrice et des tick ranges).
2. Une logique de seuil (par ex., rebalancing, redistribution par paliers, ou activation par range) est déclenchée lorsque la taille du swap ou le mouvement de prix franchit une frontière interne.
3. L'arrondi est appliqué de manière incohérente (par ex., troncature vers zéro, floor versus ceil) entre le calcul avant et le chemin de settlement. De petites divergences ne se compensent pas et créditent plutôt l'appelant.
4. Des swaps exact‑input, précisément calibrés pour chevaucher ces frontières, récoltent répétitivement le reste positif d'arrondi. L'attaquant retire ensuite le crédit accumulé.

Conditions préalables à l'attaque
- Un pool utilisant un hook v4 personnalisé qui effectue des calculs supplémentaires à chaque swap (par ex., une LDF/rebalancer).
- Au moins un chemin d'exécution où l'arrondi avantage l'initiateur du swap lors des franchissements de seuil.
- Capacité à répéter de nombreux swaps de manière atomique (les flash loans sont idéaux pour fournir la trésorerie temporaire et amortir le gas).

## Méthodologie pratique d'attaque

1) Identifier les pools candidats avec hooks
- Énumérer les pools v4 et vérifier PoolKey.hooks != address(0).
- Inspecter le bytecode/ABI du hook pour les callbacks : beforeSwap/afterSwap et toute méthode de rebalancing personnalisée.
- Chercher des mathématiques qui : divisent par liquidity, convertissent entre token et liquidity, ou agrègent BalanceDelta avec arrondi.

2) Modéliser les mathématiques et seuils du hook
- Recréer la formule de liquidity/redistribution du hook : les entrées incluent typiquement sqrtPriceX96, tickLower/Upper, currentTick, fee tier, et net liquidity.
- Cartographier les fonctions de seuil/paliers : ticks, frontières de buckets, ou breakpoints LDF. Déterminer de quel côté de chaque frontière le delta est arrondi.
- Identifier où les conversions castent entre uint256/int256, utilisent SafeCast, ou reposent sur mulDiv avec floor implicite.

3) Calibrer des swaps exact‑input pour franchir les frontières
- Utiliser Foundry/Hardhat simulations pour calculer le Δin minimal nécessaire pour déplacer le prix juste au‑delà d'une frontière et déclencher la branche du hook.
- Vérifier qu'après le settlement du swap, l'appelant est crédité de plus que le coût, laissant un BalanceDelta ou un crédit positif dans la comptabilité du hook.
- Répéter les swaps pour accumuler le crédit ; puis appeler le chemin de retrait/settlement du hook.

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
Calibrer l'exactInput
- Calculer ΔsqrtP pour un pas de tick : sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Approximer Δin en utilisant les formules v3/v4 : Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Veiller à ce que le sens d'arrondi corresponde aux calculs fondamentaux.
- Ajuster Δin de ±1 wei autour de la frontière pour trouver la branche où le hook arrondit en votre faveur.

4) Amplify with flash loans
- Emprunter un montant important (p. ex., 3M USDT ou 2000 WETH) pour exécuter de nombreuses itérations atomiquement.
- Exécuter la boucle de swap calibrée, puis withdraw et repay dans la callback du flash loan.

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
5) Sortie et réplication inter‑chaînes
- Si des hooks sont déployés sur plusieurs chaînes, répétez la même calibration par chaîne.
- On utilise un bridge pour renvoyer les fonds vers la chaîne cible et, optionnellement, on effectue des cycles via des protocoles de prêt pour obfusquer les flux.

## Common root causes in hook math

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: using unrounded ticks in one path and tick‑spaced rounding in another.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: per‑swap remainders tracked as credits that are withdrawable by the caller instead of being burned/zero‑sum.

## Defensive guidance

- Differential testing: mirror the hook’s math vs a reference implementation using high‑precision rational arithmetic and assert equality or bounded error that is always adversarial (never favorable to caller).
- Invariant/property tests:
- Sum of deltas (tokens, liquidity) across swap paths and hook adjustments must conserve value modulo fees.
- No path should create positive net credit for the swap initiator over repeated exactInput iterations.
- Threshold/tick boundary tests around ±1 wei inputs for both exactInput/exactOutput.
- Rounding policy: centralize rounding helpers that always round against the user; eliminate inconsistent casts and implicit floors.
- Settlement sinks: accumulate unavoidable rounding residue to protocol treasury or burn it; never attribute to msg.sender.
- Rate‑limits/guardrails: minimum swap sizes for rebalancing triggers; disable rebalances if deltas are sub‑wei; sanity‑check deltas against expected ranges.
- Review hook callbacks holistically: beforeSwap/afterSwap and before/after liquidity changes should agree on tick alignment and delta rounding.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) with an LDF applied per swap to rebalance.
- Root cause: rounding/precision error in LDF liquidity accounting during threshold‑crossing swaps; per‑swap discrepancies accrued as positive credits for the caller.
- Ethereum leg: attacker took a ~3M USDT flash loan, performed calibrated exact‑input swaps on USDC/USDT to build credits, withdrew inflated balances, repaid, and routed funds via Aave.
- UniChain leg: repeated the exploit with a 2000 WETH flash loan, siphoning ~1366 WETH and transferring the funds via a bridge to Ethereum.
- Impact: ~USD 8.3M drained across chains. No user interaction required; entirely on‑chain.

## Hunting checklist

- Does the pool use a non‑zero hooks address? Which callbacks are enabled?
- Are there per‑swap redistributions/rebalances using custom math? Any tick/threshold logic?
- Where are divisions/mulDiv, Q64.96 conversions, or SafeCast used? Are rounding semantics globally consistent?
- Can you construct Δin that barely crosses a boundary and yields a favorable rounding branch? Test both directions and both exactInput and exactOutput.
- Does the hook track per‑caller credits or deltas that can be withdrawn later? Ensure residue is neutralized.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
