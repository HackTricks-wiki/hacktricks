# DeFi/AMM Uitbuiting: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



Hierdie bladsy dokumenteer ’n klas DeFi/AMM-uitbuitingstegnieke teen Uniswap v4–styl DEXe wat kern‑wiskunde met custom hooks uitbrei. ’n Onlangse voorval by Bunni V2 het ’n afrondings-/presisie‑fout in ’n Liquidity Distribution Function (LDF) benut wat by elke swap uitgevoer is, wat die aanvaller in staat gestel het om positiewe krediete te verwerf en likiditeit af te dreineer.

Belangrike idee: as ’n hook addisionele rekeningkunde implementeer wat afhanklik is van fixed‑point wiskunde, tick‑afronding en drempel‑logika, kan ’n aanvaller presies‑gespesifiseerde exact‑input swaps saamstel wat spesifieke drempels kruis sodat afrondingsverskille in hul guns ophoop. Deur die patroon te herhaal en dan die opgeblase balans terug te trek, word wins gerealiseer, dikwels gefinansier met ’n flash loan.

## Agtergrond: Uniswap v4 hooks en swap‑vloei

- Hooks is kontrakte wat die PoolManager by spesifieke lewensiklus‑punte aanroep (bv. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools word geïnitialiseer met ’n PoolKey wat die hooks‑adres insluit. As dit nie‑nul is, voer PoolManager callbacks uit by elke relevante operasie.
- Hooks kan **custom deltas** teruggee wat die finale balansveranderings van ’n swap of liquidity‑aksie wysig (custom accounting). Daardie deltas word as netto‑balanse aan die einde van die oproep vereffen, so enige afrondingsfout binne hook‑wiskunde hoop op voordat vereffening plaasvind.
- Kern‑wiskunde gebruik fixed‑point formate soos Q64.96 vir sqrtPriceX96 en tick‑aritmetika met 1.0001^tick. Enige custom wiskunde bo‑op moet versorg lyk na wedstrydige afrondingssemantiek om invariant‑drif te vermy.
- Swaps kan exactInput of exactOutput wees. In v3/v4 beweeg prys langs ticks; die oorsteek van ’n tick‑grens kan range liquidity aktiveer/deaktiveer. Hooks kan ekstra logika implementeer by drempel/tick‑oorsteek.

## Kwetsbaarheid‑archetipe: drempel‑oorsteek presisie/afrondings‑drift

’n Tipiese kwesbare patroon in custom hooks:

1. Die hook bereken per‑swap liquidity of balansdeltas met integer‑deling, mulDiv, of fixed‑point omskakelings (bv. token ↔ liquidity met gebruik van sqrtPrice en tick‑reekse).
2. Drempel‑logika (bv. rebalancing, stapgewys herverdeling, of per‑range aktivering) word geaktiveer wanneer ’n swapgrootte of prysbewegings ’n interne grens kruis.
3. Afronding word inkonsekwent toegepas (bv. truncation na nul, floor teenoor ceil) tussen die vorentoe berekening en die vereffeningspad. Klein verskille kanselleer nie en krediteer in plaas daarvan die oproeper.
4. Exact‑input swaps, presies geskaal om daardie grense te randseer, pluk herhalend die positiewe afrondingsreste. Die aanvaller onttrek later die opgehoopte krediet.

Vereistes vir aanval
- ’n Pool wat ’n custom v4 hook gebruik wat addisionele wiskunde by elke swap uitvoer (bv. ’n LDF/rebalancer).
- Ten minste een uitvoeringspad waar afronding die swap‑initiatiefnemer bevoordeel oor drempel‑oorsteek.
- Vermoë om baie swaps atomies te herhaal (flash loans is ideaal om tydelike float te voorsien en gas te amortiseer).

## Praktiese aanvalsmethodologie

1) Identifiseer kandidaat‑pools met hooks
- Enumereer v4 pools en kontroleer PoolKey.hooks != address(0).
- Inspekteer hook‑bytecode/ABI vir callbacks: beforeSwap/afterSwap en enige custom rebalancing‑metodes.
- Soek na wiskunde wat: deel deur liquidity, omskakel tussen token‑bedrae en liquidity, of BalanceDelta agregg eer met afronding.

2) Modelleer die hook se wiskunde en drempels
- H erskep die hook se liquidity/redistributie‑formule: insette sluit tipies sqrtPriceX96, tickLower/Upper, currentTick, fee tier, en netto liquidity in.
- Kaart drempel/step‑funksies: ticks, bucket‑grense, of LDF‑breekpunte. Bepaal aan watter kant van elke grens die delta afgerond word.
- Identifiseer waar omskakelings tussen uint256/int256 plaasvind, SafeCast gebruik word, of mulDiv met implisiete floor staatmaak.

3) Kalibreer exact‑input swaps om grense te kruis
- Gebruik Foundry/Hardhat simulasies om die minimale Δin te bereken wat nodig is om die prys net oor ’n grens te skuif en die hook‑tak te aktiveer.
- Verifieer dat naSwap‑vereffening die oproeper meer krediteer as die koste, wat ’n positiewe BalanceDelta of krediet in die hook‑rekeninglaat.
- Herhaal swaps om krediet op te bou; roep dan die hook se withdrawal/settlement‑pad aan.

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
Kalibrering van exactInput
- Bereken ΔsqrtP vir 'n tick-stap: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Benader Δin met behulp van v3/v4-formules: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Verseker dat die afrondingsrigting ooreenstem met die kernwiskunde.
- Pas Δin aan met ±1 wei rondom die grens om die tak te vind waar die hook in jou guns afrond.

4) Vergroot met flash loans
- Neem 'n groot nominale lening (bv. 3M USDT of 2000 WETH) om baie iterasies atomies uit te voer.
- Voer die gekalibreerde swap-lus uit, onttrek daarna en betaal terug binne die flash loan callback.

Aave V3 flash loan skelet
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
- As hooks op verskeie kettings ontplooi is, herhaal dieselfde kalibrasie per ketting.
- Brug die opbrengs terug na die teikenketting en opsioneel kringloop via lending protocols om vloei te versluier.

## Common root causes in hook math

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: using unrounded ticks in one path and tick‑spaced rounding in another.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: per‑swap remainders tracked as credits that are withdrawable by the caller instead of being burned/zero‑sum.


## Custom accounting & delta amplification

- Uniswap v4 custom accounting lets hooks return deltas that directly adjust what the caller owes/receives. If the hook tracks credits internally, rounding residue can accumulate across many small operations **before** the final settlement happens.
- This makes boundary/threshold abuse stronger: the attacker can alternate `swap → withdraw → swap` in the same tx, forcing the hook to recompute deltas on slightly different state while all balances are still pending.
- When reviewing hooks, always trace how BalanceDelta/HookDelta is produced and settled. A single biased rounding in one branch can become a compounding credit when deltas are repeatedly re‑computed.

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
- Affected pools: USDC/USDT on Ethereum and weETH/ETH on Unichain, totaling about $8.4M.
- Step 1 (price push): the attacker flash‑borrowed ~3M USDT and swapped to push the tick to ~5000, shrinking the **active** USDC balance down to ~28 wei.
- Step 2 (rounding drain): 44 tiny withdrawals exploited floor rounding in `BunniHubLogic::withdraw()` to reduce the active USDC balance from 28 wei to 4 wei (‑85.7%) while only a tiny fraction of LP shares was burned. Total liquidity was underestimated by ~84.4%.
- Step 3 (liquidity rebound sandwich): a large swap moved the tick to ~839,189 (1 USDC ≈ 2.77e36 USDT). Liquidity estimates flipped and increased by ~16.8%, enabling a sandwich where the attacker swapped back at the inflated price and exited with profit.
- Fix identified in the post‑mortem: change the idle‑balance update to round **up** so repeated micro‑withdrawals can’t ratchet the pool’s active balance downward.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Opsporingskontrolelys

- Gebruik die pool 'n nie‑nul hooks address? Watter callbacks is geaktiveer?
- Is daar per‑swap redistributions/rebalances wat custom math gebruik? Enige tick/threshold logic?
- Waar word divisions/mulDiv, Q64.96 conversions, of SafeCast gebruik? Is rounding semantics wêreldwyd konsekwent?
- Kan jy Δin konstrueer wat skaars 'n grens oorsteek en 'n gunstige rounding branch lewer? Toets beide rigtings en beide exactInput en exactOutput.
- Hou die hook per‑caller krediete of deltas by wat later onttrek kan word? Verseker dat residu geneutraliseer word.

## Verwysings

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
