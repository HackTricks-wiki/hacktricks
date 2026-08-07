# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy dokumenteer ’n klas DeFi/AMM-exploitation-tegnieke teen Uniswap v4–styl DEXes wat core math uitbrei met custom hooks. ’n Onlangse incident in Bunni V2 het ’n rounding/precision-fout in ’n Liquidity Distribution Function (LDF) uitgebuit wat met elke swap uitgevoer is, waardeur die attacker positiewe credits kon opbou en liquidity kon dreineer.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

Die kernidee: indien ’n hook addisionele accounting implementeer wat van fixed-point math, tick rounding en threshold-logika afhang, kan ’n attacker exact-input swaps saamstel wat spesifieke thresholds kruis, sodat rounding-discrepansies in hul guns ophoop. Deur die patroon te herhaal en daarna die inflated balance te onttrek, word profit gerealiseer, dikwels gefinansier met ’n flash loan.

## Agtergrond: Uniswap v4 hooks en swap flow

- Hooks is contracts wat die PoolManager op spesifieke lifecycle-punte aanroep (byvoorbeeld beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[3]](#references)[[6]](#references)</sup>
- Pools word geïnisialiseer met ’n PoolKey wat ’n hooks-adres insluit. Indien dit nie nul is nie, voer PoolManager callbacks op elke relevante operasie uit.<sup>[[6]](#references)</sup>
- Hooks kan **custom deltas** terugstuur wat die finale balance changes van ’n swap of liquidity-aksie wysig (custom accounting). Hierdie deltas word as net balances aan die einde van die call vereffen, sodat enige rounding error binne hook-math ophoop voordat settlement plaasvind.<sup>[[5]](#references)</sup>
- Core math gebruik fixed-point-formate soos Q64.96 vir sqrtPriceX96 en tick arithmetic met 1.0001^tick. Enige custom math wat daaroor gelaag word, moet die rounding-semantiek noukeurig ooreenstem om invariant drift te voorkom.<sup>[[4]](#references)[[8]](#references)</sup>
- Swaps kan exactInput of exactOutput wees. In v3/v4 beweeg die prys langs ticks; wanneer ’n tick boundary gekruis word, kan range liquidity geaktiveer/gedeaktiveer word. Hooks kan addisionele logika op threshold/tick crossings implementeer.<sup>[[5]](#references)</sup>

## Vulnerability archetype: threshold-crossing precision/rounding drift

’n Tipiese vulnerable pattern in custom hooks:

1. Die hook bereken per-swap liquidity- of balance-deltas deur integer division, mulDiv of fixed-point conversions te gebruik (byvoorbeeld token ↔ liquidity deur sqrtPrice en tick ranges).
2. Threshold-logika (byvoorbeeld rebalancing, stepwise redistribution of per-range activation) word geaktiveer wanneer ’n swap-grootte of prysbeweging ’n interne boundary kruis.
3. Rounding word inkonsekwent toegepas (byvoorbeeld truncation na nul, floor teenoor ceil) tussen die forward calculation en die settlement path. Klein discrepansies kanselleer nie uit nie en krediteer eerder die caller.
4. Exact-input swaps wat presies groot genoeg is om hierdie boundaries te kruis, harvest herhaaldelik die positiewe rounding remainder. Die attacker onttrek later die opgehoopte credit.

Voorvereistes vir die aanval
- ’n Pool wat ’n custom v4 hook gebruik wat addisionele math op elke swap uitvoer (byvoorbeeld ’n LDF/rebalancer).
- Ten minste een execution path waar rounding die swap initiator bevoordeel wanneer thresholds gekruis word.
- Die vermoë om baie swaps atomies te herhaal (flash loans is ideaal om tydelike float te voorsien en gas te amortiseer).

## Praktiese aanvalmetodologie

1) Identifiseer kandidaat-pools met hooks
- Enumerate v4-pools en kontroleer of PoolKey.hooks != address(0).
- Inspekteer hook-bytecode/ABI vir callbacks: beforeSwap/afterSwap en enige custom rebalancing methods.
- Soek na math wat: deur liquidity deel, tussen token amounts en liquidity omskakel, of BalanceDelta met rounding aggregate.

2) Modelleer die hook se math en thresholds
- Recreate die hook se liquidity/redistribution-formule: inputs sluit tipies sqrtPriceX96, tickLower/Upper, currentTick, fee tier en net liquidity in.
- Map threshold/step-funksies: ticks, bucket boundaries of LDF breakpoints. Bepaal aan watter kant van elke boundary die delta afgerond word.
- Identifiseer waar conversions tussen uint256/int256 cast, SafeCast gebruik, of op mulDiv met implicit floor staatmaak.

3) Kalibreer exact-input swaps om boundaries te kruis
- Gebruik Foundry/Hardhat-simulations om die minimum Δin te bereken wat nodig is om die prys net oor ’n boundary te beweeg en die hook se branch te trigger.
- Verifieer dat afterSwap-settlement die caller meer krediteer as die koste, sodat ’n positiewe BalanceDelta of credit in die hook se accounting oorbly.
- Herhaal swaps om credit op te bou; roep daarna die hook se withdrawal/settlement path aan.

Voorbeeld van ’n Foundry-styl test harness (pseudocode)
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
Kalibrering van die exactInput
- Bereken ΔsqrtP vir ’n tick-stap: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Benader Δin deur v3/v4-formules te gebruik: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Maak seker dat die afrondingsrigting met die core math ooreenstem.
- Pas Δin met ±1 wei rondom die grens aan om die branch te vind waar die hook in jou guns afrond.

4) Versterk met flash loans
- Leen ’n groot nominale bedrag (bv. 3M USDT of 2000 WETH) om baie iterasies atomies uit te voer.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Voer die gekalibreerde swap-loop uit, en onttrek en betaal dan terug binne die flash loan callback.

Aave V3 flash loan-skelet
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
5) Uitgang en cross-chain replication
- Indien hooks op meerdere chains ontplooi is, herhaal dieselfde kalibrasie per chain.
- Bridge die opbrengste terug na die teiken-chain en cycle opsioneel via lending protocols om flows te obfuscate.<sup>[[2]](#references)</sup>

## Algemene hoofoorsake in hook-math

- Gemengde rounding-semantiek: mulDiv floor, terwyl latere paths effektief round up; of conversions tussen tokens/liquidity pas verskillende rounding toe.
- Tick-alignment-foute: gebruik van ongeronde ticks in een path en tick-spaced rounding in ’n ander.
- BalanceDelta-sign/overflow-probleme wanneer tussen int256 en uint256 tydens settlement omgeskakel word.
- Precision loss in Q64.96-conversions (sqrtPriceX96) wat nie in die reverse mapping weerspieël word nie.
- Accumulation pathways: per-swap remainders word as credits nagespoor wat deur die caller onttrekbaar is, eerder as om geburn te word of zero-sum te wees.

## Custom accounting & delta amplification

- Uniswap v4 custom accounting laat hooks toe om deltas terug te stuur wat direk aanpas wat die caller skuld/ontvang. Indien die hook credits intern naspoor, kan rounding residue oor baie klein operasies ophoop **voordat** die finale settlement plaasvind.<sup>[[5]](#references)</sup>
- Dit maak boundary/threshold-abuse sterker: die attacker kan `swap → withdraw → swap` in dieselfde tx afwissel, wat die hook dwing om deltas op effens verskillende state te herbereken terwyl alle balances steeds pending is.
- Wanneer hooks nagegaan word, trace altyd hoe BalanceDelta/HookDelta geproduseer en gesettle word. ’n Enkele bevooroordeelde rounding in een branch kan ’n compounding credit word wanneer deltas herhaaldelik herbereken word.

## Defensive guidance

- Differential testing: mirror die hook se math teenoor ’n reference implementation met high-precision rational arithmetic en assert equality of ’n bounded error wat altyd adversarial is (nooit gunstig vir die caller nie).
- Invariant/property tests:
- Die som van deltas (tokens, liquidity) oor swap paths en hook adjustments moet waarde behou, modulo fees.
- Geen path behoort positiewe net credit vir die swap initiator oor herhaalde exactInput-iterations te skep nie.
- Threshold/tick-boundary-tests rondom ±1 wei inputs vir beide exactInput/exactOutput.
- Rounding policy: sentraliseer rounding helpers wat altyd teen die user round; elimineer inkonsekwente casts en implicit floors.
- Settlement sinks: akkumuleer onvermydelike rounding residue in die protocol treasury of burn dit; ken dit nooit aan msg.sender toe nie.
- Rate-limits/guardrails: minimum swap sizes vir rebalancing triggers; disable rebalances indien deltas sub-wei is; sanity-check deltas teenoor verwagte ranges.
- Review hook callbacks holisties: beforeSwap/afterSwap en before/after liquidity changes behoort oor tick alignment en delta rounding ooreen te stem.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) met ’n LDF wat per swap toegepas word om te rebalance.<sup>[[7]](#references)</sup>
- Affected pools: USDC/USDT op Ethereum en weETH/ETH op Unichain, met ’n totaal van ongeveer $8.4M.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 1 (price push): die attacker het ~3M USDT flash-borrowed en geswap om die tick na ~5000 te push, wat die **active** USDC-balance tot ongeveer 28 wei laat krimp het.<sup>[[7]](#references)</sup>
- Step 2 (rounding drain): 44 klein withdrawals het floor rounding in `BunniHubLogic::withdraw()` uitgebuit om die active USDC-balance van 28 wei na 4 wei te verminder (‑85.7%), terwyl slegs ’n klein fraksie van LP-shares geburn is. Totale liquidity is met ~84.4% onderskat.<sup>[[2]](#references)[[7]](#references)</sup>
- Step 3 (liquidity rebound sandwich): ’n Groot swap het die tick na ~839,189 verskuif (1 USDC ≈ 2.77e36 USDT). Liquidity-estimates het omgeslaan en met ~16.8% toegeneem, wat ’n sandwich moontlik gemaak het waarin die attacker teen die opgeblaasde prys teruggeswap en met wins uitgegaan het.<sup>[[7]](#references)</sup>
- Fix identified in the post-mortem: verander die idle-balance-update om **up** te round sodat herhaalde micro-withdrawals nie die pool se active balance afwaarts kan ratchet nie.<sup>[[7]](#references)</sup>

Simplified vulnerable line (and post-mortem fix)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Jagkontrolelys

- Gebruik die pool 'n nie-nul hooks-adres? Watter callbacks is geaktiveer?
- Is daar per-swap-herverdelings/herbalanserings wat custom math gebruik? Is daar enige tick-/drempellogika?
- Waar word divisions/mulDiv, Q64.96-conversions of SafeCast gebruik? Is die afrondingssemantiek wêreldwyd konsekwent?
- Kan jy Δin konstrueer wat skaars 'n grens oorskry en 'n gunstige afrondingstak oplewer? Toets albei rigtings en beide exactInput en exactOutput.
- Hou die hook krediete of delta's per caller na wat later onttrek kan word? Verseker dat residue geneutraliseer word.

## Verwysings

- [1] [Bunni V2 Exploit: $8.3M uitgetap via likiditeitsfout (opsomming)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: Volledige Hack-analise](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Uniswap v4-agtergrond (QuillAudits-navorsing)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Likiditeitsmeganika in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Swap-meganika in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Uniswap v4 Hooks en sekuriteitsoorwegings](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
