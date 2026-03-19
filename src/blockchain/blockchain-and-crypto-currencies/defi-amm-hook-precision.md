# DeFi/AMM‑eksploitasie: Uniswap v4 Hook‑presisie/afrondingsmisbruik

{{#include ../../banners/hacktricks-training.md}}



Hierdie bladsy dokumenteer ’n klas DeFi/AMM‑eksploitasietegnieke teen Uniswap v4–styl DEXe wat kern‑wiskunde uitbrei met custom hooks. ’n Onlangse insident in Bunni V2 het ’n afrondings-/presisieflaw in ’n Liquidity Distribution Function (LDF) wat op elke swap uitgevoer is, uitgebuit en die aanvaller in staat gestel om positiewe krediete te akkumuleer en likiditeit te tap.

Belangrike idee: as ’n hook addisionele boekhouding implementeer wat afhang van fixed‑point math, tick rounding en threshold logic, kan ’n aanvaller exact‑input swaps skep wat spesifieke drempels oorskry sodat afrondingsverskille in hul guns ophoop. Herhaling van die patroon en daarna die onttrekking van die opgeblase balans realiseer wins, dikwels gefinansier met ’n flash loan.

## Agtergrond: Uniswap v4 hooks en swap‑vloei

- Hooks is contracts wat die PoolManager op spesifieke lewensikluspuncte aanroep (bv. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools word geïnitialiseer met ’n PoolKey insluitend hooks address. As dit nie‑nul is, voer PoolManager callbacks uit op elke relevante operasie.
- Hooks kan **custom deltas** teruggee wat die finale balansveranderings van ’n swap of liquidity‑aksie wysig (custom accounting). Daardie deltas word as netbalanse aan die einde van die call vereffen, so enige afrondingsfout binne hook‑wiskunde loop op voor die vereffening.
- Kern‑wiskunde gebruik fixed‑point formate soos Q64.96 vir sqrtPriceX96 en tick arithmetic met 1.0001^tick. Enige custom wiskunde bo‑op moet afgerondingssemantiek noukeurig match om invariant‑drift te vermy.
- Swaps kan exactInput of exactOutput wees. In v3/v4 beweeg die prys oor ticks; ’n tick‑grens kruis kan range liquidity aktiveer/deaktiveer. Hooks kan addisionele logika implementeer by threshold/tick crossings.

## Swaartepunt van kwesbaarheid: threshold‑crossing presisie/afronding‑drift

’n Tipiese kwesbare patroon in custom hooks:

1. Die hook bereken per‑swap liquidity of balansdeltas deur gebruik te maak van integer division, mulDiv, of fixed‑point conversions (bv. token ↔ liquidity met sqrtPrice en tick ranges).
2. Threshold logic (bv. rebalancing, stepwise redistribution, of per‑range activation) word geaktiveer wanneer ’n swap‑grootte of prysbeweging ’n interne grens oorskry.
3. Afronding word inkonsekwent toegepas (bv. truncation toward zero, floor versus ceil) tussen die vorentoe berekening en die vereffeningspad. Klein verskille kanselleer nie en krediteer in plaas daarvan die caller.
4. Exact‑input swaps, presies gemeet om daardie grense te skaaf, oes herhaaldelik die positiewe afrondingsrest. Die aanvaller onttrek later die opgehoopte krediet.

Voorwaardes vir die aanval
- ’n Pool wat ’n custom v4 hook gebruik wat addisionele wiskunde op elke swap uitvoer (bv. ’n LDF/rebalancer).
- Ten minste een uitvoeringspad waar afronding die swap‑inisiator bevoordeel oor threshold crossings.
- Vermoë om baie swaps atomies te herhaal (flash loans is ideaal om tydelike float te voorsien en gas te amortiseer).

## Praktiese aanvalsmetodologie

1) Identifiseer kandidaat‑pools met hooks
- Enummerer v4 pools en kontroleer PoolKey.hooks != address(0).
- Inspect hook bytecode/ABI vir callbacks: beforeSwap/afterSwap en enige custom rebalancing‑metodes.
- Soek wiskunde wat: deel deur liquidity, omskakel tussen token amounts en liquidity, of BalanceDelta aggregateer met afronding.

2) Modelleer die hook se wiskunde en drempels
- Recreate die hook se liquidity/redistribution‑formule: insette sluit gewoonlik sqrtPriceX96, tickLower/Upper, currentTick, fee tier, en net liquidity in.
- Map threshold/step‑funksies: ticks, bucket boundaries, of LDF breakpoints. Bepaal aan watter kant van elke grens die delta afgerond word.
- Identifiseer waar conversions cast tussen uint256/int256, gebruik SafeCast, of staatmaak op mulDiv met implisiete floor.

3) Kalibreer exact‑input swaps om grense te kruis
- Gebruik Foundry/Hardhat simulations om die minimale Δin te bereken wat nodig is om die prys net oor ’n grens te skuif en die hook se branch te trigger.
- Verifieer dat afterSwap settlement die caller meer krediteer as die kostes, wat ’n positiewe BalanceDelta of krediet in die hook se boekhouding agterlaat.
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
Kalibreer die exactInput
- Bereken ΔsqrtP vir 'n tick step: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Benader Δin met behulp van v3/v4-formules: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Maak seker dat die afrondingsrigting ooreenstem met die kernwiskunde.
- Pas Δin met ±1 wei rondom die grens aan om die tak te vind waar die hook in jou guns afrond.

4) Vergroot met flash loans
- Neem 'n groot notionele bedrag (bv. 3M USDT of 2000 WETH) om baie iterasies atomies uit te voer.
- Voer die gekalibreerde swap-lus uit, onttrek dan en betaal terug binne die flash loan callback.

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
5) Uitgang en kruis‑ketting replikasie
- As hooks op verskeie kettings uitgerol is, herhaal dieselfde kalibrasie per ketting.
- Bridge stuur die opbrengs terug na die teiken‑ketting en kan opsioneel deur lending protocols sirkuleer om vloei te verdoesel.

## Algemene oorsake in hook‑wiskunde

- Gemengde afrondingssemantiek: mulDiv gebruik floor terwyl latere paadjies effektief na bo afrond; of omskakelings tussen token/likiditeit pas verskillende afrondings toe.
- Tick‑uitlijnfoute: gebruik van nie‑afgeronde ticks in een paadjie en tick‑spasiëring‑afronding in 'n ander.
- BalanceDelta teken/overflow‑kwessies wanneer tussen int256 en uint256 omgeskakel word tydens afhandeling.
- Presisieverlies in Q64.96‑omskakelings (sqrtPriceX96) wat nie in die omgekeerde mapping weerspieël word nie.
- Akkumulasie‑paaie: per‑swap oortollighede wat as krediete getrakteer word en deur die caller onttrek kan word in plaas daarvan om verbrand/zero‑sum te wees.

## Aangepaste rekeningkunde & delta‑versterking

- Uniswap v4 custom accounting laat hooks toe om deltas terug te gee wat direk aanpas wat die caller skuldig is/ontvang. As die hook intern krediete naspoor, kan afrondingsreste oor baie klein operasies ophoop voordat die finale afhandeling plaasvind.
- Dit maak grens-/drempel‑misbruik sterker: die aanvaller kan afwissel tussen `swap → withdraw → swap` in dieselfde tx, wat die hook dwing om deltas op effens verskillende state te herbereken terwyl alle balances nog hangende is.
- Wanneer hooks nagegaan word, spoor altyd hoe BalanceDelta/HookDelta geproduseer en vereffen word. 'n Enkele bevooroordeelde afronding in een tak kan 'n saamgestelde krediet word wanneer deltas herhaaldelik herbereken word.

## Verdedigende riglyne

- Differensiële toetsing: spiegel die hook se wiskunde teen 'n verwysingsimplementering met hoë‑presisie rasionele aritmetiek en verifieer gelykheid of 'n begrensde fout wat altyd nadelig is (nooit in die caller se guns nie).
- Invariante/eienskapstoetse:
- Som van deltas (tokens, likiditeit) oor swap‑paaie en hook‑aanpassings moet waarde behou modulo fooie.
- Geen paadjie mag 'n positiewe netto krediet vir die swap‑initiator skep oor herhaalde exactInput‑iterasies nie.
- Drempel/tick‑grens toetse rondom ±1 wei insette vir beide exactInput/exactOutput.
- Afrondingsbeleid: sentraliseer afrondingshelpers wat altyd teen die gebruiker afrond; elimineer inkonsekwente casts en implisiete floors.
- Afwikkelings‑sinke: akkumuleer onontkoombare afrondingsreste na die protocol treasury of verbrand dit; ken dit nooit toe aan msg.sender nie.
- Rate‑limits/guardrails: minimum swap‑groottes vir rebalanserings‑triggers; deaktiveer rebalanserings as deltas sub‑wei is; sanity‑check deltas teen verwagte reekse.
- Hersien hook callbacks holisties: beforeSwap/afterSwap en before/after likiditeitsveranderinge moet saamstem oor tick‑uitlijning en delta‑afronding.

## Gevallestudie: Bunni V2 (2025‑09‑02)

- Protokol: Bunni V2 (Uniswap v4 hook) met 'n LDF toegepas per swap om te rebalanseer.
- Benadeelde pools: USDC/USDT op Ethereum en weETH/ETH op Unichain, totaal ongeveer $8.4M.
- Stap 1 (prysstoot): die aanvaller flash‑borrowed ~3M USDT en geswap om die tick na ~5000 te druk, waardeur die **aktiewe** USDC‑balans gekrimp het na ~28 wei.
- Stap 2 (afrondingslek): 44 klein onttrekkings het floor‑afronding in `BunniHubLogic::withdraw()` uitgebuit om die aktiewe USDC‑balans van 28 wei na 4 wei te verlaag (‑85.7%) terwyl slegs 'n klein fraksie van LP‑aandele verbrand is. Totale likiditeit is onderskat met ~84.4%.
- Stap 3 (likiditeits‑terugslag sandwich): 'n groot swap het die tick na ~839,189 beweeg (1 USDC ≈ 2.77e36 USDT). Likiditeitsberamings het omgeslaan en met ~16.8% toegeneem, wat 'n sandwich moontlik gemaak het waar die aanvaller teruggeswap het teen die opgeblase prys en met wins uitgegaan het.
- Regstelling geïdentifiseer in die post‑mortem: verander die idle‑balance‑opdatering om **op** te afrond sodat herhaalde mikro‑onttrekkings die pool se aktiewe balans nie afwaarts kan ratchet nie.

Vereenvoudigde kwesbare reël (en post‑mortem regstelling)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Jagkontrolelys

- Gebruik die pool 'n nie‑nul hooks address? Watter callbacks is geaktiveer?
- Is daar per‑swap redistributions/rebalances wat custom math gebruik? Enige tick/threshold logika?
- Waar word divisions/mulDiv, Q64.96 conversions, of SafeCast gebruik? Is die rounding-semantiek wêreldwyd konsekwent?
- Kan jy Δin konstrueer wat niptelik 'n grens oorskry en 'n gunstige rounding branch lewer? Toets beide rigtings en sowel exactInput as exactOutput.
- Hou die hook per‑caller credits of deltas by wat later onttrek kan word? Verseker dat residu geneutraliseer word.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
