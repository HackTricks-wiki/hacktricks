# DeFi/AMM Uitbuiting: Uniswap v4 Hook Presisie/Afrondingsmisbruik

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy dokumenteer ’n klas DeFi/AMM‑uitbuitingstegnieke teen Uniswap v4‑styl DEXes wat kern‑wiskunde uitbrei met custom hooks. ’n Onlangse voorval in Bunni V2 het ’n afronding/presisie fout in ’n Liquidity Distribution Function (LDF) benut wat by elke swap uitgevoer is, wat die aanvaller in staat gestel het om positiewe krediete aan te bou en likiditeit te dreineer.

Sleutelidee: as ’n hook addisionele rekeningkunde implementeer wat afhanklik is van fixed‑point math, tick rounding, en drempel‑logika, kan ’n aanvaller exact‑input swaps saamstel wat spesifieke drempels kruis sodat afrondingsverskille in hul guns ophoop. Deur die patroon te herhaal en dan die opgeblase balans terug te trek, word wins gerealiseer — dikwels gefinansier met ’n flash loan.

## Achtergrond: Uniswap v4 hooks en swap flow

- Hooks is kontrakte wat die PoolManager op spesifieke lewensikluspunte aanroep (bv. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Pools word geïnitialiseer met ’n PoolKey wat die hooks address insluit. As dit nie‑nul is, voer PoolManager callbacks uit by elke relevante operasie.
- Core math gebruik fixed‑point formats soos Q64.96 vir sqrtPriceX96 en tick arithmetic met 1.0001^tick. Enige custom math wat daarbo geplaas word, moet die afrondingssemantiek noukeurig pas om invariant drift te vermy.
- Swaps kan exactInput of exactOutput wees. In v3/v4 beweeg die prys oor ticks; die oorskryding van ’n tick‑grens kan range liquidity aktiveer/deaktiveer. Hooks kan addisionele logika implementeer op threshold/tick crossings.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

’n Tipiese kwesbare patroon in custom hooks:

1. Die hook bereken per‑swap liquidity of balansdelta’s met integer division, mulDiv, of fixed‑point conversions (bv. token ↔ liquidity gebruikende sqrtPrice en tick ranges).
2. Threshold‑logika (bv. rebalancing, stepwise redistribution, of per‑range activation) word geaktiveer wanneer ’n swap‑grootte of prysbeweging ’n interne grens kruis.
3. Afronding word onsystematies toegepas (bv. truncation toward zero, floor versus ceil) tussen die vooruitberekening en die settlement‑pad. Klein verskille kanselleer nie en krediteer eerder die caller.
4. Exact‑input swaps, presies gemeet om daardie grense te oorbrug, oes herhaaldelik die positiewe afrondingsreste. Die aanvaller onttrek later die opgehoopte krediet.

Aanvals‑voorwaardes
- ’n Pool wat ’n custom v4 hook gebruik wat by elke swap addisionele wiskunde uitvoer (bv. ’n LDF/rebalancer).
- Ten minste een uitvoeringspad waar afronding die swap initiator bevoordeel oor drempel‑oorskrywings.
- Vermoë om baie swaps atomies te herhaal (flash loans is ideaal om tydelike float te verskaf en gas te amortiseer).

## Praktiese aanvals‑metodologie

1) Identifiseer kandidaatpools met hooks
- Enumereer v4 pools en kontroleer PoolKey.hooks != address(0).
- Inspekteer hook bytecode/ABI vir callbacks: beforeSwap/afterSwap en enige custom rebalancing metodes.
- Soek na wiskunde wat: deel deur liquidity, omskakel tussen token amounts en liquidity, of BalanceDelta aggregasie met afronding uitvoer.

2) Modelleer die hook se wiskunde en drempels
- Herbou die hook se liquidity/redistribution formule: inpute sluit gewoonlik sqrtPriceX96, tickLower/Upper, currentTick, fee tier, en net liquidity in.
- Kaart threshold/step funksies: ticks, bucket boundaries, of LDF breakpoints. Bepaal aan watter kant van elke grens die delta afgerond word.
- Identifiseer waar omskakelings tussen uint256/int256 plaasvind, SafeCast gebruik word, of mulDiv met implisiete floor staatmaak.

3) Kalibreer exact‑input swaps om grense te kruis
- Gebruik Foundry/Hardhat simulatsies om die minimale Δin te bereken wat nodig is om die prys net oor ’n grens te skuif en die hook‑branch te trigger.
- Verifieer dat afterSwap settlement die caller meer krediteer as die koste, wat ’n positiewe BalanceDelta of krediet in die hook‑rekeninglaat agterlaat.
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
Kalibrering van die exactInput
- Bereken ΔsqrtP vir 'n tick-stap: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Benader Δin met behulp van v3/v4-formules: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Sorg dat die afrondingsrigting ooreenstem met die kernwiskunde.
- Pas Δin met ±1 wei rondom die grens aan om die tak te vind waar die hook in jou guns afrond.

4) Vergroot met flash loans
- Leen 'n groot notionele bedrag (bv. 3M USDT of 2000 WETH) om baie iterasies atomies uit te voer.
- Voer die gekalibreerde swap-lus uit, onttrek en betaal dan terug binne die flash loan callback.

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
5) Uitstap en oorketting‑replikasie
- As hooks op verskeie kettings ontplooi is, herhaal dieselfde kalibrasie per ketting.
- Brug stuur opbrengste terug na die teikenketting en kan opsioneel via leningsprotokolle kringloop om vloei te verwring.

## Algemene oorsake in hook‑wiskunde

- Gemengde afrondingssemantiek: mulDiv voer floor uit terwyl later paaie effektief na bo afrond; of omskakelings tussen token/liquidity pas verskillende afronding toe.
- Tick‑uitlijningsfoute: gebruik van onafgeronde ticks in een pad en tick‑spas‑afronding in 'n ander.
- BalanceDelta teken/overflow‑kwessies wanneer omgeskakel word tussen int256 en uint256 tydens settlement.
- Presisieverlies in Q64.96 omskakelings (sqrtPriceX96) nie gespiegeld in die omgekeerde mapping nie.
- Akkumulatie‑paaie: per‑swap watreste wat as krediete gevolg word en deur die caller onttrekbaar is in plaas daarvan om verbrand/zero‑sum te wees.

## Verdedigende riglyne

- Differensiële toetsing: spieël die hook se wiskunde teen 'n verwysingsimplementering met hoë‑presisie rasionele rekenkunde en stel gelykheid of 'n begrensde fout wat altyd adversarieel is (nooit in die caller se guns nie).
- Invariant/eienskapstoetse:
- Som van deltas (tokens, liquidity) oor swap‑paaie en hook‑aanpassings moet waarde conserveer modulo fooie.
- Geen pad mag 'n positiewe netto krediet vir die swap‑initiatior skep oor herhaalde exactInput‑iterasies nie.
- Drempel/tick‑grens toetse rondom ±1 wei insette vir beide exactInput/exactOutput.
- Afrondingsbeleid: sentraliseer afrondingshelpers wat altyd teen die gebruiker afrond; verwyder inkonsekwente casts en implisiete floors.
- Settlement sinks: akkumuleer onvermydelike afrondingsresidu na die protokol‑kassie of verbrand dit; ken dit nooit toe aan msg.sender nie.
- Rate‑limits/guardrails: minimum swap‑groottes vir rebalanserings‑triggers; deaktiveer rebalanses as deltas sub‑wei is; sanity‑check deltas teen verwagte reekse.
- Hersien hook callbacks holisties: beforeSwap/afterSwap en before/after liquidity‑veranderings moet saamstem oor tick‑uitlijning en delta‑afronding.

## Gevallestudie: Bunni V2 (2025‑09‑02)

- Protokol: Bunni V2 (Uniswap v4 hook) met 'n LDF toegepas per swap om te rebalanseer.
- Oorsaak: afrondings/presisie‑fout in LDF liquiditeitsrekeninghouding tydens drempel‑oorsteek swaps; per‑swap ongelykhede het opgeloop as positiewe krediete vir die caller.
- Ethereum poot: aanvaller het 'n ~3M USDT flash loan geneem, gekalibreerde exact‑input swaps op USDC/USDT uitgevoer om krediete op te bou, opgehewe opgeblase balances, terugbetaal, en fondse via Aave gerouteer.
- UniChain poot: het die exploit herhaal met 'n 2000 WETH flash loan, ongeveer 1366 WETH afgesyfer en na Ethereum gebridged.
- Impak: ~USD 8.3M leeggemaak oor kettings. Geen gebruikersinteraksie benodig; heeltemal on‑chain.

## Opsporingskontrolelys

- Gebruik die pool 'n nie‑nul hooks‑adres? Watter callbacks is geaktiveer?
- Is daar per‑swap herverdelings/rebalanses wat aangepaste wiskunde gebruik? Enige tick/drempel logika?
- Waar word divisions/mulDiv, Q64.96 omskakelings, of SafeCast gebruik? Is afrondingssemantiek globaal konsekwent?
- Kan jy Δin konstrueer wat skaars 'n grens oorsteek en 'n gunstige afrondings‑tak lewer? Toets beide rigtings en beide exactInput en exactOutput.
- Hou die hook per‑caller krediete of deltas by wat later onttrek kan word? Verseker dat residu geneutraliseer word.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
