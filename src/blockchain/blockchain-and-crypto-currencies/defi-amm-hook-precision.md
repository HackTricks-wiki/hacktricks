# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy dokumenteer ’n klas DeFi/AMM-exploitation-tegnieke teen Uniswap v4–styl DEX’e wat kernwiskunde met custom hooks uitbrei. ’n Bunni V2-voorval illustreer ’n verwante fout: ’n afrondingsrigting-bug in withdrawal accounting het aktiewe liquidity onderskat, en ’n latere swap het hierdie onderskatting in ’n winsgewende sandwich blootgelê.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Kernidee: as ’n hook addisionele accounting implementeer wat van fixed-point math, tick rounding en threshold logic afhanklik is, kan ’n aanvaller exact-input swaps saamstel wat spesifieke thresholds kruis sodat rounding discrepancies in hul guns ophoop. Deur die patroon te herhaal en daarna die inflated balance te withdraw, word wins gerealiseer, dikwels gefinansier met ’n flash loan.

## Agtergrond: Uniswap v4 hooks en swap-vloei

- Hooks is contracts wat die PoolManager op spesifieke lifecycle-punte aanroep (byvoorbeeld beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools word geïnisialiseer met ’n PoolKey wat die hook contract insluit. ’n Nie-nul hook address aktiveer die callbacks wat vir daardie pool gekies is.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks kan **custom deltas** terugstuur wat die finale balance changes van ’n swap of liquidity action wysig (custom accounting). Hierdie deltas word as net balances aan die einde van die call vereffen, sodat enige rounding error binne hook math ophoop voordat settlement plaasvind.<sup>[[4]](#references)</sup>
- Core math gebruik fixed-point-formate soos Q64.96 vir sqrtPriceX96 en tick arithmetic met 1.0001^tick. Enige custom math wat daarop gelê word, moet rounding semantics noukeurig ooreenstem om invariant drift te voorkom.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps kan exactInput of exactOutput wees. In v3/v4 beweeg die prys langs ticks; die kruising van ’n tick boundary kan range liquidity aktiveer/deaktiveer. Hooks kan addisionele logic tydens threshold/tick crossings implementeer.<sup>[[9]](#references)[[11]](#references)</sup>

## Kwesbaarheidsarchetipe: threshold‑crossing precision/rounding drift

’n Tipiese kwesbare patroon in custom hooks:

1. Die hook bereken per-swap liquidity- of balance-deltas met integer division, mulDiv of fixed-point conversions (byvoorbeeld token ↔ liquidity met sqrtPrice en tick ranges).
2. Threshold logic (byvoorbeeld rebalancing, stepwise redistribution of per-range activation) word geaktiveer wanneer ’n swap-grootte of price movement ’n interne boundary kruis.
3. Rounding word inkonsekwent toegepas (byvoorbeeld truncation na zero, floor versus ceil) tussen die forward calculation en die settlement path. Klein discrepancies kanselleer nie uit nie en krediteer eerder die caller.
4. Exact-input swaps wat presies groot genoeg is om hierdie boundaries te kruis, harvest herhaaldelik die positive rounding remainder. Die aanvaller withdraw later die opgehoopte credit.

Aanvalvoorwaardes
- ’n Pool wat ’n custom v4 hook gebruik wat addisionele math op elke swap uitvoer (byvoorbeeld ’n LDF/rebalancer).
- Ten minste een execution path waar rounding die swap initiator tydens threshold crossings bevoordeel.
- Die vermoë om baie swaps atomies te herhaal (flash loans is ideaal om tydelike float te voorsien en gas te amortiseer).

## Praktiese aanvalmetodologie

1) Identifiseer kandidaatpools met hooks
- Enumerate v4 pools en kontroleer PoolKey.hooks != address(0).
- Inspekteer hook bytecode/ABI vir callbacks: beforeSwap/afterSwap en enige custom rebalancing methods.
- Soek na math wat: deur liquidity deel, tussen token amounts en liquidity omskakel, of BalanceDelta met rounding aggregateer.

2) Modelleer die hook se math en thresholds
- Recreate die hook se liquidity/redistribution-formule: inputs sluit tipies sqrtPriceX96, tickLower/Upper, currentTick, fee tier en net liquidity in.
- Map threshold/step functions: ticks, bucket boundaries of LDF breakpoints. Bepaal aan watter kant van elke boundary die delta afgerond word.
- Identifiseer waar conversions tussen uint256/int256 cast, SafeCast gebruik of op mulDiv met implicit floor staatmaak.

3) Kalibreer exact‑input swaps om boundaries te kruis
- Gebruik Foundry/Hardhat simulations om die minimale Δin te bereken wat nodig is om die prys net oor ’n boundary te beweeg en die hook se branch te aktiveer.
- Verifieer dat afterSwap settlement die caller meer krediteer as die koste, wat ’n positive BalanceDelta of credit in die hook se accounting laat.
- Herhaal swaps om credit op te bou; call dan die hook se withdrawal/settlement path.

In v4 moet die swap loop vanuit ’n PoolManager unlock callback loop; negative `amountSpecified` dui exact input aan, en `sqrtPriceLimitX96` moet streng binne die geldige reeks wees. ’n Zero price limit revert, dus gebruik die pseudocode hieronder die lower bound vir ’n zero-for-one swap.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Voorbeeld van ’n Foundry-styl test harness (pseudocode)
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
Kalibrering van die exactInput
- Bereken die teiken met core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) in terme van werklike waardes; die Q64.96-resultaat word deur TickMath afgerond.<sup>[[13]](#references)</sup>
- Benader ’n token0 (zero-for-one)-invoer met die Q64.96-bewuste formule: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Pas die core-roetine se rigtingspesifieke afronding aan.<sup>[[12]](#references)</sup>
- Pas Δin met ±1 wei rondom die grens aan om die vertakking te vind waar die hook in jou guns afrond.

4) Versterk met flash loans
- Leen ’n groot notionele bedrag (byvoorbeeld 3M USDT of 2000 WETH) om baie iterasies atomies uit te voer.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Voer die gekalibreerde swap-lus uit, en onttrek en betaal daarna terug binne die flash loan-callback.

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
5) Exit en kruisketting-replikasie
- Indien hooks op veelvuldige kettings ontplooi is, herhaal dieselfde kalibrasie per ketting.
- In die Bunni-incident het flash-loan-likiditeit en bridge-roetes per ketting verskil; neem dus daardie kettingspesifieke beperkings in ag wanneer die analise gereproduseer word.<sup>[[1]](#references)[[2]](#references)</sup>

## Algemene grondoorsake in hook-wiskunde

- Gemengde afrondingssemantiek: mulDiv rond af, terwyl latere paaie effektief op afronding na bo neerkom; of omskakelings tussen tokens/likiditeit gebruik verskillende afronding.
- Foute met tick-belyning: afgeronde ticks word in een pad gebruik en tick-spaced afronding in ’n ander.
- BalanceDelta-teken-/oorloopkwessies wanneer tussen int256 en uint256 tydens settlement omgeskakel word.
- Presisieverlies in Q64.96-omskakelings (sqrtPriceX96) wat nie in die omgekeerde mapping weerspieël word nie.
- Akkumulasiepaaie: remainder per swap word as krediete nagespoor wat deur die caller onttrekbaar is, eerder as om vernietig te word of ’n zero-sum-uitkoms te hê.

## Custom accounting & delta-versterking

- Uniswap v4 custom accounting laat hooks toe om deltas terug te gee wat direk aanpas wat die caller verskuldig is/ontvang. Indien die hook krediete intern naspoor, kan afrondingsreste oor baie klein operasies ophoop **voordat** die finale settlement plaasvind.<sup>[[4]](#references)</sup>
- Indien die hook ’n versoenbare withdrawal-pad blootstel, kan ’n aanvaller `swap → withdraw → swap` binne dieselfde PoolManager unlock callback afwissel, wat die hook dwing om deltas teen effens verskillende state te herbereken terwyl balances hangende bly totdat die unlock gevestig word.<sup>[[4]](#references)[[10]](#references)</sup>
- Wanneer hooks nagegaan word, volg altyd hoe BalanceDelta/HookDelta geproduseer en gevestig word. ’n Enkele bevooroordeelde afronding in een vertakking kan ’n samestellende krediet word wanneer deltas herhaaldelik herbereken word.

## Defensiewe riglyne

- Differential testing: vergelyk die hook se wiskunde met ’n reference implementation deur hoëpresisie-rationele rekenkunde te gebruik, en bevestig gelykheid of ’n begrensde fout wat altyd adversarial is (nooit gunstig vir die caller nie).
- Invariant/property tests:
- Die som van deltas (tokens, likiditeit) oor swap-paaie en hook-aanpassings moet waarde behou, modulo fooie.
- Geen pad behoort positiewe netto krediet vir die swap initiator oor herhaalde exactInput-iterasies te skep nie.
- Drempel-/tick-grenstoetse rondom ±1 wei-insette vir beide exactInput/exactOutput.
- Afrondingsbeleid: sentraliseer afrondingshelpers wat altyd teen die gebruiker afrond; elimineer inkonsekwente casts en implisiete floors.
- Settlement sinks: akkumuleer onvermydelike afrondingsreste in die protocol treasury of verbrand dit; ken dit nooit aan msg.sender toe nie.
- Rate-limits/guardrails: minimum swap-groottes vir rebalancing-snellers; deaktiveer rebalances indien deltas sub-wei is; doen sanity checks op deltas teenoor verwagte reekse.
- Hersien hook-callbacks holisties: beforeSwap/afterSwap en before/after liquidity changes moet oor tick-belyning en delta-afronding ooreenstem.

## Gevallestudie: Bunni V2 (2025-09-02)

- Protokol: Bunni V2, ’n Uniswap v4-hook wat ’n Liquidity Density Function (LDF) gebruik om tokendigtheid en skattings van totale likiditeit te bereken.<sup>[[1]](#references)[[2]](#references)</sup>
- Geaffekteerde pools: USDC/USDT op Ethereum en weETH/ETH op Unichain, met ’n totaal van ongeveer $8.4M.<sup>[[1]](#references)</sup>
- Stap 1 (prysopstuwing): die aanvaller het ~3M USDT deur ’n flash-loan geleen en dit geswap om die tick na ~5000 te skuif, wat die **aktiewe** USDC-balans tot ongeveer 28 wei verklein het.<sup>[[1]](#references)</sup>
- Stap 2 (afrondingsdreinering): 44 klein onttrekkings het floor rounding in `BunniHubLogic::withdraw()` uitgebuit om die aktiewe USDC-balans van 28 wei na 4 wei te verminder (-85.7%), terwyl slegs ’n klein fraksie van LP-shares verbrand is. Totale likiditeit het met ~84.4% afgeneem.<sup>[[1]](#references)[[2]](#references)</sup>
- Stap 3 (likiditeitsherstel-sandwich): ’n Groot swap het die tick na ~839,189 geskuif (1 USDC ≈ 2.77e36 USDT). Likiditeitskattings het omgeslaan en met ~16.8% toegeneem, wat ’n sandwich moontlik gemaak het waarin die aanvaller teen die opgeblase prys teruggeswap en met wins uitgeklim het.<sup>[[1]](#references)</sup>
- Oplossing wat in die post-mortem geïdentifiseer is: verander die idle-balance-opdatering om **na bo** af te rond, sodat herhaalde mikro-onttrekkings nie meer die pool se aktiewe balans stelselmatig afwaarts verlaag nie.<sup>[[1]](#references)</sup>

Vereenvoudigde kwesbare reël (en post-mortem-oplossing).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Jagkontrolelys

- Gebruik die pool ’n nie-nul hooks-adres? Watter callbacks is geaktiveer?
- Is daar per-swap-herverdelings/herbalanserings wat custom math gebruik? Is daar enige tick/threshold-logika?
- Waar word divisions/mulDiv, Q64.96 conversions of SafeCast gebruik? Is die afrondingssemantiek wêreldwyd konsekwent?
- Kan jy Δin konstrueer wat skaars ’n grens oorsteek en ’n gunstige afrondingsvertakking lewer? Toets albei rigtings en beide exactInput en exactOutput.
- Hou die hook per-caller-krediete of deltas dop wat later onttrek kan word? Verseker dat die res geneutraliseer word.

## References

- [1] [Bunni Exploit-nadoodse ondersoek (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: Volledige hack-analise](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M gedreineer via likiditeitsfout (opsomming)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core-witskrif](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4-agtergrond (QuillAudits-navorsing)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Likiditeitsmeganika in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Swap-meganika in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks en sekuriteitsoorwegings](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
