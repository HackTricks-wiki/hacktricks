# DeFi/AMM-uitbuiting: Uniswap v4 Hook-presisie-/afrondingsmisbruik

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy dokumenteer ’n klas DeFi/AMM-uitbuitingstegnieke teen DEX’e in Uniswap v4-styl, wat kernwiskunde met pasgemaakte hooks uitbrei. ’n Bunni V2-voorval illustreer ’n verwante fout: ’n fout met afrondingsrigting in onttrekkingsrekeningkunde het die aktiewe likiditeit onderskat, en ’n latere swap het dié onderskatting in ’n winsgewende sandwich blootgelê.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Kernidee: as ’n hook bykomende rekeningkunde implementeer wat van vastepuntwiskunde, tick-afronding en drempellogika afhanklik is, kan ’n aanvaller presiese exact-input-swaps saamstel wat spesifieke drempels oorsteek, sodat afrondingsverskille in hul guns ophoop. Deur die patroon te herhaal en dan die opgeblase saldo te onttrek, word wins gerealiseer, dikwels gefinansier met ’n flash loan.

## Agtergrond: Uniswap v4-hooks en swap-vloei

- Hooks is kontrakte wat die PoolManager op spesifieke lewensiklus-punte aanroep (bv. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Poele word geïnisialiseer met ’n PoolKey wat die hook-kontrak insluit. ’n Nie-nul hook-adres aktiveer die callbacks wat vir daardie poel gekies is.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks kan **pasgemaakte deltas** teruggee wat die finale balansveranderings van ’n swap- of likiditeitsaksie wysig (pasgemaakte rekeningkunde). Daardie deltas word aan die einde van die oproep as netto saldo’s vereffen, dus hoop enige afrondingsfout in hook-wiskunde voor vereffening op.<sup>[[4]](#references)</sup>
- Kernwiskunde gebruik vastepuntformate soos Q64.96 vir sqrtPriceX96 en tick-rekenkunde met 1.0001^tick. Enige pasgemaakte wiskunde wat hierop gebou word, moet afrondingsemantiek noukeurig ewenaar om afwyking van die invariant te voorkom.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps kan exactInput of exactOutput wees. In v3/v4 beweeg die prys langs ticks; die oorsteek van ’n tick-grens kan reeks-likiditeit aktiveer/deaktiveer. Hooks kan ekstra logika vir drempel-/tick-oorsteekpunte implementeer.<sup>[[9]](#references)[[11]](#references)</sup>

## Kwesbaarheidsarchetipe: presisie-/afrondingsafwyking wanneer drempels oorgesteek word

’n Tipiese kwesbare patroon in pasgemaakte hooks:

1. Die hook bereken likiditeits- of saldodeltas per swap met behulp van heelgetaldeling, mulDiv of vastepuntomskakelings (bv. token ↔ likiditeit met sqrtPrice en tick-reekse).
2. Drempellogika (bv. herbalansering, stapsgewyse herverdeling of aktivering per reeks) word geaktiveer wanneer ’n swapgrootte of prysbeweging ’n interne grens oorsteek.
3. Afronding word inkonsekwent toegepas (bv. afkapping na nul, floor teenoor ceil) tussen die voorwaartse berekening en die vereffeningspad. Klein verskille kanselleer nie uit nie en krediteer eerder die oproeper.
4. Presies gedoseerde exact-input-swaps wat hierdie grense oorsteek, oes die positiewe afrondingsreserwe herhaaldelik. Die aanvaller onttrek later die opgehoopte krediet.

Voorvereistes vir die aanval
- ’n Poel wat ’n pasgemaakte v4-hook gebruik wat bykomende wiskunde op elke swap uitvoer (bv. ’n LDF/herbalanseerder).
- Minstens een uitvoeringspad waar afronding die swap-inisieerder bevoordeel wanneer drempels oorgesteek word.
- Die vermoë om baie swaps atomies te herhaal (flash loans is ideaal om tydelike kapitaal te voorsien en gas te amortiseer).

## Praktiese aanvalmetodologie

1) Identifiseer kandidaatpoele met hooks
- Lys v4-poele op en kontroleer PoolKey.hooks != address(0).
- Ondersoek die hook-bytecode/ABI vir callbacks: beforeSwap/afterSwap en enige pasgemaakte herbalanseringsmetodes.
- Soek wiskunde wat: deur likiditeit deel, tussen tokenbedrae en likiditeit omskakel, of BalanceDelta met afronding saamvoeg.

2) Modelleer die hook se wiskunde en drempels
- Herskep die hook se likiditeits-/herverdelingsformule: insette sluit tipies sqrtPriceX96, tickLower/Upper, currentTick, fooivlak en netto likiditeit in.
- Karteer drempel-/stapfunksies: ticks, emmergrense of LDF-breekpunte. Bepaal aan watter kant van elke grens die delta afgerond word.
- Identifiseer waar omskakelings tussen uint256/int256 plaasvind, SafeCast gebruik word, of op mulDiv met implisiete floor staatgemaak word.

3) Stel exact-input-swaps in om grense oor te steek
- Gebruik Foundry/Hardhat-simulasies om die minimum Δin te bereken wat nodig is om die prys net oor ’n grens te beweeg en die hook se vertakking te aktiveer.
- Bevestig dat afterSwap-vereffening die oproeper meer as die koste krediteer, wat ’n positiewe BalanceDelta of krediet in die hook se rekeningkunde laat.
- Herhaal swaps om krediet op te bou; roep dan die hook se onttrekkings-/vereffeningspad aan.

In v4 moet die swap-lus vanuit ’n PoolManager-ontsluit-callback loop; negatiewe `amountSpecified` dui op exact input, en `sqrtPriceLimitX96` moet streng binne die geldige reeks wees. ’n Nulpryslimiet veroorsaak ’n revert, daarom gebruik die pseudokode hieronder die ondergrens vir ’n zero-for-one-swap.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Voorbeeld van ’n Foundry-styl-toetsharnas (pseudokode)
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
- Bereken die teiken met core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) in reëlewaardeterme; die Q64.96-resultaat word deur TickMath afgerond.<sup>[[13]](#references)</sup>
- Benader ’n token0 (zero-for-one)-invoer met die Q64.96-bewuste formule: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Pas die rigtingspesifieke afronding van die core-roetine toe.<sup>[[12]](#references)</sup>
- Verstel Δin met ±1 wei rondom die grens om die vertakking te vind waar die hook in jou guns afrond.

4) Versterk met flash loans
- Leen ’n groot notional (bv. 3M USDT of 2000 WETH) om baie iterasies atomies uit te voer.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Voer die gekalibreerde ruil-lus uit, en onttrek en betaal dan terug binne die flash loan-callback.

Aave V3-flash loan-skelet
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

5) Uittrede en kruisketting-replikasie
- As hooks op verskeie kettings ontplooi is, herhaal dieselfde kalibrasie vir elke ketting.
- In die Bunni-voorval het flash-loan-likiditeit en brugroetes per ketting verskil. Neem dus hierdie kettingspesifieke beperkings in ag wanneer jy die ontleding reproduseer.<sup>[[1]](#references)[[2]](#references)</sup>

## Algemene hoofoorsake in hook-wiskunde

- Gemengde afrondingssemantiek: mulDiv rond af, terwyl latere paaie in die praktyk opwaarts afrond; of omskakelings tussen tokens en likiditeit gebruik verskillende afrondings.
- Tick-belyningsfoute: ongeronde ticks in een pad gebruik en in ’n ander pad volgens tick-spasiëring afrond.
- BalanceDelta-teken-/oorloopkwessies wanneer daar tydens vereffening tussen int256 en uint256 omgeskakel word.
- Presisieverlies in Q64.96-omskakelings (sqrtPriceX96) wat nie in die omgekeerde kartering weerspieël word nie.
- Akkumulasiepaaie: remainders per swap word as krediete nagespoor wat die aanroeper kan onttrek, eerder as om verbrand te word of nul-som te wees.

## Pasgemaakte rekeningkunde en delta-amplifikasie

- Uniswap v4 se pasgemaakte rekeningkunde laat hooks toe om deltas terug te gee wat direk aanpas wat die aanroeper skuld of ontvang. As die hook krediete intern naspoor, kan afrondingsresidue oor baie klein bewerkings ophoop **voordat** die finale vereffening plaasvind.<sup>[[4]](#references)</sup>
- As die hook ’n versoenbare onttrekkingspad blootstel, kan ’n aanvaller `swap → withdraw → swap` binne dieselfde PoolManager-ontsluitterugroeping afwissel. Dit dwing die hook om deltas op effens verskillende toestande te herbereken terwyl die saldo’s hangende bly totdat die ontsluiting vereffen word.<sup>[[4]](#references)[[10]](#references)</sup>
- Wanneer jy hooks hersien, volg altyd hoe BalanceDelta/HookDelta geskep en vereffen word. ’n Enkele bevooroordeelde afronding in een vertakking kan ’n opbouende krediet word wanneer deltas herhaaldelik herbereken word.

## Verdedigingsriglyne

- Differensiële toetsing: vergelyk die hook se wiskunde met ’n verwysingsimplementering wat hoëpresisie-rasionale rekenkunde gebruik, en bevestig gelykheid of ’n begrensde fout wat altyd teen die aanvaller werk (nooit ten gunste van die aanroeper nie).
- Invariant-/eienskaptoetse:
  - Die som van deltas (tokens, likiditeit) oor swap-paaie en hook-aanpassings moet waarde behou, afgegesien van fooie.
  - Geen pad behoort oor herhaalde exactInput-iterasies ’n positiewe netto krediet vir die swap-inisieerder te skep nie.
  - Toetse op drempel-/tick-grense met ±1 wei-insette vir beide exactInput en exactOutput.
- Afrondingsbeleid: sentraliseer afrondingshelpers wat altyd teen die gebruiker afrond; skakel inkonsekwente casts en implisiete afronding af.
- Vereffeningsbestemmings: stuur onvermydelike afrondingsresidue na die protokol se tesourie of verbrand dit; skryf dit nooit aan msg.sender toe nie.
- Tempo-beperkings/beskermingsmaatreëls: stel minimum swap-groottes vir herbalanseringsnellers in; deaktiveer herbalanserings as deltas kleiner as een wei is; kontroleer of deltas binne verwagte reekse val.
- Hersien hook-terugroepe omvattend: beforeSwap/afterSwap en voor-/ná-likiditeitsveranderinge moet ooreenstem oor tick-belyning en delta-afronding.

## Gevallestudie: Bunni V2 (2025‑09‑02)

- Protokol: Bunni V2, ’n Uniswap v4-hook wat ’n Liquidity Density Function (LDF) gebruik om tokendigtheid en totale-likiditeitsramings te bereken.<sup>[[1]](#references)[[2]](#references)</sup>
- Geaffekteerde poele: USDC/USDT op Ethereum en weETH/ETH op Unichain, altesaam ongeveer $8.4M.<sup>[[1]](#references)</sup>
- Stap 1 (prysverskuiwing): die aanvaller het ~3M USDT deur ’n flash loan geleen en dit omgeruil om die tick tot ~5000 te verskuif, waardeur die **aktiewe** USDC-saldo tot ~28 wei gekrimp het.<sup>[[1]](#references)</sup>
- Stap 2 (dreinering deur afronding): 44 klein onttrekkings het afronding na onder in `BunniHubLogic::withdraw()` uitgebuit om die aktiewe USDC-saldo van 28 wei tot 4 wei te verminder (-85.7%), terwyl slegs ’n klein fraksie van LP-aandele verbrand is. Die totale likiditeit het met ~84.4% afgeneem.<sup>[[1]](#references)[[2]](#references)</sup>
- Stap 3 (likiditeitsherstel-sandwich): ’n groot swap het die tick na ~839,189 verskuif (1 USDC ≈ 2.77e36 USDT). Likiditeitsramings het omgekeer en met ~16.8% toegeneem, wat ’n sandwich moontlik gemaak het waarin die aanvaller teen die opgeblaasde prys teruggeswap het en met wins uitgetree het.<sup>[[1]](#references)</sup>
- Regstelling wat in die nadoodse verslag geïdentifiseer is: verander die opdatering van die idle-saldo om **opwaarts** af te rond, sodat herhaalde mikro-onttrekkings nie meer die aktiewe saldo van die poel afwaarts laat ratel nie.<sup>[[1]](#references)</sup>

Vereenvoudigde kwesbare reël (en regstelling in die nadoodse verslag).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Jagkontrolelys

- Gebruik die pool ’n hooks-adres wat nie nul is nie? Watter callbacks is geaktiveer?
- Is daar herverdelings/herbalanserings per swap wat pasgemaakte wiskunde gebruik? Enige tick-/drempellogika?
- Waar word divisions/mulDiv, Q64.96-omskakelings of SafeCast gebruik? Is afrondingssemantiek konsekwent deurgaans?
- Kan jy ’n Δin konstrueer wat ’n grens net-net oorsteek en ’n gunstige afrondingstak oplewer? Toets albei rigtings en beide exactInput en exactOutput.
- Hou die hook krediete of delta’s per oproeper by wat later onttrek kan word? Maak seker dat oorblyfsels geneutraliseer word.

## References

- [1] [Bunni Exploit-nadoodse ondersoek (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: Volledige Hack-analise](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M gedreineer via ’n likiditeitsfout (opsomming)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core-witskrif](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Agtergrond oor Uniswap v4 (QuillAudits-navorsing)](https://www.quillaudits.com/research/uniswap-development)
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
