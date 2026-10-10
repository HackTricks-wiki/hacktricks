# DeFi/AMM-uitbuiting: Uniswap v4 Hook-presisie-/afrondingsmisbruik

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy dokumenteer ’n klas DeFi/AMM-uitbuitingstegnieke teen DEX’e in die styl van Uniswap v4, wat kernwiskunde met custom hooks uitbrei. ’n Bunni V2-voorval illustreer ’n verwante fout: ’n fout in die afrondingsrigting van onttrekkingsrekeningkunde het aktiewe likiditeit onderskat, en ’n latere swap het daardie onderskatting in ’n winsgewende sandwich blootgelê.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Kernidee: as ’n hook bykomende rekeningkunde implementeer wat van fixed-point-wiskunde, tick-afronding en drempellogika afhanklik is, kan ’n aanvaller exact-input-swaps saamstel wat spesifieke drempels oorsteek sodat afrondingsverskille in hul guns ophoop. Deur die patroon te herhaal en daarna die opgeblase saldo te onttrek, realiseer hulle wins, dikwels gefinansier met ’n flash loan.

## Agtergrond: Uniswap v4-hooks en swap-vloei

- Hooks is kontrakte wat die PoolManager op spesifieke lewensiklus-punte aanroep (bv. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools word geïnisialiseer met ’n PoolKey wat die hook-kontrak insluit. ’n Nie-nul hook-adres aktiveer die terugroepe wat vir daardie pool gekies is.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks kan **custom deltas** terugstuur wat die finale balansveranderings van ’n swap of likiditeitsaksie wysig (custom accounting). Daardie deltas word aan die einde van die oproep as netto saldo’s vereffen, dus hoop enige afrondingsfout in die hook se wiskunde voor vereffening op.<sup>[[4]](#references)</sup>
- Kernwiskunde gebruik fixed-point-formate soos Q64.96 vir sqrtPriceX96, en tick-rekenkunde met 1.0001^tick. Enige custom-wiskunde wat hierop gebou word, moet die afrondingssemantiek noukeurig ooreen laat stem om invariant-drywing te voorkom.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps kan exactInput of exactOutput wees. In v3/v4 beweeg die prys langs ticks; die oorsteek van ’n tick-grens kan reeks-likiditeit aktiveer/deaktiveer. Hooks kan bykomende logika vir drempel-/tick-oorgange implementeer.<sup>[[9]](#references)[[11]](#references)</sup>

## Kwesbaarheidsarchetipe: presisie-/afrondingsdrywing wanneer drempels oorgesteek word

’n Tipiese kwesbare patroon in custom hooks:

1. Die hook bereken likiditeits- of balansdeltas per swap met behulp van heelgetalverdeling, mulDiv of fixed-point-omskakelings (bv. token ↔ likiditeit met sqrtPrice en tick-reekse).
2. Drempellogika (bv. herbalansering, stapsgewyse herverdeling of aktivering per reeks) word geaktiveer wanneer ’n swap se grootte of prysbeweging ’n interne grens oorsteek.
3. Afronding word inkonsekwent toegepas (bv. afkapping na nul, floor teenoor ceil) tussen die voorwaartse berekening en die vereffeningspad. Klein verskille kanselleer mekaar nie uit nie en krediteer eerder die oproeper.
4. Exact-input-swaps wat presies groot genoeg is om daardie grense te oorbrug, oes die positiewe afrondingsres in herhaling. Die aanvaller onttrek later die opgehoopte krediet.

Aanvalvoorvereistes
- ’n Pool wat ’n custom v4-hook gebruik wat bykomende wiskunde op elke swap uitvoer (bv. ’n LDF/herbalanseerder).
- Ten minste een uitvoeringspad waar afronding die swap-inisieerder bevoordeel wanneer drempels oorgesteek word.
- Die vermoë om baie swaps atomies te herhaal (flash loans is ideaal om tydelike kapitaal te verskaf en gaskoste te amortiseer).

## Praktiese aanvalmetodologie

1) Identifiseer kandidaat-pools met hooks
- Lys v4-pools op en kontroleer PoolKey.hooks != address(0).
- Ondersoek die hook se bytecode/ABI vir terugroepe: beforeSwap/afterSwap en enige custom-herbalanseringsmetodes.
- Soek wiskunde wat: deur likiditeit deel, tussen tokenbedrae en likiditeit omskakel, of BalanceDelta met afronding saamvoeg.

2) Modelleer die hook se wiskunde en drempels
- Herskep die hook se likiditeits-/herverdelingsformule: insette sluit gewoonlik sqrtPriceX96, tickLower/Upper, currentTick, fooi-vlak en netto likiditeit in.
- Karteer drempel-/stapfunksies: ticks, emmergrense of LDF-breekpunte. Bepaal aan watter kant van elke grens die delta afgerond word.
- Identifiseer waar omskakelings tussen uint256/int256 plaasvind, SafeCast gebruik word, of op mulDiv met implisiete floor staatgemaak word.

3) Stel exact-input-swaps in om grense oor te steek
- Gebruik Foundry/Hardhat-simulasies om die minimale Δin te bereken wat nodig is om die prys net oor ’n grens te skuif en die hook se vertakking te aktiveer.
- Verifieer dat afterSwap-vereffening die oproeper meer krediteer as wat dit kos, en ’n positiewe BalanceDelta of krediet in die hook se rekeningkunde laat.
- Herhaal swaps om krediet op te bou; roep dan die hook se onttrekkings-/vereffeningspad aan.

In v4 moet die swap-lus vanaf ’n PoolManager-unlock-terugroep uitgevoer word; ’n negatiewe `amountSpecified` dui op exact input, en `sqrtPriceLimitX96` moet streng binne die geldige reeks wees. ’n Nul-pryslimiet herroep, dus gebruik die pseudokode hieronder die onderste grens vir ’n zero-for-one-swap.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Voorbeeld van ’n Foundry-styl-toetstuig (pseudokode)
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
- Bereken die teiken met core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) in reële waardes; die Q64.96-resultaat word deur TickMath afgerond.<sup>[[13]](#references)</sup>
- Benader ’n token0 (zero-for-one)-invoer met die Q64.96-bewuste formule: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Pas die afronding in die kernroetine se rigtingspesifieke afronding.<sup>[[12]](#references)</sup>
- Pas Δin met ±1 wei rondom die grens aan om die tak te vind waar die hook in jou guns afrond.

4) Versterk met flash loans
- Leen ’n groot nominale bedrag (bv. 3M USDT of 2000 WETH) om baie iterasies atomies uit te voer.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Voer die gekalibreerde ruil-lus uit, en onttrek dan en betaal terug binne die flash loan-callback.

Aave V3-flitsleningskelet
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

5) Uitgang en kettingoorgrens-replikasie
- As hooks op verskeie kettings ontplooi is, herhaal dieselfde kalibrasie vir elke ketting.
- In die Bunni-insident het flitslening-likiditeit en brugroetes per ketting verskil; hou dus rekening met hierdie kettingspesifieke beperkings wanneer jy die ontleding herhaal.<sup>[[1]](#references)[[2]](#references)</sup>

## Algemene grondoorsake in hook-wiskunde

- Gemengde afrondingssemantiek: mulDiv rond af, terwyl latere paaie in effek opwaarts afrond; of omskakelings tussen tokens en likiditeit gebruik verskillende afronding.
- Foute met tick-belyning: afgeronde ticks word in een pad gebruik, maar tick-gespasieerde afronding in ’n ander.
- BalanceDelta-teken-/oorloopprobleme wanneer daar tydens vereffening tussen int256 en uint256 omgeskakel word.
- Presisieverlies in Q64.96-omskakelings (sqrtPriceX96) wat nie in die omgekeerde kartering weerspieël word nie.
- Opeenhopingspaaie: resbedrae per swap word as krediete nagespoor wat die oproeper kan onttrek, eerder as om dit te verbrand of ’n nulsom te handhaaf.

## Pasgemaakte rekeningkunde en delta-versterking

- Uniswap v4 se pasgemaakte rekeningkunde laat hooks toe om delta’s terug te gee wat direk aanpas wat die oproeper skuld of ontvang. As die hook krediete intern naspoor, kan afrondingsreste oor baie klein bewerkings ophoop **voordat** die finale vereffening plaasvind.<sup>[[4]](#references)</sup>
- As die hook ’n versoenbare onttrekkingspad blootstel, kan ’n aanvaller `swap → withdraw → swap` binne dieselfde PoolManager-ontsluitterugroep afwissel. Dit dwing die hook om delta’s op effens verskillende toestande te herbereken terwyl saldo’s hangende bly totdat die ontsluiting vereffen word.<sup>[[4]](#references)[[10]](#references)</sup>
- Wanneer jy hooks nagaan, spoor altyd na hoe BalanceDelta/HookDelta geskep en vereffen word. Een bevooroordeelde afronding in ’n vertakking kan ’n saamgestelde krediet word wanneer delta’s herhaaldelik herbereken word.

## Verdedigingsriglyne

- Differensiële toetsing: vergelyk die hook se wiskunde met ’n verwysingsimplementering wat hoëpresisie-rasionale rekenkunde gebruik, en bevestig gelykheid of ’n begrensde fout wat altyd die gebruiker benadeel (nooit die oproeper bevoordeel nie).
- Invariant-/eienskaptoetse:
  - Die som van delta’s (tokens, likiditeit) oor swap-paaie en hook-aanpassings moet waarde behou, met uitsondering van fooie.
  - Geen pad behoort oor herhaalde exactInput-iterasies netto positiewe krediet vir die swap-inisieerder te skep nie.
  - Toets drempel-/tick-grense met insette van ±1 wei vir beide exactInput en exactOutput.
- Afrondingsbeleid: sentraliseer afrondingshulpfunksies wat altyd teen die gebruiker afrond; skakel inkonsekwente casts en implisiete afronding af.
- Vereffeningsbestemmings: voeg onvermydelike afrondingsreste by die protokol se tesourie of verbrand dit; skryf dit nooit aan msg.sender toe nie.
- Tempo-beperkings/veiligheidsmaatreëls: stel minimum swap-groottes vir herbalansering-snellers; deaktiveer herbalansering as delta’s kleiner as ’n wei is; kontroleer delta’s teen verwagte reekse.
- Hersien hook-terugroepe holisties: beforeSwap/afterSwap en before/after-likiditeitsveranderinge moet ooreenstem oor tick-belyning en delta-afronding.

## Gevallestudie: Bunni V2 (2025‑09‑02)

- Protokol: Bunni V2, ’n Uniswap v4-hook wat ’n Liquidity Density Function (LDF) gebruik om tokendigtheid en ramings van totale likiditeit te bereken.<sup>[[1]](#references)[[2]](#references)</sup>
- Geaffekteerde poele: USDC/USDT op Ethereum en weETH/ETH op Unichain, met ’n totale waarde van sowat $8.4M.<sup>[[1]](#references)</sup>
- Stap 1 (prysverskuiwing): die aanvaller het ~3M USDT deur ’n flitslening geleen en dit geruil om die tick tot ~5000 te verskuif, wat die **aktiewe** USDC-saldo tot ~28 wei laat daal het.<sup>[[1]](#references)</sup>
- Stap 2 (afrondingsdreinering): 44 klein onttrekkings het afronding na onder in `BunniHubLogic::withdraw()` uitgebuit om die aktiewe USDC-saldo van 28 wei tot 4 wei te verminder (-85.7%), terwyl slegs ’n klein fraksie van LP-aandele verbrand is. Totale likiditeit het met ~84.4% afgeneem.<sup>[[1]](#references)[[2]](#references)</sup>
- Stap 3 (likiditeitsterugslag-sandwich): ’n Groot swap het die tick na ~839,189 verskuif (1 USDC ≈ 2.77e36 USDT). Likiditeitsramings het omgeswaai en met ~16.8% toegeneem, wat ’n sandwich moontlik gemaak het waarin die aanvaller teen die opgeblaasde prys teruggeruil en met wins uitgetree het.<sup>[[1]](#references)</sup>
- Oplossing wat in die nadoodse verslag geïdentifiseer is: verander die opdatering van die ongebruikte saldo sodat dit **opwaarts** afrond. Herhaalde mikro-onttrekkings sal dan nie meer die poel se aktiewe saldo trapsgewys afwaarts dryf nie.<sup>[[1]](#references)</sup>

Vereenvoudigde kwesbare reël (en die oplossing uit die nadoodse verslag).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Jagkontrolelys

- Gebruik die pool ’n nie-nul hooks-adres? Watter callbacks is geaktiveer?
- Is daar herverdelings/herbalanserings per swap met pasgemaakte wiskunde? Enige tick-/drempellogika?
- Waar word delings, mulDiv, Q64.96-omskakelings of SafeCast gebruik? Is afrondingsgedrag oral konsekwent?
- Kan jy ’n Δin opstel wat net-net ’n grens oorskry en ’n gunstige afrondingstak oplewer? Toets albei rigtings en sowel exactInput as exactOutput.
- Hou die hook krediete of delta’s per oproeper by wat later onttrek kan word? Maak seker dat oorskiet geneutraliseer word.

## References

- [1] [Bunni-uitbuiting: Nadoodse verslag (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2-uitbuiting: Volledige hack-ontleding](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2-uitbuiting: $8.3M gedreineer weens ’n likiditeitsfout (opsomming)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4-kern-witskrif](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Agtergrond oor Uniswap v4 (QuillAudits-navorsing)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Likiditeitsmeganika in Uniswap v4-kern](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Swap-meganika in Uniswap v4-kern](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks en sekuriteitsoorwegings](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4-kern Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4-kern PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4-kern SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4-kern TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
