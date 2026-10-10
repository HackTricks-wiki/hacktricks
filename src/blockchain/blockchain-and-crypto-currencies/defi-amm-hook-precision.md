# DeFi/AMM eksploatacija: zloupotreba preciznosti/zaokruživanja u Uniswap v4 hookovima

{{#include ../../banners/hacktricks-training.md}}

Ova stranica opisuje klasu DeFi/AMM tehnika eksploatacije usmerenih na DEX-ove u stilu Uniswap v4, koji proširuju osnovnu matematiku prilagođenim hookovima. Incident sa Bunni V2 pokazuje sličan propust: greška u smeru zaokruživanja pri obračunu isplata potcenila je aktivnu likvidnost, a kasniji swap je iskoristio to potcenjivanje u profitabilnom sandwich napadu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ključna ideja: ako hook obavlja dodatni obračun koji zavisi od matematike sa fiksnom tačkom, zaokruživanja tick-ova i logike pragova, napadač može konstruisati swap-ove sa tačnim ulaznim iznosom koji prelaze određene pragove, tako da se razlike u zaokruživanju gomilaju u njegovu korist. Ponavljanjem obrasca, a zatim povlačenjem uvećanog salda, ostvaruje se profit, često finansiran flash loan-om.

## Osnovne informacije: Uniswap v4 hook-ovi i tok swap-a

- Hook-ove poziva PoolManager u određenim tačkama životnog ciklusa (npr. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pool-ovi se inicijalizuju pomoću PoolKey-ja koji uključuje hook ugovor. Adresa hook-a različita od nule omogućava callback-ove odabrane za taj pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Hook-ovi mogu da vrate **prilagođene delte** koje menjaju konačne promene salda pri swap-u ili akciji sa likvidnošću (prilagođeno obračunavanje). Te delte se poravnavaju kao neto salda na kraju poziva, pa se sve greške zaokruživanja u hook matematici akumuliraju pre poravnanja.<sup>[[4]](#references)</sup>
- Osnovna matematika koristi formate sa fiksnom tačkom, kao što je Q64.96 za sqrtPriceX96, i aritmetiku tick-ova zasnovanu na 1.0001^tick. Svaka prilagođena matematika nadograđena na tome mora pažljivo da uskladi pravila zaokruživanja kako bi se izbeglo odstupanje od invarijante.<sup>[[12]](#references)[[13]](#references)</sup>
- Swap-ovi mogu da budu exactInput ili exactOutput. U v3/v4, cena se menja duž tick-ova; prelazak granice tick-a može da aktivira/deaktivira likvidnost opsega. Hook-ovi mogu da primenjuju dodatnu logiku pri prelasku pragova/tick-ova.<sup>[[9]](#references)[[11]](#references)</sup>

## Tip ranjivosti: odstupanje preciznosti/zaokruživanja pri prelasku praga

Tipičan ranjivi obrazac u prilagođenim hook-ovima:

1. Hook izračunava promene likvidnosti ili salda za svaki swap pomoću celobrojnog deljenja, mulDiv-a ili konverzija sa fiksnom tačkom (npr. konverzija tokena ↔ likvidnosti pomoću sqrtPrice-a i opsega tick-ova).
2. Logika pragova (npr. rebalansiranje, postepena preraspodela ili aktivacija po opsezima) pokreće se kada veličina swap-a ili promena cene pređe internu granicu.
3. Zaokruživanje se primenjuje nedosledno (npr. odsecanje prema nuli, floor umesto ceil) između izračunavanja unapred i putanje poravnanja. Male razlike se ne poništavaju, već donose korist pozivaocu.
4. Swap-ovi sa tačnim ulaznim iznosom, precizno odmereni da pređu te granice, iznova prikupljaju pozitivan ostatak od zaokruživanja. Napadač kasnije povlači akumulirani iznos.

Uslovi za napad
- Pool koristi prilagođeni v4 hook koji obavlja dodatne matematičke izračune pri svakom swap-u (npr. LDF/rebalanser).
- Postoji bar jedna putanja izvršavanja u kojoj zaokruživanje pri prelasku pragova ide u korist inicijatora swap-a.
- Mogućnost ponavljanja velikog broja swap-ova atomarno (flash loan-ovi su idealni za obezbeđivanje privremenih sredstava i raspodelu troškova gasa).

## Praktična metodologija napada

1) Identifikujte potencijalne pool-ove sa hook-ovima
- Nabrojte v4 pool-ove i proverite da li je PoolKey.hooks != address(0).
- Pregledajte bytecode/ABI hook-a i potražite callback-ove: beforeSwap/afterSwap i sve metode prilagođenog rebalansiranja.
- Potražite matematiku koja: deli likvidnošću, konvertuje između iznosa tokena i likvidnosti ili agregira BalanceDelta uz zaokruživanje.

2) Modelujte matematiku i pragove hook-a
- Rekonstruišite formulu likvidnosti/preraspodele hook-a: ulazi obično uključuju sqrtPriceX96, tickLower/Upper, currentTick, nivo naknade i neto likvidnost.
- Mapirajte funkcije pragova/koraka: tick-ove, granice segmenata ili LDF prelomne tačke. Utvrdite na koju stranu svake granice se delta zaokružuje.
- Utvrdite gde se konverzije kastuju između uint256/int256, koriste SafeCast ili se oslanjaju na mulDiv sa implicitnim floor-om.

3) Podesite swap-ove sa tačnim ulaznim iznosom tako da pređu granice
- Koristite Foundry/Hardhat simulacije da izračunate minimalni Δin potreban za pomeranje cene tek preko granice i aktiviranje grane hook-a.
- Proverite da li poravnanje afterSwap pripisuje pozivaocu veći iznos od troška, ostavljajući pozitivan BalanceDelta ili iznos u obračunu hook-a.
- Ponavljajte swap-ove da biste akumulirali iznos, a zatim pozovite putanju za povlačenje/poravnanje hook-a.

U v4, swap petlja mora da se izvršava iz callback-a za otključavanje PoolManager-a; negativan `amountSpecified` označava tačan ulazni iznos, a `sqrtPriceLimitX96` mora da bude strogo unutar važećeg opsega. Nulta granica cene izaziva revert, pa pseudokod ispod koristi donju granicu za swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Primer testnog okruženja u stilu Foundry-ja (pseudokod)
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

Kalibracija `exactInput`
- Izračunaj cilj pomoću core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) u vrednostima realnih brojeva; rezultat Q64.96 zaokružuje TickMath.<sup>[[13]](#references)</sup>
- Aproksimiraj ulaz token0 (zero-for-one) pomoću formule koja uzima Q64.96 u obzir: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Uskladi smer zaokruživanja sa core rutinom.<sup>[[12]](#references)</sup>
- Podesi Δin za ±1 wei oko granice da pronađeš granu u kojoj hook zaokružuje u tvoju korist.

4) Povećaj obim pomoću flash loan-ova
- Pozajmi veliki iznos (npr. 3M USDT ili 2000 WETH) da bi atomarno izvršio mnogo iteracija.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Izvrši kalibrisanu petlju swap-ova, zatim povuci sredstva i otplati zajam unutar flash loan callback-a.

Kostur za Aave V3 flash loan
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

5) Izlaz i reprodukcija između lanaca
- Ako su hookovi raspoređeni na više lanaca, ponovite istu kalibraciju za svaki lanac.
- U incidentu sa Bunni-jem, likvidnost za flash loan i bridge putanje razlikovale su se po lancima, pa pri reprodukciji analize uzmite u obzir ograničenja specifična za svaki lanac.<sup>[[1]](#references)[[2]](#references)</sup>

## Česti osnovni uzroci u hook matematici

- Različita pravila zaokruživanja: mulDiv zaokružuje naniže, dok kasnije putanje efektivno zaokružuju naviše; ili se pri konverziji između tokena i likvidnosti primenjuju različita zaokruživanja.
- Greške u poravnavanju tick-ova: u jednoj putanji koriste se nezaokruženi tick-ovi, a u drugoj zaokruživanje prema razmaku između tick-ova.
- Problemi sa znakom ili prekoračenjem vrednosti BalanceDelta pri konverziji između int256 i uint256 tokom poravnanja.
- Gubitak preciznosti pri konverzijama Q64.96 (sqrtPriceX96) koji nije preslikan u obrnutom smeru.
- Putanje akumulacije: ostaci po zameni prate se kao krediti koje pozivalac može da povuče, umesto da budu poništeni ili da zbir bude nula.

## Prilagođeno računovodstvo i uvećavanje delta vrednosti

- Prilagođeno računovodstvo u Uniswap v4 omogućava hookovima da vrate delta vrednosti koje direktno menjaju ono što pozivalac duguje ili prima. Ako hook interno prati kredite, ostaci od zaokruživanja mogu da se akumuliraju kroz mnogo malih operacija **pre** konačnog poravnanja.<sup>[[4]](#references)</sup>
- Ako hook izlaže kompatibilnu putanju za povlačenje, napadač može da naizmenično poziva `swap → withdraw → swap` unutar istog PoolManager unlock callback-a, primoravajući hook da ponovo izračunava delta vrednosti na blago izmenjenom stanju, dok sredstva ostaju na čekanju do završetka unlock-a.<sup>[[4]](#references)[[10]](#references)</sup>
- Pri pregledu hookova, uvek pratite kako se BalanceDelta/HookDelta izračunava i poravnava. Jedno pristrasno zaokruživanje u jednoj grani može da postane kredit koji se uvećava pri ponovnom izračunavanju delta vrednosti.

## Smernice za odbranu

- Diferencijalno testiranje: uporedite matematiku hook-a sa referentnom implementacijom koja koristi racionalnu aritmetiku visoke preciznosti i proverite jednakost ili ograničenu grešku koja je uvek na štetu napadača (nikad u korist pozivaoca).
- Testovi invarijanti/svojstava:
  - Zbir delta vrednosti (tokena, likvidnosti) kroz putanje zamene i prilagođavanja hook-a mora da očuva vrednost, osim naknada.
  - Nijedna putanja ne sme da stvori pozitivan neto kredit za pokretača zamene kroz ponovljene iteracije exactInput.
  - Testirajte pragove/granice tick-ova za ulaze od ±1 wei za exactInput i exactOutput.
- Pravila zaokruživanja: objedinite pomoćne funkcije za zaokruživanje tako da uvek zaokružuju na štetu korisnika; uklonite nedosledna kastovanja i implicitna zaokruživanja naniže.
- Odredišta za poravnanje: akumulirajte neizbežne ostatke od zaokruživanja u protokolskom trezoru ili ih spaljujte; nikada ih ne pripisujte msg.sender.
- Ograničenja brzine/zaštitne mere: uvedite minimalne veličine zamena za okidače rebalansiranja; onemogućite rebalansiranje ako su delta vrednosti manje od jednog wei; proveravajte da li su delta vrednosti u očekivanom opsegu.
- Holistički pregledajte callback-ove hook-a: beforeSwap/afterSwap i promene likvidnosti pre/posle treba da budu usaglašeni u pogledu poravnanja tick-ova i zaokruživanja delta vrednosti.

## Studija slučaja: Bunni V2 (2025‑09‑02)

- Protokol: Bunni V2, Uniswap v4 hook koji koristi Liquidity Density Function (LDF) za izračunavanje gustine tokena i procena ukupne likvidnosti.<sup>[[1]](#references)[[2]](#references)</sup>
- Pogođeni pool-ovi: USDC/USDT na Ethereum-u i weETH/ETH na Unichain-u, ukupne vrednosti oko $8.4M.<sup>[[1]](#references)</sup>
- Korak 1 (pomak cene): napadač je pozajmio oko 3M USDT putem flash loan-a i zamenio tokene da bi pomerio tick na oko 5000, smanjivši **aktivni** saldo USDC-a na oko 28 wei.<sup>[[1]](#references)</sup>
- Korak 2 (odliv usled zaokruživanja): 44 mala povlačenja iskoristila su zaokruživanje naniže u `BunniHubLogic::withdraw()` da smanje aktivni saldo USDC-a sa 28 wei na 4 wei (-85.7%), dok je spaljen samo mali deo LP udela. Ukupna likvidnost se smanjila za oko 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Korak 3 (sendvič sa oporavkom likvidnosti): velika zamena pomerila je tick na oko 839,189 (1 USDC ≈ 2.77e36 USDT). Procene likvidnosti su se obrnule i porasle za oko 16.8%, što je omogućilo sendvič u kom je napadač zamenio tokene nazad po naduvanoj ceni i izašao sa dobiti.<sup>[[1]](#references)</sup>
- Ispravka navedena u post-mortem analizi: izmeniti ažuriranje neaktivnog salda tako da se zaokružuje **naviše**, kako ponovljena mikro-povlačenja više ne bi postepeno smanjivala aktivni saldo pool-a.<sup>[[1]](#references)</sup>

Pojednostavljena ranjiva linija (i ispravka iz post-mortem analize).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Kontrolna lista za lov

- Da li pool koristi hooks adresu različitu od nule? Koji su callbacks omogućeni?
- Da li se pri svakoj zameni obavljaju preraspodele/rebalansiranja pomoću prilagođene matematike? Postoji li logika za tick/threshold?
- Gde se koriste deljenja/mulDiv, konverzije Q64.96 ili SafeCast? Da li su pravila zaokruživanja dosledna svuda?
- Možete li da konstruišete Δin koji jedva prelazi granicu i aktivira povoljnu granu zaokruživanja? Testirajte oba smera i exactInput i exactOutput.
- Da li hook prati kredite ili razlike po pozivaocu koje se kasnije mogu povući? Pobrinite se da se ostatak neutrališe.

## References

- [1] [Naknadna analiza Bunni eksploatacije (septembar 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 eksploatacija: potpuna analiza hakovanja](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 eksploatacija: 8,3 miliona dolara izvučeno zbog greške u likvidnosti (sažetak)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 osnovni dokument](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Pozadina Uniswap v4 (istraživanje QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mehanika likvidnosti u Uniswap v4 jezgru](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mehanika zamene u Uniswap v4 jezgru](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks i bezbednosna razmatranja](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 jezgro Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 jezgro PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 jezgro SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 jezgro TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
