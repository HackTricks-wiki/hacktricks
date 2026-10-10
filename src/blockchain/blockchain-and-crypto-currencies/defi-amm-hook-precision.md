# DeFi/AMM eksploatacija: zloupotreba preciznosti/zaokruživanja u Uniswap v4 hookovima

{{#include ../../banners/hacktricks-training.md}}

Ova stranica opisuje klasu tehnika za DeFi/AMM eksploataciju usmerenih na DEX-ove nalik Uniswap v4, koji proširuju osnovnu matematiku prilagođenim hookovima. Incident sa Bunni V2 ilustruje sličan propust: greška u smeru zaokruživanja pri obračunu povlačenja potcenila je aktivnu likvidnost, a kasniji swap je otkrio to potcenjivanje u profitabilnom sandwich napadu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ključna ideja: ako hook implementira dodatni obračun koji zavisi od matematike sa fiksnom tačkom, zaokruživanja tick-ova i logike pragova, napadač može da napravi exact-input swapove koji prelaze određene pragove, tako da se razlike u zaokruživanju akumuliraju u njegovu korist. Ponavljanjem obrasca, a zatim povlačenjem uvećanog salda, ostvaruje se profit, često finansiran flash loan-om.

## Osnovne informacije: Uniswap v4 hookovi i tok swap-a

- Hookovi su ugovori koje PoolManager poziva u određenim tačkama životnog ciklusa (npr. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pool-ovi se inicijalizuju pomoću PoolKey-a koji uključuje ugovor hook-a. Adresa hook-a koja nije nula omogućava callback-ove izabrane za taj pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Hookovi mogu da vrate **custom deltas** koji menjaju konačne promene salda pri swap-u ili akciji sa likvidnošću (custom accounting). Te razlike se namiruju kao neto salda na kraju poziva, pa se svaka greška zaokruživanja u matematici hook-a akumulira pre namirenja.<sup>[[4]](#references)</sup>
- Osnovna matematika koristi formate sa fiksnom tačkom, kao što je Q64.96 za sqrtPriceX96, i aritmetiku tick-ova sa 1.0001^tick. Svaka prilagođena matematika nadograđena na to mora pažljivo da uskladi semantiku zaokruživanja kako bi se izbeglo odstupanje invarijante.<sup>[[12]](#references)[[13]](#references)</sup>
- Swap-ovi mogu biti exactInput ili exactOutput. U v3/v4, cena se kreće duž tick-ova; prelazak granice tick-a može da aktivira/deaktivira likvidnost raspona. Hookovi mogu da implementiraju dodatnu logiku pri prelasku pragova/tick-ova.<sup>[[9]](#references)[[11]](#references)</sup>

## Obrazac ranjivosti: odstupanje preciznosti/zaokruživanja pri prelasku pragova

Tipičan ranjiv obrazac u prilagođenim hookovima:

1. Hook izračunava promene likvidnosti ili salda po swap-u koristeći celobrojno deljenje, mulDiv ili konverzije sa fiksnom tačkom (npr. konverziju između tokena i likvidnosti pomoću sqrtPrice-a i opsega tick-ova).
2. Logika pragova (npr. rebalansiranje, postepena preraspodela ili aktivacija po opsegu) pokreće se kada veličina swap-a ili kretanje cene pređe internu granicu.
3. Zaokruživanje se primenjuje nedosledno (npr. odsecanje ka nuli, floor umesto ceil) u proračunu unapred i putanji namirenja. Male razlike se ne poništavaju, već pripisuju sredstva pozivaocu.
4. Tačno kalibrisani exact-input swap-ovi koji prelaze te granice više puta prisvajaju pozitivan ostatak od zaokruživanja. Napadač kasnije povlači akumulirani kredit.

Preduslovi za napad
- Pool koji koristi prilagođeni v4 hook i obavlja dodatne proračune pri svakom swap-u (npr. LDF/rebalancer).
- Najmanje jedna putanja izvršavanja u kojoj zaokruživanje koristi inicijatoru swap-a pri prelasku pragova.
- Mogućnost atomskog ponavljanja velikog broja swap-ova (flash loan-ovi su idealni za obezbeđivanje privremenih sredstava i amortizaciju troškova gasa).

## Praktična metodologija napada

1) Identifikujte kandidate za pool-ove sa hookovima
- Popišite v4 pool-ove i proverite da li je PoolKey.hooks != address(0).
- Pregledajte bytecode/ABI hook-a i potražite callback-ove: beforeSwap/afterSwap i sve prilagođene metode za rebalansiranje.
- Potražite matematiku koja: deli vrednosti likvidnošću, pretvara između iznosa tokena i likvidnosti ili agregira BalanceDelta uz zaokruživanje.

2) Modelujte matematiku i pragove hook-a
- Rekonstruišite formulu likvidnosti/preraspodele hook-a: ulazi obično uključuju sqrtPriceX96, tickLower/Upper, currentTick, fee tier i neto likvidnost.
- Mapirajte funkcije pragova/koraka: tick-ove, granice bucket-ova ili LDF prelomne tačke. Utvrdite na kojoj strani svake granice se zaokružuje delta.
- Utvrdite gde se konverzije kastuju između uint256/int256, koriste SafeCast ili se oslanjaju na mulDiv sa implicitnim floor-om.

3) Kalibrišite exact-input swap-ove za prelazak granica
- Koristite Foundry/Hardhat simulacije da izračunate minimalni Δin potreban za pomeranje cene tek preko granice i aktiviranje grane hook-a.
- Proverite da li afterSwap namirenje pripisuje pozivaocu više od troška, ostavljajući pozitivan BalanceDelta ili kredit u obračunu hook-a.
- Ponavljajte swap-ove radi akumulacije kredita; zatim pozovite putanju za povlačenje/namirenje u hook-u.

U v4, swap petlja mora da se izvrši iz callback-a za otključavanje PoolManager-a; negativan `amountSpecified` označava exact input, a `sqrtPriceLimitX96` mora biti strogo unutar važećeg opsega. Nulta granica cene izaziva revert, pa pseudokod u nastavku koristi donju granicu za swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Primer test harness-a u stilu Foundry-ja (pseudokod)
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

Kalibrisanje funkcije exactInput
- Izračunajte cilj pomoću core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) u realnim vrednostima; rezultat Q64.96 zaokružuje TickMath.<sup>[[13]](#references)</sup>
- Aproksimirajte ulaz token0 (zero-for-one) pomoću formule koja uzima u obzir Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Uskladite zaokruživanje sa smerom u core rutini.<sup>[[12]](#references)</sup>
- Podesite Δin za ±1 wei oko granice da biste pronašli granu u kojoj hook zaokružuje u vašu korist.

4) Uvećanje pomoću flash zajmova
- Pozajmite veliki nominalni iznos (npr. 3M USDT ili 2000 WETH) kako biste atomarno izvršili mnogo iteracija.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Izvršite kalibrisanu petlju zamena, a zatim povucite sredstva i otplatite zajam unutar flash loan callback-a.

Osnovni skelet flash zajma Aave V3
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

5) Izlaz i replikacija između lanaca
- Ako su hook-ovi raspoređeni na više lanaca, ponovite istu kalibraciju za svaki lanac.
- U incidentu sa Bunni-jem, likvidnost za flash-loan i bridge rute razlikovale su se po lancima, zato pri reprodukciji analize uzmite u obzir ograničenja specifična za svaki lanac.<sup>[[1]](#references)[[2]](#references)</sup>

## Uobičajeni osnovni uzroci u hook matematici

- Mešovita pravila zaokruživanja: mulDiv zaokružuje naniže, dok se u kasnijim putanjama efektivno zaokružuje naviše; ili se pri konverziji između tokena i likvidnosti primenjuju različita pravila zaokruživanja.
- Greške u poravnanju tick-ova: u jednoj putanji koriste se nezaokruženi tick-ovi, a u drugoj zaokruživanje prema razmaku između tick-ova.
- Problemi sa znakom/prekoračenjem vrednosti u BalanceDelta pri konverziji između int256 i uint256 tokom poravnanja.
- Gubitak preciznosti u konverzijama Q64.96 (sqrtPriceX96) koji se ne odražava pri obrnutom mapiranju.
- Putanje akumulacije: ostatak po swap-u beleži se kao kredit koji pozivalac može da povuče, umesto da se potroši ili da se obezbedi nulti zbir.

## Prilagođeno obračunavanje i uvećavanje delta vrednosti

- Prilagođeno obračunavanje u Uniswap v4 omogućava hook-ovima da vrate delta vrednosti koje direktno menjaju iznos koji pozivalac duguje ili prima. Ako hook interno prati kredite, ostatak od zaokruživanja može da se akumulira kroz veliki broj malih operacija **pre** konačnog poravnanja.<sup>[[4]](#references)</sup>
- Ako hook izlaže kompatibilnu putanju za povlačenje, napadač može naizmenično da izvršava `swap → withdraw → swap` unutar istog PoolManager unlock callback-a, primoravajući hook da ponovo izračunava delta vrednosti na blago izmenjenom stanju, dok salda ostaju na čekanju do poravnanja pri unlock-u.<sup>[[4]](#references)[[10]](#references)</sup>
- Pri pregledu hook-ova uvek pratite kako se BalanceDelta/HookDelta izračunava i poravnava. Jedno pristrasno zaokruživanje u jednoj grani može da postane kredit koji se uvećava pri svakom ponovnom izračunavanju delta vrednosti.

## Smernice za odbranu

- Diferencijalno testiranje: uporedite matematiku hook-a sa referentnom implementacijom koja koristi racionalnu aritmetiku visoke preciznosti i zahtevajte jednakost ili ograničenu grešku koja je uvek nepovoljna za napadača (nikad povoljna za pozivaoca).
- Testovi invarijanti/svojstava:
  - Zbir delta vrednosti (tokena, likvidnosti) kroz putanje swap-a i prilagođavanja hook-a mora da očuva vrednost, osim naknada.
  - Nijedna putanja ne sme da stvori pozitivan neto kredit za inicijatora swap-a tokom ponovljenih iteracija exactInput.
  - Testirajte pragove/granice tick-ova sa ulazima od ±1 wei za exactInput/exactOutput.
- Pravila zaokruživanja: objedinite pomoćne funkcije za zaokruživanje tako da uvek zaokružuju na štetu korisnika; uklonite nedosledna kastovanja i implicitna zaokruživanja naniže.
- Odredišta za poravnanje: akumulirajte neizbežni ostatak od zaokruživanja u protokolskom trezoru ili ga spalite; nikada ga ne pripisujte msg.sender-u.
- Ograničenja učestalosti/zaštitne mere: minimalne veličine swap-a za okidače ponovnog balansiranja; onemogućite ponovno balansiranje ako su delta vrednosti manje od wei-ja; proverite razumnost delta vrednosti u odnosu na očekivane opsege.
- Sveobuhvatno pregledajte callback-ove hook-a: beforeSwap/afterSwap i pre/posle promene likvidnosti moraju da primenjuju usaglašeno poravnanje tick-ova i zaokruživanje delta vrednosti.

## Studija slučaja: Bunni V2 (2025‑09‑02)

- Protokol: Bunni V2, Uniswap v4 hook koji koristi Liquidity Density Function (LDF) za izračunavanje gustine tokena i procena ukupne likvidnosti.<sup>[[1]](#references)[[2]](#references)</sup>
- Pogođeni pulovi: USDC/USDT na Ethereum-u i weETH/ETH na Unichain-u, ukupne vrednosti oko $8.4M.<sup>[[1]](#references)</sup>
- Korak 1 (pomak cene): napadač je pozajmio oko 3M USDT putem flash-loan-a i izvršio swap kako bi pomerio tick na oko 5000, smanjivši **aktivni** saldo USDC-a na oko 28 wei-ja.<sup>[[1]](#references)</sup>
- Korak 2 (odliv usled zaokruživanja): 44 mala povlačenja iskoristila su zaokruživanje naniže u `BunniHubLogic::withdraw()` da smanje aktivni saldo USDC-a sa 28 wei-ja na 4 wei-ja (-85.7%), dok je spaljen samo neznatan deo LP udela. Ukupna likvidnost smanjena je za oko 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Korak 3 (sendvič sa oporavkom likvidnosti): veliki swap pomerio je tick na oko 839,189 (1 USDC ≈ 2.77e36 USDT). Procene likvidnosti su se preokrenule i porasle za oko 16.8%, omogućavajući sendvič u kom je napadač zamenio tokene nazad po naduvanoj ceni i ostvario profit pri izlasku.<sup>[[1]](#references)</sup>
- Ispravka navedena u post-mortem izveštaju: promeniti ažuriranje neaktivnog salda tako da se zaokružuje **naviše**, čime se sprečava da ponovljena mikro-povlačenja postepeno smanjuju aktivni saldo pula.<sup>[[1]](#references)</sup>

Pojednostavljena ranjiva linija (i ispravka iz post-mortem izveštaja).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Kontrolna lista za lov

- Da li pool koristi adresu hooks koja nije nula? Koji callback-ovi su omogućeni?
- Da li se pri svakoj zameni vrše preraspodele/rebalansi pomoću prilagođene matematike? Postoji li logika zasnovana na tick-ovima/pragovima?
- Gde se koriste deljenja/mulDiv, konverzije Q64.96 ili SafeCast? Da li su pravila zaokruživanja dosledna u celom sistemu?
- Možete li konstruisati Δin koji jedva prelazi granicu i aktivira povoljnu granu zaokruživanja? Testirajte oba smera, kao i exactInput i exactOutput.
- Da li hook prati kredite ili delte po pozivaocu koje se kasnije mogu povući? Osigurajte da se ostatak neutrališe.

## References

- [1] [Postmortem Bunni Exploita (septembar 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: potpuna analiza napada](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M ukradeno zbog propusta u likvidnosti (sažetak)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4: osnovni tehnički dokument](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Pozadina Uniswap v4 (istraživanje QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mehanika likvidnosti u jezgru Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mehanika zamena u jezgru Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks i bezbednosna razmatranja](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
