# Eksploatacija DeFi/AMM: zloupotreba preciznosti/zaokruživanja Uniswap v4 Hook mehanizma

{{#include ../../banners/hacktricks-training.md}}

Ova stranica dokumentuje klasu DeFi/AMM exploitation tehnika protiv DEX-ova u stilu Uniswap v4, koji proširuju osnovnu matematiku prilagođenim hook-ovima. Incident Bunni V2 prikazuje sličan problem: greška u smeru zaokruživanja pri obračunu povlačenja umanjila je prikazanu aktivnu likvidnost, a kasniji swap je tu procenu izložio kroz profitabilan sandwich.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ključna ideja: ako hook implementira dodatni obračun koji zavisi od fixed-point matematike, zaokruživanja tick-ova i logike pragova, napadač može konstruisati exact-input swap-ove koji prelaze određene pragove tako da se razlike u zaokruživanju akumuliraju u njegovu korist. Ponavljanjem obrasca, a zatim povlačenjem uvećanog salda, ostvaruje se profit, često finansiran flash loan-om.

## Osnove: Uniswap v4 hook-ovi i tok swap-a

- Hook-ovi su contract-i koje PoolManager poziva u određenim tačkama životnog ciklusa (npr. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pool-ovi se inicijalizuju pomoću PoolKey-a koji uključuje hook contract. Adresa hook-a koja nije nula omogućava callback-ove izabrane za taj pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Hook-ovi mogu vraćati **custom deltas** koji menjaju konačne promene salda swap-a ili liquidity akcije (custom accounting). Ti delta-i se izmiruju kao neto salda na kraju poziva, pa se svaka greška u zaokruživanju unutar hook matematike akumulira pre settlement-a.<sup>[[4]](#references)</sup>
- Osnovna matematika koristi fixed-point formate, kao što je Q64.96 za sqrtPriceX96, i tick aritmetiku sa 1.0001^tick. Svaka prilagođena matematika postavljena preko toga mora pažljivo pratiti semantiku zaokruživanja kako bi se izbeglo pomeranje invarianti.<sup>[[12]](#references)[[13]](#references)</sup>
- Swap-ovi mogu biti exactInput ili exactOutput. U v3/v4, cena se kreće duž tick-ova; prelazak granice tick-a može aktivirati/deaktivirati range liquidity. Hook-ovi mogu implementirati dodatnu logiku pri prelasku pragova/tick-ova.<sup>[[9]](#references)[[11]](#references)</sup>

## Obrazac ranjivosti: drift preciznosti/zaokruživanja pri prelasku pragova

Tipičan ranjivi obrazac u prilagođenim hook-ovima:

1. Hook izračunava liquidity ili balance delta-e po swap-u koristeći celobrojno deljenje, mulDiv ili fixed-point konverzije (npr. token ↔ liquidity pomoću sqrtPrice-a i tick opsega).
2. Logika pragova (npr. rebalansiranje, stepwise redistribucija ili aktivacija po range-u) pokreće se kada veličina swap-a ili pomeranje cene pređe internu granicu.
3. Zaokruživanje se primenjuje nedosledno (npr. odsecanje ka nuli, floor u odnosu na ceil) između prosleđenog izračunavanja i settlement putanje. Male razlike se ne poništavaju, već kreditiraju caller-a.
4. Exact-input swap-ovi, precizno podešeni da obuhvate te granice, ponavljano prikupljaju pozitivan ostatak zaokruživanja. Napadač kasnije povlači akumulirani kredit.

Preduslovi napada
- Pool koji koristi prilagođeni v4 hook i obavlja dodatnu matematiku pri svakom swap-u (npr. LDF/rebalancer).
- Najmanje jedna execution putanja u kojoj zaokruživanje pogoduje inicijatoru swap-a pri prelasku pragova.
- Mogućnost atomskog ponavljanja velikog broja swap-ova (flash loan-ovi su idealni za obezbeđivanje privremenog kapitala i amortizaciju gas troškova).

## Praktična metodologija napada

1) Identifikujte pool-ove sa hook-ovima
- Enumerišite v4 pool-ove i proverite da li je PoolKey.hooks != address(0).
- Pregledajte bytecode/ABI hook-a u potrazi za callback-ovima: beforeSwap/afterSwap i svim prilagođenim metodama za rebalansiranje.
- Potražite matematiku koja: deli sa liquidity-em, konvertuje između iznosa token-a i liquidity-ja ili agregira BalanceDelta uz zaokruživanje.

2) Modelujte matematiku hook-a i pragove
- Rekonstruišite formulu za liquidity/redistribuciju hook-a: ulazi obično uključuju sqrtPriceX96, tickLower/Upper, currentTick, fee tier i net liquidity.
- Mapirajte threshold/step funkcije: tick-ove, granice bucket-a ili LDF breakpoint-e. Odredite na kojoj strani svake granice se delta zaokružuje.
- Identifikujte mesta na kojima se vrše cast-ovi između uint256/int256, koristi SafeCast ili se oslanja na mulDiv sa implicitnim floor-om.

3) Kalibrišite exact-input swap-ove za prelazak granica
- Koristite Foundry/Hardhat simulacije za izračunavanje minimalnog Δin potrebnog da se cena pomeri neposredno preko granice i pokrene grana hook-a.
- Proverite da li afterSwap settlement kreditira caller-a iznosom većim od troška, ostavljajući pozitivan BalanceDelta ili kredit u accounting-u hook-a.
- Ponavljajte swap-ove radi akumuliranja kredita; zatim pozovite withdrawal/settlement putanju hook-a.

U v4, swap loop mora da se izvršava iz PoolManager unlock callback-a; negativan `amountSpecified` označava exact input, a `sqrtPriceLimitX96` mora biti strogo unutar validnog opsega. Nulta granica cene izaziva revert, pa pseudocode u nastavku koristi donju granicu za zero-for-one swap.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Primer Foundry-style test harness-a (pseudocode)
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
Kalibracija za exactInput
- Izračunajte cilj koristeći core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) u terminima stvarnih vrednosti; Q64.96 rezultat zaokružuje TickMath.<sup>[[13]](#references)</sup>
- Aproksimirajte ulaz token0 (zero-for-one) koristeći formulu prilagođenu za Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Uskladite zaokruživanje specifično za smer sa core rutinom.<sup>[[12]](#references)</sup>
- Prilagodite Δin za ±1 wei oko granice da biste pronašli granu u kojoj hook zaokružuje u vašu korist.

4) Povećajte obim pomoću flash loans
- Pozajmite veliki notional (npr. 3M USDT ili 2000 WETH) da biste izvršili mnogo iteracija atomski.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Izvršite kalibrisanu swap petlju, zatim povucite sredstva i vratite zajam u okviru flash loan callback-a.

Aave V3 flash loan kostur
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
5) Izlaz i cross-chain replikacija
- Ako su hooks deployed na više chain-ova, ponovite istu kalibraciju za svaki chain.
- U Bunni incidentu, flash-loan likvidnost i bridge rute razlikovale su se po chain-u, zato pri reprodukciji analize uzmite u obzir ograničenja specifična za svaki chain.<sup>[[1]](#references)[[2]](#references)</sup>

## Uobičajeni osnovni uzroci u hook matematici

- Mešane semantike zaokruživanja: `mulDiv` zaokružuje naniže, dok kasnije putanje efektivno zaokružuju naviše; ili konverzije između tokena/likvidnosti koriste različito zaokruživanje.
- Greške u poravnanju tick-ova: korišćenje nezaokruženih tick-ova u jednoj putanji i zaokruživanja na razmak tick-ova u drugoj.
- Problemi sa znakom/prekoračenjem kod `BalanceDelta` prilikom konverzije između `int256` i `uint256` tokom settlement-a.
- Gubitak preciznosti u Q64.96 konverzijama (`sqrtPriceX96`) koji nije preslikan u obrnutom mapiranju.
- Putanje akumulacije: ostaci po swap-u evidentiraju se kao credits koje caller može da povuče, umesto da budu spaljeni ili deo zero-sum obračuna.

## Custom accounting i amplifikacija delta

- Uniswap v4 custom accounting omogućava hooks da vrate delta vrednosti koje direktno menjaju iznos koji caller duguje ili prima. Ako hook interno prati credits, ostatak nastao zaokruživanjem može da se akumulira kroz mnogo malih operacija **pre** konačnog settlement-a.<sup>[[4]](#references)</sup>
- Ako hook izlaže kompatibilnu withdrawal putanju, attacker može da naizmenično izvršava `swap → withdraw → swap` unutar istog PoolManager unlock callback-a, primoravajući hook da ponovo izračuna delta vrednosti na blago izmenjenom stanju, dok salda ostaju pending do settlement-a unlock-a.<sup>[[4]](#references)[[10]](#references)</sup>
- Pri pregledu hooks-a uvek pratite kako se `BalanceDelta`/`HookDelta` kreira i settlement-uje. Jedno pristrasno zaokruživanje u jednoj grani može postati kumulativni credit kada se delta vrednosti iznova izračunavaju.

## Odbrambene smernice

- Differential testing: uporedite matematiku hook-a sa referentnom implementacijom koja koristi racionalnu aritmetiku visoke preciznosti i zahtevajte jednakost ili ograničenu grešku koja je uvek adversarial (nikada povoljna za caller-a).
- Invariant/property testovi:
- Zbir delta vrednosti (tokena, likvidnosti) kroz swap putanje i hook prilagođavanja mora očuvati vrednost, uz izuzetak fee-jeva.
- Nijedna putanja ne sme da kreira pozitivan neto credit za inicijatora swap-a kroz ponovljene exactInput iteracije.
- Testovi pragova/tick granica oko ulaza od ±1 wei za exactInput/exactOutput.
- Politika zaokruživanja: centralizujte helper-e za zaokruživanje koji uvek zaokružuju na štetu user-a; uklonite nekonzistentne cast-ove i implicitna zaokruživanja naniže.
- Settlement sinks: neizbežni ostatak nastao zaokruživanjem akumulirajte u protocol treasury ili ga spaljujte; nikada ga nemojte pripisivati `msg.sender`-u.
- Rate-limits/guardrails: minimalne veličine swap-a za trigger-e rebalansiranja; onemogućite rebalansiranja ako su delta vrednosti manje od jednog wei-ja; proveravajte delta vrednosti u odnosu na očekivane opsege.
- Holistički pregledajte hook callback-e: beforeSwap/afterSwap i before/after promene likvidnosti moraju biti usklađeni u pogledu poravnanja tick-ova i zaokruživanja delta vrednosti.

## Studija slučaja: Bunni V2 (2025-09-02)

- Protocol: Bunni V2, Uniswap v4 hook koji koristi Liquidity Density Function (LDF) za izračunavanje gustine tokena i procena ukupne likvidnosti.<sup>[[1]](#references)[[2]](#references)</sup>
- Pogođeni pool-ovi: USDC/USDT na Ethereum-u i weETH/ETH na Unichain-u, ukupne vrednosti oko $8.4M.<sup>[[1]](#references)</sup>
- Korak 1 (pomak cene): attacker je pozajmio ~3M USDT putem flash loan-a i izvršio swap kako bi pomerio tick na ~5000, smanjujući **aktivno** USDC stanje na ~28 wei.<sup>[[1]](#references)</sup>
- Korak 2 (drain zaokruživanjem): 44 mala withdrawal-a iskoristila su zaokruživanje naniže u `BunniHubLogic::withdraw()` kako bi smanjila aktivno USDC stanje sa 28 wei na 4 wei (-85.7%), dok je spaljen samo mali deo LP shares-a. Ukupna likvidnost smanjena je za ~84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Korak 3 (liquidity rebound sandwich): veliki swap pomerio je tick na ~839,189 (1 USDC ≈ 2.77e36 USDT). Procene likvidnosti su se preokrenule i povećale za ~16.8%, što je omogućilo sandwich u kojem je attacker izvršio swap nazad po naduvanoj ceni i izašao sa profitom.<sup>[[1]](#references)</sup>
- Identifikovana ispravka u post-mortem izveštaju: izmeniti ažuriranje idle balance-a tako da se zaokružuje **naviše**, čime se sprečava da ponovljena mikro-withdrawal povlačenja postepeno smanjuju aktivno stanje pool-a.<sup>[[1]](#references)</sup>

Pojednostavljena ranjiva linija (i ispravka iz post-mortem izveštaja).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- Da li pool koristi non-zero hooks adresu? Koji callback-ovi su omogućeni?
- Da li postoje redistribucije/rebalansi po swap-u koji koriste prilagođenu matematiku? Da li postoji logika zasnovana na tick-u/granici?
- Gde se koriste divisions/mulDiv, Q64.96 konverzije ili SafeCast? Da li su semantike zaokruživanja dosledne globalno?
- Možete li konstruisati Δin koji jedva prelazi granicu i daje povoljnu granu zaokruživanja? Testirajte oba smera i exactInput i exactOutput.
- Da li hook prati kredite ili delta vrednosti po caller-u koje se kasnije mogu povući? Uverite se da je residue neutralisan.

## References

- [1] [Bunni analiza nakon Exploit-a (sep. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: potpuna analiza hack-a](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M izvučeno kroz propust u likvidnosti (sažetak)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Pozadina Uniswap v4 (istraživanje QuillAudits-a)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mehanika likvidnosti u Uniswap v4 core-u](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mehanika swap-a u Uniswap v4 core-u](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks i bezbednosna razmatranja](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
