# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

Ova stranica dokumentuje klasu DeFi/AMM exploitation tehnika protiv Uniswap v4–style DEX-ova koji proširuju core math pomoću custom hooks. Incident Bunni V2 prikazuje sličan propust: bug u smeru rounding-a u withdrawal accounting-u potcenio je active liquidity, a kasniji swap je tu potcenjenost izložio u profitabilnom sandwich-u.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ključna ideja: ako hook implementira dodatni accounting koji zavisi od fixed-point math-a, tick rounding-a i threshold logike, attacker može da kreira exact-input swaps koji prelaze određene threshold-e, tako da se rounding discrepancies akumuliraju u njegovu korist. Ponavljanjem ovog obrasca, a zatim povlačenjem uvećanog balance-a, ostvaruje se profit, često finansiran flash loan-om.

## Background: Uniswap v4 hooks i tok swap-a

- Hooks su contracti koje PoolManager poziva u određenim lifecycle tačkama (npr. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pool-ovi se inicijalizuju pomoću PoolKey-a koji uključuje hook contract. Non-zero hook address omogućava callbacks izabrane za taj pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks mogu vraćati **custom deltas** koji menjaju konačne balance changes swap-a ili liquidity akcije (custom accounting). Ti deltas se settle-uju kao net balances na kraju poziva, pa se svaka rounding greška unutar hook math-a akumulira pre settlement-a.<sup>[[4]](#references)</sup>
- Core math koristi fixed-point formate kao što je Q64.96 za sqrtPriceX96 i tick arithmetic sa 1.0001^tick. Svaki custom math postavljen preko toga mora pažljivo da uskladi rounding semantics kako bi se izbegao invariant drift.<sup>[[12]](#references)[[13]](#references)</sup>
- Swap-ovi mogu biti exactInput ili exactOutput. U v3/v4, cena se pomera duž tick-ova; crossing tick boundary-ja može aktivirati/deaktivirati range liquidity. Hooks mogu implementirati dodatnu logiku pri threshold/tick crossing-u.<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold-crossing precision/rounding drift

Tipičan ranjivi obrazac u custom hooks:

1. Hook izračunava liquidity ili balance deltas po swap-u koristeći integer division, mulDiv ili fixed-point conversions (npr. token ↔ liquidity koristeći sqrtPrice i tick ranges).
2. Threshold logika (npr. rebalancing, stepwise redistribution ili per-range activation) pokreće se kada veličina swap-a ili pomeranje cene pređe internu granicu.
3. Rounding se primenjuje nedosledno (npr. truncation prema nuli, floor nasuprot ceil) između forward calculation-a i settlement path-a. Male discrepancies se ne poništavaju, već credit-uju caller-a.
4. Exact-input swap-ovi, precizno podešeni da pređu te granice, ponavljano preuzimaju pozitivan rounding remainder. Attacker kasnije povlači akumulirani credit.

Attack preconditions
- Pool koji koristi custom v4 hook i obavlja dodatni math pri svakom swap-u (npr. LDF/rebalancer).
- Najmanje jedan execution path u kojem rounding ide u korist swap initiator-a pri threshold crossing-u.
- Mogućnost ponavljanja velikog broja swap-ova atomically (flash loans su idealni za obezbeđivanje privremenog float-a i amortizaciju gas-a).

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumeriši v4 pool-ove i proveri da li je PoolKey.hooks != address(0).
- Pregledaj hook bytecode/ABI radi callbacks-a: beforeSwap/afterSwap i svih custom rebalancing metoda.
- Potraži math koji: deli sa liquidity-jem, konvertuje između token amounts i liquidity-ja ili agregira BalanceDelta uz rounding.

2) Model the hook’s math and thresholds
- Rekonstruiši hook-ovu liquidity/redistribution formulu: inputs obično uključuju sqrtPriceX96, tickLower/Upper, currentTick, fee tier i net liquidity.
- Mapiraj threshold/step functions: tick-ove, bucket boundaries ili LDF breakpoints. Utvrdi sa koje strane svake granice se delta zaokružuje.
- Identifikuj mesta gde se vrši cast između uint256/int256, koristi SafeCast ili oslanja na mulDiv sa implicitnim floor-om.

3) Calibrate exact‑input swaps to cross boundaries
- Koristi Foundry/Hardhat simulations za izračunavanje minimalnog Δin potrebnog da se cena pomeri neposredno preko granice i pokrene branch hook-a.
- Proveri da li afterSwap settlement credit-uje caller-a iznosom većim od troška, ostavljajući pozitivan BalanceDelta ili credit u hook accounting-u.
- Ponavljaj swap-ove radi akumulacije credit-a; zatim pozovi withdrawal/settlement path hook-a.

U v4, swap loop mora da se izvršava iz PoolManager unlock callback-a; negativan `amountSpecified` označava exact input, a `sqrtPriceLimitX96` mora biti strogo unutar validnog range-a. Nulti price limit izaziva revert, pa pseudocode u nastavku koristi donju granicu za zero-for-one swap.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
Kalibracija exactInput
- Izračunajte cilj pomoću core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) u terminima realnih vrednosti; Q64.96 rezultat zaokružuje TickMath.<sup>[[13]](#references)</sup>
- Aproksimirajte token0 (zero-for-one) input pomoću formule koja uzima u obzir Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Uskladite zaokruživanje specifično za smer sa core rutinom.<sup>[[12]](#references)</sup>
- Podesite Δin za ±1 wei oko granice da biste pronašli granu u kojoj hook zaokružuje u vašu korist.

4) Pojačajte pomoću flash loans
- Pozajmite veliki nominalni iznos (npr. 3M USDT ili 2000 WETH) da biste atomarno izvršili mnogo iteracija.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Izvršite kalibrisanu swap petlju, zatim povucite sredstva i otplatite dug unutar flash loan callback-a.

Osnova Aave V3 flash loan-a
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
5) Izlazak i cross-chain replikacija
- Ako su hook-ovi deployovani na više chain-ova, ponovite istu kalibraciju za svaki chain.
- U incidentu sa Bunni-jem, flash-loan likvidnost i bridge rute razlikovale su se po chain-ovima, zato pri reprodukovanju analize uzmite u obzir ograničenja specifična za svaki chain.<sup>[[1]](#references)[[2]](#references)</sup>

## Uobičajeni osnovni uzroci u hook matematici

- Mešovita semantika zaokruživanja: `mulDiv` zaokružuje nadole, dok kasnije putanje efektivno zaokružuju naviše; ili konverzije između tokena/likvidnosti primenjuju različita zaokruživanja.
- Greške u poravnanju tick-ova: korišćenje nezaokruženih tick-ova u jednoj putanji i zaokruživanja prema razmaku tick-ova u drugoj.
- Problemi sa znakom/prekoračenjem kod BalanceDelta prilikom konverzije između int256 i uint256 tokom settlement-a.
- Gubitak preciznosti u Q64.96 konverzijama (sqrtPriceX96), koji nije preslikan u obrnutom mapiranju.
- Putevi akumulacije: ostaci po swap-u evidentiraju se kao krediti koje caller može da povuče umesto da budu spaljeni ili uklonjeni kroz zero-sum obračun.

## Custom accounting i amplifikacija delta

- Uniswap v4 custom accounting omogućava hook-ovima da vrate delta vrednosti koje direktno menjaju ono što caller duguje ili prima. Ako hook interno prati kredite, ostatak od zaokruživanja može da se akumulira kroz veliki broj malih operacija **pre** konačnog settlement-a.<sup>[[4]](#references)</sup>
- Ako hook izlaže kompatibilnu withdrawal putanju, attacker može da naizmenično izvršava `swap → withdraw → swap` unutar istog PoolManager unlock callback-a, primoravajući hook da ponovo izračuna delta vrednosti na neznatno izmenjenom stanju, dok bilansi ostaju na čekanju sve dok se unlock ne završi.<sup>[[4]](#references)[[10]](#references)</sup>
- Pri reviziji hook-ova uvek pratite kako se BalanceDelta/HookDelta generiše i settlement-uje. Jedno pristrasno zaokruživanje u jednoj grani može da postane kumulativni kredit kada se delta vrednosti više puta ponovo izračunavaju.

## Odbrambene smernice

- Differential testing: uporedite matematiku hook-a sa referentnom implementacijom koja koristi racionalnu aritmetiku visoke preciznosti i zahtevajte jednakost ili ograničenu grešku koja je uvek adversarialna (nikada povoljna za caller-a).
- Invariant/property testovi:
- Zbir delta vrednosti (tokena, likvidnosti) kroz swap putanje i hook prilagođavanja mora da očuva vrednost, osim naknada.
- Nijedna putanja ne sme da generiše pozitivan neto kredit za inicijatora swap-a kroz ponovljene exactInput iteracije.
- Testovi pragova/tick granica oko ulaza od ±1 wei za exactInput/exactOutput.
- Politika zaokruživanja: centralizujte pomoćne funkcije za zaokruživanje koje uvek zaokružuju na štetu korisnika; uklonite nekonzistentne cast-ove i implicitna zaokruživanja nadole.
- Settlement sinks: neizbežni ostatak od zaokruživanja akumulirajte u protokol treasury ili ga spaljujte; nikada ga nemojte pripisivati msg.sender-u.
- Rate-limits/guardrails: minimalne veličine swap-ova za pokretanje rebalansiranja; onemogućite rebalansiranja ako su delta vrednosti manje od jednog wei-ja; proverite delta vrednosti u odnosu na očekivane opsege.
- Holistički pregled hook callback-ova: beforeSwap/afterSwap i before/after promene likvidnosti moraju da koriste isto poravnanje tick-ova i zaokruživanje delta vrednosti.

## Studija slučaja: Bunni V2 (2025-09-02)

- Protokol: Bunni V2, Uniswap v4 hook koji koristi Liquidity Density Function (LDF) za izračunavanje gustine tokena i procena ukupne likvidnosti.<sup>[[1]](#references)[[2]](#references)</sup>
- Pogođeni pool-ovi: USDC/USDT na Ethereum-u i weETH/ETH na Unichain-u, ukupne vrednosti od približno $8.4M.<sup>[[1]](#references)</sup>
- Korak 1 (pomeranje cene): attacker je pozajmio približno 3M USDT putem flash borrow-a i izvršio swap kako bi pomerio tick na približno 5000, smanjujući **aktivni** USDC bilans na približno 28 wei.<sup>[[1]](#references)</sup>
- Korak 2 (drain zaokruživanjem): 44 mala povlačenja iskoristila su zaokruživanje nadole u `BunniHubLogic::withdraw()` kako bi smanjila aktivni USDC bilans sa 28 wei na 4 wei (-85.7%), dok je spaljen samo mali deo LP share-ova. Ukupna likvidnost smanjila se za približno 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Korak 3 (liquidity rebound sandwich): veliki swap pomerio je tick na približno 839,189 (1 USDC ≈ 2.77e36 USDT). Procene likvidnosti su se preokrenule i povećale za približno 16.8%, što je omogućilo sandwich u kom je attacker izvršio swap nazad po naduvanoj ceni i izašao sa profitom.<sup>[[1]](#references)</sup>
- Rešenje identifikovano u post-mortem analizi: izmenu idle-balance-a treba zaokružiti **naviše**, kako ponovljena mikro-povlačenja više ne bi postepeno smanjivala aktivni bilans pool-a.<sup>[[1]](#references)</sup>

Pojednostavljena ranjiva linija (i ispravka iz post-mortem analize).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Checklista za hunting

- Da li pool koristi hooks adresu različitu od nule? Koji callbacks su omogućeni?
- Da li postoje redistribucije/rebalansi po swap-u koji koriste prilagođenu matematiku? Postoji li logika zasnovana na tick-u/pragu?
- Gde se koriste divisions/mulDiv, Q64.96 konverzije ili SafeCast? Da li su semantike zaokruživanja globalno konzistentne?
- Možete li konstruisati Δin koji jedva prelazi granicu i proizvodi povoljnu granu zaokruživanja? Testirajte oba smera i exactInput i exactOutput.
- Da li hook prati kredite ili delte po caller-u koji se kasnije mogu povući? Uverite se da je ostatak neutralizovan.

## References

- [1] [Bunni analiza incidenta nakon eksploatacije (sep. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 exploit: potpuna analiza hack-a](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 exploit: $8,3M izvučeno zbog propusta u likvidnosti (sažetak)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 background (istraživanje QuillAudits-a)](https://www.quillaudits.com/research/uniswap-development)
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
