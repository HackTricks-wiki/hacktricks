# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Ova stranica dokumentuje klasu DeFi/AMM exploitation tehnika protiv Uniswap v4–style DEX-ova koji proširuju osnovnu matematiku pomoću custom hooks. Nedavni incident u Bunni V2 iskoristio je rounding/precision propust u Liquidity Distribution Function (LDF) koji se izvršava pri svakom swap-u, što je napadaču omogućilo da akumulira pozitivne kredite i isprazni liquidity.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

Ključna ideja: ako hook implementira dodatno računovodstvo koje zavisi od fixed-point matematike, tick rounding-a i threshold logike, napadač može konstruisati exact-input swap-ove koji prelaze određene threshold-e, tako da se rounding discrepancies akumuliraju u njegovu korist. Ponavljanjem ovog obrasca, a zatim povlačenjem uvećanog salda, ostvaruje se profit, često finansiran flash loan-om.

## Background: Uniswap v4 hooks i tok swap-a

- Hooks su contracts koje PoolManager poziva u određenim tačkama lifecycle-a (npr. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[3]](#references)[[6]](#references)</sup>
- Pools se inicijalizuju pomoću PoolKey-a koji uključuje hooks address. Ako nije nulta vrednost, PoolManager izvršava callbacks pri svakoj relevantnoj operaciji.<sup>[[6]](#references)</sup>
- Hooks mogu vraćati **custom deltas** koji menjaju konačne promene salda swap-a ili liquidity akcije (custom accounting). Ovi deltas se obrađuju kao net balances na kraju poziva, pa se svaka greška zaokruživanja unutar hook matematike akumulira pre settlement-a.<sup>[[5]](#references)</sup>
- Core math koristi fixed-point formate kao što je Q64.96 za sqrtPriceX96 i tick aritmetiku sa 1.0001^tick. Svaka custom matematika nadograđena na ovo mora pažljivo da uskladi rounding semantics kako bi se izbegao invariant drift.<sup>[[4]](#references)[[8]](#references)</sup>
- Swap-ovi mogu biti exactInput ili exactOutput. U v3/v4, cena se kreće duž tick-ova; crossing tick boundary-ja može aktivirati/deaktivirati range liquidity. Hooks mogu implementirati dodatnu logiku pri threshold/tick crossing-ima.<sup>[[5]](#references)</sup>

## Vulnerability archetype: threshold-crossing precision/rounding drift

Tipičan ranjivi obrazac u custom hooks:

1. Hook izračunava liquidity ili balance deltas po swap-u koristeći integer division, mulDiv ili fixed-point conversions (npr. token ↔ liquidity pomoću sqrtPrice-a i tick range-ova).
2. Threshold logika (npr. rebalancing, stepwise redistribution ili per-range activation) aktivira se kada veličina swap-a ili pomeranje cene pređe internu granicu.
3. Rounding se nedosledno primenjuje (npr. truncation prema nuli, floor nasuprot ceil-u) između forward calculation-a i settlement path-a. Male razlike se ne poništavaju, već umesto toga kreditiraju caller-a.
4. Exact-input swap-ovi, precizno podešeni da prelaze te granice, ponavljano prikupljaju pozitivan rounding remainder. Napadač kasnije povlači akumulirani kredit.

Attack preconditions
- Pool koji koristi custom v4 hook i izvršava dodatnu matematiku pri svakom swap-u (npr. LDF/rebalancer).
- Najmanje jedan execution path u kom rounding pogoduje initiator-u swap-a pri crossing-u threshold-a.
- Mogućnost ponavljanja velikog broja swap-ova atomically (flash loans su idealni za obezbeđivanje privremenog float-a i amortizaciju gas-a).

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumerate v4 pools i proveri da li je PoolKey.hooks != address(0).
- Inspect-uj hook bytecode/ABI radi callbacks-a: beforeSwap/afterSwap i svih custom rebalancing metoda.
- Potraži matematiku koja: deli sa liquidity-jem, konvertuje između token amounts i liquidity-ja ili agregira BalanceDelta uz rounding.

2) Model the hook’s math and thresholds
- Recreate-uj formulu hook-a za liquidity/redistribution: inputs obično uključuju sqrtPriceX96, tickLower/Upper, currentTick, fee tier i net liquidity.
- Mapiraj threshold/step funkcije: tick-ove, bucket boundaries ili LDF breakpoints. Odredi sa koje strane svake granice se delta zaokružuje.
- Identifikuj mesta na kojima se vrši cast između uint256/int256, koristi SafeCast ili se oslanja na mulDiv sa implicitnim floor-om.

3) Calibrate exact‑input swaps to cross boundaries
- Koristi Foundry/Hardhat simulations da izračunaš minimalni Δin potreban za pomeranje cene neposredno preko granice i aktiviranje odgovarajuće grane hook-a.
- Proveri da li afterSwap settlement kreditira caller-a iznosom većim od troška, ostavljajući pozitivan BalanceDelta ili kredit u accounting-u hook-a.
- Ponavljaj swap-ove radi akumulacije kredita; zatim pozovi withdrawal/settlement path hook-a.

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
Kalibrisanje exactInput
- Izračunajte ΔsqrtP za korak tick-a: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Aproksimujte Δin koristeći v3/v4 formule: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Uverite se da smer zaokruživanja odgovara core math.
- Podesite Δin za ±1 wei oko granice da biste pronašli granu u kojoj hook zaokružuje u vašu korist.

4) Amplifikacija pomoću flash loans
- Pozajmite veliki nominalni iznos (npr. 3M USDT ili 2000 WETH) da biste izvršili mnogo iteracija atomski.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Izvršite kalibrisanu swap petlju, zatim povucite sredstva i otplatite zajam unutar flash loan callback-a.

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
5) Izlaz i cross-chain replikacija
- Ako su hooks deployed na više chain-ova, ponovite istu kalibraciju za svaki chain.
- Prebacite sredstva bridge-om nazad na ciljni chain i opciono ih provedite kroz lending protokole radi prikrivanja tokova.<sup>[[2]](#references)</sup>

## Uobičajeni osnovni uzroci u hook matematici

- Mešane semantike zaokruživanja: mulDiv zaokružuje naniže, dok kasnije putanje efektivno zaokružuju naviše; ili konverzije između tokena/liquidity koriste različito zaokruživanje.
- Greške u poravnanju tick-ova: u jednoj putanji koriste se nezaokruženi tick-ovi, a u drugoj zaokruživanje prema razmaku između tick-ova.
- Problemi sa znakom/prekoračenjem kod BalanceDelta prilikom konverzije između int256 i uint256 tokom settlement-a.
- Gubitak preciznosti u Q64.96 konverzijama (sqrtPriceX96) koji nije preslikan obrnutim mapiranjem.
- Putanje akumulacije: ostaci po swap-u prate se kao krediti koje caller može da povuče umesto da budu spaljeni ili uključeni u zero-sum obračun.

## Custom accounting i delta amplifikacija

- Uniswap v4 custom accounting omogućava hooks-ovima da vrate delte koje direktno prilagođavaju ono što caller duguje ili prima. Ako hook interno prati kredite, ostatak od zaokruživanja može da se akumulira kroz mnogo malih operacija **pre** konačnog settlement-a.<sup>[[5]](#references)</sup>
- Ovo pojačava abuse granica/threshold-a: attacker može da smenjuje `swap → withdraw → swap` u istoj tx, primoravajući hook da ponovo izračuna delte na malo drugačijem stanju dok su svi balansi još uvek pending.
- Prilikom review-a hook-ova uvek pratite kako se BalanceDelta/HookDelta generiše i settlement-uje. Jedno pristrasno zaokruživanje u jednoj grani može postati kumulativni kredit kada se delte iznova obračunavaju.

## Defensive smernice

- Differential testing: uporedite matematiku hook-a sa referentnom implementacijom koja koristi racionalnu aritmetiku visoke preciznosti i proverite jednakost ili ograničenu grešku koja je uvek adversarial (nikada povoljna za caller-a).
- Invariant/property testovi:
- Zbir delta (tokena, liquidity) kroz swap putanje i hook prilagođavanja mora da očuva vrednost, uz izuzetak fee-jeva.
- Nijedna putanja ne sme da kreira pozitivan neto kredit za swap initiator-a kroz ponovljene exactInput iteracije.
- Testovi granica threshold-a/tick-a oko ulaza od ±1 wei za exactInput/exactOutput.
- Politika zaokruživanja: centralizujte pomoćne funkcije za zaokruživanje koje uvek zaokružuju na štetu user-a; uklonite nedosledne cast-ove i implicitna zaokruživanja naniže.
- Settlement sinks: neizbežni ostatak od zaokruživanja akumulirajte u protocol treasury ili ga spaljujte; nikada ga nemojte pripisivati msg.sender-u.
- Rate-limits/guardrails: uvedite minimalne veličine swap-ova za rebalancing triggers; onemogućite rebalansiranje ako su delte manje od jednog wei-ja; proveravajte delte u odnosu na očekivane opsege.
- Holistički pregledajte hook callbacks: beforeSwap/afterSwap i before/after promene liquidity-ja moraju da budu usklađeni u pogledu poravnanja tick-ova i zaokruživanja delta.

## Studija slučaja: Bunni V2 (2025-09-02)

- Protocol: Bunni V2 (Uniswap v4 hook) sa LDF-om koji se primenjuje po swap-u radi rebalansiranja.<sup>[[7]](#references)</sup>
- Pogođeni pool-ovi: USDC/USDT na Ethereum-u i weETH/ETH na Unichain-u, ukupne vrednosti oko $8.4M.<sup>[[1]](#references)[[2]](#references)</sup>
- Korak 1 (price push): attacker je flash-borrowed ~3M USDT i izvršio swap kako bi pomerio tick na ~5000, smanjujući **active** USDC balans na približno 28 wei.<sup>[[7]](#references)</sup>
- Korak 2 (rounding drain): 44 sitna withdrawal-a iskoristila su floor rounding u `BunniHubLogic::withdraw()` da smanje active USDC balans sa 28 wei na 4 wei (-85.7%), dok je spaljen samo mali deo LP share-ova. Ukupna liquidity bila je potcenjena za ~84.4%.<sup>[[2]](#references)[[7]](#references)</sup>
- Korak 3 (liquidity rebound sandwich): veliki swap pomerio je tick na ~839,189 (1 USDC ≈ 2.77e36 USDT). Procene liquidity-ja su se preokrenule i povećale za ~16.8%, što je omogućilo sandwich u kojem je attacker izvršio swap nazad po naduvanoj ceni i izašao sa profitom.<sup>[[7]](#references)</sup>
- Rešenje utvrđeno u post-mortem-u: izmenu idle-balance ažuriranja izvršiti uz zaokruživanje **naviše**, kako ponovljeni micro-withdrawal-i ne bi mogli postepeno da smanjuju active balans pool-a.<sup>[[7]](#references)</sup>

Pojednostavljena ranjiva linija (i izmena iz post-mortem-a)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Checklista za hunting

- Da li pool koristi hooks adresu različitu od nule? Koji callbacks su omogućeni?
- Da li postoje redistribucije/rebalansiranja po swapu koja koriste custom math? Postoji li logika za tick/threshold?
- Gde se koriste divisions/mulDiv, Q64.96 conversions ili SafeCast? Da li su semantike zaokruživanja dosledne globalno?
- Možete li konstruisati Δin koji jedva prelazi granicu i daje povoljnu granu za zaokruživanje? Testirajte oba smera i exactInput i exactOutput.
- Da li hook prati kredite ili delte po calleru koji se kasnije mogu povući? Uverite se da je residue neutralisan.

## Reference

- [1] [Bunni V2 Exploit: $8.3M iscrpljeno zbog propusta u likvidnosti (sažetak)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: kompletna Hack analiza](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Uniswap v4 pozadina (QuillAudits istraživanje)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Mehanizmi likvidnosti u Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Mehanizmi swapa u Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Uniswap v4 Hooks i bezbednosna razmatranja](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Bunni Exploit Post Mortem (sep. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
