# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Ova stranica dokumentuje klasu DeFi/AMM eksploatacionih tehnika protiv Uniswap v4–stil DEX‑ova koji proširuju osnovnu matematiku dodatnim hookovima. Nedavan incident u Bunni V2 iskoristio je grešku u zaokruživanju/preciznosti u Liquidity Distribution Function (LDF) koja se izvršavala pri svakoj zameni, omogućivši napadaču da akumulira pozitivne kredite i isisava likvidnost.

Ključna ideja: ako hook implementira dodatno računovodstvo koje zavisi od fixed‑point matematike, zaokruživanja tick‑ova i logike praga, napadač može da sastavi exact‑input swapove koji prelaze specifične pragove tako da se razlike u zaokruživanju akumuliraju u njegovu korist. Ponavljanje obrasca i potom povlačenje uvećanog salda realizuje profit, često finansiran flash loan‑om.

## Background: Uniswap v4 hooks and swap flow

- Hooks su contracti koje PoolManager poziva u specifičnim tačkama životnog ciklusa (npr. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Pools se inicijalizuju sa PoolKey koji uključuje hooks address. Ako nije nula, PoolManager izvršava callbacks pri svakoj relevantnoj operaciji.
- Core math koristi fixed‑point formate kao što je Q64.96 za sqrtPriceX96 i tick aritmetiku sa 1.0001^tick. Bilo koja custom matematika koja se nadograđuje mora pažljivo da uskladi semantiku zaokruživanja da bi se izbegao drift invarianti.
- Swaps mogu biti exactInput ili exactOutput. U v3/v4 cena se pomera duž tickova; prelazak granice tick‑a može aktivirati/deaktivirati range likvidnost. Hooks mogu implementirati dodatnu logiku na prelascima praga/ticka.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Tipičan ranjiv obrazac u custom hookovima:

1. Hook računa per‑swap delta‑e likvidnosti ili balansa koristeći integer division, mulDiv, ili fixed‑point konverzije (npr. token ↔ liquidity koristeći sqrtPrice i tick range).
2. Logika praga (npr. rebalansiranje, stepwise redistribucija, ili per‑range aktivacija) se aktivira kada veličina swapa ili pomeranje cene pređe internu granicu.
3. Zaokruživanje se primenjuje nekonzistentno (npr. truncation toward zero, floor naspram ceil) između forward izračuna i settlement puta. Male razlike se ne poništavaju već umesto toga kreditiraju pozivaoca.
4. Exact‑input swapovi, precizno dimenzionisani da obuhvate te granice, ponavljano sakupljaju pozitivan remainder iz zaokruživanja. Napadač kasnije povlači akumulirani kredit.

Preduslovi napada
- Pool koji koristi custom v4 hook koji obavlja dodatne matematičke operacije pri svakoj zameni (npr. LDF/rebalancer).
- Bar jedan izvršni put gde zaokruživanje koristi u korist inicijatora swapa preko prelaska praga.
- Mogućnost ponavljanja mnogo swapova atomično (flash loan‑ovi su idealni da obezbede privremeni float i amortizuju gas).

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumerišite v4 pools i proverite PoolKey.hooks != address(0).
- Inspektujte hook bytecode/ABI za callbacks: beforeSwap/afterSwap i bilo koje custom rebalancing metode.
- Tražite matematiku koja: deli po likvidnosti, konvertuje između token amount‑a i liquidity, ili agregira BalanceDelta sa zaokruživanjem.

2) Model the hook’s math and thresholds
- Rekreirajte hook‑ov formula za likvidnost/redistribuciju: ulazi tipično uključuju sqrtPriceX96, tickLower/Upper, currentTick, fee tier, i net liquidity.
- Mapirajte threshold/step funkcije: tickove, bucket granice, ili LDF breakpoint‑ove. Odredite na kojoj strani svake granice delta biva zaokružena.
- Identifikujte gde konverzije kastuju između uint256/int256, koriste SafeCast, ili se oslanjaju na mulDiv sa implicitnim floor.

3) Calibrate exact‑input swaps to cross boundaries
- Koristite Foundry/Hardhat simulacije da izračunate minimalni Δin potreban da pomerite cenu tek preko granice i aktivirate hook‑ovu granu.
- Potvrdite da afterSwap settlement kreditira pozivaoca više nego što je trošak, ostavljajući pozitivan BalanceDelta ili kredit u hook‑ovom računovodstvu.
- Ponavljajte swapove da akumulirate kredit; zatim pozovite hook‑ov withdrawal/settlement put.

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
Calibrating the exactInput
- Izračunajte ΔsqrtP za tick korak: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Aproksimirajte Δin koristeći v3/v4 formule: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Pazite da smer zaokruživanja odgovara osnovnoj matematici.
- Podesite Δin za ±1 wei oko granice da biste pronašli granu u kojoj hook zaokružuje u vašu korist.

4) Amplify with flash loans
- Pozajmite veliki notional (npr. 3M USDT ili 2000 WETH) da biste pokrenuli mnogo iteracija atomski.
- Izvršite kalibrisani swap loop, zatim povucite sredstva i vratite ih unutar flash loan callback-a.

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
5) Izlaz i replikacija između lanaca
- Ako su hooks deploy‑ovani na više chain‑ova, ponovite istu kalibraciju po chain‑u.
- Bridge vraća sredstva nazad na target chain i opciono kruži preko lending protocol‑a da zamagli tokove.

## Uobičajeni osnovni uzroci u matematici hook‑a

- Pomešana semantika zaokruživanja: mulDiv radi floor dok kasniji putevi efektivno zaokružuju nagore; ili konverzije između token/liquidity primenjuju različito zaokruživanje.
- Greške u usklađivanju tick‑ova: korišćenje nezaokrugljenih ticks u jednom putu i tick‑spaced zaokruživanja u drugom.
- Problemi sa znakom/overflow BalanceDelta pri konverziji između int256 i uint256 tokom settlement‑a.
- Gubitak preciznosti u Q64.96 konverzijama (sqrtPriceX96) koji nije zrcaljen u obrnutom mapiranju.
- Putanje akumulacije: per‑swap rezerve praćene kao krediti koji su withdrawable by the caller umesto da budu burned/zero‑sum.

## Odbrambene smernice

- Diferencijalno testiranje: zrcalite matematičku logiku hook‑a sa referentnom implementacijom koristeći visokopreciznu racionalnu aritmetiku i assertujte jednakost ili ograničenu grešku koja je uvek adversarijalna (nikad povoljna za caller‑a).
- Testovi invarianti/svojstava:
- Zbir delta (tokens, liquidity) preko swap path‑ova i podešavanja hook‑a mora sačuvati vrednost modulo fees.
- Nijedan path ne bi trebalo da stvori pozitivan net credit za swap initiator‑a pri ponovljenim exactInput iteracijama.
- Testovi oko pragova/tick granica za ±1 wei inpute za oba exactInput/exactOutput.
- Politika zaokruživanja: centralizujte rounding helpers koji uvek round against the user; eliminišite nekonzistentne casts i implicitne floors.
- Settlement sinks: akumulirajte neizbežan rounding residue u trezor protokola ili ga burn‑ujte; nikada ga ne pripisujte msg.sender‑u.
- Rate‑limits/guardrails: minimalne veličine swap‑ova za rebalancing okidače; onemogućite rebalanse ako su delte sub‑wei; sanity‑check delte protiv očekivanih opsega.
- Pregledajte hook callbacks holistički: beforeSwap/afterSwap i before/after promene likvidnosti treba da se poklapaju u pogledu tick usklađivanja i delta zaokruživanja.

## Studija slučaja: Bunni V2 (2025‑09‑02)

- Protokol: Bunni V2 (Uniswap v4 hook) sa LDF primenjenim po swap‑u za rebalans.
- Osnovni uzrok: greška u zaokruživanju/preciznosti u LDF accounting‑u likvidnosti tokom threshold‑crossing swap‑ova; per‑swap razlike akumulirane kao pozitivni krediti za caller‑a.
- Ethereum leg: attacker uzeo ~3M USDT flash loan, izveo kalibrisane exact‑input swap‑ove na USDC/USDT da izgradi kredite, povukao inflirane balance‑e, vratio i routovao sredstva preko Aave.
- UniChain leg: ponovio exploit sa 2000 WETH flash loan‑om, iskorištavajući ~1366 WETH i bridžujući na Ethereum.
- Uticaj: ~USD 8.3M isisano preko chain‑ova. Nije bila potrebna interakcija korisnika; potpuno on‑chain.

## Kontrolna lista za otkrivanje

- Da li pool koristi non‑zero hooks adresu? Koji callbacks su enabled?
- Postoje li per‑swap redistributions/rebalances koji koriste custom math? Bilo kakva tick/threshold logika?
- Gde su divisions/mulDiv, Q64.96 konverzije, ili SafeCast korišćeni? Da li su semantike zaokruživanja globalno konzistentne?
- Možete li konstruisati Δin koji jedva pređe granicu i daje povoljnu rounding branch? Testirajte obe smerove i oba exactInput i exactOutput.
- Da li hook prati per‑caller kredite ili delte koje kasnije mogu biti withdrawn? Osigurajte da je residue neutralisan.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
