# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



Ova stranica dokumentuje klasu DeFi/AMM eksploatacijskih tehnika protiv Uniswap v4–stil DEX‑ova koji proširuju osnovnu matematiku prilagođenim hook‑ovima. Nedavni incident u Bunni V2 iskoristio je grešku u zaokruživaju/preciznosti u Liquidity Distribution Function (LDF) izvršavanom pri svakom swap‑u, što je napadaču omogućilo akumulaciju pozitivnih kreditnih stanja i isisavanje likvidnosti.

Ključna ideja: ako hook implementira dodatno računovodstvo koje zavisi od fixed‑point matematike, zaokruživanja tick‑ova i logike pragova, napadač može konstruisati exact‑input swap‑ove koji prelaze tačno određene pragove tako da se razlike u zaokruživanju nagomeštaju u njegovu korist. Ponavljanje obrasca i naknadno podizanje uvećanog salda realizuje profit, često finansirano flash loan‑om.

## Background: Uniswap v4 hooks and swap flow

- Hooks su contract‑i koje PoolManager poziva u određenim tačkama životnog ciklusa (npr. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools se inicijalizuju sa PoolKey koji uključuje hooks address. Ako nije nula, PoolManager poziva callback‑ove pri svakoj relevantnoj operaciji.
- Hooks mogu vratiti **prilagođene delta‑vrednosti** koje modifikuju finalne promene balansa swap‑a ili akcije likvidnosti (custom accounting). Te delta‑vrednosti se obračunavaju kao neto bilansi na kraju poziva, tako da se svaka greška u zaokruživanju unutar hook matematike akumulira pre poravnanja.
- Core math koristi fixed‑point formate kao što su Q64.96 za sqrtPriceX96 i tick aritmetiku sa 1.0001^tick. Bilo koja prilagođena matematika složena preko mora pažljivo uskladiti semantiku zaokruživanja da bi se izbeglo kršenje invariantnosti.
- Swaps mogu biti exactInput ili exactOutput. U v3/v4 cena se pomera duž tick‑ova; prelazak tick granice može aktivirati/deaktivirati range liquidity. Hooks mogu implementirati dodatnu logiku na crossing‑u pragova/tick‑ova.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Tipičan ranjiv obrazac u prilagođenim hook‑ovima:

1. Hook izračunava po‑swap delte likvidnosti ili balansa koristeći integer division, mulDiv, ili fixed‑point konverzije (npr. token ↔ liquidity koristeći sqrtPrice i tick range‑ove).
2. Logika pragova (npr. rebalansiranje, stepwise redistribution, ili per‑range aktivacija) se aktivira kada veličina swap‑a ili pomeranje cene pređe interni boundary.
3. Zaokruživanje se primenjuje nekonzistentno (npr. truncation prema nuli, floor nasuprot ceil) između forward kalkulacije i settlement puta. Male discrepancije se ne poništavaju već umesto toga kreditiraju caller‑u.
4. Exact‑input swap‑ovi, precizno veličine da straddle‑uju te boundary‑je, višestruko harvest‑uju pozitivni remainder od zaokruživanja. Napadač kasnije podiže akumulirani kredit.

Preduslovi napada
- Pool koji koristi prilagođeni v4 hook koji vrši dodatnu matematiku pri svakom swap‑u (npr. LDF/rebalancer).
- Najmanje jedan execution path gde zaokruživanje pogoduje initiator‑u swap‑a preko crossing‑a pragova.
- Sposobnost ponavljanja mnogo swap‑ova atomski (flash loans su idealni za obezbeđivanje privremenog float‑a i amortizaciju gasa).

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumerišite v4 pools i proverite PoolKey.hooks != address(0).
- Inspect‑ujte hook bytecode/ABI za callback‑ove: beforeSwap/afterSwap i bilo koje custom rebalancing metode.
- Tražite matematiku koja: deli po liquidity, konvertuje između token amounts i liquidity, ili agregira BalanceDelta sa zaokruživanjima.

2) Model the hook’s math and thresholds
- Rekreirajte hook‑ovu formulu za likvidnost/redistribuciju: ulazi obično uključuju sqrtPriceX96, tickLower/Upper, currentTick, fee tier, i net liquidity.
- Mapirajte threshold/step funkcije: tick‑ove, bucket boundary‑e, ili LDF breakpoint‑ove. Odredite sa koje strane svakog boundary‑ja delta biva zaokružena.
- Identifikujte gde konverzije castuju između uint256/int256, koriste SafeCast, ili se oslanjaju na mulDiv sa implicitnim floor.

3) Calibrate exact‑input swaps to cross boundaries
- Koristite Foundry/Hardhat simulacije da izračunate minimalni Δin potreban da pomerite cenu tik preko boundary‑ja i triggujete hook‑ovu granu.
- Verifikujte da poravnanje posle swap‑a kreditira caller‑a više nego što košta, ostavljajući pozitivan BalanceDelta ili kredit u hook‑ovom računovodstvu.
- Ponavljajte swap‑ove da akumulirate kredit; zatim pozovite hook‑ov withdrawal/settlement path.

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
Calibrisanje exactInput
- Izračunaj ΔsqrtP za tick korak: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Aproksimiraj Δin koristeći v3/v4 formule: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Osiguraj da smer zaokruživanja odgovara osnovnoj matematici.
- Podesi Δin za ±1 wei oko granice da pronađeš granu gde hook zaokružuje u tvoju korist.

4) Pojačaj korišćenjem flash loans
- Pozajmi veliki nominalni iznos (npr. 3M USDT ili 2000 WETH) da izvršiš mnogo iteracija atomarno.
- Izvrši kalibrisanu swap petlju, zatim povuci i otplati unutar flash loan callback-a.

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
- Ako su hooks raspoređeni na više lanaca, ponovite istu kalibraciju za svaki lanac.
- Bridge prebaci sredstva nazad na ciljnu mrežu i opciono kruži kroz lending protokole da zamagli tokove.

## Uobičajeni osnovni uzroci u matematici hook‑ova

- Mixed rounding semantics: mulDiv koristi floor dok kasniji putevi efektivno zaokružuju nagore; ili konverzije između token/liquidity primenjuju različita pravila zaokruživanja.
- Tick alignment errors: korišćenje nezaokruženih tickova u jednom putu i tick‑spaced zaokruživanja u drugom.
- BalanceDelta sign/overflow problemi pri konverziji između int256 i uint256 tokom settlementa.
- Gubitak preciznosti u Q64.96 konverzijama (sqrtPriceX96) koji nije reflektovan u obrnutom mapiranju.
- Accumulation pathways: ostatci po swapu praćeni kao krediti koji su podizivi od strane pozivaoca umesto da budu spaljeni/zero‑sum.

## Prilagođeno računovodstvo & amplifikacija delte

- Uniswap v4 custom accounting omogućava hooks da vrate delte koje direktno prilagođavaju šta pozivalac duguje/primа. Ako hook internо prati kredite, zaostatak odoknadnog zaokruživanja može se akumulirati kroz mnogo malih operacija pre nego što se izvrši konačni settlement.
- Ovo pojačava zloupotrebu na granicama/pragovima: napadač može naizmenično raditi `swap → withdraw → swap` u istoj tx, prisiljavajući hook da ponovo izračuna delte u blago drugačijem stanju dok su svi balansi još uvek u pending režimu.
- Prilikom pregleda hook‑ova, uvek pratite kako se BalanceDelta/HookDelta proizvode i settled. Jedno pristrasno zaokruživanje u jednoj grani može postati kumulativni kredit kada se delte opetovano preračunavaju.

## Odbrambene smernice

- Differential testing: preslikajte matematiku hook‑a naspram referentne implementacije koristeći racionalnu aritmetiku visoke preciznosti i asertujte jednakost ili ograničenu grešku koja je uvek adversarijalna (nikada povoljna za pozivaoca).
- Invarianti/testovi svojstava:
- Zbir delti (tokeni, liquidity) preko swap puteva i prilagodbi hook‑a mora očuvati vrednost modulo fees.
- Nijedan put ne bi trebalo da stvori pozitivan neto kredit za inicijatora swap‑a pri ponovljenim exactInput iteracijama.
- Testovi praga/granice tick‑a oko ±1 wei inputa za oba exactInput/exactOutput.
- Politika zaokruživanja: centralizujte helper‑e za zaokruživanje koji uvek zaokružuju protiv korisnika; eliminišite nekonzistentne caste i implicitne floore.
- Sinks za settlement: akumulirajte neizbežnu ostatnu vrednost od zaokruživanja u treasury protokola ili je spalite; nikada ne pripisujte msg.sender.
- Rate‑limits/guardrails: minimalne veličine swap‑a za pokretanje rebalansiranja; onemogućite rebalanse ako su delte sub‑wei; sanity‑check delti u odnosu na očekivane opsege.
- Pregledajte hook callbacks holistički: beforeSwap/afterSwap i before/after promene liquidity treba da se slažu u vezi tick poravnanja i zaokruživanja delti.

## Studija slučaja: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) sa LDF primenjenim po swapu za rebalans.
- Affected pools: USDC/USDT na Ethereum‑u i weETH/ETH na Unichain‑u, ukupno oko $8.4M.
- Step 1 (price push): napadač je flash‑borrowed ~3M USDT i zamenio ih da potisne tick na ~5000, svodeći **aktivni** USDC balans na ~28 wei.
- Step 2 (rounding drain): 44 tiny withdrawals iskoristile su floor zaokruživanje u `BunniHubLogic::withdraw()` da smanje aktivni USDC balans sa 28 wei na 4 wei (‑85.7%) dok je spaljen samo mali deo LP share‑ova. Ukupna liquidity je bila podcenjena za ~84.4%.
- Step 3 (liquidity rebound sandwich): veliki swap pomerio je tick na ~839,189 (1 USDC ≈ 2.77e36 USDT). Procene likvidnosti su se preokrenule i povećale za ~16.8%, omogućivši sandwich gde je napadač ponovo zamenio po napumpanoj ceni i izašao sa profitom.
- Popravka identifikovana u post‑mortem: promeniti idle‑balance update da zaokružuje **nagore** tako da ponovljene mikro‑withdrawal operacije ne mogu da „spuste“ aktivni balans pool‑a.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Lista provere

- Da li pool koristi non‑zero hooks adresu? Koji callbacks su omogućeni?
- Postoje li per‑swap redistributions/rebalances koje koriste custom math? Bilo kakva tick/threshold logika?
- Gde se koriste divisions/mulDiv, Q64.96 conversions, ili SafeCast? Da li su rounding semantics globalno dosledne?
- Možeš li konstruisati Δin koji jedva prelazi granicu i izaziva povoljnu rounding branch? Testiraj oba smera i oba exactInput i exactOutput.
- Da li hook prati per‑caller credits ili deltas koje je moguće povući kasnije? Osiguraj da je ostatak neutralisan.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
