# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaelezea darasa la mbinu za kuharibu DeFi/AMM dhidi ya DEXes za mtindo wa Uniswap v4 ambazo zinaongeza hisabati ya msingi kwa hooks maalum. Tukio la hivi karibuni kwenye Bunni V2 lilitumia hitilafu ya rounding/usahihi kwenye Liquidity Distribution Function (LDF) iliyotekelezwa kila swap, ikimruhusu mshambuliaji kupata credits chanya na kuondoa liquidity.

Wazo kuu: ikiwa hook inatekeleza uhasibu wa ziada unaotegemea math ya fixed‑point, tick rounding, na mantiki ya thresholds, mshambuliaji anaweza kuunda exact‑input swaps ambazo zinavuka thresholds maalum ili utofauti wa rounding ukusanyike kwa faida yao. Kurudia muundo huo kisha kutoa salio lililofanywa upya hurealisha faida, mara nyingi kwa kufadhiliwa na flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks ni mikataba ambayo PoolManager inaita kwa point maalum za lifecycle (mfano, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Pools zinaanzishwa na PoolKey ikijumuisha hooks address. Ikiwa sio zero, PoolManager hufanya callbacks kwenye kila operation inayofaa.
- Hisabati ya msingi inatumia formats za fixed‑point kama Q64.96 kwa sqrtPriceX96 na tick arithmetic kwa 1.0001^tick. Math yoyote maalum iliyowekwa juu ya hayo lazima iendane kwa uangalifu na semantics za rounding ili kuepuka invariant drift.
- Swaps zinaweza kuwa exactInput au exactOutput. Katika v3/v4, bei inasogea pamoja na ticks; kuvuka boundary ya tick kunaweza kuwasha/deactivate range liquidity. Hooks zinaweza kutekeleza mantiki ya ziada kwenye threshold/tick crossings.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Mfano wa kawaida wa kuwa hatarini kwenye hooks maalum:

1. Hook inahesabu per‑swap liquidity au balance deltas kwa kutumia integer division, mulDiv, au conversions za fixed‑point (mfano, token ↔ liquidity kwa kutumia sqrtPrice na tick ranges).
2. Mantiki ya threshold (mfano, rebalancing, stepwise redistribution, au per‑range activation) inaamshwa wakati swap size au price movement inapovuka boundary ya ndani.
3. Rounding inatumiwa kwa njia isiyoendana (mfano, truncation kuelekea sifuri, floor dhidi ya ceil) kati ya hesapisho la mbele na njia ya settlement. Tofauti ndogo hazibatiliani na badala yake zinamcredit caller.
4. Exact‑input swaps, zilizo sizing kwa usahihi ili kutengeneza straddle ya boundaries hizo, zinasaga remainder chanya wa rounding mara kwa mara. Mshambuliaji baadaye hutoa credit iliyokusanywa.

Masharti ya kushambuliwa
- Pool inayotumia v4 hook maalum ambayo inafanya hisabati ya ziada kwa kila swap (mfano, LDF/rebalancer).
- Angalau njia moja ya utekelezwaji ambapo rounding inamnufaisha swap initiator wakati wa threshold crossings.
- Uwezo wa kurudia swaps nyingi atomically (flash loans ni bora kutoa float ya muda na kugawanya gharama za gas).

## Practical attack methodology

1) Tambua pools zinazowezekana zenye hooks
- Enumarate v4 pools na angalia PoolKey.hooks != address(0).
- Inspekta hook bytecode/ABI kwa callbacks: beforeSwap/afterSwap na njia zozote za rebalancing maalum.
- Tafuta hisabati inayofanya: kugawanya kwa liquidity, kubadilisha kati ya token amounts na liquidity, au kujumlisha BalanceDelta kwa rounding.

2) Modeli hisabati na thresholds za hook
- Recreate formula ya liquidity/redistribution ya hook: input kawaida ni sqrtPriceX96, tickLower/Upper, currentTick, fee tier, na net liquidity.
- Ramani functions za threshold/step: ticks, mipaka ya buckets, au LDF breakpoints. Tambua upande gani wa kila boundary delta inarounded.
- Tambua ambapo conversions zinaweka kati ya uint256/int256, kutumia SafeCast, au kutegemea mulDiv na implicit floor.

3) Calibrate exact‑input swaps ili kuvuka boundaries
- Tumia Foundry/Hardhat simulations kuhesabu Δin ndogo kabisa inayohitajika kusogeza price kidogo kuvuka boundary na kuamsha branch ya hook.
- Thibitisha kuwa afterSwap settlement inamcredit caller zaidi ya gharama, ikiacha BalanceDelta chanya au credit katika uhasibu wa hook.
- Rudia swaps ili kukusanya credit; kisha ita call njia ya hook ya withdrawal/settlement.

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
Kusawazisha exactInput
- Hesabu ΔsqrtP kwa hatua ya tick: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Kadiria Δin ukitumia fomula za v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Hakikisha mwelekeo wa rounding unalingana na hisabati ya msingi.
- Rekebisha Δin kwa ±1 wei karibu na boundary ili kupata branch ambapo hook inazungusha kwa faida yako.

4) Kuongeza kwa flash loans
- Kopa notional kubwa (mfano: 3M USDT au 2000 WETH) ili kuendesha iteresheni nyingi kwa atomiki.
- Endesha loop ya swap iliyokalibrwa, kisha toa na lipa ndani ya flash loan callback.

Muundo wa flash loan wa Aave V3
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
5) Kutoka na kuiga kwa mnyororo tofauti
- Ikiwa hooks zimewekwa kwenye mnyororo mbalimbali, rudia kalibrishaji sawa kwa kila mnyororo.
- Bridge hurudisha mapato kwenye mnyororo lengwa na kwa hiari inaweza kuzunguka kupitia lending protocols ili kuficha mtiririko.

## Sababu za msingi za kawaida katika hisabati ya hook

- Semantiki mchanganyiko za rounding: mulDiv hufloor wakati njia za baadaye kwa ufanisi hufanya round up; au uongofu kati ya token/liquidity unatumia rounding tofauti.
- Makosa ya upatanisho wa tick: kutumia ticks zisizozungushwa katika njia moja na tick‑spaced rounding katika nyingine.
- Masuala ya ishara/overflow ya BalanceDelta wakati wa kubadilisha kati ya int256 na uint256 wakati wa settlement.
- Kupoteza usahihi katika uongofu wa Q64.96 (sqrtPriceX96) ambayo haijaonyeshwa katika reverse mapping.
- Njia za kuongezeka: mabaki ya kila swap yanayofuatiliwa kama credits yanayoweza kutolewa na mwito badala ya kuchomwa/zero‑sum.

## Mwongozo wa kujilinda

- Differential testing: kuiga hisabati ya hook dhidi ya utekelezaji wa rejea kwa kutumia arithmetic ya rational yenye usahihi mkubwa na kuthibitisha usawa au kosa lililofungwa ambalo daima ni la kushambulia (sio kamwe lenye faida kwa mwito).
- Invariant/property tests:
  - Jumla ya deltas (tokens, liquidity) katika njia za swap na marekebisho ya hook lazima izihifadhi thamani modulo fees.
  - Hakuna njia inapaswa kuunda mkopo safi chanya kwa mianzishaji wa swap katika mizunguko iliyorudiwa ya exactInput.
  - Majaribio ya mipaka ya threshold/tick karibu na ingizo za ±1 wei kwa exactInput/exactOutput.
  - Sera za rounding: kuunganisha helpers za rounding ambazo kila mara huzungusha dhidi ya mtumiaji; ondoa casts zisizoendana na implicit floors.
  - Settlement sinks: kusanya mabaki ya rounding yasiyoweza kuepukika kwa hazina ya protocol au kuyachoma; kamwe usiyachukue kama msg.sender.
  - Rate‑limits/guardrails: ukubwa wa chini wa swap kwa triggers za rebalancing; zima rebalances ikiwa deltas ni sub‑wei; angalia akili deltas dhidi ya anuwai zilizotarajiwa.
  - Kagua callbacks za hook kwa ujumla: beforeSwap/afterSwap na before/after mabadiliko ya liquidity zinapaswa kukubaliana kuhusu upatanisho wa tick na rounding ya delta.

## Masomo ya kesi: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) na LDF iliyoanzishwa kwa kila swap ili kurebalance.
- Sababu ya msingi: kosa la rounding/usahihi katika uhasibu wa liquidity wa LDF wakati wa swaps zinazoipitisha threshold; tofauti za kila swap zilikusanywa kama credits chanya kwa mwito.
- Ethereum leg: mshambuliaji alichukua flash loan ya ~3M USDT, alifanya swaps za calibrated exact‑input kwenye USDC/USDT kujenga credits, alitoa salio lililopanuliwa, alirudisha deni, na alipanga fedha kupitia Aave.
- UniChain leg: walirudia exploit kwa flash loan ya 2000 WETH, wakivuta ~1366 WETH na kuibandika/bridge kwenda Ethereum.
- Athari: takriban USD 8.3M zilivutwa katika mnyororo mbalimbali. Hakuna mwingiliano wa mtumiaji uliohitajika; yote yalifanyika on‑chain.

## Orodha ya ukaguzi

- Je, pool inatumia anwani ya hooks isiyo sifuri? Ni callbacks gani zimewezeshwa?
- Je kuna redistributions/rebalances za kila swap zinotumia hisabati maalum? Kuna mantiki ya tick/threshold?
- Divisions/mulDiv, Q64.96 conversions, au SafeCast zimetumika wapi? Je semantiki za rounding ni zinazoendana kimataifa?
- Je unaweza kuunda Δin inayopita mpaka kwa ncha na kutoa tawi la rounding lenye faida? Jaribu pande zote na exactInput na exactOutput.
- Je hook inafuata credits au deltas kwa kila mwito ambazo zinaweza kutolewa baadaye? Hakikisha mabaki yananuletraliza.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
