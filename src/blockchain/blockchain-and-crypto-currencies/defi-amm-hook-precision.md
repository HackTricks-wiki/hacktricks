# Exploitation ya DeFi/AMM: Uniswap v4 Hook Precision/Rounding Abuse

Ukurasa huu unaandika kuhusu aina ya mbinu za exploitation za DeFi/AMM dhidi ya DEX za mtindo wa Uniswap v4 zinazopanua core math kwa custom hooks. Tukio la Bunni V2 linaonyesha failure inayohusiana: bug ya rounding-direction katika withdrawal accounting ilikadiria chini active liquidity, na swap iliyofuata ilifichua ukadiriaji huo mdogo kupitia sandwich yenye faida.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Wazo kuu: ikiwa hook itatekeleza accounting ya ziada inayotegemea fixed-point math, tick rounding, na threshold logic, attacker anaweza kutengeneza exact-input swaps zinazovuka thresholds maalum ili tofauti za rounding zijikusanye kwa manufaa yake. Kurudia pattern hiyo na kisha kutoa inflated balance kunatengeneza profit, mara nyingi ikifadhiliwa kwa flash loan.

## Background: Uniswap v4 hooks na swap flow

- Hooks ni contracts ambazo PoolManager haziita katika lifecycle points maalum (kwa mfano, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools huanzishwa kwa PoolKey inayojumuisha hook contract. Hook address isiyo-zero huwezesha callbacks zilizochaguliwa kwa pool hiyo.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks zinaweza kurejesha **custom deltas** zinazobadilisha final balance changes za swap au liquidity action (custom accounting). Deltas hizo husettle kama net balances mwishoni mwa call, hivyo rounding error yoyote ndani ya hook math hujikusanya kabla ya settlement.<sup>[[4]](#references)</sup>
- Core math hutumia fixed-point formats kama Q64.96 kwa sqrtPriceX96 na tick arithmetic yenye 1.0001^tick. Custom math yoyote iliyowekwa juu yake lazima ilinganishe kwa uangalifu rounding semantics ili kuzuia invariant drift.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps zinaweza kuwa exactInput au exactOutput. Katika v3/v4, price husogea kupitia ticks; kuvuka tick boundary kunaweza ku-activate/deactivate range liquidity. Hooks zinaweza kutekeleza logic ya ziada wakati wa threshold/tick crossings.<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold-crossing precision/rounding drift

Pattern ya kawaida yenye vulnerability katika custom hooks:

1. Hook hukokotoa per-swap liquidity au balance deltas kwa kutumia integer division, mulDiv, au fixed-point conversions (kwa mfano, token ↔ liquidity kwa kutumia sqrtPrice na tick ranges).
2. Threshold logic (kwa mfano, rebalancing, stepwise redistribution, au per-range activation) huanzishwa wakati swap size au price movement inapovuka internal boundary.
3. Rounding hutumika bila consistency (kwa mfano, truncation kuelekea sifuri, floor badala ya ceil) kati ya forward calculation na settlement path. Tofauti ndogo hazifutani, bali humcredit caller.
4. Exact-input swaps, zilizopimwa kwa usahihi ili kuvuka boundaries hizo, huvuna positive rounding remainder mara kwa mara. Baadaye attacker hutoa accumulated credit.

Attack preconditions
- Pool inayotumia custom v4 hook inayotekeleza math ya ziada kwenye kila swap (kwa mfano, LDF/rebalancer).
- Angalau execution path moja ambapo rounding humfaidi swap initiator wakati wa threshold crossings.
- Uwezo wa kurudia swaps nyingi atomically (flash loans ni bora kwa kutoa temporary float na kugawanya gas cost).

## Practical attack methodology

1) Tambua pools zenye hooks
- Enumerate v4 pools na uangalie kama PoolKey.hooks != address(0).
- Kagua hook bytecode/ABI kwa callbacks: beforeSwap/afterSwap na custom rebalancing methods zozote.
- Tafuta math ambayo: hugawanya kwa liquidity, hubadilisha kati ya token amounts na liquidity, au huaggregates BalanceDelta kwa rounding.

2) Model hook math na thresholds zake
- Recreate formula ya hook ya liquidity/redistribution: inputs kwa kawaida hujumuisha sqrtPriceX96, tickLower/Upper, currentTick, fee tier, na net liquidity.
- Map threshold/step functions: ticks, bucket boundaries, au LDF breakpoints. Tambua upande ambao delta inarounded kwenye kila boundary.
- Tambua mahali conversions zinapocast kati ya uint256/int256, zinapotumia SafeCast, au zinapotegea mulDiv yenye implicit floor.

3) Calibrate exact-input swaps ili kuvuka boundaries
- Tumia Foundry/Hardhat simulations kukokotoa Δin ndogo zaidi inayohitajika kusogeza price ivuke boundary kidogo na ku-trigger branch ya hook.
- Thibitisha kwamba afterSwap settlement humcredit caller zaidi ya cost, na kuacha positive BalanceDelta au credit katika hook’s accounting.
- Rudia swaps ili kukusanya credit; kisha ita hook’s withdrawal/settlement path.

Katika v4, swap loop lazima iendeshwe kutoka PoolManager unlock callback; `amountSpecified` yenye thamani hasi huashiria exact input, na `sqrtPriceLimitX96` lazima iwe strictly ndani ya valid range. Price limit ya sifuri hurevert, kwa hiyo pseudocode iliyo hapa chini hutumia lower bound kwa swap ya zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Example Foundry-style test harness (pseudocode)
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
Kukalibisha exactInput
- Kokotoa lengwa kwa kutumia core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) kwa thamani halisi; matokeo ya Q64.96 huzungushwa na TickMath.<sup>[[13]](#references)</sup>
- Kadiria ingizo la token0 (zero-for-one) kwa kutumia fomula inayozingatia Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Linganisha mzunguko wa core wa rounding unaotegemea mwelekeo.<sup>[[12]](#references)</sup>
- Rekebisha Δin kwa ±1 wei kuzunguka mpaka wa mpito ili kupata branch ambapo hook inazungusha kwa faida yako.

4) Kuongeza kwa kutumia flash loans
- Kopa notional kubwa (k.m., 3M USDT au 2000 WETH) ili kutekeleza iterations nyingi atomically.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Tekeleza swap loop iliyokalibishwa, kisha toa na ulipe ndani ya flash loan callback.

Muundo wa msingi wa Aave V3 flash loan
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
5) Exit na cross-chain replication
- Ikiwa hooks zimetumwa kwenye chains nyingi, rudia calibration ileile kwa kila chain.
- Katika tukio la Bunni, flash-loan liquidity na bridge routes zilitofautiana kulingana na chain, kwa hiyo zingatia vikwazo maalum vya kila chain unapozalisha upya analysis.<sup>[[1]](#references)[[2]](#references)</sup>

## Sababu kuu za kawaida katika hook math

- Mixed rounding semantics: mulDiv hukata sehemu ya desimali huku paths zinazofuata zikifanya kazi kana kwamba zina-round up; au conversions kati ya token/liquidity hutumia rounding tofauti.
- Makosa ya tick alignment: kutumia ticks ambazo hazija-round katika path moja na tick-spaced rounding katika nyingine.
- Matatizo ya BalanceDelta sign/overflow wakati wa kubadilisha kati ya int256 na uint256 wakati wa settlement.
- Kupotea kwa precision katika conversions za Q64.96 (sqrtPriceX96) ambako hakujarudiwa katika reverse mapping.
- Accumulation pathways: remainders za kila swap kufuatiliwa kama credits zinazoweza kutolewa na caller badala ya kuchomwa/kusawazishwa kuwa zero-sum.

## Custom accounting & delta amplification

- Uniswap v4 custom accounting huruhusu hooks kurudisha deltas zinazorekebisha moja kwa moja kile ambacho caller anadaiwa/kupokea. Ikiwa hook inafuatilia credits internally, rounding residue inaweza kujikusanya katika operations nyingi ndogo **kabla** ya final settlement kufanyika.<sup>[[4]](#references)</sup>
- Ikiwa hook inafichua withdrawal path inayooana, attacker anaweza kubadilisha `swap → withdraw → swap` ndani ya PoolManager unlock callback ileile, na kulazimisha hook ihesabu upya deltas katika state iliyotofautiana kidogo huku balances zikiwa bado pending hadi unlock itakapokamilisha settlement.<sup>[[4]](#references)[[10]](#references)</sup>
- Unapokagua hooks, fuatilia kila wakati jinsi BalanceDelta/HookDelta inavyotengenezwa na kusettled. Rounding moja yenye upendeleo katika branch moja inaweza kuwa credit inayoongezeka kila mara wakati deltas zinapohesabiwa upya mara kwa mara.

## Mwongozo wa ulinzi

- Differential testing: linganisha math ya hook na reference implementation kwa kutumia high-precision rational arithmetic, kisha thibitisha equality au bounded error ambayo daima ni adversarial (kamwe isimpendelee caller).
- Invariant/property tests:
- Jumla ya deltas (tokens, liquidity) katika swap paths na hook adjustments lazima ihifadhi value isipokuwa fees.
- Hakuna path inayopaswa kuunda positive net credit kwa swap initiator katika exactInput iterations zinazorudiwa.
- Threshold/tick boundary tests karibu na inputs za ±1 wei kwa exactInput/exactOutput zote mbili.
- Rounding policy: centralize rounding helpers ambazo daima zina-round dhidi ya user; ondoa casts zisizolingana na implicit floors.
- Settlement sinks: kusanya rounding residue isiyoweza kuepukika kwenye protocol treasury au ichome; kamwe usiihusishe na msg.sender.
- Rate-limits/guardrails: minimum swap sizes kwa rebalancing triggers; zima rebalances ikiwa deltas ni sub-wei; fanya sanity-check ya deltas dhidi ya expected ranges.
- Kagua hook callbacks kwa ujumla: beforeSwap/afterSwap na mabadiliko ya liquidity ya before/after yanapaswa kukubaliana kuhusu tick alignment na delta rounding.

## Case study: Bunni V2 (2025-09-02)

- Protocol: Bunni V2, Uniswap v4 hook inayotumia Liquidity Density Function (LDF) kukokotoa token density na makadirio ya total-liquidity.<sup>[[1]](#references)[[2]](#references)</sup>
- Pools zilizoathirika: USDC/USDT kwenye Ethereum na weETH/ETH kwenye Unichain, zikiwa na jumla ya takriban $8.4M.<sup>[[1]](#references)</sup>
- Hatua ya 1 (price push): attacker alikopa kwa flash-loan takriban 3M USDT na kufanya swap ili kusukuma tick hadi takriban 5000, na kupunguza **active** USDC balance hadi takriban 28 wei.<sup>[[1]](#references)</sup>
- Hatua ya 2 (rounding drain): withdrawals 44 ndogo zilitumia floor rounding katika `BunniHubLogic::withdraw()` kupunguza active USDC balance kutoka 28 wei hadi 4 wei (-85.7%), huku ni sehemu ndogo sana ya LP shares ikichomwa. Total liquidity ilipungua kwa takriban 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Hatua ya 3 (liquidity rebound sandwich): swap kubwa ilisogeza tick hadi takriban 839,189 (1 USDC ≈ 2.77e36 USDT). Makadirio ya liquidity yalibadilika na kuongezeka kwa takriban 16.8%, na kuwezesha sandwich ambapo attacker alifanya swap ya kurudi kwa bei iliyopandishwa na kutoka akiwa na profit.<sup>[[1]](#references)</sup>
- Fix iliyobainishwa katika post-mortem: badilisha idle-balance update ili i-round **up**, kwa hiyo micro-withdrawals zinazorudiwa hazitaendelea kupunguza active balance ya pool.<sup>[[1]](#references)</sup>

Mstari uliorahisishwa ulio katika hali ya vulnerability (na post-mortem fix).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Orodha ya ukaguzi wa Hunting

- Je, pool inatumia hooks address isiyo sifuri? Ni callbacks zipi zimewezeshwa?
- Je, kuna redistributions/rebalances za kila swap zinazotumia custom math? Kuna mantiki yoyote ya tick/threshold?
- Divisions/mulDiv, ubadilishaji wa Q64.96, au SafeCast zinatumika wapi? Je, rounding semantics zina ulinganifu kote?
- Je, unaweza kuunda Δin inayovuka boundary kwa kiasi kidogo na kutoa rounding branch yenye faida? Jaribu pande zote mbili na exactInput pamoja na exactOutput.
- Je, hook inafuatilia credits au deltas za kila caller ambazo zinaweza kutolewa baadaye? Hakikisha residue inafutwa.

## References

- [1] [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (muhtasari)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
