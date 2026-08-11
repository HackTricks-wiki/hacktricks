# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza aina ya mbinu za DeFi/AMM exploitation dhidi ya DEX za mtindo wa Uniswap v4 zinazopanua core math kwa kutumia custom hooks. Tukio la Bunni V2 linaonyesha failure inayohusiana: bug ya rounding-direction katika withdrawal accounting ilipunguza kwa makadirio active liquidity, na swap iliyofuata ilifichua upunguzaji huo katika sandwich yenye faida.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Wazo kuu: ikiwa hook itatekeleza accounting ya ziada inayotegemea fixed-point math, tick rounding, na threshold logic, attacker anaweza kuunda exact-input swaps zinazovuka thresholds maalum ili tofauti za rounding zijikusanye kwa manufaa yake. Kwa kurudia pattern hiyo na kisha kutoa balance iliyoongezwa, attacker hupata faida, mara nyingi kwa ufadhili wa flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks ni contracts ambazo PoolManager huziita katika lifecycle points maalum (kwa mfano, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools huanzishwa kwa PoolKey inayojumuisha hook contract. Hook address isiyo-zero huwezesha callbacks zilizochaguliwa kwa pool hiyo.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks zinaweza kurudisha **custom deltas** zinazobadilisha final balance changes za swap au liquidity action (custom accounting). Deltas hizo husawazishwa kama net balances mwishoni mwa call, hivyo error yoyote ya rounding ndani ya hook hujikusanya kabla ya settlement.<sup>[[4]](#references)</sup>
- Core math hutumia fixed-point formats kama Q64.96 kwa sqrtPriceX96 na tick arithmetic yenye 1.0001^tick. Custom math yoyote iliyowekwa juu yake lazima ilingane kwa uangalifu na rounding semantics ili kuzuia invariant drift.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps zinaweza kuwa exactInput au exactOutput. Katika v3/v4, bei husogea kwenye ticks; kuvuka tick boundary kunaweza ku-activate/deactivate range liquidity. Hooks zinaweza kutekeleza logic ya ziada wakati wa threshold/tick crossings.<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Pattern ya kawaida iliyo vulnerable katika custom hooks:

1. Hook huhesabu per-swap liquidity au balance deltas kwa kutumia integer division, mulDiv, au fixed-point conversions (kwa mfano, token ↔ liquidity kwa kutumia sqrtPrice na tick ranges).
2. Threshold logic (kwa mfano, rebalancing, stepwise redistribution, au per-range activation) huanzishwa wakati swap size au price movement inapovuka internal boundary.
3. Rounding hutumika bila consistency (kwa mfano, truncation kuelekea sifuri, floor badala ya ceil) kati ya forward calculation na settlement path. Tofauti ndogo hazighairiani, bali hum-credit caller.
4. Exact-input swaps, zikiwa zimepimwa kwa usahihi wa kuvuka boundaries hizo, huvuna positive rounding remainder mara kwa mara. Baadaye attacker hutoa credit iliyokusanywa.

Attack preconditions
- Pool inayotumia custom v4 hook inayotekeleza math ya ziada kwenye kila swap (kwa mfano, LDF/rebalancer).
- Angalau execution path moja ambapo rounding humfaidi swap initiator wakati wa threshold crossings.
- Uwezo wa kurudia swaps nyingi atomically (flash loans ni bora kwa kutoa temporary float na kusambaza gharama ya gas).

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumerate v4 pools na uangalie PoolKey.hooks != address(0).
- Kagua hook bytecode/ABI kwa callbacks: beforeSwap/afterSwap na custom rebalancing methods zozote.
- Tafuta math inayofanya yafuatayo: kugawanya kwa liquidity, kubadilisha kati ya token amounts na liquidity, au kujumlisha BalanceDelta kwa kutumia rounding.

2) Model the hook’s math and thresholds
- Tengeneza upya formula ya hook ya liquidity/redistribution: inputs kwa kawaida hujumuisha sqrtPriceX96, tickLower/Upper, currentTick, fee tier, na net liquidity.
- Chora threshold/step functions: ticks, bucket boundaries, au LDF breakpoints. Tambua ni upande gani wa kila boundary delta inazungushwa.
- Tambua mahali conversions zinapocast kati ya uint256/int256, zinapotumia SafeCast, au zinapotegemea mulDiv yenye implicit floor.

3) Calibrate exact‑input swaps to cross boundaries
- Tumia Foundry/Hardhat simulations kukokotoa Δin ndogo zaidi inayohitajika kusogeza bei kuvuka boundary kidogo na ku-trigger branch ya hook.
- Thibitisha kuwa afterSwap settlement inampa caller zaidi ya gharama, na kuacha positive BalanceDelta au credit katika hook’s accounting.
- Rudia swaps ili kukusanya credit; kisha ita hook’s withdrawal/settlement path.

Katika v4, swap loop lazima iendeshwe kutoka PoolManager unlock callback; negative `amountSpecified` huashiria exact input, na `sqrtPriceLimitX96` lazima iwe ndani kabisa ya valid range. Price limit ya sifuri husababisha revert, hivyo pseudocode iliyo hapa chini hutumia lower bound kwa swap ya zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Example Foundry‑style test harness (pseudocode)
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
Calibrating the exactInput
- Kokotoa lengo kwa kutumia core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) kwa thamani halisi; matokeo ya Q64.96 huzungushwa na TickMath.<sup>[[13]](#references)</sup>
- Kadiria ingizo la token0 (zero-for-one) kwa kutumia fomula inayozingatia Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Linganisha mzunguko wa core na rounding unaoelekezwa kwa mwelekeo husika.<sup>[[12]](#references)</sup>
- Rekebisha Δin kwa ±1 wei kuzunguka mpaka wa mpaka ili kupata tawi ambalo hook huzungusha kwa manufaa yako.

4) Amplify with flash loans
- Kopa notional kubwa (kwa mfano, 3M USDT au 2000 WETH) ili kutekeleza marudio mengi kwa atomiki.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Tekeleza kitanzi cha swap kilichosawazishwa, kisha toa na ulipie ndani ya flash loan callback.

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
5) Kuondoka na replication ya cross-chain
- Ikiwa hooks zimetumwa kwenye chains nyingi, rudia calibration hiyo hiyo kwa kila chain.
- Katika tukio la Bunni, flash-loan liquidity na bridge routes zilitofautiana kwa kila chain, hivyo zingatia vikwazo maalum vya kila chain unapotoa tena uchanganuzi.<sup>[[1]](#references)[[2]](#references)</sup>

## Sababu za kawaida za msingi katika hook math

- Mixed rounding semantics: mulDiv hufanya floor, huku paths zinazofuata zikifanya effectively round up; au conversions kati ya token/liquidity zikitumia rounding tofauti.
- Tick alignment errors: kutumia ticks ambazo hazijarounded katika path moja na tick-spaced rounding katika nyingine.
- Masuala ya BalanceDelta sign/overflow wakati wa kubadilisha kati ya int256 na uint256 wakati wa settlement.
- Kupotea kwa precision katika conversions za Q64.96 (sqrtPriceX96) ambazo hazijaakisiwa katika reverse mapping.
- Accumulation pathways: per-swap remainders kufuatiliwa kama credits zinazoweza kutolewa na caller badala ya kuchomwa/kufanya zero-sum.

## Custom accounting & delta amplification

- Uniswap v4 custom accounting huruhusu hooks kurudisha deltas zinazorekebisha moja kwa moja kiasi ambacho caller anadaiwa/anachopokea. Ikiwa hook inafuatilia credits internally, rounding residue inaweza kujikusanya katika operations nyingi ndogo **kabla** ya final settlement kufanyika.<sup>[[4]](#references)</sup>
- Ikiwa hook inafichua withdrawal path inayooana, attacker anaweza kubadilisha `swap → withdraw → swap` ndani ya PoolManager unlock callback ile ile, na kuilazimisha hook ihesabu tena deltas kwenye state iliyotofautiana kidogo huku balances zikiendelea kuwa pending hadi unlock itakapofanya settlement.<sup>[[4]](#references)[[10]](#references)</sup>
- Wakati wa kukagua hooks, fuatilia kila mara jinsi BalanceDelta/HookDelta inavyotengenezwa na kufanyiwa settlement. Rounding yenye upendeleo katika branch moja inaweza kuwa credit inayojilimbikiza wakati deltas zinapohesabiwa tena mara kwa mara.

## Mwongozo wa kujilinda

- Differential testing: linganisha math ya hook na reference implementation inayotumia high-precision rational arithmetic, kisha assert equality au bounded error ambayo daima ni adversarial (kamwe isinufaishie caller).
- Invariant/property tests:
- Jumla ya deltas (tokens, liquidity) katika swap paths na hook adjustments lazima ihifadhi value isipokuwa fees.
- Hakuna path inayopaswa kuunda positive net credit kwa swap initiator wakati wa exactInput iterations zinazorudiwa.
- Threshold/tick boundary tests karibu na inputs za ±1 wei kwa exactInput/exactOutput zote.
- Rounding policy: centralize rounding helpers zinazofanya rounding dhidi ya user kila mara; ondoa casts zisizolingana na implicit floors.
- Settlement sinks: kusanya rounding residue isiyoweza kuepukika kwenye protocol treasury au ichome; kamwe usiiattribue kwa msg.sender.
- Rate-limits/guardrails: minimum swap sizes kwa rebalancing triggers; zima rebalances ikiwa deltas ziko chini ya wei; fanya sanity-check ya deltas dhidi ya expected ranges.
- Kagua hook callbacks kwa ujumla: beforeSwap/afterSwap na before/after liquidity changes zinapaswa kukubaliana kuhusu tick alignment na delta rounding.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2, Uniswap v4 hook inayotumia Liquidity Density Function (LDF) kukokotoa token density na makadirio ya total-liquidity.<sup>[[1]](#references)[[2]](#references)</sup>
- Pools zilizoathirika: USDC/USDT kwenye Ethereum na weETH/ETH kwenye Unichain, zenye jumla ya takriban $8.4M.<sup>[[1]](#references)</sup>
- Hatua ya 1 (price push): attacker alikopa takriban 3M USDT kupitia flash-borrow na kufanya swap ili kusukuma tick hadi takriban 5000, na kupunguza **active** USDC balance hadi takriban wei 28.<sup>[[1]](#references)</sup>
- Hatua ya 2 (rounding drain): withdrawals 44 ndogo zilitumia floor rounding katika `BunniHubLogic::withdraw()` ili kupunguza active USDC balance kutoka wei 28 hadi wei 4 (-85.7%), huku sehemu ndogo tu ya LP shares ikichomwa. Total liquidity ilipungua kwa takriban 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Hatua ya 3 (liquidity rebound sandwich): swap kubwa ilisogeza tick hadi takriban 839,189 (1 USDC ≈ 2.77e36 USDT). Makadirio ya liquidity yalibadilika na kuongezeka kwa takriban 16.8%, na kuwezesha sandwich ambapo attacker alifanya swap ya kurudi kwa bei iliyopandishwa na kuondoka na faida.<sup>[[1]](#references)</sup>
- Fix iliyotambuliwa katika post-mortem: badilisha idle-balance update ili iround **up**, hivyo micro-withdrawals zinazorudiwa zisiweze tena kupunguza active balance ya pool hatua kwa hatua.<sup>[[1]](#references)</sup>

Simplified vulnerable line (and post‑mortem fix).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Orodha ya ukaguzi wa Hunting

- Je, pool inatumia anwani ya hooks isiyo sifuri? Ni callbacks zipi zimewezeshwa?
- Je, kuna ugawaji upya/rebalance kwa kila swap unaotumia custom math? Kuna mantiki yoyote ya tick/threshold?
- Divisions, mulDiv, ubadilishaji wa Q64.96, au SafeCast zinatumika wapi? Je, semantics za rounding zinalingana kote?
- Je, unaweza kuunda Δin inayovuka boundary kwa kiasi kidogo na kutoa rounding branch yenye faida? Jaribu pande zote mbili na exactInput pamoja na exactOutput.
- Je, hook inafuatilia credits au deltas za kila caller zinazoweza kutolewa baadaye? Hakikisha residue inabadilishwa kuwa sifuri.

## References

- [1] [Ripoti ya Baada ya Tukio la Bunni Exploit (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: Uchambuzi Kamili wa Hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M Zilitolewa kupitia Kasoro ya Liquidity (muhtasari)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper ya Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Usuli wa Uniswap v4 (utafiti wa QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mekanika za Liquidity katika Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mekanika za Swap katika Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks za Uniswap v4 na Mazingatio ya Usalama](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol ya Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol ya Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams ya Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol ya Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol ya Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey ya Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
