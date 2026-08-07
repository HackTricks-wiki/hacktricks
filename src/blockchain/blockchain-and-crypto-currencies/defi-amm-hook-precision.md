# Unyonyaji wa DeFi/AMM: Unyonyaji wa Usahihi wa Hook/Rounding katika Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza aina ya mbinu za unyonyaji wa DeFi/AMM dhidi ya DEX za mtindo wa Uniswap v4 zinazopanua hesabu msingi kwa kutumia custom hooks. Tukio la hivi karibuni katika Bunni V2 lilitumia hitilafu ya rounding/precision katika Liquidity Distribution Function (LDF) iliyotekelezwa kwenye kila swap, na kumwezesha mshambuliaji kukusanya credits chanya na kutoa liquidity.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

Wazo kuu: ikiwa hook itatekeleza accounting ya ziada inayotegemea fixed-point math, tick rounding, na threshold logic, mshambuliaji anaweza kuunda exact-input swaps zinazovuka thresholds maalum ili tofauti za rounding zikusanyike kwa faida yake. Kwa kurudia muundo huo na kisha kutoa balance iliyoongezwa, mshambuliaji hutengeneza faida, mara nyingi akifadhili operesheni hiyo kwa flash loan.

## Msingi: Uniswap v4 hooks na mtiririko wa swap

- Hooks ni contracts ambazo PoolManager huita katika pointi maalum za lifecycle (kwa mfano, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[3]](#references)[[6]](#references)</sup>
- Pools huanzishwa kwa PoolKey inayojumuisha hooks address. Ikiwa si zero, PoolManager hutekeleza callbacks kwenye kila operation husika.<sup>[[6]](#references)</sup>
- Hooks zinaweza kurudisha **custom deltas** zinazobadilisha mabadiliko ya mwisho ya balance ya swap au liquidity action (custom accounting). Deltas hizo husettle kama net balances mwishoni mwa call, hivyo error yoyote ya rounding ndani ya hook hujilimbikiza kabla ya settlement.<sup>[[5]](#references)</sup>
- Core math hutumia fixed-point formats kama Q64.96 kwa sqrtPriceX96 na tick arithmetic yenye 1.0001^tick. Hesabu yoyote custom iliyowekwa juu yake lazima ilingane kwa uangalifu na rounding semantics ili kuzuia invariant drift.<sup>[[4]](#references)[[8]](#references)</sup>
- Swaps zinaweza kuwa exactInput au exactOutput. Katika v3/v4, bei husogea kwenye ticks; kuvuka tick boundary kunaweza kuamilisha/kuzima range liquidity. Hooks zinaweza kutekeleza logic ya ziada wakati wa threshold/tick crossings.<sup>[[5]](#references)</sup>

## Aina ya udhaifu: threshold-crossing precision/rounding drift

Muundo wa kawaida ulio hatarini katika custom hooks:

1. Hook hukokotoa liquidity au balance deltas za kila swap kwa kutumia integer division, mulDiv, au fixed-point conversions (kwa mfano, token ↔ liquidity kwa kutumia sqrtPrice na tick ranges).
2. Threshold logic (kwa mfano, rebalancing, stepwise redistribution, au per-range activation) huanzishwa wakati ukubwa wa swap au price movement unapovuka boundary ya ndani.
3. Rounding hutumiwa bila ulinganifu (kwa mfano, truncation kuelekea zero, floor dhidi ya ceil) kati ya forward calculation na settlement path. Tofauti ndogo hazifutani, bali humcredit caller.
4. Exact-input swaps zilizowekwa kwa usahihi ili kuvuka boundaries hizo huvuna mara kwa mara positive rounding remainder. Baadaye mshambuliaji hutoa credit iliyokusanywa.

Masharti ya shambulio
- Pool inayotumia custom v4 hook inayofanya hesabu za ziada kwenye kila swap (kwa mfano, LDF/rebalancer).
- Angalau execution path moja ambapo rounding humfaidi swap initiator wakati wa threshold crossings.
- Uwezo wa kurudia swaps nyingi atomically (flash loans ni bora kwa kutoa float ya muda na kugawanya gharama ya gas).

## Mbinu ya vitendo ya shambulio

1) Tambua pools zinazoweza kuwa na hooks
- Orodhesha v4 pools na ukague PoolKey.hooks != address(0).
- Kagua hook bytecode/ABI kwa callbacks: beforeSwap/afterSwap na methods zozote custom za rebalancing.
- Tafuta math inayofanya yafuatayo: kugawanya kwa liquidity, kubadilisha kati ya token amounts na liquidity, au kujumlisha BalanceDelta kwa rounding.

2) Model hook math na thresholds zake
- Unda upya formula ya hook ya liquidity/redistribution: inputs kwa kawaida hujumuisha sqrtPriceX96, tickLower/Upper, currentTick, fee tier, na net liquidity.
- Chora threshold/step functions: ticks, bucket boundaries, au LDF breakpoints. Bainisha upande ambao delta inarounded kwenye kila boundary.
- Tambua mahali ambapo conversions hubadilisha kati ya uint256/int256, hutumia SafeCast, au hutegemea mulDiv yenye implicit floor.

3) Calibrate exact-input swaps ili kuvuka boundaries
- Tumia Foundry/Hardhat simulations kukokotoa Δin ya chini kabisa inayohitajika kusogeza bei ivuke boundary kidogo na kuanzisha branch ya hook.
- Thibitisha kwamba afterSwap settlement inamcredit caller zaidi ya gharama, na kuacha positive BalanceDelta au credit katika accounting ya hook.
- Rudia swaps ili kukusanya credit; kisha ita hook’s withdrawal/settlement path.

Mfano wa test harness ya mtindo wa Foundry (pseudocode)
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
- Compute ΔsqrtP for a tick step: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Approximate Δin using v3/v4 formulas: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Ensure rounding direction matches core math.
- Adjust Δin by ±1 wei around the boundary to find the branch where the hook rounds in your favor.

4) Amplify with flash loans
- Borrow a large notional (e.g., 3M USDT or 2000 WETH) to run many iterations atomically.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Execute the calibrated swap loop, then withdraw and repay within the flash loan callback.

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
5) Kutoka na replication ya cross-chain
- Ikiwa hooks zimetumwa kwenye chains nyingi, rudia calibration ileile kwa kila chain.
- Peleka mapato kurudi kwenye chain lengwa na, kwa hiari, yapitishe kwa mzunguko kupitia lending protocols ili kuficha mtiririko wa fedha.<sup>[[2]](#references)</sup>

## Sababu kuu za msingi katika hesabu za hook

- Semantiki mchanganyiko za rounding: mulDiv hufanya floor huku paths zinazofuata zikifanya rounding up; au conversions kati ya token/liquidity zikitumia rounding tofauti.
- Hitilafu za tick alignment: kutumia ticks ambazo hazijarounded katika path moja na rounding ya tick-spaced katika nyingine.
- Masuala ya sign/overflow ya BalanceDelta wakati wa kubadilisha kati ya int256 na uint256 wakati wa settlement.
- Kupotea kwa precision katika conversions za Q64.96 (sqrtPriceX96) kusikofuatwa na mapping ya reverse.
- Njia za mkusanyiko: remainders za kila swap kufuatiliwa kama credits zinazoweza kutolewa na caller badala ya kuchomwa/kufanya mfumo wa zero-sum.

## Custom accounting & delta amplification

- Uniswap v4 custom accounting huruhusu hooks kurudisha deltas zinazobadilisha moja kwa moja kiasi ambacho caller anadaiwa/anachopokea. Ikiwa hook inafuatilia credits internally, rounding residue inaweza kujikusanya katika operations nyingi ndogo **kabla** ya final settlement kufanyika.<sup>[[5]](#references)</sup>
- Hii hufanya boundary/threshold abuse kuwa imara zaidi: attacker anaweza kubadilisha `swap → withdraw → swap` katika tx ileile, na kulazimisha hook kuhesabu upya deltas kwenye state tofauti kidogo huku balances zote bado zikiwa pending.
- Wakati wa kukagua hooks, fuatilia kila mara jinsi BalanceDelta/HookDelta inavyotengenezwa na kusettle-iwa. Rounding yenye upendeleo katika branch moja inaweza kuwa credit inayojilimbikiza wakati deltas zinapohesabiwa upya mara kwa mara.

## Mwongozo wa kujilinda

- Differential testing: linganisha math ya hook na reference implementation inayotumia high-precision rational arithmetic na uthibitishe equality au bounded error ambayo daima ni ya upande wa attacker (kamwe isiwe na manufaa kwa caller).
- Invariant/property tests:
- Jumla ya deltas (tokens, liquidity) katika swap paths na hook adjustments lazima ihifadhi value, isipokuwa fees.
- Hakuna path inayopaswa kuunda net credit chanya kwa swap initiator baada ya exactInput iterations zinazorudiwa.
- Threshold/tick boundary tests karibu na inputs za ±1 wei kwa exactInput/exactOutput zote.
- Rounding policy: centralize rounding helpers ambazo daima hufanya rounding dhidi ya user; ondoa casts zisizolingana na implicit floors.
- Settlement sinks: kusanya rounding residue isiyoweza kuepukwa kwenye protocol treasury au ichome; kamwe usiipe msg.sender.
- Rate-limits/guardrails: weka minimum swap sizes kwa rebalancing triggers; zima rebalances ikiwa deltas ziko chini ya wei; hakiki sanity ya deltas dhidi ya ranges zinazotarajiwa.
- Kagua hook callbacks kwa ujumla: beforeSwap/afterSwap na before/after liquidity changes zinapaswa kukubaliana kuhusu tick alignment na delta rounding.

## Case study: Bunni V2 (2025-09-02)

- Protocol: Bunni V2 (Uniswap v4 hook) yenye LDF inayotumika kwa kila swap ili kufanya rebalance.<sup>[[7]](#references)</sup>
- Pools zilizoathiriwa: USDC/USDT kwenye Ethereum na weETH/ETH kwenye Unichain, zenye jumla ya takriban $8.4M.<sup>[[1]](#references)[[2]](#references)</sup>
- Hatua ya 1 (price push): attacker alikopa kwa flash takriban 3M USDT na kufanya swap ili kusukuma tick hadi takriban 5000, na kupunguza **active** USDC balance hadi takriban 28 wei.<sup>[[7]](#references)</sup>
- Hatua ya 2 (rounding drain): withdrawals 44 ndogo zilitumia floor rounding katika `BunniHubLogic::withdraw()` ili kupunguza active USDC balance kutoka 28 wei hadi 4 wei (-85.7%) huku sehemu ndogo sana ya LP shares ikiwa burned. Jumla ya liquidity ilikadiriwa chini kwa takriban 84.4%.<sup>[[2]](#references)[[7]](#references)</sup>
- Hatua ya 3 (liquidity rebound sandwich): swap kubwa ilisogeza tick hadi takriban 839,189 (1 USDC ≈ 2.77e36 USDT). Makadirio ya liquidity yalibadilika na kuongezeka kwa takriban 16.8%, na kuwezesha sandwich ambapo attacker alifanya swap ya kurudi kwa bei iliyoinflatiwa na kutoka akiwa na profit.<sup>[[7]](#references)</sup>
- Fix iliyotambuliwa katika post-mortem: badilisha update ya idle-balance ifanye rounding **up** ili micro-withdrawals zinazorudiwa zisiweze kushusha active balance ya pool hatua kwa hatua.<sup>[[7]](#references)</sup>

Mstari uliorahisishwa ulio vulnerable (na fix ya post-mortem)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Orodha ya ukaguzi wa Hunting

- Je, pool inatumia hooks address isiyo sifuri? Ni callbacks zipi zimewezeshwa?
- Je, kuna ugawaji upya/rebalance za kila swap zinazotumia custom math? Kuna logic yoyote ya tick/threshold?
- Divisions/mulDiv, ubadilishaji wa Q64.96, au SafeCast zinatumika wapi? Je, semantics za rounding zinaendana kote?
- Je, unaweza kutengeneza Δin inayovuka boundary kwa kiasi kidogo na kutoa rounding branch yenye faida? Test pande zote mbili na exactInput pamoja na exactOutput.
- Je, hook inafuatilia credits au deltas za kila caller ambazo zinaweza kutolewa baadaye? Hakikisha residue inafutiliwa mbali.

## Marejeo

- [1] [Bunni V2 Exploit: $8.3M Zilitolewa kupitia Kasoro ya Liquidity (muhtasari)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: Uchambuzi Kamili wa Hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Usuli wa Uniswap v4 (utafiti wa QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Mekanika za Liquidity katika Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Mekanika za Swap katika Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Hooks za Uniswap v4 na Mazingatio ya Usalama](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Post Mortem ya Bunni Exploit (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Whitepaper ya Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
