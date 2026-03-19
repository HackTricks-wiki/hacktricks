# Matumizi Mabaya ya DeFi/AMM: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



Ukurasa huu unaelezea daraja la mbinu za matumizi mabaya ya DeFi/AMM dhidi ya DEXes za mtindo wa Uniswap v4 ambazo zinaongeza hisabati ya msingi kwa hooks za kawaida. Tukio la hivi karibuni katika Bunni V2 lilitumia kasoro ya rounding/precision katika Liquidity Distribution Function (LDF) inayotekelezwa kila swap, na kumruhusu attacker kupata mikopo chanya na kuondoa liquidity.

Key idea: kama hook inatekeleza uhasibu wa ziada unaotegemea fixed‑point math, tick rounding, na mantiki ya vizingiti, attacker anaweza kutengeneza exact‑input swaps zinazovuka vizingiti maalum ili tofauti za rounding zikusanye kwa faida yao. Kurudia mtindo huo kisha kutoa salio lililojaa linaleta faida, mara nyingi likifadhiliwa na flash loan.

## Mandhari: Uniswap v4 hooks and swap flow

- Hooks ni mikataba ambayo PoolManager huita katika pointi maalum za mzunguko wa maisha (e.g., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools zinaanzishwa na PoolKey inayojumuisha anwani ya hooks. Ikiwa si‑zero, PoolManager hufanya callbacks kwa kila operesheni inayohusiana.
- Hooks zinaweza kurudisha **custom deltas** zinazobadilisha mabadiliko ya salio ya mwisho ya swap au liquidity action (custom accounting). Deltas hizo zinalipishwa kama salio net mwishoni mwa wito, kwa hivyo kosa lolote la rounding ndani ya hisabati ya hook linakusanyika kabla ya settlement.
- Hisabati ya msingi inatumia fixed‑point formats kama Q64.96 kwa sqrtPriceX96 na tick arithmetic na 1.0001^tick. Hisabati yoyote ya ziada iliyowekwa juu lazima iendane kwa uangalifu na semantiki za rounding ili kuepuka invariant drift.
- Swaps zinaweza kuwa exactInput au exactOutput. Katika v3/v4, bei inasogea kwa ticks; kuvuka mpaka wa tick kunaweza kuamsha/kuzima range liquidity. Hooks zinaweza kutekeleza mantiki ya ziada kwenye kuvuka vizingiti/ticks.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Muundo dhaifu wa kawaida katika hooks za custom:

1. Hook inahesabu per‑swap liquidity au balance deltas kwa kutumia integer division, mulDiv, au fixed‑point conversions (e.g., token ↔ liquidity kutumia sqrtPrice na tick ranges).
2. Mantiki ya vizingiti (e.g., rebalancing, stepwise redistribution, au per‑range activation) inachochewa wakati ukubwa wa swap au mabadiliko ya bei yanapovuka mpaka wa ndani.
3. Rounding/ukataji unatumika kwa ukosefu wa mshikamano (e.g., truncation toward zero, floor versus ceil) kati ya hesabu ya mbele na njia ya malipo. Tofauti ndogo hazibatilishi na badala yake zinampa caller mkopo.
4. Exact‑input swaps, zilizo na ukubwa sahihi kuvuka vizingiti hivyo, mara kwa mara hupunguza mabaki chanya ya rounding. Baadaye attacker anatoa credit iliyokusanywa.

Attack preconditions
- Pool inayotumia custom v4 hook inayofanya hisabati ya ziada kwenye kila swap (e.g., LDF/rebalancer).
- Angalau njia moja ya utekelezaji ambapo rounding inamfaidi swap initiator wakati wa kuvuka vizingiti.
- Uwezo wa kurudia swaps nyingi atomically (flash loans ni nzuri kutoa float ya muda mfupi na kugawanya gas).

## Mbinu ya vitendo ya shambulio

1) Tambua pools zinazowezekana zilizo na hooks
- Orodhesha v4 pools na angalia PoolKey.hooks != address(0).
- Kagua hook bytecode/ABI kwa callbacks: beforeSwap/afterSwap na njia zozote za custom rebalancing.
- Tafuta hisabati inayofanya: kugawanya kwa liquidity, kubadilisha kati ya token amounts na liquidity, au kujumlisha BalanceDelta na rounding.

2) Fanya mfano wa hisabati na vizingiti vya hook
- Rekreeta formula ya liquidity/redistribution ya hook: inputs kawaida ni sqrtPriceX96, tickLower/Upper, currentTick, fee tier, na net liquidity.
- Ramani za threshold/step functions: ticks, bucket boundaries, au LDF breakpoints. Tambua upande wa kila mpaka ambapo delta inakatwa/rounded.
- Tambua mahali ambapo conversions zinakata kati ya uint256/int256, zinatumia SafeCast, au tegemea mulDiv yenye implicit floor.

3) Sanidi exact‑input swaps kuvuka vizingiti
- Tumia Foundry/Hardhat simulations kuhesabu minimal Δin inayohitajika kusonga bei ikivuka mpaka na kuchochea tawi la hook.
- Thibitisha kwamba afterSwap settlement inampa caller zaidi kuliko gharama, ikiacha BalanceDelta chanya au credit katika uhasibu wa hook.
- Rudia swaps kukusanya credit; kisha piga njia ya hook ya withdrawal/settlement.

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
Kurekebisha exactInput
- Hesabu ΔsqrtP kwa hatua ya tick: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Kadiria Δin kutumia fomula za v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Hakikisha mwelekeo wa kuzungusha (rounding) unalingana na hesabu ya msingi.
- Rekebisha Δin kwa ±1 wei karibu na mpaka ili kupata tawi ambapo hook inazungusha kwa faida yako.

4) Kuongeza kwa kutumia flash loans
- Kopa kiasi kikubwa (mfano, 3M USDT au 2000 WETH) ili kuendesha marudio mengi kwa atomiki.
- Tekeleza loop ya swap iliyorekebishwa, kisha toa na ulipie ndani ya callback ya flash loan.

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
5) Kuondoka na uenezaji kuvuka‑mnyororo
- If hooks are deployed on multiple chains, rudia utatuzi huo huo kwa kila mnyororo.
- Bridge inarudi kwenye target chain na, kwa hiari, inaweza kuzunguka kupitia protokoli za lending ili kuficha mtiririko.

## Common root causes in hook math

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: kutumia ticks zisizozungushwa katika njia moja na tick‑spaced rounding katika nyingine.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: mabaki kwa kila swap yafuatwa kama mikopo inayoweza kuondolewa na caller badala ya kuchomwa/zero‑sum.

## Custom accounting & delta amplification

- Uniswap v4 custom accounting inaruhusu hooks kurudisha deltas zinazobadilisha moja kwa moja kile mtia wito analia/analipwa. Ikiwa hook inafuata mikopo ndani yake, mabaki ya rounding yanaweza kukusanyika kwenye shughuli ndogo nyingi **kabla** ya settlement ya mwisho kutokea.
- Hii inafanya matumizi mabaya ya boundary/threshold kuwa yenye nguvu zaidi: mshambulizi anaweza kubadilisha kati ya `swap → withdraw → swap` katika tx ile ile, akilazimisha hook kukokotoa deltas upya kwenye state kidogo tofauti wakati salio zote bado zinatarajiwa.
- Wakati wa kukagua hooks, fuatilia jinsi BalanceDelta/HookDelta zinatengenezwa na kusuluhishwa. Kuizungusha yenye upendeleo katika tawi moja inaweza kuwa mkopo unaoongezeka wakati deltas zinakaribiwa kukokotwa tena kwa mara nyingi.

## Defensive guidance

- Differential testing: tengeneza picha ya hisabati ya hook dhidi ya implementation ya rejea ukitumia hesabu ya rational yenye usahihi wa juu na thibitisha usawa au kosa lililowekwa ambalo siku zote linakuwa la advesarial (si faida kwa caller).
- Invariant/property tests:
- Jumla ya deltas (tokens, liquidity) kwenye njia za swap na marekebisho ya hook lazima ihifadhi thamani modulo ada.
- Hakuna njia inapaswa kuunda mkopo chanya kwa mtia wito wa swap baada ya kurudia iteresheni za exactInput.
- Majaribio ya boundary/threshold za tick karibu na ±1 wei inputs kwa both exactInput/exactOutput.
- Sera ya kuzungusha: centralize helper za rounding ambazo kila mara huzungusha dhidi ya user; ondoa casts zisizo thabiti na implicit floors.
- Settlement sinks: kusanya mabaki ya rounding yasiyotepukika kwenye hazina ya protocol au kuyachoma; usiwachambulishe kama mali za msg.sender.
- Rate‑limits/guardrails: ukubwa mdogo wa swap kwa vichocheo vya rebalancing; zima rebalances ikiwa deltas ni sub‑wei; angalia sanity deltas dhidi ya anuwai zinazotarajiwa.
- Kagua callbacks za hook kwa ujumla: beforeSwap/afterSwap na before/after liquidity changes zinapaswa kukubaliana kwenye tick alignment na rounding ya delta.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) na LDF iliyowekwa kwa kila swap kwa ajili ya rebalancing.
- Affected pools: USDC/USDT on Ethereum na weETH/ETH on Unichain, jumla takriban $8.4M.
- Step 1 (price push): mshambulizi alikopa kwa flash takriban ~3M USDT na kufanya swap kusukuma tick hadi ~5000, akipunguza salio la **active** USDC hadi ~28 wei.
- Step 2 (rounding drain): misukumo 44 midogo ya withdraw ilitumia floor rounding katika `BunniHubLogic::withdraw()` kupunguza salio la active USDC kutoka 28 wei hadi 4 wei (‑85.7%) wakati sehemu ndogo sana ya LP shares ilichomwa. Liquidity zote zilikadiriwa chini kwa takriban ~84.4%.
- Step 3 (liquidity rebound sandwich): swap kubwa ilisukuma tick hadi ~839,189 (1 USDC ≈ 2.77e36 USDT). Makadirio ya liquidity yalibadilika na kuongezeka kwa ~16.8%, kuruhusu sandwich ambapo mshambulizi alibadilisha tena kwa bei iliyopandishwa na kutoka na faida.
- Fix identified in the post‑mortem: badilisha update ya idle‑balance iwe round **up** ili withdrawals ndogo zinazorudiwa zisizoweza kupunguza salio la active la pool.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Orodha ya uchunguzi

- Je, pool inatumia anwani ya hooks isiyo sifuri? Ni callbacks gani zimeruhusiwa?
- Je, kuna per‑swap redistributions/rebalances zinazotumia custom math? Kuna tick/threshold logic yoyote?
- Wapi divisions/mulDiv, Q64.96 conversions, au SafeCast zimetumika? Je, rounding semantics ni thabiti kwa ujumla?
- Je, unaweza kuunda Δin ambayo inavuka mpaka kwa karibu na kusababisha tawi la rounding lenye manufaa? Jaribu pande zote mbili na exactInput na exactOutput.
- Je, hook inafuatilia per‑caller credits au deltas ambazo zinaweza kutolewa baadaye? Hakikisha mabaki yameondolewa.

## Marejeo

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
