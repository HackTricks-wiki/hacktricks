# DeFi/AMM शोषण: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ Uniswap v4–style DEXes के खिलाफ एक क्लास के DeFi/AMM शोषण तकनीकों का दस्तावेज़ीकरण करता है जो core math को custom hooks के साथ बढ़ाती हैं। हाल का एक घटना Bunni V2 में Liquidity Distribution Function (LDF) के एक rounding/precision दोष का उपयोग करके हुई थी, जो हर swap पर चलता था और attacker को positive credits जमा करने और liquidity निकालने में सक्षम बनाती थी।

मुख्य विचार: यदि किसी hook में अतिरिक्त accounting लागू है जो fixed‑point math, tick rounding, और threshold logic पर निर्भर करती है, तो attacker ऐसे exact‑input swaps तैयार कर सकता है जो विशिष्ट thresholds को पार करें ताकि rounding विसंगतियाँ उनके फायदे में जमा हो जाएँ। इस पैटर्न को दोहराकर और फिर inflate किए गए बैलेंस को निकालकर मुनाफा प्राप्त किया जा सकता है, अक्सर flash loan से फंड करके।

## पृष्ठभूमि: Uniswap v4 hooks और swap flow

- Hooks वे contracts हैं जिन्हें PoolManager lifecycle के specific points पर कॉल करता है (उदा., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity)।
- Pools को PoolKey के साथ initialize किया जाता है जिसमें hooks address शामिल होता है। अगर non‑zero है, तो PoolManager हर संबंधित ऑपरेशन पर callbacks चलाता है।
- Core math fixed‑point formats का उपयोग करती है जैसे Q64.96 for sqrtPriceX96 और tick arithmetic 1.0001^tick के साथ। ऊपर लेयर्ड कोई भी custom math rounding semantics को सावधानी से मिलाना चाहिए ताकि invariant drift न हो।
- Swaps exactInput या exactOutput हो सकते हैं। v3/v4 में, price ticks के साथ चलता है; एक tick boundary को पार करने से range liquidity activate/deactivate हो सकती है। Hooks threshold/tick crossings पर अतिरिक्त लॉजिक लागू कर सकते हैं।

## Vulnerability archetype: threshold‑crossing precision/rounding drift

custom hooks में एक सामान्य vulnerable pattern:

1. Hook per‑swap liquidity या balance deltas की गणना integer division, mulDiv, या fixed‑point conversions (उदा., token ↔ liquidity using sqrtPrice और tick ranges) का उपयोग करके करता है।
2. Threshold logic (उदा., rebalancing, stepwise redistribution, या per‑range activation) तब ट्रिगर होती है जब swap size या price movement किसी internal boundary को पार करता है।
3. Rounding inconsistently लागू होता है (उदा., truncation toward zero, floor versus ceil) forward calculation और settlement path के बीच। छोटी विसंगतियाँ cancel नहीं होतीं और इसके बजाय caller को credit कर देती हैं।
4. Exact‑input swaps, ठीक उसी आकार के जिनका उद्देश्य उन boundaries को straddle करना होता है, बार‑बार positive rounding remainder को harvest करते हैं। बाद में attacker accumulated credit को withdrawal के माध्यम से निकालता है।

Attack preconditions
- एक pool जो custom v4 hook का उपयोग कर रहा हो जो प्रत्येक swap पर अतिरिक्त math करता है (उदा., एक LDF/rebalancer)।
- कम से कम एक execution path जहाँ rounding swap initiator को threshold crossings पर लाभ पहुंचाती हो।
- कई swaps को atomically repeat करने की क्षमता (flash loans अस्थायी float प्रदान करने और gas amortize करने के लिए आदर्श हैं)।

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 pools enumerate करें और PoolKey.hooks != address(0) जांचें।
- hook bytecode/ABI inspect करें callbacks के लिए: beforeSwap/afterSwap और कोई भी custom rebalancing methods।
- ऐसी math देखें जो: liquidity से divide करती है, token amounts और liquidity के बीच convert करती है, या BalanceDelta को rounding के साथ aggregate करती है।

2) Model the hook’s math and thresholds
- Hook की liquidity/redistribution formula recreate करें: inputs आमतौर पर sqrtPriceX96, tickLower/Upper, currentTick, fee tier, और net liquidity शामिल करते हैं।
- threshold/step functions का map बनाएं: ticks, bucket boundaries, या LDF breakpoints। निर्धारित करें कि प्रत्येक boundary के किन पक्षों पर delta को कैसे rounded किया जाता है।
- Identify करें जहाँ conversions uint256/int256 के बीच cast होते हैं, SafeCast का उपयोग होता है, या mulDiv पर implicit floor निर्भर है।

3) Calibrate exact‑input swaps to cross boundaries
- Foundry/Hardhat simulations का उपयोग करके minimal Δin compute करें जो price को boundary के ठीक पार ले जाए और hook की branch trigger करे।
- Verify करें कि afterSwap settlement caller को cost से अधिक credit करती है, जिससे positive BalanceDelta या hook के accounting में credit बचता है।
- Swaps को repeat करके credit accumulate करें; फिर hook के withdrawal/settlement path को कॉल करें।

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
exactInput को कैलिब्रेट करना
- एक tick step के लिए ΔsqrtP की गणना करें: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- v3/v4 सूत्रों का उपयोग करके Δin का अनुमान लगाएँ: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). सुनिश्चित करें कि राउंडिंग दिशा कोर गणित के अनुरूप हो।
- बाउंडरी के आसपास Δin को ±1 wei से समायोजित करें ताकि वह ब्रांच मिल सके जहाँ hook आपके पक्ष में राउंड करे।

4) flash loans के साथ प्रभाव बढ़ाएँ
- कई iterations को atomic तरीके से चलाने के लिए एक बड़ी notional राशि उधार लें (उदा., 3M USDT या 2000 WETH)।
- calibrated swap loop को execute करें, फिर flash loan callback के अंदर withdraw और repay करें।

Aave V3 flash loan का ढांचा
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
5) निकास और क्रॉस‑चेन प्रतिकरण
- यदि hooks कई chains पर परिनियोजित हैं, तो प्रत्येक chain के लिए वही calibration दोहराएँ।
- Bridge proceeds back to the target chain और वैकल्पिक रूप से फ्लो को अस्पष्ट करने के लिए lending protocols के माध्यम से चक्रित करें।

## Common root causes in hook math

- Mixed rounding semantics: mulDiv floors जबकि बाद के रास्ते प्रभावी रूप से round up करते हैं; या token/liquidity के बीच conversions में अलग राउंडिंग लागू होती है।
- Tick alignment errors: एक path में unrounded ticks का उपयोग और दूसरे में tick‑spaced rounding।
- BalanceDelta sign/overflow issues जब settlement के दौरान int256 और uint256 के बीच conversion होता है।
- Precision loss in Q64.96 conversions (sqrtPriceX96) जो reverse mapping में प्रतिबिंबित नहीं होता।
- Accumulation pathways: per‑swap remainders को credits के रूप में ट्रैक किया जाना जो caller द्वारा withdrawable हो सकते हैं बजाय इसके कि वे burned/zero‑sum हों।

## Defensive guidance

- Differential testing: hook की math को एक reference implementation के साथ high‑precision rational arithmetic का उपयोग करके mirror करें और equality या bounded error को assert करें जो हमेशा adversarial हो (कभी caller के पक्ष में नहीं)।
- Invariant/property tests:
- swap paths और hook adjustments में deltas (tokens, liquidity) का योग fees के मोड्यूलो के सापेक्ष वैल्यू को संरक्षित करना चाहिए।
- किसी भी path को repeated exactInput iterations के दौरान swap initiator के लिए positive net credit नहीं बनाना चाहिए।
- ±1 wei इनपुट के आसपास threshold/tick boundary tests चलाएँ, दोनों exactInput और exactOutput के लिए।
- Rounding policy: ऐसे rounding helpers को केंद्रीकृत करें जो हमेशा user के खिलाफ राउंड करें; inconsistent casts और implicit floors को हटाएँ।
- Settlement sinks: अनिवार्य rounding residue को protocol treasury में संचित करें या उसे burn करें; इसे कभी भी msg.sender को attribute न करें।
- Rate‑limits/guardrails: rebalancing triggers के लिए minimum swap sizes निर्धारित करें; यदि deltas sub‑wei हैं तो rebalances को disable करें; deltas को expected ranges के खिलाफ sanity‑check करें।
- Hook callbacks की समग्र समीक्षा करें: beforeSwap/afterSwap और before/after liquidity changes को tick alignment और delta rounding पर सहमत होना चाहिए।

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) जिसमें प्रति swap rebalancing के लिए एक LDF लागू था।
- Root cause: threshold‑crossing swaps के दौरान LDF liquidity accounting में rounding/precision त्रुटि; per‑swap असंगतियाँ caller के लिए positive credits के रूप में जमा हो गयीं।
- Ethereum leg: attacker ने ~3M USDT flash loan ली, USDC/USDT पर calibrated exact‑input swaps करके credits बनाए, inflated balances निकाले, repaid किया, और funds को Aave के माध्यम से route किया।
- UniChain leg: exploit को 2000 WETH flash loan के साथ दोहराया, लगभग 1366 WETH siphon किए और Ethereum पर bridge किया।
- Impact: लगभग USD 8.3M कई chains में निकाले गए। किसी user interaction की आवश्यकता नहीं थी; पूरी प्रक्रिया on‑chain थी।

## Hunting checklist

- क्या pool किसी non‑zero hooks address का उपयोग करता है? कौन से callbacks enabled हैं?
- क्या per‑swap redistributions/rebalances custom math का उपयोग करते हैं? कोई tick/threshold logic है?
- divisions/mulDiv, Q64.96 conversions, या SafeCast कहाँ उपयोग हो रहे हैं? क्या rounding semantics वैश्विक रूप से consistent हैं?
- क्या आप ऐसा Δin बना सकते हैं जो लगभग boundary को पार करे और favorable rounding branch दे? दोनों दिशाओं और दोनों exactInput तथा exactOutput के लिए टेस्ट करें।
- क्या hook per‑caller credits या deltas ट्रैक करता है जिन्हें बाद में withdraw किया जा सकता है? सुनिश्चित करें कि residue neutralized हो।

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
