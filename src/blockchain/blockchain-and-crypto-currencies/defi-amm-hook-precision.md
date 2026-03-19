# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



This page documents a class of DeFi/AMM exploitation techniques against Uniswap v4–style DEXes that extend core math with custom hooks. A recent incident in Bunni V2 leveraged a rounding/precision flaw in a Liquidity Distribution Function (LDF) executed on each swap, enabling the attacker to accrue positive credits and drain liquidity.

Key idea: if a hook implements additional accounting that depends on fixed‑point math, tick rounding, and threshold logic, an attacker can craft exact‑input swaps that cross specific thresholds so that rounding discrepancies accumulate in their favor. Repeating the pattern and then withdrawing the inflated balance realizes profit, often financed with a flash loan.

## पृष्ठभूमि: Uniswap v4 hooks और swap flow

- Hooks वे contracts हैं जिन्हें PoolManager विशेष lifecycle बिंदुओं पर कॉल करता है (उदा., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate)।
- Pools को PoolKey में hooks address के साथ initialized किया जाता है। यदि non‑zero है, तो PoolManager हर संबंधित operation पर callbacks करता है।
- Hooks **custom deltas** लौट सकते हैं जो swap या liquidity action के final balance changes को modify करते हैं (custom accounting)। ये deltas कॉल के अंत में net balances के रूप में settle होते हैं, इसलिए hook के अंदर किसी भी rounding error का असर settlement से पहले accumulate हो जाता है।
- Core math fixed‑point formats जैसे Q64.96 का उपयोग करती है sqrtPriceX96 के लिए और tick arithmetic 1.0001^tick के साथ चलता है। किसी भी custom math परत को rounding semantics से सावधानी से जोड़ा जाना चाहिए अन्यथा invariant drift हो सकता है।
- Swaps exactInput या exactOutput हो सकते हैं। v3/v4 में price ticks के साथ चलता है; किसी tick boundary को cross करने से range liquidity activate/deactivate हो सकती है। Hooks threshold/tick crossings पर अतिरिक्त लॉजिक लागू कर सकते हैं।

## Vulnerability archetype: threshold‑crossing precision/rounding drift

एक सामान्य vulnerable पैटर्न custom hooks में:

1. Hook per‑swap liquidity या balance deltas की गणना integer division, mulDiv, या fixed‑point conversions से करता है (उदा., token ↔ liquidity के लिए sqrtPrice और tick ranges का उपयोग)।
2. Threshold logic (उदा., rebalancing, stepwise redistribution, या per‑range activation) तब trigger होती है जब swap size या price movement किसी internal boundary को पार कर देती है।
3. Rounding inconsistently लागू होती है (उदा., truncation toward zero, floor बनाम ceil) forward calculation और settlement path के बीच। छोटे अंतर cancel नहीं होते और इसके बजाय caller को credit कर देते हैं।
4. Exact‑input swaps, जो ठीक ऐसे boundaries को straddle करने के लिए size किए जाते हैं, बार‑बार positive rounding remainder को harvest करते हैं। बाद में attacker accumulated credit withdraw कर देता है।

Attack preconditions
- एक pool जो custom v4 hook का उपयोग करता है जो हर swap पर अतिरिक्त math करता है (उदा., एक LDF/rebalancer)।
- कम से कम एक execution path जहाँ rounding swap initiator को threshold crossings के पार लाभ पहुँचाती है।
- कई swaps को atomically repeat करने की क्षमता (flash loans अस्थायी float देने और gas amortize करने के लिए ideal हैं)।

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 pools को enumerate करें और चेक करें PoolKey.hooks != address(0)।
- Hook bytecode/ABI inspect करें callbacks के लिए: beforeSwap/afterSwap और कोई भी custom rebalancing methods।
- ऐसे math की तलाश करें जो: liquidity से divide करता हो, token amounts और liquidity के बीच convert करता हो, या rounding के साथ BalanceDelta aggregate करता हो।

2) Model the hook’s math and thresholds
- Hook की liquidity/redistribution formula recreate करें: inputs आमतौर पर sqrtPriceX96, tickLower/Upper, currentTick, fee tier, और net liquidity होते हैं।
- Threshold/step functions का मैप बनाएं: ticks, bucket boundaries, या LDF breakpoints। निर्धारित करें कि प्रत्येक boundary के किस साइड पर delta rounded होता है।
- पहचानें जहाँ conversions uint256/int256 के बीच cast करते हैं, SafeCast का उपयोग होता है, या mulDiv implicit floor पर निर्भर करता है।

3) Calibrate exact‑input swaps to cross boundaries
- Foundry/Hardhat simulations का उपयोग करके वह न्यूनतम Δin गणना करें जो price को बस एक boundary के पार ले जाए और hook की branch को trigger करे।
- Verify करें कि afterSwap settlement caller को खर्च से अधिक credit करता है, जिससे positive BalanceDelta या hook के accounting में credit बचता है।
- Credit accumulate करने के लिए swaps repeat करें; फिर hook की withdrawal/settlement path कॉल करें।

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

- एक tick step के लिए ΔsqrtP की गणना करें: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Δin को v3/v4 फ़ॉर्मूलों का उपयोग कर अनुमानित करें: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). राउंडिंग दिशा कोर गणित के अनुरूप हो यह सुनिश्चित करें।
- बाउंडरी के आसपास Δin को ±1 wei से समायोजित करें ताकि वह ब्रांच मिल सके जहाँ hook आपके पक्ष में राउंड करता है।

4) Flash loans से प्रभाव बढ़ाएँ

- कई iterations को atomically चलाने के लिए बड़ा notional उधार लें (उदा., 3M USDT या 2000 WETH)।
- कैलिब्रेटेड swap loop को execute करें, फिर flash loan callback के भीतर withdraw और repay करें।

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
5) निकलने और क्रॉस‑चेन प्रतिकृति
- यदि hooks कई चेन पर तैनात हैं, तो हर चेन के लिए वही कैलीबरेशन दोहराएं।
- Bridge धन्वापसी लक्ष्य चेन पर वापस भेजता है और वैकल्पिक रूप से फ्लो को अस्पष्ट करने के लिए lending protocols के माध्यम से साइकिल कर सकता है।

## Hook गणित में सामान्य मूल कारण

- Mixed rounding semantics: mulDiv फ़्लोर करता है जबकि बाद के पाथ प्रभावत: ऊपर राउंड करते हैं; या token/liquidity के बीच रूपांतरण अलग राउंडिंग लागू करते हैं।
- Tick alignment errors: एक पाथ में unrounded ticks का उपयोग और दूसरे में tick‑spaced rounding।
- BalanceDelta sign/overflow issues जब settlement के दौरान int256 और uint256 के बीच परिवर्तित किया जाता है।
- Q64.96 परिवर्तन (sqrtPriceX96) में precision loss जो reverse mapping में प्रतिबिंबित नहीं होता।
- Accumulation pathways: प्रति‑swap बाकी बचा हुआ हिस्सा credits के रूप में ट्रैक किया जाता है जिन्हें caller द्वारा withdrawable माना जाता है बजाय उन्हें burn/zero‑sum करने के।

## Custom accounting & delta amplification

- Uniswap v4 custom accounting hooks को ऐसे deltas लौटाने देता है जो सीधे caller के देनदारियों/प्राप्तियों को समायोजित करते हैं। यदि hook credits को आंतरिक रूप से ट्रैक करता है, तो rounding residue कई छोटे ऑपरेशनों में जमा हो सकता है इससे पहले कि अंतिम settlement हो।
- यह boundary/threshold abuse को मजबूत बनाता है: attacker एक ही tx में `swap → withdraw → swap` वैकल्पिक कर सकता है, जिससे hook को हल्का बदलें हुए state पर deltas पुनःगणना करने के लिए मजबूर किया जाता है जबकि सभी बैलेंस अभी भी pending होते हैं।
- Hooks की समीक्षा करते समय, हमेशा ट्रेस करें कि BalanceDelta/HookDelta कैसे उत्पन्न और settle होते हैं। एक शाखा में एकल पक्षपाती राउंडिंग बार‑बार deltas पुनः‑गणना होने पर एक संचित क्रेडिट बन सकती है।

## रक्षात्मक मार्गदर्शन

- Differential testing: hook की गणना को high‑precision rational arithmetic का उपयोग करके एक reference implementation के विरुद्ध mirror करें और equality या ऐसा bounded error assert करें जो हमेशा प्रतिकूल हो (कभी भी caller के अनुकूल नहीं)।
- Invariant/property परीक्षण:
  - swap पाथ्स और hook समायोजनों में deltas (tokens, liquidity) का योग fees को छोड़कर मूल्य का संरक्षण करना चाहिए।
  - किसी भी पाथ को repeated exactInput iterations में swap initiator के लिए सकारात्मक नेट क्रेडिट पैदा नहीं करना चाहिए।
  - ±1 wei इनपुट के आसपास Threshold/tick boundary परीक्षण दोनों exactInput/exactOutput के लिए।
- Rounding policy: राउंडिंग हेल्पर्स को केंद्रीकृत करें जो हमेशा user के खिलाफ राउंड करें; असंगत casts और implicit floors को समाप्त करें।
- Settlement sinks: अपरिहार्य राउंडिंग residue को protocol treasury में संग्रहीत करें या बर्न करें; इसे कभी भी msg.sender को नहीं लौटाएं।
- Rate‑limits/guardrails: rebalancing triggers के लिए न्यूनतम swap आकार; यदि deltas sub‑wei हैं तो rebalances अक्षम करें; deltas की sanity‑check अपेक्षित रेंज के खिलाफ करें।
- Hook callbacks की समग्र समीक्षा करें: beforeSwap/afterSwap और before/after liquidity changes को tick alignment और delta rounding पर सहमत होना चाहिए।

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) जिसमें हर swap पर rebalancing के लिए एक LDF लागू था।
- Affected pools: USDC/USDT on Ethereum और weETH/ETH on Unichain, कुल लगभग $8.4M।
- Step 1 (price push): attacker ने लगभग 3M USDT flash‑borrowed करके swap किया ताकि tick ~5000 तक धकेल दिया जाए, जिससे **सक्रिय** USDC बैलेंस लगभग 28 wei तक सिकुड़ गया।
- Step 2 (rounding drain): 44 छोटे withdrawals ने `BunniHubLogic::withdraw()` में floor rounding का शोषण करके सक्रिय USDC बैलेंस को 28 wei से 4 wei (‑85.7%) तक घटा दिया जबकि केवल बेहद छोटे हिस्से के LP shares बर्न हुए। कुल liquidity का अनुमान लगभग 84.4% कम आंका गया।
- Step 3 (liquidity rebound sandwich): एक बड़ा swap tick को ~839,189 तक ले गया (1 USDC ≈ 2.77e36 USDT). Liquidity के अनुमान पलट गए और ~16.8% बढ़ गए, जिससे attacker ने inflated price पर वापस swap करके और exit करके लाभ कमाया।
- पोस्ट‑मोर्टेम में पहचाना गया फिक्स: idle‑balance अपडेट को **up** की ओर राउंड करने के लिए बदलें ताकि बार‑बार माइक्रो‑withdrawals पूल के सक्रिय बैलेंस को नीचे की ओर ratchet न कर सकें।

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## हंटिंग चेकलिस्ट

- क्या pool non‑zero hooks address का उपयोग करता है? कौन‑से callbacks सक्षम हैं?
- क्या per‑swap redistributions/rebalances custom math का उपयोग करके होते हैं? कोई tick/threshold logic है?
- divisions/mulDiv, Q64.96 conversions, या SafeCast कहाँ उपयोग होते हैं? क्या rounding semantics वैश्विक रूप से सुसंगत हैं?
- क्या आप ऐसा Δin तैयार कर सकते हैं जो सीमा को मुश्किल से पार करे और अनुकूल rounding branch दे? दोनों दिशाओं और दोनों exactInput और exactOutput के साथ परीक्षण करें।
- क्या hook per‑caller credits या deltas ट्रैक करता है जिन्हें बाद में निकाला जा सकता है? सुनिश्चित करें कि अवशेष निष्प्रभावी कर दिए गए हों।

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
