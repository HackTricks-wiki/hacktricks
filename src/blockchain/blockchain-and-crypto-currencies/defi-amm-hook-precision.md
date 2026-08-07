# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ Uniswap v4–style DEXes के विरुद्ध DeFi/AMM exploitation techniques की एक श्रेणी का दस्तावेजीकरण करता है, जो custom hooks के साथ core math को extend करते हैं। Bunni V2 में हुई एक recent incident में प्रत्येक swap पर execute होने वाले Liquidity Distribution Function (LDF) में मौजूद rounding/precision flaw का लाभ उठाया गया, जिससे attacker positive credits जमा करके liquidity drain करने में सक्षम हुआ।<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

मुख्य विचार: यदि कोई hook fixed‑point math, tick rounding और threshold logic पर निर्भर additional accounting लागू करता है, तो attacker exact‑input swaps तैयार कर सकता है जो specific thresholds को cross करें, ताकि rounding discrepancies उसके पक्ष में जमा होती रहें। इस pattern को दोहराने और फिर inflated balance withdraw करने से profit प्राप्त होता है, जिसे अक्सर flash loan से finance किया जाता है।

## Background: Uniswap v4 hooks और swap flow

- Hooks वे contracts हैं जिन्हें PoolManager specific lifecycle points पर call करता है (जैसे beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate)।<sup>[[3]](#references)[[6]](#references)</sup>
- Pools को hooks address सहित PoolKey के साथ initialize किया जाता है। यदि यह non-zero हो, तो PoolManager प्रत्येक relevant operation पर callbacks perform करता है।<sup>[[6]](#references)</sup>
- Hooks **custom deltas** return कर सकते हैं, जो किसी swap या liquidity action के final balance changes को modify करते हैं (custom accounting)। इन deltas को call के अंत में net balances के रूप में settle किया जाता है, इसलिए settlement से पहले hook math के भीतर कोई भी rounding error accumulate होता रहता है।<sup>[[5]](#references)</sup>
- Core math sqrtPriceX96 के लिए Q64.96 जैसे fixed‑point formats और 1.0001^tick के साथ tick arithmetic का उपयोग करता है। Invariant drift से बचने के लिए इसके ऊपर layered किसी भी custom math को rounding semantics से सावधानीपूर्वक match करना आवश्यक है।<sup>[[4]](#references)[[8]](#references)</sup>
- Swaps exactInput या exactOutput हो सकते हैं। v3/v4 में price ticks के along move करता है; tick boundary cross करने पर range liquidity activate/deactivate हो सकती है। Hooks threshold/tick crossings पर extra logic लागू कर सकते हैं।<sup>[[5]](#references)</sup>

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Custom hooks में एक typical vulnerable pattern:

1. Hook integer division, mulDiv या fixed‑point conversions का उपयोग करके per‑swap liquidity या balance deltas calculate करता है (जैसे sqrtPrice और tick ranges का उपयोग करके token ↔ liquidity conversion)।
2. Threshold logic (जैसे rebalancing, stepwise redistribution या per‑range activation) तब trigger होता है जब swap size या price movement किसी internal boundary को cross करता है।
3. Forward calculation और settlement path के बीच rounding inconsistent रूप से लागू की जाती है (जैसे zero की ओर truncation, floor बनाम ceil)। छोटी discrepancies cancel नहीं होतीं, बल्कि caller को credit कर देती हैं।
4. Exact‑input swaps, जिन्हें इन boundaries को straddle करने के लिए precisely size किया जाता है, positive rounding remainder को बार-बार harvest करते हैं। बाद में attacker accumulated credit withdraw कर लेता है।

Attack preconditions
- ऐसा pool जिसमें custom v4 hook प्रत्येक swap पर additional math perform करता हो (जैसे कोई LDF/rebalancer)।
- कम से कम एक execution path जिसमें threshold crossings के दौरान rounding swap initiator को लाभ पहुंचाती हो।
- कई swaps को atomically repeat करने की ability (temporary float supply करने और gas amortize करने के लिए flash loans ideal हैं)।

## Practical attack methodology

1) Hooks वाले candidate pools की पहचान करें
- v4 pools enumerate करें और जाँचें कि PoolKey.hooks != address(0) है।
- Callbacks के लिए hook bytecode/ABI inspect करें: beforeSwap/afterSwap और कोई भी custom rebalancing methods।
- ऐसा math खोजें जो: liquidity से divide करता हो, token amounts और liquidity के बीच convert करता हो, या rounding के साथ BalanceDelta aggregate करता हो।

2) Hook के math और thresholds को model करें
- Hook का liquidity/redistribution formula recreate करें: inputs में सामान्यतः sqrtPriceX96, tickLower/Upper, currentTick, fee tier और net liquidity शामिल होते हैं।
- Threshold/step functions map करें: ticks, bucket boundaries या LDF breakpoints। निर्धारित करें कि प्रत्येक boundary के किस side पर delta round किया जाता है।
- उन स्थानों की पहचान करें जहाँ uint256/int256 के बीच casts किए जाते हैं, SafeCast का उपयोग होता है, या implicit floor के साथ mulDiv पर निर्भरता होती है।

3) Boundaries cross करने के लिए exact‑input swaps calibrate करें
- Boundary के ठीक पार price move करने और hook की branch trigger करने के लिए आवश्यक minimal Δin calculate करने हेतु Foundry/Hardhat simulations का उपयोग करें।
- Verify करें कि afterSwap settlement caller को cost से अधिक credit करती है, जिससे hook की accounting में positive BalanceDelta या credit बचता है।
- Credit accumulate करने के लिए swaps repeat करें; फिर hook का withdrawal/settlement path call करें।

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
exactInput को calibrate करना
- एक tick step के लिए ΔsqrtP की गणना करें: sqrtP_next = sqrtP_current × 1.0001^(Δtick)।
- v3/v4 formulas का उपयोग करके Δin का अनुमान लगाएं: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current))। सुनिश्चित करें कि rounding direction core math के अनुरूप हो।
- boundary के आसपास Δin को ±1 wei से समायोजित करें, ताकि वह branch मिल सके जिसमें hook आपके पक्ष में round करे।

4) flash loans के साथ amplify करें
- कई iterations को atomically चलाने के लिए बड़ा notional (जैसे, 3M USDT या 2000 WETH) borrow करें।<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- calibrated swap loop execute करें, फिर flash loan callback के भीतर withdraw करके loan repay करें।

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
5) Exit और cross-chain replication
- यदि hooks multiple chains पर deployed हैं, तो प्रत्येक chain पर वही calibration दोहराएँ।
- Proceeds को target chain पर वापस bridge करें और flows को obfuscate करने के लिए optional रूप से lending protocols के माध्यम से cycle करें।<sup>[[2]](#references)</sup>

## Hook math में सामान्य root causes

- Mixed rounding semantics: mulDiv floor करता है, जबकि बाद के paths प्रभावी रूप से round up करते हैं; या token/liquidity के बीच conversions में अलग-अलग rounding लागू होती है।
- Tick alignment errors: एक path में unrounded ticks और दूसरे में tick-spaced rounding का उपयोग।
- Settlement के दौरान int256 और uint256 के बीच conversion करते समय BalanceDelta sign/overflow issues।
- Q64.96 conversions (sqrtPriceX96) में precision loss, जिसे reverse mapping में mirror नहीं किया जाता।
- Accumulation pathways: per-swap remainders को credits के रूप में track करना, जिन्हें caller withdraw कर सकता है, बजाय इसके कि उन्हें burn किया जाए या zero-sum रखा जाए।

## Custom accounting और delta amplification

- Uniswap v4 custom accounting hooks को ऐसे deltas return करने देता है, जो caller द्वारा owed/received राशि को सीधे adjust करते हैं। यदि hook internally credits track करता है, तो final settlement होने से **पहले** कई छोटी operations के दौरान rounding residue accumulate हो सकता है।<sup>[[5]](#references)</sup>
- इससे boundary/threshold abuse अधिक प्रभावी हो जाता है: attacker उसी tx में `swap → withdraw → swap` को alternate कर सकता है, जिससे hook थोड़ी अलग state पर deltas को फिर से compute करने के लिए मजबूर होता है, जबकि सभी balances अभी भी pending रहते हैं।
- Hooks की review करते समय हमेशा trace करें कि BalanceDelta/HookDelta कैसे produce और settle होता है। एक branch में किया गया single biased rounding repeated delta recomputation के दौरान compounding credit बन सकता है।

## Defensive guidance

- Differential testing: high-precision rational arithmetic का उपयोग करने वाली reference implementation के विरुद्ध hook की math को mirror करें और equality या bounded error assert करें, जो हमेशा adversarial हो (कभी भी caller के लिए favorable न हो)।
- Invariant/property tests:
- Swap paths और hook adjustments के across deltas (tokens, liquidity) का sum fees को छोड़कर value conserve करना चाहिए।
- Repeated exactInput iterations के दौरान किसी भी path को swap initiator के लिए positive net credit create नहीं करना चाहिए।
- exactInput/exactOutput दोनों के लिए ±1 wei inputs के आसपास threshold/tick boundary tests।
- Rounding policy: ऐसे centralized rounding helpers बनाएँ जो हमेशा user के विरुद्ध round करें; inconsistent casts और implicit floors समाप्त करें।
- Settlement sinks: unavoidable rounding residue को protocol treasury में accumulate करें या burn करें; इसे कभी भी msg.sender को attribute न करें।
- Rate-limits/guardrails: rebalancing triggers के लिए minimum swap sizes; यदि deltas sub-wei हों तो rebalances disable करें; expected ranges के विरुद्ध deltas की sanity-check करें।
- Hook callbacks की holistic review करें: beforeSwap/afterSwap और before/after liquidity changes को tick alignment और delta rounding पर सहमत होना चाहिए।

## Case study: Bunni V2 (2025-09-02)

- Protocol: Bunni V2 (Uniswap v4 hook), जिसमें rebalance के लिए प्रति swap LDF लागू किया गया था।<sup>[[7]](#references)</sup>
- Affected pools: Ethereum पर USDC/USDT और Unichain पर weETH/ETH, जिनकी कुल राशि लगभग $8.4M थी।<sup>[[1]](#references)[[2]](#references)</sup>
- Step 1 (price push): attacker ने लगभग 3M USDT flash-borrow किया और tick को लगभग 5000 तक push करने के लिए swap किया, जिससे **सक्रिय** USDC balance घटकर लगभग 28 wei रह गया।<sup>[[7]](#references)</sup>
- Step 2 (rounding drain): 44 tiny withdrawals ने `BunniHubLogic::withdraw()` में floor rounding का exploit किया और active USDC balance को 28 wei से घटाकर 4 wei (-85.7%) कर दिया, जबकि LP shares का केवल एक बहुत छोटा fraction burn किया गया। Total liquidity को लगभग 84.4% कम आंका गया।<sup>[[2]](#references)[[7]](#references)</sup>
- Step 3 (liquidity rebound sandwich): एक large swap ने tick को लगभग 839,189 तक move किया (1 USDC ≈ 2.77e36 USDT)। Liquidity estimates flip हुए और लगभग 16.8% बढ़ गए, जिससे एक sandwich संभव हुआ जिसमें attacker ने inflated price पर वापस swap किया और profit के साथ exit किया।<sup>[[7]](#references)</sup>
- Post-mortem में identified fix: idle-balance update को **round up** करने के लिए बदलें, ताकि repeated micro-withdrawals pool के active balance को downward ratchet न कर सकें।<sup>[[7]](#references)</sup>

Simplified vulnerable line (और post-mortem fix)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- क्या pool non-zero hooks address का उपयोग करता है? कौन से callbacks enabled हैं?
- क्या custom math का उपयोग करके per-swap redistributions/rebalances किए जाते हैं? क्या कोई tick/threshold logic है?
- divisions/mulDiv, Q64.96 conversions या SafeCast का उपयोग कहाँ किया गया है? क्या rounding semantics पूरे सिस्टम में consistent हैं?
- क्या आप ऐसा Δin बना सकते हैं जो किसी boundary को barely cross करे और favorable rounding branch उत्पन्न करे? दोनों directions और exactInput तथा exactOutput, दोनों का परीक्षण करें।
- क्या hook per-caller credits या deltas track करता है जिन्हें बाद में withdraw किया जा सकता है? सुनिश्चित करें कि residue neutralized हो।

## References

- [1] [Bunni V2 Exploit: Liquidity Flaw के माध्यम से $8.3M Drained (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Uniswap v4 core में Liquidity mechanics](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Uniswap v4 core में Swap mechanics](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
