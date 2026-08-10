# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

यह पेज custom hooks के साथ core math को extend करने वाले Uniswap v4–style DEXes के विरुद्ध DeFi/AMM exploitation techniques की एक श्रेणी का दस्तावेजीकरण करता है। Bunni V2 incident एक संबंधित failure को दर्शाता है: withdrawal accounting में rounding-direction bug के कारण active liquidity कम आंकी गई, और बाद के swap ने एक profitable sandwich में उस underestimation को उजागर कर दिया।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

मुख्य विचार: यदि कोई hook fixed-point math, tick rounding और threshold logic पर निर्भर additional accounting लागू करता है, तो attacker exact-input swaps तैयार कर सकता है जो specific thresholds को पार करें, जिससे rounding discrepancies उसके पक्ष में जमा होती जाएँ। इस pattern को दोहराने और फिर inflated balance withdraw करने से profit प्राप्त होता है, जिसे अक्सर flash loan से finance किया जाता है।

## Background: Uniswap v4 hooks और swap flow

- Hooks वे contracts हैं जिन्हें PoolManager specific lifecycle points पर call करता है (जैसे beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate)।<sup>[[4]](#references)</sup>
- Pools को एक PoolKey के साथ initialize किया जाता है जिसमें hook contract शामिल होता है। Non-zero hook address उस pool के लिए selected callbacks को enable करता है।<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks **custom deltas** return कर सकते हैं, जो swap या liquidity action के final balance changes को modify करते हैं (custom accounting)। ये deltas call के अंत में net balances के रूप में settle होते हैं, इसलिए hook math के अंदर कोई भी rounding error settlement से पहले accumulate होता रहता है।<sup>[[4]](#references)</sup>
- Core math sqrtPriceX96 के लिए Q64.96 जैसे fixed-point formats और 1.0001^tick के साथ tick arithmetic का उपयोग करता है। Invariant drift से बचने के लिए इसके ऊपर लागू की गई किसी भी custom math को rounding semantics से सावधानीपूर्वक match करना चाहिए।<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps exactInput या exactOutput हो सकते हैं। v3/v4 में price ticks के अनुसार move होती है; tick boundary को cross करने पर range liquidity activate/deactivate हो सकती है। Hooks threshold/tick crossings पर extra logic लागू कर सकते हैं।<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Custom hooks में एक सामान्य vulnerable pattern:

1. Hook integer division, mulDiv या fixed-point conversions का उपयोग करके per-swap liquidity या balance deltas calculate करता है (जैसे sqrtPrice और tick ranges का उपयोग करके token ↔ liquidity conversion)।
2. Threshold logic (जैसे rebalancing, stepwise redistribution या per-range activation) तब trigger होती है जब swap size या price movement किसी internal boundary को cross करती है।
3. Forward calculation और settlement path के बीच rounding असंगत रूप से लागू होती है (जैसे zero की ओर truncation, floor बनाम ceil)। छोटी discrepancies cancel नहीं होतीं, बल्कि caller को credit कर देती हैं।
4. उन boundaries को straddle करने के लिए precisely sized exact-input swaps positive rounding remainder को बार-बार harvest करते हैं। बाद में attacker accumulated credit withdraw करता है।

Attack preconditions
- ऐसा pool जिसमें custom v4 hook प्रत्येक swap पर additional math करता हो (जैसे LDF/rebalancer)।
- कम-से-कम एक execution path जिसमें threshold crossings के दौरान rounding swap initiator को लाभ पहुँचाती हो।
- कई swaps को atomically repeat करने की क्षमता (temporary float उपलब्ध कराने और gas को amortize करने के लिए flash loans ideal हैं)।

## Practical attack methodology

1) Hooks वाले candidate pools की पहचान करें
- v4 pools enumerate करें और जाँचें कि PoolKey.hooks != address(0) है।
- Callback methods के लिए hook bytecode/ABI inspect करें: beforeSwap/afterSwap और कोई भी custom rebalancing methods।
- ऐसी math खोजें जो: liquidity से divide करती हो, token amounts और liquidity के बीच convert करती हो, या BalanceDelta को rounding के साथ aggregate करती हो।

2) Hook की math और thresholds को model करें
- Hook के liquidity/redistribution formula को recreate करें: inputs में आमतौर पर sqrtPriceX96, tickLower/Upper, currentTick, fee tier और net liquidity शामिल होते हैं।
- Threshold/step functions map करें: ticks, bucket boundaries या LDF breakpoints। निर्धारित करें कि प्रत्येक boundary के किस side पर delta round होती है।
- उन स्थानों की पहचान करें जहाँ uint256/int256 के बीच casts होते हैं, SafeCast का उपयोग होता है, या implicit floor के साथ mulDiv पर निर्भरता होती है।

3) Boundaries cross करने के लिए exact‑input swaps calibrate करें
- Foundry/Hardhat simulations का उपयोग करके उस minimal Δin की गणना करें जो price को boundary के ठीक पार ले जाए और hook की branch trigger करे।
- Verify करें कि afterSwap settlement caller को cost से अधिक credit करती है, जिससे hook की accounting में positive BalanceDelta या credit बचता है।
- Credit accumulate करने के लिए swaps repeat करें; फिर hook का withdrawal/settlement path call करें।

v4 में swap loop को PoolManager unlock callback से run करना आवश्यक है; negative `amountSpecified` exact input को दर्शाता है, और `sqrtPriceLimitX96` valid range के अंदर strictly होना चाहिए। Zero price limit revert करता है, इसलिए नीचे दिया गया pseudocode zero-for-one swap के लिए lower bound का उपयोग करता है।<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
exactInput को calibrate करना
- Core TickMath से target compute करें: sqrtP_next = sqrtP_current × 1.0001^(Δtick) real-value terms में; Q64.96 result को TickMath द्वारा round किया जाता है।<sup>[[13]](#references)</sup>
- Q64.96-aware formula का उपयोग करके token0 (zero-for-one) input का approximation निकालें: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)। Core routine के direction-specific rounding से match करें।<sup>[[12]](#references)</sup>
- Boundary के आसपास Δin को ±1 wei से adjust करके वह branch खोजें जहाँ hook आपके पक्ष में round करता है।

4) Flash loans से amplify करें
- कई iterations को atomically चलाने के लिए बड़ा notional (जैसे, 3M USDT या 2000 WETH) borrow करें।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Calibrated swap loop execute करें, फिर flash loan callback के भीतर withdraw करके repay करें।

Aave V3 flash loan का skeleton
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
- यदि hooks multiple chains पर deploy किए गए हैं, तो हर chain के लिए वही calibration दोहराएँ।
- Bunni incident में flash-loan liquidity और bridge routes chain के अनुसार अलग थे, इसलिए analysis को reproduce करते समय उन chain-specific constraints को ध्यान में रखें।<sup>[[1]](#references)[[2]](#references)</sup>

## Hook math के सामान्य मूल कारण

- Mixed rounding semantics: mulDiv floor करता है, जबकि बाद के paths प्रभावी रूप से round up करते हैं; या token/liquidity के बीच conversions में अलग-अलग rounding लागू होती है।
- Tick alignment errors: एक path में unrounded ticks का उपयोग और दूसरे में tick-spaced rounding।
- Settlement के दौरान int256 और uint256 के बीच conversion करते समय BalanceDelta sign/overflow issues।
- Q64.96 conversions (sqrtPriceX96) में precision loss, जिसका reverse mapping में समान रूप से समाधान नहीं किया गया।
- Accumulation pathways: प्रत्येक swap के remainders को credits के रूप में track किया जाता है, जिन्हें caller withdraw कर सकता है, बजाय इसके कि उन्हें burn किया जाए या zero-sum रखा जाए।

## Custom accounting और delta amplification

- Uniswap v4 custom accounting hooks को ऐसे deltas return करने देता है, जो caller द्वारा owed/received राशि को सीधे adjust करते हैं। यदि hook internally credits track करता है, तो rounding residue अंतिम settlement होने से **पहले** कई छोटे operations के दौरान accumulate हो सकता है।<sup>[[4]](#references)</sup>
- यदि hook एक compatible withdrawal path expose करता है, तो attacker उसी PoolManager unlock callback के भीतर `swap → withdraw → swap` को alternate कर सकता है। इससे hook थोड़ी अलग state पर deltas को फिर से compute करने के लिए मजबूर होता है, जबकि balances unlock settle होने तक pending रहते हैं।<sup>[[4]](#references)[[10]](#references)</sup>
- Hooks की समीक्षा करते समय हमेशा trace करें कि BalanceDelta/HookDelta कैसे produce और settle होता है। एक branch में single biased rounding, जब deltas को बार-बार re-compute किया जाता है, तो compounding credit बन सकता है।

## Defensive guidance

- Differential testing: high-precision rational arithmetic का उपयोग करके hook की math को reference implementation के विरुद्ध mirror करें और equality या bounded error assert करें, जो हमेशा adversarial हो (कभी भी caller के पक्ष में favorable न हो)।
- Invariant/property tests:
- Swap paths और hook adjustments में deltas (tokens, liquidity) का sum fees को छोड़कर value को conserve करना चाहिए।
- Repeated exactInput iterations के दौरान किसी भी path को swap initiator के लिए positive net credit create नहीं करना चाहिए।
- ±1 wei inputs के आसपास exactInput/exactOutput दोनों के लिए threshold/tick boundary tests।
- Rounding policy: ऐसे centralized rounding helpers बनाएँ जो हमेशा user के विरुद्ध round करें; inconsistent casts और implicit floors को समाप्त करें।
- Settlement sinks: unavoidable rounding residue को protocol treasury में accumulate करें या burn करें; इसे कभी भी msg.sender को attribute न करें।
- Rate-limits/guardrails: rebalancing triggers के लिए minimum swap sizes; यदि deltas sub-wei हों तो rebalances disable करें; expected ranges के विरुद्ध deltas का sanity-check करें।
- Hook callbacks की holistic समीक्षा करें: beforeSwap/afterSwap और before/after liquidity changes को tick alignment और delta rounding पर सहमत होना चाहिए।

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2, एक Uniswap v4 hook जो token density और total-liquidity estimates compute करने के लिए Liquidity Density Function (LDF) का उपयोग करता है।<sup>[[1]](#references)[[2]](#references)</sup>
- Affected pools: Ethereum पर USDC/USDT और Unichain पर weETH/ETH, जिनकी कुल राशि लगभग $8.4M थी।<sup>[[1]](#references)</sup>
- Step 1 (price push): attacker ने ~3M USDT flash-borrow किया और tick को ~5000 तक push करने के लिए swap किया, जिससे **active** USDC balance घटकर ~28 wei रह गया।<sup>[[1]](#references)</sup>
- Step 2 (rounding drain): 44 tiny withdrawals ने `BunniHubLogic::withdraw()` में floor rounding का exploit किया और active USDC balance को 28 wei से घटाकर 4 wei (-85.7%) कर दिया, जबकि LP shares का केवल बहुत छोटा हिस्सा burn हुआ। Total liquidity ~84.4% घट गई।<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (liquidity rebound sandwich): एक large swap ने tick को ~839,189 तक move किया (1 USDC ≈ 2.77e36 USDT)। Liquidity estimates flip हुए और ~16.8% बढ़ गए, जिससे एक sandwich संभव हुआ जिसमें attacker ने inflated price पर वापस swap किया और profit के साथ exit किया।<sup>[[1]](#references)</sup>
- Post-mortem में पहचाना गया fix: idle-balance update को **ऊपर की ओर round** करने के लिए बदलें, ताकि repeated micro-withdrawals pool के active balance को नीचे की ओर ratchet न कर सकें।<sup>[[1]](#references)</sup>

Simplified vulnerable line (और post‑mortem fix)।<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- क्या pool non-zero hooks address का उपयोग करता है? कौन से callbacks enabled हैं?
- क्या custom math का उपयोग करके per-swap redistributions/rebalances होते हैं? क्या कोई tick/threshold logic है?
- divisions/mulDiv, Q64.96 conversions या SafeCast कहाँ उपयोग किए गए हैं? क्या rounding semantics globally consistent हैं?
- क्या आप ऐसा Δin बना सकते हैं जो किसी boundary को मुश्किल से पार करे और favorable rounding branch दे? दोनों directions और exactInput तथा exactOutput, दोनों का परीक्षण करें।
- क्या hook per-caller credits या deltas track करता है जिन्हें बाद में withdraw किया जा सकता है? सुनिश्चित करें कि residue neutralized हो।

## References

- [1] [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
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
