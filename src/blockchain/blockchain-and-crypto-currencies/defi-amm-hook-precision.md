# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ custom hooks के साथ core math को extend करने वाले Uniswap v4–style DEXes के विरुद्ध DeFi/AMM exploitation techniques की एक श्रेणी का दस्तावेजीकरण करता है। Bunni V2 incident एक संबंधित failure को दर्शाता है: withdrawal accounting में rounding-direction bug के कारण active liquidity कम आंकी गई, और बाद के swap ने इस underestimation को एक profitable sandwich में उजागर कर दिया।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

मुख्य विचार: यदि कोई hook fixed‑point math, tick rounding और threshold logic पर निर्भर अतिरिक्त accounting लागू करता है, तो attacker exact‑input swaps तैयार कर सकता है जो विशेष thresholds को cross करें, ताकि rounding discrepancies उसके पक्ष में जमा होती रहें। इस pattern को दोहराने और फिर inflated balance withdraw करने से profit प्राप्त होता है, जिसे अक्सर flash loan से finance किया जाता है।

## Background: Uniswap v4 hooks and swap flow

- Hooks वे contracts हैं जिन्हें PoolManager विशिष्ट lifecycle points पर call करता है (जैसे beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate)।<sup>[[4]](#references)</sup>
- Pools को एक PoolKey के साथ initialize किया जाता है, जिसमें hook contract शामिल होता है। Non-zero hook address उस pool के लिए चुने गए callbacks को enable करता है।<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks **custom deltas** return कर सकते हैं, जो swap या liquidity action के final balance changes को modify करते हैं (custom accounting)। ये deltas call के अंत में net balances के रूप में settle होते हैं, इसलिए hook math के भीतर होने वाली कोई भी rounding error settlement से पहले accumulate होती रहती है।<sup>[[4]](#references)</sup>
- Core math sqrtPriceX96 के लिए Q64.96 जैसे fixed-point formats और 1.0001^tick के साथ tick arithmetic का उपयोग करता है। Invariant drift से बचने के लिए इसके ऊपर layered किसी भी custom math को rounding semantics से सावधानीपूर्वक match करना चाहिए।<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps exactInput या exactOutput हो सकते हैं। v3/v4 में price ticks के साथ move होती है; किसी tick boundary को cross करने पर range liquidity activate/deactivate हो सकती है। Hooks threshold/tick crossings पर अतिरिक्त logic लागू कर सकते हैं।<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Custom hooks में एक typical vulnerable pattern:

1. Hook integer division, mulDiv या fixed-point conversions का उपयोग करके per-swap liquidity या balance deltas compute करता है (जैसे sqrtPrice और tick ranges के बीच token ↔ liquidity conversion)।
2. Threshold logic (जैसे rebalancing, stepwise redistribution या per-range activation) तब trigger होती है जब swap size या price movement किसी internal boundary को cross करता है।
3. Forward calculation और settlement path के बीच rounding असंगत रूप से लागू की जाती है (जैसे truncation toward zero, floor बनाम ceil)। छोटी discrepancies cancel नहीं होतीं और इसके बजाय caller को credit कर देती हैं।
4. इन boundaries को straddle करने के लिए precisely sized exact-input swaps बार-बार positive rounding remainder को harvest करते हैं। बाद में attacker accumulated credit withdraw करता है।

Attack preconditions
- ऐसा pool जिसमें custom v4 hook प्रत्येक swap पर अतिरिक्त math करता हो (जैसे LDF/rebalancer)।
- कम-से-कम एक execution path जिसमें threshold crossings के दौरान rounding swap initiator को लाभ पहुँचाती हो।
- कई swaps को atomically repeat करने की ability (temporary float उपलब्ध कराने और gas amortize करने के लिए flash loans ideal हैं)।

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 pools enumerate करें और जाँचें कि PoolKey.hooks != address(0) है।
- Callbacks के लिए hook bytecode/ABI inspect करें: beforeSwap/afterSwap और कोई भी custom rebalancing methods।
- ऐसे math की तलाश करें जो: liquidity से divide करती हो, token amounts और liquidity के बीच convert करती हो, या rounding के साथ BalanceDelta aggregate करती हो।

2) Model the hook’s math and thresholds
- Hook का liquidity/redistribution formula recreate करें: inputs में सामान्यतः sqrtPriceX96, tickLower/Upper, currentTick, fee tier और net liquidity शामिल होते हैं।
- Threshold/step functions map करें: ticks, bucket boundaries या LDF breakpoints। Determine करें कि प्रत्येक boundary के किस side पर delta round होती है।
- उन स्थानों की पहचान करें जहाँ uint256/int256 के बीच casts होते हैं, SafeCast का उपयोग होता है या implicit floor के साथ mulDiv पर निर्भरता होती है।

3) Calibrate exact‑input swaps to cross boundaries
- Foundry/Hardhat simulations का उपयोग करके उस minimal Δin को compute करें जो price को boundary के ठीक पार ले जाए और hook की branch को trigger करे।
- Verify करें कि afterSwap settlement caller को cost से अधिक credit करती है, जिससे hook की accounting में positive BalanceDelta या credit बचता है।
- Credit accumulate करने के लिए swaps repeat करें; फिर hook का withdrawal/settlement path call करें।

v4 में swap loop को PoolManager unlock callback से run करना आवश्यक है; negative `amountSpecified` exact input को दर्शाता है, और `sqrtPriceLimitX96` valid range के भीतर strictly होना चाहिए। Zero price limit revert करता है, इसलिए नीचे दिया गया pseudocode zero-for-one swap के लिए lower bound का उपयोग करता है।<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
- core TickMath के साथ target compute करें: वास्तविक-मूल्य terms में sqrtP_next = sqrtP_current × 1.0001^(Δtick); Q64.96 result को TickMath द्वारा round किया जाता है।<sup>[[13]](#references)</sup>
- Q64.96-aware formula का उपयोग करके token0 (zero-for-one) input का approximation निकालें: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)। core routine की direction-specific rounding से match करें।<sup>[[12]](#references)</sup>
- boundary के आसपास Δin को ±1 wei से adjust करें, ताकि वह branch मिले जहाँ hook आपके पक्ष में round करता है।

4) flash loans के साथ Amplify करें
- कई iterations को atomically चलाने के लिए बड़ा notional (जैसे, 3M USDT या 2000 WETH) borrow करें।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- calibrated swap loop execute करें, फिर flash loan callback के भीतर withdraw और repay करें।

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
- यदि hooks multiple chains पर deploy किए गए हैं, तो प्रत्येक chain पर वही calibration दोहराएँ।
- Bunni incident में flash-loan liquidity और bridge routes chain के अनुसार अलग थे, इसलिए analysis को दोहराते समय उन chain-specific constraints को ध्यान में रखें।<sup>[[1]](#references)[[2]](#references)</sup>

## Hook math में सामान्य root causes

- Mixed rounding semantics: `mulDiv` नीचे की ओर round करता है, जबकि बाद के paths प्रभावी रूप से ऊपर की ओर round करते हैं; या token/liquidity के बीच conversions में अलग-अलग rounding लागू होती है।
- Tick alignment errors: एक path में unrounded ticks और दूसरे में tick-spaced rounding का उपयोग करना।
- Settlement के दौरान `int256` और `uint256` के बीच conversion करते समय `BalanceDelta` sign/overflow issues।
- Q64.96 conversions (`sqrtPriceX96`) में precision loss, जो reverse mapping में mirror नहीं होता।
- Accumulation pathways: प्रत्येक swap के remainders को credits के रूप में track करना, जिन्हें caller withdraw कर सकता है, बजाय इसके कि उन्हें burn किया जाए या zero-sum रखा जाए।

## Custom accounting और delta amplification

- Uniswap v4 custom accounting hooks को ऐसे deltas return करने देता है, जो caller द्वारा owed/received राशि को सीधे adjust करते हैं। यदि hook internally credits track करता है, तो rounding residue कई छोटी operations के दौरान accumulate हो सकता है **before** final settlement होता है।<sup>[[4]](#references)</sup>
- यदि hook compatible withdrawal path expose करता है, तो attacker उसी PoolManager unlock callback के भीतर `swap → withdraw → swap` alternate कर सकता है। इससे hook को थोड़ी अलग state पर deltas फिर से compute करने पड़ते हैं, जबकि balances unlock settle होने तक pending रहते हैं।<sup>[[4]](#references)[[10]](#references)</sup>
- Hooks की review करते समय हमेशा trace करें कि `BalanceDelta`/`HookDelta` कैसे produce और settle होता है। एक branch में biased rounding, deltas को बार-बार re-compute किए जाने पर compounding credit में बदल सकती है।

## Defensive guidance

- Differential testing: hook के math को high-precision rational arithmetic वाली reference implementation के विरुद्ध mirror करें और equality या bounded error assert करें, जो हमेशा adversarial हो (caller के लिए कभी favorable न हो)।
- Invariant/property tests:
- Swap paths और hook adjustments में deltas (tokens, liquidity) का sum fees को छोड़कर value conserve करना चाहिए।
- Repeated exactInput iterations में कोई path swap initiator के लिए positive net credit create नहीं करना चाहिए।
- ±1 wei inputs के आसपास threshold/tick boundary tests, दोनों exactInput/exactOutput के लिए।
- Rounding policy: ऐसे centralized rounding helpers बनाएँ जो हमेशा user के विरुद्ध round करें; inconsistent casts और implicit floors समाप्त करें।
- Settlement sinks: unavoidable rounding residue को protocol treasury में accumulate करें या burn करें; इसे कभी `msg.sender` को attribute न करें।
- Rate-limits/guardrails: rebalancing triggers के लिए minimum swap sizes; यदि deltas sub-wei हों तो rebalances disable करें; deltas को expected ranges के विरुद्ध sanity-check करें।
- Hook callbacks की holistic review करें: beforeSwap/afterSwap और before/after liquidity changes को tick alignment और delta rounding पर सहमत होना चाहिए।

## Case study: Bunni V2 (2025-09-02)

- Protocol: Bunni V2, एक Uniswap v4 hook जो token density और total-liquidity estimates compute करने के लिए Liquidity Density Function (LDF) का उपयोग करता है।<sup>[[1]](#references)[[2]](#references)</sup>
- प्रभावित pools: Ethereum पर USDC/USDT और Unichain पर weETH/ETH, जिनकी कुल राशि लगभग $8.4M थी।<sup>[[1]](#references)</sup>
- चरण 1 (price push): attacker ने लगभग 3M USDT flash-borrow किए और tick को लगभग 5000 तक push करने के लिए swap किया, जिससे **active** USDC balance घटकर लगभग 28 wei रह गया।<sup>[[1]](#references)</sup>
- चरण 2 (rounding drain): 44 छोटे withdrawals ने `BunniHubLogic::withdraw()` में floor rounding का exploit करके active USDC balance को 28 wei से घटाकर 4 wei (-85.7%) कर दिया, जबकि LP shares का केवल बहुत छोटा हिस्सा burn हुआ। Total liquidity लगभग 84.4% घट गई।<sup>[[1]](#references)[[2]](#references)</sup>
- चरण 3 (liquidity rebound sandwich): एक बड़े swap ने tick को लगभग 839,189 तक move किया (1 USDC ≈ 2.77e36 USDT)। Liquidity estimates flip हुए और लगभग 16.8% बढ़ गए, जिससे attacker ने inflated price पर वापस swap करके profit के साथ exit करने वाला sandwich किया।<sup>[[1]](#references)</sup>
- Post-mortem में पहचाना गया fix: idle-balance update को **ऊपर की ओर** round करने के लिए बदलें, ताकि repeated micro-withdrawals pool के active balance को नीचे की ओर ratchet न कर सकें।<sup>[[1]](#references)</sup>

सरलीकृत vulnerable line (और post-mortem fix)।<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- क्या pool non-zero hooks address का उपयोग करता है? कौन से callbacks enabled हैं?
- क्या per-swap redistributions/rebalances custom math का उपयोग करते हैं? क्या कोई tick/threshold logic है?
- divisions/mulDiv, Q64.96 conversions या SafeCast कहाँ उपयोग किए गए हैं? क्या rounding semantics globally consistent हैं?
- क्या आप ऐसा Δin बना सकते हैं जो किसी boundary को barely cross करे और favorable rounding branch दे? दोनों directions तथा exactInput और exactOutput, दोनों का परीक्षण करें।
- क्या hook per-caller credits या deltas track करता है जिन्हें बाद में withdraw किया जा सकता है? सुनिश्चित करें कि residue neutralized हो।

## References

- [1] [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: पूर्ण Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: Liquidity Flaw के माध्यम से $8.3M Drained (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 core में Liquidity mechanics](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 core में Swap mechanics](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
