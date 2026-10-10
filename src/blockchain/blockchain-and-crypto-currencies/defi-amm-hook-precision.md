# DeFi/AMM Exploitation: Uniswap v4 Hook में Precision/Rounding का दुरुपयोग

{{#include ../../banners/hacktricks-training.md}}

यह पेज Uniswap v4-शैली के DEXes के विरुद्ध DeFi/AMM exploitation techniques के एक वर्ग का वर्णन करता है, जो custom hooks के ज़रिए core math को विस्तारित करते हैं। Bunni V2 की एक घटना इसी तरह की विफलता दिखाती है: withdrawal accounting में rounding-direction bug के कारण active liquidity कम आंकी गई, और बाद में एक swap ने लाभदायक sandwich में इस कम आकलन को उजागर कर दिया।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

मुख्य विचार: यदि कोई hook fixed-point math, tick rounding और threshold logic पर निर्भर अतिरिक्त accounting लागू करता है, तो attacker ऐसे exact-input swaps तैयार कर सकता है जो खास thresholds को पार करें, ताकि rounding की विसंगतियाँ उसके पक्ष में जमा हों। इस pattern को दोहराने और फिर बढ़ा हुआ balance withdraw करने से लाभ हासिल होता है; इसके लिए अक्सर flash loan का इस्तेमाल किया जाता है।

## पृष्ठभूमि: Uniswap v4 hooks और swap flow

- Hooks ऐसे contracts होते हैं जिन्हें PoolManager lifecycle के खास बिंदुओं पर call करता है (जैसे beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate)।<sup>[[4]](#references)</sup>
- Pools को PoolKey के साथ initialize किया जाता है, जिसमें hook contract शामिल होता है। Non-zero hook address उस pool के लिए चुने गए callbacks को सक्षम करता है।<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks **custom deltas** लौटा सकते हैं, जो swap या liquidity action के अंतिम balance changes को बदलते हैं (custom accounting)। ये deltas call के अंत में net balances के रूप में settle होते हैं, इसलिए hook math के भीतर rounding की कोई भी त्रुटि settlement से पहले जमा होती जाती है।<sup>[[4]](#references)</sup>
- Core math में sqrtPriceX96 के लिए Q64.96 जैसे fixed-point formats और 1.0001^tick वाला tick arithmetic इस्तेमाल होता है। इसके ऊपर बनाई गई किसी भी custom math को invariant drift से बचने के लिए rounding semantics से सावधानीपूर्वक मेल खाना चाहिए।<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps exactInput या exactOutput हो सकते हैं। v3/v4 में price ticks के साथ आगे बढ़ता है; tick boundary पार करने पर range liquidity सक्रिय या निष्क्रिय हो सकती है। Hooks, threshold/tick crossings पर अतिरिक्त logic लागू कर सकते हैं।<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold-crossing precision/rounding drift

Custom hooks में आमतौर पर दिखने वाला vulnerable pattern:

1. Hook integer division, mulDiv या fixed-point conversions (जैसे sqrtPrice और tick ranges का उपयोग करके token ↔ liquidity रूपांतरण) से प्रति-swap liquidity या balance deltas निकालता है।
2. Threshold logic (जैसे rebalancing, stepwise redistribution या per-range activation) तब trigger होती है जब swap का आकार या price movement किसी आंतरिक boundary को पार करता है।
3. Forward calculation और settlement path में rounding असंगत तरीके से लागू होती है (जैसे zero की ओर truncation, floor बनाम ceil)। छोटी विसंगतियाँ एक-दूसरे को निरस्त नहीं करतीं, बल्कि caller को credit देती हैं।
4. इन boundaries को पार करने के लिए सटीक आकार वाले exact-input swaps बार-बार positive rounding remainder हासिल करते हैं। Attacker बाद में जमा हुआ credit withdraw करता है।

Attack की पूर्वशर्तें
- ऐसा pool जो custom v4 hook का उपयोग करता हो और हर swap पर अतिरिक्त math करता हो (जैसे LDF/rebalancer)।
- कम-से-कम एक execution path, जहाँ threshold crossings के दौरान rounding swap initiator के पक्ष में हो।
- कई swaps को atomically दोहराने की क्षमता (अस्थायी float उपलब्ध कराने और gas लागत को बाँटने के लिए flash loans आदर्श हैं)। 

## व्यावहारिक attack methodology

1) Hooks वाले candidate pools पहचानें
- v4 pools की सूची बनाएँ और जाँचें कि PoolKey.hooks != address(0) है।
- Callbacks के लिए hook bytecode/ABI देखें: beforeSwap/afterSwap और कोई भी custom rebalancing methods।
- ऐसी math खोजें जो liquidity से divide करती हो, token amounts और liquidity के बीच रूपांतरण करती हो, या rounding के साथ BalanceDelta को aggregate करती हो।

2) Hook की math और thresholds को model करें
- Hook का liquidity/redistribution formula दोबारा बनाएँ: inputs में आमतौर पर sqrtPriceX96, tickLower/Upper, currentTick, fee tier और net liquidity शामिल होते हैं।
- Threshold/step functions का नक्शा बनाएँ: ticks, bucket boundaries या LDF breakpoints। पता करें कि हर boundary के किस तरफ delta को round किया जाता है।
- पहचानें कि conversions कहाँ uint256/int256 के बीच cast करती हैं, SafeCast का उपयोग करती हैं या implicit floor वाले mulDiv पर निर्भर करती हैं।

3) Boundaries पार करने के लिए exact-input swaps को calibrate करें
- Foundry/Hardhat simulations का उपयोग करके वह न्यूनतम Δin निकालें जो price को boundary के ठीक पार ले जाकर hook की branch trigger करे।
- पुष्टि करें कि afterSwap settlement caller को लागत से अधिक credit देती है, जिससे positive BalanceDelta या hook की accounting में credit बचता है।
- Credit जमा करने के लिए swaps दोहराएँ; फिर hook का withdrawal/settlement path call करें।

v4 में swap loop को PoolManager unlock callback से चलाना पड़ता है; negative `amountSpecified` exact input दर्शाता है, और `sqrtPriceLimitX96` valid range के भीतर होना चाहिए। Zero price limit revert होता है, इसलिए नीचे दिए गए pseudocode में zero-for-one swap के लिए lower bound का उपयोग किया गया है।<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Foundry-शैली के test harness का उदाहरण (pseudocode)
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

exactInput को कैलिब्रेट करना
- core TickMath से लक्ष्य की गणना करें: वास्तविक मानों में sqrtP_next = sqrtP_current × 1.0001^(Δtick); Q64.96 परिणाम को TickMath राउंड करता है।<sup>[[13]](#references)</sup>
- Q64.96-अनुकूल फ़ॉर्मूले का उपयोग करके token0 (zero-for-one) इनपुट का अनुमान लगाएँ: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)। core रूटीन के दिशा-विशिष्ट राउंडिंग से मेल बैठाएँ।<sup>[[12]](#references)</sup>
- उस ब्रांच को खोजने के लिए सीमा के आसपास Δin को ±1 wei से समायोजित करें जिसमें hook आपके पक्ष में राउंड करे।

4) flash loans से बढ़ाएँ
- कई iterations को atomically चलाने के लिए बड़ी notional राशि (जैसे, 3M USDT या 2000 WETH) उधार लें।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- calibrated swap loop चलाएँ, फिर flash loan callback के भीतर रकम निकालकर चुकाएँ।

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
- यदि hooks कई chains पर deploy किए गए हैं, तो हर chain पर वही calibration दोहराएँ।
- Bunni incident में, flash-loan liquidity और bridge routes हर chain पर अलग थे, इसलिए analysis को दोहराते समय उन chain-specific सीमाओं का ध्यान रखें।<sup>[[1]](#references)[[2]](#references)</sup>

## hook math में सामान्य मूल कारण

- Rounding के मिले-जुले semantics: mulDiv नीचे की ओर round करता है, जबकि बाद के paths प्रभावी रूप से ऊपर की ओर round करते हैं; या token/liquidity के बीच conversions में अलग-अलग rounding लागू होती है।
- Tick alignment की त्रुटियाँ: एक path में unrounded ticks का उपयोग और दूसरे में tick-spaced rounding।
- Settlement के दौरान int256 और uint256 के बीच conversion करते समय BalanceDelta के sign/overflow से जुड़ी समस्याएँ।
- Q64.96 conversions (sqrtPriceX96) में precision loss, जिसका reverse mapping में हिसाब नहीं रखा जाता।
- Accumulation pathways: per-swap remainders को credits के रूप में track किया जाता है, जिन्हें caller withdraw कर सकता है, बजाय इसके कि उन्हें burn किया जाए या zero-sum रखा जाए।

## Custom accounting और delta amplification

- Uniswap v4 का custom accounting hooks को ऐसे deltas लौटाने देता है, जो सीधे caller की देनदारी या उसे मिलने वाली रकम में बदलाव करते हैं। यदि hook आंतरिक रूप से credits track करता है, तो अंतिम settlement से **पहले** कई छोटे operations के दौरान rounding residue जमा हो सकता है।<sup>[[4]](#references)</sup>
- यदि hook में compatible withdrawal path उपलब्ध है, तो attacker उसी PoolManager unlock callback के भीतर `swap → withdraw → swap` को बारी-बारी से कर सकता है। इससे hook को थोड़ी बदली हुई state पर deltas फिर से calculate करने के लिए मजबूर किया जाता है, जबकि unlock के settle होने तक balances pending रहते हैं।<sup>[[4]](#references)[[10]](#references)</sup>
- Hooks की समीक्षा करते समय हमेशा trace करें कि BalanceDelta/HookDelta कैसे बनाया और settle किया जाता है। किसी एक branch में biased rounding, deltas को बार-बार फिर से calculate किए जाने पर compounding credit बन सकता है।

## बचाव संबंधी मार्गदर्शन

- Differential testing: hook के math की तुलना high-precision rational arithmetic वाली reference implementation से करें और equality या ऐसी bounded error सुनिश्चित करें जो हमेशा caller के लिए प्रतिकूल हो, कभी अनुकूल नहीं।
- Invariant/property tests:
  - Swap paths और hook adjustments में tokens तथा liquidity के deltas का योग, fees को छोड़कर, value को conserve करना चाहिए।
  - Repeated exactInput iterations के दौरान किसी भी path से swap initiator के लिए positive net credit नहीं बनना चाहिए।
  - exactInput/exactOutput, दोनों के लिए ±1 wei inputs के आसपास threshold/tick boundary tests करें।
- Rounding policy: ऐसे rounding helpers को केंद्रीकृत करें जो हमेशा user के विरुद्ध round करें; असंगत casts और implicit floors हटाएँ।
- Settlement sinks: अपरिहार्य rounding residue को protocol treasury में जमा करें या burn करें; इसे कभी msg.sender के नाम न करें।
- Rate-limits/guardrails: rebalancing triggers के लिए minimum swap sizes तय करें; यदि deltas sub-wei हों, तो rebalances disable करें; deltas को expected ranges के अनुसार sanity-check करें।
- Hook callbacks की समग्र समीक्षा करें: beforeSwap/afterSwap और liquidity changes से पहले/बाद के callbacks में tick alignment और delta rounding एकसमान होने चाहिए।

## केस स्टडी: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2, एक Uniswap v4 hook जो token density और total-liquidity estimates calculate करने के लिए Liquidity Density Function (LDF) का उपयोग करता है।<sup>[[1]](#references)[[2]](#references)</sup>
- प्रभावित pools: Ethereum पर USDC/USDT और Unichain पर weETH/ETH, जिनकी कुल राशि लगभग $8.4M थी।<sup>[[1]](#references)</sup>
- चरण 1 (price push): attacker ने लगभग 3M USDT flash-borrow किए और tick को लगभग 5000 तक पहुँचाने के लिए swap किया, जिससे **active** USDC balance घटकर लगभग 28 wei रह गया।<sup>[[1]](#references)</sup>
- चरण 2 (rounding drain): 44 छोटे withdrawals ने `BunniHubLogic::withdraw()` में floor rounding का फायदा उठाकर active USDC balance को 28 wei से घटाकर 4 wei (-85.7%) कर दिया, जबकि LP shares का केवल बहुत छोटा हिस्सा burn हुआ। कुल liquidity लगभग 84.4% घट गई।<sup>[[1]](#references)[[2]](#references)</sup>
- चरण 3 (liquidity rebound sandwich): एक बड़े swap ने tick को लगभग 839,189 तक पहुँचा दिया (1 USDC ≈ 2.77e36 USDT)। Liquidity estimates पलटकर लगभग 16.8% बढ़ गए, जिससे sandwich संभव हुआ: attacker ने बढ़ी हुई कीमत पर वापस swap किया और मुनाफे के साथ बाहर निकला।<sup>[[1]](#references)</sup>
- Post-mortem में पहचाना गया fix: idle-balance update को ऊपर की ओर round करने के लिए बदलें, ताकि बार-बार होने वाले micro-withdrawals pool के active balance को लगातार नीचे न धकेलें।<sup>[[1]](#references)</sup>

सरलीकृत vulnerable line (और post-mortem fix)।<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## शिकार की चेकलिस्ट

- क्या pool में non-zero hooks address का इस्तेमाल होता है? कौन-से callbacks enabled हैं?
- क्या हर swap पर custom math का इस्तेमाल करके redistribution/rebalance होता है? क्या कोई tick/threshold logic है?
- divisions/mulDiv, Q64.96 conversions या SafeCast का इस्तेमाल कहाँ होता है? क्या rounding semantics पूरे सिस्टम में एकसमान हैं?
- क्या आप ऐसा Δin बना सकते हैं जो मुश्किल से boundary पार करे और अनुकूल rounding branch दे? दोनों दिशाओं और exactInput तथा exactOutput—दोनों की जाँच करें।
- क्या hook per-caller credits या deltas ट्रैक करता है, जिन्हें बाद में withdraw किया जा सकता है? सुनिश्चित करें कि बचा हुआ residue बेअसर हो जाए।

## References

- [1] [Bunni exploit की घटना के बाद की रिपोर्ट (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 exploit: पूरी hack analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 exploit: liquidity flaw के ज़रिए $8.3M की निकासी (सारांश)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core का whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 की पृष्ठभूमि (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 core में liquidity की कार्यप्रणाली](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 core में swap की कार्यप्रणाली](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks और security से जुड़े विचार](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
