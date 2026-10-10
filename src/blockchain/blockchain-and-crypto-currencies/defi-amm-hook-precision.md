# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

यह पेज Uniswap v4-शैली के DEXes के विरुद्ध DeFi/AMM exploitation techniques के एक वर्ग का दस्तावेज़ीकरण करता है, जो custom hooks के ज़रिए core math का विस्तार करते हैं। Bunni V2 की एक घटना इससे जुड़ी विफलता दिखाती है: withdrawal accounting में rounding-direction bug के कारण active liquidity कम आंकी गई, और बाद के swap ने एक लाभदायक sandwich में उस कम आकलन को उजागर कर दिया।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

मुख्य विचार: यदि कोई hook ऐसा अतिरिक्त accounting लागू करता है जो fixed-point math, tick rounding और threshold logic पर निर्भर है, तो attacker ऐसे exact-input swaps तैयार कर सकता है जो विशिष्ट thresholds को पार करें, ताकि rounding की विसंगतियाँ उसके पक्ष में जमा हों। इस pattern को दोहराने और फिर बढ़ी हुई balance को निकालने से लाभ प्राप्त होता है, जिसे अक्सर flash loan से वित्तपोषित किया जाता है।

## पृष्ठभूमि: Uniswap v4 hooks और swap flow

- Hooks ऐसे contracts हैं जिन्हें PoolManager, lifecycle के खास बिंदुओं पर कॉल करता है (उदाहरण के लिए, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate)।<sup>[[4]](#references)</sup>
- Pools को PoolKey के साथ initialize किया जाता है, जिसमें hook contract शामिल होता है। Non-zero hook address उस pool के लिए चुने गए callbacks को सक्षम करता है।<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks **custom deltas** लौटा सकते हैं, जो swap या liquidity action के अंतिम balance changes को संशोधित करते हैं (custom accounting)। ये deltas call के अंत में net balances के रूप में settle होते हैं, इसलिए settlement से पहले hook math में rounding की कोई भी त्रुटि जमा होती रहती है।<sup>[[4]](#references)</sup>
- Core math में sqrtPriceX96 जैसे fixed-point formats (जैसे Q64.96) और 1.0001^tick का उपयोग करने वाली tick arithmetic शामिल हैं। Drift से बचने के लिए, इनके ऊपर की गई किसी भी custom math को rounding semantics से सावधानीपूर्वक मेल खाना चाहिए।<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps exactInput या exactOutput हो सकते हैं। v3/v4 में price ticks के साथ आगे बढ़ता है; tick boundary पार करने से range liquidity सक्रिय/निष्क्रिय हो सकती है। Hooks, threshold/tick crossings पर अतिरिक्त logic लागू कर सकते हैं।<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold-crossing precision/rounding drift

Custom hooks में एक आम vulnerable pattern:

1. Hook, integer division, mulDiv या fixed-point conversions का उपयोग करके हर swap पर liquidity या balance deltas की गणना करता है (उदाहरण के लिए, sqrtPrice और tick ranges का उपयोग करके token ↔ liquidity conversion)।
2. Threshold logic (उदाहरण के लिए, rebalancing, stepwise redistribution या per-range activation) तब trigger होती है जब swap का आकार या price movement किसी आंतरिक boundary को पार करता है।
3. Forward calculation और settlement path में rounding असंगत तरीके से लागू होती है (उदाहरण के लिए, zero की ओर truncation, floor बनाम ceil)। छोटी विसंगतियाँ रद्द नहीं होतीं, बल्कि caller को credit देती हैं।
4. उन boundaries को पार करने के लिए ठीक-ठीक आकार दिए गए exact-input swaps, बार-बार positive rounding remainder को हासिल करते हैं। Attacker बाद में जमा हुआ credit निकाल लेता है।

Attack की पूर्वशर्तें
- ऐसा pool जो custom v4 hook का उपयोग करता हो और हर swap पर अतिरिक्त math करता हो (उदाहरण के लिए, LDF/rebalancer)।
- कम-से-कम एक ऐसा execution path जहाँ threshold crossings के दौरान rounding, swap initiator को लाभ पहुँचाती हो।
- कई swaps को atomically दोहराने की क्षमता (अस्थायी float उपलब्ध कराने और gas amortize करने के लिए flash loans आदर्श हैं)।

## व्यावहारिक attack methodology

1) Hooks वाले candidate pools पहचानें
- v4 pools की सूची बनाएँ और जाँचें कि PoolKey.hooks != address(0) है।
- Callbacks के लिए hook bytecode/ABI की जाँच करें: beforeSwap/afterSwap और कोई भी custom rebalancing methods।
- ऐसी math खोजें जो: liquidity से divide करती हो, token amounts और liquidity के बीच conversion करती हो, या rounding के साथ BalanceDelta को aggregate करती हो।

2) Hook की math और thresholds को model करें
- Hook के liquidity/redistribution formula को दोबारा बनाएँ: inputs में आम तौर पर sqrtPriceX96, tickLower/Upper, currentTick, fee tier और net liquidity शामिल होते हैं।
- Threshold/step functions का मानचित्र बनाएँ: ticks, bucket boundaries या LDF breakpoints। तय करें कि हर boundary के किस ओर delta round होता है।
- उन जगहों को पहचानें जहाँ conversions uint256/int256 के बीच cast करती हैं, SafeCast का उपयोग करती हैं, या implicit floor के साथ mulDiv पर निर्भर करती हैं।

3) Boundaries पार करने के लिए exact-input swaps calibrate करें
- किसी boundary के ठीक पार price ले जाने और hook की branch trigger करने के लिए आवश्यक न्यूनतम Δin की गणना Foundry/Hardhat simulations से करें।
- सत्यापित करें कि afterSwap settlement caller को लागत से अधिक credit देती है, जिससे positive BalanceDelta बचता है या hook के accounting में credit जमा होता है।
- Credit जमा करने के लिए swaps दोहराएँ; फिर hook का withdrawal/settlement path कॉल करें।

v4 में, swap loop को PoolManager unlock callback से चलाना होता है; negative `amountSpecified` exact input दर्शाता है, और `sqrtPriceLimitX96` valid range के भीतर होना चाहिए। Zero price limit पर revert होता है, इसलिए नीचे दिए गए pseudocode में zero-for-one swap के लिए lower bound का उपयोग किया गया है।<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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

exactInput को calibrate करना
- core TickMath से target की गणना करें: वास्तविक मानों में sqrtP_next = sqrtP_current × 1.0001^(Δtick); Q64.96 परिणाम को TickMath round करता है।<sup>[[13]](#references)</sup>
- Q64.96-aware formula से token0 (zero-for-one) input का अनुमान लगाएँ: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)। core routine की direction-specific rounding से मेल करें।<sup>[[12]](#references)</sup>
- उस branch को खोजने के लिए, जहाँ hook आपके पक्ष में round करे, सीमा के आसपास Δin को ±1 wei से adjust करें।

4) flash loans से प्रभाव बढ़ाएँ
- एक साथ कई iterations चलाने के लिए बड़ा notional उधार लें (जैसे, 3M USDT या 2000 WETH)।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- calibrated swap loop execute करें, फिर flash loan callback के भीतर funds निकालें और loan चुकाएँ।

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
- यदि hooks कई chains पर deploy किए गए हैं, तो प्रत्येक chain पर यही calibration दोहराएँ।
- Bunni incident में flash-loan liquidity और bridge routes हर chain पर अलग थे, इसलिए analysis दोहराते समय उन chain-specific सीमाओं का ध्यान रखें।<sup>[[1]](#references)[[2]](#references)</sup>

## Common root causes in hook math

- Rounding semantics का मिश्रण: mulDiv नीचे की ओर round करता है, जबकि बाद के paths प्रभावी रूप से ऊपर की ओर round करते हैं; या token/liquidity के बीच conversions में अलग-अलग rounding लागू होती है।
- Tick alignment की त्रुटियाँ: एक path में unrounded ticks का उपयोग करना और दूसरे में tick-spaced rounding करना।
- Settlement के दौरान int256 और uint256 के बीच conversion करते समय BalanceDelta के sign/overflow की समस्याएँ।
- Q64.96 conversions (sqrtPriceX96) में precision loss, जो reverse mapping में प्रतिबिंबित नहीं होता।
- Accumulation pathways: per-swap remainders को credits के रूप में track करना, जिन्हें caller withdraw कर सकता है, बजाय उन्हें burn करने या zero-sum रखने के।

## Custom accounting & delta amplification

- Uniswap v4 custom accounting hooks को ऐसे deltas लौटाने देता है जो सीधे caller के देय/प्राप्य मूल्य को समायोजित करते हैं। यदि hook आंतरिक रूप से credits track करता है, तो अंतिम settlement होने से **पहले** कई छोटे operations में rounding residue जमा हो सकता है।<sup>[[4]](#references)</sup>
- यदि hook में संगत withdrawal path उपलब्ध है, तो attacker उसी PoolManager unlock callback के भीतर `swap → withdraw → swap` को बारी-बारी से चला सकता है। इससे hook को थोड़ी बदली हुई state पर deltas फिर से compute करने के लिए मजबूर किया जा सकता है, जबकि unlock के settle होने तक balances लंबित रहते हैं।<sup>[[4]](#references)[[10]](#references)</sup>
- Hooks की समीक्षा करते समय हमेशा पता लगाएँ कि BalanceDelta/HookDelta कैसे बनता और settle होता है। किसी एक branch में biased rounding, deltas बार-बार recompute होने पर बढ़ते हुए credit में बदल सकती है।

## Defensive guidance

- Differential testing: hook के math की तुलना high-precision rational arithmetic वाली reference implementation से करें और equality या ऐसी bounded error सुनिश्चित करें जो हमेशा caller के विरुद्ध हो (कभी उसके पक्ष में नहीं)।
- Invariant/property tests:
  - Swap paths और hook adjustments में tokens तथा liquidity के deltas का योग fees को छोड़कर value को बनाए रखना चाहिए।
  - बार-बार exactInput iterations के दौरान किसी भी path से swap initiator के लिए positive net credit नहीं बनना चाहिए।
  - exactInput/exactOutput, दोनों के लिए ±1 wei inputs के आसपास threshold/tick boundary tests करें।
- Rounding policy: ऐसे rounding helpers को केंद्रीकृत करें जो हमेशा user के विरुद्ध round करें; असंगत casts और implicit floors हटाएँ।
- Settlement sinks: अपरिहार्य rounding residue को protocol treasury में जमा करें या burn करें; इसे कभी msg.sender के नाम न करें।
- Rate-limits/guardrails: rebalancing triggers के लिए minimum swap sizes तय करें; deltas sub-wei हों तो rebalances बंद करें; deltas को अपेक्षित ranges के विरुद्ध sanity-check करें।
- Hook callbacks की समग्र समीक्षा करें: beforeSwap/afterSwap और liquidity changes से पहले/बाद के callbacks में tick alignment और delta rounding एकसमान होने चाहिए।

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2, Uniswap v4 hook, जो token density और total-liquidity estimates compute करने के लिए Liquidity Density Function (LDF) का उपयोग करता है।<sup>[[1]](#references)[[2]](#references)</sup>
- प्रभावित pools: Ethereum पर USDC/USDT और Unichain पर weETH/ETH, जिनकी कुल राशि लगभग $8.4M थी।<sup>[[1]](#references)</sup>
- Step 1 (price push): attacker ने ~3M USDT flash-borrow करके swap किया और tick को ~5000 तक पहुँचाया, जिससे **सक्रिय** USDC balance घटकर ~28 wei रह गया।<sup>[[1]](#references)</sup>
- Step 2 (rounding drain): 44 छोटे withdrawals ने `BunniHubLogic::withdraw()` में floor rounding का फायदा उठाकर active USDC balance को 28 wei से घटाकर 4 wei (-85.7%) कर दिया, जबकि LP shares का केवल एक छोटा अंश burn हुआ। कुल liquidity ~84.4% घट गई।<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (liquidity rebound sandwich): एक बड़े swap ने tick को ~839,189 (1 USDC ≈ 2.77e36 USDT) तक पहुँचा दिया। Liquidity estimates पलटकर ~16.8% बढ़ गए, जिससे sandwich संभव हुआ: attacker ने बढ़ी हुई कीमत पर वापस swap किया और मुनाफ़े के साथ बाहर निकला।<sup>[[1]](#references)</sup>
- Post-mortem में पहचाना गया fix: idle-balance update को **ऊपर की ओर** round करने के लिए बदलें, ताकि बार-बार होने वाले micro-withdrawals pool के active balance को लगातार नीचे न धकेलें।<sup>[[1]](#references)</sup>

कमज़ोर line का सरलीकृत रूप (और post-mortem fix)।<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## जांच की चेकलिस्ट

- क्या pool में non-zero hooks address का उपयोग होता है? कौन-से callbacks enabled हैं?
- क्या हर swap पर custom math का उपयोग करके redistribution/rebalance होता है? क्या कोई tick/threshold logic है?
- divisions/mulDiv, Q64.96 conversions या SafeCast का उपयोग कहाँ होता है? क्या rounding semantics हर जगह एकसमान हैं?
- क्या आप ऐसा Δin बना सकते हैं जो मुश्किल से किसी boundary को पार करे और rounding की अनुकूल branch दे? दोनों दिशाओं और exactInput तथा exactOutput—दोनों को टेस्ट करें।
- क्या hook per-caller credits या deltas track करता है, जिन्हें बाद में withdraw किया जा सकता है? सुनिश्चित करें कि residue neutralize हो जाए।

## References

- [1] [Bunni Exploit की घटना के बाद का विश्लेषण (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: पूरी Hack का विश्लेषण](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: Liquidity की खामी से $8.3M की निकासी (सारांश)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 की पृष्ठभूमि (QuillAudits का शोध)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 core में Liquidity की कार्यप्रणाली](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 core में Swap की कार्यप्रणाली](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks और सुरक्षा संबंधी विचार](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
