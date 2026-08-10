# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

Bu sayfa, core math işlemlerini custom hook'larla genişleten Uniswap v4 tarzı DEX'lere karşı gerçekleştirilen bir DeFi/AMM exploitation teknikleri sınıfını belgeler. Bir Bunni V2 olayı, ilgili bir hatayı gösterir: withdrawal accounting'deki rounding-direction bug, active liquidity miktarını olduğundan düşük gösterdi ve daha sonraki bir swap, bu düşük tahmini kârlı bir sandwich işlemiyle açığa çıkardı.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Temel fikir: Bir hook, fixed-point math, tick rounding ve threshold logic'e bağlı ek accounting işlemleri uyguluyorsa saldırgan, belirli threshold'ları geçecek exact-input swap'ler oluşturarak rounding discrepancies'lerin kendi lehine birikmesini sağlayabilir. Bu pattern tekrarlandıktan ve ardından şişirilmiş balance çekildikten sonra kâr elde edilir; bu işlem çoğunlukla bir flash loan ile finanse edilir.

## Background: Uniswap v4 hooks and swap flow

- Hooks, PoolManager'ın belirli lifecycle noktalarında çağırdığı contract'lardır (ör. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pool'lar, hook contract'ını içeren bir PoolKey ile initialize edilir. Sıfır olmayan bir hook adresi, bu pool için seçilen callback'leri etkinleştirir.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks, bir swap veya liquidity action'ın final balance değişikliklerini değiştiren **custom deltas** döndürebilir (custom accounting). Bu delta'lar call sonunda net balance'lar olarak settle edilir; dolayısıyla hook math içindeki herhangi bir rounding error settlement öncesinde birikir.<sup>[[4]](#references)</sup>
- Core math, sqrtPriceX96 için Q64.96 gibi fixed-point format'lar ve 1.0001^tick kullanan tick arithmetic kullanır. Üzerine eklenen herhangi bir custom math, invariant drift'i önlemek için rounding semantics ile dikkatle eşleşmelidir.<sup>[[12]](#references)[[13]](#references)</sup>
- Swap'ler exactInput veya exactOutput olabilir. v3/v4'te price tick'ler boyunca hareket eder; bir tick boundary'nin geçilmesi range liquidity'yi etkinleştirebilir/devre dışı bırakabilir. Hooks, threshold/tick crossing'leri üzerinde ek logic uygulayabilir.<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Custom hook'larda tipik bir vulnerable pattern:

1. Hook, integer division, mulDiv veya fixed-point conversion'lar kullanarak swap başına liquidity veya balance delta'larını hesaplar (ör. sqrtPrice ve tick range'leri kullanarak token ↔ liquidity dönüşümü).
2. Threshold logic (ör. rebalancing, stepwise redistribution veya per-range activation), swap size veya price movement internal bir boundary'yi geçtiğinde tetiklenir.
3. Rounding, forward calculation ile settlement path arasında tutarsız uygulanır (ör. zero'ya doğru truncation, floor ile ceil arasındaki fark). Küçük discrepancies'ler birbirini götürmez ve bunun yerine caller'ı credit'ler.
4. Bu boundary'leri geçmek üzere hassas şekilde boyutlandırılmış exact-input swap'ler, pozitif rounding remainder'ını tekrar tekrar toplar. Saldırgan daha sonra biriken credit'i çeker.

Attack preconditions
- Her swap'te ek math gerçekleştiren custom v4 hook kullanan bir pool (ör. bir LDF/rebalancer).
- Threshold crossing'leri boyunca rounding'in swap initiator'ına fayda sağladığı en az bir execution path.
- Birçok swap'i atomic olarak tekrar edebilme imkânı (geçici float sağlamak ve gas maliyetini amorti etmek için flash loan'lar idealdir).

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 pool'larını enumerate edin ve PoolKey.hooks != address(0) olduğunu kontrol edin.
- Hook bytecode/ABI'sini callback'ler için inceleyin: beforeSwap/afterSwap ve custom rebalancing method'ları.
- Şunları yapan math işlemlerini arayın: liquidity'ye bölme, token amount'ları ile liquidity arasında dönüşüm yapma veya BalanceDelta'yı rounding ile aggregate etme.

2) Model the hook’s math and thresholds
- Hook'un liquidity/redistribution formula'sını yeniden oluşturun: input'lar genellikle sqrtPriceX96, tickLower/Upper, currentTick, fee tier ve net liquidity içerir.
- Threshold/step function'larını map'leyin: tick'ler, bucket boundary'leri veya LDF breakpoint'leri. Her boundary'nin hangi tarafında delta'nın round edildiğini belirleyin.
- Conversion'ların uint256/int256 arasında cast edildiği, SafeCast kullanıldığı veya implicit floor içeren mulDiv'ye güvenildiği noktaları belirleyin.

3) Calibrate exact‑input swaps to cross boundaries
- Bir boundary'yi geçerek hook branch'ini tetiklemek için gereken minimum Δin miktarını hesaplamak üzere Foundry/Hardhat simulation'ları kullanın.
- afterSwap settlement'ın caller'a maliyetten daha fazlasını credit ettiğini ve hook accounting'inde pozitif bir BalanceDelta veya credit bıraktığını doğrulayın.
- Credit biriktirmek için swap'leri tekrarlayın; ardından hook'un withdrawal/settlement path'ini çağırın.

v4'te swap loop, bir PoolManager unlock callback içinden çalıştırılmalıdır; negative `amountSpecified` exact input anlamına gelir ve `sqrtPriceLimitX96` geçerli aralığın kesinlikle içinde olmalıdır. Sıfır price limit revert eder; bu nedenle aşağıdaki pseudocode, zero-for-one swap için lower bound'u kullanır.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
exactInput'ı kalibre etme
- Hedefi core TickMath ile hesaplayın: gerçek değerler cinsinden sqrtP_next = sqrtP_current × 1.0001^(Δtick); Q64.96 sonucu TickMath tarafından yuvarlanır.<sup>[[13]](#references)</sup>
- Q64.96 farkındalığına sahip formülü kullanarak token0 (zero-for-one) girdisini yaklaşık olarak hesaplayın: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Core rutininin yöne özgü yuvarlamasıyla eşleştirin.<sup>[[12]](#references)</sup>
- Hook'un lehinize yuvarlama yaptığı branch'i bulmak için sınır çevresinde Δin değerini ±1 wei olacak şekilde ayarlayın.

4) Flash loan'lar ile büyütün
- Atomik olarak çok sayıda iterasyon çalıştırmak için büyük bir notional borç alın (ör. 3M USDT veya 2000 WETH).<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Kalibre edilmiş swap döngüsünü çalıştırın, ardından flash loan callback'i içinde çekim yapıp borcu geri ödeyin.

Aave V3 flash loan iskeleti
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
5) Çıkış ve cross-chain replication
- Hook'lar birden fazla chain üzerinde deploy edildiyse, aynı kalibrasyonu her chain için tekrarlayın.
- Bunni incident'ında flash-loan liquidity ve bridge rotaları chain'e göre farklılık gösteriyordu; bu nedenle analizi yeniden üretirken chain'e özgü kısıtları hesaba katın.<sup>[[1]](#references)[[2]](#references)</sup>

## Hook math'te yaygın root cause'lar

- Karışık rounding semantics: mulDiv aşağı yuvarlarken sonraki path'ler fiilen yukarı yuvarlıyor olabilir; veya token/liquidity dönüşümleri farklı rounding uyguluyor olabilir.
- Tick alignment hataları: bir path'te yuvarlanmamış tick'ler, diğerinde ise tick-spaced rounding kullanılması.
- Settlement sırasında int256 ve uint256 arasında dönüşüm yapılırken BalanceDelta sign/overflow sorunları.
- Q64.96 dönüşümlerinde (sqrtPriceX96) oluşan precision loss'un reverse mapping'de yansıtılmaması.
- Accumulation path'leri: her swap'ten kalan remainder'ların, yakılmak veya zero-sum olmak yerine caller tarafından withdraw edilebilir credit'ler olarak takip edilmesi.

## Custom accounting ve delta amplification

- Uniswap v4 custom accounting, hook'ların caller'ın borçlu olduğu veya alacağı miktarı doğrudan ayarlayan delta'lar döndürmesine izin verir. Hook credit'leri dahili olarak takip ediyorsa rounding residue, final settlement gerçekleşmeden önce birçok küçük operation boyunca birikebilir.<sup>[[4]](#references)</sup>
- Hook uyumlu bir withdrawal path sunuyorsa, attacker aynı PoolManager unlock callback içinde `swap → withdraw → swap` işlemlerini dönüşümlü olarak gerçekleştirebilir. Böylece unlock settle edilene kadar bakiyeler pending durumda kalırken hook, delta'ları biraz farklı state üzerinden yeniden hesaplamaya zorlanır.<sup>[[4]](#references)[[10]](#references)</sup>
- Hook'ları review ederken BalanceDelta/HookDelta'nın nasıl üretildiğini ve settle edildiğini her zaman trace edin. Bir branch'teki tek bir biased rounding, delta'lar tekrar tekrar yeniden hesaplandığında compounding credit'e dönüşebilir.

## Defensive guidance

- Differential testing: hook'un math'ini high-precision rational arithmetic kullanan bir reference implementation ile karşılaştırın ve her zaman adversarial olan (caller lehine olmayan) equality veya bounded error koşulunu assert edin.
- Invariant/property test'leri:
- Swap path'leri ve hook adjustment'ları genelindeki delta toplamı (token'lar, liquidity), fee'ler modulo'sunda value'yu korumalıdır.
- Tekrarlanan exactInput iteration'ları boyunca hiçbir path, swap initiator için pozitif net credit oluşturmamalıdır.
- Hem exactInput hem de exactOutput için ±1 wei input'ları etrafında threshold/tick boundary test'leri.
- Rounding policy: her zaman user aleyhine yuvarlayan rounding helper'larını merkezileştirin; tutarsız cast'leri ve implicit floor'ları ortadan kaldırın.
- Settlement sink'leri: kaçınılmaz rounding residue'larını protocol treasury'ye aktarın veya burn edin; bunları hiçbir zaman msg.sender'a atfetmeyin.
- Rate-limit/guardrail'ler: rebalancing trigger'ları için minimum swap size'ları; delta'lar sub-wei ise rebalancing'i devre dışı bırakın; delta'ları beklenen aralıklara karşı sanity-check edin.
- Hook callback'lerini bütünsel olarak review edin: beforeSwap/afterSwap ve liquidity değişikliklerindeki before/after callback'leri tick alignment ve delta rounding konusunda uyumlu olmalıdır.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2; token density ve total-liquidity estimate'lerini hesaplamak için Liquidity Density Function (LDF) kullanan bir Uniswap v4 hook'udur.<sup>[[1]](#references)[[2]](#references)</sup>
- Etkilenen pool'lar: Ethereum üzerindeki USDC/USDT ve Unichain üzerindeki weETH/ETH; toplamda yaklaşık $8.4M.<sup>[[1]](#references)</sup>
- Step 1 (price push): attacker yaklaşık 3M USDT'yi flash-borrow etti ve tick'i yaklaşık 5000'e taşımak için swap gerçekleştirdi; bunun sonucunda **active** USDC balance yaklaşık 28 wei'ye düştü.<sup>[[1]](#references)</sup>
- Step 2 (rounding drain): 44 küçük withdrawal, `BunniHubLogic::withdraw()` içindeki floor rounding'den yararlanarak active USDC balance'ı 28 wei'den 4 wei'ye (-85.7%) düşürdü; bu sırada LP share'lerinin yalnızca küçük bir bölümü burn edildi. Total liquidity yaklaşık %84.4 azaldı.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (liquidity rebound sandwich): büyük bir swap tick'i yaklaşık 839,189'a taşıdı (1 USDC ≈ 2.77e36 USDT). Liquidity estimate'leri tersine dönerek yaklaşık %16.8 arttı; bu da attacker'ın şişirilmiş fiyattan geri swap yapıp profit ile çıkmasını sağlayan bir sandwich'i mümkün kıldı.<sup>[[1]](#references)</sup>
- Post-mortem'de belirlenen fix: idle-balance update'ini **up** yönünde round edecek şekilde değiştirmek; böylece tekrarlanan micro-withdrawal'lar pool'un active balance'ını artık kademeli olarak aşağı çekemez.<sup>[[1]](#references)</sup>

Basitleştirilmiş vulnerable line (ve post-mortem fix).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- Pool sıfır olmayan bir hooks adresi kullanıyor mu? Hangi callback'ler etkin?
- Özel matematik kullanan swap başına redistribution/rebalance işlemleri var mı? Herhangi bir tick/threshold mantığı bulunuyor mu?
- Divisions/mulDiv, Q64.96 conversions veya SafeCast nerede kullanılıyor? Rounding semantiği genel olarak tutarlı mı?
- Bir sınırı zar zor aşan ve avantajlı bir rounding branch üreten Δin oluşturabilir misiniz? Her iki yönü ve hem exactInput hem de exactOutput'u test edin.
- Hook, daha sonra withdraw edilebilecek caller başına credits veya deltas izliyor mu? Residue'nin etkisiz hâle getirildiğinden emin olun.

## References

- [1] [Bunni Exploit Post Mortem (Eyl 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
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
