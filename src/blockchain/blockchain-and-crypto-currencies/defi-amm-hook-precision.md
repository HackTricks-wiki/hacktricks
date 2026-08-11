# DeFi/AMM Exploitation: Uniswap v4 Hook Hassasiyet/Yuvarlama İstismarı

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, temel matematiği özel hook'larla genişleten Uniswap v4 tarzı DEX'lere yönelik bir DeFi/AMM exploitation teknikleri sınıfını belgeler. Bir Bunni V2 olayı, ilişkili bir hatayı göstermektedir: withdrawal accounting'deki yuvarlama yönü hatası active liquidity değerini olduğundan düşük gösterdi ve daha sonraki bir swap, bu düşük tahmini kârlı bir sandwich saldırısında açığa çıkardı.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Temel fikir şudur: Bir hook, fixed-point math, tick yuvarlaması ve threshold logic'e bağlı ek accounting uyguluyorsa, saldırgan yuvarlama farklılıklarının kendi lehine birikmesini sağlayacak şekilde belirli threshold'ları geçen exact-input swap'ler oluşturabilir. Bu model tekrarlanıp ardından şişirilmiş balance çekildiğinde kâr elde edilir; işlem genellikle bir flash loan ile finanse edilir.

## Arka plan: Uniswap v4 hook'ları ve swap akışı

- Hook'lar, PoolManager tarafından belirli lifecycle noktalarında çağrılan contract'lardır (ör. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pool'lar, hook contract'ını içeren bir PoolKey ile initialize edilir. Sıfır olmayan bir hook address, bu pool için seçilen callback'leri etkinleştirir.<sup>[[4]](#references)[[14]](#references)</sup>
- Hook'lar, bir swap veya liquidity action'ın nihai balance değişikliklerini değiştiren **custom deltas** döndürebilir (custom accounting). Bu delta'lar call sonunda net balance'lar olarak settle edilir; dolayısıyla hook math içindeki herhangi bir yuvarlama hatası settlement'dan önce birikir.<sup>[[4]](#references)</sup>
- Core math, sqrtPriceX96 için Q64.96 gibi fixed-point format'ları ve 1.0001^tick kullanan tick arithmetic'i kullanır. Üzerine eklenen herhangi bir custom math, invariant drift'i önlemek için yuvarlama semantics'leriyle dikkatle eşleşmelidir.<sup>[[12]](#references)[[13]](#references)</sup>
- Swap'ler exactInput veya exactOutput olabilir. v3/v4'te fiyat tick'ler boyunca hareket eder; bir tick boundary'nin geçilmesi range liquidity'yi etkinleştirebilir/devre dışı bırakabilir. Hook'lar threshold/tick crossing'leri üzerinde ek logic uygulayabilir.<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold-crossing precision/rounding drift

Custom hook'larda yaygın görülen vulnerable pattern:

1. Hook, integer division, mulDiv veya fixed-point conversion'lar kullanarak swap başına liquidity veya balance delta'larını hesaplar (ör. sqrtPrice ve tick range'leri kullanarak token ↔ liquidity dönüşümü).
2. Threshold logic (ör. rebalancing, stepwise redistribution veya per-range activation), bir swap size veya price movement dahili bir boundary'yi geçtiğinde tetiklenir.
3. Forward calculation ile settlement path arasında yuvarlama tutarsız uygulanır (ör. zero'ya doğru truncation, floor ve ceil arasındaki fark). Küçük farklılıklar birbirini götürmez ve bunun yerine caller'a credit verir.
4. Bu boundary'leri aşacak şekilde hassas boyutlandırılmış exact-input swap'ler, pozitif yuvarlama kalanını tekrar tekrar toplar. Saldırgan daha sonra biriken credit'i withdraw eder.

Attack preconditions
- Her swap'te ek math gerçekleştiren custom bir v4 hook kullanan bir pool (ör. bir LDF/rebalancer).
- Threshold crossing'leri boyunca rounding'in swap initiator'ını avantajlı kıldığı en az bir execution path.
- Birçok swap'i atomik olarak tekrarlayabilme (flash loan'lar geçici float sağlamak ve gas maliyetini amorti etmek için idealdir).

## Practical attack methodology

1) Hook kullanan aday pool'ları belirleyin
- v4 pool'larını enumerate edin ve PoolKey.hooks != address(0) olduğunu kontrol edin.
- Hook bytecode/ABI'sini callback'ler için inceleyin: beforeSwap/afterSwap ve custom rebalancing method'ları.
- Şu işlemleri gerçekleştiren math'i arayın: liquidity'ye bölme, token amount'ları ile liquidity arasında dönüşüm yapma veya BalanceDelta'yı yuvarlama ile aggregate etme.

2) Hook math'ini ve threshold'ları modelleyin
- Hook'un liquidity/redistribution formula'sını yeniden oluşturun: input'lar genellikle sqrtPriceX96, tickLower/Upper, currentTick, fee tier ve net liquidity içerir.
- Threshold/step function'larını map edin: tick'ler, bucket boundary'leri veya LDF breakpoint'leri. Delta'nın her boundary'nin hangi tarafına yuvarlandığını belirleyin.
- Dönüşümlerin uint256/int256 arasında cast edildiği, SafeCast kullanıldığı veya implicit floor içeren mulDiv'e güvenildiği noktaları belirleyin.

3) Boundary'leri geçecek exact-input swap'leri kalibre edin
- Fiyatı bir boundary'nin hemen ötesine taşımak ve hook branch'ini tetiklemek için gereken minimum Δin değerini hesaplamak üzere Foundry/Hardhat simulation'ları kullanın.
- afterSwap settlement'ın callera maliyetten daha fazla credit verdiğini ve hook accounting'inde pozitif bir BalanceDelta veya credit bıraktığını doğrulayın.
- Credit biriktirmek için swap'leri tekrarlayın; ardından hook'un withdrawal/settlement path'ini çağırın.

v4'te swap loop'u bir PoolManager unlock callback'inden çalıştırılmalıdır; negatif `amountSpecified` exact input anlamına gelir ve `sqrtPriceLimitX96` geçerli aralığın kesinlikle içinde olmalıdır. Sıfır price limit revert eder; bu nedenle aşağıdaki pseudocode, zero-for-one swap için lower bound'u kullanır.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Example Foundry-style test harness (pseudocode)
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
exactInput'ı Kalibre Etme
- Hedefi core TickMath ile hesaplayın: gerçek değerler cinsinden sqrtP_next = sqrtP_current × 1.0001^(Δtick); Q64.96 sonucu TickMath tarafından yuvarlanır.<sup>[[13]](#references)</sup>
- Q64.96 uyumlu formülü kullanarak token0 (zero-for-one) girişini yaklaşık olarak hesaplayın: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Core rutininin yöne özgü yuvarlamasıyla eşleştirin.<sup>[[12]](#references)</sup>
- Hook'un lehinize yuvarladığı branch'i bulmak için sınır çevresinde Δin değerini ±1 wei olacak şekilde ayarlayın.

4) flash loans ile büyütün
- Atomik olarak çok sayıda iterasyon çalıştırmak için büyük bir notional (ör. 3M USDT veya 2000 WETH) borrow edin.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Calibrated swap loop'u çalıştırın, ardından flash loan callback'i içinde çekim yapıp borcu repay edin.

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
- Hook'lar birden fazla chain üzerinde deploy edildiyse aynı kalibrasyonu her chain için tekrarlayın.
- Bunni incident'ında flash-loan likiditesi ve bridge rotaları chain'e göre farklılık gösteriyordu; bu nedenle analizi yeniden üretirken chain'e özgü kısıtları hesaba katın.<sup>[[1]](#references)[[2]](#references)</sup>

## Hook matematiğinde yaygın kök nedenler

- Karışık rounding semantiği: mulDiv aşağı yuvarlarken sonraki yollar fiilen yukarı yuvarlıyor olabilir; ya da token/liquidity dönüşümleri farklı rounding uyguluyor olabilir.
- Tick hizalama hataları: bir path'te yuvarlanmamış tick'lerin, diğerinde ise tick-spaced rounding'in kullanılması.
- Settlement sırasında int256 ile uint256 arasında dönüşüm yapılırken BalanceDelta işaret/taşma sorunları.
- Q64.96 dönüşümlerinde (sqrtPriceX96) oluşan precision loss'un ters eşlemede yansıtılmaması.
- Birikim yolları: swap başına kalan miktarların, yakılmak veya zero-sum yapılmak yerine caller tarafından çekilebilir credit'ler olarak takip edilmesi.

## Custom accounting ve delta amplification

- Uniswap v4 custom accounting, hook'ların caller'ın borçlu olduğu veya alacağı miktarı doğrudan ayarlayan delta'lar döndürmesine izin verir. Hook dahili olarak credit'leri takip ediyorsa rounding kalıntısı, final settlement gerçekleşmeden **önce** çok sayıda küçük işlem boyunca birikebilir.<sup>[[4]](#references)</sup>
- Hook uyumlu bir withdrawal path sunuyorsa saldırgan, aynı PoolManager unlock callback'i içinde `swap → withdraw → swap` işlemlerini dönüşümlü olarak gerçekleştirebilir. Böylece unlock settlement'ı gerçekleşene kadar bakiyeler pending durumda kalırken hook'u delta'ları biraz farklı state üzerinde yeniden hesaplamaya zorlar.<sup>[[4]](#references)[[10]](#references)</sup>
- Hook'ları incelerken BalanceDelta/HookDelta'nın nasıl üretildiğini ve settle edildiğini her zaman izleyin. Tek bir branch'teki biased rounding, delta'lar tekrar tekrar yeniden hesaplandığında bileşik bir credit'e dönüşebilir.

## Defensive guidance

- Differential testing: hook'un matematiğini high-precision rational arithmetic kullanan bir reference implementation ile karşılaştırın ve her zaman caller lehine olmayan adversarial bir eşitlik veya bounded error doğrulayın.
- Invariant/property testleri:
- Swap path'leri ve hook adjustment'ları boyunca delta'ların (token'lar, liquidity) toplamı, fee'ler dışında value'yu korumalıdır.
- Hiçbir path, tekrarlanan exactInput iterasyonları boyunca swap initiator'ı için pozitif net credit oluşturmamalıdır.
- Hem exactInput hem de exactOutput için ±1 wei input'ları çevresindeki threshold/tick boundary testleri.
- Rounding policy: her zaman user aleyhine yuvarlayan rounding helper'larını merkezileştirin; tutarsız cast'leri ve implicit floor'ları ortadan kaldırın.
- Settlement sink'leri: kaçınılmaz rounding kalıntısını protocol treasury'ye biriktirin veya burn edin; bunu hiçbir zaman msg.sender'a atfetmeyin.
- Rate-limit/guardrail'ler: rebalancing trigger'ları için minimum swap boyutları; delta'lar sub-wei ise rebalances'ı devre dışı bırakın; delta'ları beklenen aralıklara göre sanity-check edin.
- Hook callback'lerini bütünsel olarak inceleyin: beforeSwap/afterSwap ve before/after liquidity change işlemleri tick alignment ve delta rounding konusunda uyumlu olmalıdır.

## Vaka çalışması: Bunni V2 (2025-09-02)

- Protocol: token density ve total-liquidity tahminlerini hesaplamak için Liquidity Density Function (LDF) kullanan bir Uniswap v4 hook'u olan Bunni V2.<sup>[[1]](#references)[[2]](#references)</sup>
- Etkilenen pool'lar: Ethereum üzerindeki USDC/USDT ve Unichain üzerindeki weETH/ETH; toplamda yaklaşık $8.4M.<sup>[[1]](#references)</sup>
- Adım 1 (price push): saldırgan yaklaşık 3M USDT'yi flash-borrow etti ve tick'i yaklaşık 5000'e taşımak için swap yaptı; böylece **active** USDC bakiyesi yaklaşık 28 wei'ye düşürüldü.<sup>[[1]](#references)</sup>
- Adım 2 (rounding drain): 44 küçük withdrawal, `BunniHubLogic::withdraw()` içindeki floor rounding'den yararlanarak active USDC bakiyesini 28 wei'den 4 wei'ye düşürdü (-85.7%); bunun karşılığında LP share'lerinin yalnızca çok küçük bir kısmı yakıldı. Total liquidity yaklaşık %84.4 azaldı.<sup>[[1]](#references)[[2]](#references)</sup>
- Adım 3 (liquidity rebound sandwich): büyük bir swap tick'i yaklaşık 839,189'a taşıdı (1 USDC ≈ 2.77e36 USDT). Liquidity tahminleri tersine dönerek yaklaşık %16.8 arttı; bu da saldırganın şişirilmiş fiyattan geri swap yapıp kârla çıkmasını sağlayan bir sandwich'e imkan verdi.<sup>[[1]](#references)</sup>
- Post-mortem'de belirlenen fix: tekrarlanan micro-withdrawal'ların pool'un active bakiyesini aşağı doğru kademeli olarak azaltmasını önlemek için idle-balance update işlemini **yukarı** yuvarlayacak şekilde değiştirin.<sup>[[1]](#references)</sup>

Basitleştirilmiş vulnerable line (ve post-mortem fix'i).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- Pool non-zero bir hooks adresi kullanıyor mu? Hangi callback'ler etkin?
- Custom math kullanılarak swap başına redistribüsyon/rebalance yapılıyor mu? Herhangi bir tick/threshold mantığı var mı?
- Divisions/mulDiv, Q64.96 dönüşümleri veya SafeCast nerede kullanılıyor? Rounding semantiği genel olarak tutarlı mı?
- Bir sınırı zar zor aşan ve avantajlı bir rounding branch üreten Δin oluşturabilir misiniz? Her iki yönü ve hem exactInput hem de exactOutput'u test edin.
- Hook, daha sonra çekilebilecek caller başına credits veya deltas takip ediyor mu? Residue'un nötralize edildiğinden emin olun.

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
