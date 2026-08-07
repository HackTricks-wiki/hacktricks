# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, core math işlemlerini custom hook'larla genişleten Uniswap v4 tarzı DEX'lere yönelik bir DeFi/AMM exploitation tekniği sınıfını belgeler. Bunni V2'de yaşanan yakın tarihli bir olayda, her swap işleminde çalıştırılan bir Liquidity Distribution Function (LDF) içerisindeki rounding/precision flaw kullanılarak saldırganın pozitif credit biriktirmesi ve likiditeyi drain etmesi sağlandı.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

Temel fikir şudur: Bir hook, fixed-point math, tick rounding ve threshold logic'e bağlı ek accounting uyguluyorsa saldırgan, belirli threshold'ları geçecek exact-input swap'ler oluşturarak rounding farklarının kendi lehine birikmesini sağlayabilir. Bu pattern tekrarlandıktan ve şişirilmiş balance withdraw edildikten sonra profit elde edilir; bu işlem çoğunlukla bir flash loan ile finanse edilir.

## Background: Uniswap v4 hooks and swap flow

- Hooks, PoolManager'ın belirli lifecycle noktalarında çağırdığı contract'lardır (ör. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[3]](#references)[[6]](#references)</sup>
- Pool'lar hooks adresini içeren bir PoolKey ile initialize edilir. Adres non-zero ise PoolManager her ilgili operation sırasında callback'leri çalıştırır.<sup>[[6]](#references)</sup>
- Hooks, bir swap veya liquidity action'ın final balance değişikliklerini değiştiren **custom deltas** döndürebilir (custom accounting). Bu delta'lar call sonunda net balance olarak settle edilir; dolayısıyla hook math içerisindeki herhangi bir rounding error settlement öncesinde birikir.<sup>[[5]](#references)</sup>
- Core math, sqrtPriceX96 için Q64.96 gibi fixed-point format'lar ve 1.0001^tick kullanan tick arithmetic kullanır. Üzerine eklenen herhangi bir custom math, invariant drift oluşmasını önlemek için rounding semantics ile dikkatli şekilde eşleşmelidir.<sup>[[4]](#references)[[8]](#references)</sup>
- Swap'ler exactInput veya exactOutput olabilir. v3/v4'te price tick'ler boyunca hareket eder; bir tick boundary'nin geçilmesi range liquidity'yi activate/deactivate edebilir. Hooks, threshold/tick crossing'leri üzerinde ek logic uygulayabilir.<sup>[[5]](#references)</sup>

## Vulnerability archetype: threshold-crossing precision/rounding drift

Custom hook'larda görülen tipik bir vulnerable pattern:

1. Hook, integer division, mulDiv veya fixed-point conversion kullanarak swap başına liquidity veya balance delta'larını hesaplar (ör. sqrtPrice ve tick range'leri kullanarak token ↔ liquidity conversion).
2. Threshold logic (ör. rebalancing, stepwise redistribution veya per-range activation), bir swap size veya price movement internal boundary'yi geçtiğinde tetiklenir.
3. Rounding, forward calculation ile settlement path arasında tutarsız şekilde uygulanır (ör. zero yönünde truncation, floor ve ceil farkı). Küçük farklar birbirini sıfırlamaz; bunun yerine caller'a credit sağlar.
4. Bu boundary'leri straddle edecek şekilde hassas olarak boyutlandırılmış exact-input swap'ler, pozitif rounding remainder'ı tekrar tekrar harvest eder. Saldırgan daha sonra biriken credit'i withdraw eder.

Attack preconditions
- Her swap'te ek math gerçekleştiren custom v4 hook kullanan bir pool (ör. LDF/rebalancer).
- Threshold crossing'leri sırasında rounding'in swap initiator'ına fayda sağladığı en az bir execution path.
- Birçok swap'i atomik olarak tekrarlayabilme imkanı (flash loan'lar geçici float sağlamak ve gas maliyetini amortize etmek için idealdir).

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 pool'larını enumerate edin ve PoolKey.hooks != address(0) olduğunu kontrol edin.
- Hook bytecode/ABI'sini callback'ler için inceleyin: beforeSwap/afterSwap ve custom rebalancing method'ları.
- Şu işlemleri yapan math'i arayın: liquidity'ye bölme, token amount ile liquidity arasında conversion veya BalanceDelta'yı rounding ile aggregate etme.

2) Model the hook’s math and thresholds
- Hook'un liquidity/redistribution formula'sını yeniden oluşturun: input'lar genellikle sqrtPriceX96, tickLower/Upper, currentTick, fee tier ve net liquidity içerir.
- Threshold/step function'larını map'leyin: tick'ler, bucket boundary'leri veya LDF breakpoint'leri. Her boundary'nin hangi tarafında delta'nın round edildiğini belirleyin.
- uint256/int256 arasında conversion yapan cast'leri, SafeCast kullanımını veya implicit floor içeren mulDiv işlemlerini tespit edin.

3) Calibrate exact‑input swaps to cross boundaries
- Bir boundary'yi hemen geçmek ve hook'un branch'ini tetiklemek için gereken minimum Δin değerini hesaplamak üzere Foundry/Hardhat simulation'ları kullanın.
- afterSwap settlement'ın caller'a maliyetten daha fazla credit verdiğini ve hook accounting'inde pozitif bir BalanceDelta veya credit bıraktığını doğrulayın.
- Credit biriktirmek için swap'leri tekrarlayın; ardından hook'un withdrawal/settlement path'ini çağırın.

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
exactInput Kalibrasyonu
- Bir tick adımı için ΔsqrtP'yi hesaplayın: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- v3/v4 formüllerini kullanarak Δin değerini yaklaşık hesaplayın: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Yuvarlama yönünün core math ile eşleştiğinden emin olun.
- Hook'un lehinize yuvarlama yaptığı branch'i bulmak için Δin değerini sınırın etrafında ±1 wei olacak şekilde ayarlayın.

4) Flash loan'larla büyütün
- Atomik olarak birçok iterasyon çalıştırmak için büyük bir notional borç alın (ör. 3M USDT veya 2000 WETH).<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Calibrated swap loop'u çalıştırın, ardından flash loan callback içinde çekim yapıp borcu geri ödeyin.

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
5) Exit ve cross-chain replication
- Hook'lar birden fazla chain üzerinde deploy edildiyse her chain için aynı kalibrasyonu tekrarlayın.
- Gelirleri bridge ile hedef chain'e geri taşıyın ve akışları gizlemek için isteğe bağlı olarak lending protokolleri üzerinden cycle yapın.<sup>[[2]](#references)</sup>

## Hook math'te yaygın kök nedenler

- Karışık rounding semantiği: `mulDiv` floor uygularken sonraki path'ler fiilen round up yapar; veya token/liquidity dönüşümleri farklı rounding uygular.
- Tick hizalama hataları: bir path'te yuvarlanmamış tick'ler, diğerinde ise tick-spaced rounding kullanılması.
- Settlement sırasında `int256` ile `uint256` arasında dönüşüm yapılırken `BalanceDelta` sign/overflow sorunları.
- Q64.96 dönüşümlerinde (`sqrtPriceX96`) oluşan precision loss'un reverse mapping'de aynen yansıtılmaması.
- Accumulation yolları: swap başına kalan miktarların, yakılmak veya zero-sum olmak yerine caller tarafından withdraw edilebilir credit'ler olarak takip edilmesi.

## Custom accounting ve delta amplification

- Uniswap v4 custom accounting, hook'ların caller'ın borçlu veya alacaklı olduğu miktarı doğrudan değiştiren delta'lar döndürmesine izin verir. Hook dahili olarak credit'leri takip ediyorsa rounding residue, final settlement gerçekleşmeden **önce** çok sayıda küçük işlem boyunca birikebilir.<sup>[[5]](#references)</sup>
- Bu durum boundary/threshold abuse'u güçlendirir: attacker aynı tx içinde `swap → withdraw → swap` işlemlerini dönüşümlü olarak çalıştırabilir ve tüm bakiyeler hâlâ pending durumundayken hook'u delta'ları biraz farklı state üzerinde yeniden hesaplamaya zorlayabilir.
- Hook'ları incelerken BalanceDelta/HookDelta'nın nasıl üretildiğini ve settle edildiğini her zaman trace edin. Tek bir branch'teki biased rounding, delta'lar tekrar tekrar hesaplandığında compounding credit'e dönüşebilir.

## Defensive guidance

- Differential testing: hook'un math'ini high-precision rational arithmetic kullanan bir reference implementation ile mirror edin ve equality veya her zaman adversarial olan, caller lehine olmayan bounded error doğrulaması yapın.
- Invariant/property tests:
- Swap path'leri ve hook adjustment'ları genelindeki delta toplamı (token'lar, liquidity), fee'ler hariç value'yu korumalıdır.
- Tekrarlanan exactInput iteration'ları boyunca hiçbir path, swap initiator için pozitif net credit oluşturmamalıdır.
- Hem exactInput hem de exactOutput için ±1 wei input çevresindeki threshold/tick boundary test'leri.
- Rounding policy: her zaman user'a karşı round yapan rounding helper'larını merkezileştirin; tutarsız cast'leri ve implicit floor'ları ortadan kaldırın.
- Settlement sinks: kaçınılmaz rounding residue'yu protocol treasury'de biriktirin veya burn edin; bunu hiçbir zaman `msg.sender`'a atfetmeyin.
- Rate-limits/guardrails: rebalancing trigger'ları için minimum swap size; delta'lar sub-wei ise rebalances'ı devre dışı bırakın; delta'ları beklenen range'lere karşı sanity-check edin.
- Hook callback'lerini bütünsel olarak inceleyin: beforeSwap/afterSwap ve liquidity change öncesi/sonrası işlemleri tick alignment ve delta rounding konusunda uyumlu olmalıdır.

## Case study: Bunni V2 (2025-09-02)

- Protocol: Her swap'ta rebalance yapmak için LDF uygulayan Bunni V2 (Uniswap v4 hook).<sup>[[7]](#references)</sup>
- Etkilenen pool'lar: Ethereum üzerindeki USDC/USDT ve Unichain üzerindeki weETH/ETH; toplam yaklaşık $8.4M.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 1 (price push): attacker yaklaşık 3M USDT flash-borrow etti ve tick'i yaklaşık 5000'e taşımak için swap yaptı; bunun sonucunda **aktif** USDC bakiyesi yaklaşık 28 wei'ye düştü.<sup>[[7]](#references)</sup>
- Step 2 (rounding drain): 44 küçük withdrawal, `BunniHubLogic::withdraw()` içindeki floor rounding'den yararlanarak aktif USDC bakiyesini 28 wei'den 4 wei'ye düşürdü (-85.7%); bu sırada LP share'lerinin yalnızca çok küçük bir kısmı burn edildi. Toplam liquidity yaklaşık %84.4 oranında düşük tahmin edildi.<sup>[[2]](#references)[[7]](#references)</sup>
- Step 3 (liquidity rebound sandwich): büyük bir swap tick'i yaklaşık 839,189'a taşıdı (1 USDC ≈ 2.77e36 USDT). Liquidity tahminleri tersine dönerek yaklaşık %16.8 arttı; bu da attacker'ın şişirilmiş fiyattan geri swap yapıp profit ile exit ettiği bir sandwich'i mümkün kıldı.<sup>[[7]](#references)</sup>
- Post-mortem'de belirlenen fix: tekrarlanan micro-withdrawal'ların pool'un aktif bakiyesini aşağı doğru ratchet etmesini önlemek için idle-balance update'ini **round up** yapacak şekilde değiştirmek.<sup>[[7]](#references)</sup>

Basitleştirilmiş vulnerable line (ve post-mortem fix)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- Pool, zero olmayan bir hooks adresi kullanıyor mu? Hangi callback'ler etkin?
- Custom math kullanılarak swap başına redistribution/rebalance yapılıyor mu? Herhangi bir tick/threshold mantığı var mı?
- Divisions/mulDiv, Q64.96 dönüşümleri veya SafeCast nerede kullanılıyor? Rounding semantiği genel olarak tutarlı mı?
- Bir sınırı kıl payı aşan ve avantajlı bir rounding branch üreten Δin oluşturabilir misiniz? Her iki yönü ve hem exactInput hem de exactOutput durumlarını test edin.
- Hook, caller başına credits veya daha sonra withdraw edilebilecek deltas takip ediyor mu? Residue'un etkisiz hâle getirildiğinden emin olun.

## References

- [1] [Bunni V2 Exploit: Liquidity Flaw nedeniyle $8.3M drained (özet)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
