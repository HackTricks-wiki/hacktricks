# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, core matematiği custom hooks ile genişleten Uniswap v4–tarzı DEX'lere yönelik bir DeFi/AMM suistimali sınıfını belgeler. Bunni V2'deki yakın tarihli bir olay, her swap'ta çalıştırılan bir Liquidity Distribution Function (LDF)’teki yuvarlama/hassasiyet hatasından yararlanarak saldırganın pozitif kredi biriktirmesine ve likiditeyi boşaltmasına imkan verdi.

Ana fikir: Bir hook ek muhasebe uyguluyor ve bu muhasebe fixed‑point math, tick rounding ve eşik mantığına bağlıysa, saldırgan belirli eşikleri geçecek şekilde tam‑girdi (exact‑input) swap'lar tasarlayabilir; böylece yuvarlama tutarsızlıkları lehlerine birikir. Bu deseni tekrarlayıp şişirilmiş bakiyeyi çektiklerinde kâr realize edilir; genellikle flash loan ile finanse edilir.

## Background: Uniswap v4 hooks and swap flow

- Hooks, PoolManager'ın belirli yaşam döngüsü noktalarında çağırdığı kontratlardır (ör. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Pool'lar, hooks adresini içeren bir PoolKey ile initialize edilir. Eğer non‑zero ise, PoolManager her ilgili operasyon için callback'ler yapar.
- Core math, sqrtPriceX96 için Q64.96 gibi fixed‑point formatları ve 1.0001^tick ile tick aritmetiğini kullanır. Üzerine inşa edilen herhangi bir custom math, invariant kaymasını önlemek için yuvarlama semantiğini dikkatle eşlemelidir.
- Swaps exactInput veya exactOutput olabilir. v3/v4'te fiyat tick'ler boyunca hareket eder; bir tick sınırını geçmek range likiditeyi aktive/deaktive edebilir. Hooks eşik/tick geçişlerinde ekstra mantık uygulayabilir.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Custom hook'larda tipik olarak görülen savunmasız pattern:

1. Hook, per‑swap likidite veya bakiye deltasını integer division, mulDiv veya fixed‑point dönüşümleriyle hesaplar (ör. token ↔ liquidity dönüşümleri için sqrtPrice ve tick range'leri kullanmak).
2. Threshold mantığı (ör. rebalancing, adım adım yeniden dağıtım, veya per‑range aktivasyon) bir swap büyüklüğü veya fiyat hareketi iç sınırı geçtiğinde tetiklenir.
3. Yuvarlama, ileri hesaplama ile settlement yolunda tutarsız uygulanır (ör. sıfıra doğru truncation, floor versus ceil). Küçük farklılıklar iptal olmaz, bunun yerine çağırana kredi olarak yazılır.
4. Eşiklerin her iki tarafını da zar zor geçen, tam olarak boyutlandırılmış exact‑input swap'lar pozitif yuvarlama artıklarını tekrar tekrar toplar. Saldırgan daha sonra biriktirilmiş krediyi çekerek kâr sağlar.

Önkoşullar
- Her swap'ta ek math yapan custom v4 hook kullanan bir pool (ör. bir LDF/rebalancer).
- Rounding'ın threshold geçişlerinde swap başlatıcısına fayda sağladığı en az bir yürütme yolu.
- Birçok swap'ı atomik olarak tekrar edebilme yeteneği (flash loans geçici float sağlamak ve gas'ı amorti etmek için idealdir).

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 pool'ları enumerate edip PoolKey.hooks != address(0) olup olmadığını kontrol et.
- Hook bytecode/ABI'sini beforeSwap/afterSwap ve herhangi bir custom rebalancing method'u için incele.
- Şunu arayın: likiditeye bölme yapan, token miktarları ile likidite arasında dönüşüm yapan veya BalanceDelta'ları yuvarlama ile toplayan math.

2) Model the hook’s math and thresholds
- Hook'un likidite/yeniden dağıtım formülünü yeniden yarat: girdiler tipik olarak sqrtPriceX96, tickLower/Upper, currentTick, fee tier ve net likidite içerir.
- Eşik/adım fonksiyonlarını haritalandır: tick'ler, bucket boundary'leri veya LDF kırılma noktaları. Her boundary'nin hangi tarafında delta'nın nasıl yuvarlandığını belirle.
- Nerelerde dönüşümlerin uint256/int256 arasında cast edildiğini, SafeCast kullanıldığını veya implisit floor ile mulDiv'e rely edildiğini tespit et.

3) Calibrate exact‑input swaps to cross boundaries
- Minimal Δin'i hesaplamak için Foundry/Hardhat simülasyonları kullan; fiyatı tam olarak bir boundary'nin ötesine taşımak ve hook branch'ini tetiklemek gerekir.
- afterSwap settlement'ın, maliyetten daha fazla caller'ı krediye yazdığını doğrula; pozitif bir BalanceDelta veya hook muhasebesinde kredi bırakmalı.
- Krediyi biriktirmek için swap'ları tekrar et; sonra hook'un withdrawal/settlement yolunu çağır.

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
exactInput'i kalibre etme
- Tick adımı için ΔsqrtP hesapla: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- v3/v4 formüllerini kullanarak Δin'i yaklaşık hesapla: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Yuvarlama yönünün core math ile eşleştiğinden emin ol.
- Sınırda hook'un lehine yuvarladığı dalı bulmak için Δin'i ±1 wei kadar ayarla.

4) flash loans ile etkisini artır
- Birçok iterasyonu atomik olarak çalıştırmak için büyük bir notional ödünç al (örn., 3M USDT veya 2000 WETH).
- Kalibre edilmiş swap döngüsünü çalıştır, sonra flash loan callback içinde çek ve geri öde.

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
5) Çıkış ve zincirler arası çoğaltma
- Eğer hooks birden çok zincirde dağıtıldıysa, aynı kalibrasyonu her zincir için tekrar edin.
- Bridge, fonları hedef zincire geri taşır ve isteğe bağlı olarak akışları gizlemek için lending protokolleri aracılığıyla döngü oluşturabilir.

## Hook matematiğindeki yaygın kök nedenler

- Karışık yuvarlama semantiği: mulDiv aşağı yuvarlarken sonraki yollar etkili olarak yukarı yuvarlayabilir; veya token/liquidity arasındaki dönüşümler farklı yuvarlama uygular.
- Tick hizalama hataları: bir yolda yuvarlanmamış tick'ler kullanılırken diğerinde tick aralıklı yuvarlama kullanılması.
- BalanceDelta işaret/taşma sorunları, settlement sırasında int256 ile uint256 dönüşümlerinde ortaya çıkabilir.
- Q64.96 dönüşümlerinde (sqrtPriceX96) hassasiyet kaybının ters haritalamada yansıtılmaması.
- Birikim yolları: işlem başına kalanların, yakılmak/zero‑sum olması gerekirken caller tarafından çekilebilen krediler olarak izlenmesi.

## Savunma rehberi

- Diferansiyel testler: hook’un matematiğini yüksek hassasiyetli rasyonel aritmetik kullanan bir referans implementasyonla aynalayın ve eşitlik veya her zaman saldırgan (asla caller lehine olmayan) sınırlandırılmış bir hata ile doğrulayın.
- Invariant/özellik testleri:
- Swap yolları ve hook ayarlamaları boyunca delta'ların toplamı (tokenlar, likidite) ücretler düşüldükten sonra değeri korumalıdır.
- Hiçbir yol, tekrar eden exactInput iterasyonları boyunca swap başlatıcısı için pozitif net kredi yaratmamalıdır.
- Threshold/tick sınır testleri: exactInput ve exactOutput için ±1 wei girişler civarında testler yapın.
- Yuvarlama politikası: her zaman kullanıcı aleyhine yuvarlayan merkezi yuvarlama yardımcıları oluşturun; tutarsız cast'leri ve örtük floor kullanımını ortadan kaldırın.
- Settlement sinks: kaçınılmaz yuvarlama artıklarını protokol hazinesine biriktirin veya yakın; asla msg.sender'a atfetmeyin.
- Rate‑limits/guardrails: yeniden dengeleme tetiklemeleri için minimum swap boyutları belirleyin; deltal ar sub‑wei ise yeniden dengelemeleri devre dışı bırakın; deltalari beklenen aralıklarla karşılaştırarak sanity‑check yapın.
- Hook callback'lerini bütünsel olarak inceleyin: beforeSwap/afterSwap ve likidite değişikliklerinin before/after'ı tick hizalaması ve delta yuvarlamasında uyumlu olmalıdır.

## Vaka çalışması: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) with an LDF applied per swap to rebalance.
- Root cause: rounding/precision error in LDF liquidity accounting during threshold‑crossing swaps; per‑swap discrepancies accrued as positive credits for the caller.
- Ethereum leg: attacker took a ~3M USDT flash loan, performed calibrated exact‑input swaps on USDC/USDT to build credits, withdrew inflated balances, repaid, and routed funds via Aave.
- UniChain leg: repeated the exploit with a 2000 WETH flash loan, siphoning ~1366 WETH and bridging to Ethereum.
- Impact: ~USD 8.3M drained across chains. No user interaction required; entirely on‑chain.

## Hunting checklist

- Does the pool use a non‑zero hooks address? Which callbacks are enabled?
- Are there per‑swap redistributions/rebalances using custom math? Any tick/threshold logic?
- Where are divisions/mulDiv, Q64.96 conversions, or SafeCast used? Are rounding semantics globally consistent?
- Can you construct Δin that barely crosses a boundary and yields a favorable rounding branch? Test both directions and both exactInput and exactOutput.
- Does the hook track per‑caller credits or deltas that can be withdrawn later? Ensure residue is neutralized.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
