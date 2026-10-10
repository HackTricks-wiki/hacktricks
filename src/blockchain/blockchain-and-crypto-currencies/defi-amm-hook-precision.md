# DeFi/AMM Exploitation: Uniswap v4 Hook Hassasiyet/Yuvarlama Suistimali

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, özel hook’larla temel matematiği genişleten Uniswap v4 tarzı DEX’lere yönelik DeFi/AMM exploitation tekniklerinin bir sınıfını belgeler. Bunni V2’deki bir olay, bununla ilişkili bir hatayı ortaya koyar: para çekme muhasebesindeki yuvarlama yönü hatası etkin likiditeyi olduğundan düşük gösterdi ve daha sonraki bir swap, bu düşük tahminin kârlı bir sandwich saldırısıyla açığa çıkmasına neden oldu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Temel fikir: Bir hook, sabit nokta matematiğine, tick yuvarlamasına ve eşik mantığına bağlı ek muhasebe işlemleri yapıyorsa saldırgan, yuvarlama tutarsızlıklarının kendi lehine birikmesini sağlayacak şekilde belirli eşikleri aşan exact-input swap’ler oluşturabilir. Bu model tekrarlanıp şişirilmiş bakiye çekildiğinde, çoğunlukla flash loan ile finanse edilen kâr elde edilir.

## Arka Plan: Uniswap v4 hook’ları ve swap akışı

- Hook’lar, PoolManager’ın belirli yaşam döngüsü noktalarında çağırdığı kontratlardır (ör. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pool’lar, hook kontratını içeren bir PoolKey ile başlatılır. Sıfır olmayan bir hook adresi, o pool için seçilen callback’leri etkinleştirir.<sup>[[4]](#references)[[14]](#references)</sup>
- Hook’lar, bir swap’in veya likidite işleminin nihai bakiye değişikliklerini değiştiren **özel farklar** (özel muhasebe) döndürebilir. Bu farklar çağrının sonunda net bakiyeler olarak kapatılır; dolayısıyla hook matematiğindeki tüm yuvarlama hataları kapatma öncesinde birikir.<sup>[[4]](#references)</sup>
- Temel matematik, sqrtPriceX96 için Q64.96 gibi sabit nokta biçimlerini ve 1.0001^tick kullanan tick aritmetiğini kullanır. Üzerine eklenen özel matematik, invariant sapmasını önlemek için yuvarlama kurallarına dikkatle uymalıdır.<sup>[[12]](#references)[[13]](#references)</sup>
- Swap’ler exactInput veya exactOutput olabilir. v3/v4’te fiyat tick’ler boyunca hareket eder; bir tick sınırının aşılması, aralık likiditesini etkinleştirebilir/devre dışı bırakabilir. Hook’lar, tick/eşik geçişlerinde ek mantık uygulayabilir.<sup>[[9]](#references)[[11]](#references)</sup>

## Güvenlik açığı modeli: eşik aşımında hassasiyet/yuvarlama sapması

Özel hook’larda sık görülen bir güvenlik açığı modeli:

1. Hook, tam sayı bölmesi, mulDiv veya sabit nokta dönüşümleri kullanarak (ör. sqrtPrice ve tick aralıklarıyla token ↔ likidite dönüşümü) swap başına likidite ya da bakiye farkları hesaplar.
2. Eşik mantığı (ör. yeniden dengeleme, kademeli yeniden dağıtım veya aralık başına etkinleştirme), swap boyutu ya da fiyat hareketi dahili bir sınırı aştığında tetiklenir.
3. Yuvarlama ileri hesaplama ve kapatma yolunda tutarsız biçimde uygulanır (ör. sıfıra doğru kesme, taban alma ve tavana yuvarlama farkı). Küçük farklar birbirini götürmez; bunun yerine çağırana kredi kazandırır.
4. Tam sınırları aşacak şekilde hassas boyutlandırılmış exact-input swap’ler, pozitif yuvarlama artığını tekrar tekrar toplar. Saldırgan daha sonra biriken krediyi çeker.

Saldırı önkoşulları
- Her swap’te ek matematik yapan (ör. bir LDF/rebalancer) özel v4 hook’u kullanan bir pool.
- Eşik aşımlarında yuvarlamanın swap’i başlatan tarafın lehine olduğu en az bir yürütme yolu.
- Tek bir işlemde çok sayıda swap’i tekrarlayabilme imkânı (geçici sermaye sağlamak ve gas maliyetini yaymak için flash loan idealdir).

## Uygulamalı saldırı yöntemi

1) Hook kullanan aday pool’ları belirleyin
- v4 pool’larını listeleyin ve PoolKey.hooks != address(0) koşulunu denetleyin.
- Hook bytecode’unu/ABI’sini; callback’ler (beforeSwap/afterSwap) ve özel yeniden dengeleme metotları açısından inceleyin.
- Şu işlemleri yapan matematiği arayın: likiditeye bölme, token miktarları ile likidite arasında dönüşüm veya BalanceDelta’yı yuvarlayarak toplama.

2) Hook matematiğini ve eşiklerini modelleyin
- Hook’un likidite/yeniden dağıtım formülünü yeniden oluşturun: girdiler genellikle sqrtPriceX96, tickLower/Upper, currentTick, fee tier ve net likiditeyi içerir.
- Eşik/kademe fonksiyonlarını haritalandırın: tick’ler, bucket sınırları veya LDF kırılma noktaları. Her sınırın hangi tarafında farkın yuvarlandığını belirleyin.
- Dönüşümlerin uint256/int256 arasında cast edildiği, SafeCast kullanıldığı veya mulDiv işleminin örtük olarak taban aldığı noktaları belirleyin.

3) Sınırları aşacak exact-input swap’leri ayarlayın
- Fiyatı sınırın hemen ötesine taşıyıp hook’un ilgili dalını tetiklemek için gereken asgari Δin miktarını Foundry/Hardhat simülasyonlarıyla hesaplayın.
- afterSwap kapatmasının çağırana maliyetinden daha fazla kredi verdiğini, böylece pozitif bir BalanceDelta veya hook muhasebesinde kredi bıraktığını doğrulayın.
- Kredi biriktirmek için swap’leri tekrarlayın; ardından hook’un para çekme/kapatma yolunu çağırın.

v4’te swap döngüsü bir PoolManager unlock callback’i içinden çalıştırılmalıdır; negatif `amountSpecified` exact input anlamına gelir ve `sqrtPriceLimitX96` geçerli aralığın kesinlikle içinde olmalıdır. Sıfır fiyat limiti işlemi revert ettirir; bu nedenle aşağıdaki sözde kodda zero-for-one swap için alt sınır kullanılmıştır.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Foundry tarzı test harness örneği (sözde kod)
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

exactInput kalibrasyonu
- Hedefi core TickMath ile hesaplayın: gerçek değerler cinsinden sqrtP_next = sqrtP_current × 1.0001^(Δtick); Q64.96 sonucu TickMath tarafından yuvarlanır.<sup>[[13]](#references)</sup>
- Q64.96 uyumlu formülle token0 (zero-for-one) girdisini yaklaşık hesaplayın: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). core yordamının yöne özgü yuvarlamasıyla eşleşin.<sup>[[12]](#references)</sup>
- Hook'un sizin lehinize yuvarladığı dalı bulmak için sınır çevresinde Δin değerini ±1 wei ayarlayın.

4) Flash loan'larla büyütün
- Atomik olarak çok sayıda yineleme çalıştırmak için yüksek tutarda borç alın (ör. 3M USDT veya 2000 WETH).<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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

5) Çıkış ve zincirler arası çoğaltma
- Hook’lar birden fazla zincirde dağıtılmışsa, aynı kalibrasyonu her zincir için tekrarlayın.
- Bunni olayında flash loan likiditesi ve bridge rotaları zincire göre farklılık gösteriyordu; analizi yeniden üretirken zincire özgü bu kısıtları hesaba katın.<sup>[[1]](#references)[[2]](#references)</sup>

## Hook matematiğindeki yaygın temel nedenler

- Farklı yuvarlama semantikleri: mulDiv aşağı yuvarlarken sonraki yollar fiilen yukarı yuvarlayabilir; ya da token/likidite dönüşümlerinde farklı yuvarlama uygulanabilir.
- Tick hizalama hataları: bir yolda yuvarlanmamış tick’ler, diğerinde tick aralığına göre yuvarlama kullanılması.
- Settlement sırasında int256 ile uint256 arasında dönüşüm yapılırken BalanceDelta işaret/taşma sorunları.
- Q64.96 dönüşümlerinde (sqrtPriceX96) oluşan hassasiyet kaybının ters eşlemede yansıtılmaması.
- Birikim yolları: swap başına kalan miktarların, yakılmak veya sıfır toplamlı olmak yerine çağıran tarafından çekilebilir krediler olarak izlenmesi.

## Özel muhasebe ve delta büyütme

- Uniswap v4 özel muhasebesi, hook’ların çağıranın borçlu olduğu veya alacağı miktarı doğrudan değiştiren delta’lar döndürmesine olanak tanır. Hook kredileri dahili olarak izliyorsa yuvarlama artıkları, nihai settlement gerçekleşmeden önce çok sayıda küçük işlem boyunca birikebilir.<sup>[[4]](#references)</sup>
- Hook uyumlu bir çekim yolu sunuyorsa saldırgan, aynı PoolManager unlock callback içinde `swap → withdraw → swap` işlemlerini sırayla yaparak hook’u, bakiyeler unlock sonuçlanana kadar beklemede kalırken, biraz farklı bir durum üzerinden delta’ları yeniden hesaplamaya zorlayabilir.<sup>[[4]](#references)[[10]](#references)</sup>
- Hook’ları incelerken BalanceDelta/HookDelta’nın nasıl üretildiğini ve settlement işleminin nasıl yapıldığını daima izleyin. Tek bir daldaki yanlı yuvarlama, delta’lar tekrar tekrar hesaplandığında birikerek büyüyen bir krediye dönüşebilir.

## Savunma yönergeleri

- Diferansiyel test: hook’un matematiğini yüksek hassasiyetli rasyonel aritmetik kullanan bir referans uygulamayla karşılaştırın ve eşitlik ya da her zaman saldırganın aleyhine olan (çağıranın lehine olmayan) sınırlı bir hata koşulu doğrulayın.
- Değişmez/property testleri:
  - Swap yolları ve hook ayarlamaları boyunca delta’ların (tokenlar, likidite) toplamı, ücretler dışında değeri korumalıdır.
  - Hiçbir yol, tekrarlanan exactInput iterasyonlarında swap’i başlatan taraf için pozitif net kredi oluşturmamalıdır.
  - Hem exactInput hem de exactOutput için ±1 wei girdileri çevresinde eşik/tick sınır testleri yapın.
- Yuvarlama politikası: daima kullanıcı aleyhine yuvarlayan yardımcı işlevleri merkezileştirin; tutarsız cast işlemlerini ve örtük aşağı yuvarlamaları ortadan kaldırın.
- Settlement artıkları: kaçınılmaz yuvarlama artıklarını protokol hazinesinde biriktirin veya yakın; bunları asla msg.sender’a atfetmeyin.
- Hız sınırları/korumalar: yeniden dengeleme tetikleyicileri için minimum swap boyutları belirleyin; delta’lar bir wei’den küçükse yeniden dengelemeyi devre dışı bırakın; delta’ların beklenen aralıklarda olduğunu doğrulayın.
- Hook callback’lerini bütünsel olarak inceleyin: beforeSwap/afterSwap ve likidite değişikliklerinden önce/sonra çağrılan işlevler, tick hizalaması ve delta yuvarlaması konusunda tutarlı olmalıdır.

## Vaka çalışması: Bunni V2 (2025‑09‑02)

- Protokol: Bunni V2; token yoğunluğunu ve toplam likidite tahminlerini hesaplamak için Liquidity Density Function (LDF) kullanan bir Uniswap v4 hook’u.<sup>[[1]](#references)[[2]](#references)</sup>
- Etkilenen havuzlar: Ethereum’daki USDC/USDT ve Unichain’deki weETH/ETH; toplamda yaklaşık $8.4M.<sup>[[1]](#references)</sup>
- Adım 1 (fiyatı itme): saldırgan yaklaşık 3M USDT flash-borrow edip tick’i yaklaşık 5000’e taşımak için swap yaptı ve **active** USDC bakiyesini yaklaşık 28 wei’ye düşürdü.<sup>[[1]](#references)</sup>
- Adım 2 (yuvarlama yoluyla fon çekme): 44 küçük çekim, `BunniHubLogic::withdraw()` içindeki aşağı yuvarlamadan yararlanarak active USDC bakiyesini 28 wei’den 4 wei’ye (-85.7%) düşürdü; buna karşılık LP hisselerinin yalnızca çok küçük bir kısmı yakıldı. Toplam likidite yaklaşık %84.4 azaldı.<sup>[[1]](#references)[[2]](#references)</sup>
- Adım 3 (likidite toparlanmasıyla sandwich): büyük bir swap tick’i yaklaşık 839,189’a taşıdı (1 USDC ≈ 2.77e36 USDT). Likidite tahminleri tersine döndü ve yaklaşık %16.8 arttı; bu da saldırganın şişirilmiş fiyattan geri swap yapıp kârla çıkmasını sağlayan bir sandwich işlemini mümkün kıldı.<sup>[[1]](#references)</sup>
- Post-mortem’da belirlenen düzeltme: tekrarlanan mikro çekimlerin havuzun active bakiyesini kademeli olarak düşürmesini önlemek için boşta bakiye güncellemesini yukarı yuvarlayacak şekilde değiştirin.<sup>[[1]](#references)</sup>

Basitleştirilmiş güvenlik açığı içeren satır (ve post-mortem düzeltmesi).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Avlanma kontrol listesi

- Pool, sıfır olmayan bir hooks adresi kullanıyor mu? Hangi callbacks etkin?
- Özel matematik kullanan swap başına yeniden dağıtımlar/yeniden dengelemeler var mı? Tick/eşik mantığı bulunuyor mu?
- Bölme işlemleri, mulDiv, Q64.96 dönüşümleri veya SafeCast nerelerde kullanılıyor? Yuvarlama kuralları genel olarak tutarlı mı?
- Bir sınırı kıl payı aşan ve avantajlı bir yuvarlama dalı oluşturan Δin değeri oluşturabilir misiniz? Her iki yönü ve hem exactInput hem de exactOutput durumlarını test edin.
- Hook, daha sonra çekilebilecek çağıran başına kredileri veya delta değerlerini izliyor mu? Artık değerin etkisiz hâle getirildiğinden emin olun.

## References

- [1] [Bunni Exploit Sonrası İnceleme (Eylül 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: Tam Hack Analizi](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: Likidite Kusuru Nedeniyle 8,3 Milyon Doların Boşaltılması (özet)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Çekirdek Teknik İncelemesi](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 arka planı (QuillAudits araştırması)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 çekirdeğinde likidite mekanikleri](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 çekirdeğinde swap mekanikleri](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks ve Güvenlik Hususları](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 çekirdeği Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 çekirdeği PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 çekirdeği SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 çekirdeği TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
