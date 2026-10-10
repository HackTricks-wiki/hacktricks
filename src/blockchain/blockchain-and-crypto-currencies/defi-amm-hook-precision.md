# DeFi/AMM Exploitation: Uniswap v4 Hook Hassasiyet/Yuvarlama Suistimali

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, özel hook’larla temel matematiği genişleten Uniswap v4 tarzı DEX’lere karşı kullanılan bir DeFi/AMM exploitation tekniği sınıfını belgeliyor. Bunni V2’de yaşanan bir olay, benzer bir hatayı ortaya koyuyor: para çekme muhasebesindeki yuvarlama yönü hatası, aktif likiditeyi olduğundan az gösterdi ve daha sonraki bir swap, bu düşük tahmini kârlı bir sandwich saldırısıyla açığa çıkardı.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Temel fikir: Bir hook, sabit nokta matematiğine, tick yuvarlamasına ve eşik mantığına bağlı ek muhasebe uyguluyorsa saldırgan, yuvarlama tutarsızlıklarının kendi lehine birikmesi için belirli eşikleri aşan exact-input swap’ler oluşturabilir. Bu düzeni tekrarlayıp şişirilmiş bakiyeyi çekmek kâr sağlar; bu işlem genellikle flash loan ile finanse edilir.

## Arka Plan: Uniswap v4 hook’ları ve swap akışı

- Hook’lar, PoolManager’ın belirli yaşam döngüsü noktalarında çağırdığı kontratlardır (ör. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pool’lar, hook kontratını içeren bir PoolKey ile başlatılır. Sıfır olmayan bir hook adresi, o pool için seçilen callback’leri etkinleştirir.<sup>[[4]](#references)[[14]](#references)</sup>
- Hook’lar, bir swap’in veya likidite işleminin nihai bakiye değişikliklerini düzenleyen **custom delta** değerleri döndürebilir (custom accounting). Bu delta’lar çağrının sonunda net bakiye olarak kapatılır; dolayısıyla hook matematiğindeki yuvarlama hataları, kapatma işleminden önce birikir.<sup>[[4]](#references)</sup>
- Temel matematik, sqrtPriceX96 için Q64.96 gibi sabit nokta biçimlerini ve 1.0001^tick kullanan tick aritmetiğini kullanır. Üzerine katmanlanan her özel matematik, invariant sapmasını önlemek için yuvarlama semantiğiyle dikkatle uyumlu olmalıdır.<sup>[[12]](#references)[[13]](#references)</sup>
- Swap’ler exactInput veya exactOutput olabilir. v3/v4’te fiyat tick’ler boyunca hareket eder; bir tick sınırının aşılması, aralık likiditesini etkinleştirebilir veya devre dışı bırakabilir. Hook’lar, eşik/tick geçişlerinde ek mantık uygulayabilir.<sup>[[9]](#references)[[11]](#references)</sup>

## Güvenlik açığı örüntüsü: eşik aşımında hassasiyet/yuvarlama sapması

Özel hook’larda sık görülen bir güvenlik açığı örüntüsü:

1. Hook, tamsayı bölmesi, mulDiv veya sabit nokta dönüşümleri kullanarak swap başına likidite ya da bakiye delta’ları hesaplar (ör. sqrtPrice ve tick aralıkları kullanarak token ↔ likidite dönüşümü).
2. Eşik mantığı (ör. yeniden dengeleme, kademeli yeniden dağıtım veya aralık başına etkinleştirme), swap boyutu ya da fiyat hareketi dahili bir sınırı aştığında tetiklenir.
3. Yuvarlama, ileri hesaplama ile kapatma yolunda tutarsız biçimde uygulanır (ör. sıfıra doğru kesme, floor yerine ceil kullanma). Küçük tutarsızlıklar birbirini götürmek yerine çağırana kredi sağlar.
4. Bu sınırları aşacak şekilde hassas ayarlanmış exact-input swap’ler, pozitif yuvarlama farkını tekrar tekrar toplar. Saldırgan daha sonra biriken krediyi çeker.

Saldırı önkoşulları
- Her swap’te ek matematik (ör. LDF/rebalancer) uygulayan özel v4 hook kullanan bir pool.
- Eşik geçişlerinde yuvarlamanın swap’i başlatana avantaj sağladığı en az bir yürütme yolu.
- Çok sayıda swap’i atomik olarak tekrarlayabilme (geçici fonlama ve gas maliyetlerini karşılamak için flash loan’lar idealdir).

## Pratik saldırı metodolojisi

1) Hook kullanan aday pool’ları belirleyin
- v4 pool’larını listeleyin ve PoolKey.hooks != address(0) koşulunu kontrol edin.
- Hook bytecode’unu/ABI’sini inceleyerek callback’leri kontrol edin: beforeSwap/afterSwap ve özel yeniden dengeleme metotları.
- Şu matematik işlemlerini arayın: likiditeye bölme, token miktarları ile likidite arasında dönüşüm veya BalanceDelta’yı yuvarlamayla toplama.

2) Hook matematiğini ve eşiklerini modelleyin
- Hook’un likidite/yeniden dağıtım formülünü yeniden oluşturun: girdiler genellikle sqrtPriceX96, tickLower/Upper, currentTick, fee tier ve net likiditeyi içerir.
- Eşik/kademe fonksiyonlarını haritalandırın: tick’ler, bucket sınırları veya LDF kırılma noktaları. Delta’nın her sınırın hangi tarafında yuvarlandığını belirleyin.
- Dönüşümlerin uint256/int256 türleri arasında cast edildiği, SafeCast kullanıldığı veya mulDiv’in örtük floor davranışına dayandığı noktaları belirleyin.

3) Sınırları aşacak exact-input swap’leri ayarlayın
- Fiyatı bir sınırın hemen ötesine taşımak ve hook’un ilgili dalını tetiklemek için gereken minimum Δin değerini hesaplamak üzere Foundry/Hardhat simülasyonları kullanın.
- afterSwap kapatma işleminin, maliyetten daha fazla tutarı çağırana verdiğini ve geriye pozitif bir BalanceDelta ya da hook muhasebesinde kredi bıraktığını doğrulayın.
- Kredi biriktirmek için swap’leri tekrarlayın; ardından hook’un para çekme/kapatma yolunu çağırın.

v4’te swap döngüsü, bir PoolManager unlock callback’i içinden çalıştırılmalıdır; negatif `amountSpecified` exact input anlamına gelir ve `sqrtPriceLimitX96` geçerli aralığın kesinlikle içinde olmalıdır. Sıfır fiyat limiti işlemi revert ettirir; bu nedenle aşağıdaki sözde kod, zero-for-one swap için alt sınırı kullanır.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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

exactInput değerini kalibre etme
- Hedefi core TickMath ile hesaplayın: sqrtP_next = sqrtP_current × 1.0001^(Δtick), gerçek değer cinsinden; Q64.96 sonucu TickMath tarafından yuvarlanır.<sup>[[13]](#references)</sup>
- Q64.96 uyumlu formülle token0 (zero-for-one) girişini yaklaşık hesaplayın: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Core yordamının yöne özgü yuvarlamasıyla eşleşmesini sağlayın.<sup>[[12]](#references)</sup>
- Hook’un lehinize yuvarladığı dalı bulmak için sınır çevresinde Δin değerini ±1 wei değiştirin.

4) Flash loan’larla büyütün
- Tek işlem içinde çok sayıda yineleme çalıştırmak için büyük bir nominal tutar (ör. 3M USDT veya 2000 WETH) borç alın.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Kalibre edilmiş swap döngüsünü çalıştırın, ardından flash loan callback’i içinde fonları çekip borcu geri ödeyin.

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
- Hook’lar birden fazla zincirde dağıtılmışsa, kalibrasyonu her zincirde tekrarlayın.
- Bunni olayında flash-loan likiditesi ve bridge rotaları zincire göre farklılık gösteriyordu; analizi yeniden üretirken zincire özgü bu kısıtları hesaba katın.<sup>[[1]](#references)[[2]](#references)</sup>

## Hook matematiğinde yaygın temel nedenler

- Karışık yuvarlama semantiği: mulDiv aşağı yuvarlarken sonraki yollar fiilen yukarı yuvarlayabilir veya token/likidite dönüşümlerinde farklı yuvarlama yöntemleri uygulanabilir.
- Tick hizalama hataları: Bir yolda yuvarlanmamış tick’ler, diğerinde tick aralığına göre yuvarlama kullanılması.
- Settlement sırasında int256 ile uint256 arasında dönüşüm yapılırken BalanceDelta işaret/taşma sorunları.
- Q64.96 dönüşümlerinde (sqrtPriceX96) oluşan hassasiyet kaybının ters eşlemede yansıtılmaması.
- Birikim yolları: Her swap’ten kalan küsuratların, yakılmak veya sıfır toplamlı olmak yerine çağıran tarafından çekilebilir krediler olarak tutulması.

## Özel muhasebe ve delta büyütme

- Uniswap v4 özel muhasebesi, hook’ların çağıranın borcunu/alacağını doğrudan değiştiren deltalar döndürmesine olanak tanır. Hook dahili olarak kredileri izliyorsa, nihai settlement gerçekleşmeden önce birçok küçük işlem boyunca yuvarlama artıkları birikebilir.<sup>[[4]](#references)</sup>
- Hook uyumlu bir çekim yolu sunuyorsa, saldırgan aynı PoolManager unlock callback’i içinde `swap → withdraw → swap` işlemlerini dönüşümlü yaparak hook’u, bakiyeler unlock tamamlanana kadar beklemede kalırken, biraz farklı bir durum üzerinden deltaları yeniden hesaplamaya zorlayabilir.<sup>[[4]](#references)[[10]](#references)</sup>
- Hook’ları incelerken BalanceDelta/HookDelta’nın nasıl üretildiğini ve settle edildiğini daima izleyin. Tek bir daldaki yanlı yuvarlama, deltalar tekrar tekrar hesaplandıkça biriken krediye dönüşebilir.

## Savunma yönergeleri

- Diferansiyel test: Hook’un matematiğini yüksek hassasiyetli rasyonel aritmetik kullanan bir referans uygulamayla karşılaştırın ve eşitlik ya da daima saldırganın aleyhine olan, sınırlı bir hata payı olduğunu doğrulayın.
- Invariant/property testleri:
  - Swap yolları ve hook ayarlamaları boyunca token ve likidite deltalarının toplamı, ücretler hariç, değeri korumalıdır.
  - Tekrarlanan exactInput yinelemelerinde hiçbir yol, swap’i başlatana net pozitif kredi oluşturmamalıdır.
  - Hem exactInput hem exactOutput için ±1 wei girdiyle eşik/tick sınır testleri.
- Yuvarlama politikası: Daima kullanıcı aleyhine yuvarlayan yardımcıları merkezîleştirin; tutarsız cast’leri ve örtük aşağı yuvarlamaları ortadan kaldırın.
- Settlement hedefleri: Kaçınılmaz yuvarlama artıklarını protokol hazinesinde biriktirin veya yakın; bunları asla msg.sender’a atfetmeyin.
- Hız sınırları/korumalar: Yeniden dengeleme tetikleyicileri için minimum swap boyutları belirleyin; deltalar 1 wei’den küçükse yeniden dengelemeyi devre dışı bırakın; deltaların beklenen aralıklarda olduğunu doğrulayın.
- Hook callback’lerini bütünsel olarak inceleyin: beforeSwap/afterSwap ve likidite değişikliklerinden önce/sonra çalışan callback’ler tick hizalama ve delta yuvarlama konusunda tutarlı olmalıdır.

## Vaka incelemesi: Bunni V2 (2025‑09‑02)

- Protokol: Token yoğunluğunu ve toplam likidite tahminlerini hesaplamak için Liquidity Density Function (LDF) kullanan bir Uniswap v4 hook’u olan Bunni V2.<sup>[[1]](#references)[[2]](#references)</sup>
- Etkilenen havuzlar: Ethereum’daki USDC/USDT ve Unichain’deki weETH/ETH; toplam değer yaklaşık $8.4M.<sup>[[1]](#references)</sup>
- Adım 1 (fiyatı itme): Saldırgan yaklaşık 3M USDT flash-borrow edip tick’i yaklaşık 5000’e taşımak için swap yaptı ve **aktif** USDC bakiyesini yaklaşık 28 wei’ye düşürdü.<sup>[[1]](#references)</sup>
- Adım 2 (yuvarlama yoluyla fon çekme): 44 küçük çekim, `BunniHubLogic::withdraw()` içindeki aşağı yuvarlamadan yararlanarak aktif USDC bakiyesini 28 wei’den 4 wei’ye (-85.7%) düşürdü; yakılan LP payı ise çok küçük bir kesirdi. Toplam likidite yaklaşık %84.4 azaldı.<sup>[[1]](#references)[[2]](#references)</sup>
- Adım 3 (likidite toparlanmasıyla sandwich): Büyük bir swap tick’i yaklaşık 839,189’a taşıdı (1 USDC ≈ 2.77e36 USDT). Likidite tahminleri tersine döndü ve yaklaşık %16.8 arttı; böylece saldırganın şişirilmiş fiyattan geri swap yapıp kârla çıkabildiği bir sandwich mümkün oldu.<sup>[[1]](#references)</sup>
- Post-mortem’da belirlenen düzeltme: Atıl bakiye güncellemesini yukarı yuvarlayacak şekilde değiştirin; böylece tekrarlanan mikro çekimler havuzun aktif bakiyesini artık kademeli olarak düşüremez.<sup>[[1]](#references)</sup>

Savunmasız satırın basitleştirilmiş hâli (ve post-mortem düzeltmesi).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Av kontrol listesi

- Pool sıfırdan farklı bir hooks adresi kullanıyor mu? Hangi callback'ler etkin?
- Her swap'te özel matematik kullanan yeniden dağıtımlar/yeniden dengelemeler var mı? Herhangi bir tick/eşik mantığı var mı?
- Bölme/mulDiv, Q64.96 dönüşümleri veya SafeCast nerelerde kullanılıyor? Yuvarlama kuralları genelinde tutarlı mı?
- Sınırı zar zor aşan ve avantajlı bir yuvarlama dalı sağlayan Δin oluşturabilir misiniz? Her iki yönü ve hem exactInput hem de exactOutput'u test edin.
- Hook, daha sonra çekilebilecek kullanıcı başına kredileri veya delta'ları izliyor mu? Artıkların etkisiz hâle getirildiğinden emin olun.

## References

- [1] [Bunni Exploit Olay Sonrası İnceleme (Eylül 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: Kapsamlı Hack Analizi](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: Likidite Açığı Nedeniyle 8,3 Milyon Dolar Boşaltıldı (özet)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core Teknik Dokümanı](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 arka planı (QuillAudits araştırması)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 core'daki likidite mekanikleri](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 core'daki swap mekanikleri](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks ve güvenlik değerlendirmeleri](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
