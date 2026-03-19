# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



This page documents a class of DeFi/AMM exploitation techniques against Uniswap v4–style DEXes that extend core math with custom hooks. A recent incident in Bunni V2 leveraged a rounding/precision flaw in a Liquidity Distribution Function (LDF) executed on each swap, enabling the attacker to accrue positive credits and drain liquidity.

Key idea: if a hook implements additional accounting that depends on fixed‑point math, tick rounding, and threshold logic, an attacker can craft exact‑input swaps that cross specific thresholds so that rounding discrepancies accumulate in their favor. Repeating the pattern and then withdrawing the inflated balance realizes profit, often financed with a flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks are contracts that the PoolManager calls at specific lifecycle points (e.g., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools are initialized with a PoolKey including hooks address. If non‑zero, PoolManager performs callbacks on every relevant operation.
- Hooks can return **custom deltas** that modify the final balance changes of a swap or liquidity action (custom accounting). Those deltas are settled as net balances at the end of the call, so any rounding error inside hook math accumulates before settlement.
- Core math uses fixed‑point formats such as Q64.96 for sqrtPriceX96 and tick arithmetic with 1.0001^tick. Any custom math layered on top must carefully match rounding semantics to avoid invariant drift.
- Swaps can be exactInput or exactOutput. In v3/v4, price moves along ticks; crossing a tick boundary may activate/deactivate range liquidity. Hooks may implement extra logic on threshold/tick crossings.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

A typical vulnerable pattern in custom hooks:

1. The hook computes per‑swap liquidity or balance deltas using integer division, mulDiv, or fixed‑point conversions (e.g., token ↔ liquidity using sqrtPrice and tick ranges).
2. Threshold logic (e.g., rebalancing, stepwise redistribution, or per‑range activation) is triggered when a swap size or price movement crosses an internal boundary.
3. Rounding is applied inconsistently (e.g., truncation toward zero, floor versus ceil) between the forward calculation and the settlement path. Small discrepancies don’t cancel and instead credit the caller.
4. Exact‑input swaps, precisely sized to straddle those boundaries, repeatedly harvest the positive rounding remainder. The attacker later withdraws the accumulated credit.

Attack preconditions
- A pool using a custom v4 hook that performs additional math on each swap (e.g., an LDF/rebalancer).
- At least one execution path where rounding benefits the swap initiator across threshold crossings.
- Ability to repeat many swaps atomically (flash loans are ideal to supply temporary float and amortize gas).

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumerate v4 pools and check PoolKey.hooks != address(0).
- Inspect hook bytecode/ABI for callbacks: beforeSwap/afterSwap and any custom rebalancing methods.
- Look for math that: divides by liquidity, converts between token amounts and liquidity, or aggregates BalanceDelta with rounding.

2) Model the hook’s math and thresholds
- Recreate the hook’s liquidity/redistribution formula: inputs typically include sqrtPriceX96, tickLower/Upper, currentTick, fee tier, and net liquidity.
- Map threshold/step functions: ticks, bucket boundaries, or LDF breakpoints. Determine which side of each boundary the delta is rounded on.
- Identify where conversions cast between uint256/int256, use SafeCast, or rely on mulDiv with implicit floor.

3) Calibrate exact‑input swaps to cross boundaries
- Use Foundry/Hardhat simulations to compute the minimal Δin needed to move price just across a boundary and trigger the hook’s branch.
- Verify that afterSwap settlement credits the caller more than the cost, leaving a positive BalanceDelta or credit in the hook’s accounting.
- Repeat swaps to accumulate credit; then call the hook’s withdrawal/settlement path.

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
Calibrating the exactInput
- Bir tick adımı için ΔsqrtP'yi hesaplayın: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Δin'i v3/v4 formüllerini kullanarak yaklaşık hesaplayın: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Yuvarlama yönünün çekirdek matematikle eşleştiğinden emin olun.
- Sınır etrafında Δin'i ±1 wei değiştirerek, hook'un sizin lehinize yuvarladığı dalı bulun.

4) Flash loanlarla artırma
- Çok sayıda iterasyonu atomik olarak çalıştırmak için büyük bir nominal borç alın (ör. 3M USDT veya 2000 WETH gibi).
- Kalibre edilmiş swap döngüsünü çalıştırın, ardından flash loan callback'i içinde çekip geri ödeyin.

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
- Eğer hooks birden fazla zincire dağıtıldıysa, her zincir için aynı kalibrasyonu tekrarlayın.
- Bridge edilen fonlar hedef zincire geri döner ve akışları gizlemek için isteğe bağlı olarak lending protokolleri üzerinden döngüye sokulabilir.

## Hook matematiğindeki yaygın temel nedenler

- Karışık yuvarlama semantiği: mulDiv floor yaparken sonraki yollar etkili olarak yukarı yuvarlar; veya token/liquidity arasındaki dönüşümler farklı yuvarlama uygular.
- Tick hizalama hataları: bir yolda yuvarlanmamış tick'ler kullanılırken diğerinde tick‑aralıklı yuvarlama kullanılması.
- BalanceDelta işaret/taşma sorunları: settlement sırasında int256 ile uint256 arasında dönüştürme yapılırken.
- Q64.96 dönüşümlerinde (sqrtPriceX96) doğruluk kaybı, ters eşlemede yansıtılmaması.
- Birikim yolları: işlem başına kalanlar, yakılmak/zero‑sum olmak yerine caller tarafından çekilebilir krediler olarak izlenir.

## Özel muhasebe & delta çoğaltma

- Uniswap v4 custom accounting, hook'ların caller'ın borçlu/aldığı miktarı doğrudan ayarlayan deltalara izin verir. Eğer hook içsel olarak kredileri takip ederse, yuvarlama artıkları **nihai settlement gerçekleşmeden önce** birçok küçük işlemde birikebilir.
- Bu, boundary/threshold suiistimalini güçlendirir: saldırgan aynı tx içinde `swap → withdraw → swap` döngüsü yaparak hook'u, tüm bakiyeler hâlâ beklemede iken biraz farklı bir durumda deltalari yeniden hesaplamaya zorlayabilir.
- Hook'ları incelerken her zaman BalanceDelta/HookDelta'nın nasıl üretildiğini ve settle edildiğini takip edin. Bir dalda tek taraflı bir yuvarlama, deltalari tekrar tekrar yeniden hesaplandığında bileşik bir krediye dönüşebilir.

## Savunma önerileri

- Diferansiyel test: hook'un matematiğini yüksek‑hassasiyetli rasyonel aritmetik kullanarak bir referans implementasyonla karşılaştırın ve eşitliği veya her zaman saldırgana karşı (asla caller lehine olmayan) sınırlı hatayı doğrulayın.
- İnvariant/özellik testleri:
- Swap yolları ve hook ayarlamaları boyunca deltaların toplamı (tokenler, likidite) ücretler modunda değeri korumalıdır.
- Hiçbir yol repeated exactInput iterasyonlarında swap başlatıcısı için pozitif net kredi yaratmamalıdır.
- Hem exactInput hem exactOutput için ±1 wei giriş çevresinde eşik/tick sınır testleri.
- Yuvarlama politikası: her zaman kullanıcıya karşı yuvarlayan merkezi yuvarlama yardımcılarını kullanın; tutarsız cast'leri ve örtük floor'ları ortadan kaldırın.
- Settlement sink'leri: kaçınılmaz yuvarlama artıklarını protokol hazinesine biriktirin veya onları yakın; asla msg.sender'a atfetmeyin.
- Rate‑limits/guardrails: yeniden dengeleme tetikleyicileri için minimum swap boyutları; deltalari sub‑wei ise rebalancingleri devre dışı bırakın; deltalari beklenen aralıklara karşı sanity‑check yapın.
- Hook callback'lerini bütünsel olarak inceleyin: beforeSwap/afterSwap ve before/after likidite değişiklikleri tick hizalaması ve delta yuvarlamasında uyumlu olmalıdır.

## Vaka çalışması: Bunni V2 (2025‑09‑02)

- Protokol: Bunni V2 (Uniswap v4 hook) ile her swap için uygulanan bir LDF ile yeniden dengeleme.
- Etkilenen havuzlar: Ethereum'daki USDC/USDT ve Unichain'deki weETH/ETH, toplam yaklaşık $8.4M.
- Adım 1 (fiyat itme): saldırgan yaklaşık ~3M USDT flash‑borrow ederek swap yaptı ve tick'i ~5000'e iterek **active** USDC bakiyesini ~28 wei'ye düşürdü.
- Adım 2 (yuvarlama boşaltması): 44 küçük çekim, `BunniHubLogic::withdraw()` içindeki floor yuvarlamasını kötüye kullanarak active USDC bakiyesini 28 wei'den 4 wei'ye düşürdü (‑%85.7) while only a tiny fraction of LP shares was burned. Toplam likidite ~%84.4 oranında küçümsendi.
- Adım 3 (likidite sıçraması sandviçi): büyük bir swap tick'i ~839,189'a taşıdı (1 USDC ≈ 2.77e36 USDT). Likidite tahminleri tersine döndü ve ~%16.8 arttı, bu sayede saldırgan şişirilmiş fiyattan tekrar swap yapıp kârla çıktı.
- Post‑mortem'te tespit edilen düzeltme: idle‑balance güncellemesini **up** olarak yuvarlayacak şekilde değiştirin, böylece tekrarlanan mikro‑çekimler havuzun active bakiyesini aşağıya doğru kademeli olarak düşüremez.

Basitleştirilmiş savunmasız satır (ve post‑mortem düzeltmesi)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- Pool non‑zero hooks adresi kullanıyor mu? Hangi callbacks etkin?
- Özelleştirilmiş matematik kullanan per‑swap redistributions/rebalances var mı? Herhangi bir tick/threshold mantığı var mı?
- divisions/mulDiv, Q64.96 conversions veya SafeCast nerede kullanılıyor? Yuvarlama semantikleri genel olarak tutarlı mı?
- Bir sınırı zar zor aşan ve avantajlı bir rounding branch'i üreten bir Δin oluşturabilir misiniz? Her iki yönü ve hem exactInput hem de exactOutput için test edin.
- Hook, daha sonra çekilebilecek per‑caller credits veya deltas takip ediyor mu? Artığın (residue) nötralize edildiğinden emin olun.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
