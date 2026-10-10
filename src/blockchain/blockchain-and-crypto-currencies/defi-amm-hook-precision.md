# Unyonyaji wa DeFi/AMM: Matumizi Mabaya ya Usahihi/Ukadiriaji wa Uniswap v4 Hook

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza aina ya mbinu za unyonyaji wa DeFi/AMM dhidi ya DEX za mtindo wa Uniswap v4 zinazopanua hesabu kuu kwa kutumia hooks maalum. Tukio la Bunni V2 linaonyesha hitilafu inayohusiana: hitilafu ya mwelekeo wa ukadiriaji katika hesabu ya uondoaji ilikadiria chini ukwasi unaotumika, na swap iliyofuata ilifichua ukadiriaji huo wa chini kupitia sandwich yenye faida.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Wazo kuu: hook ikitekeleza uhasibu wa ziada unaotegemea hesabu za fixed-point, ukadiriaji wa tick na mantiki ya vizingiti, mshambuliaji anaweza kutengeneza exact-input swaps zinazovuka vizingiti maalum ili tofauti za ukadiriaji zijikusanye kwa faida yake. Kurudia muundo huo na kisha kutoa salio lililoongezeka huwezesha kupata faida, ambayo mara nyingi hugharimiwa kwa flash loan.

## Usuli: hooks za Uniswap v4 na mtiririko wa swap

- Hooks ni contracts ambazo PoolManager huita katika sehemu maalum za mzunguko wa maisha (kwa mfano, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools huanzishwa kwa PoolKey inayojumuisha contract ya hook. Anwani ya hook isiyo sifuri huwasha callbacks zilizochaguliwa kwa pool hiyo.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks zinaweza kurudisha **custom deltas** zinazobadilisha mabadiliko ya mwisho ya salio ya swap au kitendo cha ukwasi (custom accounting). Deltas hizo hulipwa kama salio halisi mwishoni mwa call, kwa hiyo hitilafu yoyote ya ukadiriaji ndani ya hesabu ya hook hujikusanya kabla ya malipo.<sup>[[4]](#references)</sup>
- Hesabu kuu hutumia fomati za fixed-point kama Q64.96 kwa sqrtPriceX96 na hesabu za tick zinazotumia 1.0001^tick. Hesabu yoyote maalum inayoongezwa juu yake lazima ilingane kwa uangalifu na kanuni za ukadiriaji ili kuzuia kupotoka kwa invariant.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps zinaweza kuwa exactInput au exactOutput. Katika v3/v4, bei husogea kwenye ticks; kuvuka mpaka wa tick kunaweza kuwasha/kuzima ukwasi wa range. Hooks zinaweza kutekeleza mantiki ya ziada wakati wa kuvuka vizingiti/ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Aina ya udhaifu: kupotoka kwa usahihi/ukadiriaji wakati wa kuvuka vizingiti

Muundo wa kawaida ulio hatarini katika hooks maalum:

1. Hook huhesabu mabadiliko ya ukwasi au salio kwa kila swap kwa kutumia integer division, mulDiv au ubadilishaji wa fixed-point (kwa mfano, token ↔ liquidity kwa kutumia sqrtPrice na tick ranges).
2. Mantiki ya vizingiti (kwa mfano, kusawazisha upya, ugawaji upya wa hatua kwa hatua au uanzishaji wa kila range) huanzishwa wakati ukubwa wa swap au mwendo wa bei unapovuka mpaka wa ndani.
3. Ukadiriaji hutumika kwa njia zisizolingana (kwa mfano, kukata kuelekea sifuri, floor dhidi ya ceil) kati ya hesabu ya awali na njia ya malipo. Tofauti ndogo haziwiani na badala yake humfaidisha aliyeanzisha call.
4. Exact-input swaps zilizopimwa kwa usahihi ili kuvuka mipaka hiyo huvuna mara kwa mara salio chanya la ukadiriaji. Mshambuliaji hutoa baadaye salio lililokusanywa.

Masharti ya awali ya shambulio
- Pool inayotumia custom v4 hook inayofanya hesabu za ziada kwa kila swap (kwa mfano, LDF/rebalancer).
- Angalau njia moja ya utekelezaji ambapo ukadiriaji humfaidisha aliyeanzisha swap wakati wa kuvuka vizingiti.
- Uwezo wa kurudia swaps nyingi kwa atomic (flash loans ni bora kutoa fedha za muda na kugawanya gharama ya gas). 

## Mbinu ya shambulio kwa vitendo

1) Tambua pools zinazoweza kuwa na hooks
- Orodhesha v4 pools na uangalie PoolKey.hooks != address(0).
- Kagua bytecode/ABI ya hook ili kupata callbacks: beforeSwap/afterSwap na mbinu zozote maalum za kusawazisha upya.
- Tafuta hesabu zinazogawanya kwa liquidity, kubadilisha kati ya kiasi cha token na liquidity, au kujumlisha BalanceDelta huku zikitumia ukadiriaji.

2) Tengeneza mfano wa hesabu na vizingiti vya hook
- Unda upya fomula ya liquidity/redistribution ya hook: ingizo kwa kawaida hujumuisha sqrtPriceX96, tickLower/Upper, currentTick, fee tier na net liquidity.
- Weka ramani ya threshold/step functions: ticks, mipaka ya buckets au sehemu za LDF. Tambua upande ambao delta hukadiriwa inapovukwa kila mipaka.
- Tambua sehemu ambazo conversions hubadilisha cast kati ya uint256/int256, hutumia SafeCast, au hutegemea mulDiv yenye floor isiyoelezwa wazi.

3) Rekebisha exact-input swaps ili zivuke mipaka
- Tumia simulations za Foundry/Hardhat kukokotoa Δin ndogo zaidi inayohitajika kusogeza bei kuvuka mpaka kidogo tu na kuwasha branch ya hook.
- Thibitisha kuwa malipo ya afterSwap humrudishia aliyeanzisha call zaidi ya gharama, na kuacha BalanceDelta chanya au credit katika uhasibu wa hook.
- Rudia swaps ili kukusanya credit; kisha ita njia ya withdrawal/settlement ya hook.

Katika v4, swap loop lazima iendeshwe kutoka kwa callback ya PoolManager unlock; `amountSpecified` hasi humaanisha exact input, na `sqrtPriceLimitX96` lazima iwe ndani ya valid range. Price limit ya sifuri husababisha revert, kwa hiyo pseudocode iliyo hapa chini hutumia lower bound kwa swap ya zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Mfano wa test harness ya mtindo wa Foundry (pseudocode)
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

Kukalibisha exactInput
- Kokotoa lengo kwa kutumia core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) kwa thamani halisi; matokeo ya Q64.96 huzungushwa na TickMath.<sup>[[13]](#references)</sup>
- Kadiria ingizo la token0 (zero-for-one) ukitumia fomula inayozingatia Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Linganisha na mwelekeo wa kuzungusha wa core routine.<sup>[[12]](#references)</sup>
- Rekebisha Δin kwa ±1 wei karibu na mpaka ili kupata tawi ambalo hook huzungusha kwa faida yako.

4) Ongeza ukubwa kwa kutumia flash loans
- Kopa kiasi kikubwa cha thamani (kwa mfano, 3M USDT au 2000 WETH) ili kuendesha marudio mengi kwa atomiki.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Tekeleza mzunguko wa swap uliokalibishwa, kisha toa na ulipe mkopo ndani ya flash loan callback.

Mfupa wa flash loan wa Aave V3
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

5) Kuondoka na urudufishaji wa cross-chain
- Ikiwa hooks zimetumwa kwenye chains nyingi, rudia calibration ileile kwa kila chain.
- Katika tukio la Bunni, liquidity ya flash-loan na njia za bridge zilitofautiana kulingana na chain, kwa hiyo zingatia vikwazo mahususi vya kila chain unapozalisha upya uchanganuzi huo.<sup>[[1]](#references)[[2]](#references)</sup>

## Visababishi vya kawaida vya msingi katika hesabu za hook

- Kanuni mchanganyiko za kuzungusha: mulDiv huzungusha chini huku njia zinazofuata zikizungusha juu; au ubadilishaji kati ya token/liquidity hutumia kanuni tofauti za kuzungusha.
- Makosa ya upangaji wa tick: kutumia ticks ambazo hazijazungushwa katika njia moja na kuzungusha kulingana na nafasi za tick katika njia nyingine.
- Masuala ya ishara/overflow ya BalanceDelta wakati wa kubadilisha kati ya int256 na uint256 wakati wa settlement.
- Upotevu wa usahihi katika ubadilishaji wa Q64.96 (sqrtPriceX96) ambao haujazingatiwa katika ramani ya kurudi.
- Njia za mkusanyiko: salio la mabaki ya kila swap huhifadhiwa kama credits zinazoweza kutolewa na mpigaji badala ya kuchomwa au kusawazishwa hadi sifuri.

## Uhasibu maalum na ukuzaji wa delta

- Uhasibu maalum wa Uniswap v4 huruhusu hooks kurudisha deltas zinazorekebisha moja kwa moja kiasi anachodaiwa/kupokea mpigaji. Ikiwa hook huhifadhi credits ndani yake, mabaki ya kuzungusha yanaweza kujikusanya kupitia shughuli nyingi ndogo **kabla** ya settlement ya mwisho kufanyika.<sup>[[4]](#references)</sup>
- Ikiwa hook ina njia inayooana ya kutoa fedha, mshambuliaji anaweza kubadilishana `swap → withdraw → swap` ndani ya callback ileile ya kufungua PoolManager, na kuilazimisha hook kukokotoa upya deltas kwenye hali iliyobadilika kidogo huku salio likisubiri hadi unlock ikamilishe settlement.<sup>[[4]](#references)[[10]](#references)</sup>
- Unapokagua hooks, fuatilia kila mara jinsi BalanceDelta/HookDelta inavyozalishwa na kufanyiwa settlement. Kuzungusha kwa upendeleo mara moja tu katika tawi moja kunaweza kugeuka kuwa salio linaloongezeka kila mara deltas zinapokokotolewa upya.

## Mwongozo wa kujilinda

- Upimaji tofauti: linganisha hesabu za hook na utekelezaji rejea unaotumia hesabu za sehemu zenye usahihi wa juu, kisha hakikisha zinafanana au kosa lililowekewa kikomo daima linaegemea upande wa mshambuliaji (kamwe lisimpendelee mpigaji).
- Majaribio ya invariants/sifa:
  - Jumla ya deltas (tokeni, liquidity) katika njia za swap na marekebisho ya hook lazima ihifadhi thamani, isipokuwa ada.
  - Hakuna njia inayopaswa kutengeneza salio halisi chanya kwa mwanzilishi wa swap baada ya marudio mengi ya exactInput.
  - Majaribio ya mipaka ya threshold/tick kwa ingizo za ±1 wei katika exactInput/exactOutput.
- Sera ya kuzungusha: weka pamoja vitendaji saidizi vya kuzungusha ambavyo daima humweka mtumiaji katika upande usio na faida; ondoa casts zisizolingana na kuzungusha chini kunakotokea bila kudhamiriwa.
- Sehemu za kuelekeza mabaki: kusanya mabaki yasiyoepukika ya kuzungusha kwenye hazina ya treasury ya protocol au uyachome; usiwahi kuyahusisha na msg.sender.
- Vikomo vya viwango/vizuizi vya usalama: weka kiwango cha chini cha ukubwa wa swap kwa vichochezi vya kusawazisha upya; zima kusawazisha upya ikiwa deltas ni chini ya wei; kagua kama deltas ziko ndani ya masafa yanayotarajiwa.
- Kagua callbacks za hook kwa ujumla: beforeSwap/afterSwap na mabadiliko ya before/after liquidity zinapaswa kuafikiana kuhusu upangaji wa tick na ulinganishaji wa delta.

## Uchunguzi kifani: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2, hook ya Uniswap v4 inayotumia Liquidity Density Function (LDF) kukokotoa msongamano wa tokeni na makadirio ya jumla ya liquidity.<sup>[[1]](#references)[[2]](#references)</sup>
- Pool zilizoathiriwa: USDC/USDT kwenye Ethereum na weETH/ETH kwenye Unichain, zenye jumla ya takriban $8.4M.<sup>[[1]](#references)</sup>
- Hatua ya 1 (kusukuma bei): mshambuliaji alikopa takriban 3M USDT kupitia flash-loan na kufanya swap ili kusogeza tick hadi takriban 5000, na kupunguza salio **hai** la USDC hadi takriban 28 wei.<sup>[[1]](#references)</sup>
- Hatua ya 2 (kutoa fedha kupitia kuzungusha): utoaji mdogo wa fedha mara 44 ulitumia udhaifu wa kuzungusha chini katika `BunniHubLogic::withdraw()` kupunguza salio hai la USDC kutoka 28 wei hadi 4 wei (-85.7%) huku sehemu ndogo tu ya hisa za LP ikichomwa. Jumla ya liquidity ilipungua kwa takriban 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Hatua ya 3 (sandwich ya kurejea kwa liquidity): swap kubwa ilisogeza tick hadi takriban 839,189 (1 USDC ≈ 2.77e36 USDT). Makadirio ya liquidity yalibadilika na kuongezeka kwa takriban 16.8%, na kuwezesha sandwich ambapo mshambuliaji alifanya swap ya kurudi kwa bei iliyopandishwa na kutoka akiwa na faida.<sup>[[1]](#references)</sup>
- Marekebisho yaliyobainishwa katika uchambuzi baada ya tukio: badilisha usasishaji wa salio lisilotumika ili kuzungusha **juu**, ili utoaji wa fedha mdogo unaorudiwa usiendelee kupunguza salio hai la pool.<sup>[[1]](#references)</sup>

Mstari rahisi wa msimbo ulio hatarini (na marekebisho ya uchambuzi baada ya tukio).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Orodha ya ukaguzi wa uwindaji

- Je, pool inatumia anwani ya hooks isiyo sifuri? Ni callbacks zipi zimewashwa?
- Je, kuna ugawaji upya/rebalance kwa kila swap unaotumia hesabu maalum? Kuna mantiki yoyote ya tick/threshold?
- Division, mulDiv, ubadilishaji wa Q64.96 au SafeCast zinatumika wapi? Je, kanuni za kuzungusha zina uthabiti kote?
- Je, unaweza kuunda Δin inayovuka mpaka kwa tofauti ndogo tu na kutoa tawi la kuzungusha lenye manufaa? Jaribu pande zote mbili na exactInput na exactOutput.
- Je, hook hufuatilia credits au deltas kwa kila caller ambazo zinaweza kutolewa baadaye? Hakikisha mabaki yanabadilishwa kuwa sifuri.

## References

- [1] [Ripoti ya Uchunguzi wa Baada ya Tukio la Bunni (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Unyonyaji wa Bunni V2: Uchambuzi Kamili wa Udukuzi](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Unyonyaji wa Bunni V2: $8.3M Zilitolewa Kupitia Kasoro ya Liquidity (muhtasari)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Waraka Rasmi wa Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Usuli wa Uniswap v4 (utafiti wa QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mienendo ya Liquidity katika Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mienendo ya Swap katika Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks za Uniswap v4 na Mambo ya Kuzingatia Kuhusu Usalama](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
