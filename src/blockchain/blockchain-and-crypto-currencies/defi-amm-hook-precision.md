# Unyonyaji wa DeFi/AMM: Matumizi Mabaya ya Usahihi/Uzungushaji katika Uniswap v4 Hook

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza kundi la mbinu za unyonyaji wa DeFi/AMM dhidi ya DEX za mtindo wa Uniswap v4 zinazopanua hesabu za msingi kwa kutumia hooks maalum. Tukio la Bunni V2 linaonyesha hitilafu inayohusiana: hitilafu ya mwelekeo wa uzungushaji katika hesabu ya uondoaji ilikadiria chini ukwasi amilifu, na swap iliyofuata ikafichua makadirio hayo ya chini kupitia sandwich yenye faida.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Wazo kuu: ikiwa hook itatekeleza hesabu za ziada zinazotegemea hesabu za fixed-point, uzungushaji wa tick, na mantiki ya vizingiti, mshambuliaji anaweza kuunda exact-input swaps zinazovuka vizingiti mahususi ili tofauti za uzungushaji zijikusanye kwa manufaa yake. Kurudia mpangilio huu kisha kutoa salio lililoongezwa huwezesha kupata faida, mara nyingi kwa kutumia flash loan.

## Usuli: hooks za Uniswap v4 na mtiririko wa swap

- Hooks ni mikataba ambayo PoolManager huiita katika sehemu mahususi za mzunguko wa maisha (kwa mfano, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools huanzishwa kwa PoolKey inayojumuisha mkataba wa hook. Anwani ya hook isiyo sifuri huwasha callbacks zilizochaguliwa kwa pool hiyo.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks zinaweza kurejesha **custom deltas** zinazorekebisha mabadiliko ya mwisho ya salio ya swap au kitendo cha ukwasi (custom accounting). Deltas hizo hulipwa kama salio halisi mwishoni mwa mwito, kwa hiyo hitilafu yoyote ya uzungushaji ndani ya hesabu za hook hujikusanya kabla ya malipo.<sup>[[4]](#references)</sup>
- Hesabu za msingi hutumia miundo ya fixed-point kama Q64.96 kwa sqrtPriceX96 na hesabu za tick zinazotumia 1.0001^tick. Hesabu yoyote maalum inayoongezwa juu yake lazima ilingane kwa makini na semantiki za uzungushaji ili kuzuia kupotoka kwa invariant.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps zinaweza kuwa exactInput au exactOutput. Katika v3/v4, bei husogea kwenye ticks; kuvuka mpaka wa tick kunaweza kuwasha/kuzima ukwasi wa range. Hooks zinaweza kutekeleza mantiki ya ziada wakati wa kuvuka vizingiti/ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Aina ya udhaifu: kupotoka kwa usahihi/uzungushaji wakati wa kuvuka kizingiti

Muundo wa kawaida ulio hatarini katika hooks maalum:

1. Hook hukokotoa mabadiliko ya ukwasi au salio kwa kila swap kwa kutumia integer division, mulDiv, au ubadilishaji wa fixed-point (kwa mfano, token ↔ ukwasi kwa kutumia sqrtPrice na mipaka ya tick).
2. Mantiki ya kizingiti (kwa mfano, kusawazisha upya, ugawaji upya wa hatua kwa hatua, au uanzishaji kwa kila range) huwashwa ukubwa wa swap au mwendo wa bei unapovuka mpaka wa ndani.
3. Uzungushaji hutekelezwa bila uthabiti (kwa mfano, kukata kuelekea sufuri, floor dhidi ya ceil) kati ya hesabu ya mbele na njia ya malipo. Tofauti ndogo hazifutani, bali humwongezea mpigaji salio.
4. Exact-input swaps zilizopimwa kwa usahihi ili kuvuka mipaka hiyo huvuna mara kwa mara mabaki chanya ya uzungushaji. Baadaye mshambuliaji hutoa salio lililokusanywa.

Masharti ya awali ya shambulio
- Pool inayotumia custom v4 hook inayofanya hesabu za ziada kwa kila swap (kwa mfano, LDF/rebalancer).
- Angalau njia moja ya utekelezaji ambapo uzungushaji hunufaisha mwanzishaji wa swap wakati wa kuvuka vizingiti.
- Uwezo wa kurudia swaps nyingi kwa transaction moja (flash loans zinafaa sana kutoa fedha za muda na kugawanya gharama ya gas). 

## Mbinu ya vitendo ya shambulio

1) Tambua pools zinazowezekana zenye hooks
- Orodhesha v4 pools na uhakiki kuwa PoolKey.hooks != address(0).
- Kagua bytecode/ABI ya hook ili kutafuta callbacks: beforeSwap/afterSwap na mbinu zozote maalum za kusawazisha upya.
- Tafuta hesabu zinazogawanya kwa ukwasi, kubadilisha kiasi cha tokeni na ukwasi, au kukusanya BalanceDelta kwa uzungushaji.

2) Tengeneza mfano wa hesabu na vizingiti vya hook
- Unda upya fomula ya ukwasi/ugawaji upya ya hook: kwa kawaida pembejeo hujumuisha sqrtPriceX96, tickLower/Upper, currentTick, fee tier, na net liquidity.
- Weka ramani ya vitendaji vya kizingiti/hatua: ticks, mipaka ya bucket, au sehemu za LDF. Bainisha delta inazungushwa upande upi wa kila mpaka.
- Tambua sehemu ambazo ubadilishaji hutumia aina za uint256/int256, SafeCast, au kutegemea mulDiv yenye floor isiyoainishwa wazi.

3) Rekebisha exact-input swaps ili zivuke mipaka
- Tumia uigaji wa Foundry/Hardhat kukokotoa Δin ya chini kabisa inayohitajika kusogeza bei ivuke mpaka kidogo tu na kuwasha tawi la hook.
- Hakikisha kuwa malipo ya afterSwap yanampa mpigaji zaidi ya gharama, na kuacha BalanceDelta chanya au salio katika hesabu za hook.
- Rudia swaps ili kukusanya salio; kisha ita njia ya uondoaji/malipo ya hook.

Katika v4, mzunguko wa swap lazima uendeshwe kutoka kwenye callback ya kufungua PoolManager; `amountSpecified` hasi humaanisha exact input, na `sqrtPriceLimitX96` lazima iwe ndani kabisa ya masafa halali. Kizuizi cha bei sifuri husababisha revert, kwa hiyo pseudocode iliyo hapa chini hutumia mpaka wa chini kwa swap ya zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
- Kadiria ingizo la token0 (zero-for-one) kwa kutumia fomula inayozingatia Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Linganisha na mwelekeo wa rounding wa utaratibu mkuu.<sup>[[12]](#references)</sup>
- Rekebisha Δin kwa ±1 wei karibu na mpaka ili kupata branch ambapo hook huzungusha kwa faida yako.

4) Ongeza ukubwa kwa mikopo ya flash
- Azima kiasi kikubwa (kwa mfano, 3M USDT au 2000 WETH) ili kutekeleza marudio mengi kwa atomiki.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Tekeleza mzunguko wa swap uliokalibishwa, kisha toa fedha na ulipe mkopo ndani ya callback ya flash loan.

Muundo wa msingi wa Aave V3 flash loan
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

5) Kuondoka na urudufishaji kati ya chain
- Ikiwa hooks zimetekelezwa kwenye chain nyingi, rudia calibration ileile kwa kila chain.
- Katika tukio la Bunni, liquidity ya flash-loan na njia za bridge zilitofautiana kulingana na chain, kwa hiyo zingatia vikwazo mahususi vya kila chain unapozalisha upya uchanganuzi huo.<sup>[[1]](#references)[[2]](#references)</sup>

## Sababu za kawaida za msingi katika hesabu za hook

- Semantiki mchanganyiko za rounding: mulDiv hukata sehemu ya desimali chini, ilhali njia zinazofuata kwa ufanisi huzungusha juu; au ubadilishaji kati ya token/liquidity hutumia rounding tofauti.
- Hitilafu za mpangilio wa Tick: kutumia ticks zisizozungushwa katika njia moja na rounding inayozingatia nafasi za tick katika njia nyingine.
- Matatizo ya ishara/overflow ya BalanceDelta wakati wa kubadilisha kati ya int256 na uint256 wakati wa settlement.
- Kupotea kwa usahihi katika ubadilishaji wa Q64.96 (sqrtPriceX96) kusikojumuishwa kwenye ramani ya kinyume.
- Njia za mkusanyiko: salio la mabaki kwa kila swap hufuatiliwa kama credits zinazoweza kutolewa na mpigaji badala ya kuchomwa/kusawazishwa hadi sifuri.

## Uhasibu maalum na ukuzaji wa delta

- Uhasibu maalum wa Uniswap v4 huruhusu hooks kurudisha deltas zinazorekebisha moja kwa moja kiasi ambacho mpigaji anadaiwa/kupokea. Ikiwa hook hufuatilia credits ndani, mabaki ya rounding yanaweza kujikusanya katika shughuli nyingi ndogo **kabla** ya settlement ya mwisho kufanyika.<sup>[[4]](#references)</sup>
- Ikiwa hook inatoa njia ya kutoa pesa inayooana, mshambuliaji anaweza kubadilishana `swap → withdraw → swap` ndani ya callback ileile ya kufungua PoolManager, na kuilazimisha hook kukokotoa upya deltas kwenye hali iliyobadilika kidogo huku salio likisubiri hadi unlock ikamilishe settlement.<sup>[[4]](#references)[[10]](#references)</sup>
- Unapokagua hooks, fuatilia kila wakati jinsi BalanceDelta/HookDelta inavyotengenezwa na kufanyiwa settlement. Rounding moja tu yenye upendeleo katika tawi moja inaweza kuwa credit inayozidi kujikusanya wakati deltas zinapokokotolewa upya mara kwa mara.

## Mwongozo wa kujilinda

- Upimaji linganishi: linganisha hesabu za hook na utekelezaji rejea unaotumia hesabu za rational zenye usahihi wa juu, na uhakikishe zinafanana au kosa lililowekewa kikomo daima linakuwa dhidi ya mshambuliaji (kamwe lisimfaidishe mpigaji).
- Majaribio ya invariant/property:
  - Jumla ya deltas (token, liquidity) katika njia za swap na marekebisho ya hook lazima ihifadhi thamani, isipokuwa ada.
  - Hakuna njia inayopaswa kuunda credit halisi chanya kwa mwanzilishi wa swap katika marudio ya exactInput.
  - Majaribio ya mipaka ya threshold/tick kwa ingizo la ±1 wei kwa exactInput/exactOutput zote mbili.
- Sera ya rounding: weka pamoja vihisabu vya rounding vinavyozungusha kila mara dhidi ya mtumiaji; ondoa casts zisizolingana na ukataji wa sehemu za desimali usio wazi.
- Sehemu za kuelekeza mabaki ya settlement: kusanya mabaki ya rounding yasiyoepukika kwenye hazina ya protocol au uyachome; usiwahi kuyahusisha na msg.sender.
- Vikomo/ulinzi wa kiwango: weka kiwango cha chini cha ukubwa wa swap kwa vichochezi vya kusawazisha upya; zima kusawazisha upya ikiwa deltas ni chini ya wei; hakiki kwamba deltas ziko ndani ya masafa yanayotarajiwa.
- Kagua callbacks za hook kwa ujumla: beforeSwap/afterSwap na mabadiliko ya liquidity kabla/baada yanapaswa kukubaliana kuhusu mpangilio wa tick na rounding ya delta.

## Uchunguzi wa tukio: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2, hook ya Uniswap v4 inayotumia Liquidity Density Function (LDF) kukokotoa msongamano wa token na makadirio ya jumla ya liquidity.<sup>[[1]](#references)[[2]](#references)</sup>
- Pool zilizoathiriwa: USDC/USDT kwenye Ethereum na weETH/ETH kwenye Unichain, zenye jumla ya takriban $8.4M.<sup>[[1]](#references)</sup>
- Hatua ya 1 (kusukuma bei): mshambuliaji alikopa kwa flash-loan takriban 3M USDT na kufanya swap ili kusukuma tick hadi takriban 5000, na kupunguza salio **amilifu** la USDC hadi takriban 28 wei.<sup>[[1]](#references)</sup>
- Hatua ya 2 (kutoa fedha kupitia rounding): utoaji pesa 44 mdogo ulitumia rounding ya kukata chini katika `BunniHubLogic::withdraw()` kupunguza salio amilifu la USDC kutoka 28 wei hadi 4 wei (-85.7%) huku sehemu ndogo tu ya hisa za LP zikichomwa. Jumla ya liquidity ilipungua kwa takriban 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Hatua ya 3 (sandwich ya kurejea kwa liquidity): swap kubwa ilisogeza tick hadi takriban 839,189 (1 USDC ≈ 2.77e36 USDT). Makadirio ya liquidity yaligeuka na kuongezeka kwa takriban 16.8%, na kuwezesha sandwich ambapo mshambuliaji alifanya swap kurudi kwa bei iliyopandishwa na kutoka akiwa na faida.<sup>[[1]](#references)</sup>
- Marekebisho yaliyobainishwa katika ripoti ya baada ya tukio: badilisha sasisho la salio lisilotumika ili lizunguze **juu**, ili utoaji pesa mdogo unaorudiwa usiendelee kupunguza salio amilifu la pool.<sup>[[1]](#references)</sup>

Mstari dhaifu uliorahisishwa (na marekebisho ya ripoti ya baada ya tukio).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Orodha ya ukaguzi wa uwindaji

- Je, pool inatumia anwani ya hooks isiyo sifuri? Ni callbacks zipi zimewezeshwa?
- Je, kuna ugawaji upya/rebalances kwa kila swap unaotumia custom math? Kuna mantiki yoyote ya tick/threshold?
- Divisions, mulDiv, ubadilishaji wa Q64.96, au SafeCast zinatumika wapi? Je, semantiki za rounding zinafanana kote?
- Je, unaweza kuunda Δin inayovuka mpaka kwa kiasi kidogo tu na kutoa rounding branch yenye manufaa? Jaribu pande zote mbili na exactInput na exactOutput.
- Je, hook inafuatilia credits au deltas za kila caller zinazoweza kutolewa baadaye? Hakikisha mabaki yanabadilishwa kuwa sifuri.

## References

- [1] [Bunni Exploit: Uchambuzi wa Baada ya Tukio (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: Uchambuzi Kamili wa Hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M Zilitolewa Kupitia Kasoro ya Liquidity (muhtasari)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core: Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Usuli wa Uniswap v4 (utafiti wa QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mbinu za Liquidity katika Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mbinu za Swap katika Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks na Mambo ya Kuzingatia Kuhusu Usalama](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
