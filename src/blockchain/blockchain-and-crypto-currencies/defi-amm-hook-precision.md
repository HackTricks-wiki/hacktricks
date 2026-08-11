# DeFi/AMM Exploitation: Uniswap v4 Hook の精度/丸め処理の悪用

{{#include ../../banners/hacktricks-training.md}}

このページでは、custom hooks によってコアの数学処理を拡張する Uniswap v4-style DEX に対する、DeFi/AMM exploitation techniques の一種について説明します。Bunni V2 の incident では、関連する failure が発生しました。withdrawal accounting における rounding-direction bug によって active liquidity が過小評価され、その後の swap によってその過小評価が profitable sandwich で露呈しました。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Key idea: hook が fixed-point math、tick rounding、threshold logic に依存する追加の accounting を実装している場合、攻撃者は特定の threshold を crossing する exact-input swaps を作成し、rounding discrepancy が自分に有利な方向へ蓄積するようにできます。このパターンを繰り返した後、inflated balance を withdraw することで profit を実現します。多くの場合、資金には flash loan を利用します。

## Background: Uniswap v4 hooks と swap flow

- Hooks は、特定の lifecycle points（例: beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity、beforeInitialize/afterInitialize、beforeDonate/afterDonate）で PoolManager によって call される contracts です。<sup>[[4]](#references)</sup>
- Pools は hook contract を含む PoolKey とともに initialized されます。non-zero の hook address によって、その pool で選択された callbacks が有効になります。<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks は **custom deltas** を返すことができ、swap または liquidity action における最終的な balance changes を変更できます（custom accounting）。これらの deltas は call の最後に net balances として settled されるため、settlement 前に hook math 内のあらゆる rounding error が蓄積します。<sup>[[4]](#references)</sup>
- Core math は sqrtPriceX96 用の Q64.96 などの fixed-point formats と、1.0001^tick を用いた tick arithmetic を使用します。その上に重ねる custom math は、invariant drift を避けるため、rounding semantics を慎重に一致させる必要があります。<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps には exactInput と exactOutput があります。v3/v4 では、price は ticks に沿って移動し、tick boundary を crossing すると range liquidity が activate/deactivate される場合があります。Hooks は threshold/tick crossings に対する追加 logic を実装できます。<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold-crossing precision/rounding drift

custom hooks における典型的な vulnerable pattern:

1. Hook は、integer division、mulDiv、または fixed-point conversions（例: sqrtPrice と tick ranges を用いた token ↔ liquidity 変換）を使用して、swap ごとの liquidity または balance deltas を計算します。
2. Threshold logic（例: rebalancing、stepwise redistribution、per-range activation）は、swap size または price movement が内部 boundary を crossing したときに trigger されます。
3. Forward calculation と settlement path の間で rounding が一貫して適用されません（例: truncation toward zero、floor と ceil の不一致）。小さな discrepancy は相殺されず、caller に credit されます。
4. これらの boundary を straddle するよう正確に size 調整された exact-input swaps により、positive rounding remainder を繰り返し harvest します。その後、攻撃者は蓄積した credit を withdraw します。

Attack preconditions
- 各 swap で追加の math を実行する custom v4 hook を使用する pool（例: LDF/rebalancer）。
- threshold crossings 全体で swap initiator に有利な rounding となる execution path が少なくとも 1 つ存在すること。
- 多数の swaps を atomically に repeat できること（一時的な float の供給と gas の amortize には flash loans が理想的です）。

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 pools を enumerate し、PoolKey.hooks != address(0) を確認します。
- Hook bytecode/ABI を inspect し、callbacks: beforeSwap/afterSwap および custom rebalancing methods を確認します。
- 次のような math を探します: liquidity による division、token amounts と liquidity 間の conversion、または BalanceDelta の rounding を伴う aggregation。

2) Model the hook’s math and thresholds
- Hook の liquidity/redistribution formula を recreate します。inputs には通常、sqrtPriceX96、tickLower/Upper、currentTick、fee tier、net liquidity が含まれます。
- Threshold/step functions を map します: ticks、bucket boundaries、または LDF breakpoints。各 boundary のどちら側で delta が rounded されるかを determine します。
- conversions が uint256/int256 間で cast される箇所、SafeCast を使用する箇所、または implicit floor を伴う mulDiv に依存する箇所を identify します。

3) Calibrate exact-input swaps to cross boundaries
- Foundry/Hardhat simulations を使用して、price を boundary の just across まで移動させ、hook の branch を trigger するために必要な最小 Δin を計算します。
- afterSwap settlement により caller が cost を上回る amount を credit され、hook の accounting に positive BalanceDelta または credit が残ることを verify します。
- Swaps を repeat して credit を accumulate し、その後 hook の withdrawal/settlement path を call します。

v4 では、swap loop は PoolManager unlock callback から実行する必要があります。negative `amountSpecified` は exact input を示し、`sqrtPriceLimitX96` は valid range の strictly inside でなければなりません。zero price limit では revert するため、以下の pseudocode では zero-for-one swap に lower bound を使用しています。<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
exactInput の調整
- core TickMath で目標値を計算する: 実数値では sqrtP_next = sqrtP_current × 1.0001^(Δtick) となり、Q64.96 の結果は TickMath によって丸められる。<sup>[[13]](#references)</sup>
- Q64.96 に対応した式を使って token0（zero-for-one）の入力を近似する: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)。core routine の方向別の丸め処理に合わせる。<sup>[[12]](#references)</sup>
- 境界の前後で Δin を ±1 wei 調整し、hook が有利に丸める分岐を見つける。

4) flash loans で増幅する
- 大きな notional（例: 3M USDT または 2000 WETH）を借り、数多くの反復処理を atomic に実行する。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- 調整済みの swap loop を実行し、その後 flash loan callback 内で引き出しと返済を行う。

Aave V3 flash loan の skeleton
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
5) Exit と cross-chain replication
- 複数の chain に hook がデプロイされている場合は、chain ごとに同じ calibration を繰り返す。
- Bunni incident では、flash-loan liquidity と bridge routes が chain ごとに異なっていたため、analysis を再現する際は、これらの chain-specific constraints を考慮する。<sup>[[1]](#references)[[2]](#references)</sup>

## hook math における一般的な root cause

- Mixed rounding semantics: mulDiv は切り捨てる一方、後続の path では実質的に切り上げる、または token/liquidity 間の conversion で異なる rounding を適用する。
- Tick alignment errors: ある path では丸めていない tick を使用し、別の path では tick-spaced rounding を使用する。
- settlement 中に int256 と uint256 を変換する際の BalanceDelta の sign/overflow issues。
- Q64.96 conversions（sqrtPriceX96）で precision が失われ、その逆 mapping に反映されない。
- Accumulation pathways: swap ごとの remainder を credits として追跡し、それを burn/zero-sum せず caller が withdrawable にする。

## Custom accounting と delta amplification

- Uniswap v4 の custom accounting では、hook が deltas を返し、caller が支払う金額または受け取る金額を直接調整できる。hook が内部で credits を追跡する場合、rounding residue は final settlement が実行される**前**に、多数の小さな operation を通じて蓄積する可能性がある。<sup>[[4]](#references)</sup>
- hook が互換性のある withdrawal path を公開している場合、attacker は同じ PoolManager unlock callback 内で `swap → withdraw → swap` を交互に実行できる。これにより、unlock の settlement まで balances が pending のまま維持される一方で、hook にわずかに異なる state 上で deltas を再計算させられる。<sup>[[4]](#references)[[10]](#references)</sup>
- hook を review する際は、BalanceDelta/HookDelta がどのように生成され、settle されるかを必ず trace する。1 つの branch における rounding bias が、deltas の再計算を繰り返すことで、累積する credit になる可能性がある。

## Defensive guidance

- Differential testing: high-precision rational arithmetic を使用した reference implementation と hook の math を mirror し、常に adversarial（caller に有利にならない）な equality または bounded error を assert する。
- Invariant/property tests:
- swap paths と hook adjustments 全体における deltas（tokens、liquidity）の合計は、fees を除いて value を conserve しなければならない。
- repeated exactInput iterations の間、swap initiator に対する positive net credit を生成する path があってはならない。
- exactInput/exactOutput の両方について、±1 wei inputs 周辺の threshold/tick boundary tests。
- Rounding policy: 常に user に不利な方向へ round する rounding helpers を centralize し、一貫性のない casts と implicit floors を排除する。
- Settlement sinks: 避けられない rounding residue は protocol treasury に accumulate するか burn し、決して msg.sender に帰属させない。
- Rate-limits/guardrails: rebalancing triggers に対する minimum swap sizes、deltas が sub-wei の場合の rebalances の無効化、expected ranges に対する deltas の sanity-check。
- hook callbacks を holistic に review する: beforeSwap/afterSwap と before/after liquidity changes は、tick alignment と delta rounding に関して一致していなければならない。

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2。Liquidity Density Function（LDF）を使用して token density と total-liquidity estimates を計算する Uniswap v4 hook。<sup>[[1]](#references)[[2]](#references)</sup>
- Affected pools: Ethereum 上の USDC/USDT と Unichain 上の weETH/ETH で、合計約 $8.4M。<sup>[[1]](#references)</sup>
- Step 1 (price push): attacker は約 3M USDT を flash-borrow し、swap によって tick を約 5000 まで押し上げ、**active** USDC balance を約 28 wei まで縮小した。<sup>[[1]](#references)</sup>
- Step 2 (rounding drain): 44 回の tiny withdrawals により、`BunniHubLogic::withdraw()` の floor rounding を悪用し、LP shares はごく一部しか burn しないまま、active USDC balance を 28 wei から 4 wei まで（-85.7%）減少させた。Total liquidity は約 84.4% 減少した。<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (liquidity rebound sandwich): large swap により tick が約 839,189（1 USDC ≈ 2.77e36 USDT）まで移動した。Liquidity estimates が反転して約 16.8% 増加し、attacker は inflated price で swap back して profit を得る sandwich が可能になった。<sup>[[1]](#references)</sup>
- Post-mortem で特定された fix: idle-balance update を**切り上げ**に変更し、repeated micro-withdrawals によって pool の active balance が下方へ ratchet されないようにする。<sup>[[1]](#references)</sup>

脆弱な line の簡略版（および post-mortem fix）。<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- Pool は non-zero の hooks address を使用しているか？有効化されている callback はどれか？
- swap ごとの redistribution/rebalance に custom math が使用されているか？tick/threshold ロジックはあるか？
- division、mulDiv、Q64.96 conversion、または SafeCast はどこで使用されているか？rounding semantics は全体で一貫しているか？
- 境界をかろうじて超え、都合のよい rounding branch を発生させる Δin を構築できるか？両方向、および exactInput と exactOutput の両方をテストする。
- hook は caller ごとの credit または後で withdraw 可能な delta を追跡しているか？residue が neutralized されていることを確認する。

## References

- [1] [Bunni Exploit Post Mortem（2025年9月）](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit：完全な Hack 分析](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit：Liquidity Flaw により $8.3M が Drain された事例（summary）](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 の背景（QuillAudits research）](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 core における Liquidity mechanics](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 core における Swap mechanics](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks と Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
