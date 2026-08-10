# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

このページでは、custom hooks によって core math を拡張する Uniswap v4–style DEXes に対する、DeFi/AMM exploitation techniques の一種について説明します。Bunni V2 の incident では、関連する failure として withdrawal accounting における rounding-direction bug により active liquidity が過小評価され、その後の swap でこの過小評価が profitable sandwich として悪用されました。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

重要な考え方: hook が fixed-point math、tick rounding、threshold logic に依存する追加の accounting を実装している場合、attacker は特定の threshold を越える exact-input swaps を正確に組み立て、rounding discrepancies が自分に有利な形で蓄積するようにできます。このパターンを繰り返した後、inflated balance を withdraw することで profit を実現します。多くの場合、資金には flash loan が利用されます。

## Background: Uniswap v4 hooks and swap flow

- Hooks は、特定の lifecycle points（例: beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity、beforeInitialize/afterInitialize、beforeDonate/afterDonate）で PoolManager から呼び出される contracts です。<sup>[[4]](#references)</sup>
- Pools は hook contract を含む PoolKey とともに initialized されます。non-zero の hook address により、その pool 用に選択された callbacks が有効になります。<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks は **custom deltas** を返し、swap または liquidity action の最終的な balance changes を変更できます（custom accounting）。これらの deltas は call の終了時に net balances として settled されるため、settlement 前に hook math 内の rounding error が蓄積します。<sup>[[4]](#references)</sup>
- Core math は sqrtPriceX96 用の Q64.96 などの fixed-point formats と、1.0001^tick を用いる tick arithmetic を使用します。その上に重ねる custom math は、invariant drift を防ぐために rounding semantics を慎重に一致させる必要があります。<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps には exactInput または exactOutput を指定できます。v3/v4 では price が ticks に沿って移動し、tick boundary を crossing すると range liquidity が activate/deactivate される場合があります。Hooks は threshold/tick crossings に対する追加 logic を実装できます。<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Custom hooks における典型的な vulnerable pattern:

1. Hook が、integer division、mulDiv、または fixed-point conversions（例: sqrtPrice と tick ranges を用いた token ↔ liquidity の変換）によって、swap ごとの liquidity または balance deltas を計算する。
2. Threshold logic（例: rebalancing、stepwise redistribution、per-range activation）は、swap size または price movement が内部 boundary を crossing したときに trigger される。
3. Forward calculation と settlement path の間で rounding が一貫して適用されない（例: truncation toward zero、floor と ceil の不一致）。小さな discrepancies が相殺されず、caller に credit される。
4. これらの boundary をまたぐよう正確に size を調整した exact-input swaps により、positive rounding remainder を繰り返し harvest する。Attacker は後から蓄積した credit を withdraw する。

Attack preconditions
- 各 swap で追加の math を実行する custom v4 hook を使用する pool（例: LDF/rebalancer）。
- Threshold crossings 全体で swap initiator に有利な rounding となる execution path が少なくとも 1 つ存在する。
- 多数の swaps を atomically に繰り返せること（flash loans は一時的な float の供給と gas の償却に適しています）。

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 pools を列挙し、PoolKey.hooks != address(0) を確認する。
- Hook の bytecode/ABI を調査し、callbacks: beforeSwap/afterSwap および custom rebalancing methods を確認する。
- 次のような math を探す: liquidity による除算、token amounts と liquidity 間の変換、または rounding を伴う BalanceDelta の aggregation。

2) Model the hook’s math and thresholds
- Hook の liquidity/redistribution formula を再現する: inputs には通常、sqrtPriceX96、tickLower/Upper、currentTick、fee tier、net liquidity が含まれる。
- Threshold/step functions を map する: ticks、bucket boundaries、または LDF breakpoints。各 boundary のどちら側で delta が rounded されるかを特定する。
- uint256/int256 間で conversions を cast する箇所、SafeCast を使用する箇所、または implicit floor を伴う mulDiv に依存する箇所を特定する。

3) Calibrate exact‑input swaps to cross boundaries
- Foundry/Hardhat simulations を使用して、price を boundary の直後まで移動させ、hook の branch を trigger するために必要な最小 Δin を計算する。
- afterSwap settlement により caller が cost を上回る credit を受け取り、hook の accounting に positive BalanceDelta または credit が残ることを検証する。
- Swaps を繰り返して credit を蓄積し、その後 hook の withdrawal/settlement path を call する。

v4 では、swap loop は PoolManager unlock callback から実行する必要があります。negative `amountSpecified` は exact input を示し、`sqrtPriceLimitX96` は valid range の内部に厳密に収まっていなければなりません。zero price limit は revert するため、以下の pseudocode では zero-for-one swap に lower bound を使用しています。<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
exactInput のキャリブレーション
- core の TickMath を使用してターゲットを計算する: 実数値では sqrtP_next = sqrtP_current × 1.0001^(Δtick) となり、Q64.96 の結果は TickMath によって丸められる。<sup>[[13]](#references)</sup>
- Q64.96 に対応した式を使用して token0（zero-for-one）の input を近似する: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)。core routine の方向別の丸め処理に合わせる。<sup>[[12]](#references)</sup>
- 境界の前後で Δin を ±1 wei 調整し、hook が有利に丸める分岐を見つける。

4) flash loan で増幅する
- 大きな notional（例: 3M USDT または 2000 WETH）を借りて、多数の iteration を atomically 実行する。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- キャリブレーション済みの swap loop を実行し、その後 flash loan callback 内で withdraw と repay を行う。

Aave V3 flash loan スケルトン
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
- 複数の chain に hooks がデプロイされている場合は、chain ごとに同じ calibration を繰り返す。
- Bunni incident では、flash-loan liquidity と bridge routes が chain ごとに異なっていたため、分析を再現する際は chain 固有の制約を考慮する。<sup>[[1]](#references)[[2]](#references)</sup>

## hook math における一般的な根本原因

- 丸めセマンティクスの混在: mulDiv は切り捨てる一方、後続の path では実質的に切り上げている。または、token/liquidity 間の変換で異なる丸めが適用されている。
- Tick alignment のエラー: ある path では丸めていない tick を使用し、別の path では tick-spaced rounding を使用している。
- settlement 中に int256 と uint256 を変換する際の BalanceDelta の符号／overflow の問題。
- Q64.96 変換（sqrtPriceX96）における precision loss が、逆 mapping で反映されていない。
- 蓄積経路: swap ごとの余りを credits として記録し、burn／zero-sum 処理する代わりに caller が withdraw できるようにしている。

## Custom accounting と delta amplification

- Uniswap v4 の custom accounting により、hooks は caller の支払額／受取額を直接調整する deltas を返せる。hook が credits を内部的に記録する場合、最終的な settlement が行われる**前**に、丸めの残差が多数の小規模な操作を通じて蓄積する可能性がある。<sup>[[4]](#references)</sup>
- hook が互換性のある withdrawal path を公開している場合、attacker は同じ PoolManager unlock callback 内で `swap → withdraw → swap` を交互に実行できる。これにより、unlock の settlement が完了するまで balances が pending のまま、hook にわずかに異なる state で deltas を再計算させられる。<sup>[[4]](#references)[[10]](#references)</sup>
- hooks を review する際は、BalanceDelta/HookDelta がどのように生成され、settle されるかを必ず追跡する。1つの branch における単一の偏った丸めが、deltas の再計算を繰り返すことで、複利的に増加する credit になる可能性がある。

## Defensive guidance

- Differential testing: hook の math を high-precision rational arithmetic を使用する reference implementation と照合し、常に adversarial（caller に有利にならない）となる equality または bounded error を assert する。
- Invariant/property tests:
- swap paths と hook adjustments 全体における deltas（tokens、liquidity）の合計は、fees を除き value を conserve しなければならない。
- 繰り返し exactInput iterations を実行した場合、swap initiator に対する正の net credit を生成する path が存在してはならない。
- exactInput/exactOutput の両方について、±1 wei の inputs 周辺にある threshold/tick boundary をテストする。
- Rounding policy: 常に user に不利な方向へ丸める rounding helpers を一元化し、一貫性のない casts と implicit floors を排除する。
- Settlement sinks: 回避できない rounding residue は protocol treasury に蓄積するか burn し、決して msg.sender に帰属させない。
- Rate-limits/guardrails: rebalancing triggers に minimum swap sizes を設定し、deltas が sub-wei の場合は rebalances を無効化する。また、deltas が想定範囲内にあることを sanity-check する。
- hook callbacks を総合的に review する: beforeSwap/afterSwap と before/after liquidity changes は、tick alignment と delta rounding に関して一致していなければならない。

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2。Liquidity Density Function (LDF) を使用して token density と total-liquidity estimates を計算する Uniswap v4 hook。<sup>[[1]](#references)[[2]](#references)</sup>
- Affected pools: Ethereum 上の USDC/USDT と Unichain 上の weETH/ETH。合計で約 $8.4M。<sup>[[1]](#references)</sup>
- Step 1 (price push): attacker は約 3M USDT を flash-borrow し、swap によって tick を約 5000 まで押し上げ、**active** USDC balance を約 28 wei まで縮小した。<sup>[[1]](#references)</sup>
- Step 2 (rounding drain): 44回の tiny withdrawals により、`BunniHubLogic::withdraw()` における floor rounding を exploit し、LP shares をごくわずかしか burn せずに active USDC balance を 28 wei から 4 wei へ削減した（-85.7%）。Total liquidity は約 84.4% 減少した。<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (liquidity rebound sandwich): large swap により tick が約 839,189 まで移動した（1 USDC ≈ 2.77e36 USDT）。Liquidity estimates が反転して約 16.8% 増加し、attacker は inflated price で swap back を行って profit を得て exit する sandwich が可能になった。<sup>[[1]](#references)</sup>
- Post-mortem で特定された fix: idle-balance update を**切り上げ**るよう変更し、repeated micro-withdrawals によって pool の active balance が下方へ段階的に減少しないようにする。<sup>[[1]](#references)</sup>

Simplified vulnerable line (and post‑mortem fix).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- プールは non-zero hooks address を使用しているか？有効化されている callbacks はどれか？
- カスタム math を使用した swap ごとの redistribution/rebalance は存在するか？tick/threshold ロジックはあるか？
- divisions、mulDiv、Q64.96 conversions、または SafeCast はどこで使用されているか？rounding semantics は全体で一貫しているか？
- 境界をかろうじて超え、望ましい rounding branch を生じさせる Δin を構築できるか？両方向、および exactInput と exactOutput の両方をテストすること。
- hook は caller ごとの credits または deltas を追跡し、後から withdraw できるようにしているか？residue が neutralized されていることを確認すること。

## References

- [1] [Bunni Exploit の事後分析（2025年9月）](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit：完全な Hack 分析](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit：Liquidity Flaw により $8.3M が Drained（summary）](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
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
