# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

このページでは、custom hooksによってcore mathを拡張するUniswap v4–style DEXに対する、DeFi/AMM exploitation techniquesの一種について説明します。最近のBunni V2のincidentでは、各swapで実行されるLiquidity Distribution Function（LDF）のrounding/precision flawが悪用され、attackerがpositive creditsを蓄積してliquidityをdrainできました。<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

重要な考え方は、hookがfixed-point math、tick rounding、threshold logicに依存する追加のaccountingを実装している場合、attackerは特定のthresholdをcrossするexact-input swapsを作成し、rounding discrepanciesが自身に有利な形で蓄積するようにできるという点です。このパターンを繰り返した後、inflated balanceをwithdrawすることでprofitを実現します。多くの場合、flash loanによって資金を調達します。

## Background: Uniswap v4 hooks and swap flow

- Hooksは、PoolManagerが特定のlifecycle points（例：beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity、beforeInitialize/afterInitialize、beforeDonate/afterDonate）で呼び出すcontractsです。<sup>[[3]](#references)[[6]](#references)</sup>
- Poolsはhooks addressを含むPoolKeyでinitializeされます。ゼロでない場合、PoolManagerは関連するすべてのoperationでcallbacksを実行します。<sup>[[6]](#references)</sup>
- Hooksは、swapまたはliquidity actionの最終的なbalance changesを変更する**custom deltas**を返せます（custom accounting）。これらのdeltasはcallの最後にnet balancesとしてsettleされるため、settlement前にhook math内のrounding errorが蓄積します。<sup>[[5]](#references)</sup>
- Core mathでは、sqrtPriceX96に使用されるQ64.96や、1.0001^tickを用いるtick arithmeticなどのfixed-point formatsが使われます。その上に重ねるcustom mathでは、invariant driftを避けるため、rounding semanticsを慎重に一致させる必要があります。<sup>[[4]](#references)[[8]](#references)</sup>
- SwapsにはexactInputまたはexactOutputがあります。v3/v4では、priceはticksに沿って移動します。tick boundaryをcrossすると、range liquidityがactivate/deactivateされる場合があります。Hooksはthreshold/tick crossingsで追加のlogicを実装できます。<sup>[[5]](#references)</sup>

## Vulnerability archetype: threshold-crossing precision/rounding drift

Custom hooksで一般的に見られるvulnerable pattern：

1. Hookが、integer division、mulDiv、またはfixed-point conversions（例：sqrtPriceとtick rangesを使用したtoken ↔ liquidity変換）を使って、swapごとのliquidityまたはbalance deltasを計算する。
2. Threshold logic（例：rebalancing、stepwise redistribution、per-range activation）は、swap sizeまたはprice movementがinternal boundaryをcrossしたときにtriggerされる。
3. Forward calculationとsettlement pathの間でroundingが一貫して適用されない（例：zero方向へのtruncation、floorとceilの違い）。小さなdiscrepanciesが相殺されず、代わりにcallerへのcreditとなる。
4. それらのboundaryをstraddleするよう正確にsizeを調整したexact-input swapsによって、positive rounding remainderを繰り返しharvestする。その後、attackerは蓄積したcreditをwithdrawする。

Attack preconditions
- 各swapで追加のmath（例：LDF/rebalancer）を実行するcustom v4 hookを使用したpool。
- Threshold crossingsにおいて、swap initiatorに有利なroundingとなるexecution pathが少なくとも1つ存在する。
- 多数のswapsをatomicallyに繰り返せること（一時的なfloatの供給とgasのamortizeにはflash loansが最適）。

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 poolsをenumerateし、PoolKey.hooks != address(0)を確認する。
- Hook bytecode/ABIをinspectし、callbacks：beforeSwap/afterSwapおよびcustom rebalancing methodsを確認する。
- 次のようなmathを探す：liquidityでのdivision、token amountsとliquidity間のconversion、またはroundingを伴うBalanceDeltaのaggregation。

2) Model the hook’s math and thresholds
- Hookのliquidity/redistribution formulaをrecreateする：inputsには通常、sqrtPriceX96、tickLower/Upper、currentTick、fee tier、net liquidityが含まれる。
- Threshold/step functionsをmapする：ticks、bucket boundaries、またはLDF breakpoints。各boundaryのどちら側でdeltaがroundされるかを特定する。
- uint256/int256間のconversionでcastを行う箇所、SafeCastを使用する箇所、またはimplicit floorを伴うmulDivに依存する箇所を特定する。

3) Calibrate exact‑input swaps to cross boundaries
- Foundry/Hardhat simulationsを使用して、priceをboundaryの直後まで移動させ、hookのbranchをtriggerするために必要な最小Δinを計算する。
- afterSwap settlementによってcallerにcostを上回る額がcreditされ、hookのaccountingにpositive BalanceDeltaまたはcreditが残ることを確認する。
- Swapsを繰り返してcreditを蓄積し、その後hookのwithdrawal/settlement pathをcallする。

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
- tick step における ΔsqrtP を計算します: sqrtP_next = sqrtP_current × 1.0001^(Δtick)。
- v3/v4 の formulas で Δin を近似します: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current))。rounding の方向が core math と一致することを確認します。
- 境界の前後で Δin を ±1 wei 調整し、hook が有利に rounds する branch を見つけます。

4) flash loans で増幅する
- 大きな notional（例: 3M USDT または 2000 WETH）を borrow し、多数の iterations を atomic に実行します。<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- calibrated swap loop を実行し、その後 flash loan callback 内で withdraw と repay を行います。

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
5) Exit と cross-chain replication
- 複数の chain に hook がデプロイされている場合は、chain ごとに同じ calibration を繰り返す。
- proceeds を target chain に bridge で戻し、必要に応じて lending protocols 経由で cycle して flows を obfuscate する。<sup>[[2]](#references)</sup>

## hook math における一般的な根本原因

- Mixed rounding semantics: mulDiv は floor する一方、後続の path では実質的に round up される。または、token/liquidity 間の conversion で異なる rounding が適用される。
- Tick alignment errors: ある path では unrounded ticks を使用し、別の path では tick-spaced rounding を使用する。
- settlement 中に int256 と uint256 の間で conversion する際の BalanceDelta の sign/overflow 問題。
- Q64.96 conversions（sqrtPriceX96）における precision loss が、reverse mapping で反映されていない。
- Accumulation pathways: swap ごとの remainder が credits として追跡され、burn または zero-sum 処理されず caller により withdraw 可能になる。

## Custom accounting と delta amplification

- Uniswap v4 の custom accounting では、hook が caller の支払額または受取額を直接調整する deltas を返せる。hook が内部で credits を追跡する場合、rounding residue は、最終的な settlement が発生する**前に**多数の小規模な operation を通じて蓄積する可能性がある。<sup>[[5]](#references)</sup>
- これにより boundary/threshold abuse がさらに強力になる。attacker は同一 tx 内で `swap → withdraw → swap` を交互に実行し、すべての balances がまだ pending の状態で、hook にわずかに異なる state に基づく deltas の再計算を強制できる。
- hook を review する際は、BalanceDelta/HookDelta がどのように生成され、settle されるかを必ず trace する。1 つの branch における biased rounding が、deltas の再計算によって繰り返し compounding credit になる可能性がある。

## Defensive guidance

- Differential testing: hook の math を high-precision rational arithmetic を使用した reference implementation と照合し、常に adversarial となる（決して caller に有利にならない）equality または bounded error を assert する。
- Invariant/property tests:
- swap paths と hook adjustments 全体における deltas（tokens、liquidity）の合計は、fees を除き value を conserve しなければならない。
- repeated exactInput iterations において、swap initiator に対する positive net credit を生成する path が存在してはならない。
- exactInput/exactOutput の双方について、±1 wei inputs 周辺の threshold/tick boundary tests を実施する。
- Rounding policy: 常に user に不利な方向へ round する rounding helpers を centralize し、一貫性のない casts と implicit floors を排除する。
- Settlement sinks: 回避できない rounding residue は protocol treasury に蓄積するか burn する。決して msg.sender に帰属させない。
- Rate-limits/guardrails: rebalancing triggers に minimum swap sizes を設定し、deltas が sub-wei の場合は rebalances を無効化する。また、deltas を expected ranges と照合して sanity-check する。
- hook callbacks を holistic に review する。beforeSwap/afterSwap と before/after liquidity changes は、tick alignment と delta rounding について整合していなければならない。

## Case study: Bunni V2 (2025-09-02)

- Protocol: Bunni V2（Uniswap v4 hook）。swap ごとに LDF が適用され、rebalance が行われる。<sup>[[7]](#references)</sup>
- Affected pools: Ethereum 上の USDC/USDT と Unichain 上の weETH/ETH。合計で約 $8.4M。<sup>[[1]](#references)[[2]](#references)</sup>
- Step 1 (price push): attacker は約 3M USDT を flash-borrow し、swap によって tick を約 5000 まで押し上げ、**active** USDC balance を約 28 wei まで縮小した。<sup>[[7]](#references)</sup>
- Step 2 (rounding drain): 44 回の tiny withdrawals により、`BunniHubLogic::withdraw()` の floor rounding を exploit し、LP shares のごく一部だけを burn しながら active USDC balance を 28 wei から 4 wei へ削減した（-85.7%）。Total liquidity は約 84.4% 過小評価された。<sup>[[2]](#references)[[7]](#references)</sup>
- Step 3 (liquidity rebound sandwich): large swap により tick が約 839,189 まで移動した（1 USDC ≈ 2.77e36 USDT）。Liquidity estimates が反転して約 16.8% 増加し、attacker は inflated price で swap back して profit を得る sandwich が可能になった。<sup>[[7]](#references)</sup>
- Post-mortem で特定された fix: idle-balance update を **round up** に変更し、repeated micro-withdrawals によって pool の active balance が段階的に低下できないようにする。<sup>[[7]](#references)</sup>

Simplified vulnerable line (and post-mortem fix)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- Pool は non-zero hooks address を使用しているか？どの callbacks が有効化されているか？
- per-swap の redistribution/rebalance が custom math を使用しているか？tick/threshold ロジックはあるか？
- divisions/mulDiv、Q64.96 conversions、または SafeCast はどこで使用されているか？rounding semantics は全体で一貫しているか？
- 境界をかろうじて超え、都合のよい rounding branch を選択する Δin を構成できるか？両方向、および exactInput と exactOutput の両方をテストする。
- hook は caller ごとの credits または deltas を追跡し、後で withdraw できるようにしているか？residue が neutralized されていることを確認する。

## References

- [1] [Bunni V2 Exploit：Liquidity Flaw により $8.3M が Drained（summary）](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit：Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Uniswap v4 の background（QuillAudits research）](https://www.quillaudits.com/research/uniswap-development)
- [4] [Uniswap v4 core における Liquidity mechanics](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Uniswap v4 core における Swap mechanics](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Bunni Exploit Post Mortem（Sep 2025）](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
