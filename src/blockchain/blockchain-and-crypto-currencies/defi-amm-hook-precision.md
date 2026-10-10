# DeFi/AMM Exploitation: Uniswap v4 Hookの精度/丸め誤差の悪用

{{#include ../../banners/hacktricks-training.md}}

このページでは、カスタムhookでコアの計算処理を拡張するUniswap v4形式のDEXを標的とした、DeFi/AMM exploitation手法について解説します。Bunni V2のインシデントでは、出金処理の計算で丸め方向を誤り、アクティブな流動性を過小評価していたことが関連する問題として確認されました。その後のswapで、この過小評価が利益を生むサンドイッチ攻撃に利用されました。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

要点: hookが固定小数点演算、tickの丸め、しきい値ロジックに依存する追加の会計処理を実装している場合、攻撃者は特定のしきい値をまたぐようにexact-input swapを調整し、丸め誤差を積み重ねて利益を得られます。このパターンを繰り返し、膨らんだ残高を出金することで利益を確定します。多くの場合、資金にはflash loanを利用します。

## 背景: Uniswap v4のhookとswapの流れ

- hookは、PoolManagerが特定のライフサイクル上のタイミング（例: beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity、beforeInitialize/afterInitialize、beforeDonate/afterDonate）で呼び出すコントラクトです。<sup>[[4]](#references)</sup>
- プールはhookコントラクトを含むPoolKeyで初期化されます。hookアドレスがゼロ以外の場合、そのプールで選択されたcallbackが有効になります。<sup>[[4]](#references)[[14]](#references)</sup>
- hookは**custom delta**を返し、swapや流動性操作による最終的な残高変化を変更できます（custom accounting）。これらのdeltaは呼び出しの最後に差し引き後の残高として精算されるため、hook内の計算で生じた丸め誤差は精算前に累積します。<sup>[[4]](#references)</sup>
- コアの計算処理では、sqrtPriceX96に使われるQ64.96などの固定小数点形式や、1.0001^tickを用いたtick計算が使われます。その上に独自の計算処理を重ねる場合、不変条件がずれないよう、丸めの仕様を慎重に合わせる必要があります。<sup>[[12]](#references)[[13]](#references)</sup>
- swapにはexactInputとexactOutputがあります。v3/v4では、価格はtickに沿って変動し、tick境界を越えるとレンジ流動性が有効化または無効化される場合があります。hookは、しきい値やtickの通過時に追加のロジックを実装できます。<sup>[[9]](#references)[[11]](#references)</sup>

## 脆弱性の類型: しきい値通過時の精度/丸め誤差の蓄積

カスタムhookで典型的に見られる脆弱なパターン:

1. hookが整数除算、mulDiv、固定小数点変換（例: sqrtPriceとtickレンジを使ったtokenと流動性の相互変換）で、swapごとの流動性または残高のdeltaを計算する。
2. しきい値ロジック（例: リバランス、段階的な再分配、レンジごとの有効化）が、swap量または価格変動が内部境界を越えたときに発動する。
3. 順方向の計算と精算処理で、丸め方法に一貫性がない（例: ゼロ方向への切り捨て、floorとceilの違い）。小さな誤差が相殺されず、呼び出し元へのクレジットになる。
4. 境界をまたぐよう正確にサイズを調整したexact-input swapで、正の丸め剰余を繰り返し回収する。攻撃者は後で累積したクレジットを出金する。

攻撃の前提条件
- swapのたびに追加の計算処理（例: LDF/rebalancer）を行うカスタムv4 hookを使ったプール。
- しきい値をまたぐ際の丸めによって、swap開始者が有利になる実行パスが少なくとも1つ存在する。
- 多数のswapをアトミックに繰り返せること（一時的な資金を用意し、ガス代を効率化するにはflash loanが最適）。

## 実践的な攻撃手法

1) hookを使った候補プールを特定する
- v4プールを列挙し、PoolKey.hooks != address(0)であることを確認する。
- hookのbytecode/ABIを調査し、callback（beforeSwap/afterSwap）やカスタムのリバランス用メソッドを探す。
- 流動性での除算、token量と流動性の相互変換、またはBalanceDeltaの丸めを伴う集計処理を探す。

2) hookの計算処理としきい値をモデル化する
- hookの流動性/再分配の式を再現する。入力には通常、sqrtPriceX96、tickLower/Upper、currentTick、fee tier、net liquidityが含まれる。
- しきい値/step関数を特定する。例: tick、bucket境界、LDFのbreakpoint。各境界のどちら側にdeltaが丸められるかを確認する。
- uint256/int256間の変換、SafeCastの使用、または暗黙的なfloorを伴うmulDivの使用箇所を特定する。

3) 境界を越えるexact-input swapを調整する
- Foundry/Hardhatでシミュレーションを行い、価格を境界のすぐ向こうまで動かしてhookの分岐を発動させるのに必要な最小Δinを計算する。
- afterSwapの精算で、コストを上回る額が呼び出し元に付与され、正のBalanceDeltaまたはhookの会計処理上のクレジットが残ることを確認する。
- swapを繰り返してクレジットを累積し、その後hookの出金/精算パスを呼び出す。

v4では、swapループはPoolManagerのunlock callbackから実行する必要があります。負の`amountSpecified`はexact inputを示し、`sqrtPriceLimitX96`は有効範囲の内側に厳密に収まっていなければなりません。price limitがゼロだとrevertするため、以下のpseudocodeではzero-for-one swapに下限値を使います。<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Foundry形式のテストハーネス例（pseudocode）
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
- core TickMath で目標値を計算する: 実数値では sqrtP_next = sqrtP_current × 1.0001^(Δtick)。Q64.96 の結果は TickMath によって丸められる。<sup>[[13]](#references)</sup>
- Q64.96 を考慮した式を使って、token0（zero-for-one）の入力を近似する: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)。core ルーチンの方向ごとの丸めに合わせる。<sup>[[12]](#references)</sup>
- 境界付近で Δin を ±1 wei 調整し、hook に有利な丸めが行われる分岐を見つける。

4) フラッシュローンで増幅する
- 大きな額（例: 300万 USDT または 2000 WETH）を借りて、多数の反復処理をアトミックに実行する。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- キャリブレーションした swap ループを実行し、その後、フラッシュローンのコールバック内で引き出して返済する。

Aave V3 フラッシュローンのスケルトン
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

5) Exitとクロスチェーンでの再現
- 複数のチェーンにhookがデプロイされている場合は、チェーンごとに同じキャリブレーションを繰り返す。
- Bunniのインシデントでは、flash-loanの流動性とブリッジ経路がチェーンごとに異なっていたため、分析を再現する際はチェーン固有の制約を考慮する。<sup>[[1]](#references)[[2]](#references)</sup>

## hookの計算処理における一般的な根本原因

- 丸め方式の混在: mulDivは切り捨てる一方、後続の処理では実質的に切り上げている、またはtokenと流動性の変換で異なる丸め方式を適用している。
- tickのアラインメントエラー: ある処理では丸めていないtickを使い、別の処理ではtick間隔に合わせて丸めている。
- 決済時にint256とuint256を変換する際のBalanceDeltaの符号やオーバーフローの問題。
- Q64.96変換（sqrtPriceX96）で発生する精度損失が、逆変換に反映されていない。
- 累積処理経路: swapごとの余りを、焼却したりゼロサムにしたりせず、呼び出し元が引き出せるクレジットとして記録する。

## カスタム会計とdeltaの増幅

- Uniswap v4のカスタム会計では、hookがdeltaを返して、呼び出し元の支払い額や受取額を直接調整できる。hookが内部的にクレジットを記録している場合、最終的な決済が行われる前に、小規模な操作を何度も行うことで丸め誤差が蓄積する可能性がある。<sup>[[4]](#references)</sup>
- hookに互換性のある引き出し経路がある場合、攻撃者は同じPoolManagerのunlock callback内で `swap → withdraw → swap` を交互に実行できる。これにより、unlockの決済まで残高が保留されたまま、わずかに異なる状態でhookにdeltaを再計算させられる。<sup>[[4]](#references)[[10]](#references)</sup>
- hookをレビューする際は、BalanceDelta/HookDeltaがどのように生成され、決済されるかを必ず追跡する。ある分岐で丸めに偏りがあると、deltaが繰り返し再計算されることで、累積するクレジットになり得る。

## 防御策

- 差分テスト: 高精度の有理数演算を使った参照実装とhookの計算処理を比較し、結果が一致すること、または誤差が常に攻撃者に有利にならない範囲内であることを検証する。
- 不変条件・プロパティテスト:
  - swap経路とhookによる調整を通じたdelta（token、流動性）の合計で、手数料を除く価値が必ず保たれること。
  - exactInputを繰り返し実行しても、swapの開始者に正味のクレジットが生じる経路がないこと。
  - exactInput/exactOutputの両方で、±1 weiの入力を含むしきい値・tick境界のテストを行う。
- 丸め方針: 丸め処理を常にユーザーに不利になるように行うヘルパーに集約し、一貫性のないキャストや暗黙の切り捨てをなくす。
- 決済時の余剰処理: 避けられない丸め余剰はプロトコルのトレジャリーに集約するか、焼却する。決してmsg.senderに割り当てない。
- レート制限・ガードレール: リバランスのトリガーに最小swapサイズを設ける。deltaがsub-weiの場合はリバランスを無効にし、deltaが想定範囲内かを検証する。
- hook callbackを包括的にレビューする: beforeSwap/afterSwapと流動性変更前後の処理で、tickのアラインメントとdeltaの丸め方が一致することを確認する。

## ケーススタディ: Bunni V2（2025-09-02）

- プロトコル: Liquidity Density Function（LDF）を使用してtoken密度と総流動性の推定値を計算する、Uniswap v4 hookのBunni V2。<sup>[[1]](#references)[[2]](#references)</sup>
- 影響を受けたプール: Ethereum上のUSDC/USDTと、Unichain上のweETH/ETH。合計で約$8.4M。<sup>[[1]](#references)</sup>
- ステップ1（価格の押し上げ）: 攻撃者は約3M USDTをflash-borrowし、swapしてtickを約5000まで押し上げ、**active** USDC残高を約28 weiまで減らした。<sup>[[1]](#references)</sup>
- ステップ2（丸め誤差による流出）: 44回の少額引き出しで、`BunniHubLogic::withdraw()`の切り捨てを悪用し、LPシェアをほんの一部しか焼却せずに、active USDC残高を28 weiから4 weiへ減らした（-85.7%）。総流動性は約84.4%減少した。<sup>[[1]](#references)[[2]](#references)</sup>
- ステップ3（流動性の回復を利用したサンドイッチ）: 大規模なswapでtickを約839,189まで動かした（1 USDC ≈ 2.77e36 USDT）。流動性の推定値が反転して約16.8%増加し、攻撃者は価格が水増しされた状態でswapを戻して利益を得るサンドイッチが可能になった。<sup>[[1]](#references)</sup>
- 事後分析で特定された修正: idle残高の更新時に切り上げるよう変更し、少額の引き出しを繰り返してもプールのactive残高が段階的に減少しないようにする。<sup>[[1]](#references)</sup>

脆弱なコードの簡略化例（および事後分析での修正）。<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Hunting checklist

- poolはnon-zeroのhooks addressを使用しているか？どのcallbacksが有効か？
- swapごとに、独自の計算を使った再分配／リバランスがあるか？tick／thresholdのロジックはあるか？
- division、mulDiv、Q64.96 conversion、SafeCastはどこで使われているか？丸めのセマンティクスは全体で一貫しているか？
- 境界をわずかに超えるΔinを構成し、有利な丸め分岐を発生させられるか？両方向とexactInput、exactOutputの両方をテストする。
- hookは、後でwithdraw可能なcallerごとのcreditやdeltaを追跡しているか？残余分を無効化すること。

## References

- [1] [Bunni Exploitの事後分析（2025年9月）](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit：ハッキングの全容分析](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit：流動性の欠陥により830万ドルが流出（概要）](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Coreホワイトペーパー](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4の背景（QuillAuditsの調査）](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 coreにおける流動性の仕組み](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 coreにおけるswapの仕組み](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooksとセキュリティ上の考慮事項](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 coreのPool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 coreのPoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4のSwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 coreのSqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 coreのTickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4のPoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
