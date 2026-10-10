# DeFi/AMM Exploitation: Uniswap v4 Hookの精度/丸め悪用

{{#include ../../banners/hacktricks-training.md}}

このページでは、カスタムhookでコアの数学処理を拡張するUniswap v4形式のDEXを対象とした、DeFi/AMM exploitation手法の一種について説明します。Bunni V2のインシデントでは、関連する不具合が明らかになりました。出金時の計上における丸め方向のバグにより、アクティブな流動性が過小評価され、その後のswapでその過小評価が利益を生むsandwich攻撃に利用されました。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

重要な考え方は次のとおりです。hookが固定小数点演算、tickの丸め、閾値ロジックに依存する追加の計上処理を実装している場合、攻撃者は特定の閾値を越えるよう正確に調整したexact-input swapを実行し、丸め誤差を自分に有利な形で蓄積できます。このパターンを繰り返した後、膨らんだ残高を引き出して利益を確定します。資金にはflash loanが使われることがよくあります。

## 背景: Uniswap v4のhookとswapの流れ

- hookは、特定のライフサイクル時点（例: beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity、beforeInitialize/afterInitialize、beforeDonate/afterDonate）でPoolManagerから呼び出されるコントラクトです。<sup>[[4]](#references)</sup>
- poolはhookコントラクトを含むPoolKeyで初期化されます。hookアドレスがゼロ以外の場合、そのpoolでは選択されたcallbackが有効になります。<sup>[[4]](#references)[[14]](#references)</sup>
- hookは、swapや流動性操作の最終的な残高変動を変更する**custom delta**を返せます（custom accounting）。これらのdeltaは呼び出しの最後に純残高として精算されるため、精算前にhookの計算内で発生した丸め誤差は累積します。<sup>[[4]](#references)</sup>
- コアの数学処理ではsqrtPriceX96のQ64.96などの固定小数点形式と、1.0001^tickによるtick演算を使用します。その上に重ねるカスタム計算では、invariantのずれを避けるため、丸めの意味を慎重に一致させる必要があります。<sup>[[12]](#references)[[13]](#references)</sup>
- swapにはexactInputとexactOutputがあります。v3/v4では価格はtickに沿って動き、tick境界を越えるとレンジ流動性が有効化または無効化されることがあります。hookがtickや閾値の通過に応じた追加ロジックを実装している場合もあります。<sup>[[9]](#references)[[11]](#references)</sup>

## 脆弱性のパターン: 閾値通過時の精度/丸め誤差の蓄積

カスタムhookでよく見られる脆弱なパターン:

1. hookが整数除算、mulDiv、固定小数点変換（例: sqrtPriceとtick範囲を使ったtokenとliquidity間の変換）で、swapごとの流動性または残高deltaを計算する。
2. 閾値ロジック（例: リバランス、段階的な再分配、レンジごとの有効化）が、swap量または価格変動が内部境界を越えたときに実行される。
3. 順方向の計算と精算経路で、丸め処理に一貫性がない（例: ゼロ方向への切り捨て、floorとceilの使い分け）。小さな誤差は相殺されず、代わりに呼び出し元へ利益を与える。
4. 境界をまたぐよう正確に調整したexact-input swapで、正の丸め剰余を繰り返し回収する。攻撃者は後で累積したcreditを引き出す。

攻撃の前提条件
- swapごとに追加計算を実行するカスタムv4 hook（例: LDF/rebalancer）を使用するpool。
- 閾値をまたぐ際、丸めによってswap開始者が有利になる実行経路が少なくとも1つある。
- 多数のswapをアトミックに繰り返せること（一時的な資金を用意し、gasを償却するにはflash loanが理想的）。

## 実践的な攻撃手法

1) hookを持つ候補poolを特定する
- v4 poolを列挙し、PoolKey.hooks != address(0)であることを確認する。
- hookのbytecode/ABIを調べ、callback（beforeSwap/afterSwap）やカスタムのリバランス用メソッドを確認する。
- 次のような計算を探す: liquidityによる除算、token量とliquidityの相互変換、丸めを伴うBalanceDeltaの集計。

2) hookの計算と閾値をモデル化する
- hookの流動性/再分配の式を再現する。入力には通常、sqrtPriceX96、tickLower/Upper、currentTick、fee tier、net liquidityが含まれる。
- 閾値/段階関数を特定する: tick、bucket境界、LDFのbreakpointなど。各境界のどちら側でdeltaが丸められるかを確認する。
- uint256/int256間のcast、SafeCastの使用箇所、暗黙のfloorを伴うmulDivへの依存箇所を特定する。

3) 境界を越えるようexact-input swapを調整する
- Foundry/Hardhatでシミュレーションし、価格を境界のすぐ向こうまで動かしてhookの分岐を実行するために必要な最小Δinを計算する。
- afterSwapの精算で、呼び出し元にswapコストを上回る額がcreditされ、正のBalanceDeltaまたはhookの計上上のcreditが残ることを確認する。
- swapを繰り返してcreditを累積し、その後hookの出金/精算経路を呼び出す。

v4ではswapループをPoolManagerのunlock callbackから実行する必要があります。負の`amountSpecified`はexact inputを示し、`sqrtPriceLimitX96`は有効範囲の内側に設定しなければなりません。価格制限をゼロにするとrevertするため、以下の疑似コードではzero-for-one swapに下限値を使用します。<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Foundry形式のテストハーネス例（疑似コード）
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
- core TickMath で目標値を計算します。実数値では sqrtP_next = sqrtP_current × 1.0001^(Δtick) となり、Q64.96 の結果は TickMath によって丸められます。<sup>[[13]](#references)</sup>
- Q64.96 を考慮した式で token0（zero-for-one）の入力値を概算します。Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)。core ルーチンの方向ごとの丸めに合わせます。<sup>[[12]](#references)</sup>
- 境界付近で Δin を ±1 wei ずつ調整し、hook の丸めが有利になる分岐を見つけます。

4) flash loan で増幅する
- 多数の反復をアトミックに実行するため、大きな名目額（例: 3M USDT または 2000 WETH）を借り入れます。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- 調整した swap ループを実行し、flash loan のコールバック内で引き出して返済します。

Aave V3 flash loan のスケルトン
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
- 複数のチェーンにhookがデプロイされている場合は、チェーンごとに同じキャリブレーションを繰り返します。
- Bunniのインシデントでは、フラッシュローンの流動性とブリッジ経路がチェーンごとに異なっていたため、分析を再現する際はチェーン固有の制約を考慮してください。<sup>[[1]](#references)[[2]](#references)</sup>

## hookの計算処理における一般的な根本原因

- 丸め処理の意味が混在している: mulDivは切り捨てる一方で、後続の処理では実質的に切り上げている。または、トークンと流動性の変換で異なる丸め処理を適用している。
- Tickのアラインメントエラー: ある処理では丸めていないtickを使い、別の処理ではtick間隔に合わせて丸めている。
- 決済時にint256とuint256を変換する際のBalanceDeltaの符号やオーバーフローの問題。
- Q64.96変換（sqrtPriceX96）で生じる精度損失が、逆変換に反映されていない。
- 蓄積経路: swapごとの余りをクレジットとして記録し、焼却したりゼロサムにしたりせず、呼び出し元が引き出せるようにしている。

## カスタム会計とdeltaの増幅

- Uniswap v4のカスタム会計では、hookがdeltaを返し、呼び出し元が支払う額や受け取る額を直接調整できます。hookがクレジットを内部で追跡する場合、最終的な決済が行われる**前に**、多数の小さな操作を通じて丸め誤差が蓄積する可能性があります。<sup>[[4]](#references)</sup>
- hookが互換性のある引き出し経路を提供している場合、攻撃者は同じPoolManagerのunlock callback内で `swap → withdraw → swap` を交互に実行できます。これにより、残高がunlockの決済まで保留されている間に、わずかに異なる状態でhookにdeltaを再計算させられます。<sup>[[4]](#references)[[10]](#references)</sup>
- hookをレビューする際は、BalanceDelta/HookDeltaがどのように生成され、決済されるかを必ず追跡してください。1つの分岐に偏った丸め処理があるだけで、deltaが繰り返し再計算されるうちに、累積するクレジットになる可能性があります。

## 防御の指針

- 差分テスト: 高精度の有理数演算を使った参照実装とhookの計算処理を照合し、結果の一致、または常に攻撃者に有利にならない（呼び出し元に有利にならない）誤差範囲を検証します。
- 不変条件・プロパティテスト:
  - swap経路とhookによる調整を通じたdelta（トークン、流動性）の合計は、手数料を除いて価値を保存する必要があります。
  - exactInputを繰り返しても、どの経路でもswap開始者に正味のクレジットが生じてはなりません。
  - exactInputとexactOutputの両方について、±1 weiの入力を使い、しきい値・tick境界でテストします。
- 丸めポリシー: ユーザーに不利になる方向に常に丸める共通ヘルパーを用意し、一貫性のないキャストや暗黙の切り捨てをなくします。
- 決済先: 避けられない丸め誤差はプロトコルのトレジャリーに蓄積するか焼却し、決してmsg.senderに割り当てません。
- レート制限・ガードレール: リバランスのトリガーに最小swapサイズを設けます。deltaがsub-weiの場合はリバランスを無効にし、deltaが想定範囲内かを検証します。
- hook callbackを全体としてレビューします: beforeSwap/afterSwapと、流動性変更前後の処理で、tickのアラインメントとdeltaの丸め処理が一致している必要があります。

## 事例: Bunni V2 (2025‑09‑02)

- プロトコル: Bunni V2。Liquidity Density Function (LDF)を使ってトークン密度と総流動性の推定値を計算するUniswap v4 hookです。<sup>[[1]](#references)[[2]](#references)</sup>
- 影響を受けたプール: Ethereum上のUSDC/USDTと、Unichain上のweETH/ETH。合計約$8.4M。<sup>[[1]](#references)</sup>
- ステップ1（価格操作）: 攻撃者は約3M USDTをフラッシュ借入し、swapしてtickを約5000まで動かし、**アクティブ**なUSDC残高を約28 weiまで減らしました。<sup>[[1]](#references)</sup>
- ステップ2（丸め誤差の悪用）: 44回の少額引き出しで、`BunniHubLogic::withdraw()`の切り捨て処理を悪用し、LPシェアのごく一部だけを焼却しながら、アクティブなUSDC残高を28 weiから4 weiへ減らしました（-85.7%）。総流動性は約84.4%減少しました。<sup>[[1]](#references)[[2]](#references)</sup>
- ステップ3（流動性の急増を利用したサンドイッチ）: 大規模なswapでtickを約839,189（1 USDC ≈ 2.77e36 USDT）まで動かしました。流動性の推定値が反転して約16.8%増加したため、攻撃者は価格がつり上がった状態でswapを戻し、利益を得て退出するサンドイッチが可能になりました。<sup>[[1]](#references)</sup>
- 事後分析で特定された修正: アイドル残高の更新時に切り上げるよう変更し、細かな引き出しを繰り返してもプールのアクティブ残高が徐々に減少しないようにします。<sup>[[1]](#references)</sup>

脆弱な行の簡略版（および事後分析での修正）。<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## 脆弱性調査チェックリスト

- プールはゼロ以外の hooks address を使用しているか？有効になっている callback はどれか？
- swap ごとに、独自の計算を使った再分配／リバランスが行われているか？tick／threshold のロジックはあるか？
- 除算、mulDiv、Q64.96 変換、SafeCast はどこで使われているか？丸めの仕様は全体で一貫しているか？
- 境界をわずかに超える Δin を構成し、有利な丸め分岐を発生させられるか？両方向と exactInput、exactOutput の両方をテストする。
- hook は、後で引き出せる caller ごとのクレジットや差分を追跡しているか？残余が中立化されることを確認する。

## References

- [1] [Bunni Exploit の事後分析（2025年9月）](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit：完全なハック分析](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit：流動性の欠陥により830万ドルが流出（概要）](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 コアのホワイトペーパー](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 の背景（QuillAudits の調査）](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 コアにおける流動性の仕組み](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 コアにおける swap の仕組み](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks とセキュリティ上の考慮事項](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 コア Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 コア PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 コア SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 コア TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
