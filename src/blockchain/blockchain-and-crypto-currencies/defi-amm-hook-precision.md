# DeFi/AMM 攻撃: Uniswap v4 Hook 精度/丸めの悪用

{{#include ../../banners/hacktricks-training.md}}

このページは、カスタム hook でコア演算に拡張を加える Uniswap v4 スタイルの DEX に対する一連の DeFi/AMM 攻撃手法を記録するものです。最近の Bunni V2 のインシデントでは、各 swap 実行時に走る Liquidity Distribution Function (LDF) における丸め／精度の欠陥を突かれ、攻撃者が正のクレジットを蓄積して流動性を抜き取ることを可能にしました。

キーアイデア: hook が fixed‑point 演算、tick の丸め、しきい値ロジックに依存する追加の会計処理を実装している場合、攻撃者はしきい値を跨ぐように精密に exact‑input swap を作成して丸め差分を自分に有利に蓄積させることができます。このパターンを繰り返してから膨らんだ残高を引き出すことで利益を確定します。多くの場合、flash loan で一時的な資金を調達してガスを分散します。

## 背景: Uniswap v4 hooks と swap フロー

- Hooks は PoolManager がライフサイクルの特定のポイント（例: beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity）で呼び出すコントラクトです。
- Pools は PoolKey に hooks アドレスを含めて初期化されます。非ゼロであれば、PoolManager は関連する各操作でコールバックを実行します。
- コア演算は Q64.96 のような fixed‑point 形式（sqrtPriceX96）や 1.0001^tick を用いる tick 演算を使用します。上に重ねる任意のカスタム演算は、丸めのセマンティクスを慎重に揃えないとインバリアントのドリフトを招きます。
- Swaps は exactInput または exactOutput になり得ます。v3/v4 では価格が tick に沿って移動し、tick 境界を跨ぐと範囲流動性の有効化/無効化が発生することがあります。Hooks はしきい値／tick のクロッシングで追加ロジックを実装することがあります。

## 脆弱性の典型: しきい値跨ぎでの精度／丸めドリフト

カスタム hook でよく見られる脆弱なパターン:

1. Hook は各 swap ごとに整数除算、mulDiv、または fixed‑point 変換（例: token ↔ liquidity を sqrtPrice や tick 範囲で換算）を使って流動性や残高のデルタを計算する。
2. 再バランスや段階的再配分、レンジごとの有効化などのしきい値ロジックが、swap サイズや価格変動が内部境界を越えたときに発動する。
3. 順方向計算と清算パスで丸めが一貫して適用されていない（ゼロ方向への切り捨て、floor と ceil の不一致など）。小さな差分は打ち消されずに呼び出し元に有利に残る。
4. 境界を跨ぐように正確にサイズ調整した exact‑input swap を繰り返し、正の丸め残差を収穫する。攻撃者は後で蓄積されたクレジットを引き出す。

攻撃の前提条件
- 各 swap で追加の演算を行うカスタム v4 hook を使っているプール（例: LDF／rebalancer）。
- しきい値跨ぎで swap 発起者に丸めが有利に働く少なくとも一つの実行パスが存在すること。
- 多数の swap をアトミックに繰り返す能力（flash loans は一時的資金を供給してガスを相殺するのに理想的）。

## 実践的攻撃手順

1) Hook を持つ候補プールを特定する
- v4 プールを列挙し、PoolKey.hooks != address(0) をチェックする。
- Hook の bytecode/ABI を調べ、beforeSwap/afterSwap や任意の再バランス用メソッドを確認する。
- 流動性で割る演算、token と liquidity の換算、または BalanceDelta を丸めで集計するような数学処理を探す。

2) Hook の演算としきい値をモデル化する
- Hook の liquidity/redistribution 公式を再現する: 入力は通常 sqrtPriceX96、tickLower/Upper、currentTick、fee tier、net liquidity などを含む。
- tick、バケット境界、LDF のブレークポイントなどのしきい値／ステップ関数をマッピングする。どちらの側でデルタが丸められるかを判定する。
- uint256/int256 へのキャスト、SafeCast の使用、または暗黙の floor を伴う mulDiv の箇所を特定する。

3) しきい値を跨ぐように exact‑input swap を較正する
- Foundry/Hardhat のシミュレーションを使って、価格を境界ちょうど跨がせて hook の分岐をトリガーするために必要な最小の Δin を計算する。
- afterSwap の清算がコストを上回る形で呼び出し元にクレジットを付与し、正の BalanceDelta や hook の会計上のクレジットが残ることを検証する。
- スワップを繰り返してクレジットを蓄積し、最後に hook の引き出し／清算経路を呼ぶ。

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
- tickステップについて ΔsqrtP を計算する: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- v3/v4 の式を使って Δin を近似する: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). 丸めの方向がコアの計算と一致していることを確認する。
- 境界付近で Δin を ±1 wei 調整し、hook が有利に丸めるブランチを見つける。

4) Amplify with flash loans
- 多数のイテレーションを原子的に実行するために、大きな名目額（例: 3M USDT または 2000 WETH）を借りる。
- キャリブレーション済みの swap loop を実行し、その後 flash loan callback 内で引き出しと返済を行う。

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
5) 退出とクロスチェーン複製
- 複数のチェーンにhooksがデプロイされている場合、各チェーンで同じ較正を繰り返す。
- ブリッジで資金をターゲットチェーンに戻し、任意でレンディングプロトコルを経由してフローを難読化する。

## hook math における一般的な根本原因

- Mixed rounding semantics: mulDiv が切り捨てる一方で後続パスが実質的に切り上げる、または token/liquidity 間の変換で異なる丸めが適用される。
- Tick alignment errors: あるパスで未丸めの ticks を使い、別のパスで tick‑spaced の丸めを行う。
- BalanceDelta 符号/オーバーフロー問題：決済時に int256 と uint256 間で変換するときに発生する。
- Q64.96 変換（sqrtPriceX96）での精度損失が逆方向のマッピングに反映されていない。
- Accumulation pathways: スワップごとの残差がバーン/ゼロサムではなく、caller が引き出せるクレジットとして蓄積される。

## 防御ガイダンス

- Differential testing: 高精度の有理数演算を用いて hook の計算を参照実装とミラーリングし、等価性または常に攻撃者不利（決して caller に有利にならない）な有界誤差をアサートする。
- 不変量/プロパティテスト：
- スワップ経路と hook の調整にわたるデルタ（tokens、liquidity）の合計は、手数料を除いて価値を保存しなければならない。
- どの経路も、繰り返される exactInput イテレーションにおいてスワップ開始者に正の純クレジットを生じさせてはならない。
- exactInput/exactOutput の両方について、±1 wei 入力周辺の閾値/tick 境界テストを行う。
- 丸めポリシー：常にユーザー不利に丸める共通の丸めヘルパーを集中化し、不整合なキャストや暗黙の切り捨てを排除する。
- 決済シンク：回避不能な丸め残差はプロトコルのトレジャリに蓄積するか焼却し、決して msg.sender に帰属させない。
- レート制限/ガードレール：リバランスのトリガーとなる最小スワップサイズを設定する；デルタがサブ‑wei の場合はリバランスを無効にする；デルタを期待範囲と照合して妥当性を検査する。
- hook コールバックを全体的に見直す：beforeSwap/afterSwap と before/after の流動性変更は tick アラインメントとデルタの丸めについて一致しているべきである。

## ケーススタディ: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) with an LDF applied per swap to rebalance.
- Root cause: rounding/precision error in LDF liquidity accounting during threshold‑crossing swaps; per‑swap discrepancies accrued as positive credits for the caller.
- Ethereum leg: attacker took a ~3M USDT flash loan, performed calibrated exact‑input swaps on USDC/USDT to build credits, withdrew inflated balances, repaid, and routed funds via Aave.
- UniChain leg: repeated the exploit with a 2000 WETH flash loan, siphoning ~1366 WETH and bridging to Ethereum.
- Impact: ~USD 8.3M drained across chains. No user interaction required; entirely on‑chain.

## ハンティングチェックリスト

- プールは non‑zero hooks アドレスを使用しているか？どのコールバックが有効か？
- カスタム計算を使ったスワップ毎の再配分/リバランスがあるか？tick/閾値のロジックはあるか？
- Where are divisions/mulDiv, Q64.96 conversions, or SafeCast used? Are rounding semantics globally consistent?
- 境界をかろうじて越える Δin を構築して有利な丸め分岐を生むことができるか？両方向・両方の exactInput と exactOutput をテストする。
- hook は後で引き出せる per‑caller のクレジットやデルタを追跡しているか？残差が中和されていることを確認する。

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
