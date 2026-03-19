# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



このページは、Uniswap v4 スタイルの DEX に対する、コアの数学にカスタム hook を拡張した実装を狙う DeFi/AMM 攻撃手法の一群を解説する。最近の Bunni V2 のインシデントでは、各スワップで実行される Liquidity Distribution Function (LDF) における丸め/精度の欠陥を突かれ、攻撃者が正のクレジットを蓄積して流動性を抜き取ることが可能になった。

主要な着眼点：hook が fixed‑point math、tick の丸め、閾値ロジックに依存する追加の会計処理を実装している場合、攻撃者は exact‑input スワップを精密に作成して特定の閾値を跨がせ、丸めの不一致を有利に累積させることができる。これを繰り返して蓄積した残高を引き出すことで利益を実現することが多く、flash loan で資金を調達して行うのが典型的である。

## Background: Uniswap v4 hooks and swap flow

- Hooks は PoolManager がライフサイクルの特定ポイント（例: beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate）で呼び出すコントラクトである。
- Pools は PoolKey に hooks address を含めて初期化される。non‑zero であれば、PoolManager は関連操作ごとにコールバックを実行する。
- Hooks はスワップや流動性操作の最終的な残高変化を変更する **custom deltas** を返すことができる（カスタム会計）。これらのデルタはコールの終了時にネット残高として決済されるため、hook 内の数学での丸め誤差は決済前に累積される。
- Core math は sqrtPriceX96 に Q64.96 のような fixed‑point フォーマットや、1.0001^tick を用いる tick 算術を使う。上に重ねる任意のカスタム数学は丸めのセマンティクスを厳密に合わせないとインバリアントのずれを招く。
- Swaps は exactInput または exactOutput になり得る。v3/v4 では価格が tick に沿って動く；tick 境界の跨ぎはレンジ流動性の有効化/無効化を引き起こすことがある。Hooks は閾値/ティックの跨ぎで追加ロジックを実装することがある。

## Vulnerability archetype: threshold‑crossing precision/rounding drift

カスタム hook における典型的な脆弱パターン:

1. Hook は整数除算、mulDiv、または fixed‑point 変換（例: token ↔ liquidity を sqrtPrice と tick 範囲を使って計算）を用いてスワップごとの流動性や残高デルタを計算する。
2. 閾値ロジック（例: リバランス、段階的再配分、レンジごとの有効化）はスワップサイズや価格変動が内部境界を越えたときにトリガーされる。
3. 前方計算と決済経路で丸めが一貫して適用されない（例: 0 方向への切り捨て、floor と ceil の不一致）。小さな差分は打ち消されず、代わりに呼び出し元にクレジットされる。
4. 閾値をまたぐよう精密にサイズ調整した exact‑input スワップが正の丸め残余を繰り返し回収する。攻撃者は後で蓄積されたクレジットを引き出す。

攻撃の前提条件
- 各スワップで追加の数学を行うカスタム v4 hook を使っているプール（例: LDF/リバランサ）。
- 閾値跨ぎにおいて丸めがスワップ開始者に有利に働く実行パスが少なくとも一つ存在すること。
- 多数のスワップを原子的に繰り返す能力（flash loans は一時的な資金供給とガス分散に好適）。

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 プールを列挙し、PoolKey.hooks != address(0) を確認する。
- hook の bytecode/ABI を検査し、beforeSwap/afterSwap やカスタムのリバランス系メソッドを探す。
- liquidity で除算している、token と liquidity の間で変換している、または丸めを伴う BalanceDelta を集約しているような数学がないかを探す。

2) Model the hook’s math and thresholds
- hook の流動性/再配分の式を再現する: 入力には通常 sqrtPriceX96, tickLower/Upper, currentTick, fee tier, net liquidity などが含まれる。
- 閾値/ステップ関数をマッピングする: tick、バケット境界、LDF のブレークポイント。各境界のどちら側でデルタが丸められるかを特定する。
- どこで uint256/int256 間のキャスト、SafeCast を使っているか、または暗黙的に floor を採る mulDiv に依存しているかを特定する。

3) Calibrate exact‑input swaps to cross boundaries
- Foundry/Hardhat のシミュレーションで、価格をちょうど境界の向こうへ動かし hook の分岐をトリガーするために必要な最小 Δin を計算する。
- afterSwap 決済後にコストよりも呼び出し元に多くクレジットされ、正の BalanceDelta または hook の会計上のクレジットが残ることを検証する。
- スワップを繰り返してクレジットを蓄積し、最後に hook の引き出し/決済パスを呼び出す。

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
exactInput の較正
- tick ステップに対する ΔsqrtP を計算する: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- v3/v4 の式を使って Δin を近似する: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). 丸め方向が core math と一致することを確認する。
- 境界付近で Δin を ±1 wei ずつ調整し、hook が自分に有利に丸める分岐を見つける。

4) flash loans で増幅する
- 多数のイテレーションを原子的に実行するために、大きな notional を借りる（例: 3M USDT や 2000 WETH）。
- キャリブレーションした swap ループを実行し、flash loan callback 内で引き出しと返済を行う。

Aave V3 の flash loan skeleton
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
5) Exit とクロスチェーン複製
- フックが複数のチェーンにデプロイされている場合、チェーンごとに同じキャリブレーションを繰り返す。
- Bridge はターゲットチェーンに戻り、フローを難読化するために貸付プロトコル経由で循環させることがある。

## フックの数学における一般的な根本原因

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between トークン/流動性 apply different rounding.
- ティック整合性エラー：一方のパスで未丸めのティックを使用し、別のパスでティック間隔に合わせた丸めを行う。
- 決済時に int256 と uint256 の間で変換する際の BalanceDelta の符号/オーバーフローの問題。
- Q64.96 変換（sqrtPriceX96）での精度損失が逆マッピングで反映されていない問題。
- 蓄積経路：スワップごとの残差がバーン/ゼロサムではなく、呼び出し元が引き出せるクレジットとして追跡される。

## カスタム会計とデルタ増幅

- Uniswap v4 カスタム会計では、hooks が呼び出し元の債務/受取額を直接調整する deltas を返せる。フックが内部でクレジットを追跡すると、最終決済が行われる**前**に丸めの残差が多数の小さな操作に渡って蓄積する可能性がある。
- これにより境界/閾値の悪用が強化される：攻撃者は同じ tx 内で `swap → withdraw → swap` を交互に行い、すべての残高がまだ保留中である間にフックにわずかに異なる状態で deltas を再計算させることができる。
- フックをレビューする際は、常に BalanceDelta/HookDelta がどのように生成・精算されるかを追跡すること。ある枝での単一の偏った丸めが、deltas が繰り返し再計算されると複利的なクレジットになることがある。

## 防御ガイダンス

- 差分テスト：高精度有理数演算を用いてフックの数学を参照実装と比較し、常に攻撃者不利（呼び出し元に有利にならない）となる等価性または有界誤差をアサートする。
- 不変量/プロパティテスト：
- スワップ経路とフック調整全体にわたる deltas（トークン、流動性）の合計は、手数料を除けば価値を保存していなければならない。
- どの経路も、繰り返される exactInput イテレーションに対してスワップ開始者に正の純クレジットを生成してはならない。
- exactInput/exactOutput の両方について、±1 wei 入力周辺の閾値/ティック境界テストを行う。
- 丸めポリシー：常にユーザーに不利になる方向に丸める共通の丸めヘルパーを集中させ、矛盾するキャストや暗黙の切り捨てを排除する。
- 決済シンク：避けられない丸め残差はプロトコルのトレジャリーに蓄積するかバーンし、決して msg.sender に帰属させない。
- レート制限/ガードレール：リバランスをトリガーする最小スワップサイズを設定する；deltas がサブワイ（sub-wei）の場合はリバランスを無効にする；deltas を期待レンジと照合して正当性を確認する。
- フックコールバックを包括的にレビューする：beforeSwap/afterSwap と流動性変更の before/after は、ティックの整列とデルタの丸めについて一致しているべきである。

## ケーススタディ: Bunni V2 (2025‑09‑02)

- プロトコル：Bunni V2 (Uniswap v4 hook)、各スワップごとにリバランスのための LDF が適用されていた。
- 影響を受けたプール：Ethereum 上の USDC/USDT と Unichain 上の weETH/ETH、合計で約 $8.4M。
- Step 1 (price push): the attacker flash‑borrowed ~3M USDT and swapped to push the tick to ~5000, shrinking the **アクティブ** USDC balance down to ~28 wei.
- Step 2 (rounding drain): 44 tiny withdrawals exploited floor rounding in `BunniHubLogic::withdraw()` to reduce the active USDC balance from 28 wei to 4 wei (‑85.7%) while only a tiny fraction of LP shares was burned. Total liquidity was underestimated by ~84.4%.
- Step 3 (liquidity rebound sandwich): a large swap moved the tick to ~839,189 (1 USDC ≈ 2.77e36 USDT). Liquidity estimates flipped and increased by ~16.8%, enabling a sandwich where the attacker swapped back at the inflated price and exited with profit.
- ポストモーテムで特定された修正：idle‑balance の更新を **切り上げ** に変更し、繰り返しのマイクロ引き出しでプールのアクティブ残高が段階的に減少することを防ぐ。

簡略化された脆弱な行（およびポストモーテムの修正）
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## ハンティングチェックリスト

- プールは non‑zero の hooks アドレスを使用していますか？どの callbacks が有効になっていますか？
- per‑swap ごとにカスタムな数学で再分配／リバランスが行われていますか？tick/threshold ロジックはありますか？
- divisions/mulDiv、Q64.96 conversions、または SafeCast はどこで使われていますか？丸めのセマンティクスは全体で一貫していますか？
- 境界をかろうじて跨ぐような Δin を構築して、有利な丸めの分岐を誘発できますか？両方向および exactInput と exactOutput の両方をテストしてください。
- hook は後で引き出せる per‑caller の credits や deltas を追跡していますか？残留（residue）が中和されていることを確認してください。

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
