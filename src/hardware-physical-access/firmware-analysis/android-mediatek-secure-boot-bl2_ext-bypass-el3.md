# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

このページでは、デバイスのブートローダー設定（seccfg）が「unlocked」のときに発生する検証のギャップを悪用することで、複数の MediaTek プラットフォームに対する実践的な secure-boot の破り方を記録します。脆弱性により、パッチを当てた bl2_ext を ARM EL3 で実行して下流の署名検証を無効化でき、信頼の連鎖が崩壊し、任意の未署名 TEE/GZ/LK/Kernel のロードが可能になります。

> 注意: ブート初期でのパッチ適用は、オフセットが間違っているとデバイスを恒久的に brick させる可能性があります。必ず完全なダンプと確実なリカバリ手段を保持してください。

## 影響を受けるブートフロー (MediaTek)

- 通常の経路: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- 脆弱な経路: seccfg が「unlocked」に設定されている場合、Preloader は bl2_ext の検証をスキップすることがあります。Preloader は依然として EL3 で bl2_ext にジャンプするため、細工した bl2_ext が以降の未検証コンポーネントをロードできます。

重要な信頼境界:
- bl2_ext は EL3 で実行され、TEE、GenieZone、LK/AEE、およびカーネルの検証を担当します。もし bl2_ext 自体が認証されていなければ、残りの信頼の連鎖は容易にバイパスされます。

## 根本原因

影響を受けるデバイスでは、seccfg が「unlocked」を示す場合に Preloader が bl2_ext パーティションの認証を強制しません。これにより、攻撃者が制御する bl2_ext をフラッシュして EL3 で動作させることが可能になります。

bl2_ext 内では、検証ポリシー関数をパッチして検証が不要であると無条件に報告させることができます。最小の概念的なパッチは次のとおりです:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
この変更により、EL3 で実行されるパッチ済みの bl2_ext によってロードされる以降のすべてのイメージ (TEE, GZ, LK/AEE, Kernel) は、暗号検証なしで受け入れられます。

## ターゲットのトリアージ方法 (expdb ログ)

bl2_ext のロード周辺のブートログ（例: expdb）をダンプ／調査します。img_auth_required = 0 かつ証明書検証時間が約 0 ms の場合、enforcement は無効になっている可能性が高く、デバイスは悪用可能です。

ログ抜粋の例:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
注: 一部のデバイスでは、locked bootloader の状態でも bl2_ext の検証をスキップする報告があり、影響がさらに大きくなります。

## 実践的な exploitation ワークフロー (Fenrir PoC)

Fenrir はこのクラスの問題向けの reference exploit/patching toolkit です。Nothing Phone (2a) (Pacman) をサポートしており、CMF Phone 1 (Tetris) 上でも動作することが知られています（ただし不完全なサポートです）。他のモデルに移植するには、デバイス固有の bl2_ext の reverse engineering が必要です。

ハイレベルな手順:
- ターゲットの codename に対応する device bootloader image を取得し、bin/<device>.bin として配置する
- bl2_ext の verification policy を無効化するように patched image をビルドする
- 生成した payload をデバイスに flash する（helper スクリプトは fastboot を想定）

コマンド:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot が利用できない場合、使用しているプラットフォームに適した別のフラッシング方法を使用する必要があります。

## Runtime payload capabilities (EL3)

パッチされた bl2_ext ペイロードは以下が可能です:
- カスタム fastboot コマンドを登録する
- ブートモードを制御／上書きする
- 実行時に組み込みの bootloader 関数を動的に呼び出す
- 実際はアンロックされている状態を強い整合性チェックを通すために「lock state」をロック済みと偽装する（一部の環境では vbmeta/AVB の調整が依然として必要な場合があります）

制限: 現在の PoC では MMU の制約によりランタイムでのメモリ書き換えがフォルトを引き起こす可能性があると報告されています；この問題が解決されるまでペイロードは通常ライブメモリ書き込みを避けます。

## Porting tips

- デバイス固有の bl2_ext をリバースエンジニアリングして検証ポリシーロジック（例: sec_get_vfy_policy）を特定する。
- ポリシーの戻り先または判断ブランチを特定し、「no verification required」にパッチする（return 0 / 無条件許可）。
- オフセットは完全にデバイスおよびファームウェア固有に保ち、バリアント間でアドレスを再利用しない。
- まず犠牲端末で検証する。フラッシュ前にリカバリ計画（例: EDL/BootROM loader/SoC 固有のダウンロードモード）を用意する。

## Security impact

- Preloader 後に EL3 コード実行が可能となり、ブートパスの残りでチェーン・オブ・トラストが崩壊する。
- unsigned な TEE/GZ/LK/Kernel をブートできる能力により、secure/verified boot の期待が回避され、永続的な侵害が可能になる。

## Detection and hardening ideas

- Preloader が seccfg の状態に関係なく bl2_ext を検証することを保証する。
- 認証結果を強制し、監査証拠を収集する（timings > 0 ms、ミスマッチ時に厳格なエラーを出す）。
- ロック状態の偽装がアテステーションに対して無効化されるようにする（lock state を AVB/vbmeta の検証決定およびフューズに基づく状態に結びつける）。

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro はロックされている状態でも bl2_ext を検証しなかったと報告あり

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
