# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

このページでは、デバイスのブートローダ設定（seccfg）が "unlocked" のときに検証の隙間を悪用することで、複数のMediaTekプラットフォームに対する実用的なsecure-bootの破りを記録します。この脆弱性により、ARM EL3でパッチされたbl2_extを実行して下流の署名検証を無効化でき、信頼の連鎖を崩壊させて任意の未署名のTEE/GZ/LK/Kernelの読み込みを可能にします。

> 注意: Early-bootでのパッチは、オフセットが誤っているとデバイスを永久にbrickする可能性があります。常にフルダンプと確実なリカバリ手段を保持してください。

## 影響を受けるブートフロー (MediaTek)

- 通常の経路: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- 脆弱な経路: seccfgがunlockedに設定されている場合、Preloaderはbl2_extの検証をスキップすることがあります。Preloaderは依然としてEL3でbl2_extにジャンプするため、細工されたbl2_extはその後未検証のコンポーネントを読み込むことができます。

重要な信頼境界:
- bl2_extはEL3で実行され、TEE、GenieZone、LK/AEE、カーネルの検証を担当します。bl2_ext自体が認証されていない場合、チェーンの残りは簡単にバイパスされます。

## 根本原因

影響を受けるデバイスでは、seccfgが"unlocked"を示すときにPreloaderがbl2_extパーティションの認証を強制しません。これにより、攻撃者が制御するbl2_extをフラッシュしてEL3で実行させることができます。

bl2_ext内部では、検証ポリシー関数をパッチして「検証は不要」と無条件に報告させることが可能です。最小限の概念的なパッチは:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
この変更により、EL3 で実行されるパッチ済み bl2_ext によってロードされる以降のすべてのイメージ（TEE、GZ、LK/AEE、Kernel）は、暗号検証なしで受け入れられます。

## ターゲットをトリアージする方法 (expdb logs)

bl2_ext のロード周辺の boot logs（例: expdb）をダンプ／解析します。img_auth_required = 0 かつ certificate verification time が約 0 ms の場合、enforcement は無効になっている可能性が高く、device は exploitable です。

ログの例（抜粋）:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Note: 一部のデバイスは locked bootloader の状態でも bl2_ext verification をスキップすると報告されており、影響がさらに大きくなります。

## Practical exploitation workflow (Fenrir PoC)

Fenrir はこのクラスの問題に対する reference exploit/patching toolkit です。Nothing Phone (2a) (Pacman) をサポートしており、CMF Phone 1 (Tetris) でも動作することが確認されています（不完全なサポート）。他モデルへの移植は device-specific bl2_ext の reverse engineering が必要です。

High-level process:
- ターゲットの codename に対応する device bootloader image を取得し、bin/<device>.bin として配置する
- bl2_ext verification policy を無効化する patched image をビルドする
- 生成した payload をデバイスにフラッシュする（helper script は fastboot を想定）

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot が利用できない場合は、プラットフォームに適した代替のフラッシング手段を使用する必要がある。

## Runtime payload capabilities (EL3)

A patched bl2_ext payload can:
- カスタム fastboot コマンドを登録できる
- ブートモードを制御／上書きできる
- 実行時に組み込みの bootloader 関数を動的に呼び出せる
- 実際は unlocked のままでも “lock state” を locked に偽装して、より強い整合性チェックを通過させる（環境によっては vbmeta/AVB の調整が依然として必要）

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Porting tips

- デバイス固有の bl2_ext をリバースエンジニアリングして、検証ポリシーのロジック（例: sec_get_vfy_policy）を特定する。
- ポリシーの戻り先または判定分岐を特定し、それを “no verification required”（return 0 / unconditional allow）にパッチする。
- オフセットは完全にデバイスおよびファームウェア固有に保ち、バリアント間でアドレスを再利用しない。
- まず犠牲デバイスで検証する。フラッシュする前にリカバリ計画（例: EDL/BootROM loader/SoC-specific download mode）を準備しておく。

## Security impact

- Preloader 後での EL3 コード実行と、以降のブートパスにおけるチェーン・オブ・トラストの完全な崩壊。
- 署名されていない TEE/GZ/LK/Kernel を起動でき、secure/verified boot の期待をバイパスして永続的な侵害を可能にする。

## Detection and hardening ideas

- Preloader が seccfg の状態に関係なく bl2_ext を検証することを保証する。
- 認証結果を強制し、監査証拠を収集する（タイミング > 0 ms、ミスマッチ時は厳格にエラー化）。
- Lock-state の偽装が attestation に対して無効化されるようにする（lock state を AVB/vbmeta の検証結果や fuse-backed state に結び付ける）。

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
