# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

このページでは、デバイスのブートローダ構成 (seccfg) が「unlocked」の場合の検証ギャップを悪用して、複数の MediaTek プラットフォームで実際に動作する secure-boot の突破を記録します。この欠陥により、パッチ済みの bl2_ext を ARM EL3 で実行して下流の署名検証を無効化でき、チェーン・オブ・トラストが崩壊して任意の未署名 TEE/GZ/LK/Kernel の読み込みが可能になります。

> Caution: Early-boot のパッチは、オフセットが間違っているとデバイスを永久に文鎮化する可能性があります。必ずフルダンプを保管し、信頼できるリカバリ経路を確保してください。

## Affected boot flow (MediaTek)

- 通常のパス: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- 脆弱なパス: seccfg が unlocked に設定されていると、Preloader は bl2_ext の検証をスキップする場合があります。Preloader はそれでも EL3 で bl2_ext にジャンプするため、巧妙に作られた bl2_ext はその後に未検証のコンポーネントをロードできます。

主要な信頼境界:
- bl2_ext は EL3 で実行され、TEE、GenieZone、LK/AEE、kernel の検証を担当します。bl2_ext 自体が認証されていない場合、残りのチェーンは簡単にバイパスされます。

## Root cause

影響を受けるデバイスでは、seccfg が「unlocked」を示す場合、Preloader は bl2_ext パーティションの認証を強制しません。これにより、攻撃者が制御する bl2_ext をフラッシュして EL3 で実行できるようになります。

bl2_ext 内では、検証ポリシー関数をパッチして検証は不要であると無条件に報告させることができます。概念的な最小パッチは次のとおりです:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
この変更により、EL3で動作するパッチ済み bl2_ext によってロードされる以降のすべてのイメージ（TEE, GZ, LK/AEE, Kernel）は、暗号検査なしで受け入れられます。

## ターゲットのトリアージ方法 (expdb logs)

bl2_ext のロード前後のブートログ（例: expdb）をダンプ/調査します。もし img_auth_required = 0 で証明書検証時間が約0 ms であれば、強制（enforcement）は無効になっている可能性が高く、デバイスは悪用可能です。

ログ抜粋の例:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
注: 一部のデバイスでは locked bootloader のままでも bl2_ext の検証をスキップするとの報告があり、影響がさらに大きくなります。

lk2 secondary bootloader を搭載するデバイスでも同じロジックの抜け穴が確認されているため、porting を試みる前に bl2_ext と lk2 の両パーティションについて expdb ログを取得し、いずれかの経路が署名を強制しているか確認してください。

## 実践的な悪用ワークフロー (Fenrir PoC)

Fenrir はこのクラスの問題に対するリファレンス exploit/patching ツールキットです。Nothing Phone (2a) (Pacman) をサポートし、CMF Phone 1 (Tetris) でも動作が確認されています（サポートは不完全）。他モデルへ移植するには、デバイス固有の bl2_ext のリバースエンジニアリングが必要です。

High-level process:
- Obtain the device bootloader image for your target codename and place it as `bin/<device>.bin`
- Build a patched image that disables the bl2_ext verification policy
- Flash the resulting payload to the device (fastboot assumed by the helper script)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
fastboot が利用できない場合は、プラットフォームに適した別のフラッシング方法を使用する必要があります。

### ビルド自動化 & payload デバッグ

- `build.sh` は初回実行時に Arm GNU Toolchain 14.2 (aarch64-none-elf) を自動ダウンロードしてエクスポートするようになったため、クロスコンパイラを手動で切り替える必要がありません。
- `build.sh` を実行する前に `DEBUG=1` をエクスポートすると、冗長なシリアル出力付きで payload をコンパイルします。これは EL3 のコードパスをブラインドパッチする際に非常に役立ちます。
- ビルドが成功すると `lk.patched` と `<device>-fenrir.bin` の両方が生成されます。後者には既に payload が注入されており、これをフラッシュ/ブートテストすべきです。

## ランタイム payload の機能 (EL3)

パッチ済みの bl2_ext payload は以下を行えます：
- カスタム fastboot コマンドを登録する
- ブートモードを制御/上書きする
- ランタイムで組み込みの bootloader 関数を動的に呼び出す
- 実際にはアンロックされている状態をロック済みとして偽装してより厳密な整合性チェックを通過させる（環境によっては vbmeta/AVB の調整が必要な場合あり）

制限事項：現行の PoC では、ランタイムでのメモリ改変が MMU の制約によりフォルトを起こす可能性があると報告されています。解決されるまでは payload は通常、ライブメモリ書き込みを避けます。

## Payload のステージングパターン (EL3)

Fenrir はインストルメンテーションを3つのコンパイル時ステージに分割します: stage1 は `platform_init()` の前に実行され、stage2 は LK が fastboot への移行を通知する前に実行され、stage3 は LK が Linux をロードする直前に実行されます。`payload/devices/` 以下の各デバイスヘッダは、これらのフックのアドレスと fastboot ヘルパーシンボルを提供するので、これらのオフセットをターゲットビルドと同期させておいてください。

Stage2 は任意の `fastboot oem` verbs を登録するのに都合の良い場所です:
```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
video_printf("r0rt1z2 was here...\n");
fastboot_info("pwned by r0rt1z2");
fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
notify_enter_fastboot();
}
```
Stage3は、下流のカーネルアクセスを必要とせずに、Androidの“Orange State”警告のような不変文字列をパッチするためにページテーブルの属性を一時的に反転する方法を示します:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Because stage1 fires prior to platform bring-up, it is the right place to call into OEM power/reset primitives or to insert additional integrity logging before the verified boot chain is torn down.

## 移植のヒント

- デバイス固有の bl2_ext をリバースエンジニアリングして、検証ポリシーのロジック（例: sec_get_vfy_policy）を特定する。
- ポリシーの戻り地点または判定ブランチを特定し、"no verification required"（return 0 / unconditional allow）となるようにパッチを当てる。
- オフセットは完全にデバイスおよびファームウェア固有に保ち、変種間でアドレスを再利用しないこと。
- まず犠牲デバイスで検証する。フラッシュする前にリカバリ計画（例: EDL/BootROM loader/SoC‑specific download mode）を用意する。
- lk2 二次ブートローダを使用しているデバイスや、ロック状態でも bl2_ext に対して “img_auth_required = 0” と報告されるデバイスは、このバグクラスの脆弱なコピーとみなすべきである。Vivo X80 Pro は、報告されたロック状態にもかかわらず検証をスキップすることが既に観測されている。
- ロック状態とアンロック状態の両方で expdb ログを比較する — 再ロックしたときに証明書のタイミングが 0 ms から非ゼロにジャンプするなら、正しい判定ポイントにパッチを当てた可能性が高いが、改変を隠すためにロック状態の偽装をさらに堅牢にする必要がある。

## セキュリティへの影響

- Preloader 実行後に EL3 コードが実行可能になり、残りのブートパスに対するチェーン・オブ・トラストが完全に崩壊する。
- unsigned な TEE/GZ/LK/Kernel を起動できるようになり、secure/verified boot の期待をバイパスして永続的な侵害を可能にする。

## デバイス注記

- 確認済み対応: Nothing Phone (2a) (Pacman)
- 動作確認済み（サポート不完全）: CMF Phone 1 (Tetris)
- 観測: Vivo X80 Pro はロック時でも bl2_ext を検証しなかったと報告されている
- 業界の報道では、追加の lk2 ベースのベンダが同じロジック欠陥を出荷していることが強調されており、2024–2025 年の MTK リリース全体でさらに重複が予想される。

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
