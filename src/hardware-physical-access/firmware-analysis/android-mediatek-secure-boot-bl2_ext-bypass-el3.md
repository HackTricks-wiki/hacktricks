# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

このページでは、デバイスのブートローダ設定 (seccfg) が "unlocked" のときの検証の抜け穴を悪用して、複数の MediaTek プラットフォームで実際に行える secure-boot の破り方を記録します。この脆弱性により、ARM EL3 でパッチした bl2_ext を実行して下流の署名検証を無効化でき、信頼の連鎖が崩壊して TEE/GZ/LK/Kernel に任意の未署名イメージを読み込ませることが可能になります。

> 注意: 早期ブートでのパッチ適用はオフセットが間違っているとデバイスを永久にブリックする可能性があります。常に完全なダンプと信頼できるリカバリ経路を用意してください。

## 影響を受けるブートフロー (MediaTek)

- 通常の経路: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- 脆弱な経路: seccfg が unlocked に設定されている場合、Preloader は bl2_ext の検証をスキップすることがあります。Preloader は引き続き EL3 で bl2_ext にジャンプするため、細工した bl2_ext により以降のコンポーネントを未検証のままロードできます。

重要な信頼境界:
- bl2_ext は EL3 で実行され、TEE、GenieZone、LK/AEE、カーネルの検証を担当します。bl2_ext 自体が認証されていなければ、チェーン全体は簡単にバイパスされます。

## 根本原因

対象デバイスでは、seccfg が "unlocked" を示す場合に、Preloader が bl2_ext パーティションの認証を強制しません。これにより、攻撃者が制御する bl2_ext をフラッシュして EL3 で実行させることが可能になります。

bl2_ext 内では、検証ポリシー関数をパッチして常に検証不要を返すようにできます。最小限の概念的なパッチ例は次のとおりです:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
この変更により、EL3で動作するパッチ済みbl2_extによってロードされる以降のすべてのイメージ（TEE、GZ、LK/AEE、Kernel）は、暗号学的チェックなしで受け入れられます。

## 対象のトリアージ方法 (expdb logs)

bl2_extのロード前後のブートログ（例: expdb）をダンプ/検査します。もし img_auth_required = 0 かつ 証明書の検証時間が ~0 ms であれば、強制はおそらく無効であり、デバイスは悪用可能です。

ログの抜粋例:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Note: Some devices reportedly skip bl2_ext verification even with a locked bootloader, which exacerbates the impact.

Devices that ship the lk2 secondary bootloader have been observed with the same logic gap, so grab expdb logs for both bl2_ext and lk2 partitions to confirm whether either path enforces signatures before you attempt porting.

If a post-OTA Preloader now logs img_auth_required = 1 for bl2_ext even while seccfg is unlocked, the vendor likely closed the gap—see the OTA persistence notes below.

## 実践的な悪用ワークフロー (Fenrir PoC)

Fenrir is a reference exploit/patching toolkit for this class of issue. It supports Nothing Phone (2a) (Pacman) and is known working (incompletely supported) on CMF Phone 1 (Tetris). Porting to other models requires reverse engineering the device-specific bl2_ext.

大まかな手順:
- ターゲットの codename 用のデバイスの bootloader image を取得し、`bin/<device>.bin` として配置する
- bl2_ext の検証ポリシーを無効化するパッチ済みイメージをビルドする
- 生成した payload をデバイスにフラッシュする（ヘルパースクリプトは fastboot を想定）

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
If fastboot が利用できない場合は、プラットフォームに適した代替の flashing method を使用する必要があります。

### OTA-patched firmware: bypass を維持する (NothingOS 4、2025年後半)

Nothing は 2025年11月の NothingOS 4 安定版 OTA (build BP2A.250605.031.A3) で Preloader をパッチし、seccfg がアンロックされていても bl2_ext の検証を強制するようにしました。Fenrir `pacman-v2.0` は、NOS 4 beta の脆弱な Preloader と安定した LK payload を組み合わせることで再び動作します:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
重要:
- 提供された Preloader は**必ず**対応する device/slot にのみフラッシュすること; 間違った Preloader を使うと即座にハードブリックします。
- フラッシュ後に expdb を確認すること; bl2_ext の img_auth_required が 0 に戻っていることを確認し、脆弱な Preloader がパッチ済みの LK より前に実行されていることを確認する。
- 将来の OTAs が Preloader と LK の両方を修正した場合に備え、脆弱な Preloader のローカルコピーを保持してギャップを再導入できるようにしておく。

### ビルド自動化と payload デバッグ

- `build.sh` は最初に実行した際に Arm GNU Toolchain 14.2 (aarch64-none-elf) を自動でダウンロードしてエクスポートするため、クロスコンパイラを手動で切り替える必要はありません。
- `build.sh` を呼び出す前に `DEBUG=1` をエクスポートすると、payloads が詳細なシリアル出力付きでコンパイルされ、EL3 のコードパスを blind-patching する際に非常に役立ちます。
- ビルドが成功すると `lk.patched` と `<device>-fenrir.bin` の両方が生成されます。後者には既に payload が注入されており、これを flash/boot-test すべきです。

## Runtime payload capabilities (EL3)

パッチ済みの bl2_ext payload は次のことが可能です:
- カスタム fastboot コマンドを登録する
- ブートモードを制御/オーバーライドする
- 実行時に組み込みの bootloader 関数を動的に呼び出す
- 実際にはアンロックされた状態でも「ロック状態」をロック済みとして偽装し、より厳しい整合性チェックを通過させる（環境によっては vbmeta/AVB の調整が依然として必要になる場合があります）

制約: 現在の PoCs は、MMU の制約によりランタイムでのメモリ変更がフォルトを起こす可能性があると指摘しているため、問題が解決するまでは payloads は通常ライブメモリ書き込みを避けます。

## Payload staging patterns (EL3)

Fenrir はインストルメンテーションを 3 つのコンパイル時ステージに分割します: stage1 は `platform_init()` より前に実行され、stage2 は LK が fastboot エントリを通知する前に実行され、stage3 は LK が Linux をロードする直前に実行されます。`payload/devices/` 以下の各デバイスヘッダは、これらのフック用アドレスと fastboot ヘルパーシンボルを提供するので、これらのオフセットをターゲットビルドと同期させてください。

Stage2 は任意の `fastboot oem` verbs を登録するのに便利な場所です:
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
Stage3 は、downstream kernel access を必要とせずに、Android の “Orange State” 警告のような不変の文字列をパッチするためにページテーブル属性を一時的に反転させる方法を示します:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Because stage1 fires prior to platform bring-up, it is the right place to call into OEM power/reset primitives or to insert additional integrity logging before the verified boot chain is torn down.

## ポーティングのヒント

- デバイス固有の bl2_ext をリバースエンジニアリングして、検証ポリシーロジック（例: sec_get_vfy_policy）を特定する。
- ポリシーの戻り箇所または判定ブランチを特定し、“no verification required”（return 0 / unconditional allow）にパッチする。
- オフセットは完全にデバイスおよびファームウェア固有に保ち、バリアント間でアドレスを使い回さない。
- まずは犠牲ユニットで検証する。フラッシュする前にリカバリープラン（例: EDL/BootROM loader/SoC-specific download mode）を用意しておく。
- lk2 セカンダリブートローダーを使用しているか、ロック状態でも bl2_ext に対して “img_auth_required = 0” を報告するデバイスは、本脆弱性クラスの影響を受けるコピーと見なすべきである；Vivo X80 Pro は報告されたロック状態にもかかわらず検証をスキップする例が既に観測されている。
- OTA がアンロック状態で bl2_ext の署名（img_auth_required = 1）を強制し始めた場合、古い Preloader（beta OTA にしばしば含まれる）をフラッシュして隙間を再度開けられるかを確認し、その後 newer LK 用にオフセットを更新して fenrir を再実行する。

## セキュリティへの影響

- Preloader の後に EL3 コードが実行され、以降のブートパスで chain-of-trust が完全に崩壊する。
- unsigned な TEE/GZ/LK/Kernel を起動できるようになり、secure/verified boot の期待をバイパスして永続的な侵害を可能にする。

## デバイス注記

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) re-enabled bl2_ext verification; fenrir `pacman-v2.0` restores the bypass by flashing the beta Preloader plus patched LK as shown above
- Industry coverage highlights additional lk2-based vendors shipping the same logic flaw, so expect further overlap across 2024–2025 MTK releases.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
