# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

このページは、seccfg が "unlocked" に設定されているときにデバイスブートローダ設定の検証ギャップを悪用することで、複数の MediaTek プラットフォームに対して実用的な Secure-Boot の破り方を記録します。脆弱性により、ARM EL3 でパッチされた bl2_ext を実行して下流の署名検証を無効化し、信頼の連鎖を崩して任意の非署名 TEE/GZ/LK/Kernel のロードを可能にします。

> 注意: Early-boot パッチはオフセットが間違っているとデバイスを永続的に文鎮化する可能性があります。必ず完全なダンプと確実なリカバリ手段を確保してください。

## Affected boot flow (MediaTek)

- 通常の経路: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- 脆弱な経路: seccfg が unlocked に設定されている場合、Preloader は bl2_ext の検証をスキップすることがあります。Preloader は依然として EL3 で bl2_ext にジャンプするため、細工された bl2_ext が以降の未検証コンポーネントをロードできます。

主要な信頼境界:
- bl2_ext は EL3 で実行され、TEE、GenieZone、LK/AEE、カーネルの検証を行う責任があります。もし bl2_ext 自体が認証されていなければ、チェーンの残りは簡単にバイパスされます。

## Root cause

影響を受けるデバイスでは、seccfg が "unlocked" を示すときに Preloader が bl2_ext パーティションの認証を強制しません。これにより、攻撃者が制御する bl2_ext をフラッシュして EL3 で実行させることが可能になります。

bl2_ext の内部では、検証ポリシー関数をパッチして検証不要と常に報告させる（または常に成功させる）ことができ、TEE/GZ/LK/Kernel の署名なし受け入れを強制できます。このパッチは EL3 で動作するため、下流コンポーネントが独自のチェックを実装していても有効です。

## Practical exploit chain

1. OTA/firmware パッケージ、EDL/DA の読み出し、またはハードウェアダンプを通じて Preloader、bl2_ext、LK/AEE などのブートローダパーティションを入手する。
2. bl2_ext の検証ルーチンを特定し、検証を常にスキップ／受け入れるようにパッチする。
3. fastboot、DA、またはアンロック済みデバイスで許可されている類似のメンテナンスチャネルを使って改変した bl2_ext をフラッシュする。
4. 再起動すると、Preloader が EL3 でパッチ済み bl2_ext にジャンプし、その後署名されていない下流イメージ（パッチ済み TEE/GZ/LK/Kernel）をロードして署名強制を無効化する。

デバイスがロック済み（seccfg locked）に構成されている場合、Preloader は bl2_ext を検証することが期待されます。その構成では、別の脆弱性がない限りこの攻撃は失敗します。

## Triage (expdb boot logs)

- bl2_ext のロード前後の boot/expdb ログをダンプする。`img_auth_required = 0` かつ証明書検証時間が ~0 ms の場合、検証がスキップされている可能性が高い。

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- 一部のデバイスはロックされていても `bl2_ext` の検証をスキップします；`lk2` の secondary bootloader パスでも同様のギャップが確認されています。もし post-OTA の `Preloader` がロック解除状態で `img_auth_required = 1` を `bl2_ext` に対してログに出力しているなら、検証の強制は復元されている可能性が高いです。

## Verification logic locations

- 関連するチェックは通常 `bl2_ext` イメージ内にあり、`verify_img` や `sec_img_auth` に類似した名前の関数内にあります。
- パッチ適用済みのバージョンは、その関数に成功を返させるか、検証呼び出し自体を完全にバイパスします。

Example patch approach (conceptual):
- TEE、GZ、LK、kernel イメージに対して `sec_img_auth` を呼ぶ関数を特定する。
- その本体を即座に成功を返すスタブに置き換える、または検証失敗を処理する条件分岐を上書きする。

パッチはスタック/フレームのセットアップを維持し、呼び出し元に期待されるステータスコードを返すようにすること。

## Fenrir PoC workflow (Nothing/CMF)

Fenrir はこの問題向けのリファレンスパッチツールキットです（Nothing Phone (2a) は完全にサポート、CMF Phone 1 は部分的にサポート）。大まかな流れ：
- デバイスの bootloader イメージを `bin/<device>.bin` として配置する。
- `bl2_ext` の検証ポリシーを無効化したパッチ適用済みイメージをビルドする。
- 生成されたペイロードを flash する（fastboot helper が提供される）。
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Use another flashing channel if fastboot is unavailable.

## EL3 パッチノート

- bl2_ext executes in ARM EL3. Crashes here can brick a device until reflashed via EDL/DA or test points.
- Use board-specific logging/UART to validate execution path and diagnose crashes.
- Keep backups of all partitions being modified and test on disposable hardware first.

## 影響

- EL3 code execution after Preloader and full chain-of-trust collapse for the rest of the boot path.
- Ability to boot unsigned TEE/GZ/LK/Kernel, bypassing secure/verified boot expectations and enabling persistent compromise.

## デバイスノート

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) re-enabled bl2_ext verification; fenrir `pacman-v2.0` restores the bypass by mixing the beta Preloader with a patched LK
- Industry coverage highlights additional lk2-based vendors shipping the same logic flaw, so expect further overlap across 2024–2025 MTK releases.

## MTK DA readback and seccfg manipulation with Penumbra

Penumbra is a Rust crate/CLI/TUI that automates interaction with MTK preloader/bootrom over USB for DA-mode operations. With physical access to a vulnerable handset (DA extensions allowed), it can discover the MTK USB port, load a Download Agent (DA) blob, and issue privileged commands such as seccfg lock flipping and partition readback.

- **Environment/driver setup**: On Linux install `libudev`, add the user to the `dialout` group, and create udev rules or run with `sudo` if the device node is not accessible. Windows support is unreliable; it sometimes works only after replacing the MTK driver with WinUSB using Zadig (per project guidance).
- **Workflow**: Read a DA payload (e.g., `std::fs::read("../DA_penangf.bin")`), poll for the MTK port with `find_mtk_port()`, and build a session using `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. After `init()` completes the handshake and gathers device info, check protections via `dev_info.target_config()` bitfields (bit 0 set → SBC enabled). Enter DA mode and attempt `set_seccfg_lock_state(LockFlag::Unlock)`—this only succeeds if the device accepts extensions. Partitions can be dumped with `read_partition("lk_a", &mut progress_cb, &mut writer)` for offline analysis or patching.
- **Security impact**: Successful seccfg unlocking reopens flashing paths for unsigned boot images, enabling persistent compromises such as the bl2_ext EL3 patching described above. Partition readback provides firmware artifacts for reverse engineering and crafting modified images.

<details>
<summary>Rust DA session + seccfg unlock + partition dump (Penumbra)</summary>
```rust
use tokio::fs::File;
use anyhow::Result;
use penumbra::{DeviceBuilder, LockFlag, find_mtk_port};
use tokio::io::{AsyncWriteExt, BufWriter};

#[tokio::main]
async fn main() -> Result<()> {
let da = std::fs::read("../DA_penangf.bin")?;
let mtk_port = loop {
if let Some(port) = find_mtk_port().await {
break port;
}
};

let mut dev = DeviceBuilder::default()
.with_mtk_port(mtk_port)
.with_da_data(da)
.build()?;

dev.init().await?;
let cfg = dev.dev_info.target_config().await;
println!("SBC: {}", (cfg & 0x1) != 0);

dev.set_seccfg_lock_state(LockFlag::Unlock).await?;

let mut progress = |_read: usize, _total: usize| {};
let mut writer = BufWriter::new(File::create("lk_a.bin")?);
dev.read_partition("lk_a", &mut progress, &mut writer).await?;
writer.flush().await?;
Ok(())
}
```
</details>

## 参考資料

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
