# MediaTek bl2_ext Secure-Boot Bypass（EL3 Code Execution）

{{#include ../../banners/hacktricks-training.md}}

このページでは、デバイスの bootloader configuration（seccfg）が「unlocked」の場合に発生する verification gap を悪用し、複数の MediaTek プラットフォームで secure-boot を実用的に破る手法について説明します。この flaw により、patched bl2_ext を ARM EL3 で実行して downstream signature verification を無効化でき、chain of trust を崩壊させて、任意の unsigned TEE/GZ/LK/Kernel のロードが可能になります。<sup>[[1]](#references)</sup>

> 注意: Early-boot patching は、offset が間違っているとデバイスを恒久的に brick させる可能性があります。常に full dump と信頼できる recovery path を確保してください。

## 影響を受ける boot flow（MediaTek）

- Normal path: BootROM → Preloader → bl2_ext（EL3、verified）→ TEE → GenieZone（GZ）→ LK/AEE → Linux kernel（EL1）
- Vulnerable path: seccfg が unlocked に設定されている場合、Preloader は bl2_ext の verification を skip する可能性があります。Preloader は引き続き EL3 の bl2_ext に jump するため、crafted bl2_ext によって以降の unverified components をロードできます。

主要な trust boundary:
- bl2_ext は EL3 で実行され、TEE、GenieZone、LK/AEE、kernel の verification を担当します。bl2_ext 自体が authenticated でなければ、chain の残りは簡単に bypass できます。<sup>[[1]](#references)</sup>

## Root cause

影響を受けるデバイスでは、seccfg が「unlocked」状態を示している場合、Preloader は bl2_ext partition の authentication を enforce しません。これにより、attacker-controlled bl2_ext を flash して EL3 で実行させることが可能になります。

bl2_ext 内部では、verification policy function を patch して、verification が不要であると無条件に report させる（または常に成功するようにする）ことができます。これにより boot chain は unsigned TEE/GZ/LK/Kernel images を受け入れるようになります。この patch は EL3 で実行されるため、downstream components が独自の checks を実装していても有効です。<sup>[[1]](#references)</sup>

## Practical exploit chain

1. OTA/firmware packages、EDL/DA readback、または hardware dumping を通じて、bootloader partitions（Preloader、bl2_ext、LK/AEE など）を取得します。
2. bl2_ext の verification routine を特定し、常に verification を skip/accept するよう patch します。
3. unlocked devices で引き続き許可されている fastboot、DA、または同様の maintenance channels を使用して、modified bl2_ext を flash します。
4. Reboot すると、Preloader は EL3 の patched bl2_ext に jump し、patched TEE/GZ/LK/Kernel などの unsigned downstream images をロードして signature enforcement を無効化します。<sup>[[1]](#references)</sup>

デバイスが locked（seccfg locked）として構成されている場合、Preloader は bl2_ext を verify することが想定されます。その構成では、別の vulnerability によって unsigned bl2_ext のロードが可能にならない限り、この attack は失敗します。

## Triage（expdb boot logs）

- bl2_ext の load 周辺にある boot/expdb logs を dump します。`img_auth_required = 0` で、certificate verification time が約 0 ms の場合、verification が skip されている可能性があります。<sup>[[1]](#references)</sup>

ログ抜粋の例:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- 一部のデバイスでは、ロック状態でも bl2_ext の検証がスキップされます。lk2 の secondary bootloader パスでも同じ欠落が確認されています。アンロック状態で post-OTA Preloader が bl2_ext に対して `img_auth_required = 1` をログ出力する場合、enforcement は復元された可能性があります。<sup>[[1]](#references)[[2]](#references)</sup>

## 検証ロジックの場所

- 該当する check は通常、bl2_ext image 内の `verify_img` や `sec_img_auth` に類似した名前の functions にあります。
- patched version では、function が success を返すように強制するか、verification call 自体を完全に bypass します。<sup>[[1]](#references)</sup>

Example patch approach (conceptual):
- TEE、GZ、LK、kernel images に対して `sec_img_auth` を呼び出す function を特定します。
- その body を、直ちに success を返す stub に置き換えるか、verification failure を処理する conditional branch を overwrite します。

patch で stack/frame setup が維持され、caller が想定する status codes が返されることを確認してください。<sup>[[1]](#references)</sup>

## Fenrir PoC workflow (Nothing/CMF)

Fenrir はこの issue 用の reference patching toolkit です（Nothing Phone (2a) は完全サポート、CMF Phone 1 は部分サポート）。<sup>[[1]](#references)</sup> High level:
- デバイスの bootloader image を `bin/<device>.bin` として配置します。
- bl2_ext verification policy を無効化する patched image を build します。
- 生成された payload を flash します（fastboot helper が提供されています）。
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
fastboot が利用できない場合は、別の flashing channel を使用してください。

## EL3 patching に関する注意事項

- bl2_ext は ARM EL3 で実行されます。ここでクラッシュすると、EDL/DA または test points 経由で再flashするまでデバイスが brick する可能性があります。
- 実行経路の検証とクラッシュの診断には、ボード固有の logging/UART を使用してください。
- 変更するすべての partition の backup を保持し、まずは使い捨て可能な hardware でテストしてください。<sup>[[1]](#references)</sup>

## 影響

- Preloader の後に EL3 code execution が可能となり、boot path の残りの部分で chain-of-trust が完全に崩壊します。
- unsigned TEE/GZ/LK/Kernel を boot でき、secure/verified boot の想定を bypass して persistent compromise を可能にします。<sup>[[1]](#references)</sup>

## Device に関する注意事項

- 対応を確認済み: Nothing Phone (2a) (Pacman)
- 動作確認済み（support は不完全）: CMF Phone 1 (Tetris)
- 確認された事例: Vivo X80 Pro は、locked 状態でも bl2_ext を verify しなかったと報告されています<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) では bl2_ext verification が再有効化されました。fenrir `pacman-v2.0` は beta Preloader と patched LK を混在させることで bypass を復元します<sup>[[3]](#references)</sup>
- 業界の coverage では、同じ logic flaw を搭載して出荷された lk2-based vendor がさらに存在することが示されており、2024–2025 の MTK release 間でさらなる重複が予想されます。<sup>[[2]](#references)[[4]](#references)</sup>

## Penumbra による MTK DA readback と seccfg manipulation

Penumbra は、USB 経由で MTK preloader/bootrom と interaction し、DA-mode operation を自動化する Rust crate/CLI/TUI です。脆弱な handset（DA extensions が許可されているもの）へ physical access できる場合、MTK USB port を検出し、Download Agent (DA) blob を load して、seccfg lock flipping や partition readback などの privileged command を発行できます。<sup>[[5]](#references)</sup>

- **Environment/driver setup**: Linux では `libudev` を install し、user を `dialout` group に追加してください。また、udev rules を作成するか、device node に access できない場合は `sudo` で実行します。Windows support は unreliable であり、project guidance に従い、Zadig を使用して MTK driver を WinUSB に replace した後にのみ動作することがあります。
- **Workflow**: DA payload（例: `std::fs::read("../DA_penangf.bin")`）を read し、`find_mtk_port()` で MTK port を poll して、`DeviceBuilder::with_mtk_port(...).with_da_data(...)` で session を build します。`init()` が handshake を完了して device info を取得した後、`dev_info.target_config()` の bitfields で protections を確認します（bit 0 が set → SBC enabled）。DA mode に入り、`set_seccfg_lock_state(LockFlag::Unlock)` を attempt します。これは device が extensions を accept する場合にのみ成功します。Partition は `read_partition("lk_a", &mut progress_cb, &mut writer)` で dump でき、offline analysis や patching に利用できます。
- **Security impact**: seccfg の unlock に成功すると、unsigned boot image の flashing path が再開され、上記の bl2_ext EL3 patching のような persistent compromise が可能になります。Partition readback により、reverse engineering や modified image の作成に利用できる firmware artifact を取得できます。

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

## 参考文献

- [1] [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – Nothing Phone の code execution vulnerability に対する PoC exploit が公開](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Fenrir pacman-v2.0 リリース（NothingOS 4 bypass bundle）](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Fenrir PoC が Nothing Phone 2a/CMF1 の secure boot を突破](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
