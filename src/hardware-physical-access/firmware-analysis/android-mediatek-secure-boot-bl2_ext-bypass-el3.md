# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 여러 MediaTek 플랫폼에서 디바이스 bootloader configuration (seccfg)이 "unlocked" 상태일 때 verification gap을 악용하여 secure-boot를 우회하는 실용적인 방법을 설명합니다. 이 flaw를 통해 ARM EL3에서 patched bl2_ext를 실행하여 이후 signature verification을 비활성화하고, trust chain을 무너뜨려 서명되지 않은 TEE/GZ/LK/Kernel을 임의로 로드할 수 있습니다.<sup>[[1]](#references)</sup>

> 주의: Early-boot patching은 offset이 잘못된 경우 디바이스를 영구적으로 brick할 수 있습니다. 항상 전체 dump와 신뢰할 수 있는 recovery 경로를 확보하십시오.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: seccfg가 unlocked로 설정되면 Preloader가 bl2_ext verification을 건너뛸 수 있습니다. Preloader는 여전히 EL3에서 bl2_ext로 jump하므로, crafted bl2_ext를 통해 이후의 검증되지 않은 components를 로드할 수 있습니다.

Key trust boundary:
- bl2_ext는 EL3에서 실행되며 TEE, GenieZone, LK/AEE 및 kernel을 검증합니다. bl2_ext 자체가 authenticated되지 않으면 chain의 나머지 부분은 쉽게 bypass됩니다.<sup>[[1]](#references)</sup>

## Root cause

영향받는 디바이스에서 seccfg가 "unlocked" 상태임을 나타내면 Preloader가 bl2_ext partition의 authentication을 강제하지 않습니다. 이로 인해 attacker-controlled bl2_ext를 flash하여 EL3에서 실행할 수 있습니다.

bl2_ext 내부의 verification policy function을 patch하여 verification이 필요하지 않다고 무조건 보고하거나 항상 성공하도록 만들 수 있습니다. 그러면 boot chain이 서명되지 않은 TEE/GZ/LK/Kernel images를 수락하게 됩니다. 이 patch는 EL3에서 실행되므로 downstream components가 자체 checks를 구현하더라도 효과가 있습니다.<sup>[[1]](#references)</sup>

## Practical exploit chain

1. OTA/firmware packages, EDL/DA readback 또는 hardware dumping을 통해 bootloader partitions (Preloader, bl2_ext, LK/AEE 등)을 확보합니다.
2. bl2_ext verification routine을 식별하고 항상 verification을 skip/accept하도록 patch합니다.
3. unlocked 디바이스에서 여전히 허용되는 fastboot, DA 또는 유사한 maintenance channels를 사용하여 modified bl2_ext를 flash합니다.
4. Reboot하면 Preloader가 EL3의 patched bl2_ext로 jump하고, patched TEE/GZ/LK/Kernel 등 서명되지 않은 downstream images를 로드한 뒤 signature enforcement를 비활성화합니다.<sup>[[1]](#references)</sup>

디바이스가 locked (seccfg locked) 상태로 구성된 경우 Preloader는 bl2_ext를 검증할 것으로 예상됩니다. 이 구성에서는 다른 vulnerability를 통해 서명되지 않은 bl2_ext를 로드할 수 있지 않는 한 attack이 실패합니다.

## Triage (expdb boot logs)

- bl2_ext load 전후의 boot/expdb logs를 dump합니다. `img_auth_required = 0`이고 certificate verification time이 약 0 ms라면 verification이 skip되었을 가능성이 높습니다.<sup>[[1]](#references)</sup>

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- 일부 기기는 locked 상태에서도 bl2_ext verification을 건너뛰며, lk2 secondary bootloader 경로에서도 동일한 gap이 확인되었습니다. OTA 이후 Preloader 로그에서 unlocked 상태의 bl2_ext에 대해 `img_auth_required = 1`이 기록된다면 enforcement가 복원되었을 가능성이 높습니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Verification logic locations

- 관련 check는 일반적으로 bl2_ext image 내부에서 `verify_img` 또는 `sec_img_auth`와 유사한 이름의 functions에 위치합니다.
- patched version은 function이 success를 반환하도록 강제하거나 verification call을 완전히 우회합니다.<sup>[[1]](#references)</sup>

Example patch approach (conceptual):
- TEE, GZ, LK 및 kernel images에서 `sec_img_auth`를 호출하는 function을 찾습니다.
- 해당 body를 즉시 success를 반환하는 stub으로 교체하거나, verification failure를 처리하는 conditional branch를 overwrite합니다.

patch가 stack/frame setup을 보존하고 callers에 예상된 status codes를 반환하는지 확인합니다.<sup>[[1]](#references)</sup>

## Fenrir PoC workflow (Nothing/CMF)

Fenrir는 이 issue를 위한 reference patching toolkit입니다 (Nothing Phone (2a)는 fully supported, CMF Phone 1은 partially supported).<sup>[[1]](#references)</sup> High level:
- device bootloader image를 `bin/<device>.bin`으로 배치합니다.
- bl2_ext verification policy를 disable하는 patched image를 build합니다.
- 결과 payload를 flash합니다 (fastboot helper 제공).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
fastboot를 사용할 수 없으면 다른 flashing channel을 사용하세요.

## EL3 patching 참고 사항

- bl2_ext는 ARM EL3에서 실행됩니다. 이 단계에서 충돌이 발생하면 EDL/DA 또는 test point를 통해 다시 flashing할 때까지 device가 brick될 수 있습니다.
- 실행 경로를 검증하고 충돌을 진단하려면 board별 logging/UART를 사용하세요.
- 수정하는 모든 partition을 백업하고, 먼저 폐기 가능한 hardware에서 테스트하세요.<sup>[[1]](#references)</sup>

## 영향

- Preloader 이후 EL3 code execution이 가능하며, 나머지 boot path 전체의 chain-of-trust가 붕괴합니다.
- unsigned TEE/GZ/LK/Kernel을 boot할 수 있어 secure/verified boot 기대 사항을 우회하고 persistent compromise를 활성화할 수 있습니다.<sup>[[1]](#references)</sup>

## Device 참고 사항

- 지원 확인: Nothing Phone (2a) (Pacman)
- 작동 확인 (지원 불완전): CMF Phone 1 (Tetris)
- 관찰 사항: Vivo X80 Pro는 locked 상태에서도 bl2_ext를 검증하지 않은 것으로 보고되었습니다.<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025)은 bl2_ext verification을 다시 활성화했습니다. fenrir `pacman-v2.0`은 beta Preloader와 patched LK를 혼합하여 bypass를 복원합니다.<sup>[[3]](#references)</sup>
- 업계 보도에 따르면 동일한 logic flaw를 적용한 추가 lk2 기반 vendor들이 제품을 출시하고 있으므로, 2024–2025 MTK release 전반에서 더 많은 중복 사례가 예상됩니다.<sup>[[2]](#references)[[4]](#references)</sup>

## Penumbra를 사용한 MTK DA readback 및 seccfg 조작

Penumbra는 USB를 통해 MTK preloader/bootrom과 상호 작용하여 DA-mode 작업을 자동화하는 Rust crate/CLI/TUI입니다. 취약한 handset에 physical access가 있고 DA extensions가 허용되면 MTK USB port를 검색하고, Download Agent (DA) blob을 로드하며, seccfg lock flipping 및 partition readback과 같은 privileged command를 실행할 수 있습니다.<sup>[[5]](#references)</sup>

- **Environment/driver setup**: Linux에서는 `libudev`를 설치하고 사용자를 `dialout` group에 추가한 다음 udev rules를 생성하거나 device node에 접근할 수 없으면 `sudo`로 실행하세요. Windows support는 불안정하며, project guidance에 따라 Zadig를 사용해 MTK driver를 WinUSB로 교체한 후에만 작동하는 경우가 있습니다.
- **Workflow**: DA payload(예: `std::fs::read("../DA_penangf.bin")`)를 읽고, `find_mtk_port()`로 MTK port를 polling한 다음, `DeviceBuilder::with_mtk_port(...).with_da_data(...)`를 사용해 session을 구성합니다. `init()`이 handshake를 완료하고 device info를 수집하면 `dev_info.target_config()` bitfields를 통해 protections를 확인합니다(bit 0 set → SBC enabled). DA mode로 진입한 후 `set_seccfg_lock_state(LockFlag::Unlock)`을 시도합니다. 이는 device가 extensions를 허용하는 경우에만 성공합니다. 오프라인 분석 또는 patching을 위해 `read_partition("lk_a", &mut progress_cb, &mut writer)`로 partition을 dump할 수 있습니다.
- **Security impact**: seccfg unlocking에 성공하면 unsigned boot image를 위한 flashing path가 다시 열리고, 위에서 설명한 bl2_ext EL3 patching과 같은 persistent compromise가 가능해집니다. Partition readback은 reverse engineering 및 modified image 제작에 필요한 firmware artifact를 제공합니다.

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

## 참고 자료

- [1] [Fenrir – MediaTek bl2_ext secure-boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – Nothing Phone 코드 실행 취약점에 대한 PoC Exploit 공개](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Fenrir pacman-v2.0 릴리스 (NothingOS 4 bypass 번들)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Fenrir PoC, Nothing Phone 2a/CMF1에서 secure boot 무력화](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – MTK DA flash/readback 및 seccfg 도구](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
