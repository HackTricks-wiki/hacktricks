# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 디바이스 부트로더 설정(seccfg)이 "unlocked" 상태일 때 인증 누락을 악용하여 여러 MediaTek 플랫폼에서 실용적인 secure-boot 우회를 문서화합니다. 이 결함은 ARM EL3에서 패치된 bl2_ext를 실행하여 하류의 서명 검증을 비활성화할 수 있게 하며, 신뢰 체인을 붕괴시켜 임의의 unsigned TEE/GZ/LK/Kernel 로딩을 가능하게 합니다.

주의: Early-boot 패치 작업은 오프셋이 틀리면 기기를 영구적으로 brick시킬 수 있습니다. 항상 전체 덤프와 신뢰할 수 있는 복구 경로를 확보하세요.

## 영향을 받는 부트 흐름 (MediaTek)

- 정상 경로: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- 취약 경로: seccfg가 unlocked로 설정된 경우 Preloader가 bl2_ext 검증을 건너뛸 수 있습니다. Preloader는 여전히 EL3에서 bl2_ext로 점프하므로, 조작된 bl2_ext가 이후에 검증되지 않은 구성 요소를 로드할 수 있습니다.

주요 신뢰 경계:
- bl2_ext는 EL3에서 실행되며 TEE, GenieZone, LK/AEE 및 커널을 검증할 책임이 있습니다. bl2_ext 자체가 인증되지 않는다면 나머지 체인은 쉽게 우회됩니다.

## 근본 원인

영향을 받는 디바이스에서 Preloader는 seccfg가 "unlocked" 상태임을 나타낼 때 bl2_ext 파티션의 인증을 강제하지 않습니다. 이는 공격자가 제어하는 bl2_ext를 플래시하여 EL3에서 실행할 수 있게 합니다.

bl2_ext 내부에서는 검증 정책 함수가 무조건적으로 검증이 필요하지 않다고 보고하게(또는 항상 성공하도록) 패치될 수 있으며, 이로 인해 부트 체인은 unsigned TEE/GZ/LK/Kernel 이미지를 수락하게 됩니다. 이 패치가 EL3에서 실행되기 때문에 하류 구성요소들이 자체 검사를 구현하더라도 효과적입니다.

## 실전 익스플로잇 체인

1. OTA/firmware packages, EDL/DA readback 또는 하드웨어 덤핑을 통해 부트로더 파티션(Preloader, bl2_ext, LK/AEE 등)을 확보합니다.
2. bl2_ext의 검증 루틴을 식별하고 검증을 항상 건너뛰거나 수락하도록 패치합니다.
3. unlocked 디바이스에서 여전히 허용되는 fastboot, DA 또는 유사한 유지관리 채널을 사용하여 수정된 bl2_ext를 플래시합니다.
4. 재부팅; Preloader는 EL3에서 패치된 bl2_ext로 점프하고, 이후 unsigned 하류 이미지(패치된 TEE/GZ/LK/Kernel)를 로드하여 서명 강제를 비활성화합니다.

디바이스가 locked(seccfg locked)로 구성된 경우 Preloader는 bl2_ext를 검증할 것으로 예상됩니다. 그런 구성에서는 다른 취약점이 없어서는 unsigned bl2_ext 로딩을 허용하지 않으므로 이 공격은 실패합니다.

## 트리아지 (expdb 부트 로그)

- bl2_ext 로드 주변의 boot/expdb 로그를 덤프하세요. `img_auth_required = 0`이고 인증서 검증 시간이 약 0 ms라면 검증이 건너뛰어진 것일 가능성이 높습니다.

예시 로그 발췌:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- 일부 기기는 잠금 상태임에도 bl2_ext 검증을 건너뛰며; lk2 secondary bootloader paths에서도 동일한 갭이 관찰되었습니다. 만약 post-OTA Preloader가 bl2_ext에 대해 잠금 해제된 상태에서 `img_auth_required = 1`을 기록한다면, 강제 적용이 복원되었을 가능성이 큽니다.

## 검증 로직 위치

- 관련 검증은 일반적으로 bl2_ext 이미지 내부의 `verify_img` 또는 `sec_img_auth`와 유사한 이름의 함수에 위치합니다.
- 패치된 버전은 해당 함수가 성공을 반환하도록 강제하거나 검증 호출을 완전히 우회합니다.

예시 패치 방식 (개념적):
- TEE, GZ, LK 및 kernel 이미지에 대해 `sec_img_auth`를 호출하는 함수를 찾습니다.
- 함수 본문을 즉시 성공을 반환하는 스텁으로 교체하거나, 검증 실패를 처리하는 조건 분기를 덮어씁니다.

패치는 스택/프레임 설정을 보존하고 호출자에게 예상되는 상태 코드(status codes)를 반환하도록 해야 합니다.

## Fenrir PoC 워크플로우 (Nothing/CMF)

Fenrir는 이 문제에 대한 레퍼런스 패칭 툴킷입니다 (Nothing Phone (2a) 완전 지원; CMF Phone 1 부분 지원). 개요:
- 기기 bootloader 이미지를 `bin/<device>.bin`에 위치시킵니다.
- bl2_ext verification 정책을 비활성화하는 패치된 이미지를 빌드합니다.
- 생성된 payload를 플래시합니다 (fastboot helper 제공).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Use another flashing channel if fastboot is unavailable.

## EL3 패치 노트

- bl2_ext는 ARM EL3에서 실행됩니다. 여기서 발생한 크래시는 EDL/DA나 test points를 통해 재플래시될 때까지 장치를 벽돌 상태로 만들 수 있습니다.
- 보드별 logging/UART를 사용하여 실행 경로를 검증하고 크래시를 진단하세요.
- 수정하는 모든 파티션의 백업을 보관하고 먼저 소모성 하드웨어에서 테스트하세요.

## 영향

- Preloader 이후 EL3 코드 실행과 부팅 경로의 나머지에 대한 신뢰 사슬(chain-of-trust) 완전 붕괴.
- unsigned TEE/GZ/LK/Kernel을 부팅할 수 있는 능력으로 secure/verified boot 기대를 우회하여 영구적인 침해를 가능하게 합니다.

## Device 노트

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro는 잠금 상태에서도 bl2_ext를 검증하지 않는 것으로 보고됨
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025)는 bl2_ext 검증을 다시 활성화했음; fenrir `pacman-v2.0`은 베타 Preloader와 패치된 LK를 혼합해 우회 복원을 제공합니다
- 업계 보도는 동일한 논리 결함을 포함한 lk2 기반 벤더들이 추가로 존재함을 강조하므로 2024–2025 MTK 릴리스 전반에 걸쳐 더 많은 중복을 예상하세요.

## MTK DA readback 및 seccfg 조작 (Penumbra)

Penumbra는 Rust crate/CLI/TUI로, DA-mode 작업을 위해 USB를 통해 MTK preloader/bootrom과의 상호작용을 자동화합니다. 취약한 핸드셋에 대한 물리적 접근(DA extensions 허용)이 가능하면 MTK USB 포트를 탐지하고 Download Agent (DA) blob을 로드하며 seccfg lock 전환 및 partition readback 같은 권한 명령을 실행할 수 있습니다.

- **Environment/driver setup**: Linux에서는 `libudev`를 설치하고 사용자를 `dialout` 그룹에 추가한 후 udev 규칙을 생성하거나 디바이스 노드에 접근할 수 없을 경우 `sudo`로 실행하세요. Windows 지원은 불안정하며, 프로젝트 지침에 따라 Zadig로 MTK 드라이버를 WinUSB로 교체한 후에만 동작하는 경우가 있습니다.
- **Workflow**: DA 페이로드를 읽기(`std::fs::read("../DA_penangf.bin")` 등), `find_mtk_port()`로 MTK 포트를 폴링하고 `DeviceBuilder::with_mtk_port(...).with_da_data(...)`로 세션을 빌드합니다. `init()`이 핸드셰이크를 완료하고 장치 정보를 수집하면 `dev_info.target_config()` 비트필드를 통해 보호 상태를 확인하세요(비트 0 설정 → SBC enabled). DA 모드로 진입한 후 `set_seccfg_lock_state(LockFlag::Unlock)`를 시도하세요—장치가 extensions를 허용할 때만 성공합니다. 파티션은 `read_partition("lk_a", &mut progress_cb, &mut writer)`로 덤프하여 오프라인 분석이나 패칭에 사용할 수 있습니다.
- **Security impact**: seccfg 잠금 해제에 성공하면 unsigned 부트 이미지를 위한 flashing 경로가 다시 열려, 위에서 설명한 bl2_ext EL3 패치와 같은 영구적 침해를 가능하게 합니다. 파티션 readback은 리버스 엔지니어링 및 수정 이미지 제작을 위한 펌웨어 아티팩트를 제공합니다.

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

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – Nothing Phone 코드 실행 취약점에 대한 PoC Exploit 공개](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 릴리스 (NothingOS 4 bypass 번들)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC가 Nothing Phone 2a/CMF1의 secure boot을 무력화](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg 도구](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
