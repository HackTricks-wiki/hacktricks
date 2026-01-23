# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 디바이스 부트로더 구성(seccfg)이 "unlocked" 상태일 때 검증 공백을 악용해 여러 MediaTek 플랫폼에서 실제로 동작하는 secure-boot break를 문서화한다. 이 결함은 패치된 bl2_ext를 ARM EL3에서 실행시켜 하류의 서명 검증을 비활성화할 수 있게 하며, 신뢰 체인을 붕괴시켜 임의의 서명되지 않은 TEE/GZ/LK/Kernel 로드를 가능하게 한다.

> 경고: 초기 부트 단계에서의 패치는 오프셋이 틀리면 기기를 영구적으로 벽돌로 만들 수 있다. 항상 전체 덤프와 신뢰할 수 있는 복구 경로를 보관하라.

## 영향 받는 부트 플로우 (MediaTek)

- 정상 경로: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- 취약 경로: seccfg가 unlocked로 설정되면 Preloader가 bl2_ext의 검증을 건너뛸 수 있다. Preloader는 여전히 EL3에서 bl2_ext로 점프하므로, 조작된 bl2_ext가 이후에 검증되지 않은 컴포넌트들을 로드할 수 있다.

핵심 신뢰 경계:
- bl2_ext는 EL3에서 실행되며 TEE, GenieZone, LK/AEE 및 커널의 검증을 담당한다. bl2_ext 자체가 인증되지 않으면 나머지 체인은 쉽게 우회된다.

## 근본 원인

영향 받는 기기들에서는 seccfg가 "unlocked" 상태를 나타낼 때 Preloader가 bl2_ext 파티션의 인증을 강제하지 않는다. 이는 공격자가 제어하는 bl2_ext를 플래시해 EL3에서 실행되도록 허용한다.

bl2_ext 내부에서 검증 정책 함수는 검증이 필요하지 않다고 무조건 보고하도록 패치될 수 있다. 최소한의 개념적 패치는 다음과 같다:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
이 변경으로 EL3에서 실행되는 패치된 bl2_ext가 로드할 때, 이후의 모든 이미지(TEE, GZ, LK/AEE, Kernel)는 암호화 검증 없이 허용됩니다.

## 타깃을 분류하는 방법 (expdb 로그)

bl2_ext 로드 주변의 부트 로그(예: expdb)를 덤프/검사하세요. 만약 img_auth_required = 0 이고 certificate verification time 이 약 ~0 ms 라면, enforcement가 꺼져 있을 가능성이 높으며 기기는 exploitable합니다.

예시 로그 발췌:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Note: Some devices reportedly skip bl2_ext verification even with a locked bootloader, which exacerbates the impact.

일부 디바이스는 locked bootloader 상태에서도 bl2_ext 검증을 건너뛴다고 보고되었으며, 이는 영향 범위를 더 악화시킨다.

Devices that ship the lk2 secondary bootloader have been observed with the same logic gap, so grab expdb logs for both bl2_ext and lk2 partitions to confirm whether either path enforces signatures before you attempt porting.

lk2 secondary bootloader를 탑재한 디바이스에서도 동일한 논리적 결함이 관찰되었으므로, 포팅을 시도하기 전에 bl2_ext 및 lk2 파티션의 expdb logs를 수집해 두 경로 중 어느 쪽이 서명을 강제하는지 확인하라.

If a post-OTA Preloader now logs img_auth_required = 1 for bl2_ext even while seccfg is unlocked, the vendor likely closed the gap—see the OTA persistence notes below.

만약 post-OTA Preloader가 seccfg가 unlocked 상태임에도 bl2_ext에 대해 img_auth_required = 1을 기록한다면, 공급업체가 문제를 해결했을 가능성이 높다 — 아래의 OTA persistence notes를 참조하라.

## Practical exploitation workflow (Fenrir PoC)

Fenrir is a reference exploit/patching toolkit for this class of issue. It supports Nothing Phone (2a) (Pacman) and is known working (incompletely supported) on CMF Phone 1 (Tetris). Porting to other models requires reverse engineering the device-specific bl2_ext.

Fenrir는 이 클래스의 문제에 대한 참조 exploit/patching 툴킷이다. Nothing Phone (2a) (Pacman)을 지원하며, CMF Phone 1 (Tetris)에서도 부분적으로 동작하는 것으로 알려져 있다. 다른 모델로 포팅하려면 기기별 bl2_ext에 대한 리버스 엔지니어링이 필요하다.

High-level process:
- Obtain the device bootloader image for your target codename and place it as `bin/<device>.bin`
- Build a patched image that disables the bl2_ext verification policy
- Flash the resulting payload to the device (fastboot assumed by the helper script)

상위 수준 절차:
- 대상 codename에 대한 device bootloader image를 확보하고 `bin/<device>.bin`으로 배치한다
- bl2_ext verification policy를 비활성화하는 patched image를 빌드한다
- 생성된 payload를 device에 flash한다 (헬퍼 스크립트는 fastboot 사용을 전제로 한다)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
fastboot를 사용할 수 없는 경우, 플랫폼에 적합한 다른 flashing method를 사용해야 합니다.

### OTA-patched firmware: 우회 유지하기 (NothingOS 4, late 2025)

Nothing는 2025년 11월 NothingOS 4 stable OTA (build BP2A.250605.031.A3)에서 Preloader를 패치하여 seccfg가 잠금 해제되어 있더라도 bl2_ext 검증을 강제했습니다. Fenrir `pacman-v2.0`는 NOS 4 beta의 취약한 Preloader와 stable LK payload를 섞어 다시 작동합니다:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
중요:
- 제공된 Preloader를 **오직** 일치하는 device/slot에만 Flash하십시오; 잘못된 preloader는 즉시 hard brick을 초래합니다.
- flashing 후 expdb를 확인하십시오; img_auth_required는 bl2_ext에 대해 0으로 돌아와야 하며, 이는 취약한 Preloader가 패치된 LK보다 먼저 실행되고 있음을 확인합니다.
- 향후 OTAs가 Preloader와 LK 둘 다 패치하면, 취약한 Preloader의 로컬 복사본을 보관하여 해당 간극을 re‑introduce할 수 있도록 하십시오.

### 빌드 자동화 & payload 디버깅

- `build.sh`은 처음 실행할 때 Arm GNU Toolchain 14.2 (aarch64-none-elf)를 자동으로 다운로드하고 export하므로 cross-compilers를 수동으로 관리할 필요가 없습니다.
- `build.sh`을 호출하기 전에 `DEBUG=1`을 export하면 verbose serial prints를 포함해 payloads를 컴파일하므로, EL3 코드 경로를 blind-patching할 때 디버깅에 크게 도움이 됩니다.
- 빌드가 성공하면 `lk.patched`와 `<device>-fenrir.bin` 두 파일이 생성됩니다; 후자는 이미 payload가 주입되어 있으므로 flash/boot-test할 대상입니다.

## 런타임 payload 기능 (EL3)

패치된 bl2_ext payload는 다음을 수행할 수 있다:
- 커스텀 fastboot 명령을 등록할 수 있다
- boot mode를 제어/오버라이드할 수 있다
- 런타임에 built‑in bootloader 함수를 동적으로 호출할 수 있다
- 실제로는 unlocked 상태인데도 “lock state”를 locked로 스푸핑하여 더 엄격한 무결성 검사를 통과할 수 있다 (일부 환경에서는 여전히 vbmeta/AVB 조정이 필요할 수 있음)

제한사항: 현재 PoCs들은 런타임 메모리 수정을 MMU 제약으로 인해 오류가 발생할 수 있다고 보고하며; 이 문제가 해결될 때까지 payloads는 일반적으로 라이브 메모리 쓰기를 피합니다.

## Payload 스테이징 패턴 (EL3)

Fenrir는 계측을 세 개의 compile-time 단계로 분리합니다: stage1은 `platform_init()` 이전에 실행되고, stage2는 LK가 fastboot 진입을 신호하기 전에 실행되며, stage3는 LK가 Linux를 로드하기 직전에 실행됩니다. `payload/devices/` 아래의 각 device 헤더는 이러한 후크들의 주소와 fastboot 헬퍼 심볼을 제공하므로, 해당 오프셋을 타깃 빌드와 동기화해 두십시오.

Stage2는 임의의 `fastboot oem` verbs를 등록하기에 편리한 위치입니다:
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
Stage3는 하위 다운스트림 커널 접근 없이 Android의 “Orange State” 경고와 같은 불변 문자열을 패치하기 위해 페이지 테이블 속성을 일시적으로 반전시키는 방법을 시연합니다:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
stage1이 플랫폼 기동 이전에 실행되므로, verified boot chain이 해체되기 전에 OEM 전원/리셋 primitives를 호출하거나 추가 무결성 로깅을 삽입하기에 적절한 위치입니다.

## Porting tips

- 기기별 bl2_ext를 리버스 엔지니어링하여 검증 정책 로직(예: sec_get_vfy_policy)을 찾으세요.
- 정책의 반환 지점이나 결정 분기(decision branch)를 식별하고 이를 “no verification required” (return 0 / unconditional allow)로 패치하세요.
- 오프셋은 완전히 기기 및 펌웨어별로 유지하세요; 변형들 간에 주소를 재사용하지 마세요.
- 먼저 희생용 장치에서 검증하세요. 플래시하기 전에 복구 계획(예: EDL/BootROM loader/SoC-specific download mode)을 준비하세요.
- lk2 세컨더리 부트로더를 사용하거나 잠긴 상태임에도 bl2_ext에 대해 “img_auth_required = 0”을 보고하는 장치는 이 취약점 클래스의 취약한 복사본으로 간주해야 합니다; Vivo X80 Pro는 보고된 잠금 상태에도 불구하고 이미 검증을 건너뛰는 것이 관찰되었습니다.
- OTA가 언락 상태에서 bl2_ext 서명(img_auth_required = 1)을 강제하기 시작하면, 구버전 Preloader(종종 beta OTA에서 제공 가능)를 플래시하여 취약점을 다시 열 수 있는지 확인한 다음, 새로운 LK에 맞게 업데이트된 오프셋으로 fenrir를 다시 실행하세요.

## Security impact

- Preloader 이후 EL3 코드 실행 및 나머지 부팅 경로에 대한 전체 chain-of-trust 붕괴.
- 서명되지 않은 TEE/GZ/LK/Kernel을 부팅할 수 있어 secure/verified boot 기대를 우회하고 지속적인 침해를 가능하게 함.

## Device notes

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
