# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

이 문서는 장치 bootloader 구성(seccfg)이 "unlocked"일 때 발생하는 검증 갭을 악용해 여러 MediaTek 플랫폼에서 실제로 동작하는 secure-boot 우회를 설명합니다. 이 결함은 패치된 bl2_ext를 ARM EL3에서 실행하여 하류의 signature verification을 비활성화할 수 있게 하며, chain of trust를 붕괴시켜 임의의 unsigned TEE/GZ/LK/Kernel 로드를 가능하게 합니다.

> Caution: Early-boot patching은 offsets가 잘못되면 장치를 영구적으로 브릭할 수 있습니다. 항상 전체 덤프(full dumps)와 신뢰할 수 있는 복구 경로(recovery path)를 확보하세요.

## 영향을 받는 부트 흐름 (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: seccfg가 unlocked로 설정된 경우, Preloader는 bl2_ext의 인증을 건너뛸 수 있습니다. Preloader는 여전히 EL3에서 bl2_ext로 점프하므로, 조작된 bl2_ext가 이후에 검증되지 않은 컴포넌트를 로드할 수 있습니다.

주요 신뢰 경계:
- bl2_ext는 EL3에서 실행되며 TEE, GenieZone, LK/AEE 및 커널을 검증할 책임이 있습니다. bl2_ext 자체가 인증되지 않으면 나머지 체인은 쉽게 우회될 수 있습니다.

## 근본 원인

영향을 받는 장치에서는 seccfg가 "unlocked" 상태를 표시할 때 Preloader가 bl2_ext 파티션의 인증을 강제하지 않습니다. 이로 인해 공격자가 제어하는 bl2_ext를 플래시하여 EL3에서 실행할 수 있게 됩니다.

bl2_ext 내부에서는 verification policy 함수를 패치하여 검증이 필요 없다고 무조건 보고하도록 만들 수 있습니다. 개념적으로 최소한의 패치는 다음과 같습니다:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
이 변경으로 인해, EL3에서 실행되는 패치된 bl2_ext가 로드할 때 이후의 모든 이미지(TEE, GZ, LK/AEE, Kernel)는 암호 검증 없이 허용된다.

## 대상 분류 방법 (expdb 로그)

bl2_ext 로드 주변의 부트 로그(예: expdb)를 덤프/검사하라. 만약 img_auth_required = 0 이고 certificate verification time is ~0 ms 라면, enforcement가 꺼져 있을 가능성이 높으며 장치는 악용 가능하다.

예시 로그 발췌:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
참고: 일부 디바이스는 보고에 따르면 locked bootloader 상태에서도 bl2_ext 검증을 건너뛰어 영향이 더 심각해질 수 있습니다.

lk2 secondary bootloader와 함께 출하되는 기기에서도 동일한 논리적 결함이 관찰되었으므로, porting을 시도하기 전에 bl2_ext와 lk2 파티션 모두의 expdb logs를 확보하여 어느 경로가 서명 검증을 수행하는지 확인하세요.

## 실전 익스플로잇 워크플로우 (Fenrir PoC)

Fenrir는 이 클래스의 문제에 대한 레퍼런스 exploit/patching 툴킷입니다. Nothing Phone (2a) (Pacman)을 지원하며 CMF Phone 1 (Tetris)에서 동작하는 것으로 알려져 있으나(불완전하게 지원됨) 완전 지원되지는 않습니다. 다른 모델로의 porting은 디바이스별 bl2_ext의 reverse engineering이 필요합니다.

High-level process:
- Obtain the device bootloader image for your target codename and place it as `bin/<device>.bin`
- Build a patched image that disables the bl2_ext verification policy
- Flash the resulting payload to the device (fastboot assumed by the helper script)

명령:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
If fastboot를 사용할 수 없는 경우, 플랫폼에 적합한 대체 플래싱 방법을 사용해야 합니다.

### 빌드 자동화 및 페이로드 디버깅

- `build.sh`는 이제 처음 실행할 때 Arm GNU Toolchain 14.2 (aarch64-none-elf)를 자동으로 다운로드하고 export하므로 크로스 컴파일러를 수동으로 관리할 필요가 없습니다.
- `build.sh`를 실행하기 전에 `DEBUG=1`을 export하면 페이로드를 상세한 시리얼 출력과 함께 컴파일하므로 EL3 코드 경로를 블라인드 패치할 때 큰 도움이 됩니다.
- 빌드가 성공하면 `lk.patched`와 `<device>-fenrir.bin` 두 파일이 생성됩니다; 후자는 이미 페이로드가 주입되어 플래시하거나 부팅 테스트할 대상입니다.

## 런타임 페이로드 기능 (EL3)

패치된 bl2_ext 페이로드는 다음을 할 수 있습니다:
- 사용자 정의 fastboot 명령 등록
- 부팅 모드 제어/오버라이드
- 런타임에 빌트인 부트로더 함수를 동적으로 호출
- 실제로는 언락된 상태지만 'locked'로 스푸핑하여 더 강력한 무결성 검사를 통과(일부 환경에서는 여전히 vbmeta/AVB 조정이 필요할 수 있음)

제한사항: 현재 PoC들은 런타임 메모리 수정이 MMU 제약으로 인해 fault가 발생할 수 있음을 지적합니다; 이 문제가 해결될 때까지 페이로드는 일반적으로 라이브 메모리 쓰기를 피합니다.

## 페이로드 스테이징 패턴 (EL3)

Fenrir는 계측을 세 개의 컴파일 타임 단계로 분리합니다: stage1은 `platform_init()` 이전에 실행되고, stage2는 LK가 fastboot 진입을 신호하기 전에 실행되며, stage3는 LK가 Linux를 로드하기 직전에 실행됩니다. `payload/devices/` 아래의 각 디바이스 헤더는 이러한 훅들의 주소와 fastboot 헬퍼 심볼을 제공합니다. 따라서 해당 오프셋을 대상 빌드와 동기화 상태로 유지하세요.

Stage2는 임의의 `fastboot oem` 명령을 등록하기에 편리한 위치입니다:
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
Stage3는 downstream kernel access 없이 Android의 “Orange State” 경고와 같은 불변 문자열을 패치하기 위해 page-table attributes를 일시적으로 뒤집는 방법을 보여줍니다:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Because stage1 fires prior to platform bring-up, it is the right place to call into OEM power/reset primitives or to insert additional integrity logging before the verified boot chain is torn down.

## 포팅 팁

- 디바이스별 bl2_ext를 리버스 엔지니어링하여 검증 정책 로직(예: sec_get_vfy_policy)을 찾으세요.
- 정책의 반환 지점 또는 결정 분기를 식별하고 이를 “no verification required” (return 0 / unconditional allow)로 패치하세요.
- 오프셋은 완전히 디바이스 및 펌웨어별로 유지하세요; 변형들 간에 주소를 재사용하지 마세요.
- 먼저 희생 장치에서 검증하세요. 플래시하기 전에 복구 계획(예: EDL/BootROM loader/SoC-specific download mode)을 준비하세요.
- 잠금 상태에서도 bl2_ext에 대해 “img_auth_required = 0”을 보고하거나 lk2 secondary bootloader를 사용하는 장치는 이 버그 계열의 취약한 복사본으로 간주해야 합니다; Vivo X80 Pro는 이미 보고된 잠금 상태에도 불구하고 검증을 건너뛰는 것으로 관찰되었습니다.
- 잠금 및 잠금 해제 상태의 expdb 로그를 비교하세요—재잠금 시 인증서 타이밍이 0 ms에서 0이 아닌 값으로 뛰면, 아마도 올바른 결정 지점을 패치했지만 변경을 숨기기 위해 lock-state 스푸핑을 강화해야 합니다.

## 보안 영향

- Preloader 이후 EL3 코드 실행 및 나머지 부트 경로에 대한 전체 chain-of-trust 붕괴.
- 서명되지 않은 TEE/GZ/LK/Kernel을 부팅할 수 있어 secure/verified boot 기대를 우회하고 지속적인 침해를 가능하게 함.

## 디바이스 노트

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- Industry coverage highlights additional lk2-based vendors shipping the same logic flaw, so expect further overlap across 2024–2025 MTK releases.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
