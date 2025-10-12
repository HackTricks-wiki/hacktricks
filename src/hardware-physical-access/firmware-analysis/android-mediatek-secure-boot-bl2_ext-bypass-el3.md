# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 디바이스 부트로더 구성(seccfg)이 "unlocked" 상태일 때 검증 격차를 악용하여 여러 MediaTek 플랫폼에서 실질적인 secure-boot 우회를 수행하는 방법을 문서화합니다. 이 취약점은 패치된 bl2_ext를 ARM EL3에서 실행시켜 하위 서명 검증을 비활성화할 수 있게 하며, 신뢰 체인을 붕괴시켜 임의의 서명되지 않은 TEE/GZ/LK/Kernel 로딩을 가능하게 합니다.

> 주의: 초기 부트 패치가 오프셋이 잘못되면 장치를 영구적으로 벽돌화할 수 있습니다. 항상 전체 덤프와 신뢰할 수 있는 복구 경로를 확보하세요.

## 영향받는 부트 흐름 (MediaTek)

- 정상 경로: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- 취약 경로: seccfg가 unlocked로 설정된 경우, Preloader가 bl2_ext 인증을 건너뛸 수 있습니다. Preloader는 여전히 EL3에서 bl2_ext로 점프하므로, 조작된 bl2_ext가 이후에 인증되지 않은 컴포넌트를 로드할 수 있습니다.

핵심 신뢰 경계:
- bl2_ext는 EL3에서 실행되며 TEE, GenieZone, LK/AEE 및 커널을 검증하는 역할을 합니다. bl2_ext 자체가 인증되지 않으면 나머지 체인은 쉽게 우회됩니다.

## 근본 원인

영향받는 기기에서 seccfg가 "unlocked" 상태를 나타내면 Preloader는 bl2_ext 파티션의 인증을 강제하지 않습니다. 이는 공격자가 제어하는 bl2_ext를 플래시하여 EL3에서 실행할 수 있게 합니다.

bl2_ext 내부에서 검증 정책 함수는 검증이 필요하지 않다고 무조건 보고하도록 패치할 수 있습니다. 최소한의 개념적 패치는 다음과 같습니다:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
이 변경으로, EL3에서 실행되는 패치된 bl2_ext가 로드할 때 이후의 모든 이미지 (TEE, GZ, LK/AEE, Kernel)는 암호학적 검사 없이 수락됩니다.

## 대상 분석 방법 (expdb 로그)

bl2_ext 로드 전후의 부트 로그(예: expdb)를 덤프/검사하세요. 만약 img_auth_required = 0이고 인증서 검증 시간이 약 0 ms라면, enforcement가 비활성 상태일 가능성이 높으며 장치는 취약합니다.

예시 로그 발췌:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
참고: 일부 기기는 bootloader가 잠겨 있어도 bl2_ext 검증을 건너뛰는 것으로 보고되어 영향이 더 커질 수 있습니다.

## 실전 익스플로잇 워크플로우 (Fenrir PoC)

Fenrir는 이 유형의 취약점에 대한 레퍼런스 exploit/patching 툴킷입니다. Nothing Phone (2a) (Pacman)을 지원하며 CMF Phone 1 (Tetris)에서 동작하는 것으로 알려져 있으나(완전 지원되지는 않음) 다른 모델로 포팅하려면 device-specific bl2_ext를 reverse engineering해야 합니다.

전반적인 절차:
- 대상 코드네임의 bootloader 이미지를 확보하여 bin/<device>.bin로 배치하세요
- bl2_ext 검증 정책을 비활성화하는 패치된 이미지를 빌드하세요
- 생성된 payload를 device에 플래시하세요 (helper script가 fastboot를 가정함)

명령:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## 런타임 페이로드 기능 (EL3)

패치된 bl2_ext payload는 다음을 수행할 수 있습니다:
- 커스텀 fastboot 명령을 등록할 수 있음
- boot mode 제어/오버라이드
- 런타임에 내장 bootloader 함수를 동적으로 호출할 수 있음
- 실제로는 unlocked 상태이지만 lock state를 locked로 스푸핑하여 더 강한 무결성 검사를 통과할 수 있음 (일부 환경에서는 여전히 vbmeta/AVB 조정이 필요할 수 있음)

제한: 현재 PoC들은 런타임 메모리 수정이 MMU 제약 때문에 오류를 일으킬 수 있음을 지적함; payload들은 일반적으로 이 문제가 해결될 때까지 라이브 메모리 쓰기를 피함.

## 포팅 팁

- 기기별 bl2_ext를 리버스 엔지니어링하여 검증 정책 로직(예: sec_get_vfy_policy)을 찾으세요.
- 정책의 반환 지점이나 결정 분기를 식별하고 이를 “검증 불필요”로 패치하세요 (return 0 / 무조건 허용).
- 오프셋은 완전히 기기 및 펌웨어별로 유지하세요; 변형들 사이에서 주소를 재사용하지 마세요.
- 먼저 희생 장치에서 검증하세요. 플래시하기 전에 복구 계획(예: EDL/BootROM loader/SoC-specific download mode)을 준비하세요.

## 보안 영향

- Preloader 이후 EL3 코드 실행 및 나머지 부트 경로에 대한 신뢰 체인 완전 붕괴.
- unsigned TEE/GZ/LK/Kernel 부팅 가능, secure/verified boot 기대를 우회하고 지속적인 침해를 가능하게 함.

## 탐지 및 강화 아이디어

- Preloader가 seccfg 상태와 관계없이 bl2_ext를 검증하도록 보장하세요.
- 인증 결과를 강제하고 감사 증거(타이밍 > 0 ms, 불일치 시 엄격한 오류)를 수집하세요.
- 잠금 상태 스푸핑은 attestation에 대해 무효화되어야 함(잠금 상태를 AVB/vbmeta 검증 결정 및 fuse-backed 상태에 연동).

## 장치 참고사항

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
