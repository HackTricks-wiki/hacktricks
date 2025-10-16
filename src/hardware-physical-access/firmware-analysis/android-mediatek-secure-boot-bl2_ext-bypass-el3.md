# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 장치 부트로더 구성(seccfg)이 "unlocked" 상태일 때 검증 간극을 악용해 여러 MediaTek 플랫폼에서 실용적인 secure-boot 우회를 달성한 사례를 문서화합니다. 이 결함은 ARM EL3에서 패치된 bl2_ext를 실행하여 하류의 서명 검증을 비활성화할 수 있게 하며, 신뢰 체인을 붕괴시켜 임의의 서명되지 않은 TEE/GZ/LK/Kernel 로드를 가능하게 합니다.

주의: 부트 초기에 패치하면 오프셋이 잘못된 경우 기기가 영구적으로 벽돌화될 수 있습니다. 항상 전체 덤프와 신뢰할 수 있는 복구 경로를 유지하세요.

## 영향받는 부트 플로우 (MediaTek)

- 정상 경로: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- 취약 경로: seccfg가 unlocked로 설정된 경우, Preloader는 bl2_ext의 인증을 건너뛸 수 있습니다. Preloader는 여전히 EL3에서 bl2_ext로 점프하므로, 조작된 bl2_ext가 이후에 검증되지 않은 컴포넌트를 로드할 수 있습니다.

핵심 신뢰 경계:
- bl2_ext는 EL3에서 실행되며 TEE, GenieZone, LK/AEE 및 커널을 검증할 책임이 있습니다. bl2_ext 자체가 인증되지 않으면 나머지 체인은 쉽게 우회됩니다.

## 근본 원인

영향받는 장치에서는, seccfg가 "unlocked" 상태를 가리킬 때 Preloader가 bl2_ext 파티션의 인증을 강제하지 않습니다. 이로 인해 공격자가 제어하는 bl2_ext를 플래시하여 EL3에서 실행할 수 있습니다.

bl2_ext 내부에서는 검증 정책 함수가 패치되어 검증이 필요 없다고 무조건 보고하도록 만들 수 있습니다. 최소한의 개념적 패치는 다음과 같습니다:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
이 변경으로 인해 EL3에서 실행되는 패치된 bl2_ext가 로드할 때 이후의 모든 이미지(TEE, GZ, LK/AEE, Kernel)는 암호학적 검사 없이 수락됩니다.

## 타깃 트리아지 방법 (expdb 로그)

bl2_ext 로드 주변의 부트 로그(예: expdb)를 덤프/검사하세요. img_auth_required = 0 이고 인증서 검증 시간이 약 0 ms라면, 강제 적용(enforcement)이 해제되어 장치를 악용할 수 있을 가능성이 큽니다.

예시 로그 발췌:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
참고: 일부 기기는 잠금된 bootloader 상태에서도 bl2_ext 검증을 건너뛰는 것으로 보고되어 영향이 더 커질 수 있습니다.

## 실전 익스플로잇 워크플로우 (Fenrir PoC)

Fenrir는 이 유형의 문제에 대한 참조용 exploit/patching toolkit입니다. Nothing Phone (2a) (Pacman)을 지원하며 CMF Phone 1 (Tetris)에서도 (부분적으로만 지원되지만) 작동하는 것으로 알려져 있습니다. 다른 모델로 포팅하려면 기기별 bl2_ext에 대한 reverse engineering이 필요합니다.

개요 절차:
- 대상 코드네임에 해당하는 device bootloader 이미지를 확보하여 bin/<device>.bin으로 배치하세요
- bl2_ext 검증 정책을 비활성화하는 패치된 이미지를 빌드하세요
- 생성된 payload를 device에 플래시하세요 (헬퍼 스크립트는 fastboot를 사용한다고 가정합니다)

명령:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot를 사용할 수 없는 경우, 플랫폼에 적합한 다른 플래싱 방식을 사용해야 합니다.

## Runtime payload capabilities (EL3)

패치된 bl2_ext 페이로드는 다음을 수행할 수 있습니다:
- 커스텀 fastboot 명령을 등록
- 부트 모드 제어/재정의
- 런타임에 내장 bootloader 함수를 동적으로 호출
- 강력한 무결성 검사 통과를 위해 실제로는 unlocked 상태인데도 "lock state"를 locked로 스푸핑(일부 환경에서는 여전히 vbmeta/AVB 조정이 필요할 수 있음)

Limitation: 현재 PoCs들은 MMU 제약으로 인해 런타임 메모리 수정이 오류를 일으킬 수 있음을 지적합니다; 페이로드는 일반적으로 이 문제가 해결될 때까지 라이브 메모리 쓰기를 피합니다.

## Porting tips

- 기기별 bl2_ext를 리버스 엔지니어링하여 검증 정책 로직(예: sec_get_vfy_policy)을 찾아라.
- 정책의 반환 지점 또는 결정 분기점을 식별하고 이를 “검증 불필요”(return 0 / 무조건 허용)로 패치하라.
- 오프셋은 기기 및 펌웨어별로 완전히 분리해 두고, 변형들 간에 주소를 재사용하지 마라.
- 먼저 희생 가능한 장치에서 검증하라. 플래싱 전에 복구 계획(예: EDL/BootROM loader/SoC-specific download mode)을 준비하라.

## Security impact

- Preloader 이후 EL3 코드 실행 및 부트 경로의 나머지에 대한 체인 오브 트러스트가 완전히 붕괴됨.
- unsigned TEE/GZ/LK/Kernel을 부팅할 수 있어 secure/verified boot 기대를 우회하고 영구적 침해를 가능하게 함.

## Detection and hardening ideas

- Preloader가 seccfg 상태와 무관하게 bl2_ext를 검증하도록 보장하라.
- 인증 결과를 강제하고 감사 증거를 수집하라 (timings > 0 ms, 불일치 시 엄격한 오류).
- 락 상태 스푸핑은 attestation에 대해 무효화되어야 함(락 상태를 AVB/vbmeta 검증 결정 및 fuse-backed 상태에 연동).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
