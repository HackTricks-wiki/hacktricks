# Android Forensics

{{#include ../../banners/hacktricks-training.md}}

## 잠긴 기기

기기의 상태를 보존하고 모든 조치를 기록하는 획득 방법을 우선적으로 선택하세요. 기기가 잠겨 있는 경우, 사용할 수 있는 옵션은 모델, Android 버전, 패치 수준, 압수 전에 액세스가 설정되었는지 여부에 따라 달라집니다. NIST는 기기와 조사 권한에 따라 방법을 선택할 것을 권장합니다.<sup>[[1]](#references)</sup>

- USB debugging이 활성화되어 있었는지, 그리고 획득에 사용하는 워크스테이션이 이미 승인되었는지 확인하세요. ADB 액세스에는 일반적으로 사용자가 기기를 잠금 해제하고 워크스테이션의 RSA 키를 확인해야 합니다.<sup>[[3]](#references)</sup>
- 관련 법률 및 절차 규칙에 따라 biometric access를 계속 사용할 수 있는지 고려하세요.
- **smudge attack**을 사용하면 화면에 남은 자국으로 그래픽 잠금 패턴을 알아낼 수 있지만, 이후의 터치와 화면 청소로 신뢰도가 낮아집니다.<sup>[[2]](#references)</sup>
- 승인된 도구가 해당 기기와 소프트웨어 빌드를 지원하는 경우, PIN, password 또는 pattern 복구나 brute force를 시도할 수 있습니다. 하드웨어 기반 자격 증명 검증, 재시도 지연, 초기화 정책은 기기에 따라 다르므로 Android 기기가 지원된다는 증거 없이 iPhone 기법이나 결과를 대신 적용하지 마세요.<sup>[[1]](#references)</sup>

## 데이터 획득

구형 기기에서는 기존 [ADB backup](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup)으로 `.backup` 파일을 만들 수 있으며, 이 파일은 Android Backup Extractor로 압축을 풀 수 있습니다.<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

모든 애플리케이션의 데이터가 수집된다고 가정하지 마세요. ADB는 해당 명령을 deprecated로 표시하며, Android 12에서는 앱이 debuggable이 아닌 경우 API level 31 이상을 대상으로 하는 앱의 데이터를 제외합니다.<sup>[[4]](#references)</sup>

### Root 또는 물리적 디버그 액세스

실행 중인 기기에 root 액세스 권한이 있다면 먼저 파티션과 마운트를 조사하세요. 아래 명령은 물리적 JTAG 획득에 직접 적용되지 않습니다. 올바른 블록 디바이스는 하드웨어에 따라 다르므로 항상 `mmcblk0`이라고 가정하지 마세요. 검증된 소스만 별도의 저장소에 이미징하세요:<sup>[[1]](#references)</sup>

JTAG 획득은 기기의 하드웨어 테스트 액세스 인터페이스와 호환되는 획득 장비를 사용해 액세스 가능한 메모리를 읽는 방식입니다. 핀 배치, 칩셋 지원, 기기 상태, 휘발성 및 비휘발성 대상의 구분은 기기마다 다릅니다. 해당 하드웨어 연결 경로를 문서화하고 그 모델에 대해 검증된 절차를 사용하세요.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

예를 들어, 파티션 목록을 통해 `/dev/block/mmcblk0`가 전체 플래시 장치임을 확인했고 대상에 충분한 공간이 있다면, 원래의 이미징 명령은 다음과 같습니다.<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

여기서 `df /data`는 `/data`를 마운트된 파일시스템과 연결하는 데 도움이 됩니다. 이것을 `mmcblk0`가 올바른 전체 장치 소스이거나 `4096`이 유효한 유일한 `dd` 블록 크기라는 증거로 취급해서는 안 됩니다.

결과의 해시를 계산하고, 정확한 명령어, 장치 식별자, 시간 및 획득 중 발생한 변경 사항을 기록합니다.<sup>[[1]](#references)</sup>

### 메모리

LiME는 Linux 및 일부 Android 장치에서 물리 메모리를 획득할 수 있지만, 대상 커널용으로 빌드하고 충분한 권한으로 로드해야 하는 커널 모듈입니다. 모듈 서명, 커널 잠금 및 최신 Android 보안 강화 기능으로 인해 모듈이 로드되지 않을 수 있습니다.<sup>[[5]](#references)</sup>

프로젝트의 Android 워크플로에서는 ADB를 사용해 일치하는 모듈을 전송하고, TCP 포트를 포워딩한 뒤, root 셸에서 모듈을 로드하고, 조사 호스트에서 스트림을 캡처합니다.<sup>[[5]](#references)</sup>

```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```

LiME은 `path=/sdcard/ram.lime`을 사용해 기기 저장소에 기록할 수도 있지만, 이 경우 기기 저장소가 변경되며 충분한 여유 공간이 필요합니다. 이 부작용을 기록하고 획득한 이미지의 해시를 계산하세요.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - 모바일 기기 포렌식 지침](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - 스마트폰 터치스크린에 대한 스머지 공격](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android 디버그 브리지](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB 백업 제한](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android 백업 추출기](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
