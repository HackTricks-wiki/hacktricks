# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## 잠긴 기기

기기의 상태를 보존하고 모든 작업을 기록하는 acquisition 방법을 우선 사용합니다. 기기가 잠겨 있는 경우 사용할 수 있는 옵션은 모델, Android 버전, patch level, 압수 전에 access가 구성되어 있었는지 여부에 따라 달라집니다. NIST는 기기와 조사 권한에 따라 방법을 선택할 것을 권장합니다.<sup>[[1]](#references)</sup>

- USB debugging이 활성화되어 있었는지, acquisition workstation이 이미 authorized 상태인지 확인합니다. ADB access에는 일반적으로 사용자가 기기를 unlock하고 workstation의 RSA key를 확인하는 과정이 필요합니다.<sup>[[3]](#references)</sup>
- 적용되는 법적 및 절차적 규정에 따라 biometric access를 계속 사용할 수 있는지 고려합니다.
- **smudge attack**을 사용하면 화면에 남은 잔여물로 graphical unlock pattern을 알아낼 수 있지만, 이후의 터치와 청소로 신뢰성이 낮아집니다.<sup>[[2]](#references)</sup>
- authorized tooling이 정확한 기기와 software build를 지원하는 경우 PIN, password 또는 pattern recovery나 brute force를 시도할 수 있습니다. Hardware-backed credential verification, retry delay 및 wipe policy로 인해 이 과정은 기기별로 크게 달라지므로, Android 기기가 지원된다는 증거 없이 iPhone 기법이나 결과를 대신 사용하지 마십시오.<sup>[[1]](#references)</sup>

## Data acquisition

구형 기기에서는 기존 [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup)을 사용해 `.backup` 파일을 생성할 수 있으며, Android Backup Extractor로 이 파일의 압축을 해제할 수 있습니다.<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
모든 application이 포함된다고 가정하지 마세요. ADB는 해당 command를 deprecated로 표시하며, Android 12에서는 application이 debuggable하지 않은 경우 API level 31 이상을 대상으로 하는 application의 data를 제외합니다.<sup>[[4]](#references)</sup>

### Root 또는 physical debug access

실행 중인 device에 root access가 있는 경우 먼저 partitions와 mounts를 inventory하세요. 아래 commands는 physical JTAG acquisition에 직접 적용되지 않습니다. 올바른 block device는 hardware에 따라 다르므로 항상 `mmcblk0`이라고 가정하지 마세요. 검증된 source만 별도의 storage에 image하세요:<sup>[[1]](#references)</sup>

JTAG acquisition은 대신 device의 hardware test-access interface와 호환되는 acquisition equipment를 사용하여 접근 가능한 memory를 읽습니다. Pinout, chipset support, device state, volatile target과 non-volatile target의 구분은 device마다 다르므로 hardware path를 문서화하고 해당 model에 대해 검증된 procedure를 사용하세요.<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
예를 들어 파티션 목록에서 `/dev/block/mmcblk0`이 전체 flash device임을 확인하고 대상에 충분한 공간이 있다면, 원래 acquisition 명령은 다음과 같습니다:<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
여기서 `df /data`는 `/data`를 마운트된 파일시스템과 연결하는 데 도움이 되지만, `mmcblk0`가 올바른 전체 디바이스 소스이거나 `4096`이 유효한 `dd` 블록 크기의 유일한 값이라는 증거로 취급해서는 안 됩니다.

결과를 해시하고, 정확한 명령, 디바이스 식별자, 시간 및 acquisition 중 수행한 모든 변경 사항을 기록합니다.<sup>[[1]](#references)</sup>

### Memory

LiME는 Linux와 일부 Android 디바이스에서 physical memory를 acquisition할 수 있지만, 해당 kernel module은 대상 kernel에 맞게 빌드되어야 하며 충분한 privileges로 로드되어야 합니다. Module signing, kernel lockdown 및 최신 Android hardening으로 인해 로드되지 않을 수 있습니다.<sup>[[5]](#references)</sup>

이 프로젝트의 Android workflow는 ADB를 사용해 일치하는 module을 push하고, TCP port를 forward하며, root shell에서 module을 로드한 다음, examination host에서 stream을 캡처합니다.<sup>[[5]](#references)</sup>
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
LiME은 `path=/sdcard/ram.lime`을 사용해 device storage에 기록할 수도 있지만, 이 경우 device의 storage가 변경되고 충분한 여유 공간이 필요합니다. 이러한 side effect를 기록하고 획득한 image의 hash를 계산하세요.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - 모바일 device forensics 지침](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smartphone touch screen에 대한 Smudge Attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB backup restriction](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
